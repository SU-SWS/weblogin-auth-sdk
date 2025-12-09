/**
 * Structured logging implementations with security-conscious redaction
 *
 * Provides multiple logger implementations for different environments:
 * - DefaultLogger: Full-featured structured logging with secret redaction
 * - ConsoleLogger: Simple console output for development
 * - SilentLogger: No-op logger for testing or minimal environments
 *
 * All loggers implement the Logger interface for consistent usage across the SDK.
 *
 * @module logger
 */

import { Logger } from './types.js';

/**
 * Default logger implementation with structured logging and redaction
 *
 * Features:
 * - Structured JSON output with timestamps and context
 * - Automatic redaction of sensitive data (passwords, certificates, etc.)
 * - Request ID and user ID context tracking
 * - Configurable verbose mode for debug logging
 * - Certificate fingerprinting for safe logging
 *
 * @example
 * ```typescript
 * const logger = new DefaultLogger(true); // Enable verbose mode
 * logger.setContext('req-123', 'user-456');
 *
 * logger.info('User logged in', { ip: '192.168.1.1' });
 * logger.debug('SAML response received', {
 *   samlResponse: 'sensitive-data' // Will be redacted
 * });
 * ```
 */
export class DefaultLogger implements Logger {
  private verbose: boolean;
  private requestId?: string;
  private userId?: string;

  /**
   * Create a new DefaultLogger instance
   *
   * @param verbose - Enable debug logging (defaults to false)
   */
  constructor(verbose = false) {
    this.verbose = verbose;
  }

  /**
   * Set request context for all subsequent log entries
   *
   * Context information is automatically included in all log entries
   * until the context is changed or cleared.
   *
   * @param requestId - Unique identifier for the current request (optional)
   * @param userId - Identifier of the authenticated user (optional)
   *
   * @example
   * ```typescript
   * logger.setContext('req-abc123', 'user-456');
   * logger.info('Processing request'); // Will include requestId and userId
   * ```
   */
  setContext(requestId?: string, userId?: string) {
    this.requestId = requestId;
    this.userId = userId;
  }

  /**
   * Internal logging method with structured output
   *
   * Creates structured log entries with automatic secret redaction.
   * Debug messages are only output when verbose mode is enabled.
   *
   * @param level - Log level (debug, info, warn, error)
   * @param message - Primary log message
   * @param meta - Additional metadata to include (will be redacted)
   *
   * @private
   */
  private log(level: string, message: string, meta: Record<string, unknown> = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      requestId: this.requestId,
      userId: this.userId,
      ...this.redactSecrets(meta),
    };

    // Only log debug messages in verbose mode
    if (level === 'debug' && !this.verbose) {
      return;
    }

    console.log(JSON.stringify(logEntry));
  }

  /**
   * Recursively redact sensitive data from log metadata
   *
   * Identifies and redacts fields that commonly contain sensitive information:
   * - Passwords and secrets
   * - Authentication tokens
   * - Certificates and private keys
   * - SAML responses
   * - Cookie values (but not cookie names or metadata)
   *
   * For certificates, generates a hash fingerprint instead of complete redaction
   * to aid in debugging certificate-related issues.
   *
   * @param obj - Object to scan and redact
   * @returns Object with sensitive values replaced with redaction markers
   *
   * @private
   */
  private redactSecrets(obj: Record<string, unknown>): Record<string, unknown> {
    const redacted = { ...obj };

    // Keys that indicate sensitive data to redact
    const secretKeys = [
      'password',
      'secret',
      'token',
      'cert',
      'certificate',
      'samlresponse',
      'authorization',
      'private',
      'pvk',
      'cookievalue',  // Actual cookie values
    ];

    // Keys that should NOT be redacted even if they contain a secret key substring
    // These are metadata about cookies, not actual sensitive values
    const allowedKeys = [
      'cookiename',
      'maincookiename',
      'jscookiename',
      'maincookie',
      'jscookie',
      'cookiesize',
      'cookieoptions',
      'httponly',
      'secure',
      'samesite',
      'path',
      'domain',
      'maxage',
    ];

    for (const [key, value] of Object.entries(redacted)) {
      const lowerKey = key.toLowerCase();

      // Skip redaction for explicitly allowed keys (cookie metadata)
      const isAllowed = allowedKeys.some(allowed => lowerKey === allowed);
      if (isAllowed) {
        // Still recursively process nested objects
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          redacted[key] = this.redactSecrets(value as Record<string, unknown>);
        }
        continue;
      }

      // Only redact if the key name specifically indicates sensitive data
      const shouldRedact = secretKeys.some(secret => lowerKey.includes(secret));

      if (shouldRedact) {
        if (typeof value === 'string' && value.length > 0) {
          // For certificates, show fingerprint/hash instead
          if (lowerKey.includes('cert')) {
            redacted[key] = `[CERT_HASH:${this.hashString(value)}]`;
          } else {
            redacted[key] = '[REDACTED]';
          }
        } else {
          redacted[key] = '[REDACTED]';
        }
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        // Recursively redact nested objects
        redacted[key] = this.redactSecrets(value as Record<string, unknown>);
      }
    }

    return redacted;
  }

  /**
   * Generate a simple hash for certificate fingerprinting
   *
   * Creates a non-cryptographic hash of the first 100 characters of input
   * to generate a consistent identifier for certificates and other data.
   * This helps with debugging while keeping sensitive data secure.
   *
   * @param input - String to hash (typically a certificate)
   * @returns Hexadecimal hash string
   *
   * @private
   * @security This is NOT a cryptographic hash - only for fingerprinting
   */
  private hashString(input: string): string {
    // Simple hash for fingerprinting (not cryptographically secure)
    let hash = 0;
    for (let i = 0; i < Math.min(input.length, 100); i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Log debug information (only when verbose mode is enabled)
   *
   * @param message - Debug message
   * @param meta - Additional debug metadata
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    this.log('debug', message, meta);
  }

  /**
   * Log general information
   *
   * @param message - Information message
   * @param meta - Additional metadata
   */
  info(message: string, meta?: Record<string, unknown>): void {
    this.log('info', message, meta);
  }

  /**
   * Log warning information
   *
   * @param message - Warning message
   * @param meta - Additional warning metadata
   */
  warn(message: string, meta?: Record<string, unknown>): void {
    this.log('warn', message, meta);
  }

  /**
   * Log error information
   *
   * @param message - Error message
   * @param meta - Additional error metadata
   */
  error(message: string, meta?: Record<string, unknown>): void {
    this.log('error', message, meta);
  }
}

/**
 * Console logger for simple environments
 *
 * A basic logger implementation that outputs directly to the console.
 * Suitable for development environments or when structured logging is not needed.
 * Does not include redaction or structured formatting.
 *
 * @example
 * ```typescript
 * const logger = new ConsoleLogger();
 * logger.info('Server starting', { port: 3000 });
 * // Output: [INFO] Server starting { port: 3000 }
 * ```
 */
export class ConsoleLogger implements Logger {
  /**
   * Log debug information to console
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    console.debug('[DEBUG]', message, meta);
  }

  /**
   * Log general information to console
   */
  info(message: string, meta?: Record<string, unknown>): void {
    console.info('[INFO]', message, meta);
  }

  /**
   * Log warning information to console
   */
  warn(message: string, meta?: Record<string, unknown>): void {
    console.warn('[WARN]', message, meta);
  }

  /**
   * Log error information to console
   */
  error(message: string, meta?: Record<string, unknown>): void {
    console.error('[ERROR]', message, meta);
  }
}

/**
 * Silent logger for testing or minimal environments
 *
 * A no-op logger implementation that discards all log messages.
 * Useful for testing environments or when logging should be completely disabled.
 *
 * @example
 * ```typescript
 * // For testing - no console output
 * const logger = new SilentLogger();
 * logger.error('This will not appear anywhere');
 * ```
 */
export class SilentLogger implements Logger {
  /**
   * Debug logging (no-op)
   */
  debug(): void {
    // Silent
  }

  /**
   * Info logging (no-op)
   */
  info(): void {
    // Silent
  }

  /**
   * Warning logging (no-op)
   */
  warn(): void {
    // Silent
  }

  /**
   * Error logging (no-op)
   */
  error(): void {
    // Silent
  }
}
