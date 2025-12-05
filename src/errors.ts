/**
 * Enhanced error handling classes for better debugging and user experience
 *
 * This module provides specialized error classes for different aspects of the authentication process.
 * Each error class includes specific metadata to help with debugging and provide better error context.
 *
 * @module errors
 */

import { AuthError } from './types.js';

/**
 * SAML-specific error for authentication failures
 *
 * Thrown when SAML authentication encounters issues such as:
 * - Invalid SAML responses
 * - Certificate validation failures
 * - Signature verification errors
 * - Malformed SAML assertions
 *
 * @example
 * ```typescript
 * throw new SAMLError(
 *   'Invalid SAML signature',
 *   'INVALID_SIGNATURE',
 *   'urn:entity:stanford-example',
 *   400
 * );
 * ```
 */
export class SAMLError extends AuthError {
  /**
   * Create a SAML-specific error
   *
   * @param message - Human-readable error message
   * @param samlCode - Specific SAML error code for programmatic handling
   * @param issuer - SAML issuer/entity ID where the error occurred (optional)
   * @param statusCode - HTTP status code (defaults to 400)
   */
  constructor(
    message: string,
    public readonly samlCode: string,
    public readonly issuer?: string,
    statusCode = 400
  ) {
    super(message, `SAML_${samlCode}`, statusCode);
    this.name = 'SAMLError';
  }
}

/**
 * Session-specific error for session management failures
 *
 * Thrown when session operations encounter issues such as:
 * - Cookie encryption/decryption failures
 * - Session expiration handling
 * - Invalid session data
 * - Cookie size limitations
 *
 * @example
 * ```typescript
 * throw new SessionError(
 *   'Session cookie exceeds size limit',
 *   'COOKIE_TOO_LARGE',
 *   'weblogin-auth-session',
 *   500
 * );
 * ```
 */
export class SessionError extends AuthError {
  /**
   * Create a session-specific error
   *
   * @param message - Human-readable error message
   * @param sessionCode - Specific session error code for programmatic handling
   * @param sessionName - Name of the session cookie that caused the error (optional)
   * @param statusCode - HTTP status code (defaults to 500)
   */
  constructor(
    message: string,
    public readonly sessionCode: string,
    public readonly sessionName?: string,
    statusCode = 500
  ) {
    super(message, `SESSION_${sessionCode}`, statusCode);
    this.name = 'SessionError';
  }
}

/**
 * Configuration error for invalid setup
 *
 * Thrown when the authentication configuration is invalid or incomplete such as:
 * - Missing required environment variables
 * - Invalid certificate formats
 * - Malformed URLs
 * - Insufficient secret key lengths
 *
 * @example
 * ```typescript
 * throw new ConfigError(
 *   'SAML certificate is required but not provided',
 *   'saml_cert',
 *   500
 * );
 * ```
 */
export class ConfigError extends AuthError {
  /**
   * Create a configuration-specific error
   *
   * @param message - Human-readable error message describing the configuration issue
   * @param configField - The configuration field that is invalid (used to generate error code)
   * @param statusCode - HTTP status code (defaults to 500)
   */
  constructor(
    message: string,
    public readonly configField: string,
    statusCode = 500
  ) {
    super(message, `CONFIG_${configField.toUpperCase()}_INVALID`, statusCode);
    this.name = 'ConfigError';
  }
}

/**
 * Network/timeout error for external service calls
 *
 * Thrown when network operations fail such as:
 * - SAML IdP connectivity issues
 * - Timeout errors during authentication
 * - DNS resolution failures
 * - SSL/TLS handshake errors
 *
 * @example
 * ```typescript
 * throw new NetworkError(
 *   'Failed to connect to IdP',
 *   'saml_login',
 *   originalError,
 *   503
 * );
 * ```
 */
export class NetworkError extends AuthError {
  /**
   * Create a network-specific error
   *
   * @param message - Human-readable error message describing the network issue
   * @param operation - The network operation that failed (used to generate error code)
   * @param originalError - The original error that caused this network error (optional)
   * @param statusCode - HTTP status code (defaults to 503)
   */
  constructor(
    message: string,
    public readonly operation: string,
    public readonly originalError?: Error,
    statusCode = 503
  ) {
    super(message, `NETWORK_${operation.toUpperCase()}_FAILED`, statusCode);
    this.name = 'NetworkError';
  }
}
