/**
 * Authentication utility functions and security helpers
 *
 * This module provides cryptographic functions, URL validation, cookie management,
 * and other security-focused utilities used throughout the authentication process.
 * All functions are designed to work in both Node.js and edge runtime environments.
 *
 * @module utils
 */

/**
 * Utility functions for authentication operations
 *
 * Provides cryptographically secure functions for:
 * - Random string generation
 * - HMAC signature creation and verification
 * - Base64 URL encoding/decoding
 * - URL sanitization and validation
 * - Cookie size monitoring
 * - CSRF token management
 *
 * All cryptographic operations use the Web Crypto API for cross-platform compatibility.
 *
 * @example
 * ```typescript
 * // Generate a secure random string
 * const nonce = AuthUtils.generateNonce(32);
 *
 * // Create HMAC signature
 * const signature = await AuthUtils.createHMAC('data', 'secret');
 *
 * // Validate URL safety
 * const safeUrl = AuthUtils.sanitizeReturnTo(userUrl, ['https://myapp.com']);
 * ```
 */
export class AuthUtils {
  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Format certificate or public key for SAML
   *
   * Cleans up certificate or key strings by removing headers, footers,
   * and whitespace. This ensures consistent formatting regardless of how the
   * key was provided (e.g., with or without headers in environment variables).
   *
   * Note: For private keys that need PEM format (like decryption keys),
   * use formatPrivateKey() instead.
   *
   * @param key - The certificate or key string to format
   * @returns Cleaned base64 string without headers/footers
   */
  static formatKey(key: string): string {
    if (!key) return '';
    return key
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s+/g, '');
  }

  /**
   * Format private key for cryptographic operations
   *
   * Normalizes a private key to proper PEM format. This is required for
   * decryption operations where the key must be in valid PEM format with
   * headers, footers, and proper line breaks.
   *
   * Handles various input formats:
   * - Already formatted PEM with headers
   * - Raw base64 without headers
   * - Keys with or without line breaks
   *
   * @param key - The private key string to format
   * @returns Private key in proper PEM format with headers and line breaks
   */
  static formatPrivateKey(key: string): string {
    if (!key) return '';

    // Remove any existing headers/footers and whitespace
    const rawKey = key
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s+/g, '');

    if (!rawKey) return '';

    // Add proper line breaks every 64 characters
    const formattedKey = rawKey.match(/.{1,64}/g)?.join('\n') || rawKey;

    // Wrap in PEM headers
    return `-----BEGIN PRIVATE KEY-----\n${formattedKey}\n-----END PRIVATE KEY-----`;
  }

  /**
   * Format certificate for metadata
   *
   * Normalizes a certificate to proper PEM format. This ensures certificates
   * are properly formatted for inclusion in SAML metadata.
   *
   * @param cert - The certificate string to format
   * @returns Certificate in proper PEM format with headers and line breaks
   */
  static formatCertificate(cert: string): string {
    if (!cert) return '';

    // Remove any existing headers/footers and whitespace
    const rawCert = cert
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s+/g, '');

    if (!rawCert) return '';

    // Add proper line breaks every 64 characters
    const formattedCert = rawCert.match(/.{1,64}/g)?.join('\n') || rawCert;

    // Wrap in certificate headers
    return `-----BEGIN CERTIFICATE-----\n${formattedCert}\n-----END CERTIFICATE-----`;
  }

  /**
   * Generate a cryptographically secure random string
   *
   * Uses the Web Crypto API to generate cryptographically secure random bytes
   * and converts them to a hexadecimal string representation.
   *
   * @param length - Number of random bytes to generate (defaults to 32)
   * @returns Hexadecimal string representation of random bytes
   *
   * @example
   * ```typescript
   * // Generate a 32-byte (64-character hex) nonce
   * const nonce = AuthUtils.generateNonce();
   *
   * // Generate a shorter 16-byte (32-character hex) nonce
   * const shortNonce = AuthUtils.generateNonce(16);
   * ```
   */
  static generateNonce(length = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create HMAC-SHA256 signature
   *
   * Creates a Hash-based Message Authentication Code using SHA-256.
   * The result is encoded as a Base64 URL-safe string for use in URLs and headers.
   *
   * @param data - Data to sign
   * @param secret - Secret key for HMAC generation
   * @returns Promise resolving to Base64 URL-encoded HMAC signature
   *
   * @example
   * ```typescript
   * const signature = await AuthUtils.createHMAC(
   *   'sensitive-data',
   *   'your-secret-key'
   * );
   * console.log(signature); // e.g., "abc123def456..."
   * ```
   *
   * @throws {Error} If Web Crypto API is not available or key import fails
   */
  static async createHMAC(data: string, secret: string): Promise<string> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, this.encoder.encode(data));
    return this.arrayBufferToBase64Url(signature);
  }

  /**
   * Verify HMAC-SHA256 signature
   *
   * Verifies that an HMAC signature was created with the expected secret.
   * Uses constant-time comparison to prevent timing attacks.
   *
   * @param data - Original data that was signed
   * @param signature - Base64 URL-encoded signature to verify
   * @param secret - Secret key that should have been used for signing
   * @returns Promise resolving to true if signature is valid, false otherwise
   *
   * @example
   * ```typescript
   * const isValid = await AuthUtils.verifyHMAC(
   *   'original-data',
   *   'received-signature',
   *   'shared-secret'
   * );
   *
   * if (isValid) {
   *   console.log('Signature is authentic');
   * } else {
   *   console.log('Signature verification failed');
   * }
   * ```
   *
   * @throws {Error} If Web Crypto API is not available or key import fails
   */
  static async verifyHMAC(data: string, signature: string, secret: string): Promise<boolean> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = this.base64UrlToArrayBuffer(signature);
    return await crypto.subtle.verify('HMAC', key, signatureBuffer, this.encoder.encode(data));
  }

    /**
   * Sanitize and validate returnTo URL
   *
   * Validates that a returnTo URL is safe for redirection by checking:
   * - URL is well-formed and parseable
   * - Protocol is HTTP or HTTPS (prevents javascript:, data:, etc.)
   * - Origin matches one of the allowed origins
   *
   * This prevents open redirect vulnerabilities and malicious URL injection.
   *
   * @param returnTo - URL to validate and sanitize
   * @param allowedOrigins - Array of allowed origin URLs (e.g., ['https://myapp.com'])
   * @returns Sanitized URL string if valid, null if invalid or unsafe
   *
   * @example
   * ```typescript
   * const safeUrl = AuthUtils.sanitizeReturnTo(
   *   'https://myapp.com/dashboard',
   *   ['https://myapp.com', 'https://admin.myapp.com']
   * );
   *
   * if (safeUrl) {
   *   // Safe to redirect
   *   return Response.redirect(safeUrl);
   * } else {
   *   // Potentially malicious URL, redirect to default
   *   return Response.redirect('/dashboard');
   * }
   * ```
   *
   * @security This function is critical for preventing open redirect attacks
   */
  static sanitizeReturnTo(returnTo: string, allowedOrigins: string[]): string | null {
    try {
      const url = new URL(returnTo);

      // Only allow same-origin URLs or explicitly allowed origins
      const isAllowed = allowedOrigins.some(origin => {
        const allowedUrl = new URL(origin);
        return url.origin === allowedUrl.origin;
      });

      if (!isAllowed) {
        return null;
      }

      // Prevent javascript: protocol and other dangerous schemes
      if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
      }

      return url.toString();
    } catch {
      return null;
    }
  }

  /**
   * Check cookie size and warn if too large
   *
   * Monitors cookie size to prevent issues with browsers and proxies that have
   * cookie size limitations. Most browsers allow 4KB cookies, but proxies and
   * load balancers may have smaller limits.
   *
   * @param cookieValue - The cookie value to check (typically encrypted session data)
   * @param threshold - Size threshold in bytes (defaults to 3500 bytes)
   * @param logger - Optional logger to emit warnings (must have warn method)
   *
   * @example
   * ```typescript
   * const sessionCookie = 'encrypted-session-data...';
   * AuthUtils.checkCookieSize(sessionCookie, 3500, logger);
   *
   * // Custom threshold for strict environments
   * AuthUtils.checkCookieSize(sessionCookie, 2000, logger);
   * ```
   *
   * @remarks
   * - Default threshold of 3.5KB leaves room for other cookies and headers
   * - Large cookies can cause 400 Bad Request errors in some environments
   * - Consider storing only essential data or using references to server-side data
   */
  static checkCookieSize(
    cookieValue: string,
    threshold = 3500,
    logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void }
  ): void {
    const size = new Blob([cookieValue]).size;

    if (size > threshold && logger) {
      logger.warn('Cookie size exceeds threshold', {
        size,
        threshold,
        warning: 'Large cookies may cause issues with some browsers and proxies'
      });
    }
  }

  /**
   * Base64 URL encode
   *
   * Converts a string to Base64 URL encoding (RFC 4648 Section 5).
   * URL-safe encoding replaces + with -, / with _, and removes padding =.
   *
   * This encoding is safe for use in URLs, headers, and JSON without escaping.
   * Uses proper Unicode handling via TextEncoder for cross-platform compatibility.
   *
   * @param data - String data to encode
   * @returns Base64 URL-encoded string
   *
   * @example
   * ```typescript
   * const encoded = AuthUtils.base64UrlEncode('Hello, 世界!');
   * console.log(encoded); // "SGVsbG8sIOS4lueVjCE"
   *
   * // Safe for URLs
   * const url = `https://api.example.com/data?payload=${encoded}`;
   * ```
   *
   * @see {@link https://tools.ietf.org/html/rfc4648#section-5 | RFC 4648 Section 5}
   */
  static base64UrlEncode(data: string): string {
    // Use TextEncoder for proper Unicode handling and cross-platform compatibility
    const bytes = AuthUtils.encoder.encode(data);

    // Convert to binary string for btoa (edge function compatible)
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    const base64 = btoa(binary);

    // Convert to URL-safe base64
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Base64 URL decode
   *
   * Converts a Base64 URL-encoded string back to the original string.
   * Handles padding restoration and URL-safe character conversion.
   *
   * Uses proper Unicode handling via TextDecoder for cross-platform compatibility
   * and works in both Node.js and edge runtime environments.
   *
   * @param encoded - Base64 URL-encoded string to decode
   * @returns Original string data
   *
   * @example
   * ```typescript
   * const decoded = AuthUtils.base64UrlDecode('SGVsbG8sIOS4lueVjCE');
   * console.log(decoded); // "Hello, 世界!"
   * ```
   *
   * @throws {Error} If the encoded string is malformed or invalid
   */
  static base64UrlDecode(encoded: string): string {
    // Add padding if needed
    const padded = encoded + '==='.slice(0, (4 - encoded.length % 4) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

    // Use native atob with proper Unicode handling for edge function compatibility
    // Use TextDecoder for proper Unicode handling and edge function compatibility
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return AuthUtils.decoder.decode(bytes);
  }

  /**
   * Convert ArrayBuffer to Base64 URL
   */
  private static arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');

    // Use native btoa for edge function compatibility
    const base64 = btoa(binary);

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Convert Base64 URL to ArrayBuffer
   */
  private static base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
    const binary = this.base64UrlDecode(base64Url);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Generate CSRF token
   *
   * Creates a cryptographically secure random token for CSRF protection.
   * The token should be included in forms and verified on submission.
   *
   * @returns 32-byte (64-character hex) CSRF token
   *
   * @example
   * ```typescript
   * // Generate token for form
   * const csrfToken = AuthUtils.generateCSRFToken();
   *
   * // Include in form
   * <input type="hidden" name="_csrf" value={csrfToken} />
   *
   * // Verify on submission
   * const isValid = AuthUtils.validateCSRFToken(submittedToken, expectedToken);
   * ```
   *
   * @security Store the token securely (e.g., in session) and validate on each request
   */
  static generateCSRFToken(): string {
    return this.generateNonce(32);
  }

  /**
   * Validate CSRF token
   *
   * Performs constant-time comparison of CSRF tokens to prevent timing attacks.
   * Both tokens must be exactly the same length and content to be considered valid.
   *
   * @param token - Token submitted by the client
   * @param expectedToken - Token stored in session or other secure location
   * @returns true if tokens match, false otherwise
   *
   * @example
   * ```typescript
   * // In route handler
   * const submittedToken = request.formData.get('_csrf');
   * const sessionToken = session.csrfToken;
   *
   * if (!AuthUtils.validateCSRFToken(submittedToken, sessionToken)) {
   *   throw new Error('CSRF token validation failed');
   * }
   * ```
   *
   * @security Uses constant-time comparison to prevent timing-based token discovery
   */
  static validateCSRFToken(token: string, expectedToken: string): boolean {
    if (!token || !expectedToken || token.length !== expectedToken.length) {
      return false;
    }

    // Constant-time comparison to prevent timing attacks
    let result = 0;
    for (let i = 0; i < token.length; i++) {
      result |= token.charCodeAt(i) ^ expectedToken.charCodeAt(i);
    }
    return result === 0;
  }
}
