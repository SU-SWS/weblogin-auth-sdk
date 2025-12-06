/**
 * Edge-compatible session management for serverless environments
 *
 * This module provides lightweight session reading capabilities for edge functions
 * and serverless environments where full Node.js dependencies aren't available.
 *
 * Features:
 * - Decrypt iron-session cookies without Node.js dependencies
 * - Works in Netlify Functions, Vercel Edge Functions, Cloudflare Workers
 * - Minimal API surface optimized for read-only session access
 * - Built-in cookie parsing and session validation
 * - Configurable logging for debugging
 *
 * This is a read-only implementation - session creation/modification should be done
 * server-side using the full SessionManager.
 *
 * @module edge-session
 */

import {
  Session,
  User
} from './types.js';
import { unsealData } from 'iron-session';

/**
 * Simple edge-compatible logger for debugging
 *
 * Minimal logger interface that works in edge runtime environments
 * where full console APIs might not be available.
 */
interface EdgeLogger {
  /** Debug logging (typically only enabled in verbose mode) */
  debug(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Minimal logger that works in edge environments
 *
 * A simple console-based logger that can be disabled for production environments.
 *
 * @example
 * ```typescript
 * const logger = new EdgeConsoleLogger(true); // Enable verbose mode
 * logger.debug('Session decryption attempt', { cookieName: 'my-session' });
 * ```
 */
class EdgeConsoleLogger implements EdgeLogger {
  /**
   * Create a new edge console logger
   * @param verbose - Enable debug output (defaults to false)
   */
  constructor(private verbose: boolean = false) {}

  /**
   * Log debug information if verbose mode is enabled
   * @param message - Debug message
   * @param meta - Optional metadata object
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    if (this.verbose) {
      console.log(`[DEBUG] ${message}`, meta || {});
    }
  }
}

/**
 * Edge-compatible cookie interface
 *
 * Simple representation of an HTTP cookie for edge environments.
 */
export interface EdgeCookie {
  /** Cookie name */
  name: string;
  /** Cookie value */
  value: string;
}

/**
 * Simple cookie parser for edge environments
 *
 * Parses HTTP Cookie header strings into individual cookie values.
 * Handles URL decoding and edge cases like cookies containing '=' characters.
 *
 * @example
 * ```typescript
 * const parser = new EdgeCookieParser(request.headers.get('cookie'));
 * const sessionValue = parser.get('weblogin-auth-session');
 * const allCookies = parser.getAll();
 * ```
 */
export class EdgeCookieParser {
  private cookies: Map<string, string> = new Map();

  /**
   * Create a new cookie parser
   *
   * @param cookieHeader - HTTP Cookie header value (e.g., "name1=value1; name2=value2")
   *
   * @example
   * ```typescript
   * const cookieHeader = request.headers.get('cookie');
   * const parser = new EdgeCookieParser(cookieHeader);
   * ```
   */
  constructor(cookieHeader?: string | null) {
    if (cookieHeader) {
      this.parseCookies(cookieHeader);
    }
  }

  /**
   * Parse cookie header string into individual cookies
   *
   * Handles URL decoding and cookies with '=' characters in values.
   *
   * @param cookieHeader - Raw cookie header string
   * @private
   */
  private parseCookies(cookieHeader: string): void {
    cookieHeader.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) {
        const value = rest.join('='); // Handle values with = in them
        this.cookies.set(name, decodeURIComponent(value));
      }
    });
  }

  /**
   * Get cookie value by name
   *
   * @param name - Cookie name to retrieve
   * @returns Cookie value or undefined if not found
   *
   * @example
   * ```typescript
   * const sessionValue = parser.get('weblogin-auth-session');
   * if (sessionValue) {
   *   // Process session cookie
   * }
   * ```
   */
  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  /**
   * Get all cookies as an object
   *
   * @returns Object with cookie names as keys and values as values
   *
   * @example
   * ```typescript
   * const allCookies = parser.getAll();
   * console.log('All cookies:', allCookies);
   * ```
   */
  getAll(): Record<string, string> {
    return Object.fromEntries(this.cookies);
  }
}

/**
 * Edge-compatible session reader
 *
 * Provides read-only session access in edge runtime environments.
 * Can decrypt iron-session cookies without Node.js dependencies.
 *
 * Key features:
 * - Read and decrypt iron-session cookies
 * - Validate session expiration
 * - Extract user information
 * - Works in Netlify, Vercel, Cloudflare environments
 *
 * This is a lightweight alternative to SessionManager for edge functions
 * where full session management isn't needed.
 *
 * @example
 * ```typescript
 * // In Netlify/Vercel edge function
 * export default async function handler(request: Request) {
 *   const reader = new EdgeSessionReader(
 *     process.env.SESSION_SECRET,
 *     'weblogin-auth-session'
 *   );
 *
 *   const isAuth = await reader.isAuthenticated(request);
 *   if (!isAuth) {
 *     return new Response('Unauthorized', { status: 401 });
 *   }
 *
 *   const user = await reader.getUser(request);
 *   return new Response(`Hello ${user?.name}!`);
 * }
 * ```
 *
 * @remarks
 * Only supports reading/decrypting sessions - not creating or updating them
 */
export class EdgeSessionReader {
  private readonly secret: string;
  private readonly cookieName: string;
  private readonly logger: EdgeLogger;

  /**
   * Create a new edge session reader
   *
   * @param secret - Session secret for decrypting cookies (must be 32+ characters)
   * @param cookieName - Name of the session cookie (defaults to 'weblogin-auth-session')
   * @param logger - Optional logger for debugging (defaults to silent logger)
   *
   * @throws {Error} If session secret is less than 32 characters
   *
   * @example
   * ```typescript
   * // Basic usage
   * const reader = new EdgeSessionReader(
   *   process.env.SESSION_SECRET!,
 *   'my-session-cookie'
   * );
   *
   * // With verbose logging
   * const reader = new EdgeSessionReader(
   *   process.env.SESSION_SECRET!,
   *   'my-session-cookie',
   *   new EdgeConsoleLogger(true)
   * );
   * ```
   */
  constructor(
    secret: string,
    cookieName: string = 'weblogin-auth-session',
    logger?: EdgeLogger
  ) {
    this.secret = secret;
    this.cookieName = cookieName;
    this.logger = logger || new EdgeConsoleLogger();

    if (this.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }
  }

  /**
   * Get session from cookie header string
   *
   * @param cookieHeader - HTTP Cookie header value
   * @returns Promise resolving to session data or null if invalid/missing
   *
   * @example
   * ```typescript
   * const cookieHeader = 'session=encrypted-value; other=value';
   * const session = await reader.getSessionFromCookieHeader(cookieHeader);
   * ```
   */
  async getSessionFromCookieHeader(cookieHeader?: string | null): Promise<Session | null> {
    if (!cookieHeader) {
      return null;
    }

    const parser = new EdgeCookieParser(cookieHeader);
    const cookieValue = parser.get(this.cookieName);

    if (!cookieValue) {
      return null;
    }

    return this.decryptSession(cookieValue);
  }

  /**
   * Get session from Request object
   *
   * @param request - Web API Request object
   * @returns Promise resolving to session data or null if invalid/missing
   *
   * @example
   * ```typescript
   * // In edge function
   * export default async function(request: Request) {
   *   const session = await reader.getSessionFromRequest(request);
   *   if (session) {
   *     console.log('Authenticated user:', session.user.id);
   *   }
   * }
   * ```
   */
  async getSessionFromRequest(request: Request): Promise<Session | null> {
    const cookieHeader = request.headers.get('cookie');
    return this.getSessionFromCookieHeader(cookieHeader);
  }

  /**
   * Check if session exists and is valid
   *
   * @param request - Web API Request object
   * @returns Promise resolving to true if user is authenticated
   *
   * @example
   * ```typescript
   * // Guard clause for protected routes
   * if (!(await reader.isAuthenticated(request))) {
   *   return new Response('Unauthorized', { status: 401 });
   * }
   * ```
   */
  async isAuthenticated(request: Request): Promise<boolean> {
    const session = await this.getSessionFromRequest(request);
    return this.isValidSession(session);
  }

  /**
   * Get user from session
   *
   * @param request - Web API Request object
   * @returns Promise resolving to user data or null if not authenticated
   *
   * @example
   * ```typescript
   * const user = await reader.getUser(request);
   * if (user) {
   *   console.log(`Welcome ${user.name}!`);
   * }
   * ```
   */
  async getUser(request: Request): Promise<User | null> {
    const session = await this.getSessionFromRequest(request);
    return session?.user || null;
  }

  /**
   * Get user ID from session
   *
   * Convenience method for extracting just the user ID.
   *
   * @param request - Web API Request object
   * @returns Promise resolving to user ID string or null if not authenticated
   *
   * @example
   * ```typescript
   * const userId = await reader.getUserId(request);
   * if (userId) {
   *   // Fetch user-specific data
   *   const userData = await fetchUserData(userId);
   * }
   * ```
   */
  async getUserId(request: Request): Promise<string | null> {
    const session = await this.getSessionFromRequest(request);
    return session?.user?.id || null;
  }

  /**
   * Validate session data
   *
   * Checks if session exists, has a valid user, and hasn't expired.
   *
   * @param session - Session data to validate
   * @returns true if session is valid and not expired
   * @private
   */
  private isValidSession(session: Session | null): boolean {
    if (!session) return false;
    if (!session.user?.id) return false;

    // Check expiration
    if (session.expiresAt && session.expiresAt > 0 && Date.now() > session.expiresAt) {
      this.logger.debug('Session expired', { expiresAt: session.expiresAt });
      return false;
    }

    return true;
  }

  /**
   * Decrypt iron-session cookie value using iron-session's unsealData
   *
   * @param cookieValue - Encrypted cookie value
   * @returns Promise resolving to decrypted session data or null if invalid
   */
  async decryptSession(cookieValue: string): Promise<Session | null> {
    try {
      // Use iron-session's unsealData function directly
      const sessionData = await unsealData<Session>(cookieValue, {
        password: this.secret,
      });

      // Validate session
      if (!this.isValidSession(sessionData)) {
        return null;
      }

      return sessionData;
    } catch (error) {
      this.logger.debug('Failed to decrypt session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }
}

/**
 * Safely get environment variable in edge environments
 *
 * Different edge environments expose environment variables differently.
 * This function tries multiple approaches to access them.
 *
 * @param key - Environment variable name
 * @returns Environment variable value or undefined
 * @private
 */
function getEdgeEnv(key: string): string | undefined {
  try {
    // Try different ways to access environment variables in edge environments
    if (typeof process !== 'undefined' && process.env) {
      return process.env[key];
    }
    // In some edge environments like Deno
    const globalEnv = globalThis as { Deno?: { env: { get: (key: string) => string | undefined } } };
    if (globalEnv.Deno?.env) {
      return globalEnv.Deno.env.get(key);
    }
    // In Cloudflare Workers, env variables are passed to fetch handler
    // This will be undefined here, but that's handled by the caller
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Factory function to create edge session reader with environment variables
 *
 * Creates an EdgeSessionReader using environment variables as defaults.
 * Throws helpful errors if required configuration is missing.
 *
 * @param secret - Session secret (optional, uses WEBLOGIN_AUTH_SESSION_SECRET env var)
 * @param cookieName - Cookie name (optional, uses WEBLOGIN_AUTH_SESSION_NAME env var)
 * @param logger - Optional logger instance
 * @returns Configured EdgeSessionReader instance
 *
 * @throws {Error} If session secret is not provided and not found in environment
 *
 * @example
 * ```typescript
 * // Uses environment variables
 * const reader = createEdgeSessionReader();
 *
 * // With custom values
 * const reader = createEdgeSessionReader(
 *   'my-secret-key-32-chars-minimum!!',
 *   'my-session-cookie'
 * );
 * ```
 */
export function createEdgeSessionReader(
  secret?: string,
  cookieName?: string,
  logger?: EdgeLogger
): EdgeSessionReader {
  const sessionSecret = secret || getEdgeEnv('WEBLOGIN_AUTH_SESSION_SECRET');
  const sessionName = cookieName || getEdgeEnv('WEBLOGIN_AUTH_SESSION_NAME') || 'weblogin-auth-session';

  if (!sessionSecret) {
    throw new Error('Session secret is required. Provide it as parameter or set WEBLOGIN_AUTH_SESSION_SECRET environment variable.');
  }

  return new EdgeSessionReader(sessionSecret, sessionName, logger);
}

/**
 * Convenience function to get user ID from request in edge functions
 *
 * High-level utility that combines session reader creation and user ID extraction.
 *
 * @param request - Web API Request object
 * @param secret - Session secret (optional, uses env var)
 * @param cookieName - Cookie name (optional, uses env var)
 * @returns Promise resolving to user ID or null if not authenticated
 *
 * @example
 * ```typescript
 * // In edge function
 * export default async function(request: Request) {
 *   const userId = await getUserIdFromRequest(request);
 *   if (!userId) {
 *     return new Response('Unauthorized', { status: 401 });
 *   }
 *
 *   return new Response(`Hello user ${userId}!`);
 * }
 * ```
 */
export async function getUserIdFromRequest(
  request: Request,
  secret?: string,
  cookieName?: string
): Promise<string | null> {
  const reader = createEdgeSessionReader(secret, cookieName);
  return reader.getUserId(request);
}

/**
 * Lightweight user ID extraction that reuses iron-session
 *
 * Direct cookie decryption without creating a full EdgeSessionReader instance.
 * Useful for one-off session checks.
 *
 * @param cookieValue - Encrypted session cookie value
 * @param secret - Session secret for decryption
 * @returns Promise resolving to user ID or null if invalid/missing
 *
 * @example
 * ```typescript
 * const cookies = parseCookies(request.headers.get('cookie'));
 * const sessionCookie = cookies['weblogin-auth-session'];
 *
 * if (sessionCookie) {
 *   const userId = await getUserIdFromCookie(sessionCookie, secret);
 *   console.log('User ID:', userId);
 * }
 * ```
 */
export async function getUserIdFromCookie(
  cookieValue: string,
  secret: string
): Promise<string | null> {
  try {
    // Use iron-session for full decryption
    const sessionData = await unsealData<Session>(cookieValue, { password: secret });
    return sessionData?.user?.id || null;
  } catch {
    return null;
  }
}
