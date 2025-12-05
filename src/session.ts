/**
 * Session management with cookie-based storage using iron-session
 *
 * This module provides framework-agnostic session management using encrypted cookies.
 * Features include:
 *
 * - Cookie-only sessions (no server-side storage required)
 * - iron-session encryption for secure cookie storage
 * - Framework adapters for Express.js and Web API
 * - Configurable cookie security settings
 * - Session size monitoring and warnings
 * - Client-side authentication status checking
 *
 * The session data is encrypted using iron-session and stored entirely in HTTP cookies,
 * making it suitable for serverless and stateless environments.
 *
 * @module session
 */

import { getIronSession, sealData } from 'iron-session';
import { Session, SessionConfig, User, Logger } from './types.js';
import { AuthUtils } from './utils.js';
import { DefaultLogger } from './logger.js';
import { IronCookieStore } from './types.js';

/**
 * Cookie store interface for framework agnostic cookie operations
 *
 * Provides an abstraction layer over different framework cookie APIs.
 * Implementations should handle the specific cookie setting/getting for their framework.
 *
 * @example
 * ```typescript
 * // Express.js implementation
 * const store: CookieStore = {
 *   get: (name) => req.cookies[name] ? { name, value: req.cookies[name] } : undefined,
 *   set: (name, value, options) => res.cookie(name, value, options),
 *   delete: (name) => res.clearCookie(name)
 * };
 * ```
 */
export interface CookieStore {
  /**
   * Retrieve a cookie by name
   * @param name - Cookie name to retrieve
   * @returns Cookie object with name and value, or undefined if not found
   */
  get: (name: string) => { name: string; value: string } | undefined;

  /**
   * Set a cookie with optional configuration
   * @param name - Cookie name to set
   * @param value - Cookie value
   * @param options - Optional cookie configuration (security, expiration, etc.)
   */
  set: (name: string, value: string, options?: CookieOptions) => void;

  /**
   * Delete a cookie by name (optional)
   * @param name - Cookie name to delete
   */
  delete?: (name: string) => void;
}

/**
 * Cookie options interface
 *
 * Defines security and behavior options for HTTP cookies.
 * These options control cookie security, scope, and lifetime.
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies | MDN Cookie Documentation}
 */
export interface CookieOptions {
  /** Prevent client-side JavaScript access to cookie (recommended: true) */
  httpOnly?: boolean;
  /** Only send cookie over HTTPS connections (recommended: true in production) */
  secure?: boolean;
  /** Control when cookies are sent with cross-site requests */
  sameSite?: 'lax' | 'strict' | 'none';
  /** URL path where cookie is valid */
  path?: string;
  /** Domain where cookie is valid */
  domain?: string;
  /** Cookie lifetime in seconds from now */
  maxAge?: number;
  /** Absolute expiration date */
  expires?: Date;
}

/**
 * Session manager class for handling authentication sessions
 *
 * Provides encrypted cookie-based session management using iron-session.
 * Features include:
 *
 * - Automatic session encryption/decryption
 * - Session expiration handling
 * - Cookie size monitoring
 * - Dual-cookie strategy (encrypted + JavaScript-readable)
 * - Framework-agnostic design
 *
 * The dual-cookie approach creates two cookies:
 * 1. Main encrypted cookie (HttpOnly) - contains session data
 * 2. Boolean cookie (JavaScript accessible) - for client-side auth checks
 *
 * @example
 * ```typescript
 * // Create session manager
 * const sessionManager = new SessionManager(
 *   cookieStore,
 *   {
 *     name: 'my-session',
 *     secret: 'your-32-character-secret-key!!'
 *   }
 * );
 *
 * // Create session
 * await sessionManager.createSession(user);
 *
 * // Check authentication
 * const isAuth = await sessionManager.isAuthenticated();
 * ```
 */
export class SessionManager {
  private config: Required<SessionConfig>;
  private logger: Logger;

  /**
   * Create a new session manager
   *
   * @param cookieStore - Framework-specific cookie store implementation
   * @param config - Session configuration with security settings
   * @param logger - Optional logger instance (defaults to DefaultLogger)
   *
   * @throws {Error} If session secret is less than 32 characters
   *
   * @example
   * ```typescript
   * const sessionManager = new SessionManager(
   *   createWebCookieStore(request, response),
   *   {
   *     name: 'adapt-auth-session',
   *     secret: process.env.SESSION_SECRET,
   *     cookie: {
   *       secure: true,
   *       sameSite: 'lax'
   *     }
   *   }
   * );
   * ```
   */
  constructor(
    private cookieStore: CookieStore,
    config: SessionConfig,
    logger?: Logger
  ) {
    this.config = {
      name: config.name,
      secret: config.secret,
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax' as const,
        path: '/',
        maxAge: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN
          ? parseInt(process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN, 10)
          : 0, // Default to browser-session cookie
        ...config.cookie,
      },
      cookieSizeThreshold: config.cookieSizeThreshold || 3500,
    };

    this.logger = logger || new DefaultLogger();

    // Validate secret length
    if (this.config.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }
  }

  /**
   * Static method to seal session data into an encrypted cookie value
   *
   * Useful for testing or manual cookie creation.
   *
   * @param session - Session data to seal
   * @param config - Session configuration
   * @returns Promise resolving to encrypted cookie string
   */
  static async sealSession(session: Session, config: SessionConfig): Promise<string> {
    if (!config.secret || config.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }

    return sealData(session, {
      password: config.secret,
      ttl: config.cookie?.maxAge || 0,
    });
  }

  /**
   * Get session data from cookie
   *
   * Decrypts and retrieves session data from the encrypted cookie.
   * Automatically handles session expiration checking.
   *
   * @returns Promise resolving to session data, or null if no valid session
   *
   * @example
   * ```typescript
   * const session = await sessionManager.getSession();
   * if (session) {
   *   console.log('User:', session.user);
   *   console.log('Metadata:', session.meta);
   * }
   * ```
   */
  async getSession(): Promise<Session | null> {
    try {
      const sessionCookie = this.cookieStore.get(this.config.name);
      if (!sessionCookie) {
        return null;
      }

      // Create a temporary iron-session compatible store
      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      // Cast our simple CookieStore adapter to the shape expected by
      // `getIronSession`. Using `as unknown as IronCookieStore
      // avoids the overly-broad `as never` assertion while keeping runtime
      // behavior unchanged.
      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: this.config.name,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      // Check if session is expired
      if (session.expiresAt && Date.now() > session.expiresAt) {
        this.logger.debug('Session expired', { expiresAt: session.expiresAt });
        await this.destroySession();
        return null;
      }

      return session;
    } catch (error) {
      this.logger.error('Failed to get session', { error: error instanceof Error ? error.message : 'Unknown error' });
      return null;
    }
  }

  /**
   * Create a new session
   *
   * Encrypts user data and metadata into a secure cookie.
   * Creates both the main encrypted cookie and a JavaScript-accessible boolean cookie.
   *
   * @param user - User data to store in session
   * @param meta - Optional metadata to include in session
   * @returns Promise resolving to the created session data
   *
   * @throws {Error} If session creation fails
   *
   * @example
   * ```typescript
   * const session = await sessionManager.createSession(
   *   { id: '123', email: 'user@stanford.edu' },
   *   { theme: 'dark', lastLogin: Date.now() }
   * );
   * ```
   */
  async createSession(user: User, meta?: Record<string, unknown>): Promise<Session> {
    const now = Date.now();
    const sessionData: Session = {
      user,
      meta,
      issuedAt: now,
      expiresAt: 0, // Session expires when browser closes
    };

    try {
      const mainCookieName = this.config.name;
      const jsCookieName = `${this.config.name}-session`;

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: mainCookieName,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      // Set session data
      Object.assign(session, sessionData);
      await session.save();

      // Create JavaScript-accessible session boolean cookie
      this.cookieStore.set(jsCookieName, 'true', {
        httpOnly: false, // JavaScript accessible
        secure: this.config.cookie.secure,
        sameSite: this.config.cookie.sameSite,
        path: this.config.cookie.path,
        domain: this.config.cookie.domain,
        maxAge: this.config.cookie.maxAge,
      });

      // Check cookie size
      const cookieValue = this.cookieStore.get(mainCookieName)?.value || '';
      AuthUtils.checkCookieSize(cookieValue, this.config.cookieSizeThreshold, this.logger);

      this.logger.info('Session created', {
        userId: user.id,
        issuedAt: sessionData.issuedAt,
        mainCookie: mainCookieName,
        jsCookie: jsCookieName
      });

      return sessionData;
    } catch (error) {
      this.logger.error('Failed to create session', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: user.id
      });
      throw error;
    }
  }

  /**
   * Update existing session
   *
   * Merges provided updates with existing session data.
   * Useful for adding metadata or updating user information.
   *
   * @param updates - Partial session data to merge
   * @returns Promise resolving to updated session, or null if no session exists
   *
   * @example
   * ```typescript
   * // Add metadata
   * await sessionManager.updateSession({
   *   meta: { lastPage: '/dashboard', preferences: {...} }
   * });
   * ```
   */
  async updateSession(updates: Partial<Session>): Promise<Session | null> {
    try {
      const currentSession = await this.getSession();
      if (!currentSession) {
        return null;
      }

      const updatedSession: Session = {
        ...currentSession,
        ...updates,
      };

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: this.config.name,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      Object.assign(session, updatedSession);
      await session.save();

      // Check cookie size
      const cookieValue = this.cookieStore.get(this.config.name)?.value || '';
      AuthUtils.checkCookieSize(cookieValue, this.config.cookieSizeThreshold, this.logger);

      this.logger.debug('Session updated', {
        userId: updatedSession.user.id
      });

      return updatedSession;
    } catch (error) {
      this.logger.error('Failed to update session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Destroy the session
   *
   * Removes both the encrypted session cookie and the JavaScript-accessible boolean cookie.
   *
   * @throws {Error} If session destruction fails
   *
   * @example
   * ```typescript
   * await sessionManager.destroySession();
   * // User is now logged out
   * ```
   */
  async destroySession(): Promise<void> {
    try {
      const mainCookieName = this.config.name;
      const jsCookieName = `${this.config.name}-session`;

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: mainCookieName,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      const userId = session.user?.id;
      session.destroy();

      // Also remove the JavaScript-accessible session boolean cookie
      if (this.cookieStore.delete) {
        this.cookieStore.delete(jsCookieName);
      }

      this.logger.info('Session destroyed', {
        userId,
        mainCookie: mainCookieName,
        jsCookie: jsCookieName
      });
    } catch (error) {
      this.logger.error('Failed to destroy session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Check if session exists and is valid
   *
   * @returns Promise resolving to true if user is authenticated
   *
   * @example
   * ```typescript
   * if (await sessionManager.isAuthenticated()) {
   *   // User is logged in
   * } else {
   *   // Redirect to login
   * }
   * ```
   */
  async isAuthenticated(): Promise<boolean> {
    const session = await this.getSession();
    return session !== null && !!session.user;
  }

  /**
   * Get user from session
   *
   * @returns Promise resolving to user data, or null if not authenticated
   *
   * @example
   * ```typescript
   * const user = await sessionManager.getUser();
   * if (user) {
   *   console.log(`Welcome ${user.name}!`);
   * }
   * ```
   */
  async getUser(): Promise<User | null> {
    const session = await this.getSession();
    return session?.user || null;
  }

  /**
   * Refresh session (sliding expiration)
   *
   * Updates the session's issued timestamp to extend its lifetime.
   * Useful for implementing sliding session expiration.
   *
   * @returns Promise resolving to refreshed session, or null if no session
   *
   * @example
   * ```typescript
   * // Refresh session on each request
   * await sessionManager.refreshSession();
   * ```
   */
  async refreshSession(): Promise<Session | null> {
    const session = await this.getSession();
    if (!session) {
      return null;
    }

    // Update issued timestamp for sliding sessions
    return await this.updateSession({
      issuedAt: Date.now(),
    });
  }
}

/**
 * Create a cookie store for Express.js
 *
 * Adapts Express request/response objects to the CookieStore interface.
 *
 * @param req - Express Request object
 * @param res - Express Response object
 * @returns CookieStore implementation for Express
 */
export function createExpressCookieStore(req: any, res: any): CookieStore {
  return {
    get: (name: string) => {
      const value = req.cookies?.[name];
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      res.cookie(name, value, options);
    },
    delete: (name: string) => {
      res.clearCookie(name);
    },
  };
}

/**
 * Create a cookie store for Web API (Request/Response)
 *
 * Adapts Web API Request/Response objects to the CookieStore interface.
 * Note: This implementation modifies the Response headers directly.
 *
 * @param request - Web API Request object
 * @param response - Web API Response object
 * @returns CookieStore implementation for Web API
 */
export function createWebCookieStore(request: Request, response: Response): CookieStore {
  return {
    get: (name: string) => {
      const cookieHeader = request.headers.get('cookie');
      if (!cookieHeader) return undefined;

      const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
        const [key, val] = cookie.trim().split('=');
        acc[key] = decodeURIComponent(val);
        return acc;
      }, {} as Record<string, string>);

      const value = cookies[name];
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      let cookieString = `${name}=${encodeURIComponent(value)}`;

      if (options?.httpOnly) cookieString += '; HttpOnly';
      if (options?.secure) cookieString += '; Secure';
      if (options?.sameSite) cookieString += `; SameSite=${options.sameSite}`;
      if (options?.path) cookieString += `; Path=${options.path}`;
      if (options?.domain) cookieString += `; Domain=${options.domain}`;
      if (options?.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
      if (options?.expires) cookieString += `; Expires=${options.expires.toUTCString()}`;

      response.headers.append('Set-Cookie', cookieString);
    },
    delete: (name: string) => {
      response.headers.append('Set-Cookie', `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
    }
  };
}

/**
 * Check if user is authenticated (Client-side utility)
 *
 * Checks for the existence of the JavaScript-accessible session boolean cookie.
 * This allows client-side code to know if a user is logged in without making a request.
 *
 * @param sessionName - Name of the session (default: 'weblogin-auth-session')
 * @returns True if session cookie exists and is 'true'
 */
export function isAuthenticated(sessionName: string = 'weblogin-auth-session'): boolean {
  if (typeof document === 'undefined') return false;

  const jsCookieName = `${sessionName}-session`;
  const cookies = document.cookie.split(';').reduce((acc, cookie) => {
    const [key, val] = cookie.trim().split('=');
    acc[key] = val;
    return acc;
  }, {} as Record<string, string>);

  return cookies[jsCookieName] === 'true';
}
