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

import { getIronSession } from 'iron-session';
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
   *     name: 'weblogin-auth',
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
      name: config.name || 'weblogin-auth',
      secret: config.secret,
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax' as const,
        path: '/',
        maxAge: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN
          ? parseInt(process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN, 10)
          : undefined, // Default to browser-session cookie (no Max-Age = expires when browser closes)
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
    this.logger.debug('Starting session creation', {
      userId: user.id,
      userEmail: user.email,
      hasMeta: !!meta,
      metaKeys: meta ? Object.keys(meta) : []
    });

    const now = Date.now();
    const sessionData: Session = {
      user,
      meta,
      issuedAt: now,
      expiresAt: 0, // Session expires when browser closes
    };

    this.logger.debug('Session data prepared', {
      userId: user.id,
      issuedAt: sessionData.issuedAt,
      expiresAt: sessionData.expiresAt,
      userFields: Object.keys(user)
    });

    try {
      const mainCookieName = this.config.name;
      const jsCookieName = `${this.config.name}-session`;

      this.logger.debug('Cookie names configured', {
        mainCookieName,
        jsCookieName
      });

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      this.logger.debug('Creating iron-session', {
        cookieName: mainCookieName,
        cookieOptions: {
          httpOnly: this.config.cookie.httpOnly,
          secure: this.config.cookie.secure,
          sameSite: this.config.cookie.sameSite,
          path: this.config.cookie.path,
          domain: this.config.cookie.domain,
          maxAge: this.config.cookie.maxAge
        }
      });

      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: mainCookieName,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      this.logger.debug('Iron-session instance created, assigning session data');

      // Set session data
      Object.assign(session, sessionData);

      this.logger.debug('Saving encrypted session to cookie');
      await session.save();
      this.logger.debug('Session saved successfully');

      // Create JavaScript-accessible session boolean cookie
      this.logger.debug('Creating JS-accessible session indicator cookie', {
        jsCookieName,
        httpOnly: false
      });

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
      const cookieSize = cookieValue.length;

      this.logger.debug('Session cookie created', {
        mainCookieName,
        cookieSize,
        threshold: this.config.cookieSizeThreshold
      });

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
        errorStack: error instanceof Error ? error.stack : undefined,
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

  /**
   * Create a sealed (encrypted) cookie value
   *
   * This static utility function creates an encrypted cookie value containing session data
   * without setting any HTTP headers. This is useful for testing scenarios where you need
   * the actual encrypted cookie string to simulate authenticated requests or for when
   * you want to manually set the cookie in a different context.
   *
   * The returned string is what would normally be stored in the HTTP cookie, encrypted
   * using iron-session's encryption algorithm.
   *
   * @param sessionData - The session data to encrypt
   * @param config - Session configuration with name, secret, and cookie options
   * @returns Promise resolving to the encrypted cookie value string
   *
   * @example
   * ```typescript
   * // Create test session data
   * const sessionData: Session = {
   *   user: { id: 'user123', email: 'test@stanford.edu' },
   *   meta: { role: 'admin' },
   *   issuedAt: Date.now(),
   *   expiresAt: 0
   * };
   *
   * // Generate encrypted cookie value for testing
   * const sealedCookie = await SessionManager.sealSession(sessionData, {
   *   name: 'test-session',
   *   secret: 'your-32-character-secret-key!!'
   * });
   *
   * // Use in test requests
   * const response = await fetch('/api/protected', {
   *   headers: {
   *     'Cookie': `test-session=${sealedCookie}`
   *   }
   * });
   * ```
   *
   * @throws {Error} If session secret is less than 32 characters or encryption fails
   */
  static async sealSession(sessionData: Session, config: SessionConfig): Promise<string> {
    // Validate secret length
    if (config.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }

    // Create a mock cookie store that captures the set cookie value
    let sealedValue = '';
    const mockCookieStore: CookieStore = {
      get: () => undefined,
      set: (name: string, value: string) => {
        if (name === config.name) {
          sealedValue = value;
        }
      }
    };

    try {
      // Create temporary iron-session store
      const ironStore = {
        get: mockCookieStore.get,
        set: mockCookieStore.set,
      };

      const sessionConfig = {
        name: config.name,
        secret: config.secret,
        cookie: {
          httpOnly: true,
          secure: true,
          sameSite: 'lax' as const,
          path: '/',
          maxAge: 0,
          ...config.cookie,
        }
      };

      // Get iron session and save the data
      const session = await getIronSession<Session>(
        ironStore as unknown as IronCookieStore,
        {
          cookieName: sessionConfig.name || 'weblogin-auth',
          password: sessionConfig.secret,
          cookieOptions: sessionConfig.cookie,
        }
      );

      // Set session data
      Object.assign(session, sessionData);
      await session.save();

      if (!sealedValue) {
        throw new Error('Failed to generate sealed cookie value');
      }

      return sealedValue;
    } catch (error) {
      throw new Error(`Failed to seal session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

/**
 * Create a cookie store adapter for Express.js
 *
 * Adapts Express.js request/response cookie handling to the CookieStore interface.
 *
 * @param req - Express.js request object with cookies property
 * @param res - Express.js response object with cookie methods
 * @returns CookieStore implementation for Express.js
 *
 * @example
 * ```typescript
 * // In Express.js route handler
 * app.post('/login', async (req, res) => {
 *   const cookieStore = createExpressCookieStore(req, res);
 *   const sessionManager = new SessionManager(cookieStore, config);
 *
 *   await sessionManager.createSession(user);
 *   res.redirect('/dashboard');
 * });
 * ```
 */
export function createExpressCookieStore(req: unknown, res: unknown): CookieStore {
  const request = req as { cookies?: Record<string, string> };
  const response = res as { cookie: (name: string, value: string, options?: CookieOptions) => void; clearCookie: (name: string) => void };

  return {
    get: (name: string) => {
      const value = request.cookies?.[name];
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      response.cookie(name, value, options);
    },
    delete: (name: string) => {
      response.clearCookie(name);
    },
  };
}

/**
 * Create a cookie store adapter for Web API Request/Response
 *
 * Adapts Web API Request/Response objects to the CookieStore interface.
 * Suitable for use in serverless functions, Cloudflare Workers, etc.
 *
 * @param request - Web API Request object
 * @param response - Web API Response object (mutable)
 * @returns CookieStore implementation for Web API
 *
 * @example
 * ```typescript
 * // In API route handler
 * export async function POST(request: Request) {
 *   const response = new Response();
 *   const cookieStore = createWebCookieStore(request, response);
 *   const sessionManager = new SessionManager(cookieStore, config);
 *
 *   await sessionManager.createSession(user);
 *   return Response.redirect('/dashboard', {
 *     headers: response.headers
 *   });
 * }
 * ```
 */
export function createWebCookieStore(request: Request, response: Response): CookieStore {
  const cookies = new Map<string, string>();

  // Parse existing cookies from request
  const cookieHeader = request.headers.get('cookie');
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies.set(name, decodeURIComponent(value));
      }
    });
  }

  return {
    get: (name: string) => {
      const value = cookies.get(name);
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      cookies.set(name, value);

      // Build cookie string
      let cookieString = `${name}=${encodeURIComponent(value)}`;

      if (options) {
        if (options.httpOnly) cookieString += '; HttpOnly';
        if (options.secure) cookieString += '; Secure';
        if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
        if (options.path) cookieString += `; Path=${options.path}`;
        if (options.domain) cookieString += `; Domain=${options.domain}`;
        if (options.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
        if (options.expires) cookieString += `; Expires=${options.expires.toUTCString()}`;
      }

      // Set cookie header on response
      const existingCookies = response.headers.get('set-cookie') || '';
      const newCookies = existingCookies ? `${existingCookies}, ${cookieString}` : cookieString;
      response.headers.set('set-cookie', newCookies);
    },
  };
}

/**
 * Client-side utility to check if user is authenticated
 *
 * Reads the JavaScript-accessible session cookie to determine authentication status.
 * This provides a way to check authentication from client-side code without
 * making server requests.
 *
 * The function looks for a boolean cookie created by SessionManager that indicates
 * whether a valid session exists.
 *
 * @param sessionName - The base session name (without -session suffix)
 * @returns boolean indicating if the user is authenticated
 *
 * @example
 * ```typescript
 * // In React component or client-side code
 * import { isAuthenticated } from 'weblogin-auth-sdk';
 *
 * function MyComponent() {
 *   const isLoggedIn = isAuthenticated('weblogin-auth');
 *
 *   return (
 *     <div>
 *       {isLoggedIn ? (
 *         <p>Welcome back!</p>
 *       ) : (
 *         <a href="/login">Please log in</a>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @remarks
 * - This function only works in browser environments
 * - Returns false in server-side environments
 * - The cookie is set automatically by SessionManager.createSession()
 * - This is a lightweight check - full session validation requires server-side code
 */
export function isAuthenticated(sessionName: string): boolean {
  if (typeof document === 'undefined') {
    // Not in browser environment
    return false;
  }

  const jsCookieName = `${sessionName}-session`;
  const cookies = document.cookie.split(';');

  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === jsCookieName && value === 'true') {
      return true;
    }
  }

  return false;
}