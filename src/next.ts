/**
 * Next.js App Router integration for WebLogin Auth SDK
 *
 * This module provides simplified authentication methods specifically designed
 * for Next.js App Router applications. It wraps the core SAML and Session
 * functionality with Next.js-specific conveniences.
 *
 * Features:
 * - App Router compatible (uses next/headers cookies)
 * - Server Components and Server Actions support
 * - Route protection middleware
 * - Automatic session management
 * - TypeScript-first API design
 * - Environment validation
 *
 * @module next
 */

import { cookies } from 'next/headers';
import { SAMLProvider } from './saml.js';
import { SessionManager, CookieStore, CookieOptions } from './session.js';
import {
  SessionConfig,
  User,
  Session,
  LoginOptions,
  AuthCallbacks,
  Logger,
  WebLoginNextConfig,
} from './types.js';
import { DefaultLogger } from './logger.js';

/**
 * Create a cookie store adapter for Next.js
 *
 * Adapts the Next.js cookies() API to the generic CookieStore interface.
 * This allows the SessionManager to work with Next.js App Router cookies.
 *
 * @param cookies - Next.js cookies object from next/headers
 * @returns CookieStore implementation compatible with Next.js
 */
export function createNextjsCookieStore(cookies: unknown): CookieStore {
  const cookiesObj = cookies as { get: (name: string) => { name: string; value: string } | undefined; set: (name: string, value: string, options?: CookieOptions) => void };

  return {
    get: (name: string) => cookiesObj.get(name),
    set: (name: string, value: string, options?: CookieOptions) => {
      cookiesObj.set(name, value, options);
    },
    delete: (name: string) => {
      cookiesObj.set(name, '', { maxAge: 0 });
    },
  };
}

/**
 * Get session from Next.js Request object (for edge functions)
 *
 * Utility function for reading sessions in Next.js edge functions
 * where the full SessionManager might not be available.
 *
 * @param request - Next.js Request object
 * @param secret - Session secret (optional, uses env var)
 * @param cookieName - Session cookie name (optional, uses env var)
 * @returns Promise resolving to session data or null
 */
export async function getSessionFromNextRequest(
  request: Request,
  secret?: string,
  cookieName?: string
): Promise<Session | null> {
  const { createEdgeSessionReader } = await import('./edge-session.js');
  const reader = createEdgeSessionReader(secret, cookieName);
  return reader.getSessionFromRequest(request);
}

/**
 * Get session from Next.js cookies object
 *
 * Utility function for reading sessions directly from Next.js cookies.
 * Useful in Server Components and Server Actions.
 *
 * @param cookies - Next.js cookies object (must have get method)
 * @param secret - Session secret (optional, uses env var)
 * @param cookieName - Session cookie name (optional, uses env var)
 * @returns Promise resolving to session data or null
 */
export async function getSessionFromNextCookies(
  cookies: { get?: (name: string) => { value: string } | undefined },
  secret?: string,
  cookieName?: string
): Promise<Session | null> {
  const sessionSecret = secret ||
    (typeof process !== 'undefined' ? process.env?.WEBLOGIN_AUTH_SESSION_SECRET : undefined);

  const sessionName = cookieName ||
    (typeof process !== 'undefined' ? process.env?.WEBLOGIN_AUTH_SESSION_NAME : undefined) ||
    'weblogin-auth-session';

  if (!sessionSecret) {
    throw new Error('Session secret is required. Provide it as parameter or set WEBLOGIN_AUTH_SESSION_SECRET environment variable.');
  }

  if (!cookies.get) {
    return null;
  }

  const cookie = cookies.get(sessionName);
  if (!cookie) {
    return null;
  }

  // Import and use EdgeSessionReader for decryption
  const { EdgeSessionReader } = await import('./edge-session.js');
  const reader = new EdgeSessionReader(sessionSecret, sessionName);

  // Use the public decryptSession method directly
  return reader.decryptSession(cookie.value);
}

/**
 * WebLoginNext class for Next.js integration
 *
 * High-level authentication class designed specifically for Next.js App Router.
 * Provides a simple API that handles SAML authentication, session management,
 * and route protection.
 */
export class WebLoginNext {
  private samlProvider: SAMLProvider;
  private sessionConfig: SessionConfig;
  private logger: Logger;
  private callbacks?: AuthCallbacks;

  /**
   * Create a new WebLoginNext instance
   *
   * Initializes SAML provider and configures session management for Next.js.
   * Merges provided configuration with sensible defaults.
   *
   * @param config - Authentication configuration (required and optional settings)
   */
  constructor(config: WebLoginNextConfig) {
    this.logger = config.logger || new DefaultLogger(config.verbose);
    this.callbacks = config.callbacks;

    // Merge required and optional SAML config
    const samlConfig = {
      ...config.saml,
    };

    // Merge required and optional session config
    this.sessionConfig = {
      ...config.session,
      ...(config.session && 'cookie' in config.session ? {} : {}), // Handle overlap
    };

    this.samlProvider = new SAMLProvider(samlConfig, this.logger);
  }

  /**
   * Check for browser environment and throw error if detected
   *
   * This method prevents accidental usage in browser environments where it would fail.
   *
   * @param methodName - Name of the method being called (for error message)
   * @throws {Error} If called in browser environment
   * @private
   */
  private assertServerEnvironment(methodName: string): void {
    if (typeof window !== 'undefined') {
      throw new Error(`WebLoginNext.${methodName}() should not be called in a browser environment`);
    }
  }

  /**
   * Get or create session manager with Next.js cookies
   *
   * Uses the directly imported Next.js cookies function to create a SessionManager.
   * Works with both Next.js 14 (sync) and Next.js 15+ (async) cookie APIs.
   *
   * @returns Promise resolving to configured SessionManager
   * @private
   */
  private async getSessionManager(): Promise<SessionManager> {
    this.logger.debug('Creating session manager with Next.js cookies');

    try {
      // Call cookies() and check if it returns a Promise (Next.js 15+) or direct value (Next.js 14)
      const cookiesCall = cookies();

      let cookieStore: unknown;
      if (typeof cookiesCall === 'object' && cookiesCall !== null && 'then' in cookiesCall && typeof (cookiesCall as { then: unknown }).then === 'function') {
        this.logger.debug('Detected Next.js 15+ async cookies() - awaiting result');
        cookieStore = await (cookiesCall as Promise<unknown>);
      } else {
        this.logger.debug('Detected Next.js 14 sync cookies() - using direct result');
        cookieStore = cookiesCall;
      }

      const webCookieStore = createNextjsCookieStore(cookieStore);
      const sessionManager = new SessionManager(webCookieStore, this.sessionConfig, this.logger);

      this.logger.debug('Session manager created successfully');
      return sessionManager;

    } catch (error) {
      this.logger.error('Failed to create Next.js session manager', {
        error: (error as Error).message,
        nodeEnv: process.env.NODE_ENV,
        platform: process.platform,
        nodeVersion: process.version,
        stack: (error as Error).stack
      });

      throw new Error(
        `Failed to access Next.js cookies: ${(error as Error).message}. Make sure this code is running in a Next.js App Router context.`
      );
    }
  }

  /**
   * Initiate SAML login
   *
   * Redirects user to IdP for authentication.
   *
   * @param options - Login options including returnTo URL
   * @returns Promise resolving to redirect Response to IdP login page
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    this.assertServerEnvironment('login');
    return this.samlProvider.login(options);
  }

  /**
   * Handle SAML authentication callback (ACS endpoint)
   *
   * Processes the SAML response from the IDP and creates a session.
   *
   * @param request - HTTP Request containing SAML response
   * @returns Promise resolving to authenticated user, session, and returnTo URL
   *
   * @throws {AuthError} If SAML authentication fails
   */
  async authenticate(request: Request): Promise<{
    user: User;
    session: Session;
    returnTo?: string;
  }> {
    this.assertServerEnvironment('authenticate');

    // Authenticate with SAML (let SAMLProvider handle its own error logging)
    const { user, returnTo } = await this.samlProvider.authenticate({
      req: request,
      callbacks: this.callbacks,
    });

    // Create session (let SessionManager handle its own error logging)
    const sessionManager = await this.getSessionManager();
    const session = await sessionManager.createSession(user);

    // Call session callback if provided
    if (this.callbacks?.session) {
      await this.callbacks.session({ session, user, req: request });
    }

    return { user, session, returnTo };
  }

  /**
   * Get current session
   *
   * @param request - Optional Request object for API routes and middleware
   * @returns Promise resolving to current session or null if not authenticated
   */
  async getSession(request?: Request): Promise<Session | null> {
    this.assertServerEnvironment('getSession');

    if (request) {
      // For API routes, middleware, etc. - use the provided Request object
      return getSessionFromNextRequest(request, this.sessionConfig.secret, this.sessionConfig.name);
    } else {
      // For Server Components, Server Actions - use Next.js cookies()
      const sessionManager = await this.getSessionManager();
      return sessionManager.getSession();
    }
  }

  /**
   * Get current user
   *
   * @param request - Optional Request object for API routes and middleware
   * @returns Promise resolving to current user or null if not authenticated
   */
  async getUser(request?: Request): Promise<User | null> {
    if (request) {
      const session = await this.getSession(request);
      return session?.user || null;
    }

    const sessionManager = await this.getSessionManager();
    return sessionManager.getUser();
  }

  /**
   * Get login URL
   *
   * Generates the SAML login URL without redirecting.
   *
   * @param options - Login options
   * @returns Promise resolving to login URL
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    this.assertServerEnvironment('getLoginUrl');
    return this.samlProvider.getLoginUrl(options);
  }

  /**
   * Check if user is authenticated
   *
   * @param request - Optional Request object for API routes and middleware
   * @returns Promise resolving to true if authenticated, false otherwise
   */
  async isAuthenticated(request?: Request): Promise<boolean> {
    if (request) {
      const session = await this.getSession(request);
      return !!session;
    }

    const sessionManager = await this.getSessionManager();
    return sessionManager.isAuthenticated();
  }

  /**
   * Logout user
   *
   * Destroys the current session.
   */
  async logout(): Promise<void> {
    this.assertServerEnvironment('logout');
    const sessionManager = await this.getSessionManager();
    const session = await sessionManager.getSession();

    if (session && this.callbacks?.signOut) {
      await this.callbacks.signOut({ session });
    }

    await sessionManager.destroySession();
  }

  /**
   * Refresh current session
   *
   * Updates the session timestamp to extend its validity.
   *
   * @returns Promise resolving to refreshed session or null if not authenticated
   */
  async refreshSession(): Promise<Session | null> {
    this.assertServerEnvironment('refreshSession');
    const sessionManager = await this.getSessionManager();
    return sessionManager.refreshSession();
  }

  /**
   * Update session metadata
   *
   * Updates the session metadata and saves it.
   *
   * @param updates - Partial session object with updates
   * @returns Promise resolving to updated session or null if not authenticated
   */
  async updateSession(updates: Partial<Session>): Promise<Session | null> {
    this.assertServerEnvironment('updateSession');
    const sessionManager = await this.getSessionManager();
    const updatedSession = await sessionManager.updateSession(updates);

    if (updatedSession && this.callbacks?.session) {
      // Create a dummy request for the callback since we don't have access to the real one
      // in Server Components/Actions context where this is typically called
      const dummyReq = new Request('http://localhost');
      await this.callbacks.session({ session: updatedSession, user: updatedSession.user, req: dummyReq });
    }
    return updatedSession;
  }

  /**
   * Authentication middleware
   *
   * Wraps a Next.js route handler to provide authentication context.
   *
   * @param handler - Route handler function
   * @returns Wrapped handler function
   */
  auth(handler: (req: Request, ctx: Record<string, unknown>) => Promise<Response>) {
    return async (req: Request, ctx: Record<string, unknown>) => {
      const session = await this.getSession(req);
      const user = session?.user || null;
      const isAuthenticated = !!session;

      // Inject auth context into the handler context
      const authContext = {
        ...ctx,
        session,
        user,
        isAuthenticated
      };

      return handler(req, authContext);
    };
  }
}

/**
 * Factory function to create WebLoginNext instance
 *
 * @param config - Authentication configuration
 * @returns Configured WebLoginNext instance
 */
export function createWebLoginNext(config: WebLoginNextConfig): WebLoginNext {
  return new WebLoginNext(config);
}
