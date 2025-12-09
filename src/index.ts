/**
 * WebLogin Auth SDK - Framework-agnostic SAML authentication for Stanford WebLogin
 *
 * A comprehensive TypeScript library for SAML 2.0 authentication with Stanford WebLogin.
 * Designed for serverless environments with cookie-only sessions using iron-session.
 *
 * @packageDocumentation
 * @version 3.0.0
 * @author Stanford University Web Services
 * @license MIT
 *
 * @example
 * ```typescript
 * // Next.js App Router usage
 * import { createWebloginNext } from '@stanford-uat/weblogin-auth-sdk';
 *
 * const auth = createWebloginNext({
 *   saml: {
 *     issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
 *     idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT!,
 *     returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!
 *   },
 *   session: {
 *     name: 'weblogin-auth',
 *     secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!
 *   }
 * });
 * ```
 *
 * @example
 * ```typescript
 * // Framework-agnostic usage with core classes
 * import { SAMLProvider, SessionManager, createWebCookieStore } from '@stanford-uat/weblogin-auth-sdk';
 *
 * const samlProvider = new SAMLProvider({ ... });
 * const sessionManager = new SessionManager(createWebCookieStore(req, res), { ... });
 * ```
 */

// Export all type definitions
export * from './types.js';

// Export core authentication classes
export * from './saml.js';
export * from './session.js';
export * from './edge-session.js';
export * from './logger.js';
export * from './utils.js';
export * from './idps.js';

/**
 * Next.js-specific integration classes and utilities
 *
 * NOTE: Next.js integration is now available as a separate import:
 * import { WebloginNext, createWebloginNext } from 'weblogin-auth-sdk/next'
 *
 * This prevents the core package from depending on Next.js and avoids
 * bundling issues in non-Next.js environments.
 */
// export { WebloginNext, createWebloginNext } from './next.js'; // Removed from default exports

/**
 * Re-export commonly used classes and functions for convenience
 * These are the primary building blocks for most authentication implementations
 */

/** SAML authentication provider for Stanford WebLogin */
export { SAMLProvider } from './saml.js';

/** Session management with cookie-based storage */
export { SessionManager } from './session.js';

/** Edge-compatible session reading for Netlify/Vercel functions */
export { EdgeSessionReader, EdgeCookieParser, createEdgeSessionReader, getUserIdFromRequest, getUserIdFromCookie } from './edge-session.js';

/** Structured logging implementations with security redaction */
export { DefaultLogger, ConsoleLogger, SilentLogger } from './logger.js';

/** Authentication utility functions and helpers */
export { AuthUtils } from './utils.js';
