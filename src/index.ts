/**
 * WebLogin Auth SDK - Framework-agnostic SAML authentication for Stanford WebLogin
 *
 * A comprehensive TypeScript library for SAML 2.0 authentication with Stanford WebLogin.
 * Designed for serverless environments with cookie-only sessions using iron-session.
 *
 * @packageDocumentation
 * @version 3.0.0
 * @author Stanford University Web Services
 * @license ISC
 */

// Export all type definitions
export * from './types.js';

// Export core authentication classes
export * from './saml.js';
export * from './session.js';
export * from './edge-session.js';
export * from './logger.js';
export * from './utils.js';

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
