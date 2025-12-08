/**
 * User data structure for session storage
 */
export type User = {
  /**
   * Unique and stable identifier for the user.
   * This value is used as the primary identifier for authentication.
   * It must be unique across all users and should not change over time.
   */
  id: string;

  /**
   * Email address of the user (optional)
   */
  email?: string;

  /**
   * Full name of the user (optional)
   */
  name?: string;

  /**
   * Profile image URL of the user (optional)
   */
  imageUrl?: string;
  [key: string]: unknown; // Allow additional user properties
};

/**
 * Session data structure
 */
export type Session = {
  user: User;
  meta?: Record<string, unknown>; // developer-defined metadata
  issuedAt: number;
  expiresAt: number;
};

/**
 * RelayState payload structure
 */
export interface RelayStatePayload {
  return_to?: string;
}

/**
 * Structured logger interface
 */
export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Required SAML configuration (minimal fields developers must provide)
 */
export interface RequiredSamlConfig {
  /**
   * SAML entity/issuer identifier (required)
   */
  issuer: string;

  /**
   * IdP certificate for validating SAML responses (required)
   */
  idpCert: string | string[];

  /**
   * Base URL of your application where SAML responses are received (required)
   */
  returnToOrigin: string;
}

/**
 * Optional SAML configuration with sensible defaults
 */
export interface OptionalSamlConfig {
  /**
   * Path component for ACS (Assertion Consumer Service) URL
   * @default ''
   */
  returnToPath?: string;

  /**
   * Whether to include returnTo URL in RelayState for post-login redirects
   * @default true
   */
  includeReturnTo?: boolean;

  /**
   * Private key for SAML signing (if different from idpCert)
   * @default process.env.WEBLOGIN_AUTH_SAML_PRIVATE_KEY || idpCert
   */
  privateKey?: string;

  /**
   * Private key for SAML decryption
   * @default process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY
   */
  decryptionPvk?: string;

  /**
   * SAML audience (usually entity URL)
   * @default `https://${issuer}.stanford.edu`
   */
  audience?: string;

  /**
   * Require signed SAML assertions
   * @default true
   */
  wantAssertionsSigned?: boolean;

  /**
   * Require signed SAML responses
   * @default true
   */
  wantAuthnResponseSigned?: boolean;

  /**
   * Allowed clock skew in milliseconds for time-based validations
   * @default 60000 (1 minute)
   */
  acceptedClockSkewMs?: number;

  /**
   * SAML signature algorithm
   * @default 'sha256'
   */
  signatureAlgorithm?: string;

  /**
   * SAML identifier format
   * @default 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
   */
  identifierFormat?: string;

  /**
   * Allow creation of new accounts
   * @default false
   */
  allowCreate?: boolean;

  /**
   * Additional parameters for SAML requests
   * @default {}
   */
  additionalParams?: Record<string, unknown>;

  /**
   * Additional authorization parameters
   * @default {}
   */
  additionalAuthorizeParams?: Record<string, unknown>;

  /**
   * IDP Entry Point URL
   * @default 'https://idp.stanford.edu/idp/profile/SAML2/Redirect/SSO'
   */
  entryPoint?: string;
}

/**
 * Complete SAML configuration (combines required and optional)
 */
export type SamlConfig = RequiredSamlConfig & OptionalSamlConfig;

/**
 * Required session configuration (minimal fields developers must provide)
 */
export interface RequiredSessionConfig {
  /**
   * Session cookie name (required)
   */
  name: string;

  /**
   * Secret for encrypting session data - must be 32+ characters (required)
   */
  secret: string;
}

/**
 * Optional session configuration with sensible defaults
 */
export interface OptionalSessionConfig {
  /**
   * Cookie configuration options
   */
  cookie?: {
    /**
     * Prevent client-side JavaScript access to cookie
     * @default true
     */
    httpOnly?: boolean;

    /**
     * Only send cookie over HTTPS in production
     * @default true
     */
    secure?: boolean;

    /**
     * SameSite cookie attribute for CSRF protection
     * @default 'lax'
     */
    sameSite?: 'lax' | 'strict' | 'none';

    /**
     * Cookie path
     * @default '/'
     */
    path?: string;

    /**
     * Cookie domain (optional)
     */
    domain?: string;

    /**
     * Cookie max age in seconds (optional, default is session cookie)
     */
    maxAge?: number;
  };

  /**
   * Cookie size warning threshold in bytes
   * @default 3500
   */
  cookieSizeThreshold?: number;
}

/**
 * Complete session configuration (combines required and optional)
 */
export type SessionConfig = RequiredSessionConfig & OptionalSessionConfig;

// Types mirroring the cookie-store shape accepted by `iron-session`'s
// getIronSession(cookies, options) overload. We keep a minimal local
// representation here so other modules can safely cast their adapters.
// See: node_modules/iron-session/dist/index.d.ts for the authoritative
// declaration (CookieStore / ResponseCookie types).
export type IronCookieSet = {
  (name: string, value: string, cookie?: Partial<Record<string, unknown>>): void;
  (options: { name: string; value: string; httpOnly?: boolean; maxAge?: number; domain?: string; path?: string; sameSite?: 'lax' | 'strict' | 'none'; secure?: boolean; expires?: Date; priority?: string }): void;
};

export interface IronCookieStore {
  get: (name: string) => { name: string; value: string } | undefined;
  set: IronCookieSet;
}

/**
 * Required authentication configuration (minimal fields developers must provide)
 */
export interface RequiredAuthConfig {
  /**
   * SAML configuration - only required fields need to be provided
   */
  saml: RequiredSamlConfig;

  /**
   * Session configuration - only required fields need to be provided
   */
  session: RequiredSessionConfig;
}

/**
 * Optional authentication configuration with sensible defaults
 */
export interface OptionalAuthConfig {
  /**
   * Optional SAML configuration (will use sensible defaults)
   */
  saml?: OptionalSamlConfig;

  /**
   * Optional session configuration (will use sensible defaults)
   */
  session?: OptionalSessionConfig;

  /**
   * Custom logger implementation
   * @default DefaultLogger
   */
  logger?: Logger;

  /**
   * Enable verbose logging for debugging
   * @default false
   */
  verbose?: boolean;

  /**
   * Authentication event callbacks
   */
  callbacks?: AuthCallbacks;
}

/**
 * Complete authentication configuration (combines required and optional)
 */
export type AuthConfig = RequiredAuthConfig & OptionalAuthConfig;

/**
 * Callbacks for customizing authentication behavior
 */
export type AuthCallbacks = {
  /**
   * Called after successful SAML authentication to map SAML profile to User
   */
  mapProfile?: (profile: SAMLProfile) => Promise<User> | User;

  /**
   * Called when creating/updating session to enrich session data
   */
  session?: (params: {
    session: Session;
    user: User;
    req: Request;
  }) => Promise<Session> | Session;

  /**
   * Called on authentication events
   */
  signIn?: (params: { user: User; profile: SAMLProfile }) => Promise<void> | void;
  signOut?: (params: { session: Session }) => Promise<void> | void;
};

/**
 * Login options
 */
export type LoginOptions = {
  returnTo?: string;
  [key: string]: unknown;
};

/**
 * Authentication options for ACS
 */
export type AuthenticateOptions = {
  req: Request;
  callbacks?: AuthCallbacks;
};

/**
 * Logout options
 */
export type LogoutOptions = {
  slo?: boolean; // Single Logout
  redirectTo?: string;
};

/**
 * SAML Response structure from Stanford
 */
export type SAMLResponseAttributes = {
  firstName?: string;
  lastName?: string;
  'oracle:cloud:identity:sessionid': string;
  encodedSUID: string;
  suid?: string;
  'oracle:cloud:identity:url': string;
  userName: string;
  [key: string]: unknown;
};

/**
 * Extended SAML Profile with Stanford-specific attributes
 */
export type SAMLProfile = {
  inResponseTo?: string;
  issuer?: string;
  nameID?: string;
  nameIDFormat?: string;
  sessionIndex?: string;
  attributes?: SAMLResponseAttributes;
  [key: string]: unknown;
} & SAMLResponseAttributes;

/**
 * SAML Response result
 */
export type SAMLResponse = {
  profile?: SAMLProfile;
  loggedOut?: boolean;
};

/**
 * Error types
 */
export class AuthError extends Error {
  public code: string;
  public statusCode: number;

  constructor(message: string, code: string, statusCode = 500) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Context passed to route handlers
 */
export type AuthContext = {
  session?: Session;
  user?: User;
  isAuthenticated: boolean;
};

/**
 * Route handler type
 */
export type RouteHandler = (
  req: Request,
  context: AuthContext
) => Promise<Response> | Response;

/**
 * Required configuration for WebLoginNext (minimal fields developers must provide)
 */
export interface RequiredWebLoginNextConfig {
  /**
   * SAML configuration - only required fields need to be provided
   */
  saml: RequiredSamlConfig;

  /**
   * Session configuration - only required fields need to be provided
   */
  session: RequiredSessionConfig;
}

/**
 * Optional configuration for WebLoginNext with sensible defaults
 */
export interface OptionalWebLoginNextConfig {
  /**
   * Optional SAML configuration (will use sensible defaults)
   */
  saml?: OptionalSamlConfig;

  /**
   * Optional session configuration (will use sensible defaults)
   */
  session?: OptionalSessionConfig;

  /**
   * Custom logger implementation
   * @default DefaultLogger
   */
  logger?: Logger;

  /**
   * Enable verbose logging for debugging
   * @default false
   */
  verbose?: boolean;

  /**
   * Authentication event callbacks
   */
  callbacks?: AuthCallbacks;
}

/**
 * Complete configuration for WebLoginNext (combines required and optional)
 */
export type WebLoginNextConfig = RequiredWebLoginNextConfig & OptionalWebLoginNextConfig;
