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

  /**
   * Private key for SAML signing (required)
   * @default process.env.WEBLOGIN_AUTH_SAML_PRIVATE_KEY
   */
  privateKey: string;

  /**
   * Public certificate for SAML signing (PEM format) (required)
   * Used for generating Service Provider metadata
   * @default process.env.WEBLOGIN_AUTH_SAML_SP_CERT
   */
  cert: string;

  /**
   * Private key for SAML decryption (required)
   * Used to decrypt encrypted SAML assertions from the IdP
   * @default process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY
   */
  decryptionPvk: string;

  /**
   * Public certificate for SAML decryption (PEM format) (required)
   * Used for generating Service Provider metadata - share this with the IdP
   * @default process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_CERT
   */
  decryptionCert: string;
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
  signatureAlgorithm?: 'sha1' | 'sha256' | 'sha512';

  /**
   * SAML digest algorithm
   * @default 'sha1'
   */
  digestAlgorithm?: 'sha1' | 'sha256' | 'sha512';

  /**
   * XML Signature Transforms
   */
  xmlSignatureTransforms?: string[];

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
   * Service Provider Name Qualifier
   */
  spNameQualifier?: string;

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
   * Additional logout parameters
   */
  additionalLogoutParams?: Record<string, unknown>;

  /**
   * IDP Entry Point URL
   * @default 'https://idp.stanford.edu/idp/profile/SAML2/Redirect/SSO'
   */
  entryPoint?: string;

  /**
   * IDP Logout URL
   * @default entryPoint
   */
  logoutUrl?: string;

  /**
   * IDP Logout Callback URL
   */
  logoutCallbackUrl?: string;

  /**
   * Skip the Assertion Consumer Service URL in both the AuthnRequest and generated SP metadata.
   * When enabled:
   * - AuthnRequest will not include the optional AssertionConsumerServiceURL
   * - Generated metadata will not include AssertionConsumerService endpoints
   *
   * This is useful for:
   * - Deployments with dynamic URLs (e.g. Vercel preview deployments)
   * - Stanford's "skipEndpointValidationWhenSigned" IdP configuration
   *
   * When the IdP has skipEndpointValidationWhenSigned enabled and the SP signs
   * authentication requests, the IdP will accept the handler URL directly from
   * the signed request without checking it against metadata endpoints.
   *
   * @see https://uit.stanford.edu/service/saml/skipendpointvalidation
   * @default true
   */
  skipRequestAcsUrl?: boolean;

  /**
   * Max Assertion Age in milliseconds
   */
  maxAssertionAgeMs?: number;

  /**
   * Attribute Consuming Service Index
   */
  attributeConsumingServiceIndex?: string;

  /**
   * Disable Requested Authentication Context
   */
  disableRequestedAuthnContext?: boolean;

  /**
   * Requested Authentication Context
   */
  authnContext?: string | string[];

  /**
   * Requested Authentication Context Comparison
   * @default 'exact'
   */
  racComparison?: 'exact' | 'minimum' | 'maximum' | 'better';

  /**
   * Force Authentication
   */
  forceAuthn?: boolean;

  /**
   * Passive Authentication
   */
  passive?: boolean;

  /**
   * Provider Name
   */
  providerName?: string;

  /**
   * Skip Request Compression
   */
  skipRequestCompression?: boolean;

  /**
   * Authentication Request Binding
   * @default 'HTTP-Redirect'
   */
  authnRequestBinding?: 'HTTP-POST' | 'HTTP-Redirect';

  /**
   * Generate Unique ID function
   */
  generateUniqueId?: () => string;

  /**
   * Scoping configuration
   */
  scoping?: Record<string, unknown>;

  /**
   * Sign Metadata
   */
  signMetadata?: boolean;

  /**
   * Validate InResponseTo
   * @default 'never'
   */
  validateInResponseTo?: 'always' | 'never' | 'ifPresent';

  /**
   * Request ID Expiration Period in milliseconds
   * @default 28800000 (8 hours)
   */
  requestIdExpirationPeriodMs?: number;

  /**
   * Cache Provider
   */
  cacheProvider?: CacheProvider;

  /**
   * IDP Issuer
   */
  idpIssuer?: string;

  /**
   * SAML Authn Request Extensions
   */
  samlAuthnRequestExtensions?: Record<string, unknown>;

  /**
   * SAML Logout Request Extensions
   */
  samlLogoutRequestExtensions?: Record<string, unknown>;

  /**
   * Metadata Contact Person
   */
  metadataContactPerson?: Record<string, unknown>[];

  /**
   * Metadata Organization
   */
  metadataOrganization?: Record<string, unknown>;
}

/**
 * Cache Provider Interface
 */
export interface CacheProvider {
  saveAsync(key: string, value: string): Promise<unknown | null>;
  getAsync(key: string): Promise<string | null>;
  removeAsync(key: string | null): Promise<string | null>;
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
   * Secret for encrypting session data - must be 32+ characters (required)
   */
  secret: string;
}

/**
 * Optional session configuration with sensible defaults
 */
export interface OptionalSessionConfig {
  /**
   * Session cookie name
   * @default 'weblogin-auth'
   */
  name?: string;

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
 * MFA Context Class References for Stanford
 */
export enum MFA {
  /**
   * REFEDS MFA Profile
   * Requires multi-factor authentication
   */
  REFEDS = 'https://refeds.org/profile/mfa',

  /**
   * Cardinal Key MFA Profile
   * Requires authentication via Cardinal Key
   */
  CARDINAL_KEY = 'https://saml.stanford.edu/profile/mfa/cardinalkey',

  /**
   * Forced MFA Profile
   * Forces multi-factor authentication even if already authenticated
   */
  FORCED = 'https://saml.stanford.edu/profile/mfa/forced',
}

/**
 * Login options
 */
export type LoginOptions = {
  returnTo?: string;
  /**
   * Force re-authentication at the IdP
   */
  forceAuthn?: boolean;
  /**
   * Request specific MFA context
   */
  mfa?: MFA | string;
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
  encodedSUID: string;
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
