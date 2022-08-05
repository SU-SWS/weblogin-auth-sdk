import { Request } from 'express';

// NOTE: This type is duplicated here so we can more easily abstract this module for distribution
export type DeepPartial<T extends {}> = {
  [P in keyof T]?: DeepPartial<T[P]>;
};

/**
 * Authorize middleware options
 */
export interface AuthorizeOptions {
  allowUnauthorized?: boolean;
  redirectUrl?: string;
}

/**
 * Session config
 */
export interface WebLoginAuthSessionConfig {
  /**
   * JWT signing secret
   */
  secret: string;
  /**
   * Name for session cookie. Defaults to 'adapt-auth'
   */
  name: string;
  /**
   * Session length. Defaults to '12h'
   */
  expiresIn: string;
  /**
   * Local path to redirect to after successful session creation
   */
  loginRedirectUrl?: string;
  /**
   * Local path to redirect to after successful session destruction
   */
  logoutRedirectUrl: string;
  /**
   * Local path to redirect to after failed authorization
   */
  unauthorizedRedirectUrl?: string;
}

/**
 * SAML Config
 */
export interface WebLoginAuthSamlConfig {
  /**
   * Login entrypoint 
   */
  serviceProviderLoginUrl: string;
  /**
   * Login entrypoint Id
   */
  entityId: string;
  /**
   * SAML public signing verification certificate
   */
  cert: string | string[];
  /**
   * Optional private key used to decrypt encrypted SAML assertions
   */
  decryptionKey?: string;
  /**
   * Absolute application for SAML document POST back
   */
   returnTo?: string;
   /**
    * Application origin for SAML document POST back
    */
   returnToOrigin?: string;
   /**
    * Application url path for SAML document POST back
    */
   returnToPath?: string;
}

/**
 * SDK configuration
 */
export interface WebLoginAuthConfig {
  saml: WebLoginAuthSamlConfig;
  session: WebLoginAuthSessionConfig;
}

/**
 * Auth user parsed from SAML profile or jwt
 */
export interface AuthUser {
  userName: string;
  email: string;
  digitalName?: string;
  SUID?: string;
  encodedSUID: string;
}

// Utility type useful for extending http request-like types
export interface AuthUserReqExtender {
  user?: AuthUser;
}

// Utility type that extends http request-like types
export type WithAuthUser<R extends {}> = R & AuthUserReqExtender;

// Http Request extended with AuthUser
export type AuthUserRequest = WithAuthUser<Request>;

/**
 * SAML RelayState Object
 */
export interface SamlRelayState {
  entity: string;
  returnTo?: string;
  finalDestination?: string;
  [key: string]: string;
}
export interface SamlUserReqExtender {
  user: AuthUser;
  samlRelayState: SamlRelayState;
}
export type WithSamlUser<R extends {}> = R & SamlUserReqExtender;
export type SamlUserRequest = WithSamlUser<Request>;
