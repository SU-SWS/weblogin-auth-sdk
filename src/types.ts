import { Request } from 'express';
import { SamlOptions } from 'passport-saml/lib/node-saml/types';

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
   * Name for session cookie. Defaults to 'weblogin-auth'
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
export interface WebLoginAuthSamlConfig extends SamlOptions {

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
  issuer: string;
  mail?: string;
  email?: string;
  givenName: string;
  displayName: string;
  eduPersonAffiliation: string | string[];
  uid: string;
  eduPersonPrincipalName: string;
  eduPersonScopedAffiliation: string;
  sn: string;
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
  finalDestination?: string;
  [key: string]: string;
}

export interface SamlUserReqExtender {
  user: AuthUser;
  samlRelayState: SamlRelayState;
}

export type WithSamlUser<R extends {}> = R & SamlUserReqExtender;

export type SamlUserRequest = WithSamlUser<Request>;
