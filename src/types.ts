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

  /**
   * Name of the SAML strategy.
   */
  name: string;

  /**
   * Force the log in even if the user has a session on the IDP?
   */
  forceAuthn: boolean;

  /**
   * Which IDP to use.
   */
  idp: 'itlab' | 'dev' | 'uat' | 'prod' | string;

  /**
   * The ACS full url (Redirect back to your site path)
   */
  callbackUrl: string;

  /**
   * The callback path
   */
  path: string;

  /**
   * The IDP logout URL
   */
  logoutUrl: string;

  /**
   * The EntityID you registered on spdb.
   */
  issuer: string;

  /**
   * Try to log in passively (don't show a login form if no session on IDP)
   */
  passive: boolean;

  /**
   * The decryption certificate
   */
  decryptionCert: string;

  /**
   * The decryption key
   */
  decryptionPvk: string;
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
