/**
 * SAML 2.0 authentication provider for Stanford WebLogin
 *
 * This module provides SAML Service Provider (SP) functionality for integrating
 * with Stanford's Identity Provider. It handles:
 *
 * - SP-initiated SAML authentication flows
 * - AuthnRequest generation with RelayState
 * - SAML Response validation and signature verification
 * - User profile mapping from SAML attributes
 * - Secure returnTo URL handling
 *
 * The implementation uses @node-saml/node-saml for SAML protocol handling
 * and provides Stanford-specific defaults and attribute mapping.
 *
 * @module saml
 */

import { SAML, SamlConfig as NodeSamlConfig } from '@node-saml/node-saml';
import {
  SamlConfig,
  SAMLProfile,
  SAMLResponse,
  LoginOptions,
  AuthenticateOptions,
  User,
  Logger,
  RelayStatePayload,
  AuthError,
} from './types.js';
import { AuthUtils } from './utils.js';
import { DefaultLogger } from './logger.js';

const OID_MAP: Record<string, string> = {
  'urn:oid:0.9.2342.19200300.100.1.1': 'uid',
  'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
  'urn:oid:0.9.2342.19200300.100.1.41': 'mobile',
  'urn:oid:0.9.2342.19200300.100.1.42': 'pager',
  'urn:oid:1.3.6.1.4.1.250.1.57': 'labeledURI',
  'urn:oid:1.3.6.1.4.1.299.11.1.4': 'suDisplayNameLF',
  'urn:oid:1.3.6.1.4.1.299.11.1.9': 'suDisplayAffiliation',
  'urn:oid:1.3.6.1.4.1.299.11.1.11': 'suEmailPager',
  'urn:oid:1.3.6.1.4.1.299.11.1.14': 'suAffiliation',
  'urn:oid:1.3.6.1.4.1.299.11.1.15': 'suMailCode',
  'urn:oid:1.3.6.1.4.1.299.11.1.18': 'suUnivID',
  'urn:oid:1.3.6.1.4.1.299.11.1.19': 'suPrivilegeGroup',
  'urn:oid:1.3.6.1.4.1.299.11.1.21': 'suGivenName',
  'urn:oid:1.3.6.1.4.1.299.11.1.30': 'suUniqueIdentifier',
  'urn:oid:1.3.6.1.4.1.299.11.1.64': 'suOU',
  'urn:oid:1.3.6.1.4.1.299.11.1.204': 'suPrimaryOrganizationName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'eduPersonPrincipalName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'eduPersonAffiliation',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.7': 'eduPersonEntitlement',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.9': 'eduPersonScopedAffiliation',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.10': 'eduPersonTargetedID',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.16': 'eduPersonOrcid',
  'urn:oasis:names:tc:SAML:attribute:subject-id': 'subject-id',
  'urn:oasis:names:tc:SAML:attribute:pairwise-id': 'pairwise-id',
  'urn:oid:2.5.4.3': 'cn',
  'urn:oid:2.5.4.4': 'sn',
  'urn:oid:2.5.4.9': 'street',
  'urn:oid:2.5.4.10': 'o',
  'urn:oid:2.5.4.11': 'ou',
  'urn:oid:2.5.4.12': 'title',
  'urn:oid:2.5.4.13': 'description',
  'urn:oid:2.5.4.16': 'postalAddress',
  'urn:oid:2.5.4.20': 'telephoneNumber',
  'urn:oid:2.5.4.42': 'givenName',
  'urn:oid:2.16.840.1.113730.3.1.3': 'employeeNumber',
  'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
};

/**
 * SAML authentication provider for Stanford WebLogin
 *
 * Handles the complete SAML Service Provider flow:
 * 1. Generate AuthnRequest and redirect to Stanford IdP
 * 2. Receive and validate SAML Response from IdP
 * 3. Map SAML attributes to user profile
 * 4. Handle RelayState for returnTo functionality
 *
 * Features:
 * - SP-initiated authentication
 * - RelayState-based returnTo URL handling
 * - Configurable certificate validation
 * - Stanford-specific attribute mapping
 * - Comprehensive error handling and logging
 *
 * @example
 * ```typescript
 * const samlProvider = new SAMLProvider({
 *   issuer: 'my-app-entity-id',
 *   idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT,
 *   returnToOrigin: 'https://myapp.com'
 * });
 *
 * // Redirect to login
 * const response = await samlProvider.login({ returnTo: '/dashboard' });
 *
 * // Handle callback
 * const { user } = await samlProvider.authenticate({ req: request });
 * ```
 */
export class SAMLProvider {
  private provider: SAML;
  private config: Required<SamlConfig>;
  private logger: Logger;

  /**
   * Create a new SAML authentication provider
   *
   * Initializes the SAML provider with configuration validation and sensible defaults.
   * Environment variables are used as fallbacks for configuration options.
   *
   * @param config - SAML configuration (required and optional settings)
   * @param logger - Optional logger instance (defaults to DefaultLogger)
   *
   * @throws {AuthError} If required configuration is missing or invalid
   *
   * @example
   * ```typescript
   * // Minimal configuration
   * const provider = new SAMLProvider({
   *   issuer: 'my-app',
   *   idpCert: certString,
   *   returnToOrigin: 'https://myapp.com'
   * });
   *
   * // With custom options
   * const provider = new SAMLProvider({
   *   issuer: 'my-app',
   *   idpCert: certString,
   *   returnToOrigin: 'https://myapp.com',
   *   wantAssertionsSigned: true,
   *   acceptedClockSkewMs: 30000
   * }, customLogger);
   * ```
   */
  constructor(config: SamlConfig, logger?: Logger) {
    this.logger = logger || new DefaultLogger();

    // Process certificates and keys to remove headers/footers if present
    const rawIdpCert = config.idpCert || process.env.WEBLOGIN_AUTH_SAML_CERT;
    const idpCert = Array.isArray(rawIdpCert)
      ? rawIdpCert.map(c => AuthUtils.formatKey(c))
      : AuthUtils.formatKey(rawIdpCert as string);

    // Determine private key (prioritize explicit config, then env)
    const rawPrivateKey = config.privateKey || process.env.WEBLOGIN_AUTH_SAML_PRIVATE_KEY;
    const privateKey = AuthUtils.formatKey(rawPrivateKey || '');

    // Decryption private key must be in PEM format for node-saml's decryption
    // Use formatPrivateKey to ensure proper PEM format with headers
    const rawDecryptionPvk = config.decryptionPvk || process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY;
    const decryptionPvk = rawDecryptionPvk ? AuthUtils.formatPrivateKey(rawDecryptionPvk) : undefined;

    // Determine public cert (prioritize explicit config, then env)
    const rawCert = config.cert || process.env.WEBLOGIN_AUTH_SAML_SP_CERT;
    const cert = AuthUtils.formatKey(rawCert || '');

    // Decryption cert - use formatKey for base64 only (metadata uses raw base64)
    const rawDecryptionCert = config.decryptionCert || process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_CERT;
    const decryptionCert = rawDecryptionCert ? AuthUtils.formatKey(rawDecryptionCert) : undefined;

    // Build configuration with defaults and environment variable fallbacks
    const samlConfig = {
      // Required fields (must be provided)
      issuer: config.issuer || process.env.WEBLOGIN_AUTH_ISSUER || process.env.WEBLOGIN_AUTH_SAML_ENTITY,
      idpCert,
      returnToOrigin: config.returnToOrigin || process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN || process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN,
      privateKey,
      cert,

      // Optional fields with sensible defaults
      audience: config.audience || config.issuer || process.env.WEBLOGIN_AUTH_ISSUER || 'weblogin.stanford.edu',
      decryptionPvk,
      decryptionCert,

      // IDP Entry Point
      entryPoint: config.entryPoint || process.env.WEBLOGIN_AUTH_IDP_ENTRY_POINT || 'https://idp.stanford.edu/idp/profile/SAML2/Redirect/SSO',

      returnToPath: config.returnToPath || process.env.WEBLOGIN_AUTH_CALLBACK_PATH || '/api/auth/callback',

      // RelayState configuration with defaults
      includeReturnTo: config.includeReturnTo ?? true,

      // SAML protocol settings with secure defaults
      signatureAlgorithm: config.signatureAlgorithm || 'sha256',
      digestAlgorithm: config.digestAlgorithm,
      xmlSignatureTransforms: config.xmlSignatureTransforms,
      identifierFormat: config.identifierFormat || 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
      allowCreate: config.allowCreate ?? false,
      spNameQualifier: config.spNameQualifier,
      wantAssertionsSigned: config.wantAssertionsSigned ?? true,
      wantAuthnResponseSigned: config.wantAuthnResponseSigned ?? true,
      acceptedClockSkewMs: config.acceptedClockSkewMs ?? 60000,
      maxAssertionAgeMs: config.maxAssertionAgeMs,
      attributeConsumingServiceIndex: config.attributeConsumingServiceIndex,
      disableRequestedAuthnContext: config.disableRequestedAuthnContext,
      authnContext: config.authnContext,
      racComparison: config.racComparison,
      forceAuthn: config.forceAuthn,
      passive: config.passive,
      providerName: config.providerName,
      skipRequestCompression: config.skipRequestCompression,
      authnRequestBinding: config.authnRequestBinding,
      generateUniqueId: config.generateUniqueId,
      scoping: config.scoping,
      signMetadata: config.signMetadata,
      validateInResponseTo: config.validateInResponseTo,
      requestIdExpirationPeriodMs: config.requestIdExpirationPeriodMs,
      cacheProvider: config.cacheProvider,
      idpIssuer: config.idpIssuer,
      logoutUrl: config.logoutUrl,
      logoutCallbackUrl: config.logoutCallbackUrl,
      samlAuthnRequestExtensions: config.samlAuthnRequestExtensions,
      samlLogoutRequestExtensions: config.samlLogoutRequestExtensions,
      metadataContactPerson: config.metadataContactPerson,
      metadataOrganization: config.metadataOrganization,

      // Additional parameters with defaults
      additionalParams: config.additionalParams || {},
      additionalAuthorizeParams: config.additionalAuthorizeParams || {},
      additionalLogoutParams: config.additionalLogoutParams || {},

      // Skip ACS URL validation in AuthnRequest
      skipRequestAcsUrl: config.skipRequestAcsUrl ?? true,
    };

    // Store the merged configuration
    this.config = samlConfig as Required<SamlConfig>;

    // Validate required configuration
    this.validateConfig();

    // Construct callback URL
    const callbackUrl = new URL(this.config.returnToPath, this.config.returnToOrigin).toString();

    // Create SAML provider with compatible config
    const nodesamlConfig = {
      entryPoint: samlConfig.entryPoint,
      issuer: samlConfig.issuer,
      idpCert: samlConfig.idpCert,
      audience: samlConfig.audience,
      privateKey: samlConfig.privateKey,
      decryptionPvk: samlConfig.decryptionPvk || undefined,
      identifierFormat: samlConfig.identifierFormat,
      wantAssertionsSigned: samlConfig.wantAssertionsSigned,
      wantAuthnResponseSigned: samlConfig.wantAuthnResponseSigned,
      acceptedClockSkewMs: samlConfig.acceptedClockSkewMs,
      allowCreate: samlConfig.allowCreate,
      callbackUrl: callbackUrl,
      disableRequestAcsUrl: samlConfig.skipRequestAcsUrl,

      // New options
      publicCert: samlConfig.cert,
      signatureAlgorithm: samlConfig.signatureAlgorithm,
      digestAlgorithm: samlConfig.digestAlgorithm,
      xmlSignatureTransforms: samlConfig.xmlSignatureTransforms,
      spNameQualifier: samlConfig.spNameQualifier,
      maxAssertionAgeMs: samlConfig.maxAssertionAgeMs,
      attributeConsumingServiceIndex: samlConfig.attributeConsumingServiceIndex,
      disableRequestedAuthnContext: samlConfig.disableRequestedAuthnContext,
      authnContext: samlConfig.authnContext,
      racComparison: samlConfig.racComparison,
      forceAuthn: samlConfig.forceAuthn,
      passive: samlConfig.passive,
      providerName: samlConfig.providerName,
      skipRequestCompression: samlConfig.skipRequestCompression,
      authnRequestBinding: samlConfig.authnRequestBinding,
      generateUniqueId: samlConfig.generateUniqueId,
      scoping: samlConfig.scoping,
      signMetadata: samlConfig.signMetadata,
      validateInResponseTo: samlConfig.validateInResponseTo,
      requestIdExpirationPeriodMs: samlConfig.requestIdExpirationPeriodMs,
      cacheProvider: samlConfig.cacheProvider,
      idpIssuer: samlConfig.idpIssuer,
      logoutUrl: samlConfig.logoutUrl,
      logoutCallbackUrl: samlConfig.logoutCallbackUrl,
      samlAuthnRequestExtensions: samlConfig.samlAuthnRequestExtensions,
      samlLogoutRequestExtensions: samlConfig.samlLogoutRequestExtensions,
      metadataContactPerson: samlConfig.metadataContactPerson,
      metadataOrganization: samlConfig.metadataOrganization,

      // Convert additionalParams to strings for node-saml compatibility
      additionalParams: Object.fromEntries(
        Object.entries(samlConfig.additionalParams).map(([k, v]) => [k, String(v)])
      ),
      additionalAuthorizeParams: Object.fromEntries(
        Object.entries(samlConfig.additionalAuthorizeParams).map(([k, v]) => [k, String(v)])
      ),
      additionalLogoutParams: Object.fromEntries(
        Object.entries(samlConfig.additionalLogoutParams).map(([k, v]) => [k, String(v)])
      ),
    };

    this.provider = new SAML(nodesamlConfig as NodeSamlConfig);

    this.logger.debug('SAML provider initialized', {
      issuer: this.config.issuer,
      audience: this.config.audience,
      entryPoint: this.config.entryPoint,
      returnToOrigin: this.config.returnToOrigin,
      callbackUrl: callbackUrl,
    });
  }

  /**
   * Validate required SAML configuration
   *
   * Ensures that all required configuration fields are present and non-empty.
   * Throws descriptive errors to help with configuration debugging.
   *
   * @throws {AuthError} If required configuration is missing
   * @private
   */
  private validateConfig(): void {
    const required = ['issuer', 'idpCert', 'entryPoint', 'returnToOrigin', 'privateKey', 'cert', 'decryptionPvk', 'decryptionCert'];
    const missing = required.filter(key => {
      const value = this.config[key as keyof SamlConfig];
      return !value || (typeof value === 'string' && value.trim() === '');
    });

    if (missing.length > 0) {
      throw new AuthError(
        `Missing required SAML configuration: ${missing.join(', ')}`,
        'INVALID_CONFIG',
        400
      );
    }
  }

  /**
   * Generate login URL for SAML authentication
   *
   * Creates a Stanford Pass login URL with proper parameters:
   * - entity: The SAML entity/issuer identifier
   * - return_to: ACS URL where SAML response will be posted
   * - final_destination: Where user should go after authentication
   * - RelayState: Encrypted payload containing returnTo URL (if enabled)
   *
   * @param options - Login options including returnTo URL and additional parameters
   * @returns Promise resolving to the complete login URL
   *
   * @example
   * ```typescript
   * // Basic login URL
   * const url = await samlProvider.getLoginUrl();
   *
   * // With returnTo URL
   * const url = await samlProvider.getLoginUrl({
   *   returnTo: '/dashboard'
   * });
   *
   * // With additional parameters
   * const url = await samlProvider.getLoginUrl({
   *   returnTo: '/admin',
   *   forceAuthn: 'true'
   * });
   * ```
   *
   * @throws {Error} If URL generation fails
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    try {
      const { returnTo, forceAuthn, mfa, ...additionalParams } = options;
      const payload: RelayStatePayload = {
        return_to: returnTo || '/',
      };
      const relayState = JSON.stringify(payload);

      const authorizeOptions: Record<string, unknown> = {
        ...this.config.additionalAuthorizeParams,
        ...additionalParams
      };

      if (forceAuthn !== undefined) {
        authorizeOptions.forceAuthn = forceAuthn;
      }

      if (mfa) {
        authorizeOptions.authnContext = [mfa];
      }

      // Generate SAML AuthnRequest URL
      const loginUrl = await this.provider.getAuthorizeUrlAsync(
        relayState,
        undefined,
        authorizeOptions
      );

      this.logger.debug('Generated login URL', {
        hasRelayState: !!relayState,
        return_to: payload.return_to,
        loginUrl: loginUrl.split('?')[0], // Log URL without parameters for security
        forceAuthn,
        mfa,
      });

      return loginUrl;
    } catch (error) {
      this.logger.error('Failed to generate login URL', {
        error: error instanceof Error ? error.message : 'Unknown error',
        options
      });
      throw error;
    }
  }

  /**
   * Initiate SAML login by redirecting to IdP
   *
   * Generates a login URL and returns a 302 redirect Response.
   * This is a convenience method that combines getLoginUrl() with Response.redirect().
   *
   * @param options - Login options including returnTo URL
   * @returns Promise resolving to a redirect Response to the IdP login page
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    const loginUrl = await this.getLoginUrl(options);
    this.logger.debug('Generated login URL:', { loginUrl });
    return Response.redirect(loginUrl, 302);
  }

  /**
   * Authenticate SAML response from IdP
   *
   * Validates and processes the SAML response received at the ACS endpoint:
   * 1. Extracts SAMLResponse from POST body
   * 2. Validates SAML signatures and assertions
   * 3. Processes RelayState for returnTo URL
   * 4. Maps SAML attributes to User object
   * 5. Calls authentication callbacks
   *
    * @param options - Authentication options with request and callbacks
   * @returns Promise resolving to authenticated user, profile, and returnTo URL
   *
   * @throws {AuthError} If authentication fails or SAML response is invalid
   *
   * @example
   * ```typescript
   * // In ACS route handler
   * export async function POST(request: Request) {
   *   const { user, profile, returnTo } = await samlProvider.authenticate({
   *     req: request,
   *     callbacks: {
   *       mapProfile: (profile) => ({
   *         id: profile.encodedSUID,
   *         email: `${profile.userName}@stanford.edu`,
   *         name: `${profile.firstName} ${profile.lastName}`
   *       })
   *     }
   *   });
   *
   *   // Create session and redirect
   *   await sessionManager.createSession(user);
   *   return Response.redirect(returnTo || '/dashboard');
   * }
   * ```
   */
  async authenticate(options: AuthenticateOptions): Promise<{
    user: User;
    profile: SAMLProfile;
    returnTo?: string;
  }> {
    const { req, callbacks } = options;

    try {
      // Validate request
      if (!req || !(req instanceof Request)) {
        throw new AuthError('Invalid request object provided', 'INVALID_REQUEST', 400);
      }

      // Extract SAML response from request body
      const requestText = await req.text();
      if (!requestText) {
        throw new AuthError('No request body found', 'MISSING_BODY', 400);
      }

      // Parse form data
      const formData = new URLSearchParams(requestText);
      const samlResponse = formData.get('SAMLResponse');
      const relayState = formData.get('RelayState');

      if (!samlResponse) {
        throw new AuthError('No SAMLResponse found in request', 'MISSING_SAML_RESPONSE', 400);
      }

      this.logger.debug('Received SAML response', {
        hasRelayState: !!relayState,
        samlResponseLength: samlResponse.length,
      });

      // Validate SAML response
      const result = await this.provider.validatePostResponseAsync({
        SAMLResponse: samlResponse
      }) as SAMLResponse;

      if (!result || !result.profile) {
        throw new AuthError('Invalid SAML response or missing profile', 'INVALID_SAML_RESPONSE', 400);
      }

      const profile = result.profile as SAMLProfile;

      this.logger.info('SAML authentication successful', {
        nameID: profile.nameID,
        issuer: profile.issuer,
        sessionIndex: profile.sessionIndex,
      });

      // Process RelayState to get returnTo URL
      let returnTo: string | undefined;
      if (relayState) {
        returnTo = await this.processRelayState(relayState);
      }

      // Map SAML profile to User object
      let user: User;
      if (callbacks?.mapProfile) {
        user = await callbacks.mapProfile(profile);
      } else {
        user = this.defaultMapProfile(profile);
      }

      // Call signIn callback if provided
      if (callbacks?.signIn) {
        await callbacks.signIn({ user, profile });
      }

      this.logger.info('User authentication completed', {
        userId: user.id,
        returnTo,
      });

      return { user, profile, returnTo };

    } catch (error) {
      this.logger.error('SAML authentication failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (error instanceof AuthError) {
        throw error;
      }

      throw new AuthError(
        'SAML authentication failed',
        'AUTHENTICATION_FAILED',
        500
      );
    }
  }

  /**
   * Generate SAML Service Provider Metadata
   *
   * Creates the XML metadata for this Service Provider to be shared with the Identity Provider.
   * This metadata includes the Entity ID, ACS URL, and optional certificates for signing/encryption.
   *
   * @param decryptionCert - Optional public certificate for encryption (PEM format)
   * @param signingCert - Optional public certificate for signing (PEM format)
   * @returns SAML Metadata XML string
   *
   * @example
   * ```typescript
   * const metadata = samlProvider.getMetadata(
   *   fs.readFileSync('sp-cert.pem', 'utf8'),
   *   fs.readFileSync('sp-cert.pem', 'utf8')
   * );
   * ```
   */
  getMetadata(decryptionCert?: string, signingCert?: string): string {

    // Use the certs from the config if not provided
    if (!decryptionCert && this.config.decryptionCert) {
      decryptionCert = this.config.decryptionCert;
    }

    if (!signingCert && this.config.cert) {
      signingCert = this.config.cert;
    }

    let metadata = this.provider.generateServiceProviderMetadata(decryptionCert ?? null, signingCert ?? null);

    // Add validUntil attribute to EntityDescriptor (valid for 1 year)
    const validUntil = new Date();
    validUntil.setFullYear(validUntil.getFullYear() + 1);

    // Simple string replacement to inject validUntil
    metadata = metadata.replace(
      '<EntityDescriptor',
      `<EntityDescriptor validUntil="${validUntil.toISOString()}"`
    );

    return metadata;
  }

  /**
   * Process RelayState to extract returnTo URL
   *
   * Parses and validates the RelayState parameter from SAML response:
   * 1. Decodes JSON payload from RelayState
   * 2. Extracts return_to URL
   * 3. Sanitizes URL against allowed origins
   * 4. Returns safe URL or fallback
   *
   * @param relayState - RelayState parameter from SAML response
   * @returns Promise resolving to sanitized returnTo URL or undefined
   *
   * @private
   * @security URLs are validated against allowed origins to prevent open redirects
   */
  private async processRelayState(relayState: string): Promise<string | undefined> {
    // Parse RelayState as simple JSON
    let payload: RelayStatePayload;

    try {
      // Parse RelayState as simple JSON
      payload = JSON.parse(relayState);
    } catch (error) {
      this.logger.warn('Malformed RelayState: invalid JSON', {
        error: error instanceof Error ? error.message : String(error),
        relayState,
      });
      return undefined;
    }

    // Sanitize return_to URL
    try {
      if (payload.return_to) {
        const allowedOrigins = [this.config.returnToOrigin];
        const sanitized = AuthUtils.sanitizeReturnTo(payload.return_to, allowedOrigins);
        if (!sanitized) {
          this.logger.warn('Return_to URL failed sanitization', { return_to: payload.return_to });
          return '/';
        }
        return sanitized;
      }
      return undefined;
    } catch (error) {
      this.logger.error('Failed to process RelayState', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return undefined;
    }
  }

  /**
   * Default mapping from SAML profile to User
   *
   * Maps Stanford SAML attributes to a standardized User object.
   *
   * @param profile - SAML profile with Stanford attributes
   * @returns User object with mapped attributes
   *
   * @private
   */
  private defaultMapProfile(profile: SAMLProfile): User {
    // Extract user information from Stanford SAML attributes
    const attributes = profile.attributes || profile;

    // Map OID attributes to friendly names
    const mappedAttributes: Record<string, unknown> = { ...attributes };
    Object.entries(attributes).forEach(([key, value]) => {
      if (OID_MAP[key]) {
        mappedAttributes[OID_MAP[key]] = value;
      }
    });

    return {
      id: (mappedAttributes.encodedSUID || mappedAttributes.uid || mappedAttributes.nameID || 'unknown') as string,
      email: (mappedAttributes.email || mappedAttributes.mail || (mappedAttributes.userName ? `${mappedAttributes.userName}@stanford.edu` : undefined)) as string | undefined,
      name: (mappedAttributes.displayName || (mappedAttributes.firstName && mappedAttributes.lastName ? `${mappedAttributes.firstName} ${mappedAttributes.lastName}` : undefined) || (mappedAttributes.givenName && mappedAttributes.sn ? `${mappedAttributes.givenName} ${mappedAttributes.sn}` : undefined)) as string | undefined,
      sessionId: (mappedAttributes.sessionIndex || mappedAttributes.sessionId) as string | undefined,
      suid: mappedAttributes.suid as string | undefined,
      imageUrl: mappedAttributes.imageUrl as string | undefined,
      ...mappedAttributes,
    };
  }
}

/**
 * Factory function to create SAMLProvider instance
 *
 * @param config - SAML configuration
 * @param logger - Optional logger
 * @returns Configured SAMLProvider instance
 */
export function createSAMLProvider(config: SamlConfig, logger?: Logger): SAMLProvider {
  return new SAMLProvider(config, logger);
}
