/* eslint-disable no-console */
import { Handler, Response, NextFunction } from 'express';
import * as passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import { serialize } from 'cookie';
import {
  WebLoginAuthConfig,
  AuthorizeOptions,
  AuthUser,
  SamlUserRequest,
  DeepPartial,
  SamlRelayState,
} from './types';
import { signJWT, validateSessionCookie, verifyToken } from './jwt';
import idps from './lib/idps';
import { attrMapper } from './lib/attributes';

export class WebLoginAuth {
  public config;

  private saml: SamlStrategy;

  constructor(config: DeepPartial<WebLoginAuthConfig> = {}) {

      // Get config values from env, but override if setting directly in constructor config
    this.config = {
      ...config,
      saml: {
        name: 'weblogin',
        forceAuthn: process.env.WEBLOGIN_AUTH_FORCE_LOGIN === 'true' || false,
        idp: process.env.WEBLOGIN_AUTH_IDP || 'prod',
        callbackUrl: process.env.WEBLOGIN_AUTH_ACS_URL,
        path: process.env.WEBLOGIN_AUTH_CALLBACK_PATH || '/auth',
        logoutUrl: process.env.WEBLOGIN_AUTH_LOGOUT_PATH || '/api/auth/logout',
        issuer: process.env.WEBLOGIN_AUTH_ISSUER || 'https://idp.stanford.edu/',
        passive: process.env.WEBLOGIN_AUTH_PASSIVE === 'true' || false,
        decryptionCert: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_CERT,
        decryptionPvk: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY,
        ...(config?.saml || {}),
      },
      session: {
        secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET || '',
        name: process.env.WEBLOGIN_AUTH_SESSION_NAME || 'weblogin-auth',
        expiresIn: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN || '12h',
        logoutRedirectUrl: process.env.WEBLOGIN_AUTH_SESSION_LOGOUT_URL || '/',
        unauthorizedRedirectUrl: process.env.WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL,
        ...(config?.session || {}),
      },
    };

    // Configure passport for SAML
    this.saml = new SamlStrategy(
      {
        logoutUrl: this.config.saml.loginPath,
        entryPoint: idps[this.config.saml.idp].entryPoint,
        cert: idps[this.config.saml.idp].cert,
        wantAssertionsSigned: true,
        signatureAlgorithm: 'sha256',
        identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        acceptedClockSkewMs: 60000,
        skipRequestCompression: false,
        passReqToCallback: true,
        ...this.config.saml,
      },
      (req, profile, done) => {
        const user = attrMapper(profile);
        const account = {
          issuer: user.issuer,
          mail: user?.mail,
          email: user?.email,
          givenName: user.givenName,
          displayName: user.displayName,
          eduPersonAffiliation: user?.eduPersonAffiliation,
          uid: user.uid,
          eduPersonPrincipalName: user.eduPersonPrincipalName,
          eduPersonScopedAffiliation: user.eduPersonScopedAffiliation,
          sn: user.sn,
        };
        done(null, account);
      }
    );

    passport.use(this.saml);
  }

  /**
   * Pass the strategy.
   *
   * For use when you want the strategy for your own passport implementation.
   */
  public getStrategy = (): SamlStrategy => {
    return this.saml;
  };

  /**
   * Pass the strategy name.
   *
   * Easy, peasy get the namesey.
   */
  public getStrategyName = ():string => {
    return this.saml.name;
  };

  /**
   * Triggers a log in event by sending the user to the IDP.
   */
  public initiate = (): Handler => (req: SamlUserRequest, res: Response, next: NextFunction) => {
    // The internal to the destination website path to redirect the user to after login.
    const { final_destination = '/' } = req.query;

    const isMoreThanUrlPath = final_destination && /^(https?:\/\/)?([a-z0-9.-]+)/.test(final_destination);

    if (isMoreThanUrlPath) {
      return res.status(400).json('Invalid "final_destination" parameter. Must be be local url path part');
    }

    // The relay object for the SAML loop.
    const relayStateObj:SamlRelayState = {
      finalDestination: final_destination,
    };
    req.query.RelayState = relayStateObj;
    req.query.RelayState = encodeURIComponent(JSON.stringify(relayStateObj));

    next();
  };

  // Passport initialize must be used prior to other passport middlewares
  public initialize = () => passport.initialize();

  /**
   * Authenticate SAML response middleware
   * Handle POSTed saml assertion and create user session
   * NOTE: Must use initilaize middleware prior to authenticate
   */
  public authenticateSaml = () => passport.authenticate(this.saml.name, { session: false });

  /**
   *
   * @param user
   * @returns
   */
  public signToken = async (user: AuthUser) => signJWT(user, {
    secret: this.config.session.secret,
    expiresIn: this.config.session.expiresIn,
  });

  /**
   *
   * @param token
   * @returns
   */
  public verifyToken = async (token: string) => verifyToken(token, { secret: this.config.session.secret });

  /**
   * Create signed auth session by setting user jwt to cookie
   */
  public createSession = () => async (req: SamlUserRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new Error('Unauthorized');
    }

    const token = await this.signToken(req.user);
    res.setHeader('Set-Cookie', [
      // HTTP Only cookie includes session token
      serialize(this.config.session.name, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'development',
        sameSite: 'strict',
        path: '/',
      }),
      // client side cookie to alert frontend that session is active
      serialize(`${this.config.session.name}-session`, 'active', {
        httpOnly: false,
        secure: false,
        sameSite: 'strict',
        path: '/',
      }),
    ]);

    await next();
  };

  /**
   * Destory the local auth session
   */
  public destroySession = (redirectUrl?: string) => (_req, res) => {
    // Destroy session cookies
    res.setHeader('Set-Cookie', [
      serialize(this.config.session.name, '', { maxAge: -1, path: '/' }),
      serialize(`${this.config.session.name}-session`, '', {
        maxAge: -1,
        path: '/',
      }),
    ]);

    const logoutRedirect = redirectUrl || this.config.session.logoutRedirectUrl;
    res.redirect(logoutRedirect);
  };

  /**
   * Convenience middleware that wraps the entire saml auth process into a single middleware
   */
  public authenticate = (): Handler => async (req, res, next) => {
    // Initialize
    this.initialize()(req, res, async (initErr) => {
      if (initErr) {
        console.log('Passport initialize ERROR:', initErr);
        return res.status(401).json('UNAUTHORIZED');
      }
      // Authenticate
      return this.authenticateSaml()(req, res, async (authErr) => {
        if (authErr) {
          console.log('SAML Authentication ERROR:', authErr);
          return res.status(401).json('UNAUTHORIZED');
        }

        // Response
        return this.createSession()(req as SamlUserRequest, res, () => {
          next();
        });
      });
    });
  };

  /**
   * Authorize middleware
   * Authorize requests against against valid jwt tokens
   * Attach authorized user to req object
   */
  public authorize = (options: AuthorizeOptions = {}): Handler => async (req, res, next) => {
    try {
      const user = await this.validateSessionCookie(req);
      req.user = user;
      await next();
    } catch (error) {
      // Allow unauthorized requests through
      if (options.allowUnauthorized) {
        await next();
      } else {
        // Check for unauthorized redirect
        const redirectUrl = options.redirectUrl || this.config.session.unauthorizedRedirectUrl;
        if (redirectUrl) {
          res.redirect(redirectUrl);
        } else {
          // Default 401 response
          res.status(401).json('UNAUTHORIZED');
        }
      }
    }
  };

  /**
   * Validate session cookie on request
   */
  public validateSessionCookie = async <T extends { cookies?: Record<string, any> }>(req: T) => validateSessionCookie(
    req,
    { secret: this.config.session.secret, name: this.config.session.name }
  );


  /**
   * Helper to extract the saml relay final destination url from req object
   */
  public getFinalDestination = (req: any) => {
    // Attach relayState to req
    try {
      const relayState = JSON.parse(decodeURIComponent(req.body.RelayState));
      const finalDest = relayState.finalDestination || null;
      return finalDest;
    } catch (err) {
      // I guess the relayState wasn't that great...
      console.log('Unable to parse samlRelayState', err);
    }
  };

  /**
   * generateServiceProviderMetadata
   */
  public generateServiceProviderMetadata = () => {
    return this.saml.generateServiceProviderMetadata(this.config.saml.decryptionCert, this.config.saml.cert);
  };
}

// Singleton client for default consumption
export const auth = new WebLoginAuth({});
