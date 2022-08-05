/* eslint-disable no-console */
import { Handler, Response, NextFunction } from 'express';
import * as passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-stanford';
import { serialize } from 'cookie';
import {
  WebLoginAuthConfig,
  AuthorizeOptions,
  AuthUser,
  SamlUserRequest,
  DeepPartial,
} from './types';
import { signJWT, validateSessionCookie, verifyToken } from './jwt';

export class WebLoginAuth {
  public config: WebLoginAuthConfig;

  private saml: SamlStrategy;

  constructor(config: DeepPartial<WebLoginAuthConfig> = {}) {
    // Get config values from env, but override if setting directly in constructor config
    this.config = {
      ...config,
      saml: {
        serviceProviderLoginUrl: process.env.WEBLOGIN_AUTH_SAML_SP_URL || '/saml',
        entityId: process.env.WEBLOGIN_AUTH_SAML_ENTITY_ID || 'https://github.com/su-sws/adapt-stripe',
        cert: process.env.WEBLOGIN_AUTH_SAML_CERT,
        decryptionCert: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_CERT,
        decryptionKey: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY,
        returnTo: process.env.WEBLOGIN_AUTH_SAML_RETURN_URL,
        returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN || '',
        returnToPath: process.env.WEBLOGIN_AUTH_SAML_RETURN_PATH || '',
        ...(config.saml || {}),
      },
      session: {
        secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET || '',
        name: process.env.WEBLOGIN_AUTH_SESSION_NAME || 'weblogin-auth',
        expiresIn: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN || '12h',
        logoutRedirectUrl: process.env.WEBLOGIN_AUTH_SESSION_LOGOUT_URL || '/',
        unauthorizedRedirectUrl:
          process.env.WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL,
        ...(config.session || {}),
      },
    };

    // Configure passport for SAML
    this.saml = new SamlStrategy(
      {
        protocol: 'http://',
        idp: 'prod',
        entityId: this.config.saml.entityId,
        path: this.config.saml.serviceProviderLoginUrl,
        loginPath: this.config.saml.serviceProviderLoginUrl,
        passReqToCallback: true,
        passport: passport,
        decryptionPvk: this.config.saml.decryptionKey,
        decryptionCert: this.config.saml.decryptionCert,
      },
      (req, profile, done) => {
        const user = {
          userName: profile.userName as string,
          email: (profile.email || profile.mail) as string,
          displayName: profile.displayName as string,
          SUID: profile.uid as string,
          affiliation: profile.suAffiliation as string,
        };

        try {
          (req as SamlUserRequest).samlRelayState = JSON.parse(
            req.body.RelayState
          );
        } catch (err) {
          // I guess the relayState wasn't that great...
          console.log('Unable to parse samlRelayState', err);
        }

        done(null, user);
      }
    );
    passport.use(this.saml);
  }

  /**
   * Redirect request to SAML idp with configured query params
   */
  public initiate = (): Handler => (req, res) => {
    // Pass along final destination
    const final = req.query.final_destination as string;
    const isMoreThanUrlPath =
      final && /^(https?:\/\/)?([a-z0-9.-]+)/.test(final);

    if (isMoreThanUrlPath) {
      return res
        .status(400)
        .json(
          'Invalid "final_destination" parameter. Must be be local url path part'
        );
    }

    const returnTo =
      this.config.saml.returnTo ||
      `${this.config.saml.returnToOrigin}${this.config.saml.returnToPath}`;
    const params = {
      entityId: this.config.saml.entityId,
      return_to: returnTo,
      // Pass final_destination through
      ...(final ? { final_destination: final } : {}),
    };
    const query = new URLSearchParams(params).toString();
    return res.redirect(`${this.config.saml.serviceProviderLoginUrl}?${query}`);
  };

  // Passport initialize must be used prior to other passport middlewares
  public initialize = () => passport.initialize();

  /**
   * Authenticate SAML response middleware
   * Handle POSTed saml assertion and create user session
   * NOTE: Must use initilaize middleware prior to authenticate
   */
  public authenticateSaml = () =>
    passport.authenticate(this.saml.name, { session: false });

  public signToken = async (user: AuthUser) =>
    signJWT(user, {
      secret: this.config.session.secret,
      expiresIn: this.config.session.expiresIn,
    });

  public verifyToken = async (token: string) =>
    verifyToken(token, { secret: this.config.session.secret });

  /**
   * Create signed auth session by setting user jwt to cookie
   */
  public createSession =
    () => async (req: SamlUserRequest, res: Response, next: NextFunction) => {
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

      next();
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
  public authorize =
    (options: AuthorizeOptions = {}): Handler =>
    async (req, res, next) => {
      try {
        const user = await this.validateSessionCookie(req);
        req.user = user;
        next();
      } catch (error) {
        // Allow unauthorized requests through
        if (options.allowUnauthorized) {
          next();
        } else {
          // Check for unauthorized redirect
          const redirectUrl =
            options.redirectUrl || this.config.session.unauthorizedRedirectUrl;
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
  public validateSessionCookie = async <
    T extends { cookies?: Record<string, any> }
  >(
    req: T
  ) =>
    validateSessionCookie(req, {
      secret: this.config.session.secret,
      name: this.config.session.name,
    });

  /**
   * Helper to extract the saml relay final destination url from req object
   */
  public getFinalDestination = (req: any) => {
    // Attach relayState to req
    try {
      const relayState = req.samlRelayState;
      const finalDest = relayState.finalDestination || null;
      return finalDest;
    } catch (err) {
      // I guess the relayState wasn't that great...
      console.log('Unable to parse samlRelayState', err);
    }
  };
}

// Singleton client for default consumption
export const auth = new WebLoginAuth();
