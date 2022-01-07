/* eslint-disable no-console */
import { Handler, Response, NextFunction } from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import jwt from 'jsonwebtoken';
import { serialize } from 'cookie';
import {
  AdaptAuthConfig,
  AuthorizeOptions,
  AuthUser,
  SamlUserRequest,
  DeepPartial,
} from './types';

export class AdaptAuth {
  public config: AdaptAuthConfig;

  private saml: SamlStrategy;

  constructor(config: DeepPartial<AdaptAuthConfig> = {}) {
    // Get config values from env, but override if setting directly in constructor config
    this.config = {
      ...config,
      saml: {
        serviceProviderLoginUrl:
          process.env.ADAPT_AUTH_SAML_SP_URL || 'https://adapt-sso-uat.stanford.edu/api/sso/login',
        entity: process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat',
        cert: process.env.ADAPT_AUTH_SAML_CERT || 'you-must-pass-cert',
        decryptionKey: process.env.ADAPT_AUTH_SAML_DECRYPTION_KEY,
        returnTo: process.env.ADAPT_AUTH_SAML_RETURN_URL,
        returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN || '',
        returnToPath: process.env.ADAPT_AUTH_SAML_RETURN_PATH || '',
        ...(config.saml || {}),
      },
      session: {
        secret: process.env.ADAPT_AUTH_SESSION_SECRET || '',
        name: process.env.ADAPT_AUTH_SESSION_NAME || 'adapt-auth',
        expiresIn: process.env.ADAPT_AUTH_SESSION_EXPIRES_IN || '12h',
        logoutRedirectUrl: process.env.ADAPT_AUTH_SESSION_LOGOUT_URL || '/',
        loginRedirectUrl: process.env.ADAPT_AUTH_SESSION_LOGIN_URL,
        unauthorizedRedirectUrl: process.env.ADAPT_AUTH_SESSION_UNAUTHORIZED_URL,
        ...(config.session || {}),
      },
    };

    // Configure passport for SAML
    this.saml = new SamlStrategy(
      {
        issuer: 'http://localhost:8000',
        cert: this.config.saml.cert,
        decryptionPvk: this.config.saml.decryptionKey,
        passReqToCallback: true,
        wantAssertionsSigned: true,
      },
      (req, profile, done) => {
        const user = {
          userName: profile.userName as string,
          email: profile.email || profile.nameID,
          firstName: profile.firstName as string,
          lastName: profile.lastName as string,
          SUID: (profile.SUID || profile.suid) as string,
          encodedSUID: profile.encodedSUID as string,
        };

        // Attach relayState to req
        try {
          (req as SamlUserRequest).samlRelayState = JSON.parse(req.body.RelayState);
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
    const isMoreThanUrlPath = final && /^(https?:\/\/)?([a-z0-9.-]+)/.test(final);

    if (isMoreThanUrlPath) {
      return res.status(400).json('Invalid "final_destination" parameter. Must be be local url path part');
    }

    const returnTo = this.config.saml.returnTo || `${this.config.saml.returnToOrigin}${this.config.saml.returnToPath}`;
    const params = {
      entity: this.config.saml.entity,
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
  public authenticateSaml = () => passport.authenticate(this.saml.name, { session: false });

  public signToken = (user: AuthUser) => {
    const token = jwt.sign(user, this.config.session.secret, {
      expiresIn: this.config.session.expiresIn,
    });
    return token;
  };

  public verifyToken = async (token: string) => new Promise<AuthUser>((resolve, reject) => {
    jwt.verify(token, this.config.session.secret, { maxAge: this.config.session.expiresIn }, (error, payload) => {
      if (error) {
        reject(error);
      } else {
        resolve(payload as AuthUser);
      }
    });
  });

  /**
   * Create signed auth session by setting user jwt to cookie
   */
  public createSession = () => (req: SamlUserRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new Error('Unauthorized');
    }

    const token = this.signToken(req.user);
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
  public authenticate = (redirectUrl?: string): Handler => async (req, res, next) => {
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
          const loginRedirect = redirectUrl || this.config.session.loginRedirectUrl;
          if (loginRedirect) {
            res.redirect(loginRedirect);
          } else {
            next();
          }
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
      next();
    } catch (error) {
      // Allow unauthorized requests through
      if (options.allowUnauthorized) {
        next();
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
  public validateSessionCookie = async <T extends { cookies?: Record<string, any> }>(req: T) => {
    const token = req.cookies[this.config.session.name];
    const user = await this.verifyToken(token);
    return user;
  };

  /**
   * Helper to extract the saml relay final destination url from req object
   */
  public getFinalDestination = (req: any) => ((req as SamlUserRequest).samlRelayState || {}).finalDestination;
}

// Singleton client for default consumption
export const auth = new AdaptAuth();