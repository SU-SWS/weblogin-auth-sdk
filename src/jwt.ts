import { SignJWT, jwtVerify } from 'jose';
import { AuthUser } from './types';

export interface JWTConfig {
  secret?: string;
  expiresIn?: string;
  name?: string;
}

const defaultJwtConfig: JWTConfig = {
  secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET || '',
  expiresIn: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN || '12h',
  name: process.env.WEBLOGIN_AUTH_SESSION_NAME || 'weblogin-auth',
};

/**
 *
 * @param user
 * @param config
 * @returns
 */
export const signJWT = async (user: AuthUser, config: JWTConfig = {}) => {
  const expiresIn = config.expiresIn || defaultJwtConfig.expiresIn;
  const secret = config.secret || defaultJwtConfig.secret;
  const token = await new SignJWT(user as Record<string, any>)
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(expiresIn)
    .sign(new TextEncoder().encode(secret));
  return token;
};

/**
 *
 * @param token
 * @param config
 * @returns
 */
export const verifyToken = async (token: string, config: JWTConfig = {}) => {
  const secret = config.secret || defaultJwtConfig.secret;
  const verified = await jwtVerify(token, new TextEncoder().encode(secret));
  return verified.payload as unknown as AuthUser;
};

/**
 *
 * @param req
 * @param config
 * @returns
 */
export const validateSessionCookie = async <T extends { cookies?: Record<string, any> }>(
  req: T,
  config: JWTConfig = {}
) => {
  const name = config.name || defaultJwtConfig.name;
  const secret = config.secret || defaultJwtConfig.secret;
  let token;

  try {
    // Cookie accessor pattern for Next 12 middleware.
    token = req.cookies.get(name);
  }
  // Cookie access for Next 11 and other frameworks that use Express cookie-parser.
  catch(err) {
    token = req.cookies[name];
  }

  // If no session cookie was found, throw an exception.
  if(!token) {
    throw new Error('Session cookie not set.');
  }

  const user = await verifyToken(token, { secret });
  return user;
};
