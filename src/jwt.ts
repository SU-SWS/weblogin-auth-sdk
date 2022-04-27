import { SignJWT, jwtVerify } from 'jose';
import { AuthUser } from './types';

export interface JWTConfig {
  secret?: string;
  expiresIn?: string;
  name?: string;
}

const defaultJwtConfig: JWTConfig = {
  secret: process.env.ADAPT_AUTH_SESSION_SECRET || '',
  expiresIn: process.env.ADAPT_AUTH_SESSION_EXPIRES_IN || '12h',
  name: process.env.ADAPT_AUTH_SESSION_NAME || 'adapt-auth',
};

export const signJWT = async (user: AuthUser, config: JWTConfig = {}) => {
  const expiresIn = config.expiresIn || defaultJwtConfig.expiresIn;
  const secret = config.secret || defaultJwtConfig.secret;
  const token = await new SignJWT(user as Record<string, any>)
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(expiresIn)
    .sign(new TextEncoder().encode(secret));
  return token;
};

export const verifyToken = async (token: string, config: JWTConfig = {}) => {
  const secret = config.secret || defaultJwtConfig.secret;
  const verified = await jwtVerify(token, new TextEncoder().encode(secret));
  return verified.payload as unknown as AuthUser;
};

export const validateSessionCookie = async <T extends { cookies?: Record<string, any> }>(
  req: T,
  config: JWTConfig = {}
) => {
  const name = config.name || defaultJwtConfig.name;
  const secret = config.secret || defaultJwtConfig.secret;
  const token = req.cookies[name];
  const user = await verifyToken(token, { secret });
  return user;
};
