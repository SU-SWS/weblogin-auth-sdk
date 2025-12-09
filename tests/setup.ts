// Jest setup file
// This file runs before each test file
import { webcrypto } from 'crypto';

// Set default test environment variables
Object.assign(process.env, {
  NODE_ENV: 'test',
  WEBLOGIN_AUTH_ISSUER: 'test-entity',
  WEBLOGIN_AUTH_SAML_CERT: 'test-cert',
  WEBLOGIN_AUTH_SAML_DECRYPTION_KEY: 'test-decryption-key',
  WEBLOGIN_AUTH_ACS_URL_ORIGIN: 'http://localhost:3000',
  WEBLOGIN_AUTH_SESSION_SECRET: 'test-session-secret-that-is-at-least-32-characters-long',
  WEBLOGIN_AUTH_SESSION_NAME: 'test-session',
});

// Mock Web Crypto API for Node.js environments that don't have it
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as Crypto;
}
