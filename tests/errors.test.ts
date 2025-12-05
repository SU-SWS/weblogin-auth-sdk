import { SAMLError, SessionError, ConfigError, NetworkError } from '../src/errors';
import { AuthError } from '../src/types';

describe('Error Classes', () => {
  describe('SAMLError', () => {
    it('should create SAML error with default status code', () => {
      const error = new SAMLError('SAML validation failed', 'INVALID_SIGNATURE', 'test-issuer');

      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(SAMLError);
      expect(error.name).toBe('SAMLError');
      expect(error.message).toBe('SAML validation failed');
      expect(error.code).toBe('SAML_INVALID_SIGNATURE');
      expect(error.statusCode).toBe(400);
      expect(error.samlCode).toBe('INVALID_SIGNATURE');
      expect(error.issuer).toBe('test-issuer');
    });

    it('should create SAML error with custom status code', () => {
      const error = new SAMLError('Authentication timeout', 'TIMEOUT', 'test-issuer', 408);

      expect(error.statusCode).toBe(408);
      expect(error.code).toBe('SAML_TIMEOUT');
    });

    it('should create SAML error without issuer', () => {
      const error = new SAMLError('Generic SAML error', 'GENERIC');

      expect(error.issuer).toBeUndefined();
      expect(error.samlCode).toBe('GENERIC');
    });

    it('should inherit from Error correctly', () => {
      const error = new SAMLError('Test error', 'TEST');

      expect(error instanceof Error).toBe(true);
      expect(error.stack).toBeDefined();
    });
  });

  describe('SessionError', () => {
    it('should create session error with default status code', () => {
      const error = new SessionError('Session decryption failed', 'DECRYPTION_FAILED', 'user-session');

      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(SessionError);
      expect(error.name).toBe('SessionError');
      expect(error.message).toBe('Session decryption failed');
      expect(error.code).toBe('SESSION_DECRYPTION_FAILED');
      expect(error.statusCode).toBe(500);
      expect(error.sessionCode).toBe('DECRYPTION_FAILED');
      expect(error.sessionName).toBe('user-session');
    });

    it('should create session error with custom status code', () => {
      const error = new SessionError('Session expired', 'EXPIRED', 'auth-session', 401);

      expect(error.statusCode).toBe(401);
      expect(error.code).toBe('SESSION_EXPIRED');
    });

    it('should create session error without session name', () => {
      const error = new SessionError('Cookie too large', 'SIZE_EXCEEDED');

      expect(error.sessionName).toBeUndefined();
      expect(error.sessionCode).toBe('SIZE_EXCEEDED');
    });
  });

  describe('ConfigError', () => {
    it('should create config error with default status code', () => {
      const error = new ConfigError('Missing required SAML issuer', 'saml.issuer');

      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(ConfigError);
      expect(error.name).toBe('ConfigError');
      expect(error.message).toBe('Missing required SAML issuer');
      expect(error.code).toBe('CONFIG_SAML.ISSUER_INVALID');
      expect(error.statusCode).toBe(500);
      expect(error.configField).toBe('saml.issuer');
    });

    it('should create config error with custom status code', () => {
      const error = new ConfigError('Invalid session secret format', 'session.secret', 400);

      expect(error.statusCode).toBe(400);
      expect(error.code).toBe('CONFIG_SESSION.SECRET_INVALID');
    });

    it('should handle config field name transformation', () => {
      const error = new ConfigError('Invalid callback URL', 'callback_url');

      expect(error.code).toBe('CONFIG_CALLBACK_URL_INVALID');
      expect(error.configField).toBe('callback_url');
    });
  });

  describe('NetworkError', () => {
    it('should create network error with default status code', () => {
      const originalError = new Error('Connection timeout');
      const error = new NetworkError('Failed to connect to IdP', 'saml_request', originalError);

      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(NetworkError);
      expect(error.name).toBe('NetworkError');
      expect(error.message).toBe('Failed to connect to IdP');
      expect(error.code).toBe('NETWORK_SAML_REQUEST_FAILED');
      expect(error.statusCode).toBe(503);
      expect(error.operation).toBe('saml_request');
      expect(error.originalError).toBe(originalError);
    });

    it('should create network error with custom status code', () => {
      const error = new NetworkError('Rate limited', 'api_call', undefined, 429);

      expect(error.statusCode).toBe(429);
      expect(error.code).toBe('NETWORK_API_CALL_FAILED');
    });

    it('should create network error without original error', () => {
      const error = new NetworkError('Generic network failure', 'fetch');

      expect(error.originalError).toBeUndefined();
      expect(error.operation).toBe('fetch');
    });

    it('should handle operation name transformation', () => {
      const error = new NetworkError('Test error', 'user-profile-fetch');

      expect(error.code).toBe('NETWORK_USER-PROFILE-FETCH_FAILED');
      expect(error.operation).toBe('user-profile-fetch');
    });
  });

  describe('Error inheritance and serialization', () => {
    it('should serialize error information correctly', () => {
      const samlError = new SAMLError('Test SAML error', 'TEST_CODE', 'test-issuer');

      // Test that error has the expected properties
      expect(samlError.name).toBe('SAMLError');
      expect(samlError.message).toBe('Test SAML error');
      expect(samlError.samlCode).toBe('TEST_CODE');
      expect(samlError.issuer).toBe('test-issuer');

      // Test JSON serialization includes custom properties
      const serialized = JSON.stringify(samlError);
      expect(serialized).toContain('TEST_CODE');
      expect(serialized).toContain('test-issuer');
    });

    it('should maintain error stack traces', () => {
      const configError = new ConfigError('Test config error', 'test.field');

      expect(configError.stack).toBeDefined();
      expect(configError.stack).toContain('ConfigError');
      expect(configError.stack).toContain('Test config error');
    });

    it('should work with instanceof checks', () => {
      const sessionError = new SessionError('Test session error', 'TEST');

      expect(sessionError instanceof Error).toBe(true);
      expect(sessionError instanceof AuthError).toBe(true);
      expect(sessionError instanceof SessionError).toBe(true);
      expect(sessionError instanceof SAMLError).toBe(false);
    });

    it('should have consistent error properties across types', () => {
      const errors = [
        new SAMLError('SAML error', 'TEST'),
        new SessionError('Session error', 'TEST'),
        new ConfigError('Config error', 'test'),
        new NetworkError('Network error', 'test')
      ];

      errors.forEach(error => {
        expect(error.message).toBeDefined();
        expect(error.code).toBeDefined();
        expect(error.statusCode).toBeDefined();
        expect(error.name).toBeDefined();
        expect(typeof error.statusCode).toBe('number');
        expect(error.statusCode >= 400).toBe(true);
        expect(error.statusCode < 600).toBe(true);
      });
    });
  });
});
