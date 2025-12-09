/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuthUtils, DefaultLogger } from '../src';

describe('AuthUtils', () => {
  describe('generateNonce', () => {
    it('should generate a nonce of default length', () => {
      const nonce = AuthUtils.generateNonce();
      expect(nonce).toHaveLength(64); // 32 bytes * 2 (hex)
      expect(nonce).toMatch(/^[a-f0-9]+$/);
    });

    it('should generate a nonce of specified length', () => {
      const nonce = AuthUtils.generateNonce(16);
      expect(nonce).toHaveLength(32); // 16 bytes * 2 (hex)
      expect(nonce).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('base64UrlEncode/Decode', () => {
    it('should encode and decode strings correctly', () => {
      const original = 'Hello, World! 123 🌍';
      const encoded = AuthUtils.base64UrlEncode(original);
      const decoded = AuthUtils.base64UrlDecode(encoded);

      expect(decoded).toBe(original);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });
  });

  describe('generateCSRFToken', () => {
    it('should generate a valid CSRF token', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(token).toHaveLength(64); // 32 bytes * 2 (hex)
      expect(token).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('validateCSRFToken', () => {
    it('should validate matching tokens', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken(token, token)).toBe(true);
    });

    it('should reject non-matching tokens', () => {
      const token1 = AuthUtils.generateCSRFToken();
      const token2 = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken(token1, token2)).toBe(false);
    });

    it('should reject empty tokens', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken('', token)).toBe(false);
      expect(AuthUtils.validateCSRFToken(token, '')).toBe(false);
    });
  });

  describe('sanitizeReturnTo', () => {
    const allowedOrigins = ['https://example.com', 'http://localhost:3000'];

    it('should allow same-origin URLs', () => {
      const result = AuthUtils.sanitizeReturnTo('https://example.com/path', allowedOrigins);
      expect(result).toBe('https://example.com/path');
    });

    it('should reject different origins', () => {
      const result = AuthUtils.sanitizeReturnTo('https://evil.com/path', allowedOrigins);
      expect(result).toBeNull();
    });

    it('should reject javascript: protocol', () => {
      const result = AuthUtils.sanitizeReturnTo('javascript:alert(1)', allowedOrigins);
      expect(result).toBeNull();
    });

    it('should reject malformed URLs', () => {
      const result = AuthUtils.sanitizeReturnTo('not-a-url', allowedOrigins);
      expect(result).toBeNull();
    });
  });
});

describe('DefaultLogger', () => {
  let logger: DefaultLogger;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new DefaultLogger(true); // verbose mode
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('should log structured messages', () => {
    logger.info('Test message', { key: 'value' });

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"level":"info"')
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"message":"Test message"')
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"key":"value"')
    );
  });

  it('should redact sensitive information', () => {
    logger.info('Test message', {
      password: 'secret123',
      token: 'abc123',
      publicInfo: 'visible'
    });

    const logCall = consoleSpy.mock.calls[0][0];
    expect(logCall).toContain('[REDACTED]');
    expect(logCall).toContain('visible');
    expect(logCall).not.toContain('secret123');
    expect(logCall).not.toContain('abc123');
  });

  it('should not log debug messages in non-verbose mode', () => {
    const nonVerboseLogger = new DefaultLogger(false);
    nonVerboseLogger.debug('Debug message');

    expect(consoleSpy).not.toHaveBeenCalled();
  });
});


