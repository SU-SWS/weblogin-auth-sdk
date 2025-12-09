import { DefaultLogger, ConsoleLogger, SilentLogger } from '../src/logger';

describe('DefaultLogger', () => {
  let logger: DefaultLogger;
  let consoleLogSpy: jest.SpyInstance;

  beforeEach(() => {
    // DefaultLogger uses console.log for all output
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe('constructor', () => {
    it('should create logger with verbose=false by default', () => {
      logger = new DefaultLogger();

      logger.debug('test debug message');

      expect(consoleLogSpy).not.toHaveBeenCalled();
    });

    it('should create logger with verbose=true when specified', () => {
      logger = new DefaultLogger(true);

      logger.debug('test debug message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"debug"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"test debug message"')
      );
    });
  });

  describe('debug logging', () => {
    it('should not log debug messages when verbose=false', () => {
      logger = new DefaultLogger(false);

      logger.debug('debug message');

      expect(consoleLogSpy).not.toHaveBeenCalled();
    });

    it('should log debug messages when verbose=true', () => {
      logger = new DefaultLogger(true);

      logger.debug('debug message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"debug"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"debug message"')
      );
    });

    it('should log debug messages with metadata when verbose=true', () => {
      logger = new DefaultLogger(true);
      const meta = { userId: 'user123', action: 'login' };

      logger.debug('debug message', meta);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.level).toBe('debug');
      expect(logData.message).toBe('debug message');
      expect(logData.userId).toBe('user123');
      expect(logData.action).toBe('login');
    });
  });

  describe('info logging', () => {
    it('should always log info messages', () => {
      logger = new DefaultLogger(false);

      logger.info('info message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"info"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"info message"')
      );
    });

    it('should log info messages with metadata', () => {
      logger = new DefaultLogger();
      const meta = { event: 'user_login', timestamp: Date.now() };

      logger.info('info message', meta);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.level).toBe('info');
      expect(logData.message).toBe('info message');
      expect(logData.event).toBe('user_login');
      expect(logData.timestamp).toEqual(meta.timestamp);
    });

    it('should log info messages when verbose=true', () => {
      logger = new DefaultLogger(true);

      logger.info('info message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"info"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"info message"')
      );
    });
  });

  describe('warn logging', () => {
    it('should always log warn messages', () => {
      logger = new DefaultLogger(false);

      logger.warn('warning message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"warn"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"warning message"')
      );
    });

    it('should log warn messages with metadata', () => {
      logger = new DefaultLogger();
      const meta = { code: 'INVALID_TOKEN', details: 'Token expired' };

      logger.warn('warning message', meta);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.level).toBe('warn');
      expect(logData.message).toBe('warning message');
      expect(logData.code).toBe('INVALID_TOKEN');
      expect(logData.details).toBe('Token expired');
    });
  });

  describe('error logging', () => {
    it('should always log error messages', () => {
      logger = new DefaultLogger(false);

      logger.error('error message');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"level":"error"')
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('"message":"error message"')
      );
    });

    it('should log error messages with metadata', () => {
      logger = new DefaultLogger();
      const meta = { error: 'AUTH_FAILED', stack: 'Error stack trace' };

      logger.error('error message', meta);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.level).toBe('error');
      expect(logData.message).toBe('error message');
      expect(logData.error).toBe('AUTH_FAILED');
      expect(logData.stack).toBe('Error stack trace');
    });
  });

  describe('context setting', () => {
    it('should include context in log messages', () => {
      logger = new DefaultLogger();
      logger.setContext('req-123', 'user-456');

      logger.info('test message');

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.requestId).toBe('req-123');
      expect(logData.userId).toBe('user-456');
    });
  });

  describe('secret redaction', () => {
    it('should redact sensitive information', () => {
      logger = new DefaultLogger();
      const sensitiveData = {
        password: 'secret123',
        token: 'bearer-token',
        cookieValue: 'session-cookie-encrypted-content',
        normalData: 'not-secret'
      };

      logger.info('test message', sensitiveData);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.password).toBe('[REDACTED]');
      expect(logData.token).toBe('[REDACTED]');
      expect(logData.cookieValue).toBe('[REDACTED]');
      expect(logData.normalData).toBe('not-secret');
    });

    it('should NOT redact cookie metadata (names, sizes, options)', () => {
      logger = new DefaultLogger();
      const cookieMetadata = {
        cookieName: 'weblogin-auth',
        mainCookieName: 'weblogin-auth',
        jsCookieName: 'weblogin-auth-session',
        cookieSize: 1234,
        mainCookie: 'weblogin-auth',
        jsCookie: 'weblogin-auth-session',
        cookieOptions: { httpOnly: true, secure: true }
      };

      logger.info('test message', cookieMetadata);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      // Cookie metadata should NOT be redacted
      expect(logData.cookieName).toBe('weblogin-auth');
      expect(logData.mainCookieName).toBe('weblogin-auth');
      expect(logData.jsCookieName).toBe('weblogin-auth-session');
      expect(logData.cookieSize).toBe(1234);
      expect(logData.mainCookie).toBe('weblogin-auth');
      expect(logData.jsCookie).toBe('weblogin-auth-session');
      expect(logData.cookieOptions).toEqual({ httpOnly: true, secure: true });
    });

    it('should redact certificate data with hash', () => {
      logger = new DefaultLogger();
      const certData = {
        cert: '-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----',
        normalData: 'not-secret'
      };

      logger.info('test message', certData);

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.cert).toMatch(/^\[CERT_HASH:[a-f0-9]+\]$/);
      expect(logData.normalData).toBe('not-secret');
    });
  });

  describe('JSON output format', () => {
    it('should output valid JSON', () => {
      logger = new DefaultLogger();

      logger.info('test message', { key: 'value' });

      const logCall = consoleLogSpy.mock.calls[0][0];

      expect(() => JSON.parse(logCall)).not.toThrow();

      const logData = JSON.parse(logCall);
      expect(logData).toHaveProperty('timestamp');
      expect(logData).toHaveProperty('level', 'info');
      expect(logData).toHaveProperty('message', 'test message');
      expect(logData).toHaveProperty('key', 'value');
    });

    it('should include ISO timestamp', () => {
      logger = new DefaultLogger();

      logger.info('test message');

      const logCall = consoleLogSpy.mock.calls[0][0];
      const logData = JSON.parse(logCall);

      expect(logData.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });
  });
});

describe('ConsoleLogger', () => {
  let logger: ConsoleLogger;
  let consoleDebugSpy: jest.SpyInstance;
  let consoleInfoSpy: jest.SpyInstance;
  let consoleWarnSpy: jest.SpyInstance;
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new ConsoleLogger();
    consoleDebugSpy = jest.spyOn(console, 'debug').mockImplementation();
    consoleInfoSpy = jest.spyOn(console, 'info').mockImplementation();
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleDebugSpy.mockRestore();
    consoleInfoSpy.mockRestore();
    consoleWarnSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  it('should log debug messages with prefix', () => {
    logger.debug('debug message', { key: 'value' });

    expect(consoleDebugSpy).toHaveBeenCalledWith('[DEBUG]', 'debug message', { key: 'value' });
  });

  it('should log info messages with prefix', () => {
    logger.info('info message', { key: 'value' });

    expect(consoleInfoSpy).toHaveBeenCalledWith('[INFO]', 'info message', { key: 'value' });
  });

  it('should log warn messages with prefix', () => {
    logger.warn('warn message', { key: 'value' });

    expect(consoleWarnSpy).toHaveBeenCalledWith('[WARN]', 'warn message', { key: 'value' });
  });

  it('should log error messages with prefix', () => {
    logger.error('error message', { key: 'value' });

    expect(consoleErrorSpy).toHaveBeenCalledWith('[ERROR]', 'error message', { key: 'value' });
  });
});

describe('SilentLogger', () => {
  let logger: SilentLogger;
  let consoleDebugSpy: jest.SpyInstance;
  let consoleInfoSpy: jest.SpyInstance;
  let consoleWarnSpy: jest.SpyInstance;
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new SilentLogger();
    consoleDebugSpy = jest.spyOn(console, 'debug').mockImplementation();
    consoleInfoSpy = jest.spyOn(console, 'info').mockImplementation();
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleDebugSpy.mockRestore();
    consoleInfoSpy.mockRestore();
    consoleWarnSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  it('should not log any messages', () => {
    logger.debug();
    logger.info();
    logger.warn();
    logger.error();

    expect(consoleDebugSpy).not.toHaveBeenCalled();
    expect(consoleInfoSpy).not.toHaveBeenCalled();
    expect(consoleWarnSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });
});
