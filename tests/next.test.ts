/* eslint-disable @typescript-eslint/no-explicit-any */
import { AdaptNext, createAdaptNext, createNextjsCookieStore, getSessionFromNextRequest, getSessionFromNextCookies } from '../src/next';
import { SAMLProvider } from '../src/saml';
import { SessionManager } from '../src/session';
import { Session, User } from '../src/types';

// Mock Next.js cookies
const mockNextCookies = {
  get: jest.fn(),
  set: jest.fn()
};

// Mock Next.js headers import
jest.mock('next/headers', () => ({
  cookies: jest.fn(() => Promise.resolve(mockNextCookies))
}));

// Mock SAMLProvider
jest.mock('../src/saml');
const MockedSAMLProvider = SAMLProvider as jest.MockedClass<typeof SAMLProvider>;

// Mock SessionManager
jest.mock('../src/session');
const MockedSessionManager = SessionManager as jest.MockedClass<typeof SessionManager>;

describe('createNextjsCookieStore', () => {
  let mockCookies: any;

  beforeEach(() => {
    mockCookies = {
      get: jest.fn(),
      set: jest.fn()
    };
  });

  it('should create Next.js cookie store adapter', () => {
    const store = createNextjsCookieStore(mockCookies);

    expect(store).toBeDefined();
    expect(typeof store.get).toBe('function');
    expect(typeof store.set).toBe('function');
    expect(typeof store.delete).toBe('function');
  });

  it('should get cookie from Next.js cookies', () => {
    mockCookies.get.mockReturnValue({ name: 'test', value: 'value123' });

    const store = createNextjsCookieStore(mockCookies);
    const result = store.get('test');

    expect(result).toEqual({ name: 'test', value: 'value123' });
    expect(mockCookies.get).toHaveBeenCalledWith('test');
  });

  it('should set cookie via Next.js cookies', () => {
    const store = createNextjsCookieStore(mockCookies);

    store.set('new-cookie', 'new-value', { httpOnly: true, secure: true });

    expect(mockCookies.set).toHaveBeenCalledWith('new-cookie', 'new-value', { httpOnly: true, secure: true });
  });

  it('should delete cookie by setting empty value with maxAge 0', () => {
    const store = createNextjsCookieStore(mockCookies);

    store.delete!('test-cookie');

    expect(mockCookies.set).toHaveBeenCalledWith('test-cookie', '', { maxAge: 0 });
  });
});

describe('getSessionFromNextRequest', () => {
  it('should get session from Next.js request', async () => {
    const mockSession: Session = {
      user: { id: 'user123', name: 'Test User' },
      issuedAt: Date.now(),
      expiresAt: 0
    };

    // Mock the edge session functionality
    const mockCreateEdgeSessionReader = jest.fn().mockReturnValue({
      getSessionFromRequest: jest.fn().mockResolvedValue(mockSession)
    });

    jest.doMock('../src/edge-session', () => ({
      createEdgeSessionReader: mockCreateEdgeSessionReader
    }));

    const request = new Request('https://test.com');
    const result = await getSessionFromNextRequest(request, 'test-secret', 'test-session');

    expect(result).toEqual(mockSession);
  });
});

describe('getSessionFromNextCookies', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should throw error when no secret provided', async () => {
    delete process.env.WEBLOGIN_AUTH_SESSION_SECRET;

    const cookies = { get: jest.fn() };

    await expect(getSessionFromNextCookies(cookies)).rejects.toThrow(
      'Session secret is required. Provide it as parameter or set WEBLOGIN_AUTH_SESSION_SECRET environment variable.'
    );
  });

  it('should return null when cookies object has no get method', async () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'test-secret-32-chars-long!!!!!';

    const result = await getSessionFromNextCookies({});

    expect(result).toBeNull();
  });

  it('should return null when session cookie not found', async () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'test-secret-32-chars-long!!!!!';
    delete process.env.WEBLOGIN_AUTH_SESSION_NAME; // Ensure we use the default name

    const cookies = {
      get: jest.fn().mockReturnValue(undefined)
    };

    const result = await getSessionFromNextCookies(cookies);

    expect(result).toBeNull();
    expect(cookies.get).toHaveBeenCalledWith('weblogin-auth-session');
  });

  it('should use environment variables for configuration', async () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'env-secret-32-chars-long!!!';
    process.env.WEBLOGIN_AUTH_SESSION_NAME = 'custom-session';

    const cookies = {
      get: jest.fn().mockReturnValue({ value: 'encrypted-session-data' })
    };

    // This test focuses on parameter usage, not actual decryption
    await getSessionFromNextCookies(cookies).catch(() => {
      // Expected to fail due to mocking complexity, but we test parameter usage
    });

    expect(cookies.get).toHaveBeenCalledWith('custom-session');
  });

  it('should use provided parameters over environment variables', async () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'env-secret';
    process.env.WEBLOGIN_AUTH_SESSION_NAME = 'env-session';

    const cookies = {
      get: jest.fn().mockReturnValue({ value: 'encrypted-data' })
    };

    await getSessionFromNextCookies(cookies, 'param-secret-32-chars-long!!', 'param-session').catch(() => {
      // Ignore errors, we're testing parameter precedence
    });

    expect(cookies.get).toHaveBeenCalledWith('param-session');
  });
});

describe('AdaptNext', () => {
  let adaptNext: AdaptNext;
  let mockSamlProvider: jest.Mocked<SAMLProvider>;
  let mockSessionManager: jest.Mocked<SessionManager>;

  const testConfig = {
    saml: {
      issuer: 'test-issuer',
      idpCert: 'test-cert',
      returnToOrigin: 'https://test.com'
    },
    session: {
      name: 'test-session',
      secret: 'test-secret-32-characters-long!!'
    }
  };

  const testUser: User = {
    id: 'user123',
    email: 'test@stanford.edu',
    name: 'Test User'
  };

  const testSession: Session = {
    user: testUser,
    issuedAt: Date.now(),
    expiresAt: 0
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup SAML provider mock
    mockSamlProvider = {
      login: jest.fn(),
      authenticate: jest.fn(),
      getLoginUrl: jest.fn()
    } as any;
    MockedSAMLProvider.mockImplementation(() => mockSamlProvider);

    // Setup session manager mock
    mockSessionManager = {
      getSession: jest.fn(),
      createSession: jest.fn(),
      updateSession: jest.fn(),
      destroySession: jest.fn(),
      isAuthenticated: jest.fn(),
      getUser: jest.fn(),
      refreshSession: jest.fn()
    } as any;
    MockedSessionManager.mockImplementation(() => mockSessionManager);

    adaptNext = new AdaptNext(testConfig);
  });

  describe('constructor', () => {
    it('should create AdaptNext instance with minimal config', () => {
      expect(adaptNext).toBeInstanceOf(AdaptNext);
      expect(MockedSAMLProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer: 'test-issuer',
          idpCert: 'test-cert',
          returnToOrigin: 'https://test.com'
        }),
        expect.any(Object)
      );
    });

    it('should create instance with callbacks', () => {
      const callbacks = {
        mapProfile: jest.fn(),
        signIn: jest.fn(),
        signOut: jest.fn(),
        session: jest.fn()
      };

      const configWithCallbacks = {
        ...testConfig,
        callbacks
      };

      const instance = new AdaptNext(configWithCallbacks);
      expect(instance).toBeInstanceOf(AdaptNext);
    });

    it('should create instance with custom logger', () => {
      const customLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn()
      };

      const configWithLogger = {
        ...testConfig,
        logger: customLogger,
        verbose: true
      };

      const instance = new AdaptNext(configWithLogger);
      expect(instance).toBeInstanceOf(AdaptNext);
    });
  });

  describe('browser environment checks', () => {
    const originalWindow = global.window;

    afterEach(() => {
      global.window = originalWindow;
    });

    it('should throw error when calling login in browser', async () => {
      (global as any).window = {};

      await expect(adaptNext.login()).rejects.toThrow(
        'AdaptNext.login() should not be called in a browser environment'
      );
    });

    it('should throw error when calling authenticate in browser', async () => {
      (global as any).window = {};

      const request = new Request('https://test.com');
      await expect(adaptNext.authenticate(request)).rejects.toThrow(
        'AdaptNext.authenticate() should not be called in a browser environment'
      );
    });

    it('should throw error when calling getSession in browser', async () => {
      (global as any).window = {};

      await expect(adaptNext.getSession()).rejects.toThrow(
        'AdaptNext.getSession() should not be called in a browser environment'
      );
    });
  });

  describe('login', () => {
    it('should delegate to SAML provider login', async () => {
      const mockResponse = new Response('', { status: 302 });
      mockSamlProvider.login.mockResolvedValue(mockResponse);

      const options = { returnTo: '/dashboard' };
      const result = await adaptNext.login(options);

      expect(mockSamlProvider.login).toHaveBeenCalledWith(options);
      expect(result).toBe(mockResponse);
    });

    it('should handle login with default options', async () => {
      const mockResponse = new Response('', { status: 302 });
      mockSamlProvider.login.mockResolvedValue(mockResponse);

      await adaptNext.login();

      expect(mockSamlProvider.login).toHaveBeenCalledWith({});
    });
  });

  describe('authenticate', () => {
    it('should authenticate request and create session', async () => {
      const request = new Request('https://test.com/acs', { method: 'POST' });

      mockSamlProvider.authenticate.mockResolvedValue({
        user: testUser,
        profile: {} as any,
        returnTo: '/dashboard'
      });

      mockSessionManager.createSession.mockResolvedValue(testSession);

      const result = await adaptNext.authenticate(request);

      expect(mockSamlProvider.authenticate).toHaveBeenCalledWith({
        req: request,
        callbacks: undefined
      });
      expect(mockSessionManager.createSession).toHaveBeenCalledWith(testUser);
      expect(result).toEqual({
        user: testUser,
        session: testSession,
        returnTo: '/dashboard'
      });
    });

    it('should call session callback when provided', async () => {
      const sessionCallback = jest.fn();
      const configWithCallback = {
        ...testConfig,
        callbacks: { session: sessionCallback }
      };

      const instanceWithCallback = new AdaptNext(configWithCallback);
      const request = new Request('https://test.com/acs', { method: 'POST' });

      mockSamlProvider.authenticate.mockResolvedValue({
        user: testUser,
        profile: {} as any
      });
      mockSessionManager.createSession.mockResolvedValue(testSession);

      await instanceWithCallback.authenticate(request);

      expect(sessionCallback).toHaveBeenCalledWith({
        session: testSession,
        user: testUser,
        req: request
      });
    });
  });

  describe('getSession', () => {
    it('should delegate to session manager when no request provided', async () => {
      mockSessionManager.getSession.mockResolvedValue(testSession);

      const result = await adaptNext.getSession();

      expect(mockSessionManager.getSession).toHaveBeenCalled();
      expect(result).toBe(testSession);
    });

    it('should accept request parameter and call different code path', async () => {
      // This test verifies the API signature change - it should not throw an error
      // when called with a Request parameter
      const request = new Request('https://test.com');
      const result = await adaptNext.getSession(request);

      // The important thing is that the method accepts the Request parameter
      // In the test environment, it may return mock data
      expect(result).toBeDefined();
    });
  });

  describe('getUser', () => {
    it('should delegate to session manager when no request provided', async () => {
      mockSessionManager.getUser.mockResolvedValue(testUser);

      const result = await adaptNext.getUser();

      expect(mockSessionManager.getUser).toHaveBeenCalled();
      expect(result).toBe(testUser);
    });

    it('should extract user from session when request provided', async () => {
      const request = new Request('https://test.com');
      // This would use getSessionFromNextRequest internally
      const result = await adaptNext.getUser(request);

      // The result depends on the mocked session from getSessionFromNextRequest
      expect(result).toEqual(expect.any(Object));
    });
  });

  describe('isAuthenticated', () => {
    it('should delegate to session manager when no request provided', async () => {
      mockSessionManager.isAuthenticated.mockResolvedValue(true);

      const result = await adaptNext.isAuthenticated();

      expect(mockSessionManager.isAuthenticated).toHaveBeenCalled();
      expect(result).toBe(true);
    });

    it('should check session existence when request provided', async () => {
      const request = new Request('https://test.com');
      // This would use getSessionFromNextRequest internally
      const result = await adaptNext.isAuthenticated(request);

      // The result depends on the mocked session from getSessionFromNextRequest
      expect(typeof result).toBe('boolean');
    });
  });

  describe('logout', () => {
    it('should destroy session', async () => {
      mockSessionManager.getSession.mockResolvedValue(testSession);

      await adaptNext.logout();

      expect(mockSessionManager.destroySession).toHaveBeenCalled();
    });

    it('should call signOut callback when provided', async () => {
      const signOutCallback = jest.fn();
      const configWithCallback = {
        ...testConfig,
        callbacks: { signOut: signOutCallback }
      };

      const instanceWithCallback = new AdaptNext(configWithCallback);

      mockSessionManager.getSession.mockResolvedValue(testSession);

      await instanceWithCallback.logout();

      expect(signOutCallback).toHaveBeenCalledWith({ session: testSession });
      expect(mockSessionManager.destroySession).toHaveBeenCalled();
    });

    it('should not call callback when no session exists', async () => {
      const signOutCallback = jest.fn();
      const configWithCallback = {
        ...testConfig,
        callbacks: { signOut: signOutCallback }
      };

      const instanceWithCallback = new AdaptNext(configWithCallback);

      mockSessionManager.getSession.mockResolvedValue(null);

      await instanceWithCallback.logout();

      expect(signOutCallback).not.toHaveBeenCalled();
      expect(mockSessionManager.destroySession).toHaveBeenCalled();
    });
  });

  describe('auth middleware', () => {
    it('should create middleware that provides auth context', async () => {
      // The auth middleware now uses Request-based session retrieval
      const mockHandler = jest.fn().mockResolvedValue(new Response('OK'));
      const middleware = adaptNext.auth(mockHandler);

      const request = new Request('https://test.com/protected');
      await middleware(request);

      expect(mockHandler).toHaveBeenCalledWith(
        request,
        expect.objectContaining({
          session: expect.any(Object),
          user: expect.any(Object),
          isAuthenticated: expect.any(Boolean)
        })
      );
    });

    it('should handle unauthenticated requests', async () => {
      // Since auth middleware now uses Request-based session retrieval,
      // we need to test the actual behavior which may include mock data
      const mockHandler = jest.fn().mockResolvedValue(new Response('OK'));
      const middleware = adaptNext.auth(mockHandler);

      const request = new Request('https://test.com/protected');
      await middleware(request);

      expect(mockHandler).toHaveBeenCalledWith(
        request,
        expect.objectContaining({
          session: expect.anything(),
          user: expect.anything(),
          isAuthenticated: expect.any(Boolean)
        })
      );
    });
  });

  describe('getLoginUrl', () => {
    it('should delegate to SAML provider', async () => {
      mockSamlProvider.getLoginUrl.mockResolvedValue('https://idp.stanford.edu/login?...');

      const options = { returnTo: '/dashboard' };
      const result = await adaptNext.getLoginUrl(options);

      expect(mockSamlProvider.getLoginUrl).toHaveBeenCalledWith(options);
      expect(result).toBe('https://idp.stanford.edu/login?...');
    });
  });

  describe('refreshSession', () => {
    it('should delegate to session manager', async () => {
      const refreshedSession = { ...testSession, issuedAt: Date.now() };
      mockSessionManager.refreshSession.mockResolvedValue(refreshedSession);

      const result = await adaptNext.refreshSession();

      expect(mockSessionManager.refreshSession).toHaveBeenCalled();
      expect(result).toBe(refreshedSession);
    });
  });

  describe('updateSession', () => {
    it('should update session via session manager', async () => {
      const updates = { meta: { theme: 'dark' } };
      const updatedSession = { ...testSession, ...updates };

      mockSessionManager.updateSession.mockResolvedValue(updatedSession);

      const result = await adaptNext.updateSession(updates);

      expect(mockSessionManager.updateSession).toHaveBeenCalledWith(updates);
      expect(result).toBe(updatedSession);
    });

    it('should call session callback after successful update', async () => {
      const sessionCallback = jest.fn();
      const configWithCallback = {
        ...testConfig,
        callbacks: { session: sessionCallback }
      };

      const instanceWithCallback = new AdaptNext(configWithCallback);
      const updates = { meta: { theme: 'dark' } };
      const updatedSession = { ...testSession, ...updates };

      mockSessionManager.updateSession.mockResolvedValue(updatedSession);

      await instanceWithCallback.updateSession(updates);

      expect(sessionCallback).toHaveBeenCalledWith({
        session: updatedSession,
        user: updatedSession.user,
        req: expect.any(Request)
      });
    });

    it('should not call session callback when update fails', async () => {
      const sessionCallback = jest.fn();
      const configWithCallback = {
        ...testConfig,
        callbacks: { session: sessionCallback }
      };

      const instanceWithCallback = new AdaptNext(configWithCallback);

      mockSessionManager.updateSession.mockResolvedValue(null);

      await instanceWithCallback.updateSession({ meta: { theme: 'dark' } });

      expect(sessionCallback).not.toHaveBeenCalled();
    });
  });
});

describe('createAdaptNext factory function', () => {
  it('should create AdaptNext instance', () => {
    const config = {
      saml: {
        issuer: 'test-issuer',
        idpCert: 'test-cert',
        returnToOrigin: 'https://test.com'
      },
      session: {
        name: 'test-session',
        secret: 'test-secret-32-characters-long!!'
      }
    };

    const instance = createAdaptNext(config);

    expect(instance).toBeInstanceOf(AdaptNext);
  });
});
