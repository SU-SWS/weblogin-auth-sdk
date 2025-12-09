/* eslint-disable @typescript-eslint/no-explicit-any */
import { SessionManager, createExpressCookieStore, createWebCookieStore, isAuthenticated, CookieOptions } from '../src/session';
import { Session, User } from '../src/types';

// Mock iron-session
jest.mock('iron-session', () => ({
  getIronSession: jest.fn()
}));

const mockGetIronSession = jest.requireMock('iron-session').getIronSession;

describe('SessionManager', () => {
  let mockCookieStore: any;
  let sessionManager: SessionManager;
  let mockIronSession: any;

  const testUser: User = {
    id: 'user123',
    email: 'test@stanford.edu',
    name: 'Test User',
    suid: '123456789',
    encodedSUID: 'encoded123'
  };

  const testSessionConfig = {
    name: 'test-session',
    secret: 'test-secret-32-characters-long!!',
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax' as const,
      path: '/',
      maxAge: 86400
    }
  };

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock cookie store
    mockCookieStore = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn()
    };

    // Create mock iron session
    mockIronSession = {
      user: null,
      meta: null,
      issuedAt: null,
      expiresAt: null,
      save: jest.fn(),
      destroy: jest.fn()
    };

    mockGetIronSession.mockResolvedValue(mockIronSession);

    sessionManager = new SessionManager(mockCookieStore, testSessionConfig);
  });

  describe('constructor', () => {
    it('should create SessionManager with valid config', () => {
      expect(sessionManager).toBeInstanceOf(SessionManager);
    });

    it('should throw error for short secret', () => {
      expect(() => {
        new SessionManager(mockCookieStore, {
          ...testSessionConfig,
          secret: 'short'
        });
      }).toThrow('Session secret must be at least 32 characters long');
    });

    it('should use default cookie options', () => {
      const manager = new SessionManager(mockCookieStore, {
        name: 'test',
        secret: 'test-secret-32-characters-long!!'
      });
      expect(manager).toBeInstanceOf(SessionManager);
    });

    it('should merge custom cookie options with defaults', () => {
      const customConfig = {
        ...testSessionConfig,
        cookie: {
          httpOnly: false,
          secure: false,
          path: '/custom'
        }
      };
      const manager = new SessionManager(mockCookieStore, customConfig);
      expect(manager).toBeInstanceOf(SessionManager);
    });
  });

  describe('getSession', () => {
    it('should return null when no session cookie exists', async () => {
      mockCookieStore.get.mockReturnValue(null);

      const session = await sessionManager.getSession();

      expect(session).toBeNull();
      expect(mockCookieStore.get).toHaveBeenCalledWith('test-session');
    });

    it('should return valid session when cookie exists', async () => {
      const mockSession: Session = {
        user: testUser,
        meta: { roles: ['user'] },
        issuedAt: Date.now(),
        expiresAt: 0
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, mockSession);

      const session = await sessionManager.getSession();

      expect(session).toEqual(expect.objectContaining(mockSession));
      expect(mockGetIronSession).toHaveBeenCalled();
    });

    it('should return null and destroy expired session', async () => {
      const expiredSession: Session = {
        user: testUser,
        issuedAt: Date.now() - 1000,
        expiresAt: Date.now() - 500
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, expiredSession);

      const session = await sessionManager.getSession();

      expect(session).toBeNull();
      expect(mockIronSession.destroy).toHaveBeenCalled();
    });

    it('should handle iron-session errors gracefully', async () => {
      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      mockGetIronSession.mockRejectedValue(new Error('Decryption failed'));

      const session = await sessionManager.getSession();

      expect(session).toBeNull();
    });
  });

  describe('createSession', () => {
    it('should create new session with user data', async () => {
      const mockTime = 1640995200000;
      jest.spyOn(Date, 'now').mockReturnValue(mockTime);

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });

      const session = await sessionManager.createSession(testUser);

      expect(session).toEqual({
        user: testUser,
        meta: undefined,
        issuedAt: mockTime,
        expiresAt: 0
      });

      expect(mockIronSession.save).toHaveBeenCalled();
      expect(mockCookieStore.set).toHaveBeenCalledWith(
        'test-session-session',
        'true',
        expect.objectContaining({
          httpOnly: false,
          secure: true,
          sameSite: 'lax',
          path: '/'
        })
      );
    });

    it('should create session with metadata', async () => {
      const metadata = { theme: 'dark', language: 'en' };
      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });

      const session = await sessionManager.createSession(testUser, metadata);

      expect(session.meta).toEqual(metadata);
    });

    it('should handle creation errors', async () => {
      mockGetIronSession.mockRejectedValue(new Error('Session creation failed'));

      await expect(sessionManager.createSession(testUser)).rejects.toThrow('Session creation failed');
    });
  });

  describe('updateSession', () => {
    it('should update existing session', async () => {
      const existingSession: Session = {
        user: testUser,
        meta: { theme: 'light' },
        issuedAt: Date.now() - 1000,
        expiresAt: 0
      };

      const updates = {
        meta: { theme: 'dark', language: 'en' }
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, existingSession);

      const updatedSession = await sessionManager.updateSession(updates);

      expect(updatedSession).toEqual(expect.objectContaining({
        ...existingSession,
        ...updates
      }));
      expect(mockIronSession.save).toHaveBeenCalled();
    });

    it('should return null when no session exists', async () => {
      mockCookieStore.get.mockReturnValue(null);

      const result = await sessionManager.updateSession({ meta: { test: true } });

      expect(result).toBeNull();
    });

    it('should handle update errors', async () => {
      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, { user: testUser, issuedAt: Date.now(), expiresAt: 0 });
      mockIronSession.save.mockRejectedValue(new Error('Update failed'));

      await expect(sessionManager.updateSession({ meta: { test: true } })).rejects.toThrow();
    });
  });

  describe('destroySession', () => {
    it('should destroy session and both cookies', async () => {
      const existingSession: Session = {
        user: testUser,
        issuedAt: Date.now(),
        expiresAt: 0
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, existingSession);

      await sessionManager.destroySession();

      expect(mockIronSession.destroy).toHaveBeenCalled();
      expect(mockCookieStore.delete).toHaveBeenCalledWith('test-session-session');
    });

    it('should handle destroy errors', async () => {
      mockGetIronSession.mockRejectedValue(new Error('Destroy failed'));

      await expect(sessionManager.destroySession()).rejects.toThrow();
    });

    it('should work when cookie store has no delete method', async () => {
      const cookieStoreWithoutDelete = {
        get: jest.fn().mockReturnValue({ name: 'test-session', value: 'encrypted-value' }),
        set: jest.fn()
      };

      const manager = new SessionManager(cookieStoreWithoutDelete, testSessionConfig);
      Object.assign(mockIronSession, { user: testUser });

      await manager.destroySession();

      expect(mockIronSession.destroy).toHaveBeenCalled();
      // Should not throw error even without delete method
    });
  });

  describe('isAuthenticated', () => {
    it('should return true for valid session', async () => {
      const validSession: Session = {
        user: testUser,
        issuedAt: Date.now(),
        expiresAt: 0
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, validSession);

      const isAuth = await sessionManager.isAuthenticated();

      expect(isAuth).toBe(true);
    });

    it('should return false for no session', async () => {
      mockCookieStore.get.mockReturnValue(null);

      const isAuth = await sessionManager.isAuthenticated();

      expect(isAuth).toBe(false);
    });

    it('should return false for session without user', async () => {
      const invalidSession = {
        user: null,
        issuedAt: Date.now(),
        expiresAt: 0
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, invalidSession);

      const isAuth = await sessionManager.isAuthenticated();

      expect(isAuth).toBe(false);
    });
  });

  describe('getUser', () => {
    it('should return user from valid session', async () => {
      const validSession: Session = {
        user: testUser,
        issuedAt: Date.now(),
        expiresAt: 0
      };

      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, validSession);

      const user = await sessionManager.getUser();

      expect(user).toEqual(testUser);
    });

    it('should return null for no session', async () => {
      mockCookieStore.get.mockReturnValue(null);

      const user = await sessionManager.getUser();

      expect(user).toBeNull();
    });
  });

  describe('refreshSession', () => {
    it('should refresh session with new timestamp', async () => {
      const oldTime = Date.now() - 1000;
      const newTime = Date.now();

      const existingSession: Session = {
        user: testUser,
        issuedAt: oldTime,
        expiresAt: 0
      };

      jest.spyOn(Date, 'now').mockReturnValue(newTime);
      mockCookieStore.get.mockReturnValue({ name: 'test-session', value: 'encrypted-value' });
      Object.assign(mockIronSession, existingSession);

      const refreshed = await sessionManager.refreshSession();

      expect(refreshed?.issuedAt).toBe(newTime);
    });

    it('should return null when no session exists', async () => {
      mockCookieStore.get.mockReturnValue(null);

      const refreshed = await sessionManager.refreshSession();

      expect(refreshed).toBeNull();
    });
  });
});

describe('createExpressCookieStore', () => {
  let mockReq: any;
  let mockRes: any;

  beforeEach(() => {
    mockReq = {
      cookies: {
        'session': 'value1',
        'other': 'value2'
      }
    };

    mockRes = {
      cookie: jest.fn(),
      clearCookie: jest.fn()
    };
  });

  it('should create Express cookie store', () => {
    const store = createExpressCookieStore(mockReq, mockRes);

    expect(store).toBeDefined();
    expect(typeof store.get).toBe('function');
    expect(typeof store.set).toBe('function');
    expect(typeof store.delete).toBe('function');
  });

  it('should get cookie from Express request', () => {
    const store = createExpressCookieStore(mockReq, mockRes);

    const result = store.get('session');

    expect(result).toEqual({ name: 'session', value: 'value1' });
  });

  it('should return undefined for missing cookie', () => {
    const store = createExpressCookieStore(mockReq, mockRes);

    const result = store.get('missing');

    expect(result).toBeUndefined();
  });

  it('should set cookie via Express response', () => {
    const store = createExpressCookieStore(mockReq, mockRes);
    const options: CookieOptions = { httpOnly: true, secure: true };

    store.set('new-cookie', 'new-value', options);

    expect(mockRes.cookie).toHaveBeenCalledWith('new-cookie', 'new-value', options);
  });

  it('should delete cookie via Express response', () => {
    const store = createExpressCookieStore(mockReq, mockRes);

    store.delete!('session');

    expect(mockRes.clearCookie).toHaveBeenCalledWith('session');
  });

  it('should handle request without cookies', () => {
    const reqWithoutCookies = {};
    const store = createExpressCookieStore(reqWithoutCookies, mockRes);

    const result = store.get('any');

    expect(result).toBeUndefined();
  });
});

describe('createWebCookieStore', () => {
  let mockRequest: Request;
  let mockResponse: Response;

  beforeEach(() => {
    mockRequest = new Request('https://example.com', {
      headers: {
        'cookie': 'session=value1; other=value2'
      }
    });

    mockResponse = new Response();
  });

  it('should create Web API cookie store', () => {
    const store = createWebCookieStore(mockRequest, mockResponse);

    expect(store).toBeDefined();
    expect(typeof store.get).toBe('function');
    expect(typeof store.set).toBe('function');
  });

  it('should parse cookies from request headers', () => {
    const store = createWebCookieStore(mockRequest, mockResponse);

    const result = store.get('session');

    expect(result).toEqual({ name: 'session', value: 'value1' });
  });

  it('should handle request without cookie header', () => {
    const requestWithoutCookies = new Request('https://example.com');
    const store = createWebCookieStore(requestWithoutCookies, mockResponse);

    const result = store.get('any');

    expect(result).toBeUndefined();
  });

  it('should set cookie header on response', () => {
    const store = createWebCookieStore(mockRequest, mockResponse);

    store.set('new-cookie', 'new-value', {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 3600
    });

    const setCookieHeader = mockResponse.headers.get('set-cookie');
    expect(setCookieHeader).toContain('new-cookie=new-value');
    expect(setCookieHeader).toContain('HttpOnly');
    expect(setCookieHeader).toContain('Secure');
    expect(setCookieHeader).toContain('SameSite=lax');
    expect(setCookieHeader).toContain('Path=/');
    expect(setCookieHeader).toContain('Max-Age=3600');
  });

  it('should handle URL encoded cookie values', () => {
    const encodedRequest = new Request('https://example.com', {
      headers: {
        'cookie': 'encoded=hello%20world'
      }
    });

    const store = createWebCookieStore(encodedRequest, mockResponse);
    const result = store.get('encoded');

    expect(result).toEqual({ name: 'encoded', value: 'hello world' });
  });

  it('should set multiple cookies', () => {
    const store = createWebCookieStore(mockRequest, mockResponse);

    store.set('cookie1', 'value1');
    store.set('cookie2', 'value2');

    const setCookieHeader = mockResponse.headers.get('set-cookie');
    expect(setCookieHeader).toContain('cookie1=value1');
    expect(setCookieHeader).toContain('cookie2=value2');
  });
});

describe('isAuthenticated (client-side utility)', () => {
  const originalDocument = global.document;

  beforeEach(() => {
    // Mock document.cookie
    Object.defineProperty(global, 'document', {
      value: {
        cookie: ''
      },
      writable: true
    });
  });

  afterEach(() => {
    global.document = originalDocument;
  });

  it('should return false in non-browser environment', () => {
    delete (global as any).document;

    const result = isAuthenticated('test-session');

    expect(result).toBe(false);
  });

  it('should return true when session cookie exists', () => {
    global.document.cookie = 'test-session-session=true; other=value';

    const result = isAuthenticated('test-session');

    expect(result).toBe(true);
  });

  it('should return false when session cookie does not exist', () => {
    global.document.cookie = 'other=value';

    const result = isAuthenticated('test-session');

    expect(result).toBe(false);
  });

  it('should return false when session cookie is not true', () => {
    global.document.cookie = 'test-session-session=false';

    const result = isAuthenticated('test-session');

    expect(result).toBe(false);
  });

  it('should handle cookies with spaces', () => {
    global.document.cookie = ' test-session-session=true ; other=value ';

    const result = isAuthenticated('test-session');

    expect(result).toBe(true);
  });
});
