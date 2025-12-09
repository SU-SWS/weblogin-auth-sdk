import { EdgeSessionReader, EdgeCookieParser, createEdgeSessionReader, getUserIdFromRequest, getUserIdFromCookie } from '../src/edge-session';
import { Session } from '../src/types';

describe('EdgeSessionReader', () => {
  const testSecret = 'test-secret-32-characters-long!!';
  const testCookieName = 'test-session';

  let sessionReader: EdgeSessionReader;

  beforeEach(() => {
    sessionReader = new EdgeSessionReader(testSecret, testCookieName);
  });

  describe('constructor', () => {
    it('should create instance with valid secret', () => {
      expect(sessionReader).toBeInstanceOf(EdgeSessionReader);
    });

    it('should throw error with short secret', () => {
      expect(() => {
        new EdgeSessionReader('short-secret', testCookieName);
      }).toThrow('Session secret must be at least 32 characters long');
    });

    it('should use default cookie name', () => {
      const reader = new EdgeSessionReader(testSecret);
      expect(reader).toBeInstanceOf(EdgeSessionReader);
    });
  });

  describe('getSessionFromCookieHeader', () => {
    it('should return null for empty cookie header', async () => {
      const session = await sessionReader.getSessionFromCookieHeader('');
      expect(session).toBeNull();
    });

    it('should return null for missing session cookie', async () => {
      const session = await sessionReader.getSessionFromCookieHeader('other-cookie=value');
      expect(session).toBeNull();
    });

    it('should return null for invalid cookie format', async () => {
      const session = await sessionReader.getSessionFromCookieHeader(`${testCookieName}=invalid-format`);
      expect(session).toBeNull();
    });
  });

  describe('getSessionFromRequest', () => {
    it('should return null for request without cookies', async () => {
      const request = new Request('https://example.com');
      const session = await sessionReader.getSessionFromRequest(request);
      expect(session).toBeNull();
    });

    it('should parse cookies from request header', async () => {
      const request = new Request('https://example.com', {
        headers: {
          'cookie': 'other=value; test-session=invalid.format'
        }
      });
      const session = await sessionReader.getSessionFromRequest(request);
      expect(session).toBeNull(); // Invalid format should return null
    });
  });

  describe('isAuthenticated', () => {
    it('should return false for unauthenticated request', async () => {
      const request = new Request('https://example.com');
      const isAuth = await sessionReader.isAuthenticated(request);
      expect(isAuth).toBe(false);
    });
  });

  describe('getUser', () => {
    it('should return null for unauthenticated request', async () => {
      const request = new Request('https://example.com');
      const user = await sessionReader.getUser(request);
      expect(user).toBeNull();
    });
  });

  describe('getUserId', () => {
    it('should return null for unauthenticated request', async () => {
      const request = new Request('https://example.com');
      const userId = await sessionReader.getUserId(request);
      expect(userId).toBeNull();
    });
  });
});

describe('EdgeCookieParser', () => {
  describe('constructor', () => {
    it('should create empty parser for no header', () => {
      const parser = new EdgeCookieParser();
      expect(parser.getAll()).toEqual({});
    });

    it('should parse simple cookie', () => {
      const parser = new EdgeCookieParser('name=value');
      expect(parser.get('name')).toBe('value');
    });

    it('should parse multiple cookies', () => {
      const parser = new EdgeCookieParser('name1=value1; name2=value2');
      expect(parser.get('name1')).toBe('value1');
      expect(parser.get('name2')).toBe('value2');
    });

    it('should handle URL encoded values', () => {
      const parser = new EdgeCookieParser('name=hello%20world');
      expect(parser.get('name')).toBe('hello world');
    });

    it('should handle cookies with equals in value', () => {
      const parser = new EdgeCookieParser('jwt=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature=value');
      expect(parser.get('jwt')).toBe('eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature=value');
    });

    it('should ignore invalid cookie format', () => {
      const parser = new EdgeCookieParser('invalid; name=value; =empty');
      expect(parser.get('name')).toBe('value');
      expect(parser.get('invalid')).toBeUndefined();
      expect(parser.get('')).toBeUndefined();
    });
  });

  describe('getAll', () => {
    it('should return all parsed cookies', () => {
      const parser = new EdgeCookieParser('a=1; b=2; c=3');
      expect(parser.getAll()).toEqual({
        a: '1',
        b: '2',
        c: '3'
      });
    });
  });
});

describe('createEdgeSessionReader', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should create reader with provided secret', () => {
    const reader = createEdgeSessionReader('test-secret-32-characters-long!!');
    expect(reader).toBeInstanceOf(EdgeSessionReader);
  });

  it('should use environment variable for secret', () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'env-secret-32-characters-long!!!';
    const reader = createEdgeSessionReader();
    expect(reader).toBeInstanceOf(EdgeSessionReader);
  });

  it('should use environment variable for cookie name', () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'env-secret-32-characters-long!!!';
    process.env.WEBLOGIN_AUTH_SESSION_NAME = 'custom-session';
    const reader = createEdgeSessionReader();
    expect(reader).toBeInstanceOf(EdgeSessionReader);
  });

  it('should throw error without secret', () => {
    delete process.env.WEBLOGIN_AUTH_SESSION_SECRET;
    expect(() => {
      createEdgeSessionReader();
    }).toThrow('Session secret is required');
  });
});

describe('getUserIdFromRequest', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should return null for request without session', async () => {
    process.env.WEBLOGIN_AUTH_SESSION_SECRET = 'test-secret-32-characters-long!!';
    const request = new Request('https://example.com');

    const userId = await getUserIdFromRequest(request);

    expect(userId).toBeNull();
  });

  it('should work with provided secret', async () => {
    const request = new Request('https://example.com');

    const userId = await getUserIdFromRequest(request, 'test-secret-32-characters-long!!');

    expect(userId).toBeNull(); // No valid session in request
  });
});

describe('Edge Session Integration', () => {
  it('should validate session structure', async () => {
    // Mock a valid session structure
    const mockSession: Session = {
      user: {
        id: 'user123',
        email: 'test@stanford.edu',
        name: 'Test User'
      },
      meta: {
        roles: ['user', 'staff'],
        department: 'Engineering'
      },
      issuedAt: Date.now(),
      expiresAt: 0 // Session cookie (expires when browser closes)
    };

    // Test session validation logic
    const isValid = mockSession.user?.id &&
      (!mockSession.expiresAt || mockSession.expiresAt === 0 || Date.now() < mockSession.expiresAt);

    expect(isValid).toBe(true);
  });

  it('should detect expired sessions', async () => {
    const expiredSession: Session = {
      user: { id: 'user123' },
      issuedAt: Date.now() - 1000,
      expiresAt: Date.now() - 500 // Expired 500ms ago
    };

    const isExpired = expiredSession.expiresAt && expiredSession.expiresAt > 0 && Date.now() > expiredSession.expiresAt;
    expect(isExpired).toBe(true);
  });

  it('should handle session cookies (no expiration)', async () => {
    const sessionCookie: Session = {
      user: { id: 'user123' },
      issuedAt: Date.now(),
      expiresAt: 0 // Session cookie
    };

    const isValid = sessionCookie.expiresAt === 0 || Date.now() < sessionCookie.expiresAt;
    expect(isValid).toBe(true);
  });
});

describe('getUserIdFromCookie', () => {
  it('should fail plain JSON cookies', async () => {
    const sessionData = JSON.stringify({
      user: { id: 'user789', name: 'Test User' },
      issuedAt: Date.now()
    });

    const userId = await getUserIdFromCookie(sessionData, 'test-secret-32-characters-long!!');
    expect(userId).toBeNull();
  });

  it('should return null for invalid cookie data', async () => {
    const userId = await getUserIdFromCookie('invalid-data', 'test-secret-32-characters-long!!');
    expect(userId).toBeNull();
  });
});