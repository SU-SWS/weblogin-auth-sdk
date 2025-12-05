import { SessionManager } from '../src/session';
import { Session, User } from '../src/types';

describe('SessionManager.sealSession', () => {
  const testUser: User = {
    id: 'user123',
    email: 'test@stanford.edu',
    name: 'Test User',
    suid: '123456789',
    encodedSUID: 'encoded123'
  };

  const testSessionData: Session = {
    user: testUser,
    meta: { roles: ['user'], theme: 'dark' },
    issuedAt: Date.now(),
    expiresAt: 0
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

  it('should seal session data into encrypted cookie value', async () => {
    const sealedValue = await SessionManager.sealSession(testSessionData, testSessionConfig);

    expect(sealedValue).toBeDefined();
    expect(typeof sealedValue).toBe('string');
    expect(sealedValue.length).toBeGreaterThan(0);

    // The sealed value should be different from the original data (encrypted)
    expect(sealedValue).not.toContain(testUser.id);
    expect(sealedValue).not.toContain(testUser.email);
  });

  it('should throw error for short secret', async () => {
    const configWithShortSecret = {
      ...testSessionConfig,
      secret: 'short'
    };

    await expect(
      SessionManager.sealSession(testSessionData, configWithShortSecret)
    ).rejects.toThrow('Session secret must be at least 32 characters long');
  });

  it('should work with minimal session config', async () => {
    const minimalConfig = {
      name: 'minimal-session',
      secret: 'minimal-secret-32-characters-long!'
    };

    const sealedValue = await SessionManager.sealSession(testSessionData, minimalConfig);

    expect(sealedValue).toBeDefined();
    expect(typeof sealedValue).toBe('string');
    expect(sealedValue.length).toBeGreaterThan(0);
  });

  it('should work with session data without metadata', async () => {
    const sessionWithoutMeta: Session = {
      user: testUser,
      issuedAt: Date.now(),
      expiresAt: 0
    };

    const sealedValue = await SessionManager.sealSession(sessionWithoutMeta, testSessionConfig);

    expect(sealedValue).toBeDefined();
    expect(typeof sealedValue).toBe('string');
    expect(sealedValue.length).toBeGreaterThan(0);
  });

  it('should work with custom cookie options', async () => {
    const customConfig = {
      ...testSessionConfig,
      cookie: {
        httpOnly: false,
        secure: false,
        sameSite: 'strict' as const,
        path: '/custom',
        maxAge: 3600,
        domain: 'example.com'
      }
    };

    const sealedValue = await SessionManager.sealSession(testSessionData, customConfig);

    expect(sealedValue).toBeDefined();
    expect(typeof sealedValue).toBe('string');
    expect(sealedValue.length).toBeGreaterThan(0);
  });

  it('should create different sealed values for different session data', async () => {
    const sessionData1: Session = {
      user: { id: 'user1', email: 'user1@test.com' },
      issuedAt: Date.now(),
      expiresAt: 0
    };

    const sessionData2: Session = {
      user: { id: 'user2', email: 'user2@test.com' },
      issuedAt: Date.now(),
      expiresAt: 0
    };

    const sealed1 = await SessionManager.sealSession(sessionData1, testSessionConfig);
    const sealed2 = await SessionManager.sealSession(sessionData2, testSessionConfig);

    expect(sealed1).not.toEqual(sealed2);
  });

  it('should create different sealed values for different secrets', async () => {
    const config1 = { ...testSessionConfig, secret: 'secret-1-must-be-32-characters-long!' };
    const config2 = { ...testSessionConfig, secret: 'secret-2-must-be-32-characters-long!' };

    const sealed1 = await SessionManager.sealSession(testSessionData, config1);
    const sealed2 = await SessionManager.sealSession(testSessionData, config2);

    expect(sealed1).not.toEqual(sealed2);
  });

  it('should include all session properties in sealed value', async () => {
    const complexSessionData: Session = {
      user: {
        id: 'complex-user',
        email: 'complex@stanford.edu',
        name: 'Complex User',
        suid: '987654321',
        encodedSUID: 'encoded987',
        customField: 'custom-value'
      },
      meta: {
        roles: ['admin', 'editor'],
        permissions: { read: true, write: true, delete: false },
        preferences: {
          theme: 'dark',
          language: 'en',
          timezone: 'America/Los_Angeles'
        },
        lastActivity: Date.now()
      },
      issuedAt: Date.now() - 1000,
      expiresAt: Date.now() + 86400000
    };

    const sealedValue = await SessionManager.sealSession(complexSessionData, testSessionConfig);

    expect(sealedValue).toBeDefined();
    expect(typeof sealedValue).toBe('string');
    expect(sealedValue.length).toBeGreaterThan(0);

    // Verify it's actually encrypted (shouldn't contain readable data)
    expect(sealedValue).not.toContain('complex-user');
    expect(sealedValue).not.toContain('complex@stanford.edu');
    expect(sealedValue).not.toContain('admin');
    expect(sealedValue).not.toContain('dark');
  });

  it('should create sealed value compatible with SessionManager', async () => {
    // Create a sealed value using the static method
    const sealedValue = await SessionManager.sealSession(testSessionData, testSessionConfig);

    // Create a simple cookie store that returns this sealed value
    const cookieStore = {
      get: (name: string) => {
        if (name === testSessionConfig.name) {
          return { name, value: sealedValue };
        }
        return undefined;
      },
      set: () => {},
      delete: () => {}
    };

    // Create a SessionManager and see if it can read the sealed session
    const sessionManager = new SessionManager(cookieStore, testSessionConfig);
    const retrievedSession = await sessionManager.getSession();

    // The session should be readable and contain the original data
    expect(retrievedSession).toBeDefined();
    expect(retrievedSession?.user.id).toBe(testUser.id);
    expect(retrievedSession?.user.email).toBe(testUser.email);
    expect(retrievedSession?.meta).toEqual(testSessionData.meta);
  });
});