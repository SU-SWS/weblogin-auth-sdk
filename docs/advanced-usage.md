# Advanced Usage

This document covers advanced features and integration patterns for the Weblogin Auth SDK.

## Custom Session Management

### Session Enhancement

Add custom metadata to sessions safely during authentication:

```typescript
callbacks: {
  session: async ({ session, user, req }) => {
    // Add metadata while respecting cookie size limits
    const userRoles = await getUserRoles(user.id);
    const tenantInfo = await getTenantInfo(user.id);

    return {
      ...session,
      meta: {
        roles: userRoles.map(r => r.id), // Store IDs, not full objects
        tenantId: tenantInfo.id,
        lastActivity: Date.now(),
        userAgent: req.headers.get('user-agent')?.substring(0, 100), // Truncate
      }
    };
  }
}
```

### Dynamic Session Updates

Use the `updateSession` method to modify session data after initial authentication:

```typescript
// Update user preferences
export async function updateUserPreferences(request: Request, preferences: any) {
  const session = await auth.getSession(request);
  if (!session) return null;

  return await auth.updateSession({
    meta: {
      ...session.meta,
      preferences,
      lastUpdated: Date.now(),
    }
  });
}

// Update user profile information
export async function updateUserProfile(request: Request, profileUpdates: Partial<User>) {
  const session = await auth.getSession(request);
  if (!session) return null;

  return await auth.updateSession({
    user: {
      ...session.user,
      ...profileUpdates,
    },
    meta: {
      ...session.meta,
      profileUpdated: Date.now(),
    }
  });
}
```

### Session Size Management

For a safe maximum, you should never exceed 4KB per cookie.
Keep sessions under the recommended size limit while updating:

```typescript
// Monitor and optimize session size
export async function updateSessionSafely(request: Request, updates: Partial<Session>) {
  const session = await auth.getSession(request);
  if (!session) return null;

  // Estimate size of updates (assumes UTF-8 and mostly alphabetical characters)
  const estimatedSize = JSON.stringify({ ...session, ...updates }).length;

  if (estimatedSize > 3500) { // Cookie size threshold
    console.warn('Session update may exceed size limit', {
      currentSize: JSON.stringify(session).length,
      estimatedSize,
      userId: session.user.id
    });

    // Trim older metadata if needed
    const trimmedMeta = trimSessionMetadata(session.meta);
    updates.meta = { ...trimmedMeta, ...updates.meta };
  }

  return await auth.updateSession(updates);
}
```

### Testing with Sealed Sessions

For testing purposes, you can create encrypted cookie values without setting HTTP headers using the `SessionManager.sealSession` static method:

```typescript
import { SessionManager, Session, User } from 'weblogin-auth-sdk';

// Create test session data
const testUser: User = {
  id: 'test-user-123',
  email: 'test@stanford.edu',
  name: 'Test User'
};

const testSession: Session = {
  user: testUser,
  meta: { roles: ['admin'], theme: 'dark' },
  issuedAt: Date.now(),
  expiresAt: 0 // Session cookie
};

const sessionConfig = {
  name: 'auth-session',
  secret: 'your-32-character-secret-key!!',
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const
  }
};

// Generate encrypted cookie value for testing
const sealedCookie = await SessionManager.sealSession(testSession, sessionConfig);

// Use in test requests
const response = await fetch('/api/protected-route', {
  headers: {
    'Cookie': `auth-session=${sealedCookie}`
  }
});
```

This is particularly useful for:
- **Unit Testing**: Creating authenticated test requests
- **Integration Testing**: Simulating different user roles and permissions
- **End-to-End Testing**: Setting up test scenarios with pre-authenticated users

### Custom Cookie Stores

Implement custom cookie storage for specialized frameworks:

```typescript
import { CookieStore } from 'weblogin-auth-sdk';

class CustomCookieStore implements CookieStore {
  constructor(private context: YourFrameworkContext) {}

  async get(name: string): Promise<string | undefined> {
    return this.context.cookies.get(name);
  }

  async set(name: string, value: string, options: any): Promise<void> {
    this.context.cookies.set(name, value, options);
  }

  async delete(name: string): Promise<void> {
    this.context.cookies.delete(name);
  }
}

// Use with SessionManager
const cookieStore = new CustomCookieStore(context);
const sessionManager = new SessionManager(cookieStore, sessionConfig);
```

## Advanced SAML Configuration

### Generating Service Provider Metadata

You can generate the SAML Service Provider metadata XML for your application, which is often required when registering your SP with an Identity Provider.

```typescript
// Generate metadata without certificates
const metadata = samlProvider.getMetadata();

// Generate metadata with encryption and signing certificates
const metadataWithCerts = samlProvider.getMetadata(
  fs.readFileSync('decryption-cert.pem', 'utf8'),
  fs.readFileSync('signing-cert.pem', 'utf8')
);
```

### Custom Attribute Mapping

Map complex SAML attributes to your user model:

```typescript
callbacks: {
  mapProfile: async (profile) => {
    // Handle multiple attribute formats
    const getAttr = (key: string) => {
      const value = profile[key];
      return Array.isArray(value) ? value[0] : value;
    };

    return {
      id: getAttr('encodedSUID'),
      email: `${getAttr('userName')}@stanford.edu`,
      name: `${getAttr('firstName')} ${getAttr('lastName')}`,

      // Map Stanford-specific attributes
      suid: getAttr('suid'),
      userName: getAttr('userName'),
      encodedSUID: getAttr('encodedSUID'),

      // Oracle-specific attributes
      sessionId: getAttr('oracle:cloud:identity:sessionid'),
    };
  }
}
```

## Error Handling and Recovery

### Comprehensive Error Handling

```typescript
import { AuthError, SAMLError, SessionError } from 'weblogin-auth-sdk';

export async function handleAuthRequest(request: Request) {
  try {
    return await auth.handleCallback(request);
  } catch (error) {
    if (error instanceof SAMLError) {
      // SAML-specific errors (signature validation, etc.)
      logger.error('SAML validation failed', {
        code: error.code,
        message: error.message,
        samlIssuer: error.issuer,
      });

      return new Response('Authentication failed', { status: 401 });
    }

    if (error instanceof SessionError) {
      // Session-related errors (encryption, size, etc.)
      logger.error('Session error', {
        code: error.code,
        sessionName: error.sessionName,
      });

      // Clear potentially corrupted session
      return auth.logout(request);
    }

    if (error instanceof AuthError) {
      // General authentication errors
      logger.error('Authentication error', error);
      return new Response('Authentication failed', { status: 401 });
    }

    // Unexpected errors
    logger.error('Unexpected authentication error', error);
    return new Response('Internal error', { status: 500 });
  }
}
```

## Advanced Routing Patterns

### Middleware Composition

```typescript
// Next.js middleware with authentication
import { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // Public routes
  if (request.nextUrl.pathname.startsWith('/public')) {
    return;
  }

  // Auth routes
  if (request.nextUrl.pathname.startsWith('/api/auth')) {
    return;
  }

  // Protected routes
  const session = await auth.getSession(request);

  if (!session) {
    const loginUrl = new URL('/api/auth/login', request.url);
    loginUrl.searchParams.set('returnTo', request.url);
    return Response.redirect(loginUrl);
  }

  // Do more validation here...
}
```

## Logging and Monitoring

### Custom Logger Implementation

```typescript
import { Logger } from 'weblogin-auth-sdk';

class ApplicationLogger implements Logger {
  constructor(
    private winston: any, // Your winston instance
    private sentryLogger: any // Your Sentry instance
  ) {}

  debug(message: string, meta?: any): void {
    this.winston.debug(message, meta);
  }

  info(message: string, meta?: any): void {
    this.winston.info(message, meta);

    // Send important events to monitoring
    if (meta?.event === 'signin' || meta?.event === 'signout') {
      this.sentryLogger.addBreadcrumb({
        message,
        category: 'auth',
        data: meta,
      });
    }
  }

  warn(message: string, meta?: any): void {
    this.winston.warn(message, meta);
    this.sentryLogger.captureMessage(message, 'warning');
  }

  error(message: string, error?: any): void {
    this.winston.error(message, error);
    this.sentryLogger.captureException(error || new Error(message));
  }
}

// Use custom logger
const auth = createWebLoginNext({
  // ... config
  logger: new ApplicationLogger(winston, Sentry),
});
```
