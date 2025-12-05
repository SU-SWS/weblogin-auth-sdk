# SealSession Utility Example

The `SessionManager.sealSession` static method allows you to generate encrypted cookie values for testing purposes without setting any HTTP headers.

## Basic Usage

```typescript
import { SessionManager, Session, User } from 'weblogin-auth-sdk';

// Create test session data
const testUser: User = {
  id: 'user123',
  email: 'test@stanford.edu',
  name: 'Test User'
};

const sessionData: Session = {
  user: testUser,
  meta: { role: 'admin', theme: 'dark' },
  issuedAt: Date.now(),
  expiresAt: 0 // Session cookie (expires when browser closes)
};

// Configuration (same as you'd use for SessionManager)
const sessionConfig = {
  name: 'my-session',
  secret: 'your-32-character-secret-key!!',
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const
  }
};

// Generate encrypted cookie value
const sealedCookie = await SessionManager.sealSession(sessionData, sessionConfig);
console.log('Sealed cookie value:', sealedCookie);
// Output: "Fe26...encrypted-iron-session-data..."
```

## Testing Usage

This is particularly useful for creating authenticated test requests:

```typescript
// In your test file
import { SessionManager } from 'weblogin-auth-sdk';

describe('Protected API Routes', () => {
  it('should allow access with valid session', async () => {
    // Create test session
    const sessionData = {
      user: { id: 'test-user', email: 'test@stanford.edu' },
      issuedAt: Date.now(),
      expiresAt: 0
    };

    // Generate encrypted cookie value
    const sealedCookie = await SessionManager.sealSession(sessionData, {
      name: 'auth-session',
      secret: process.env.SESSION_SECRET!
    });

    // Use in test request
    const response = await fetch('/api/protected-route', {
      headers: {
        'Cookie': `auth-session=${sealedCookie}`
      }
    });

    expect(response.status).toBe(200);
  });
});
```

## Integration Testing

You can also use this for integration tests where you need to simulate logged-in users:

```typescript
import request from 'supertest';
import { app } from '../app';
import { SessionManager } from 'weblogin-auth-sdk';

describe('User Dashboard', () => {
  it('should display user dashboard for admin users', async () => {
    // Create admin session
    const adminSession = {
      user: { 
        id: 'admin123', 
        email: 'admin@stanford.edu',
        name: 'Admin User' 
      },
      meta: { roles: ['admin'] },
      issuedAt: Date.now(),
      expiresAt: 0
    };

    const sessionCookie = await SessionManager.sealSession(adminSession, {
      name: 'app-session',
      secret: 'test-secret-32-characters-long!!'
    });

    const response = await request(app)
      .get('/dashboard')
      .set('Cookie', [`app-session=${sessionCookie}`])
      .expect(200);

    expect(response.text).toContain('Admin Dashboard');
  });
});
```

## Key Features

- **Framework Agnostic**: Works with any HTTP client or testing framework
- **Secure**: Uses the same iron-session encryption as the main SessionManager
- **Consistent**: Cookie values are compatible with SessionManager.getSession()
- **Flexible**: Supports all session configuration options
- **Testing Focused**: Perfect for unit tests, integration tests, and end-to-end tests

## Notes

- The secret must be at least 32 characters long (same requirement as SessionManager)
- The returned string is the encrypted cookie value, not the full cookie header
- Use the same configuration you would use for your production SessionManager
- The sealed session can be read by any SessionManager instance with the same secret and configuration
