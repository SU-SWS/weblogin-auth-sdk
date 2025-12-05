# Next.js App Router Example

This example shows how to integrate Weblogin Auth SDK with Next.js App Router using the built-in Next.js adapter.

## Setup

### 1. Install Dependencies

```bash
npm install weblogin-auth-sdk
```

### 2. Environment Variables

```bash
# .env.local
WEBLOGIN_AUTH_SAML_ENTITY=your-entity-id
WEBLOGIN_AUTH_SAML_CERT=your-certificate-string
WEBLOGIN_AUTH_SAML_RETURN_ORIGIN=http://localhost:3000
WEBLOGIN_AUTH_SESSION_SECRET=your-32-character-secret-key-min
```

### 3. Configuration

```typescript
// lib/auth.ts
import { createWebLoginNext } from 'weblogin-auth-sdk/next';

export const auth = createWebLoginNext({
  saml: {
    issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
    idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT!,
    returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,
  },
  session: {
    name: 'weblogin-auth-session',
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
    cookie: {
      maxAge: 60 * 60 * 24 * 7, // 1 week
    },
  },
  verbose: process.env.NODE_ENV === 'development',
});
```

## Usage Patterns

The Weblogin Auth SDK provides two ways to access session data in Next.js:

### 1. Server Components & Server Actions
In Server Components and Server Actions, call session methods without parameters:

```typescript
// Server Component
export default async function MyPage() {
  const session = await auth.getSession(); // No parameters
  const user = await auth.getUser();       // No parameters
  const isAuth = await auth.isAuthenticated(); // No parameters
  
  // Use session data...
}
```

### 2. API Routes & Middleware  
In API routes and middleware, always pass the `Request` object:

```typescript
// API route
export async function GET(request: Request) {
  const session = await auth.getSession(request); // Pass request
  const user = await auth.getUser(request);       // Pass request
  const isAuth = await auth.isAuthenticated(request); // Pass request
  
  // Use session data...
}

// Middleware
export function middleware(request: NextRequest) {
  const session = await auth.getSession(request); // Pass request
  // ...
}
```

The SDK automatically handles the different contexts and cookie access patterns.

## Authentication Routes

### Login Route

```typescript
// app/api/auth/login/route.ts
import { auth } from '@/lib/auth';

export async function GET(request: Request) {
  const url = new URL(request.url);
  const returnTo = url.searchParams.get('returnTo') || '/';

  return auth.login({ returnTo });
}
```

### Callback Route (ACS)

```typescript
// app/api/auth/acs/route.ts
import { auth } from '@/lib/auth';

export async function POST(request: Request) {
  return auth.handleCallback(request);
}
```

### Logout Route

```typescript
// app/api/auth/logout/route.ts
import { auth } from '@/lib/auth';

export async function POST(request: Request) {
  return auth.logout(request);
}
```

### Session Info Route

```typescript
// app/api/auth/session/route.ts
import { auth } from '@/lib/auth';

export async function GET(request: Request) {
  const session = await auth.getSession(request);

  if (!session) {
    return Response.json({ user: null }, { status: 401 });
  }

  return Response.json({
    user: session.user,
    meta: session.meta,
  });
}
```

## Server Components

### Protected Page

```typescript
// app/protected/page.tsx
import { redirect } from 'next/navigation';
import { auth } from '@/lib/auth';

export default async function ProtectedPage() {
  // In Server Components, use getSession() without parameters
  // It will automatically use Next.js cookies() internally
  const session = await auth.getSession();

  if (!session) {
    redirect('/api/auth/login?returnTo=/protected');
  }

  return (
    <div>
      <h1>Protected Page</h1>
      <p>Welcome, {session.user.name || session.user.email}!</p>
      <p>User ID: {session.user.id}</p>

      {session.user.imageUrl && (
        <img src={session.user.imageUrl} alt="Profile" width={64} height={64} />
      )}

      <form action="/api/auth/logout" method="post">
        <button type="submit">Logout</button>
      </form>
    </div>
  );
}
```

### User Profile Component

```typescript
// components/UserProfile.tsx
import { auth } from '@/lib/auth';

export default async function UserProfile() {
  // In Server Components, use getSession() without parameters
  const session = await auth.getSession();

  if (!session) {
    return (
      <div>
        <a href="/api/auth/login">Sign In</a>
      </div>
    );
  }

  return (
    <div className="user-profile">
      <h3>Welcome back!</h3>
      <p>{session.user.name || session.user.email}</p>
      <form action="/api/auth/logout" method="post">
        <button type="submit">Sign Out</button>
      </form>
    </div>
  );
}
```

## Client Components

### Login Button

```typescript
// components/LoginButton.tsx
'use client';

export default function LoginButton() {
  const handleLogin = () => {
    // Capture current URL for returnTo
    const returnTo = encodeURIComponent(window.location.pathname);
    window.location.href = `/api/auth/login?returnTo=${returnTo}`;
  };

  return (
    <button onClick={handleLogin} className="login-btn">
      Sign In with Stanford
    </button>
  );
}
```

### Session Hook

```typescript
// hooks/useSession.ts
'use client';

import { useState, useEffect } from 'react';

interface User {
  id: string;
  email?: string;
  name?: string;
  imageUrl?: string;
}

interface SessionData {
  user: User | null;
  loading: boolean;
  error?: string;
}

export function useSession(): SessionData {
  const [session, setSession] = useState<SessionData>({
    user: null,
    loading: true,
  });

  useEffect(() => {
    fetch('/api/auth/session')
      .then(async (res) => {
        if (res.ok) {
          const data = await res.json();
          setSession({ user: data.user, loading: false });
        } else {
          setSession({ user: null, loading: false });
        }
      })
      .catch((error) => {
        setSession({
          user: null,
          loading: false,
          error: error.message
        });
      });
  }, []);

  return session;
}
```

### Client Session Component

```typescript
// components/ClientSession.tsx
'use client';

import { useSession } from '@/hooks/useSession';

export default function ClientSession() {
  const { user, loading, error } = useSession();

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  if (!user) {
    return (
      <div>
        <p>You are not signed in.</p>
        <button onClick={() => window.location.href = '/api/auth/login'}>
          Sign In
        </button>
      </div>
    );
  }

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      window.location.reload();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <div>
      <h3>Signed in as {user.name || user.email}</h3>
      <p>User ID: {user.id}</p>
      <button onClick={handleLogout}>Sign Out</button>
    </div>
  );
}
```

## Middleware (Optional)

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';

export async function middleware(request: NextRequest) {
  // Only protect specific routes
  if (request.nextUrl.pathname.startsWith('/protected')) {
    // In middleware, always pass the request object
    const session = await auth.getSession(request);

    if (!session) {
      const loginUrl = new URL('/api/auth/login', request.url);
      loginUrl.searchParams.set('returnTo', request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/protected/:path*', '/admin/:path*'],
};
```

## Layout with Authentication

```typescript
// app/layout.tsx
import UserProfile from '@/components/UserProfile';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <header>
          <nav>
            <div>My App</div>
            <UserProfile />
          </nav>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
```

## Advanced Features

### Custom Callbacks

```typescript
// lib/auth.ts
import { createWebLoginNext } from 'weblogin-auth-sdk';

export const auth = createWebLoginNext({
  saml: {
    issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
    idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT!,
    returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,
  },
  session: {
    name: 'weblogin-auth-session',
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
  },
  callbacks: {
    async mapProfile(profile) {
      // Custom profile mapping
      return {
        id: profile.nameID,
        email: profile.email || profile.mail,
        name: profile.displayName || `${profile.givenName} ${profile.sn}`,
        imageUrl: profile.picture,
        department: profile.department,
        roles: profile.roles?.split(',') || [],
      };
    },
    async session({ session, user }) {
      // Add custom session data
      return {
        ...session,
        meta: {
          ...session.meta,
          lastLogin: new Date().toISOString(),
          userAgent: 'Next.js App',
        },
      };
    },
  },
});
```

### Role-Based Access

```typescript
// lib/auth-utils.ts
import { auth } from './auth';

export async function requireRole(request: Request, role: string) {
  const session = await auth.getSession(request);

  if (!session) {
    throw new Error('Not authenticated');
  }

  const userRoles = session.meta?.roles as string[] || [];

  if (!userRoles.includes(role)) {
    throw new Error(`Missing required role: ${role}`);
  }

  return session;
}

// Usage in API route
// app/api/admin/users/route.ts
import { requireRole } from '@/lib/auth-utils';

export async function GET(request: Request) {
  try {
    const session = await requireRole(request, 'admin');

    // Admin-only logic here
    return Response.json({ users: [] });
  } catch (error) {
    return Response.json(
      { error: error.message },
      { status: 403 }
    );
  }
}
```

## Testing

### Mocking Authentication in Tests

```typescript
// __tests__/auth.test.ts
import { createMocks } from 'node-mocks-http';
import { auth } from '@/lib/auth';

// Mock session for testing
jest.mock('@/lib/auth', () => ({
  auth: {
    getSession: jest.fn(),
  },
}));

describe('Authentication', () => {
  it('should handle authenticated requests', async () => {
    const mockSession = {
      user: { id: '123', email: 'test@stanford.edu' },
      meta: {},
      issuedAt: Date.now(),
      expiresAt: Date.now() + 86400000,
    };

    (auth.getSession as jest.Mock).mockResolvedValue(mockSession);

    const { req } = createMocks({ method: 'GET' });
    const session = await auth.getSession(req);

    expect(session?.user.id).toBe('123');
  });
});
