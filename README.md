# Weblogin Auth SDK

**Version 3**

A framework-agnostic TypeScript authentication library for Stanford Pass SAML integration. 
Designed for serverless, stateless environments with security-first defaults and cookie-only sessions.

## Features

- **Framework Agnostic**: Works with Next.js, Express.js, and any Web API framework
- **TypeScript First**: Complete TypeScript implementation with strict typing
- **Security Focused**: Encrypted sessions, CSRF protection
- **Serverless Ready**: Cookie-only sessions, no server-side storage required
- **Edge Compatible**: Session validation in edge functions for ultra-fast performance
- **Developer Friendly**: Simple API inspired by Auth.js patterns

## Quick Start

### Installation

```bash
npm install weblogin-auth-sdk
```

### Basic Usage (Next.js)

```typescript
// lib/auth.ts
import { createWebLoginNext, idps } from 'weblogin-auth-sdk';

export const auth = createWebLoginNext({
  saml: {
    issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
    // Use the production IdP preset
    entryPoint: idps.prod.entryPoint,
    idpCert: idps.prod.cert,
    returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,
  },
  session: {
    name: 'weblogin-auth',
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
  },
});
```

### Basic Usage (Framework-Agnostic)

```typescript
// For other frameworks or custom implementations
import { SAMLProvider, SessionManager, createWebCookieStore, idps } from 'weblogin-auth-sdk';

const samlProvider = new SAMLProvider({
  issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
  // Use the production IdP preset
  entryPoint: idps.prod.entryPoint,
  idpCert: idps.prod.cert,
  returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,
});

const sessionManager = new SessionManager(
  createWebCookieStore(req, res),
  { 
    name: 'weblogin-auth',
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!
  }
);
```

#### Optional Configuration

The SDK uses sensible defaults, but you can customize any behavior:

```typescript
export const auth = createWebLoginNext({
  saml: {
    // Required
    issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
    idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT!,
    returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,

    // Optional - customize as needed
    serviceProviderLoginUrl: 'https://custom.stanford.edu/api/sso/login',
    returnToPath: '/custom/callback',
    includeReturnTo: true,
    privateKey: process.env.WEBLOGIN_AUTH_SAML_PRIVATE_KEY,
    decryptionPvk: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    acceptedClockSkewMs: 60000, // 1 minute
    allowCreate: false,
    additionalParams: { custom: 'value' },
    additionalAuthorizeParams: { prompt: 'login' },
  },
  session: {
    // Required
    name: 'weblogin-auth',  // Creates 'weblogin-auth' (main) and 'weblogin-auth-session' (JS) cookies
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,

    // Optional - customize as needed
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 86400, // 1 day
    },
    cookieSizeThreshold: 3500,
  },

  // Optional global settings
  logger: customLogger,
  verbose: process.env.NODE_ENV === 'development',
});
```

```typescript
// app/api/auth/login/route.ts
export async function GET() {
  return auth.login({ returnTo: '/dashboard' });
}

// app/api/auth/callback/route.ts
export async function POST(request: Request) {
  const { user, session, returnTo } = await auth.authenticate(request);
  const redirectUrl = returnTo || '/dashboard';
  return Response.redirect(redirectUrl);
}

// app/api/auth/logout/route.ts
export async function POST() {
  await auth.logout();
  return Response.redirect('/login');
}
```

## Documentation

📚 **[Getting Started](./docs/getting-started.md)** - Installation and basic setup for Next.js and Express.js

⚙️ **[Configuration](./docs/configuration.md)** - Complete configuration reference and environment variables

🔒 **[Security](./docs/security.md)** - Security features, best practices, and threat protection

⚡ **[Edge Functions](./docs/edge-functions.md)** - Ultra-fast session validation in edge environments

🚀 **[Advanced Usage](./docs/advanced-usage.md)** - Custom implementations, performance optimization, and advanced patterns

📖 **[API Reference](./docs/api-reference.md)** - Complete API documentation with examples

🔄 **[Migration Guide](./docs/migration.md)** - Migrating from v1.x and other authentication libraries

## Environment Variables

Set these required environment variables:

```bash
WEBLOGIN_AUTH_SAML_ENTITY="your-saml-entity-id"
WEBLOGIN_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----..."
WEBLOGIN_AUTH_SAML_RETURN_ORIGIN="https://your-app.com"
WEBLOGIN_AUTH_SESSION_SECRET="your-32-character-minimum-secret"
```

## Key Features

### Security First
- SAML 2.0 signature validation
- Encrypted cookie sessions
- CSRF protection

### Developer Experience
- TypeScript-first with strict typing
- Framework-agnostic design
- Simple, intuitive API
- Comprehensive error handling
- Detailed logging with automatic PII redaction

### Production Ready
- Serverless/stateless architecture
- Cookie-only sessions (no server storage)
- Comprehensive test coverage

## Quick Examples

### Getting User Session

```typescript
const session = await auth.getSession();
if (session) {
  console.log('User:', session.user.name);
  console.log('Authenticated:', await auth.isAuthenticated());
}
```

### Updating Session Data

```typescript
// Add custom metadata to session
await auth.updateSession({
  meta: {
    theme: 'dark',
    language: 'en',
    lastVisited: '/dashboard',
    preferences: { notifications: true }
  }
});

// Update user information in session
const currentSession = await auth.getSession();
await auth.updateSession({
  user: {
    ...currentSession?.user,
    displayName: 'John Doe',
    avatar: '/images/avatar.jpg'
  }
});
```

### Client-Side Authentication Check

```typescript
// Check authentication status in browser JavaScript
import { isAuthenticated } from 'weblogin-auth-sdk/session';

if (isAuthenticated('weblogin-auth')) {
  console.log('User is authenticated');
} else {
  window.location.href = '/api/auth/login';
}
```

### Protecting Routes

```typescript
// Next.js middleware
export async function middleware(request: NextRequest) {
  const session = await auth.getSession(request);
  if (!session && request.nextUrl.pathname.startsWith('/protected')) {
    return Response.redirect(new URL('/api/auth/login', request.url));
  }
}
```

### Custom Profile Mapping

```typescript
const auth = createWebLoginNext({
  // ... config
  callbacks: {
    mapProfile: async (profile) => ({
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
      department: profile.department,
    }),
  },
});
```

### Edge Function Session Validation

```typescript
// Ultra-fast session checking in edge functions
import { isAuthenticatedEdge } from 'weblogin-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  const isAuthenticated = await isAuthenticatedEdge(request);
  if (!isAuthenticated && request.nextUrl.pathname.startsWith('/protected')) {
    return Response.redirect(new URL('/api/auth/login', request.url));
  }
}

export const config = { runtime: 'edge' };
```

## License

GNU Version 3 License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## Security

Security issues should be reported privately. Please do not open public GitHub issues for security vulnerabilities.

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issues](https://github.com/su-sws/weblogin-auth-sdk/issues)
