# Migration Guide

This guide helps you migrate between major versions of the Weblogin Auth SDK.

## Migrating from v2.x to v3.0

Version 3.0 introduces built-in Identity Provider (IdP) presets for easier configuration.

### IdP Configuration

Instead of manually copying certificates and entry points, you can now use the `idps` export:

```typescript
// v2.x
const auth = createWebLoginNext({
  saml: {
    issuer: 'my-app',
    entryPoint: 'https://login.stanford.edu/...',
    idpCert: 'MIIDnzCCAoegAwIBAgIJAJl9YtyaxKsZMA0GCSqGSIb3DQEBBQUAMGYxCzAJBgNV...',
    // ...
  }
});

// v3.0
import { createWebLoginNext, idps } from 'weblogin-auth-sdk';

const auth = createWebLoginNext({
  saml: {
    issuer: 'my-app',
    // Use presets for entryPoint and idpCert
    entryPoint: idps.prod.entryPoint,
    idpCert: idps.prod.cert,
    // ...
  }
});
```

## Migrating from v1.x to v2.0

Weblogin Auth SDK v2.0 introduces significant architectural improvements:

- **Framework Agnostic**: Works with any framework (Next.js, Express, etc.)
- **Cookie-Only Sessions**: No server-side session storage required
- **Enhanced Security**: Built-in CSRF protection and URL sanitization
- **Modern TypeScript**: Full TypeScript rewrite with strict typing
- **Simplified API**: Cleaner, more intuitive interfaces

## Breaking Changes

### 1. Package Installation

```bash
# Remove v1.x
npm uninstall weblogin-auth-sdk@1.x

# Install v2.0
npm install weblogin-auth-sdk@^2.0
```

### 2. Import Changes

```typescript
// v1.x
import { WebLoginAuth } from 'weblogin-auth-sdk';

// v2.0
import { createWebLoginNext } from 'weblogin-auth-sdk/next';
// or for other frameworks
import { SAMLProvider, SessionManager } from 'weblogin-auth-sdk';
```

### 3. Configuration Structure

```typescript
// v1.x
const auth = new WebLoginAuth({
  entityId: 'your-entity',
  certificate: 'cert-data',
  sessionSecret: 'secret',
});

// v2.0
const auth = createWebLoginNext({
  saml: {
    issuer: 'your-entity',
    idpCert: 'cert-data',
    returnToOrigin: 'https://your-app.com',
  },
  session: {
    name: 'weblogin-auth',
    secret: 'secret',
  },
});
```

### 4. Environment Variables

Update your environment variable names:

This section provides a detailed mapping of environment variables from v1.x to v2.0, including which variables are still used, renamed, or no longer needed.

### Required Variables (Must Be Set)

| v1.x Variable | v2.0 Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `WEBLOGIN_AUTH_SAML_ENTITY` | `WEBLOGIN_AUTH_SAML_ENTITY` | ✅ **Same** | SAML entity ID (required) |
| `WEBLOGIN_AUTH_SAML_CERT` | `WEBLOGIN_AUTH_SAML_CERT` | ✅ **Same** | IdP certificate (required) |
| `WEBLOGIN_AUTH_SESSION_SECRET` | `WEBLOGIN_AUTH_SESSION_SECRET` | ✅ **Same** | Session encryption secret (required) |
| `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN` | `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN` | ✅ **Same** | Application base URL (required) |
| `WEBLOGIN_AUTH_SESSION_EXPIRES_IN` | `WEBLOGIN_AUTH_SESSION_EXPIRES_IN` | ✅ **Same** | Sessions default to expire when browser closes |


### Optional Variables (Still Supported)

| v1.x Variable | v2.0 Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `WEBLOGIN_AUTH_SAML_SP_URL` | `WEBLOGIN_AUTH_SAML_SP_URL` | ✅ **Same** | Service Provider login URL |
| `WEBLOGIN_AUTH_SAML_RETURN_PATH` | `WEBLOGIN_AUTH_SAML_RETURN_PATH` | ✅ **Same** | ACS path component |
| `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY` | `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY` | ✅ **Same** | Private key for decryption |
| `WEBLOGIN_AUTH_SESSION_NAME` | `WEBLOGIN_AUTH_SESSION_NAME` | ✅ **Same** | Session cookie name |

### Deprecated Variables (No Longer Used)

| v1.x Variable | v2.0 Equivalent | Status | Migration Notes |
|---------------|-----------------|--------|-----------------|
| `WEBLOGIN_AUTH_SAML_RETURN_URL` | *Not used* | ❌ **Removed** | Use `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN` + `WEBLOGIN_AUTH_SAML_RETURN_PATH` |
| `WEBLOGIN_AUTH_SESSION_LOGOUT_URL` | *Application logic* | ❌ **Removed** | Handle logout redirects in your app |
| `WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL` | *Application logic* | ❌ **Removed** | Handle unauthorized redirects in your app |

### 5. API Methods

All methods are now asynchronous:

```typescript
// v1.x
auth.login(req, res);
auth.callback(req, res);
const user = auth.getUser(req);

// v2.0
await auth.login(request);
await auth.authenticate(request);
const session = await auth.getSession(request);
const user = session?.user;
```

### Handling Removed Functionality

**Logout URL (`WEBLOGIN_AUTH_SESSION_LOGOUT_URL`)**
```typescript
// v1.x: Automatic redirect after logout
WEBLOGIN_AUTH_SESSION_LOGOUT_URL="/login"

// v2.0: Handle in your logout route
export async function POST(request: Request) {
  await auth.logout(request);
  return Response.redirect('/login'); // Handle redirect in your code
}
```

**Unauthorized URL (`WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL`)**
```typescript
// v1.x: Automatic redirect for unauthorized requests
WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL="/unauthorized"

// v2.0: Handle in middleware or route handlers
export async function GET(request: Request) {
  const session = await auth.getSession(request);
  if (!session) {
    return Response.redirect('/unauthorized'); // Handle in your code
  }
  // ... continue with protected logic
}
```
