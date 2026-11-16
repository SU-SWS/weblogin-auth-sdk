# Migration Guide

This guide helps you migrate between major versions of the Weblogin Auth SDK.

## Migrating from v3.x to v4.0

Version 4.0 upgrades the session library, iron-session, from v8 to v9. Your configuration and API calls do not change. Check these three things:

### 1. Node.js 22.13 or later

The SDK now requires Node.js 22.13 or later (previously 18). iron-session v9 ships only ES modules, and the SDK's CommonJS build relies on Node's support for `require()` of ES modules, added in 22.13.

```json
{
  "engines": {
    "node": ">=22.13.0"
  }
}
```

### 2. Do not store `Date` objects in session data

Session data must be plain JSON. Saving a session that contains a `Date` now throws an error. Previously the `Date` was silently converted to a string.

```typescript
// v3.x: worked, but you got a string back when reading the session
await sessionManager.updateSession({
  meta: { lastLogin: new Date() }
});

// v4.0: store a timestamp (or an ISO string)
await sessionManager.updateSession({
  meta: { lastLogin: Date.now() }
});
```

This applies to anything you put in `meta`, whether through `createSession`, `updateSession`, `SessionManager.sealSession`, or a `session` callback. `Map`, `Set`, `BigInt` and functions are also rejected.

### 3. `getSession()` returns `null` for unreadable cookies

When a session cookie is present but cannot be decrypted (invalid, tampered with, or sealed with a different secret), `SessionManager.getSession()` now returns `null`. It used to return an empty object with no `user`.

If you already check for `null`, nothing changes. Code that assumed a non-null session always had a user no longer crashes on those cookies:

```typescript
const session = await sessionManager.getSession();
if (!session) {
  // No session, expired session, or unreadable cookie
}
```

`isAuthenticated()` and `getUser()` behave as before.

### Existing sessions keep working

Cookies created by v3.x remain valid after upgrading, so users stay signed in. Cookies created by v4.0 are also readable by v3.x, so you can roll back a deploy without signing everyone out.

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
    // name is optional, defaults to 'weblogin-auth'
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
| `WEBLOGIN_AUTH_SESSION_EXPIRES_IN` | `WEBLOGIN_AUTH_SESSION_EXPIRES_IN` | ✅ **Same** | Cookie max-age in seconds; omit for session cookies (expires when browser closes) |


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
