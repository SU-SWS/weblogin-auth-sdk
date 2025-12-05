# Netlify Edge Functions Usage Examples

This directory contains examples of how to use the Weblogin Auth SDK in Netlify edge functions for fast session validation.

## Key Concepts

### Session Checking in Edge Functions

The SDK provides `createEdgeSessionReader` for checking sessions in edge environments:

- **Read-only**: Can decrypt and validate existing sessions
- **No Dependencies**: Uses only Web APIs (crypto, btoa/atob)
- **Optimized for Netlify**: Fast session validation at the edge

### Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│  Netlify    │────│  Node.js    │
│             │    │    Edge     │    │   Server    │
│             │    │             │    │             │
│ UI + Cookie │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │             │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Authentication Flow

1. **Login**: User redirected to Node.js server for SAML authentication
2. **Session Creation**: Node.js server creates encrypted session cookie
3. **Edge Validation**: Netlify edge functions validate session cookie without Node.js
4. **Performance**: Fast session checks at the edge, close to users

## Examples

### Netlify Edge Function

```typescript
// netlify/edge-functions/auth-check.ts
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  const sessionReader = createEdgeSessionReader(
    Deno.env.get('WEBLOGIN_AUTH_SESSION_SECRET')!
  );

  const isAuthenticated = await sessionReader.isAuthenticated(request);

  if (!isAuthenticated) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const userId = await sessionReader.getUserId(request);

  return Response.json({
    authenticated: true,
    userId,
  });
}

export const config = {
  path: "/api/auth-check",
};
```

### Netlify Edge Function for Protected Routes

```typescript
// netlify/edge-functions/protect.ts
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  const url = new URL(request.url);

  // Only protect certain paths
  if (!url.pathname.startsWith('/protected')) {
    return; // Continue to next function/origin
  }

  const sessionReader = createEdgeSessionReader(
    Deno.env.get('WEBLOGIN_AUTH_SESSION_SECRET')!
  );

  const isAuthenticated = await sessionReader.isAuthenticated(request);

  if (!isAuthenticated) {
    // Redirect to login
    return Response.redirect(new URL('/api/auth/login', request.url).toString());
  }

  // User is authenticated, continue
  return;
}

export const config = {
  path: "/protected/*",
};
```

### Get User ID for Logging or Analytics

```typescript
// netlify/edge-functions/analytics.ts
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  const sessionReader = createEdgeSessionReader(
    Deno.env.get('WEBLOGIN_AUTH_SESSION_SECRET')!
  );

  // Get just the user ID for logging/analytics
  const userId = await sessionReader.getUserId(request);

  if (userId) {
    // Log user activity
    console.log(`User ${userId} accessed ${request.url}`);

    // Add user ID to response headers for downstream services
    const response = await context.next();
    response.headers.set('X-User-ID', userId);
    return response;
  }

  // Continue without user tracking for anonymous users
  return await context.next();
}

export const config = {
  path: "/*",
};
```
