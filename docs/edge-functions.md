# Edge Functions Compatibility

This document details how to use the Weblogin Auth SDK in edge function environments where Node.js APIs are not available.

## Overview

The Weblogin Auth SDK provides **hybrid architecture support** where:

- **SAML authentication** runs on Node.js servers (full feature support)
- **Session validation** runs in edge functions (fast, lightweight)

This gives you the best of both worlds: secure SAML processing where it works best, and ultra-fast session checking at the edge.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│    Edge     │────│  Node.js    │
│             │    │  Function   │    │   Server    │
│             │    │             │    │             │
│ UI + Cookie │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │ (Read-only) │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Edge-Compatible Features

### ✅ What Works in Edge Functions

- **Session Reading**: Decrypt and validate existing sessions
- **Authentication Checks**: Fast user authentication validation
- **Cookie Parsing**: Parse and validate session cookies
- **CSRF Token Validation**: Validate CSRF tokens
- **Return URL Processing**: Process return URLs from RelayState

### ❌ What Requires Node.js

- **SAML Processing**: XML parsing, signature validation, certificate handling
- **Session Creation**: Creating new encrypted session cookies
- **Database Operations**: User lookups, audit logging
- **Complex Authentication Logic**: Multi-factor auth, custom providers

## Edge Session Reader

The `EdgeSessionReader` class provides lightweight session validation:

### Key Features

- **Zero Dependencies**: Uses only Web APIs (crypto, btoa/atob)
- **Iron-Session Compatible**: Can decrypt sessions created by the main SDK
- **Framework Agnostic**: Works with any edge function platform
- **Security Focused**: Same security standards as the main SDK

### Basic Usage

```typescript
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

// Create reader with session secret
const sessionReader = createEdgeSessionReader(
  process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
  'weblogin-auth' // cookie name
);

// Check authentication from Request
const isAuthenticated = await sessionReader.isAuthenticated(request);

// Get user from session
const user = await sessionReader.getUser(request);

// Get user ID
const userId = await sessionReader.getUserId(request);
```

## Platform-Specific Examples

### Next.js Edge Middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  let userId;

  // Create reader with session secret
  const sessionReader = createEdgeSessionReader(
    process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
    'weblogin-auth' // cookie name
  );

  try {
    isAuthenticated = await sessionReader.isAuthenticated(req);
    if (isAuthenticated) {
      userId = await sessionReader.getUserId(req);
    }
  } catch (err) {
    console.error('Unauthorized User in Middleware', err);
    return NextResponse.redirect(new URL('/api/auth/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/protected/:path*', '/admin/:path*'],
};
```

## Environment Variables

Ensure session secrets are available in edge environments:

```bash
# Required in both Node.js and Edge environments
WEBLOGIN_AUTH_SESSION_SECRET="your-32-character-secret"

# Optional - only needed if you use a custom session name (defaults to 'weblogin-auth')
WEBLOGIN_AUTH_SESSION_NAME="weblogin-auth"
```

### Debug Logging

Enable debug logging to troubleshoot:

```typescript
import { DefaultLogger, createEdgeSessionReader } from 'weblogin-auth-sdk';

const logger = new DefaultLogger();
const sessionReader = createEdgeSessionReader(secret, cookieName, logger);
```
