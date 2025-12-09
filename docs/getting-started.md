# Getting Started

This guide will help you get up and running with the Weblogin Auth SDK quickly.

## Installation

```bash
npm install weblogin-auth-sdk
```

## Requirements

- Node.js 18 or higher
- TypeScript 5.x (recommended)
- A SAML entity and certificate

## Quick Start

### Next.js App Router

```typescript
// app/auth/config.ts
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
    // name is optional, defaults to 'weblogin-auth'
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
  },
  verbose: process.env.NODE_ENV === 'development',
});

// app/api/auth/login/route.ts
import { auth } from '../../config';

export async function GET() {
  return await auth.login({ returnTo: '/dashboard' });
}

// app/api/auth/acs/route.ts (SAML Assertion Consumer Service)
import { NextRequest } from 'next/server';
import { auth } from '@/utils/authInstance';

export async function POST(request: NextRequest) {
  // The authenticate() method handles the complete SAML callback flow:
  // 1. Validates the SAML response signature and assertions
  // 2. Extracts user attributes from the SAML assertion
  // 3. Creates an encrypted session cookie with the user data
  // 4. Returns the returnTo URL from RelayState
  try {
    const { returnTo } = await auth.authenticate(request);

    // Session is now created and stored in an encrypted cookie.
    // You can optionally access it immediately:
    const session = await auth.getSession();

    if (session?.user) {
      console.log('User authenticated:', session.user.id);
      // session.user contains: { id, email, name, ... }
    }

    // Redirect to the original page or a default
    const redirectUrl = returnTo || '/';
    return Response.redirect(new URL(redirectUrl, request.url));

  } catch (error) {
    console.error('Authentication failed:', error);
    return Response.redirect(new URL('/login?error=auth_failed', request.url));
  }
}

// app/api/auth/logout/route.ts
import { auth } from '@/utils/authInstance';

export async function POST() {
  await auth.logout();
  return Response.redirect('/');
}

// app/dashboard/page.tsx
import { auth } from '@/utils/authInstance';
import { redirect } from 'next/navigation';

export default async function Dashboard() {
  const user = await auth.getUser();

  if (!user) {
    redirect('/login');
  }

  return (
    <div>
      <h1>Welcome, {user.name}!</h1>
      <p>Email: {user.email}</p>
    </div>
  );
}
```

### Express.js

```typescript
import express from 'express';
import { SAMLProvider, SessionManager, createExpressCookieStore, idps } from 'weblogin-auth-sdk';

const app = express();
app.use(express.urlencoded({ extended: true }));

const samlProvider = new SAMLProvider({
  issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY!,
  // Use the production IdP preset
  entryPoint: idps.prod.entryPoint,
  idpCert: idps.prod.cert,
  returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN!,
});

// Login route
app.get('/auth/login', async (req, res) => {
  const loginUrl = await samlProvider.getLoginUrl({ returnTo: '/dashboard' });
  res.redirect(loginUrl);
});

// SAML callback (ACS) - Assertion Consumer Service
app.post('/auth/callback', async (req, res) => {
  try {
    // Step 1: Validate SAML response and extract user profile
    // The authenticate() method verifies the SAML signature, checks
    // conditions (NotBefore, NotOnOrAfter, Audience), and maps
    // SAML attributes to a User object.
    const { user, returnTo } = await samlProvider.authenticate({ req });

    // Step 2: Create the session cookie store
    const cookieStore = createExpressCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, {
      name: 'weblogin-auth', // optional, this is the default
      secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
    });

    // Step 3: Create an encrypted session with the authenticated user
    // This sets an HttpOnly, Secure cookie with the session data.
    // The session includes: user, meta, issuedAt, expiresAt
    await sessionManager.createSession(user);

    // Optional: Add custom metadata to the session
    // await sessionManager.createSession(user, {
    //   roles: ['user'],
    //   department: user.department,
    // });

    // Step 4: Redirect to the original page
    res.redirect(returnTo || '/dashboard');
  } catch (error) {
    console.error('Authentication failed:', error);
    res.redirect('/login?error=auth_failed');
  }
});

// Protected route middleware
const requireAuth = async (req, res, next) => {
  const cookieStore = createExpressCookieStore(req, res);
  const sessionManager = new SessionManager(cookieStore, {
    name: 'weblogin-auth',
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET!,
  });

  const user = await sessionManager.getUser();
  if (!user) {
    return res.redirect('/login');
  }

  req.user = user;
  next();
};

app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Welcome, ${req.user.name}!` });
});

app.listen(3000);
```
