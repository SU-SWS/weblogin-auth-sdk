# Gatsby Integration Examples

## Example 1: Basic Authentication Setup

### Configuration

```javascript
// src/lib/auth.js
import { SAMLProvider, SessionManager } from 'weblogin-auth-sdk';

const samlConfig = {
  issuer: process.env.WEBLOGIN_AUTH_SAML_ENTITY,
  idpCert: process.env.WEBLOGIN_AUTH_SAML_CERT,
  returnToOrigin: process.env.WEBLOGIN_AUTH_SAML_RETURN_ORIGIN,
};

const sessionConfig = {
  // name is optional, defaults to 'weblogin-auth'
  secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET,
};

export const samlProvider = new SAMLProvider(samlConfig);
export { sessionConfig };
```

### Environment Variables

```bash
WEBLOGIN_AUTH_SAML_ENTITY="your-entity-id"
WEBLOGIN_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
WEBLOGIN_AUTH_SAML_RETURN_ORIGIN="http://localhost:8000"
WEBLOGIN_AUTH_SESSION_SECRET="your-32-character-secret-key"
```

### API Routes

```javascript
// src/api/auth/login.js
import { samlProvider } from '../../lib/auth.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }

  try {
    const { redirectUrl } = await samlProvider.login({
      returnTo: req.query.returnTo || '/'
    });
    
    return res.redirect(redirectUrl);
  } catch (error) {
    return res.status(500).json({ error: 'Login failed' });
  }
}
```

```javascript
// src/api/auth/acs.js
import { samlProvider, sessionConfig } from '../../lib/auth.js';
import { SessionManager, createWebCookieStore } from 'weblogin-auth-sdk';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).end();
  }

  try {
    const request = new Request(`http://localhost:8000${req.url}`, {
      method: 'POST',
      headers: req.headers,
      body: new URLSearchParams(req.body).toString(),
    });

    const { user, returnTo } = await samlProvider.authenticate({
      req: request
    });

    const cookieStore = createWebCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, sessionConfig);
    
    await sessionManager.createSession(user);

    return res.redirect(returnTo || '/');
  } catch (error) {
    return res.redirect('/login?error=auth_failed');
  }
}
```

```javascript
// src/api/session.js
import { SessionManager, createWebCookieStore } from 'weblogin-auth-sdk';
import { sessionConfig } from '../lib/auth.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }

  try {
    const cookieStore = createWebCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, sessionConfig);
    
    const session = await sessionManager.getSession();
    return res.json(session);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to get session' });
  }
}
```

## Example 2: Protected Page Component

```jsx
// src/pages/protected.js
import React, { useState, useEffect } from 'react';

const ProtectedPage = () => {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/session')
      .then(response => response.json())
      .then(data => {
        setSession(data);
        setLoading(false);
        
        if (!data) {
          window.location.href = '/api/auth/login';
        }
      })
      .catch(() => {
        setLoading(false);
        window.location.href = '/api/auth/login';
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!session) {
    return <div>Redirecting to login...</div>;
  }

  return (
    <div>
      <h1>Protected Page</h1>
      <p>Welcome, {session.user.name || session.user.id}!</p>
      <button onClick={() => window.location.href = '/api/auth/logout'}>
        Logout
      </button>
    </div>
  );
};

export default ProtectedPage;
```

## Example 3: Edge Function Session Check

```javascript
// netlify/edge-functions/auth-check.ts
import { createEdgeSessionReader } from 'weblogin-auth-sdk/edge-session';

export default async function handler(request: Request) {
  const sessionReader = createEdgeSessionReader(
    Deno.env.get('WEBLOGIN_AUTH_SESSION_SECRET')
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
