# Configuration

This document covers all configuration options for the Weblogin Auth SDK.

## Environment Variables

The SDK can be configured using environment variables for convenience:

### Required Variables

```bash
# SAML Configuration
WEBLOGIN_AUTH_SAML_ENTITY="your-saml-entity-id"
WEBLOGIN_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----..."
WEBLOGIN_AUTH_SAML_RETURN_ORIGIN="https://your-app.com"

# Session Configuration
WEBLOGIN_AUTH_SESSION_SECRET="your-32-character-minimum-secret"
```

### Optional Variables

See [environment-variables.md](./environment-variables.md) for more information on optional variables.

## Configuration Object

For more control, you can configure the SDK programmatically:

```typescript
import { createWebLoginNext, idps } from 'weblogin-auth-sdk';

const auth = createWebLoginNext({
  saml: {
    // Required
    issuer: 'your-saml-entity',
    // Use the production IdP preset
    entryPoint: idps.prod.entryPoint,
    idpCert: idps.prod.cert,
    returnToOrigin: 'https://your-app.com',

    // Optional
    serviceProviderLoginUrl: 'https://weblogin.stanford.edu/api/sso/login',
    returnToPath: '/api/auth/acs',
    includeReturnTo: true,
    relayStateMaxAge: 300, // 5 minutes

    // SAML Protocol Options
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    acceptedClockSkewMs: 60000,
    skipRequestAcsUrl: false, // Set to true for dynamic deployments (e.g. Vercel preview)
  },
  session: {
    // Required
    secret: 'your-session-secret-32-chars-min',
    
    // Optional - name defaults to 'weblogin-auth' if not provided
    name: 'weblogin-auth',
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      // maxAge: undefined means cookie expires when browser closes (default)
      // Set maxAge in seconds for persistent cookies, e.g.: maxAge: 86400 (1 day)
    },
    cookieSizeThreshold: 3500, // Warn if cookie exceeds this size
  },
  callbacks: {
    // Custom profile mapping
    mapProfile: async (profile) => ({
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
    }),

    // Authentication events
    signIn: async ({ user, profile }) => {
      console.log(`User ${user.id} signed in`);
    },
    signOut: async ({ session }) => {
      console.log(`User ${session.user.id} signed out`);
    },
  },
  verbose: process.env.NODE_ENV === 'development',
});
```

## SAML Configuration Options

### Using IdP Presets

The SDK includes built-in configurations for Stanford's Identity Providers (IdPs). You can import these presets to easily configure your application for different environments.

```typescript
import { createWebLoginNext, idps } from 'weblogin-auth-sdk';

const auth = createWebLoginNext({
  saml: {
    // ... other config
    entryPoint: idps.prod.entryPoint, // Use production IdP
    idpCert: idps.prod.cert,
  },
  // ...
});
```

Available presets:
- `idps.prod` (aliased as `idps.stanford`): Production IdP
- `idps.uat`: User Acceptance Testing IdP
- `idps.dev`: Development IdP
- `idps.itlab`: IT Lab IdP

### Required Options

| Option | Type | Description |
|--------|------|-------------|
| `issuer` | `string` | Your SAML entity ID - Usually a URL |
| `idpCert` | `string` | The IdP certificate for validating SAML responses |
| `returnToOrigin` | `string` | The base URL of your application |
| `privateKey` | `string` | Private key for SAML signing |
| `cert` | `string` | Public certificate for SAML signing (PEM format) |

### Optional Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serviceProviderLoginUrl` | `string` | Stanford SP URL | URL to initiate SAML login |
| `returnToPath` | `string` | `''` | Path component for ACS URL |
| `includeReturnTo` | `boolean` | `true` | Include return URL in RelayState |
| `relayStateMaxAge` | `number` | `300` | Max age for RelayState in seconds |
| `wantAssertionsSigned` | `boolean` | `true` | Require signed SAML assertions |
| `wantAuthnResponseSigned` | `boolean` | `true` | Require signed SAML responses |
| `acceptedClockSkewMs` | `number` | `60000` | Allowed clock skew in milliseconds |
| `skipRequestAcsUrl` | `boolean` | `true` | Skip ACS URL validation in AuthnRequest (useful for dynamic deployments) |
| `decryptionCert` | `string` | `undefined` | Public certificate for SAML decryption (PEM format) |
| `signatureAlgorithm` | `string` | `'sha256'` | SAML signature algorithm ('sha1', 'sha256', 'sha512') |
| `digestAlgorithm` | `string` | `'sha1'` | SAML digest algorithm ('sha1', 'sha256', 'sha512') |
| `identifierFormat` | `string` | `transient` | SAML identifier format |
| `allowCreate` | `boolean` | `false` | Allow creation of new accounts |
| `spNameQualifier` | `string` | `undefined` | Service Provider Name Qualifier |
| `authnContext` | `string` | `undefined` | Requested Authentication Context |
| `forceAuthn` | `boolean` | `undefined` | Force Authentication |
| `passive` | `boolean` | `undefined` | Passive Authentication |
| `providerName` | `string` | `undefined` | Provider Name |
| `skipRequestCompression` | `boolean` | `undefined` | Skip Request Compression |
| `authnRequestBinding` | `string` | `'HTTP-Redirect'` | Authentication Request Binding |
| `signMetadata` | `boolean` | `undefined` | Sign Metadata |
| `validateInResponseTo` | `string` | `'never'` | Validate InResponseTo ('always', 'never', 'ifPresent') |
| `requestIdExpirationPeriodMs` | `number` | `28800000` | Request ID Expiration Period in milliseconds |
| `idpIssuer` | `string` | `undefined` | IDP Issuer |
| `logoutUrl` | `string` | `entryPoint` | IDP Logout URL |
| `logoutCallbackUrl` | `string` | `undefined` | IDP Logout Callback URL |

## Session Configuration Options

### Required Options

| Option | Type | Description |
|--------|------|-------------|
| `secret` | `string` | Secret for encrypting session data (32+ chars) |

### Optional Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | `string` | `'weblogin-auth'` | Name of the session cookie. Creates two cookies: the main encrypted cookie (`weblogin-auth`) and a JS-accessible cookie (`weblogin-auth-session`) |
| `cookie.httpOnly` | `boolean` | `true` | Prevent client-side access to cookie |
| `cookie.secure` | `boolean` | `true` | Only send cookie over HTTPS |
| `cookie.sameSite` | `string` | `'lax'` | SameSite cookie attribute |
| `cookie.path` | `string` | `'/'` | Cookie path |
| `cookie.domain` | `string` | `undefined` | Cookie domain |
| `cookie.maxAge` | `number` | `undefined` | Cookie max age in seconds. When `undefined` (default), cookie expires when browser closes (session cookie) |
| `cookieSizeThreshold` | `number` | `3500` | Warn when cookie exceeds this size |

## Callback Functions

The SDK supports several callback functions for customizing behavior:

### Profile Mapping

```typescript
callbacks: {
  mapProfile: async (profile) => {
    // Transform SAML profile to your User object
    return {
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
      department: profile.department,
      // Add any custom fields
    };
  }
}
```

### Authentication Events

```typescript
callbacks: {
  signIn: async ({ user, profile }) => {
    // Called when user successfully signs in
    await logAuditEvent('signin', user.id);
    await updateLastLogin(user.id);
  },

  signOut: async ({ session }) => {
    // Called when user signs out
    await logAuditEvent('signout', session.user.id);
  }
}
```

### Session Enhancement

```typescript
callbacks: {
  session: async ({ session, user, req }) => {
    // Enrich session data
    return {
      ...session,
      meta: {
        userAgent: req.headers.get('user-agent'),
        lastActivity: Date.now(),
      }
    };
  }
}
```

## Framework-Specific Configuration

### Next.js

```typescript
// Use createWebLoginNext for simplified Next.js integration
import { createWebLoginNext } from 'weblogin-auth-sdk/next';

export const auth = createWebLoginNext({
  // ... configuration
});
```

### Express.js

```typescript
// Use individual classes for Express.js
import { SAMLProvider, SessionManager, createExpressCookieStore } from 'weblogin-auth-sdk';

const samlProvider = new SAMLProvider({
  // SAML configuration
});

// Create session manager per request
app.use((req, res, next) => {
  const cookieStore = createExpressCookieStore(req, res);
  req.sessionManager = new SessionManager(cookieStore, {
    // Session configuration
  });
  next();
});
```

### Web API / Other Frameworks

```typescript
import { SAMLProvider, SessionManager, createWebCookieStore } from 'weblogin-auth-sdk';

export async function handler(request: Request): Promise<Response> {
  const response = new Response();
  const cookieStore = createWebCookieStore(request, response);

  const sessionManager = new SessionManager(cookieStore, {
    // Session configuration
  });

  // ... handle request

  return response;
}
```

## Best Practices

1. **Use environment variables** for sensitive configuration
2. **Set strong session secrets** (use a password manager)
3. **Use HTTPS in production** (required for secure cookies)
4. **Monitor cookie sizes** to prevent browser compatibility issues
5. **Implement proper error handling** for configuration failures
