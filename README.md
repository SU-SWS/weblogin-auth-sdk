# Weblogin Auth SDK

The WebLoginAuth SDK provides all the functionality to easily integrate your Javascript
web applications with our Stanford SAML federated identity provider.

## Usage

The WebLoginAuth SDK is intended to be used in node [connect](https://github.com/senchalabs/connect)
style http server middleware (e.g. [express](https://expressjs.com/)).
To use it just configure your env, import the SDK client, and use the middlewares in your app.

```typescript
import express from 'express';
import { auth } from 'WebLoginAuth';

const app = express();

// Add WebLoginAuth authorization middleware
app.use(auth.authorize());
app.get('/my-protected-endpoint', (req, res) => {
  // Nothing to see here...
});


app.listen(3000);
```

### Configuration
The easiest way to configure WebLoginAuth is by setting environment variables
```bash
# Implement forced login by always showing login form.
# wether or not the IDP has a session.
# Always a string so 'true' for true and everything else is false.
WEBLOGIN_AUTH_FORCE_LOGIN="true"
# Which IDP to connect to 'itlab' | 'dev' | 'uat' | 'prod'
WEBLOGIN_AUTH_IDP="prod"
# The ACS full url (Redirect back to your site path)
WEBLOGIN_AUTH_ACS_URL="https://deploy-preview-24--adapt-stripe.netlify.app/auth"
# The SAML callback path (Should match the ACS url)
WEBLOGIN_AUTH_CALLBACK_PATH="/auth"
# Logout path to the IDP for SLO
WEBLOGIN_AUTH_LOGOUT_PATH="Not implemented as far as I can tell"
# The EntityID you registered on spdb.
WEBLOGIN_AUTH_ISSUER="https://my-project.stanford.edu"
# Try to log in passively (don't show a login form if no session on IDP)
# Always a string so 'true' for true and everything else is false.
WEBLOGIN_AUTH_PASSIVE="true"
# The decryption certificate in your metadata
WEBLOGIN_AUTH_SAML_DECRYPTION_CERT="--BEGIN CERTIFICATE--\n..."
# The decryption key for encrypted responses.
WEBLOGIN_AUTH_SAML_DECRYPTION_KEY="--BEGIN PRIVATE KEY--\n..."
# Secret used for signing/verifying local session jwts (REQUIRED)
WEBLOGIN_AUTH_SESSION_SECRET="some-signing-secret"
# Name for local session cookie (optional)
WEBLOGIN_AUTH_SESSION_NAME="weblogin-auth"
# expiresIn / maxAge for session tokens
WEBLOGIN_AUTH_SESSION_EXPIRES_IN="24h"
# Local url to redirect to after logging out of session (optional) defaults to "/"
WEBLOGIN_AUTH_SESSION_LOGOUT_URL="/login"
# Local url to redirect to after authorize middleware failure (optional) defaults to responding 401
WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL
```

You can optionally instantiate a new WebLoginAuth instance and pass your own configuration values.
```typescript
import { WebLoginAuth } from 'weblogin-auth-sdk';

export const auth = new WebLoginAuth({
  saml: {
    forceAuthn: process.env.NODE_ENV === 'production',
    idp: process.env.WEBLOGIN_AUTH_IDP || 'prod',
    callbackUrl: process.env.WEBLOGIN_AUTH_ACS_URL || `${appUrl}/auth`,
    issuer: process.env.WEBLOGIN_AUTH_ISSUER || 'https://github.com/su-sws/adapt-stripe',
    decryptionPvk: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY,
  },
  session: {
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET || 'SupEr!S33CR3T',
    name: process.env.WEBLOGIN_AUTH_SESSION_NAME || 'weblogin-auth',
    expiresIn: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN || '12h',
    logoutRedirectUrl: process.env.WEBLOGIN_AUTH_SESSION_LOGOUT_URL || '/',
    unauthorizedRedirectUrl:
      process.env.WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL,
  },
});
...
```

## Basic Auth Flow Integration

A basic usage of this SDK would involve the following endpoints setup:
- Using `auth.initiate` to redirect users to the SAML service provider
- Using `auth.authenticate` to handle the SAML document POST back from the IdP and create a local session
- Using `auth.authorize` on protected endpoints/routes to verify valid local sessions
- Using `auth.destroySession` to provide an additional way for a user to manually end their session

Here's an example express app:
```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import { auth } from 'WebLoginAuth';
import { service } from './service';

const app = express();

// Basic middlewares
app.use(express.json());
app.use(cookieParser());

// Initiate SAML SP redirect
app.get('/login', auth.initiate(), auth.authenticate());

// Handle SAML document POST back. User redirected to '/dashboard' on successful authentication
app.post(
  '/api/auth/callback',
  authInstance.authenticate(),
  (req, res, next) => {
    res.redirect('/dashboard);
  }
);

// Protect endpoints with local session authorization. Unauthorized users redirected to '/login' here
app.get(
  '/dashboard',
  auth.authorize({ redirectUrl: '/login' }),
  async (req, res) => {
    // Utilize SAML user properties in authorized session endpoints
    const dashboardStuff = await service.getDashboardStuff(req.user.encodedSUID);

    res.json({ data: dashboardStuff });
  }
);

// Log users out of local session and redirect them to '/home'
app.get('/logout', auth.destroySession('/home'));

// A public homepage for completeness
app.get('/home', (req, res) => {
  const homeStuff = await service.getHomeStuff();

  res.json({ data: homeStuff });
})

app.listen(3000);
```

### Required middlewares
It should be noted that these middleware expect certain other basic middlewares to be present.
Most notably, you should have [`express.json`](https://expressjs.com/en/api.html#express.json)
and [`cookie-parser`](http://expressjs.com/en/resources/middleware/cookie-parser.html) middlewares
setup as there is an expectation that we will be able to access data at `req.body` and `req.cookies`.

### Usage in Lambda functions

To use WebLoginAuth middlewares in a lambda function all you need to do is create a simple
express application for your handler that uses the middleware, then wrap it with
[serverless-http](https://github.com/dougmoscrop/serverless-http).
Here's a link to a [Netlify post](https://www.netlify.com/blog/2018/09/13/how-to-run-express.js-apps-with-netlify-functions/)
that goes through the whole process :wink:.

### Usage with Next.js API routes
If you're using [Next.js api routes](https://nextjs.org/docs/api-routes/introduction) you can easily
integrate the WebLoginAuth middlewares with the [next-connect](https://github.com/hoangvvo/next-connect) package.
It provides a simple connect interface that outputs a `NextApiHandler`! Boom! :collision: done.

```
import { NextApiRequest, NextApiResponse } from 'next';
import nc from 'next-connect';
import { auth } from './utils/authInstance';

// -----------------------------------------------------------------------------

const handler = nc<NextApiRequest, NextApiResponse>();

handler
  .use(auth.initiate())
  .use(auth.authenticate())
  .get((req, res) => {
    res.status(400).send('Something went wrong');
  });

export default handler;
```

## API
### `WebLoginAuth.initiate() + WebLoginAuth.authenticate()`

Creates a middleware handler that sends the request to the weblogin IDP
with the confgiured paramters for entity and returnTo url. Note that this also handles passing along
a `final_destination` if present in `req.query.final_destination` to be added to the SAML RelayState.

```typescript
app.get('/saml/login', auth.initiate(), auth.authenticate());
```

### `WebLoginAuth.initialize()`
This is a simple pass-through of passports initialze middleware. It must be called prior to `WebLoginAuth.authenticateSaml`

### `WebLoginAuth.authenticateSaml`
Simple pass-through of `passport.authenticate` with confgired SamlStrategy. Required `WebLoginAuth.initialize` middleware to have run prior.

### `WebLoginAuth.signToken(user: AuthUser)`
Simple utility function to sign session jwts with the configured secrets and passed user as payload.

### `WebLoginAuth.verifyToken(token: string)`
Simple utility to verify and decode session jwts. Rejects on invalid token. Resolves decoded user payload.

### `WebLoginAuth.createSession()`
Simple middleware for saving the authenticated SAML user to a local jwt session. Creates an http only secure cookie
with SAML user payload as well as a basic http cookie signifying that the session exists.
**NOTE:** This middleware expects to find a valid SamlUser on the request object at `req.user`. It will return a `401` otherwise.

### `WebLoginAuth.destroySession(redirectUrl?: string)`
Middleware that destroys local jwt session and redirects.

- `redirectUrl?: string` Local path to redirect to after session destroyed. Overrides `config.logoutRedirectUrl`.

```typescript
app.get('/logout', auth.destroySession('/public-homepage'));
```

### `WebLoginAuth.authenticate()`
This middleware is a wrapper for the entire authentication process intended to be used as the saml POST back endpoint.
It handles passport initialization, SAML document verification, and local jwt session creation.

```typescript
app.post('/handle/saml', auth.authenticate());
```

### `WebLoginAuth.authorize(options?: AuthorizeOptions = {})`
Middleware to validate incoming requests against the local jwt session.

#### `AuthorizeOptions`
- `options.allowUnauthorized?: boolean` - Allow unauthorized requests to go to next middleware (useful for auth optional endpoints)
- `options.redirectUrl?: string` - URL to redirect to on unauthorized. Will override `config.unauthorizedRedirectUrl` if set.

```typescript
app.get(
  '/user-details',
  auth.authorize({ redirectUrl: '/login' }),
  async (req, res) => {
    const user = await getUser();
    res.json(user);
  }
)
```

### `WebLoginAuth.getFinalDestination(req: any)`
Helper function to extract possible `finalDestination` url from SAML relay state on request object.

- `req: any` The request object to extract saml final destination from


### Caveats when using on Netlify-hosted sites
If you are using https://github.com/bencao/netlify-plugin-inline-functions-env to inline your environment variables,
be aware that it only replaces process.env.[variable_name] usages for files inside your functions directory.

Because of this, you should not rely on the singleton object or the defaults provided by the constructor.
You'll need to initate an WebLoginAuth instance inside a file in your functions directory, and pass in the full list of options.
It's fine to copy-paste these from the constructor in src/WebLoginAuth.ts as a starting point, as shown below:

```
import { WebLoginAuth } from 'weblogin-auth-sdk';

export const auth = new WebLoginAuth({
  saml: {
    forceAuthn: process.env.NODE_ENV === 'production',
    idp: process.env.WEBLOGIN_AUTH_IDP || 'prod',
    path: process.env.WEBLOGIN_AUTH_CALLBACK_PATH || '/auth',
    callbackUrl: process.env.WEBLOGIN_AUTH_ACS_URL || `${appUrl}/auth`,
    issuer: process.env.WEBLOGIN_AUTH_ISSUER || 'https://github.com/su-sws/adapt-stripe',
    decryptionPvk: process.env.WEBLOGIN_AUTH_SAML_DECRYPTION_KEY,
  },
  session: {
    secret: process.env.WEBLOGIN_AUTH_SESSION_SECRET || 'SupEr!S33CR3T',
    name: process.env.WEBLOGIN_AUTH_SESSION_NAME || 'weblogin-auth',
    expiresIn: process.env.WEBLOGIN_AUTH_SESSION_EXPIRES_IN || '12h',
    logoutRedirectUrl: process.env.WEBLOGIN_AUTH_SESSION_LOGOUT_URL || '/',
    unauthorizedRedirectUrl:
      process.env.WEBLOGIN_AUTH_SESSION_UNAUTHORIZED_URL,
  },
});
```
