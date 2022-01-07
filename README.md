# Adapt Auth SDK

The AdaptAuth SDK provides all the functionality to easily integrate your Javascript
web applications with our Stanford SAML federated identity provider. 

## Usage

The AdaptAuth SDK is intended to be used in node [connect](https://github.com/senchalabs/connect)
style http server middleware (e.g. [express](https://expressjs.com/)).
To use it just configure your env, import the SDK client, and use the middlewares in your app.

```typescript
import express from 'express';
import { auth } from 'AdaptAuth';

const app = express();

// Add AdaptAuth authorization middleware
app.use(auth.authorize());
app.get('/my-protected-endpoint', (req, res) => {
  // Nothing to see here...
});


app.listen(3000);
```

### Configuration
The easiest way to configure AdaptAuth is by setting environment variables
```bash
# adapt-sso-sp SAML service provider login url (REQUIRED)
ADAPT_AUTH_SAML_SP_URL="https://adapt-sso-uat.stanford.edu/api/sso/login"
# adapt-sso-sp SAML registry entity id (REQUIRED)
ADAPT_AUTH_SAML_ENTITY="my-saml-app-entity"
# SAML signing pem certificate (REQUIRED)
ADAPT_AUTH_SAML_CERT="PEM used for saml document signing"
# Private key used to decrypt encrypted SAML assertions (optional)
ADAPT_AUTH_SAML_DECRYPTION_KEY="private decryption key"
# Local app origin part for SAML returnTo POST back
ADAPT_AUTH_SAML_RETURN_ORIGIN="https://my-app.stanford.edu"
# Local app path part for SAML returnTo POST back
ADAPT_AUTH_SAML_RETURN_PATH="/auth/saml"
# Local app endpoint to handle SAML POST back (overrides host/path when set)
# ADAPT_AUTH_SAML_RETURN_URL="https://my-app.stanford.edu/auth/saml"
# Secret used for signing/verifying local session jwts (REQUIRED)
ADAPT_AUTH_SESSION_SECRET="some-signing-secret"
# Name for local session cookie (optional)
ADAPT_AUTH_SESSION_NAME="adapt-auth"
# expiresIn / maxAge for session tokens
ADAPT_AUTH_SESSION_EXPIRES_IN="24h"
# Local url to redirect to after logging out of session (optional) defaults to "/"
ADAPT_AUTH_SESSION_LOGOUT_URL="/login"
# Local url to redirect to after logging in (optional)
ADAPT_AUTH_SESSION_LOGIN_URL="/dashboard"
# Local url to redirect to after authorize middleware failure (optional) defaults to responding 401
ADAPT_AUTH_SESSION_UNAUTHORIZED_URL
```

You can optionally instantiate a new AdaptAuth instance and pass your own configuration values.
```typescript
import { AdaptAuth } from 'AdaptAuth';

const myAuthInstance = new AdaptAuth({
  saml: {
    serviceProviderLoginUrl: 'https://adapt-sso.stanford.edu/api/sso/login',
    entity: 'my-other-saml-entity',
    returnToHost: process.env.APP_HOST,
    returnToPath: '/auth/saml'
    cert: 'MySamlCert',
  },
  session: {
    name: 'my-auth-session',
    secret: 'my-jwt-secret',
    logoutRedirectUrl: '/login',
    loginRedirectUrl: '/dashboard',
    unauthorizedRedirectUrl: '/login?code=UNAUTHORIZED',
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
import { auth } from 'AdaptAuth';
import { service } from './service';

const app = express();

// Basic middlewares
app.use(express.json());
app.use(cookieParser());

// Initiate SAML SP redirect
app.get('/login', auth.initiate());

// Handle SAML document POST back. User redirected to '/dashboard' on successful authentication
app.post('/saml/authenticate', auth.authenticate('/dashboard'));

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

To use AdaptAuth middlewares in a lambda function all you need to do is create a simple
express application for your handler that uses the middleware, then wrap it with
[serverless-http](https://github.com/dougmoscrop/serverless-http).
Here's a link to a [Netlify post](https://www.netlify.com/blog/2018/09/13/how-to-run-express.js-apps-with-netlify-functions/)
that goes through the whole process :wink:.

### Usage with Next.js API routes
If you're using [Next.js api routes](https://nextjs.org/docs/api-routes/introduction) you can easily
integrate the AdaptAuth middlewares with the [next-connect](https://github.com/hoangvvo/next-connect) package.
It provides a simple connect interface that outputs a `NextApiHandler`! Boom! :collision: done.

## API
### `AdaptAuth.initiate()`

Creates a middleware handler that simply redirects the request to the adapt-sso-sp servicer provider
with the confgiured paramters for entity and returnTo url. Note that this also handles passing along
a `final_destination` if present in `req.query.final_destination` to be added to the SAML RelayState.

```typescript
app.get('/saml/login', auth.initiate());
```

### `AdaptAuth.initialize()`
This is a simple pass-through of passports initialze middleware. It must be called prior to `AdaptAuth.authenticateSaml`

### `AdaptAuth.authenticateSaml`
Simple pass-through of `passport.authenticate` with confgired SamlStrategy. Required `AdaptAuth.initialize` middleware to have run prior.

### `AdaptAuth.signToken(user: AuthUser)`
Simple utility function to sign session jwts with the configured secrets and passed user as payload.

### `AdaptAuth.verifyToken(token: string)`
Simple utility to verify and decode session jwts. Rejects on invalid token. Resolves decoded user payload.

### `AdaptAuth.createSession()`
Simple middleware for saving the authenticated SAML user to a local jwt session. Creates an http only secure cookie
with SAML user payload as well as a basic http cookie signifying that the session exists.
**NOTE:** This middleware expects to find a valid SamlUser on the request object at `req.user`. It will return a `401` otherwise.

### `AdaptAuth.destroySession(redirectUrl?: string)`
Middleware that destroys local jwt session and redirects.

- `redirectUrl?: string` Local path to redirect to after session destroyed. Overrides `config.logoutRedirectUrl`.

```typescript
app.get('/logout', auth.destroySession('/public-homepage'));
```

### `AdaptAuth.authenticate(redirectUrl?: string)`
This middleware is a wrapper for the entire authentication process intended to be used as the saml POST back endpoint.
It handles passport initialization, SAML document verification, and local jwt session creation.
NOTE: When `redirectUrl` and `config.loginRedirectUrl` are unset `authenticate` calls `next()` like any other standard middleware.

- `redirectUrl?: string` Optional url to redirect to after authentication complete. Overrides `config.loginRedirectUrl`.

```typescript
app.post('/handle/saml', auth.authenticate('/dashboard'));
```

### `AdaptAuth.authorize(options?: AuthorizeOptions = {})`
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

### `AdaptAuth.getFinalDestination(req: any)`
Helper function to extract possible `finalDestination` url from SAML relay state on request object.

- `req: any` The request object to extract saml final destination from