# Environment Variables

This document provides a complete reference for all environment variables supported by the Weblogin Auth SDK.

## Overview

The Weblogin Auth SDK can be configured using environment variables for convenience, especially in serverless and edge environments. All environment variables are optional when using programmatic configuration, but some are required for the SDK to function.

## Required Environment Variables

These variables must be set either as environment variables or provided in the configuration object:

### `WEBLOGIN_AUTH_SAML_ENTITY`

**Description**: Your SAML entity ID (also known as Service Provider entity ID)  
**Type**: `string`  
**Required**: Yes (if not provided in config)  
**Example**: `weblogin-sso-uat`  
**Used by**: SAML authentication, metadata generation  

```bash
WEBLOGIN_AUTH_SAML_ENTITY="your-saml-entity-id"
```

### `WEBLOGIN_AUTH_SAML_CERT`

**Description**: The Identity Provider (IdP) certificate used for validating SAML responses  
**Type**: `string` (PEM format)  
**Required**: Yes (if not provided in config)  
**Example**: Certificate in PEM format  
**Security**: This is public key material, safe to include in environment variables  

```bash
WEBLOGIN_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----
MIIDBjCCAe4CAQAwDQYJKoZIhvcNAQEFBQAwSjELMAkGA1UEBhMC...
-----END CERTIFICATE-----"
```

### `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN`

**Description**: The base URL of your application where users will be returned after authentication  
**Type**: `string` (URL)  
**Required**: Yes (if not provided in config)  
**Example**: `https://your-app.com`  
**Note**: Used to construct the Assertion Consumer Service (ACS) URL  

```bash
WEBLOGIN_AUTH_SAML_RETURN_ORIGIN="https://your-app.com"
```

### `WEBLOGIN_AUTH_SESSION_SECRET`

**Description**: Secret key used for encrypting session cookies (iron-session)  
**Type**: `string`  
**Required**: Yes (if not provided in config)  
**Length**: Minimum 32 characters  
**Security**: Keep this secret secure and rotate regularly  
**Generation**: Use a cryptographically secure random string generator  

```bash
WEBLOGIN_AUTH_SESSION_SECRET="your-32-character-minimum-secret-key-here"
```

## Optional Environment Variables

### SAML Configuration

#### `WEBLOGIN_AUTH_SAML_SP_URL`

**Description**: URL to initiate SAML login at the Service Provider  
**Type**: `string` (URL)  
**Default**: `https://{WEBLOGIN_AUTH_SAML_ENTITY}.stanford.edu/api/sso/login`  
**Example**: `https://weblogin.stanford.edu/api/sso/login`  

```bash
WEBLOGIN_AUTH_SAML_SP_URL="https://weblogin.stanford.edu/api/sso/login"
```

#### `WEBLOGIN_AUTH_SAML_RETURN_PATH`

**Description**: Path component for the Assertion Consumer Service (ACS) URL  
**Type**: `string`  
**Default**: `''` (empty string)  
**Example**: `/api/auth/callback`  
**Full URL**: `{WEBLOGIN_AUTH_SAML_RETURN_ORIGIN}{WEBLOGIN_AUTH_SAML_RETURN_PATH}`  

```bash
WEBLOGIN_AUTH_SAML_RETURN_PATH="/api/auth/callback"
```

#### `WEBLOGIN_AUTH_SAML_PRIVATE_KEY`

**Description**: Private key for signing SAML requests (optional)  
**Type**: `string` (PEM format)  
**Default**: Falls back to `WEBLOGIN_AUTH_SAML_CERT`  
**Security**: Keep this highly secure, only needed if signing requests  
**Use Case**: Required only if your IdP requires signed authentication requests  

```bash
WEBLOGIN_AUTH_SAML_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"
```

#### `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY`

**Description**: Private key for decrypting SAML assertions (optional)  
**Type**: `string` (PEM format)  
**Default**: `undefined`  
**Security**: Keep this highly secure  
**Use Case**: Required as your IdP encrypts SAML assertions  

```bash
WEBLOGIN_AUTH_SAML_DECRYPTION_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"
```

### Session Configuration

#### `WEBLOGIN_AUTH_SESSION_NAME`

**Description**: Name of the session cookie  
**Type**: `string`  
**Default**: `weblogin-auth-session`  
**Example**: `my-app-session`  

```bash
WEBLOGIN_AUTH_SESSION_NAME="weblogin-auth"
```

### Development Configuration

#### `NODE_ENV`

**Description**: Node.js environment mode  
**Type**: `string`  
**Values**: `development`, `production`, `test`  
**Default**: `undefined`  
**Impact**:
- Affects default verbosity (verbose logging enabled in development)
- Influences cookie security settings (secure cookies in production)
- Used for environment-specific behavior

```bash
NODE_ENV="development"  # or "production"
```
