# Environment Variables

This document provides a complete reference for all environment variables supported by the Weblogin Auth SDK.

## Overview

The Weblogin Auth SDK can be configured using environment variables for convenience, especially in serverless and edge environments. All environment variables are optional when using programmatic configuration, but some are required for the SDK to function.

## Required Environment Variables

These variables must be set either as environment variables or provided in the configuration object:

### `WEBLOGIN_AUTH_ISSUER`

**Description**: Your SAML entity ID (also known as Service Provider entity ID)  
**Type**: `string`  
**Required**: Yes (if not provided in config)  
**Alias**: `WEBLOGIN_AUTH_SAML_ENTITY` (legacy)  
**Example**: `https://myapp.stanford.edu`  
**Used by**: SAML authentication, metadata generation  

```bash
WEBLOGIN_AUTH_ISSUER="https://myapp.stanford.edu"
```

### `WEBLOGIN_AUTH_SAML_CERT`

**Description**: The Identity Provider (IdP) certificate used for validating SAML responses  
**Type**: `string` (PEM format, with or without headers)  
**Required**: Yes (if not provided in config)  
**Example**: Certificate in PEM format  
**Security**: This is public key material, safe to include in environment variables  
**Note**: Headers/footers (`-----BEGIN CERTIFICATE-----`) are automatically stripped  

```bash
WEBLOGIN_AUTH_SAML_CERT="MIIDBjCCAe4CAQAwDQYJKoZIhvcNAQEFBQAwSjELMAkGA1UEBhMC..."
```

### `WEBLOGIN_AUTH_ACS_URL_ORIGIN`

**Description**: The base URL of your application where users will be returned after authentication  
**Type**: `string` (URL)  
**Required**: Yes (if not provided in config)  
**Alias**: `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN` (legacy)  
**Example**: `https://myapp.example.com`  
**Note**: Used to construct the Assertion Consumer Service (ACS) URL  

```bash
WEBLOGIN_AUTH_ACS_URL_ORIGIN="https://myapp.example.com"
```

### `WEBLOGIN_AUTH_SAML_PRIVATE_KEY`

**Description**: Private key for signing SAML requests (SP signing key)  
**Type**: `string` (PEM format, with or without headers)  
**Required**: Yes (if not provided in config)  
**Security**: Keep this highly secure - never commit to version control  
**Note**: Headers/footers (`-----BEGIN PRIVATE KEY-----`) are automatically stripped  

```bash
WEBLOGIN_AUTH_SAML_PRIVATE_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
```

### `WEBLOGIN_AUTH_SAML_SP_CERT`

**Description**: Public certificate corresponding to the private key (SP signing certificate)  
**Type**: `string` (PEM format, with or without headers)  
**Required**: Yes (if not provided in config)  
**Used by**: Metadata generation, request signing  
**Note**: Headers/footers are automatically stripped  

```bash
WEBLOGIN_AUTH_SAML_SP_CERT="MIIDBjCCAe4CAQAwDQYJKoZIhvcNAQEFBQAwSjELMAkGA1UEBhMC..."
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

### `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY`

**Description**: Private key for decrypting encrypted SAML assertions  
**Type**: `string` (PEM format, with or without headers)  
**Required**: Yes (if not provided in config)  
**Security**: Keep this highly secure - never commit to version control  
**Note**: Headers/footers (`-----BEGIN PRIVATE KEY-----`) are automatically stripped  
**Related**: Must be the private key corresponding to `WEBLOGIN_AUTH_SAML_DECRYPTION_CERT`  

```bash
WEBLOGIN_AUTH_SAML_DECRYPTION_KEY="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
```

### `WEBLOGIN_AUTH_SAML_DECRYPTION_CERT`

**Description**: Public certificate for SAML assertion decryption  
**Type**: `string` (PEM format, with or without headers)  
**Required**: Yes (if not provided in config)  
**Used by**: Metadata generation - share this with the IdP for encryption  
**Note**: Headers/footers are automatically stripped  
**Related**: Must correspond to `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY`  

```bash
WEBLOGIN_AUTH_SAML_DECRYPTION_CERT="MIIDBjCCAe4CAQAwDQYJKoZIhvcNAQEFBQAwSjELMAkGA1UEBhMC..."
```

## Optional Environment Variables

### SAML Configuration

#### `WEBLOGIN_AUTH_IDP_ENTRY_POINT`

**Description**: URL of the IdP's Single Sign-On service  
**Type**: `string` (URL)  
**Default**: `https://idp.stanford.edu/idp/profile/SAML2/Redirect/SSO`  
**Example**: `https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO`  

```bash
WEBLOGIN_AUTH_IDP_ENTRY_POINT="https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO"
```

#### `WEBLOGIN_AUTH_CALLBACK_PATH`

**Description**: Path component for the Assertion Consumer Service (ACS) URL  
**Type**: `string`  
**Default**: `/api/auth/callback`  
**Example**: `/auth/saml/callback`  
**Full URL**: `{WEBLOGIN_AUTH_ACS_URL_ORIGIN}{WEBLOGIN_AUTH_CALLBACK_PATH}`  

```bash
WEBLOGIN_AUTH_CALLBACK_PATH="/api/auth/callback"
```

### Session Configuration

#### `WEBLOGIN_AUTH_SESSION_NAME`

**Description**: Name of the session cookie  
**Type**: `string`  
**Default**: `weblogin-auth`  
**Required**: No (optional, has default)  
**Example**: `my-app-session`  
**Note**: Creates two cookies: the main encrypted cookie (e.g., `weblogin-auth`) and a JS-accessible cookie (e.g., `weblogin-auth-session`)  

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

## Environment Variable to Config Mapping

| Environment Variable | Config Property | Required |
|---------------------|-----------------|----------|
| `WEBLOGIN_AUTH_ISSUER` | `issuer` | Yes |
| `WEBLOGIN_AUTH_SAML_CERT` | `idpCert` | Yes |
| `WEBLOGIN_AUTH_ACS_URL_ORIGIN` | `returnToOrigin` | Yes |
| `WEBLOGIN_AUTH_SAML_PRIVATE_KEY` | `privateKey` | Yes |
| `WEBLOGIN_AUTH_SAML_SP_CERT` | `cert` | Yes |
| `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY` | `decryptionPvk` | Yes |
| `WEBLOGIN_AUTH_SAML_DECRYPTION_CERT` | `decryptionCert` | Yes |
| `WEBLOGIN_AUTH_SESSION_SECRET` | `session.secret` | Yes |
| `WEBLOGIN_AUTH_IDP_ENTRY_POINT` | `entryPoint` | No |
| `WEBLOGIN_AUTH_CALLBACK_PATH` | `returnToPath` | No |
| `WEBLOGIN_AUTH_SESSION_NAME` | `session.name` | No (default: `'weblogin-auth'`) |

## Legacy Environment Variables

The following environment variables are supported for backwards compatibility but are deprecated:

| Legacy Variable | Replacement |
|----------------|-------------|
| `WEBLOGIN_AUTH_SAML_ENTITY` | `WEBLOGIN_AUTH_ISSUER` |
| `WEBLOGIN_AUTH_SAML_RETURN_ORIGIN` | `WEBLOGIN_AUTH_ACS_URL_ORIGIN` |

## Example `.env` File

```bash
# Required SAML Configuration
WEBLOGIN_AUTH_ISSUER="https://myapp.stanford.edu"
WEBLOGIN_AUTH_SAML_CERT="MIIDpDCCAoygAwIBAgIGAYN..."
WEBLOGIN_AUTH_ACS_URL_ORIGIN="https://myapp.example.com"
WEBLOGIN_AUTH_SAML_PRIVATE_KEY="MIIEvgIBADANBgkqhkiG9w0..."
WEBLOGIN_AUTH_SAML_SP_CERT="MIIDpDCCAoygAwIBAgIGAYN..."

# Required Decryption Keys (for encrypted SAML assertions)
WEBLOGIN_AUTH_SAML_DECRYPTION_KEY="MIIEvgIBADANBgkqhkiG9w0..."
WEBLOGIN_AUTH_SAML_DECRYPTION_CERT="MIIDpDCCAoygAwIBAgIGAYN..."

# Required Session Configuration
WEBLOGIN_AUTH_SESSION_SECRET="your-super-secret-32-character-minimum-key"

# Optional SAML Configuration
WEBLOGIN_AUTH_IDP_ENTRY_POINT="https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO"
WEBLOGIN_AUTH_CALLBACK_PATH="/api/auth/callback"

# Optional Session Configuration
# Default is 'weblogin-auth' which creates 'weblogin-auth' (main) and 'weblogin-auth-session' (JS) cookies
WEBLOGIN_AUTH_SESSION_NAME="myapp-session"

# Environment
NODE_ENV="production"
```

## Security Best Practices

1. **Never commit secrets to version control** - Use `.env.local` files or environment variable injection
2. **Use different secrets per environment** - Development, staging, and production should have unique secrets
3. **Rotate secrets regularly** - Especially `WEBLOGIN_AUTH_SESSION_SECRET`
4. **Keep private keys secure** - `WEBLOGIN_AUTH_SAML_PRIVATE_KEY` and `WEBLOGIN_AUTH_SAML_DECRYPTION_KEY` should be stored securely
5. **Minimum secret length** - Session secrets must be at least 32 characters
