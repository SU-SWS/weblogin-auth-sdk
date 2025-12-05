# Weblogin Auth SDK
github: su-sws/weblogin-auth-sdk


## Copilot Instructions — Auth Package (TypeScript + SAML + iron-session)

For Copilot: Build a framework-agnostic authentication library in TypeScript using node-saml (SAML 2.0) and iron-session (cookie-only sessions). The package targets serverless, stateless hosts (e.g., Netlify, Vercel, Cloudflare). Provide Next.js App Router conveniences inspired by Auth.js’s DX (callbacks, events, helpers). Security-first defaults. No server-side session store.

0) Scope & Goals

Runtime: Node 18+ (Web Crypto available). Serverless friendly. No in-memory state.

Flows: SP‑initiated SAML only (AuthnRequest → IdP → ACS). IdP‑initiated login is out of scope.

Sessions: Cookie-only via iron-session; no database or memory storage. Short TTL + optional sliding refresh.

RelayState: Must carry a signed value that includes an optional returnTo URL so users are redirected back to the page that initiated login.

SLO: Optional/nice-to-have (front-channel). If implemented, behind a feature flag.

Metadata in session: Make it easy for developers to add user and custom metadata into the cookie session (typed, size-aware).

Logging: Configurable; verbose mode emits detailed, structured logs with strict redaction of secrets.

Testing: Include Jest tests.

Docs: Generate developer docs (README + deep dives).

CSRF: ensure CSRF protection for state-changing requests (e.g., login, logout).

DX: Create convenient hooks and utilities for common tasks (e.g., session management, SAML requests).

1) SAML (SP‑initiated only) & RelayState

Login: Build AuthnRequest → redirect to IdP. Generate RelayState as simple JSON:

type RelayStatePayload = { return_to?: string };
// Stored as: JSON.stringify(payload)

If includeReturnTo, set return_to to the URL that initiated login (sanitize + allow-list same-origin).

Store no server state; validate at ACS by sanitizing return_to URLs.

ACS:

Verify signature(s) and conditions (Audience, Recipient, NotBefore/NotOnOrAfter, clock skew).

Enforce InResponseTo if requests are signed.

Map attributes → User via attributeMapping or callbacks.mapProfile.

Create/refresh iron-session cookie with { user, meta? } (see size note below).

Redirect to returnTo (if present and safe) or default post-login path.

SLO (optional): Provide auth.logout({ slo: true }) which triggers LogoutRequest if configured; otherwise just clears the cookie.

Cookie size guidance: Keep combined session under ~3.5KB to avoid header bloat. Encourage storing identifiers (e.g., roleIds, tenantId) rather than large objects. Provide runtime warning in verbose mode if size > threshold.

2) Sessions (iron-session only)

Cookie flags: HttpOnly, Secure, SameSite=Lax, Path=/, __Host- prefix when possible. Use subdomains like mysite.stanford.edu instead of stanford.edu

Data model Example (extensible):

type Session = {
  user: { id: string; email?: string; name?: string; imageUrl?: string };
  meta?: Record<string, unknown>; // developer-defined metadata
  issuedAt: number;
  expiresAt: number;
};

Mutation hooks: callbacks.session({ session, user, req }) to enrich/trim cookie data safely.

Session length: cookies should expire at the end of the browser session. Ie, they close the window or tab.

3) Logging (verbose mode)

Interface: { debug, info, warn, error } structured logs, include requestId, userId if available.

Verbose on: log SAML authn request building, RelayState generation/validation (without secrets), ACS decision points, cookie set/clear events, redirect targets.

Redaction: Never log raw SAMLResponse, cookies, secrets, or full certificates (log hashes/fingerprints only).