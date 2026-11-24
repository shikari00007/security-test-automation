# Web methodology

Each item: what to look for, then secure expectation. Evidence is always `path:line`.

## Authentication and session
- Look for: hardcoded credentials, weak password storage (MD5/SHA1/unsalted), session id in URL, missing session regeneration at login, long-lived tokens, no logout invalidation, JWT in localStorage, `alg` none or unverified signatures.
- Secure: salted adaptive hashing (argon2/bcrypt/scrypt), regenerated and invalidated sessions, cookies `Secure; HttpOnly; SameSite`.

## Access control
- Look for: handlers without authn/authz middleware, authorization only in the UI, IDs taken from the request without ownership check, role checks via client-supplied fields, forced browsing of admin routes.
- Secure: server-side, deny-by-default checks per object and function.

## Injection
- SQL/NoSQL: string concatenation or f-strings into queries; unsafe ORM raw calls. Command: `exec`, `system`, `child_process` with user data. Template injection: user input compiled as template. XXE: XML parsers with external entities. LDAP: filters built from input. Path traversal: file paths from input without canonicalization.
- Secure: parameterization, allowlists, safe APIs, XML external entities disabled.

## Cross-site scripting and client side
- Look for: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`, unescaped template output, `postMessage` handlers without origin checks, prototype pollution via unsafe merge, open WebSocket origins.
- Secure: contextual output encoding, trusted types or sanitizer, strict CSP.

## CSRF, CORS and headers
- Look for: state-changing GETs, missing CSRF tokens with cookie auth, `Access-Control-Allow-Origin` reflecting origin with credentials, missing CSP/HSTS/frame protections, permissive `X-Frame-Options`.
- Secure: anti-CSRF tokens or SameSite plus origin checks, explicit CORS allowlist, baseline security headers.

## SSRF and redirects
- Look for: server fetches of user-supplied URLs, webhook or image-proxy features, unvalidated `redirect` parameters.
- Secure: allowlist of hosts, block internal ranges, resolve then verify, relative-only redirects.

## Files and deserialization
- Look for: uploads served from webroot, trusting content-type or extension, archive extraction without path checks, `pickle`, `yaml.load`, Java/PHP/.NET unsafe deserialization.
- Secure: store outside webroot, validate type and size, safe loaders.

## Enterprise authentication (SSO)
- SAML: signature validation on assertion and response, audience and recipient checks, replay protection, XML signature wrapping. OIDC/OAuth: `state` and `nonce`, exact `redirect_uri` match, PKCE for public clients, `iss`/`aud`/`exp` validation, token storage. LDAP: bind credentials not in client code, LDAPS/StartTLS, filter escaping. Kerberos/Windows integrated auth: delegation settings and service-principal config review only.

## Secrets, errors and configuration
- Look for: committed secrets, debug mode on, verbose stack traces, default admin credentials, exposed `.git` or backup files in web root, source maps with secrets.

## Business logic
- Look for: price or quantity from client, missing workflow state checks, race windows on balance changes (review code only; do not race production).

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
