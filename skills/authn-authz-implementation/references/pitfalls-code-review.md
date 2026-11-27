# Pitfalls and how they look in code review

## Standards map (editions)

| Topic | Primary source (edition) |
|---|---|
| Authentication | OWASP ASVS 5.0.0 (May 2025) V6; note ASVS 5.0 renumbered chapters: V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC, V3 Web Frontend Security (cookies 3.3, CSRF/CORS 3.4-3.5), V4 API and Web Service. (In ASVS 4.0.3, V2/V3/V4 were Authentication/Session/Access Control; do not mix the numberings.) |
| Password storage | OWASP Password Storage Cheat Sheet (live, fetched 2026-11-25) |
| Sessions, recovery, authorization | OWASP Session Management / Forgot Password / Authorization Cheat Sheets (live, fetched 2026-11-25) |
| OAuth | RFC 9700 (BCP 240, Jan 2025), RFC 7636, RFC 9207, RFC 9449, RFC 8252 |
| JWT | RFC 8725 (BCP 225, Feb 2020), RFC 7519, RFC 9068 |
| API risks | OWASP API Security Top 10 2023 |
| Weakness IDs | CWE 5.0: 639, 862, 863, 915, 384, 347, 307, 916, 352, 306, 285, 1275 (titles checked on cwe.mitre.org) |

## Pitfalls table

| Pitfall | How it looks in review | Fix | Reference |
|---|---|---|---|
| Missing object check (BOLA) | `Order.objects.get(pk=pk)` / `db.get(id)` in a handler with no owner/tenant filter | scoped loader/queryset; matrix test | authorization-patterns; CWE-639 |
| Check only on read, not write | GET loads via scoped helper, PATCH/DELETE use raw `get(id)` | all handlers use same loader | CWE-863 |
| Scattered role ifs | `if user.role == "admin"` repeated; a new route has none | permission map + global hook | CWE-862 |
| Client-supplied tenant/owner | `tenant_id = request.json["tenant_id"]`, `X-Tenant` header | from session; strict models | ASVS 8.4.1 |
| Mass assignment | `Model(**request.json)`, `serializer fields="__all__"`, `Object.assign(user, req.body)` | explicit allowlist, `extra="forbid"` | CWE-915 |
| Auth only in `middleware.ts`/gateway | handler trusts that "something upstream" authenticated | verify session in handler too; patch framework | CVE-2025-29927 |
| Unmapped route open | new route works for any logged-in user | deny-by-default test (route set equals map) | cheat sheet |
| Fast hash for passwords | `sha256(pw)`, `md5`, `hashlib.pbkdf2_hmac` with 1000 iters | Argon2id/scrypt at OWASP parameters | CWE-916 |
| `==` on secrets | `if token == stored` / `hash == hash` | `hmac.compare_digest` / `crypto.timingSafeEqual` | credentials reference |
| User enumeration | different message/status/timing for unknown user, "email not found" on reset | uniform response, dummy hash verify | ASVS 6.3.8 |
| Session fixation | session id unchanged at login | new id, destroy old | CWE-384; ASVS 7.2.4 |
| Logout only deletes cookie | server session still valid | server-side destroy; test replay of old cookie | ASVS 7.4.1 |
| Weak cookie flags | missing `Secure`/`HttpOnly`/`SameSite`, `Domain=.example.com` | `__Host-` cookie, flags | ASVS 3.3.x (CWE-1275 covers only the SameSite attribute) |
| Cookie auth without CSRF defence | state-changing POST authenticated by cookie only | CSRF token or custom header + SameSite | CWE-352; ASVS 3.5.x |
| JWT `alg` from token / no allowlist | `jwt.decode(t, verify=False)`, `algorithms` omitted, `options={"verify_signature": False}` | explicit algorithms; verify signature first | CWE-347; ASVS 9.1.x |
| JWT claims unchecked | no `aud`/`iss`/`exp` validation | require and check; token-type check | RFC 8725; ASVS 9.2.x |
| Roles/tenant trusted from long-lived JWT | `claims["role"]` used for 24 h | short TTL or DB lookup for sensitive actions | ASVS 8.3.2 |
| Token in localStorage / URL | `localStorage.setItem("token"...)`, `?token=` | BFF or HttpOnly cookie | ASVS 10.1.1 |
| OAuth without PKCE/state | authorization URL built without `code_challenge`/`state`; callback ignores state | PKCE S256, state/nonce bound to session | RFC 9700 2.1.1; ASVS 10.2.1 |
| Redirect URI prefix/regex match | `startswith(registered)` | exact string compare | ASVS 10.4.1 |
| Implicit/password grant | `response_type=token`, `grant_type=password` | code + PKCE | ASVS 10.4.4 |
| Hard lockout | account locked after 5 fails forever | delay/soft lock, notify, per-IP too | ASVS 6.1.1 |
| Per-process rate limit | in-memory dict, multiple workers | shared store | credentials reference |
| Trusting `X-Forwarded-For` | rate limit keyed on client-sent header | configured trusted proxy hops | |
| Reset link from `Host` header | `f"https://{request.host}/reset?..."` | configured base URL | Forgot Password cheat sheet |
| Reset token reusable/long-lived/plaintext | no `used` flag, no expiry | hashed, single-use, short expiry | ASVS 6.4.x |
| Reset keeps old sessions | no session purge on password change | end other sessions | ASVS 7.4.3 |
| Service trusts internal network | no auth on internal endpoints | token/mTLS, audience check | ASVS 8.3.3 |
| Default/seed admin | `admin/admin` in migrations | bootstrap from deployment secret, forced change | ASVS 6.3.2 |
| Tests only the happy path | auth tests assert logged-in user gets 200 | matrix with denied cells and broken-app check | permission-map-test-matrix |
