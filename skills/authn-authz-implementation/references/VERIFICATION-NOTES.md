# Verification notes (authn-authz-implementation)

Date of verification: 2026-11-25; re-executed 2026-11-26 after an independent review (see "Re-execution" below). Environment: Linux, Python 3.14.8, pytest 8.4.2, FastAPI 0.118.0 (Starlette 0.46.1, Pydantic 2.12.5), Flask 3.1.2, Django 4.2.27, PyJWT 2.10.1, argon2-cffi 25.1.0, bcrypt 5.0.0, Node 24.21.0, Express 5.3.0, TypeScript (latest at install) with zod.

## Code executed

Every fenced block whose first line is `# file: <name>` or `// file: <name>` in these references was extracted verbatim into a throwaway sandbox directory (outside the repo) and run:

| Block set | Command | Result |
|---|---|---|
| hashing.py, test_hashing.py, session_store.py, jwt_verify.py, pkce.py and their tests, policy.py, app_fastapi.py, test_matrix.py, flask_recipe.py, django_recipe.py and tests | `python3 -m pytest -q` | 79 passed |
| express_recipe.js, express_recipe.test.js | `node --test` | 5 passed |
| Next.js TypeScript sketch | `tsc --noEmit --strict` (with zod installed) | no errors; not run as an app |

Behaviour confirmed by execution:
- scrypt N=2^17,r=8,p=1 hash/verify round-trip, unique salts, `hmac.compare_digest`, needs_rehash, unknown-user path uses a dummy hash. Argon2id via argon2-cffi at m=19456,t=2,p=1 produced `$argon2id$v=19$m=19456,t=2,p=1$...`; `check_needs_rehash` flips when parameters rise. bcrypt 5.0.0 raises `ValueError` for passwords over 72 bytes.
- Sessions: login rotation kills the pre-login id; logout invalidates; idle and absolute timeouts (injected clock); other sessions purged; store keyed by hash.
- JWT: stdlib HS256 verifier rejects `alg: none` (empty and junk signature), header alg mismatch, tampered payload, expired, wrong aud/iss, future nbf, missing exp, `jku` header, unknown/retired kid; key-rotation overlap works. PyJWT 2.10.1: `decode(..., algorithms=["HS256"], audience=, issuer=, options={"require": [...]})` accepts a good token, rejects an unsigned `none` token and a wrong audience (`InvalidAudienceError`).
- PKCE: S256 challenge matches the RFC 7636 Appendix B vector (`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` gives `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`); state mismatch and issuer mismatch rejected.
- Authorization: FastAPI matrix (function-level 7 endpoints x 6 callers, object-level principals x endpoints, list scoping, mass assignment 422, tenant from principal, unmapped route 403, route-set equals policy-set). Red/green evidence: with the object rule monkeypatched to allow everything (test only; the former `check_objects` flag was removed from the app factory) user bob reads alice's document (HTTP 200 instead of 404) and `object_matrix_failures` returns 10 mismatches; with the check it returns 0. Flask, Django (real sessions, sqlite in memory, `force_login`) and Express recipes show the same 200/404/403/401 results and the missing-check variant leaking (200).
- Django 4.2.27 `Argon2PasswordHasher` defaults read from the class: time_cost=2, memory_cost=102400, parallelism=8.

## Sources fetched (primary)

- OWASP Password Storage Cheat Sheet: argon2id minimums (m=47104/t=1, 19456/2, 12288/3, 9216/4, 7168/5, p=1), scrypt options (r=8; N=2^17 p=1 down to N=2^13 p=10), bcrypt work factor >= 10 and 72-byte limit, PBKDF2 600,000 (SHA-256) / 220,000 (SHA-512), pepper guidance.
- OWASP Session Management, Forgot Password, Authorization Cheat Sheets (claims paraphrased in references).
- OWASP ASVS 5.0.0 (May 2025), GitHub `OWASP/ASVS` master `5.0/en`: chapter files V3 Web Frontend Security, V4 API and Web Service, V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC. Requirement ids and levels cited in the references come from those pages. The requester's "V2/V3/V4" numbering matches ASVS 4.0.x; in 5.0 the relevant chapters are V6-V10.
- RFC front matter and text from rfc-editor.org: RFC 9700 (BCP 240, January 2025; section 2.1.1 PKCE rules, S256, downgrade, sections 4.4/4.5/4.8), RFC 7636 (code verifier 43-128 chars), RFC 8725 (BCP 225, section titles 3.1-3.12), RFC 9068, RFC 7519, RFC 6749, RFC 9449, RFC 8252, RFC 7515, RFC 9207, RFC 7662, RFC 8693, RFC 8705.
- W3C WebAuthn: Level 2 is a W3C Recommendation; Level 3 page shows Candidate Recommendation Snapshot of 26 May 2026.
- OWASP API Security Top 10 2023 (api-security.owasp.org): API1 BOLA, API3 BOPLA, API5 BFLA.
- GitHub advisory GHSA-f82v-jwr5-mffw: CVE-2025-29927, Next.js middleware authorization bypass, published 2025-03-21; patched 15.2.3, 14.2.25, 13.5.9, 12.3.5.
- CWE titles from cwe.mitre.org (CWE 5.0): 639, 862, 863, 915, 384, 347, 307, 916, 352, 306, 285, 1275. CWE-613 is marked DEPRECATED there and is deliberately not cited.

## Not verified / limits

- WebAuthn server libraries (py_webauthn, @simplewebauthn/server), Flask-Limiter, express-rate-limit, django-axes, express-session option names, OPA/Cedar/Casbin/OpenFGA, PostgreSQL RLS syntax: named as options only; the reader must check current docs. No code for them was executed.
- Next.js, DRF, NestJS, Spring recipes are descriptions or sketches (Next sketch type-checked only).
- Cheat sheets are living pages; numbers may change. Re-fetch before quoting in audits.
- The ASVS 6.5.x lifetime/entropy numbers were taken from a summarising fetch of the chapter file; confirm exact wording in the ASVS text when citing in a compliance document.
- Sandbox identities and tokens are synthetic. No live host was contacted other than documentation sites.

## Re-execution after independent review (2026-11-26)

Method: each defect was first reproduced as a failing test against the previous code in a throwaway sandbox under /tmp, then the fix was applied to the references and every `# file:` block was re-extracted and re-run. Sandbox deleted afterwards.

| Change | Failing before | Passing after |
|---|---|---|
| JWT `kid` as list/dict (pre-signature) raised TypeError | 2 failures (list, dict) | InvalidToken for list, dict, int, None |
| Signed `exp` string/None/NaN/list, `nbf` string | 5 failures (NaN accepted forever) | all InvalidToken; bool also rejected |
| `typ` not checked | `verify()` had no `typ` parameter | `typ=` enforced, mismatch raises |
| Token + `=` / `==` / newline accepted | DID NOT RAISE | strict base64url regex rejects |
| FastAPI mounted sub-app and plain Starlette route served anonymously (200); old completeness test stayed green | old check did not raise | `check_complete` fails on both; mounted routes still return 200, which is why the test must catch them |
| Express `Bearer __proto__/constructor/toString/hasOwnProperty` gave 403 not 401 | 403 | 401 with `Map` lookup |
| Django without `CsrfViewMiddleware`: tokenless POST with `enforce_csrf_checks` | not rejected | 403, middleware ordered before the policy middleware |
| Bypass flags in factories (`check_objects`, `check_owner`, `checkOwner`) | signature test failed | flags removed; FastAPI/Flask use `monkeypatch`, Express swaps `gates.ownerOk` in the test; matrix still goes red |
| New: SessionStore reserved keys (`created`, `seen`) | n/a | ValueError |

New recipe `app_login.py` (FastAPI login/logout with `authenticate()`, `SessionStore.create(old_sid=...)`, `__Host-sid` cookie, Origin / `Sec-Fetch-Site` CSRF guard) with 7 tests including replay of the pre-login and post-logout cookie values. Two mutations were checked: passing `old_sid=None` makes the fixation test fail; a no-op `destroy` makes the logout replay test fail (it caught a first version of the fixation test that was not discriminating, now fixed).

Full run on the re-extracted blocks: `python3 -m pytest -q` 101 passed (was 79); `node --test` 6 passed (was 5). Environment: Python 3.14, FastAPI 0.118.0, Starlette 0.46.1, Flask 3.1.2, Django 4.2.27, PyJWT 2.10.1, Node 24.21.0, Express 5 (npm).

Not executed: the Next.js route-glob test (described only), Flask-WTF `CSRFProtect` and Express CSRF libraries (named only), the ASVS 10.5.3 / OIDC Core 3.1.3.7 re-attribution was applied from the review and not re-fetched.
