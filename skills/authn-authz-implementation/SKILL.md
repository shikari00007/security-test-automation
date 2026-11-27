---
name: authn-authz-implementation
description: "Guides building authn and authz correctly: password hashing, sessions and cookie flags, JWT vs opaque tokens, OAuth/OIDC with PKCE, MFA/WebAuthn, rate limiting, account recovery, and above all deny-by-default authorization (BOLA/IDOR, function-level, tenant, mass assignment) driven by a permission map with a generated role-by-endpoint test matrix. Recipes: FastAPI, Flask, Django, Express, Next.js. Use when: \"add login to my app\", \"implement JWT auth\", \"how should I hash passwords\", \"users can see each other's data\", \"add roles and permissions\", \"multi-tenant isolation\", \"add Google login\", \"password reset flow\". Not for: auditing or probing an existing API (api-security-testing), XSS/CSRF page review (web-security-testing), writing security tests for existing code (security-unit-testing), reviewing a diff or PR (security-code-review), storing keys/secrets (secrets-management), pinning a finding as a regression test (security-regression-generation). Related: security-project-context, security-test-strategy."
license: MIT
compatibility: Any Agent Skills runtime with file read/write and a shell for running tests. Python 3.10+ and/or Node 20+ for the recipes. No network required.
metadata:
  author: security-test-automation contributors
  version: "0.4.0"
  category: build
---

> **Developer Preview.** Guidance and snippets were executed only in a small sandbox; adapt and test in your own stack.

# Authentication and Authorization Implementation

**Objective.** Prevent the bugs that ship when login and permissions are bolted on route by route: a new endpoint with no check, `get(id)` without an owner or tenant filter (user B reads user A's invoice), a tenant id read from the request body, a JWT accepted with `alg: none` or the wrong audience, passwords stored with a fast hash, a session id that survives login and logout, and an OAuth flow without PKCE or `state`. The method is: declare the permissions as data, enforce them in one place that denies by default, scope every object lookup, and generate tests from the declaration.

## When this applies
- Adding or changing login, sessions, tokens, SSO/OAuth, MFA, password reset, roles, permissions, tenancy, admin routes, service-to-service calls.
- A reviewer or user reports one user seeing another's data.

## When it does not apply
- Auditing an existing API or running authorization tests against a target: `api-security-testing` (live tests need written scope; see `security-project-context`).
- Writing security tests for code that already exists: `security-unit-testing`; reviewing a diff or PR: `security-code-review`; where to keep and rotate keys and secrets: `secrets-management`.
- XSS, CSP, CSRF review of pages: `web-security-testing`.
- Converting a confirmed finding into a regression test: `security-regression-generation` (this skill only supplies the matrix pattern).
- Pure UI hiding of buttons with no server endpoint, or an app with no users and no protected data: nothing to build.

## Discovery questions
First read `.agents/security-project-context.md` if present (written by `security-project-context`) and do not re-ask what it answers. Otherwise ask at most:
1. Stack and framework (FastAPI, Flask, Django, Express, Next.js, other)?
2. Who authenticates: browser users (cookie session), mobile/SPA, other services? Any SSO/IdP?
3. Roles, and what must a user own versus share? Single- or multi-tenant?
4. Which objects/endpoints are sensitive (money, personal data, admin)?
5. Existing auth code or library, and test setup (pytest, jest/node:test)?
6. Compliance target (ASVS level, internal policy) and session timeout decisions?

## Workflow
1. **Inventory and decide.** List routes (grep decorators or dump the router) and the objects they touch. Choose session vs token using the table in [sessions-tokens-oauth](references/sessions-tokens-oauth.md) (default: server-side cookie session for first-party web). Produce: a short decision note (ADR or context file) with timeouts and token choice.
2. **Write the permission map.** `PERMISSIONS` data: endpoint to public/roles/object rule ([permission-map-test-matrix](references/permission-map-test-matrix.md)). Produce: `policy.py`/`policy.ts`. Done when every route has an entry.
3. **Write the generated tests first.** Completeness test (routes equal map), function-level role matrix, object-level matrix with two users in one tenant and one in another, mass-assignment test. Run: they must fail on current code. Done when you have seen red.
4. **Implement enforcement.** One global hook, deny on unknown route; one object loader scoped by tenant and owner taken from the session; strict input models; tenant/owner set server-side. Use the framework recipe in [framework-recipes](references/framework-recipes.md). Run tests to green.
5. **Credentials and sessions.** Argon2id (or scrypt) at the OWASP parameters, uniform login failures, rate limit and delay, rotate session on login, destroy on logout, idle and absolute timeouts, CSRF protection for cookie-authenticated state changes (ASVS 3.5.x, see [framework-recipes](references/framework-recipes.md) for the login/logout recipe and per-framework mechanism), cookie flags: [credentials-mfa-recovery](references/credentials-mfa-recovery.md). Test with an injected clock.
6. **Tokens and OAuth.** Verify JWTs with an explicit algorithm allowlist, `iss`, `aud`, `exp`; PKCE S256 plus `state`/`nonce` for OAuth; prefer a maintained library over hand-rolled code.
7. **Prove the tests can fail.** Remove the object check (or add an unmapped route, or mount a sub-app) and confirm the matrix goes red, then restore. Prefer `monkeypatch`/mutating the loader inside the test over a flag in the app; never ship a switch that disables a check. Record the output.
8. **Review pass.** Walk [pitfalls-code-review](references/pitfalls-code-review.md) against the diff; hand off.

Decision points: object not owned: return 404, wrong role: 403, unauthenticated: 401. Roles in a long-lived JWT for sensitive actions: re-read from the database. Unsure whether a rule is intended (can admins see all tenants?): ask, and write the answer into the map.

## Secure-by-default rules
- Unmapped route or unknown rule means deny.
- Every id lookup (read, write, list, nested, bulk) goes through the scoped loader.
- Tenant id and user id come from the verified session or token, never from body, query, path or headers sent by the client.
- Input models reject unknown fields; privileged fields are set server-side.
- Passwords: Argon2id m=19456 KiB, t=2, p=1 minimum (scrypt N=2^17, r=8, p=1 if no Argon2); compare secrets in constant time; no composition rules, accept 64+ characters.
- Session ids from a CSPRNG, rotated at login and privilege change, destroyed server-side at logout; cookie `__Host-`, `Secure`, `HttpOnly`, explicit `SameSite`.
- JWT: allowlisted algorithms, never `none`, require and check `exp`, `iss`, `aud`; keys from configuration, `kid` lookup in your own keyset; short TTL.
- OAuth: authorization code with PKCE (S256), per-transaction `state` and `nonce` bound to the session, exact redirect URI match, no implicit or password grants.
- Do not weaken or bypass a control to make a test pass; fix the test fixture instead.
- Secrets (pepper, signing keys, client secrets) come from the environment or vault, never source.

## Verification
- Run the generated matrix and the unit tests; show red before the change and green after (step 3 and 4), plus the deliberately broken variant failing (step 7).
- Run the project linter/type checker. If the optional `security-skills` CLI is installed, check `security-skills --help` for current commands before using any; it is not required.
- Report as "these checks passed: N function-level cells, M object-level cells, mass-assignment, unmapped route"; never claim the application is secure. List what was not tested (see Limitations).

## Examples
**Triggers.** "Users can open /invoices/42 of other customers." Add the invoices entries to `PERMISSIONS`, write the matrix (alice/bob same tenant, dave other tenant), see it fail, replace `Invoice.get(id)` with the scoped loader, rerun, then remove the check once to confirm the test fails.

**Does not trigger.** "Scan our staging API for broken auth." That is a testing task on a live target: use `api-security-testing` and obtain written scope first. This skill would only be used afterwards to fix what was found.

## Integration
- Upstream: `security-project-context` (stack, auth model, scope), `security-test-strategy` (what to test).
- Downstream: `security-regression-generation` (pin fixed bugs as tests), `api-security-testing` and `web-security-testing` (independent review), `security-finding-validation` (confirm findings), `security-reporting`.
- No CLI is needed; every step works with file edits and the test runner.

## Limitations
- Snippets were run against FastAPI 0.118, Flask 3.1, Django 4.2, Express 5.3 in a sandbox (the Django/Flask/Express/FastAPI recipes and the login/logout recipe included); Next.js, DRF, NestJS, Spring and policy engines are described, not executed.
- The hand-written JWT verifier and session store prove the rules; production code should use maintained libraries and a shared session store.
- Matrix tests catch declared-intent violations only; wrong intent in the map, business-logic flaws, race conditions, SSRF, XSS and infrastructure issues are out of scope.
- Cheat sheet values and ASVS 5.0.0 numbering were verified on 2026-11-25 and can change; see [VERIFICATION-NOTES](references/VERIFICATION-NOTES.md).

## References
- [credentials-mfa-recovery](references/credentials-mfa-recovery.md): hashing, rate limiting, MFA/WebAuthn, recovery
- [sessions-tokens-oauth](references/sessions-tokens-oauth.md): sessions, JWT vs opaque, OAuth/OIDC, runnable code
- [authorization-patterns](references/authorization-patterns.md): deny-by-default, BOLA/BFLA, tenancy, mass assignment, admin, S2S
- [permission-map-test-matrix](references/permission-map-test-matrix.md): permission map as data and generated tests
- [framework-recipes](references/framework-recipes.md): FastAPI, Flask, Django, Express, Next.js
- [pitfalls-code-review](references/pitfalls-code-review.md): standards map and review table
- [VERIFICATION-NOTES](references/VERIFICATION-NOTES.md): what was executed and fetched
