---
name: security-unit-testing
description: "Use when the user says things like \"write security tests for this endpoint\", \"write a failing test first for this missing ownership check\", \"set up a tests/security folder with Supertest tests for tenant isolation\", \"add negative tests\", \"test that other users can't read my data\", \"role x endpoint matrix\", \"unit test the auth middleware\", \"pytest security tests\". Writes security tests during development: abuse cases, authorization matrices from a permission map, authentication (forged/expired tokens), input-boundary, injection-as-data, upload, error-leakage, secrets-in-logs tests in pytest, Jest, Vitest, Supertest, proven red then green. Not for: one confirmed finding needing evidence (security-regression-generation), a running staging host (api-security-testing, web-security-testing), code review without tests (security-code-review), building the auth feature (authn-authz-implementation). Related: security-regression-generation, secure-coding-patterns, security-test-strategy, vulnerability-triage-and-fix."
license: MIT
compatibility: Any Agent Skills runtime with file read/write and a shell. Python 3.10+ with pytest, or Node 18+ with Jest/Vitest. Offline; no network, scanners or live hosts needed.
metadata:
  author: security-test-automation contributors
  version: "0.4.0"
  category: test
---

# Security Unit Testing

> **Developer Preview.** Guidance and templates, not a guarantee; passing tests show the checked behaviours hold, not that the application is secure.

## Objective

Features ship with only happy-path tests, so a missing owner check, an unsigned-token path or a password in a log line passes CI and surfaces in production. This skill makes Claude Code write the *negative* tests next to the feature: for every endpoint or function that handles untrusted input, identity or data ownership, assert what must be **rejected**, and prove each test can fail. A security test that was never red proves nothing.

## When this applies

- A new or changed endpoint, handler, middleware, validator, query, template or upload path.
- The user asks for authz/authn/validation/headers/logging tests, or "tests for this feature".
- A permission model exists (roles, tenants, owners) and has no matrix test.

## When it does not apply

- A specific confirmed finding needs a durable regression test with evidence: `security-regression-generation`.
- The behaviour needs a running stack (real TLS, proxy/CDN headers, real rate limiting across instances, cloud IAM, browser rendering): hand off to `api-security-testing` / `web-security-testing`. See [scope boundaries](references/ci-conventions-and-scope.md).
- The user wants a vulnerability review of existing code, not tests: `security-code-review`.
- Plain functional tests with no security angle: the project's normal unit-testing workflow (not this suite).

## Discovery questions

Read `.agents/security-project-context.md` first if it exists and do not re-ask what it answers. Otherwise ask at most:

1. Language, framework and test runner already in use (do not introduce another).
2. Roles, tenants and ownership rules (the permission model), or where they are defined.
3. How authentication works (session cookie, JWT, API key) and where the check lives.
4. Is there a threat model or list of abuse cases? If not, derive one in step 1.
5. Where do tests live and how does CI run them?

## Workflow

1. **Enumerate what must be rejected.** For the changed code list assets, actors and boundaries; write 5-15 abuse cases as one-line statements ("member reads another member's note", "token with `alg: none`"). Output: a table in the test file docstring or PR description. See [attacker-view design](references/test-design-attacker-view.md).
2. **Pick the oracle.** Status code and body shape for HTTP, a state check after the call (the denied delete did not delete), `caplog`/spy for logs, header map for headers. Never assert on the exact wording of a message.
3. **Write table-driven tests** in `tests/security/` (see [conventions](references/ci-conventions-and-scope.md)): one parametrized function per rule, cases listed as data, attacker-oriented ids. Authorization cases are generated from a permission map ([recipe](references/authorization-matrix-recipe.md)), plus a test that fails when a route has no map entry.
4. **Add a control test** per group (valid caller succeeds) so a 401 is proven to come from the rule and not a broken fixture.
5. **Use synthetic, deterministic fixtures**: fresh in-memory state per test, fixed users and ids, no real data, no network, forged tokens built in the test. See [pytest](references/pytest-patterns.md) or [Jest/Vitest](references/jest-vitest-supertest-patterns.md).
6. **Prove red then green** ([procedure](references/red-green-discipline.md)): run against the vulnerable/unfixed code (stash the fix, or flip the fix toggle) and capture failures; restore, capture passes. Tests that pass on both are labelled guards, not fixes.
7. **Check the oracle is not vacuous**: for each injection or leakage test, confirm the harmless marker really would succeed on the vulnerable code (a quote-escaped tautology that does not parse in the query passes both ways).
8. **Wire into CI** as a fast, separate job or marker; keep every test under about 100 ms ([CI notes](references/ci-conventions-and-scope.md)).
9. **Report** which rules are covered, which tests are guards, which behaviours were left for integration/dynamic testing, with the red and green command output.

## Secure-by-default rules

- Every protected route has a policy entry and an anonymous-rejected test; a route missing from the map fails the build.
- Every authorization test has the three cells: wrong role, wrong owner, wrong tenant. Admin of tenant A must not reach tenant B.
- Denied requests assert both the status (`403` or `404`, as the app defines) and the absence of side effects.
- Token tests cover: missing/malformed header, wrong key, expired, `alg: none`, tampered payload, revoked after logout. Wrong-key, `alg: none` and tampered-payload tests are regression guards, not proof of the algorithm allowlist (see [red-green](references/red-green-discipline.md)).
- Injection tests assert the payload is stored or searched as data and that data of other users is not returned; never assert on a DB error string.
- Error tests assert no stack trace, query, path or exception class name in the body.
- Log tests plant a canary secret and assert it never appears in captured logs.
- If a real-looking secret appears in a fixture, `.env.example` or config, do not copy or read it; tell the user to rotate/replace it and use an obviously fake canary in tests.
- Test data is synthetic; test-only keys are named as such and never reused outside tests.
- Never weaken, skip or `xfail` a security test to get green; never disable the control under test inside the test.
- Payloads are harmless markers (a quote, `<b id=marker>`), not working exploits.
- No requests to hosts other than the in-process app.

## Verification

- Run the new tests: report the command, pass/fail counts and exit status.
- Show red on the unfixed variant (list the failing test ids) and green on the fixed one. If the code under test is already fixed, revert the fix temporarily or use the toggle, then restore; confirm the working tree equals the intended diff.
- Run the whole suite once to catch fixture coupling, and run the new tests twice in random order (install `pytest-randomly`, on by default; `jest --randomize` shuffles only within a file).
- State results as "these checks passed", never "the endpoint is secure". Report denominators: rules covered / rules identified.

## Examples

**Triggers.** "I added `GET /invoices/{id}`, write the security tests." Claude Code reads the handler, lists abuse cases (other user's invoice, other tenant, anonymous, expired token, non-numeric id), adds rows to the permission map, writes `tests/security/test_invoices_authz.py` with a parametrized matrix and a control, runs it against the code, temporarily removes the ownership check to show the cross-owner cases go red, restores it and reports both runs.

**Does not trigger.** "Staging is at https://staging.example.test, find IDORs." That is dynamic testing against a live host: hand off to `api-security-testing` after scope is confirmed. Also not: "here is finding FIND-007, make a regression test and evidence" (`security-regression-generation`).

## Integration

- `secure-coding-patterns` / `authn-authz-implementation`: patterns the tests assert; `vulnerability-triage-and-fix`: write the failing test first, then the fix.
- `security-regression-generation`: formal finding-linked tests; `security-code-review`: gaps found become abuse cases here.
- `api-security-testing`, `web-security-testing`: what unit tests cannot cover.
- Optional CLI: none required. If `security-skills` is installed, `security-skills regression verify` can replay red/green for a proposed test; the manual commands in [red-green](references/red-green-discipline.md) always work.

## Limitations

- Unit-level tests see the application in-process: they miss proxy, TLS, CDN, deployment and infrastructure behaviour, and real concurrency (races, multi-instance rate limits).
- A permission map is only as right as its author; it can encode the same wrong assumption as the code. Review it with the product owner.
- Tests catch regressions of the rules you thought of; they do not find unknown vulnerabilities.
- No JUnit/Go recipes yet.
- Templates are teaching-sized (in-memory stores, cheap hashing, one signing key); copy the structure, not the app code.
- Django and Vitest snippets are shorter and less exhaustively exercised than the FastAPI/Express templates (see [verification notes](references/VERIFICATION-NOTES.md)).

## References

- [Attacker-view test design](references/test-design-attacker-view.md): threat model to abuse cases, per-category assertions, standards map
- [Authorization matrix recipe](references/authorization-matrix-recipe.md): generator from a role/permission dict (pytest and Jest)
- [pytest patterns](references/pytest-patterns.md): fixtures, parametrize, FastAPI/Flask/Django clients
- [Jest/Vitest/Supertest patterns](references/jest-vitest-supertest-patterns.md)
- [Red-green discipline](references/red-green-discipline.md): git stash, fix toggle, guards, vacuous oracles
- [CI, conventions and scope boundaries](references/ci-conventions-and-scope.md)
- [Verification notes](references/VERIFICATION-NOTES.md): exact commands and results
- Templates: `references/templates/fastapi-pytest/` and `references/templates/express-jest/`
