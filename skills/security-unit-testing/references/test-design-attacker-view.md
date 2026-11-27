# Test design from the attacker's view

## 1. From threat model to abuse cases

Do not start from the code path that works; start from what an attacker or careless user would try. Fast derivation (10 minutes, per changed endpoint/function):

| Question | Produces abuse cases like |
|---|---|
| What asset does this touch (record, file, token, secret)? | "reads/changes/deletes an asset it does not own" |
| Who may call it (role, owner, tenant, anonymous)? | one case per *non-permitted* actor |
| What does the caller control (path, query, body, header, filename, token)? | boundary values, wrong types, oversized, markers |
| What leaves the system (response, log, error, header)? | secret/stack/other-user data present |
| What state changes, and can it be replayed or used after revocation? | logout, lockout, reuse |

If a threat model exists (`docs/threat-model*`, `.agents/security-project-context.md`), copy each "threat -> mitigation" row into one test; the mitigation is the assertion. A mitigation with no test is a gap to report.

Write each abuse case as an id plus one sentence, then a table-driven test. Keep the list in the test module docstring so reviewers see what is covered and what was consciously left out.

## 2. Table-driven shape

One test function per **rule**, cases as data, ids that read as attacks:

```python
@pytest.mark.parametrize("actor,note_id,allowed", [
    ("alice", 1, True),   # owner
    ("alice", 2, False),  # other owner, same tenant
    ("carol", 1, False),  # other tenant
], ids=lambda v: str(v))
def test_read_note(client, login, actor, note_id, allowed): ...
```

Rules: no logic in the test body that mirrors the implementation (no `if role == ...` computing the expectation; the expectation is data); denied cases assert status in the app's documented set (`403` or `404`) **and** no side effect; every group has a positive control.

## 3. What to assert per category

| Category | Assert | Do not assert |
|---|---|---|
| Authorization | status for each (actor, resource) cell; denied action left state unchanged; list endpoints return only permitted rows | the exact error text |
| Authentication | `401` for missing/malformed/forged/expired/none-alg/tampered/revoked; same response for unknown user vs wrong password; lockout engaged after N failures | timing of hashing |
| Input validation | min, max, min-1, max+1, empty, null, wrong type, unicode, oversized body -> `4xx` with no state change | that a specific regex is used |
| Injection safety | marker payload returns only the caller's own matching rows (or none) and metacharacters round-trip as stored data | a DB error string (driver specific) |
| Output encoding | stored markup appears escaped in rendered output (`&lt;`) and the raw marker is absent | a snapshot of whole HTML |
| Headers | present and with the required token (`nosniff`, `no-store`, `frame-ancestors 'none'`) on authenticated and error responses | full header equality (breaks on harmless additions) |
| Rate limit / lockout | the limiter's decision logic (counter/threshold) with an injected clock | real throttling across instances (integration) |
| Upload | pure validator table: extension allowlist, double extensions, traversal, NUL, size 0 / max / max+1 | content scanning by AV (integration) |
| Error leakage | status class and absence of `Traceback`, `stack`, file paths, SQL keywords, exception class names | specific driver wording (`sqlite`, `syntax`): brittle and can pass vacuously |
| Secrets in logs | planted canary secret absent from captured log text; positive control that logging happened | log format |

## 4. Fixtures and data hygiene

- Synthetic only: `alice`, `tenant-a`, `pw-alice-test`. Never copy production rows, emails or tokens.
- Deterministic: fixed ids, fixed seed rows, injected clock (`time.time` monkeypatch / `jest.useFakeTimers`) for expiry; no `random` without a seed.
- Fresh app + store per test (in-memory SQLite, new `Map`) so tests are order independent and parallel safe.
- Tokens are built inside tests with a test-only key named as such (`forge` helper). Do not read real secrets from the environment; fail the test if a real-looking secret is needed.
- The canary for secret-in-log tests is an obviously fake string (`pw-synthetic-canary-7731`).

## 5. Standards map (edition-pinned; verified 2026-11 against primary sources)

Use these to name coverage in PR descriptions, not as a checklist to satisfy. ASVS = OWASP Application Security Verification Standard **5.0.0** (May 2025), `github.com/OWASP/ASVS` tag `v5.0.0`. WSTG = OWASP Web Security Testing Guide **v4.2**, `github.com/OWASP/wstg` tag `v4.2`.

| Test group | ASVS 5.0.0 | WSTG v4.2 |
|---|---|---|
| Function-level authorization matrix | 8.2.1 | WSTG-ATHZ-02 Bypassing Authorization Schema, ATHZ-03 Privilege Escalation |
| Owner / tenant (IDOR/BOLA) | 8.2.2 | WSTG-ATHZ-04 Insecure Direct Object References |
| Authorization enforced server-side | 8.3.1 | - |
| Token validation, alg allowlist, no `none` | 9.1.1, 9.1.2 | - |
| Logout/expiry stops further use | 7.4.1 | WSTG-SESS-06 Logout Functionality |
| Lockout / anti-automation | 6.3.1 | WSTG-ATHN-03 Weak Lock Out Mechanism |
| Injection treated as data | chapter V1 Encoding and Sanitization | WSTG-INPV-05 SQL Injection |
| Output encoding | chapter V1 | WSTG-INPV-02 Stored XSS (stored-markup test), INPV-01 Reflected XSS (reflected variant) |
| Input validation / business logic limits | chapter V2 Validation and Business Logic | - |
| Upload extension and size | 5.2.1 (size), 5.2.2 (extension/content) | WSTG-BUSL-08 Upload of Unexpected File Types |
| Security headers | chapter V3 Web Frontend Security | CLNT-09 Clickjacking (frame-ancestors); WSTG-CONF-07 HSTS is a live-host check, hand off (see scope table) |
| Generic error messages | 16.5.1 | WSTG-ERRH-01 Improper Error Handling, ERRH-02 Stack Traces |
| No credentials in logs | 16.2.5 | - |

Requirement numbers quoted are the 5.0.0 numbering; ASVS 4.0.3 numbers differ, so always state the edition when citing.
