# Verification notes

Date: 2026-11-25. Host: Linux, Python 3.14.8, Node v24.21.0, npm 12.2.0. Everything ran in throwaway directories under `/tmp/sut-sandbox` and `/tmp/sut-clean` (deleted afterwards). No network service was contacted other than package registries and the standards pages below. No git commands were run for this skill, by the author. The independent review later executed the `git stash push -- <path>`/pop and `git revert --no-commit`/`git revert --abort` recipes in a scratch repo: they behave as documented. The fix-toggle method was also executed.

## Library versions actually installed

Python: fastapi 0.165.0, starlette 1.10.0, httpx 0.28.1, PyJWT 2.15.1, pytest 9.2.0, Flask 3.1.3.
Node: express 5.3.0, jsonwebtoken 9.0.3, jest 30.5.2, supertest 7.3.2, vitest 5.1.2.

## FastAPI + pytest template (`templates/fastapi-pytest`)

Clean install from the shipped `requirements.txt` in a fresh venv:

```
python3 -m venv v && v/bin/pip install -r requirements.txt
SUT_FIXED=0 v/bin/pytest -q -W ignore     -> 26 failed, 26 passed in 1.02s   (vulnerable: RED)
SUT_FIXED=1 v/bin/pytest -q -W ignore     -> 52 passed in 0.98s              (fixed: GREEN)
```

Failing ids on the vulnerable variant (26): authn: `test_logout_invalidates_the_token`, `test_lockout_after_repeated_failures_even_with_correct_password`; authz: `test_role_not_in_map_is_forbidden[DELETE-/admin/notes/{note_id}-member]`, `test_read_note_object_level[alice-2-False|alice-3-False|carol-1-False|adam-3-False]`, `test_delete_note_object_level[alice-1-False|adam-3-False]`, `test_list_contains_only_own_notes`, `test_denied_delete_did_not_delete`; input/output: `test_search_payload_is_treated_as_data_not_sql`, `test_search_does_not_cross_owner_boundary`, `test_malformed_query_does_not_leak_database_internals`, `test_unhandled_error_response_has_no_exception_details`, `test_note_body_boundaries[''-422]` and the 1001-char case, 7 of the `test_upload_validation_table` rows, `test_security_headers_present`, `test_failed_login_does_not_log_the_password`.
The 26 passing on the vulnerable variant are controls/guards (valid token works, wrong-key, expired, `alg: none`, tampered-claim tokens already rejected by PyJWT with an explicit `algorithms` list, anonymous rejected, route-completeness, metacharacters round-trip as data on INSERT, unknown-user vs wrong-password same response, valid boundaries, valid upload rows).

Two oracle bugs were found and fixed during authoring by checking the red run (see red-green-discipline.md): a SQL marker that did not actually inject, and a leakage assertion on driver words that passed while the leak existed. Also: default `TestClient` re-raises server errors, so the unhandled-error test builds `TestClient(app, raise_server_exceptions=False)`.

## Express + Jest/Supertest template (`templates/express-jest`)

Clean `npm install` from the shipped `package.json`:

```
npm run test:vulnerable  (SUT_FIXED=0 jest --runInBand) -> Tests: 20 failed, 21 passed, 41 total   (RED)
npm run test:fixed       (SUT_FIXED=1 jest --runInBand) -> Tests: 41 passed, 41 total             (GREEN)
```

Red ids: lockout; logout invalidation; denied-delete-did-not-delete; admin DELETE forbidden for member; delete alice->1, adam->3; list own notes only; read adam->3, alice->2, alice->3, carol->1; password in log; malformed-JSON stack leak; note body boundaries 2-6; security headers; unescaped stored markup.

## Other snippets

- Flask client table test (pytest-patterns.md): green against a fixed toy app (5 passed); with `fixed=False` it failed 3 (cross-owner x2, header), as expected. Run in `/tmp/sut-sandbox/fl`.
- Vitest + Supertest table (`describe.each`): 3 passed with vitest 5.1.2.
- Django snippet: executed by the independent review (pytest-django, toy view): secure 2 passed; with the owner check removed the cross-owner case failed (200 != 404). Still review against your Django/pytest-django versions.
- `jest --randomize` (41 passed) and `pytest-randomly` (52 passed) were run by the independent review.

## Standards verification (primary sources fetched 2026-11-25)

- ASVS **5.0.0** (May 2025), `raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/`: chapter titles V1 Encoding and Sanitization, V2 Validation and Business Logic, V3 Web Frontend Security, V5 File Handling, V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V16 Security Logging and Error Handling confirmed. Requirement text read for 5.2.1, 5.2.2, 6.3.1, 7.4.1, 8.2.1, 8.2.2, 8.2.3, 8.3.1, 9.1.1, 9.1.2, 16.2.5, 16.5.1.
- OWASP WSTG **v4.2** (`github.com/OWASP/wstg` tag `v4.2`; the live site redirects to v4.2 paths): IDs confirmed from the file headers: ATHZ-02, ATHZ-03, ATHZ-04, ATHN-03, SESS-06, INPV-01, INPV-05, CONF-06, CONF-07, CLNT-09, BUSL-08, ERRH-01, ERRH-02.
- Not verified: any newer WSTG release than v4.2.

## Limits of this verification

Templates ran on one OS and one Python/Node version each. Behaviour with other major versions (Express 4, Jest 29, older PyJWT) was not tested. The red/green proof uses the in-repo toggle, not a real code history.
