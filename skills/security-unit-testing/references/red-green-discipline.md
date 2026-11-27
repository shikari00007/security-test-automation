# Red-green discipline for security tests

A security test is accepted only with evidence that it **fails without the control** and **passes with it**.

## Cases

| Situation | How to get red |
|---|---|
| Writing the test first (preferred, bug fix or new feature) | Write test, run: red. Implement the control, run: green. |
| Control already exists in the working tree (uncommitted) | `git stash push --include-untracked -- <paths of the fix>` (`-u` is needed if the fix adds new files); run tests (red); `git stash pop`; run (green). |
| Control already committed | Make a temporary revert: `git revert --no-commit <fix-commit>` (or check out the parent's version of the file), run (red), then `git revert --abort` / `git checkout -- <file>`; run (green). Confirm `git status` shows only the intended change. |
| No usable history (greenfield, template) | Fix toggle: the app factory takes `fixed` (see templates, `SUT_FIXED=0/1`) or comment out the single guard line in a scratch copy, never in the shared tree. |

Commands, templates (the toggle is a teaching device; a real repo has no toggle):

```bash
SUT_FIXED=0 pytest -q tests/security   # expect failures: list the failing ids
SUT_FIXED=1 pytest -q tests/security   # expect all pass
```

Only run git stash/revert in the user's own repo with their knowledge; never `git stash` unrelated work, never leave the tree in the red state, and re-run `git status`/`git diff --stat` at the end.

## Reading the red run

- **Right reason**: the failure message is the assertion about the security property (`assert 200 in (403, 404)`), not an `ImportError`, `fixture not found`, 500 from a bad fixture or a typo in a path.
- **Expected set**: the failing ids are exactly the cases the bug affects (cross-owner cells, not the owner cell).
- **Guards**: tests that pass on both variants are controls or guards for already-correct behaviour (valid token works, `alg: none` already rejected by the library). Label them as guards in the report: they protect against regressions but did not demonstrate a fix.
- **Token guards**: Token tests (wrong key, alg none, tampered payload) are regression guards: with PyJWT/jsonwebtoken a widened algorithms list still rejects "none" when a secret is given, so these only go red if verification is skipped entirely (verified by mutation 2026-11). Do not report them as proof of the allowlist.
- **Vacuous oracle**: a test that was green on the vulnerable code must be examined. Real example from the template: the injection marker `x' OR '1'='1` was green on the string-built query because `LIKE '%x' OR '1'='1%'` is still false; the working marker `zzz' OR 1=1 --` comments out the tail and went red. Likewise asserting `"sqlite" not in body` passed while the body leaked `database error: ...`; asserting the status class and absence of `error` went red.
- **One change per run**: toggle only the fix under test so each red is attributable.

## Evidence to record

Command, environment (language/library versions), counts, list of failing test ids on red, final line on green, and the diff of the fix (or the toggle used). Template: see [VERIFICATION-NOTES](VERIFICATION-NOTES.md).

## Anti-patterns

- Marking the failing test `skip`/`xfail(strict=False)` to land the PR.
- Mocking the guard (`monkeypatch` the authorization function to allow, then asserting allow).
- Re-deriving the expected value with the same logic as the implementation.
- Fixing the test (loosening the assertion) because red was inconvenient.
