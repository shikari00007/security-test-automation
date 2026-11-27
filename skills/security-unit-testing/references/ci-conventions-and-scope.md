# CI, naming, placement and scope boundaries

## Placement and naming

| Item | Convention |
|---|---|
| Directory | `tests/security/` mirroring app areas (`test_authz_*.py`, `test_authn.py`, `test_input_*.py`); JS: `tests/security/*.test.js` |
| Marker | `@pytest.mark.security` (registered in `pytest.ini`); Jest: `testMatch` or a `--testPathPattern=security` script |
| Names | `test_<actor>_cannot_<action>_<resource>` or parametrize ids that read as attacks; link a finding id in the docstring when one exists |
| Permission map | `tests/security/permission_map.py` (or `.js`), reviewed by code owners |
| Fixtures | shared in `tests/conftest.py`; synthetic users only; no files with real data |
| CODEOWNERS | require security-champion review on `tests/security/**` and the permission map so tests are not quietly weakened |

## Fast and stable in CI

- Budget: whole security suite under 30 s, each test under about 100 ms; the templates run 52 and 41 tests in about 1 s.
- In-process app + in-memory SQLite/Map; no network, no sleeps, no containers. Anything slower belongs in the integration tier.
- Deterministic: fixed clock, fixed ids, no random without a seed; no dependence on test order (verify with `pytest-randomly`, which is on by default once installed and disabled with `-p no:randomly`, or `jest --randomize`, which shuffles only within a file).
- Hash cost: tests can lower KDF cost via configuration (e.g. cheap rounds in test settings) but never test with the hashing disabled, and never ship the test setting.
- Separate job `security-tests` on every PR; failing blocks merge; do not auto-retry (a flaky security test is a bug in the test).
- Pin test dependencies; cache the venv/`node_modules`.
- Treat skips as failures for this directory (`--strict-markers`, fail on `xfail` strict) and block `.only`.
- Coverage: report per rule (matrix cells covered) rather than line coverage.

```yaml
# GitHub Actions fragment
- run: pip install -r requirements.txt
- run: pytest -m security -q --strict-markers
```

## What NOT to unit test (hand off)

| Behaviour | Why a unit test cannot show it | Hand off to |
|---|---|---|
| TLS config, HSTS actually served, cipher suites | terminated by proxy/CDN, not the app | `web-security-testing` on a scoped lab/staging host |
| Real cookie flags through a browser, CSP enforcement, DOM XSS | needs a browser | `web-security-testing` |
| Rate limiting across instances, WAF, bot protection | needs the deployed topology and real concurrency | dynamic/integration tier; review config in unit tests only |
| Race conditions (double spend, TOCTOU) | needs real parallelism against real storage | integration test with real DB, `api-security-testing` |
| IAM/cloud/K8s policy | not app code | `cloud-kubernetes-security` |
| Dependency vulnerabilities | not behaviour you wrote | `supply-chain-security` |
| Deserialization/parsing of hostile files by native libs | needs real libs/OS limits | integration with sandboxing |
| Anything requiring a live host not in written scope | out of bounds | `security-project-context` scope rules first |

A unit test may still assert *configuration intent* (the app sets the header, the limiter is configured with N/min) and *decision logic with an injected clock*; say explicitly that real behaviour needs the other tier.

## Reporting

List: rules identified, rules with tests, tests that are guards, red/green evidence, handed-off items. Use "these checks passed", never "secure".
