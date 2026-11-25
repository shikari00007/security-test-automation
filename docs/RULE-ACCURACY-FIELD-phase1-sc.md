# Accuracy phase 1: SEC-SC-001 and SEC-SC-006

Baseline (docs/RULE-ACCURACY-FIELD-web-api-sc.md): SC-001 field precision 4%, SC-006 20%.
Severity, confidence and profiles are unchanged (maintainer decision after measurement).
Tuning evidence: the baseline field doc plus abstract false-positive patterns; no hold-out data was read.
Cases: `fixtures/accuracy/web-api-sc-phase1-sc/cases.json` (each change has >=3 negative and >=2 positive cases).
No pre-existing case changed.

## SEC-SC-001 (manifest without lockfile)

1. Non-application trees skipped: a non-root manifest whose parent directory is named
   third_party/third-party/thirdparty/vendored/external/extern/example(s)/sample(s)/demo(s)/docs/doc/documentation/test(s)/__tests__/testdata/fixtures/e2e/playground.
   Rationale: such manifests are not deployed by this repo. Root manifests are never skipped.
   Recall risk: a real service living under a dir with one of those names (e.g. `examples/` that is deployed, `external/api`) is missed.
2. Library detection extended: npm `peerDependencies` counts as a library marker (still requires no `start` script and not `private`);
   poetry projects with `classifiers`/`keywords` and no `package-mode = false`; Pipfile next to a `setup.py`.
   Recall risk: a published-looking app with a `peerDependencies` field and no start script; a poetry app that carries keywords without `package-mode = false`.

## SEC-SC-006 (hardcoded secrets), generic detector only

Provider-format tokens (AKIA/ASIA, ghp_ etc., xox, sk_live, PEM private keys...) are untouched by all items below.

1. Smoke/packaging scripts: path token in {smoke, packaging, package, sanity, verify, e2e, ci, healthcheck, selftest} AND a reserved-domain identity
   (`.test/.invalid/.example/.localhost`, example.com/org/net, localhost) within -4..+2 lines AND the value is not a high-entropy key (>=24 chars, entropy >=3.5, letters+digits).
   Recall risk: a real default admin password in a smoke script that uses an example.com account.
2. Key names that name a secret location rather than hold it (`*_env`, `*_file`, `*_path`, `*_name`, `*_header`, `*_field`, `*Name`, ... ).
   Recall risk: a real secret stored under a key such as `password_hint`/`secret_name` is missed.
3. Docs/examples/samples/demo/tutorial directories skipped for generic literals (tests were already skipped).
   Recall risk: real credentials committed to an `examples/` dir that is actually used.
4. Well-known sample values: hunter2, letmein, qwerty*, secret/password(+digits), p@ssw0rd, supersecret, correct-horse*, test-/demo-/mock-/sample- prefixes,
   values containing abc123/abcdef/123456/12345678, 6+ repeated characters.
   Recall risk: genuinely weak production passwords of this shape (e.g. `password123`) are not reported.
5. Crypto test vectors: pure hex (>=16 chars) key material is ignored when the path has a vector/kat/rfc/wycheproof token or within +-10 lines there is
   a "test vector", "known answer", KAT, RFC nnnn, wycheproof, ciphertext, plaintext or nonce marker.
   Recall risk: a hex secret near crypto vocabulary (encryption code that also stores a real hex key next to a `nonce`).
6. Key-name matches reading from env/config were already skipped per line (`os.environ`, `process.env`, `getenv`, ...); unquoted accessor calls never match the literal regex.

## Test results
`python3 -m pytest -q tests/test_rule_accuracy.py tests/test_rules_web_api_sc.py tests/test_fixtures_e2e.py`: 565 passed. Full suite: 752 passed, 4 skipped.
