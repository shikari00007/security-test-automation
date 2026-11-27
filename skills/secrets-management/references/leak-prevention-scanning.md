# Preventing leaks: pre-commit and CI scanning

All configs below were executed in a sandbox unless marked otherwise (see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md)). gitleaks 8.30.1, pre-commit 4.7.0, detect-secrets 1.5.0.

Layering: editor/pre-commit (fast feedback, skippable) -> CI on every PR with full history (not skippable) -> periodic full-history and org-level scans (provider push protection where available). Use more than one tool where risk is high; they detect different things (OWASP cheat sheet, Detection section).

## .pre-commit-config.yaml (ready to use)

```yaml
# Install once per clone: pre-commit install --install-hooks
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1            # pin to a release you have reviewed; bump deliberately
    hooks:
      - id: gitleaks        # runs: gitleaks git --pre-commit --redact --staged --verbose
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

Gotchas found when executing it:
- Optional second scanner (detect-secrets). It is not in the block above because the hook fails with `Invalid path: .secrets.baseline` until a baseline exists. Create it first (`detect-secrets scan > .secrets.baseline`, review with `detect-secrets audit .secrets.baseline`, commit it), then add under `repos:`:

  ```yaml
    - repo: https://github.com/Yelp/detect-secrets
      rev: v1.5.0
      hooks:
        - id: detect-secrets
          args: ["--baseline", ".secrets.baseline"]
  ```

  Update the baseline with `detect-secrets scan --baseline .secrets.baseline`. gitleaks alone is a reasonable start.
- The gitleaks hook is defined by the gitleaks repo as `gitleaks git --pre-commit --redact --staged --verbose` with `pass_filenames: false`; `--redact` keeps the secret out of terminal logs.
- gitleaks discovers `.gitleaks.toml` in the scanned path, so keep your config at the repo root (verified: with the file in the root, the hook blocked a planted token; without it, the custom rule did not run).
- Do not skip the hook to get a commit through. If a finding is a false positive, make the fixture obviously fake or add a narrow, described allowlist entry and let the hook pass. CI is a backstop, not a reason to bypass the hook.
- Hooks are not installed by `git clone`; document `pre-commit install` in the README and enforce in CI.

## .gitleaks.toml (ready to use)

```toml
title = "project gitleaks config"

[extend]
useDefault = true          # keep the built-in rules; useDefault cannot be combined with extend.path

# Project-specific rule: internal service tokens look like "svc_<env>_<32 alnum>".
[[rules]]
id = "internal-service-token"
description = "Internal service token"
regex = '''\bsvc_(?:dev|stg|prd)_[A-Za-z0-9]{32}\b'''
keywords = ["svc_"]

# Narrow, documented allowlists. Prefer path + targetRules over blanket paths.
[[allowlists]]
description = "Synthetic test fixtures"
paths = ['''tests/fixtures/.*''']
targetRules = ["internal-service-token"]

[[allowlists]]
description = "Obvious placeholders in docs"
regexes = ['''(?i)^(changeme|replace_me|<your[-_ ]?token>)$''']
```

Regex allowlists are matched against the detected secret (default `regexTarget`) and apply to all rules unless `targetRules` is set. Anchor them, otherwise a real-looking value ending in `_changeme` is suppressed (checked with a custom rule: unanchored suppressed `acme_<32 alnum>_changeme`, anchored reported it, and `password = "changeme"` stayed suppressed either way). The built-in `generic-api-key` rule has its own stopword `change`, so it ignores such values with or without your allowlist.

Executed result: finding on `app.env` (rule `internal-service-token`), none for `tests/fixtures/ok.env` or the `REPLACE_ME` line. Syntax notes from the gitleaks README: `[[allowlists]]` replaced `[allowlist]` in v8.25.0 and `[[rules.allowlists]]` replaced `[rules.allowlist]` in v8.21.0 (old forms still parse for rules); config resolution order is `--config`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, then `.gitleaks.toml` in the target. Pin the gitleaks version because syntax moves between releases.

Allowlist hygiene: every entry has a `description`; never allowlist `.env` or a whole `config/` directory; review allowlist diffs in code review (`security-code-review`).

## Commands (flags verified against gitleaks 8.30.1 `--help`)

```bash
gitleaks dir --redact --no-banner .                          # working tree
gitleaks git --redact --no-banner .                          # all history
gitleaks git --redact --no-banner --log-opts="origin/main..HEAD" .   # a PR range
gitleaks git --pre-commit --redact --staged --no-banner .    # what the hook runs
gitleaks git --redact --report-format sarif --report-path gitleaks.sarif .
gitleaks git --baseline-path gitleaks-report.json .          # ignore already-triaged findings
```

Exit code is 1 when leaks are found (override with `--exit-code`). Always pass `--redact` so CI logs do not become a second leak. A baseline hides existing findings: record why, and still rotate real ones.

## CI job (GitHub Actions, executed command; YAML parses)

```yaml
name: secret-scan
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a full commit SHA in real use
        with:
          fetch-depth: 0            # full history so PR commits are scanned
      - name: Install gitleaks (pinned version, checksum verified)
        env:
          GITLEAKS_VERSION: "8.30.1"
          GITLEAKS_SHA256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"  # gitleaks_8.30.1_linux_x64.tar.gz
        run: |
          curl -sSfL -o gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
          echo "${GITLEAKS_SHA256}  gl.tgz" | sha256sum -c -
          tar -xzf gl.tgz gitleaks
      - name: Scan (fails the job on findings; output redacted)
        run: ./gitleaks git --redact --no-banner --exit-code 1 --report-format sarif --report-path gitleaks.sarif .
```

URL pattern and checksum verified 2026-11-26 against the v8.30.1 release; re-fetch the checksum from `gitleaks_<ver>_checksums.txt` when you bump the version; a mismatch must fail the job. `security-ci-cd-integration` owns required-check and SARIF-upload policy.

## trufflehog (from its README; not executed, not installed)

```bash
trufflehog git file://. --since-commit main --branch feature-1 --results=verified,unknown --fail
trufflehog filesystem path/to/dir
```

`--results=verified` limits output to credentials the tool confirmed live; `--fail` returns a non-zero code (the README says 183) when results are found. Verified-only is low noise but hits the provider API with the candidate secret; include `unknown` to avoid missing unverifiable ones. For a GitHub Action the README uses `trufflesecurity/trufflehog@main` with `extra_args: --results=verified,unknown` after a `fetch-depth: 0` checkout; pin to a release tag or SHA instead of `main`.

## Reducing false positives without hiding real ones

1. Decide real vs fake for each finding. Real -> rotate (incident-response.md). Fake -> make it obviously fake (see [redaction-and-test-fixtures.md](redaction-and-test-fixtures.md)) so no allowlist is needed.
2. Only then allowlist, narrowly, with a description.
3. Add custom rules for your internal token formats; default rules do not know them (executed: the default ruleset did not flag the `svc_prd_` token; the custom rule did).
