# Verification notes (secrets-management)

Date: 2026-11-25. Sandbox: `/tmp/sm` (throwaway; throwaway git repos, venv). All fake values; no network calls except package installs and documentation fetches. Nothing was run against live hosts.

## Executed

| Item | Tool / version | Result |
|---|---|---|
| Python redaction helper + 3 tests (keys, value patterns, logging filter incl. `log.exception`) | python3, pytest | 3 passed |
| JS redaction helper + 3 `node --test` tests (keys, values, Error stack) | node (`node:test`) | 3 pass, 0 fail |
| pydantic-settings loader + 2 tests (fail fast naming variable; SecretStr hidden in repr/str) | pydantic-settings 2.16.3, pydantic 2.14.4, pytest 9.2.0 (in a venv) | 2 passed |
| Node fail-fast config loader + 2 tests (missing names only; masked in JSON/string/inspect) | node `node:test` | 2 pass, 0 fail |
| `.gitleaks.toml` (extend default + custom rule + path/regex allowlists) | gitleaks 8.30.1 from `~/.local/share/security-skills/tools/gitleaks/8.30.1` | `git` and `dir` scans: 1 finding on `app.env` (rule `internal-service-token`), fixture path and `REPLACE_ME` not flagged; `--staged --pre-commit` on a clean file: no leaks, exit 0; SARIF written, exit 1 on findings |
| `.pre-commit-config.yaml` | pre-commit 4.7.0, detect-secrets 1.5.0 | `validate-config` OK; `pre-commit run --all-files` passes on clean tree (all 4 hooks); with `.gitleaks.toml` in repo root a planted `svc_prd_` token made the gitleaks hook Failed (exit 1); without the baseline file detect-secrets failed (documented) |
| Pinned tags exist | `git ls-remote --tags` | gitleaks v8.30.1, detect-secrets v1.5.0, pre-commit-hooks v5.0.0 each found |
| CI workflow YAML | PyYAML `safe_load` | parses; the gitleaks command line in it was executed locally (exit 1 with findings, SARIF 49 KB) |
| History rewrite | git-filter-repo `a40bce548d2c` | `--sensitive-data-removal --replace-text` and `--sensitive-data-removal --invert-paths --path app.env` on fresh clones: gitleaks clean, token occurrences in history 0 |
| Fixture token formats vs gitleaks default rules | gitleaks 8.30.1 | results table in redaction-and-test-fixtures.md |

## Not executed (stated limits)

- trufflehog: not installed; commands taken from its README (`--results=verified,unknown`, `--fail` returns exit code 183, GitHub Action with `extra_args`).
- GitHub Actions workflows (secret-scan, OIDC): only YAML-parsed, not run on GitHub; the SHA-256 in the install step is the real value (see re-verification below).
- AWS OIDC trust policy and `configure-aws-credentials` step: copied from GitHub docs, not run against AWS.
- SOPS, Sealed Secrets, Vault, BuildKit secrets, pino `redact`, framework public-env prefixes: summarised; SOPS `.sops.yaml` and encrypt syntax were not verifiable from fetched pages and are linked, not shown. BFG flags not verified.
- Pre-commit `gitleaks-docker`/`gitleaks-system` hooks not run (only the `gitleaks` hook).

## Primary sources fetched (2026-11-25)

- OWASP Secrets Management Cheat Sheet, cheatsheetseries.owasp.org. The page carries no edition date or version (CC BY-SA 4.0; references NIST SP 800-57 Part 1 Rev. 5). Used for: automation/dynamic secrets, rotation lifecycle, least privilege, auditing, detection at developer level with more than one tool, OIDC over static keys in CI, never ENV/ARG in images, Kubernetes sidecar/memory volumes, incident response (history rewriting side effects).
- OWASP ASVS 5.0.0, chapter V13 Configuration (raw file `0x22-V13-Configuration.md` at tag v5.0.0; the page did not print a version, tag is the evidence). Used IDs: V13.3 Secret Management; 13.3.1 (L2, no secrets in source or build artifacts; use a secrets management tool); 13.3.2 (L2, least privilege); 13.3.3 (L3, crypto operations in isolated module); 13.3.4 (L3, expiry and rotation); 13.1.4 (L3, document secrets and rotation schedule); 13.2.1 (L2, no static service credentials); 13.2.3 (L2, no default credentials); 13.4.1 (L1, no `.git` in deployments). Requirement paraphrases, levels as returned by the fetch tool; re-check wording before quoting.
- gitleaks README (master) and `.pre-commit-hooks.yaml`; flags re-confirmed with `gitleaks git --help` / `dir --help` on 8.30.1 (`--staged`, `--pre-commit`, `--log-opts`, `--redact`, `--baseline-path`, `--exit-code`, `--no-banner`). Note the README example rev (v8.24.2) is older than the pin used here.
- detect-secrets README (pre-commit example rev v1.5.0, baseline, audit commands).
- trufflehog README (commands above).
- pydantic-settings docs (`env_file`, `secrets_dir`, `env_prefix`, priority, required fields).
- git-filter-repo manual (`--replace-text` file format, `--sensitive-data-removal`, `--invert-paths`, force-push and reclone warnings). The first docs URL tried returned 404; the raw manual text was used.
- GitHub docs: "Removing sensitive data from a repository" (rotate first, cached views, forks, Support, filter-repo 2.47+ for `--sensitive-data-removal`, BFG not mentioned) and "OIDC in AWS" (permissions block, trust condition); GitHub OIDC overview (short-lived tokens, `sub` claim, newer immutable subject format).
- Kubernetes docs "Secrets": unencrypted in etcd by default; enable encryption at rest, RBAC least privilege, restrict container access, consider external store. The page was truncated, so the list/watch wording and env-vs-volume recommendation were not confirmed from it; the skill states the file-mount preference as practice from the OWASP cheat sheet, not as a Kubernetes statement.
- SOPS README/docs: formats and backends, `sops decrypt`, `sops edit` only.

## Environment issues encountered

- A combined cleanup-and-clone command was denied by the sandbox safety check (it contained a recursive delete); it was not retried. Fresh directory names were used instead, no deletions were performed.
- `pydantic-settings` and `git-filter-repo` were not installed system-wide; both were installed into a throwaway venv under `/tmp/sm`.

## Re-verification after independent review (2026-11-26)

Sandbox `/tmp/sm2` (deleted afterwards), gitleaks 8.30.1 (tool cache binary and a fresh release download), pre-commit, pydantic-settings, git-filter-repo in a venv. All values fake.

| Review change | Re-executed | Result |
|---|---|---|
| 2 redaction regex | Code blocks extracted from redaction-and-test-fixtures.md and run in Python (pytest) and Node (`node --test`), old pattern vs new. New tests cover `access_token=`, `client_secret=`, `DB_PASSWORD=`, `password: x`, JSON `{"password": "x"}` and `{"password":"x"}`, plus `token_count=5` untouched | Old pattern: new test fails in both languages (3 of 4 pass). New pattern: 4 of 4 pass in both |
| 3, 4 pre-commit config | Config block extracted into a fresh throwaway git repo with `.gitleaks.toml`; `pre-commit run --all-files`, then `pre-commit install` and a commit with a planted fake `svc_prd_` token | First run: all 3 hooks pass (no baseline needed). Commit with planted token blocked by gitleaks (rule `internal-service-token`), not created |
| 5 allowlist anchoring | Extracted `.gitleaks.toml` with anchored vs unanchored regex plus two demo custom rules | `password = "changeme"` and `REPLACE_ME` suppressed in both. `acme_<32>_changeme`: suppressed by unanchored, reported by anchored. Real-looking `password`/`acme_` values reported in both. Correction to the review: its `api_key = "..._changeme"` example is ignored by gitleaks default `generic-api-key` stopword `change` even with no allowlist, so that example does not demonstrate the regex issue; the anchoring still matters for custom rules |
| 6 checksum | Fetched `gitleaks_8.30.1_checksums.txt` from the official release; downloaded the tarball | `551f6fc8...470eb` matches the official file and `sha256sum -c` passes; binary reports 8.30.1 |
| 1 history rewrite | Bare origin, working clone pushes main, topic, tag with a fake token in history; fresh clone from the bare origin, `filter-repo --sensitive-data-removal --replace-text`, `git remote -v`, `push --force --mirror origin` | Origin remote was the hosted (bare) repo; token occurrences 0 in clone and in origin after push; gitleaks on both: no leaks found |
| 10 config error | Settings and tests extracted from safe-config-loading.md | 2 passed; error text now `APP_DATABASE_URL`, `APP_STRIPE_SECRET_KEY` (env var names with prefix) |

Changes 7, 8, 9 are text/eval edits (not executable beyond `python3 scripts/skill_evals.py validate`). Not re-run: trufflehog, SOPS, GitHub-hosted workflows, AWS OIDC.
