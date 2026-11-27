# Verification notes (2026-11-25)

What was checked, how, and what was not. "Local" = run in a throwaway sandbox under /tmp on the author's machine.

## Linting and parsing

| Artifact | Check | Result |
|---|---|---|
| `pr-security.yml`, `release.yml`, `dast.yml` | `yaml.safe_load` | parsed |
| same three | `actionlint` v1.7.12, built with `go install github.com/rhysd/actionlint/cmd/actionlint@latest` into /tmp | no findings (shellcheck not installed, so embedded shell not shellchecked) |
| negative control | same workflow with `echo "${{ github.event.pull_request.title }}"` in `run:` | actionlint reported "potentially untrusted ... [expression]" |
| `gitlab-ci.yml` | `yaml.safe_load` only | parsed; **not** run in GitLab, GitLab CI Lint not used |
| `dependabot.yml` snippet | `yaml.safe_load` | parsed |
| workflows embedded in `github-actions-workflows.md` | extracted from the markdown fences and re-linted (YAML + actionlint) | see final check below |

## Action names, versions, SHAs (GitHub API, `gh api`)

Each `uses:` SHA was resolved from the tag (annotated tags dereferenced to the commit) and re-checked programmatically against the workflow text: all matched.

| Action | Tag | Commit SHA |
|---|---|---|
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/upload-artifact | v7.0.2 | cf430e030ddbb5b0abf93d22962f4752f3646cd9 |
| actions/setup-python | v7.1.0 | 6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 |
| actions/dependency-review-action | v5.0.1 | bbc44d14a204704ccc493733616cd1e93a0321ec |
| github/codeql-action (init, analyze, upload-sarif) | v4.39.5 | 915412ff23e8b7659517e607487dbeae018f2934 |
| aquasecurity/trivy-action | v0.36.0 | ed142fd0673e97e23eac54620cfb913e5ce36c25 |
| google/osv-scanner-action (reusable PR workflow) | v2.7.1 | 32d3cd482bdadfb38b186c0ad1b031902d55d932 |
| docker/setup-buildx-action | v4.4.1 | f87e5991a6d7451dcb8d9637bfbc97413f497069 |
| docker/login-action | v4.8.0 | 8aa5831fb8d48d8f76594c7ddde61ae58019f550 |
| docker/build-push-action | v7.4.0 | c3c9e263c25d99ce0380d002d59b67737d91b0dc |
| anchore/sbom-action | v0.24.4 | dfcb83b97731532d72be422cbc51ee64adb6fd56 |
| sigstore/cosign-installer | v4.1.4 (installs cosign v3.1.5 by default) | 881c63bd87e38389154debd8331404ce7ca8a3ab |
| actions/attest-build-provenance | v4.2.2 | 4d101475d8b20a2381f78447822ac1eab6504dd8 |
| actions/attest | v4.2.2 | 1e69f48acb82d1966a394da916b4c1698aa569d6 |
| zaproxy/action-baseline | v0.15.0 | de8ad967d3548d44ef623df22cf95c3b0baf8b25 |
| aws-actions/configure-aws-credentials (hardening example only) | v6.3.0 | e1253824e5c10ff9df46874f81ed3ec929e19cfd |

Inputs used were compared with each action's `action.yml` (fetched from the repository at the resolved ref or default branch): dependency-review (`fail-on-severity`, `comment-summary-in-pr`; severities low/moderate/high/critical and `warn-only` from its README), codeql-action init (`languages`, `build-mode`), analyze (`category`), upload-sarif (`sarif_file`, `category`), trivy-action (`scan-type`, `scan-ref`, `image-ref`, `severity`, `ignore-unfixed`, `exit-code`, `format`, `output`), sbom-action (`image`, `format`, `output-file`, `artifact-name`), cosign-installer (`cosign-release`), attest-build-provenance (`subject-name`, `subject-digest`, `push-to-registry`), attest (`sbom-path` plus the same subject inputs), zaproxy/action-baseline (`target`, `rules_file_name`, `fail_action`, `allow_issue_writing`), osv-scanner reusable-pr workflow (`fail-on-vuln`, `scan-args`, `upload-sarif`; job needs `actions: read`, `contents: read`, `security-events: write`). `gitleaks/gitleaks-action` v3.0.0 exists but its README requires `GITLEAKS_LICENSE` for organization repos, so the examples use the CLI.

## CLIs executed locally

| Tool | What was run | Observed |
|---|---|---|
| gitleaks 8.30.1 (linux x64 release; sha256 matched the published checksums file) | `gitleaks dir --redact --exit-code 1 --report-format sarif` on a file with a synthetic token shaped like `sk_live_...` and the AWS docs example key | exit 1; 1 result (`stripe-access-token`); the AWS `...EXAMPLE` key was not flagged; secret not present in SARIF. `gitleaks git [flags] [repo]` and `--log-opts` confirmed via `--help` only (not run: it needs a git repository and no git commands were run) |
| semgrep 1.187.0 | local one-rule file, `--sarif-output --error --metrics=off --disable-version-check` | exit 1, SARIF 2.1.0; **result objects have no `level`; severity is in `rules[].defaultConfiguration.level`**; the jq gate in the workflow was rewritten after this finding and re-tested (count 1 on the sample, 0 on empty) |
| pip-audit 2.10.1 | `--help` | `-r`, `--strict`, `--ignore-vuln` are flags; formats are columns/json/cyclonedx/markdown (no SARIF) |
| jq | the `security-gate` and semgrep gate expressions on synthetic JSON | success case exit 0, failure case exit 1 |
| cosign v3.1.5 | `sign --help`, `verify --help` | `--yes`, `--certificate-identity[-regexp]`, `--certificate-oidc-issuer` exist |
| gh | `gh attestation verify --help` | `--repo`, `--owner`, `--signer-workflow`, `--predicate-type`, `oci://` form exist |
| `security-skills` (`python3 -m security_runner`) | `audit ... --type supply-chain --report sarif --fail-on high`, with `--gate candidates|confirmed`, `--strict` | on the project's vulnerable supply-chain fixture: default and `--gate confirmed` exit 0 (no confirmed or high-confidence candidates), `--strict` exit 1 with "gate: failing on high finding"; secure fixture exit 0 |
| `security-skills` on the workflows in this skill | copied to a temp dir under `.github/workflows/` and audited | 3 checks passed, 0 findings, exit 0 with `--strict` |
| `security-skills` on a deliberately unsafe workflow (`pull_request_target`, `write-all`, head checkout, injected title, `@main`) | same command | 4 candidates (SEC-SC-004, SEC-SC-005), exit 1 with `--strict` |

## Documentation read (fetched 2026-11-25)

- GitHub docs "Secure use reference" and "Securely using pull_request_target" (github/docs repository, markdown source): script injection via env vars, untrusted checkout risk, SHA pinning, CODEOWNERS for workflows, OIDC, self-hosted runner risk, `workflow_run`/`pull_request_target` share the default-branch cache.
- GitHub docs "dependency caching": only certain default-branch-resolving triggers may write caches; `pull_request` caches are scoped to the merge ref.
- GitLab template files under `lib/gitlab/ci/templates/Security/` and `Jobs/` (existence, job names `sast`, `secret_detection`, `dependency_scanning`, `container_scanning`, `CS_IMAGE`, `allow_failure: true` defaults, `artifacts:reports:container_scanning`).
- gcr.io/projectsigstore/cosign tag `v3.1.5` exists (registry tag list).

## Not verified / limits

- No workflow ran on a GitHub or GitLab runner; runtime behaviour such as the osv reusable workflow's fork handling, trivy-action SARIF plus `exit-code`, and ZAP rules-file format was not exercised.
- `gh attestation verify` and `cosign verify` examples were not run (no published image).
- GitLab `id_tokens` + `SIGSTORE_ID_TOKEN` keyless signing: shown in GitLab's `doc/ci/yaml/_index.md` (`id_tokens` section) per the independent review; not executed. GitLab security-policy tiers not checked. The GitLab snippet's `build-image` (kaniko) job is an untested minimal example.
- OWASP/CWE/SLSA identifiers are deliberately not cited in this skill; none were invented.
- Thresholds (budgets, FP targets, suppression expiry) are authoring judgement, not sourced standards.
- Whether a `workflow lockfile` feature is available to a given GitHub plan was not checked (mentioned in GitHub docs conditionally).

## Review round 2026-11-26 (changes from an independent review)

- All workflows in `github-actions-workflows.md` (pr-security, release, dast, new scheduled-security) were extracted and linted with actionlint v1.7.12 plus shellcheck (installed in a /tmp sandbox) and yamllint (default rules minus line-length, truthy, document-start, comments): 0 findings. The remaining YAML blocks (hardening, gate-policy, GitLab, the security-skills step fragment after dedent) pass yamllint. Not run on a runner.
- Pins unchanged. The new `scheduled-security.yml` reuses already-pinned SHAs; `actions/checkout` v7.0.1, `github/codeql-action` v4.39.5 and `google/osv-scanner-action` v2.7.1 were re-resolved with `gh api` (annotated tags dereferenced) and match; `osv-scanner-reusable.yml` exists at that SHA with inputs `fail-on-vuln`, `upload-sarif` and permissions `actions: read`, `contents: read`, `security-events: write`. `aws-actions/configure-aws-credentials` v6.3.1 exists (commit 45666896f5d8e0f10ae255413f3a4cdd03bdc8f5, not adopted); the hardening example stays on v6.3.0 with a re-resolve note.
- release.yml: added `artifact-metadata: write` (both attest steps use `push-to-registry: true`; `actions/attest` creates a storage record by default). Whether a missing permission warns or fails was not verified.
- pr-security.yml: `merge_group:` trigger added; PR-diff jobs (secrets, dependency-review, osv, semgrep) skip on non-PR events; concurrency group falls back to `github.ref`; the Dockerfile build and image-scan steps use `!cancelled() && ...` so a failed IaC scan no longer hides the image scan; osv reusable workflow gets `upload-sarif` guarded for fork PRs. Fork and merge-queue behaviour is reasoned, not observed.
- GitLab: stages `[build, test, release]`, `build-image` job with a dotenv report, `sign-image` has `needs` with `artifacts: true`; misleading hardening comment fixed. Stage order and needs checked by parsing the YAML and by hand against the Container-Scanning template stage (`test`). CI Lint not available.
- Report-only rollout no longer recommends `continue-on-error: true`; the pipe in a table cell is escaped; the OIDC example is job-scoped.
- Routing: descriptions of this skill and `supply-chain-security` retargeted (read-only audit stays with supply-chain-security; scanners, gates and signing here; secrets storage and leaks to secrets-management); eval prompts reworded and negatives added.
