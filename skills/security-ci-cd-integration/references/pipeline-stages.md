# Staged pipeline model

Put each check where it is cheapest to run and cheapest to fix. Fast, high-signal checks run early and block; slow or noisy checks run later and report. Time budgets are targets, not guarantees: measure your own p95 and move a check a stage later if it breaks the budget.

| Stage | Trigger | Budget | Checks | Default effect |
|---|---|---|---|---|
| 0. Local / pre-commit | `git commit` (developer machine) | < 10 s | secret scan of staged changes, formatter, lint, large-file/private-key check | block the commit; bypass is possible, so stage 1 repeats secrets |
| 1. PR (required) | `pull_request` | < 10 min | unit + security unit tests, secret scan of the PR's commits, dependency review / SCA on changed manifests, SAST (diff-aware), IaC scan, Dockerfile lint | block on high-confidence high+; warn on the rest |
| 2. PR (extended, parallel) | same | < 20 min | CodeQL (whole-repo semantic), container image scan, license policy | block on high/critical fixable; the rest warn |
| 3. Main / merge queue | push to default branch | < 30 min | full SAST baseline refresh, full SCA, upload SARIF to the default-branch scope (so alerts track the default branch) | report; open issues |
| 4. Release | tag push | < 45 min | build once, scan the digest, SBOM, keyless signature, provenance attestation, environment approval | block the release on failed scan or missing attestation |
| 5. Pre-prod / scheduled | nightly or weekly | up to hours | DAST baseline against an ephemeral stack under written scope, full dependency re-scan (new advisories against old code), secret scan of full history once | report; ticket |

## Placement rules

1. Block early only on checks with a low false-positive rate: secrets (verified patterns), new known-vulnerable dependencies, high-confidence SAST rules.
2. A check that has never been run against the repo starts as `report-only` (stage 5 behaviour) and is promoted to PR when its noise is measured, see [gate-policy-and-rollout.md](gate-policy-and-rollout.md).
3. Scan changes, not the world, on PRs (`--baseline-commit`, `dependency-review`, osv-scanner PR workflow, gitleaks `--log-opts base..head`). Scan the world on a schedule.
4. Build once. Scan, SBOM, sign and attest the same **digest** that gets deployed.
5. Scheduled scans matter even if no code changed: advisories appear after merge.
6. DAST only against an ephemeral environment you started yourself or a lab/staging host named in a written scope (`authorized_by`, `environment`, `targets`, `isolation_confirmed`, `expires`). Never production. Passive baseline first; active scanning is a separate decision.

## Tool picks (all optional; pick one per slot)

| Slot | Option | Gate signal | Notes |
|---|---|---|---|
| Secrets | gitleaks CLI | exit code 1 on leak; `--redact` keeps secrets out of logs | `.gitleaksignore` and `--baseline-path` for known leaks; also rotate real ones, see `secrets-management` |
| Dependencies (PR diff) | `actions/dependency-review-action` | `fail-on-severity` low/moderate/high/critical | needs dependency graph; also license and `deny-packages` |
| Dependencies (full) | pip-audit, `npm audit`, osv-scanner | pip-audit: any vuln; npm: `--audit-level`; osv: reusable PR workflow fails only on newly introduced | choose by ecosystem; lockfile required for accuracy |
| SAST | semgrep | rule severity ERROR/WARNING/INFO | diff-aware with `--baseline-commit`; pin version and rulesets |
| SAST (semantic) | CodeQL | code scanning alerts | gating via ruleset, not workflow exit code |
| IaC / container | trivy (`config`, `image`) | `--exit-code`, `--severity`, `--ignore-unfixed` | `.trivyignore` with expiry comment |
| SBOM | syft via `anchore/sbom-action`, or CycloneDX tools | file produced | attach and attest; see `supply-chain-security` for review |
| Signing / provenance | cosign keyless, `actions/attest-build-provenance` | verify step | verify identity on the consumer side |
| DAST | ZAP baseline | rules file IGNORE/WARN/FAIL | ephemeral target, written scope |

## Monorepo and language notes

- Python: pip-audit on `requirements*.txt` or a lock export; Bandit-style rules arrive through semgrep `p/default`. JavaScript/TypeScript: `npm audit`/`pnpm audit`/`yarn npm audit`, eslint-plugin-security if already used. Java/Go: osv-scanner covers `pom.xml`/`go.mod`; CodeQL supports both with `build-mode` options (check the CodeQL docs for which languages allow `none`).
- Path filters (`on.pull_request.paths`) are fine for fast jobs but never for the aggregate `security-gate`: a required check that never runs blocks merging forever, one that is filtered out looks green. Keep the gate unfiltered and let inner jobs no-op.
