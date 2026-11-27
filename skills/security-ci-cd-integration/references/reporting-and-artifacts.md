# Reporting: SARIF, PR comments, artifacts

## Where results go

| Channel | Use for | How | Caveat |
|---|---|---|---|
| Code scanning (SARIF) | findings with file/line, tracked over time, dismissals with reasons | `github/codeql-action/upload-sarif` with `sarif_file` and a distinct `category` per tool | needs `security-events: write`; fork PRs have a read-only token so skip upload there; private repos need the code scanning feature |
| Job summary | readable per-run overview | append Markdown to `$GITHUB_STEP_SUMMARY` | no history, no dedupe |
| PR comment | the one thing a developer must act on | `dependency-review-action` `comment-summary-in-pr` (needs `pull-requests: write`), or one updated comment from a job | one comment, updated in place; do not post secret values |
| Artifacts | raw reports, SBOM, SARIF for audit | `actions/upload-artifact` with `retention-days` | retention costs storage; never upload unredacted secret findings; use gitleaks `--redact` |
| Check annotations | inline on changed lines | produced automatically by code scanning on PRs | limited count |
| Release assets | SBOM, attestations | attach SBOM; attestations live in the attestation store / registry | consumers must verify, see release workflow |

## SARIF rules that avoid pain

- SARIF version 2.1.0. Each tool uploads with its own `category` (`semgrep`, `trivy-iac`, `/language:python`), otherwise runs overwrite each other.
- Keep `ruleId` stable across runs; GitHub fingerprints results to detect "same alert" across commits.
- Redact before upload: gitleaks `--redact`; never put a secret in `message.text` or snippets.
- Verdict and confidence belong in result `properties`, not in `level` alone; the CLI keeps the verdict there (see `security-reporting`).
- Upload on `!cancelled()` so a failing gate still publishes the evidence, but skip for fork PRs.
- A SARIF upload is not a gate. Gate through exit codes in the job or a ruleset on code scanning results.

## What to put in the PR comment (template)

```
Security checks for <short sha>: 2 blocking, 5 warnings (baseline: 143 existing, not shown)
Blocking
  1. <rule id> <path>:<line>  <one-line reason>  how to fix: <link or hint>
  2. ...
Warnings: see the Security tab (category: semgrep), artifact: security-reports
Not run: DAST (scheduled), container scan (no Dockerfile)
```

Always state what did **not** run. A comment that only lists passes hides missing coverage (see `security-coverage-analysis` for denominators).

## Handing results on

- Findings to be reported to stakeholders: `security-reporting` (Markdown/JSON/SARIF/JUnit, coverage first).
- Confirm or reject candidates before blocking on them long-term: `security-finding-validation`.
- Pipeline-wide coverage (which checks ran, which were blocked): `security-coverage-analysis`.
- A fixed finding should leave a regression test in the PR stage: `security-regression-generation`.
