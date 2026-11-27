# Gate policy, suppression, noise metrics and first-week rollout

## Gate-policy decision table

"Confidence" means the tool's own rating plus a human/second-tool reproduction. A raw scanner hit is a candidate, not a confirmed vulnerability (see `security-finding-validation`).

| Finding | PR (changed code) | Default branch / release | Action |
|---|---|---|---|
| Verified live secret (pattern + provider validation or obvious real credential) | block | block | rotate first, then remove; history rewrite is secondary (see `secrets-management`) |
| Secret-like string, low entropy / test fixture | warn | warn | allowlist by path or fingerprint with owner + expiry |
| Known vulnerable dependency, **newly introduced**, severity high/critical, fix available | block | block | upgrade or pin; see `vulnerability-triage-and-fix` |
| Same, no fix available | warn + ticket | warn | document mitigation, suppress with expiry (<= 30 days) |
| Same, pre-existing (in baseline) | do not block the PR | warn, scheduled ticket | burn down by priority, not by blocking unrelated PRs |
| Vulnerable dependency, not reachable / dev-only | warn | warn | suppress with reason, owner, expiry |
| SAST ERROR-level, high-confidence rule, in changed lines | block | block | fix or justify in review |
| SAST ERROR-level, rule with known noise | warn | warn | tune rule or path, track false-positive rate |
| SAST WARNING/INFO | warn | report | trend only |
| IaC misconfig HIGH/CRITICAL on changed file | block | block | fix; exceptions in file with expiry |
| Container OS/library CVE, fixable HIGH/CRITICAL | block at release, warn on PR if base image only | block | rebuild on a patched base |
| Container CVE, unfixed (`--ignore-unfixed`) | ignore at gate | report | revisit on schedule |
| License violation (deny list) | block | block | legal policy, not a security severity |
| DAST baseline FAIL rule | n/a (not on PR) | warn then ticket; block only after tuned | rules file with owners |
| Scanner crashed / timed out / could not run | **fail** the check (do not pass silently) | fail | a check that did not run is `blocked`, not `pass` |
| Unknown severity | warn | warn | treat as medium until triaged |

Principles:

- Block on confirmed or high-confidence **and** high severity **and** introduced by this change. Everything else warns.
- Never advertise a green pipeline as "secure". Say "these checks passed on this commit".
- A gate that people bypass is worse than none: if the PR block rate for a check exceeds what reviewers tolerate, demote it to warn and fix the rule, do not add a bypass label.
- Do not weaken a gate in the same PR that makes it fail (see `constraint-driven-development` for detecting lowered bars).

## Baseline and suppress

1. **Baseline** = findings that exist on the default branch today. Record them once (SARIF on main, `gitleaks --baseline-path`, semgrep `--baseline-commit`, dependency-review diff). PRs fail only on findings **not in the baseline**.
2. **Suppression record** (one file, reviewed through CODEOWNERS), each entry with: tool + rule/advisory ID, location or package, reason, owner, created date, **expiry (max 90 days; 30 for dependencies)**, link to ticket.

```yaml
# .security/suppressions.yml  (illustrative format; the CI step that enforces expiry is yours to write)
- tool: pip-audit
  id: GHSA-xxxx-xxxx-xxxx         # advisory ID, example placeholder
  package: example-lib==1.2.3
  reason: vulnerable function not called; confirmed by grep + test
  owner: team-payments
  created: 2026-11-25
  expires: 2026-12-25
  ticket: SEC-123
```

3. Expired entries fail a scheduled job (not every PR) and open a ticket assigned to the owner. Suppression without owner or expiry is rejected in review.
4. Prefer in-tool mechanisms where precise (`# nosemgrep: rule-id` with a reason comment, `.trivyignore` with comment, `gitleaks:allow` on the line or fingerprint in `.gitleaksignore`) but still register them in the suppression file so they can expire.

## Alert-fatigue controls

- One owner per check; alerts route to the code owner of the path, not a shared inbox.
- PR comments: one summary comment updated in place, never one comment per finding; cap at top 10.
- Annotate only changed lines on PRs; full lists go to the code scanning tab/artifact.
- Rate-limit by severity: only high+ creates tickets automatically.
- Group dependency alerts by package; let Dependabot/Renovate open one PR per upgrade group.
- Retire rules that are > 50% false positive after review (see metrics).

## Measure noise

Track weekly, per tool (a spreadsheet or the scanner's API is enough):

| Metric | Formula | Healthy signal (starting targets, tune per team) |
|---|---|---|
| PR block rate | PRs blocked by security / PRs opened | < 5% after week 4 |
| False-positive rate | findings closed as not-a-vuln / findings triaged | < 30% to keep blocking; > 50% retire or tune |
| Time to green | median minutes from first red to green on blocked PRs | < 1 day |
| Time to fix | median days from alert to fix for blocking-class issues | trending down |
| Suppression health | active suppressions, share expired, share without owner | 0 expired, 0 ownerless |
| Bypass count | admin merges / force-merges over failing security checks | 0 without a written reason |
| Runtime | p95 minutes of stage 1 | within budget in [pipeline-stages.md](pipeline-stages.md) |

These targets are starting points chosen for this guide, not industry standards.

## First-week rollout for an existing noisy repo

Goal: reach a blocking gate on **new** problems without freezing delivery, and without hiding the old ones.

| Day | Do | Done when |
|---|---|---|
| 1 | Harden the pipeline first ([pipeline-hardening.md](pipeline-hardening.md)): `permissions:`, SHA pins, CODEOWNERS for `.github/`. Add secrets scan **PR-diff only** (not history) as blocking, since new secrets are the cheapest, highest-value gate. Run full-history gitleaks once locally; list real hits, rotate them. | PR with a fake secret fails; clean PR passes; real hits have rotation tickets |
| 2 | Add dependency review + osv/pip-audit/npm audit in **report-only** (use the tool's own non-failing mode: dependency-review `warn-only: true`, `npm audit` / trivy with `--exit-code 0`, semgrep without `--error`. Do NOT use `continue-on-error: true`: it also hides scanner crashes. Write the promotion date in the PR description; report-only with no date is how gates stay off forever). Export the current finding list as the baseline. | Baseline file/SARIF committed or stored; counts recorded |
| 3 | Add SAST (semgrep diff-aware + CodeQL) report-only; upload SARIF so alerts appear in the Security tab. Triage the top 20 by severity x confidence; mark clear false positives with reasons. | FP rate measured on those 20 |
| 4 | Add IaC and container scans report-only. Fix or baseline. Create `.security/suppressions.yml` with owners and expiries for everything accepted. | No suppression without owner/expiry |
| 5 | Promote to **blocking for new findings only**: secrets, newly introduced high/critical fixable dependencies, SAST ERROR high-confidence on changed lines, IaC HIGH/CRITICAL on changed files. Add the `security-gate` aggregate job and make it the required check (ruleset). Keep the rest warn. | A deliberately vulnerable test PR is blocked; a normal PR passes; rollback plan written (how to demote a check in one commit) |
| 6-7 | Watch the metrics above, fix the noisiest rule, post the summary (counts, what blocks, what warns, suppression owners, next review date) in the repo. Schedule the weekly full scan and the suppression-expiry job. | First weekly report issued |

Rules during the week: do not bulk-suppress to get green; do not block on pre-existing findings; announce each promotion to the team before it lands; every promotion is a separate small PR so it can be reverted.

Test PR for day 5 (synthetic, harmless): in a throwaway branch add a dependency pin to a known-old version with a published advisory, and a file with a made-up token shaped like a provider token (for example `sk_live_` followed by 24 random alphanumerics; gitleaks 8.30.1 flagged this shape as `stripe-access-token` in the local test, whereas vendor documentation examples such as the AWS `...EXAMPLE` key were not flagged). Confirm the gates fire, then delete the branch. Never commit a real credential to test a scanner.
