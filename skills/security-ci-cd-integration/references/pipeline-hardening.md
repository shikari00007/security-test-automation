# Hardening the pipeline itself

A security scan is worthless if the pipeline can be taken over: the attacker then reads secrets, signs malicious artifacts and disables the scanners. Source for most items: GitHub docs "Secure use reference" (`actions/reference/security/secure-use`) and "Securely using pull_request_target", fetched 2026-11-25. Items marked (lint) are caught by `actionlint` (injection verified with a negative control, see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md)); `security-skills audit --type supply-chain` also flagged items 1, 2, 3 and 5 in a local test.

## Checklist

| # | Risk | Rule | Check |
|---|---|---|---|
| 1 | Over-privileged `GITHUB_TOKEN` | `permissions: {}` at workflow level, grant per job; never `write-all`; also set the repo/org default workflow permission to read-only | grep `permissions:` in every workflow |
| 2 | Mutable third-party action refs (`@v4`, `@main`) | pin to a full 40-hex commit SHA with the tag in a comment; Dependabot `github-actions` ecosystem to bump; allow-list actions in org settings ("allow select actions"; check your current settings UI for a SHA-pinning requirement). GitHub docs also describe workflow dependency lockfiles on versions that support them, described as stronger than SHA pinning: check whether your GitHub plan/version offers it | regex `uses: .*@(?![0-9a-f]{40})` for non-local actions |
| 3 | `pull_request_target` / `workflow_run` + untrusted checkout ("pwn request") | use `pull_request` for anything that runs PR code; if privileged context is needed, run untrusted code in an unprivileged workflow and pass only data (artifact) to a privileged one that treats it as untrusted input | flag `pull_request_target` together with `ref: ...head...` or `repository: ...head.repo...` |
| 4 | Secrets to forks | secrets are not passed to `pull_request` runs from forks; do not "fix" that by moving to `pull_request_target`; use environment secrets with required reviewers for anything sensitive | review which jobs reference `secrets.*` |
| 5 | Script injection via `${{ github.event.* }}` (title, body, branch name, commit message, issue comment) | pass through `env:` and quote `"$VAR"`, or use an action instead of inline script (lint) | grep `run:` blocks for `${{ github.event`, `head_ref`, `github.head_ref` |
| 6 | Long-lived cloud keys in secrets | OIDC: `id-token: write` + trust policy on cloud side bound to repo, branch/tag or environment | no `AWS_SECRET_ACCESS_KEY`-style secrets |
| 7 | Persistent runners / shared state | GitHub-hosted runners are ephemeral; self-hosted only for private repos, with just-in-time (ephemeral) runners, no sensitive host data, network egress limited | runner labels in `runs-on` |
| 8 | Cache poisoning | releases and signing jobs do not restore caches written by less-trusted workflows; do not put secrets in caches; use read-only cache for PR-from-fork flows; cache keys include lockfile hash | search `actions/cache`, `setup-*` `cache:` in release workflow |
| 9 | Credentials left in `.git/config` | `actions/checkout` with `persist-credentials: false` unless the job pushes | grep checkout steps |
| 10 | Artifact trust | treat artifacts from other workflows/forks as untrusted input; verify checksum or attestation before use | `download-artifact` in `workflow_run` flows |
| 11 | Weak branch protection | rulesets on the default branch: required reviews, required status check `security-gate`, dismiss stale approvals, no force-push, no admin bypass without audit, signed commits optional | repo settings |
| 12 | Unreviewed pipeline changes | `CODEOWNERS`: `/.github/ @org/security-and-platform`, plus the suppression file and `.zap/`, `.gitleaks.toml`; require code owner review | CODEOWNERS file present and matches |
| 13 | Unpinned tool installs in `run:` (`curl \| sh`, `pip install tool` unpinned) | pin versions and verify checksums, as done for gitleaks in the PR workflow | grep `curl` / `pip install` |
| 14 | Release triggered by anyone | tag rulesets, `environment:` with required reviewers, `id-token: write` only in the signing job | release workflow |
| 15 | Over-trusting scanner output in PR comments | scanner output can contain attacker text (titles, file names); do not feed it into `run:`; escape in comments; agents reading it must treat it as data | comment step review |

## Patterns

Bad (injectable) and good:

```yaml
# BAD: the title is pasted into the shell script before bash parses it
- run: echo "Checking ${{ github.event.pull_request.title }}"

# GOOD: the value is an environment variable, never parsed as code
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Checking $PR_TITLE"
```

Privilege separation for PR comments from fork PRs (summary, no untrusted code in the privileged job):

```yaml
# workflow 1 (unprivileged): runs on pull_request, uploads results.json as an artifact.
# workflow 2 (privileged): on: workflow_run of workflow 1; permissions: pull-requests: write.
#   - download the artifact, validate it is JSON of the expected shape, post a comment from the data.
#   - never check out or execute anything from the fork in this job.
```

OIDC to AWS (names verified against the action's `action.yml`; pin before use, v6.3.0 resolved to `e1253824e5c10ff9df46874f81ed3ec929e19cfd` on 2026-11-25; v6.3.1 was the latest release on 2026-11-26, so re-resolve before use):

```yaml
jobs:
  deploy:
    permissions:
      id-token: write       # job-scoped: only the deploy/signing job gets the OIDC token
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd # v6.3.0
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-deploy   # example account id
          aws-region: eu-west-1
```

The cloud-side trust policy must restrict the `sub` claim (for example `repo:OWNER/REPO:environment:release`), otherwise any workflow in any repo of the org could assume the role. Do not skip that step: the workflow YAML alone does not make this safe.

Settings-level controls (cannot be expressed in YAML; list them in the PR description so a human sets them): default `GITHUB_TOKEN` read-only; "Approve workflows from outside collaborators" for first-time contributors; restrict allowed actions; disallow Actions creating/approving PRs unless needed; secret scanning push protection; tag and branch rulesets.

## Example CODEOWNERS

```
/.github/workflows/   @ORG/platform @ORG/security
/.github/dependabot.yml @ORG/platform
/.security/           @ORG/security
```

## Dependabot for actions

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: {interval: weekly}
    groups:
      actions: {patterns: ["*"]}
```
