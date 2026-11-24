# Supply chain methodology

## Dependency integrity
- Lockfile missing or not committed, floating versions (`*`, `latest`, wide ranges), dependencies from git URLs or tarballs without integrity, mixed registries, `--ignore-scripts` absent where relevant (review install scripts in dependencies by reading, never executing).
- Dependency confusion: internal-looking package names resolvable from public registry; missing scope or registry pinning in `.npmrc`/`pip.conf`/`settings.xml`.
- Typosquat-like names and recently changed maintainers are candidates to review, not findings by themselves.

## Vulnerable and outdated components
- Match lockfile versions with advisories (OSV, GitHub Advisory, NVD) using a local database; without it the check is `blocked`. End-of-life frameworks and runtimes.

## CI/CD workflows
- GitHub Actions: `pull_request_target` checking out untrusted code, `${{ github.event.* }}` interpolated into `run:` (script injection), actions pinned by tag instead of commit SHA, default broad `permissions`, secrets exposed to forks, self-hosted runners on public repos.
- GitLab/Jenkins equivalents: unprotected variables, scripts from untrusted branches, curl-pipe-shell.
- Secure: least-privilege `permissions`, pinned SHAs, no secrets for untrusted code.

## Secrets
- Committed keys, tokens, `.env` files, private keys, cloud credentials; history review with a scanner such as Gitleaks. Report fingerprints only, rotate if real.

## Build, containers and artifacts
- Dockerfile: unpinned base image (tag only, no digest), `latest`, running as root, `ADD` from URL, secrets via build args, copying whole context including `.env`.
- No SBOM, no signing, no provenance (SLSA levels), unsigned releases, artifact checksums absent, release pipeline modifiable by any contributor.

## Governance
- Missing branch protection and review requirements, CODEOWNERS, dependency update automation without review.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
