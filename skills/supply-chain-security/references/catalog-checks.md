# Catalog checks for supply-chain

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks supply-chain`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-SC-001 | static | medium | Dependency manifest without a lockfile |
| SEC-SC-002 | static | medium | Floating or unpinned dependency specifications |
| SEC-SC-003 | static | low | npm install lifecycle scripts present |
| SEC-SC-004 | static | medium | GitHub Actions not pinned to a commit SHA |
| SEC-SC-005 | static | high | GitHub workflow privilege and injection risks |
| SEC-SC-006 | static | high | Hardcoded secrets in the repository |
| SEC-SC-008 | static | medium | Dependencies fetched from VCS, URLs or plain HTTP |
| SEC-SC-020 | static | high | Known-vulnerable dependencies (OSV) |
