# Security policy

## Reporting a vulnerability in this framework

Please report vulnerabilities **privately** using [GitHub private vulnerability reporting](https://github.com/shikari00007/security-test-automation/security/advisories/new) for this repository. Do not open a public issue, and do not include real secrets or customer data in a report.

Examples of in-scope reports: a way to escape the target directory or write inside the audited tree, forge or tamper with a verified run, bypass the scope/policy gate, cause unintended command execution or network access, or leak secrets through reports.

Not in scope: findings the tool reports about *your* code (those are candidates to review), and missing features listed as unimplemented in the README.

This is a Developer Preview maintained on a best-effort basis; there is no guaranteed response time, but reports are taken seriously and credited if you wish.

## Design boundaries (tested)

The runner is offline and read-only by default. It never follows symlinks out of the target, refuses output inside the target tree, redacts secrets in evidence, never accepts a non-empty evidence string as proof of execution, and refuses dynamic testing without a valid authorization scope. Skills are guidance, not a sandbox. Hash-chained manifests are tamper-*evident*, not forgery-proof, unless you supply `--hmac-key-env`. See [docs/VERIFICATION.md](docs/VERIFICATION.md).
