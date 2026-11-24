# Security policy

Report vulnerabilities in this framework privately via GitHub Security Advisories on `shikari00007/security-test-automation` (once published). Do not include secrets or customer data in reports.

Design boundaries (tested in `tests/test_core_engine.py`): the runner is offline and read-only by default; it never follows symlinks out of the target, refuses output inside the target tree, redacts secrets from evidence, never accepts a non-empty evidence string as proof of execution, and refuses dynamic testing without a valid authorization scope. Skills are guidance, not a sandbox. Hash-chained manifests are tamper-*evident*, not forgery-proof, unless you supply `--hmac-key-env`.
