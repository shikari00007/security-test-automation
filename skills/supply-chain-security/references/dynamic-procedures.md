# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (need written scope or owner approval)

1. Advisory lookup with network: only after the user approves the specific database; send package names and versions only, never source.
2. Registry checks (does an internal name exist publicly?): read-only queries to the public registry with owner approval; no publishing of any package.
3. CI platform settings (branch protection, secrets scope): read-only via admin API with owner-provided token and written scope; do not alter settings.
4. Build reproducibility check in a sandbox without network and without production secrets.

Never publish packages, trigger pipelines, or run `npm install`/`pip install` of untrusted dependencies on the host; use an isolated sandbox if execution is unavoidable.
