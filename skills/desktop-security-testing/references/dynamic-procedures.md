# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (isolated VM, written scope)

1. Install in a clean lab VM and inspect file and registry permissions of the install location and services.
2. Monitor file, registry and process events during startup and login with test accounts (Procmon or `strace`), look for loads from writable paths.
3. Check update traffic in the lab against a lab update server named in scope; verify signature enforcement by serving a test-signed vs unsigned package.
4. Electron: with DevTools in the lab build, review window configuration at runtime and IPC messages.
5. Review stored credentials and tokens in the lab profile directory after using test accounts.

No testing against the vendor's production update or authentication servers.
