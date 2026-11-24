# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (simulator in a lab; written scope for any backend)

1. Run the app in the Xcode simulator, then inspect the app container for plaintext secrets after using test accounts.
2. Open custom URL schemes and universal links with crafted synthetic parameters; observe handling.
3. Lab proxy: only when the app targets the lab backend in scope; verify ATS and pinning behavior.
4. LLDB or Frida: only with written authorization on a device or simulator you own; never against production or third-party apps.
5. Keychain inspection on a simulator build only.

Physical-device testing needs owner approval; jailbreaking is out of scope by default.
