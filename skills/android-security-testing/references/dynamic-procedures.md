# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (emulator or lab device, written scope for any backend)

1. Install the APK on an emulator: `adb install`; review `adb shell dumpsys package <pkg>` for exported components.
2. Launch exported components with `adb shell am start` and crafted intents using synthetic data; observe unauthorized access.
3. Inspect app data directory on the emulator for plaintext secrets after using test accounts.
4. Proxy traffic through a lab proxy only if the app is configured for the lab backend named in scope; check TLS validation behavior.
5. Frida or drozer instrumentation: only with written authorization, on the emulator, never on third-party or production services.
6. Collect `logcat` output and redact secrets.

Rooted or personal devices: not allowed without explicit owner approval.
