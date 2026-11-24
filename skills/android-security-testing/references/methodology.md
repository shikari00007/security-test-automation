# Android methodology (grouped by MASVS v2 categories)

## MASVS-STORAGE
- Look for: sensitive data in `SharedPreferences` (not encrypted), SQLite without protection, world-readable files, secrets in `strings.xml` or BuildConfig, data in logs (`Log.d`), clipboard use, `allowBackup="true"`.
- Secure: Keystore-backed encryption, no secrets in resources or logs, backup disabled or rules excluding sensitive data.

## MASVS-CRYPTO
- Look for: hardcoded keys, ECB mode, MD5/SHA1 for security, static IVs, `java.util.Random` for secrets.

## MASVS-AUTH
- Look for: client-side-only authentication decisions, biometric prompts without cryptographic binding (`CryptoObject`), tokens stored in plain storage.

## MASVS-NETWORK
- Look for: `usesCleartextTraffic`, `cleartextTrafficPermitted`, custom TrustManager accepting all, `HostnameVerifier` returning true, missing pinning where required, user-added CA trust in release.

## MASVS-PLATFORM
- Exported activities, services, receivers, providers without permission (`android:exported`, intent filters), `PendingIntent` with mutable base intent, deep links accepting unvalidated parameters, content provider path traversal, WebView: `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`, `loadUrl` with untrusted data.

## MASVS-CODE
- `debuggable="true"`, outdated `minSdkVersion`/`targetSdkVersion`, vulnerable libraries (see `supply-chain-security`), unsafe deserialization, native code issues.

## MASVS-RESILIENCE
- Absence of obfuscation or tamper detection is informational unless the threat model requires it. Do not present it as a vulnerability by default.

## MASVS-PRIVACY
- Excess permissions, SDKs collecting identifiers, data sent to third parties without disclosure.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
