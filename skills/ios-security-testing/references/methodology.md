# iOS methodology (MASVS v2 categories)

## MASVS-STORAGE
- Look for: secrets in `UserDefaults`, plist files or Core Data without protection, Keychain items with `kSecAttrAccessibleAlways` or `...AfterFirstUnlock` where stricter is needed, missing `NSFileProtection`, sensitive data in logs (`NSLog`, `print`), pasteboard use, screenshots of sensitive screens (snapshot caching).
- Secure: Keychain with `WhenUnlockedThisDeviceOnly` for secrets, file protection complete, no secret logging.

## MASVS-CRYPTO
- Hardcoded keys, weak algorithms (`kCCAlgorithmDES`, MD5/SHA1 for security), ECB, static IVs, insecure random.

## MASVS-AUTH
- Biometric checks via `LAContext` only (not bound to Keychain access control), client-side auth decisions.

## MASVS-NETWORK
- `NSAppTransportSecurity` with `NSAllowsArbitraryLoads` or broad exception domains, custom `URLSessionDelegate` accepting any trust, missing pinning where the model requires it.

## MASVS-PLATFORM
- Custom URL schemes handled without validation, universal links with weak `apple-app-site-association` scoping, `UIWebView` (deprecated) or `WKWebView` with JavaScript bridge exposing sensitive handlers, `file://` access flags, pasteboard leakage, extensions and app groups sharing data broadly.
- Entitlements: `get-task-allow` in release, overly broad `keychain-access-groups`, `com.apple.developer.associated-domains` misconfiguration.

## MASVS-CODE
- Outdated deployment target, vulnerable third-party pods (see `supply-chain-security`), binary hardening flags (PIE, stack protector, ARC) where binary is available.

## MASVS-RESILIENCE and PRIVACY
- Jailbreak detection absence is informational unless threat model requires; privacy manifest and tracking domains, excessive permissions strings in Info.plist.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
