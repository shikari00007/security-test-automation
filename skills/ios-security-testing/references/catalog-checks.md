# Catalog checks for ios

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks ios`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-IOS-001 | static | high | App Transport Security disabled (NSAllowsArbitraryLoads) |
| SEC-IOS-002 | static | high | get-task-allow entitlement enabled |
| SEC-IOS-003 | static | high | Insecure Keychain accessibility or secrets in UserDefaults |
| SEC-IOS-004 | static | medium | Deprecated UIWebView or WKWebView file-URL access preferences |
| SEC-IOS-050 | dynamic | medium | URL scheme and universal link hijack validation |
| SEC-IOS-051 | manual | low | Runtime binary protections review (jailbreak detection, anti-tamper) |
