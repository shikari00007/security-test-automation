# Catalog checks for android

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks android`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-AND-001 | static | high | Exported component without permission protection |
| SEC-AND-002 | static | high | Application is debuggable in manifest |
| SEC-AND-003 | static | medium | Application data backup enabled |
| SEC-AND-004 | static | high | Cleartext (HTTP) traffic permitted |
| SEC-AND-005 | static | high | WebView with JavaScript enabled exposes JS bridge or file access |
| SEC-AND-006 | static | high | Insecure local storage (world-accessible files, plaintext secrets in SharedPreferences) |
| SEC-AND-050 | dynamic | medium | Runtime certificate-pinning bypass and instrumentation resistance review |
| SEC-AND-051 | dynamic | medium | Intent fuzzing of exported components |
