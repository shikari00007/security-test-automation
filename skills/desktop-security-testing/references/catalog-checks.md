# Catalog checks for desktop

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks desktop`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-DSK-001 | static | high | Electron insecure webPreferences (nodeIntegration, contextIsolation, sandbox, webSecurity) |
| SEC-DSK-002 | static | high | shell.openExternal or loadURL with unvalidated or remote input |
| SEC-DSK-003 | static | high | Auto-update over HTTP or with signature verification disabled |
| SEC-DSK-004 | static | high | Connection string with embedded password in application config |
| SEC-DSK-005 | static | high | Insecure deserialization (BinaryFormatter, ObjectInputStream, pickle) |
| SEC-DSK-050 | dynamic | medium | DLL search-order and hijack testing |
| SEC-DSK-051 | dynamic | medium | IPC and named-pipe authorization testing |
