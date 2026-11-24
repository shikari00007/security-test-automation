# Desktop methodology

## Electron
- `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent`, `enableRemoteModule`, loading remote content in a privileged window.
- Preload scripts exposing generic `ipcRenderer.send` or filesystem/shell access; IPC handlers trusting renderer input without validation or sender checks.
- `shell.openExternal` with unvalidated URLs; custom protocol handlers; `will-navigate` and `new-window` not restricted; permissive CSP.
- Fuses (RunAsNode, NodeOptions, asar integrity) and ASAR tamper resistance.
- Secure: context isolation on, sandbox on, minimal preload API, validated IPC, allowlisted navigation.

## .NET and native clients
- Direct database connections from the client with embedded credentials (two-tier), connection strings in config files, hardcoded API keys.
- DLL search order hijack: loading libraries without full path, writable install directories; unquoted service paths; services running as SYSTEM with writable binaries.
- Insecure deserialization (BinaryFormatter, `TypeNameHandling`), named pipes and local sockets without ACLs, COM/registry permissions.
- Weak local protection: credentials in plaintext files, registry or weak encryption; secure use is DPAPI or OS credential store.

## Update and installation channel
- HTTP update feeds, missing signature verification on downloaded updates, unsigned installers, update to attacker-writable directory.

## Enterprise authentication
- LDAP: bind credentials embedded in the client, LDAP without TLS, unescaped filter construction. Kerberos/SSPI: service principal names, delegation, fallback to NTLM; review configuration. SSO/OIDC in desktop: use of system browser and PKCE, token storage in OS store, loopback redirect handling, refresh token lifetime.

## Data and privacy
- Logs with secrets, crash dumps, temp files, clipboard and screenshot handling.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
