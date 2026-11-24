# Catalog checks for web

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks web`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-WEB-001 | static | medium | Session cookies set without HttpOnly, Secure and SameSite |
| SEC-WEB-002 | static | high | DOM XSS sinks fed with non-literal input |
| SEC-WEB-003 | static | high | Debug mode enabled in production code or configuration |
| SEC-WEB-004 | static | high | Permissive CORS with wildcard or reflected origin and credentials |
| SEC-WEB-005 | static | high | Command and code injection sinks built from dynamic strings |
| SEC-WEB-006 | static | high | SQL statements built by string concatenation or interpolation |
| SEC-WEB-007 | static | high | TLS certificate verification disabled |
| SEC-WEB-008 | static | high | Weak password hashing or insecure randomness for tokens |
| SEC-WEB-009 | static | medium | Open redirect driven by request parameter |
| SEC-WEB-010 | static | medium | CSRF protection disabled or exempted |
| SEC-WEB-050 | dynamic | medium | Session is invalidated server-side after logout |
| SEC-WEB-051 | hybrid | high | File upload validation (type, size, storage location) |
| SEC-WEB-052 | dynamic | medium | Login rate limiting and account lockout |
