# Catalog checks for api

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks api`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-API-001 | static | high | OpenAPI operations without a security requirement |
| SEC-API-002 | static | medium | API key or token accepted in the query string |
| SEC-API-003 | static | high | API server URLs use plain HTTP |
| SEC-API-004 | static | high | JWT verification disabled, alg none or audience not validated |
| SEC-API-005 | static | medium | GraphQL introspection or IDE enabled in production configuration |
| SEC-API-006 | static | high | Mass assignment from request body into models |
| SEC-API-050 | dynamic | high | Broken object-level authorization (two-identity test) |
| SEC-API-051 | dynamic | medium | Schema conformance fuzzing with Schemathesis |
