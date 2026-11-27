# Authorization patterns

Editions: OWASP Authorization Cheat Sheet (live page, fetched 2026-11-25); OWASP ASVS 5.0.0 (May 2025) V8; OWASP API Security Top 10 2023 (API1 BOLA, API3 BOPLA, API5 BFLA); CWE 5.0 entries cited below. Working code: [permission-map-test-matrix](permission-map-test-matrix.md) and [framework-recipes](framework-recipes.md).

## Principles (each is a checkable rule)

| Rule | Source | In code |
|---|---|---|
| Deny by default: a route/action with no policy entry is refused | Cheat sheet "Deny by Default"; ASVS 8.2.1 | enforcement hook returns 403 when the lookup misses; boot-time failure where possible |
| Check on every request, configured globally, not per method; one missed check is enough for an attacker | Cheat sheet "Validate Permissions on Every Request"; ASVS 8.3.1 | middleware/dependency/registrar, not `if user.is_admin` scattered in handlers |
| Server-side only; client hiding a button is not a control | ASVS 8.3.1 | never branch on a client-sent role/flag |
| Object-level: every read AND write of an object by id verifies the principal's relation to that object | ASVS 8.2.2 (IDOR/BOLA); API1:2023; CWE-639 | one loader/queryset scope used by every handler and list |
| Function-level from a declared permission map | ASVS 8.1.1, 8.2.1; API5:2023; CWE-862 | `PERMISSIONS` data + generated tests |
| Field-level: which properties may be read/written | ASVS 8.2.3, 8.1.2; API3:2023; CWE-915 | strict input models, explicit response serializers |
| Multi-tenancy: cross-tenant operations impossible | ASVS 8.4.1 | tenant id taken from the authenticated session/token, applied in the query, not from the request |
| Authorization changes take effect promptly | ASVS 8.3.2 (L3) | session lookups or short token TTL; avoid long-lived role claims |
| Downstream services act with the originating subject's rights | ASVS 8.3.3 (L3) | propagate user context/token exchange, not a blanket service identity |
| Admin interfaces not protected by network location alone | ASVS 8.4.2 (L3) | role check + re-auth/MFA, separate route prefix, audit log |

## Central policy vs scattered ifs

Scattered `if` checks fail by omission: the new endpoint has none. Central enforcement fails closed: the new endpoint is denied until someone declares it. Choose by size:

| Project | Mechanism |
|---|---|
| Small/medium service | permission map as data + one enforcement hook + one object loader (the matrix reference) |
| Many roles, resource-specific rules, multi-tenant | ABAC/ReBAC (the cheat sheet prefers these over plain RBAC); policy engines such as OPA/Rego, Cedar, Casbin or OpenFGA (confirm the current API in their docs before adopting); still keep a deny-by-default hook and generated tests |
| Framework-native | DRF `DEFAULT_PERMISSION_CLASSES`, Spring Security filter chain, Django middleware, NestJS guards registered globally (`APP_GUARD`) |

Do not let the library's defaults define your requirements; write the map first, then configure the tool and test the configuration (cheat sheet "Review Tools and Frameworks Carefully").

## Object-level (BOLA/IDOR) recipe

1. Never fetch by bare id: `get(id)` becomes `get(id, scope=principal)` or a queryset already filtered by tenant and ownership (`Model.objects.visible_to(request)`).
2. Apply the same scope to list, search, export, bulk, nested routes (`/projects/{p}/files/{f}`: verify BOTH `p` and that `f` belongs to `p`) and GraphQL resolvers/batch endpoints.
3. Write paths (PATCH/PUT/DELETE/POST-action) need the check too, and POST-create must verify that referenced foreign ids (`project_id`, `assignee_id`) belong to the caller's tenant.
4. Unpredictable ids (UUIDs) help but are not a control (cheat sheet). Return 404 for foreign objects, 403 for forbidden functions.
5. Files and presigned URLs: check ownership before generating the URL; scope the key prefix by tenant.

## Multi-tenancy

- Tenant id comes from the session/verified token claim, set at login; ignore `X-Tenant-Id`, `?tenant=`, body fields. If a user can switch tenants, verify membership server-side on switch and re-issue the session.
- Enforce at the lowest shared layer: a default-scoped repository/queryset, and for PostgreSQL consider row-level security with `SET LOCAL app.tenant_id` per transaction (test it with a second tenant; verify against your PostgreSQL version's docs).
- Caches, queues, search indexes, object-store keys and logs also need tenant scoping; a cache key without tenant id is a cross-tenant leak.
- Test: seed two tenants, run every object endpoint as tenant B against tenant A ids (the object matrix).

## Mass assignment (CWE-915, API3:2023)

- Input models list writable fields explicitly and reject unknown ones (`extra="forbid"`, zod `.strict()`, DRF `fields=[...]`, Django forms with explicit `fields`). Server sets `owner_id`, `tenant_id`, `role`, `is_admin`, `status`, `price`, `created_by`.
- Output models are explicit too (no `return user.__dict__`); hide password hashes, tokens, internal flags.
- Test: send `{"role":"admin"}` / `{"owner_id":...}` and assert 4xx and unchanged state.

## Admin endpoints and privileged actions

Own route prefix with a role check from the map; require recent re-authentication/MFA for destructive or account-takeover-capable actions (ASVS 7.5.3 L3, 8.4.2 L3); audit-log who did what to which object; admin cannot set user passwords (ASVS 6.4.6); bootstrap admins from deployment config, no default credentials (ASVS 6.3.2); the "admin" role is tenant-scoped unless an explicit, separate super-admin concept exists.

## Service-to-service

| Need | Pattern |
|---|---|
| Internal call with no user | OAuth client-credentials with short-lived, audience-restricted tokens, or mTLS (RFC 8705); each service verifies `iss`/`aud` (ASVS 9.2.3) |
| Call on behalf of a user | pass/exchange the user's token (RFC 8693 token exchange) so the downstream authorizes the originating subject (ASVS 8.3.3) |
| Shared API keys | per-caller, rotatable, scoped, stored hashed, never in URLs; not a replacement for authorization |
| "Internal network = trusted" | not a control; authenticate every hop |

## Writing the authorization test first (red then green)

1. Add the policy entry and matrix test for the new endpoint; run it: it must fail (403 deny-by-default, or matrix cell red).
2. Implement; run; matrix green.
3. Temporarily remove the object check and confirm a cell goes red (monkeypatch the object rule in the test, never a flag in the app), restore it.
Report as "these checks passed", never "secure".
