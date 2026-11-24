# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (lab only)

1. BOLA: authenticate as user A, request user B's object ids; expect 403/404. Repeat across tenants.
2. BFLA: call admin functions with a normal-role token; expect 403.
3. Mass assignment: add `role` or `isAdmin` to a create/update body for a test object; expect ignored or rejected.
4. JWT: submit a test token with modified claims and unsigned variant to the lab; expect 401. Only your own test tokens.
5. Schema conformance: run Schemathesis in a conservative mode against the lab with a request cap approved in scope.
6. Pagination: request an over-limit page size once; expect clamped or rejected. This is a single request, not a load test.
