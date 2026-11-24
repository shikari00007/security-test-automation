# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (lab only)

1. Session cookie flags: log in with a test account, inspect `Set-Cookie` attributes.
2. Access control: with two same-role accounts and one other-tenant account, request object ids owned by the other account; expect 403/404.
3. CSRF: submit a state-changing request from a different origin page in the lab; expect rejection.
4. XSS: insert a harmless unique marker string in input fields, check encoded output in context; do not use payloads that exfiltrate.
5. SSO: replay a captured test-IdP assertion with modified audience in the lab IdP; expect rejection.
6. Headers/CORS: read responses with a controlled `Origin`.

Stop on unexpected side effects, record exactly which requests were sent.
