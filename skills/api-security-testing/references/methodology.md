# API methodology (OWASP API Security Top 10, 2023 naming)

- API1 Broken Object Level Authorization: handlers loading objects by client-supplied id without owner or tenant check. Secure: per-object authorization in every handler.
- API2 Broken Authentication: weak or missing token validation, JWT `alg` none, unverified signature, `kid` injection, missing expiry, long-lived tokens, API keys in URLs, no lockout design (review config only), OAuth flows missing `state`/PKCE.
- API3 Broken Object Property Level Authorization: mass assignment (binding request bodies to models), excessive data exposure in responses, writable read-only fields (`role`, `isAdmin`).
- API4 Unrestricted Resource Consumption: missing pagination limits, no rate limit configuration, unbounded uploads, GraphQL depth and complexity limits absent, batching/alias abuse. Review configuration; do not load test.
- API5 Broken Function Level Authorization: admin or internal functions reachable by regular roles; method-level differences (GET protected, PUT not).
- API6 Unrestricted Access to Sensitive Business Flows: flows like purchase or signup without abuse controls; review design and controls.
- API7 Server Side Request Forgery: endpoints fetching user-supplied URLs, webhooks, import-by-URL.
- API8 Security Misconfiguration: permissive CORS, verbose errors, debug endpoints, missing TLS, default credentials, unnecessary HTTP methods.
- API9 Improper Inventory Management: old versions, undocumented or shadow endpoints, test environments reachable; compare spec to routes.
- API10 Unsafe Consumption of APIs: trusting third-party responses, missing TLS verification, following redirects blindly.

## GraphQL notes
Introspection enabled in production, field-level authorization missing, query depth/cost limits absent, batching, verbose errors.

## gRPC and SOAP notes
Reflection enabled, missing per-method authn, XML external entities and WS-Security misconfiguration for SOAP.

## Enterprise auth
OIDC/OAuth resource-server validation of `iss`, `aud`, `exp`, scopes; token introspection; mTLS client cert mapping; LDAP-backed auth filter escaping.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.
