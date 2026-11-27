# Change-type checklists

Pick every row that matches the diff. Each bullet is checkable by reading code or running a test. "ASVS" refers to OWASP ASVS 5.0.0 (May 2025); CWE ids were checked against cwe.mitre.org (CWE 5.0 pages). They are pointers for the author, not a compliance claim.

## New endpoint / route / handler
- Authentication required unless intentionally public; the decorator/middleware is actually applied to THIS route (not only to the router next door).
- Function-level authorization: only roles that need it (ASVS 8.2.1; CWE-862 Missing Authorization, CWE-306 for critical functions without authn).
- Object-level authorization: every lookup by client-supplied id is scoped to the caller's ownership or tenant, or has an explicit policy check (ASVS 8.2.2; CWE-639). Cross-check the query: does it filter on owner/tenant, or only `WHERE id = ?`?
- Input validated against an allow-list of type/length/range (ASVS 2.2.1); unknown fields not bound into models (ASVS 15.3.3; CWE-915); response returns only needed fields (ASVS 15.3.1).
- State-changing action uses POST/PUT/PATCH/DELETE and CSRF protection if cookie-authenticated (ASVS 3.5.1 anti-forgery or Sec-Fetch validation, 3.5.3 method choice; CWE-352).
- Errors are generic to the client, detailed only in logs (ASVS 16.5.1).
- A test asserts denial (other user gets 403/404, anonymous gets 401), not just success.

## New or changed database query
- Values are bound parameters or ORM filters; identifiers (table, column, ORDER BY direction) come from an allow-list (ASVS 1.2.4; CWE-89).
- Raw-SQL escape hatches (`.raw`, `.extra`, `text()`, `$queryRawUnsafe`, string-built `query()`) are the review target; ORM `filter()` style calls are normally not.
- Multi-tenant: owner/tenant predicate present on reads AND writes.
- Selected columns do not drag sensitive fields (hashes, tokens) into responses.
- Pagination/limits exist for list endpoints (resource exhaustion).

## New or changed template / rendering
- Auto-escaping on for this template type; no `|safe`, `mark_safe`, `Markup`, `{% autoescape off %}`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML` with untrusted data (ASVS 1.2.1; CWE-79). Check the exceptions for plain-text template extensions, JavaScript/URL/attribute contexts, which auto-escaping does not fully cover.
- Template built from user-supplied string (`render_template_string(user_input)`) is server-side template injection (CWE-94 family), not XSS.
- User-controlled URLs in `href/src` restricted to safe schemes (ASVS 1.2.2).
- Markdown/HTML from users goes through a maintained sanitizer with an allow-list (ASVS 1.3.5 for scriptable content).

## New file upload / file handling
- Size limit, extension allow-list and content check (ASVS 5.2.1, 5.2.2; CWE-434).
- Stored name is generated server-side, never the client name in a path (ASVS 5.3.2; CWE-22); resolved path is verified to stay inside the base directory.
- Stored outside web root or served with a forced download type; never executed (ASVS 5.3.1).
- Archives: member names and total expanded size checked. Image/PDF/office parsers run on untrusted bytes: note the parser's patch status.
- Download endpoint checks ownership of the file, not only that the id exists.

## New outbound request / webhook / URL fetch
- URL host/scheme/port validated against an allow-list; redirects not followed unless intended (ASVS 1.3.6, 15.3.2; CWE-918). Blocking "localhost" strings is not enough: consider DNS names resolving to internal addresses.
- Webhook receivers verify a signature or shared secret with constant-time comparison.
- Timeouts and response size limits set.

## New dependency or version change
- Package exists in the intended registry, name is exactly the intended one, publisher and age look sane, not suggested only by an AI assistant (see `ai-generated-code-and-test-review.md`).
- Lockfile updated consistently with manifest; no new registry/URL source; integrity hashes present.
- Install/postinstall scripts and native builds noted; known advisories checked with the project's audit tool when available (CWE-1395; ASVS 15.2.1, 15.2.4).
- Unused or dev-only dependency not added to the production image.
- Hand off supply-chain depth to `supply-chain-security`.

## Config / infrastructure change
- No debug mode, verbose errors or default credentials in production settings (ASVS 13.4.2).
- Secrets come from a secret store or environment, not source, defaults or committed `.env` (ASVS 13.3.1; CWE-798).
- CORS origins are explicit; no wildcard with credentials (CWE-942). Security headers not removed.
- IaC: no `0.0.0.0/0` on admin ports, public buckets, wildcard IAM actions/resources, privileged or root containers. Hand off depth to `cloud-kubernetes-security`.
- CI: untrusted PR code never runs with secrets; third-party actions pinned; least-privilege token permissions.

## Authentication / session / authorization change
- Diff the policy: list who could do X before and who can after. State it explicitly in the review.
- Password/OTP/reset: single-use, expiring, rate-limited tokens; no user enumeration in messages; secure comparison.
- Sessions/tokens: Secure, HttpOnly, SameSite flags; rotation on login/privilege change; JWT verification pins algorithms and checks `exp`, `aud`, `iss`.
- "Admin" and "internal" shortcuts (header checks, IP checks, debug flags) are not trust anchors on their own.
- Authorization is enforced server-side at a trusted layer (ASVS 8.3.1), not by hiding UI.
- Escalate to `web-security-testing` or `api-security-testing` for dynamic checks within written scope.

## Cryptography change
- No custom primitives; no ECB or PKCS#1 v1.5 padding (ASVS 11.3.1); no MD5/SHA-1 for signatures or other cryptographic use (ASVS 11.4.1; CWE-327). Passwords use a slow salted password hash, argon2id, scrypt or bcrypt (ASVS 11.4.2).
- Randomness for tokens/IDs from a CSPRNG (`secrets`, `crypto.randomBytes`), not `random`/`Math.random` (CWE-330; ASVS 11.5.1).
- Keys not in source; nonces/IVs never reused with the same key where the mode forbids it.
- TLS verification not disabled (`verify=False`, `rejectUnauthorized: false`) except in a clearly test-only path.

## LLM / agent feature
- Untrusted text (user input, retrieved documents, web pages, tool results, other agents) is treated as data that can contain instructions (OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection).
- Model output is not passed unvalidated into SQL, shell, `eval`, HTML or URLs (LLM05 Improper Output Handling).
- Tools/agents get least privilege; destructive or money-moving actions need a human confirmation or a policy gate (LLM06 Excessive Agency).
- Secrets and other tenants' data are not placed in prompts or retrieval indexes the caller should not see (LLM02 Sensitive Information Disclosure); per-user authorization applies to retrieval.
- Token/cost/loop limits exist (LLM10 Unbounded Consumption). System prompt is not the only control (LLM07).
- Hand off depth to `ai-llm-security`.

## Database migration
- Migration is reversible or has a documented rollback; no data-destroying statement without backup/confirmation.
- Backfills do not copy secrets/PII into less-protected columns or logs; new columns holding sensitive data are encrypted or hashed as appropriate.
- Constraints that enforce security invariants (NOT NULL owner_id, unique, FK) are added, not dropped, and backfill sets owner/tenant correctly.
- Migration scripts do not embed credentials and do not run dynamic SQL from external input.
- Row-level security or tenant filters still hold on new tables/views.
