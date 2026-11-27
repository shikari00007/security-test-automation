# False alarms, severity, confidence, evidence, block vs suggest

## Avoiding false alarms

A review that cries wolf gets ignored. Before you write a finding, pass it through this gate, in order:

1. **Reachable?** Is the code on a deployed path (not test-only, dead, behind a flag that is off)? Check callers with a search, do not guess.
2. **Attacker-controlled?** Who controls the value at the source? An admin-only setting or a constant is not the same as a query parameter.
3. **Already protected?** Name the control and point at it: framework auto-escaping, ORM parameterization, CSRF middleware, request-model validation, a gateway policy, a wrapper function. If you cannot name it, you may not claim protection; if you can, do not flag the sink. Verify the control applies in this exact context (see table below).
4. **Exploitable or hygiene?** Can you describe a concrete harmful request or state? If not, label it hygiene and keep it non-blocking.
5. **State assumptions** explicitly, and what would change the verdict.

If a point is "protected by the framework", you may still add a short "checked, no issue" line so the author knows it was looked at. Do not file it as a finding.

### Framework protections: where they hold and where they stop

| Protection | Holds | Stops holding |
|---|---|---|
| Jinja2/Flask autoescape, Django template autoescape | Variables in `.html` templates in HTML text and quoted attributes | `|safe`, `mark_safe`, `Markup`, autoescape off, `.txt` templates, unquoted attributes, `<script>` bodies and `javascript:` URLs, `render_template_string` of user-built template text |
| React JSX escaping | Text children and attribute values | `dangerouslySetInnerHTML`, `href={userUrl}` with `javascript:`, server-built HTML strings, `eval`-like sinks |
| ORM filters (Django, SQLAlchemy, Prisma, TypeORM) | Values bound as parameters | `.raw()`/`.extra()`/`text()`/`$queryRawUnsafe`/string-built SQL, dynamic identifiers (ORDER BY, column names) |
| Pydantic / FastAPI request models | Type validation; unknown fields ignored by default | Model that declares a privileged field (`is_admin`) and is bound straight to the DB model; `extra="allow"` |
| Django CSRF middleware | State-changing views with session cookies when middleware is enabled | `@csrf_exempt`, middleware removed, token-authenticated APIs (different model) |
| `subprocess` with list argv, `execFile` | Metacharacters stay literal | `shell=True`, `exec(string)`, `sh -c` wrappers, argument injection (a value beginning with `-`) |

The first row, the React row, the ORM row, the pydantic row and the subprocess row were executed in a sandbox; see `worked-example.md` for how to rerun them.

## Severity

Severity answers "how bad if exploited, and how easy is it to exploit here". Write the reason next to the label. Use these five labels; they are review labels, not a CVSS score (use `security-reporting` and the project's scheme for formal scoring).

| Label | Typical meaning | Examples |
|---|---|---|
| Critical | Remote, unauthenticated or low-privilege, leads to code execution, full data exposure or account takeover | Unauthenticated SQL injection, hard-coded admin credential in a deployed service |
| High | Authenticated user can read/modify other users' sensitive data or escalate privilege | IDOR on invoices, missing authorization on an admin action |
| Medium | Needs a precondition (specific role, user interaction, unusual config) or limited impact | Reflected XSS needing a click, SSRF restricted to a small set of hosts |
| Low | Hard to exploit or small impact | Verbose error to authenticated users, missing rate limit on low-value action |
| Hygiene | No demonstrated exploit path; weakens defence in depth or future maintainability | PII in logs, unpinned dev dependency, missing security header with no sensitive content |

Exposure and data sensitivity move severity up or down by one level; say which.

## Confidence

| Label | Meaning | What to do |
|---|---|---|
| High | You traced source to sink, found no protection, and can describe the request/state that triggers it | Report as a finding; offer a reproduction idea |
| Medium | Path looks real but one hop depends on code or config you could not see | Report with the explicit assumption; ask the author to confirm |
| Low | Pattern match or intuition | Ask a question instead of making a claim; do not block |

Confidence and severity are independent. "High severity, low confidence" becomes a question to the author plus a request for independent confirmation, not a block.

## Evidence format

Every finding carries:

- **Where:** `path/to/file.py:42` (and the other hops).
- **Data-flow path:** `<int:invoice_id> (app.py:36) -> invoice_detail(invoice_id) (app.py:37) -> SELECT ... WHERE id = ? (app.py:39-41) -> render_template (app.py:45)`.
- **Missing or broken control:** what should have stopped it.
- **Minimal reproduction idea:** a description or test, with synthetic ids and a harmless marker; no weaponized payloads, no live hosts, no production data. Example: "log in as user B, request `/invoices/<id owned by user A>`, expect 404, actually 200".
- **Redaction:** show at most the last 4 characters of any secret; use synthetic data in comments.

## Block vs suggest

| Decision | Use when | Wording |
|---|---|---|
| Block (request changes) | Confidence is medium or high AND severity is high or critical, or the change removes an existing security control, or leaks secrets/credentials | "Blocking: ..." |
| Fix before release | Medium severity with clear fix; can merge behind a flag or follow-up with an owner and date agreed | "Please fix before this ships: ..." |
| Suggest | Low severity or hygiene; defence in depth | "Suggestion (non-blocking): ..." |
| Question | Low confidence, missing context | "Question: ..." |
| Praise | A good security decision (denial test added, allow-list used) | "Nice: ..." |

Never block on style, on a theoretical issue you cannot describe an attack for, or on something the framework demonstrably handles. A committed live secret is always blocking: also ask for rotation, since deleting it from the diff does not unexpose it.

Independent confirmation: before a high or critical finding is stated to stakeholders, hand the evidence packet to `security-finding-validation` (fresh-context verifier). The reviewer's label is a candidate until that verdict returns. Hand confirmed findings to `vulnerability-triage-and-fix` for the fix, then to `security-regression-generation` for the test.
