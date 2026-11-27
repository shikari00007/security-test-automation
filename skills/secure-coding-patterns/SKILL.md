---
name: secure-coding-patterns
description: "Use when the user says things like \"add an endpoint that takes user input\", \"is it ok to build this SQL query with an f-string\", \"write this query safely\", \"how do I log failed logins without leaking passwords\", \"let users upload a file\", \"fetch a URL the user gives us\", \"render user text in a template\". Applies secure patterns as Claude Code writes code: validation, output encoding, parameterised queries, argv-list commands, safe paths/uploads, SSRF-safe fetches, deserialization, redirects, CSRF/CORS, generic errors, log hygiene, ReDoS. Not for: reviewing a diff/PR (security-code-review) or a running app (web-security-testing, api-security-testing), login/session/password design (authn-authz-implementation), secret storage (secrets-management), LLM/agent features (ai-llm-security), dependency risk (supply-chain-security), proving a finding (security-finding-validation). Related: security-unit-testing, vulnerability-triage-and-fix, security-project-context, security-regression-generation."
license: MIT
compatibility: Any Agent Skills runtime with file read/write access. Recipes target Python 3.9+ and Node 22.19+ (undici 8); for older Node pin an older undici and re-run the SSRF test; optional security-skills CLI (Python 3.10+, offline). No network required.
metadata:
  author: security-test-automation contributors
  version: "0.4.0"
  category: build
---

# Secure Coding Patterns

> **Developer Preview.** Recipes were executed in a sandbox on the versions listed in the verification notes; they are baselines, not a guarantee, and other versions or frameworks may behave differently.

**Objective.** Stop the injection-class and boundary bugs that a coding assistant most often writes by default: an f-string SQL query that returns every row for `' OR '1'='1`, `shell=True` with a filename, `open(root + name)` that reads `../secret`, `requests.get(user_url)` that reaches `169.254.169.254` or a redirect to an internal host, `pickle.loads` on a request body, `redirect(request.args["next"])`, `str(exc)` in a 500 body, and a password in a log line. This skill makes you pick the safe pattern for the sink *before* writing the line, and prove with a test that the hostile input fails safely.

## When this applies

- You are about to write or change code that touches a trust boundary: request data, files, queues, webhooks, config from users, third-party responses.
- You are about to use a dangerous sink: SQL/NoSQL/LDAP query, shell or process, template, HTML output, filesystem path, outbound HTTP, deserializer, XML parser, redirect, regex, logger.

## When this does not apply

- Reviewing a diff, PR or existing source: `security-code-review`. Testing a running app or API: `web-security-testing` / `api-security-testing`. Then `security-finding-validation`.
- Login, session, password hashing or reset-flow design: `authn-authz-implementation`. Secret storage and keeping secrets out of logs: `secrets-management`. Writing security unit tests as the deliverable: `security-unit-testing`. Fixing a reported finding: `vulnerability-triage-and-fix`.
- LLM prompt-injection and agent tool safety (`ai-llm-security`), package and CI trust (`supply-chain-security`), cloud/Kubernetes config (`cloud-kubernetes-security`): out of scope here; say so and hand off.
- Pure refactor with no new input, output or I/O: do not invoke; no security ceremony needed.

## Discovery questions (ask only what the code cannot answer)

First read `.agents/security-project-context.md` if present (written by `security-project-context`) and do not re-ask what it answers (stack, trust boundaries, data classes, auth model).

1. Which language, framework and data-access layer (ORM or raw driver) does this code use?
2. Where does the input come from, and who controls it (anonymous user, authenticated user, another service, an admin)?
3. What does the task touch: database, files, outbound HTTP, templates/HTML, shell, auth/session, deserialization?
4. Is there an existing project helper (validator, safe-fetch, sanitizer, logger redaction) to reuse instead of adding a new one?
5. What must keep working (accepted file types, allowed hosts, sort keys, origins)? Those become allow-lists.

## Workflow

1. **Classify the task** by what it touches (list from question 3). Output: one line per sink, e.g. `SQL: orders by id`, `HTTP out: webhook URL`.
2. **Run the preflight** for each touched area in [decision tables and preflight](references/decision-tables-and-preflight.md). Output: the pattern chosen per sink from the decision table. Decision point: if the safest option is "do not accept this input" or "do not fetch user URLs" (fixed mapping), prefer it and say so.
3. **Find the recipe** for your language: [injection and commands](references/injection-safe-data-access-and-commands.md), [validation and encoding](references/input-validation-and-output-encoding.md), [files, uploads and races](references/files-paths-uploads-and-races.md), [outbound requests, parsers, redirects](references/outbound-requests-parsers-and-redirects.md), [web boundary, errors, logging, regex](references/web-boundary-errors-logging-and-regex.md). Prefer the framework's built-in control over hand-rolling; reuse project helpers first.
4. **Write the code** with the safe pattern. Keep the diff small: change the sink and its immediate validation, not the surrounding design. Validate at the boundary (schema), encode at the sink.
5. **Write the hostile-input test** next to the feature: a harmless marker input (`' OR '1'='1`, `../secret.txt`, `; echo MARKER`, `<img src=x onerror=MARKER>`, a local test server standing in for the internal service). Output: a test that fails against the unsafe form and passes against yours. Prove "fails before" by running it on the unsafe version or a temporary stub, then restore.
6. **Run** the project's tests and linters, and `security-skills audit . --profile quick` only if the CLI is installed. Record what ran and what did not.
7. **Hand off** anything out of scope (see Integration) and list assumptions (allow-lists you chose, limits you set) for the user to confirm.

## Secure-by-default rules

- Data and structure travel separately: bound parameters, argv elements, escaped filter values, template variables. Never concatenate user text into SQL, shell, templates, filters or HTML.
- Identifiers (column, table, sort, field names) are chosen from an allow-list dict, never bound or concatenated.
- Validate at the server boundary with a strict schema (unknown fields rejected, types, ranges, lengths); client checks are UX only.
- Encode for the exact output context; a scheme allow-list for user URLs; no `innerHTML`/`|safe`/`mark_safe` on user text.
- No shell (`shell=True`, `exec`/`execSync` with strings); use `--` before user-controlled args; set timeouts.
- Paths: generated names; otherwise `resolve()` then verify containment; uploads: extension allow-list, content check, size cap, stored outside the web root.
- Outbound requests to user-influenced URLs: prefer a fixed mapping; else allow-list + public-address check on the connecting address + no automatic redirects + timeouts and size cap.
- Never unpickle/`yaml.load`/`eval` untrusted data; XML parsers with DTD/entities/network off.
- Redirect only to validated local paths or mapped ids.
- Errors to clients are generic with a correlation id; details go to the log. Logs carry no secrets, tokens or raw newlines.
- Check-then-act on shared state is one atomic operation (conditional UPDATE, `O_EXCL`, unique constraint).
- Do not disable, loosen or comment out an existing control (CSRF, escaping, validation, TLS verification) to make a test pass; fix the input or ask.
- Cite ASVS or CWE only from the verified map (ASVS 5.0.0), and only when the code matches.

## Verification

- Run the hostile-input test and show both outcomes: the unsafe form is exploitable (marker appears) and the final code is not, while benign input still works.
- Run the full project test suite and any installed linter or `security-skills` command; report exactly what passed.
- Say "these checks passed", never "this is secure". State what was not tested (live DB, HTTPS pinning, archives, browsers).
- Never test against hosts you were not given; use local servers and temp directories. Scope rules: `security-project-context`.

## Examples

**Triggers.** User: "add `GET /files/<name>` that returns an uploaded file". Classify: files. Preflight: name is user input. Use generated ids or `resolve()` plus containment; add a test requesting `../secret.txt`, an absolute path and a symlink; confirm 403/404 and that the marker file's content never appears.

**Triggers.** User: "let admins paste a webhook URL and we POST to it". Classify: HTTP out. Choose allow-list or fixed mapping, public-address check on the connecting address, redirects off; test with a local "internal" server and a 302 to it.

**Does NOT trigger.** User: "review this repo for vulnerabilities and write a report" (use `security-code-review`, or `web-security-testing` for a running app, then `security-reporting`). Also not: "rename this variable" or "make this CSS responsive".

## Integration

- Reviewing existing code or a diff: `security-code-review`; fixing a reported finding: `vulnerability-triage-and-fix`; building login/sessions/password hashing: `authn-authz-implementation`; log redaction and secret storage design: `secrets-management`; security unit tests as the deliverable: `security-unit-testing`.
- Running app or API needs testing: `web-security-testing`, `api-security-testing`; confirm candidates with `security-finding-validation`.
- Bug fixed and needs a lock-in test: `security-regression-generation`.
- LLM or agent features touch this code: `ai-llm-security`. New dependency needed for a safer parser or sanitizer: `supply-chain-security` before adding it.
- Missing stack facts or scope: `security-project-context`; deciding depth of checks: `security-test-strategy`.
- Optional CLI (verify with `security-skills --help`): `security-skills detect ./app`, `security-skills audit ./app --profile quick`.

## Limitations

- Recipes are patterns for common stacks, not a complete secure design; authentication, authorisation, session management and cryptography are outside this skill.
- Sandbox verification used SQLite, Flask/FastAPI test clients, local HTTP servers and Node 24; MongoDB, LDAP servers, PostgreSQL/MySQL drivers, HTTPS pinning, archives, real browsers, Windows and a running Next.js app were not exercised (see [verification notes](references/VERIFICATION-NOTES.md)).
- Library behaviour changes across versions (Werkzeug already normalised one redirect bypass we expected); re-run the hostile-input test on your versions.
- The ASVS/CWE map is for ASVS 5.0.0 only; ASVS 4.0.3 IDs differ.
- A passing test shows one hostile input failed safely, not that the sink is safe against all inputs.
