# Reading a change for security

How to go from "here is a diff" to a short list of places worth a second look. Time-box it: a normal PR deserves 10-20 minutes of this, not a full audit.

## 1. Orient (2 minutes)

1. Read the PR title, description and linked ticket. State in one sentence what the change is supposed to do. If you cannot, ask (see "Questions when context is missing").
2. List changed files and group them: routes/handlers, data access, templates/views, auth/session, crypto, config/env/infra, dependencies/lockfiles, CI/CD, tests, generated code.
3. Rank by exposure: anything reachable by an unauthenticated or low-privilege caller first, then anything touching money, identity, secrets or other users' data, then internal-only code.
4. Note what is NOT in the diff but is affected: callers, middleware, base classes, decorators, framework settings. Open them. A diff shows the change, not the protections that wrap it.

## 2. Find trust boundaries and new inputs/outputs

Scan the diff for each of these and write down every hit; each is a candidate source or sink.

| Look for | Why it matters |
|---|---|
| New route, RPC, GraphQL field, queue consumer, webhook, cron, CLI arg | New attacker-reachable entry point (source) |
| `request.*`, `req.body/query/params/headers`, `searchParams`, form fields, file names, uploaded bytes | Attacker-controlled data |
| Data read back from DB, cache, third-party API, LLM output, uploaded file metadata | Second-order input: trusted only if it was validated on the way in AND is encoded for this sink |
| SQL/NoSQL/ORM raw calls, shell/process spawn, `eval`/`exec`/template-from-string, deserializers, XML parsers, path joins, outbound HTTP, redirects, `innerHTML`-style sinks, regex built from input | Injection and unsafe-consumption sinks |
| Response bodies, logs, error messages, emails, exports, analytics events | Output channels: leakage of other users' data, secrets, PII |
| Role/permission checks added, removed, moved or reordered | Authorization drift |

## 3. Trace source to sink

For each new source, write the path as `file:line -> file:line -> sink` and answer four questions at each hop:

1. Who can control the value (anonymous, any logged-in user, admin only, another service)?
2. Is it validated (type, range, allow-list) or transformed (encoded, parameterized, normalized) on this path? Where exactly?
3. Does the caller have the right to act on THIS object (authorization on the object, not only "is logged in")?
4. What is the worst thing the sink can do with a hostile value (read other tenants' rows, run a command, fetch an internal URL, write outside a directory)?

If the path is broken by a framework or library control you can name and point to, record it as "protected by X" (see `false-alarms-severity-evidence.md`). If you cannot follow the path because it leaves the diff, open the callee; if you still cannot, record an assumption and ask.

Trace both directions when useful: from sinks backwards (grep the sink, find who calls it) catches code that the diff only touched lightly.

## 4. What changed in the security-sensitive areas

Compare before and after, not just the after.

| Area | Questions on the delta |
|---|---|
| Authorization | Was a decorator, middleware, policy or ownership filter removed, bypassed by a new route, or not applied to the new route? Does every new data access scope by owner/tenant? Is the check server-side? Do new fields become writable (mass assignment)? |
| Authentication / session | Changed token lifetime, cookie flags, password/OTP/reset flow, "remember me", SSO callback validation, JWT verification options (`alg`, `aud`, `iss`, expiry), new unauthenticated route or health/debug endpoint? |
| Crypto | New hash/cipher/mode/key/IV/nonce handling; randomness source for tokens; comparison of secrets with `==`; hard-coded keys; TLS verification switched off; homemade schemes |
| Config / infra | Debug flags, permissive CORS, CSP/headers removed, bucket/ingress/security-group opened, default credentials, secrets in env files or IaC, container running as root or privileged, new public port |
| Dependencies | New package: does it exist, is it the intended one (typo, look-alike, internal-name collision), maintained, licensed, install scripts? Version bump: changelog and advisories; lockfile changed without manifest change or vice versa; registry/URL source changed |
| CI / build | Workflow triggers on untrusted PRs with secrets, `pull_request_target` checking out PR code, unpinned third-party actions, script injection via `${{ github.event... }}` in `run:`, widened token permissions, artifact upload of secrets |
| Data / migrations | See migration checklist in `change-type-checklists.md` |

## 5. Questions to ask when context is missing

Ask once, grouped, and keep reviewing the rest. State what you assumed meanwhile so the author can correct you quickly.

- Who can call this (anonymous, any user, admin, internal service)? Is there a gateway/middleware doing authn/authz that is not in the diff?
- Is this value ever attacker-influenced, or is it internal config?
- Which framework version and settings apply (autoescape, CSRF middleware, ORM, request-model validation)?
- Is this code path deployed, behind a flag, or test-only?
- What data does this table/endpoint hold (PII, payment, secrets) and who owns a row (user, org, tenant)?
- Is there a design/threat note or `.agents/security-project-context.md` I should read first?

Template: "I assumed X because Y. If that is wrong (for example Z), the severity changes to W. Could you confirm?"

## 6. Quick mode ("quick review of this PR")

Output at most: verdict line, up to 5 findings (each: label, `file:line`, one-sentence why, one-sentence fix), a "checked and fine" line, and a "not checked" line. Procedure: sections 1-3 only, skip lower-ranked files, never silently skip: say what you skipped. Format in `comment-and-report-templates.md`.
