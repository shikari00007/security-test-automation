# Which pattern for which sink, preflight checks, and standards map

## 1. Decision table: sink -> pattern -> recipe

| You are about to... | Use | Never | Recipe |
|---|---|---|---|
| run SQL with a user value | bound parameters (`?`, `%s`, `$1`, `:name`) | f-string / template literal / `+` | [injection](injection-safe-data-access-and-commands.md) |
| use a user value as column/table/sort | allow-list dict key -> constant | bind it (impossible) or concatenate | [injection](injection-safe-data-access-and-commands.md) |
| call ORM raw API (`text()`, `raw()`, `extra()`, `cursor.execute`) | same params rule | f-string inside the raw call | [injection](injection-safe-data-access-and-commands.md) |
| build a NoSQL filter from JSON | type-check to primitives (zod/pydantic); no `$where` | pass `req.body` fields straight in | [injection](injection-safe-data-access-and-commands.md) |
| build an LDAP filter | `escape_filter_chars` (RFC 4515) | concatenation | [injection](injection-safe-data-access-and-commands.md) |
| start a process | argv list, no shell, `--` before values, timeout | `shell=True`, `exec()`/`execSync` with a string | [injection](injection-safe-data-access-and-commands.md) |
| put text in HTML | autoescaping template / `html.escape` / `textContent` | `innerHTML`, `\|safe`, `mark_safe`, `dangerouslySetInnerHTML` on user text | [encoding](input-validation-and-output-encoding.md) |
| put data in a `<script>` | JSON with `<` escaped, or a JSON endpoint | f-string into script text | [encoding](input-validation-and-output-encoding.md) |
| build a URL / link | `urlencode` / `URLSearchParams`; scheme allow-list | concatenation, `javascript:` href | [encoding](input-validation-and-output-encoding.md) |
| render a template | user data as variables only; autoescape on | template text from user input | [encoding](input-validation-and-output-encoding.md) |
| accept a request body | pydantic / zod strict schema at the handler | `dict`/`any`, trusting client validation | [encoding](input-validation-and-output-encoding.md) |
| open a file by user-influenced name | generated names; `resolve()` + containment check | `join` + open, `startswith(str)` | [files](files-paths-uploads-and-races.md) |
| accept an upload | ext allow-list + magic bytes + size cap + generated name | client filename, content-type header only | [files](files-paths-uploads-and-races.md) |
| create a file/record only if absent, or spend a balance | atomic op (`O_EXCL`, conditional UPDATE, unique key) | check, then act | [files](files-paths-uploads-and-races.md) |
| fetch a URL a user influences | fixed server-side mapping, else allow-list + public-IP check on the connecting address + no redirects | `urlopen(url)`, `fetch(url)`, deny-list only | [outbound](outbound-requests-parsers-and-redirects.md) |
| load serialized data | JSON + schema; `yaml.safe_load` | `pickle`, `yaml.load`, `eval`, `torch.load` default | [outbound](outbound-requests-parsers-and-redirects.md) |
| parse XML | `defusedxml`, or lxml with entities/DTD/network off | default parser on untrusted XML | [outbound](outbound-requests-parsers-and-redirects.md) |
| merge JSON into objects (JS) | strict schema, key blocklist, `Map` | recursive merge of parsed input | [outbound](outbound-requests-parsers-and-redirects.md) |
| redirect after login/action | validated local path or id->URL map | `redirect(request.args["next"])`, `startswith("/")` | [outbound](outbound-requests-parsers-and-redirects.md) |
| add a cookie-session POST endpoint | CSRF token + `SameSite` + `Secure` + `HttpOnly` | none of these | [web boundary](web-boundary-errors-logging-and-regex.md) |
| enable CORS | fixed origin allow-list, `Vary: Origin` | reflect `Origin`, `*` with credentials | [web boundary](web-boundary-errors-logging-and-regex.md) |
| return an error | generic body + error id; detail to log | `str(exc)`, stack trace, SQL in response | [web boundary](web-boundary-errors-logging-and-regex.md) |
| write a log line | `%r`/structured JSON, redact keys | secrets, tokens, raw newlines, PII | [web boundary](web-boundary-errors-logging-and-regex.md) |
| write or accept a regex | linear patterns, length cap, `re.escape` for user text | nested quantifiers, user-supplied patterns | [web boundary](web-boundary-errors-logging-and-regex.md) |

## 2. Before you write this, check (preflight keyed by what the task touches)

Run the matching list before writing code; after writing, run the tests in the recipe (unsafe input fails safely).

- **Database:** Are all values bound? Are identifiers allow-listed? Is there a raw-SQL escape hatch (ORM `raw`, `text`, `extra`) with string building? Does the endpoint return only needed columns (ASVS 5.0.0 V15.3.1)? Does a check-then-update need to be one conditional statement?
- **Files and paths:** Does any path segment come from a request, message or archive entry? Can you use a generated name instead? Is containment checked after `resolve()`/`realpath`? Upload: type allow-list, size cap, stored outside web root, served with fixed content type?
- **HTTP out (server-side requests):** Can the user influence host, port, scheme, path or redirect? Is there an allow-list? Does the check apply to the address actually connected to? Redirects off? Response size and timeout capped? Cloud metadata reachable from this host (`169.254.169.254`, link-local)?
- **Templates and HTML:** Is autoescape on for this engine/environment? Any `safe`/`mark_safe`/`innerHTML`/`dangerouslySetInnerHTML`/`Markup`? Is user text ever part of the template source? Any user URL placed in `href`/`src`?
- **Shell and processes:** Can the library do this without a subprocess? If not: argv list, no shell, `--`, timeout, minimal environment, fixed executable path.
- **Auth, sessions, state change:** Cookie flags set? CSRF protection active for cookie-authenticated unsafe methods? Authorisation checked inside the handler or action, not only on the page that links to it (Next.js Server Actions are reachable by direct POST)? Redirect targets validated? (Authentication design itself: `security-start` routes you to the right skill.)
- **Parsing and deserialising:** JSON + schema? Any pickle/yaml.load/XML parser/`eval` on data that crosses a trust boundary? Unknown fields rejected (mass assignment, ASVS 5.0.0 V15.3.3)?
- **Errors and logs:** Could an exception text, stack trace or SQL reach the client? Does the log line contain a token, password, key, session id or personal data? Can an attacker-controlled value add a line?
- **Regex, sizes, numbers:** Nested quantifiers or untrusted patterns? Body, array, string and page-size limits? Integer range checked before arithmetic or allocation?

## 3. Framework quick map (what to reach for)

| Need | Flask | Django | FastAPI | Express / Next.js |
|---|---|---|---|---|
| Schema validation | pydantic model in handler | forms/serializers | typed body model (verified) | zod `strictObject` (verified); in Next, inside every route handler and Server Action |
| Autoescaping templates | Jinja2 via `render_template` | DTL default (verified) | Jinja2 only if you add it | React escapes text; avoid raw HTML APIs |
| CSRF | Flask-WTF `CSRFProtect` (verified) | `CsrfViewMiddleware` | token/origin check for cookie auth | custom check; Next Server Actions compare Origin/Host (docs) |
| Body size limit | `MAX_CONTENT_LENGTH` (verified) | `DATA_UPLOAD_MAX_MEMORY_SIZE` (name verified) | proxy limit / streaming check | `express.json({limit})` |
| Security headers | after_request / Flask-Talisman | `SecurityMiddleware` settings (names verified) | middleware | `helmet` (verified on Express) |

## 4. Standards map (verified against the primary sources; re-verify before extending)

- OWASP ASVS **5.0.0** (machine-readable release JSON from the OWASP/ASVS repository, tag v5.0.0, fetched 2026-11-25; every ID below was read from it). 4.0.3 numbering differs; do not mix editions.
- CWE names read from the MITRE catalog file `cwec_latest` (reports "Version 5.0", date attribute 2026-10-28; fetched 2026-11-25).
- Next.js claims: nextjs.org "How to think about data security in Next.js" (page last updated 2026-11-18).

| Pattern | ASVS 5.0.0 | CWE |
|---|---|---|
| Parameterised queries, NoSQL | V1.2.4 | CWE-89, CWE-943 |
| OS command safety | V1.2.5 | CWE-78 |
| LDAP escaping | V1.2.6 | CWE-90 |
| HTML/attribute/JS/URL encoding | V1.2.1, V1.2.2, V1.2.3, V3.2.2 | CWE-79 |
| Template injection / dynamic code | V1.3.7 / V1.3.2 | CWE-1336 / CWE-95 |
| Input validation allow-list, server-side | V2.2.1, V2.2.2, V2.2.3 | CWE-20 |
| Mass assignment, response minimisation | V15.3.3, V15.3.1 | CWE-915 |
| SSRF; no automatic redirects out | V1.3.6; V15.3.2 | CWE-918 |
| Safe deserialization | V1.5.2 | CWE-502 |
| XXE | V1.5.1 | CWE-611 |
| Prototype pollution (JS) | V15.3.6 | CWE-1321 |
| Path/file name handling, uploads | V5.3.2, V5.3.3, V5.2.1, V5.2.2 | CWE-22, CWE-73, CWE-434, CWE-400 |
| Open redirect | V3.7.2, V3.7.3 (V10.4.1 for OAuth redirect URIs) | CWE-601 |
| CSRF / cookie flags | V3.3.1, V3.3.2, V3.3.4, V3.5.1, V3.5.3 | CWE-352, CWE-614, CWE-1004 |
| CORS allow-list; headers | V3.4.2; V3.4.1, V3.4.3-V3.4.6 | CWE-942 |
| Error handling | V16.5.1, V16.5.3, V16.5.4; V13.4.2 (debug off) | CWE-209 |
| Logging without secrets | V16.2.5 | CWE-532, CWE-117 |
| ReDoS; integer range | V1.3.12; V1.4.2 | CWE-1333; CWE-190 |
| TOCTOU / atomic check-and-act | V15.4.2 | CWE-367 |

Cite an ID in a finding or code comment only when the code actually matches it.
