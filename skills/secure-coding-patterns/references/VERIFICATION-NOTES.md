# Verification notes

Date of verification: 2026-11-25. Environment: Linux, Python 3.14.8, Node 24.21.0. Libraries: Flask 3.1.2, Werkzeug 3.1.4, Jinja2 3.1.6, Django 4.2.27, pydantic 2.12.5, FastAPI 0.118.0, PyYAML 6.0.2, lxml 6.0.2, Flask-WTF 1.2.2, defusedxml 0.7.1, SQLAlchemy 2.1.9, ldap3 2.9.1; npm: express 5.3.0, zod 4.6.7, helmet 8.3.0, undici 8.13.1, qs 6.17.1 (installed, not used).

## Method

1. Every fenced snippet that carries a `<!-- case:ID role -->` marker in this folder's other files was **extracted mechanically** by a script (not retyped), so what was executed is byte-for-byte what is documented. Roles: `unsafe` (exploitable pattern), `weak` (a common but insufficient fix), `safe`/`safe2`.
2. Python snippets were syntax-checked with `ast.parse`, then `exec`'d and driven by a harness; JavaScript snippets were syntax-checked with `vm.Script` and run via `new Function` with Node's `require`.
3. For each case the harness asserts both sides: the unsafe/weak form is exploitable with a harmless marker, and the safe form is not, while benign input still works.
4. Everything ran in a throwaway temp directory, in-memory SQLite, Flask/FastAPI test clients, or HTTP servers bound to `127.0.0.1`/`127.0.0.2` on an ephemeral port. No external host was contacted (the "public" test address `93.184.216.34` was only passed to an IP classifier, never connected to). The DNS-rebinding test replaces the resolver in-process with a function that answers `127.0.0.1` first and `127.0.0.2` second.
5. Markers used: extra rows returned, an echoed word, `49` from `{{ 7*7 }}`, `len([1,2,3])` as the "attacker-chosen callable", a parsed-in attribute name, a Location host, a temp-file marker string. No payload does anything beyond that.
6. The harness (about 500 lines) lives in a sandbox outside the skill, not shipped. To reproduce: extract the marked blocks, install the libraries above, and assert the same properties listed per case below.

## Result

97 snippets in 47 cases (46 unsafe, 3 weak, 48 safe/safe2; one case, JS-REDIR, has no unsafe form) were executed. 191 assertions ran: 124 Python (including 10 Django-settings name checks) and 67 JavaScript; 191 passed, 0 failed (after fixing two harness/doc issues, below).

| Case | What was demonstrated |
|---|---|
| PY-SQL, PY-DJANGO, PY-SQLA, JS-SQL | marker payload `' OR '1'='1` returns every row with string building, zero rows when bound |
| PY-IDENT | `id DESC LIMIT 1 --` alters the result set; allow-list rejects it |
| JS-NOSQL | filter object carries `{"$ne": ""}` (also through Express `express.json()`); safe version throws. **Not run against MongoDB** |
| PY-LDAP | filter gains extra terms when unescaped; escaped value keeps template structure. **Not run against a directory server** |
| PY-CMD, PY-CMDOPT, JS-EXEC | `; echo INJECTED_MARKER` executes via shell, literal with argv list; `--version` read as an option without `--`/check |
| PY-HTML, PY-ATTR, PY-JSCTX, JS-HTML, JS-SCRIPTJSON | output parsed with `html.parser` (Python) or counted (JS): injected element/attribute/second `<script>` present vs absent; escaped JSON still round-trips |
| PY-URLQ, PY-HREF, JS-URL | injected query parameter, `javascript:` href |
| PY-SSTI, PY-JINJA, PY-DJTPL | `{{ 7*7 }}` evaluated to 49; plain Jinja2 Environment does not escape; `mark_safe` bypasses Django autoescape |
| PY-PYD, PY-FASTAPI, JS-ZOD | negative qty, bad SKU, extra `is_admin` accepted vs rejected (ValidationError / HTTP 422 / ZodError) |
| PY-PATH, JS-PATH | `../`, absolute path, symlink and sibling-prefix directory (`uploads-evil`) escapes read a secret file outside the root vs blocked |
| PY-UPLOAD | client filename `../pwned.txt` writes outside; safe version stores under generated name and rejects `.php`, wrong magic bytes, oversize |
| PY-LIMIT | 2 MB body accepted vs HTTP 413 with `MAX_CONTENT_LENGTH` |
| PY-TOCTOU-FILE | symlink planted between `exists()` and write overwrites victim file; `O_EXCL|O_NOFOLLOW` refuses and keeps victim intact |
| PY-TOCTOU-DB | interleaved withdrawals overdraw (100 minus 160 handled as success); conditional UPDATE refuses; 4 threads on separate connections: exactly one succeeds |
| PY-SSRF, JS-SSRF | local "internal" server marker reached by `urlopen`/`fetch`, by decimal-IP form, via redirect, and via simulated DNS rebinding (check-then-refetch "weak" form); safe forms block loopback/metadata/non-allow-listed hosts/`file:`, do not follow redirects, pin the validated address (Python) or validate inside the connection `lookup` (undici); IP classifier checked on 8 (Python) and 12 (JS) non-public forms |
| PY-PICKLE, PY-YAML, JS-PROTO | callable executed on `pickle.loads`/`yaml.load`, refused by JSON/`safe_load`; `Object.prototype` polluted by naive merge, not by guarded merge |
| PY-XXE | external entity read a temp secret file with lxml with entity resolution on; `defusedxml` raised `EntitiesForbidden`; hardened lxml did not expand it |
| PY-REDIR, JS-REDIR | absolute and `//host` redirects leave the site with unsafe/weak forms; validated forms stay on `app.test` |
| PY-CSRF | token-less POST 200 vs 400; POST with valid token 200; cookie config values present |
| PY-CORS, JS-HEADERS | evil Origin reflected with credentials vs ignored; allow-listed origin echoed with `Vary: Origin`; security headers present (Flask hand-set, Express via helmet) |
| PY-ERR, JS-ERR | marker secret and stack trace in response vs generic body with error id; detail found in the log under the same id |
| PY-LOG, JS-LOG | credential logged and forged second line vs one line without the secret |
| PY-REDOS, JS-REDOS | `^(a+)+$` on 27-28 `a` + `!` takes seconds vs microseconds; safe form still accepts valid input |
| DJANGO-SETTINGS | 10 setting names exist in Django 4.2.27 `global_settings` (names only) |

## Issues found while verifying (and fixed)

- A first draft claimed `/\evil.example` defeats `startswith("/")` in Flask. Werkzeug 3.1.4 percent-encodes the backslash in `Location`, so that specific bypass did not reproduce; the text now says so and keeps the backslash rejection as defence that does not depend on the framework. `//evil.example` did reproduce.
- A first threaded balance test shared one SQLite connection across threads and proved nothing; it now uses one connection per thread on a file database.

## Re-verification after independent review (2026-11-26)

Environment: Python 3.14.8, Node 24.21.0, Flask/Werkzeug from the system packages, npm express 5 and undici 8 (undici 8.13.1 `engines`: `node >=22.19.0`, read from the npm registry). The five changed cases were re-extracted mechanically from these files and re-executed; each test was first run on the old snippet (failed) and then on the fixed one (passed).

| Case | Test (old snippet -> fixed) |
|---|---|
| PY-ERR safe | `GET /nope` 404, `POST /user/1` 405, `/user/abc` 404, `abort(400)` 400, raising loader 500 with generic body and `error_id`: old gave 500 for the first (`500 != 404`), fixed passes |
| JS-ERR safe | malformed JSON 400, 300 kB body 413 (needs the `express.json({limit})` line now in the snippet), thrown error 500 generic: old catch-all gave `500 == 400` failure, fixed passes |
| JS-SSRF safe | allow-listed `[::ffff:7f00:1]` and `[::ffff:127.0.0.1]` rejected (old reached the local marker server); port outside `allowedPorts` rejected; allowed port plus injected `isPublic` returns the marker; default `isPublic` still blocks loopback |
| PY-SSRF safe | host-allowed loopback server on a non-allowed port raises `ValueError` (old returned the marker); allowed port works; default `is_public` and `[::ffff:127.0.0.1]` still blocked |
| PY-TOCTOU-DB safe | `withdraw(conn, 1, -1000)` and amount 0 raise `ValueError` and leave balance 40 (old returned True, balance 1040); a valid 30 succeeds once, second 30 refused |

Standards re-read from the ASVS v5.0.0 flat JSON: V3.7.2 (redirect only to allow-listed other hostnames), V3.7.3 (notify and allow cancel), V10.4.1 (OAuth redirect URIs, exact match), V3.5.1 (CSRF: anti-forgery token or origin validation). Node: `node:sqlite` needs 22.5+; undici 8 needs 22.19+.

Not re-run: the other 42 cases (unchanged), Python older than 3.14, `PY-HREF` on older CPython.

## Standards and docs verification

- ASVS: OWASP ASVS **5.0.0** machine-readable release (GitHub OWASP/ASVS tag v5.0.0). All requirement IDs cited were read from that file. Open redirect maps to V3.7.2/V3.7.3 (V10.4.1 for OAuth redirect URIs); re-read 2026-11-26 from the v5.0.0 flat JSON, as were V3.5.1 (anti-forgery token / origin validation; added to the CSRF row).
- CWE: names read from the MITRE catalog XML (`cwec_latest`, reports Version 5.0, date attribute 2026-10-28).
- Next.js: nextjs.org data-security guide, page "lastUpdated 2026-11-18" (Server Actions reachable by direct POST; validate and authorise inside each action; Origin/Host comparison for Server Actions).
- Library behaviour (pydantic `extra="forbid"`, zod `strictObject`, FastAPI 422, Flask `MAX_CONTENT_LENGTH`, Express 5 async error forwarding, helmet defaults, undici `connect.lookup`, defusedxml, ldap3 `escape_filter_chars`) was confirmed by execution above, not from memory.

## Not verified (limits)

- Live databases: MongoDB, LDAP server, PostgreSQL/MySQL drivers (placeholders `$1`, `%s` for those drivers are stated from the drivers' conventions; sqlite, Django cursor and SQLAlchemy were executed).
- HTTPS pinning for SSRF (the Python pinned-connection snippet is HTTP-only; the undici snippet's logic is protocol-independent but was only exercised over HTTP).
- Archive extraction (zip slip, decompression bombs), image processing, antivirus scanning, Django `raw()`/`extra()` (same parameter mechanism as `cursor.execute`, not run), Django settings behaviour, Flask-Talisman, JavaScript XML parsers, browser-side behaviour (the HTML tests parse with Python's `html.parser`, not a browser; real browsers are more lenient with malformed markup), Windows semantics (`O_NOFOLLOW`, path rules), Next.js itself (no Next app was run), other Python/Node versions.
- Timing assertions for ReDoS depend on the CPU; thresholds were set loosely (over 0.5 s vs under 10 ms).
