# Language and framework checklists

Use after the change-type checklist. Each bullet names the thing to grep for and the safe form. Claims marked [run] were executed in a sandbox (Python 3 with Flask 3.1, Django 4.2, pydantic 2, Jinja2 3.1; Node 24 with Express 5.3, React 19.3), script in `worked-example/`. Version-specific behaviour should be re-checked against the project's pinned versions.

## Python (general)
- `subprocess` with a list and no shell is safe; `shell=True`, `os.system`, `os.popen` with interpolated input are findings [run].
- `eval`, `exec`, `pickle.loads`, `yaml.load` (use `safe_load`), `marshal`, `shelve` on untrusted data; `tarfile`/`zipfile` extraction without member-path checks.
- `random` for tokens (use `secrets`); `==` on secrets (use `hmac.compare_digest`); `hashlib.md5/sha1` for passwords or signatures (non-security cache keys are fine if you say so).
- `requests.*(verify=False)`; missing `timeout=`; user-supplied URL fetched (SSRF).
- f-strings or `%`/`.format` building SQL, `os.path.join(base, user_value)` without resolving and checking the prefix.
- `assert` used for authorization (removed under `-O`).
- Logging of `request.headers`, tokens, form bodies.

## Django
- ORM `filter/get/exclude` bind parameters [run]; review `.raw()`, `.extra()`, `RawSQL`, `cursor.execute(f"...")` [run].
- Templates autoescape [run]; review `|safe`, `mark_safe`, `format_html` misuse (format_html with already-built user HTML), `{% autoescape off %}`.
- Views: `@login_required` / permission mixins / DRF `permission_classes` present on every new view or viewset; DRF default permission class in settings; object-level checks via `get_queryset()` scoped to `request.user` or `has_object_permission`.
- `@csrf_exempt` justified (webhooks with signature, token APIs); CSRF middleware still enabled.
- DRF serializers: `fields = "__all__"` or writable privileged fields = mass assignment; use explicit `fields` and `read_only_fields`.
- Settings: `DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY` from env, secure cookie flags, `SECURE_*` settings, `CORS_ALLOW_ALL_ORIGINS`.
- File uploads: `FileField` upload_to, validators, `MEDIA_ROOT` not executed; `FileResponse` path from user input.

## Flask
- Autoescape applies to `.html/.htm/.xml/.xhtml` templates and `render_template_string`; not to `.txt` and other extensions [run]. Review `|safe`, `Markup()`.
- `render_template_string(user_input)` or `Template(user_input)` = server-side template injection.
- No CSRF protection by default: check Flask-WTF `CSRFProtect` or equivalent for cookie-authenticated state changes.
- `app.run(debug=True)`, `SECRET_KEY` default or committed; `session` is signed, not encrypted: do not store secrets in it.
- `send_file`/`send_from_directory` with user-supplied names: use `send_from_directory` and verify; `secure_filename` for uploads and also generate your own name.
- Auth decorators (`login_required`) applied per route, easy to forget on new routes; look for blueprint-level `before_request` instead.

## FastAPI
- Auth through `Depends(...)` on each router/route (or router-level dependencies); a new route outside the protected router is the classic gap.
- Pydantic request models ignore unknown fields by default; a model that declares privileged fields and is passed to the ORM is mass assignment [run]. Use separate input/output models; set `response_model` to avoid leaking fields.
- Path/query params typed; raw SQL via `text()` needs bound params; `BackgroundTasks` and `UploadFile` read size limits.
- CORS middleware: explicit origins; `allow_credentials=True` with wildcard is a finding.
- OpenAPI docs and debug routes exposed in production; `HTTPException` details not leaking internals.

## JavaScript / TypeScript (general)
- `eval`, `new Function`, `setTimeout(string)`, `child_process.exec` with interpolated input (use `execFile`/`spawn` with argv) [run].
- `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, jQuery `.html()` with untrusted data; URL sinks (`location`, `href`) with `javascript:` risk.
- Prototype pollution through deep merge of user objects (`__proto__`, `constructor`); `Object.assign` into config.
- `Math.random` for tokens; string `===` for secrets (use `crypto.timingSafeEqual`).
- Regex built from user input, or catastrophic patterns on user text (CWE-1333).
- `JSON.parse` result trusted as typed: validate with a schema (zod, ajv) at the boundary.
- `npm` scripts, `postinstall`, dependency confusion on internal scope names.

## Express
- `res.send` of a template string containing request data reflects HTML [run]; use a templating engine with escaping or `res.json`.
- Auth middleware order: `app.use(auth)` must come before the routes it should protect; per-router application. Check new routers.
- `helmet`, `cors({origin: true, credentials: true})` (reflects any origin), `express.static` on a directory with secrets, `trust proxy` setting, `cookie` flags (`httpOnly`, `secure`, `sameSite`).
- Body parsing limits; `req.body` spread into DB models (mass assignment); query objects from `req.query` passed to Mongo filters (operator injection).
- Error handler returning `err.stack` to clients.
- No built-in CSRF protection: check for tokens or SameSite cookies when sessions use cookies.

## Next.js
- Server Actions and Route Handlers are public HTTP endpoints: each needs its own authentication and authorization check; do not rely on middleware or UI hiding alone (ASVS 8.3.1).
- Only variables prefixed `NEXT_PUBLIC_` are bundled to the client; any secret referenced in client components or prefixed that way is exposed. Server-only modules imported into client code are a leak route.
- `getServerSideProps`/Server Component props serialize everything returned to the browser: return only needed fields (ASVS 15.3.1).
- Check `next.config` for permissive `images.remotePatterns`, `rewrites` to internal hosts (SSRF), headers/CSP removal, `dangerouslyAllowSVG`.
- `fetch` of user-supplied URLs server-side = SSRF; caching of per-user data under a shared cache key leaks between users.
- Pin and check the Next.js version against advisories; middleware-only authorization has been bypassed in past advisories, so treat it as defence in depth.

## React
- JSX text and attributes are escaped [run]; review `dangerouslySetInnerHTML` [run] (sanitize with a maintained library), `href`/`src` from user data (allow-list `http(s):`), `target="_blank"` without `rel`.
- Tokens in `localStorage` (XSS-readable) vs HttpOnly cookies: note the trade-off.
- Do not put secrets in client bundles; client-side "role checks" are UX only.
- `useEffect`/`postMessage` handlers must check `event.origin`.
- Markdown renderers and SVG upload display: sanitize (ASVS 1.3.4, 1.3.5).

## Java / Go quick pointers (when the repo is not Python/JS)
- Java: string-built JPQL/SQL, `ObjectInputStream`, XXE-prone `DocumentBuilderFactory` defaults, Spring `@PreAuthorize` missing on new controller methods, SpEL on user input.
- Go: `fmt.Sprintf` into SQL, `exec.Command("sh","-c",...)`, `http.Get(userURL)`, `filepath.Join` without prefix check, `InsecureSkipVerify: true`, `math/rand` for tokens.
