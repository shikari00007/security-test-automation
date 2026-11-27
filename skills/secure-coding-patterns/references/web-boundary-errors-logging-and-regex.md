# Web boundary basics, error handling, logging and regex

All pairs executed (Flask/Express test clients or in-process); see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md). These are baselines, not a full header/CSRF design; session and auth design belong to your auth work (see `authn-authz-implementation` for design and `security-code-review` for review).

## CSRF: state-changing requests need a token (or an equivalent origin check)

<!-- case:PY-CSRF unsafe -->
```python
from flask import Flask

def make_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-only-secret"
    app.config["WTF_CSRF_ENABLED"] = True  # has no effect: CSRFProtect is never installed

    @app.post("/transfer")
    def transfer():
        return {"ok": True}

    return app
```
<!-- case:PY-CSRF safe -->
```python
from flask import Flask
from flask_wtf.csrf import CSRFProtect

def make_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-only-secret"  # load from env/secret store in real code
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    CSRFProtect(app)

    @app.post("/transfer")
    def transfer():
        return {"ok": True}

    return app
```
Why: without the extension a cross-site form POST with the user's cookie succeeds; with `CSRFProtect` a POST lacking a valid token gets 400. `SameSite` cookies are a second layer, not a replacement (ASVS 5.0.0 V3.3.2). Cookie flags: `Secure`, `HttpOnly`, `SameSite` (V3.3.1, V3.3.2, V3.3.4). Use the framework's CSRF feature: Django `CsrfViewMiddleware` (enabled by default in the project template), Next.js Server Actions compare `Origin` with `Host` and only accept POST (Next.js docs, last updated 2026-11-18), Express needs your own token or origin check middleware. APIs authenticated by a bearer header (not a cookie) are not CSRF-prone, but cookie-authenticated JSON APIs are.

## CORS: never reflect the Origin; allow-list it

<!-- case:PY-CORS unsafe -->
```python
from flask import Flask, request

def make_app():
    app = Flask(__name__)

    @app.get("/me")
    def me():
        return {"user": "alice"}

    @app.after_request
    def cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    return app
```
<!-- case:PY-CORS safe -->
```python
from flask import Flask, request

ALLOWED_ORIGINS = {"https://app.example.com"}

def make_app():
    app = Flask(__name__)

    @app.get("/me")
    def me():
        return {"user": "alice"}

    @app.after_request
    def headers(resp):
        origin = request.headers.get("Origin")
        resp.headers.add("Vary", "Origin")
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    return app
```
Why: reflecting any `Origin` with credentials lets any website read the logged-in user's responses (ASVS 5.0.0 V3.4.2 requires a fixed value or an allow-list check). The other headers map to V3.4.1 (HSTS), V3.4.3 (CSP), V3.4.4 (nosniff), V3.4.5 (referrer policy), V3.4.6 (`frame-ancestors`). Start with a CSP you can tighten, test it in report-only mode first, and send HSTS only over HTTPS you control. In practice use a maintained package (Flask-Talisman, Django `SecurityMiddleware` settings, `helmet` for Express).

### Express

<!-- case:JS-HEADERS unsafe -->
```js
const express = require('express');

function makeApp() {
  const app = express();
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', req.get('Origin') || '*');
    res.set('Access-Control-Allow-Credentials', 'true');
    next();
  });
  app.get('/me', (req, res) => res.json({ user: 'alice' }));
  return app;
}
```
<!-- case:JS-HEADERS safe -->
```js
const express = require('express');
const helmet = require('helmet');

const ALLOWED = new Set(['https://app.example.com']);

function makeApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use((req, res, next) => {
    res.vary('Origin');
    const origin = req.get('Origin');
    if (origin && ALLOWED.has(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
    }
    next();
  });
  app.get('/me', (req, res) => res.json({ user: 'alice' }));
  return app;
}
```
Why: same rule; `helmet` (8.x) sets nosniff, HSTS, CSP, referrer policy and removes `X-Powered-By`. Express 5.3 was used. Review the default CSP against your frontend rather than copying it.

### Django settings that exist in 4.2 (names verified, behaviour not executed)

`DEBUG = False`, `ALLOWED_HOSTS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, `X_FRAME_OPTIONS`; run `python manage.py check --deploy` to list what is missing.

## Errors: generic message out, details to the log

<!-- case:PY-ERR unsafe -->
```python
import traceback
from flask import Flask, jsonify

def make_app(load_user):
    app = Flask(__name__)

    @app.get("/user/<int:uid>")
    def user(uid):
        try:
            return jsonify(load_user(uid))
        except Exception as exc:
            return jsonify(error=str(exc), trace=traceback.format_exc()), 500

    return app
```
<!-- case:PY-ERR safe -->
```python
import logging
import uuid
from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger("app")

def make_app(load_user):
    app = Flask(__name__)

    @app.errorhandler(Exception)
    def last_resort(exc):
        if isinstance(exc, HTTPException):
            return exc  # keep 400/403/404/405/413 as-is; they carry no internals
        error_id = uuid.uuid4().hex[:12]
        log.error("unhandled error id=%s", error_id, exc_info=exc)
        return jsonify(error="internal error", error_id=error_id), 500

    @app.get("/user/<int:uid>")
    def user(uid):
        return jsonify(load_user(uid))

    return app
```
Why: exception text and stack traces reveal queries, hosts, paths and sometimes secrets (ASVS 5.0.0 V16.5.1; last-resort handler V16.5.4). The client gets a correlation id; the log gets the detail. Also keep `DEBUG`/Werkzeug debugger and Django `DEBUG=True` off in production (V13.4.2). Without the `HTTPException` branch, 404/405/400/413 all become 500s (and every 404 logs a stack trace). Test `GET /nope == 404`. Fail closed: a validation or authorisation exception must end in a denial, not a fall-through (V16.5.3).

### Express

<!-- case:JS-ERR unsafe -->
```js
const express = require('express');

function makeApp(loadUser) {
  const app = express();
  app.get('/user/:id', async (req, res) => {
    try {
      res.json(await loadUser(req.params.id));
    } catch (e) {
      res.status(500).json({ error: e.message, stack: e.stack });
    }
  });
  return app;
}
```
<!-- case:JS-ERR safe -->
```js
const express = require('express');
const crypto = require('node:crypto');

function makeApp(loadUser, log = console) {
  const app = express();
  app.use(express.json({ limit: '100kb' }));
  app.get('/user/:id', async (req, res, next) => {
    try {
      res.json(await loadUser(req.params.id));
    } catch (e) {
      next(e);
    }
  });
  app.use((err, req, res, next) => {
    const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
    const id = crypto.randomUUID().slice(0, 12);
    log.error(`error id=${id} status=${status}`, err);
    res.status(status).json({ error: status === 500 ? 'internal error' : 'request rejected', error_id: id });
  });
  return app;
}
```
Why: same pattern. Body-parser errors (malformed JSON, oversize body) carry `err.status` 400/413; a catch-all that always sends 500 hides them, so the handler honours 4xx statuses and only unexpected errors become `internal error`. Express 5 forwards rejected promises from handlers to the error middleware; set `NODE_ENV=production` so Express default handler hides stacks.

## Logging: no secrets, no raw newlines

<!-- case:PY-LOG unsafe -->
```python
import logging

log = logging.getLogger("auth")

def record_failed_login(user, password):
    log.warning(f"login failed user={user} password={password}")
```
<!-- case:PY-LOG safe -->
```python
import logging

log = logging.getLogger("auth")

def record_failed_login(user, password):
    log.warning("login failed user=%r", user)   # never log the password; %r escapes newlines
```
Why: the unsafe line stores the credential and lets `user="bob\nINFO forged entry"` forge a second log line (CWE-117). Log identifiers and outcomes, not secrets, tokens, full card numbers or personal data (ASVS 5.0.0 V16.2.5: enforce logging by data protection level). Prefer structured (JSON) logging so values cannot add lines, and a redaction filter as a backstop.

<!-- case:JS-LOG unsafe -->
```js
function logLogin(log, user, password) {
  log(`login failed user=${user} password=${password}`);
}
```
<!-- case:JS-LOG safe -->
```js
const SENSITIVE = new Set(['password', 'token', 'authorization', 'cookie', 'secret']);

function redact(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => (SENSITIVE.has(k.toLowerCase()) ? '[redacted]' : v)));
}

function logLogin(log, event) {
  log(JSON.stringify({ msg: 'login failed', ...redact(event) }));
}
```
Why: `JSON.stringify` escapes newlines, and the replacer drops sensitive fields even if a caller passes the whole request body. Redaction by key name is a backstop; the first defence is not passing secrets to the logger.

## Regular expression denial of service (ReDoS) and size limits

<!-- case:PY-REDOS unsafe -->
```python
import re

PATTERN = re.compile(r"^(a+)+$")

def is_token(value):
    return bool(PATTERN.match(value))
```
<!-- case:PY-REDOS safe -->
```python
import re

PATTERN = re.compile(r"^a+$")

def is_token(value):
    if len(value) > 256:
        return False
    return bool(PATTERN.match(value))
```
Why: nested quantifiers backtrack exponentially on near-matches (`"aaaa...!"`), so a short string can pin a CPU core. Fix the pattern (remove the ambiguity) and cap input length before matching (ASVS 5.0.0 V1.3.12). Python's `re` and JavaScript's built-in engine both backtrack; for untrusted patterns use a linear-time engine (RE2 bindings) and never compile user-supplied regexes. Escape user text used inside a pattern with `re.escape` / an escape function (V1.2.9).

<!-- case:JS-REDOS unsafe -->
```js
const PATTERN = /^(a+)+$/;

function isToken(value) {
  return PATTERN.test(value);
}
```
<!-- case:JS-REDOS safe -->
```js
const PATTERN = /^a+$/;

function isToken(value) {
  return typeof value === 'string' && value.length <= 256 && PATTERN.test(value);
}
```
Why: identical cause and fix.
