# Framework recipes (Python and JavaScript/TypeScript)

All recipes implement the same four things: (1) authenticate, (2) central deny-by-default function check from the permission map ([permission-map-test-matrix](permission-map-test-matrix.md)), (3) one object-level loader scoped by tenant/owner, (4) strict input models. Executed evidence and library versions: [VERIFICATION-NOTES](VERIFICATION-NOTES.md). Python 3.14, FastAPI 0.118.0, Flask 3.1.2, Django 4.2.27, Node 24, Express 5.3.0 were used; check your own versions.

## Where each recipe hooks in

| Framework | Central function check | Object-level | Input models | Session / password settings |
|---|---|---|---|---|
| FastAPI | `FastAPI(dependencies=[Depends(enforce)])`, route read from `request.scope["route"]` (full code in the matrix reference) | one `load_doc` dependency | Pydantic `ConfigDict(extra="forbid")` | own session store or `starlette.middleware.sessions` (signed cookie: tamper-proof but NOT server-revocable) |
| Flask | `@app.before_request` keyed by `request.endpoint` | `load_owned()` helper | explicit allowlist of fields | `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE`, `session.clear()` before login |
| Django | middleware `process_view` keyed by `resolver_match.view_name` | `Model.objects.visible_to(request)` + `get_object_or_404` | `ModelForm`/DRF serializer with explicit `fields` (never `__all__`) | `SESSION_COOKIE_*`, `login()` cycles the key |
| Express | route registrar that throws at boot if a route has no policy | `loadDoc(req)` | allowlist/`zod` with `.strict()` | `express-session` with `regenerate()` at login, or a framework auth library |
| Next.js | `withPolicy()` wrapper on every Route Handler / Server Action; middleware only as a first filter | same loader in the data layer | `zod` `.strict()` | Auth.js or your session library; check the session in the handler |

FastAPI global dependencies do not cover `mount()`ed apps, plain Starlette routes or static files; the completeness test must fail on them (it does, see `check_complete` in the matrix reference). CSRF: the FastAPI/Starlette recipes have no built-in protection; cookie-authenticated state-changing routes need a token, or an Origin / `Sec-Fetch-Site` check as in the login recipe below (ASVS 3.5.x).

## End-to-end login and logout (FastAPI, cookie session)

The pieces (`authenticate()` from [credentials-mfa-recovery](credentials-mfa-recovery.md), `SessionStore` and `SESSION_COOKIE` from [sessions-tokens-oauth](sessions-tokens-oauth.md)) wired into real endpoints, with a CSRF origin guard. The tests replay the pre-login cookie (fixation) and the post-logout cookie; the last test mutates `destroy` to show the replay check can fail. Add rate limiting and a concurrency cap on hashing in front of `/login`; they are not shown. Reuse this wiring (rotate with `old_sid`, `store.destroy` on logout, uniform 401) in Flask/Django/Express; Django's `login()`/`logout()` and `express-session` `regenerate()`/`destroy()` do the rotation and kill for you.

```python
# file: app_login.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

import hashing
from session_store import SESSION_COOKIE, SessionStore

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str


def create_app(users: dict, store: SessionStore, allowed_origins=("https://app.example",)) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        """Cookie-authenticated unsafe requests must come from our own origin (ASVS 3.5.x).
        Sec-Fetch-Site is sent by current browsers; fall back to Origin; neither => reject."""
        if request.method not in SAFE_METHODS:
            site = request.headers.get("sec-fetch-site")
            ok = site in ("same-origin", "none") if site else request.headers.get("origin") in allowed_origins
            if not ok:
                return JSONResponse({"error": "csrf check failed"}, status_code=403)
        return await call_next(request)

    @app.post("/login")
    def login(creds: Credentials, request: Request):
        # In production: rate-limit and cap concurrent hashing BEFORE this call.
        user = hashing.authenticate(users, creds.username, creds.password)
        if user is None:
            return JSONResponse({"error": "invalid credentials"}, status_code=401)   # one message for all failures
        old = request.cookies.get(SESSION_COOKIE["key"])
        sid = store.create(user["id"], old_sid=old)            # NEW id; the pre-login id is destroyed
        resp = JSONResponse({"user": user["id"]})
        resp.set_cookie(SESSION_COOKIE["key"], sid, httponly=True, secure=True,
                        samesite="lax", path="/")               # no Domain, __Host- prefix
        return resp

    @app.post("/logout")
    def logout(request: Request):
        sid = request.cookies.get(SESSION_COOKIE["key"])
        if sid:
            store.destroy(sid)                                  # server-side kill, not just cookie removal
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE["key"], path="/", secure=True, httponly=True, samesite="lax")
        return resp

    @app.get("/me")
    def me(request: Request):
        rec = store.get(request.cookies.get(SESSION_COOKIE["key"]))
        if rec is None or rec["user_id"] is None:
            return JSONResponse({"error": "authentication required"}, status_code=401)
        return {"user": rec["user_id"]}

    return app
```

```python
# file: test_app_login.py
import pytest
from fastapi.testclient import TestClient

import hashing
from app_login import create_app
from session_store import SessionStore

ORIGIN = {"Origin": "https://app.example"}
PW = "correct horse battery staple"
USERS = {"alice": {"id": "alice", "password_hash": hashing.hash_password(PW)}}   # one slow hash for the module


def client(store):
    return TestClient(create_app(USERS, store), base_url="https://app.example")   # https: Secure cookies are sent


def set_sid(c, value):
    c.cookies.set("__Host-sid", value, domain="app.example", path="/")


def login(c, password=PW, headers=ORIGIN):
    return c.post("/login", json={"username": "alice", "password": password}, headers=headers)


def test_login_then_me_then_logout():
    store = SessionStore()
    c = client(store)
    assert c.get("/me").status_code == 401
    r = login(c)
    assert r.status_code == 200
    set_cookie = r.headers["set-cookie"].lower()
    assert "__host-sid=" in set_cookie and "httponly" in set_cookie and "secure" in set_cookie
    assert "samesite=lax" in set_cookie and "domain=" not in set_cookie
    assert c.get("/me").json() == {"user": "alice"}
    assert c.post("/logout", headers=ORIGIN).status_code == 200
    assert c.get("/me").status_code == 401


def test_cookie_replay_after_logout_and_fixation_cookie_replay():
    store = SessionStore()
    c = client(store)
    pre = store.create(None)                                   # anonymous pre-login session
    set_sid(c, pre)
    login(c)
    post = c.cookies.get("__Host-sid")
    assert post != pre                                         # rotated at login
    assert store.get(pre) is None                              # pre-login id destroyed server-side (fixation)
    attacker = client(store)
    set_sid(attacker, pre)
    assert attacker.get("/me").status_code == 401              # replay of the pre-login cookie is dead
    replay = client(store)
    set_sid(replay, post)
    assert replay.get("/me").json() == {"user": "alice"}       # cookie works while logged in...
    c.post("/logout", headers=ORIGIN)
    assert replay.get("/me").status_code == 401                # ...and the SAME cookie value is dead after logout


def test_failures_are_uniform():
    c = client(SessionStore())
    wrong = c.post("/login", json={"username": "alice", "password": "nope"}, headers=ORIGIN)
    unknown = c.post("/login", json={"username": "mallory", "password": "nope"}, headers=ORIGIN)
    assert (wrong.status_code, wrong.json()) == (unknown.status_code, unknown.json()) == (401, {"error": "invalid credentials"})
    assert "set-cookie" not in wrong.headers


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}])
def test_csrf_guard_blocks_cross_site_unsafe_requests(headers):
    store = SessionStore()
    c = client(store)
    assert login(c, headers=headers).status_code == 403
    login(c)
    assert c.post("/logout", headers=headers).status_code == 403
    assert c.get("/me").status_code == 200                      # the forged logout did nothing


def test_replay_test_can_fail(monkeypatch):
    """Mutation: if logout only removed the cookie client-side, the replay assertion must catch it."""
    store = SessionStore()
    monkeypatch.setattr(store, "destroy", lambda sid: None)    # TEST-ONLY mutation
    c = client(store)
    login(c)
    stolen = c.cookies.get("__Host-sid")
    c.post("/logout", headers=ORIGIN)
    replay = client(store)
    set_sid(replay, stolen)
    assert replay.get("/me").status_code == 200                 # the leak the real test above guards against
```

## Flask

```python
# file: flask_recipe.py
from flask import Flask, abort, g, jsonify, request

PERMISSIONS = {                       # keyed by endpoint (function) name
    "health": {"access": "public"},
    "read_doc": {"roles": ["member", "admin"]},
    "admin_users": {"roles": ["admin"]},
}
TOKENS = {"t-alice": ("alice", "t1", "member"), "t-bob": ("bob", "t1", "member"),
          "t-dave": ("dave", "t2", "member"), "t-carol": ("carol", "t1", "admin")}
DOCS = {1: {"id": 1, "owner_id": "alice", "tenant_id": "t1", "title": "alice doc"}}


def owner_ok(doc):
    # TEST-ONLY mutation target: tests monkeypatch this to prove the matrix can fail.
    # Never expose a switch for it via config/env.
    return doc["owner_id"] == g.user_id or g.role == "admin"


def create_app():
    app = Flask(__name__)
    app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="__Host-session",
                      SECRET_KEY="test-only-not-a-real-key")

    @app.before_request
    def enforce():                                     # one place, deny by default
        rule = PERMISSIONS.get(request.endpoint)
        if rule is None:
            abort(403)
        if rule.get("access") == "public":
            return
        auth = request.headers.get("Authorization", "")
        ident = TOKENS.get(auth[7:]) if auth.startswith("Bearer ") else None
        if ident is None:
            abort(401)
        g.user_id, g.tenant_id, g.role = ident
        if g.role not in rule["roles"]:
            abort(403)

    def load_owned(doc_id):
        doc = DOCS.get(doc_id)
        if doc is None or doc["tenant_id"] != g.tenant_id:        # tenant from principal
            abort(404)
        if not owner_ok(doc):
            abort(404)
        return doc

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/docs/<int:doc_id>")
    def read_doc(doc_id):
        return jsonify(load_owned(doc_id))

    @app.get("/admin/users")
    def admin_users():
        return jsonify(["alice"])

    @app.get("/forgot-to-map")
    def forgot_to_map():
        return jsonify(secret=True)

    return app
```

```python
# file: test_flask_recipe.py
import flask_recipe
from flask_recipe import create_app


def get(app, path, tok=None):
    h = {"Authorization": f"Bearer {tok}"} if tok else {}
    return app.test_client().get(path, headers=h).status_code


def test_flask_authorization_matrix():
    app = create_app()
    assert get(app, "/health") == 200
    assert get(app, "/docs/1") == 401
    assert get(app, "/docs/1", "t-alice") == 200
    assert get(app, "/docs/1", "t-bob") == 404       # same tenant, not owner
    assert get(app, "/docs/1", "t-dave") == 404      # other tenant
    assert get(app, "/docs/1", "t-carol") == 200     # tenant admin
    assert get(app, "/admin/users", "t-alice") == 403
    assert get(app, "/forgot-to-map", "t-carol") == 403   # deny by default


def test_flask_missing_owner_check_is_caught(monkeypatch):
    monkeypatch.setattr(flask_recipe, "owner_ok", lambda doc: True)    # TEST-ONLY mutation
    assert get(create_app(), "/docs/1", "t-bob") == 200   # the bug the matrix above would flag


def test_flask_cookie_config():
    app = create_app()
    assert app.config["SESSION_COOKIE_SECURE"] and app.config["SESSION_COOKIE_HTTPONLY"]
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_NAME"].startswith("__Host-")
```

Flask notes: Flask's default session is a signed client-side cookie; it cannot be revoked server-side, so for login/logout invalidation use a server-side store (Flask-Login + server-side session extension, or the `SessionStore` pattern in [sessions-tokens-oauth](sessions-tokens-oauth.md)). Call `session.clear()` before setting the user at login. Use `Flask-Limiter` for throttling. CSRF: with cookie sessions enable Flask-WTF `CSRFProtect(app)` (token on every unsafe form/XHR), or require a custom header plus an Origin check for pure JSON APIs. This recipe keys policy by endpoint name only, so one view function serving GET and POST shares one rule; split the views or key by `(endpoint, method)`.

## Django

Django's `django.contrib.auth.login()` cycles the session key and `logout()` flushes the session. `Argon2PasswordHasher` (needs `argon2-cffi`) defaults to time_cost=2, memory_cost=102400, parallelism=8 in 4.2.27, which is above the OWASP minimum; put it first in `PASSWORD_HASHERS` so old hashes upgrade on login.

```python
# file: django_recipe.py
import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False, SECRET_KEY="test-only-not-a-real-key", ROOT_URLCONF="django_recipe",
        ALLOWED_HOSTS=["testserver"], DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth", "django.contrib.sessions"],
        MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware",
                    "django.middleware.csrf.CsrfViewMiddleware",
                    "django.contrib.auth.middleware.AuthenticationMiddleware",
                    "django_recipe.DenyByDefaultMiddleware"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        CSRF_COOKIE_SECURE=True,
        PASSWORD_HASHERS=["django.contrib.auth.hashers.Argon2PasswordHasher",
                          "django.contrib.auth.hashers.PBKDF2PasswordHasher"],
    )
    django.setup()

from django.db import models                                   # noqa: E402
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse   # noqa: E402
from django.shortcuts import get_object_or_404                 # noqa: E402
from django.urls import path                                   # noqa: E402

POLICY = {"health": {"public": True}, "doc-detail": {"role": "member"}, "admin-home": {"role": "admin"}}


class DenyByDefaultMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        rule = POLICY.get(request.resolver_match.view_name)
        if rule is None:
            return HttpResponseForbidden("no policy")           # deny by default
        if rule.get("public"):
            return None
        if not request.user.is_authenticated:
            return HttpResponse(status=401)
        if rule["role"] == "admin" and not request.user.is_staff:
            return HttpResponseForbidden()
        return None


class DocumentQuerySet(models.QuerySet):
    def visible_to(self, request):
        tenant = request.session["tenant_id"]                   # tenant from the SESSION
        qs = self.filter(tenant_id=tenant)
        return qs if request.user.is_staff else qs.filter(owner_id=request.user.pk)


class Document(models.Model):
    owner_id = models.IntegerField()
    tenant_id = models.CharField(max_length=20)
    title = models.CharField(max_length=100)
    objects = DocumentQuerySet.as_manager()

    class Meta:
        app_label = "demo"


def health(request):
    return JsonResponse({"ok": True})


def doc_detail(request, pk):
    doc = get_object_or_404(Document.objects.visible_to(request), pk=pk)   # 404 for others
    return JsonResponse({"id": doc.pk, "title": doc.title})


def admin_home(request):
    return JsonResponse({"admin": True})


def forgot_to_map(request):
    return JsonResponse({"secret": True})


urlpatterns = [
    path("health", health, name="health"),
    path("docs/<int:pk>", doc_detail, name="doc-detail"),
    path("admin-home", admin_home, name="admin-home"),
    path("forgot", forgot_to_map, name="forgot"),
]
```

```python
# file: test_django_recipe.py
import pytest
import django_recipe as r
from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import connection
from django.test import Client


@pytest.fixture(scope="module")
def db_ready():
    call_command("migrate", run_syncdb=True, verbosity=0)
    with connection.schema_editor() as editor:
        editor.create_model(r.Document)


def login(username, tenant, staff=False):
    user, _ = User.objects.get_or_create(username=username, defaults={"is_staff": staff})
    c = Client()
    c.force_login(user)
    s = c.session
    s["tenant_id"] = tenant
    s.save()
    return c, user


def test_django_object_and_function_level(db_ready):
    alice_c, alice = login("alice", "t1")
    bob_c, _ = login("bob", "t1")
    dave_c, _ = login("dave", "t2")
    carol_c, _ = login("carol", "t1", staff=True)
    doc = r.Document.objects.create(owner_id=alice.pk, tenant_id="t1", title="alice doc")
    url = f"/docs/{doc.pk}"
    assert alice_c.get(url).status_code == 200
    assert bob_c.get(url).status_code == 404            # same tenant, not owner
    assert dave_c.get(url).status_code == 404           # other tenant
    assert carol_c.get(url).status_code == 200          # tenant admin (is_staff)
    assert Client().get(url).status_code == 401
    assert alice_c.get("/admin-home").status_code == 403
    assert carol_c.get("/admin-home").status_code == 200
    assert carol_c.get("/forgot").status_code == 403    # unmapped => denied


def test_csrf_middleware_runs_before_policy_and_rejects_tokenless_post():
    from django.conf import settings
    mw = settings.MIDDLEWARE
    assert mw.index("django.middleware.csrf.CsrfViewMiddleware") < mw.index("django_recipe.DenyByDefaultMiddleware")
    assert Client(enforce_csrf_checks=True).post("/health").status_code == 403


def test_django_settings_and_hasher():
    from django.conf import settings
    from django.contrib.auth.hashers import check_password, make_password
    assert settings.SESSION_COOKIE_SECURE and settings.SESSION_COOKIE_HTTPONLY
    h = make_password("pw-1234567890")
    assert h.startswith("argon2$argon2id$") and check_password("pw-1234567890", h)
```

Django notes: `CsrfViewMiddleware` is required for cookie sessions (it is in the recipe's `MIDDLEWARE`; send the token on every unsafe request, `CSRF_COOKIE_SECURE=True`). `is_staff` stands in for "admin" here to keep the sample short; in a multi-tenant app use a tenant-membership role instead (admin is tenant-scoped, never global). Never `fields = "__all__"` in a `ModelForm`/DRF serializer that accepts user input (mass assignment); list fields explicitly and keep `owner`, `tenant`, `is_staff`, `role` out. In DRF set `DEFAULT_PERMISSION_CLASSES` to `IsAuthenticated` (or a deny class) globally so a new view is closed by default, and implement `get_queryset()` with the same scoping as `visible_to`.

## Express (Node)

Express routes are registered imperatively, so the central check is a registrar that refuses to register a route without a policy entry (fails at boot, not at 3 a.m.) plus a test that walks the router.

```javascript
// file: express_recipe.js
const express = require("express");

const PERMISSIONS = {
  "GET /health": { access: "public" },
  "GET /documents/:id": { roles: ["member", "admin"] },
  "PATCH /documents/:id": { roles: ["member", "admin"] },
  "GET /admin/users": { roles: ["admin"] },
};
const TOKENS = new Map([            // a Map: a plain object would make `Bearer __proto__` a "principal"
  ["t-alice", { userId: "alice", tenantId: "t1", role: "member" }],
  ["t-bob", { userId: "bob", tenantId: "t1", role: "member" }],
  ["t-dave", { userId: "dave", tenantId: "t2", role: "member" }],
  ["t-carol", { userId: "carol", tenantId: "t1", role: "admin" }],
]);
const UPDATABLE = new Set(["title"]);

// TEST-ONLY mutation target: tests replace gates.ownerOk to prove the matrix can fail.
// Never expose a switch for it via config/env.
const gates = { ownerOk: (doc, p) => doc.ownerId === p.userId || p.role === "admin" };

function createApp() {
  const docs = new Map([[1, { id: 1, ownerId: "alice", tenantId: "t1", title: "alice doc" }]]);
  const app = express();
  app.use(express.json());

  function register(method, path, handler) {
    const rule = PERMISSIONS[`${method.toUpperCase()} ${path}`];
    if (!rule) throw new Error(`no policy for ${method} ${path}`);      // boot-time deny
    app[method](path, (req, res, next) => {
      if (rule.access !== "public") {
        const h = req.get("authorization") || "";
        const principal = h.startsWith("Bearer ") ? TOKENS.get(h.slice(7)) : undefined;
        if (!principal) return res.status(401).json({ error: "authentication required" });
        if (!rule.roles.includes(principal.role)) return res.status(403).json({ error: "forbidden" });
        req.principal = principal;
      }
      return handler(req, res, next);
    });
  }

  function loadDoc(req, res) {                    // single object-level gate
    const doc = docs.get(Number(req.params.id));
    const p = req.principal;
    const ok = doc && doc.tenantId === p.tenantId && gates.ownerOk(doc, p);
    if (!ok) { res.status(404).json({ error: "not found" }); return null; }
    return doc;
  }

  register("get", "/health", (req, res) => res.json({ ok: true }));
  register("get", "/documents/:id", (req, res) => {
    const doc = loadDoc(req, res); if (doc) res.json(doc);
  });
  register("patch", "/documents/:id", (req, res) => {
    const doc = loadDoc(req, res); if (!doc) return;
    const extra = Object.keys(req.body || {}).filter((k) => !UPDATABLE.has(k));
    if (extra.length) return res.status(422).json({ error: "unknown fields", extra });
    if (typeof req.body.title === "string") doc.title = req.body.title;
    res.json(doc);
  });
  register("get", "/admin/users", (req, res) => res.json(["alice", "bob", "carol"]));
  return { app, docs, register };
}

module.exports = { createApp, PERMISSIONS, gates };
```

```javascript
// file: express_recipe.test.js
const test = require("node:test");
const assert = require("node:assert");
const { createApp, PERMISSIONS, gates } = require("./express_recipe");

async function withServer(opts, fn) {
  const ctx = createApp(opts);
  const server = ctx.app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, ctx); } finally { server.close(); }
}
const call = (base, path, tok, init = {}) =>
  fetch(base + path, { ...init, headers: { "content-type": "application/json",
    ...(tok ? { authorization: `Bearer ${tok}` } : {}) } }).then((r) => r.status);

test("function and object level", () => withServer({}, async (base) => {
  assert.equal(await call(base, "/health"), 200);
  assert.equal(await call(base, "/documents/1"), 401);
  assert.equal(await call(base, "/documents/1", "t-alice"), 200);
  assert.equal(await call(base, "/documents/1", "t-bob"), 404);
  assert.equal(await call(base, "/documents/1", "t-dave"), 404);
  assert.equal(await call(base, "/documents/1", "t-carol"), 200);
  assert.equal(await call(base, "/admin/users", "t-alice"), 403);
}));

test("mass assignment rejected", () => withServer({}, async (base, { docs }) => {
  const s = await call(base, "/documents/1", "t-alice",
    { method: "PATCH", body: JSON.stringify({ title: "x", ownerId: "bob" }) });
  assert.equal(s, 422);
  assert.equal(docs.get(1).ownerId, "alice");
}));

test("missing owner check is detectable", async () => {
  const real = gates.ownerOk;
  gates.ownerOk = () => true;                                     // TEST-ONLY mutation
  try {
    await withServer({}, async (base) => {
      assert.equal(await call(base, "/documents/1", "t-bob"), 200);   // the bug
    });
  } finally { gates.ownerOk = real; }
});

test("Object.prototype keys are not credentials", () => withServer({}, async (base) => {
  for (const k of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    assert.equal(await call(base, "/documents/1", k), 401, k);
  }
}));

test("route without policy refuses to register", () => {
  const { register } = createApp();
  assert.throws(() => register("get", "/oops", () => {}), /no policy/);
});

test("every registered route has a policy entry", () => {
  const { app } = createApp();
  const seen = new Set();
  for (const layer of app.router.stack) {
    if (layer.route) for (const m of Object.keys(layer.route.methods)) {
      seen.add(`${m.toUpperCase()} ${layer.route.path}`);
    }
  }
  assert.deepEqual([...seen].sort(), Object.keys(PERMISSIONS).sort());
});
```

Express notes: set the cookie options on `express-session` (`cookie: {secure: true, httpOnly: true, sameSite: "lax"}`, name `__Host-sid`, `resave: false`, `saveUninitialized: false`), call `req.session.regenerate()` on login and `req.session.destroy()` on logout, set `app.set("trust proxy", n)` only to the real number of proxies, and add `express-rate-limit` on login/reset routes. CSRF: `csurf` is deprecated; use a maintained double-submit/synchronizer-token library, or for JSON APIs require a custom header and check `Origin` / `Sec-Fetch-Site` on unsafe methods. Look tokens up in a `Map` (or `Object.hasOwn`), never with `obj[userInput]`. Confirm option names in the installed version's docs.

## Next.js (App Router, TypeScript)

Not executed in the sandbox (no Next install); the pattern is the same registrar idea and must be tested like the others.

```typescript
// lib/policy.ts  (sketch: adapt getSession to your session library)
import { z } from "zod";

type Principal = { userId: string; tenantId: string; role: "member" | "admin" };
declare function getSession(req: Request): Promise<Principal | null>;   // your session library

export const PERMISSIONS = {
  "GET /api/documents/[id]": { roles: ["member", "admin"] },
  "PATCH /api/documents/[id]": { roles: ["member", "admin"] },
} as const;

export function withPolicy<K extends keyof typeof PERMISSIONS>(key: K, handler: (req: Request, ctx: { principal: Principal; params: any }) => Promise<Response>) {
  return async (req: Request, ctx: { params: Promise<any> }) => {
    const principal = await getSession(req);                 // verify the session HERE
    if (!principal) return new Response(null, { status: 401 });
    if (!(PERMISSIONS[key].roles as readonly string[]).includes(principal.role)) return new Response(null, { status: 403 });
    return handler(req, { principal, params: await ctx.params });
  };
}

export const UpdateDoc = z.object({ title: z.string().max(200) }).strict();   // mass assignment
```

- The `withPolicy` wrapper is opt-in: a Route Handler that forgets it is open, so this recipe is NOT deny-by-default by itself. Add a test that globs `app/**/route.ts` and fails unless each file exports only wrapped handlers (or is listed in `PERMISSIONS`); this was not executed here.
- Check authorization inside every Route Handler and Server Action (they are public HTTP endpoints), and again in the data-access layer where the object loader scopes by `principal.tenantId`.
- Do not make `middleware.ts` your only gate. CVE-2025-29927 (GHSA-f82v-jwr5-mffw, published 2025-03-21) allowed bypassing Next.js middleware authorization via the `x-middleware-subrequest` header; fixed in 15.2.3, 14.2.25, 13.5.9, 12.3.5. Keep Next patched, strip that header at the edge proxy if you cannot upgrade, and keep defence in depth in handlers.
- Keep session secrets and tokens server-side; do not read tenant/user ids from `searchParams`, body or hidden form fields.
