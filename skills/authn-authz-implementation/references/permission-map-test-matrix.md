# Permission map as data, and the generated authorization test matrix

Goal: the declared intent (who may call what, on which objects) lives in ONE data structure. The app enforces it centrally (deny by default) and the tests are generated from it, so a new route without a policy entry fails CI and a missing object check fails a matrix cell. ASVS 5.0 V8.1.1 asks for exactly this documented rule set; V8.2.1/8.2.2/8.3.1/8.4.1 are what the code and tests enforce. Executed evidence: [VERIFICATION-NOTES](VERIFICATION-NOTES.md).

## Pattern

1. `policy.py` holds `PERMISSIONS`: `"METHOD /route/{param}" -> {access, roles, object}`. `object` names an ownership rule (`owner`, `owner_or_tenant_admin`) implemented once in `object_allowed`.
2. One enforcement point: a global dependency (FastAPI), `before_request` (Flask), middleware `process_view` (Django) or a route registrar (Express). It looks the route up and returns 403 when it is not in the map.
3. Object-level check in ONE loader used by every handler that takes an id, plus the same predicate for list filters. Tenant id and user id come from the authenticated principal, never from the request body, query or path.
4. Request models forbid unknown fields (mass assignment), with owner/tenant set server-side.
5. Tests: (a) completeness (routes in app == routes in map), (b) function-level matrix (role x endpoint), (c) object-level matrix (principal x owner x tenant), (d) mass-assignment, (e) a deliberately broken app (the object check monkeypatched to allow everything, in the test only) that the matrix MUST flag, proving the tests can fail. Do not add a "disable the check" flag to the production app factory.
6. The oracle in tests (what each rule should mean) is written from the rule text, not imported from the implementation, otherwise the test only proves the code equals itself. Keep `object_allowed` and the oracle as two separate pieces of code.

Decision: return 404 (not 403) when the object exists but belongs to someone else, to avoid confirming existence; return 403 when the *function* is not permitted for the role. Log the denial either way.

```python
# file: policy.py
ROLES = ["member", "admin"]          # admin is tenant-scoped, never global

PERMISSIONS = {
    "GET /health":                {"access": "public"},
    "GET /documents":             {"access": "roles", "roles": ["member", "admin"], "object": "owner_or_tenant_admin"},
    "POST /documents":            {"access": "roles", "roles": ["member", "admin"]},
    "GET /documents/{doc_id}":    {"access": "roles", "roles": ["member", "admin"], "object": "owner_or_tenant_admin"},
    "PATCH /documents/{doc_id}":  {"access": "roles", "roles": ["member", "admin"], "object": "owner_or_tenant_admin"},
    "DELETE /documents/{doc_id}": {"access": "roles", "roles": ["member", "admin"], "object": "owner"},
    "GET /admin/users":           {"access": "roles", "roles": ["admin"]},
}


def object_allowed(rule: str, principal, doc: dict) -> bool:
    """Single implementation of object-level rules. Cross-tenant is always denied."""
    if doc["tenant_id"] != principal.tenant_id:
        return False
    if rule == "owner":
        return doc["owner_id"] == principal.user_id
    if rule == "owner_or_tenant_admin":
        return doc["owner_id"] == principal.user_id or principal.role == "admin"
    return False                      # unknown rule: deny
```

```python
# file: app_fastapi.py
from dataclasses import dataclass

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

import policy


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: str


TOKENS = {   # stand-in for session/JWT verification; synthetic identities
    "t-alice": Principal("alice", "t1", "member"),
    "t-bob":   Principal("bob",   "t1", "member"),
    "t-carol": Principal("carol", "t1", "admin"),
    "t-dave":  Principal("dave",  "t2", "member"),
    "t-erin":  Principal("erin",  "t2", "admin"),
}
SEED = {
    1: {"id": 1, "title": "alice doc", "owner_id": "alice", "tenant_id": "t1"},
    2: {"id": 2, "title": "dave doc",  "owner_id": "dave",  "tenant_id": "t2"},
    3: {"id": 3, "title": "bob doc",   "owner_id": "bob",   "tenant_id": "t1"},
}


class DocumentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")      # mass-assignment guard
    title: str


class DocumentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = None


def create_app() -> FastAPI:
    docs = {k: dict(v) for k, v in SEED.items()}
    next_id = [100]

    def enforce(request: Request):
        """Central function-level check. Unknown route => deny (403)."""
        route = request.scope.get("route")
        rule = policy.PERMISSIONS.get(f"{request.method} {route.path}") if route else None
        if rule is None:
            raise HTTPException(403, "no policy for this route")
        request.state.rule = rule
        if rule["access"] == "public":
            return None
        header = request.headers.get("authorization", "")
        principal = TOKENS.get(header[7:]) if header.startswith("Bearer ") else None
        if principal is None:
            raise HTTPException(401, "authentication required")
        if principal.role not in rule["roles"]:
            raise HTTPException(403, "role not permitted")
        return principal

    def load_doc(doc_id: int, request: Request, principal: Principal = Depends(enforce)):
        """Single object-level gate for every handler that takes an id."""
        doc = docs.get(doc_id)
        if doc is None:
            raise HTTPException(404)
        if not policy.object_allowed(request.state.rule["object"], principal, doc):
            raise HTTPException(404)               # hide existence
        return doc

    # Global dependencies guard only APIRoutes: mount()ed apps, plain Starlette routes and static
    # files bypass them. test_every_route_... below fails if any such route exists.
    app = FastAPI(dependencies=[Depends(enforce)], docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/documents")
    def list_documents(request: Request, principal: Principal = Depends(enforce)):
        rule = request.state.rule["object"]
        return [d for d in docs.values() if policy.object_allowed(rule, principal, d)]

    @app.post("/documents", status_code=201)
    def create_document(body: DocumentCreate, principal: Principal = Depends(enforce)):
        next_id[0] += 1
        doc = {"id": next_id[0], "title": body.title,
               "owner_id": principal.user_id, "tenant_id": principal.tenant_id}  # from session
        docs[doc["id"]] = doc
        return doc

    @app.get("/documents/{doc_id}")
    def read_document(doc: dict = Depends(load_doc)):
        return doc

    @app.patch("/documents/{doc_id}")
    def update_document(body: DocumentUpdate, doc: dict = Depends(load_doc)):
        if body.title is not None:
            doc["title"] = body.title
        return doc

    @app.delete("/documents/{doc_id}", status_code=204)
    def delete_document(doc: dict = Depends(load_doc)):
        del docs[doc["id"]]

    @app.get("/admin/users")
    def admin_users(principal: Principal = Depends(enforce)):
        return sorted(p.user_id for p in TOKENS.values() if p.tenant_id == principal.tenant_id)

    app.state.docs = docs
    return app
```

```python
# file: test_matrix.py
"""Authorization tests GENERATED from policy.PERMISSIONS."""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import policy
from app_fastapi import TOKENS, create_app

PRINCIPALS = {tok[2:]: tok for tok in TOKENS}   # "alice" -> "t-alice"
ANON = {}


def hdr(who):
    return {"Authorization": f"Bearer {PRINCIPALS[who]}"} if who else ANON


def concrete(key):
    method, path = key.split(" ", 1)
    return method, path.replace("{doc_id}", "1")


# ---- oracle: written from the rule text, independent of policy.object_allowed ----
def oracle(rule, who, doc):
    p = TOKENS[PRINCIPALS[who]]
    if p.tenant_id != doc["tenant_id"]:
        return False
    if rule == "owner":
        return p.user_id == doc["owner_id"]
    return p.user_id == doc["owner_id"] or p.role == "admin"


def call(client, method, path, who):
    body = {"title": "x"} if method in ("PATCH", "POST") else None
    return client.request(method, path, headers=hdr(who), json=body)


def object_matrix_failures(app_factory):
    """Return a list of (endpoint, principal, expected, got) mismatches."""
    failures = []
    for key, rule in policy.PERMISSIONS.items():
        if "object" not in rule or "{doc_id}" not in key:
            continue
        for who in [*PRINCIPALS]:
            if TOKENS[PRINCIPALS[who]].role not in rule["roles"]:
                continue
            app = app_factory()
            doc = dict(app.state.docs[1])                 # alice's doc, tenant t1
            method, path = concrete(key)
            got = call(TestClient(app), method, path, who).status_code
            allowed = oracle(rule["object"], who, doc)
            if allowed != (got < 300):
                failures.append((key, who, "allow" if allowed else "deny", got))
    return failures


def check_complete(app):
    foreign = [r for r in app.routes if not isinstance(r, APIRoute) and r.path not in ("/openapi.json",)]
    assert not foreign, f"routes outside the policy hook: {foreign}"
    routes = {f"{m} {r.path}" for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    assert routes == set(policy.PERMISSIONS)


def test_every_route_has_a_policy_entry_and_vice_versa():
    check_complete(create_app())


def test_completeness_check_fails_on_mounts_and_plain_starlette_routes():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    app = create_app()
    app.mount("/sub", Starlette(routes=[Route("/secret", lambda r: JSONResponse({"leak": True}))]))
    app.router.routes.append(Route("/plain", lambda r: JSONResponse({"leak": True})))
    c = TestClient(app)
    assert c.get("/sub/secret").status_code == 200          # the global dependency does NOT cover these
    assert c.get("/plain").status_code == 200
    with pytest.raises(AssertionError, match="outside the policy hook"):
        check_complete(app)


@pytest.mark.parametrize("key", sorted(policy.PERMISSIONS))
@pytest.mark.parametrize("who", [None, *PRINCIPALS])
def test_function_level_matrix(key, who):
    rule = policy.PERMISSIONS[key]
    method, path = concrete(key)
    got = call(TestClient(create_app()), method, path, who).status_code
    if rule["access"] == "public":
        assert got not in (401, 403)
    elif who is None:
        assert got == 401
    elif TOKENS[PRINCIPALS[who]].role not in rule["roles"]:
        assert got == 403
    else:
        assert got not in (401, 403)


def test_object_level_matrix_secure_app_has_no_failures():
    assert object_matrix_failures(create_app) == []


def test_matrix_detects_a_missing_object_check(monkeypatch):
    # TEST-ONLY mutation: the object rule is patched to allow everything. Never ship a flag for this.
    monkeypatch.setattr(policy, "object_allowed", lambda rule, principal, doc: True)
    failures = object_matrix_failures(create_app)
    assert failures, "matrix must fail when the ownership check is removed"
    assert any(who == "bob" and key == "GET /documents/{doc_id}" for key, who, _, _ in failures)


def test_user_b_cannot_read_user_a_object_but_owner_can():
    c = TestClient(create_app())
    assert c.get("/documents/1", headers=hdr("alice")).json()["owner_id"] == "alice"
    assert c.get("/documents/1", headers=hdr("bob")).status_code == 404       # same tenant
    assert c.get("/documents/1", headers=hdr("erin")).status_code == 404      # other tenant admin
    assert c.get("/documents/1", headers=hdr("carol")).status_code == 200     # tenant admin


def test_list_is_scoped_by_the_same_rule():
    c = TestClient(create_app())
    assert [d["id"] for d in c.get("/documents", headers=hdr("alice")).json()] == [1]
    assert sorted(d["id"] for d in c.get("/documents", headers=hdr("carol")).json()) == [1, 3]
    assert [d["id"] for d in c.get("/documents", headers=hdr("dave")).json()] == [2]


def test_mass_assignment_and_tenant_from_session():
    app = create_app()
    c = TestClient(app)
    r = c.patch("/documents/1", headers=hdr("alice"), json={"title": "t", "owner_id": "bob"})
    assert r.status_code == 422 and app.state.docs[1]["owner_id"] == "alice"
    r = c.post("/documents", headers=hdr("alice"), json={"title": "n", "tenant_id": "t2"})
    assert r.status_code == 422
    r = c.post("/documents", headers=hdr("alice"), json={"title": "n"})
    assert r.status_code == 201 and r.json()["tenant_id"] == "t1" and r.json()["owner_id"] == "alice"


def test_unmapped_route_is_denied_by_default():
    app = create_app()
    app.add_api_route("/oops", lambda: {"leak": True}, methods=["GET"])   # developer forgot the policy
    r = TestClient(app).get("/oops", headers=hdr("carol"))
    assert r.status_code == 403


def test_admin_list_is_tenant_scoped():
    c = TestClient(create_app())
    assert c.get("/admin/users", headers=hdr("carol")).json() == ["alice", "bob", "carol"]
    assert c.get("/admin/users", headers=hdr("alice")).status_code == 403
```

How to adopt in a real project (small diffs): (1) list routes (`grep -rnE "@(app|router)\.(get|post|put|patch|delete)"`, or dump `app.routes` / `url_map`) and write the `PERMISSIONS` entries; (2) add the single enforcement hook; (3) route every id lookup through one loader; (4) copy the matrix tests and replace `TOKENS` with your fixtures; (5) run the suite once with the object check mutated (the `monkeypatch` test above automates that; prefer mutating the loader in the test over a flag in the app) and confirm the matrix fails, then restore it.

Generated-matrix output for review (print it in the PR): rows = endpoints, columns = anon/member/admin/other-tenant, cell = expected status class. A reviewer can read intent in 20 seconds and a CI diff shows any permission change as a changed cell.
