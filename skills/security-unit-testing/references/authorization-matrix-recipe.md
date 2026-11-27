# Authorization matrix recipe (generate tests from a permission map)

Idea: one dict is the specification; the tests are generated from it; a completeness test fails when code and dict diverge. Working versions live in `templates/fastapi-pytest/tests/security/` and `templates/express-jest/tests/security/` (verified; see VERIFICATION-NOTES).

## Step 1: write the permission map

```python
# tests/security/permission_map.py
ROLES_ALLOWED = {                      # (METHOD, route template) -> roles allowed; None = public on purpose
    ("POST", "/login"): None,
    ("GET", "/notes/{note_id}"): {"member", "admin"},      # plus object rules below
    ("DELETE", "/admin/notes/{note_id}"): {"admin"},
}
ALL_ROLES = {"member", "admin"}
ROLE_USERS = {"member": "alice", "admin": "adam"}          # one synthetic user per role
# object-level rules as data: (actor, resource id, allowed)
READ_NOTE = [("alice", 1, True), ("alice", 2, False), ("carol", 1, False), ("adam", 3, False)]
```

Derive the first draft from the code (decorators, router config), but get the *intent* from the spec or product owner: a map copied from buggy code encodes the bug.

## Step 2: generate the cases

| Generated test | Cases |
|---|---|
| anonymous rejected | every protected key -> `401` |
| role not allowed | every (key, role) with `role not in allowed` -> `403` |
| allowed role works | every (key, role in allowed) -> not 401/403 (control; needs valid sample data) |
| object level | every row of the object table: allowed -> 2xx, else status in `{403, 404}` and no side effect |
| tenant isolation | rows that pair an actor of tenant A with a resource of tenant B, including *admin* of A |
| completeness | set of routes registered in the app == set of keys in the map |

```python
CASES = [(m, p, role) for (m, p), allowed in ROLES_ALLOWED.items() if allowed is not None
         for role in ALL_ROLES - allowed]

@pytest.mark.parametrize("method,path,role", CASES, ids=lambda v: str(v))
def test_role_not_in_map_is_forbidden(client, login, method, path, role):
    r = client.request(method, concrete(path), headers=login(ROLE_USERS[role]))
    assert r.status_code == 403
```

Completeness (FastAPI/Starlette): `{(m, r.path) for r in app.routes for m in r.methods - {"HEAD","OPTIONS"}} == set(ROLES_ALLOWED)`. Disable docs/openapi routes in the app factory under test, or list them as public in the map. Express 5: iterate `app.router.stack` entries with `.route` (Express 4: `app._router.stack`); the template handles both. Flask: `app.url_map.iter_rules()`; Django: walk `get_resolver().url_patterns`.

## Step 3: keep it honest

- Add the user as a new row when you add a role; the generator then creates the whole new column.
- Denied cases check side effects too: after a denied delete, a legitimate owner can still read the resource.
- Use the app's documented denial status. If the app uses `404` to avoid confirming existence, assert `in {403, 404}` for object rules but exactly `403` for function-level rules, so a change of policy is a conscious edit.
- Field-level rules (ASVS 8.2.3): add `(actor, resource, forbidden_fields)` rows and assert the fields are absent from the response.
- Do not generate the expected value from the implementation (importing the app's own role table as the oracle makes the test tautological).

## Step 4: failure output to expect

On the vulnerable template variant the matrix goes red on exactly the cross-owner, cross-tenant, member-on-admin cells, e.g. `test_read_note_object_level[alice-2-False]`, `test_delete_note_object_level[adam-3-False]`, while the anonymous and valid-token controls stay green: that pattern is what a correct matrix looks like.
