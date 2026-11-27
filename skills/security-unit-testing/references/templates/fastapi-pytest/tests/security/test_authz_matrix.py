"""Authorization matrix generated from permission_map.py (role x endpoint, owner vs non-owner, tenant A vs B)."""
import pytest

from notes_app import USERS, create_app
import permission_map as pm

pytestmark = pytest.mark.security
DENIED = (403, 404)
SAMPLE_PATH = {"{note_id}": "1"}


def concrete(path: str) -> str:
    for k, v in SAMPLE_PATH.items():
        path = path.replace(k, v)
    return path


def call(client, method, path, headers=None):
    kwargs = {"params": {"q": "x"}} if path.endswith("/search") else {}
    if method == "POST" and path == "/notes":
        kwargs["json"] = {"body": "synthetic"}
    return client.request(method, path, headers=headers or {}, **kwargs)


def test_every_route_has_a_policy_entry():
    """A new endpoint with no entry in the permission map must fail the build."""
    routes = {(m, r.path) for r in create_app().routes for m in getattr(r, "methods", set())
              if m not in {"HEAD", "OPTIONS"}}
    assert routes == set(pm.ROLES_ALLOWED), f"unmapped or stale: {routes ^ set(pm.ROLES_ALLOWED)}"


PROTECTED = [(m, p) for (m, p), roles in pm.ROLES_ALLOWED.items() if roles is not None]


@pytest.mark.parametrize("method,path", PROTECTED, ids=lambda v: str(v))
def test_anonymous_is_rejected(client, method, path):
    assert call(client, method, concrete(path)).status_code == 401


CASES = [(m, p, role) for (m, p), allowed in pm.ROLES_ALLOWED.items() if allowed is not None
         for role in pm.ALL_ROLES - allowed]


@pytest.mark.parametrize("method,path,role", CASES, ids=lambda v: str(v))
def test_role_not_in_map_is_forbidden(client, login, method, path, role):
    headers = login(pm.ROLE_USERS[role])
    assert call(client, method, concrete(path), headers).status_code == 403


@pytest.mark.parametrize("actor,note_id,allowed", pm.READ_NOTE, ids=lambda v: str(v))
def test_read_note_object_level(client, login, actor, note_id, allowed):
    r = client.get(f"/notes/{note_id}", headers=login(actor))
    assert (r.status_code == 200) if allowed else (r.status_code in DENIED), r.text


@pytest.mark.parametrize("actor,note_id,allowed", pm.DELETE_NOTE, ids=lambda v: str(v))
def test_delete_note_object_level(client, login, actor, note_id, allowed):
    r = client.delete(f"/admin/notes/{note_id}", headers=login(actor))
    assert (r.status_code == 204) if allowed else (r.status_code in DENIED), r.text


def test_list_contains_only_own_notes(client, login):
    bodies = [n["body"] for n in client.get("/notes", headers=login("alice")).json()]
    assert bodies == ["alice private note"]


def test_denied_delete_did_not_delete(client, login):
    client.delete("/admin/notes/3", headers=login("adam"))
    assert client.get("/notes/3", headers=login("carol")).status_code == 200
