# pytest patterns (FastAPI, Flask, Django)

Full, executed project: `templates/fastapi-pytest/` (52 tests; 26 red on vulnerable, 52 green on fixed).

## Layout and config

```
tests/
  conftest.py              # app/client/login/forge fixtures (synthetic users)
  security/
    permission_map.py
    test_authz_matrix.py
    test_authn.py
    test_input_and_output.py
pytest.ini                 # pythonpath = src ; markers = security
```

Mark with `pytestmark = pytest.mark.security` so CI can run `pytest -m security` as its own fast job.

## Fixtures

```python
@pytest.fixture
def app():            return create_app()                     # fresh in-memory state per test
@pytest.fixture
def client(app):      return TestClient(app)
@pytest.fixture
def login(client):    # returns headers for a synthetic user
    def _login(user):
        r = client.post("/login", json={"username": user, "password": PASSWORDS[user]})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _login
@pytest.fixture
def forge():          # tokens with chosen claims/keys/algs for negative tests
    ...
```

Prefer `jwt.encode(claims, key, algorithm="none")`-style forging in the test over a mock of the verifier: mocking the verifier tests the mock. For expiry use a past `exp` claim or freeze time; never `sleep`.

## FastAPI (Starlette TestClient)

- `from fastapi.testclient import TestClient` (needs `httpx`).
- `TestClient` re-raises unhandled server exceptions by default; to test the *response* to an unhandled error use `TestClient(app, raise_server_exceptions=False)`.
- Override auth dependencies only to test **other** behaviour; the auth tests must use the real dependency. Clear `app.dependency_overrides` in a fixture finalizer.

## Flask (verified with Flask 3.1.3)

```python
@pytest.fixture
def client(): return create_app().test_client()

@pytest.mark.parametrize("user,nid,status", [("alice", 1, 200), ("alice", 2, 404), ("bob", 1, 404), (None, 1, 401)])
def test_owner_matrix(client, user, nid, status):
    headers = {"X-Test-User": user} if user else {}
    assert client.get(f"/notes/{nid}", headers=headers).status_code == status
```

(In the project use your real login flow or `flask-login` test helpers rather than a test header; a test-only header must be absent from production code.) Headers: `client.get(...).headers["X-Content-Type-Options"]`.

## Django (pytest-django; snippet executed by the independent review against a toy view)

```python
import pytest
from django.contrib.auth import get_user_model

@pytest.fixture
def users(db):
    U = get_user_model()
    return {n: U.objects.create_user(n, password=f"pw-{n}-test") for n in ("alice", "bob")}

@pytest.mark.parametrize("actor,owner,status", [("alice", "alice", 200), ("alice", "bob", 404)])
def test_object_level(client, users, actor, owner, status):
    from myapp.models import Note
    note = Note.objects.create(owner=users[owner], body="synthetic")
    client.force_login(users[actor])                     # Django test client
    assert client.get(f"/notes/{note.pk}/").status_code == status
```

Also: anonymous -> `302` to login or `401/403` (assert the app's documented behaviour), `@pytest.mark.django_db` for DB access, `override_settings(SECURE_...)` only to test the *setting-driven* behaviour you ship.

## Caplog, monkeypatch, parametrize tips

- Secrets in logs: `with caplog.at_level(logging.DEBUG): ...; assert canary not in caplog.text` plus a positive control that something was logged. Include third-party loggers (httpx/urllib3 log URLs; do not put secrets in query strings).
- Time: `monkeypatch.setattr(module.time, "time", lambda: FIXED)`.
- `ids=lambda v: str(v)` or explicit `pytest.param(..., id="member-reads-other-owner")` so a failure names the attack.
- Do not catch `AssertionError` or use `pytest.raises(Exception)` broadly; assert the exact outcome.
- Property-style fuzzing (Hypothesis) of validators is welcome for pure functions, bounded with `@settings(max_examples=50, derandomize=True)` to keep CI stable.
