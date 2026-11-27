"""Fixtures: fresh app + in-memory DB per test, deterministic synthetic users.

Select the variant with SUT_FIXED=1 (fixed) or SUT_FIXED=0 (vulnerable). Default: fixed.
In a real project there is no toggle: the tests run against your app, and "red" is produced
by reverting the fix (see references/red-green-discipline.md).
"""
import os
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import notes_app

PASSWORDS = {"alice": "pw-alice-test", "bob": "pw-bob-test", "carol": "pw-carol-test", "adam": "pw-adam-test"}


@pytest.fixture
def app():
    return notes_app.create_app(fixed=os.getenv("SUT_FIXED", "1") == "1")


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def login(client):
    def _login(user: str) -> dict:
        r = client.post("/login", json={"username": user, "password": PASSWORDS[user]})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _login


@pytest.fixture
def forge():
    """Build tokens with chosen claims/keys/algorithms, for authentication negative tests."""
    def _forge(key=notes_app.SECRET, alg="HS256", **overrides):
        now = int(time.time())
        claims = {"sub": "alice", "role": "member", "tenant": "tenant-a", "jti": "forged-1",
                  "iat": now, "exp": now + 600}
        claims.update(overrides)
        return {"Authorization": "Bearer " + jwt.encode(claims, key, algorithm=alg)}
    return _forge
