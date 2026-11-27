"""Authentication negative paths: forged / expired / none-alg tokens, logout, lockout."""
import time

import jwt
import pytest

pytestmark = pytest.mark.security


def status(client, headers):
    return client.get("/notes", headers=headers).status_code


def test_valid_token_works(client, login):               # control: proves the rest are not 401 by accident
    assert status(client, login("alice")) == 200


def test_missing_and_malformed_authorization_header(client):
    assert status(client, {}) == 401
    assert status(client, {"Authorization": "Bearer"}) == 401
    assert status(client, {"Authorization": "Basic abc"}) == 401
    assert status(client, {"Authorization": "Bearer not.a.jwt"}) == 401


def test_token_signed_with_wrong_key_is_rejected(client, forge):
    assert status(client, forge(key="some-other-signing-key-0123456789-xyz")) == 401


def test_expired_token_is_rejected(client, forge):
    assert status(client, forge(exp=int(time.time()) - 10)) == 401


def test_alg_none_token_is_rejected(client):
    unsigned = jwt.encode({"sub": "adam", "role": "admin", "tenant": "tenant-a", "jti": "n1",
                           "exp": int(time.time()) + 600}, key=None, algorithm="none")
    assert status(client, {"Authorization": f"Bearer {unsigned}"}) == 401


def test_tampered_claims_are_rejected(client, login):
    token = login("alice")["Authorization"][7:]
    head, _payload, sig = token.split(".")
    forged_payload = jwt.utils.base64url_encode(
        b'{"sub":"adam","role":"admin","tenant":"tenant-a","jti":"x","exp":9999999999}').decode()
    assert status(client, {"Authorization": f"Bearer {head}.{forged_payload}.{sig}"}) == 401


def test_logout_invalidates_the_token(client, login):
    headers = login("alice")
    assert client.post("/logout", headers=headers).status_code == 204
    assert status(client, headers) == 401


def test_lockout_after_repeated_failures_even_with_correct_password(client):
    for _ in range(5):
        assert client.post("/login", json={"username": "bob", "password": "wrong"}).status_code == 401
    r = client.post("/login", json={"username": "bob", "password": "pw-bob-test"})
    assert r.status_code == 429


def test_login_errors_do_not_reveal_which_part_was_wrong(client):
    a = client.post("/login", json={"username": "nobody", "password": "x"})
    b = client.post("/login", json={"username": "alice", "password": "x"})
    assert (a.status_code, a.json()) == (b.status_code, b.json())
