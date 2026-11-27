"""Input boundaries, injection-safe queries, error leakage, headers, upload rules, secrets in logs."""
import logging

import pytest

from notes_app import MAX_UPLOAD_BYTES, validate_upload
import os

pytestmark = pytest.mark.security
FIXED = os.getenv("SUT_FIXED", "1") == "1"
MARKER = "zzz' OR 1=1 --"                    # harmless marker: closes the quote, adds a tautology, comments the rest


def test_search_payload_is_treated_as_data_not_sql(client, login):
    h = login("alice")
    r = client.get("/notes/search", params={"q": MARKER}, headers=h)
    assert r.status_code == 200
    assert r.json() == []                    # an injected tautology would have returned every row


def test_search_does_not_cross_owner_boundary(client, login):
    r = client.get("/notes/search", params={"q": "private"}, headers=login("alice"))
    assert [n["body"] for n in r.json()] == ["alice private note"]


def test_sql_metacharacters_round_trip_as_stored_data(client, login):
    h = login("alice")
    payload = "'); DROP TABLE notes;--"
    nid = client.post("/notes", json={"body": payload}, headers=h).json()["id"]
    assert client.get(f"/notes/{nid}", headers=h).json()["body"] == payload
    assert client.get("/notes", headers=h).status_code == 200      # table still exists


def test_malformed_query_does_not_leak_database_internals(client, login):
    r = client.get("/notes/search", params={"q": "'"}, headers=login("alice"))
    # Fixed code treats the quote as data: 200 with no rows. Assert on state/shape (status class and an
    # empty list), not on words, so an app whose normal JSON has an "error" key is not falsely failed.
    assert r.status_code < 500 and r.json() == []


def test_unhandled_error_response_has_no_exception_details(app, monkeypatch):
    import notes_app
    from fastapi.testclient import TestClient
    quiet = TestClient(app, raise_server_exceptions=False)  # default TestClient re-raises server errors
    monkeypatch.setattr(notes_app, "SECRET", None)       # force an internal failure on login
    r = quiet.post("/login", json={"username": "alice", "password": "pw-alice-test"})
    assert r.status_code == 500
    # Generic body, or at least no stack/exception markers (case-insensitive); never match exact wording.
    assert r.json() == {"detail": "internal error"} or not any(
        w in r.text.lower() for w in ("traceback", "exception", "error:", " line "))


@pytest.mark.parametrize("body,expected", [
    ("a", 201), ("a" * 1000, 201),                     # boundaries: min and max
    ("", 422), ("a" * 1001, 422),                      # just outside
    (None, 422), (123, 422), (["a"], 422),             # wrong types
], ids=lambda v: repr(v)[:20])
def test_note_body_boundaries(client, login, body, expected):
    r = client.post("/notes", json={"body": body}, headers=login("alice"))
    assert r.status_code == expected


@pytest.mark.parametrize("name,size,ok", [
    ("avatar.png", 10, True), ("avatar.JPG", MAX_UPLOAD_BYTES, True),
    ("avatar.png", MAX_UPLOAD_BYTES + 1, False), ("avatar.png", 0, False),
    ("shell.php", 10, False), ("a.png.php", 10, False), ("a.php.png", 10, False),
    ("../a.png", 10, False), ("a.png\x00.php", 10, False), ("noext", 10, False),
], ids=lambda v: str(v))
def test_upload_validation_table(name, size, ok):
    assert validate_upload(name, size, fixed=FIXED) is ok


def test_security_headers_present(client, login):
    r = client.get("/notes", headers=login("alice"))
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "no-store" in r.headers.get("cache-control", "")
    assert "frame-ancestors 'none'" in r.headers.get("content-security-policy", "")


def test_failed_login_does_not_log_the_password(client, caplog):
    secret = "pw-synthetic-canary-7731"
    with caplog.at_level(logging.DEBUG):
        client.post("/login", json={"username": "alice", "password": secret})
    assert secret not in caplog.text
