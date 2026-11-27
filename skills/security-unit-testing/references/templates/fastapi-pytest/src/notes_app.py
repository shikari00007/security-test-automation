"""Tiny notes API with INTENTIONAL security bugs, behind a fix toggle.

create_app(fixed=False) is the vulnerable variant; create_app(fixed=True) is the fixed one.
Everything here is synthetic. Do not deploy: secrets are test-only, hashing is cheap on purpose.
"""
import hashlib
import hmac
import logging
import sqlite3
import time
import uuid
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

log = logging.getLogger("notes")
SECRET = "test-only-signing-key-0123456789-abcdef"  # synthetic
ALGORITHM = "HS256"
TOKEN_TTL = 900
MAX_FAILED_LOGINS = 5
ALLOWED_UPLOAD_EXT = {".png", ".jpg", ".jpeg"}
MAX_UPLOAD_BYTES = 1_000_000


def _hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"test-salt", 1000).hex()


USERS = {  # username -> (password hash, role, tenant)
    "alice": (_hash("pw-alice-test"), "member", "tenant-a"),
    "bob": (_hash("pw-bob-test"), "member", "tenant-a"),
    "carol": (_hash("pw-carol-test"), "member", "tenant-b"),
    "adam": (_hash("pw-adam-test"), "admin", "tenant-a"),
}


def validate_upload(filename: str, size: int, fixed: bool = True) -> bool:
    """Pure function so it is unit-testable without a server."""
    name = filename.lower()
    if not fixed:
        return name.endswith((".png", ".jpg", ".jpeg", ".php"))  # BUG: wrong list, no size cap
    if size <= 0 or size > MAX_UPLOAD_BYTES:
        return False
    if "/" in filename or "\\" in filename or "\x00" in filename:
        return False
    parts = name.split(".")
    # exactly one extension: "x.png.php" and "x.php.png" are refused
    return len(parts) == 2 and "." + parts[1] in ALLOWED_UPLOAD_EXT


class NoteIn(BaseModel):
    body: str


class NoteInStrict(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


class Login(BaseModel):
    username: str
    password: str


def create_app(fixed: bool = True) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, tenant TEXT, body TEXT)")
    db.executemany(
        "INSERT INTO notes (id, owner, tenant, body) VALUES (?,?,?,?)",
        [(1, "alice", "tenant-a", "alice private note"),
         (2, "bob", "tenant-a", "bob private note"),
         (3, "carol", "tenant-b", "carol private note")],
    )
    revoked: set = set()
    failures: dict = {}

    if fixed:
        @app.middleware("http")
        async def security_headers(request: Request, call_next):
            resp = await call_next(request)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            return resp

    def current_user(authorization: Optional[str] = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "authentication required")
        try:
            claims = jwt.decode(authorization[7:], SECRET, algorithms=[ALGORITHM])
        except jwt.PyJWTError:
            raise HTTPException(401, "invalid token")
        if fixed and claims.get("jti") in revoked:
            raise HTTPException(401, "invalid token")
        return claims

    @app.post("/login")
    def login(data: Login):
        entry = USERS.get(data.username)
        if fixed and failures.get(data.username, 0) >= MAX_FAILED_LOGINS:
            raise HTTPException(429, "too many attempts")
        ok = entry is not None and hmac.compare_digest(entry[0], _hash(data.password))
        if not ok:
            failures[data.username] = failures.get(data.username, 0) + 1
            if fixed:
                log.warning("login failed user=%s", data.username)
            else:
                log.warning("login failed user=%s password=%s", data.username, data.password)  # BUG
            raise HTTPException(401, "invalid credentials")
        failures.pop(data.username, None)
        now = int(time.time())
        token = jwt.encode(
            {"sub": data.username, "role": entry[1], "tenant": entry[2],
             "jti": uuid.uuid4().hex, "iat": now, "exp": now + TOKEN_TTL},
            SECRET, algorithm=ALGORITHM)
        return {"access_token": token}

    @app.post("/logout", status_code=204)
    def logout(user: dict = Depends(current_user)):
        if fixed:
            revoked.add(user["jti"])

    @app.get("/notes")
    def list_notes(user: dict = Depends(current_user)):
        if fixed:
            rows = db.execute("SELECT id, body FROM notes WHERE owner=?", (user["sub"],)).fetchall()
        else:  # BUG: every tenant's notes
            rows = db.execute("SELECT id, body FROM notes").fetchall()
        return [{"id": r[0], "body": r[1]} for r in rows]

    @app.post("/notes", status_code=201)
    def create_note(data: dict, user: dict = Depends(current_user)):
        model = NoteInStrict if fixed else NoteIn
        try:
            note = model(**data)
        except Exception:
            raise HTTPException(422, "invalid note")
        cur = db.execute("INSERT INTO notes (owner, tenant, body) VALUES (?,?,?)",
                         (user["sub"], user["tenant"], note.body))
        return {"id": cur.lastrowid, "body": note.body}

    @app.get("/notes/search")
    def search(q: str, user: dict = Depends(current_user)):
        try:
            if fixed:
                rows = db.execute("SELECT id, body FROM notes WHERE owner=? AND body LIKE ?",
                                  (user["sub"], f"%{q}%")).fetchall()
            else:  # BUG: string-built SQL, and the DB error is echoed to the client
                rows = db.execute(
                    f"SELECT id, body FROM notes WHERE body LIKE '%{q}%'").fetchall()
        except sqlite3.Error as exc:
            raise HTTPException(500, f"database error: {exc}")
        return [{"id": r[0], "body": r[1]} for r in rows]

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, user: dict = Depends(current_user)):
        row = db.execute("SELECT id, owner, tenant, body FROM notes WHERE id=?", (note_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "not found")
        # BUG in vulnerable variant: any authenticated user can read any note (IDOR)
        if fixed:
            is_owner = row[1] == user["sub"]
            is_tenant_admin = user.get("role") == "admin" and row[2] == user["tenant"]
            if not (is_owner or is_tenant_admin):
                raise HTTPException(404, "not found")  # 404: do not confirm existence
        return {"id": row[0], "owner": row[1], "body": row[3]}

    @app.delete("/admin/notes/{note_id}", status_code=204)
    def admin_delete(note_id: int, user: dict = Depends(current_user)):
        row = db.execute("SELECT tenant FROM notes WHERE id=?", (note_id,)).fetchone()
        if fixed:  # BUG in vulnerable variant: no role check, no tenant check
            if user.get("role") != "admin":
                raise HTTPException(403, "forbidden")
            if row is None or row[0] != user["tenant"]:
                raise HTTPException(404, "not found")
        if row is None:
            raise HTTPException(404, "not found")
        db.execute("DELETE FROM notes WHERE id=?", (note_id,))

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        if fixed:
            return JSONResponse({"detail": "internal error"}, status_code=500)
        return JSONResponse({"detail": f"{type(exc).__name__}: {exc}"}, status_code=500)

    app.state.fixed = fixed
    return app
