# Injection-safe data access and commands

Every pair below was executed in a sandbox (see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md)). The unsafe form is shown only so you can recognise it in existing code; the marker used in tests is harmless (extra rows, an echoed word, a parsed attribute name).

Rule that covers all of this: **data goes in a separate channel from structure** (bound parameter, argv element, escaped filter value). Never build structure by concatenating strings, even after "sanitising".

## SQL: bound parameters (Python, stdlib sqlite3 shown; same shape for psycopg/mysqlclient with `%s`)

<!-- case:PY-SQL unsafe -->
```python
def find_user(conn, name):
    return conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
```
<!-- case:PY-SQL safe -->
```python
def find_user(conn, name):
    return conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
```
Why: the driver sends the value out-of-band, so quotes in `name` cannot end the string literal.

## SQL identifiers (ORDER BY, column, table) cannot be bound: allow-list them

<!-- case:PY-IDENT unsafe -->
```python
def list_users(conn, sort):
    return conn.execute(f"SELECT id, name FROM users ORDER BY {sort}").fetchall()
```
<!-- case:PY-IDENT safe -->
```python
SORTABLE = {"id": "id", "name": "name", "newest": "id DESC"}

def list_users(conn, sort):
    order = SORTABLE.get(sort)
    if order is None:
        raise ValueError("unsupported sort key")
    return conn.execute(f"SELECT id, name FROM users ORDER BY {order}").fetchall()
```
Why: the f-string now only ever receives one of your own constants; user input selects a key, never text.

## Django: raw cursor / `raw()` / `extra()` / `RawSQL` take params, not f-strings

<!-- case:PY-DJANGO unsafe -->
```python
from django.db import connection

def find_user(name):
    with connection.cursor() as cur:
        cur.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
        return cur.fetchall()
```
<!-- case:PY-DJANGO safe -->
```python
from django.db import connection

def find_user(name):
    with connection.cursor() as cur:
        cur.execute("SELECT id, name FROM users WHERE name = %s", [name])
        return cur.fetchall()
```
Why: `%s` here is a Django placeholder (not Python formatting); the second argument is bound by the backend. Prefer the ORM (`User.objects.filter(name=name)`); the same params rule applies to `Model.objects.raw(sql, params)`, which was not executed here.

## SQLAlchemy: `text()` with an f-string is raw SQL

<!-- case:PY-SQLA unsafe -->
```python
from sqlalchemy import text

def find_user(conn, name):
    return conn.execute(text(f"SELECT id, name FROM users WHERE name = '{name}'")).fetchall()
```
<!-- case:PY-SQLA safe -->
```python
from sqlalchemy import text

def find_user(conn, name):
    return conn.execute(text("SELECT id, name FROM users WHERE name = :n"), {"n": name}).fetchall()
```
Why: `:n` is a bound parameter; the ORM/Core constructs (`select(User).where(User.name == name)`) bind automatically.

## SQL (JavaScript, Node built-in `node:sqlite` (Node 22.5+, flagged before 22.13); `pg` uses `$1`, `mysql2` uses `?`)

<!-- case:JS-SQL unsafe -->
```js
function findUser(db, name) {
  return db.prepare(`SELECT id, name FROM users WHERE name = '${name}'`).all();
}
```
<!-- case:JS-SQL safe -->
```js
function findUser(db, name) {
  return db.prepare('SELECT id, name FROM users WHERE name = ?').all(name);
}
```
Why: `prepare()` on a template literal is still string building; the value must travel through `.all(...)`. Tagged-template libraries (`sql\`...${x}\``) bind safely only when the tag is the library's own; a plain template literal is not.

## NoSQL operator injection (MongoDB-style): validate types, not just content

JSON bodies can carry objects where you expect strings: `{"password": {"$ne": ""}}` becomes a query operator.

<!-- case:JS-NOSQL unsafe -->
```js
function loginFilter(body) {
  return { user: body.user, password: body.password };
}
```
<!-- case:JS-NOSQL safe -->
```js
function loginFilter(body) {
  if (typeof body.user !== 'string' || typeof body.password !== 'string') {
    throw new Error('invalid credentials shape');
  }
  return { user: body.user, password: body.password };
}
```
Why: operators only exist as objects; forcing primitives removes them. Better still, look up by `user` only and compare a password hash in code. Also never pass user text to `$where`, `$function` or `mapReduce`. Verified: the filter objects built here; not executed against a live MongoDB.

## LDAP filter values: escape per RFC 4515 (Python `ldap3`)

<!-- case:PY-LDAP unsafe -->
```python
def user_filter(uid):
    return f"(&(objectClass=person)(uid={uid})(active=TRUE))"
```
<!-- case:PY-LDAP safe -->
```python
from ldap3.utils.conv import escape_filter_chars

def user_filter(uid):
    return f"(&(objectClass=person)(uid={escape_filter_chars(uid)})(active=TRUE))"
```
Why: `*`, `(`, `)`, `\` and NUL in the value become `\2a \28 \29 \5c \00`, so they cannot add filter terms. DN components need a different escape (RFC 4514). Verified at string level only, no directory server.

## OS commands: no shell, argv list, `--` before user values

<!-- case:PY-CMD unsafe -->
```python
import subprocess

def list_path(name):
    return subprocess.run(f"ls {name}", shell=True, capture_output=True, text=True).stdout
```
<!-- case:PY-CMD safe -->
```python
import subprocess

def list_path(name):
    return subprocess.run(["ls", "--", name], capture_output=True, text=True, timeout=10).stdout
```
Why: with an argv list there is no shell to interpret `;`, `&&`, `$()` or backticks, and `--` stops a value like `--version` being read as an option.

Option injection even without a shell:

<!-- case:PY-CMDOPT unsafe -->
```python
import subprocess

def list_path(name):
    return subprocess.run(["ls", name], capture_output=True, text=True).stdout
```
<!-- case:PY-CMDOPT safe -->
```python
import subprocess

def list_path(name):
    if name.startswith("-"):
        raise ValueError("path must not start with '-'")
    return subprocess.run(["ls", "--", name], capture_output=True, text=True, timeout=10).stdout
```
Why: argv lists stop shell injection but not flag injection; `--` plus a leading-dash check handles it. Not every tool honours `--`; check its manual or use absolute paths.

<!-- case:JS-EXEC unsafe -->
```js
const { execSync } = require('node:child_process');

function listPath(name) {
  return execSync(`ls ${name}`, { encoding: 'utf8', stdio: 'pipe' });
}
```
<!-- case:JS-EXEC safe -->
```js
const { execFileSync } = require('node:child_process');

function listPath(name) {
  return execFileSync('ls', ['--', name], { encoding: 'utf8', stdio: 'pipe', timeout: 10000 });
}
```
Why: `exec`/`execSync` spawn a shell; `execFile*` and `spawn` with `shell: false` (default) pass argv directly.

If you truly need a shell pipeline, keep the constant script fixed and pass values as positional arguments (`["sh", "-c", 'wc -c < "$1"', "sh", name]`), never inside the script text. Prefer a library call (zipfile, Pillow, `fs`) over shelling out at all.

## Dynamic code and templates built from user text

Never `eval`/`exec`/`new Function` user input (ASVS 5.0.0 V1.3.2) and never build a template from it (V1.3.7). See the Jinja2 pair in [input-validation-and-output-encoding.md](input-validation-and-output-encoding.md).
