# Files, paths, uploads, limits and check-then-act races

All pairs executed in a temp directory; see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md).

## Path traversal: resolve, then confirm containment

<!-- case:PY-PATH unsafe -->
```python
from pathlib import Path

def read_upload(root, name):
    return (Path(root) / name).read_text()
```
<!-- case:PY-PATH safe -->
```python
from pathlib import Path

def read_upload(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise PermissionError("path escapes upload root")
    return target.read_text()
```
Why: `..` segments, an absolute `name` (which silently replaces `root` in `Path` joins) and symlinks inside `root` all leave the directory; `resolve()` follows them and `is_relative_to` (Python 3.9+) compares the real location. Do not use `str.startswith(root)` (it accepts `/data/uploads-evil`).

<!-- case:JS-PATH unsafe -->
```js
const path = require('node:path');
const fs = require('node:fs');

function readUpload(root, name) {
  return fs.readFileSync(path.join(root, name), 'utf8');
}
```
<!-- case:JS-PATH safe -->
```js
const path = require('node:path');
const fs = require('node:fs');

function readUpload(root, name) {
  const base = fs.realpathSync(root);
  const real = fs.realpathSync(path.resolve(base, name));
  if (real !== base && !real.startsWith(base + path.sep)) {
    throw new Error('path escapes upload root');
  }
  return fs.readFileSync(real, 'utf8');
}
```
Why: `realpathSync` resolves symlinks; the `base + path.sep` prefix test avoids the sibling-directory prefix trap. In Express, `res.sendFile(name, { root })` with a fixed `root` rejects `..` traversal; still validate the name.

Best of all: do not use user-supplied names for paths. Store files under a generated id and keep the original name as metadata (ASVS 5.0.0 V5.3.2).

## Uploads: allow-list type, check content, cap size, generate the name

<!-- case:PY-UPLOAD unsafe -->
```python
from pathlib import Path

def save_upload(root, client_name, data):
    dest = Path(root) / client_name
    dest.write_bytes(data)
    return dest
```
<!-- case:PY-UPLOAD safe -->
```python
import uuid
from pathlib import Path

MAGIC = {".png": b"\x89PNG\r\n\x1a\n", ".pdf": b"%PDF-"}
MAX_BYTES = 1_000_000

def save_upload(root, client_name, data):
    ext = Path(client_name).suffix.lower()
    if ext not in MAGIC:
        raise ValueError("file type not allowed")
    if len(data) > MAX_BYTES:
        raise ValueError("file too large")
    if not data.startswith(MAGIC[ext]):
        raise ValueError("content does not match extension")
    dest = Path(root).resolve() / (uuid.uuid4().hex + ext)
    with open(dest, "xb") as fh:  # "x": never overwrite an existing file
        fh.write(data)
    return dest
```
Why: the stored name is yours (no traversal, no overwrite, no `.php`/`.html` execution surface), the type is an allow-list, and size is bounded (ASVS 5.0.0 V5.2.1, V5.2.2, V5.3.2). Check size while streaming in real frameworks (below), not after reading everything into memory. Store outside the web root, serve with a fixed `Content-Type` and `Content-Disposition: attachment`, and virus-scan if you serve files to other users. Archives need extra care (zip slip, decompression bombs, symlinks: V5.2.3, V5.2.5, V5.3.3) and were not verified here.

## Request and body size limits

<!-- case:PY-LIMIT unsafe -->
```python
from flask import Flask, request

def make_app():
    app = Flask(__name__)

    @app.post("/upload")
    def upload():
        return {"bytes": len(request.get_data())}

    return app
```
<!-- case:PY-LIMIT safe -->
```python
from flask import Flask, request

def make_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000

    @app.post("/upload")
    def upload():
        return {"bytes": len(request.get_data())}

    return app
```
Why: Flask answers 413 for bodies over `MAX_CONTENT_LENGTH` instead of buffering them. Equivalents: Express `express.json({ limit: '100kb' })`, Django `DATA_UPLOAD_MAX_MEMORY_SIZE` / `FILE_UPLOAD_MAX_MEMORY_SIZE` (setting names exist in Django 4.2; limits not executed), and proxy-level `client_max_body_size`. Also bound page sizes, array lengths and recursion depth in schemas (`max_length`, `.max()`), and check integer ranges before arithmetic or allocation (ASVS 5.0.0 V1.4.2).

## Check-then-act races (time of check / time of use)

A check and the action it protects must be one atomic operation (ASVS 5.0.0 V15.4.2).

### File creation

<!-- case:PY-TOCTOU-FILE unsafe -->
```python
import os
from pathlib import Path

def create_report(path, data):
    if os.path.exists(path):
        raise FileExistsError(path)
    Path(path).write_text(data)
```
<!-- case:PY-TOCTOU-FILE safe -->
```python
import os

def create_report(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)  # raises FileExistsError atomically
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
```
Why: between `exists()` and `write_text()` another process can plant a symlink at `path`, and the write then follows it. `O_EXCL|O_NOFOLLOW` makes check and create one kernel operation. Use `tempfile.mkstemp`/`NamedTemporaryFile` for temp files; never invent predictable names in `/tmp`. (`O_NOFOLLOW` is POSIX; Windows differs.)

### Balances, quotas, stock, one-time tokens

<!-- case:PY-TOCTOU-DB unsafe -->
```python
def withdraw(conn, acct, amount):
    (bal,) = conn.execute("SELECT balance FROM accounts WHERE id = ?", (acct,)).fetchone()
    if bal < amount:
        return False
    conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (bal - amount, acct))
    return True
```
<!-- case:PY-TOCTOU-DB safe -->
```python
def withdraw(conn, acct, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")  # a negative amount would add money (ASVS 5.0.0 V2.2.1)
    cur = conn.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
        (amount, acct, amount),
    )
    return cur.rowcount == 1
```
Why: read-modify-write lets two concurrent requests both see enough balance; a single conditional UPDATE lets the database serialise them. The same idea: `INSERT ... ON CONFLICT`, unique constraints for "only once", `SELECT ... FOR UPDATE`, optimistic version columns. The test interleaves the second request deterministically between the read and the write.
