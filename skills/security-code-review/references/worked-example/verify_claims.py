"""Executes the three claims made in the worked example against ../worked-example/after.

Run:  python3 -I verify_claims.py      (needs Flask; uses only synthetic data, no network)
Exit status 0 means every claim held. Prints one line per claim.
"""
import importlib.util
import logging
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = """
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT);
CREATE TABLE invoices(id INTEGER PRIMARY KEY, owner_id INTEGER, total_cents INTEGER, note TEXT);
INSERT INTO users VALUES (1,'Alice','alice@example.test'),(2,'Bob','bob@example.test');
INSERT INTO invoices VALUES (10,1,5000,'<script>alert(1)</script>'),(20,2,700,'thanks');
"""


def load_app(src_dir: Path, db_path: Path):
    spec = importlib.util.spec_from_file_location(f"app_{src_dir.name}", src_dir / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # lets Flask locate templates/ next to app.py
    spec.loader.exec_module(mod)
    mod.app.config.update(DATABASE=str(db_path), TESTING=True)
    return mod.app


def fresh_db(tmp: Path, name: str) -> Path:
    p = tmp / name
    con = sqlite3.connect(p)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return p


def login(client, uid):
    with client.session_transaction() as s:
        s["user_id"] = uid


def main() -> int:
    ok = True

    def check(label, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + label)
        ok &= bool(cond)

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        app = load_app(HERE / "after", fresh_db(tmp, "a.db"))
        c = app.test_client()

        # Issue 1 (real): Bob (user 2) reads Alice's invoice 10
        login(c, 2)
        r = c.get("/invoices/10")
        check("issue1 IDOR: user 2 gets 200 on user 1's invoice (vulnerable)", r.status_code == 200)

        # Issue 2 (framework-protected): stored note is HTML-escaped by Jinja2 autoescape
        body = r.get_data(as_text=True)
        check("issue2 XSS: raw <script> absent from response", "<script>" not in body)
        check("issue2 XSS: escaped &lt;script&gt; present", "&lt;script&gt;" in body)

        # Issue 3 (hygiene): the e-mail address lands in the application log
        records = []
        h = logging.Handler()
        h.emit = records.append
        app.logger.addHandler(h)
        app.logger.setLevel(logging.INFO)
        c.get("/invoices/20")
        check("issue3 log: e-mail written to log record", any("bob@example.test" in r.getMessage() for r in records))

        # Fix check: apply the suggested patch to a copy and re-run the denial assertions
        fixed = tmp / "fixed"
        shutil.copytree(HERE / "after", fixed, ignore=shutil.ignore_patterns("tests"))
        src = (fixed / "app.py").read_text()
        src = src.replace(
            '"SELECT id, owner_id, total_cents, note FROM invoices WHERE id = ?", (invoice_id,)',
            '"SELECT id, total_cents, note FROM invoices WHERE id = ? AND owner_id = ?",\n        (invoice_id, user["id"]),',
        ).replace(
            'app.logger.info("invoice %s viewed by %s (%s)", inv["id"], user["name"], user["email"])',
            'app.logger.info("invoice %s viewed by user_id=%s", inv["id"], user["id"])',
        )
        (fixed / "app.py").write_text(src)
        fapp = load_app(fixed, fresh_db(tmp, "f.db"))
        fc = fapp.test_client()
        login(fc, 2)
        check("fix: user 2 gets 404 on user 1's invoice", fc.get("/invoices/10").status_code == 404)
        check("fix: user 2 still gets 200 on own invoice", fc.get("/invoices/20").status_code == 200)
        login(fc, 1)
        check("fix: owner still gets 200", fc.get("/invoices/10").status_code == 200)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
