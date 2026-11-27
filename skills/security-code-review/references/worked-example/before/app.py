"""Tiny invoice service (synthetic). 'before' = main branch."""
import sqlite3

from flask import Flask, abort, g, render_template, session

app = Flask(__name__)
app.config["SECRET_KEY"] = "test-only-not-a-real-secret"  # synthetic; real apps load from env


def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config.get("DATABASE", ":memory:"))
        g.db.row_factory = sqlite3.Row
    return g.db


def current_user():
    uid = session.get("user_id")
    if uid is None:
        abort(401)
    row = db().execute("SELECT id, name, email FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        abort(401)
    return row


@app.get("/invoices")
def list_invoices():
    user = current_user()
    rows = db().execute(
        "SELECT id, total_cents FROM invoices WHERE owner_id = ?", (user["id"],)
    ).fetchall()
    return {"invoices": [dict(r) for r in rows]}
