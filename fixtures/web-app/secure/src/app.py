import os
import secrets
import subprocess

import bcrypt
from flask import Flask, redirect, request, make_response
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
DEBUG = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
SAFE_PAGES = {"home": "/", "profile": "/profile"}


def reset_token():
    return secrets.token_urlsafe(32)


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    resp.set_cookie("session_id", reset_token(), httponly=True, secure=True, samesite="Lax")
    return resp


@app.route("/lookup")
def lookup(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM accounts WHERE name = %s", (name,))


@app.route("/backup")
def backup():
    target = request.args.get("path")
    subprocess.run(["tar", "czf", "/tmp/backup.tgz", target], check=True)


@app.route("/next")
def next_page():
    page = request.args.get("next")
    return redirect(SAFE_PAGES.get(page, "/"))


def store_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


if __name__ == "__main__":
    app.run(debug=os.environ.get("APP_DEBUG") == "1")
