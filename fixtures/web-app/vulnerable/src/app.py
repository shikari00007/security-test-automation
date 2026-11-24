import hashlib
import os
import random
import subprocess

from flask import Flask, redirect, request, make_response
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["WTF_CSRF_ENABLED"] = False
DEBUG = True
SESSION_COOKIE_HTTPONLY = False


def reset_token():
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return token


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    resp.set_cookie("session_id", reset_token())
    return resp


@app.route("/lookup")
def lookup(cursor):
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM accounts WHERE name = '{name}'")


@app.route("/backup")
def backup():
    target = request.args.get("path")
    os.system(f"tar czf /tmp/backup.tgz {target}")
    subprocess.run("ls " + target, shell=True)


@app.route("/next")
def next_page():
    next_url = request.args.get("next")
    return redirect(next_url)


def store_password(password):
    return hashlib.sha1(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
