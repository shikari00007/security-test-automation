"""Verifies the Python framework claims in references/language-framework-checklists.md.
Run: python3 -I verify_py_claims.py   (needs Flask, Django, pydantic; synthetic data; no network)"""
import subprocess
import sys

import django
from django.conf import settings

settings.configure(
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
    TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates"}],
    USE_TZ=True,
)
django.setup()

from django.contrib.auth.models import User  # noqa: E402
from django.db import connection  # noqa: E402
from django.template import Context, Template  # noqa: E402
from django.utils.safestring import mark_safe  # noqa: E402
from flask import Flask, render_template_string  # noqa: E402
from jinja2 import DictLoader  # noqa: E402
from pydantic import BaseModel  # noqa: E402

ok = True


def check(label, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + label)
    ok &= bool(cond)


M = "<b id=mark>"

# Flask / Jinja2
app = Flask(__name__)
app.jinja_loader = DictLoader({"a.html": "{{ x }}", "a.txt": "{{ x }}", "s.html": "{{ x|safe }}"})
with app.test_request_context():
    from flask import render_template
    check("Flask: .html template autoescapes", M not in render_template("a.html", x=M))
    check("Flask: render_template_string autoescapes", M not in render_template_string("{{ x }}", x=M))
    check("Flask: .txt template is NOT autoescaped", M in render_template("a.txt", x=M))
    check("Jinja2: |safe disables escaping", M in render_template("s.html", x=M))

# Django templates
check("Django template autoescapes", M not in Template("{{ x }}").render(Context({"x": M})))
check("Django mark_safe disables escaping", M in Template("{{ x }}").render(Context({"x": mark_safe(M)})))

# Django ORM: filter() parameterises; raw() with an f-string does not
with connection.schema_editor() as se:
    se.create_model(User)
User.objects.create(username="alice")
User.objects.create(username="bob")
payload = "x' OR '1'='1"
check("Django ORM filter(): quote in value is data (0 rows)", User.objects.filter(username=payload).count() == 0)
unsafe = list(User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{payload}'"))
check("Django raw() with f-string: quote changes the query (rows leak)", len(unsafe) == 2)
safe = list(User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [payload]))
check("Django raw() with params: 0 rows", len(safe) == 0)


# pydantic (FastAPI request models): unknown fields are ignored by default
class Profile(BaseModel):
    display_name: str


p = Profile.model_validate({"display_name": "a", "is_admin": True})
check("pydantic default ignores unknown field is_admin", not hasattr(p, "is_admin"))


class Bad(BaseModel):
    display_name: str
    is_admin: bool = False


check("pydantic model that DECLARES is_admin accepts it from the client (mass assignment risk)",
      Bad.model_validate({"display_name": "a", "is_admin": True}).is_admin is True)

# subprocess: list argv without shell keeps metacharacters literal
out = subprocess.run(["echo", "a; echo INJECTED"], capture_output=True, text=True).stdout.strip()
check("subprocess list argv, no shell: metacharacters literal", out == "a; echo INJECTED")
sys.exit(0 if ok else 1)
