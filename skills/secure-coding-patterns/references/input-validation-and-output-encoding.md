# Input validation and output encoding

Two separate jobs. **Validate** at the trust boundary (reject what is not expected, once, on the server). **Encode** at the sink (escape for the exact context the data lands in). Validation never replaces encoding: a valid name like `O'Brien <b>` is still dangerous in HTML.

All pairs were executed; see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md).

## Validate at the boundary with a schema (allow-list, reject unknown fields)

### Python: pydantic v2 (verified on 2.12)

<!-- case:PY-PYD unsafe -->
```python
def parse_order(data: dict):
    return {"sku": data["sku"], "qty": int(data["qty"]), "is_admin": data.get("is_admin", False)}
```
<!-- case:PY-PYD safe -->
```python
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Order(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sku: str = Field(pattern=r"^[A-Z0-9-]{3,20}$")
    qty: int = Field(gt=0, le=1000)
    gift_wrap: Literal["none", "basic"] = "none"

def parse_order(data: dict):
    return Order.model_validate(data).model_dump()
```
Why: unknown fields (mass assignment such as `is_admin`), negative or absurd quantities and malformed SKUs are rejected with `ValidationError`; the caller gets typed data only.

### FastAPI: a typed body is the validation layer (verified on 0.118)

<!-- case:PY-FASTAPI unsafe -->
```python
from fastapi import FastAPI

def make_app():
    app = FastAPI()

    @app.post("/orders")
    def create(body: dict):
        return {"saved": body}

    return app
```
<!-- case:PY-FASTAPI safe -->
```python
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

class OrderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sku: str = Field(pattern=r"^[A-Z0-9-]{3,20}$")
    qty: int = Field(gt=0, le=1000)

def make_app():
    app = FastAPI()

    @app.post("/orders")
    def create(body: OrderIn):
        return {"saved": body.model_dump()}

    return app
```
Why: `body: dict` accepts anything; a pydantic model returns HTTP 422 for unknown, missing or out-of-range fields before your code runs. Return a separate response model so DB-only fields never leak (ASVS 5.0.0 V15.3.1).

### TypeScript / Express / Next: zod (verified on 4.6)

<!-- case:JS-ZOD unsafe -->
```js
function parseOrder(body) {
  return { sku: body.sku, qty: Number(body.qty), isAdmin: body.isAdmin };
}
```
<!-- case:JS-ZOD safe -->
```js
const { z } = require('zod');

const Order = z.strictObject({
  sku: z.string().regex(/^[A-Z0-9-]{3,20}$/),
  qty: z.number().int().positive().max(1000),
});

function parseOrder(body) {
  return Order.parse(body); // throws ZodError on unknown keys, wrong types, out-of-range
}
```
Why: `strictObject` rejects unknown keys; `.parse` throws, so unvalidated data cannot flow on. Use `.safeParse` and return a 400 in request handlers. In Next.js, call the same schema at the top of every route handler and Server Action: Server Actions are reachable by direct POST, so validate and authorise inside each one (Next.js data-security guide, last updated 2026-11-18).

Client-side validation is UX only (ASVS 5.0.0 V2.2.2). Validate type, length, range and format; for relationships between fields (start before end) check them too (V2.2.3).

## Output encoding by context

| Context | Encode with | Never |
|---|---|---|
| HTML text | `html.escape` / template autoescape / `textContent` | string concatenation, `|safe`, `innerHTML` |
| HTML attribute | autoescape or `html.escape(v, quote=True)`, and always quote the attribute | unquoted attributes |
| JS / JSON in a `<script>` | `json.dumps` plus `<` escaped as `\u003c`; better: JSON in a `data-` attribute or a JSON endpoint | f-string into script text |
| URL path/query | `urllib.parse.quote` / `urlencode`, `encodeURIComponent`, `URLSearchParams` | concatenating `&k=v` |
| URL as href/src | allow-list scheme (`http`, `https`, relative) | `javascript:` / `data:` |
| CSS, HTTP header | avoid user data; strip CR/LF | raw interpolation |

### HTML body

<!-- case:PY-HTML unsafe -->
```python
def greeting(name):
    return f"<p>Hello {name}</p>"
```
<!-- case:PY-HTML safe -->
```python
import html

def greeting(name):
    return f"<p>Hello {html.escape(name)}</p>"
```
Why: `<`, `>`, `&`, quotes become entities, so the browser renders text instead of parsing a tag. (Prefer a template engine with autoescape over hand-built HTML.)

### HTML attribute

<!-- case:PY-ATTR unsafe -->
```python
def search_box(value):
    return f'<input name="q" value="{value}">'
```
<!-- case:PY-ATTR safe -->
```python
import html

def search_box(value):
    return f'<input name="q" value="{html.escape(value, quote=True)}">'
```
Why: an unescaped `"` closes the attribute and lets the input add its own attributes (such as an event handler).

### JavaScript data inside a page

<!-- case:PY-JSCTX unsafe -->
```python
import json

def bootstrap(query):
    return f"<script>var q = {json.dumps(query)};</script>"
```
<!-- case:PY-JSCTX safe -->
```python
import json

def bootstrap(query):
    data = json.dumps(query).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f"<script>var q = {data};</script>"
```
Why: `json.dumps` alone leaves `</script>` intact, which ends the script block early; the `\u003c` form is identical JavaScript but inert HTML (ASVS 5.0.0 V1.2.3).

<!-- case:JS-SCRIPTJSON unsafe -->
```js
function bootstrap(query) {
  return `<script>var q = ${JSON.stringify(query)};</script>`;
}
```
<!-- case:JS-SCRIPTJSON safe -->
```js
function bootstrap(query) {
  const data = JSON.stringify(query).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
  return `<script>var q = ${data};</script>`;
}
```
Why: same reason. React/Next escape text children automatically; the danger is `dangerouslySetInnerHTML`, `innerHTML`, and hand-built `<script>` strings.

### HTML in JavaScript (Express, Next, plain DOM)

<!-- case:JS-HTML unsafe -->
```js
function greeting(name) {
  return `<p>Hello ${name}</p>`;
}
```
<!-- case:JS-HTML safe -->
```js
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ESC[c]);
}

function greeting(name) {
  return `<p>Hello ${escapeHtml(name)}</p>`;
}
```
Why: same entity encoding. In the browser prefer `el.textContent = name` over `innerHTML` (ASVS 5.0.0 V3.2.2); if you must render user HTML (rich text), sanitise with a maintained library (DOMPurify on the client, `nh3`/`bleach`-style on the server), not a regex (V1.3.1).

### URLs: build with encoders, link only safe schemes

<!-- case:PY-URLQ unsafe -->
```python
def search_url(q):
    return f"/search?q={q}"
```
<!-- case:PY-URLQ safe -->
```python
from urllib.parse import urlencode

def search_url(q):
    return "/search?" + urlencode({"q": q})
```
Why: raw `&admin=1` in `q` otherwise becomes a second parameter (parameter injection).

<!-- case:PY-HREF unsafe -->
```python
def link(url, label):
    return f'<a href="{url}">{label}</a>'
```
<!-- case:PY-HREF safe -->
```python
import html
from urllib.parse import urlsplit

def safe_href(url):
    parts = urlsplit(url.strip())
    return url if parts.scheme in ("http", "https", "") else "#"

def link(url, label):
    return f'<a href="{html.escape(safe_href(url), quote=True)}">{html.escape(label)}</a>'
```
Why: HTML-escaping does not neutralise a `javascript:` URL; only a scheme allow-list does (ASVS 5.0.0 V1.2.2). Browsers ignore leading control characters in schemes, so strip them or reject any URL containing control characters in production.

<!-- case:JS-URL unsafe -->
```js
function searchUrl(q) {
  return `/search?q=${q}`;
}
```
<!-- case:JS-URL safe -->
```js
function searchUrl(q) {
  return '/search?' + new URLSearchParams({ q }).toString();
}
```
Why: `URLSearchParams` percent-encodes `&`, `=`, `#`.

## Templates

<!-- case:PY-SSTI unsafe -->
```python
from jinja2 import Template

def render_greeting(name):
    return Template("Hello " + name).render()
```
<!-- case:PY-SSTI safe -->
```python
from jinja2 import Template

def render_greeting(name):
    return Template("Hello {{ name }}").render(name=name)
```
Why: user text must be a template *variable*, never part of the template source (server-side template injection; ASVS 5.0.0 V1.3.7). The test marker is `{{ 7*7 }}` rendering as `49`.

<!-- case:PY-JINJA unsafe -->
```python
from jinja2 import Environment

env = Environment()  # autoescape is OFF by default in plain Jinja2

def render_card(name):
    return env.from_string("<p>{{ name }}</p>").render(name=name)
```
<!-- case:PY-JINJA safe -->
```python
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(default=True))

def render_card(name):
    return env.from_string("<p>{{ name }}</p>").render(name=name)
```
Why: a bare `jinja2.Environment` does not escape. Flask's `render_template` autoescapes `.html` templates; the risk appears with your own Environment, `render_template_string` with `|safe`, or `Markup(user_text)`.

<!-- case:PY-DJTPL unsafe -->
```python
from django.template import Context, Engine
from django.utils.safestring import mark_safe

def render_bio(bio):
    return Engine().from_string("<div>{{ bio }}</div>").render(Context({"bio": mark_safe(bio)}))
```
<!-- case:PY-DJTPL safe -->
```python
from django.template import Context, Engine

def render_bio(bio):
    return Engine().from_string("<div>{{ bio }}</div>").render(Context({"bio": bio}))
```
Why: Django autoescapes by default; `mark_safe`, `|safe` and `{% autoescape off %}` opt out, so grep for them in review.
