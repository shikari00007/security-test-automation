# Outbound requests, parsers and redirects

All pairs executed against local servers (127.0.0.1 / 127.0.0.2 on an ephemeral port) or in-process; nothing leaves the machine. See [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md).

## SSRF-safe outbound requests

When the server fetches a URL that a user influences (webhook, image import, link preview, "fetch from URL"), the attacker's target is your internal network and cloud metadata (for example `169.254.169.254`). Layers, in order of strength:

1. **Do not fetch user URLs.** Let the user pick from a server-side list (provider key -> fixed base URL).
2. **Allow-list** scheme, host and port (ASVS 5.0.0 V1.3.6). A deny-list of "bad IPs" alone is not enough: decimal, octal, IPv6 and DNS-name forms of the same address exist.
3. **Resolve once, validate every resolved address is public, connect to that address** (closes DNS rebinding: a name that answers "public" to your check and "127.0.0.1" to the connection).
4. **Do not follow redirects** automatically (V15.3.2); if you must, re-run steps 2-3 on every hop.
5. Timeouts and response size cap; network egress policy as defence in depth (not verified here).

### Python

<!-- case:PY-SSRF unsafe -->
```python
import urllib.request

def fetch_url(url):
    return urllib.request.urlopen(url, timeout=3).read()
```
<!-- case:PY-SSRF weak -->
```python
import socket
import urllib.request
from urllib.parse import urlsplit
import ipaddress

def is_public_ip(ip):
    return ipaddress.ip_address(ip).is_global

def fetch_url(url):
    host = urlsplit(url).hostname
    if not is_public_ip(socket.gethostbyname(host)):   # check ...
        raise ValueError("non-public destination")
    return urllib.request.urlopen(url, timeout=3).read()  # ... then resolve AGAIN
```
<!-- case:PY-SSRF safe -->
```python
import http.client
import ipaddress
import socket
from urllib.parse import urlsplit

def is_public_ip(ip):
    return ipaddress.ip_address(ip).is_global

def fetch_allowed(url, allowed_hosts, allowed_ports=frozenset({80}), is_public=is_public_ip):
    u = urlsplit(url)
    if u.scheme != "http" or u.hostname not in allowed_hosts:
        raise ValueError("destination not allowed")
    port = u.port or 80
    if port not in allowed_ports:
        raise ValueError("port not allowed")
    infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    ips = [i[4][0] for i in infos]
    if not ips or not all(is_public(ip) for ip in ips):
        raise ValueError("destination resolves to a non-public address")
    conn = http.client.HTTPConnection(ips[0], port, timeout=3)  # pinned: no second lookup
    conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""), headers={"Host": u.netloc})
    resp = conn.getresponse()                                    # http.client never follows redirects
    return resp.status, resp.read(1_000_000)
```
Why: the first version reaches anything (internal services, redirects, `file:` URLs); the "weak" one validates one resolution and fetches with another, so a rebinding DNS answer wins; the safe one allow-lists the host and port, validates all addresses, connects to the validated address and does not follow redirects. `is_public` is a parameter only so tests can point at loopback; keep the default in production.

Limit: the safe snippet is HTTP-only. For HTTPS you must still connect to the pinned address but verify the certificate against the original hostname (custom connection with `server_hostname=`, or a vetted library hook, or an egress proxy that enforces the policy). That path was **not executed** here.

`ipaddress.ip_address(x).is_global` was checked to be false for loopback, link-local (metadata), RFC 1918, IPv6 loopback and IPv4-mapped loopback on Python 3.14; behaviour for mapped addresses varies by Python version, so re-test on yours.

### JavaScript / TypeScript (undici `Agent` with a guarded `lookup`; verified on undici 8.x, Node 24)

Runtime: undici 8 declares `engines: node >=22.19.0`. On older Node pin an older undici and re-run the SSRF test.

<!-- case:JS-SSRF unsafe -->
```js
async function fetchUrl(url) {
  const res = await fetch(url);           // follows redirects, any host
  return res.text();
}
```
<!-- case:JS-SSRF safe -->
```js
const dns = require('node:dns');
const net = require('node:net');
const { Agent, fetch } = require('undici');

function isPublicIp(ip) {
  let v = ip.toLowerCase();
  if (v.startsWith('::ffff:') && net.isIPv4(v.slice(7))) v = v.slice(7);
  if (net.isIPv4(v)) {
    const [a, b] = v.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)));
  }
  return net.isIPv6(v) && /^[23]/.test(v); // global unicast 2000::/3 only
}

function guardedLookup(isPublic) {
  return (hostname, options, cb) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
      if (err) return cb(err);
      if (!addrs.length || !addrs.every((a) => isPublic(a.address))) {
        return cb(new Error('destination resolves to a non-public address'));
      }
      return options.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

async function fetchAllowed(url, allowedHosts, { isPublic = isPublicIp, allowedPorts = new Set(['80', '443']) } = {}) {
  const u = new URL(url);
  if (!['http:', 'https:'].includes(u.protocol) || !allowedHosts.has(u.hostname)) {
    throw new Error('destination not allowed');
  }
  if (!allowedPorts.has(u.port || (u.protocol === 'https:' ? '443' : '80'))) throw new Error('port not allowed');
  const bare = u.hostname.replace(/^\[|\]$/g, ''); // WHATWG URL keeps the brackets on IPv6 literals
  if (net.isIP(bare) && !isPublic(bare)) throw new Error('non-public destination');
  const dispatcher = new Agent({ connect: { lookup: guardedLookup(isPublic) } });
  const res = await fetch(u, { dispatcher, redirect: 'manual', signal: AbortSignal.timeout(3000) });
  return { status: res.status, body: (await res.text()).slice(0, 1_000_000) };
}
```
Why: the address that is validated is the address the socket uses (validation happens inside the connection's own `lookup`), `redirect: 'manual'` returns the 3xx to you instead of following it, and the allow-list is checked first. The port is allow-listed too (default 80/443): an allow-listed host otherwise exposes every port on it. WHATWG `URL.hostname` keeps the brackets of IPv6 literals (`[::ffff:7f00:1]`), so they are stripped before `net.isIP` and the public check; without that the literal check is silently skipped. Plain `fetch(url)` in Node, `axios` and `got` all follow redirects by default unless told otherwise. `isPublic` is injectable only for tests.

## Deserialization: use data formats, not object formats

<!-- case:PY-PICKLE unsafe -->
```python
import pickle

def load_blob(blob):
    return pickle.loads(blob)
```
<!-- case:PY-PICKLE safe -->
```python
import json

def load_blob(blob):
    data = json.loads(blob)
    if not isinstance(data, dict):
        raise ValueError("expected an object")
    return data   # then validate with a pydantic model / schema
```
Why: unpickling calls attacker-chosen callables (the test uses harmless `len`); JSON can only produce data. Never unpickle (or `marshal`, `shelve`, `dill`, `torch.load` without `weights_only=True`) data that crosses a trust boundary, and do not "sign" pickles as a fix unless the key is truly private (ASVS 5.0.0 V1.5.2).

<!-- case:PY-YAML unsafe -->
```python
import yaml

def load_config(text):
    return yaml.load(text, Loader=yaml.Loader)
```
<!-- case:PY-YAML safe -->
```python
import yaml

def load_config(text):
    return yaml.safe_load(text)
```
Why: the full loader constructs arbitrary Python objects (`!!python/object/apply:...`); `safe_load` builds plain types only and raises `ConstructorError` otherwise. Checked on PyYAML 6.0.2.

JavaScript: `JSON.parse` is data-only. Avoid `eval`, `new Function`, `node-serialize`-style libraries and `vm` for untrusted input. After `JSON.parse`, beware prototype pollution when merging:

<!-- case:JS-PROTO unsafe -->
```js
function merge(target, src) {
  for (const key of Object.keys(src)) {
    if (src[key] && typeof src[key] === 'object') {
      target[key] = target[key] || {};
      merge(target[key], src[key]);
    } else {
      target[key] = src[key];
    }
  }
  return target;
}
```
<!-- case:JS-PROTO safe -->
```js
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);

function merge(target, src) {
  for (const key of Object.keys(src)) {
    if (BLOCKED.has(key)) continue;
    if (src[key] && typeof src[key] === 'object') {
      if (!Object.hasOwn(target, key)) target[key] = {};
      merge(target[key], src[key]);
    } else {
      target[key] = src[key];
    }
  }
  return target;
}
```
Why: `JSON.parse('{"__proto__":{"x":1}}')` creates an own key named `__proto__`; the unsafe merge walks into `Object.prototype` and adds a property to every object. Better: validate with a strict schema (zod `strictObject`) or use `Map`/`Object.create(null)` for dictionaries (ASVS 5.0.0 V15.3.6).

## XML: disable DTDs and entities

<!-- case:PY-XXE unsafe -->
```python
from lxml import etree

def parse_xml(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    return etree.fromstring(xml_bytes, parser)
```
<!-- case:PY-XXE safe -->
```python
from defusedxml import ElementTree

def parse_xml(xml_bytes):
    return ElementTree.fromstring(xml_bytes)  # raises on DTD entities (EntitiesForbidden)
```
<!-- case:PY-XXE safe2 -->
```python
from lxml import etree

def parse_xml(xml_bytes):
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True, huge_tree=False)
    return etree.fromstring(xml_bytes, parser)
```
Why: an external entity such as `<!ENTITY x SYSTEM "file:///...">` makes the parser read local files or URLs (ASVS 5.0.0 V1.5.1). The test reads a marker file created in a temp directory. Prefer `defusedxml` (verified 0.7.1); if you need lxml, turn entity resolution, DTD loading and network access off. SOAP/SAML/SVG/OOXML parsers are XML parsers too. JavaScript XML libraries were **not** verified here; check each library's entity/DTD options before use.

## Redirects: only to your own pages

ASVS 5.0.0 V3.7.2 requires automatic redirects to a different hostname to be on an allow-list (V3.7.3: notify the user and offer to cancel; V10.4.1 covers OAuth redirect URIs); the weakness is CWE-601. Rule: redirect targets are relative paths you validate, or keys that map to fixed URLs.

<!-- case:PY-REDIR unsafe -->
```python
from flask import Flask, redirect, request

def make_app():
    app = Flask(__name__)

    @app.get("/done")
    def done():
        return redirect(request.args.get("next", "/"))

    return app
```
<!-- case:PY-REDIR weak -->
```python
from flask import Flask, redirect, request

def make_app():
    app = Flask(__name__)

    @app.get("/done")
    def done():
        nxt = request.args.get("next", "/")
        return redirect(nxt if nxt.startswith("/") else "/")   # accepts //evil.example

    return app
```
<!-- case:PY-REDIR safe -->
```python
from urllib.parse import urlsplit
from flask import Flask, redirect, request

def safe_next(target, default="/"):
    if not target or "\\" in target or any(c in target for c in "\r\n\t"):
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return default
    return target

def make_app():
    app = Flask(__name__)

    @app.get("/done")
    def done():
        return redirect(safe_next(request.args.get("next")))

    return app
```
Why: `//evil.example` starts with `/` but browsers treat it as another host (checked: the weak version redirects there). `/\evil.example` is read the same way by browsers; Werkzeug happened to percent-encode that backslash in `Location`, but do not rely on the framework: the safe version rejects backslashes and accepts only single-slash local paths.

<!-- case:JS-REDIR weak -->
```js
function safeNext(target) {
  return typeof target === 'string' && target.startsWith('/') ? target : '/';
}
```
<!-- case:JS-REDIR safe -->
```js
function safeNext(target, base = 'https://app.test') {
  if (typeof target !== 'string' || /[\\\r\n\t]/.test(target)) return '/';
  let url;
  try {
    url = new URL(target, base);
  } catch {
    return '/';
  }
  return url.origin === new URL(base).origin && target.startsWith('/') && !target.startsWith('//')
    ? url.pathname + url.search + url.hash
    : '/';
}
```
Why: resolve with the WHATWG `URL` parser (the one browsers use) and compare origins, instead of pattern-matching strings. For redirects to other sites, map an id to a fixed URL.
