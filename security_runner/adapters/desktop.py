"""Desktop / thick-client static rules (SEC-DSK-001..005)."""
from __future__ import annotations

import re

import json

from .android import rule, _scan, strip_c, strip_hash, strip_xml_comments, blank_strings, is_test_path
from .base import Observation, RuleResult, ScanContext

_JS_GLOBS = ("*.js", "*.mjs", "*.cjs", "*.ts")


def _js_files(ctx: ScanContext) -> list[str]:
    return [f for f in ctx.match(*_JS_GLOBS)
            if "node_modules/" not in f and not f.endswith(".min.js") and not f.endswith(".d.ts")
            and not is_test_path(f) and not re.search(r"\.(?:spec|test)\.[cm]?[jt]s$", f)]


def _blank_js_strings(code: str) -> str:
    """Blank single-line JS string literals unless they are used as an object key ('k': v)."""
    return re.sub(r"""(["'`])(?:\\.|(?!\1)[^\\\n])*\1(?!\s*:)""",
                  lambda m: m.group(1) + " " * (len(m.group(0)) - 2) + m.group(1), code)


def _electron_files(ctx: ScanContext) -> list[str]:
    out = []
    for rel in _js_files(ctx):
        if re.search(r"""require\(\s*['"]electron['"]\s*\)|from\s+['"]electron['"]|\bwebPreferences\b""",
                     ctx.read(rel)):
            out.append(rel)
    return out


_WP = re.compile(r"""\b(nodeIntegration(?:InWorker|InSubFrames)?['"]?\s*:\s*true\b|contextIsolation['"]?\s*:\s*false\b"""
                 r"""|sandbox['"]?\s*:\s*false\b|webSecurity['"]?\s*:\s*false\b)""")


@rule("SEC-DSK-001")
def electron_prefs(ctx: ScanContext):
    files = _electron_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        for i, ln in enumerate(_blank_js_strings(strip_c(ctx.read(rel))).splitlines(), 1):
            m = _WP.search(ln)
            if m:
                pref = re.sub(r"['\"\s]+", " ", m.group(1)).replace(" :", ":")
                obs.append(Observation(rel, i, "insecure Electron webPreference: " + pref))
    return RuleResult(obs)


_VALIDATION = re.compile(
    r"new URL\(|allow(?:ed)?_?list|ALLOWED|isAllowed|isSafe|safeUrl|validate\w*\(|\.startsWith\(\s*['\"]https:"
    r"|\b\w*(?:URL|Url)\w*(?:REG|Reg|RE|Regex|REGEX|Pattern)\w*\.test\("
    r"|\^https\??:|protocol\s*[!=]==?\s*['\"]https?:", re.I)
_OPEN_EXT = re.compile(r"\bshell\.openExternal\s*\(\s*([^)]*)\)")
_LOAD_URL = re.compile(r"\.loadURL\s*\(\s*([^)]*)\)")


def _constant_arg(arg: str, code: str) -> bool:
    """True when the argument is a fixed literal, an ALL_CAPS constant or a variable bound to a literal."""
    if re.match(r"""^(['"`])(?:(?!\1)[^\\$]|\\.)*\1$""", arg) and "${" not in arg:
        return True
    if re.match(r"^[A-Z][A-Z0-9_]+$", arg):
        return True
    if re.match(r"^[A-Za-z_]\w*$", arg):
        for m in re.finditer(rf"""\b(?:const|let|var)\s+{re.escape(arg)}\s*=\s*(['"`])((?:(?!\1).)*)\1\s*[;,]?\s*$""",
                             code, re.M):
            if "${" not in m.group(2):
                return True
    return False


@rule("SEC-DSK-002")
def open_external(ctx: ScanContext):
    files = _electron_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        code = strip_c(ctx.read(rel))
        validated = bool(_VALIDATION.search(code))
        for i, ln in enumerate(code.splitlines(), 1):
            m = _OPEN_EXT.search(ln)
            if m:
                arg = m.group(1).strip()
                if not re.match(r"""['"`]https://""", arg) and not validated and not _constant_arg(arg, code):
                    obs.append(Observation(rel, i, "shell.openExternal called with unvalidated input"))
                continue
            m = _LOAD_URL.search(ln)
            if m:
                arg = m.group(1).strip()
                if re.match(r"""['"`]http://(?!localhost|127\.0\.0\.1)""", arg):
                    obs.append(Observation(rel, i, "loadURL over plaintext HTTP"))
                elif re.match(r"^[A-Za-z_][\w.\[\]]*$", arg) and not validated and not _constant_arg(arg, code):
                    obs.append(Observation(rel, i, "loadURL called with unvalidated variable"))
    return RuleResult(obs)


_SIG_OFF = re.compile(r"verifyUpdateCodeSignature\s*[:=]\s*false|(?:disable|skip)SignatureVerification\s*[:=]\s*true"
                      r"|verifySignature\s*[:=]\s*false", re.I)
_HTTP_FEED = re.compile(r"""(?:url|feed|server)\w*["']?\s*[:=(,]\s*["'`]?http://(?!localhost|127\.|\[::1\])""", re.I)
_UPDATE_CTX_JS = re.compile(r"autoUpdater|setFeedURL|electron-updater|update-electron-app|Squirrel|electron-builder")
_UPDATE_CTX_CFG = re.compile(r"^\s*(?:publish|provider)\s*:|\belectron-builder\b", re.M)
_YML_UPDATE = ("electron-builder.yml", "electron-builder.yaml", "app-update.yml", "dev-app-update.yml")


def _pkg_publish_urls(text: str) -> list[str] | None:
    """http:// update URLs under package.json build.publish; None when not an electron-builder project."""
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    build = doc.get("build") if isinstance(doc, dict) else None
    if not isinstance(build, dict):
        return None
    pub = build.get("publish")
    items = pub if isinstance(pub, list) else [pub]
    out = []
    for it in items:
        u = it.get("url") if isinstance(it, dict) else None
        if isinstance(u, str) and re.match(r"http://(?!localhost|127\.|\[::1\])", u, re.I):
            out.append(u)
    return out


@rule("SEC-DSK-003")
def auto_update(ctx: ScanContext):
    obs, seen = [], False
    for rel in _js_files(ctx):
        if not _UPDATE_CTX_JS.search(ctx.read(rel)):
            continue
        seen = True
        code = strip_c(ctx.read(rel))
        obs += _scan(rel, code, _SIG_OFF, "update signature verification disabled")
        obs += _scan(rel, code, _HTTP_FEED, "update feed served over plaintext HTTP")
    for rel in ctx.match(*_YML_UPDATE):
        text = ctx.read(rel)
        if not _UPDATE_CTX_CFG.search(text):
            continue
        seen = True
        code = strip_hash(text)
        obs += _scan(rel, code, _SIG_OFF, "update signature verification disabled")
        obs += _scan(rel, code, _HTTP_FEED, "update feed served over plaintext HTTP")
    for rel in ctx.match("package.json"):
        if "node_modules/" in rel:
            continue
        text = ctx.read(rel)
        urls = _pkg_publish_urls(text)
        if urls is None:
            continue
        seen = True
        obs += _scan(rel, text, _SIG_OFF, "update signature verification disabled")
        for u in urls:
            for i, ln in enumerate(text.splitlines(), 1):
                if u in ln:
                    obs.append(Observation(rel, i, "update feed served over plaintext HTTP"))
                    break
    return RuleResult(obs) if seen else None


_CFG_GLOBS = ("appsettings*.json", "app.config", "web.config", "*.ini")
_CONN_CTX = re.compile(r"Server\s*=|Data Source\s*=|Host\s*=|User ?Id\s*=|Uid\s*=|Provider\s*=|Initial Catalog|Database\s*=", re.I)
_PWD = re.compile(r"(?:Password|Pwd)\s*=\s*([^;\"'<\s][^;\"'<]*)", re.I)
_URL_CRED = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@\"']+:([^\s@/\"']+)@", re.I)
_JSON_PWD = re.compile(r'"(?:\w*)(?:Password|Pwd)"\s*:\s*"([^"]+)"')


def _placeholder(v: str) -> bool:
    return bool(re.match(r"\s*(\{|\$|%|<|#\{|__\w+__|@Microsoft\.KeyVault|ENC[(\[]|\*+$|xxx|\.\.\.)", v, re.I))


@rule("SEC-DSK-004")
def connection_strings(ctx: ScanContext):
    files = ctx.match(*_CFG_GLOBS)
    if not files:
        return None
    obs = []
    for rel in files:
        text = ctx.read(rel)
        code = strip_xml_comments(text) if rel.endswith((".config", ".xml")) else text
        is_json = rel.endswith(".json")
        for i, ln in enumerate(code.splitlines(), 1):
            if re.match(r"\s*[;#]", ln):
                continue
            m = _PWD.search(ln)
            if m and _CONN_CTX.search(ln) and not _placeholder(m.group(1)):
                obs.append(Observation(rel, i, "connection string with embedded password"))
                continue
            u = _URL_CRED.search(ln)
            if u and not _placeholder(u.group(1)):
                obs.append(Observation(rel, i, "URL with embedded credentials"))
                continue
            j = _JSON_PWD.search(ln) if is_json else None
            if j and not _placeholder(j.group(1)) and " " not in j.group(1).strip():
                obs.append(Observation(rel, i, "credential literal in application config"))
    return RuleResult(obs)


_NET = re.compile(r"\b(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\b")
_NET_DESER = re.compile(r"\.(?:Unsafe)?Deserialize\w*\s*\(")
_JAVA_OIS = re.compile(r"(?<![\w.])(?:new\s+)?(?:java\.io\.)?ObjectInputStream\s*\(")
_PY_PICKLE = re.compile(r"\b(?:c?[Pp]ickle|dill|marshal)\.loads?\s*\(")
_PY_GUI = re.compile(r"\b(?:tkinter|PyQt\d?|PySide\d?|wx|kivy|customtkinter)\b")


@rule("SEC-DSK-005")
def deserialization(ctx: ScanContext):
    files = ctx.match("*.cs", "*.vb", "*.java", "*.kt", "*.py")
    files = [f for f in files if "node_modules/" not in f and not is_test_path(f)]
    if not files:
        return None
    obs = []
    for rel in files:
        text = ctx.read(rel)
        if rel.endswith((".cs", ".vb")):
            code = blank_strings(strip_c(text)) if rel.endswith(".cs") else text
            if _NET_DESER.search(code):          # writing with these formatters is not the exposure
                obs += _scan(rel, code, _NET, "unsafe .NET binary deserializer")
        elif rel.endswith((".java", ".kt")):
            code = strip_c(text)
            if not re.search(r"ObjectInputFilter|ValidatingObjectInputStream|setObjectInputFilter|\bresolveClass\b", code):
                obs += _scan(rel, blank_strings(code), _JAVA_OIS, "ObjectInputStream without a deserialization filter")
        else:
            code = strip_hash(text)
            if _PY_GUI.search(code):
                obs += _scan(rel, code, _PY_PICKLE, "pickle-style deserialization in a desktop app")
    return RuleResult(obs)
