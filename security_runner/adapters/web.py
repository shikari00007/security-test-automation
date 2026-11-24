"""Static web-application rules (SEC-WEB-001..010) plus shared helpers for the api/supply_chain modules.

All rules are regex/structure based, read-only and deterministic. Files are read only through
``ctx.read``. Whole-line comments are blanked before matching (see :func:`clean`).
"""
from __future__ import annotations

import json
import re
from bisect import bisect_right

from .base import Observation, RuleResult, ScanContext, rule

# --------------------------------------------------------------------------------------
# Shared helpers (also imported by api.py and supply_chain.py)
# --------------------------------------------------------------------------------------
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", ".git", "site-packages", "venv", ".venv",
             "__pycache__", "bower_components"}
JS_GLOBS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.vue", "*.svelte", "*.html", "*.htm"]
PY_GLOBS = ["*.py"]
OTHER_SRC_GLOBS = ["*.java", "*.kt", "*.rb", "*.php", "*.go"]
CODE_GLOBS = JS_GLOBS + PY_GLOBS
CONFIG_GLOBS = [".env", ".env.*", "*.env", "Dockerfile*", "*.yml", "*.yaml", "*.sh", "*.conf", "*.ini",
                "*.cfg", "*.properties", "*.toml"]
DEV_NAME = re.compile(r"(?:^|[/._-])(dev|develop|development|test|tests|local|example|sample|template)(?:[/._-]|$)",
                      re.I)


_TESTY = re.compile(r"(?:^|[/._-])(?:tests?|spec|specs|__tests__|conftest|mocks?|fixtures?|e2e|stubs?|testing|selftest|testdata|test_data)(?:[/._-]|$)|conftest|(?:^|/)_?tests?[a-z]*\.(?:py|js|ts)$",
                    re.I)
_DEV_CLASS = re.compile(r"^(\s*)class\s+\w*(?:dev|test|debug|local|sandbox)\w*", re.I)
_ANY_CLASS = re.compile(r"^(\s*)class\s+\w+")


def in_dev_class(lines: list[str], idx: int) -> bool:
    """True when line ``idx`` sits inside a Python class whose name says Dev/Test/Debug/Local."""
    ind = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx - 1, -1, -1):
        m = _ANY_CLASS.match(lines[j])
        if m and len(m.group(1)) < ind:
            return bool(_DEV_CLASS.match(lines[j]))
    return False


def non_test(files: list[str]) -> list[str]:
    return [f for f in files if not _TESTY.search(f)]


def sel(ctx: ScanContext, *globs: str) -> list[str]:
    """ctx.match minus vendored/build directories and minified bundles."""
    out = []
    for rel in ctx.match(*globs):
        parts = rel.split("/")
        if SKIP_DIRS.intersection(parts[:-1]) or rel.endswith((".min.js", ".min.css", ".d.ts", ".d.mts", ".d.cts")):
            continue
        out.append(rel)
    return out


def _style(rel: str) -> str:
    base = rel.rsplit("/", 1)[-1].lower()
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in ("py", "yml", "yaml", "sh", "toml", "ini", "cfg", "conf", "properties", "rb", "env") \
            or base.startswith((".env", "dockerfile")):
        return "hash"
    if ext in ("html", "htm", "vue", "svelte"):
        return "html"
    return "c"


def clean(text: str, rel: str) -> str:
    """Blank whole-line comments (and block comments / docstrings), preserving line numbering."""
    style = _style(rel)
    out: list[str] = []
    block_end: str | None = None
    for line in text.split("\n"):
        s = line.strip()
        if block_end:
            if block_end in line:
                block_end = None
            out.append("")
            continue
        if style == "hash":
            if s.startswith("#"):
                out.append("")
                continue
            s_ = re.sub(r"^[rRuUbBfF]{1,2}(?=\"\"\"|''')", "", s) if rel.endswith(".py") else s
            if rel.endswith(".py") and (s_.startswith('"""') or s_.startswith("'''")):
                q = s_[:3]
                s = s_
                if s.count(q) < 2:
                    block_end = q
                out.append("")
                continue
        else:
            if s.startswith("//"):
                out.append("")
                continue
            if s.startswith("/*") or (style == "html" and s.startswith("<!--")):
                end = "*/" if s.startswith("/*") else "-->"
                if end not in s[2:] and end not in s[4:]:
                    block_end = end
                out.append("")
                continue
            if s.startswith("*") and not s.startswith("*/") and style == "c":
                out.append("")
                continue
        out.append(line)
    return "\n".join(out)


MAX_CODE_LINE = 1500   # longer lines are minified/bundled/generated output, not reviewable source


def read_clean(ctx: ScanContext, rel: str) -> str:
    text = clean(ctx.read(rel), rel)
    if len(text) > 2000:
        ls = text.split("\n")
        if len(text) / len(ls) > 200:   # minified file (few, very long lines)
            return "\n" * (len(ls) - 1)
        if any(len(l) > MAX_CODE_LINE for l in ls):
            text = "\n".join("" if len(l) > MAX_CODE_LINE else l for l in ls)
    return text


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def call_span(text: str, open_idx: int, limit: int = 4000) -> str:
    """Return text from the '(' at open_idx through its matching ')' (string aware)."""
    depth = 0
    in_str = None
    i = open_idx
    end = min(len(text), open_idx + limit)
    while i < end:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in "\"'`":
            in_str = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx:i + 1]
        i += 1
    return text[open_idx:end]


def first_arg(span: str) -> str:
    """First top-level argument of a call span '(a, b, ...)' (string aware)."""
    depth, q, i, body = 0, None, 0, span[1:]
    while i < len(body):
        c = body[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return body[:i]
            depth -= 1
        elif c == "," and depth == 0:
            return body[:i]
        i += 1
    return body


def scan_lines(ctx: ScanContext, files: list[str], rx: "re.Pattern[str]", check=None,
               detail: str = "") -> list[Observation]:
    """Per-line regex scan on comment-cleaned text. ``check(line, match, lines, idx, rel)`` may return
    a detail string (hit), None (no hit) or True (hit with default detail)."""
    obs: list[Observation] = []
    for rel in files:
        lines = read_clean(ctx, rel).split("\n")
        for i, line in enumerate(lines):
            m = rx.search(line)
            if not m:
                continue
            d: object = detail
            if check is not None:
                d = check(line, m, lines, i, rel)
                if not d:
                    continue
                if d is True:
                    d = detail
            obs.append(Observation(rel, i + 1, str(d)))
    return obs


def result(obs: list[Observation]) -> RuleResult:
    seen = set()
    uniq = []
    for o in sorted(obs, key=lambda o: (o.file, o.line, o.detail)):
        if (o.file, o.line) in seen:
            continue
        seen.add((o.file, o.line))
        uniq.append(o)
    return RuleResult(uniq)


_STR_LIT = re.compile(r"""^\s*(?:(['"])(?:(?!\1)[^\\]|\\.)*\1|`[^`$]*`)\s*$""")


def is_literal(expr: str) -> bool:
    e = expr.strip().rstrip(";").strip()
    return e == "" or bool(_STR_LIT.match(e))


# --------------------------------------------------------------------------------------
# Line-aware JSON / YAML parsers (tolerant, stdlib only)
# --------------------------------------------------------------------------------------
class LDict(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.lines: dict = {}


class LList(list):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.lines: dict = {}


def parse_json(text: str):
    nl = [m.start() for m in re.finditer("\n", text)]

    def ln(i: int) -> int:
        return bisect_right(nl, i - 1) + 1 if i > 0 else 1

    ws = re.compile(r"\s*")
    string_rx = re.compile(r'"(?:[^"\\]|\\.)*"')
    lit_rx = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")
    pos = [0]

    def skip():
        pos[0] = ws.match(text, pos[0]).end()

    def value():
        skip()
        i = pos[0]
        if i >= len(text):
            raise ValueError("eof")
        c = text[i]
        if c == "{":
            d = LDict()
            pos[0] += 1
            while True:
                skip()
                if text[pos[0]:pos[0] + 1] == "}":
                    pos[0] += 1
                    return d
                m = string_rx.match(text, pos[0])
                if not m:
                    raise ValueError("key")
                k = json.loads(m.group(0))
                d.lines[k] = ln(pos[0])
                pos[0] = m.end()
                skip()
                if text[pos[0]:pos[0] + 1] != ":":
                    raise ValueError("colon")
                pos[0] += 1
                d[k] = value()
                skip()
                if text[pos[0]:pos[0] + 1] == ",":
                    pos[0] += 1
        if c == "[":
            lst = LList()
            pos[0] += 1
            while True:
                skip()
                if text[pos[0]:pos[0] + 1] == "]":
                    pos[0] += 1
                    return lst
                lst.lines[len(lst)] = ln(pos[0])
                lst.append(value())
                skip()
                if text[pos[0]:pos[0] + 1] == ",":
                    pos[0] += 1
        m = string_rx.match(text, i)
        if m:
            pos[0] = m.end()
            return json.loads(m.group(0))
        m = lit_rx.match(text, i)
        if m:
            pos[0] = m.end()
            return json.loads(m.group(0))
        raise ValueError("token")

    v = value()
    skip()
    if pos[0] != len(text):
        raise ValueError("trailing")
    return v


def _strip_yaml_comment(s: str) -> str:
    q = None
    for i, c in enumerate(s):
        if q:
            if c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


_KEY_RX = re.compile(r"""^("(?:[^"\\]|\\.)*"|'[^']*'|[^\s:'"\-\[{][^:]*?|-[^\s:][^:]*?)\s*:(?:\s+(.*))?$""")


def _scalar(s: str):
    s = s.strip()
    if s == "":
        return None
    if s[0] in "\"'" and s[-1] == s[0] and len(s) >= 2:
        return s[1:-1]
    if s[0] == "[" and s[-1] == "]":
        inner = s[1:-1].strip()
        lst = LList()
        if inner:
            for n, part in enumerate(_split_flow(inner)):
                lst.append(_scalar(part))
        return lst
    if s[0] == "{" and s[-1] == "}":
        d = LDict()
        inner = s[1:-1].strip()
        if inner:
            for part in _split_flow(inner):
                if ":" in part:
                    k, v = part.split(":", 1)
                    d[str(_scalar(k))] = _scalar(v)
        return d
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def _split_flow(s: str) -> list[str]:
    parts, depth, cur, q = [], 0, "", None
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "\"'":
            q = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return parts


def parse_yaml(text: str):
    """Small tolerant YAML subset parser (block maps/sequences, flow scalars, block scalars)."""
    toks: list[list] = []
    block_indent = None
    for n, raw in enumerate(text.split("\n"), 1):
        if raw.strip() in ("---", "...") or raw.startswith("%"):
            continue
        ind = len(raw) - len(raw.lstrip(" "))
        if block_indent is not None:
            if raw.strip() == "" or ind > block_indent:
                continue
            block_indent = None
        body = _strip_yaml_comment(raw).rstrip()
        if body.strip() == "":
            continue
        toks.append([ind, body.strip(), n])
        if re.search(r"(?:^|[\s:])[|>][+-]?\d*$", body.strip()):
            block_indent = ind
    i = [0]

    def node(indent: int):
        if i[0] >= len(toks):
            return None
        t = toks[i[0]]
        if t[1] == "-" or t[1].startswith("- "):
            return seq(t[0])
        return mapping(t[0])

    def child_or_none(parent_indent: int, allow_same_seq: bool = False):
        if i[0] < len(toks):
            t = toks[i[0]]
            if t[0] > parent_indent:
                return node(t[0])
            if allow_same_seq and t[0] == parent_indent and (t[1] == "-" or t[1].startswith("- ")):
                return seq(t[0])
        return None

    def mapping(indent: int):
        d = LDict()
        while i[0] < len(toks) and toks[i[0]][0] == indent:
            t = toks[i[0]]
            if t[1] == "-" or t[1].startswith("- "):
                break
            m = _KEY_RX.match(t[1])
            if not m:
                i[0] += 1
                continue
            key = m.group(1).strip()
            if key[:1] in "\"'" and key[-1:] == key[:1]:
                key = key[1:-1]
            rest = (m.group(2) or "").strip()
            d.lines[key] = t[2]
            i[0] += 1
            if rest == "":
                d[key] = child_or_none(indent, allow_same_seq=True)
            elif re.fullmatch(r"[|>][+-]?\d*", rest):
                d[key] = ""
            else:
                d[key] = _scalar(rest)
        return d

    def seq(indent: int):
        lst = LList()
        while i[0] < len(toks) and toks[i[0]][0] == indent and \
                (toks[i[0]][1] == "-" or toks[i[0]][1].startswith("- ")):
            t = toks[i[0]]
            rest = t[1][1:].lstrip()
            offset = len(t[1]) - len(rest)
            lst.lines[len(lst)] = t[2]
            if rest == "":
                i[0] += 1
                lst.append(child_or_none(indent))
            elif _KEY_RX.match(rest) and not rest.startswith(("\"", "'")) or re.match(r'^"[^"]*"\s*:(\s|$)', rest):
                toks[i[0]] = [indent + offset, rest, t[2]]
                lst.append(mapping(indent + offset))
            else:
                i[0] += 1
                lst.append(_scalar(rest))
        return lst

    return node(0)


def parse_doc(rel: str, text: str):
    """Parse JSON or YAML according to extension. Raises ValueError on failure."""
    if rel.lower().endswith(".json"):
        return parse_json(text)
    return parse_yaml(text)


# --------------------------------------------------------------------------------------
# WEB-001  session cookie flags
# --------------------------------------------------------------------------------------
_COOKIE_CALL = re.compile(r"\.(?:cookie|set_cookie|setCookie)\s*\(")
_SESSION_NAME = re.compile(r"session|sess|sid|auth|token|jwt|login", re.I)
_SESSION_MW = re.compile(r"\b(?:session|cookieSession)\s*\(\s*\{")


def _flag_present(text: str, name: str) -> bool:
    return bool(re.search(name + r"""['"]?\s*[:=]\s*(?!false\b|False\b|None\b|null\b|undefined\b)\S""", text, re.I))


@rule("SEC-WEB-001")
def web_001(ctx: ScanContext):
    files = sel(ctx, *CODE_GLOBS)
    if not files:
        return None
    obs: list[Observation] = []
    for rel in files:
        text = read_clean(ctx, rel)
        for m in _COOKIE_CALL.finditer(text):
            span = call_span(text, m.end() - 1)
            first = span[1:].split(",", 1)[0]
            if not _SESSION_NAME.search(first) or "(" in first:
                continue
            missing = []
            if not _flag_present(span, r"http_?only"):
                missing.append("HttpOnly")
            if not _flag_present(span, r"\bsecure"):
                missing.append("Secure")
            if not _flag_present(span, r"same_?site"):
                missing.append("SameSite")
            if missing:
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "Session/auth cookie set without " + ", ".join(missing)))
        for m in _SESSION_MW.finditer(text):
            span = call_span(text, m.end() - 2)
            if not re.search(r"\b(secret|keys)\b", span):
                continue
            missing = []
            cm = re.search(r"cookie\s*:\s*\{", span)
            cspan = call_span(span, cm.end() - 1) if cm else ""
            if re.search(r"http_?only['\"]?\s*:\s*false", cspan, re.I):
                missing.append("HttpOnly")
            if not _flag_present(cspan, r"\bsecure"):
                missing.append("Secure")
            if not _flag_present(cspan, r"same_?site"):
                missing.append("SameSite")
            if missing:
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "Session middleware cookie lacks " + ", ".join(missing)))
        for i, line in enumerate(text.split("\n"), 1):
            m = re.search(r"SESSION_COOKIE_(HTTPONLY|SECURE)\W{1,6}False\b", line)
            if m:
                obs.append(Observation(rel, i, f"SESSION_COOKIE_{m.group(1)} disabled"))
            elif re.search(r"SESSION_COOKIE_SAMESITE\s*=\s*None\b", line):
                obs.append(Observation(rel, i, "SESSION_COOKIE_SAMESITE disabled"))
            elif re.search(r"\bdocument\.cookie\s*=(?!=).*(session|sid|auth|token|jwt)", line, re.I):
                obs.append(Observation(rel, i, "Session/auth cookie written from JavaScript (cannot be HttpOnly)"))
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-002  DOM XSS sinks
# --------------------------------------------------------------------------------------
_SANITIZED = re.compile(r"sanitiz|DOMPurify|escapeHtml|escapeHTML|encodeHTML|\bescape\s*\(|textContent|trusted|\bsafe", re.I)


_TERNARY_LIT = re.compile(r"^.+\?\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*:\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*;?\s*$")


_LIT_CONCAT_ALL = re.compile(r"^\s*(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")(?:\s*\+\s*(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"))*\s*;?\s*$")


@rule("SEC-WEB-002")
def web_002(ctx: ScanContext):
    files = non_test(sel(ctx, *JS_GLOBS))
    if not files:
        return None
    obs: list[Observation] = []
    inner = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*(.*)$")
    write = re.compile(r"\bdocument\.(?:write|writeln)\s*\((.*)$")
    adj = re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,)]+,\s*(.*)$")
    dang = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*(.*)$")
    vhtml = re.compile(r"""\bv-html\s*=\s*(["'])(.*?)\1""")
    for rel in files:
        lines_ = read_clean(ctx, rel).split("\n")
        for i, line in enumerate(lines_, 1):
            for rx, name in ((inner, "innerHTML/outerHTML"), (write, "document.write"),
                             (adj, "insertAdjacentHTML"), (dang, "dangerouslySetInnerHTML")):
                m = rx.search(line)
                if not m:
                    continue
                rhs = re.sub(r"\)\s*;?\s*$", "", m.group(1)) if rx in (write, adj) else m.group(1)
                rhs = re.sub(r"\}\}.*$", "", rhs) if rx is dang else rhs
                if rx is inner and rhs.strip() == "" and i < len(lines_):
                    rhs = lines_[i]  # value continues on the next line
                if rx is inner:
                    j = i
                    while rhs.rstrip().endswith("+") and j < len(lines_) and j - i < 40:
                        rhs = rhs.rstrip()[:-1] + " + " + lines_[j].strip()  # multi-line concatenation
                        j += 1
                    if _LIT_CONCAT_ALL.match(rhs) or re.search(r"\.innerHTML\b", rhs):
                        continue  # literal-only markup, or read-modify-write of the element's own markup
                if is_literal(rhs) or _SANITIZED.search(rhs) or _TERNARY_LIT.match(rhs):
                    continue
                obs.append(Observation(rel, i, f"{name} receives a non-literal, unsanitized value"))
                break
            else:
                m = vhtml.search(line)
                if m and not is_literal(m.group(2)) and not _SANITIZED.search(m.group(2)):
                    obs.append(Observation(rel, i, "v-html renders a non-literal, unsanitized expression"))
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-003  debug mode
# --------------------------------------------------------------------------------------
_WEBY = re.compile(r"(?:^|/)(?:\w*settings\w*|\w*config\w*|conf|prod\w*|app|wsgi|asgi|manage|server)\.py|"
                   r"\b(?:django|flask|fastapi|bottle|pyramid|tornado|aiohttp|sanic|starlette)\b", re.I)


@rule("SEC-WEB-003")
def web_003(ctx: ScanContext):
    code = [f for f in sel(ctx, *CODE_GLOBS) if not DEV_NAME.search(f)]
    conf = [f for f in sel(ctx, *CONFIG_GLOBS) if not DEV_NAME.search(f)]
    if not code and not conf:
        return None
    py_rx = re.compile(r"^\s*DEBUG\s*=\s*True\b|\bapp\.run\([^)]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True"
                       r"|\bFLASK_DEBUG\W{1,4}(?:1|true|True)\b|\bFLASK_ENV\W{1,4}development")
    js_rx = re.compile(r"""\bapp\.set\(\s*['"]env['"]\s*,\s*['"]development|process\.env\.NODE_ENV\s*=\s*['"]development""")
    cfg_rx = re.compile(r"""^\s*(?:ENV\s+)?(?:FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG|DEBUG)\s*[=:]\s*['"]?(?:1|true|True|yes|on)['"]?\s*$"""
                        r"""|^\s*(?:ENV\s+)?FLASK_ENV\s*[=: ]\s*['"]?development|^\s*(?:ENV\s+)?NODE_ENV\s*[=: ]\s*['"]?development"""
                        r"""|^\s*debug\s*:\s*true\s*$""", re.I)
    def chk_py(line, m, ls, i, rel):
        if in_dev_class(ls, i):
            return None
        if re.match(r"\s*DEBUG\s*=", line) and not _WEBY.search(rel + "\n" + ctx.read(rel)[:20000]):
            return None  # module-level DEBUG flag in a non-web library
        return True
    obs = scan_lines(ctx, [f for f in code if f.endswith(".py")], py_rx, check=chk_py,
                     detail="Debug mode enabled in application code")
    for rel in (f for f in code if f.endswith(".py")):  # multi-line app.run(..., debug=True)
        text = read_clean(ctx, rel)
        for m in re.finditer(r"\b(?:app|application)\.run\s*\(", text):
            if re.search(r"\bdebug\s*=\s*True\b", call_span(text, m.end() - 1)):
                obs.append(Observation(rel, line_of(text, m.start()), "Debug mode enabled in application code"))
    obs += scan_lines(ctx, [f for f in code if not f.endswith(".py")], js_rx, detail="Development environment forced in code")
    obs += scan_lines(ctx, [f for f in conf if f.rsplit("/", 1)[-1] != "Cargo.toml"], cfg_rx,
                      detail="Debug/development setting enabled in deployment config")
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-004  permissive CORS
# --------------------------------------------------------------------------------------
_REFLECT_CHECK = re.compile(r"ALLOWED|allowlist|whitelist|\.includes\(|\bin\s+[A-Z_]{3,}|indexOf|\.has\(", re.I)


@rule("SEC-WEB-004")
def web_004(ctx: ScanContext):
    files = sel(ctx, *CODE_GLOBS)
    if not files:
        return None
    obs: list[Observation] = []
    for rel in files:
        text = read_clean(ctx, rel)
        lines = text.split("\n")
        for m in re.finditer(r"\bcors\s*\(\s*\{", text):
            span = call_span(text, m.end() - 2)
            wide = re.search(r"""origin\s*:\s*(?:true\b|['"]\*['"]|req\.headers?\.origin)|cb\w*\(\s*null\s*,\s*true\s*\)|callback\(\s*null\s*,\s*true\s*\)""", span)
            if wide and re.search(r"cb\w*\(|callback\(", wide.group(0)) and _REFLECT_CHECK.search(span):
                continue  # callback origin function that consults an allowlist
            if wide and re.search(r"credentials\s*:\s*true", span):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "CORS allows any/reflected origin together with credentials"))
        for m in re.finditer(r"\bCORS\s*\(", text):
            span = call_span(text, m.end() - 1)
            if re.search(r"""['"]\*['"]|\.\*""", span) and re.search(r"supports_credentials\s*=\s*True", span):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "CORS wildcard origin with supports_credentials=True"))
        creds_hdr = re.search(r"""(?i)allow-credentials['"]?\s*[,:=]\s*['"]?true""", text)
        for i, line in enumerate(lines):
            if re.search(r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True", line) and \
                    re.search(r"CORS_ALLOW_CREDENTIALS\s*=\s*True", text):
                obs.append(Observation(rel, i + 1, "Django CORS allows all origins with credentials"))
                continue
            m = re.search(r"""(?i)access-control-allow-origin['"]?\s*[,:=]\s*(.+)$""", line)
            if m and creds_hdr:
                v = m.group(1).strip()
                wildcard = re.match(r"""['"]?\*['"]?""", v)
                reflected = re.search(r"origin", v) is not None and not re.match(r"""['"]https?://""", v)
                if wildcard or reflected:
                    window = "\n".join(lines[max(0, i - 8):i + 1])
                    if wildcard or not _REFLECT_CHECK.search(window):
                        obs.append(Observation(rel, i + 1,
                                               "Access-Control-Allow-Origin is wildcard/reflected with credentials allowed"))
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-005  command / code injection sinks
# --------------------------------------------------------------------------------------
_PY_DYN = re.compile(r"""\bf["']|\.format\(|["']\s*%\s*[\w(]|["']\s*\+|\+\s*["'\w]""")
_JS_DYN = re.compile(r"""\$\{|["'`]\s*\+|\+\s*["'`]""")


_TAINT_WORDS = re.compile(r"(?i)request|\breq\b|input|user|param|query|form|argv|stdin|payload|body|cmd|command|expr|"
                         r"untrusted|\bargs\b|getenv|environ|\bGET\b|\bPOST\b|json|formula|location|hash|search|cookie")


def _untrusted_expr(arg: str, dyn: "re.Pattern[str]") -> bool:
    """eval/exec argument worth reporting: built as a dynamic string, or visibly derived from request/user input."""
    return bool(dyn.search(arg) or _TAINT_WORDS.search(arg))


_LIT = r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
_LIT_CONCAT = re.compile(r"^\s*" + _LIT + r"(?:\s*\+\s*" + _LIT + r")*\s*(?:,.*)?$", re.S)


@rule("SEC-WEB-005")
def web_005(ctx: ScanContext):
    js = non_test(sel(ctx, *JS_GLOBS))
    py = non_test(sel(ctx, *PY_GLOBS))
    if not js and not py:
        return None
    obs: list[Observation] = []
    for rel in js:
        text = read_clean(ctx, rel)
        for m in re.finditer(r"(?<![\w.$])(?<!function )eval\s*\(", text):
            span = call_span(text, m.end() - 1)
            if not is_literal(span[1:-1]) and _untrusted_expr(span[1:-1], _JS_DYN):
                obs.append(Observation(rel, line_of(text, m.start()), "eval() with non-literal argument"))
        for m in re.finditer(r"\bnew\s+Function\s*\(", text):
            span = call_span(text, m.end() - 1)
            if not all(is_literal(p) for p in span[1:-1].split(",")):
                obs.append(Observation(rel, line_of(text, m.start()), "new Function() built from non-literal input"))
        for m in re.finditer(r"(?<![\w.$])(?:exec|execSync)\s*\(|\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\(", text):
            span = call_span(text, m.end() - 1)
            fa = first_arg(span)
            if not fa.lstrip().startswith("{") and _JS_DYN.search(fa):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "child_process exec with concatenated/templated command string"))
    for rel in py:
        text = read_clean(ctx, rel)
        for m in re.finditer(r"\bos\.(?:system|popen)\s*\(", text):
            span = call_span(text, m.end() - 1)
            if _PY_DYN.search(span) and not _LIT_CONCAT.match(span[1:-1]):
                obs.append(Observation(rel, line_of(text, m.start()), "os.system/popen with dynamically built command"))
        for m in re.finditer(r"\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(", text):
            span = call_span(text, m.end() - 1)
            if re.search(r"shell\s*=\s*True", span) and _PY_DYN.search(span) and not _LIT_CONCAT.match(span[1:-1]):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "subprocess with shell=True and dynamically built command"))
        for m in re.finditer(r"(?<![\w.])(?<!def )(?:eval|exec)\s*\(", text):
            span = call_span(text, m.end() - 1)
            fa = first_arg(span)
            if not is_literal(fa) and _untrusted_expr(fa, _PY_DYN):
                obs.append(Observation(rel, line_of(text, m.start()), "eval/exec with non-literal argument"))
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-006  SQL built by string building
# --------------------------------------------------------------------------------------
_SEL_COL = r"""[\w.`"\[\]*]+(?:\([^)]*\))?(?:\s+AS\s+\w+)?"""
_SQL_KW = re.compile(r"""(?i)["'`]\s*(?:SELECT\s+(?:DISTINCT\s+)?""" + _SEL_COL + r"""(?:\s*,\s*""" + _SEL_COL + r""")*\s+FROM\s|INSERT\s+INTO\s|UPDATE\s+\w+\s+SET\s|DELETE\s+FROM\s)""")
_SQL_DYN = re.compile(r"""\bf"[^"]*\{|\bf'[^']*\{|["']\s*\+\s*(?:[\w(]|$)|[\w)]\s*\+\s*["']|\.format\(|["']\s*%\s+[\w(]|["']\s*%\(|\$\{""")


@rule("SEC-WEB-006")
def web_006(ctx: ScanContext):
    files = non_test(sel(ctx, *CODE_GLOBS, *OTHER_SRC_GLOBS))
    if not files:
        return None
    def chk(line, m, ls, i, rel):
        kw = re.search(r"[A-Za-z]+", m.group(0)).group(0)
        if len(kw) > 1 and kw[0].isupper() and kw[1:].islower():
            return None  # Title-case "Select ..."/"Delete from ..." is prose, not SQL
        if re.search(r"quote_name|quote_ident|escape_identifier|quoted_name|\bquote\(", line):
            return None  # identifier passed through the driver's quoting helper
        stripped = re.sub(r"\$\{[A-Z][A-Z0-9_.]*\}|\{[A-Z][A-Z0-9_]*\}", "", line)  # constant interpolation
        # identifiers cannot be bound as parameters: `FROM {self.table_name}` / `FROM %s" % table`
        stripped = re.sub(r"(?i)\b(FROM|INTO|UPDATE|TABLE|JOIN)\s+(?:\$?\{[^{}]*(?:table|tbl|schema)[^{}]*\}"
                          r"|%s[\"']?\s*%\s*\(?\s*[\w.]*(?:table|tbl)\w*\s*,?\s*\)?)", r"\1 X", stripped)
        if _SQL_DYN.search(stripped):
            return True
        # PHP: "..." . $var concatenation / "$var" interpolation
        return rel.endswith(".php") and bool(re.search(r"[\"']\s*\.\s*\$\w|\"[^\"]*\$\w+", line))
    obs = scan_lines(ctx, files, _SQL_KW, check=chk,
                     detail="SQL statement built with string concatenation/interpolation")
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-007  TLS verification disabled
# --------------------------------------------------------------------------------------
_TLS_RX = re.compile(
    r"""\bverify(?:_ssl)?\s*[=:]\s*False\b|(?<![\w.])rejectUnauthorized\s*:\s*false|"""
    r"""NODE_TLS_REJECT_UNAUTHORIZED\s*['"]?\s*[=:]\s*['"]?0\b|_create_unverified_context|ssl\.CERT_NONE|"""
    r"""check_hostname\s*=\s*False|strictSSL\s*:\s*false|InsecureSkipVerify\s*:\s*true|"""
    r"""\bcurl\b[^|;#]*\s(?:-k|--insecure)\b""")


@rule("SEC-WEB-007")
def web_007(ctx: ScanContext):
    files = [f for f in sel(ctx, *CODE_GLOBS, *OTHER_SRC_GLOBS, *CONFIG_GLOBS) if not _TESTY.search(f)]
    if not files:
        return None
    def chk(line, m, ls, i, rel):
        # `ssl.CERT_REQUIRED if strict else ssl.CERT_NONE` style conditionals enable verification by default
        if re.search(r"CERT_REQUIRED|CERT_OPTIONAL", line):
            return None
        if re.search(r"nosec|noqa:\s*S(?:323|501|502|504)", line) or re.search(r"[!=]=\s*(?:ssl\.)?CERT_NONE", line) \
                or re.search(r":\s*\w+\s*=\s*(?:ssl\.)?CERT_NONE", line):
            return None  # acknowledged suppression / comparison / typed parameter default
        if re.search(r"\bverify\s*=\s*False", line) and not re.search(
                r"(?i)requests|httpx|urllib|aiohttp|\bssl\b|https?://|session|curl|tls", ctx.read(rel)[:50000]):
            return None  # `verify=False` unrelated to TLS (e.g. decorator flag)
        if "CERT_NONE" in line and not re.search(
                r"(?<![=!<>])=(?!=)\s*(?:ssl\.)?CERT_NONE|[(,]\s*(?:\w+\s*=\s*)?(?:ssl\.)?CERT_NONE\s*[,)]", line) \
                and not re.search(r"_create_unverified_context|check_hostname\s*=\s*False|verify\w*\s*[=:]\s*False", line):
            return None  # comparison / dict key / mapping, not an assignment of CERT_NONE
        # opt-out branch: `if cfg.ignore_certs:` / `if not verify:` directly above
        if re.search(r"\b(?:if|elif|unless)\b.*(?:ignore|insecure|skip|unsafe|no_?verif|disable|allow_?invalid|trust_?all)",
                     "\n".join(ls[max(0, i - 3):i]), re.I):
            return None
        return "TLS certificate/hostname verification disabled"
    return result(scan_lines(ctx, files, _TLS_RX, check=chk))


# --------------------------------------------------------------------------------------
# WEB-008  weak password hashing / insecure randomness
# --------------------------------------------------------------------------------------
_WEAK_HASH = re.compile(r"""\bhashlib\.(?:md5|sha1)\s*\(|createHash\(\s*['"](?:md5|sha1)['"]\s*\)""")
_PW_WORD = re.compile(r"passw|pwd|passphrase", re.I)
_WEAK_RAND = re.compile(r"\bMath\.random\s*\(|(?<![\w.])random\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\(")
_TOKEN_WORD = re.compile(
    r"(?<![a-z])(?:token|session_(?:id|key|token|cookie|secret)|secret|api_?key|otp|csrf|password|passwd|"
    r"salt|verification|invite|auth(?:orization)?)(?![a-z])")


def _token_context(line: str) -> bool:
    # split camelCase so `csrfToken`/`authorName` are judged by their words, not substrings
    return bool(_TOKEN_WORD.search(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", line).lower().replace("-", "_")))


@rule("SEC-WEB-008")
def web_008(ctx: ScanContext):
    files = non_test(sel(ctx, *CODE_GLOBS))
    if not files:
        return None
    def chk_hash(line, m, ls, i, rel):
        if re.search(r"nosec|noqa:\s*S3(?:24|03|11)", line):
            return None  # author explicitly acknowledged the weak primitive
        window = "\n".join(ls[i:i + 3])
        if re.search(r"usedforsecurity\s*=\s*False", window):
            return None
        return "MD5/SHA-1 used for password hashing" if _PW_WORD.search(window) else None
    def chk_rand(line, m, ls, i, rel):
        return "Non-cryptographic PRNG used for a token/secret" if _token_context(line) else None
    obs = scan_lines(ctx, files, _WEAK_HASH, check=chk_hash)
    obs += scan_lines(ctx, files, _WEAK_RAND, check=chk_rand)
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-009  open redirect
# --------------------------------------------------------------------------------------
_REDIR_VALID = re.compile(r"""startsWith\(\s*['"]/[^/]|is_safe_url|url_has_allowed_host|is_safe_redirect|allowlist|whitelist|ALLOWED_|new URL\(|urlparse|\.netloc|\.hostname""", re.I)


@rule("SEC-WEB-009")
def web_009(ctx: ScanContext):
    files = sel(ctx, *CODE_GLOBS)
    if not files:
        return None
    obs: list[Observation] = []
    py_src = r"request\.(?:args|GET|form|values|POST|query_params)"
    js_src = r"req\.(?:query|params|body)"
    for rel in files:
        lines = read_clean(ctx, rel).split("\n")
        tainted: set[str] = set()
        for ln_ in lines:
            for m in re.finditer(r"\b(\w+)\s*=\s*" + py_src + r"(?:\.get\(|\[)", ln_):
                tainted.add(m.group(1))
            for m in re.finditer(r"\b(\w+)\s*=\s*" + js_src + r"\.\w+", ln_):
                tainted.add(m.group(1))
            for m in re.finditer(r"\{\s*([\w\s,]+?)\s*\}\s*=\s*" + js_src + r"\b", ln_):
                tainted.update(x.strip() for x in m.group(1).split(","))
            for m in re.finditer(r"\b(\w+)\s*=\s*(?:new\s+URLSearchParams\([^)]*\)|\w*[pP]arams|url\.searchParams)\.get\(", ln_):
                tainted.add(m.group(1))
        tainted.discard("")
        tn = "|".join(re.escape(t) for t in sorted(tainted)) or r"(?!)"
        sinks = [
            re.compile(r"\b(?:redirect|HttpResponseRedirect|RedirectResponse|HTTPFound)\s*\(\s*(?:\d+\s*,\s*)?(?:" + py_src + r"|" + js_src + r"|(?:" + tn + r")\s*[),|]|(?:" + tn + r")\s*$)"),
            re.compile(r"\blocation(?:\.href)?\s*=\s*(?:" + tn + r")\s*;?\s*$"),
            re.compile(r"\blocation\.(?:assign|replace)\(\s*(?:" + tn + r")\s*\)"),
            re.compile(r"\blocation(?:\.href)?\s*=\s*(?:new\s+URLSearchParams\([^)]*\)|\w*[pP]arams)\.get\("),
        ]
        for i, line in enumerate(lines):
            if not any(s.search(line) for s in sinks):
                continue
            window = "\n".join(lines[max(0, i - 10):i + 1])
            if _REDIR_VALID.search(window):
                continue
            obs.append(Observation(rel, i + 1, "Redirect target taken from request parameter without validation"))
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-010  CSRF protection disabled
# --------------------------------------------------------------------------------------
_CSRF_RX = re.compile(
    r"""@csrf_exempt\b|\bcsrf_exempt\(|WTF_CSRF_ENABLED\W{1,6}False|WTF_CSRF_CHECK_DEFAULT\W{1,6}False|"""
    r"""@\w*csrf\w*\.exempt|\bcsrf\s*:\s*false\b|csrf\(\s*\)\s*\.\s*disable\(|\bcsrf\.disable\(|"""
    r"""csrf\(\s*(?:AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\(\))|"""
    r"""skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session|skip_forgery_protection""")


@rule("SEC-WEB-010")
def web_010(ctx: ScanContext):
    files = [f for f in sel(ctx, *CODE_GLOBS, *OTHER_SRC_GLOBS) if not _TESTY.search(f)]
    if not files:
        return None
    return result(scan_lines(ctx, files, _CSRF_RX,
                             check=lambda line, m, ls, i, rel: None if in_dev_class(ls, i) else True,
                             detail="CSRF protection disabled or exempted"))
