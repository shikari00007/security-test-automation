"""Static web-application rules (SEC-WEB-001..010) plus shared helpers for the api/supply_chain modules.

All rules are regex/structure based, read-only and deterministic. Files are read only through
``ctx.read``. Whole-line comments are blanked before matching (see :func:`clean`).
"""
from __future__ import annotations

import json
import re
from bisect import bisect_right

from . import web_php_java as _pj
from . import web_python_ts as _pt
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
    tq: str | None = None   # inside a multi-line triple-quoted VALUE (`x = """..."""`), not a docstring
    for line in text.split("\n"):
        s = line.strip()
        if tq:
            # keep the body; the closing quote must not be mistaken for the start of a docstring, which
            # would blank all following code until the next triple quote (recall loss)
            out.append(line)
            if line.count(tq) % 2 == 1:
                tq = None
            continue
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
        if style == "hash" and rel.endswith(".py"):
            for q in ('"""', "'''"):
                if line.count(q) % 2 == 1:
                    tq = q
                    break
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
# Constant-flow helpers shared by WEB-002 / WEB-005 / WEB-006 (phase 1 precision work)
#
# Principle: a dynamic fragment is only exempted when LOCAL dataflow in the same file proves it is not
# attacker-influenced: a literal, a conditional/concatenation/join of such fragments, a lookup in a
# literal table, a loop variable over a closed (literal / allowlist-filtered / catalog) collection, or a
# name whose EVERY binding in scope is one of those. Anything unknown (parameters, attributes, calls,
# imports, names never bound in the file) is treated as attacker-influenced, i.e. still reported.
# --------------------------------------------------------------------------------------
import ast as _ast
import warnings as _warnings

_CATALOG_CALLS = {"get_table_names", "get_columns", "get_schema_names", "get_view_names", "sorted_tables"}
_CATALOG_SQL = re.compile(r"(?i)information_schema|pg_catalog|sqlite_master|sqlite_schema|pg_tables")
_MODEL_ATTRS = {"model_fields", "__fields__", "__annotations__", "_fields", "__slots__", "column_attrs"}
_STRIP_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "title"}
_SQL_ANY = re.compile(r"(?i)\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b")


class _PyFlow:
    """Conservative constant-flow analysis over a parsed Python module (see block comment above)."""

    def __init__(self, tree):
        self.tree = tree
        self.parent = {}
        for n in _ast.walk(tree):
            for c in _ast.iter_child_nodes(n):
                self.parent[c] = n
        self._scope_cache = {}

    # ---- scopes / bindings -------------------------------------------------------------
    def _scope_of(self, node):
        n = self.parent.get(node)
        while n is not None and not isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.Lambda, _ast.Module)):
            n = self.parent.get(n)
        return n or self.tree

    def _bindings(self, scope):
        if scope in self._scope_cache:
            return self._scope_cache[scope]
        b: dict = {}

        def add(name, *rec):
            b.setdefault(name, []).append(rec)

        def names_in(t):
            return [x.id for x in _ast.walk(t) if isinstance(x, _ast.Name)]

        if isinstance(scope, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.Lambda)):
            a = scope.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]:
                add(arg.arg, "unknown")
        stack = list(scope.body if not isinstance(scope, _ast.Lambda) else [scope.body])
        while stack:
            n = stack.pop()
            if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                add(n.name, "unknown")
                continue   # nested scope: its own bindings are separate
            if isinstance(n, _ast.Lambda):
                continue
            if isinstance(n, _ast.Assign):
                for t in n.targets:
                    if isinstance(t, _ast.Name):
                        add(t.id, "assign", n.value)
                    elif isinstance(t, _ast.Subscript) and isinstance(t.value, _ast.Name):
                        add(t.value.id, "setitem", t.slice, n.value)
                    elif isinstance(t, (_ast.Tuple, _ast.List)) and isinstance(n.value, (_ast.Tuple, _ast.List)) \
                            and len(t.elts) == len(n.value.elts) and all(isinstance(x, _ast.Name) for x in t.elts):
                        for x, v in zip(t.elts, n.value.elts):    # `a, b = [], []`
                            add(x.id, "assign", v)
                    else:
                        for nm in names_in(t):
                            add(nm, "unknown")
            elif isinstance(n, _ast.AnnAssign) and isinstance(n.target, _ast.Name) and n.value is not None:
                add(n.target.id, "assign", n.value)
            elif isinstance(n, _ast.AugAssign) and isinstance(n.target, _ast.Name):
                add(n.target.id, "aug", n.value)
            elif isinstance(n, (_ast.For, _ast.AsyncFor)):
                for nm in names_in(n.target):
                    add(nm, "for", n.target, n.iter)
            elif isinstance(n, _ast.withitem) and n.optional_vars is not None:
                for nm in names_in(n.optional_vars):
                    add(nm, "unknown")
            elif isinstance(n, _ast.ExceptHandler) and n.name:
                add(n.name, "unknown")
            elif isinstance(n, (_ast.Import, _ast.ImportFrom)):
                for al in n.names:
                    add((al.asname or al.name).split(".")[0], "unknown")
            elif isinstance(n, (_ast.Global, _ast.Nonlocal)):
                for nm in n.names:
                    add(nm, "unknown")
            elif isinstance(n, _ast.NamedExpr):
                add(n.target.id, "unknown")
            elif isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) and isinstance(n.func.value, _ast.Name):
                if n.func.attr in ("append", "add"):
                    add(n.func.value.id, "item", n.args[0] if n.args else None)
                elif n.func.attr == "extend":
                    add(n.func.value.id, "items", n.args[0] if n.args else None)
                elif n.func.attr == "insert":
                    add(n.func.value.id, "item", n.args[1] if len(n.args) > 1 else None)
                elif n.func.attr in ("update", "setdefault", "pop", "popitem", "clear", "remove"):
                    if n.func.attr in ("update", "setdefault"):
                        add(n.func.value.id, "unknown")
            stack.extend(_ast.iter_child_nodes(n))
        self._scope_cache[scope] = b
        return b

    def _lookup(self, name, node):
        scope = self._scope_of(node)
        while True:
            b = self._bindings(scope)
            if name in b:
                return b[name], scope
            if isinstance(scope, _ast.Module):
                return None, scope
            scope = self._scope_of(scope)

    # ---- safe scalar/fragment values ---------------------------------------------------
    def safe(self, node, env=None, shell=False, seen=None):
        env = env or {}
        seen = seen if seen is not None else set()
        S = lambda x, e=env: self.safe(x, e, shell, seen)   # noqa: E731
        if node is None:
            return False
        if isinstance(node, _ast.Constant):
            return True
        if isinstance(node, _ast.JoinedStr):
            return all(S(v) for v in node.values)
        if isinstance(node, _ast.FormattedValue):
            return S(node.value) and (node.format_spec is None or S(node.format_spec))
        if isinstance(node, _ast.IfExp):
            return S(node.body) and S(node.orelse)       # the test only selects between safe fragments
        if isinstance(node, _ast.BoolOp):
            return all(S(v) for v in node.values)
        if isinstance(node, _ast.BinOp):
            if isinstance(node.op, (_ast.Add, _ast.Mult)):
                return S(node.left) and S(node.right)
            if isinstance(node.op, _ast.Mod):
                r = node.right
                return S(node.left) and (all(S(x) for x in r.elts) if isinstance(r, _ast.Tuple) else S(r))
            return False
        if isinstance(node, (_ast.List, _ast.Tuple, _ast.Set)):
            return all(S(x.value if isinstance(x, _ast.Starred) else x) for x in node.elts)
        if isinstance(node, _ast.Dict):
            return all(k is not None for k in node.keys) and all(S(v) for v in node.values)
        if isinstance(node, (_ast.GeneratorExp, _ast.ListComp, _ast.SetComp)):
            e2 = self._comp_env(node.generators, env, shell, seen)
            return e2 is not None and self.safe(node.elt, e2, shell, seen)
        if isinstance(node, _ast.Subscript):
            # `{"a": "col_a"}[key]` / `COLS[key]`: the result is always one of the literal values
            return self._container_safe(node.value, env, shell, seen) or self._derived_from_closed(node.value, env, seen)
        if isinstance(node, _ast.Attribute):
            return self._derived_from_closed(node.value, env, seen)
        if isinstance(node, _ast.Call):
            f = node.func
            if isinstance(f, _ast.Name) and f.id == "len":
                return True
            if isinstance(f, _ast.Name) and f.id == "str" and len(node.args) == 1:
                return S(node.args[0])
            if isinstance(f, _ast.Attribute):
                if f.attr == "join" and node.args:
                    return S(f.value) and S(node.args[0])
                if f.attr == "format":
                    return S(f.value) and all(S(a.value if isinstance(a, _ast.Starred) else a) for a in node.args) \
                        and all(S(k.value) for k in node.keywords)
                if f.attr == "get" and node.args and self._container_safe(f.value, env, shell, seen):
                    return len(node.args) < 2 or S(node.args[1])
                if f.attr in _STRIP_METHODS and S(f.value):
                    return True
                if f.attr in ("dedent", "cleandoc") and node.args:
                    return S(node.args[0])
                if shell and f.attr in ("quote", "join") and isinstance(f.value, _ast.Name) and f.value.id in ("shlex", "pipes"):
                    return f.attr == "quote" or f.value.id == "shlex"   # shell-quoted arguments cannot inject
            return self._derived_from_closed(node, env, seen)
        if isinstance(node, _ast.Name):
            if node.id in env:
                return env[node.id]
            key = (id(node), node.id)
            b, scope = self._lookup(node.id, node)
            if not b:
                return False
            k2 = (id(scope), node.id)
            if k2 in seen:
                return True     # self-reference (x = x + "..."): other bindings decide
            seen = seen | {k2}
            S2 = lambda x: self.safe(x, env, shell, seen)   # noqa: E731
            for rec in b:
                kind = rec[0]
                if kind == "assign" and S2(rec[1]):
                    continue
                if kind == "aug" and S2(rec[1]):
                    continue
                if kind == "item" and S2(rec[1]):
                    continue
                if kind == "items" and self._elems(rec[1], "elem", env, shell, seen):
                    continue
                if kind == "setitem" and S2(rec[1]) and S2(rec[2]):
                    continue
                if kind == "for" and self._for_safe(rec[1], rec[2], env, shell, seen):
                    continue
                return False
            return True
        return False

    def _container_safe(self, node, env, shell, seen):
        """node is (or names) a literal container whose values are all safe fragments."""
        return isinstance(node, (_ast.Dict, _ast.List, _ast.Tuple, _ast.Set, _ast.Name)) \
            and self.safe(node, env, shell, seen)

    def _derived_from_closed(self, node, env, seen):
        """`row["name"]` / `col.name` / `f.name.lower()` where the root is a loop variable over a closed source."""
        while isinstance(node, (_ast.Attribute, _ast.Subscript)):
            node = node.value
        if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute) and node.func.attr in _STRIP_METHODS:
            return self._derived_from_closed(node.func.value, env, seen)
        if not isinstance(node, _ast.Name) or node.id in env and not env[node.id]:
            return False
        if node.id in env:
            return True
        b, _ = self._lookup(node.id, node)
        return bool(b) and all(r[0] == "for" and self._for_safe(r[1], r[2], env, False, seen) for r in b)

    # ---- closed collections ------------------------------------------------------------
    def _for_safe(self, target, it, env, shell, seen):
        mode = "items" if isinstance(target, _ast.Tuple) and isinstance(it, _ast.Call) \
            and isinstance(it.func, _ast.Attribute) and it.func.attr == "items" else "elem"
        return self._elems(it, mode, env, shell, seen)

    def _allow_filtered(self, gen, env, shell, seen):
        """`for k in data if k in ALLOWED` : the loop variable is restricted to a closed allowlist."""
        names = {x.id for x in _ast.walk(gen.target) if isinstance(x, _ast.Name)}
        conds = []
        for c in gen.ifs:
            conds += c.values if isinstance(c, _ast.BoolOp) and isinstance(c.op, _ast.And) else [c]
        for c in conds:
            if isinstance(c, _ast.Compare) and len(c.ops) == 1 and isinstance(c.ops[0], _ast.In) \
                    and isinstance(c.left, _ast.Name) and c.left.id in names \
                    and self._elems(c.comparators[0], "elem", env, shell, seen):
                return True
        return False

    def _comp_env(self, generators, env, shell, seen):
        e2 = dict(env)
        for g in generators:
            ok = self._for_safe(g.target, g.iter, e2, shell, seen) or self._allow_filtered(g, e2, shell, seen)
            for x in _ast.walk(g.target):
                if isinstance(x, _ast.Name):
                    e2[x.id] = ok
        return e2

    def _elems(self, node, mode, env, shell, seen):
        """True when every element yielded by iterating ``node`` (keys / values / items per mode) is safe."""
        E = lambda x, m=mode: self._elems(x, m, env, shell, seen)   # noqa: E731
        Sf = lambda x: self.safe(x, env, shell, seen)   # noqa: E731
        if isinstance(node, _ast.Dict):
            if any(k is None for k in node.keys):
                return False
            return (mode == "values" or all(Sf(k) for k in node.keys)) and \
                (mode == "elem" or mode == "keys" or all(Sf(v) for v in node.values))
        if isinstance(node, (_ast.List, _ast.Tuple, _ast.Set)):
            return mode in ("elem", "keys", "values") and Sf(node)
        if isinstance(node, (_ast.ListComp, _ast.SetComp, _ast.GeneratorExp)):
            e2 = self._comp_env(node.generators, env, shell, seen)
            return mode in ("elem", "keys", "values") and self.safe(node.elt, e2, shell, seen)
        if isinstance(node, _ast.DictComp):
            e2 = self._comp_env(node.generators, env, shell, seen)
            return (mode == "values" or self.safe(node.key, e2, shell, seen)) and \
                (mode in ("elem", "keys") or self.safe(node.value, e2, shell, seen))
        if isinstance(node, _ast.Name):
            if node.id in env:
                return env[node.id]
            b, scope = self._lookup(node.id, node)
            k2 = (id(scope), node.id, "e")
            if not b or k2 in seen:
                return bool(b)
            seen = seen | {k2}
            for rec in b:
                if rec[0] == "assign" and self._elems(rec[1], mode, env, shell, seen):
                    continue
                if rec[0] in ("aug", "items") and self._elems(rec[1], mode, env, shell, seen):
                    continue
                if rec[0] == "item" and self.safe(rec[1], env, shell, seen):
                    continue
                if rec[0] == "setitem" and mode != "items" and self.safe(rec[1], env, shell, seen) \
                        and (mode == "keys" or mode == "elem" or self.safe(rec[2], env, shell, seen)):
                    continue
                return False
            return True
        if isinstance(node, _ast.BinOp):
            if isinstance(node.op, _ast.BitAnd):
                return E(node.left) or E(node.right)      # an intersection is bounded by either side
            if isinstance(node.op, (_ast.Add, _ast.BitOr)):
                return E(node.left) and E(node.right)
            if isinstance(node.op, _ast.Sub):
                return E(node.left)
            return False
        if isinstance(node, _ast.Attribute):
            if node.attr in _MODEL_ATTRS:
                return True
            return node.attr in ("columns", "c") and isinstance(node.value, (_ast.Attribute, _ast.Call)) and \
                (getattr(node.value, "attr", "") in ("__table__", "__mapper__")
                 or (isinstance(node.value, _ast.Call) and getattr(node.value.func, "id", "") == "inspect"))
        if isinstance(node, _ast.Call):
            f = node.func
            fname = f.attr if isinstance(f, _ast.Attribute) else getattr(f, "id", "")
            if fname in _CATALOG_CALLS or fname == "fields" and node.args:
                return True
            if fname in ("keys", "values", "items") and isinstance(f, _ast.Attribute) and not node.args:
                return self._elems(f.value, fname if fname != "keys" else "keys", env, shell, seen)
            if fname in ("sorted", "list", "tuple", "set", "frozenset", "reversed") and node.args:
                return E(node.args[0])
            if fname == "enumerate" and node.args:
                return E(node.args[0])
            if fname == "zip" and node.args:
                return all(E(a) for a in node.args)
            if fname == "range":
                return True
            # catalog introspection: iterating the rows of `SELECT ... FROM information_schema...`
            consts = [c.value for c in _ast.walk(node) if isinstance(c, _ast.Constant) and isinstance(c.value, str)]
            return bool(consts) and bool(_CATALOG_SQL.search(" ".join(consts))) and \
                all(isinstance(c, (_ast.Constant, _ast.Call, _ast.Attribute, _ast.Name)) for c in node.args)
        return False

    # ---- call-site helpers -------------------------------------------------------------
    def nodes_covering(self, lineno, types):
        return [n for n in _ast.walk(self.tree) if isinstance(n, types) and hasattr(n, "lineno")
                and n.lineno <= lineno <= (n.end_lineno or n.lineno)]

    def sql_safe(self, lineno):
        """All SQL-looking string-building expressions covering ``lineno`` are built from safe fragments."""
        cand = [n for n in self.nodes_covering(lineno, (_ast.JoinedStr, _ast.BinOp, _ast.Call))
                if (isinstance(n, _ast.JoinedStr) or (isinstance(n, _ast.BinOp) and isinstance(n.op, (_ast.Add, _ast.Mod)))
                    or (isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) and n.func.attr == "format"))
                and _SQL_ANY.search(" ".join(c.value for c in _ast.walk(n)
                                             if isinstance(c, _ast.Constant) and isinstance(c.value, str)))]
        cand = [n for n in cand if not any(self.parent.get(n) is not None and self._has_ancestor(n, o) for o in cand if o is not n)]
        return bool(cand) and all(self.safe(n) for n in cand)

    def _has_ancestor(self, n, anc):
        p = self.parent.get(n)
        while p is not None:
            if p is anc:
                return True
            p = self.parent.get(p)
        return False

    def calls_at(self, lineno, dotted):
        out = []
        for n in self.nodes_covering(lineno, (_ast.Call,)):
            if n.lineno != lineno:
                continue
            f, parts = n.func, []
            while isinstance(f, _ast.Attribute):
                parts.append(f.attr)
                f = f.value
            if isinstance(f, _ast.Name):
                parts.append(f.id)
            if ".".join(reversed(parts)) in dotted:
                out.append(n)
        return out


def py_flow(ctx: ScanContext, rel: str, cache: dict):
    """Parsed constant-flow analyser for a Python file, or None when it cannot be parsed."""
    if rel not in cache:
        flow = None
        if rel.endswith(".py"):
            try:
                with _warnings.catch_warnings():
                    _warnings.simplefilter("ignore")
                    src = ctx.read(rel)
                    flow = _PyFlow(_ast.parse(src)) if len(src) < 600_000 else None
            except (SyntaxError, ValueError, RecursionError):
                flow = None
        cache[rel] = flow
    return cache[rel]


# ---- JavaScript: operand classification (WEB-002 / WEB-005) -------------------------------
_JS_STR = r"""(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\$]|\\.|\$(?!\{))*`)"""
_JS_LIT_EXPR = re.compile(r"^\s*" + _JS_STR + r"(?:\s*\+\s*" + _JS_STR + r")*\s*$")
_JS_NUM = re.compile(r"^\s*-?\d+(?:\.\d+)?\s*$")
_JS_NUMERIC_CALL = re.compile(r"(?:^|[\s(])(?:Number|parseInt|parseFloat|Math\.\w+)\s*\(|\.(?:length|toFixed|size)\s*$|\.(?:toFixed)\s*\(")
# known HTML escapers / sanitizers (HTML sinks only); `_SANITIZED` above covers sanitize*/DOMPurify/escapeHtml/escape()
_JS_HTML_ESC = re.compile(r"(?<![\w$])(?:_\.escape|he\.(?:encode|escape)|encodeURI(?:Component)?|escapeAttr\w*|htmlEscape\w*|esc|"
                          r"escapeXml|escapeHTMLAttr)\s*\(")
# translation of a constant message id: t('key'), _('text'), i18n.t('k'), gettext('x'), $.i18n('x'), chrome.i18n.getMessage('x')
_JS_I18N = re.compile(r"""^\s*(?:\$\.i18n|(?:[\w$]+\.)*(?:i18n\.)?(?:t|_|__|tr|gettext|ngettext|translate|getMessage))\s*\(\s*"""
                      + _JS_STR + r"""(?:\s*,\s*""" + _JS_STR + r""")*\s*\)\s*$""")


def split_top(expr: str, sep: str) -> list[str]:
    """Split ``expr`` on top-level ``sep``, aware of strings, template literals and brackets."""
    out, depth, q, cur, i = [], 0, None, [], 0
    while i < len(expr):
        c = expr[i]
        if q:
            cur.append(c)
            if c == "\\" and i + 1 < len(expr):
                cur.append(expr[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif depth == 0 and expr.startswith(sep, i):
            out.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


_JS_HELPER_NAME = re.compile(r"(?:^|\.)(?:icon|svg_?icon|get_?icon|translate|__|_|t|\$t|tr|gettext|ngettext|trans|i18n\w*|l10n\w*)$"
                             r"|(?:^|\.)skeleton\w*(?:\.\w+)?$", re.I)


class JsConsts:
    """Per-file registry of names bound only to literal strings / literal tables (JS/TS)."""

    def __init__(self, text: str):
        self.text = text
        self._memo: dict = {}

    def _literal_decls(self, name: str):
        """All declarations of ``name``: list of RHS expression texts, or None if any declaration is not literal."""
        t, n = self.text, re.escape(name)
        decls = list(re.finditer(r"(?<![\w$.])(?:const|let|var)\s+" + n + r"\b(?!\s*[,)])\s*(?::[^=;\n]+)?=\s*", t))
        if not decls:
            return None
        # shadowing by parameters / destructuring / loop bindings makes the single declaration unreliable
        if re.search(r"\(\s*[^()]*(?<![\w$.])" + n + r"\b[^()]*\)\s*(?:=>|\{)|(?<![\w$.])" + n + r"\s*=>|"
                     r"(?:const|let|var)\s*[\[{][^=;]*\b" + n + r"\b[^=;]*[\]}]\s*=|\b(?:const|let|var)\s+[\w$]+\s*,\s*" + n + r"\b|"
                     r"\bfor\s*\(\s*(?:const|let|var)\s+" + n + r"\s+(?:of|in)\b|\bcatch\s*\(\s*" + n + r"\s*\)", t):
            return None
        rhs_all = []
        for m in decls:
            tail = t[m.end():m.end() + 6000]
            if tail.lstrip().startswith("{") or tail.lstrip().startswith("["):
                o = m.end() + (len(tail) - len(tail.lstrip()))
                rhs = call_span(t, o)
            else:
                lit = re.match(r"\s*" + _JS_STR + r"(?:\s*\+\s*" + _JS_STR + r")*", tail)
                if not lit:
                    return None
                rhs = lit.group(0)
            rhs_all.append(rhs)
        # re-assignments (let/var) of the name anywhere else
        if any(m for m in re.finditer(r"(?<![\w$.])" + n + r"\s*(?:[-+*/|&?]{0,2}=)(?![=>])", t)
               if not any(d.end() - 1 <= m.end() <= d.end() + 1 or d.start() <= m.start() < d.end() for d in decls)):
            return None
        return rhs_all

    def const_str(self, name: str) -> bool:
        k = ("s", name)
        if k not in self._memo:
            d = self._literal_decls(name)
            self._memo[k] = d is not None and all(_JS_LIT_EXPR.match(r) for r in d)
        return self._memo[k]

    def literal_table(self, name: str) -> bool:
        """`const T = { a: '<b>', c: 'x' }` / `['a','b']` : every value is a literal string/number."""
        k = ("t", name)
        if k not in self._memo:
            d = self._literal_decls(name)
            ok = d is not None
            for rhs in d or []:
                body = rhs.strip()[1:-1]
                for item in split_top(body, ","):
                    item = item.strip()
                    if not item:
                        continue
                    if rhs.strip().startswith("{"):
                        m = re.match(r"""(?:[\w$]+|'[^']*'|"[^"]*"|\[[^\]]*\])\s*:\s*(.+)$""", item, re.S)
                        item = m.group(1) if m else ""
                    if not (_JS_LIT_EXPR.match(item) or _JS_NUM.match(item)):
                        ok = False
            self._memo[k] = ok
        return self._memo[k]

    def operand_safe(self, op: str, html: bool, depth: int = 0) -> bool:
        """One operand of a concatenation/template is not attacker-influenced (or neutralised for an HTML sink)."""
        o = op.strip()
        while o.startswith("(") and o.endswith(")") and call_span(o, 0) == o:
            o = o[1:-1].strip()
        if o == "" or _JS_LIT_EXPR.match(o) and "${" not in o or _JS_NUM.match(o) or o in ("true", "false", "null", "undefined"):
            return True
        if depth > 6:
            return False
        if o.startswith("`"):   # template literal containing ${...}: each interpolation must be safe
            return self.template_safe(o, html, depth + 1)
        parts = split_top(o, "+")
        if len(parts) > 1:
            return all(self.operand_safe(p, html, depth + 1) for p in parts)
        q = self._ternary(o)
        if q:
            return all(self.operand_safe(p, html, depth + 1) for p in q)
        for sep in ("||", "??"):
            bits = split_top(o, sep)
            if len(bits) > 1:
                return all(self.operand_safe(b, html, depth + 1) for b in bits)
        if _JS_I18N.match(o) or self._literal_helper_call(o):
            return True
        if _JS_NUMERIC_CALL.search(o) and re.match(r"^(?:Number|parseInt|parseFloat|Math\.\w+)\s*\(.*\)$|^[\w$.\[\]]+\.(?:length|size)$|^[\w$.\[\]()]+\.toFixed\([^)]*\)$", o, re.S):
            return True
        if html and (_SANITIZED.search(o) or _JS_HTML_ESC.search(o)):
            return True
        if re.match(r"^[A-Za-z_$][\w$]*$", o) and self.const_str(o):
            return True
        m = re.match(r"^([A-Za-z_$][\w$]*)\s*(?:\[[^\]]+\]|\.[A-Za-z_$][\w$]*)$", o)
        return bool(m) and self.literal_table(m.group(1))

    @staticmethod
    def _literal_helper_call(o: str) -> bool:
        """`frappe.utils.icon('x', 'sm')`, `await translate('msg')`, `frappe.ui.skeleton.html({width: '40%'})`: a
        render/translation/icon helper whose arguments are ALL literals returns constant markup. Only helper
        families that cannot read request data qualify (reader-style names such as getItem/get/val stay unsafe)."""
        s = re.sub(r"^await\s+", "", o.strip())
        m = re.match(r"^((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)\s*\(", s)
        if not m:
            return False
        name = m.group(1)
        if not _JS_HELPER_NAME.search(name):
            return False
        span = call_span(s, m.end() - 1)
        if s[m.end() - 1:] != span:
            return False
        for a in split_top(span[1:-1], ","):
            a = a.strip()
            if not a:
                continue
            if a.startswith("{") and a.endswith("}"):
                for item in split_top(a[1:-1], ","):
                    mm = re.match(r"""^\s*(?:[\w$]+|'[^']*'|"[^"]*")\s*:\s*(.+)$""", item.strip(), re.S)
                    if item.strip() and not (mm and (_JS_LIT_EXPR.match(mm.group(1)) or _JS_NUM.match(mm.group(1))
                                                     or mm.group(1).strip() in ("true", "false", "null"))):
                        return False
            elif not (_JS_LIT_EXPR.match(a) or _JS_NUM.match(a) or a in ("true", "false", "null")):
                return False
        return True

    @staticmethod
    def _ternary(o: str):
        depth, q, i, qi = 0, None, 0, -1
        while i < len(o):
            c = o[i]
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
                depth -= 1
            elif c == "?" and depth == 0 and o[i + 1:i + 2] not in (".", "?") and o[i - 1:i] != "?":
                qi = i
                break
            i += 1
        if qi < 0:
            return None
        rest = o[qi + 1:]
        # split on the first top-level ':' (nested ternaries are not decomposed: they stay unsafe)
        cut = None
        depth, q = 0, None
        for j, c in enumerate(rest):
            if q:
                if c == q:
                    q = None
            elif c in "\"'`":
                q = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ":" and depth == 0:
                cut = j
                break
        if cut is None:
            return None
        return [rest[:cut], rest[cut + 1:]]

    def template_safe(self, o: str, html: bool, depth: int = 0) -> bool:
        # extract ${ ... } bodies with brace matching
        i = 0
        while True:
            i = o.find("${", i)
            if i < 0:
                return True
            j, d = i + 2, 1
            while j < len(o) and d:
                d += (o[j] == "{") - (o[j] == "}")
                j += 1
            if d or not self.operand_safe(o[i + 2:j - 1], html, depth + 1):
                return False
            i = j

    def expr_safe(self, rhs: str, html: bool) -> bool:
        return self.operand_safe(rhs.strip().rstrip(";"), html)


# --------------------------------------------------------------------------------------
# WEB-002  DOM XSS sinks
# --------------------------------------------------------------------------------------
_SANITIZED = re.compile(r"sanitiz|DOMPurify|escapeHtml|escapeHTML|encodeHTML|\bescape\s*\(|textContent|trusted|\bsafe", re.I)


_TERNARY_LIT = re.compile(r"^.+\?\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*:\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*;?\s*$")


_LIT_CONCAT_ALL = re.compile(r"^\s*(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")(?:\s*\+\s*(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"))*\s*;?\s*$")


PHP_JAVA_GLOBS = ["*.php", "*.phtml", "*.inc", "*.java", "*.jsp", "*.jspx"]


def php_java_obs(ctx: ScanContext, rule_id: str, files: list[str], skip: "dict[str, set[int]] | None" = None) -> list[Observation]:
    """Request-taint based PHP/Java/JSP findings (see web_php_java), minus lines another detector already reported."""
    obs: list[Observation] = []
    for rel in files:
        kind = _pj.kind_of(rel)
        if not kind:
            continue
        seen = (skip or {}).get(rel, set())
        for line, detail, via in _pj.analyze(ctx.read(rel), kind)[rule_id]:
            if line in seen or (via and all(any(l in seen for l in range(a, b + 1)) for a, b in via)):
                continue
            obs.append(Observation(rel, line, detail))
    return obs


_PT_JS_GLOBS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"]
_PT_TEMPLATE_GLOBS = ["*.html", "*.htm", "*.jinja", "*.jinja2", "*.j2", "*.tmpl"]


def _pt_cache(ctx: ScanContext) -> dict:
    c = getattr(ctx, "_pyts_cache", None)
    if c is None:
        c = ctx._pyts_cache = {}    # type: ignore[attr-defined]
    return c


def py_ts_obs(ctx: ScanContext, rule_id: str, skip: "dict[str, set[int]] | None" = None, ci_skip: bool = False) -> list[Observation]:
    """Request-taint based Python / TypeScript / JavaScript findings (see web_python_ts), minus lines another
    detector already reported (or whose construction lines it already reported)."""
    cache = _pt_cache(ctx)
    obs: list[Observation] = []
    files = non_test(sel(ctx, *PY_GLOBS, *_PT_JS_GLOBS))
    for rel in files:
        if ci_skip and _CI_PATH.search(rel):
            continue
        key = ("a", rel)
        if key not in cache:
            text = ctx.read(rel)
            cache[key] = _pt.analyze_py(text) if rel.endswith(".py") else _pt.analyze_js(text, rel)
        seen = (skip or {}).get(rel, set())
        for line, detail, via in cache[key][rule_id]:
            if line in seen or any(l in seen for a, b in via for l in range(a, b + 1)):
                continue
            obs.append(Observation(rel, line, detail))
    if rule_id == "SEC-WEB-002":
        obs += _pt_template_obs(ctx, cache, skip)
    return obs


def _pt_template_obs(ctx: ScanContext, cache: dict, skip) -> list[Observation]:
    tmpl = non_test(sel(ctx, *_PT_TEMPLATE_GLOBS))
    if not tmpl:
        return []
    if "keys" not in cache:
        keys: set = set()
        for rel in non_test(sel(ctx, *PY_GLOBS)):
            text = ctx.read(rel)
            if "render" in text or "TemplateResponse" in text:
                keys |= _pt.view_context_keys(text)
        cache["keys"] = keys
    obs = []
    for rel in tmpl:
        text = ctx.read(rel)
        if "|safe" not in text and "[innerHTML]" not in text and "[outerHTML]" not in text:
            continue
        sib = ""
        if rel.endswith(".component.html"):
            ts = rel[:-5] + ".ts"
            try:
                sib = ctx.read(ts)
            except PermissionError:
                sib = ""
        seen = (skip or {}).get(rel, set())
        for line, detail in _pt.analyze_template(text, rel, sib, cache["keys"]):
            if line not in seen:
                obs.append(Observation(rel, line, detail))
    return obs


_EJS_SAFE = re.compile(r"^\s*(?:include|partial|layout|body|content|contentFor|yield|block|style|script|stylesheet|"
                       r"title|meta|_?csrf\w*)\b|\b(?:include|partial|render)\s*\(", re.I)


@rule("SEC-WEB-002")
def web_002(ctx: ScanContext):
    files = non_test(sel(ctx, *JS_GLOBS, "*.ejs"))
    pj = non_test(sel(ctx, *PHP_JAVA_GLOBS))
    if not files and not pj and not sel(ctx, *PY_GLOBS):
        return None
    obs: list[Observation] = php_java_obs(ctx, "SEC-WEB-002", pj)
    inner = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*(.*)$")
    write = re.compile(r"\bdocument\.(?:write|writeln)\s*\((.*)$")
    adj = re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,)]+,\s*(.*)$")
    dang = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*(.*)$")
    vhtml = re.compile(r"""\bv-html\s*=\s*(["'])(.*?)\1""")
    for rel in files:
        ctext = read_clean(ctx, rel)
        lines_ = ctext.split("\n")
        consts = JsConsts(ctext)
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
                    if re.match(r"^\s*[\w$.\[\]]+\.(?:outerHTML|innerHTML)\s*;?\s*$", rhs):
                        continue  # DOM-to-DOM copy of an existing node's serialisation
                # Operand-wise analysis (see JsConsts.operand_safe): every operand of the concatenation/template
                # must be a literal, a number, a known escaper/sanitizer call, a translation of a constant message,
                # a const bound to a literal, or a lookup in a literal table. One unsafe operand still reports.
                if is_literal(rhs) or _TERNARY_LIT.match(rhs) or consts.expr_safe(rhs, html=True):
                    continue
                obs.append(Observation(rel, i, f"{name} receives a non-literal, unsanitized value"))
                break
            else:
                m = vhtml.search(line)
                if m and not is_literal(m.group(2)) and not consts.expr_safe(m.group(2), html=True):
                    obs.append(Observation(rel, i, "v-html renders a non-literal, unsanitized expression"))
                if rel.endswith(".svelte"):
                    for sm in re.finditer(r"\{@html\s+([^{}]+?)\s*\}", line):
                        if not is_literal(sm.group(1)) and not consts.expr_safe(sm.group(1), html=True):
                            obs.append(Observation(rel, i, "{@html} renders a non-literal, unsanitized expression"))
                            break
                elif rel.endswith(".ejs"):
                    for em in re.finditer(r"<%-\s*([^%]+?)\s*-?%>", line):
                        ex = em.group(1)
                        if _EJS_SAFE.search(ex) or is_literal(ex) or consts.expr_safe(ex, html=True):
                            continue
                        obs.append(Observation(rel, i, "EJS unescaped output <%- %> of a non-literal expression"))
                        break
    sk: dict[str, set[int]] = {}
    for o in obs:
        sk.setdefault(o.file, set()).add(o.line)
    obs += py_ts_obs(ctx, "SEC-WEB-002", sk)
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


_CI_PATH = re.compile(r"(?:^|/)\.(?:github|gitlab|circleci)/")
_REQ_SRC = re.compile(r"\b(?:req|request)\.(?:body|query|params|headers|cookies)\b")


@rule("SEC-WEB-005")
def web_005(ctx: ScanContext):
    js = [f for f in non_test(sel(ctx, *JS_GLOBS)) if not _CI_PATH.search(f)]
    py = [f for f in non_test(sel(ctx, *PY_GLOBS)) if not _CI_PATH.search(f)]   # CI helper scripts are not request-reachable
    pj = non_test(sel(ctx, *PHP_JAVA_GLOBS))
    if not js and not py and not pj:
        return None
    obs: list[Observation] = php_java_obs(ctx, "SEC-WEB-005", pj)
    flows: dict = {}

    def js_definition(text, m, span):
        """`eval(code) {` / `async exec(cmd) {` at the start of a line is a method definition, not a call."""
        ls = text.rfind("\n", 0, m.start()) + 1
        after = text[m.end() - 1 + len(span):][:200]
        return bool(re.match(r"^\s*(?:(?:async|static|public|private|protected|get|set)\s+)*$", text[ls:m.start()])
                    and re.match(r"\s*(?::\s*[\w<>\[\]|. ]+)?\s*\{", after))

    def py_const(rel, line, names, shell, pick):
        """Python sink whose command/code argument is provably constant by local dataflow (see _PyFlow)."""
        flow = py_flow(ctx, rel, flows)
        calls = flow.calls_at(line, names) if flow else []
        return bool(calls) and all(pick(c) is not None and flow.safe(pick(c), shell=shell) for c in calls)

    first = lambda c: c.args[0] if c.args else next((k.value for k in c.keywords if k.arg in ("args", "command")), None)   # noqa: E731
    for rel in js:
        text = read_clean(ctx, rel)
        consts = JsConsts(text)
        for m in re.finditer(r"(?<![\w.$])(?<!function )eval\s*\(", text):
            span = call_span(text, m.end() - 1)
            if js_definition(text, m, span):
                continue
            if not is_literal(span[1:-1]) and _untrusted_expr(span[1:-1], _JS_DYN) \
                    and not consts.expr_safe(span[1:-1], html=False):
                obs.append(Observation(rel, line_of(text, m.start()), "eval() with non-literal argument"))
        for m in re.finditer(r"(?<=[\w$])\.(?:eval|evaluate|runInNewContext|runInThisContext)\s*\(", text):
            span = call_span(text, m.end() - 1)   # `mathjs.eval(req.body.expr)`: request data straight into an evaluator
            if _REQ_SRC.search(span) and not js_definition(text, m, span):
                obs.append(Observation(rel, line_of(text, m.start()), "expression/code evaluator fed request data"))
        for m in re.finditer(r"\bnew\s+Function\s*\(", text):
            span = call_span(text, m.end() - 1)
            if not all(is_literal(p) for p in span[1:-1].split(",")) \
                    and not all(consts.expr_safe(p, html=False) for p in split_top(span[1:-1], ",")):
                obs.append(Observation(rel, line_of(text, m.start()), "new Function() built from non-literal input"))
        for m in re.finditer(r"(?<![\w.$])(?:exec|execSync)\s*\(|\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\(", text):
            span = call_span(text, m.end() - 1)
            fa = first_arg(span)
            if js_definition(text, m, span):
                continue
            if not fa.lstrip().startswith("{") and _JS_DYN.search(fa) and not consts.expr_safe(fa, html=False):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "child_process exec with concatenated/templated command string"))
    for rel in py:
        text = read_clean(ctx, rel)
        for m in re.finditer(r"\bos\.(?:system|popen)\s*\(", text):
            span = call_span(text, m.end() - 1)
            if _PY_DYN.search(span) and not _LIT_CONCAT.match(span[1:-1]) \
                    and not py_const(rel, line_of(text, m.start()), ("os.system", "os.popen"), True, first):
                obs.append(Observation(rel, line_of(text, m.start()), "os.system/popen with dynamically built command"))
        for m in re.finditer(r"\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(", text):
            span = call_span(text, m.end() - 1)
            if re.search(r"shell\s*=\s*True", span) and _PY_DYN.search(span) and not _LIT_CONCAT.match(span[1:-1]) \
                    and not py_const(rel, line_of(text, m.start()), tuple("subprocess." + f for f in (
                        "run", "call", "check_output", "check_call", "Popen")), True, first):
                obs.append(Observation(rel, line_of(text, m.start()),
                                       "subprocess with shell=True and dynamically built command"))
        for m in re.finditer(r"(?<![\w.])(?<!def )(?:eval|exec)\s*\(", text):
            span = call_span(text, m.end() - 1)
            fa = first_arg(span)
            if not is_literal(fa) and _untrusted_expr(fa, _PY_DYN) \
                    and not py_const(rel, line_of(text, m.start()), ("eval", "exec"), False, first):
                obs.append(Observation(rel, line_of(text, m.start()), "eval/exec with non-literal argument"))
    sk: dict[str, set[int]] = {}
    for o in obs:
        sk.setdefault(o.file, set()).add(o.line)
    obs += py_ts_obs(ctx, "SEC-WEB-005", sk, ci_skip=True)
    return result(obs)


# --------------------------------------------------------------------------------------
# WEB-006  SQL built by string building
# --------------------------------------------------------------------------------------
_SEL_COL = r"""[\w.`"\[\]*]+(?:\([^)]*\))?(?:\s+AS\s+\w+)?"""
_SQL_KW = re.compile(r"""(?i)["'`]\s*(?:SELECT\s+(?:DISTINCT\s+)?""" + _SEL_COL + r"""(?:\s*,\s*""" + _SEL_COL + r""")*\s+FROM\s|INSERT\s+INTO\s|UPDATE\s+\w+\s+SET\s|DELETE\s+FROM\s)""")
_SQL_DYN = re.compile(r"""\bf"[^"]*\{|\bf'[^']*\{|["']\s*\+\s*(?:[\w(]|$)|[\w)]\s*\+\s*["']|\.format\(|["']\s*%\s+[\w(]|["']\s*%\(|\$\{""")


_IDENT_HELPER = r"(?:get_\w*name\w*\(|quote_\w+\(|\bqn\(|escape_identifier|quoted_name)"
_DDL_CTX = re.compile(r"(?i)\b(?:CREATE|ALTER|DROP|TRIGGER|PRAGMA|REINDEX|VACUUM|ATTACH|DETACH|RENAME)\b")
_WRAP_NAME = re.compile(r"(?i)(?:^|[_.])(?:\w*sql|\w*query|subquery|compiled\w*|placeholder_rows|rows_sql)$")


def _compiled_sql_wrap(line: str) -> bool:
    """`"SELECT * FROM ({})".format(part_sql)` / `f"SELECT * FROM {placeholder_rows}"` / `"... (%s) subquery" % sql`:
    the ONLY dynamic piece is a whole compiled statement/derived table (name evidence: *_sql, *query, compiled*)."""
    m = re.search(r"""(?i)["']\s*SELECT\s+\*\s+FROM\s+\(?\s*(?:\{(\w*)\}|%s)\s*\)?(?:\s+\w+)?\s*["']""", line)
    if not m:
        return False
    if m.group(1):   # f-string `{name}`
        return bool(_WRAP_NAME.search(m.group(1))) and line.count("{") == 1
    fm = re.search(r"\.format\(\s*([\w.]+)\s*\)", line)
    pm = re.search(r"""["']\s*%\s*([\w.]+)\s*[,)]?""", line)
    name = (fm or pm).group(1) if (fm or pm) else ""
    return bool(_WRAP_NAME.search(name)) and line.count("{") <= 1


@rule("SEC-WEB-006")
def web_006(ctx: ScanContext):
    files = non_test(sel(ctx, *CODE_GLOBS, *OTHER_SRC_GLOBS))
    if not files:
        return None
    flows: dict = {}

    def chk(line, m, ls, i, rel):
        kw = re.search(r"[A-Za-z]+", m.group(0)).group(0)
        if len(kw) > 1 and kw[0].isupper() and kw[1:].islower():
            return None  # Title-case "Select ..."/"Delete from ..." is prose, not SQL
        if re.search(r"quote_name|quote_ident|escape_identifier|quoted_name|\bquote\(", line):
            return None  # identifier passed through the driver's quoting helper
        if re.search(r"noqa:\s*(?:[A-Z]\d+\s*,\s*)*S608|#\s*nosec\b", line):
            return None  # author acknowledged the dynamic statement (bandit B608 / ruff S608 suppression)
        if _compiled_sql_wrap(line):
            return None  # `SELECT * FROM ({compiled_sql})`: wraps an already-compiled statement, params bound separately
        stripped = re.sub(r"\$\{[A-Z][A-Z0-9_.]*\}|\{[A-Z][A-Z0-9_]*\}", "", line)  # constant interpolation
        # identifier position + explicit identifier-helper evidence (quoted/validated helper call): not injectable
        stripped = re.sub(r"(?i)\b(FROM|INTO|UPDATE|TABLE|JOIN|ON|TRIGGER|INDEX)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?\{[^{}]*" + _IDENT_HELPER + r"[^{}]*\}",
                          r"\1 X", stripped)
        if _DDL_CTX.search(line):   # DDL/PRAGMA/TRIGGER: identifiers cannot be bound; accept only evidenced identifiers
            stripped = re.sub(r"\{[^{}]*(?:" + _IDENT_HELPER + r"|\b\w*_table(?:_name)?\b|\btable_?name\b|\bcolumn_?name\b|"
                              r"\bindex_?name\b|\btrigger_?name\b|\bschema_?name\b)[^{}]*\}", "", stripped)
        # identifiers cannot be bound as parameters: `FROM {self.table_name}` / `FROM %s" % table`
        stripped = re.sub(r"(?i)\b(FROM|INTO|UPDATE|TABLE|JOIN)\s+(?:\$?\{[^{}]*(?:table|tbl|schema)[^{}]*\}"
                          r"|%s[\"']?\s*%\s*\(?\s*[\w.]*(?:table|tbl)\w*\s*,?\s*\)?)", r"\1 X", stripped)
        if _SQL_DYN.search(stripped):
            if rel.endswith(".java") and not _pj.java_line_dynamic(line, ctx.read(rel)):
                return None   # every concatenated operand is a constant / numeric-typed / parsed value
            # Python: every interpolated fragment provably constant / closed-set by local dataflow => not injectable
            flow = py_flow(ctx, rel, flows)
            return not (flow and flow.sql_safe(i + 1))
        # PHP: "..." . $var concatenation / "$var" interpolation
        # identifier-only interpolation (table-name helpers, `{$this->table}`) is not injectable: see web_php_java.php_line_dynamic
        return (rel.endswith(".php") and bool(re.search(r"[\"']\s*\.\s*\$\w|\"[^\"]*\$\w+", line))
                and _pj.php_line_dynamic(line, ctx.read(rel)))
    obs = scan_lines(ctx, files, _SQL_KW, check=chk,
                     detail="SQL statement built with string concatenation/interpolation")
    seen: dict[str, set[int]] = {}
    for o in obs:
        seen.setdefault(o.file, set()).add(o.line)
    obs += php_java_obs(ctx, "SEC-WEB-006", [f for f in files if _pj.kind_of(f)], seen)
    obs += py_ts_obs(ctx, "SEC-WEB-006", seen)
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
