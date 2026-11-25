"""Python / TypeScript / JavaScript request-taint detectors for SEC-WEB-002 (XSS/SSTI), SEC-WEB-005 (command/code
execution) and SEC-WEB-006 (SQL / NoSQL injection).

Precision-first and deterministic; no third-party parser:

* Python files are parsed with :mod:`ast`; taint is tracked per function (flow-insensitive, two sweeps) from
  Flask/Django/FastAPI/aiohttp/tornado/http.server request sources and route-handler parameters;
* TS/JS files are tokenised (strings, template literals, comments) and the same-function assignment graph is
  followed from ``req.body/query/params`` style sources and handler parameters.

A sink is reported only when a *tainted* operand reaches it NOT wrapped in a neutraliser (int(), shlex.quote,
html escape, ...) or, for SQL only, when an SQL-looking literal is combined with a clearly dynamic function
parameter in a value position. Constants, bound parameters, closed-set lookups and validated values are never
reported. Files are only read by the caller.
"""
from __future__ import annotations

import ast
import re

RULE_IDS = ("SEC-WEB-002", "SEC-WEB-005", "SEC-WEB-006")


def _empty() -> dict[str, list]:
    return {r: [] for r in RULE_IDS}


# =====================================================================================================
# Python
# =====================================================================================================
_REQ_ROOTS = {"request", "req"}
_REQ_ATTRS = {"args", "form", "values", "json", "cookies", "headers", "data", "files", "GET", "POST", "COOKIES",
              "META", "body", "query_params", "path_params", "query_string", "view_args", "environ", "query",
              "match_info", "rel_url", "url", "path", "full_path", "base_url", "host_url", "params", "matchdict",
              "media", "forms", "get_json", "post", "text", "read", "stream", "get_param", "arguments", "raw_uri",
              "query_arguments", "body_arguments"}
_SELF_SRC_CALLS = {"get_argument", "get_query_argument", "get_body_argument", "get_arguments", "get_cookie",
                   "get_secure_cookie", "get_query_arguments", "get_body_arguments"}
_HANDLER_DECOR = {"route", "get", "post", "put", "delete", "patch", "head", "options", "api_route", "websocket",
                  "errorhandler", "exception_handler", "view_config"}
_OBJ_PARAM = re.compile(r"^(?:\w|\w\w|obj|object|instance|model|form|formset|queryset|qs|template|item|entry|record|row)$")
_SAFE_PARAM_NAME = re.compile(r"^(?:self|cls|request|req|response|resp|db|session|conn|connection|cursor|engine|"
                              r"background_tasks|current_user|user|app|ctx|context|logger|settings|config|"
                              r"id|pk|uid|page|page_size|limit|offset|skip|n|count|year|month|day|\w+_id|\w+_pk|\w+_ids?)$")
_SAFE_ANN = re.compile(r"^(?:Optional\[)?(?:int|float|bool|UUID|uuid\.UUID|Decimal|date|datetime|time|timedelta|"
                       r"Request|Response|Session|AsyncSession|Connection|BackgroundTasks|HTTPConnection|WebSocket|"
                       r"UploadFile|conint\(.*\)|PositiveInt|NonNegativeInt)\]?$")
_NUM_CALLS = {"int", "float", "bool", "len", "abs", "round", "ord", "chr", "hash", "Decimal", "UUID", "uuid4",
              "min", "max", "sum", "isinstance", "secure_filename", "slugify", "hexdigest", "digest", "intval"}
_BOOL_ATTRS = {"isdigit", "isnumeric", "isalnum", "isidentifier", "isalpha", "isdecimal", "startswith", "endswith",
               "count", "isoformat", "strftime", "total_seconds", "timestamp", "keys", "bit_length"}
_ESCAPERS = {"escape", "e", "esc", "html_escape", "escape_html", "conditional_escape", "format_html", "strip_tags",
             "force_escape", "escapejs", "sanitize", "sanitize_html", "clean_html", "urlquote", "quote", "quote_plus",
             "urlencode", "json_script", "linebreaks", "urlize", "shlex_quote", "list2cmdline", "escapeshellarg",
             "identifier", "literal", "placeholder", "quote_ident", "escape_string", "escape_identifier", "quote_name",
             "quote_identifier", "bindparam", "quote_literal", "escape_literal", "real_escape_string", "quoted_name",
             "mogrify", "adapt"}
_QUALIFIED_ESCAPERS = {"shlex.split", "bleach.clean", "nh3.clean", "markupsafe.escape", "html.escape", "cgi.escape", "shlex.join",
                       "shlex.quote", "pipes.quote"}
_IDENT_NAME = re.compile(r"(?i)(?:table|tbl|column|col|schema|index|ident|order|sort|direction|fields|columns|"
                         r"placeholder|clause|conditions?|joins?|limit|offset)")
_SQL_WORD = re.compile(r"(?is)\b(?:select\b.+\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|"
                       r"where\s+\S+\s*(?:=|like|in)\b|values\s*\(|order\s+by|group\s+by|union\s+select)")
_SQL_SINK_ATTRS = {"execute", "executemany", "executescript", "raw", "exec_driver_sql", "read_sql", "read_sql_query"}
_HTMLISH = re.compile(r"<\s*[a-zA-Z/!]")
_PROC_SHELL_ALWAYS = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput",
                      "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
                      "os.popen2", "os.popen3"}
_DESERIAL = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "dill.load",
             "marshal.loads", "jsonpickle.decode", "cloudpickle.loads", "_pickle.loads"}
_STR_METHODS = {"format", "join", "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "replace", "encode",
                "decode", "split", "rsplit", "splitlines", "get", "getlist", "items", "values", "copy", "group", "groups",
                "groupdict", "read", "readline", "readlines", "text", "format_map", "casefold", "swapcase", "zfill",
                "ljust", "rjust", "center", "expandtabs", "partition", "rpartition", "removeprefix", "removesuffix",
                "__getitem__", "pop", "setdefault", "getvalue", "to_dict"}
_PASS_THROUGH = {"str", "bytes", "bytearray", "list", "dict", "tuple", "set", "sorted", "reversed", "iter", "next",
                 "enumerate", "zip", "map", "filter", "repr", "format", "unquote", "unquote_plus", "unquote_to_bytes",
                 "urlparse", "urlsplit", "parse_qs", "parse_qsl", "b64decode", "urlsafe_b64decode", "loads", "load",
                 "search", "match", "fullmatch", "findall", "finditer", "split", "sub", "subn", "open", "copy",
                 "deepcopy", "fromstring", "to_str", "force_str", "force_text", "smart_str", "ensure_str", "dumps",
                 "join", "BytesIO", "StringIO", "TextIOWrapper", "lower", "upper", "strip", "decode", "encode",
                 "dict_items", "ChainMap", "OrderedDict", "defaultdict", "frozenset", "slice"}
_NOSEC = re.compile(r"#\s*nosec\b|noqa:\s*(?:[A-Z]\d+\s*,\s*)*(?:S608|S602|S605|S307)")
_VALUE_PLACEHOLDER = re.compile(r"""'%(?:\(\w+\))?s'|=\s*%(?:\(\w+\))?s|(?i:like)\s+%(?:\(\w+\))?s|"""
                                r"""'\{\w*\}'|=\s*\{\w*\}""")


def _dotted(n: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    elif isinstance(n, ast.Call):
        parts.append(_dotted(n.func) + "()")
    return ".".join(reversed(parts))


def _last(n: ast.AST) -> str:
    if isinstance(n, ast.Attribute):
        return n.attr
    if isinstance(n, ast.Name):
        return n.id
    return ""


def _is_literal_container(n: ast.AST) -> bool:
    return all(isinstance(x, (ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Load, ast.UnaryOp, ast.USub,
                              ast.UAdd)) for x in ast.walk(n))


def _kind_of(k: set[str]) -> str:
    return "req" if "req" in k else sorted(k)[0]


class _Fn:
    """Taint state of one function scope (flow-insensitive)."""

    def __init__(self, parent: "_Fn | None", imports: str):
        self.taint: dict[str, str] = dict(parent.taint) if parent else {}
        self.defs: dict[str, list[ast.AST]] = {k: list(v) for k, v in parent.defs.items()} if parent else {}
        self.validated: set[str] = set(parent.validated) if parent else set()
        self.cls_http = parent.cls_http if parent else False
        self.flask_like = False
        self.imports = imports

    # ---- taint of an expression: set of kinds ('req', 'param', 'exc') that survive -------------------------
    def kinds(self, n) -> set[str]:
        if n is None or isinstance(n, ast.Constant):
            return set()
        if isinstance(n, ast.Name):
            if n.id in self.validated:
                return set()
            k = self.taint.get(n.id)
            return {k} if k else set()
        if isinstance(n, (ast.Attribute, ast.Subscript, ast.Call)) and self._is_source(n):
            return {"req"}
        if isinstance(n, ast.Attribute):
            return self.kinds(n.value)
        if isinstance(n, ast.Subscript):
            if _is_literal_container(n.value) or (isinstance(n.value, ast.Name) and n.value.id.isupper()):
                return set()   # lookup in a literal / ALL_CAPS constant table => closed set
            return self.kinds(n.value)
        if isinstance(n, ast.JoinedStr):
            out: set[str] = set()
            for v in n.values:
                if isinstance(v, ast.FormattedValue):
                    spec = v.format_spec
                    if isinstance(spec, ast.JoinedStr) and spec.values and isinstance(spec.values[0], ast.Constant) \
                            and re.search(r"[dfeEgGxXobn%]$", str(spec.values[0].value)):
                        continue   # numeric format spec
                    out |= self.kinds(v.value)
            return out
        if isinstance(n, ast.BinOp):
            if isinstance(n.op, (ast.Add, ast.Mod)):
                return self.kinds(n.left) | self.kinds(n.right)
            return set()   # arithmetic / repetition
        if isinstance(n, ast.BoolOp):
            return set().union(*[self.kinds(v) for v in n.values])
        if isinstance(n, ast.IfExp):
            return self.kinds(n.body) | self.kinds(n.orelse)
        if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
            return set().union(*[self.kinds(v) for v in n.elts])
        if isinstance(n, ast.Dict):
            return set().union(*[self.kinds(v) for v in n.values if v is not None])
        if isinstance(n, (ast.Await, ast.Starred, ast.NamedExpr)):
            return self.kinds(n.value)
        if isinstance(n, ast.Lambda):
            return self.kinds(n.body)
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comp(n.generators, n.elt)
        if isinstance(n, ast.DictComp):
            return self._comp(n.generators, n.value)
        if isinstance(n, ast.Call):
            return self._call_kinds(n)
        return set()   # Compare, Lambda, UnaryOp ...

    def _comp(self, gens, elt) -> set[str]:
        """Comprehension: the element expression is evaluated with the loop targets carrying the iterable's taint, so
        `[escape(x) for x in tainted]` stays clean while `[x for x in tainted]` is tainted."""
        saved = dict(self.taint)
        try:
            for g in gens:
                k = self.kinds(g.iter)
                for t in ast.walk(g.target):
                    if isinstance(t, ast.Name):
                        if k:
                            self.taint[t.id] = _kind_of(k)
                        else:
                            self.taint.pop(t.id, None)
            return self.kinds(elt)
        finally:
            self.taint = saved

    def _call_kinds(self, n: ast.Call) -> set[str]:
        name, dotted = _last(n.func), _dotted(n.func)
        if name in _NUM_CALLS or name in _BOOL_ATTRS or name.lower() in _ESCAPERS or dotted in _QUALIFIED_ESCAPERS:
            return set()
        if "objects" in dotted.split(".") or name in ("get_object_or_404", "get_list_or_404", "get_or_create", "filter_by"):
            return set()   # ORM lookups return model rows, not request data
        if name == "sub" and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) \
                and n.args[0].value.startswith("[^"):
            return set()   # allow-list stripping: re.sub(r"[^\w]", "", x)
        out: set[str] = set()
        if isinstance(n.func, ast.Attribute):
            out |= self.kinds(n.func.value)     # method on a tainted receiver: str/dict/regex-match style pass-through
        if name in _PASS_THROUGH or dotted in _PASS_THROUGH or (isinstance(n.func, ast.Attribute) and name in ("format", "join", "replace", "format_map", "ljust", "rjust", "center", "zfill")):
            for a in n.args:
                out |= self.kinds(a)
            for k in n.keywords:
                out |= self.kinds(k.value)
        if "param" in out and "req" not in out and name not in _PASS_THROUGH and name not in _STR_METHODS:
            out.discard("param")   # weak (plain function-argument) taint only flows through string plumbing
        return out

    def _is_source(self, n) -> bool:
        """`request.args`, `request.args.get('x')`, `request.form['x']`, `request.GET`, `self.get_argument()` ..."""
        cur, chain = n, []
        while True:
            if isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            elif isinstance(cur, (ast.Subscript, ast.Await)):
                cur = cur.value
            elif isinstance(cur, ast.Call):
                cur = cur.func
            else:
                break
        chain.reverse()
        if not isinstance(cur, ast.Name):
            return False
        if cur.id in _REQ_ROOTS and chain and chain[0] in _REQ_ATTRS:
            return True
        if cur.id == "self" and chain:
            if chain[0] in _SELF_SRC_CALLS and isinstance(n, ast.Call):
                return True
            if chain[0] == "request" and len(chain) > 1 and chain[1] in _REQ_ATTRS:
                return True
            if self.cls_http and chain[0] in ("path", "headers", "rfile"):
                return True
        if cur.id == "flask" and len(chain) > 1 and chain[0] == "request":
            return True
        return False

    # ---- statement-level propagation -------------------------------------------------------------------------
    def assign(self, target, value) -> None:
        k = self.kinds(value)
        if isinstance(target, ast.Name):
            if target.id in self.validated:
                return
            if k:
                self.taint[target.id] = _kind_of(k)
            self.defs.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) \
                    and not any(isinstance(e, ast.Starred) for e in target.elts + value.elts):
                for t, v in zip(target.elts, value.elts):
                    self.assign(t, v)
            else:
                for t in target.elts:
                    self.assign(t.value if isinstance(t, ast.Starred) else t, value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and k:
            self.taint.setdefault(target.value.id, _kind_of(k))


def _decor_is_route(d: ast.AST) -> bool:
    f = d.func if isinstance(d, ast.Call) else d
    return isinstance(f, ast.Attribute) and f.attr in _HANDLER_DECOR and isinstance(d, ast.Call)


def _unparse(a) -> str:
    try:
        return ast.unparse(a) if a is not None else ""
    except Exception:   # pragma: no cover
        return ""


def _seed_params(fn: _Fn, node, strong: bool, route: bool = True) -> None:
    a = node.args
    pos = list(a.posonlyargs) + list(a.args)
    defaults = dict(zip([p.arg for p in pos[len(pos) - len(a.defaults):]], a.defaults))
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        if d is not None:
            defaults[arg.arg] = d
    if len(pos) >= 2 and pos[0].arg == "event" and pos[1].arg in ("context", "ctx", "_context"):
        fn.taint["event"] = "req"   # AWS-Lambda style handler(event, context): the event is the request
    for arg in pos + list(a.kwonlyargs):
        nm, ann, dtxt = arg.arg, _unparse(arg.annotation), _unparse(defaults.get(arg.arg))
        explicit = re.match(r"(?:Query|Path|Body|Form|Header|Cookie)\(", dtxt)
        if (_SAFE_PARAM_NAME.match(nm) and not explicit) or (not route and _OBJ_PARAM.match(nm) and not explicit) or _SAFE_ANN.match(ann) or re.match(r"(?:Depends|Security)\(", dtxt):
            continue
        fn.taint[nm] = "req" if strong else "param"
    if strong:
        for va in (a.vararg, a.kwarg):
            if va is not None:
                fn.taint[va.arg] = "req"


def _validated_names(node) -> set[str]:
    """Names checked against a closed set / numeric / regex guard anywhere in the function (flow-insensitive)."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and len(n.ops) == 1 \
                and isinstance(n.ops[0], (ast.In, ast.NotIn)):
            c = n.comparators[0]
            if (isinstance(c, (ast.Tuple, ast.List, ast.Set)) and c.elts and all(isinstance(e, ast.Constant) for e in c.elts)) \
                    or (isinstance(c, ast.Name) and c.id.isupper()) or (isinstance(c, ast.Attribute) and c.attr.isupper()):
                out.add(n.left.id)
        if isinstance(n, ast.Call):
            f = _last(n.func)
            if f in ("isdigit", "isnumeric", "isalnum", "isidentifier", "isdecimal") and isinstance(n.func, ast.Attribute) \
                    and isinstance(n.func.value, ast.Name):
                out.add(n.func.value.id)
            elif f in ("match", "fullmatch") and _dotted(n.func).startswith("re.") and len(n.args) >= 2 \
                    and isinstance(n.args[1], ast.Name) and isinstance(n.args[0], ast.Constant) \
                    and str(n.args[0].value).startswith("^") and str(n.args[0].value).endswith("$"):
                out.add(n.args[1].id)
            elif re.match(r"(?:validate|is_valid|check_|assert_valid|ensure_)", f) and n.args and isinstance(n.args[0], ast.Name):
                out.add(n.args[0].id)
    return out


def _flatten(fn: _Fn, n, depth: int = 0) -> list[tuple[str, ast.AST]]:
    """Parts of a dynamically built string: ('lit', Constant) / ('dyn', expr). Names resolve through local defs."""
    if n is None or depth > 6:
        return []
    if isinstance(n, ast.Constant):
        return [("lit", n)] if isinstance(n.value, (str, bytes)) else [("dyn", n)]
    if isinstance(n, ast.JoinedStr):
        return [("dyn", v.value) if isinstance(v, ast.FormattedValue) else ("lit", v) for v in n.values]
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        return _flatten(fn, n.left, depth + 1) + _flatten(fn, n.right, depth + 1)
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
        r = n.right
        ops = r.elts if isinstance(r, ast.Tuple) else (r.values if isinstance(r, ast.Dict) else [r])
        return _flatten(fn, n.left, depth + 1) + [("dyn", o) for o in ops if o is not None]
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return _flatten(fn, n.func.value, depth + 1) + [("dyn", a) for a in n.args] + [("dyn", k.value) for k in n.keywords]
    if isinstance(n, ast.Name) and n.id in fn.defs:
        out: list = []
        for d in fn.defs[n.id][-4:]:
            out += _flatten(fn, d, depth + 1)
        return out or [("dyn", n)]
    return [("dyn", n)]


def _lit_text(parts) -> str:
    return " ".join(str(p.value) if isinstance(p, ast.Constant) else "" for k, p in parts if k == "lit")


def _dyn_kinds(fn: _Fn, parts) -> set[str]:
    out: set[str] = set()
    for k, p in parts:
        if k == "dyn" and not isinstance(p, ast.Constant):
            out |= fn.kinds(p)
    return out


def _lines_of(fn: _Fn, e) -> list[tuple[int, int]]:
    out = []
    for nm in ast.walk(e):
        if isinstance(nm, ast.Name) and nm.id in fn.defs:
            for d in fn.defs[nm.id]:
                out.append((d.lineno, getattr(d, "end_lineno", d.lineno) or d.lineno))
    return out


class _PyAnalysis:
    def __init__(self, text: str):
        self.hits = _empty()
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return
        self.lines = text.split("\n")
        imp = "\n".join(l for l in self.lines if l.lstrip().startswith(("import ", "from ")))
        self.imports = imp
        self.flask = bool(re.search(r"\b(?:flask|bottle|quart)\b", imp))
        self.web = bool(re.search(r"\b(?:flask|django|fastapi|starlette|aiohttp|tornado|bottle|pyramid|sanic|quart|"
                                  r"falcon|cherrypy|werkzeug|rest_framework|aiohttp_jinja2)\b", imp))
        mod = _Fn(None, imp)
        top = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        for st in top:
            if isinstance(st, ast.Assign) and isinstance(st.value, (ast.Constant, ast.BinOp, ast.JoinedStr)) \
                    and all(isinstance(t, ast.Name) for t in st.targets):
                for t in st.targets:
                    mod.defs.setdefault(t.id, []).append(st.value)
        self._scope(tree, mod, False, False)
        self._autoescape(tree)

    def add(self, rule: str, line: int, detail: str, via=None) -> None:
        spans = [(line, line)] + list(via or [])
        if any(_NOSEC.search(self.lines[l - 1]) for a, b in spans for l in range(a, min(b, len(self.lines)) + 1) if 0 < l):
            return
        if all(h[0] != line for h in self.hits[rule]):
            self.hits[rule].append((line, detail, via or []))

    # --- scopes -----------------------------------------------------------------------------------------------
    def _scope(self, node, parent: _Fn, http: bool, view: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                h = any("RequestHandler" in _dotted(b) for b in child.bases)
                v = any(re.search(r"View|Resource|Endpoint|Handler", _dotted(b)) for b in child.bases)
                self._scope(child, parent, h, v)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(child, parent, http, view)
            else:
                self._scope(child, parent, http, view)

    def _function(self, node, parent: _Fn, http: bool, view: bool) -> None:
        fn = _Fn(parent, self.imports)
        fn.cls_http = fn.cls_http or http
        names = [a.arg for a in list(node.args.posonlyargs) + list(node.args.args)]
        is_route = any(_decor_is_route(d) for d in node.decorator_list)
        django_view = (names[:1] in (["request"], ["req"]) or names[1:2] in (["request"], ["req"])) and not is_route
        method_view = view and node.name.lower() in ("get", "post", "put", "patch", "delete", "dispatch", "head")
        fn.flask_like = self.flask and (is_route or node.name.startswith("do_"))
        _seed_params(fn, node, is_route or django_view or method_view, route=is_route)
        fn.validated |= _validated_names(node)
        nodes = list(self._own_nodes(node))
        for _ in range(2):
            for n in nodes:
                self._propagate(fn, n)
        self._sinks(fn, nodes)
        for n in nodes:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(n, fn, http, view)

    @staticmethod
    def _own_nodes(node):
        stack = list(reversed(node.body))
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(n))))

    def _propagate(self, fn: _Fn, n) -> None:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                fn.assign(t, n.value)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            fn.assign(n.target, n.value)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
            k = fn.kinds(n.value) if isinstance(n.op, (ast.Add, ast.Mod)) else set()
            if k and n.target.id not in fn.validated:
                fn.taint[n.target.id] = _kind_of(k)
            fn.defs.setdefault(n.target.id, []).append(n.value)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            k = fn.kinds(n.iter)
            if k:
                for t in ast.walk(n.target):
                    if isinstance(t, ast.Name):
                        fn.taint[t.id] = _kind_of(k)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for it in n.items:
                if it.optional_vars is not None:
                    fn.assign(it.optional_vars, it.context_expr)
        elif isinstance(n, ast.NamedExpr):
            fn.assign(n.target, n.value)
        elif isinstance(n, ast.Try):
            body = ast.Module(body=n.body, type_ignores=[])
            if any(fn.kinds(x) for x in ast.walk(body) if isinstance(x, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))):
                for h in n.handlers:
                    if h.name:
                        fn.taint.setdefault(h.name, "exc")

    # --- sinks ------------------------------------------------------------------------------------------------
    def _sinks(self, fn: _Fn, nodes) -> None:
        pending: dict[str, list[int]] = {}
        for n in nodes:
            if isinstance(n, ast.Call):
                self._call_sinks(fn, n)
            elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and n.value is not None:
                tgt = n.targets[0] if isinstance(n, ast.Assign) else n.target
                if isinstance(tgt, ast.Name) and self._htmlish_name(fn, tgt.id, n.value) \
                        and fn.kinds(n.value) & {"req", "exc"} and not isinstance(n.value, ast.Name):
                    pending.setdefault(tgt.id, []).append(n.lineno)
            elif isinstance(n, ast.Return) and n.value is not None:
                self._return_sink(fn, n)
        if pending:
            self._html_flow(fn, nodes, pending)

    @staticmethod
    def _htmlish_name(fn: _Fn, name: str, value) -> bool:
        """The statement's own value carries an HTML literal fragment (e.g. `"<b>%s</b>" % x`)."""
        return any(isinstance(x, ast.Constant) and isinstance(x.value, str) and _HTMLISH.search(x.value)
                   for x in ast.walk(value))

    def _html_flow(self, fn: _Fn, nodes, pending) -> None:
        for n in nodes:
            exprs: list[ast.AST] = []
            if isinstance(n, ast.Return) and n.value is not None and self._returns_html(fn, n.value):
                exprs.append(n.value)
            elif isinstance(n, ast.Call) and self._is_html_out(fn, n):
                exprs += list(n.args[:1]) + [k.value for k in n.keywords if k.arg in ("content", "body", "text")]
            for e in exprs:
                for nm in ast.walk(e):
                    if isinstance(nm, ast.Name) and nm.id in pending and nm.id not in fn.validated:
                        for ln in pending.pop(nm.id):
                            self.add("SEC-WEB-002", ln, "request-derived value interpolated into an HTML string that "
                                     "is returned/written unescaped", [(ln, ln)])
                        break

    def _returns_html(self, fn: _Fn, v) -> bool:
        if isinstance(v, ast.Tuple) and v.elts:
            return self._returns_html(fn, v.elts[0])
        if isinstance(v, ast.Call):
            return self._is_html_out(fn, v)
        return fn.flask_like and not isinstance(v, (ast.Dict, ast.List, ast.Constant))

    def _is_html_out(self, fn: _Fn, c: ast.Call) -> bool:
        name = _last(c.func)
        if name not in ("HttpResponse", "make_response", "HTMLResponse", "Response", "write", "finish", "render_string"):
            return False
        if name == "write" and not (isinstance(c.func, ast.Attribute) and _dotted(c.func.value).endswith(("wfile", "self"))):
            return False
        ct = [str(k.value.value).lower() for k in c.keywords if k.arg in ("content_type", "mimetype", "media_type")
              and isinstance(k.value, ast.Constant)]
        if any("html" not in x for x in ct):
            return False
        if name == "Response" and not (any("html" in x for x in ct) or fn.flask_like):
            return False
        return True

    def _return_sink(self, fn: _Fn, n: ast.Return) -> None:
        v = n.value.elts[0] if isinstance(n.value, ast.Tuple) and n.value.elts else n.value
        if isinstance(v, (ast.Call, ast.Name)) or not self._returns_html(fn, v):
            return   # calls are handled at the call; plain names via the pending flow
        parts = _flatten(fn, v)
        if _HTMLISH.search(_lit_text(parts)) and _dyn_kinds(fn, parts) & {"req", "exc"}:
            self.add("SEC-WEB-002", n.lineno, "request-derived value interpolated into a returned HTML string unescaped")

    # --- call sinks -------------------------------------------------------------------------------------------
    def _call_sinks(self, fn: _Fn, c: ast.Call) -> None:
        name, dotted, line = _last(c.func), _dotted(c.func), c.lineno
        first = c.args[0] if c.args else next((k.value for k in c.keywords if k.arg in (
            "sql", "query", "command", "cmd", "args", "source", "template", "template_string", "text", "expression", "s", "html",
            "content")), None)

        def tainted(e, want=("req",)) -> bool:
            return bool((fn.kinds(e) | _dyn_kinds(fn, _flatten(fn, e))) & set(want))

        # ---------------- SEC-WEB-002 ------------------
        if first is not None and (name in ("render_template_string", "from_string", "render_string")
                                  or (name == "Template" and dotted in ("Template", "jinja2.Template", "mako.template.Template"))):
            if tainted(first, ("req", "exc")):
                self.add("SEC-WEB-002", line, "request-derived data is part of the template source (SSTI/XSS)", _lines_of(fn, first))
        elif first is not None and name in ("Markup", "mark_safe", "SafeString", "SafeText"):
            if tainted(first):
                self.add("SEC-WEB-002", line, f"{name}() marks request-derived data as safe HTML", _lines_of(fn, first))
        elif first is not None and name in ("HttpResponse", "HTMLResponse", "make_response") and self._is_html_out(fn, c):
            parts = _flatten(fn, first)
            if not isinstance(first, (ast.Name, ast.Constant)) and (_HTMLISH.search(_lit_text(parts)) or name == "HTMLResponse") \
                    and _dyn_kinds(fn, parts) & {"req", "exc"}:
                self.add("SEC-WEB-002", line, f"request-derived value interpolated into {name}() body unescaped", _lines_of(fn, first))
        # ---------------- SEC-WEB-005 ------------------
        if first is not None and (dotted in _PROC_SHELL_ALWAYS):
            if not isinstance(first, (ast.List, ast.Tuple)) and tainted(first):
                self.add("SEC-WEB-005", line, "shell command built from request-derived data", _lines_of(fn, first))
        elif first is not None and name in ("run", "call", "check_output", "check_call", "Popen") \
                and (dotted.startswith("subprocess.") or dotted == name):
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in c.keywords)
            if not isinstance(first, (ast.List, ast.Tuple)) and (shell or isinstance(first, (ast.JoinedStr, ast.BinOp, ast.Call))
                                                                  or (isinstance(first, ast.Name) and first.id in fn.defs)):
                if tainted(first):
                    self.add("SEC-WEB-005", line, "subprocess command string built from request-derived data" + (" (shell=True)" if shell else ""),
                             _lines_of(fn, first))
            elif isinstance(first, (ast.List, ast.Tuple)) and len(first.elts) >= 3 and isinstance(first.elts[0], ast.Constant) \
                    and str(first.elts[0].value).split("/")[-1] in ("sh", "bash", "zsh", "cmd", "cmd.exe") \
                    and isinstance(first.elts[1], ast.Constant) and str(first.elts[1].value) in ("-c", "/c"):
                if any(tainted(e) for e in first.elts[2:]):
                    self.add("SEC-WEB-005", line, "shell -c command built from request-derived data", _lines_of(fn, first))
        elif dotted.startswith("os.") and re.match(r"(?:exec[lv]p?e?|spawn[lv]p?e?)$", name) and c.args:
            if any(tainted(a) for a in c.args if not isinstance(a, ast.Constant)) and not all(isinstance(a, ast.Constant) for a in c.args[1:] if False):
                self.add("SEC-WEB-005", line, f"os.{name}() runs a program/arguments derived from request data", _lines_of(fn, first))
        elif first is not None and isinstance(c.func, ast.Name) and name in ("eval", "exec", "compile"):
            if tainted(first):
                self.add("SEC-WEB-005", line, f"{name}() evaluates request-derived input", _lines_of(fn, first))
        elif first is not None and name == "eval" and isinstance(c.func, ast.Attribute) and not dotted.startswith(("self.", "model.", "torch.")):
            if tainted(first):
                self.add("SEC-WEB-005", line, "expression evaluator fed request-derived input", _lines_of(fn, first))
        elif first is not None and dotted in _DESERIAL:
            if tainted(first):
                self.add("SEC-WEB-005", line, "request-derived bytes deserialised with a code-executing format", _lines_of(fn, first))
        elif first is not None and dotted in ("yaml.load", "yaml.load_all"):
            ldr = next((k.value for k in c.keywords if k.arg == "Loader"), c.args[1] if len(c.args) > 1 else None)
            if tainted(first) and (ldr is None or re.search(r"(?:^|\.)(?:Loader|UnsafeLoader|FullLoader|CLoader)$", _dotted(ldr))):
                self.add("SEC-WEB-005", line, "yaml.load with an unsafe loader on request-derived data", _lines_of(fn, first))
        # ---------------- SEC-WEB-006 ------------------
        if (name in _SQL_SINK_ATTRS and isinstance(c.func, ast.Attribute)) or (name in ("text", "RawSQL") and isinstance(c.func, ast.Name)):
            self._sql_check(fn, c, first, line)
        elif name == "extra" and isinstance(c.func, ast.Attribute):
            for k in c.keywords:
                if k.arg in ("where", "select", "tables", "order_by") and isinstance(k.value, (ast.List, ast.Tuple)):
                    for e in k.value.elts:
                        self._sql_check(fn, c, e, line, loose=True)

    def _sql_check(self, fn: _Fn, c: ast.Call, first, line: int, loose: bool = False) -> None:
        if first is None or isinstance(first, ast.Constant):
            return
        if isinstance(first, ast.Call) and _last(first.func) == "text" and first.args:
            first = first.args[0]
            if isinstance(first, ast.Constant):
                return
        parts = _flatten(fn, first)
        lit = _lit_text(parts)
        dyn = [p for k, p in parts if k == "dyn" and not isinstance(p, ast.Constant)]
        if not dyn:
            return
        strong, weak = False, []
        for p in dyn:
            k = fn.kinds(p)
            if "req" in k:
                strong = True
            elif "param" in k:
                weak.append(_unparse(p))
        sqlish = bool(_SQL_WORD.search(lit)) or loose
        built = len(parts) > 1 or isinstance(first, (ast.JoinedStr, ast.BinOp, ast.Call))
        direct = strong and not isinstance(first, ast.Name) and len(parts) == 1 and fn.kinds(first) == {"req"}
        if strong and ((sqlish and built) or direct):
            self.add("SEC-WEB-006", line, "SQL statement built from request-derived data", _lines_of(fn, first))
        elif weak and sqlish and built and not any(_IDENT_NAME.search(w) for w in weak) and self._value_position(parts):
            self.add("SEC-WEB-006", line, "SQL statement built by interpolating a function argument", _lines_of(fn, first))

    @staticmethod
    def _value_position(parts) -> bool:
        """The dynamic fragment sits in a value position (after a quote / comparison / VALUES / IN / LIKE) or a quoted
        `%s` / `{}` placeholder of a formatted literal; identifier positions are not reported."""
        lit = _lit_text(parts)
        if _VALUE_PLACEHOLDER.search(lit) and not any(isinstance(p, ast.JoinedStr) for _, p in parts):
            return True
        for i, (k, _) in enumerate(parts):
            if k == "dyn" and i > 0 and parts[i - 1][0] == "lit":
                prev = str(getattr(parts[i - 1][1], "value", ""))
                if re.search(r"""(?i)(?:'|%|=|<|>|\blike|\bin\s*\(|\bvalues\s*\(|\blimit|\boffset)\s*$""", prev):
                    return True
        return False

    # --- jinja environments ---------------------------------------------------------------------------------
    def _autoescape(self, tree) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and self.web:
                for k in n.keywords:
                    if k.arg == "autoescape" and isinstance(k.value, ast.Constant) and k.value.value is False \
                            and _last(n.func) in ("Environment", "setup_jinja", "setup", "Jinja2Templates", "Jinja2"):
                        self.add("SEC-WEB-002", n.lineno, "Jinja environment created with autoescape=False in a web application")
            elif isinstance(n, ast.Assign) and self.web and isinstance(n.value, ast.Constant) and n.value.value is False:
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and t.attr == "autoescape" and "jinja_env" in _dotted(t):
                        self.add("SEC-WEB-002", n.lineno, "Jinja autoescape disabled in a web application")


def analyze_py(text: str) -> dict[str, list]:
    """{rule: [(line, detail, via_line_ranges)]} for one Python source text."""
    try:
        return _PyAnalysis(text).hits
    except RecursionError:   # pragma: no cover
        return _empty()


# =====================================================================================================
# TypeScript / JavaScript
# =====================================================================================================
_JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_JS_PUNCT = re.compile(r"===|!==|\.\.\.|=>|==|!=|<=|>=|&&|\|\||\?\?=?|\?\.|\+\+|--|\+=|-=|\*=|/=|%=|\*\*|<<|>>|&=|\|=|\^=|[{}()\[\];,.:?+\-*/%=<>!&|^~@#]")
_JS_REGEX_PREV_KW = {"return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "yield",
                     "await", "instanceof"}
_ID_RX = re.compile(r"[A-Za-z_$À-￿][\w$À-￿]*")
_NUM_RX = re.compile(r"0[xXbBoO][\da-fA-F_]+n?|\d[\d_]*\.?\d*(?:[eE][+-]?\d+)?n?|\.\d+")


class _T:
    __slots__ = ("t", "s", "ln", "lit", "exprs", "end_ln")

    def __init__(self, t, s, ln, lit="", exprs=None, end_ln=None):
        self.t, self.s, self.ln, self.lit, self.exprs = t, s, ln, lit, exprs or []
        self.end_ln = end_ln or ln

    def __repr__(self) -> str:   # pragma: no cover
        return f"{self.t}:{self.s!r}"


def _tokenize(src: str, line0: int = 1, depth: int = 0) -> list[_T]:
    out: list[_T] = []
    i, n, ln = 0, len(src), line0
    while i < n:
        c = src[i]
        if c == "\n":
            ln += 1
            i += 1
            continue
        if c in " \t\r﻿":
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            ln += src.count("\n", i, j)
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(_T("str", src[i:j + 1], ln, lit=src[i + 1:j]))
            i = min(j + 1, n)
            continue
        if c == "`":
            j, lit, exprs, start_ln = i + 1, [], [], ln
            while j < n and src[j] != "`":
                if src[j] == "\\":
                    lit.append(src[j:j + 2])
                    j += 2
                    continue
                if src.startswith("${", j) and depth < 6:
                    k, d = j + 2, 1
                    while k < n and d:
                        if src[k] in "{":
                            d += 1
                        elif src[k] == "}":
                            d -= 1
                        elif src[k] in "\"'`":
                            q = src[k]
                            k += 1
                            while k < n and src[k] != q:
                                k += 2 if src[k] == "\\" else 1
                        k += 1
                    exprs.append(_tokenize(src[j + 2:k - 1], ln, depth + 1))
                    ln += src.count("\n", j, k)
                    lit.append("\x00")
                    j = k
                    continue
                if src[j] == "\n":
                    ln += 1
                lit.append(src[j])
                j += 1
            out.append(_T("tpl", "`", start_ln, lit="".join(lit), exprs=exprs, end_ln=ln))
            i = min(j + 1, n)
            continue
        if c == "/":
            prev = out[-1] if out else None
            div = prev is not None and (prev.t in ("num", "str", "tpl", "re") or (prev.t == "id" and prev.s not in _JS_REGEX_PREV_KW)
                                        or prev.s in (")", "]", "}"))
            if not div:
                j, cls = i + 1, False
                while j < n and src[j] != "\n":
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        cls = True
                    elif src[j] == "]":
                        cls = False
                    elif src[j] == "/" and not cls:
                        break
                    j += 1
                if j < n and src[j] == "/":
                    j += 1
                    while j < n and src[j].isalpha():
                        j += 1
                    out.append(_T("re", src[i:j], ln, lit=src[i:j]))
                    i = j
                    continue
        m = _ID_RX.match(src, i)
        if m:
            out.append(_T("id", m.group(0), ln))
            i = m.end()
            continue
        m = _NUM_RX.match(src, i)
        if m and (c.isdigit() or c == "."):
            out.append(_T("num", m.group(0), ln))
            i = m.end()
            continue
        m = _JS_PUNCT.match(src, i)
        if m:
            out.append(_T("p", m.group(0), ln))
            i = m.end()
            continue
        i += 1
    return out


_OPEN, _CLOSE = {"(": ")", "[": "]", "{": "}"}, {")", "]", "}"}


def _brackets(toks: list[_T]):
    """match[i] -> index of the matching bracket (or -1); parent[i] -> index of the innermost enclosing open bracket."""
    match, parent, stack = [-1] * len(toks), [-1] * len(toks), []
    for i, t in enumerate(toks):
        parent[i] = stack[-1] if stack else -1
        if t.t == "p" and t.s in _OPEN:
            stack.append(i)
        elif t.t == "p" and t.s in _CLOSE and stack:
            j = stack.pop()
            match[j], match[i] = i, j
            parent[i] = stack[-1] if stack else -1
    return match, parent


_KEYWORDS_NOT_METHODS = {"if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "await",
                         "new", "super", "import", "else", "do", "try", "finally", "constructor_"}
_SRC_ROOTS = {"req", "request", "ctx", "event", "context"}
_SRC_ATTRS = {"body", "query", "params", "headers", "cookies", "files", "signedCookies", "rawBody", "originalUrl", "url",
              "path", "queryStringParameters", "pathParameters", "multiValueQueryStringParameters", "payload", "request",
              "hostname", "baseUrl", "rawHeaders", "searchParams", "file"}
_CLIENT_SRC = {("location", "search"), ("location", "hash"), ("location", "href"), ("location", "pathname"),
               ("document", "URL"), ("document", "documentURI"), ("document", "referrer"), ("document", "cookie"),
               ("document", "location"), ("window", "name"), ("window", "location"), ("snapshot", "params"),
               ("snapshot", "queryParams"), ("snapshot", "paramMap"), ("snapshot", "queryParamMap"),
               ("snapshot", "fragment"), ("route", "queryParams"), ("route", "params"), ("activatedRoute", "queryParams"),
               ("activatedRoute", "params")}
_JS_SANITIZERS = {"number", "parseint", "parsefloat", "boolean", "encodeuricomponent", "encodeuri", "escape",
                  "escapehtml", "escapeid", "escapeliteral", "escapeidentifier", "sanitize", "sanitizehtml", "xss",
                  "filterxss", "striptags", "encode", "htmlencode", "isnumeric", "isint", "isnan", "isfinite", "abs",
                  "floor", "round", "ceil", "max", "min", "tofixed", "quote", "shellescape", "escapeshellarg", "isuuid",
                  "parsebool", "tonumber", "toint", "isinteger", "uuidvalidate", "validate", "clean", "stringify",
                  "escapestring", "sqlescape", "quoteliteral", "quoteident", "format_ident", "isemail", "bigint"}
_JS_STR_METHODS = {"toString", "trim", "toLowerCase", "toUpperCase", "concat", "join", "slice", "substring", "substr", "replace", "String", "padStart", "padEnd", "normalize", "repeat", "split", "map"}
_JS_SANITIZER_PREFIX = re.compile(r"(?i)^(?:sanitiz|escape|encode|esc[A-Z_]|quote|purify|clean[A-Z]|validate)")
_WEAK_SKIP_NAMES = {"res", "response", "reply", "next", "cb", "callback", "done", "err", "error", "e", "resolve", "reject",
                    "_", "i", "j", "k", "idx", "index", "key", "event", "evt", "ev", "args", "opts", "options", "self",
                    "this", "done", "fn", "handler", "app", "server", "socket", "io", "db", "conn", "connection", "pool",
                    "client", "knex", "sequelize", "prisma", "logger", "log", "config", "settings", "ctx", "context",
                    "tx", "trx", "transaction", "manager", "repo", "repository", "state", "dispatch", "props", "req", "request"}
_WEAK_ID_NAME = re.compile(r"^(?:id|pk|\w*Id|\w*ID|\w+_id|page|limit|offset|n|count|size|length|num|\w*Count|\w*Num|"
                           r"\w*Ids|\w+_ids|\w*Index)$")
_JS_SQL_WORD = re.compile(r"(?is)\b(?:select\b.+?\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|"
                          r"where\s+\S+\s*(?:=|like|in)\b|values\s*\(|order\s+by|group\s+by|union\s+select)")
_JS_VALUE_POS = re.compile(r"""(?i)(?:'|%|=|<|>|\blike|\bin\s*\(|\bvalues\s*\(|\blimit|\boffset)\s*$""")
_DB_RECV = re.compile(r"(?i)(?:^|\.)(?:\w*db\w*|\w*database\w*|\w*conn\w*|\w*pool\w*|\w*client\w*|\w*sqlite\w*|\w*knex\w*|"
                      r"\w*trx\w*|\w*tx|\w*sequelize\w*|\w*prisma\w*|\w*manager\w*|pg|mysql\w*|con|cn|dbh|\w*orm\w*|"
                      r"\w*connection\w*|\w*repo\w*|\w*sql\w*)$")
_SQL_CALLS_ANY = {"query", "execute", "raw", "queryraw", "executeraw", "$queryrawunsafe", "$executerawunsafe", "whereraw",
                  "orderbyraw", "havingraw", "joinraw", "selectraw", "groupbyraw", "unsafe", "literal"}
_SQL_CALLS_DB = {"run", "all", "get", "each", "exec", "any", "one", "many", "none", "oneornone", "manyornone", "prepare",
                 "querystream", "result", "execsql", "sql"}
_CP_NAMES = {"exec", "execsync"}
_JS_HTML = re.compile(r"<\s*[a-zA-Z/!]")


class _Scope:
    __slots__ = ("lo", "hi", "kids", "taint", "defs", "roots", "handler", "angular_cb")

    def __init__(self, lo: int, hi: int):
        self.lo, self.hi = lo, hi
        self.kids: list["_Scope"] = []
        self.taint: dict[str, str] = {}
        self.defs: dict[str, list[tuple[int, int]]] = {}
        self.roots: set[str] = set()
        self.handler = False
        self.angular_cb = False


class _JsAnalysis:
    def __init__(self, text: str, rel: str):
        self.hits = _empty()
        self.rel = rel
        if len(text) > 600_000:
            return
        self.src = text
        self.toks = _tokenize(text)
        self.match, self.parent = _brackets(self.toks)
        self.cp_file = bool(re.search(r"child_process|shelljs|execa|\bshell\.exec|require\(['\"]sh['\"]\)", text))
        self.angular = "@angular" in text
        self.has_sql_hint = bool(re.search(r"(?i)select|insert|update|delete|\$where|raw", text))
        if not self.toks:
            return
        root = _Scope(0, len(self.toks))
        self.scopes = self._find_scopes(root)
        self._walk(root)

    def add(self, rule: str, tok: _T, detail: str, end_ln=None, via=None) -> None:
        via = via if via is not None else getattr(self, "_via", [])
        if all(h[0] != tok.ln for h in self.hits[rule]):
            self.hits[rule].append((tok.ln, detail, list(via)))

    def _set_via(self, sc: "_Scope", lo: int, hi: int) -> None:
        """Line ranges of the definitions of identifiers used in toks[lo:hi] (so callers can de-duplicate)."""
        out = []
        for t in self.toks[lo:hi]:
            if t.t == "id" and t.s in sc.defs:
                for a, b in sc.defs[t.s]:
                    if a < b <= len(self.toks):
                        out.append((self.toks[a].ln, self.toks[b - 1].end_ln))
        self._via = out

    # --- scope discovery -------------------------------------------------------------------------------------
    def _find_scopes(self, root: _Scope):
        toks, match = self.toks, self.match
        found: list[tuple[int, int, int, int]] = []   # (params_open, params_close, body_lo, body_hi)
        n = len(toks)

        def body_after(k: int):
            """token index of '{' body start after a parameter list ending at k (skips `: Type` annotations)."""
            j = k + 1
            depth_guard = 0
            while j < n and depth_guard < 60:
                t = toks[j]
                if t.t == "p" and t.s == "{":
                    return j
                if t.t == "p" and t.s in (";", "=", "=>", ")", ",") and not (t.s == "=>"):
                    return -1
                if t.t == "p" and t.s in ("<", "(", "["):
                    # generics / tuple types: skip the balanced part
                    if t.s != "<" and match[j] > 0:
                        j = match[j]
                elif t.t == "p" and t.s == "=>":
                    return -1
                j += 1
                depth_guard += 1
            return -1

        for i, t in enumerate(toks):
            if t.t == "id" and t.s == "function":
                j = i + 1
                if j < n and toks[j].s == "*":
                    j += 1
                if j < n and toks[j].t == "id":
                    j += 1
                if j < n and toks[j].s == "(" and match[j] > 0:
                    b = body_after(match[j])
                    if b > 0 and match[b] > 0:
                        found.append((j, match[j], b, match[b]))
            elif t.t == "p" and t.s == "=>":
                if i == 0:
                    continue
                pj = i - 1
                if toks[pj].s == ")" and match[pj] >= 0:
                    po, pc = match[pj], pj
                elif toks[pj].t == "id":
                    po, pc = pj - 1, pj + 1   # synthetic: single bare parameter
                else:
                    continue
                if i + 1 < n and toks[i + 1].s == "{" and match[i + 1] > 0:
                    found.append((po, pc if po != pj - 1 else -pj, i + 1, match[i + 1]))
                else:
                    end = self._expr_end(i + 1)
                    found.append((po, pc if po != pj - 1 else -pj, i, end))
            elif t.t == "id" and t.s not in _KEYWORDS_NOT_METHODS and i + 1 < n and toks[i + 1].s == "(" and match[i + 1] > 0:
                prev = toks[i - 1] if i else None
                if prev is not None and (prev.s in (".", "?.", "function", "new", "=>") or (prev.t == "id" and prev.s not in
                                         ("async", "static", "public", "private", "protected", "get", "set", "readonly", "override"))):
                    continue
                b = body_after(match[i + 1])
                if b > 0 and match[b] > 0 and b == match[i + 1] + 1 or (b > 0 and match[b] > 0 and toks[match[i + 1] + 1].s == ":"):
                    found.append((i + 1, match[i + 1], b, match[b]))
        # build tree by containment
        scopes = []
        for po, pc, lo, hi in sorted(found, key=lambda f: (f[2], -f[3])):
            sc = _Scope(lo, hi)
            scopes.append((sc, po, pc))
        self._pinfo = {}
        stack: list[_Scope] = [root]
        for sc, po, pc in scopes:
            while len(stack) > 1 and sc.lo >= stack[-1].hi:
                stack.pop()
            stack[-1].kids.append(sc)
            self._pinfo[id(sc)] = (po, pc)
            stack.append(sc)
        return scopes

    def _expr_end(self, i: int) -> int:
        toks, n, match = self.toks, len(self.toks), self.match
        j = i
        while j < n:
            t = toks[j]
            if t.t == "p":
                if t.s in ("(", "[", "{") and match[j] > 0:
                    j = match[j] + 1
                    continue
                if t.s in (",", ";", ")", "]", "}"):
                    return j
            if j > i and t.ln > toks[j - 1].end_ln and toks[j - 1].s not in ("+", "-", "*", "/", "&&", "||", "?", ":", "=", ".", "?.", "=>", "(", "[", "{", ",", "??") \
                    and not (t.t == "p" and t.s in (".", "?.", "+", "-", "*", "/", "&&", "||", "?", ":", "??", ")", "]")):
                return j
            j += 1
        return n

    # --- parameters ------------------------------------------------------------------------------------------
    def _seed(self, sc: _Scope) -> None:
        toks, match = self.toks, self.match
        po, pc = self._pinfo.get(id(sc), (-1, -1))
        params: list[list[_T]] = []
        if pc < 0 and pc != -1:   # synthetic single bare parameter (negative marker)
            params = [[toks[-pc]]]
        elif po >= 0 and pc > po:
            cur: list[_T] = []
            j = po + 1
            while j < pc:
                t = toks[j]
                if t.t == "p" and t.s == "," :
                    params.append(cur)
                    cur = []
                elif t.t == "p" and t.s in ("(", "[", "{") and match[j] > 0:
                    cur += toks[j:match[j] + 1]
                    j = match[j]
                else:
                    cur.append(t)
                j += 1
            if cur:
                params.append(cur)
        names_all = [p[0].s for p in params if p and p[0].t == "id"]
        handler = any(nm in ("res", "response", "reply", "next") for nm in names_all) or \
            any(re.search(r"\bRequest\b|NextRequest|FastifyRequest", " ".join(t.s for t in p)) for p in params)
        for p in params:
            if not p:
                continue
            decor = None
            k = 0
            while k < len(p) and p[k].s == "@":
                decor = p[k + 1].s if k + 1 < len(p) else None
                k += 2
                if k < len(p) and p[k].s == "(":
                    mm = 0
                    depth = 0
                    for q in range(k, len(p)):
                        if p[q].s == "(":
                            depth += 1
                        elif p[q].s == ")":
                            depth -= 1
                            if depth == 0:
                                mm = q
                                break
                    k = mm + 1
            rest = p[k:]
            if not rest:
                continue
            ann = " ".join(t.s for t in rest)
            if rest[0].s in ("{", "["):
                inner = [t for t in rest[1:] if t.t == "id"]
                end_pat = next((q for q, t in enumerate(rest) if t.s in ("}", "]")), len(rest))
                inner_names = [t.s for t in rest[1:end_pat] if t.t == "id" and not (rest[1:end_pat].index(t) > 0 and False)]
                for t in inner_names:
                    if handler and t in ("body", "query", "params", "headers", "cookies"):
                        sc.taint[t] = "req"
                    elif t not in _WEAK_SKIP_NAMES and not _WEAK_ID_NAME.match(t) and rest[0].s == "{" and not handler:
                        sc.taint.setdefault(t, "param")
                continue
            if rest[0].t != "id":
                continue
            nm = rest[0].s
            numeric = bool(re.search(r":\s*(?:number|boolean|Date|bigint)\b", ann))
            if nm in ("req", "request") or re.search(r":\s*(?:\w+\.)?(?:Request|NextRequest|FastifyRequest)\b", ann) \
                    or (nm in _SRC_ROOTS and nm != "context"):
                sc.roots.add(nm)
                sc.handler = True
                continue
            lam = po >= 1 and any("handler" in toks[q].s.lower() for q in range(max(0, po - 8), po) if toks[q].t == "id")
            if nm == "event" and (lam or (len(params) >= 2 and params[1] and params[1][0].s in ("context", "ctx", "callback", "cb", "_context"))):
                sc.taint[nm] = "req"   # AWS-Lambda style handler(event, context): the event is the request
                continue
            if decor in ("Req", "Request"):
                sc.roots.add(nm)
                continue
            if decor in ("Body", "Query", "Param", "Headers", "Ip", "UploadedFile") and not numeric:
                sc.taint[nm] = "req"
                continue
            if self.angular and nm in ("params", "queryParams", "qp", "queryParam", "param", "fragment") and not numeric:
                sc.taint[nm] = "req"
                continue
            if nm in _WEAK_SKIP_NAMES or _WEAK_ID_NAME.match(nm) or numeric or decor:
                continue
            if handler and False:
                continue
            sc.taint.setdefault(nm, "param")
        sc.handler = sc.handler or handler

    # --- main walk -------------------------------------------------------------------------------------------
    def _walk(self, sc: _Scope, parent: "_Scope | None" = None) -> None:
        if parent is not None:
            sc.taint = {**parent.taint, **sc.taint}
            sc.defs = {k: list(v) for k, v in parent.defs.items()}
            sc.roots |= parent.roots
        self._seed(sc)
        own = self._own_ranges(sc)
        for _ in range(2):
            for lo, hi in own:
                self._assignments(sc, lo, hi)
        for lo, hi in own:
            self._sinks(sc, lo, hi)
        for kid in sc.kids:
            self._walk(kid, sc)

    def _own_ranges(self, sc: _Scope) -> list[tuple[int, int]]:
        out, pos = [], sc.lo + (1 if self.toks[sc.lo].s in ("{", "=>") else 0) if sc.lo < len(self.toks) else 0
        for kid in sc.kids:
            po, pc = self._pinfo.get(id(kid), (-1, -1))
            start = po if (po >= 0 and pc > po) else kid.lo
            if start > pos:
                out.append((pos, start))
            pos = max(pos, kid.hi + 1)
        if pos < sc.hi:
            out.append((pos, sc.hi))
        return out

    # --- taint of a token range ---------------------------------------------------------------------------------
    def _occurrences(self, sc: _Scope, lo: int, hi: int):
        """Yield (start_idx, end_idx, kind) of tainted occurrences inside toks[lo:hi]."""
        toks = self.toks
        i = lo
        while i < hi:
            t = toks[i]
            if t.t == "tpl":
                for ex in t.exprs:
                    pass
            if t.t == "id":
                prev = toks[i - 1] if i > lo else (toks[i - 1] if i > 0 else None)
                member = prev is not None and prev.t == "p" and prev.s in (".", "?.")
                nxt = toks[i + 1] if i + 1 < len(toks) else None
                if not member:
                    key = nxt is not None and nxt.s == ":" and prev is not None and prev.s in ("{", ",")
                    if t.s in sc.roots:
                        j = i + 1
                        if j < hi and toks[j].s in (".", "?.") and j + 1 < hi and toks[j + 1].s in _SRC_ATTRS:
                            e = j + 1
                            yield i, self._chain_end(e, hi), "req"
                            i = e
                        elif j + 1 < hi and toks[j].s == "[" and toks[j + 1].t == "str" and toks[j + 1].lit in _SRC_ATTRS \
                                and self.match[j] > 0:
                            e = self.match[j]
                            yield i, self._chain_end(e, hi), "req"
                            i = e
                    elif t.s in sc.taint and not key and not (nxt is not None and nxt.s == "=>"):
                        yield i, self._chain_end(i, hi), sc.taint[t.s]
                    elif i + 2 < hi and toks[i + 1].s in (".", "?.") and (t.s, toks[i + 2].s) in _CLIENT_SRC:
                        yield i, self._chain_end(i + 2, hi), "req"
                else:
                    pass
            i += 1

    def _chain_end(self, e: int, hi: int) -> int:
        toks, match = self.toks, self.match
        while e + 1 < hi:
            nx = toks[e + 1]
            if nx.s in (".", "?.") and e + 2 < hi and toks[e + 2].t == "id":
                e += 2
            elif nx.s == "[" and match[e + 1] > 0 and match[e + 1] < hi:
                e = match[e + 1]
            else:
                break
        return e

    def _neutral(self, sc: _Scope, s: int, e: int, lo: int, hi: int, weak: bool = False) -> bool:
        toks, parent = self.toks, self.parent
        if weak:
            # function-argument taint is deliberately shallow: it does not flow through calls to other functions,
            # and any sanitising helper anywhere in the operand neutralises it
            if any(t.t == "id" and (t.s.lower() in _JS_SANITIZERS or _JS_SANITIZER_PREFIX.match(t.s)) for t in toks[lo:hi]):
                return True
            j = parent[s]
            while j >= 0 and j >= lo - 1:
                if toks[j].s == "(" and j > 0 and toks[j - 1].t == "id" and toks[j - 1].s not in _JS_STR_METHODS:
                    return True
                j = parent[j]
        nxt = toks[e + 1] if e + 1 < len(toks) else None
        if nxt is not None:
            if nxt.s in ("===", "==", "!==", "!=", ">", "<", ">=", "<=", "instanceof", "in") and True:
                return True
            if nxt.s == "?" and (s == lo or toks[s - 1].s in ("(", "!", "&&", "||")):
                return True
            if nxt.s in (".", "?.") and e + 2 < len(toks):
                m = toks[e + 2].s
                if m in ("length", "size", "toString_", "includes", "startsWith", "endsWith", "test", "has", "toFixed", "indexOf"):
                    return True
                if m == "replace" and e + 4 < len(toks) and toks[e + 3].s == "(" and toks[e + 4].t == "re" \
                        and toks[e + 4].s.startswith("/[^"):
                    return True
        if s > 0 and toks[s - 1].s in ("typeof", "!"):
            return True
        # enclosing sanitiser call(s)
        j = parent[s]
        while j >= 0 and j >= lo - 1:
            if toks[j].s == "(" and j > 0 and toks[j - 1].t == "id":
                if toks[j - 1].s.lower() in _JS_SANITIZERS or _JS_SANITIZER_PREFIX.match(toks[j - 1].s):
                    return True
                # `String(x).replace(/[^..]/g,'')`
                cl = self.match[j]
                if cl > 0 and cl + 4 < len(toks) and toks[cl + 1].s == "." and toks[cl + 2].s == "replace" \
                        and toks[cl + 4].t == "re" and toks[cl + 4].s.startswith("/[^"):
                    return True
            j = parent[j]
        return False

    def kind(self, sc: _Scope, lo: int, hi: int) -> "str | None":
        out = None
        for s, e, k in self._occurrences(sc, lo, hi):
            if self._neutral(sc, s, e, lo, hi, weak=(k == "param")):
                continue
            if k == "req":
                return "req"
            out = k
        # template literal expressions are separate token lists: tainted names inside them
        for t in self.toks[lo:hi]:
            if t.t == "tpl":
                for ex in t.exprs:
                    k = self._kind_list(sc, ex)
                    if k == "req":
                        return "req"
                    out = out or k
        return out

    def _kind_list(self, sc: _Scope, toks: list[_T]) -> "str | None":
        """Taint of an embedded token list (template expression) evaluated in scope ``sc``."""
        sub = _JsAnalysis.__new__(_JsAnalysis)
        sub.toks = toks
        sub.match, sub.parent = _brackets(toks)
        sub.angular = self.angular
        return sub.kind(sc, 0, len(toks))

    # --- assignments ----------------------------------------------------------------------------------------
    def _assignments(self, sc: _Scope, lo: int, hi: int) -> None:
        toks, match = self.toks, self.match
        i = lo
        while i < hi:
            t = toks[i]
            if t.t == "p" and t.s == "=" and i > lo:
                prev = toks[i - 1]
                names: list[str] = []
                if prev.t == "id" and (i - 2 < 0 or toks[i - 2].s not in (".", "?.")):
                    names = [prev.s]
                elif prev.s in ("}", "]") and match[i - 1] >= 0:
                    names = [x.s for x in toks[match[i - 1] + 1:i - 1] if x.t == "id"]
                elif prev.t == "id" or prev.s == ">":
                    names = []
                if names:
                    e = min(self._expr_end(i + 1), hi)
                    k = self.kind(sc, i + 1, e)
                    for nm in names:
                        if k:
                            sc.taint[nm] = "req" if k == "req" or sc.taint.get(nm) == "req" else k
                        sc.defs.setdefault(nm, []).append((i + 1, e))
                    i = i + 1
                    continue
            elif t.t == "p" and t.s == "+=" and i > lo and toks[i - 1].t == "id":
                e = min(self._expr_end(i + 1), hi)
                nm = toks[i - 1].s
                k = self.kind(sc, i + 1, e)
                if k:
                    sc.taint[nm] = "req" if k == "req" or sc.taint.get(nm) == "req" else k
                sc.defs.setdefault(nm, []).append((i + 1, e))
            elif t.t == "id" and t.s in ("of", "in") and i > lo + 1 and toks[i - 1].t == "id" and toks[i - 2].s in ("const", "let", "var", "("):
                e = min(self._expr_end(i + 1), hi)
                k = self.kind(sc, i + 1, e)
                if k:
                    sc.taint[toks[i - 1].s] = k
            i += 1

    # --- string building analysis ----------------------------------------------------------------------------
    def _parts(self, sc: _Scope, lo: int, hi: int, depth: int = 0):
        """Parts of a concatenation / template: ('lit', text) | ('dyn', (lo, hi) or token list)."""
        toks, match = self.toks, self.match
        out: list[tuple[str, object]] = []
        if depth > 5:
            return [("dyn", (lo, hi))]
        # split on top-level '+'
        segs, cur, j = [], lo, lo
        while j < hi:
            t = toks[j]
            if t.t == "p" and t.s in ("(", "[", "{") and match[j] > 0:
                j = match[j]
            elif t.t == "p" and t.s == "+" and j > lo:
                segs.append((cur, j))
                cur = j + 1
            j += 1
        segs.append((cur, hi))
        for a, b in segs:
            if a >= b:
                continue
            seg = toks[a:b]
            if len(seg) == 1 and seg[0].t == "str":
                out.append(("lit", seg[0].lit))
            elif len(seg) == 1 and seg[0].t == "tpl":
                tpl = seg[0]
                pieces = tpl.lit.split("\x00")
                for q, piece in enumerate(pieces):
                    if piece:
                        out.append(("lit", piece))
                    if q < len(tpl.exprs):
                        out.append(("dyn", tpl.exprs[q]))
            elif len(seg) >= 2 and seg[0].t == "id" and seg[1].t == "tpl" and len(seg) == 2:
                out.append(("lit", ""))   # tagged template (sql`...`): parameterised by the tag
            elif seg[0].s == "(" and match[a] == b - 1 and b - a > 2:
                out += self._parts(sc, a + 1, b - 1, depth + 1)
            elif len(seg) == 1 and seg[0].t == "id" and seg[0].s in sc.defs and depth < 4:
                for (da, db) in sc.defs[seg[0].s][-4:]:
                    out += self._parts(sc, da, db, depth + 1)
                if not sc.defs[seg[0].s]:
                    out.append(("dyn", (a, b)))
            elif len(seg) >= 3 and seg[0].t == "str" and any(x.s == "+" for x in seg):
                out.append(("dyn", (a, b)))
            else:
                out.append(("dyn", (a, b)))
        return out

    def _dyn_kind(self, sc: _Scope, d) -> "str | None":
        if isinstance(d, list):
            return self._kind_list(sc, d)
        return self.kind(sc, d[0], d[1])

    def _sql_dynamic(self, sc: _Scope, lo: int, hi: int, need_sql: bool = True, weak_ok_recv: bool = False):
        parts = self._parts(sc, lo, hi)
        lit = " ".join(p for k, p in parts if k == "lit")
        if need_sql and not _JS_SQL_WORD.search(lit):
            return None
        strong, weak_ok = False, False
        for q, (k, p) in enumerate(parts):
            if k != "dyn":
                continue
            kd = self._dyn_kind(sc, p)
            if kd == "req":
                strong = True
            elif kd == "param" and weak_ok_recv and q > 0 and parts[q - 1][0] == "lit" and _JS_VALUE_POS.search(parts[q - 1][1]) \
                    and not self._ident_like(p) and need_sql:
                weak_ok = True
        return "req" if strong else ("param" if weak_ok else None)

    def _ident_like(self, d) -> bool:
        toks = d if isinstance(d, list) else self.toks[d[0]:d[1]]
        return any(t.t == "id" and re.search(r"(?i)table|column|col\b|field|schema|order|sort|dir\b|limit|offset|index|ident", t.s)
                   for t in toks)

    # --- sinks ------------------------------------------------------------------------------------------------
    def _split_args(self, o: int, c: int):
        toks, match = self.toks, self.match
        args, cur, j = [], o + 1, o + 1
        while j < c:
            t = toks[j]
            if t.t == "p" and t.s in ("(", "[", "{") and match[j] > 0:
                j = match[j]
            elif t.t == "p" and t.s == ",":
                args.append((cur, j))
                cur = j + 1
            j += 1
        if cur < c:
            args.append((cur, c))
        return args

    def _callee(self, i: int):
        """dotted callee text ending at token i (identifier before '(')."""
        toks = self.toks
        parts = [toks[i].s]
        j = i - 1
        while j >= 1 and toks[j].s in (".", "?."):
            if toks[j - 1].t == "id":
                parts.append(toks[j - 1].s)
                j -= 2
            elif toks[j - 1].s == ")" and self.match[j - 1] >= 1 and toks[self.match[j - 1] - 1].t == "id":
                k = self.match[j - 1]
                parts.append(toks[k - 1].s + "()")   # `$('#x').html(...)` / `getEl().html(...)`
                j = k - 2
            else:
                break
        return ".".join(reversed(parts))

    def _sinks(self, sc: _Scope, lo: int, hi: int) -> None:
        toks, match = self.toks, self.match
        for i in range(lo, hi):
            t = toks[i]
            if t.t == "id" and i + 1 < len(toks) and toks[i + 1].s == "(" and match[i + 1] > 0:
                if i > 0 and toks[i - 1].s in ("function", "new") and t.s not in ("Function",):
                    continue
                self._call(sc, i, i + 1, match[i + 1])
            elif t.t == "id" and t.s == "$where" or (t.t == "str" and t.lit == "$where"):
                if i + 1 < hi and toks[i + 1].s == ":":
                    e = min(self._expr_end(i + 2), hi)
                    parts = self._parts(sc, i + 2, e)
                    if len(parts) > 1 and any(k == "dyn" for k, _ in parts) and any(
                            k == "dyn" and self._dyn_kind(sc, p) == "req" for k, p in parts):
                        self.add("SEC-WEB-006", t, "NoSQL $where expression built from request-derived data")
            elif t.t == "id" and t.s == "new" and i + 1 < hi and toks[i + 1].s == "Function" and i + 2 < len(toks) and toks[i + 2].s == "(":
                self._eval_like(sc, i, toks[i + 2:i + 3] and i + 2, match[i + 2], "new Function() built from request-derived input")
            elif t.t == "p" and t.s == "=" and i >= 2 and toks[i - 1].t == "id" and toks[i - 1].s == "body" and toks[i - 2].s == "." \
                    and i >= 3 and toks[i - 3].s == "ctx":
                e = min(self._expr_end(i + 1), hi)
                self._html_arg(sc, toks[i - 1], i + 1, e, "ctx.body")

    def _eval_like(self, sc, at: int, o: int, c: int, detail: str) -> None:
        if o is None or c <= 0:
            return
        args = self._split_args(o, c)
        if args and self.kind(sc, args[-1][0], args[-1][1]) == "req" and not self._all_literal(args[-1]):
            self.add("SEC-WEB-005", self.toks[at], detail)

    def _all_literal(self, a) -> bool:
        return all(t.t in ("str", "num") or t.s in ("+", "(", ")") for t in self.toks[a[0]:a[1]])

    def _call(self, sc: _Scope, i: int, o: int, c: int) -> None:
        toks = self.toks
        name = toks[i].s
        lname = name.lower()
        callee = self._callee(i)
        recv = callee.rsplit(".", 1)[0] if "." in callee else ""
        args = self._split_args(o, c)
        if not args:
            return
        a0 = args[0]
        self._set_via(sc, a0[0], c)
        # ---------------- SEC-WEB-006 ----------------
        sql_call = (lname in _SQL_CALLS_ANY and (recv or lname in ("query", "execute"))) or \
            (lname in _SQL_CALLS_DB and recv and _DB_RECV.search(recv))
        if sql_call:
            weak_recv = bool(recv) and not recv.startswith("this") and bool(_DB_RECV.search(recv)) and lname in ("query", "execute", "run", "all", "get", "any", "one", "many", "none")
            k = self._sql_dynamic(sc, a0[0], a0[1], need_sql=lname not in ("whereraw", "orderbyraw", "havingraw", "joinraw", "selectraw", "groupbyraw"),
                                  weak_ok_recv=weak_recv)
            if k == "req":
                self.add("SEC-WEB-006", toks[i], "SQL statement built from request-derived data")
                return
            if k == "param":
                self.add("SEC-WEB-006", toks[i], "SQL statement built by concatenating a function argument into a value position")
                return
        # ---------------- SEC-WEB-005 ----------------
        if lname in ("exec", "execsync") and (not recv and self.cp_file or re.search(r"(?i)child_?process|^cp$|shell|shelljs|execa", recv)):
            if self.kind(sc, a0[0], a0[1]) == "req" and not self._all_literal(a0):
                self.add("SEC-WEB-005", toks[i], "child_process exec of a command built from request-derived data")
                return
        if lname in ("spawn", "spawnsync", "execfile", "execfilesync") and (not recv and self.cp_file or re.search(r"(?i)child_?process|^cp$", recv)):
            opts = " ".join(t.s for t in toks[o:c])
            shell_true = re.search(r"shell\s*:\s*true", opts)
            dash_c = len(args) >= 2 and toks[a0[0]].t == "str" and toks[a0[0]].lit.split("/")[-1] in ("sh", "bash", "zsh", "cmd", "cmd.exe") \
                and any(t.t == "str" and t.lit in ("-c", "/c") for t in toks[args[1][0]:args[1][1]])
            if (shell_true and self.kind(sc, a0[0], a0[1]) == "req" and not self._all_literal(a0)) or \
                    (dash_c and self.kind(sc, args[1][0], args[1][1]) == "req"):
                self.add("SEC-WEB-005", toks[i], "child_process spawn with a shell and request-derived command")
                return
        if name == "eval" and not recv or lname in ("runinnewcontext", "runinthiscontext", "runincontext") and re.search(r"vm", recv) \
                or name == "Script" and recv.endswith("vm"):
            if self.kind(sc, a0[0], a0[1]) == "req" and not self._all_literal(a0):
                self.add("SEC-WEB-005", toks[i], f"{name}() evaluates request-derived code")
                return
        if lname in ("eval", "evaluate", "unserialize") and recv and re.search(r"(?i)math|expr|parser|jexl|serialize|evaluator|safeeval|notevil", recv):
            if self.kind(sc, a0[0], a0[1]) == "req":
                self.add("SEC-WEB-005", toks[i], "expression evaluator / unserializer fed request-derived data")
                return
        if name in ("setTimeout", "setInterval") and not recv and toks[a0[0]].t != "id" or False:
            pass
        # ---------------- SEC-WEB-002 ----------------
        if lname.startswith("bypasssecuritytrust"):
            self._angular_bypass(sc, i, a0, lname)
            return
        if lname in ("send", "write", "end", "html") and recv and re.search(r"(?i)(?:^|\.)(?:res|response|reply|rep|ctx|h)\b", recv):
            self._html_arg(sc, toks[i], a0[0], a0[1], callee)
            return
        if lname in ("render", "compile", "renderstring", "template", "rendersync") and recv and re.search(
                r"(?i)^(?:ejs|pug|jade|handlebars|nunjucks|swig|mustache|_|lodash|dot|doT|hogan|twig|liquid|eta|squirrelly|marked)$|nunjucks|env$", recv):
            if self.kind(sc, a0[0], a0[1]) == "req" and not self._all_literal(a0) and lname != "render_":
                self.add("SEC-WEB-002", toks[i], "template engine compiles request-derived source (SSTI/XSS)")
                return
        if lname in ("html", "append", "prepend", "after", "before", "replacewith", "appendto", "prependto") and recv and not re.search(r"(?i)^(?:res|response|reply|array|arr|list|path|str|string|buf|buffer|stream|set|map|files?|data)$", recv.split(".")[-1]) \
                and re.match(r"^(?:\$|jQuery|\$\w*|\w*[Jj]query\w*)", recv):
            if self._client_tainted(sc, a0[0], a0[1]):
                self.add("SEC-WEB-002", toks[i], "jQuery HTML insertion of client-controlled data")

    def _client_tainted(self, sc: _Scope, lo: int, hi: int) -> bool:
        """Only direct browser sources (location/document/window.name/query params/Angular route data), not server data."""
        saved = sc.taint
        sc.taint = {k: v for k, v in saved.items() if v == "req"}
        try:
            for s, e, k in self._occurrences(sc, lo, hi):
                if k == "req" and not self._neutral(sc, s, e, lo, hi) and self.toks[s].s not in sc.roots:
                    return True
        finally:
            sc.taint = saved
        return False

    def _html_arg(self, sc: _Scope, at: _T, lo: int, hi: int, callee: str) -> None:
        if any(t.t == "str" and re.match(r"(?i)(?:text/(?:plain|xml|css|javascript)|application/(?:json|xml|javascript))", t.lit)
               for t in self.toks[sc.lo:sc.hi]):
            return   # the handler declares a non-HTML content type
        parts = self._parts(sc, lo, hi)
        lit = " ".join(p for k, p in parts if k == "lit")
        if not _JS_HTML.search(lit):
            return
        if any(k == "dyn" and self._dyn_kind(sc, p) == "req" for k, p in parts):
            self.add("SEC-WEB-002", at, f"request-derived value interpolated into an HTML string sent via {callee}() unescaped")

    def _angular_bypass(self, sc: _Scope, i: int, a0, lname: str) -> None:
        toks = self.toks
        seg = toks[a0[0]:a0[1]]
        if not seg or all(t.t == "str" or t.s in ("+", "(", ")") for t in seg):
            return
        if len(seg) == 1 and seg[0].t == "tpl" and not seg[0].exprs:
            return
        text = " ".join(t.s for t in seg)
        if re.search(r"(?i)sanitiz|dompurify|escape|\.instant\(|translate|i18n|\bgettext\b|\bt\(", text):
            return
        if len(seg) == 1 and seg[0].t == "id" and seg[0].s in sc.defs:
            ds = sc.defs[seg[0].s]
            if ds and all(all(t.t in ("str", "num") or t.s == "+" or (t.t == "tpl" and not t.exprs) for t in toks[a:b]) for a, b in ds):
                return   # bound only to literal strings
        if lname in ("bypasssecuritytrusthtml", "bypasssecuritytrustscript"):
            self.add("SEC-WEB-002", toks[i], "Angular bypassSecurityTrust*() on a non-literal value disables the HTML sanitiser")
        elif self.kind(sc, a0[0], a0[1]) == "req":
            self.add("SEC-WEB-002", toks[i], "Angular bypassSecurityTrust*() on a request/route-derived value")


def analyze_js(text: str, rel: str) -> dict[str, list]:
    """{rule: [(line, detail, via_line_ranges)]} for one TS/JS source text."""
    if not rel.lower().endswith(_JS_EXT):
        return _empty()
    try:
        return _JsAnalysis(text, rel).hits
    except RecursionError:   # pragma: no cover
        return _empty()


# =====================================================================================================
# Templates (Jinja / Django `|safe`, Angular `[innerHTML]`)
# =====================================================================================================
_TEMPLATE_EXT = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".tmpl", ".tpl")
_SAFE_FILTER = re.compile(r"\{\{-?\s*([A-Za-z_][\w.]*)(?:\[[^\]]*\])?\s*\|\s*safe\s*-?\}\}")
_USERISH = re.compile(r"(?i)^(?:query|search|search_term|searchterm|term|keyword|q|username|user_input|userinput|input|"
                      r"payload|param|search_query|searchquery|reflected|echo)$")


def analyze_template(text: str, rel: str, sibling_ts: str = "", ctx_keys: "set[str] | None" = None) -> list[tuple[int, str]]:
    """Template findings as (line, detail): Jinja/Django `{{ x|safe }}` of a view-supplied request value and Angular
    `[innerHTML]` bound to data that the component marks trusted with bypassSecurityTrustHtml."""
    out: list[tuple[int, str]] = []
    low = rel.lower()
    if not low.endswith(_TEMPLATE_EXT):
        return out
    lines = text.split("\n")
    base = rel.rsplit("/", 1)[-1]
    for i, line in enumerate(lines, 1):
        for m in _SAFE_FILTER.finditer(line):
            root = m.group(1).split(".")[0]
            if "&lt;" in line:
                break   # documentation snippet shown inside <code>/<pre>
            simple = "." not in m.group(1)
            if (ctx_keys and (base, root) in ctx_keys) or (simple and _USERISH.match(root)):
                out.append((i, f"template renders `{m.group(1)}|safe`: request-derived value emitted without escaping"))
                break
        if sibling_ts and "bypassSecurityTrustHtml" in sibling_ts:
            m = re.search(r"\[(?:innerHTML|outerHTML)\]\s*=\s*\"([^\"]+)\"", line)
            if m and not re.match(r"""^\s*['"`]""", m.group(1)) and "| translate" not in m.group(1) and "sanitiz" not in m.group(1).lower():
                out.append((i, "Angular [innerHTML] bound to data trusted via bypassSecurityTrustHtml in the component"))
    return out


def view_context_keys(py_text: str) -> set[tuple[str, str]]:
    """(template basename, context key) pairs where a Django/Flask view passes a request-derived value to a literal
    template name: render(request, 'a.html', {'q': request.GET['q']}) / render_template('a.html', q=request.args['q'])."""
    out: set[tuple[str, str]] = set()
    try:
        tree = ast.parse(py_text)
    except (SyntaxError, ValueError, RecursionError):
        return out
    for fnode in ast.walk(tree):
        if not isinstance(fnode, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fn = _Fn(None, "")
        names = [a.arg for a in list(fnode.args.posonlyargs) + list(fnode.args.args)]
        _seed_params(fn, fnode, bool(names[:1] == ["request"] or names[1:2] == ["request"]
                                      or any(_decor_is_route(d) for d in fnode.decorator_list)))
        nodes = list(_PyAnalysis._own_nodes(fnode))
        helper = _PyAnalysis.__new__(_PyAnalysis)
        for _ in range(2):
            for n in nodes:
                helper._propagate(fn, n)
        for n in nodes:
            if not (isinstance(n, ast.Call) and _last(n.func) in ("render", "render_template", "TemplateResponse")):
                continue
            tmpl = next((a.value for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)), None)
            if not tmpl:
                continue
            base = tmpl.rsplit("/", 1)[-1]
            for a in n.args:
                if isinstance(a, ast.Dict):
                    for k, v in zip(a.keys, a.values):
                        if isinstance(k, ast.Constant) and "req" in fn.kinds(v):
                            out.add((base, str(k.value)))
            for kw in n.keywords:
                if kw.arg and kw.arg != "context" and "req" in fn.kinds(kw.value):
                    out.add((base, kw.arg))
                if kw.arg == "context" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if isinstance(k, ast.Constant) and "req" in fn.kinds(v):
                            out.add((base, str(k.value)))
    return out
