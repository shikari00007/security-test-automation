"""PHP / Java / JSP detectors for SEC-WEB-002 (XSS output), SEC-WEB-005 (command/code exec) and SEC-WEB-006 (SQL).

Precision-first, statement-level taint tracking (no external parser):

* a *source* is request-derived data (``$_GET``/``$_POST``/``$_REQUEST``/``$_COOKIE``, ``request.getParameter``,
  Spring/JAX-RS annotated parameters, ...);
* a variable is *tainted* when it is assigned from a source / tainted variable inside the same function and the
  right-hand side does not pass it through a sanitiser, cast or validator;
* a sink is reported only when a tainted occurrence reaches it NOT enclosed by a sanitiser call (htmlspecialchars,
  escapeshellarg, intval, Integer.parseInt, Encode.forHtml, ...), or - Java SQL/command strings only - when a
  SQL-looking literal is concatenated with a clearly dynamic, non-constant, non-numeric operand.

Constants, prepared-statement placeholders and numeric-typed operands are never reported.
Everything is deterministic regex/scan logic; files are only read through the caller.
"""
from __future__ import annotations

import re
from functools import lru_cache

PHP_EXT = (".php", ".phtml", ".php5", ".inc")
JAVA_EXT = (".java",)
JSP_EXT = (".jsp", ".jspx")


def kind_of(rel: str) -> str | None:
    r = rel.lower()
    if r.endswith(PHP_EXT):
        return "php"
    if r.endswith(JAVA_EXT):
        return "java"
    if r.endswith(JSP_EXT):
        return "jsp"
    return None


# ------------------------------------------------------------------------------------------------
# Pre-processing: drop comments / non-code HTML, normalise heredocs and JSP scriptlets
# ------------------------------------------------------------------------------------------------
def _skip_string(t: str, i: int, q: str) -> int:
    j = i + 1
    while j < len(t):
        if t[j] == "\\":
            j += 2
            continue
        if t[j] == q:
            return j + 1
        j += 1
    return len(t)


def _prep_code(t: str, php: bool) -> str:
    out: list[str] = []
    i, n = 0, len(t)
    while i < n:
        c = t[i]
        two = t[i:i + 2]
        if two == "//" or (php and c == "#" and t[i + 1:i + 2] != "["):
            j = i
            while j < n and t[j] != "\n":
                if php and t.startswith("?>", j):
                    break
                j += 1
            i = j
            continue
        if two == "/*":
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * t.count("\n", i, j))
            i = j
            continue
        if php and t.startswith("<<<", i):
            m = re.match(r"<<<[ \t]*(['\"]?)(\w+)\1\r?\n", t[i:])
            if m:
                end = re.search(r"\n[ \t]*" + re.escape(m.group(2)) + r"\b", t[i + m.end() - 1:])
                body_end = i + m.end() - 1 + (end.start() if end else len(t))
                body = t[i + m.end():body_end].replace('"', "'")
                out.append('"' + body + '"')
                i = body_end + (end.end() - end.start() if end else 0)
                continue
        if not php and t.startswith('"""', i):
            j = t.find('"""', i + 3)
            j = n if j < 0 else j + 3
            out.append(t[i:j])
            i = j
            continue
        if c in "\"'" or (php and c == "`"):
            j = _skip_string(t, i, c)
            out.append(t[i:j])
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _prep_php(t: str) -> str:
    """Blank inline HTML, turn `<?=` into echo, `?>` into a statement end; strip comments in code regions."""
    out: list[str] = []
    pos, n = 0, len(t)
    open_rx = re.compile(r"<\?(php\b|=)?")
    while pos < n:
        m = open_rx.search(t, pos)
        if not m:
            out.append(re.sub(r"[^\n]", " ", t[pos:]))
            break
        out.append(re.sub(r"[^\n]", " ", t[pos:m.start()]))
        out.append("echo " if m.group(1) == "=" else "     ")
        # find the closing ?> outside strings / comments
        i, depth_end = m.end(), None
        j = i
        while j < n:
            c = t[j]
            if t.startswith("?>", j):
                depth_end = j
                break
            if t.startswith("//", j) or (c == "#" and t[j + 1:j + 2] != "["):
                while j < n and t[j] != "\n" and not t.startswith("?>", j):
                    j += 1
                continue
            if t.startswith("/*", j):
                k = t.find("*/", j + 2)
                j = n if k < 0 else k + 2
                continue
            if t.startswith("<<<", j) and re.match(r"<<<[ \t]*['\"]?\w+['\"]?\r?\n", t[j:]):
                mm = re.match(r"<<<[ \t]*(['\"]?)(\w+)\1\r?\n", t[j:])
                e = re.search(r"\n[ \t]*" + re.escape(mm.group(2)) + r"\b", t[j + mm.end() - 1:])
                j = j + mm.end() - 1 + (e.end() if e else len(t))
                continue
            if c in "\"'`":
                j = _skip_string(t, j, c)
                continue
            j += 1
        code = t[i:depth_end if depth_end is not None else n]
        out.append(_prep_code(code, True))
        if depth_end is None:
            break
        out.append(";")
        pos = depth_end + 2
    return "".join(out)


def _prep_jsp(t: str) -> str:
    t = re.sub(r"<%--.*?--%>", lambda m: "\n" * m.group(0).count("\n"), t, flags=re.S)
    out: list[str] = []
    pos = 0
    for m in re.finditer(r"<%([=@!]?)(.*?)%>", t, re.S):
        out.append(re.sub(r"[^\n]", " ", t[pos:m.start()]))
        body = _prep_code(m.group(2), False)      # strip comments per scriptlet (they must not run into the next block)
        if m.group(1) == "=":
            out.append("out.print(" + body.strip().rstrip(";") + ");" + "\n" * body.count("\n"))
        elif m.group(1) == "@":
            out.append("\n" * body.count("\n"))
        else:
            out.append(body + " ")   # no extra newline: keeps reported lines aligned with the file
        pos = m.end()
    out.append(re.sub(r"[^\n]", " ", t[pos:]))
    return _prep_code("".join(out), False)


def prep(text: str, kind: str) -> str:
    if kind == "php":
        return _prep_php(text)
    if kind == "jsp":
        return _prep_jsp(text)
    return _prep_code(text, False)


# ------------------------------------------------------------------------------------------------
# Statement splitting with string masking
# ------------------------------------------------------------------------------------------------
class Stmt:
    __slots__ = ("line", "raw", "masked", "blank")

    def __init__(self, line, raw, masked, blank):
        self.line, self.raw, self.masked, self.blank = line, raw, masked, blank

    def line_at(self, idx: int) -> int:
        return self.line + self.blank.count("\n", 0, idx)


def statements(code: str, kind: str) -> list[Stmt]:
    php = kind == "php"
    out: list[Stmt] = []
    raw: list[str] = []
    msk: list[str] = []
    blk: list[str] = []
    depth = 0
    lineno = 1          # line of the character at index i
    start_line = 1
    i, n = 0, len(code)

    def flush():
        nonlocal raw, msk, blk
        r = "".join(raw)
        if r.strip():
            lead = len(r) - len(r.lstrip())
            out.append(Stmt(start_line + r.count("\n", 0, lead), r[lead:].rstrip(),
                            "".join(msk)[lead:].rstrip(), "".join(blk)[lead:].rstrip()))
        raw, msk, blk = [], [], []

    while i < n:
        c = code[i]
        if c in "\"'" or (php and c == "`"):
            if code.startswith('\"\"\"', i) and not php:
                j = code.find('\"\"\"', i + 3)
                j = n if j < 0 else j + 3
            else:
                j = _skip_string(code, i, c)
            lit = code[i:j]
            if not raw:
                start_line = lineno
            raw.append(lit)
            body = lit[1:-1] if len(lit) >= 2 else ""
            blank = c + "".join("\n" if ch == "\n" else "x" for ch in body) + (c if len(lit) >= 2 else "")
            if php and c in '"`':
                msk.append(c + body.replace("(", " ").replace(")", " ") + c)
            elif php and c == "'" and re.search(r"\[\s*$", "".join(blk)) and re.match(r"^\w+$", body):
                msk.append(lit)   # array key: $_SERVER['HTTP_X']
            elif php and c == "'" and re.fullmatch(_TYPED_NAMES, body) and re.search(r",\s*$", "".join(blk)):
                msk.append(lit)   # filter-type argument: ->get('id', 0, 'int')
            else:
                msk.append(blank)
            blk.append(blank)
            lineno += lit.count("\n")
            i = j
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        if depth == 0 and c in ";{}":
            flush()
            i += 1
            continue
        if not raw:
            start_line = lineno
        raw.append(c)
        msk.append(c)
        blk.append(c)
        if c == "\n":
            lineno += 1
        i += 1
    flush()
    return out


# ------------------------------------------------------------------------------------------------
# Taint machinery
# ------------------------------------------------------------------------------------------------
# `->get('id', 0, 'int')` / `->get('tmpl', '', 'cmd')`: a trailing literal filter naming a numeric / charset-restricted type
_TYPED_NAMES = r"int|uint|integer|float|double|bool|boolean|cmd|word|alnum|alpha|base64|username"
_TYPED_ARG = r"(?![^()]*,\s*['\"](?:" + _TYPED_NAMES + r")['\"]\s*\))"
_PHP_SRC = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$HTTP_(?:GET|POST)_VARS\b|"
    r"\$_SERVER\s*\[\s*['\"](?:PHP_SELF|REQUEST_URI|QUERY_STRING|PATH_INFO|PATH_TRANSLATED|HTTP_\w+)['\"]\s*\]|"
    r"\$request\s*->\s*(?:input|get|query|post|cookie|all|param|getParam|getQueryParams|getParsedBody)\s*\(" + _TYPED_ARG + r"|"
    r"\bInput::(?:get|post|all|input)\s*\(" + _TYPED_ARG + r"|\$this\s*->\s*input\s*->\s*(?:get|post|cookie|get_post|server)\s*\(" + _TYPED_ARG + r"|"
    r"\bfilter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE|REQUEST)\b(?![^)]*FILTER_(?:VALIDATE|SANITIZE))")
_JAVA_SRC = re.compile(
    r"\b(?:request|req|httpRequest|servletRequest|httpServletRequest|hsr)\s*\.\s*(?:getParameter|getParameterValues|"
    r"getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getRequestURI|getRequestURL|getPathInfo|"
    r"getInputStream|getReader|getAttribute)\s*\(|\.\s*(?:getParameter|getQueryString)\s*\(")

_SAN_PHP = re.compile(
    r"(?:^|[>:\\])(?:htmlspecialchars|htmlentities|esc_\w+|wp_kses\w*|strip_tags|intval|floatval|doubleval|absint|"
    r"filter_var|urlencode|rawurlencode|json_encode|number_format|md5|sha1|crc32|base64_encode|bin2hex|count|sizeof|strlen|"
    r"isset|empty|is_\w+|ctype_\w+|preg_match\w*|in_array|array_key_exists|escapeshellarg|escapeshellcmd|"
    r"\w*sanitiz\w*|\w*escape\w*|Q|[Xx]ss::\w+|check_plain|\w*[jJ]son\w*|\w*[Hh]ash\w*|filter_xss\w*|\w*[Xx]ss\w*|addslashes|\w*quote\w*|pg_escape\w*|e|h|purify\w*|xss_clean|encode\w*|"
    r"mysqli?_real_escape_string|real_escape_string|date|time|rand|mt_rand|uniqid|basename|round|ceil|floor|abs|max|min)$",
    re.I)
_SAN_JAVA = re.compile(
    r"(?:^|\.)(?:parseInt|parseLong|parseDouble|parseFloat|parseBoolean|parseShort|fromString|"
    r"\w*[eE]scape\w*|encodeFor\w+|forHtml\w*|forJava\w*|forUri\w*|forXml\w*|\w*[sS]anitiz\w*|encode\w*|\w*[qQ]uote\w*|"
    r"clean|length|size|isEmpty|hashCode|matches|equals|equalsIgnoreCase|contains|startsWith|endsWith|isNumeric|"
    r"\w*[vV]alidat\w*|toInt|toLong|ofNullable|requireNonNull|hash\w*|"
    r"writeValueAsString|writeValueAsBytes|toJson|toJSONString|valueToTree|"
    r"(?:HTMLFilter|HtmlFilter|[Hh]tmlUtils|\w*Escap\w*|[Xx]ss\w*|ESAPI|[Ee]ncoder|Sanitizer|\w*Helper)\.(?:filter|html\w*|\w*[Ee]scap\w*|\w*[Ee]ncode\w*|\w*[Ss]anitiz\w*))$")
_CAST = re.compile(r"\(\s*(?:int|integer|float|double|bool|boolean|long|short)\s*\)\s*$", re.I)
_PHP_VALID = re.compile(r"\b(?:preg_match\w*|ctype_\w+|is_numeric|is_int|in_array|filter_var|array_key_exists)\s*\(")
_JAVA_VALID = re.compile(r"\.matches\s*\(|\bisNumeric\s*\(|\bPattern\.matches\s*\(|\b(?:ALLOWED|ALLOW|WHITELIST|ALLOWLIST)\w*\.contains\s*\(|"
                         r"(?i:allowlist|whitelist|allowed\w*)\.contains\s*\(")


def _enclosing(masked: str, pos: int) -> list[str]:
    depth, names = 0, []
    j = pos - 1
    while j >= 0:
        c = masked[j]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                m = re.search(r"([\w$.>:\\-]+)\s*$", masked[max(0, j - 80):j])
                names.append(m.group(1) if m else "")
            else:
                depth -= 1
        j -= 1
    return names


class State:
    def __init__(self, kind: str):
        self.kind = kind
        self.cfgnames: set[str] = set()   # Java: names whose every assignment in the file is a config read / constant
        self.reset()
        self.reported: set[str] = set()   # vars already reported where they were built (avoid double reports)

    def reset(self):
        self.tainted: dict[str, tuple[int, int]] = {}   # var -> (first, last) line of its last tainting statement
        self.dirty: dict[str, int] = {}     # Java SQL/command strings with a dynamic (non-tainted) operand
        self.sqlvars: set[str] = set()
        self.numeric: set[str] = set()
        self.const_vars: set[str] = set()
        self.htmlobjs: set[str] = set()   # PHP: variables holding HTML-builder widgets (class name html_*/Html*Field ...)
        self.nonhtml = False   # Java: a non-HTML Content-Type was set earlier in this method
        self.reported = set() if not hasattr(self, "reported") else self.reported


def _var_rx(kind: str, names) -> "re.Pattern[str] | None":
    if not names:
        return None
    alt = "|".join(re.escape(x.lstrip("$")) for x in sorted(names, key=len, reverse=True))
    if kind == "php":
        return re.compile(r"\$(?:" + alt + r")\b")
    return re.compile(r"(?<![\w$.])(?:" + alt + r")\b(?!\s*\()")


_NOPROP = re.compile(
    r"(?:^|[>:\\.])(?:mysqli?_\w+|pg_\w+|sqlite_\w+|query|exec|execute|prepare|shell_exec|system|passthru|popen|proc_open|"
    r"file_get_contents|file_put_contents|fopen|file|curl_\w+|include\w*|require\w*|unlink|mail|executeQuery|executeUpdate|"
    r"createQuery|createNativeQuery|prepareStatement|getRuntime|eval|header|setcookie)$")


_OBJECT_CAST = re.compile(r"\(\s*(?!(?:String|Object|CharSequence)\s*\))[A-Z][\w.]*(?:<[\w.<>?, \[\]]*>)?(?:\[\])?\s*\)\s*$")
_CMP_AFTER = re.compile(r"^\s*(?:===?|!==?|<>|<=>?|>=|\binstanceof\b)")
_CMP_BEFORE = re.compile(r"(?:===?|!==?|<>|\binstanceof)\s*$")


def _comparison_operand(masked: str, p: int, end: int) -> bool:
    """The occurrence is an operand of a comparison (`$_GET['x'] === 'y'`, `prefix == null`): the value yields a boolean
    and does not flow into the surrounding expression."""
    if masked[end - 1:end] == "(":                       # method-style source: skip the argument list
        _, close = call_args(masked, end - 1)
        end = close + 1
    while True:                                          # `$_GET['a']['b']`
        m = re.match(r"\s*\[", masked[end:])
        if not m:
            break
        _, close = call_args(masked, end + m.end() - 1)
        end = close + 1
    return bool(_CMP_AFTER.match(masked[end:]) or _CMP_BEFORE.search(masked[max(0, p - 14):p]))


def tainted_hits(st: State, masked: str, skip: set[str] | None = None, prop: bool = False) -> list[int]:
    """Positions in ``masked`` of tainted occurrences (source or tainted var) NOT enclosed by a sanitiser/cast.
    ``prop=True``: for taint propagation into an assigned variable - results of query/exec calls are not tainted."""
    src = _PHP_SRC if st.kind == "php" else _JAVA_SRC
    san = _SAN_PHP if st.kind == "php" else _SAN_JAVA
    spans = [(m.start(), m.end()) for m in src.finditer(masked)]
    names = {v for v in st.tainted if not (skip and v in skip)}
    rx = _var_rx(st.kind, names)
    if rx:
        spans += [(m.start(), m.end()) for m in rx.finditer(masked)]
    ends: dict[int, int] = {}
    for a, b in spans:
        ends[a] = max(ends.get(a, 0), b)
    hits = []
    for p in sorted(ends):
        if _CAST.search(masked[max(0, p - 20):p]) or _comparison_operand(masked, p, ends[p]):
            continue
        if st.kind == "java" and "getAttribute" in masked[p:ends[p]] and _OBJECT_CAST.search(masked[max(0, p - 60):p]):
            continue    # `(Session) request.getAttribute("x")`: a server-side object stored by the application, not request text
        enc = _enclosing(masked, p)
        if any(san.search(nm) for nm in enc) or (prop and any(_NOPROP.search(nm) for nm in enc)):
            continue
        if st.htmlobjs and any(nm.split("->")[0] in st.htmlobjs for nm in enc if "->" in nm):
            continue    # `$field->show($_POST['x'])` on a form-widget object that escapes its values
        hits.append(p)
    return hits


def split_args(s: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def call_args(text: str, open_idx: int) -> tuple[str, int]:
    """Text between the parenthesis at open_idx and its match; returns (inner, end_idx)."""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] in "([":
            depth += 1
        elif text[j] in ")]":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:j], j
    return text[open_idx + 1:], len(text)


def _split_plus(blank: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in blank:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "+" and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


# ------------------------------------------------------------------------------------------------
# Java: dynamic non-constant operands
# ------------------------------------------------------------------------------------------------
_NUM_TYPES = r"int|long|short|byte|double|float|boolean|char|Integer|Long|Short|Double|Float|Boolean|BigDecimal|BigInteger|UUID|LocalDate|LocalDateTime|Instant|Date|Timestamp"
_SAFE_NAME = re.compile(r"(?i:table|tablename|columns?|columnlist|schema|placeholders?|marks|limit|offset|clause|alias|prefix|orderby|sortorder|direction|joiner)$|"
                        r"(?:^|_)(?:col|cols|tbl)$|(?<=[a-z0-9])(?:Col|Cols|Tbl)$")
_SQL_LIT = re.compile(r"""(?is)["'][^"']*\b(?:select\s.+?\sfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|where\s|\border\s+by\b|\bfrom\s+\S|\bvalues\s*\()""")
_FMT_SAFE = re.compile(r"%(?:[-+0, #]*\d*(?:\.\d+)?[dfnbxXoeEgG%]|n)")


def _dynamic_operand(part: str, st: State) -> bool:
    p = part.strip()
    while p.startswith("(") and p.endswith(")"):
        p = p[1:-1].strip()
    if not p or p[0] in "\"'" or re.match(r"^-?\d[\w.]*$", p) or p in ("true", "false", "null"):
        return False
    if re.match(r"^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)*$", p):
        return False
    if re.match(r"^(?:Integer|Long|Double|Float|Short|Boolean|Math|BigDecimal|BigInteger|UUID)\.\w+\s*\(", p):
        return False
    if re.search(r"\.(?:size|length|ordinal|count|getId|intValue|longValue)\s*\(\s*\)\s*$", p):
        return False
    base = re.match(r"^(?:this\.)?([A-Za-z_]\w*)$", p)
    if base and base.group(1) in st.numeric:
        return False
    if base and base.group(1) in st.cfgnames:
        return False   # only ever assigned from configuration / constants in this file
    last = re.search(r"([A-Za-z_]\w*)\s*(?:\(\s*\))?$", p)
    if last and _SAFE_NAME.search(last.group(1)):
        return False
    if re.match(r"^String\.valueOf\s*\(\s*(\w+)\s*\)$", p) and re.match(r"^String\.valueOf\s*\(\s*(\w+)\s*\)$", p).group(1) in st.numeric:
        return False
    if re.match(r"^String\.join\s*\(", p):
        return False   # placeholder lists: String.join(",", Collections.nCopies(n, "?"))
    return True


def java_dynamic_sql(stmt_raw: str, blank: str, st: State) -> bool:
    """SQL-looking literal combined (+ / String.format / concat) with a non-constant, non-numeric operand."""
    if not _SQL_LIT.search(stmt_raw):
        return False
    fm = re.search(r"\b(?:String\.format|\.formatted)\s*\(", blank)
    if fm:
        inner, _ = call_args(blank, fm.end() - 1) if blank[fm.end() - 1] == "(" else ("", 0)
        raw_inner, _ = call_args(stmt_raw, stmt_raw.find("(", fm.start()))
        parts = split_args(inner)
        fmt = split_args(raw_inner)[0] if raw_inner else ""
        specs = re.findall(r"%[-+0, #]*\d*(?:\.\d+)?[a-zA-Z%]", fmt)
        if specs and all(_FMT_SAFE.fullmatch(s) for s in specs):
            return False
        return any(_dynamic_operand(a, st) for a in parts[1:])
    parts = _split_plus(blank)
    if len(parts) > 1 and any(_dynamic_operand(a, st) for a in parts):
        return True
    cm = re.search(r"\.\s*concat\s*\(([^)]*)\)", blank)
    return bool(cm and _dynamic_operand(cm.group(1), st))


# ------------------------------------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------------------------------------
_PHP_FUNC = re.compile(r"(?:^|\s)function\b")
_JAVA_KW = re.compile(r"^(?:if|for|while|switch|catch|return|new|else|try|throw|do|synchronized\s*\(|assert|case|import|package)\b")
_JAVA_HEADER = re.compile(
    r"^(?:@\w+(?:\s*\((?:[^()]|\([^()]*\))*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
    r"(?:<[^>]+>\s*)?[\w.<>\[\],? ]+?\s+\w+\s*\((.*)\)\s*(?:throws\s+[\w.,\s]+)?$", re.S)
_TAINT_ANN = re.compile(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|"
                        r"HeaderParam|ModelAttribute|MatrixParam|RequestPart)\b")
_NAMEWORD_PHP = re.compile(r"\$(?:cmd|command|user_?input|input|payload|expr|argv|args|param|params|code)\b")

_PHP_HTML_NEW = re.compile(r"new\s+\\?(?:html_\w+|Html\w*(?:Field|Input|Select|Textarea|Button|Checkbox|Radio|Table|Label)\w*)\s*[(;]|new\s+\\?(?:html_\w+|Html\w*(?:Field|Input|Select|Textarea|Button|Checkbox|Radio|Table|Label)\w*)\s*$", re.I)
_PHP_CLI = re.compile(r"\A#!.*\bphp|\bPHP_SAPI\b|\bphp_sapi_name\s*\(|\$argv\b|\$_SERVER\s*\[\s*['\"]argv['\"]|\b(?:STDIN|STDERR|STDOUT)\b|"
                      r"\bextends\s+(?:\\?\w+\\)*Command\b|Console\\Command|\b(?:Input|Output)Interface\b|\bSymfonyStyle\b|\bnamespace\s+[\w\\]*\\(?:Console|Command|Cli)\b")
_PHP_REQ_SURFACE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request\b|\$this\s*->\s*input\b|\bfilter_input\s*\(|\bInput::|\$HTTP_\w+_VARS")
_PHP_XSS_CT = re.compile(r"Content-Type\s*:\s*(?:application/(?:json|octet-stream|xml)|text/(?:plain|csv|xml))", re.I)


_ANN_PREFIX = re.compile(r"^(?:@\w+(?:\s*\((?:[^()]|\([^()]*\))*\))?\s+)*")


def _java_header(st: State, blank: str, raw: str) -> bool:
    """Method header: reset per-method state and register request-bound (annotated) parameters as tainted."""
    if _JAVA_KW.match(blank.lstrip()) or not _JAVA_HEADER.match(blank):
        return False
    ann_end = _ANN_PREFIX.match(blank).end()
    if "=" in blank[ann_end:].split("(", 1)[0]:
        return False
    st.reset()
    params, _ = call_args(raw, blank.find("(", ann_end))
    for p in split_args(params):
        pm = re.search(r"([\w.<>\[\]?]+)\s+(\w+)\s*$", p.strip())
        if not pm:
            continue
        typ, name = pm.group(1), pm.group(2)
        if re.fullmatch(_NUM_TYPES, typ):
            st.numeric.add(name)
        elif _TAINT_ANN.search(p):
            st.tainted[name] = (0, 0)
    return True


_JAVA_DECL = re.compile(r"^(?:final\s+)?(?:[A-Za-z_][\w.<>\[\],?]*\s+)?([A-Za-z_]\w*)\s*(\+?=)(?!=)\s*(.*)$", re.S)
_PHP_ASSIGN = re.compile(r"^(\$\w+)\s*(\.?=)(?![=>])\s*(.*)$", re.S)
_JAVA_NONHTML_CT = re.compile(
    r"""(?:setContentType|\bsetHeader|\baddHeader)\s*\(\s*(?:"Content-Type"\s*,\s*)?"(?:application/(?:json|xml|octet-stream|pdf|[\w.+-]*\+(?:json|xml))|"""
    r"""text/(?:plain|csv|xml|calendar)|message/|image/)""", re.I)
_JAVA_HTML_CT = re.compile(r"""(?:setContentType|\bsetHeader|\baddHeader)\s*\(\s*(?:"Content-Type"\s*,\s*)?"(?:text/html|application/xhtml)""", re.I)
_JAVA_NUMDECL = re.compile(r"\b(?:" + _NUM_TYPES + r")\s+(\w+)\s*(?:=|$)")


def _constant_expr(blank: str) -> bool:
    """PHP right-hand side made only of literals and constants (no variables, calls or properties)."""
    s = re.sub(r"\b[A-Z][A-Z0-9_]*\b", "", blank.strip())
    return bool(blank.strip()) and not re.search(r"\$|\(|->|::", s)


_PHP_GUARD = re.compile(r"\b(?:preg_match\w*|ctype_\w+|is_numeric|is_int|in_array|filter_var)\s*\(")
_JAVA_GUARD_RX = (re.compile(r"(\w+)\s*\.\s*matches\s*\("), re.compile(r"\bisNumeric\s*\(\s*(\w+)"),
                  re.compile(r"(?i:\ballow\w*|whitelist\w*)\s*\.\s*contains\s*\(\s*(\w+)"),
                  re.compile(r"\bPattern\.matches\s*\([^,]*,\s*(\w+)"))
_PHP_CFG = re.compile(
    r"(?:[\w$\\]+(?:::\w+\([^()]*\))?(?:\s*->\s*\w+(?:\([^()]*\))?)*\s*->\s*config\s*->\s*get\w*\s*\(|"
    r"\$(?:this\s*->\s*)?(?:config|settings|conf|cfg|options)\s*(?:->\s*\w+\s*)?->\s*get\w*\s*\(|"
    r"\bConfig::\w+\s*\(|\bconfig\s*\(|\bgetenv\s*\(|\bget_option\s*\(|\bvariable_get\s*\(|->\s*getParameter\s*\()|"
    r"\$_ENV\b|\$(?:conf|config|cfg|settings|CFG)\s*\[")


def _strip_cfg(m: str) -> tuple[str, bool]:
    """Remove configuration reads (with their argument lists) from a masked expression."""
    found = False
    while True:
        mm = _PHP_CFG.search(m)
        if not mm:
            return m, found
        found = True
        end = mm.end()
        if m[end - 1] == "(":
            _, close = call_args(m, end - 1)
            end = close + 1
        elif m[end - 1] == "[":
            _, close = call_args(m, end - 1)
            end = close + 1
        m = m[:mm.start()] + " " + m[end:]


_SHELL_SAFE = re.compile(r"(?:^|[>:\\])(?:escapeshell(?:arg|cmd)|intval|absint|floatval|abs|md5|sha1|crc32|bin2hex|base64_encode|"
                         r"urlencode|rawurlencode|count|strlen|uniqid|date|time|basename)$", re.I)


def _trusted_php_rhs(rhs_m: str, rhs_r: str, st: State) -> bool:
    """Right-hand side whose only dynamic parts are trusted: values read from application configuration / environment, and
    variables that appear solely inside a sanitiser call. Used to stop the variable-name heuristic (`$cmd`, `$args`) from
    treating an operator-configured or escaped command line as attacker-controlled."""
    m = rhs_m.replace("\\$", "")
    escaped_map = False
    for am in re.finditer(r"""array_map\s*\(\s*['"]escapeshell(?:arg|cmd)['"]""", rhs_r):   # array_map('escapeshellarg', $parts)
        if am.start() < len(m):
            _, close = call_args(m, m.find("(", am.start()))
            m = m[:am.start()] + " " * (close + 1 - am.start()) + m[close + 1:]
            escaped_map = True
    m, cfg = _strip_cfg(m)
    san, loose = 0, 0
    for v in re.finditer(r"\$\w+", m):
        if v.group(0) in st.const_vars:
            san += 1          # variable itself trusted (config value / constant / escaped earlier)
        elif any(_SHELL_SAFE.search(n) for n in _enclosing(m, v.start())):
            san += 1
        else:
            loose += 1
    return not loose and bool(cfg or san or escaped_map) and not tainted_hits(st, rhs_m)


_ESC_RHS = re.compile(r"\b(?:escapeshell(?:arg|cmd)|intval|absint|basename)\s*\(")


def _untaint_validated(st: State, m_: str, php: bool):
    if php:
        for g in _PHP_GUARD.finditer(m_):
            inner, _ = call_args(m_, g.end() - 1)
            for v in re.findall(r"\$\w+", inner):
                st.tainted.pop(v, None)
    else:
        for rx in _JAVA_GUARD_RX:
            for g in rx.finditer(m_):
                st.tainted.pop(g.group(1), None)



_CFG_RHS = re.compile(
    r"""^\s*(?:\(\s*String\s*\)\s*)?(?:(?:"(?:[^"\\]|\\.)*"|[A-Z][A-Z0-9_.]*)(?:\s*\+\s*(?:"(?:[^"\\]|\\.)*"|[A-Z][A-Z0-9_.]*))*\s*$|"""
    r"""(?:[\w.$]+\s*\.\s*)?(?:getProperty|getInitParameter|getenv|getStringProperty|getRequiredProperty|getPropertyValue|getConfigValue)\s*\()""")
_VALUE_FIELD = re.compile(r"@Value\s*\([^)]*\)\s*(?:(?:private|protected|public|final|static)\s+)*[\w.<>\[\]]+\s+(\w+)\s*;")


def java_config_names(stmts: "list[Stmt]", text: str) -> set[str]:
    """Names (fields / locals) whose every assignment in the file reads application configuration or a constant
    (`props.getProperty(..)`, `getInitParameter(..)`, `System.getenv(..)`, `"lit"`, `@Value` injection): identifier-position data
    such as table / column names that an operator, not a request, controls."""
    good: set[str] = {m.group(1) for m in _VALUE_FIELD.finditer(text)}
    bad: set[str] = set()
    for s in stmts:
        if _JAVA_KW.match(s.blank.lstrip()):
            continue
        am = _JAVA_DECL.match(s.blank)
        if not am or "(" in s.blank.split("=", 1)[0]:
            continue
        name, op, off = am.group(1), am.group(2), am.start(3)
        if op == "=" and _CFG_RHS.match(s.raw[off:]):
            good.add(name)
        else:
            bad.add(name)
    return good - bad


def analyze(text: str, kind: str) -> dict[str, list]:
    return _analyze(text, kind)


@lru_cache(maxsize=256)
def _analyze(text: str, kind: str):
    res: dict[str, list] = {"SEC-WEB-002": [], "SEC-WEB-005": [], "SEC-WEB-006": []}
    code = prep(text, kind)
    stmts = statements(code, kind)
    php = kind == "php"
    st = State("php" if php else "java")
    skip_xss = php and bool(_PHP_XSS_CT.search(code))
    # the variable-name heuristic ($cmd/$args/...) is skipped for CLI-only files (shebang, argv, STDIN, console Command
    # classes) that never touch a request: build/maintenance scripts are not web attack surface
    req_surface = (not php) or bool(_PHP_REQ_SURFACE.search(code)) or not _PHP_CLI.search(text)
    if not php:
        st.cfgnames = java_config_names(stmts, code)
    java_writers = {"out"}
    imports_script = bool(re.search(r"javax\.script|ScriptEngine|GroovyShell|SpelExpressionParser|\bOgnl\b|\bMVEL\b", code))

    def add(rule: str, s: Stmt, idx: int, detail: str, via=None):
        res[rule].append((s.line_at(idx), detail, tuple(via) if via else ()))

    for s in stmts:
        m_, b_, r_ = s.masked, s.blank, s.raw
        if php and re.match(r"^(?:(?:public|private|protected|static|final|abstract)\s+)*function\b", b_):
            st.reset()
            continue
        if not php:
            if _java_header(st, b_, r_):
                continue
            for mw in re.finditer(r"\b(\w+)\s*=\s*(?:\w+\.)?getWriter\s*\(\s*\)|\bPrintWriter\s+(\w+)\b", b_):
                java_writers.add(mw.group(1) or mw.group(2))
            for md in _JAVA_NUMDECL.finditer(b_):
                st.numeric.add(md.group(1))
            if _JAVA_HTML_CT.search(r_):
                st.nonhtml = False
            elif _JAVA_NONHTML_CT.search(r_):
                st.nonhtml = True

        # sinks first: they see the taint state before this statement's own assignment
        if php:
            _php_sinks(s, st, add, skip_xss, req_surface)
        else:
            _java_sinks(s, st, add, java_writers, imports_script)
        _untaint_validated(st, m_, php)

        # ---- taint propagation -------------------------------------------------------------------------------
        if php:
            am = _PHP_ASSIGN.match(m_)
        else:
            am = None if _JAVA_KW.match(b_.lstrip()) else _JAVA_DECL.match(b_)
            if am and "(" in b_.split("=", 1)[0]:
                am = None
            ap = re.match(r"^([A-Za-z_]\w*)\s*\.\s*append\s*\(", b_)
            if ap and not am:
                var, op = ap.group(1), ap.end() - 1
                inner_m, _ = call_args(m_, op)
                inner_b, _ = call_args(b_, op)
                if tainted_hits(st, inner_m, prop=True):
                    st.tainted[var] = (s.line, s.line_at(len(s.blank)))
                elif var in st.sqlvars and any(_dynamic_operand(a, st) for a in _split_plus(inner_b)):
                    st.dirty[var] = (s.line, s.line_at(len(s.blank)))
                if _SQL_LIT.search(r_):
                    st.sqlvars.add(var)
                continue
        if not am:
            if php:
                fe = re.search(r"\bforeach\s*\((.*?)\s+as\s+(?:(\$\w+)\s*=>\s*)?(\$\w+)", m_, re.S)
                if fe and tainted_hits(st, fe.group(1)):
                    for g in (fe.group(2), fe.group(3)):
                        if g:
                            st.tainted[g] = (s.line, s.line)
            continue
        var, op, off = am.group(1), am.group(2), am.start(3)
        rhs_m, rhs_b, rhs_r = m_[off:], b_[off:], r_[off:]
        hits = tainted_hits(st, rhs_m, prop=True)
        if php:
            if op == "=" and _PHP_HTML_NEW.match(rhs_m.strip()):
                st.htmlobjs.add(var)
            if hits:
                st.tainted[var] = (s.line, s.line_at(len(s.blank)))
                st.const_vars.discard(var)
            elif op == "=":
                st.tainted.pop(var, None)
                st.reported.discard(var)
                if _constant_expr(rhs_b) or _ESC_RHS.search(rhs_m) or _trusted_php_rhs(rhs_m, rhs_r, st):
                    st.const_vars.add(var)
                else:
                    st.const_vars.discard(var)
        else:
            if hits:
                st.tainted[var] = (s.line, s.line_at(len(s.blank)))
            elif op == "=":
                st.tainted.pop(var, None)
                st.dirty.pop(var, None)
            if _SQL_LIT.search(rhs_r):
                st.sqlvars.add(var)
            if not hits and (java_dynamic_sql(rhs_r, rhs_b, st) or (
                    op == "+=" and var in st.sqlvars and any(_dynamic_operand(a, st) for a in _split_plus(rhs_b)))):
                st.dirty[var] = (s.line, s.line_at(len(s.blank)))
            tm = re.match(r"^\s*(?:final\s+)?(" + _NUM_TYPES + r")\b", b_)
            if tm:
                st.numeric.add(var)
    return {k: sorted(set(v)) for k, v in res.items()}


# --------------------------------------------------------------------------------------------------
# PHP sinks
# --------------------------------------------------------------------------------------------------
_PHP_SQL_FN = re.compile(r"(?<![\w$>:])(?:mysql_query|mysql_db_query|mysql_unbuffered_query|mysqli_query|mysqli_multi_query|"
                         r"mysqli_real_query|pg_query|pg_send_query|sqlite_query|sqlite_exec|sqlsrv_query|odbc_exec|mssql_query)\s*\(")
_PHP_SQL_M = re.compile(r"(?:->|::)\s*(?:query|exec|multi_query|real_query|prepare|unprepared|statement|select|selectRaw|whereRaw|"
                        r"orderByRaw|havingRaw|rawQuery|execSQL|raw)\s*\(|\bDB::(?:select|raw|statement|unprepared|insert|update|delete)\s*\(")
_PHP_CMD_FN = re.compile(r"(?<![\w$>:])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(")
_PHP_EVAL = re.compile(r"(?<![\w$>:])(?:eval|assert|create_function)\s*\(")


def _php_arg_hits(st: State, masked: str, open_idx: int, which: tuple[int, ...] | None):
    inner, end = call_args(masked, open_idx)
    args = split_args(inner)
    sel = args if which is None else [args[i] for i in which if i < len(args)]
    base = open_idx + 1
    hits = []
    off = 0
    for i, a in enumerate(args):
        if which is None or i in which:
            for h in tainted_hits(st, a):
                hits.append(base + off + h)
        off += len(a) + 1
    return hits, inner


def _php_sinks(s: Stmt, st: State, add, skip_xss: bool, req_surface: bool = True):
    m_, b_ = s.masked, s.blank
    # ---- XSS: echo / print / printf / die / exit with tainted data --------------------------------------
    if not skip_xss:
        for m in re.finditer(r"(?<![\w$>:])(echo|print|printf|vprintf|print_r|die|exit)\b(?!\s*\()?", m_):
            frag = m_[m.end():]
            # `echo (…)` form is fine too; analyse the remaining statement text
            if m.group(1) in ("die", "exit") and not frag.strip().startswith("("):
                continue
            hits = [h for h in tainted_hits(st, frag) if not _in_reported(st, frag, h)]
            if hits:
                add("SEC-WEB-002", s, m.start(), "echo/print outputs request-derived data without HTML escaping")
                break
        am = _PHP_ASSIGN.match(m_)
        if am:
            rhs_m, rhs_r = m_[am.start(3):], s.raw[am.start(3):]
            if re.match(r"\s*[\"']", rhs_r) and re.search(r"""["'][^"']*<\s*[a-zA-Z/!]""", rhs_r):
                hits = tainted_hits(st, rhs_m)
                if hits:
                    add("SEC-WEB-002", s, am.start(3), "HTML markup built from request-derived data without escaping")
                    st.reported.add(am.group(1))
    # ---- command / code execution ------------------------------------------------------------------------
    for rx, label in ((_PHP_CMD_FN, "shell command"), (_PHP_EVAL, "PHP code")):
        for m in rx.finditer(m_):
            op = m.end() - 1
            inner, _ = call_args(m_, op)
            if rx is _PHP_CMD_FN:
                args_idx = (0,)
            else:
                args_idx = None
            hits, inner = _php_arg_hits(st, m_, op, args_idx)
            hit = bool(hits)
            if not hit:
                first = split_args(inner)[0] if inner.strip() else ""
                hit = req_surface and any(nm.group(0) not in st.const_vars for nm in _NAMEWORD_PHP.finditer(first))
            if hit:
                add("SEC-WEB-005", s, m.start(), f"{label} execution built from request-derived/dynamic data")
    for m in re.finditer(r"`[^`]*\$\w+[^`]*`", m_):
        if tainted_hits(st, m.group(0)):
            add("SEC-WEB-005", s, m.start(), "backtick shell execution built from request-derived data")
    # ---- SQL ---------------------------------------------------------------------------------------------
    for rx, which_fn in ((_PHP_SQL_FN, True), (_PHP_SQL_M, False)):
        for m in rx.finditer(m_):
            op = m.end() - 1
            inner, _ = call_args(m_, op)
            nargs = len(split_args(inner))
            which = (1,) if which_fn and nargs >= 2 else (0,)
            hits, _i = _php_arg_hits(st, m_, op, which)
            if hits and not re.search(r"\bbind_param\b|\bbindParam\b", m_):
                # bare variable already reported where the statement was built
                add("SEC-WEB-006", s, m.start(), "SQL query built from request-derived data", via_lines(st, m_, hits))


def via_lines(st: State, masked: str, hits: list[int]):
    """Statement line ranges that tainted the variables at ``hits``; () when a hit is a direct request source."""
    out = []
    for h in hits:
        m = re.match(r"\$?(\w+)", masked[h:])
        key = ("$" + m.group(1)) if (m and st.kind == "php") else (m.group(1) if m else "")
        rng = st.tainted.get(key) or st.dirty.get(key)
        if not rng:
            return ()
        out.append(rng)
    return out


def _in_reported(st: State, frag: str, h: int) -> bool:
    m = re.match(r"\$(\w+)", frag[h:])
    return bool(m and "$" + m.group(1) in st.reported)


# --------------------------------------------------------------------------------------------------
# Java sinks
# --------------------------------------------------------------------------------------------------
_JAVA_SQL_STRICT = r"executeQuery|executeUpdate|executeLargeUpdate|createNativeQuery|createSQLQuery|createQuery|prepareStatement|prepareCall"
_JAVA_SQL_LOOSE = r"execute|addBatch|query|queryForObject|queryForList|queryForMap|update|batchUpdate|nativeQuery"
_JAVA_SQL = re.compile(r"\.\s*(" + _JAVA_SQL_STRICT + "|" + _JAVA_SQL_LOOSE + r")\s*\(")
_JAVA_EXEC = re.compile(r"\b(?:[Rr]untime(?:\s*\.\s*getRuntime\s*\(\s*\))?|\w*[Rr]untime)\s*\.\s*exec\s*\(|\bnew\s+ProcessBuilder\s*\(")
_JAVA_SCRIPT = re.compile(r"\b(?:\w*[Ee]ngine\w*|nashorn|\w*[Ss]hell)\s*\.\s*(?:eval|evaluate)\s*\(|\bGroovyShell\s*\(\s*\)\s*\.\s*(?:evaluate|parse)\s*\(|"
                          r"\.\s*parseExpression\s*\(|\bOgnl\s*\.\s*getValue\s*\(|\bMVEL\s*\.\s*eval\s*\(")
_SHELL_LIT = re.compile(r"""["'](?:/bin/|/usr/bin/)?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']""", re.I)


def _java_sinks(s: Stmt, st: State, add, writers: set[str], imports_script: bool):
    m_, b_, r_ = s.masked, s.blank, s.raw
    # ---- XSS: writer output ----------------------------------------------------------------------------
    wr = "|".join(re.escape(w) for w in sorted(writers))
    for m in ([] if st.nonhtml else re.finditer(r"(?:\bresponse\s*\.\s*getWriter\s*\(\s*\)|(?<![\w.])(?:" + wr + r"))\s*\.\s*(?:println|print|write|append|printf|format)\s*\(", m_)):
        inner, _ = call_args(m_, m.end() - 1)
        if tainted_hits(st, inner):
            add("SEC-WEB-002", s, m.start(), "response writer outputs request-derived data without HTML encoding")
    # ---- SQL ----------------------------------------------------------------------------------------------
    for m in _JAVA_SQL.finditer(m_):
        name = m.group(1)
        op = m.end() - 1
        inner_m, _ = call_args(m_, op)
        inner_b, _ = call_args(b_, op)
        inner_r, _ = call_args(r_, op)
        arg0_m = split_args(inner_m)[0] if inner_m.strip() else ""
        arg0_b = split_args(inner_b)[0] if inner_b.strip() else ""
        arg0_r = split_args(inner_r)[0] if inner_r.strip() else ""
        bare = re.match(r"^\s*(\w+)\s*(?:\.\s*toString\s*\(\s*\))?\s*$", arg0_b)
        sqlish = bool(_SQL_LIT.search(arg0_r)) or bool(bare and bare.group(1) in st.sqlvars)
        strict = re.fullmatch(_JAVA_SQL_STRICT, name) is not None
        if not (sqlish or strict):
            continue
        hit, via = False, ()
        th = tainted_hits(st, arg0_m)
        if th:
            hit, via = True, via_lines(st, arg0_m, th)
        elif bare and bare.group(1) in st.dirty:
            hit, via = True, [st.dirty[bare.group(1)]]
        elif sqlish and java_dynamic_sql(arg0_r, arg0_b, st):
            hit = True
        if hit:
            add("SEC-WEB-006", s, m.start(), "SQL statement built by concatenating/formatting non-constant data", via)
    # ---- command / code execution -----------------------------------------------------------------------
    for m in _JAVA_EXEC.finditer(m_):
        op = m.end() - 1
        inner_m, _ = call_args(m_, op)
        inner_b, _ = call_args(b_, op)
        inner_r, _ = call_args(r_, op)
        hit = False
        parts = _split_plus(inner_b)
        array_form = "{" in inner_b or len(split_args(inner_b)) > 1
        shell = bool(_SHELL_LIT.search(inner_r))
        th = tainted_hits(st, inner_m)
        if not array_form:
            hit = bool(th) or (len(parts) > 1 and any(_dynamic_operand(p, st) for p in parts)) or \
                  bool(re.search(r"\bString\.format\s*\(", inner_b) and java_fmt_dynamic(inner_b, inner_r, st))
        elif shell:
            hit = bool(th) or any(len(_split_plus(a)) > 1 and any(_dynamic_operand(p, st) for p in _split_plus(a))
                                  for a in split_args(inner_b)) or \
                  any(re.match(r"^\s*(\w+)\s*$", a) and re.match(r"^\s*(\w+)\s*$", a).group(1) in st.dirty
                      for a in split_args(inner_b))
        if not hit and not array_form:
            bare = re.match(r"^\s*(\w+)\s*$", inner_b)
            hit = bool(bare and bare.group(1) in st.dirty)
        if hit:
            add("SEC-WEB-005", s, m.start(), "OS command built from request-derived/dynamic data")
    if imports_script:
        for m in _JAVA_SCRIPT.finditer(m_):
            inner_m, _ = call_args(m_, m.end() - 1)
            inner_b, _ = call_args(b_, m.end() - 1)
            if tainted_hits(st, inner_m) or (len(_split_plus(inner_b)) > 1 and any(
                    _dynamic_operand(p, st) for p in _split_plus(inner_b)) and re.search(r"\.\s*(?:eval|evaluate)\b", m_[m.start():m.end()])):
                add("SEC-WEB-005", s, m.start(), "script/expression evaluation of request-derived/dynamic data")


def java_fmt_dynamic(inner_b: str, inner_r: str, st: State) -> bool:
    fm = re.search(r"\bString\.format\s*\(", inner_b)
    if not fm:
        return False
    args, _ = call_args(inner_b, fm.end() - 1)
    return any(_dynamic_operand(a, st) for a in split_args(args)[1:])


def _statements_containing(line: str, file_text: str) -> list[str]:
    """Every statement (lines joined, up to the terminating `;`) in which a line equal to ``line`` occurs."""
    lines = file_text.splitlines()
    key = line.strip()
    out = []
    for i, ln in enumerate(lines):
        if ln.strip() != key:
            continue
        a = i
        while a > 0 and (lines[a].strip().startswith("+") or lines[a - 1].rstrip().endswith("+")) and i - a < 30:
            a -= 1
        b = i
        while b < len(lines) - 1 and not lines[b].rstrip().endswith((";", "{", "}")) and b - i < 30:
            b += 1
        out.append(" ".join(x.strip() for x in lines[a:b + 1]))
    return out


def java_line_dynamic_joined(stmt: str, st: State) -> bool:
    blank = re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: '"' + "x" * (len(m.group(0)) - 2) + '"', stmt)
    expr = re.sub(r"^(?:return\s+|[^\"=(]*[^=!<>]=(?!=)\s*)", "", blank.strip().rstrip(";").strip())
    expr = re.sub(r"^[\w.\s]*\(\s*(?=\")", "", expr)                  # `st.executeQuery(` before the first literal
    while expr.endswith(")") and expr.count(")") > expr.count("("):
        expr = expr[:-1].rstrip()
    if re.search(r"[({]", re.sub(r'"x*"', '""', expr)):
        return True
    return any(_dynamic_operand(p, st) for p in _split_plus(expr))


@lru_cache(maxsize=64)
def _java_cfg_names_cached(file_text: str) -> set[str]:
    code = prep(file_text, "java")
    return java_config_names(statements(code, "java"), code)


def java_line_dynamic(line: str, file_text: str) -> bool:
    """Single-line re-check for the generic SQL-concatenation heuristic on .java files: True when the line carries a
    non-constant, non-numeric operand (or anything this helper cannot classify, so recall is kept)."""
    st = State("java")
    st.cfgnames = _java_cfg_names_cached(file_text)
    st.numeric = {m.group(1) for m in re.finditer(r"\b(?:" + _NUM_TYPES + r")\s+(\w+)\s*[=,;)]", file_text)}
    blank = re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: '"' + "x" * (len(m.group(0)) - 2) + '"', line)
    if re.search(r"\bString\.format\s*\(|\.formatted\s*\(", blank):
        return java_dynamic_sql(line, blank, st) or bool(not _SQL_LIT.search(line))
    bs = blank.strip()
    if bs.endswith("+") or bs.startswith("+"):
        # part of a multi-line concatenation: judge the WHOLE statement this line belongs to
        stmts_ = _statements_containing(line, file_text)
        if not stmts_:
            return True
        return any(java_line_dynamic_joined(j, st) for j in stmts_)
    if '"' not in blank:
        return True   # not a plain concatenation: keep the finding
    seg = split_args(blank[blank.find('"'):])[0].rstrip().rstrip(";").rstrip()
    while seg.endswith(")") and seg.count(")") > seg.count("("):
        seg = seg[:-1].rstrip()
    parts = _split_plus(seg)
    if len(parts) < 2:
        return True
    return any(_dynamic_operand(p, st) for p in parts)


# --------------------------------------------------------------------------------------------------
# PHP: single-line re-check for the generic `"SELECT ..." . $var` SQL-concatenation heuristic (web.py hook)
# --------------------------------------------------------------------------------------------------
_PHP_IDENT_CALL = re.compile(
    r"(?i)(?:->|::|\\|^)\s*(?:table_?name|get_?table\w*|get\w*table|quote\w*|backquote|qn|escape\w*|real_escape_string|now|"
    r"intval|absint|floatval|count|prefixTable|tbl|e)\s*\(")
_PHP_IDENT_NAME = re.compile(
    r"(?i)(?:^|[_>:\\$])(?:\w*table|\w*tbl|tablename|\w*columns?|cols|colnames?|schema|placeholders?|marks|prefix|vals|alias)$")
_PHP_CONST = re.compile(r"^(?:(?:self|static|[A-Z]\w*)::)?[A-Z][A-Z0-9_]*$")


def _php_operand_safe(expr: str) -> bool:
    e = expr.strip()
    while e.startswith("(") and e.endswith(")") and call_args(e, 0)[1] == len(e) - 1:
        e = e[1:-1].strip()
    if not e:
        return True
    if re.match(r"^\(\s*(?:int|integer|float|double|bool)\s*\)", e) or re.match(r"^-?\d[\d.]*$", e) or _PHP_CONST.match(e):
        return True
    if _PHP_IDENT_CALL.search(e.split("(", 1)[0] + "("):
        return True
    base = re.sub(r"\s*\([^()]*\)\s*$", "", e)          # trailing call: $this->getTable()
    base = re.sub(r"\[[^\]]*\]$", "", base)
    tail = re.search(r"([A-Za-z_]\w*)\s*$", base)
    return bool(tail and _PHP_IDENT_NAME.search(tail.group(1)))


def php_line_dynamic(line: str, file_text: str = "") -> bool:
    """True when the line's SQL string carries a dynamic operand that is NOT a quoted identifier / table-name helper /
    table- or column-named variable / numeric cast / constant. Anything this helper cannot classify stays a finding."""
    ops: list[str] = []
    q = re.search(r"[\"']", line)
    line = line[q.start():] if q else line      # drop `$sql = ` / `$db->query(` / `return ` before the first literal
    i, n = 0, len(line)
    cur: list[str] = []
    depth = 0
    while i < n:
        c = line[i]
        if c in "\"'":
            j = _skip_string(line, i, c)
            if c == '"':
                body = line[i + 1:j - 1]
                for m in re.finditer(r"\{\$([^{}]*)\}|(?<!\\)\$(\w+(?:->\w+)?)", body):
                    ops.append("$" + (m.group(1) or m.group(2)))
            cur.append("s")
            i = j
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if depth < 0 or (depth == 0 and c in ",;"):
            break              # end of the first argument / statement
        if c == "." and depth == 0 and not re.match(r"\.\d", line[i:i + 2]) and line[i:i + 3] != "...":
            part = "".join(cur).strip()
            if part and part != "s":
                ops.append(part)
            cur = []
        else:
            cur.append(c)
        i += 1
    last = "".join(cur).strip().rstrip(";,)").strip()
    if last and last != "s":
        ops.append(last)
    ops = [o for o in ops if not re.fullmatch(r"s*", o)]
    if not ops:
        return True        # nothing parseable: keep the finding
    return not all(_php_operand_safe(o) for o in ops if o.startswith("$") or re.search(r"[\w)]", o))
