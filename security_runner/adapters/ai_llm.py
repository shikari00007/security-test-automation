"""AI / LLM application static rules (SEC-AI-001..004). Heuristic, line-oriented."""
from __future__ import annotations

import json
import re

from .android import rule, strip_c
from .base import Observation, RuleResult, ScanContext

_CODE_GLOBS = ("*.py", "*.js", "*.mjs", "*.cjs", "*.ts")
_LLM_MARK = re.compile(r"openai|anthropic|langchain|llama_?index|ollama|autogen|crewai|gemini|\bllm\b|chat\.completions|\bagent", re.I)


_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|__mocks__)/|(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.py|conftest\.py|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?)$")


def _code_files(ctx: ScanContext) -> list[str]:
    """Source files only: vendored dependencies, typings and test code (mocks, stub executors) are skipped."""
    return [f for f in ctx.match(*_CODE_GLOBS)
            if "node_modules/" not in f and not f.endswith(".d.ts") and not _TEST_PATH.search(f)]


def _in_string(ln: str, pos: int) -> bool:
    """True when ``pos`` lies inside a quoted literal (simple scanner; ignores f-string braces)."""
    q = None
    i = 0
    while i < pos:
        c = ln[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "'\"`":
            q = c
        i += 1
    return q is not None


def strip_hash(text: str) -> str:
    """Blank '#' comments (full-line and trailing, outside string literals) preserving line numbers.

    The shared android.strip_hash lets ``\\s*`` swallow preceding newlines, which shifts reported lines.
    """
    out = []
    for ln in text.split("\n"):
        pos = ln.find("#")
        while pos != -1 and _in_string(ln, pos):
            pos = ln.find("#", pos + 1)
        out.append(ln if pos == -1 else ln[:pos])
    return "\n".join(out)


def _strip(rel: str, text: str) -> str:
    return strip_hash(text) if rel.endswith(".py") else strip_c(text)


def _llm_files(ctx: ScanContext) -> list[str]:
    return [f for f in _code_files(ctx) if _LLM_MARK.search(ctx.read(f))]


# --------------------------------------------------------------------------- 001
_LLM_CALL = re.compile(
    r"chat\.completions\.create|completions\.create|messages\.create|responses\.create|\.invoke\(|\bllm\(|"
    r"\.generate\(|\.predict\(|ollama\.(?:chat|generate)|generateText\(|generate_content\(|\.run_sync\(", re.I)
_ASSIGN = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(.*)$")
_SINK = re.compile(
    r"\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\("
    r"|\bnew\s+Function\s*\(|\bexecSync\s*\(|\bchild_process\.exec\w*\s*\(|\bspawnSync\s*\(|\bvm\.runIn\w+\s*\(")
# Names of allow-list containers. A *name* alone never sanitises anything: only an enforced membership test
# or a direct lookup against such a container (that is not the tainted variable itself) does.
_CONT = r"(?:ALLOWED\w*|ALLOW_?LIST\w*|WHITELIST\w*|SAFE_\w+|allowed\w*|allow_?list\w*|whitelist\w*|safe_\w+)"
_SANITISER_CALL = r"(?:shlex\.quote|shlex\.join|int|float|bool|re\.escape|parseInt|parseFloat|Number)"
_ENFORCE = re.compile(r"\b(?:raise|return|continue|break|abort|exit|throw|sys\.exit)\b")


def _sql_sink(line: str, var: str) -> bool:
    m = re.search(r"\.(?:execute|executemany|query|raw)\s*\(\s*(.*)$", line)
    if not m:
        return False
    a = m.group(1)
    v = re.escape(var)
    if re.match(r"f[\"']", a) and re.search(rf"\{{\s*{v}\b", a):   # f"... '{out}' ..." incl. quoted placeholders
        return True
    return bool(re.match(rf"(?:{v}\s*[,)]|`[^`]*\$\{{\s*{v}\b|[\"'][^\"']*[\"']\s*(?:\+|%|\.format)[^,)]*\b{v}\b)", a)) \
        or bool(re.match(rf"{v}\s*$", a))


def _first_sink(ln: str):
    for m in _SINK.finditer(ln):
        if not _in_string(ln, m.start()):
            return m
    return None


_DEF = re.compile(r"^\s*(?:async\s+def|def|(?:async\s+)?function)\b")


def _guard_enforced(lines: list[str], idx: int, negated: bool) -> bool:
    """Does the membership test on lines[idx] actually gate what follows (reject, or guard a non-empty block)?"""
    ln = lines[idx]
    if re.search(r"\bassert\b", ln) or re.search(r"\bif\b.*\belse\b", ln):
        return True
    nxt = [x.strip() for x in lines[idx + 1: idx + 4] if x.strip()]
    if negated:
        return bool(_ENFORCE.search(ln.split(":", 1)[-1]) or any(_ENFORCE.search(x) for x in nxt[:2]))
    return bool(nxt) and nxt[0] not in ("pass", "...", "{}", "}")


def _validates(lines: list[str], idx: int, t: str):
    """None if line idx has no allow-list test on ``t``; else True/False whether it is enforced."""
    ln = lines[idx]
    tv = re.escape(t)
    m = re.search(rf"\b{tv}\b\s+(not\s+)?in\s+({_CONT})\b", ln)
    if m and m.group(2) != t:
        return _guard_enforced(lines, idx, bool(m.group(1)))
    m = re.search(rf"(!\s*)?\b({_CONT})\.(?:includes|has)\(\s*{tv}\s*\)", ln)
    if m and m.group(2) != t:
        return _guard_enforced(lines, idx, bool(m.group(1)))
    return None


@rule("SEC-AI-001")
def output_to_sink(ctx: ScanContext):
    files = _llm_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        lines = _strip(rel, ctx.read(rel)).splitlines()
        tainted: set[str] = set()
        for idx, ln in enumerate(lines):
            i = idx + 1
            if _DEF.match(ln):
                tainted.clear()  # taint is tracked per function; module-level flow into functions is not modelled
            sink = _first_sink(ln)
            m = _ASSIGN.match(ln)
            if m and not sink:
                name, rhs = m.group(1), m.group(2)
                # direct lookups `X[t]` / `X.get(t)` return only values the developer wrote
                rhs_flow = re.sub(r"(?<=[\w\])])\[[^\]]*\]|\.get\([^)]*\)", "", rhs)
                if _LLM_CALL.search(rhs):
                    tainted.add(name)
                elif re.match(rf"\s*{_SANITISER_CALL}\s*\(", rhs):
                    tainted.discard(name)  # cast/quote wrapper: value is constrained
                elif tainted and any(re.search(rf"\b{re.escape(t)}\b", rhs_flow) for t in tainted):
                    tainted.add(name)
                else:
                    tainted.discard(name)  # overwritten with a value that does not derive from model output
            enforced_here = False
            for t in list(tainted):
                v = _validates(lines, idx, t)
                if v:
                    tainted.discard(t)
                    enforced_here = True
            if enforced_here and not (sink and _LLM_CALL.search(ln[sink.start():])):
                continue
            hit = False
            if sink:
                sink_text = ln[sink.start():]
                if _LLM_CALL.search(sink_text):
                    hit = True
                else:
                    for t in tainted:
                        tv = re.escape(t)
                        rest = re.sub(rf"(?<=[\w\])])\[\s*{tv}\s*\]", "[]", sink_text)   # `X[t]` lookup
                        rest = re.sub(rf"{_SANITISER_CALL}\(\s*{tv}\s*\)", "", rest)       # shlex.quote(t), int(t)
                        if re.search(rf"\b{tv}\b", rest):
                            hit = True
                            break
            if not hit:
                for t in tainted:
                    if _sql_sink(ln, t):
                        hit = True
                        break
            if hit:
                obs.append(Observation(rel, i, "model output reaches a code-execution, shell or SQL sink (heuristic)"))
    return RuleResult(obs, notes="heuristic taint tracking; confidence low, precision not established")


# --------------------------------------------------------------------------- 002
_MCP_GLOBS = ("*mcp*.json", "*mcp*.yaml", "*mcp*.yml", "claude_desktop_config.json")
_ROOTS = {"/", "~", "/home", "/Users", "/etc", "/root", "$HOME", "${HOME}", "C:\\", "C:/", "C:\\\\"}
_SECRET_KEY = re.compile(r"(?:token|secret|passw(?:or)?d|passwd|api_?key|apikey|access_?key|(?:^|_)key|credential|private_?key|auth(?:orization)?)$|"
                         r"^(?:auth|authorization|bearer)$", re.I)
_SECRET_VAL = re.compile(r"(?:ghp_|github_pat_|sk-|xox[bpa]-|AKIA|AIza|Bearer\s+)[\w\-]{6,}")


def _is_literal_secret(v: str) -> bool:
    """Heuristic: an env value that looks like a credential rather than a reference, URL, flag or mode."""
    v = v.strip()
    if len(v) < 8 or re.match(r"^(?:\$|\{|<|%|\$\{)", v) or v.lower().startswith(("env:", "your_", "<", "http://", "https://")):
        return False
    if v.startswith(("/", "~", "./", "../")) or re.search(r"\.(?:pem|key|json|txt|ya?ml)$", v):
        return False  # a file path, not the secret itself
    if v.lower() in ("true", "false", "none", "null", "changeme", "placeholder"):
        return False
    return not re.search(r"\s|\$\{|\{\{", v)


_EXACT_VER = re.compile(r"^v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.+-]+)?$|^[0-9a-f]{40}$|^sha\d+-\S+$")
_UVX_VALUE_FLAGS = {"--python", "-p", "--with", "--index", "--index-url", "--extra-index-url", "--env-file", "--with-requirements"}


def _classify(version: str | None) -> str | None:
    """None when exactly pinned (exact version, 40-hex commit or integrity hash); else 'unpinned' or 'range'."""
    if version is None or version in ("", "latest", "*"):
        return "unpinned"
    return None if _EXACT_VER.match(version) else "range"   # ^1.2, ~1, >=1, 1.x, next, beta, 1, ...


def _pin_state(cmd: str, args: list[str]):
    """Return (package, None|'unpinned'|'range') for npx/uvx-style launchers, or None when not a registry launcher.

    Only exact versions or immutable refs count as pinned. Ranges (^ ~ > < * x), major-only versions and
    dist-tags (latest, next, beta, ...) are reported as not exactly pinned.
    """
    base = cmd.replace("\\", "/").rsplit("/", 1)[-1]
    base = re.sub(r"\.(cmd|exe)$", "", base)
    if base in ("npx", "bunx", "pnpx"):
        if not any(a in ("-y", "--yes") for a in args):
            return None
        explicit = [a.split("=", 1)[1] for a in args if a.startswith("--package=")]
        explicit += [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-p", "--package")]
        pkgs = explicit or [a for a in args if not a.startswith("-")]
        if not pkgs:
            return None
        pkg = pkgs[0]
        if pkg.startswith((".", "/", "~", "file:")):
            return None  # local path, not fetched from a registry
        if re.match(r"(?:github:|git\+|https?://)", pkg) or "#" in pkg:
            sha = pkg.rsplit("#", 1)[-1] if "#" in pkg else ""
            return pkg, (None if re.fullmatch(r"[0-9a-f]{40}", sha) else "unpinned")
        m = re.match(r"^(@?[^@]+)(?:@(.*))?$", pkg)
        return pkg, _classify(m.group(2) if m else None)
    if base == "uvx":
        frm = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--from"]
        if frm:
            pkg = frm[0]
        else:
            pkg = None
            skip = False
            for a in args:
                if skip:
                    skip = False
                elif a in _UVX_VALUE_FLAGS:
                    skip = True
                elif not a.startswith("-"):
                    pkg = a
                    break
            if pkg is None:
                return None
        if pkg.startswith((".", "/", "~")):
            return None
        if pkg.startswith("git+"):
            return pkg, (None if re.search(r"@[0-9a-f]{40}$", pkg) else "unpinned")
        m = re.match(r"^[^=<>!~@]+(?:===?|@)(.+)$", pkg)
        if m and "*" not in m.group(1) and not re.search(r"[<>!~,]", pkg):
            return pkg, _classify(m.group(1))
        return pkg, ("range" if re.search(r"[<>!~,=@]", pkg) else "unpinned")
    return None


_PIN_DETAIL = {"unpinned": "MCP server launched from an unpinned package",
               "range": "MCP server package not pinned to an exact version (range or dist-tag)"}


def _find(lines: list[str], start: int, needle: str) -> int:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return start + 1


def _servers(data):
    if isinstance(data, dict):
        for key in ("mcpServers", "servers", "mcp_servers"):
            v = data.get(key)
            if isinstance(v, dict):
                yield from ((n, c) for n, c in v.items() if isinstance(c, dict))
        mcp = data.get("mcp")
        if isinstance(mcp, dict):
            yield from _servers(mcp)


@rule("SEC-AI-002")
def mcp_config(ctx: ScanContext):
    files = ctx.match(*_MCP_GLOBS)
    if not files:
        return None
    obs = []
    notes = []
    for rel in files:
        text = ctx.read(rel)
        lines = text.splitlines()
        data = None
        if rel.endswith(".json"):
            try:
                data = json.loads(text)
            except ValueError:
                notes.append(f"{rel}: invalid JSON, line heuristics used")
        if data is not None:
            for name, cfg in _servers(data):
                start = _find(lines, 0, f'"{name}"') - 1
                cmd = str(cfg.get("command", ""))
                args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int))] if isinstance(cfg.get("args", []), list) else []
                if cmd.rsplit("/", 1)[-1] == "pnpm" and args[:1] == ["dlx"]:
                    cmd, args = "npx", ["-y"] + args[1:]
                ps = _pin_state(cmd, args)
                if ps and ps[1]:
                    obs.append(Observation(rel, _find(lines, start, ps[0]), _PIN_DETAIL[ps[1]]))
                if any("filesystem" in a for a in args) or "filesystem" in name.lower():
                    for a in args:
                        if a in _ROOTS or a.rstrip("/") in _ROOTS:
                            obs.append(Observation(rel, _find(lines, start, json.dumps(a)[1:-1]),
                                                   "filesystem MCP server exposes a root or home directory"))
                env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
                for k, v in env.items():
                    if _SECRET_KEY.search(k) and isinstance(v, str) and _is_literal_secret(v):
                        obs.append(Observation(rel, _find(lines, start, f'"{k}"'), "inline credential in MCP server env"))
                hdr = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
                for k, v in hdr.items():
                    if isinstance(v, str) and _SECRET_VAL.search(v):
                        obs.append(Observation(rel, _find(lines, start, f'"{k}"'), "inline credential in MCP server headers"))
                for a in args:
                    if _SECRET_VAL.search(a):
                        obs.append(Observation(rel, _find(lines, start, a), "inline credential in MCP server args"))
        else:
            code = strip_hash(text)
            for i, ln in enumerate(code.splitlines(), 1):
                m = re.search(r"\b(?:npx|bunx)\s+(?:-y|--yes)\s+([^\s\"',\]]+)", ln)
                u = re.search(r"\buvx\s+([^\s\"',\]-][^\s\"',\]]*)", ln)
                ps = (_pin_state("npx", ["-y", m.group(1)]) if m else None) or (_pin_state("uvx", [u.group(1)]) if u else None)
                if ps and ps[1]:
                    obs.append(Observation(rel, i, _PIN_DETAIL[ps[1]]))
                if _SECRET_VAL.search(ln):
                    obs.append(Observation(rel, i, "inline credential in MCP config"))
    return RuleResult(sorted(set(obs), key=lambda o: (o.file, o.line, o.detail)), notes="; ".join(notes))


# --------------------------------------------------------------------------- 003
_DANGER = re.compile(
    r"allow_dangerous_(?:code|requests)\s*=\s*True|dangerouslyAllowBrowser\s*:\s*true|dangerously-skip-permissions"
    r"|[aA]uto_?[aA]pprove\w*\s*[:=]\s*(?:True|true|yes|Yes|on)\b|human_in_the_loop\s*[:=]\s*(?:False|false|no|No)\b")
_TOOL = re.compile(r"\b(?:ShellTool|PythonREPLTool|PythonAstREPLTool|PythonREPL|BashTool)\s*\(")
_APPROVAL = re.compile(
    r"HumanApprovalCallbackHandler|interrupt_before|require_approval|human_approval|requires_approval|\bapprove\(|"
    r"needs_approval|on_approval|approval_callback|ToolApproval|require_confirmation|confirm_tool")
# explicit isolation tokens; a bare word such as "sandbox" (or an import of a module named sandbox_*) is not enough
_SANDBOX = re.compile(
    r"\b\w*Sandbox\w*\b|\bsandbox\w*\s*[:=]\s*(?:True|true|[\"'](?!none|off|false|disabled|danger)\w)|"
    r"container_auto|container_reference|network_policy|\bdocker\b|\be2b\b|firejail|bwrap|gvisor|nsjail")
_OFF = re.compile(r"^\w*\s*[:=]\s*(?:False|false|None|null|no|off|0|[\"'](?:none|off|false|never|disabled|danger-full-access)[\"'])")


def _marker(text: str, rx: re.Pattern, *, skip_imports: bool = True) -> bool:
    """True if ``rx`` matches in ``text`` on a line that is not an import and is not assigned an 'off' value."""
    for ln in text.splitlines():
        if skip_imports and re.match(r"\s*(?:from|import)\b", ln):
            continue
        for m in rx.finditer(ln):
            if not _OFF.match(ln[m.end():]):
                return True
    return False


def _scope(lines: list[str], idx: int) -> str:
    """Text of the enclosing function (or class, for methods); module-level code if not inside a def."""
    def indent(x):
        return len(x) - len(x.lstrip())

    cur = indent(lines[idx])
    start = None
    for j in range(idx, -1, -1):
        if lines[j].strip() and indent(lines[j]) < cur and re.match(r"\s*(?:async\s+def|def|class|(?:async\s+)?function)\b", lines[j]):
            start, cur = j, indent(lines[j])
            if lines[j].lstrip().startswith(("class", "function", "async function")) or indent(lines[j]) == 0:
                break
    if start is None:
        # module level: every line that is not part of a def/class body
        keep, depth = [], None
        for ln in lines:
            if ln.strip() and depth is not None and indent(ln) <= depth:
                depth = None
            if depth is None and re.match(r"\s*(?:async\s+def|def|class|(?:async\s+)?function)\b", ln):
                depth = indent(ln)
                continue
            if depth is None:
                keep.append(ln)
        return "\n".join(keep)
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].strip() and indent(lines[j]) <= indent(lines[start]):
            end = j
            break
    return "\n".join(lines[start:end])


@rule("SEC-AI-003")
def dangerous_tools(ctx: ScanContext):
    files = _code_files(ctx) + [f for f in ctx.match("*.yaml", "*.yml", "*.toml") if not _TEST_PATH.search(f)]
    files = sorted({f for f in files if "node_modules/" not in f and _LLM_MARK.search(ctx.read(f))})
    if not files:
        return None
    obs = []
    for rel in files:
        text = ctx.read(rel)
        code = strip_c(text) if rel.endswith((".js", ".mjs", ".cjs", ".ts")) else strip_hash(text)
        lines = code.splitlines()
        for idx, ln in enumerate(lines):
            i = idx + 1
            if re.match(r"\s*(?:from|import)\b", ln):
                continue
            if _DANGER.search(ln):
                obs.append(Observation(rel, i, "agent configured with dangerous capability enabled"))
            elif _TOOL.search(ln):
                # approval / isolation must be in the same function (or class, for methods), not merely in the file
                sc = _scope(lines, idx)
                if not _marker(sc, _APPROVAL) and not _marker(sc, _SANDBOX):
                    obs.append(Observation(rel, i, "shell/REPL tool exposed to an agent without an approval or sandbox marker in "
                                                   "the same function (low confidence)"))
    return RuleResult(obs, notes="heuristic; shell/REPL sub-rule is low confidence")


# --------------------------------------------------------------------------- 004
_PICKLE_LOAD = re.compile(r"\b(?:pickle|cPickle|_pickle|dill|cloudpickle|joblib)\.loads?\s*\(")
_TORCH_LOAD = re.compile(r"\btorch\.load\s*\(")
_REMOTE_CODE = re.compile(r"\btrust_remote_code\s*=\s*True\b")
_DOWNLOAD = re.compile(
    r"hf_hub_download|snapshot_download|from_pretrained\s*\(|requests\.get|urlretrieve|urlopen|\bwget\b|"
    r"\bdownload\w*\s*\(|boto3|s3\.|httpx\.get|\.download_file\s*\(")


@rule("SEC-AI-004")
def model_artifact_loading(ctx: ScanContext):
    files = [f for f in ctx.match("*.py") if "node_modules/" not in f and not _TEST_PATH.search(f)]
    if not files:
        return None
    obs = []
    for rel in files:
        text = ctx.read(rel)
        if not re.search(r"trust_remote_code|pickle|joblib|dill|torch", text):
            continue
        lines = strip_hash(text).splitlines()
        for idx, ln in enumerate(lines):
            if re.match(r"\s*(?:from|import)\b", ln):
                continue
            if _REMOTE_CODE.search(ln) and not _in_string(ln, _REMOTE_CODE.search(ln).start()):
                obs.append(Observation(rel, idx + 1, "trust_remote_code=True executes code shipped with the model repository"))
                continue
            if _PICKLE_LOAD.search(ln) and not _in_string(ln, _PICKLE_LOAD.search(ln).start()):
                if _marker(_scope(lines, idx), _DOWNLOAD, skip_imports=True):
                    obs.append(Observation(rel, idx + 1, "pickle-family deserialisation in a function that also downloads data (low confidence)"))
                continue
            if _TORCH_LOAD.search(ln) and not _in_string(ln, _TORCH_LOAD.search(ln).start()):
                call = " ".join(lines[idx: idx + 4])
                if re.search(r"weights_only\s*=\s*False", call):
                    obs.append(Observation(rel, idx + 1, "torch.load with weights_only=False deserialises arbitrary pickle (low confidence)"))
                elif not re.search(r"weights_only\s*=", call) and _marker(_scope(lines, idx), _DOWNLOAD):
                    obs.append(Observation(rel, idx + 1, "torch.load without weights_only on downloaded data; default depends on torch version (low confidence)"))
    return RuleResult(obs, notes="heuristic; confidence low")
