"""Static supply-chain rules (SEC-SC-001..006, 008). SEC-SC-020 is external (osv-scanner) metadata only."""
from __future__ import annotations

import re

from .base import Observation, RuleResult, ScanContext, rule
from .web import SKIP_DIRS, clean, parse_json, read_clean, result, sel

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _in_vendor(rel: str) -> bool:
    return bool(SKIP_DIRS.intersection(rel.split("/")[:-1]))


def _pkg_jsons(ctx: ScanContext):
    """[(rel, doc|None)] for non-vendored package.json files."""
    out = []
    for rel in ctx.match("package.json"):
        if _in_vendor(rel):
            continue
        try:
            doc = parse_json(ctx.read(rel))
        except (ValueError, IndexError, RecursionError):
            doc = None
        out.append((rel, doc))
    return out


def _req_files(ctx: ScanContext) -> list[str]:
    return [f for f in sel(ctx, "requirements*.txt", "*-requirements.txt", "constraints*.txt")]


def _req_lines(ctx: ScanContext, rel: str):
    """Yield (lineno, spec) for dependency lines (comments, blanks and option lines dropped)."""
    for i, raw in enumerate(ctx.read(rel).split("\n"), 1):
        s = re.sub(r"\s+#.*$", "", raw).strip()
        if not s or s.startswith("#"):
            continue
        yield i, s


# --------------------------------------------------------------------------------------
# SEC-SC-001 manifest without lockfile
# --------------------------------------------------------------------------------------
_LOCKS = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"),
    "Pipfile": ("Pipfile.lock",),
    "Gemfile": ("Gemfile.lock",),
    "composer.json": ("composer.lock",),
    "Cargo.toml": ("Cargo.lock",),
}


# Trees whose manifests are not deployed applications of this repository: vendored/third-party code,
# examples/samples/demos, documentation and test fixtures. A manifest is only treated this way when the
# segment is a *parent directory* of a non-root manifest (a root manifest is always evaluated), so a
# top-level app is never hidden by this rule.
_NON_APP_DIRS = {"third_party", "third-party", "thirdparty", "vendored", "external", "extern",
                 "example", "examples", "sample", "samples", "demo", "demos", "docs", "doc", "documentation",
                 "test", "tests", "__tests__", "testdata", "test-data", "fixtures", "fixture", "e2e", "playground"}


def _in_non_app_tree(rel: str) -> bool:
    return bool(_NON_APP_DIRS.intersection(s.lower() for s in rel.split("/")[:-1]))


def _has_lock(ctx: ScanContext, rel: str, names) -> bool:
    d = rel.rsplit("/", 1)[0] if "/" in rel else ""
    fileset = set(ctx.files)
    # same directory or any ancestor (workspace roots)
    while True:
        for n in names:
            if (f"{d}/{n}" if d else n) in fileset:
                return True
        if not d:
            return False
        d = d.rsplit("/", 1)[0] if "/" in d else ""


@rule("SEC-SC-001")
def sc_001(ctx: ScanContext):
    manifests = []
    for name in _LOCKS:
        manifests += [f for f in ctx.match(name) if not _in_vendor(f)]
    for f in ctx.match("pyproject.toml"):
        if not _in_vendor(f):
            manifests.append(f)
    if not manifests:
        return None
    obs: list[Observation] = []
    for rel in sorted(manifests):
        if _in_non_app_tree(rel):
            continue  # vendored / example / docs / test tree: not a deployed application of this repo
        text = ctx.read(rel)
        base = rel.rsplit("/", 1)[-1]
        if base == "package.json":
            try:
                doc = parse_json(text)
                if not any(isinstance(doc.get(s), dict) and doc.get(s) for s in DEP_SECTIONS):
                    continue
                scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
                if any(k in doc for k in ("main", "module", "exports", "types", "typings", "bin", "files", "keywords", "publishConfig", "sideEffects", "peerDependencies")) \
                        and doc.get("private") is not True and "start" not in scripts:
                    continue  # published library: lockfiles are not committed/consumed downstream
            except (ValueError, IndexError, RecursionError):
                pass
            names = _LOCKS[base]
        elif base == "composer.json":
            try:
                doc = parse_json(text)
                if not any(isinstance(doc.get(k), dict) and doc.get(k) for k in ("require", "require-dev")) \
                        or doc.get("type") in ("library", "component", "metapackage"):
                    continue  # no dependencies, or a published library
            except (ValueError, IndexError, RecursionError, AttributeError):
                pass
            names = _LOCKS[base]
        elif base == "pyproject.toml":
            if "[tool.poetry" in text:
                # Library heuristic: package metadata aimed at an index (classifiers/keywords) and no
                # explicit `package-mode = false` (poetry's marker for a non-package application).
                if re.search(r"^\s*(?:classifiers|keywords)\s*=", text, re.M) \
                        and not re.search(r"^\s*package-mode\s*=\s*false", text, re.M):
                    continue
                names = ("poetry.lock",)
            elif "[tool.pdm" in text:
                names = ("pdm.lock",)
            elif "[tool.uv" in text:
                names = ("uv.lock",)
            else:
                continue
        else:
            names = _LOCKS[base]
            if base == "Pipfile" and "setup.py" in {f.rsplit("/", 1)[-1] for f in ctx.files
                                                   if f.rsplit("/", 1)[0] == rel.rsplit("/", 1)[0] or "/" not in f and "/" not in rel}:
                continue  # Pipfile only provides a dev environment for an installable library (setup.py)
            _pre = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
            if base == "Cargo.toml" and ("[lib]" in text or _pre + "src/lib.rs" in set(ctx.files)) \
                    and "[[bin]]" not in text and _pre + "src/main.rs" not in set(ctx.files):
                continue  # library crate: committing Cargo.lock is optional
            if base == "Gemfile" and re.search(r"^\s*gemspec\b", text, re.M):
                continue  # gem library
        if not _has_lock(ctx, rel, names):
            obs.append(Observation(rel, 1, f"Dependency manifest has no lockfile ({' / '.join(names[:2])})"))
    return result(obs)


# --------------------------------------------------------------------------------------
# SEC-SC-002 floating specs
# --------------------------------------------------------------------------------------
_PINNED_GIT_REF = re.compile(r"^(?:semver:.*|v?\d+\.\d+\.\d+.*|[0-9a-f]{40})$")
_GIT_SPEC = re.compile(r"^(?:git\+|git://|github:|gitlab:|bitbucket:|[\w.-]+/[\w.-]+(?:#|$))")


def _floating_npm(spec: str) -> str | None:
    s = spec.strip()
    if s in ("", "*", "x", "X", "latest"):
        return "wildcard/latest version spec"
    if re.fullmatch(r"[A-Za-z][\w-]*", s):
        return "dist-tag instead of a version"
    if re.fullmatch(r">=?\s*[\d.]+", s):
        return "open-ended version range"
    if re.match(r"^(?:git\+|git://|github:|gitlab:|bitbucket:)", s) or re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", s):
        ref = s.split("#", 1)[1] if "#" in s else ""
        if not _PINNED_GIT_REF.match(ref):
            return "git dependency tracks a branch/default HEAD"
    return None


_REQ_SHAPE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*(?:(?:[<>=!~]=?|===)\s*[^\s;#]+(?:\s*,\s*[<>=!~]=?\s*[^\s;#]+)*)?"
                        r"\s*(?:;.*)?(?:\s+--hash.*)?\s*\\?|[A-Za-z0-9][\w.-]*\s*@\s*\S+|(?:git\+|https?://|\.|/|file:).*)$")


@rule("SEC-SC-002")
def sc_002(ctx: ScanContext):
    pkgs = _pkg_jsons(ctx)
    reqs = _req_files(ctx)
    if not pkgs and not reqs:
        return None
    obs: list[Observation] = []
    bad = []
    for rel, doc in pkgs:
        if doc is None:
            bad.append(rel)
            continue
        for sec in DEP_SECTIONS:
            d = doc.get(sec)
            if not isinstance(d, dict):
                continue
            for name, spec in d.items():
                if isinstance(spec, str):
                    why = _floating_npm(spec)
                    if why:
                        obs.append(Observation(rel, d.lines.get(name, 1), f"{sec}: '{name}' uses {why}"))
    for rel in reqs:
        specs = [x for x in _req_lines(ctx, rel) if not x[1].startswith("-")]
        bad_ = sum(1 for _, x in specs if not _REQ_SHAPE.match(x))
        if specs and bad_ / len(specs) > 0.3:
            continue  # prose / documentation that merely has a requirements*.txt name
        for ln_, s in _req_lines(ctx, rel):
            if s.startswith("-") and not s.startswith(("-e ", "--editable")):
                continue
            if not s.startswith("-") and not _REQ_SHAPE.match(s):
                continue
            s2 = re.sub(r"^(?:-e|--editable)\s+", "", s)
            if re.match(r"^(?:\.{1,2}(?:/|$)|/|file:)", s2):
                continue  # local path requirement
            if "git+" in s2:
                if not re.search(r"@[0-9a-f]{40}(?:#|$|\s)", s2):
                    obs.append(Observation(rel, ln_, "VCS requirement not pinned to a commit"))
                continue
            if "://" in s2 or " @ " in s2:
                continue
            spec = s2.split(";")[0].split("--hash")[0].strip().rstrip("\\").strip()
            if not re.search(r"===?\s*[\w.*!+-]+", spec):
                obs.append(Observation(rel, ln_, "Requirement is not pinned with =="))
    res = result(obs)
    if bad:
        res.notes = "could not parse: " + ", ".join(bad)
        res.inconclusive = not obs and not reqs
    return res


# --------------------------------------------------------------------------------------
# SEC-SC-003 npm lifecycle scripts
# --------------------------------------------------------------------------------------
_BENIGN_HOOK = re.compile(r"^(?:patch-package|husky(?:\s+install(?:\s+[\w./-]+)?)?|node-gyp rebuild|prisma generate)$")


@rule("SEC-SC-003")
def sc_003(ctx: ScanContext):
    pkgs = _pkg_jsons(ctx)
    if not pkgs:
        return None
    obs: list[Observation] = []
    for rel, doc in pkgs:
        scripts = doc.get("scripts") if isinstance(doc, dict) else None
        if not isinstance(scripts, dict):
            continue
        for name in ("preinstall", "install", "postinstall"):
            if name in scripts:
                if isinstance(scripts[name], str) and _BENIGN_HOOK.match(scripts[name].strip()):
                    continue
                obs.append(Observation(rel, scripts.lines.get(name, 1),
                                       f"'{name}' lifecycle script runs automatically on install"))
    return result(obs)


# --------------------------------------------------------------------------------------
# Workflow helpers
# --------------------------------------------------------------------------------------
def _workflow_files(ctx: ScanContext) -> list[str]:
    out = []
    for rel in ctx.files:
        base = rel.rsplit("/", 1)[-1]
        if rel.endswith((".yml", ".yaml")) and (rel.startswith((".github/workflows/", ".github/actions/"))
                                                 or "/.github/workflows/" in rel
                                                 or (base in ("action.yml", "action.yaml"))):
            out.append(rel)
    return out


@rule("SEC-SC-004")
def sc_004(ctx: ScanContext):
    files = _workflow_files(ctx)
    if not files:
        return None
    obs: list[Observation] = []
    rx = re.compile(r"""^\s*-?\s*uses\s*:\s*['"]?([^\s'"#]+)""")
    for rel in files:
        for i, line in enumerate(read_clean(ctx, rel).split("\n"), 1):
            m = rx.match(line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    obs.append(Observation(rel, i, "Docker action not pinned to an image digest"))
                continue
            if not re.search(r"@[0-9a-f]{40}$", ref):
                obs.append(Observation(rel, i, "Action not pinned to a full-length commit SHA"))
    return result(obs)


_INJ = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run|inputs)\b[^}]*?"
    r"\b(?:title|body|message|name|email|ref|label|default_branch|homepage|description|head_ref|branch)\b|github\.head_ref)")


@rule("SEC-SC-005")
def sc_005(ctx: ScanContext):
    files = _workflow_files(ctx)
    if not files:
        return None
    obs: list[Observation] = []
    for rel in files:
        text = read_clean(ctx, rel)
        lines = text.split("\n")
        is_prt = re.search(r"\bpull_request_target\b", text) is not None
        # (a) pull_request_target + checkout of PR head
        if is_prt:
            for i, ln_ in enumerate(lines, 1):
                if re.match(r"\s*(?:ref|repository)\s*:.*(?:github\.event\.pull_request\.head\.|github\.head_ref|refs/pull/)", ln_):
                    obs.append(Observation(rel, i, "pull_request_target workflow checks out untrusted PR head"))
        # (b) missing permissions
        if rel.startswith(".github/workflows/") or "/.github/workflows/" in rel:
            has_top = re.search(r"^permissions\s*:", text, re.M) is not None
            if not has_top:
                jobs_idx = next((i for i, l in enumerate(lines) if re.match(r"jobs\s*:\s*$", l)), None)
                if jobs_idx is not None:
                    job_indent = None
                    jobs: list[tuple[int, str]] = []
                    for i in range(jobs_idx + 1, len(lines)):
                        l = lines[i]
                        if not l.strip():
                            continue
                        ind = len(l) - len(l.lstrip())
                        if ind == 0:
                            break
                        if job_indent is None:
                            job_indent = ind
                        if ind == job_indent and re.match(r"\s*[\w-]+\s*:", l):
                            jobs.append((i, l.strip().split(":")[0]))
                    for n, (i, name) in enumerate(jobs):
                        end = jobs[n + 1][0] if n + 1 < len(jobs) else len(lines)
                        block = lines[i + 1:end]
                        if not any(re.match(r"\s*permissions\s*:", b) for b in block):
                            obs.append(Observation(rel, i + 1, f"Job '{name}' has no permissions block and none is set at workflow level"))
        # (c) expression injection in run:
        i = 0
        while i < len(lines):
            m = re.match(r"(\s*)(?:-\s*)?run\s*:\s*(.*)$", lines[i])
            if not m:
                i += 1
                continue
            base_ind = len(m.group(1))
            rest = m.group(2)
            if re.fullmatch(r"[|>][+-]?\d*", rest.strip()):
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base_ind):
                    if _INJ.search(lines[j]):
                        obs.append(Observation(rel, j + 1, "Untrusted event data interpolated into run: script"))
                    j += 1
                i = j
            else:
                if _INJ.search(rest):
                    obs.append(Observation(rel, i + 1, "Untrusted event data interpolated into run: command"))
                i += 1
    return result(obs)


# --------------------------------------------------------------------------------------
# SEC-SC-006 hardcoded secrets
# --------------------------------------------------------------------------------------
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tgz", ".jar", ".class",
             ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".bin", ".so", ".dll", ".exe", ".pyc", ".map",
             ".md", ".rst", ".lock", ".sum", ".min.js", ".example", ".sample", ".template", ".tmpl")
_DOC_NAME = re.compile(r"(?i)(?:^|/)(?:licen[cs]e|notice|thirdpartynotices|changelog|copying|authors|readme)[\w.-]*$")
_CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb", ".php", ".rs", ".c", ".h",
             ".cc", ".cpp", ".cs", ".swift")
_SKIP_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock",
               "expected.json")

_PROVIDER = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "private key block"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    (re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}"), "Stripe live key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}"), "LLM provider API key"),
    (re.compile(r"\bSG\.[\w-]{22}\.[\w-]{43}\b"), "SendGrid API key"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "npm access token"),
]
_GENERIC_Q = re.compile(
    r"""(?i)[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)[\w.-]*["']?\s*[:=]\s*["']([^"'\n]{8,})["']""")
_GENERIC_UQ = re.compile(
    r"""(?i)^\s*(?:export\s+)?[\w.-]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token)[\w.-]*\s*[:=]\s*([^\s"'#$<{\[*&!|>][^\s#]*)\s*$""")
_URL_CRED = re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^/\s@'\"]{6,})@(?!(?:[\w-]+\.)*example\.(?:com|org|net)\b|localhost\b)[\w.-]+")
_PLACEHOLDER = re.compile(r"(?i)your|xxxx|placeholder|change[_-]?me|<|>|\$\{|\{\{|dummy|redacted|fake|insert|todo|replace|"
                          r"\*\*\*|example|sample|none|null|true|false|process\.env|environ|getenv|\bpassword\b\W*$|%[sdr]|%\(|\{[^}]*\}")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_ENV_REF = re.compile(r"os\.environ|process\.env|getenv|ENV\[|secrets\.|\$\{\{")
_UQ_EXT = (".env", ".yml", ".yaml", ".properties", ".ini", ".cfg", ".conf")


_TEST_PATH = re.compile(r"(?:^|[/._-])(?:tests?|spec|specs|__tests__|conftest|mocks?|fixtures?|e2e|stubs?|testing|testdata|test_data|selftest)(?:[/._-]|$)",
                        re.I)


_KEYWORD = re.compile(r"(?i)password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|"
                      r"client[_-]?secret|private[_-]?key")


def _real_keyword(key: str) -> bool:
    """A credential word counts only when written as a word (not straddling camelCase like kSecReturn)."""
    if re.search(r"(?i)\blib\w*\.so\b|\.so(?:\.\d+)+|\.(?:dll|dylib)\b", key):
        return False  # shared-library file name used as a map key
    for m in _KEYWORD.finditer(key):
        t = m.group(0)
        compound = re.match(r"(?i)api|access|auth|client|private", t) is not None
        if compound or t == t.lower() or t == t.upper() or t == t.capitalize():
            return True
    return False


# --- iter3 (SC-006 precision): value shapes that are never key material --------------------------------
# Each family was measured as a false-positive family on benign third-party repos (see
# docs/RULE-ACCURACY-FIELD-iter3-sc006.md). They apply to the *generic* detector only; provider-format
# tokens and PEM keys do not pass through them.
_ALGO_TOKENS = {"hmac", "sha", "sha1", "sha2", "sha3", "sha224", "sha256", "sha384", "sha512", "md5", "aes", "rsa", "des", "3des",
                "ecdsa", "eddsa", "ed25519", "x25519", "chacha20", "poly1305", "gcm", "cbc", "ctr", "ecb", "pkcs1", "pkcs5",
                "pkcs7", "pkcs8", "oaep", "pss", "hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512",
                "ps256", "pbkdf2", "bcrypt", "scrypt", "argon2", "argon2id", "argon2i", "argon2d", "blake2b", "blake2s",
                "hkdf", "v1", "v2", "v3", "hmacsha256", "hs", "rs", "es", "ps"}
_FILE_EXT = r"(?:txt|pem|key|json|ya?ml|env|conf|cfg|crt|cer|pub|p12|pfx|jks|properties|ini|xml|toml|secret|secrets|token|pass|passwd|htpasswd|gpg|asc|kdbx)"
_SECRET_REF = re.compile(r"(?i)^(?:env|vault|op|file|ssm|ref\+[a-z]+|secretref|secretsmanager|keyvault|gcpsm|awssm|k8s|kms|sops)[:/]|^arn:aws|^ENC\[|^projects/[^/]+/secrets/")


def _sequential_run(v: str, n: int = 8) -> bool:
    """True when v holds an ascending run of >= n consecutive letters/digits ('abcdefgh', '01234567', '1234567890'):
    an alphabet / charset constant or an obviously hand-typed placeholder, not random key material."""
    def nxt(a: str, b: str) -> bool:
        if not (a.isascii() and b.isascii() and a.isalnum() and b.isalnum()):
            return False
        if a.isdigit() != b.isdigit() or a.isupper() != b.isupper():
            return False
        return ord(b) == ord(a) + 1 or (a == "9" and b == "0")
    run = 1
    for a, b in zip(v, v[1:]):
        run = run + 1 if nxt(a, b) else 1
        if run >= n:
            return True
    return False


def _readable_base64(v: str) -> bool:
    """Base64 whose payload is readable prose ('my-secret-key-should-be-changed...'): a documented dev default."""
    import base64
    if len(v) < 24 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
        return False
    try:
        d = base64.b64decode(v + "=" * (-len(v) % 4), validate=True).decode("ascii")
    except Exception:
        return False
    d = d.lower()
    # must read as an instruction to replace it ('...should-be-changed-in-production'), not merely be ASCII
    return bool(re.fullmatch(r"[a-z][a-z0-9 _.-]*[a-z0-9]\s*", d)) and bool(re.search(r"should|changed?[-_ ]|replace|your[-_ ]|placeholder|default|do[-_ ]not|please", d))


def _non_secret_value_shape(v: str) -> bool:
    if re.search(r"[^\x00-\x24F\u2000-\u206F]", v) and any(ch.isalpha() and ord(ch) > 0x24F for ch in v):
        return True   # non-Latin-script letters (CJK, Cyrillic, Arabic, ...): human-language UI text, not a key
    if re.fullmatch(r"(?:catalog|workspace|npm|link|file|portal|patch|jsr|git\+\w+):[^\s]*", v) or \
            re.fullmatch(r"[~^<>=v ]*\d+(?:\.[\dx*]+){1,3}(?:[-+][\w.]+)?", v):
        return True   # dependency specifier ('catalog:', 'workspace:*', '^1.2.3') in a manifest key like "secretlint"
    if _sequential_run(v):
        return True   # character-set / alphabet constant ('abc..xyz0123456789') or typed placeholder
    toks = [t for t in re.split(r"[-_/+ .]+", v.lower()) if t]
    if len(toks) >= 1 and all(t in _ALGO_TOKENS or re.fullmatch(r"\d{1,4}", t) for t in toks) and not re.fullmatch(r"\d+", v):
        return True   # algorithm / cipher / scheme name ('HS256', 'aes-256-gcm', 'hmac-sha256')
    if " " not in v and (re.search(r"\." + _FILE_EXT + "$", v, re.I) or re.fullmatch(r"(?:[a-z0-9._-]{1,30}/){2,}[a-z0-9._-]*", v) and not re.search(r"\d[a-z]+\d", v)) \
            and re.fullmatch(r"[\w./-]+", v):
        return True   # relative file path / file name pointing at a secret file ('config/secrets.yml', 'db_password.txt')
    if _SECRET_REF.match(v):
        return True   # reference into a secret store / env, not the secret itself
    if re.fullmatch(r"[a-z]+(?:[:/.][a-z_]+)+", v):
        return True   # lowercase scope / permission identifier ('read:admin', 'write:repository')
    ws = re.split(r"[-_.]+", v)
    if len(ws) >= 2 and v == v.lower() and all(re.fullmatch(r"[a-z]{2,}\d{0,2}|v?\d{1,2}", t) for t in ws):
        return True   # kebab/snake identifier or feature flag ('amazons3_accesskey', 'passwordless-login-v2')
    if re.search(r"[!=]=?|\bin\b", v) and re.fullmatch(r"[\w.!=,/ -]+", v) and re.search(r"[a-z]{3,}[.!=]", v) and "!=" in v:
        return True   # selector expression ('type!=kubernetes.io/...')
    if _readable_base64(v):
        return True   # base64 of a readable placeholder phrase
    return False


def _looks_secret(v: str) -> bool:
    if _PLACEHOLDER.search(v) or re.search(r"\s", v) or re.match(r"\$(?:2[aby]|argon2|pbkdf2|scrypt)|(?:pbkdf2|scrypt|bcrypt)[:$]", v):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", v) and not re.search(r"\d", v):
        return False
    if re.match(r"\d{4}-\d{2}-\d{2}(?:[T ]|$)", v) or re.match(r"https?://[^@\s]*$", v) or re.fullmatch(r"[a-z]+/[a-z]+", v):
        return False  # timestamp / plain URL / service-principal-like path
    if "::" in v or re.fullmatch(r"[^\W\d_]+[?!]*", v) or re.fullmatch(r"[A-Za-z]+(?:[-_.][A-Za-z]+)+", v):
        return False  # C++/enum-style name or a bare word / type name (unicode-aware: 'Lösenord', 'contraseña')
    if re.fullmatch(r"\$\{[A-Za-z_]\w*(?::?[-=?+][^}]*)?\}|\$[A-Z_][A-Z0-9_]*|\$\([^()]*\)", v):
        return False  # iter2: shell/env variable reference ($VAR, ${var:-x}, $(cmd)): value comes from the environment
    if re.fullmatch(r"_*[a-z]+(?:[-_.][a-z]+)*[-_.]", v) or re.fullmatch(r"_+[a-z][a-z0-9]*(?:_[a-z0-9]+)*", v):
        return False  # iter2: key PREFIX ('django-insecure-') or underscore-led snake identifier ('_app_claim_name')
    if _UUID.match(v) or re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", v):
        return False  # GUID / UPPER_SNAKE constant name
    if v.startswith(("/", "./", "~/")) or re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)+", v):
        return False  # filesystem path / lowercase-word identifier (e.g. header name x-api-key)
    if _non_secret_value_shape(v):
        return False
    has_alpha = re.search(r"[A-Za-z]", v) is not None
    has_digit = re.search(r"\d", v) is not None
    has_special = re.search(r"[^A-Za-z0-9]", v) is not None
    return bool(has_alpha and (has_digit or has_special))


# --- precision heuristics for the *generic* (non provider-format) detector only -------------------
# Provider-format tokens (AKIA.., ghp_.., xox.., PEM keys) never go through these checks.
_DOCS_PATH = re.compile(r"(?:^|/)(?:docs?|documentation|examples?|samples?|demos?|tutorials?)/", re.I)
# Files that smoke-test / package / verify a build against a throwaway environment.
_SMOKE_TOKENS = {"smoke", "packaging", "package", "sanity", "verify", "e2e", "ci", "healthcheck", "selftest"}
# Identity on a reserved (RFC 2606/6761) domain => synthetic account that cannot exist on the internet.
_RESERVED_ID = re.compile(r"(?i)[\w.+-]+@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|[\w-]+\.(?:test|invalid|example|localhost)|localhost)\b")
# Names a secret / says how to obtain it, rather than being the secret.
_NAME_SUFFIX = re.compile(r"(?:[_-](?:env|envvar|var|name|file|path|label|header|field|prompt|placeholder|hint|policy|regex|pattern|type|length|claim|prefix|suffix|scheme|cookie|param|attr|attribute|hash|digest|checksum|fingerprint|thumbprint|selector|algorithm|alg|algo|hashing_algorithm))$"
                          r"|[a-z](?:Env|Var|Name|File|Path|Label|Header|Field|Prompt|Placeholder|Hint|Policy|Regex|Pattern|Type|Length|Claim|Prefix|Suffix|Scheme|Cookie|Param|Attr|Attribute|Hash|Digest|Checksum|Fingerprint|Thumbprint|Selector|Algorithm|Alg|Algo)$", re.I)
# Well-known documentation / tutorial sample secrets and obviously synthetic shapes.
_SAMPLE_VALUE = re.compile(r"(?i)^(?:hunter2\d*|letmein|qwerty\w*|s3cr3t\w*|secret\d*|password\d*|p@ss?w0rd\d*|passw0rd\d*|supersecret\w*|mysecret\w*|"
                           r"correct[-_ ]?horse\w*|(?:test|demo|mock|sample)[-_.]?[\w.-]*|\w*(?:abc123|abcdef|123456|12345678)\w*|(.)\1{5,})$")
_VECTOR_MARK = re.compile(r"(?i)test[ _-]?vectors?|known[ _-]answer|\bKAT\b|\bRFC[ -]?\d{3,4}\b|wycheproof|ciphertext|plaintext|\bnonce\b")
_VECTOR_PATH = re.compile(r"(?i)(?:^|[/._-])(?:vectors?|testvectors?|kat|rfc\d+|wycheproof)(?:[/._-]|$)")


def _entropy(v: str) -> float:
    from math import log2
    return -sum(c / len(v) * log2(c / len(v)) for c in (v.count(x) for x in set(v))) if v else 0.0


def _high_entropy_key(v: str) -> bool:
    return len(v) >= 24 and _entropy(v) >= 3.5 and re.search(r"[A-Za-z]", v) is not None and re.search(r"\d", v) is not None


def _generic_noise(rel: str, key: str, val: str, lines_all: list[str], i: int) -> bool:
    """True when a generic credential-looking literal is documentation/test material rather than a secret."""
    key = key.strip(" \t\"'")
    if _NAME_SUFFIX.search(key):
        return True   # `password_env = "DB_PASS_9"`, `secretName`: key names a secret location, not its value
    if _DOCS_PATH.search(rel):
        return True   # documentation / example / sample / demo trees (provider tokens are handled elsewhere)
    if _SAMPLE_VALUE.match(val):
        return True   # tutorial sample values (hunter2, password123, test-xxx, 12345678, aaaaaa...)
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]{16,}", val) and (
            _VECTOR_PATH.search(rel) or any(_VECTOR_MARK.search(x) for x in lines_all[max(0, i - 11):i + 10])):
        return True   # hex key material inside a crypto known-answer test / RFC vector table
    toks = set(re.split(r"[/._-]+", rel.lower()))
    if not _high_entropy_key(val) and _RESERVED_ID.search("\n".join(lines_all[max(0, i - 4):i + 3])) and (
            toks & _SMOKE_TOKENS or rel.lower().endswith((".json", ".http", ".yml", ".yaml", ".txt", ".sh"))):
        return True   # smoke script / API request sample logging in as a synthetic reserved-domain (example.com) account
    return False


# iter2: translation catalogs. UI text such as "password": "Lösenord" or a .po msgstr describing a
# `user:password@host` URL template is human language, not key material. Rule: in a locale-named
# directory (or .po/.pot) the *generic* and URL-credential detectors only fire when the value is
# TOKEN-SHAPED (ASCII, >=20 chars, no whitespace, letters+digits, entropy >= 3.5). Provider-format
# tokens (ghp_, AKIA.., xox.., PEM keys ...) are never subject to this and are always reported.
_LOCALE_PATH = re.compile(r"(?i)\.pot?$|(?:^|/)(?:(?-i:[a-z]{2,3}[-_](?:[A-Z]{2}|[A-Z][a-z]{3}|\d{3})(?:[-_][A-Za-z0-9]{2,4})?)|(?:en|de|fr|es|it|pt|ru|ja|zh|ko|nl|pl|sv|tr|cs|da|fi|nb|hu|ro|uk|ar|he|vi|th|el|bg|hr|sk|sl|sr|lt|lv|et|ca|eu|gl|fa|hi|bn|ms))\.(?:ya?ml|json|ini|properties|toml)$|(?:^|/)(?:language|languages|lang|langs|locale|locales|l10n|i18n|translations?|lc_messages)/")


def _token_shaped(v: str) -> bool:
    return (len(v) >= 20 and v.isascii() and not re.search(r"\s", v) and re.search(r"[A-Za-z]", v) is not None
            and re.search(r"\d", v) is not None and _entropy(v) >= 3.5)


def _PROVIDER_ANY(line: str) -> bool:
    return any(rx.search(line) for rx, _ in _PROVIDER)


@rule("SEC-SC-006")
def sc_006(ctx: ScanContext):
    files = []
    for rel in ctx.files:
        base = rel.rsplit("/", 1)[-1]
        if _in_vendor(rel) or base in _SKIP_NAMES or rel.lower().endswith(_SKIP_EXT) or _DOC_NAME.search(rel):
            continue
        files.append(rel)
    if not files:
        return None
    obs: list[Observation] = []
    for rel in files:
        text = ctx.read(rel)
        if "\x00" in text[:4096]:
            continue
        base = rel.rsplit("/", 1)[-1].lower()
        uq = base.startswith(".env") or base.endswith(_UQ_EXT)
        lines_all = text.split("\n")
        gen_lines = clean(text, rel).split("\n") if rel.lower().endswith(_CODE_EXT) else text.split("\n")
        for i, line in enumerate(text.split("\n"), 1):
            if len(line) > 2000:
                continue
            gen_line = gen_lines[i - 1] if i - 1 < len(gen_lines) else line   # comments/docstrings blanked
            hit = None
            for rx, name in _PROVIDER:
                if rx.search(line):
                    hit = name
                    break
            if hit == "private key block":
                nxt = lines_all[i].strip() if i < len(lines_all) else ""
                has_body = re.search(r"-----[\\n]*[\"']?[A-Za-z0-9+/]{16,}", line.split("-----", 2)[-1] if line.count("-----") >= 2 else "") \
                    or re.match(r"[A-Za-z0-9+/=]{16,}$|(?:Proc-Type|DEK-Info|Version|Comment):", nxt)
                if "XXXX" in line or _TEST_PATH.search(rel) or not has_body:
                    hit = None  # documentation example / test vector / bare header constant
            if hit and hit != "private key block":
                tok = next(mm.group(0) for rx, nm in _PROVIDER if nm == hit for mm in [rx.search(line)] if mm)
                if _sequential_run(tok, 10) or re.search(r"(.)\1{9,}", tok):
                    hit = None  # iter3: hand-typed placeholder token (ascending 0123456789/abcdefghij run or one repeated char)
            if hit == "AWS access key ID" and "EXAMPLE" in line and (
                    re.search(r"(?i)example|docs?/|sample|test", rel) or _LOCALE_PATH.search(rel)):
                hit = None  # AWS documentation sample key in docs/examples/tests
            if hit is None and re.search(r"(?i)\bexamples?\b|e\.g\.|usage:", line) and not _PROVIDER_ANY(line):
                continue
            if hit is None and not _ENV_REF.search(line) and not _TEST_PATH.search(rel) and len(line) <= 600:
                line = gen_line
                m = _GENERIC_Q.search(line)
                kname = re.split(r"[:=]", m.group(0), maxsplit=1)[0] if m else ""
                if m and _real_keyword(kname) and _looks_secret(m.group(1)) \
                        and not (_LOCALE_PATH.search(rel) and not _token_shaped(m.group(1))) \
                        and not _generic_noise(rel, kname, m.group(1), lines_all, i - 1):
                    hit = "hardcoded credential literal"
                elif uq:
                    m = _GENERIC_UQ.match(line)
                    if m and _looks_secret(m.group(1)) \
                            and not (_LOCALE_PATH.search(rel) and not _token_shaped(m.group(1))) \
                            and not _generic_noise(rel, re.split(r"[:=]", m.group(0), maxsplit=1)[0], m.group(1), lines_all, i - 1):
                        hit = "hardcoded credential value in configuration"
                if hit is None:
                    m = _URL_CRED.search(line)
                    if m and _looks_secret(m.group(1)) and not (_LOCALE_PATH.search(rel) and not _token_shaped(m.group(1))):
                        hit = "credentials embedded in a URL"
            if hit:
                obs.append(Observation(rel, i, f"Possible hardcoded secret ({hit}); value withheld"))
    return result(obs)


# --------------------------------------------------------------------------------------
# SEC-SC-008 dependencies from VCS / URL / http
# --------------------------------------------------------------------------------------
@rule("SEC-SC-008")
def sc_008(ctx: ScanContext):
    pkgs = _pkg_jsons(ctx)
    reqs = _req_files(ctx)
    locks = [f for f in ctx.match("package-lock.json", "yarn.lock") if not _in_vendor(f)]
    if not pkgs and not reqs and not locks:
        return None
    obs: list[Observation] = []
    for rel, doc in pkgs:
        if not isinstance(doc, dict):
            continue
        for sec in DEP_SECTIONS:
            d = doc.get(sec)
            if not isinstance(d, dict):
                continue
            for name, spec in d.items():
                if not isinstance(spec, str):
                    continue
                s = spec.strip()
                if re.match(r"^(?:git\+|git://|github:|gitlab:|bitbucket:|https?://|ssh://)", s) or \
                        re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", s):
                    kind = "plain-HTTP URL" if s.startswith("http://") else "VCS/URL"
                    obs.append(Observation(rel, d.lines.get(name, 1), f"{sec}: '{name}' is fetched from a {kind} source"))
    for rel in reqs:
        for ln_, s in _req_lines(ctx, rel):
            if re.search(r"(?:^|\s)(?:--index-url|--extra-index-url|-i|-f|--find-links)[\s=]+http://(?!localhost|127\.|\[::1\]|0\.0\.0\.0)", s):
                obs.append(Observation(rel, ln_, "Package index configured over plain HTTP"))
            elif re.search(r"git\+|^\s*(?:-e\s+)?(?:https?|git)://|\s@\s*(?:https?|git\+)", s):
                obs.append(Observation(rel, ln_, "Requirement fetched from VCS/URL instead of a package index"))
    for rel in locks:
        for i, line in enumerate(ctx.read(rel).split("\n"), 1):
            if re.search(r"""resolved["']?\s*[:\s]\s*["']http://""", line):
                obs.append(Observation(rel, i, "Lockfile resolves a package over plain HTTP"))
    return result(obs)
