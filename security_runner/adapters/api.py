"""Static API rules (SEC-API-001..006). Planned-only checks (050/051) live in metadata only."""
from __future__ import annotations

import re

from .base import Observation, RuleResult, ScanContext, rule
from .web import (_TESTY, CODE_GLOBS, CONFIG_GLOBS, DEV_NAME, JS_GLOBS, PY_GLOBS, call_span, line_of, parse_doc,
                  read_clean, result, scan_lines, sel)

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "trace")
_SPEC_NAME = re.compile(r"openapi|swagger|api|spec", re.I)
_SPEC_MARK = re.compile(r"""^\s*["']?(?:openapi|swagger)["']?\s*:\s*["']?[23]""", re.M)


def _load_specs(ctx: ScanContext):
    """Return (list[(rel, doc)], parse_errors). None if there is no spec file at all."""
    docs, errors = [], []
    cands = [f for f in sel(ctx, "*.json", "*.yaml", "*.yml") if _SPEC_NAME.search(f)]
    for rel in cands:
        text = ctx.read(rel)
        if not _SPEC_MARK.search(text):
            continue
        try:
            doc = parse_doc(rel, text)
        except (ValueError, IndexError, RecursionError):
            errors.append(rel)
            continue
        if isinstance(doc, dict):
            docs.append((rel, doc))
    if not docs and not errors:
        return None
    return docs, errors


def _operations(doc):
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return
    for p, item in paths.items():
        if not isinstance(item, dict):
            continue
        for m in HTTP_METHODS:
            op = item.get(m)
            if isinstance(op, dict):
                yield p, m, op, item.lines.get(m, 1), item


@rule("SEC-API-001")
def api_001(ctx: ScanContext):
    loaded = _load_specs(ctx)
    if loaded is None:
        return None
    docs, errors = loaded
    obs: list[Observation] = []
    for rel, doc in docs:
        global_sec = doc.get("security")
        has_global = isinstance(global_sec, list) and len(global_sec) > 0
        for p, m, op, line, _ in _operations(doc):
            if "security" in op:
                continue  # explicit requirement, or explicit "security: []" (deliberately public)
            if not has_global:
                obs.append(Observation(rel, line, f"{m.upper()} {p} has no security requirement"))
    res = result(obs)
    if errors:
        res.inconclusive = not obs
        res.notes = "could not parse: " + ", ".join(errors)
    return res


_KEY_PARAM = re.compile(r"(?i)^(?:x-)?(?:api[-_]?key|apikey|access[-_]?token|auth[-_]?token|token|key|secret|password|passwd|session[-_]?id)$")


@rule("SEC-API-002")
def api_002(ctx: ScanContext):
    loaded = _load_specs(ctx)
    if loaded is None:
        return None
    docs, errors = loaded
    obs: list[Observation] = []

    def check_param(rel, prm):
        if isinstance(prm, dict) and prm.get("in") == "query" and isinstance(prm.get("name"), str) \
                and _KEY_PARAM.match(prm["name"]) \
                and not re.search(r"(?i)pagina|cursor|continuation|next[ -]page|page[ -]token",
                                  str(prm.get("description") or "")):
            obs.append(Observation(rel, prm.lines.get("name", 1),
                                   "Credential-like parameter accepted in the query string"))

    for rel, doc in docs:
        comps = doc.get("components") if isinstance(doc.get("components"), dict) else {}
        schemes = {}
        if isinstance(comps.get("securitySchemes"), dict):
            schemes.update(comps["securitySchemes"])
        if isinstance(doc.get("securityDefinitions"), dict):
            schemes.update(doc["securityDefinitions"])
        for name, sc in schemes.items():
            if isinstance(sc, dict) and sc.get("type") == "apiKey" and sc.get("in") == "query":
                obs.append(Observation(rel, sc.lines.get("in", 1), "apiKey security scheme transmitted in query string"))
        if isinstance(comps.get("parameters"), dict):
            for prm in comps["parameters"].values():
                check_param(rel, prm)
        for p, m, op, line, item in _operations(doc):
            for prm in (op.get("parameters") or []):
                check_param(rel, prm)
        for p, item in (doc.get("paths") or {}).items():
            if isinstance(item, dict):
                for prm in (item.get("parameters") or []):
                    check_param(rel, prm)
    res = result(obs)
    if errors:
        res.notes = "could not parse: " + ", ".join(errors)
    return res


_LOCAL = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|[\w.-]*\.local|[\w.-]*\.localhost|[\w.-]*\.internal"
                    r"|[\w-]+)(?::\d+)?$", re.I)  # last alternative: single-label (compose/cluster service) host


def _is_local(host: str) -> bool:
    return bool(_LOCAL.match(host))


@rule("SEC-API-003")
def api_003(ctx: ScanContext):
    loaded = _load_specs(ctx)
    if loaded is None:
        return None
    docs, errors = loaded
    obs: list[Observation] = []
    for rel, doc in docs:
        servers = doc.get("servers")
        if isinstance(servers, list):
            for idx, sv in enumerate(servers):
                if isinstance(sv, dict) and isinstance(sv.get("url"), str):
                    m = re.match(r"http://([^/]*)", sv["url"], re.I)
                    if m and not _is_local(m.group(1)):
                        obs.append(Observation(rel, sv.lines.get("url", 1), "Server URL uses plain HTTP"))
        schemes = doc.get("schemes")
        if isinstance(schemes, list) and "http" in schemes and doc.get("swagger"):
            host = doc.get("host") if isinstance(doc.get("host"), str) else ""
            if not _is_local(host):
                idx = schemes.index("http")
                obs.append(Observation(rel, schemes.lines.get(idx, 1), "Swagger schemes allows plain HTTP"))
    res = result(obs)
    if errors:
        res.notes = "could not parse: " + ", ".join(errors)
    return res


# --------------------------------------------------------------------------------------
# SEC-API-004 JWT verification
# --------------------------------------------------------------------------------------
@rule("SEC-API-004")
def api_004(ctx: ScanContext):
    files = sel(ctx, *CODE_GLOBS)
    if not files:
        return None
    obs: list[Observation] = []
    for rel in files:
        text = read_clean(ctx, rel)
        flagged_lines: set[int] = set()
        for m in re.finditer(r"\b(?:jwt|jsonwebtoken|jws|jose)\.(?:verify|decode)\s*\(|\bjwtVerify\s*\(", text):
            span = call_span(text, m.end() - 1)
            line = line_of(text, m.start())
            if re.search(r"""verify_signature['"]?\s*[:=]\s*(?:False|false)|\bverify\s*=\s*False|\balgorithms?['"]?\s*[:=]\s*\[?\s*['"]none['"]|ignoreExpiration\s*:\s*true|verify_exp['"]?\s*[:=]\s*(?:False|false)|verify_aud['"]?\s*[:=]\s*(?:False|false)""", span, re.I):
                obs.append(Observation(rel, line, "JWT verification weakened (signature/alg/expiry/audience check disabled)"))
                flagged_lines.add(line)
            elif re.search(r"\.verify\(|jwtVerify\(", m.group(0)) or "decode" in m.group(0):
                is_verify = "verify" in m.group(0).lower() or re.search(r"algorithms", span)
                if is_verify and not re.search(r"audience|\baud\b", span, re.I):
                    obs.append(Observation(rel, line, "JWT verified without audience validation"))
        for i, ln_ in enumerate(text.split("\n"), 1):
            am = re.search(r"""\balg(?:orithm)?['"]?\s*[:=]\s*['"]none['"]""", ln_, re.I)
            if i not in {o.line for o in obs if o.file == rel} and am and \
                    (ln_[:am.start()].count('"') % 2 == 0 and ln_[:am.start()].count("'") % 2 == 0):
                obs.append(Observation(rel, i, "JWT 'none' algorithm configured"))
    return result(obs)


# --------------------------------------------------------------------------------------
# SEC-API-005 GraphQL introspection / playground
# --------------------------------------------------------------------------------------
_GQL_ENVGATE = re.compile(r"NODE_ENV|isDev|IS_DEV|is_dev|!==?\s*['\"]production|DEBUG|development|\bdev\b", re.I)
_GQL = re.compile(r"""(?<![\w-])["']?(?:introspection|playground|graphiql|graphql_ide)["']?\s*[:=]\s*(?:true|True)\b""")


@rule("SEC-API-005")
def api_005(ctx: ScanContext):
    files = [f for f in sel(ctx, *CODE_GLOBS, "*.json", "*.yml", "*.yaml", "*.toml", ".env", ".env.*")
             if not DEV_NAME.search(f) and not f.endswith("package-lock.json")]
    if not files:
        return None
    files = [f for f in files if not _TESTY.search(f)]
    return result(scan_lines(ctx, files, _GQL,
                             check=lambda line, m, ls, i, rel: not _GQL_ENVGATE.search("\n".join(ls[max(0, i - 3):i + 1])),
                             detail="GraphQL introspection/IDE enabled in production-facing configuration"))


# --------------------------------------------------------------------------------------
# SEC-API-006 mass assignment
# --------------------------------------------------------------------------------------
_MA_PY = re.compile(r"\b[A-Z]\w*(?:\.objects\.(?:create|update_or_create|get_or_create))?\(\s*\*\*\s*request\.(?:json|get_json\(\)|data|POST|form|args)\b|\.update\(\s*\*\*\s*request\.(?:json|get_json\(\)|data|POST)\b")
_MA_JS = re.compile(
    r"Object\.assign\(\s*[\w.]+\s*,\s*req\.body\s*\)|"
    r"\b[A-Z]\w*\.(?:create|insertMany|update|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate)\(\s*(?:[\w.]+\s*,\s*)?(?:\{\s*\.\.\.\s*)?req\.body\s*\}?\s*[,)]|"
    r"\bnew\s+(?!(?:Error|TypeError|Date|URL|URLSearchParams|Buffer|Map|Set|Promise|RegExp|Array|String|Number|Blob|"
    r"Uint8Array|Response|Request|Headers|FormData)\b)[A-Z]\w*\(\s*(?:\{\s*\.\.\.\s*)?req\.body\s*\}?\s*\)")


@rule("SEC-API-006")
def api_006(ctx: ScanContext):
    js = sel(ctx, *JS_GLOBS)
    py = sel(ctx, *PY_GLOBS)
    if not js and not py:
        return None
    d = "Request body bound wholesale to a model (mass assignment)"
    obs = scan_lines(ctx, py, _MA_PY, detail=d) + scan_lines(ctx, js, _MA_JS, detail=d)
    return result(obs)
