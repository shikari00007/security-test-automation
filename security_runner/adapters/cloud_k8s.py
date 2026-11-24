"""Cloud / Kubernetes static rules (SEC-K8S-001..006). YAML is handled with tolerant
line-oriented parsing (no YAML library, no anchors/aliases expanded)."""
from __future__ import annotations

import re

from .android import rule
from .base import Observation, RuleResult, ScanContext


# --------------------------------------------------------------------------- helpers
def _k8s_files(ctx: ScanContext) -> list[str]:
    out = []
    for rel in ctx.match("*.yaml", "*.yml"):
        t = ctx.read(rel)
        if re.search(r"(?m)^\s*apiVersion\s*:", t) and re.search(r"(?m)^\s*kind\s*:", t):
            out.append(rel)
    return out


def _docs(text: str):
    """Yield (kind, [(lineno, line)]) per YAML document; comment lines removed."""
    cur: list[tuple[int, str]] = []
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        if re.match(r"---(?:\s|$)", ln):
            out.append(cur)
            cur = []
            continue
        if re.match(r"\s*#", ln):
            continue
        cur.append((i, ln))
    out.append(cur)
    res = []
    for d in out:
        kind = None
        for _, ln in d:
            m = re.match(r"kind\s*:\s*['\"]?([A-Za-z]+)", ln)
            if m:
                kind = m.group(1)
                break
        res.append((kind, d))
    return res


_BLOCK_SCALAR = re.compile(r"(?::|^\s*-)\s*[|>][+-]?\d*\s*(?:#.*)?$")
_TPL_OPEN = re.compile(r"\{\{-?\s*(?:if|with|range|define|block)\b")
_TPL_END = re.compile(r"\{\{-?\s*end\b")


def _live_lines(doc):
    """Document lines minus block-scalar bodies (embedded scripts/configs) and Helm conditional/loop bodies."""
    out, skip_indent, tpl = [], None, 0
    for i, ln in doc:
        if skip_indent is not None:
            if not ln.strip() or len(ln) - len(ln.lstrip()) > skip_indent:
                continue
            skip_indent = None
        if _TPL_END.search(ln):
            tpl = max(0, tpl - 1)
            continue
        if _TPL_OPEN.search(ln):
            tpl += 1
            continue
        if tpl:
            continue
        out.append((i, ln))
        if _BLOCK_SCALAR.search(ln):
            skip_indent = len(ln) - len(ln.lstrip())
    return out


# Kinds whose content is inert data / policy text rather than a workload spec.
_INERT = {"ConfigMap", "Secret", "PodSecurityPolicy", "ConstraintTemplate", "Kustomization", "NetworkPolicy",
          "Service", "Ingress", "SealedSecret", "ExternalSecret",
          "CustomResourceDefinition", "Cluster", "ClusterPolicy", "Policy"}   # schemas / kind-cluster config / policy text


def _grep_k8s(ctx: ScanContext, rx: "re.Pattern[str]", detail: str):
    files = _k8s_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        for kind, doc in _docs(ctx.read(rel)):
            if kind in _INERT:
                continue
            for i, ln in _live_lines(doc):
                if "{{" in ln:
                    continue
                if rx.search(ln):
                    obs.append(Observation(rel, i, detail))
    return RuleResult(obs)


# --------------------------------------------------------------------------- 001 / 002
_PRIV = re.compile(r"^\s*(?:-\s*)?(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*['\"]?true\b"
                   r"|^\s*(?:-\s*)?hostPath\s*:"
                   r"|\{[^}]*\b(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*['\"]?true\b"
                   r"|\{[^}]*\bhostPath\s*:", re.I)


@rule("SEC-K8S-001")
def privileged(ctx: ScanContext):
    return _grep_k8s(ctx, _PRIV, "privileged container setting, host namespace sharing or hostPath mount")


_ROOT = re.compile(r"^\s*(?:-\s*)?(?:runAsUser\s*:\s*['\"]?0['\"]?\s*(?:#.*)?$|runAsNonRoot\s*:\s*['\"]?false\b)"
                   r"|\{[^}]*\brunAsUser\s*:\s*['\"]?0['\"]?\s*[,}]|\{[^}]*\brunAsNonRoot\s*:\s*['\"]?false\b", re.I)


@rule("SEC-K8S-002")
def run_as_root(ctx: ScanContext):
    return _grep_k8s(ctx, _ROOT, "container explicitly runs as root")


# --------------------------------------------------------------------------- 003 Dockerfile
def _dockerfiles(ctx: ScanContext) -> list[str]:
    from .android import is_test_path      # test-fixture images (tests/ dirs) are not shipped
    return [f for f in ctx.match("Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile", "Containerfile") if not is_test_path(f)]


@rule("SEC-K8S-003")
def dockerfile(ctx: ScanContext):
    files = _dockerfiles(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        lines = [(i, ln) for i, ln in enumerate(ctx.read(rel).splitlines(), 1) if not re.match(r"\s*#", ln)]
        stages: set[str] = set()
        last_from = None
        user_ok = False
        for i, ln in lines:
            m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", ln, re.I)
            if m:
                img, name = m.group(1), m.group(2)
                last_from = i
                user_ok = False
                nonroot_img = bool(re.search(r":[\w.-]*nonroot|^cgr\.dev/chainguard/", img, re.I))
                if img.lower() != "scratch" and img.lower() not in stages and "$" not in img and "@sha256:" not in img:
                    tag = img.rsplit("/", 1)[-1]
                    if ":" not in tag:
                        obs.append(Observation(rel, i, "base image has no tag (implicitly latest)"))
                    elif tag.endswith(":latest"):
                        obs.append(Observation(rel, i, "base image uses the mutable :latest tag"))
                user_ok = nonroot_img      # distroless :nonroot / chainguard images default to non-root
                if name:
                    stages.add(name.lower())
                continue
            u = re.match(r"\s*USER\s+(\S+)", ln, re.I)
            if u:
                user_ok = u.group(1).split(":")[0].lower() not in ("root", "0")
            if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", ln):
                obs.append(Observation(rel, i, "remote script piped straight into a shell"))
        if last_from is not None and not user_ok:
            obs.append(Observation(rel, last_from, "final image stage never sets a non-root USER"))
    return RuleResult(sorted(obs, key=lambda o: (o.file, o.line)))


# --------------------------------------------------------------------------- 004 Terraform
_ADMIN_PORTS = {22, 23, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 1433}


def _strip_str(ln: str) -> str:
    return re.sub(r'"[^"]*"', '""', ln)


def _block_end(lines: list[str], start: int) -> int:
    d = 0
    for k in range(start, len(lines)):
        ln = _strip_str(lines[k])
        d += ln.count("{") - ln.count("}")
        if d <= 0 and k >= start and "{" in "".join(_strip_str(x) for x in lines[start:k + 1]):
            return k
    return len(lines) - 1


def _block_bounds(lines: list[str], idx: int):
    """Innermost brace block enclosing line idx (exclusive of idx itself) -> (start, end)."""
    depth = 0
    for j in range(idx - 1, -1, -1):
        ln = _strip_str(lines[j])
        depth += ln.count("}") - ln.count("{")
        if depth < 0:
            return j, _block_end(lines, j)
    return None


def _open_cidr_line(lines: list[str], i: int) -> bool:
    """Line i is a world-open CIDR assigned to a cidr_* attribute (single-line or multi-line list)."""
    ln = lines[i]
    if not re.search(r'"0\.0\.0\.0/0"|"::/0"', ln):
        return False
    if re.match(r"\s*\w*cidr\w*\s*=", ln, re.I):
        return True
    if "=" in ln:
        return False
    for j in range(i - 1, max(-1, i - 40), -1):          # continuation inside `cidr_blocks = [ ... ]`
        if "]" in lines[j]:
            return False
        if re.match(r"\s*\w*cidr\w*\s*=\s*\[", lines[j], re.I):
            return True
    return False


def _tf(ctx: ScanContext) -> list[str]:
    return ctx.match("*.tf")


@rule("SEC-K8S-004")
def terraform(ctx: ScanContext):
    files = _tf(ctx)
    if not files:
        return None
    obs = []
    all_text = {rel: ctx.read(rel) for rel in files}
    sse_targets: set[str] = set()
    for text in all_text.values():
        ls = [("" if re.match(r"\s*(#|//)", ln) else ln) for ln in text.splitlines()]
        for k, ln in enumerate(ls):
            if re.match(r'\s*resource\s+"aws_s3_bucket_server_side_encryption_configuration"', ln):
                blk = "\n".join(ls[k:_block_end(ls, k) + 1])
                for bl in blk.splitlines():          # `bucket = cond ? aws_s3_directory_bucket.x.bucket : aws_s3_bucket.this[0].id` too
                    if re.match(r"\s*bucket\s*=", bl):
                        sse_targets.update(re.findall(r"\baws_s3_bucket\.(\w+)", bl))
    for rel, text in all_text.items():
        lines = [("" if re.match(r"\s*(#|//)", ln) else ln) for ln in text.splitlines()]
        for i, ln in enumerate(lines):
            if _open_cidr_line(lines, i):
                b = _block_bounds(lines, i)
                if not b:
                    continue
                block = "\n".join(lines[b[0]:b[1] + 1])
                head = lines[b[0]]
                is_ingress = bool(re.match(r"\s*ingress\b", head) or "ingress" in head or
                                  re.search(r'type\s*=\s*"ingress"', block))
                if re.match(r"\s*egress\b", head) or "egress" in head:
                    is_ingress = False
                if not is_ingress:
                    continue
                fp = re.search(r"from_port\s*=\s*(\d+)", block)
                tp = re.search(r"to_port\s*=\s*(\d+)", block)
                proto = re.search(r'(?:ip_)?protocol\s*=\s*"?(-?\w+)"?', block)
                lo = int(fp.group(1)) if fp else None
                hi = int(tp.group(1)) if tp else lo
                allp = bool(proto and proto.group(1) in ("-1", "all")) or (lo == 0 and hi in (0, 65535))
                if allp or (lo is not None and any(lo <= p <= (hi if hi is not None else lo) for p in _ADMIN_PORTS)):
                    obs.append(Observation(rel, i + 1, "security group ingress open to the internet on an admin/all port"))
            if re.search(r'\bacl\s*=\s*"public-read(?:-write)?"', ln):
                obs.append(Observation(rel, i + 1, "S3 bucket ACL grants public access"))
            m = re.match(r'\s*resource\s+"aws_s3_bucket"\s+"([^"]+)"', ln)
            if m:
                name = m.group(1)
                block = "\n".join(lines[i:_block_end(lines, i) + 1])
                inline = "server_side_encryption_configuration" in block
                sep = name in sse_targets
                if not inline and not sep:
                    obs.append(Observation(rel, i + 1, "S3 bucket has no server-side encryption configuration"))
    return RuleResult(sorted(set(obs), key=lambda o: (o.file, o.line)))


# --------------------------------------------------------------------------- 005 Secrets
@rule("SEC-K8S-005")
def plaintext_secrets(ctx: ScanContext):
    files = _k8s_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        for kind, doc in _docs(ctx.read(rel)):
            if kind != "Secret":
                continue
            if any(re.match(r"sops\s*:", ln) for _i, ln in doc):
                continue                      # SOPS-encrypted manifest
            doc = _live_lines(doc)
            for n, (i, ln) in enumerate(doc):
                m = re.match(r"(\s*)(data|stringData)\s*:\s*(\S.*)?$", ln)
                if not m or "{{" in ln:
                    continue
                indent = len(m.group(1))
                inline = (m.group(3) or "").strip()
                if inline:                    # flow style: data: {k: v}
                    fm = re.match(r"\{\s*([\w.\-]+)\s*:\s*(\S.*?)\s*[,}]", inline)
                    if fm and not _empty_or_template(fm.group(2)):
                        obs.append(Observation(rel, i, f"Secret manifest embeds {m.group(2)} values in plaintext/base64"))
                    continue
                for _j, child in doc[n + 1:]:
                    if not child.strip():
                        continue
                    ci = len(child) - len(child.lstrip())
                    if ci <= indent:
                        break
                    cm = re.match(r"\s*[\w.\-]+\s*:\s*(\S.*)$", child)
                    if cm and not _empty_or_template(cm.group(1)):
                        obs.append(Observation(rel, i, f"Secret manifest embeds {m.group(2)} values in plaintext/base64"))
                        break
    return RuleResult(obs)


def _empty_or_template(v: str) -> bool:
    v = re.sub(r"\s+#.*$", "", v.strip())
    return v in ("", '""', "''", "null", "~") or "{{" in v or "${" in v or v.startswith("ENC[")


# --------------------------------------------------------------------------- 006 RBAC
@rule("SEC-K8S-006")
def rbac(ctx: ScanContext):
    files = _k8s_files(ctx)
    if not files:
        return None
    obs = []
    for rel in files:
        for kind, doc in _docs(ctx.read(rel)):
            if kind in ("Role", "ClusterRole"):
                key = None
                for i, ln in doc:
                    m = re.match(r"\s*-?\s*(verbs|resources)\s*:\s*(.*)$", ln)
                    if m:
                        key = m.group(1)
                        if re.search(r"""['"]\*['"]""", m.group(2)):
                            obs.append(Observation(rel, i, f"wildcard in RBAC {key}"))
                        continue
                    if re.match(r"\s*-?\s*(apiGroups|nonResourceURLs|resourceNames)\s*:", ln):
                        key = None
                        continue
                    if key and re.match(r"""\s*-\s*['"]?\*['"]?\s*$""", ln):
                        obs.append(Observation(rel, i, f"wildcard in RBAC {key}"))
            elif kind in ("ClusterRoleBinding", "RoleBinding"):
                in_ref = False
                for i, ln in doc:
                    if re.match(r"roleRef\s*:\s*\{[^}]*\bname\s*:\s*['\"]?cluster-admin['\"]?\s*[,}]", ln):
                        obs.append(Observation(rel, i, "binding grants cluster-admin"))
                        continue
                    if re.match(r"roleRef\s*:", ln):
                        in_ref = True
                        continue
                    if in_ref and re.match(r"\S", ln):
                        in_ref = False
                    if in_ref and re.match(r"\s+name\s*:\s*['\"]?cluster-admin['\"]?\s*$", ln):
                        obs.append(Observation(rel, i, "binding grants cluster-admin"))
    return RuleResult(obs)
