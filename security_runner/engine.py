"""Planning and execution. Status/outcome/verdict are separate fields:

status:  planned | not_applicable | blocked | deferred | executed
outcome: pass | fail | inconclusive   (only when status == executed)
verdict: confirmed | needs_validation | rejected   (findings only, set by verification)
"""
from __future__ import annotations

import datetime as dt
import secrets
import shutil
import time

from . import __version__, adapters, catalog, evidence
from .discovery import discover
from .policy import Policy
from .adapters.base import ScanContext

ADAPTER = {"id": "builtin-static", "version": __version__}
EXTERNAL_TOOLS = {"osv-scanner": {"binary": "osv-scanner", "needs_network": True}}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def applicable_domains(found: dict, requested: str | list[str] | None) -> dict:
    """Detected domains, optionally narrowed by --type. Supply chain stays eligible."""
    if not requested or requested == "auto":
        return dict(found["domains"])
    wanted = {requested} if isinstance(requested, str) else set(requested)
    unknown = wanted - set(catalog.domains())
    if unknown:
        raise ValueError(f"unknown domain(s): {sorted(unknown)}")
    out = {d: v for d, v in found["domains"].items() if d in wanted}
    for d in wanted - set(out):   # explicit request that detection did not confirm
        out[d] = {"confidence": "low", "evidence": ["explicitly requested; not detected in project"]}
    if "supply-chain" in found["domains"]:
        out["supply-chain"] = found["domains"]["supply-chain"]
    return out


def tool_policy(mode: str = "offline", scope=None) -> Policy:
    allowed = frozenset(n for n, t in EXTERNAL_TOOLS.items()
                        if shutil.which(t["binary"]) and (not t["needs_network"] or mode != "offline"))
    return Policy(mode=mode, scope=scope, allowed_tools=allowed)


def build_plan(found: dict, profile: str, policy: Policy, domain_request=None) -> dict:
    prof = catalog.profiles()
    if profile not in prof:
        raise ValueError(f"unknown profile {profile!r}")
    dom = applicable_domains(found, domain_request)
    items = []
    for cid, c in sorted(catalog.checks().items()):
        if c["domain"] not in dom:
            st, why = "not_applicable", f"domain '{c['domain']}' not detected/selected"
        elif profile not in c["profiles"]:
            st, why = "deferred", f"not part of the '{profile}' profile"
        else:
            ok, why = policy.decide(c)
            if ok:
                st, why = "planned", ""
            else:
                st = "blocked"
        if st == "blocked" and c["executor"] == "external" and EXTERNAL_TOOLS.get(c.get("rule"), {}).get("needs_network") \
                and policy.mode == "offline":
            why = f"requires network access to a vulnerability database; blocked in offline mode ({why})"
        if st == "blocked" and c["mode"] in ("manual",) and why.startswith("no automated"):
            st = "blocked"
        items.append({"check_id": cid, "domain": c["domain"], "status": st, "reason": why,
                      "mode": c["mode"]})
    if profile != "deep":   # keep planned-only checks out of non-deep plans (deferred, still counted)
        for it in items:
            c = catalog.checks()[it["check_id"]]
            if it["status"] == "blocked" and c["executor"] == "none" and profile not in c["profiles"]:
                it["status"], it["reason"] = "deferred", f"not part of the '{profile}' profile"
    return {"profile": profile, "policy": policy.describe(), "domains": dom, "items": items,
            "catalog_sha256": catalog.catalog_sha256()}


def _evidence_item(ctx: ScanContext, run_id: str, ob, assets_by_path: dict) -> dict:
    lines = ctx.read(ob.file).splitlines()
    raw = lines[ob.line - 1] if 0 < ob.line <= len(lines) else ""
    return {"path": ob.file, "line": ob.line, "detail": ob.detail,
            "snippet": evidence.redact(raw), "line_mac": evidence.line_mac(run_id, raw),
            "file_sha256": assets_by_path.get(ob.file, "")}


def run_audit(target, profile: str = "standard", policy: Policy | None = None, domain_request=None,
              key: bytes | None = None) -> dict:
    policy = policy or tool_policy()
    adapters.load_all()
    found = discover(target)
    plan = build_plan(found, profile, policy, domain_request)
    ctx = ScanContext(__import__("pathlib").Path(found["root"]), found["files"], found["domains"])
    run_id = f"run-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
    execs, findings = [], []
    for it in plan["items"]:
        c = catalog.checks()[it["check_id"]]
        rec = {"check_id": it["check_id"], "domain": it["domain"], "status": it["status"],
               "outcome": None, "reason": it["reason"], "adapter": None, "started_at": None,
               "ended_at": None, "duration_ms": 0, "assets": [], "observations": []}
        if it["status"] == "planned":
            fn = adapters.RULES.get(it["check_id"])
            if fn is None:
                rec.update(status="blocked", reason="no implementation registered")
            else:
                rec["started_at"] = now()
                t0 = time.monotonic()
                ctx.begin_rule()
                try:
                    res = fn(ctx)
                    err = None
                except Exception as e:  # a crashing rule is blocked work, never a pass
                    res, err = None, f"{type(e).__name__}: {e}"
                rec["ended_at"] = now()
                rec["duration_ms"] = int((time.monotonic() - t0) * 1000)
                assets = ctx.rule_assets()
                if err:
                    rec.update(status="blocked", reason=f"adapter_error: {err[:200]}")
                elif res is None or not assets:
                    rec.update(status="not_applicable", reason="no applicable files for this check")
                else:
                    by = {a["path"]: a["sha256"] for a in assets}
                    rec.update(status="executed", adapter=ADAPTER, assets=assets, reason="",
                               outcome="inconclusive" if res.inconclusive else ("fail" if res.observations else "pass"))
                    rec["observations"] = [_evidence_item(ctx, run_id, o, by) for o in res.observations]
                    if res.notes:
                        rec["notes"] = res.notes
                    for ev_item in rec["observations"]:
                        findings.append(_finding(c, run_id, ev_item))
        execs.append(rec)
    run = {"schema_version": "1.0", "run_id": run_id, "tool": {"name": "security-skills", "version": __version__},
           "created_at": now(), "target": {"path": found["root"], "files_inspected": len(found["files"]),
                                           "file_limit_reached": found["truncated"]},
           "profile": profile, "policy": plan["policy"], "domains": plan["domains"],
           "catalog_sha256": plan["catalog_sha256"], "executions": execs, "findings": findings}
    return evidence.seal(run, key)


def _finding(c: dict, run_id: str, ev: dict) -> dict:
    fid = "FIND-" + evidence.sha256_bytes(f"{c['id']}|{ev['path']}|{ev['line']}".encode())[:10].upper()
    return {"id": fid, "check_id": c["id"], "domain": c["domain"], "title": c["title"],
            "severity": c["severity"], "confidence": c["confidence"], "standards": c["standards"],
            "location": {"path": ev["path"], "line": ev["line"]}, "evidence": [ev],
            "remediation": c["remediation"], "expected_secure_behavior": c["expected_secure_behavior"],
            "status": "candidate", "verification": None}
