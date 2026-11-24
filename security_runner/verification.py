"""Run-manifest verification and independent finding verification.

verify_run: rejects fabricated results (fake evidence strings, unregistered check IDs,
impossible state/outcome combinations, broken hash chain, assets/evidence that do not
match the actual target files).
verify_findings: re-executes the rule from a fresh context and re-reads the evidence line.
This is automated re-verification, NOT a human review; see docs/VERIFICATION.md.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

from . import adapters, catalog, evidence
from .adapters.base import MAX_READ_BYTES, ScanContext
from .discovery import discover

STATUSES = {"planned", "not_applicable", "blocked", "deferred", "executed"}
OUTCOMES = {"pass", "fail", "inconclusive"}
TESTISH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|examples?|docs?|samples?|mocks?)(/|$)|\.(test|spec)\.", re.I)
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|<!--|--)")


def verify_run(run: dict, target: str | Path | None = None, key: bytes | None = None) -> dict:
    errors: list[str] = []
    known = catalog.checks()
    if not isinstance(run, dict) or not isinstance(run.get("executions"), list):
        return {"valid": False, "errors": ["not a run manifest"], "structural_only": True}
    body = {k: v for k, v in run.items() if k not in ("manifest_sha256", "signature")}
    if run.get("manifest_sha256") != evidence.sha256_bytes(evidence.canonical_json(body)):
        errors.append("manifest digest mismatch (run.json was modified after sealing)")
    if key is not None:
        sig = run.get("signature")
        want = hmac.new(key, str(run.get("manifest_sha256")).encode(), "sha256").hexdigest()
        if not sig or not hmac.compare_digest(sig, want):
            errors.append("manifest signature missing or invalid")
    root = Path(target).resolve() if target else None
    prev, seen = "0" * 64, set()
    run_id = run.get("run_id", "")
    for i, rec in enumerate(run["executions"]):
        cid = rec.get("check_id")
        tag = f"execution[{i}] {cid}"
        if cid not in known:
            errors.append(f"{tag}: unregistered check id")
            continue
        if cid in seen:
            errors.append(f"{tag}: duplicate execution record")
        seen.add(cid)
        if rec.get("prev_hash") != prev or rec.get("record_hash") != evidence.record_hash(rec, prev):
            errors.append(f"{tag}: hash chain broken")
        prev = rec.get("record_hash", "")
        st, oc = rec.get("status"), rec.get("outcome")
        if st not in STATUSES:
            errors.append(f"{tag}: invalid status {st!r}")
        if st == "executed":
            if oc not in OUTCOMES:
                errors.append(f"{tag}: executed without a valid outcome")
            meta = known[cid]
            if meta["executor"] == "none" or meta["mode"] in ("dynamic", "manual"):
                errors.append(f"{tag}: marked executed but check has no automated implementation")
            if not (rec.get("adapter") or {}).get("id"):
                errors.append(f"{tag}: executed without adapter identity")
            if not rec.get("assets"):
                errors.append(f"{tag}: executed without any examined asset")
            if not (rec.get("started_at") and rec.get("ended_at") and rec["started_at"] <= rec["ended_at"]):
                errors.append(f"{tag}: missing/invalid timestamps")
            if oc == "fail" and not rec.get("observations"):
                errors.append(f"{tag}: fail outcome without evidence")
            if oc == "pass" and rec.get("observations"):
                errors.append(f"{tag}: pass outcome with observations")
            asset_hash = {a.get("path"): a.get("sha256") for a in rec.get("assets", [])}
            for ev in rec.get("observations", []):
                if ev.get("path") not in asset_hash:
                    errors.append(f"{tag}: evidence references a file the check never examined")
                if not isinstance(ev.get("line_mac"), str) or len(ev.get("line_mac", "")) != 64:
                    errors.append(f"{tag}: evidence lacks a line fingerprint")
            if root is not None:
                for a in rec.get("assets", []):
                    p = root / a.get("path", "")
                    if not _inside(p, root) or not p.is_file():
                        errors.append(f"{tag}: asset {a.get('path')!r} missing from target")
                        continue
                    data = p.read_bytes()[:MAX_READ_BYTES]   # same cap the scanner applies; appended bytes must change the hash
                    if hashlib.sha256(data).hexdigest() != a.get("sha256") or len(data) != a.get("bytes"):
                        errors.append(f"{tag}: asset {a.get('path')!r} hash differs from recorded (changed since run or forged)")
                for ev in rec.get("observations", []):
                    lines = _lines(root / ev.get("path", ""))
                    ln = ev.get("line", 0)
                    if not (isinstance(ln, int) and 0 < ln <= len(lines)) or \
                            evidence.line_mac(run_id, lines[ln - 1]) != ev.get("line_mac"):
                        errors.append(f"{tag}: evidence at {ev.get('path')}:{ev.get('line')} does not match the file")
        else:
            if oc is not None:
                errors.append(f"{tag}: outcome set on non-executed check")
            if rec.get("observations"):
                errors.append(f"{tag}: evidence on non-executed check")
    missing = set(known) - seen
    if missing and run.get("executions"):
        errors.append(f"{len(missing)} catalog checks have no execution record (e.g. {sorted(missing)[0]})")
    ex = {r.get("check_id"): r for r in run["executions"]}
    for f in run.get("findings", []):
        r = ex.get(f.get("check_id"))
        if not r or r.get("outcome") != "fail":
            errors.append(f"finding {f.get('id')}: no failing execution backs it")
        if f.get("status") == "confirmed":
            errors += [f"finding {f.get('id')}: {e}" for e in validation_errors(f.get("validation"))]
    return {"valid": not errors, "errors": errors, "structural_only": root is None}


def _inside(p: Path, root: Path) -> bool:
    try:
        return p.resolve().is_relative_to(root) and not p.is_symlink()
    except OSError:
        return False


def _lines(p: Path) -> list[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def verify_findings(run: dict, target: str | Path) -> list[dict]:
    """Attach an independent verdict to each finding by re-running the rule on a fresh context."""
    adapters.load_all()
    found = discover(target)
    root = Path(found["root"])
    cache: dict = {}   # one fresh re-execution per check, not per finding
    for f in run.get("findings", []):
        if f.get("status") == "confirmed":      # a recorded independent validation is never overwritten
            continue
        f["verification"] = _verify_one(f, root, found, run.get("run_id", ""), cache)
        f["status"] = {"reproduced": "candidate"}.get(f["verification"]["verdict"], f["verification"]["verdict"])
    return run["findings"]


def _verify_one(f: dict, root: Path, found: dict, run_id: str, cache: dict) -> dict:
    ev = f["evidence"][0]
    path, line = ev["path"], ev["line"]

    def v(verdict, why):
        return {"verdict": verdict, "method": "fresh-context-reexecution", "rationale": why,
                "independent_human_review": False}
    p = root / path
    if not _inside(p, root) or not p.is_file():
        return v("rejected", "file no longer exists in target")
    lines = _lines(p)
    if not (0 < line <= len(lines)) or evidence.line_mac(run_id, lines[line - 1]) != ev["line_mac"]:
        return v("needs_validation", "source line changed since the run; re-run the audit")
    if COMMENT.match(lines[line - 1]):
        return v("rejected", "matched text is inside a comment")
    fn = adapters.RULES.get(f["check_id"])
    if fn is None:
        return v("needs_validation", "rule unavailable for re-execution")
    if f["check_id"] not in cache:
        ctx = ScanContext(root, found["files"], found["domains"])
        ctx.begin_rule()
        try:
            cache[f["check_id"]] = (fn(ctx), None)
        except Exception as e:  # noqa: BLE001
            cache[f["check_id"]] = (None, type(e).__name__)
    res, err = cache[f["check_id"]]
    if err:
        return v("needs_validation", f"re-execution error: {err}")
    if res is None or not any(o.file == path and o.line == line for o in res.observations):
        return v("rejected", "pattern did not reproduce on independent re-execution")
    if TESTISH.search(path):
        return v("needs_validation", "reproduced, but located in test/fixture/example code; confirm it ships")
    return v("reproduced", f"static pattern reproduced on fresh re-execution (rule confidence: {f['confidence']}); "
                            "this is a CANDIDATE - it does not demonstrate a security boundary violation")


VALIDATION_METHODS = {"manual-review", "dynamic-test", "fresh-agent-review"}


def validation_errors(v) -> list[str]:
    """A finding is `confirmed` only with a recorded, independent demonstration of a boundary violation."""
    if not isinstance(v, dict):
        return ["confirmed without a validation record"]
    errs = []
    if v.get("method") not in VALIDATION_METHODS:
        errs.append(f"validation.method must be one of {sorted(VALIDATION_METHODS)}")
    if not str(v.get("validator", "")).strip():
        errs.append("validation.validator missing")
    if len(str(v.get("boundary_violated", "")).strip()) < 20:
        errs.append("validation.boundary_violated must describe the violated security boundary (>=20 chars)")
    if not re.fullmatch(r"[0-9a-f]{64}", str(v.get("evidence_sha256", ""))):
        errs.append("validation.evidence_sha256 missing (hash of the evidence artifact)")
    return errs


def confirm_finding(run: dict, finding_id: str, *, validator: str, method: str, boundary: str,
                    evidence_file: str | Path) -> dict:
    f = next((x for x in run.get("findings", []) if x["id"] == finding_id), None)
    if f is None:
        raise ValueError(f"finding {finding_id} not found")
    if f.get("status") == "rejected":
        raise ValueError("a rejected finding cannot be confirmed")
    p = Path(evidence_file)
    if not p.is_file() or p.stat().st_size == 0:
        raise ValueError("evidence file must exist and be non-empty")
    f["validation"] = {"validator": validator, "method": method, "boundary_violated": boundary,
                       "evidence_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                       "evidence_file": p.name}
    errs = validation_errors(f["validation"])
    if errs:
        f.pop("validation")
        raise ValueError("; ".join(errs))
    f["status"] = "confirmed"
    return f
