"""security-skills command line. Exit codes: 0 ok | 1 gating findings | 2 usage/policy error | 3 integrity failure."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, catalog, coverage, engine, regression, reporting, verification
from .discovery import discover
from .paths import is_within
from .policy import PolicyError, Policy, load_scope

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _key(args) -> bytes | None:
    name = getattr(args, "hmac_key_env", None)
    if not name:
        return None
    v = os.environ.get(name)
    if not v:
        raise ValueError(f"environment variable {name} is empty/unset")
    return v.encode()


def _out_dir(path: str, target: Path) -> Path:
    out = Path(path).expanduser().resolve(strict=False)
    if is_within(out, target):
        raise ValueError("output directory must be outside the target source tree (no unapproved source writes)")
    return out


def _policy(args) -> Policy:
    scope = load_scope(args.scope) if getattr(args, "scope", None) else None
    if args.mode != "offline" and scope is None:
        raise PolicyError(f"--mode {args.mode} requires --scope <file> (authorization, allow-listed targets, isolation)")
    if args.mode == "offline" and scope is not None:
        raise PolicyError("--scope supplied but --mode is offline; choose --mode lab|staging to use it")
    return engine.tool_policy(args.mode, scope)


def cmd_detect(a):
    d = discover(a.target)
    d.pop("files")
    print(json.dumps(d, indent=2))
    return 0


def cmd_plan(a):
    found = discover(a.target)
    plan = engine.build_plan(found, a.profile, _policy(a), a.type)
    counts = {}
    for it in plan["items"]:
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    plan["summary"] = {"counts": counts, "execution_performed": False}
    text = json.dumps(plan, indent=2)
    if a.output:
        p = _out_dir(a.output, Path(found["root"]))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")
        print(f"plan written to {p}: {counts} (nothing executed)")
    else:
        print(text)
    return 0


def cmd_audit(a):
    formats = reporting.parse_formats(a.report)
    target = Path(a.target).resolve(strict=True)
    out = _out_dir(a.output_dir, target)
    run = engine.run_audit(target, a.profile, _policy(a), a.type, key=_key(a))
    if not a.no_verify:
        verification.verify_findings(run, target)
        # findings changed after sealing: re-seal so the manifest covers verdicts
        from . import evidence
        evidence.seal(run, _key(a))
    chk = verification.verify_run(run, target, _key(a))
    if not chk["valid"]:
        print("integrity check failed:\n  " + "\n  ".join(chk["errors"]), file=sys.stderr)
        return 3
    cov = coverage.summarize(run)
    paths = reporting.write_reports(run, cov, out, formats)
    (out / "run.json").write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n")
    print(f"audit {run['run_id']} profile={a.profile} domains={','.join(run['domains'])}")
    print(f"  executed {cov['executed']}/{cov['applicable']} applicable | passed {cov['passed']} failed {cov['failed']} "
          f"| blocked/untested {cov['blocked_or_untested']} | not applicable {cov['not_applicable']}")
    print(f"  confirmed vulnerabilities {cov['verified_vulnerabilities']} | reproduced candidates {cov['reproduced_candidates']} "
          f"| needs validation {cov['needs_validation']} | rejected {cov['rejected_candidates']}")
    print("  note: static matches are CANDIDATES; only `security-skills confirm` (independent validation) makes a finding confirmed")
    print("  reports: " + ", ".join(str(p) for p in paths + [out / 'run.json']))
    gate = SEV_ORDER.index(a.fail_on) if a.fail_on != "never" else None
    if gate is not None:
        for f in run["findings"]:
            if a.gate == "confirmed":
                counted = f["status"] == "confirmed"
            else:   # candidates: confirmed, or reproduced high-confidence candidates; --strict adds everything unrejected
                counted = f["status"] == "confirmed" or (f["status"] == "candidate" and f["confidence"] == "high") \
                    or (a.strict and f["status"] in ("candidate", "needs_validation"))
            if counted and SEV_ORDER.index(f["severity"]) >= gate:
                print(f"gate: failing on {f['severity']} finding {f['id']} ({f['status']})", file=sys.stderr)
                return 1
    return 0


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def cmd_verify(a):
    run = _load(a.results)
    res = verification.verify_run(run, a.target, _key(a))
    if a.target and a.findings:
        verification.verify_findings(run, a.target)
        res["findings"] = {f["id"]: f["status"] for f in run["findings"]}
    print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 3


def cmd_confirm(a):
    from . import evidence
    path = Path(a.results)
    run = _load(path)
    f = verification.confirm_finding(run, a.finding, validator=a.validator, method=a.method,
                                     boundary=a.boundary, evidence_file=a.evidence_file)
    evidence.seal(run, _key(a))
    path.write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n")
    print(f"{f['id']} marked confirmed by {a.validator} ({a.method}); evidence sha256 {f['validation']['evidence_sha256'][:12]}... recorded")
    return 0


def cmd_coverage(a):
    print(json.dumps(coverage.summarize(_load(a.results)), indent=2))
    return 0


def cmd_rerun(a):
    old = _load(a.results)
    target = old["target"]["path"]
    run = engine.run_audit(target, old["profile"], engine.tool_policy("offline"))
    verification.verify_findings(run, target)
    prev = {f["id"] for f in old["findings"]}
    cur = {f["id"] for f in run["findings"] if f["status"] != "rejected"}
    print(json.dumps({"fixed": sorted(prev - cur), "new": sorted(cur - prev), "persisting": sorted(prev & cur)}, indent=2))
    return 1 if cur else 0


def cmd_regression(a):
    if a.action == "generate":
        run = _load(a.results)
        f = next((x for x in run["findings"] if x["id"] == a.finding), None)
        if f is None:
            raise ValueError(f"finding {a.finding} not found")
        p = regression.generate(f, run["target"]["path"], a.output_dir, a.framework, accept_candidate=a.accept_candidate)
        exp = " [EXPERIMENTAL skeleton - not executed]" if a.framework != "pytest" else ""
        print(f"proposed regression test written to {p} (source code untouched){exp}")
        return 0
    res = regression.verify_red_green(a.test, a.vulnerable, a.fixed)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


def cmd_catalog(a):
    if a.action in ("import", "validate", "stats", "list"):
        from .catalogtool.cli import main as ctool
        return ctool([a.action] + a.rest)
    if a.action == "checks":
        for cid, c in sorted(catalog.checks().items()):
            if a.rest and c["domain"] not in a.rest:
                continue
            print(f"{cid}\t{c['domain']}\t{c['mode']}\t{c['executor']}\t{c['severity']}\t{c['title']}")
        return 0
    probs = catalog.validate_checks()
    print(json.dumps({"valid": not probs, "problems": probs, "checks": len(catalog.checks())}, indent=2))
    return 0 if not probs else 3


def cmd_skills(a):
    from .skillcheck import validate_dir
    res = validate_dir(a.dir)
    print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 3


def parser() -> argparse.ArgumentParser:
    P = argparse.ArgumentParser(prog="security-skills", description="Security & Test Automation Skills runner (offline by default)")
    P.add_argument("--version", action="version", version=__version__)
    sp = P.add_subparsers(dest="cmd", required=True)
    dom = ["auto"] + sorted(catalog.domains())

    def common(p, scan=True):
        p.add_argument("target")
        p.add_argument("--type", default="auto", choices=dom + ["thick-client"])
        p.add_argument("--profile", default="standard", choices=["quick", "standard", "deep"])
        p.add_argument("--mode", default="offline", choices=["offline", "lab", "staging"])
        p.add_argument("--scope", help="authorization scope JSON (required for --mode lab|staging)")

    p = sp.add_parser("detect"); p.add_argument("target"); p.set_defaults(fn=cmd_detect)
    p = sp.add_parser("plan"); common(p); p.add_argument("--output"); p.set_defaults(fn=cmd_plan)
    p = sp.add_parser("audit"); common(p)
    p.add_argument("--report", default="json,sarif,markdown,junit")
    p.add_argument("--output-dir", default="./security-artifacts")
    p.add_argument("--fail-on", default="high", choices=SEV_ORDER + ["never"])
    p.add_argument("--gate", default="candidates", choices=["candidates", "confirmed"],
                   help="candidates (default): confirmed + reproduced high-confidence candidates; confirmed: only independently validated findings")
    p.add_argument("--strict", action="store_true", help="also gate on every non-rejected candidate")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--hmac-key-env", help="env var holding a key used to sign/verify the manifest")
    p.set_defaults(fn=cmd_audit)
    p = sp.add_parser("verify"); p.add_argument("results"); p.add_argument("--target")
    p.add_argument("--findings", action="store_true"); p.add_argument("--hmac-key-env"); p.set_defaults(fn=cmd_verify)
    p = sp.add_parser("coverage"); p.add_argument("results"); p.set_defaults(fn=cmd_coverage)
    p = sp.add_parser("rerun"); p.add_argument("results"); p.set_defaults(fn=cmd_rerun)
    p = sp.add_parser("regression"); p.add_argument("action", choices=["generate", "verify"])
    p.add_argument("--results"); p.add_argument("--finding"); p.add_argument("--framework", default="pytest")
    p.add_argument("--output-dir", default="./security-regression"); p.add_argument("--test")
    p.add_argument("--vulnerable"); p.add_argument("--fixed")
    p.add_argument("--accept-candidate", action="store_true",
                   help="generate from a reproduced static candidate (test is labeled candidate-derived)")
    p.set_defaults(fn=cmd_regression)
    p = sp.add_parser("confirm", help="record an independent validation that turns a candidate into a confirmed finding")
    p.add_argument("results"); p.add_argument("--finding", required=True); p.add_argument("--validator", required=True)
    p.add_argument("--method", required=True, choices=sorted(verification.VALIDATION_METHODS))
    p.add_argument("--boundary", required=True, help="the security boundary that was demonstrably violated")
    p.add_argument("--evidence-file", required=True); p.add_argument("--hmac-key-env"); p.set_defaults(fn=cmd_confirm)
    p = sp.add_parser("catalog"); p.add_argument("action", choices=["checks", "validate-checks", "import", "validate", "stats", "list"])
    p.add_argument("rest", nargs=argparse.REMAINDER); p.set_defaults(fn=cmd_catalog)
    p = sp.add_parser("skills"); p.add_argument("action", choices=["validate"]); p.add_argument("dir", nargs="?", default="skills")
    p.set_defaults(fn=cmd_skills)
    return P


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "type", None) == "thick-client":
        args.type = "desktop"
    try:
        return args.fn(args)
    except (ValueError, OSError, PolicyError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as e:
        print(f"error: component not available: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
