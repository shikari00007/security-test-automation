"""Coverage accounting. Every number carries its denominator; nothing untested is hidden."""
from __future__ import annotations

from collections import Counter


def summarize(run: dict) -> dict:
    ex = run["executions"]
    st = Counter(r["status"] for r in ex)
    executed = [r for r in ex if r["status"] == "executed"]
    oc = Counter(r["outcome"] for r in executed)
    fnd = run.get("findings", [])
    ver = Counter(f.get("status") for f in fnd)
    applicable = st["executed"] + st["blocked"] + st["planned"]
    per_domain: dict[str, Counter] = {}
    for r in ex:
        per_domain.setdefault(r["domain"], Counter())[r["status"]] += 1
    return {
        "catalog_checks": len(ex),
        "applicable": applicable,
        "executed": st["executed"],
        "passed": oc["pass"], "failed": oc["fail"], "inconclusive": oc["inconclusive"],
        "blocked_or_untested": st["blocked"] + st["planned"],
        "not_applicable": st["not_applicable"],
        "deferred_out_of_profile": st["deferred"],
        "execution_rate": round(st["executed"] / applicable, 3) if applicable else None,
        "findings_total": len(fnd),
        "verified_vulnerabilities": ver["confirmed"],
        "reproduced_candidates": sum(1 for f in fnd if f.get("status") == "candidate" and f.get("verification")),
        "unverified_candidates": sum(1 for f in fnd if f.get("status") == "candidate" and not f.get("verification")),
        "needs_validation": ver["needs_validation"],
        "rejected_candidates": ver["rejected"],
        "by_domain": {d: dict(c) for d, c in sorted(per_domain.items())},
        "note": "Static matches are candidates, not confirmed vulnerabilities. A passed check covers only that check's pattern; it does not prove the category is secure.",
    }
