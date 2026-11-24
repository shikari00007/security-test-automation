from __future__ import annotations

from xml.sax.saxutils import quoteattr


def render(run: dict, cov: dict) -> str:
    by_dom: dict[str, list] = {}
    for r in run["executions"]:
        by_dom.setdefault(r["domain"], []).append(r)
    fnd = {}
    for f in run.get("findings", []):
        fnd.setdefault(f["check_id"], []).append(f)
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites name=\"security-skills\">"]
    for dom, recs in sorted(by_dom.items()):
        fails = sum(1 for r in recs if r["outcome"] == "fail")
        skips = sum(1 for r in recs if r["status"] != "executed")
        out.append(f'  <testsuite name={quoteattr(dom)} tests="{len(recs)}" failures="{fails}" errors="0" skipped="{skips}">')
        for r in recs:
            out.append(f'    <testcase classname={quoteattr(dom)} name={quoteattr(r["check_id"])} time="{r["duration_ms"] / 1000:.3f}">')
            if r["status"] != "executed":
                out.append(f'      <skipped message={quoteattr(r["status"] + ": " + (r["reason"] or ""))}/>')
            elif r["outcome"] == "fail":
                msg = "; ".join(f'{f["location"]["path"]}:{f["location"]["line"]} [{f["status"]}]' for f in fnd.get(r["check_id"], []))
                out.append(f'      <failure message={quoteattr(msg[:500])} type="security"/>')
            elif r["outcome"] == "inconclusive":
                out.append('      <skipped message="inconclusive"/>')
            out.append("    </testcase>")
        out.append("  </testsuite>")
    out.append("</testsuites>")
    return "\n".join(out) + "\n"
