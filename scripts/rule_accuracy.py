"""Render docs/RULE-ACCURACY.md (per-rule TP/FP/FN on the accuracy corpus). Usage: python scripts/rule_accuracy.py"""
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from test_rule_accuracy import CASES, run_case  # noqa: E402

stat = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0})
for c in CASES:
    got = run_case(c)
    s = stat[c["rule"]]
    s["n"] += 1
    if c["kind"] == "negative":
        s["fp" if got else "tn"] += 1
    else:
        want = sorted(list(x) for x in c["expect"])
        s["tp"] += sum(1 for x in got if x in want)
        s["fp"] += sum(1 for x in got if x not in want)
        s["fn"] += sum(1 for x in want if x not in got)
lines = ["# Rule accuracy (curated corpus)", "",
         "Measured on `fixtures/accuracy/*/cases.json`: hand-written positive variants and tricky benign negatives per rule.",
         "**These numbers describe the curated corpus only; they are not a field false-positive rate.** Field spot checks: RULE-ACCURACY-FIELD-*.md."
         "Zero FP/FN here holds *by construction*: rules were tuned until every case passed, so this proves regression-safety, not accuracy.", "",
         "| Rule | Cases | TP | FP | FN | Negatives clean |", "|---|---|---|---|---|---|"]
for r in sorted(stat):
    s = stat[r]
    lines.append(f"| {r} | {s['n']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} |")
(ROOT / "docs" / "RULE-ACCURACY.md").write_text("\n".join(lines) + "\n")
print("wrote docs/RULE-ACCURACY.md", len(CASES), "cases")
