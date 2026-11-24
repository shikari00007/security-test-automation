"""Rule accuracy harness. Cases live in fixtures/accuracy/*/cases.json:
{"cases":[{"id":"web007-neg-ternary","rule":"SEC-WEB-007","kind":"negative|positive","note":"why",
           "files":{"app.py":"...text..."},"expect":[["app.py",3]]}]}
negative => rule must report nothing; positive => rule must report exactly `expect`.
Every executable rule needs >=3 positive and >=4 negative cases. `python scripts/rule_accuracy.py` renders docs/RULE-ACCURACY.md."""
import json
import tempfile
from pathlib import Path

import pytest

from security_runner import adapters, catalog
from security_runner.regression import observations_for

ACC = Path(__file__).resolve().parents[1] / "fixtures" / "accuracy"


def load_cases():
    out = []
    for f in sorted(ACC.glob("*/cases.json")):
        out += json.loads(f.read_text())["cases"]
    return out


CASES = load_cases()


def run_case(case):
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        for rel, text in case["files"].items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return [list(x) for x in observations_for(case["rule"], root)]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_case(case):
    got = run_case(case)
    want = [] if case["kind"] == "negative" else sorted(list(x) for x in case["expect"])
    assert got == want, f"{case['rule']} {case['id']} ({case.get('note','')}): expected {want}, got {got}"


def test_every_executable_rule_has_enough_cases():
    adapters.load_all()
    pos, neg = {}, {}
    for c in CASES:
        (pos if c["kind"] == "positive" else neg).setdefault(c["rule"], []).append(c["id"])
    short = [r for r in adapters.RULES if len(pos.get(r, [])) < 3 or len(neg.get(r, [])) < 4]
    assert not short, f"rules lacking >=3 positive/>=4 negative accuracy cases: {short}"
    assert len({c["id"] for c in CASES}) == len(CASES), "duplicate case ids"
