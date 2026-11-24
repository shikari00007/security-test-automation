"""End-to-end: run the real engine (not just rules) over every secure/vulnerable fixture pair."""
import json
from pathlib import Path

import pytest

from security_runner import engine, verification

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CASES = sorted(p for p in FIX.glob("*/expected.json"))


@pytest.mark.parametrize("exp", CASES, ids=lambda p: p.parent.name)
def test_fixture_pair(exp):
    spec = json.loads(exp.read_text())
    base = exp.parent
    vuln = engine.run_audit(base / "vulnerable", "deep", engine.tool_policy())
    assert verification.verify_run(vuln, base / "vulnerable")["valid"]
    got = {}
    for e in vuln["executions"]:
        if e["status"] == "executed" and e["outcome"] == "fail":
            got[e["check_id"]] = sorted([o["path"], o["line"]] for o in e["observations"])
    for cid, locs in spec["vulnerable"].items():
        assert got.get(cid) == sorted(list(x) for x in locs), f"{cid}: expected {locs}, got {got.get(cid)}"
    secure = engine.run_audit(base / "secure", "deep", engine.tool_policy())
    assert verification.verify_run(secure, base / "secure")["valid"]
    failed = {e["check_id"] for e in secure["executions"] if e["outcome"] == "fail"}
    assert not failed, f"false positives on secure fixture: {sorted(failed)}"
    ran = {e["check_id"] for e in secure["executions"] if e["status"] == "executed"}
    missing = set(spec.get("secure_clean", [])) - ran - {e["check_id"] for e in secure["executions"] if e["status"] == "not_applicable"}
    assert not missing, f"secure_clean checks neither ran nor N/A: {sorted(missing)}"


def test_fixtures_present_for_all_executable_domains():
    names = {p.parent.name for p in CASES}
    assert len(names) >= 8, names
