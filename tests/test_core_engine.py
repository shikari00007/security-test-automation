"""Core engine tests: discovery, policy, sandbox, evidence/verification, planning, reports, CLI.
Each defect found in the v0.2 foundation has a regression test here (marked REG-*)."""
import copy
import datetime as dt
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from security_runner import __version__, catalog, engine, evidence, verification
from security_runner.cli import main
from security_runner.discovery import discover
from security_runner.paths import confine_output
from security_runner.policy import PolicyError, load_scope
from security_runner.sandbox import SandboxError, safe_run

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


def write(p, rel, text):
    f = p / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    return f


# ---- Phase 0 regressions ------------------------------------------------------------
def test_REG_version_single_source():
    import tomllib
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == __version__


def test_REG_detection_uses_names_not_substrings(proj):
    write(proj, "requirements.txt", "dmcpkg==1\nflask-notreally==2\n")
    d = discover(proj)["domains"]
    assert "ai-llm" not in d and "api" not in d


def test_REG_detects_real_python_deps(proj):
    write(proj, "requirements.txt", "mcp==1.0\nFlask>=2\n")
    d = discover(proj)["domains"]
    assert "ai-llm" in d and "api" in d


def test_REG_output_symlink_dir_cannot_escape_into_target(proj, tmp_path):
    link = tmp_path / "lnk"
    link.symlink_to(proj, target_is_directory=True)
    with pytest.raises(ValueError):
        confine_output(link / "plan.json", [proj])


def test_REG_fixture_inside_install_root_is_scannable():
    # v0.2 refused any target under the framework install dir, so fixtures could not be scanned
    d = discover(ROOT / "tests")
    assert d["root"].startswith(str(ROOT))


def test_REG_quick_profile_does_not_hide_detected_domains(proj):
    write(proj, "Dockerfile", "FROM scratch")
    write(proj, "package.json", '{"dependencies":{"openai":"1"}}')
    plan = engine.build_plan(discover(proj), "quick", engine.tool_policy())
    doms = {i["domain"] for i in plan["items"] if i["status"] in ("planned", "blocked", "deferred")}
    assert {"cloud-kubernetes", "ai-llm"} <= doms     # present in plan (planned or explicitly deferred), never silently absent


def test_REG_installed_wheel_finds_catalog(tmp_path):
    # data must live inside the package so a pip-installed copy works
    for rel in ("data/domains.json", "data/profiles.json", "data/schemas/check.schema.json"):
        assert (ROOT / "security_runner" / rel).is_file()
    assert catalog.checks()


# ---- domains / catalog ---------------------------------------------------------------
def test_eight_domains_with_classification():
    d = catalog.domains()
    assert len(d) == 8
    assert {k for k, v in d.items() if v["conditional"]} == {"cloud-kubernetes", "ai-llm"}
    assert not ({"wireless", "iot", "active-directory"} & set(d))


def test_reviewed_catalog_valid():
    assert catalog.validate_checks() == []


# ---- discovery ------------------------------------------------------------------------
def test_supply_chain_always_eligible(proj):
    assert list(discover(proj)["domains"]) == ["supply-chain"]


def test_polyglot_detection(proj):
    write(proj, "package.json", '{"dependencies":{"next":"1","openai":"1","express":"4"}}')
    write(proj, "Dockerfile", "FROM scratch")
    assert {"web", "api", "ai-llm", "cloud-kubernetes", "supply-chain"} <= set(discover(proj)["domains"])


def test_symlinks_not_followed(proj, tmp_path):
    (proj / "out").symlink_to("/etc", target_is_directory=True)
    (proj / "AndroidManifest.xml").symlink_to("/etc/hostname")
    d = discover(proj)
    assert "android" not in d["domains"] and not any(f.startswith("out/") for f in d["files"])


# ---- policy ---------------------------------------------------------------------------
def _scope(tmp_path, **kw):
    d = {"authorized_by": "qa lead", "environment": "lab", "targets": ["lab.internal"],
         "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat(), "isolation_confirmed": True}
    d.update(kw)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(d))
    return p


def test_scope_valid(tmp_path):
    assert load_scope(_scope(tmp_path)).environment == "lab"


@pytest.mark.parametrize("kw", [{"environment": "production"}, {"targets": []}, {"targets": ["*"]},
                                {"isolation_confirmed": False}, {"authorized_by": ""},
                                {"expires": "2001-01-01T00:00:00+00:00"}])
def test_scope_rejections(tmp_path, kw):
    with pytest.raises(PolicyError):
        load_scope(_scope(tmp_path, **kw))


def test_active_mode_requires_scope(proj, tmp_path):
    assert main(["plan", str(proj), "--mode", "lab"]) == 2


def test_dynamic_checks_never_run_offline(proj):
    plan = engine.build_plan(discover(proj), "deep", engine.tool_policy())
    dyn = [i for i in plan["items"] if i["mode"] in ("dynamic", "hybrid", "manual") and i["status"] != "not_applicable"]
    assert all(i["status"] in ("blocked", "deferred") for i in dyn)


# ---- sandbox --------------------------------------------------------------------------
def test_sandbox_rejects_shell_strings_and_unlisted_binaries(tmp_path):
    with pytest.raises(SandboxError):
        safe_run("echo hi", allowed={"echo"})  # type: ignore[arg-type]
    with pytest.raises(SandboxError):
        safe_run(["rm", "-rf", "/nonexistent"], allowed={"echo"})
    with pytest.raises(SandboxError):
        import shutil
        planted = tmp_path / "echo"
        shutil.copy(shutil.which("echo"), planted)   # same name, untrusted location
        safe_run([str(planted), "x"], allowed={"echo"}, allowed_paths=set())


def test_sandbox_timeout_and_output_cap():
    r = safe_run(["sleep", "5"], allowed={"sleep"}, timeout=0.5)
    assert r.timed_out and r.exit_code is None
    r = safe_run([sys.executable, "-c", "print('A'*5000)"], allowed={os.path.basename(sys.executable)},
                 allowed_paths={sys.executable}, max_output=100)
    assert r.truncated and len(r.stdout) == 100


def test_sandbox_scrubs_environment(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "hunter2")
    r = safe_run(["env"], allowed={"env"})
    assert "SECRET_TOKEN" not in r.stdout


def test_sandbox_network_isolation():
    r = safe_run([sys.executable, "-c",
                  "import socket;s=socket.socket();s.settimeout(2)\ntry:\n s.connect(('1.1.1.1',53));print('NET')\nexcept OSError:print('NONET')"],
                 allowed={os.path.basename(sys.executable)}, allowed_paths={sys.executable}, no_network=True)
    assert r.stdout.strip() == "NONET"


# ---- evidence & verification ----------------------------------------------------------
VULN_PY = "import requests\n\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n"


def _audit(p, profile="standard"):
    run = engine.run_audit(p, profile, engine.tool_policy())
    return run


def _sample_failing_run(proj):
    write(proj, "requirements.txt", "flask==3.0.0\n")
    write(proj, "app.py", VULN_PY)
    write(proj, ".github/workflows/ci.yml", "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    return _audit(proj)


def test_redaction():
    s = evidence.redact('password = "hunter22"; k=AKIAIOSFODNN7EXAMPLE; u=https://a:secret1@h/x')
    assert "hunter22" not in s and "AKIAIOSFODNN7EXAMPLE" not in s and "secret1" not in s


def test_honest_run_verifies(proj):
    run = _sample_failing_run(proj)
    assert any(e["status"] == "executed" and e["outcome"] == "fail" for e in run["executions"])
    assert verification.verify_run(run, proj)["valid"]


def test_fake_evidence_string_rejected(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    victim = next(e for e in r["executions"] if e["status"] == "blocked")
    victim.update(status="executed", outcome="pass", evidence=["fake"])
    assert not verification.verify_run(r, proj)["valid"]


def test_fake_run_even_if_rehashed_rejected(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    victim = next(e for e in r["executions"] if e["status"] == "blocked")
    victim.update(status="executed", outcome="pass", adapter={"id": "x", "version": "1"},
                  assets=[{"path": "app.py", "sha256": "0" * 64, "bytes": 1}],
                  started_at="2026-01-01T00:00:00", ended_at="2026-01-01T00:00:01")
    evidence.seal(r)
    res = verification.verify_run(r, proj)
    assert not res["valid"]
    assert any("no automated implementation" in e or "hash differs" in e for e in res["errors"])


def test_unregistered_check_id_rejected(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    r["executions"][0]["check_id"] = "SEC-WEB-999"
    evidence.seal(r)
    assert any("unregistered" in e for e in verification.verify_run(r, proj)["errors"])


def test_tamper_detected_without_reseal(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    r["executions"][3]["reason"] = "edited"
    assert not verification.verify_run(r, proj)["valid"]


def test_pass_with_observations_and_outcome_on_nonexecuted_rejected(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    blocked = next(e for e in r["executions"] if e["status"] == "blocked")
    blocked["outcome"] = "pass"
    evidence.seal(r)
    assert any("outcome set on non-executed" in e for e in verification.verify_run(r, proj)["errors"])


def test_target_modified_after_run_detected(proj):
    run = _sample_failing_run(proj)
    write(proj, "app.py", VULN_PY.replace("False", "True"))
    assert not verification.verify_run(run, proj)["valid"]


def test_hmac_signature(proj):
    run = engine.run_audit(proj, "quick", engine.tool_policy(), key=b"k1")
    assert verification.verify_run(run, proj, key=b"k1")["valid"]
    assert not verification.verify_run(run, proj, key=b"other")["valid"]


def test_findings_verification_and_regression_red_green(proj, tmp_path):
    from security_runner import regression
    run = _sample_failing_run(proj)
    verification.verify_findings(run, proj)
    f = next(x for x in run["findings"] if x["check_id"] == "SEC-WEB-007")
    assert f["status"] == "candidate" and f["verification"]["verdict"] == "reproduced"   # never auto-confirmed
    with pytest.raises(ValueError):
        regression.generate(f, proj, tmp_path / "reg")                                    # needs explicit opt-in
    test = regression.generate(f, proj, tmp_path / "reg", accept_candidate=True)
    assert "CANDIDATE" in test.read_text()
    fixed = tmp_path / "fixed"
    fixed.mkdir()
    write(fixed, "requirements.txt", "flask==3.0.0\n")
    write(fixed, "app.py", VULN_PY.replace("verify=False", "verify=True"))
    res = regression.verify_red_green(test, proj, fixed)
    assert res["ok"], res


def test_regression_refuses_unverified_and_target_output(proj, tmp_path):
    from security_runner import regression
    run = _sample_failing_run(proj)
    f = next(x for x in run["findings"] if x["check_id"] == "SEC-WEB-007")
    with pytest.raises(ValueError):
        regression.generate(f, proj, tmp_path / "r")          # still a candidate
    f["status"] = "candidate"; f["verification"] = {"verdict": "reproduced"}
    with pytest.raises(ValueError):
        regression.generate(f, proj, proj / "tests", accept_candidate=True)   # inside target


def test_comment_match_rejected_by_verifier(proj):
    run = _sample_failing_run(proj)
    f = next(x for x in run["findings"] if x["check_id"] == "SEC-WEB-007")
    # mutate: same line number, now a comment, but fingerprint recorded for old text -> needs_validation (stale)
    write(proj, "app.py", VULN_PY.replace("    return", "    # return"))
    verification.verify_findings(run, proj)
    assert f["status"] in ("needs_validation", "rejected")


# ---- reports & CLI --------------------------------------------------------------------
def test_cli_audit_all_formats_and_gating(proj, tmp_path, capsys):
    _sample_failing_run(proj)
    out = tmp_path / "art"
    rc = main(["audit", str(proj), "--profile", "standard", "--report", "sarif,json,markdown,junit", "--output-dir", str(out), "--fail-on", "medium"])
    assert rc == 1                                    # reproduced high-confidence candidate gates CI by default
    assert main(["audit", str(proj), "--output-dir", str(tmp_path / "g"), "--gate", "confirmed"]) == 0   # no confirmed findings
    sarif = json.loads((out / "results.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    ET.parse(out / "junit.xml")
    md = (out / "REPORT.md").read_text()
    assert "Coverage" in md and "Blocked / untested" in md
    run = json.loads((out / "run.json").read_text())
    assert verification.verify_run(run, proj)["valid"]
    assert main(["verify", str(out / "run.json"), "--target", str(proj)]) == 0
    assert main(["audit", str(proj), "--output-dir", str(tmp_path / "a2"), "--fail-on", "never"]) == 0
    # low-confidence candidates never gate by default, even at the lowest threshold
    lowonly = tmp_path / "lowonly"; lowonly.mkdir()
    write(lowonly, "package.json", '{"name":"app","dependencies":{"express":"4"},"scripts":{"start":"node x.js"}}')
    assert main(["audit", str(lowonly), "--output-dir", str(tmp_path / "lo"), "--fail-on", "info"]) == 0


def test_cli_refuses_output_inside_target(proj):
    assert main(["audit", str(proj), "--output-dir", str(proj / "out")]) == 2


def test_cli_verify_detects_tampered_file(proj, tmp_path):
    _sample_failing_run(proj)
    out = tmp_path / "art"
    main(["audit", str(proj), "--output-dir", str(out), "--fail-on", "never"])
    run = json.loads((out / "run.json").read_text())
    run["executions"][0]["status"] = "executed"
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(run))
    assert main(["verify", str(p), "--target", str(proj)]) == 3


def test_cli_bad_args(proj):
    assert main(["audit", str(proj), "--report", "pdf"]) == 2
    assert main(["audit", "/nonexistent-dir-xyz"]) == 2
    assert main(["audit", str(proj), "--type", "web", "--scope", "x.json"]) == 2


def test_module_entrypoint_runs():
    r = subprocess.run([sys.executable, "-m", "security_runner", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert r.stdout.strip() == __version__


def test_REG_tls_rule_ignores_conditional_that_requires_verification(proj):
    # found by auditing real third-party code (aioquic): ternary with CERT_REQUIRED was a false positive
    write(proj, "requirements.txt", "flask==3.0.0\n")
    write(proj, "tls.py", "import ssl\nmode = ssl.CERT_REQUIRED if is_client else ssl.CERT_NONE\n")
    run = _audit(proj)
    assert not [f for f in run["findings"] if f["check_id"] == "SEC-WEB-007"]


def test_static_matches_are_never_confirmed_automatically(proj):
    run = _sample_failing_run(proj)
    verification.verify_findings(run, proj)
    assert run["findings"] and all(f["status"] != "confirmed" for f in run["findings"])
    from security_runner import coverage
    cov = coverage.summarize(run)
    assert cov["verified_vulnerabilities"] == 0 and cov["reproduced_candidates"] >= 1


def test_confirm_requires_recorded_independent_validation(proj, tmp_path):
    run = _sample_failing_run(proj)
    verification.verify_findings(run, proj)
    f = run["findings"][0]
    ev = tmp_path / "poc.txt"
    ev.write_text("request/response transcript from the lab showing TLS MITM accepted")
    with pytest.raises(ValueError):
        verification.confirm_finding(run, f["id"], validator="x", method="guess", boundary="x" * 30, evidence_file=ev)
    with pytest.raises(ValueError):
        verification.confirm_finding(run, f["id"], validator="a", method="manual-review", boundary="short", evidence_file=ev)
    with pytest.raises(ValueError):
        verification.confirm_finding(run, f["id"], validator="a", method="manual-review", boundary="y" * 30,
                                     evidence_file=tmp_path / "missing")
    verification.confirm_finding(run, f["id"], validator="alice", method="dynamic-test",
                                 boundary="Client accepts forged server certificates, breaking transport authenticity",
                                 evidence_file=ev)
    evidence.seal(run)
    assert f["status"] == "confirmed" and verification.verify_run(run, proj)["valid"]


def test_forged_confirmed_status_without_validation_rejected(proj):
    run = _sample_failing_run(proj)
    r = copy.deepcopy(run)
    r["findings"][0]["status"] = "confirmed"
    evidence.seal(r)
    assert any("validation record" in e for e in verification.verify_run(r, proj)["errors"])


def test_REG_appending_to_examined_file_is_detected(proj):
    # found by the release gate: verification re-hashed only the originally recorded byte count
    run = _sample_failing_run(proj)
    p = proj / "app.py"
    p.write_text(p.read_text() + "\n# appended after the run\n")
    res = verification.verify_run(run, proj)
    assert not res["valid"] and any("hash differs" in e for e in res["errors"])


def test_default_gate_excludes_low_and_medium_confidence_findings(proj, tmp_path):
    """Publication condition: low-confidence candidates must never fail CI by default (even critical/high severity)."""
    from security_runner import cli
    run = _sample_failing_run(proj)
    verification.verify_findings(run, proj)
    # synthesize the worst case: a critical-severity, low-confidence reproduced candidate
    f = run["findings"][0]
    f.update(severity="critical", confidence="low", status="candidate")
    for conf in ("low", "medium"):
        f["confidence"] = conf
        counted = lambda g, strict=False: g["status"] == "confirmed" or (g["status"] == "candidate" and g["confidence"] == "high") \
            or (strict and g["status"] in ("candidate", "needs_validation"))
        assert not counted(f)            # mirrors cli gate logic for --gate candidates
        assert counted(f, strict=True)   # only --strict includes it
    # end-to-end: a project whose only reproduced findings are low/medium confidence exits 0 at the strictest threshold
    only_low = tmp_path / "onlylow"
    only_low.mkdir()
    write(only_low, "package.json", '{"name":"x","dependencies":{"express":"4"}}')            # SC-001 (low) fires
    write(only_low, "src/a.py", "import requests\nrequests.get(u, verify=False)\n")            # WEB-007 (medium) fires
    out = tmp_path / "lo2"
    assert main(["audit", str(only_low), "--output-dir", str(out), "--fail-on", "info"]) == 0
    r = json.loads((out / "run.json").read_text())
    assert any(x["confidence"] in ("low", "medium") and x["status"] == "candidate" for x in r["findings"])
    assert main(["audit", str(only_low), "--output-dir", str(tmp_path / "lo3"), "--fail-on", "info", "--strict"]) == 1
