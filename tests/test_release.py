"""Release-content controls: allowlist, restricted-content scanner (with positive controls), licensing metadata."""
import importlib.util
import json

import pytest
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


scan_restricted = _load("scan_restricted")
build_release = _load("build_release")


def _raw(tmp, text):
    d = tmp / "raw"
    d.mkdir()
    (d / "x.jsonl").write_text(json.dumps({"raw_id": "RAW-1", "text_decoded": text}) + "\n")
    return d


def test_scanner_detects_full_entry_and_long_run(tmp_path):
    raw = _raw(tmp_path, "Verify that purple lanterns hum quietly beneath seventeen unlit bridges tonight")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.md").write_text("Notes: verify that PURPLE lanterns hum quietly beneath seventeen unlit bridges tonight.\n")
    res = scan_restricted.scan(tree, raw)
    assert res["status"] == "FAIL" and res["hits"]


def test_scanner_passes_clean_and_skips_without_raw(tmp_path):
    raw = _raw(tmp_path, "Verify that purple lanterns hum quietly beneath seventeen unlit bridges tonight")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.md").write_text("Lanterns should stay dim near the bridges.\n")
    assert scan_restricted.scan(tree, raw)["status"] == "PASS"
    assert scan_restricted.scan(tree, tmp_path / "missing")["status"] == "SKIPPED"   # never reported as clean


def test_allowlist_excludes_restricted_material():
    files = build_release.select()
    bad = [f for f in files if f.startswith(("catalog/", "docs/baseline/", "security_runner/catalogtool/", "dist/"))
           or f.endswith((".zip",)) or f in ("tests/test_catalogtool.py", "docs/WORKSTREAM-CONTRACT.md")]
    assert not bad, bad
    assert "LICENSE" in files and "NOTICE" in files and "skills/security-start/SKILL.md" in files


def test_license_metadata():
    tomllib = pytest.importorskip("tomllib")
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert meta["license"] == "MIT"
    lic = (ROOT / "LICENSE").read_text()
    assert lic.startswith("MIT License\n") and "Copyright (c) 2026 shikari00007" in lic and "Apache" not in lic
    third = (ROOT / "docs" / "THIRD-PARTY.md").read_text()
    for sha in ("5087a3461d49da76b1e794d9b0bfbd23f38dc75b", "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
                "6196ba7464662de34e8744d359f175d1a7bca530"):
        assert sha in third


def test_no_network_capable_imports_in_runner():
    banned = re.compile(r"^\s*(import|from)\s+(socket|urllib|http|requests|httpx|ftplib|smtplib|aiohttp)\b", re.M)
    offenders = [str(p.relative_to(ROOT)) for p in (ROOT / "security_runner").rglob("*.py")
                 if "catalogtool" not in p.parts and banned.search(p.read_text())]
    assert not offenders, offenders


def test_developer_preview_labelled():
    assert "Developer Preview" in (ROOT / "README.md").read_text()
