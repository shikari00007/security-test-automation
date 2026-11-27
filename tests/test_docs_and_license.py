"""Documentation, licensing and public-content consistency (with positive controls for the checkers)."""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


check_links = _load("check_links")


def test_repo_links_resolve():
    assert check_links.check(ROOT) == []


def test_link_checker_detects_breakage(tmp_path):
    (tmp_path / "a.md").write_text("# Title\n[ok](b.md) [bad](missing.md) [anchor](b.md#nope) [good](b.md#real-heading)\n"
                                   "```\n[ignored](nothing.md)\n```\n")
    (tmp_path / "b.md").write_text("## Real Heading\n")
    problems = check_links.check(tmp_path)
    assert len(problems) == 2 and any("missing.md" in p for p in problems) and any("#nope" in p for p in problems)


def test_license_checker_passes_repo_and_fails_apache(tmp_path):
    ok = subprocess.run([sys.executable, str(ROOT / "scripts/check_public_mit.py"), str(ROOT)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout
    (tmp_path / "LICENSE").write_text("Apache License\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nlicense = "Apache-2.0"\n')
    (tmp_path / "skills" / "x").mkdir(parents=True)
    (tmp_path / "skills" / "x" / "SKILL.md").write_text("---\nname: x\nlicense: Apache-2.0\n---\n")
    bad = subprocess.run([sys.executable, str(ROOT / "scripts/check_public_mit.py"), str(tmp_path)], capture_output=True, text=True)
    assert bad.returncode == 1 and "LICENSE" in bad.stdout


def test_apache_mentions_are_only_historical_or_in_allowed_files():
    allowed = {"README.md", "CONTRIBUTING.md", "NOTICE", "CHANGELOG.md", "docs/THIRD-PARTY.md", "docs/RELEASE-GATES.md",
               "docs/PHASE0-AUDIT.md", "tests/test_docs_and_license.py", "tests/test_release.py", "scripts/check_public_mit.py", "scripts/release_gate.py", ".github/workflows/validate.yml"}
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    files = out.stdout.split() if out.returncode == 0 else [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()]
    offenders = []
    for f in files:
        p = ROOT / f
        if f in allowed or not p.is_file() or f.startswith((".git/", "fixtures/", "build/", "dist/")) or ".egg-info/" in f:
            continue
        try:
            if "Apache" in p.read_text(encoding="utf-8"):
                offenders.append(f)
        except UnicodeDecodeError:
            pass
    assert not offenders, offenders


def test_current_licence_is_mit_everywhere():
    lic = (ROOT / "LICENSE").read_text()
    assert lic.startswith("MIT License\n") and "Copyright (c) 2026 shikari00007" in lic
    notice = (ROOT / "NOTICE").read_text()
    assert "MIT License" in notice and "v0.3.0rc1" in notice and "Apache-2.0" in notice   # historical release clarified
    assert re.search(r'^license\s*=\s*"MIT"', (ROOT / "pyproject.toml").read_text(), re.M)


def test_readme_required_content():
    r = (ROOT / "README.md").read_text()
    assert "npx skills add shikari00007/security-test-automation" in r
    for section in ("Quick start", "Example prompts", "Supported AI coding agents", "Skills catalog", "Security domains",
                    "Audit profiles", "Optional CLI runner", "Developer security workflow",
                    "Security automation and regression testing", "Honest limitations and accuracy",
                    "Contributing and community", "License and acknowledgments"):
        assert f"## {section}" in r, section
    assert "51% strict precision" in r and "Developer Preview" in r
    from security_runner.skillcheck import validate_dir
    names = validate_dir(ROOT / "skills")["skills"]
    assert len(names) == 24 and all(f"skills/{n})" in r for n in names), "README skill table must link all 24 skills"


def test_documented_scripts_exist():
    text = (ROOT / "CONTRIBUTING.md").read_text() + (ROOT / "README.md").read_text()
    for s in set(re.findall(r"scripts/([A-Za-z0-9_]+\.(?:py|sh))", text)):
        assert (ROOT / "scripts" / s).is_file(), s


def test_documented_cli_subcommands_exist():
    text = (ROOT / "CONTRIBUTING.md").read_text() + (ROOT / "README.md").read_text()
    for m in set(re.findall(r"(?:python -m security_runner|security-skills) ([a-z]+(?: [a-z-]+)?)", text)):
        top = m.split()[0]
        assert top in {"detect", "plan", "audit", "verify", "confirm", "coverage", "rerun", "regression", "catalog", "skills"}, m


def test_pyproject_structure_is_valid():
    """Regression: a [project.urls] table inserted mid-[project] swallowed later keys and broke `pip install -e`."""
    import pytest
    tomllib = pytest.importorskip("tomllib")
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert proj["dependencies"] == [] and proj["license"] == "MIT" and proj["requires-python"] == ">=3.10"
    assert proj["urls"] and all(isinstance(v, str) and v.startswith("https://") for v in proj["urls"].values())
    assert "build>=1" in proj["optional-dependencies"]["dev"]
    assert not any(c.startswith("License ::") for c in proj["classifiers"]), "license classifiers conflict with an SPDX expression"
