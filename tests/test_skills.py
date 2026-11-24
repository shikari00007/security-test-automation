"""Validate the 16 Agent Skills under skills/."""
import re
from pathlib import Path

import pytest

from security_runner import catalog
from security_runner.skillcheck import parse_frontmatter, validate_dir, validate_skill

SKILLS = Path(__file__).resolve().parents[1] / "skills"
EXPECTED = {
    "security-start", "security-project-context", "security-do", "security-test-strategy",
    "security-coverage-analysis", "web-security-testing", "api-security-testing",
    "android-security-testing", "ios-security-testing", "desktop-security-testing",
    "supply-chain-security", "cloud-kubernetes-security", "ai-llm-security",
    "security-finding-validation", "security-regression-generation", "security-reporting",
}
DIRS = sorted(p for p in SKILLS.iterdir() if p.is_dir())


def md_files(d):
    return [d / "SKILL.md"] + sorted((d / "references").glob("*.md"))


def test_exact_skill_set():
    assert {p.name for p in DIRS} == EXPECTED
    assert len(DIRS) == 16


def test_validate_dir_clean():
    res = validate_dir(SKILLS)
    assert res["errors"] == [] and res["valid"]


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_spec_and_frontmatter(d):
    assert validate_skill(d) == []
    fm, body = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
    assert fm["name"] == d.name
    assert fm["license"] == "Apache-2.0"
    assert fm.get("compatibility")
    assert fm["metadata"].get("version") and fm["metadata"].get("author")
    desc = fm["description"]
    assert len(desc) <= 1024
    assert "Use when" in desc, "description needs a 'Use when' trigger"
    assert "Not for" in desc, "description needs 'Not for' boundaries"
    assert len(body.splitlines()) < 200
    assert (d / "references").is_dir() and list((d / "references").glob("*.md"))


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_relative_links_resolve(d):
    for f in md_files(d):
        for target in re.findall(r"\]\((?!https?:|#|mailto:)([^)\s]+)\)", f.read_text(encoding="utf-8")):
            path = target.split("#")[0]
            assert (f.parent / path).exists(), f"{f}: broken link {target}"


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_check_ids_exist(d):
    known = catalog.checks()
    if not known:
        pytest.skip("catalog empty")
    for f in md_files(d):
        for cid in set(re.findall(r"\bSEC-[A-Z]+-\d{3}\b", f.read_text(encoding="utf-8"))):
            assert cid in known, f"{f}: unknown check id {cid}"


LIVE = re.compile(r"live host|staging|production|deployed|against (?:a )?(?:server|host|endpoint|url)", re.I)


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_live_host_mentions_are_scope_gated(d):
    _, body = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
    if LIVE.search(body):
        assert "written scope" in body or "authorized" in body.lower()
    # safety gates always present
    assert "written scope" in body
    assert "untrusted" in body


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_standalone_install_hint_and_fallback(d):
    body = (d / "SKILL.md").read_text(encoding="utf-8")
    assert "pip install git+https://github.com/shikari00007/security-test-automation" in body
    assert "not yet published" in body
    assert "Without the CLI" in body
    for state in ("planned", "not_applicable", "blocked", "deferred", "executed", "needs_validation"):
        assert state in body


def test_readme_attribution():
    t = (SKILLS / "README.md").read_text(encoding="utf-8")
    for s in ("cloudflare/security-audit-skill", "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
              "petrkindlmann/qa-skills", "5087a3461d49da76b1e794d9b0bfbd23f38dc75b",
              "SnailSploit/Claude-Red", "6196ba7464662de34e8744d359f175d1a7bca530"):
        assert s in t
