"""Validate the 24 Agent Skills under skills/: 16 runner-integrated skills and 8 developer-workflow skills."""
import re
from pathlib import Path

import pytest

from security_runner import catalog
from security_runner.skillcheck import parse_frontmatter, validate_dir, validate_skill

SKILLS = Path(__file__).resolve().parents[1] / "skills"
RUNNER = {
    "security-start", "security-project-context", "security-do", "security-test-strategy",
    "security-coverage-analysis", "web-security-testing", "api-security-testing",
    "android-security-testing", "ios-security-testing", "desktop-security-testing",
    "supply-chain-security", "cloud-kubernetes-security", "ai-llm-security",
    "security-finding-validation", "security-regression-generation", "security-reporting",
}
DEV = {
    "threat-modeling", "secure-coding-patterns", "authn-authz-implementation", "secrets-management",
    "security-unit-testing", "security-code-review", "vulnerability-triage-and-fix", "security-ci-cd-integration",
}
EXPECTED = RUNNER | DEV
DIRS = sorted(p for p in SKILLS.iterdir() if p.is_dir())
RUNNER_DIRS = [p for p in DIRS if p.name in RUNNER]
DEV_DIRS = [p for p in DIRS if p.name in DEV]
FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.S | re.M)
INLINE_CODE = re.compile(r"`+[^`\n]*`+")
LINK = re.compile(r"\]\((?!https?:|#|mailto:)([^)\s]+)\)")


def strip_code(text):
    """Remove fenced code blocks and inline code so code that looks like a link is not parsed as one."""
    return INLINE_CODE.sub("", FENCE.sub("", text))


def broken_links(f):
    return [t for t in LINK.findall(strip_code(f.read_text(encoding="utf-8"))) if not (f.parent / t.split("#")[0]).exists()]


def md_files(d):
    return [d / "SKILL.md"] + sorted((d / "references").glob("*.md"))


def test_exact_skill_set():
    assert not (RUNNER & DEV) and len(RUNNER) == 16 and len(DEV) == 8
    assert {p.name for p in DIRS} == RUNNER | DEV
    assert len(DIRS) == 24


def test_validate_dir_clean():
    res = validate_dir(SKILLS)
    assert res["errors"] == [] and res["valid"]


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_spec_and_frontmatter(d):
    assert validate_skill(d) == []
    fm, body = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
    assert fm["name"] == d.name
    assert fm["license"] == "MIT"
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
        assert broken_links(f) == [], f"{f}: broken link(s)"


def test_link_check_ignores_code_but_catches_real_breaks(tmp_path):
    (tmp_path / "ok.md").write_text("x")
    f = tmp_path / "doc.md"
    f.write_text("```sql\ngrep -E '(SELECT|INSERT)' [a](nope.md)\n```\nInline `grep (SELECT|INSERT)` and `[x](gone.md)` here.\n"
                 "~~~\n[t](tilde-missing.md)\n~~~\nSee [ok](ok.md) and [web](https://example.com/x).\n")
    assert broken_links(f) == []
    f.write_text(f.read_text() + "A real [broken](missing.md#a) link.\n")
    assert broken_links(f) == ["missing.md#a"]
    f.write_text("```\nunclosed fence is not code\n```\n[bad](missing2.md)\n")
    assert broken_links(f) == ["missing2.md"]


@pytest.mark.parametrize("d", DIRS, ids=lambda p: p.name)
def test_check_ids_exist(d):
    known = catalog.checks()
    if not known:
        pytest.skip("catalog empty")
    for f in md_files(d):
        for cid in set(re.findall(r"\bSEC-[A-Z]+-\d{3}\b", f.read_text(encoding="utf-8"))):
            assert cid in known, f"{f}: unknown check id {cid}"


LIVE = re.compile(r"live host|staging|production|deployed|against (?:a )?(?:server|host|endpoint|url)", re.I)


@pytest.mark.parametrize("d", RUNNER_DIRS, ids=lambda p: p.name)
def test_live_host_mentions_are_scope_gated(d):
    _, body = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
    if LIVE.search(body):
        assert "written scope" in body or "authorized" in body.lower()
    # safety gates always present
    assert "written scope" in body
    assert "untrusted" in body


@pytest.mark.parametrize("d", RUNNER_DIRS, ids=lambda p: p.name)
def test_standalone_install_hint_and_fallback(d):
    body = (d / "SKILL.md").read_text(encoding="utf-8")
    assert "pip install git+https://github.com/shikari00007/security-test-automation" in body
    assert "pip install git+https://github.com/shikari00007/security-test-automation" in body
    assert "Without the CLI" in body
    for state in ("planned", "not_applicable", "blocked", "deferred", "executed", "needs_validation"):
        assert state in body


def all_text(d):
    return "\n".join(f.read_text(encoding="utf-8") for f in md_files(d))


QUOTED = re.compile(r"[\"\u201c][^\"\u201d\n]*[\"\u201d]")
EXAMPLE_MARK = re.compile(r"\bTODO\b|REPLACE_ME")
LIVE_DEV = re.compile(r"live hosts?|staging|production|deployed|against (?:a )?(?:live )?(?:server|host|endpoint|url)", re.I)


@pytest.mark.parametrize("d", DEV_DIRS, ids=lambda p: p.name)
def test_dev_skill_rules(d):
    text = (d / "SKILL.md").read_text(encoding="utf-8")
    fm, body = parse_frontmatter(text)
    assert fm["license"] == "MIT"
    desc = fm["description"]
    assert "Use when" in desc and "Not for" in desc
    assert "Developer Preview" in body
    assert (d / "references" / "VERIFICATION-NOTES.md").is_file(), "dev skills must ship references/VERIFICATION-NOTES.md"
    for f in md_files(d):
        # TODO / REPLACE_ME are allowed only inside code examples or when quoted as something to look for in reviewed code
        prose = QUOTED.sub("", strip_code(f.read_text(encoding="utf-8")))
        assert not EXAMPLE_MARK.search(prose), f"{f}: unresolved placeholder outside a code block"
    both = all_text(d)
    if LIVE_DEV.search(both):
        assert re.search(r"authori[sz]ed|\bscope\b", both, re.I), "live-host mention needs an 'authorized' or 'scope' qualifier"


def test_readme_attribution():
    t = (SKILLS / "README.md").read_text(encoding="utf-8")
    for s in ("cloudflare/security-audit-skill", "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
              "petrkindlmann/qa-skills", "5087a3461d49da76b1e794d9b0bfbd23f38dc75b",
              "SnailSploit/Claude-Red", "6196ba7464662de34e8744d359f175d1a7bca530"):
        assert s in t
