"""Assemble the public release tree from an explicit allowlist (nothing is published by this script).

Usage: python scripts/build_release.py [--out dist/release-candidate]
Excluded by design: catalog/raw*, canonical catalog, mappings/reports, catalog tooling, baseline planning docs,
internal workstream docs, caches. Writes RELEASE-MANIFEST.txt (sha256 + size per file).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

INCLUDE = [
    "README.md", "LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "pyproject.toml", ".gitignore",
    ".github/workflows/*.yml", ".github/secret_scanning.yml",
    "skills/*", "skills/**",
    "security_runner/*.py", "security_runner/adapters/*.py", "security_runner/reporting/*.py",
    "security_runner/data/*.json", "security_runner/data/checks/*.json", "security_runner/data/schemas/*.json",
    "fixtures/**",
    "tests/*.py",
    "scripts/build_release.py", "scripts/release_gate.py", "scripts/scan_restricted.py", "scripts/rule_accuracy.py",
    "scripts/verify_published.sh", "scripts/check_public_mit.py", "scripts/check_links.py",
    ".github/ISSUE_TEMPLATE/*", ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/VERIFICATION.md", "docs/RULE-ACCURACY.md", "docs/RULE-ACCURACY-FIELD*.md", "docs/RELEASE-GATES.md",
    "docs/THIRD-PARTY.md", "docs/PHASE0-AUDIT.md", "docs/CATALOG.md", "docs/ACCURACY-HOLDOUT.md", "docs/methodology/*.md",
]
EXCLUDE = [
    "**/__pycache__/**", "**/*.pyc", "**/.pytest_cache/**", "**/*.egg-info/**",
    "tests/test_catalogtool.py",            # needs the private raw sources
    "security_runner/catalogtool/**",       # maintainer-internal importer
    "**/.DS_Store",
]


def _match(rel: str, pats: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or (p.endswith("/**") and rel.startswith(p[:-2])) for p in pats)


def select() -> list[str]:
    out = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith("dist/") or rel.startswith(".git/"):
            continue
        if _match(rel, INCLUDE) and not _match(rel, EXCLUDE):
            out.append(rel)
    return out


def build(out: Path) -> list[str]:
    if out.exists():
        shutil.rmtree(out)
    files = select()
    for rel in files:
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
    lines = [f"{hashlib.sha256((out / r).read_bytes()).hexdigest()}  {(out / r).stat().st_size:>8}  {r}" for r in files]
    (out / "RELEASE-MANIFEST.txt").write_text("\n".join(lines) + "\n")
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "release-candidate"))
    ap.add_argument("--tarball", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out).resolve()
    files = build(out)
    print(f"release tree: {out} ({len(files)} files + RELEASE-MANIFEST.txt)")
    if a.tarball:
        tb = out.parent / (out.name + ".tar.gz")
        with tarfile.open(tb, "w:gz") as t:
            t.add(out, arcname=out.name)
        print(f"tarball: {tb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
