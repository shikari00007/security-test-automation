"""Agent Skills specification validator (https://agentskills.io/specification)."""
from __future__ import annotations

import re
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ALLOWED = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}


def parse_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\n(.*?)\n---\n?(.*)$", text, re.S)
    if not m:
        raise ValueError("missing YAML frontmatter")
    fm: dict = {}
    cur = None
    for line in m.group(1).splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")):
            if cur is None:
                raise ValueError("indented line without key")
            k, _, v = line.strip().partition(":")
            fm.setdefault(cur, {})
            if not isinstance(fm[cur], dict):
                raise ValueError(f"{cur} mixes scalar and map")
            fm[cur][k.strip()] = v.strip().strip("\"'")
            continue
        k, sep, v = line.partition(":")
        if not sep:
            raise ValueError(f"bad frontmatter line {line!r}")
        cur = k.strip()
        v = v.strip()
        fm[cur] = v.strip("\"'") if v else {}
    return fm, m.group(2)


def validate_skill(d: Path) -> list[str]:
    errs = []
    f = d / "SKILL.md"
    if not f.is_file():
        return [f"{d.name}: SKILL.md missing"]
    try:
        fm, body = parse_frontmatter(f.read_text(encoding="utf-8"))
    except ValueError as e:
        return [f"{d.name}: {e}"]
    name, desc = fm.get("name", ""), fm.get("description", "")
    if not isinstance(name, str) or not (1 <= len(name) <= 64) or not NAME_RE.match(name):
        errs.append(f"{d.name}: invalid name {name!r}")
    if name != d.name:
        errs.append(f"{d.name}: name must match directory")
    if not isinstance(desc, str) or not (1 <= len(desc) <= 1024):
        errs.append(f"{d.name}: description must be 1-1024 chars")
    if len(fm.get("compatibility", "")) > 500:
        errs.append(f"{d.name}: compatibility > 500 chars")
    for k in fm:
        if k not in ALLOWED:
            errs.append(f"{d.name}: unknown frontmatter field {k!r}")
    if len(body.splitlines()) > 500:
        errs.append(f"{d.name}: body exceeds 500 lines (move detail to references/)")
    for ref in re.findall(r"\]\(((?:references|scripts|assets)/[^)#\s]+)", body):
        if not (d / ref).exists():
            errs.append(f"{d.name}: broken relative reference {ref}")
    return errs


def validate_dir(root: str | Path) -> dict:
    root = Path(root)
    skills = sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
    errs: list[str] = []
    for s in skills:
        errs += validate_skill(s)
    return {"valid": not errs and bool(skills), "skills": [s.name for s in skills], "errors": errs}
