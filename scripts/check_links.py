#!/usr/bin/env python3
"""Check relative links (and #anchors) in the repository's Markdown files.

Usage: python scripts/check_links.py [repo-root]
External (http/https/mailto) links are not fetched. Links inside fenced code blocks are ignored.
Exit code 0 = all links resolve, 1 = broken links found.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)|\!\[[^\]]*\]\(([^)\s]+)\)")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "fixtures", "__pycache__"}


def slug(heading: str) -> str:
    s = re.sub(r"[`*_~]", "", heading.strip().lower())
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out, seen, fence = set(), {}, False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"#{1,6}\s+(.*)", line)
        if m:
            base = slug(m.group(1))
            n = seen.get(base, 0)
            seen[base] = n + 1
            out.add(base if n == 0 else f"{base}-{n}")
    return out


def check(root: Path) -> list[str]:
    problems = []
    for md in sorted(root.rglob("*.md")):
        rel = md.relative_to(root)
        if SKIP_DIRS & set(rel.parts[:-1]):
            continue
        fence = False
        for ln, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fence = not fence
                continue
            if fence:
                continue
            for m in LINK.finditer(re.sub(r"`[^`]*`", "", line)):
                target = unquote(m.group(1) or m.group(2))
                if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                    continue                       # http:, https:, mailto: ...
                path_part, _, frag = target.partition("#")
                dest = md if not path_part else (md.parent / path_part).resolve()
                if path_part and not str(dest).startswith(str(root.resolve())):
                    problems.append(f"{rel}:{ln}: link escapes repository: {target}")
                    continue
                if not dest.exists():
                    problems.append(f"{rel}:{ln}: missing target: {target}")
                    continue
                if frag and dest.is_file() and dest.suffix == ".md" and frag.lower() not in anchors(dest):
                    problems.append(f"{rel}:{ln}: missing anchor #{frag} in {dest.relative_to(root.resolve())}")
    return problems


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]).resolve() if argv else Path(__file__).resolve().parents[1]
    problems = check(root)
    for p in problems:
        print("BROKEN:", p)
    print(f"checked Markdown links under {root}: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
