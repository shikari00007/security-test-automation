"""Scan a release tree for reproduced third-party checklist text.

Needs the private raw inventory (catalog/raw/*.jsonl), which is NOT shipped. Without it the scan reports SKIPPED
(never "clean"). Detection: (a) any full raw entry (>=5 words) appearing as a normalized line/substring,
(b) any run of >=10 consecutive words shared with a raw entry.
Usage: python scripts/scan_restricted.py <release-tree> [--raw catalog/raw]
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHINGLE = 10
TEXT_EXT = {".md", ".json", ".py", ".yml", ".yaml", ".txt", ".toml", ".js", ".ts", ".java", ".kt", ".xml", ".plist", ".tf", ".swift", ".cs", ".html", ""}


def norm(s: str) -> list[str]:
    s = html.unescape(s).lower()
    return re.findall(r"[a-z0-9][a-z0-9._/-]*", s)


def load_raw(raw_dir: Path):
    entries, shingles = set(), {}
    for f in sorted(raw_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            w = norm(e.get("text_decoded") or e.get("text_original", ""))
            if len(w) >= 5:
                entries.add(" ".join(w))
            for i in range(0, max(0, len(w) - SHINGLE + 1)):
                shingles.setdefault(" ".join(w[i:i + SHINGLE]), e.get("raw_id", f.stem))
    return entries, shingles


def scan(tree: Path, raw_dir: Path) -> dict:
    if not raw_dir.is_dir() or not list(raw_dir.glob("*.jsonl")):
        return {"status": "SKIPPED", "reason": f"raw inventory not found at {raw_dir}", "hits": []}
    entries, shingles = load_raw(raw_dir)
    hits = []
    for p in sorted(tree.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in TEXT_EXT:
            continue
        rel = p.relative_to(tree).as_posix()
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        words = norm(text)
        joined = " ".join(words)
        for e in entries:
            if e in joined:
                hits.append({"file": rel, "kind": "full-entry", "text": e[:100]})
        for i in range(0, max(0, len(words) - SHINGLE + 1)):
            sh = " ".join(words[i:i + SHINGLE])
            if sh in shingles:
                hits.append({"file": rel, "kind": f"{SHINGLE}-word-run", "text": sh[:100], "raw_id": shingles[sh]})
                break   # one per file is enough to flag; reported text is short
    return {"status": "FAIL" if hits else "PASS", "hits": hits, "raw_entries_checked": len(entries)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--raw", default=str(ROOT / "catalog" / "raw"))
    a = ap.parse_args(argv)
    res = scan(Path(a.tree), Path(a.raw))
    print(json.dumps(res, indent=2))
    return {"PASS": 0, "FAIL": 1, "SKIPPED": 3}[res["status"]]


if __name__ == "__main__":
    sys.exit(main())
