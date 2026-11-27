#!/usr/bin/env python3
"""Report skill pairs whose descriptions are likely to collide in routing (stdlib only).

  python scripts/skill_collisions.py [--skills skills] [--threshold 0.45] [--allowlist evals/collision-allowlist.json]
        [--max-unreviewed N] [--json]

Each skill is the text `slug words + description`, tokenised and weighted with TF-IDF; pairs with cosine similarity
>= --threshold are listed. The allowlist is JSON: {"allowed": [{"pair": ["skill-a", "skill-b"], "reason": "..."}]}.
Allowlisted pairs are shown as reviewed. Exit code is 1 when unreviewed pairs exceed --max-unreviewed (default: no limit,
exit 0), so CI can use --max-unreviewed 0. An allowlist entry without a reason is an error (exit 2).
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runner.skillcheck import parse_frontmatter  # noqa: E402

STOP = frozenset("a an and are as at be by for from in is it of on or that the this to use when with not your you can any".split())


def tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOP and len(t) > 1]


def load_docs(skills_dir: Path) -> dict[str, list[str]]:
    docs = {}
    for d in sorted(p for p in Path(skills_dir).iterdir() if p.is_dir() and (p / "SKILL.md").is_file()):
        fm, _ = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
        desc = fm.get("description", "")
        docs[d.name] = tokens(d.name.replace("-", " ") + " " + (desc if isinstance(desc, str) else ""))
    return docs


def vectors(docs: dict[str, list[str]]) -> dict[str, dict[str, float]]:
    n = len(docs)
    df = Counter(t for toks in docs.values() for t in set(toks))
    out = {}
    for name, toks in docs.items():
        tf = Counter(toks)
        v = {t: (1 + math.log(c)) * (math.log((1 + n) / (1 + df[t])) + 1) for t, c in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        out[name] = {t: x / norm for t, x in v.items()}
    return out


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(t, 0.0) for t, x in a.items())


def similar_pairs(docs: dict[str, list[str]], threshold: float) -> list[tuple[str, str, float]]:
    vec = vectors(docs)
    names = sorted(vec)
    pairs = [(a, b, cosine(vec[a], vec[b])) for i, a in enumerate(names) for b in names[i + 1:]]
    return sorted([p for p in pairs if p[2] >= threshold], key=lambda p: -p[2])


def load_allowlist(path: Path) -> dict[frozenset, str]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    out = {}
    for e in data.get("allowed", []):
        pair, reason = e.get("pair"), e.get("reason")
        if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, str) for x in pair)):
            raise ValueError(f"allowlist entry needs a 2-item 'pair': {e!r}")
        if not (isinstance(reason, str) and reason.strip()):
            raise ValueError(f"allowlist entry {pair} needs a non-empty 'reason'")
        out[frozenset(pair)] = reason
    return out


def run(skills_dir: Path, threshold: float, allowlist: Path, max_unreviewed: int | None) -> tuple[int, dict]:
    pairs = similar_pairs(load_docs(skills_dir), threshold)
    allowed = load_allowlist(allowlist)
    rows = [{"pair": [a, b], "score": round(s, 3), "reviewed": frozenset((a, b)) in allowed,
             "reason": allowed.get(frozenset((a, b)))} for a, b, s in pairs]
    unreviewed = sum(not r["reviewed"] for r in rows)
    code = 1 if max_unreviewed is not None and unreviewed > max_unreviewed else 0
    return code, {"threshold": threshold, "pairs": rows, "unreviewed": unreviewed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skills", default="skills")
    ap.add_argument("--threshold", type=float, default=0.45)
    ap.add_argument("--allowlist", default="evals/collision-allowlist.json")
    ap.add_argument("--max-unreviewed", type=int, default=None, help="exit 1 if more unreviewed pairs than this")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        code, rep = run(Path(a.skills), a.threshold, Path(a.allowlist), a.max_unreviewed)
    except ValueError as ex:
        print(f"allowlist invalid: {ex}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(rep, indent=1))
    else:
        print(f"{len(rep['pairs'])} pair(s) with cosine >= {rep['threshold']}; {rep['unreviewed']} unreviewed")
        for r in rep["pairs"]:
            print(f"  {r['score']:.3f}  {r['pair'][0]} <-> {r['pair'][1]}" + (f"  [reviewed: {r['reason']}]" if r["reviewed"] else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
