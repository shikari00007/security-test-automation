# Threat-model linter

Stdlib-only Python 3 script that checks the structure of `docs/security/threat-model.md`. It does not judge whether threats are good or complete.

## Use

Extract the script block below into `tmlint.py` outside the repo's source tree (or a `tools/` folder you control), then:

```bash
python3 -I tmlint.py docs/security/threat-model.md
```

Exit code 0 = no structural problems; 1 = problems printed as `FAIL line N: ...`.

## What it checks

- `last_reviewed: YYYY-MM-DD` present and a valid date.
- At least one mermaid block, starting `flowchart`/`graph` with a direction; balanced brackets, parentheses and quotes; balanced `subgraph`/`end`; unquoted node or edge labels containing `( ) : ; #` are flagged, and `end` used as a node id is flagged (all are mermaid parse errors). Mermaid problems are reported at the offending line.
- Threat table has the columns id, where, category, abuse case, impact, likelihood, risk, why, mitigation, status, test.
- Ids match `T-001`, are unique; abuse case, why, mitigation, test, where, category are non-empty.
- Impact and likelihood are integers 1-3 and Risk equals the banded product, for example `High (6)`.
- Status is one of planned, implemented, accepted, transferred, eliminated; `accepted` needs the word `owner` or `accepted by` in Why.

## How it was verified

Run in a sandbox against: the worked example (11 threats, 0 problems); the template with a real date (2 threats, 0 problems; the placeholder date is rejected); and deliberately broken copies (wrong risk band, empty test cell, duplicate id, accepted without owner, unquoted parenthesis in a label, unquoted edge label `-->|F1 login (reset): HTTPS|`, `end` as a node id, missing `end`), each of which produced the expected FAIL. The same diagrams were parsed with `mermaid@11` `parse()` under jsdom: the worked-example and template diagrams parse, and an unquoted-parenthesis label fails, matching the linter's rule. The linter is a convention check, not a renderer; open the file in a mermaid-capable viewer (GitHub renders it) to see the picture.

## Script

```python
#!/usr/bin/env python3
"""Lint docs/security/threat-model.md. Stdlib only. Exit 0 = pass, 1 = problems.

Usage: python3 -I tmlint.py docs/security/threat-model.md
"""
import re
import sys
from datetime import date

REQUIRED_COLS = ["id", "where", "category", "abuse case", "impact", "likelihood",
                 "risk", "why", "mitigation", "status", "test"]
STATUSES = {"planned", "implemented", "accepted", "transferred", "eliminated"}
ID_RE = re.compile(r"^T-\d{3}$")
NODE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*(\[|\(|\{|-->|---|-\.|==|$)")


def band(score):
    return "High" if score >= 6 else "Medium" if score >= 3 else "Low"


def split_row(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def lint_mermaid(block, start, problems):
    lines = [(start + k, l) for k, l in enumerate(block) if l.strip() and not l.strip().startswith("%%")]
    if not lines or not re.match(r"^(flowchart|graph)\s+(TD|TB|BT|LR|RL)\b", lines[0][1].strip()):
        problems.append(f"line {start}: mermaid block must start with 'flowchart TD|LR|...'")
        return
    depth = 0
    for ln, l in lines[1:]:
        s = l.strip()
        if s.startswith("subgraph"):
            depth += 1
        elif s == "end":
            depth -= 1
            if depth < 0:
                problems.append(f"line {ln}: 'end' without subgraph")
                depth = 0
        if s.count("[") != s.count("]") or s.count("(") != s.count(")") or s.count('"') % 2:
            problems.append(f"line {ln}: unbalanced brackets or quotes: {s[:60]}")
        for m in re.finditer(r"\|([^|\"]*)\|", s):
            if re.search(r"[():;#]", m.group(1)):
                problems.append(f"line {ln}: quote edge labels containing ( ) : ; # -> {m.group(0)[:50]}")
        if re.match(r"^end\s*(\[|\(|\{|-->|---)", s):
            problems.append(f"line {ln}: 'end' used as a node id")
        # labels with raw parentheses/colons must be quoted
        for m in re.finditer(r"\[([^\]\"]*)\]", s):
            if re.search(r"[():;#]", m.group(1)):
                problems.append(f"line {ln}: quote labels containing ( ) : ; # -> {m.group(0)[:50]}")
    if depth != 0:
        problems.append(f"line {start}: unclosed subgraph")


def main(path):
    text = open(path, encoding="utf-8").read().splitlines()
    problems = []
    joined = "\n".join(text)
    m = re.search(r"last_reviewed:\s*(\d{4}-\d{2}-\d{2})", joined)
    if not m:
        problems.append("missing 'last_reviewed: YYYY-MM-DD'")
    else:
        try:
            date.fromisoformat(m.group(1))
        except ValueError:
            problems.append("last_reviewed is not a valid date")
    # mermaid
    i, nblocks = 0, 0
    while i < len(text):
        if text[i].strip() == "```mermaid":
            j = i + 1
            while j < len(text) and text[j].strip() != "```":
                j += 1
            nblocks += 1
            lint_mermaid(text[i + 1:j], i + 2, problems)
            i = j
        i += 1
    if nblocks == 0:
        problems.append("no mermaid data-flow diagram found")
    # threat table
    cols, threats, ids = None, 0, set()
    for n, line in enumerate(text, 1):
        if not line.startswith("|"):
            cols = None if cols and not line.strip() else cols
            continue
        cells = split_row(line)
        low = [c.lower() for c in cells]
        if "abuse case" in low and "id" in low:
            cols = {name: low.index(name) for name in low}
            miss = [c for c in REQUIRED_COLS if not any(k.startswith(c) for k in cols)]
            if miss:
                problems.append(f"line {n}: threat table missing columns {miss}")
                cols = None
            continue
        if cols is None or set(line.replace("|", "").strip()) <= set("-: "):
            continue
        def get(prefix):
            for k, idx in cols.items():
                if k.startswith(prefix):
                    return cells[idx] if idx < len(cells) else ""
            return ""
        tid = get("id")
        if not ID_RE.match(tid):
            problems.append(f"line {n}: bad threat id '{tid}' (want T-001)")
            continue
        threats += 1
        if tid in ids:
            problems.append(f"line {n}: duplicate id {tid}")
        ids.add(tid)
        for f in ("abuse case", "why", "mitigation", "test", "where", "category"):
            if not get(f):
                problems.append(f"line {n}: {tid} has empty '{f}'")
        try:
            imp, lik = int(get("impact")), int(get("likelihood"))
            assert 1 <= imp <= 3 and 1 <= lik <= 3
            risk = get("risk")
            want = f"{band(imp * lik)} ({imp * lik})"
            if risk != want:
                problems.append(f"line {n}: {tid} risk '{risk}' != '{want}'")
        except (ValueError, AssertionError):
            problems.append(f"line {n}: {tid} impact/likelihood must be integers 1-3")
        st = get("status").lower()
        if st not in STATUSES:
            problems.append(f"line {n}: {tid} status '{st}' not in {sorted(STATUSES)}")
        if st == "accepted" and not re.search(r"owner|accepted by", get("why"), re.I):
            problems.append(f"line {n}: {tid} accepted risk needs an owner in 'why'")
    if threats == 0:
        problems.append("no threats found in table")
    for p in problems:
        print("FAIL", p)
    print(f"{threats} threats, {nblocks} diagram(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: tmlint.py <threat-model.md>")
    sys.exit(main(sys.argv[1]))
```
