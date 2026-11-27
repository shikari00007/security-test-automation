#!/usr/bin/env python3
"""Skill evals for the security skill suite.

  python scripts/skill_evals.py validate [--skills skills] [--evals evals/skills]
  (validate also enforces description <= 1024 chars after YAML unescape and the description lint with the shrink-only
   baseline evals/lint-baseline.json; see lint_skills)
  python scripts/skill_evals.py routing  [--skills skills] [--evals evals/skills] [--only NAME ...]
        [--mode isolated|realistic] [--max-calls N] [--concurrency N] [--claude claude] [--out FILE]

`routing` runs REAL headless Claude Code sessions (`claude -p`, billed to the logged-in account) in a throwaway project
containing the skills and records which Skill the model invokes FIRST. should_trigger prompts must invoke the target
skill; should_not_trigger prompts must not. `isolated` ignores user-level settings/skills (`--setting-sources project`);
`realistic` keeps the developer's whole environment, so our skills compete with everything else installed.
Results are written as JSON; nothing is modified in the repository.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MIN_ROUTE, MIN_SCEN = 8, 3
BUILTIN_OK = {"code-review", "security-review", "simplify", "init", "run", "loop", "claude-api"}   # allowed as better_skill


def load_evals(evals_dir: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(evals_dir.glob("[!_]*.json"))]


import re

KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def validate(skills_dir: Path, evals_dir: Path, strict_better: bool = False) -> list[str]:
    """better_skill may name a skill outside this suite (a real neighbour in a developer environment); strict_better enforces suite-only."""
    errs, names = [], {p.name for p in skills_dir.iterdir() if p.is_dir()}
    seen = set()
    for p in sorted(evals_dir.glob("[!_]*.json")):
        try:
            e = json.loads(p.read_text())
        except ValueError as ex:
            errs.append(f"{p.name}: invalid JSON ({ex})")
            continue
        sk = e.get("skill")
        if sk != p.stem or sk not in names:
            errs.append(f"{p.name}: skill {sk!r} must equal the file stem and an existing skill directory")
        seen.add(sk)
        r = e.get("route", {})
        pos, neg = r.get("should_trigger", []), r.get("should_not_trigger", [])
        if len(pos) < MIN_ROUTE or not all(isinstance(x, str) and len(x.split()) >= 3 for x in pos):
            errs.append(f"{p.name}: need >= {MIN_ROUTE} should_trigger prompts of >= 3 words")
        if len(neg) < MIN_ROUTE:
            errs.append(f"{p.name}: need >= {MIN_ROUTE} should_not_trigger items")
        for n in neg:
            if not isinstance(n, dict) or not n.get("prompt"):
                errs.append(f"{p.name}: should_not_trigger items need a prompt")
                continue
            b = n.get("better_skill")
            if b is not None and not (isinstance(b, str) and KEBAB.match(b)):
                errs.append(f"{p.name}: better_skill {b!r} must be a kebab-case skill name or null")
            elif b is not None and strict_better and b not in names and b not in BUILTIN_OK:
                errs.append(f"{p.name}: better_skill {b!r} is not a skill in this suite")
        if len(set(pos)) != len(pos):
            errs.append(f"{p.name}: duplicate should_trigger prompts")
        sc = e.get("scenarios", [])
        if len(sc) < MIN_SCEN or not all(s.get("task") and len(s.get("rubric", [])) >= 3 for s in sc):
            errs.append(f"{p.name}: need >= {MIN_SCEN} scenarios, each with a task and >= 3 rubric items")
    return errs


MAX_DESC = 1024
MAX_BODY_LINES = 200


def _parse(skill_md: Path):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from security_runner.skillcheck import parse_frontmatter
    return parse_frontmatter(skill_md.read_text(encoding="utf-8"))


def check_description_limits(skills_dir: Path) -> list[str]:
    """Hard errors: every skills/*/SKILL.md must parse and its (unescaped) description must be 1..1024 chars."""
    errs = []
    for d in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        try:
            fm, _ = _parse(f)
        except ValueError as ex:
            errs.append(f"{d.name}: {ex}")
            continue
        desc = fm.get("description", "")
        if not isinstance(desc, str) or not desc:
            errs.append(f"{d.name}: description missing")
        elif len(desc) > MAX_DESC:
            errs.append(f"{d.name}: description is {len(desc)} chars (limit {MAX_DESC})")
    return errs


def lint_skills(skills_dir: Path) -> list[str]:
    """Stable 'slug: rule' failure keys for the description lint (compared with the baseline by lint_check)."""
    out = []
    for d in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        try:
            fm, body = _parse(f)
        except ValueError:
            out.append(f"{d.name}: frontmatter-unparseable")
            continue
        desc = fm.get("description", "")
        desc = desc if isinstance(desc, str) else ""
        if fm.get("name") != d.name:
            out.append(f"{d.name}: name-not-dir")
        if not desc.rstrip().endswith((".", "!", "?", ")", '"', "'")):
            out.append(f"{d.name}: description-no-end-punctuation")
        if "Use when" not in desc:
            out.append(f"{d.name}: description-no-use-when")
        if "Not for" not in desc:
            out.append(f"{d.name}: description-no-not-for")
        if len(body.splitlines()) >= MAX_BODY_LINES:
            out.append(f"{d.name}: body-too-long")
    return out


def lint_check(skills_dir: Path, baseline_file: Path) -> list[str]:
    """New lint failures fail; baseline entries that no longer fail must be removed (the baseline can only shrink)."""
    base = set()
    if baseline_file.is_file():
        base = set(json.loads(baseline_file.read_text()).get("failures", []))
    cur = set(lint_skills(skills_dir))
    errs = [f"lint: {x}" for x in sorted(cur - base)]
    errs += [f"lint baseline is stale, remove: {x}" for x in sorted(base - cur)]
    return errs


NEUTRAL_FILES = {"app.py": "from flask import Flask, request\napp = Flask(__name__)\n\n@app.get('/items')\ndef items():\n    return {'items': []}\n",
                 "README.md": "# Demo service\nA small web API.\n", "requirements.txt": "flask==3.0.0\n"}


def make_project(skills_dir: Path) -> Path:
    root = Path(tempfile.mkdtemp(prefix="skill-eval-"))
    shutil.copytree(skills_dir, root / ".claude" / "skills")
    for n, t in NEUTRAL_FILES.items():
        (root / n).write_text(t)
    return root


def first_skill(stream_text: str) -> tuple[str | None, float]:
    """(first Skill invoked by the assistant or None, total_cost_usd) from `--output-format stream-json` output."""
    skill, cost = None, 0.0
    for line in stream_text.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "assistant" and skill is None:
            for c in e.get("message", {}).get("content", []):
                if c.get("type") == "tool_use" and c.get("name") == "Skill":
                    s = (c.get("input") or {}).get("skill")
                    skill = s.split(":")[-1] if isinstance(s, str) else None
                    break
        if e.get("type") == "result":
            cost = float(e.get("total_cost_usd") or 0)
    return skill, cost


def run_prompt(claude: str, project: Path, prompt: str, mode: str, timeout: int = 150, max_turns: int = 2, permission_mode: str = "default") -> dict:
    """NOTE: `--permission-mode plan` suppresses Skill use (measured: 1/6 vs 3/6 with default permissions), so it is NOT the default.
    Tools the model tries beyond Skill are denied in headless mode; the project is a throwaway temp directory."""
    cmd = [claude, "-p", prompt, "--output-format", "stream-json", "--verbose", "--max-turns", str(max_turns)]
    if permission_mode != "default":
        cmd += ["--permission-mode", permission_mode]
    if mode == "isolated":
        cmd += ["--setting-sources", "project"]
    try:
        r = subprocess.run(cmd, cwd=project, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        skill, cost = first_skill(r.stdout)
        return {"skill": skill, "cost": cost, "error": None if r.stdout.strip() else (r.stderr.strip()[:200] or "no output")}
    except subprocess.TimeoutExpired:
        return {"skill": None, "cost": 0.0, "error": "timeout"}


def score(results: list[dict]) -> dict:
    per = collections.defaultdict(lambda: {"trigger_hit": 0, "trigger_n": 0, "neg_ok": 0, "neg_n": 0, "better_hit": 0, "better_n": 0, "errors": 0})
    wrong = collections.defaultdict(collections.Counter)
    for r in results:
        p = per[r["target"]]
        if r["error"]:
            p["errors"] += 1
            continue
        if r["kind"] == "trigger":
            p["trigger_n"] += 1
            p["trigger_hit"] += r["skill"] == r["target"]
            if r["skill"] != r["target"]:
                wrong[r["target"]][r["skill"] or "(none)"] += 1
        else:
            p["neg_n"] += 1
            p["neg_ok"] += r["skill"] != r["target"]
            if r.get("better"):
                p["better_n"] += 1
                p["better_hit"] += r["skill"] == r["better"]
    return {"per_skill": per, "wrong_picks": {k: dict(v) for k, v in wrong.items()}}


def routing(a) -> int:
    skills_dir, evals_dir = Path(a.skills), Path(a.evals)
    errs = validate(skills_dir, evals_dir)
    if errs:
        print("eval files invalid:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 2
    import random
    rnd = random.Random(a.seed)
    jobs = []
    for e in load_evals(evals_dir):
        if a.only and e["skill"] not in a.only:
            continue
        pos = list(e["route"]["should_trigger"])
        neg = list(e["route"]["should_not_trigger"])
        if a.sample:                       # deterministic per-skill subsample to bound cost
            rnd.shuffle(pos)
            rnd.shuffle(neg)
            pos, neg = pos[:a.sample], neg[:a.sample]
        for p in pos:
            jobs.append({"target": e["skill"], "kind": "trigger", "prompt": p})
        for n in neg:
            jobs.append({"target": e["skill"], "kind": "negative", "prompt": n["prompt"], "better": n.get("better_skill")})
    if len(jobs) > a.max_calls:
        print(f"refusing: {len(jobs)} prompts exceed --max-calls {a.max_calls} (each is a billed Claude Code call)", file=sys.stderr)
        return 2
    project = make_project(skills_dir)
    try:
        with cf.ThreadPoolExecutor(max_workers=a.concurrency) as ex:
            outs = list(ex.map(lambda j: {**j, **run_prompt(a.claude, project, j["prompt"], a.mode, max_turns=a.max_turns, permission_mode=a.permission_mode)}, jobs))
    finally:
        shutil.rmtree(project, ignore_errors=True)
    s = score(outs)
    total_cost = sum(o["cost"] for o in outs)
    print(f"mode={a.mode} prompts={len(outs)} cost=${total_cost:.2f}")
    T = [0, 0, 0, 0]
    for sk, p in sorted(s["per_skill"].items()):
        T[0] += p["trigger_hit"]; T[1] += p["trigger_n"]; T[2] += p["neg_ok"]; T[3] += p["neg_n"]
        print(f"  {sk:34} trigger {p['trigger_hit']}/{p['trigger_n']}  not-trigger {p['neg_ok']}/{p['neg_n']}  errors {p['errors']}")
    print(f"  {'ALL':34} trigger {T[0]}/{T[1]} = {T[0]/max(T[1],1):.0%}  not-trigger {T[2]}/{T[3]} = {T[2]/max(T[3],1):.0%}")
    if a.out:
        Path(a.out).write_text(json.dumps({"mode": a.mode, "cost_usd": total_cost, "summary": s, "results": outs}, indent=1, default=dict))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    v = sp.add_parser("validate"); v.add_argument("--skills", default="skills"); v.add_argument("--evals", default="evals/skills")
    v.add_argument("--strict-better", action="store_true", help="require better_skill to name a skill of this suite")
    v.add_argument("--lint-baseline", default="evals/lint-baseline.json", help="shrink-only list of pre-existing lint failures")
    r = sp.add_parser("routing"); r.add_argument("--skills", default="skills"); r.add_argument("--evals", default="evals/skills")
    r.add_argument("--only", nargs="*"); r.add_argument("--mode", choices=["isolated", "realistic"], default="isolated")
    r.add_argument("--max-calls", type=int, default=120); r.add_argument("--concurrency", type=int, default=3)
    r.add_argument("--claude", default="claude"); r.add_argument("--out")
    r.add_argument("--max-turns", type=int, default=2); r.add_argument("--permission-mode", default="default", choices=["default", "acceptEdits", "plan"])
    r.add_argument("--sample", type=int, default=0, help="N positives and N negatives per skill (seeded)"); r.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    if a.cmd == "validate":
        errs = validate(Path(a.skills), Path(a.evals), a.strict_better)
        errs += check_description_limits(Path(a.skills))
        errs += lint_check(Path(a.skills), Path(a.lint_baseline))
        print("\n".join(errs) if errs else f"eval files valid ({len(list(Path(a.evals).glob('[!_]*.json')))} skills)")
        return 1 if errs else 0
    return routing(a)


if __name__ == "__main__":
    sys.exit(main())
