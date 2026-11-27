"""Harness logic tested against a fake `claude` binary (no API calls)."""
import importlib.util
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("skill_evals", ROOT / "scripts" / "skill_evals.py")
se = importlib.util.module_from_spec(spec)
sys.modules["skill_evals"] = se
spec.loader.exec_module(se)


def stream(skill):
    ev = [{"type": "system"}]
    if skill:
        ev.append({"type": "assistant", "message": {"content": [{"type": "text", "text": "ok"}, {"type": "tool_use", "name": "Skill", "input": {"skill": skill}}]}})
    else:
        ev.append({"type": "assistant", "message": {"content": [{"type": "text", "text": "just answering"}]}})
    ev.append({"type": "result", "total_cost_usd": 0.05})
    return "\n".join(json.dumps(e) for e in ev)


def test_first_skill_parsing():
    assert se.first_skill(stream("security-start")) == ("security-start", 0.05)
    assert se.first_skill(stream(None)) == (None, 0.05)
    assert se.first_skill(stream("plugin:security-do"))[0] == "security-do"
    assert se.first_skill("garbage\n{not json")[0] is None


def test_scoring():
    rs = [{"target": "a", "kind": "trigger", "skill": "a", "error": None}, {"target": "a", "kind": "trigger", "skill": "b", "error": None},
          {"target": "a", "kind": "negative", "skill": "a", "error": None, "better": "b"}, {"target": "a", "kind": "negative", "skill": "b", "error": None, "better": "b"},
          {"target": "a", "kind": "trigger", "skill": None, "error": "timeout"}]
    p = se.score(rs)["per_skill"]["a"]
    assert (p["trigger_hit"], p["trigger_n"], p["neg_ok"], p["neg_n"], p["better_hit"], p["errors"]) == (1, 2, 1, 2, 1, 1)


def make_skill_tree(tmp, names):
    for n in names:
        (tmp / "skills" / n).mkdir(parents=True)
        (tmp / "skills" / n / "SKILL.md").write_text(f"---\nname: {n}\ndescription: x\n---\n")


def good_eval(name, other):
    return {"skill": name, "route": {"should_trigger": [f"please do thing number {i} now" for i in range(8)],
                                     "should_not_trigger": [{"prompt": f"unrelated {i}", "better_skill": other} for i in range(8)]},
            "scenarios": [{"id": str(i), "task": "t", "setup": "s", "rubric": ["a", "b", "c"]} for i in range(3)]}


def test_validate_catches_problems(tmp_path):
    make_skill_tree(tmp_path, ["alpha", "beta"])
    ev = tmp_path / "evals"
    ev.mkdir()
    (ev / "alpha.json").write_text(json.dumps(good_eval("alpha", "beta")))
    assert se.validate(tmp_path / "skills", ev) == []
    assert se.validate(tmp_path / "skills", ev, strict_better=False) == []
    bad = good_eval("alpha", "Not A Kebab Name")
    bad["route"]["should_trigger"] = bad["route"]["should_trigger"][:3]
    bad["scenarios"] = bad["scenarios"][:1]
    (ev / "alpha.json").write_text(json.dumps(bad))
    errs = " ".join(se.validate(tmp_path / "skills", ev))
    assert "should_trigger" in errs and "better_skill" in errs and "scenarios" in errs
    ext = good_eval("alpha", "some-external-skill")
    (ev / "alpha.json").write_text(json.dumps(ext))
    assert se.validate(tmp_path / "skills", ev) == []                           # external neighbours are allowed
    assert any("not a skill in this suite" in e for e in se.validate(tmp_path / "skills", ev, strict_better=True))
    (ev / "ghost.json").write_text(json.dumps(good_eval("ghost", "alpha")))
    assert any("existing skill directory" in e for e in se.validate(tmp_path / "skills", ev))


def fake_claude(tmp, mapping):
    """A stand-in CLI: picks a skill by keyword in the prompt, like a (perfectly routed) model."""
    script = tmp / "fakeclaude"
    script.write_text("#!/usr/bin/env python3\nimport sys,json\nprompt=sys.argv[sys.argv.index('-p')+1]\n"
                      f"m={json.dumps(mapping)}\nskill=None\nfor k,v in m.items():\n    if k in prompt: skill=v\n"
                      "ev=[{'type':'system'}]\nif skill: ev.append({'type':'assistant','message':{'content':[{'type':'tool_use','name':'Skill','input':{'skill':skill}}]}})\n"
                      "else: ev.append({'type':'assistant','message':{'content':[{'type':'text','text':'hi'}]}})\n"
                      "ev.append({'type':'result','total_cost_usd':0.01})\nprint('\\n'.join(json.dumps(e) for e in ev))\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_routing_end_to_end_with_fake_claude(tmp_path, capsys):
    make_skill_tree(tmp_path, ["alpha", "beta"])
    ev = tmp_path / "evals"
    ev.mkdir()
    (ev / "alpha.json").write_text(json.dumps(good_eval("alpha", "beta")))
    fake = fake_claude(tmp_path, {"thing number": "alpha", "unrelated": "beta"})
    out = tmp_path / "out.json"
    rc = se.main(["routing", "--skills", str(tmp_path / "skills"), "--evals", str(ev), "--claude", fake, "--out", str(out), "--concurrency", "2"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["cost_usd"] > 0 and len(data["results"]) == 16
    p = data["summary"]["per_skill"]["alpha"]
    assert p["trigger_hit"] == 8 and p["neg_ok"] == 8 and p["better_hit"] == 8
    assert "ALL" in capsys.readouterr().out


def test_plan_mode_not_default_and_flags_passed(tmp_path):
    """Regression: plan mode suppressed skill use in measurement; default must omit --permission-mode."""
    rec = tmp_path / "args.json"
    script = tmp_path / "recclaude"
    script.write_text("#!/usr/bin/env python3\nimport sys,json\nopen(%r,'w').write(json.dumps(sys.argv[1:]))\nprint('{}')\n" % str(rec))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    se.run_prompt(str(script), tmp_path, "hello there friend", "isolated")
    a = json.loads(rec.read_text())
    assert "--permission-mode" not in a and "--max-turns" in a and a[a.index("--max-turns") + 1] == "2" and "--setting-sources" in a
    se.run_prompt(str(script), tmp_path, "hello there friend", "realistic", permission_mode="plan")
    a = json.loads(rec.read_text())
    assert a[a.index("--permission-mode") + 1] == "plan" and "--setting-sources" not in a


def test_routing_refuses_over_budget(tmp_path):
    make_skill_tree(tmp_path, ["alpha", "beta"])
    ev = tmp_path / "evals"
    ev.mkdir()
    (ev / "alpha.json").write_text(json.dumps(good_eval("alpha", "beta")))
    assert se.main(["routing", "--skills", str(tmp_path / "skills"), "--evals", str(ev), "--max-calls", "5", "--claude", "/bin/false"]) == 2


def _skill(tmp, name, desc, body="body\n", fm_name=None):
    d = tmp / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f'---\nname: {fm_name or name}\ndescription: {json.dumps(desc)}\n---\n{body}')


GOOD = "Does a thing. Use when: \"x\". Not for: y - use z."


def test_validate_fails_on_long_unescaped_description(tmp_path):
    _skill(tmp_path, "alpha", "x" * 1025)
    _skill(tmp_path, "beta", 'q"' * 500 + " Use when. Not for.")      # 1000+ chars, escaped form is longer than 1024
    errs = se.check_description_limits(tmp_path / "skills")
    assert any("alpha" in e and "1025" in e for e in errs)
    assert not any("beta" in e for e in errs)                          # judged after unescape, not on raw YAML length
    ev = tmp_path / "evals"
    ev.mkdir()
    assert se.main(["validate", "--skills", str(tmp_path / "skills"), "--evals", str(ev), "--lint-baseline", str(tmp_path / "b.json")]) == 1


def test_lint_rules_and_baseline_shrink_only(tmp_path):
    _skill(tmp_path, "good", GOOD)
    _skill(tmp_path, "bad", "No trigger words here")
    _skill(tmp_path, "mismatch", GOOD, fm_name="other")
    _skill(tmp_path, "long", GOOD, body="l\n" * 200)
    sk = tmp_path / "skills"
    fails = set(se.lint_skills(sk))
    assert {"bad: description-no-use-when", "bad: description-no-not-for", "bad: description-no-end-punctuation",
            "mismatch: name-not-dir", "long: body-too-long"} <= fails
    assert not any(f.startswith("good:") for f in fails)
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"failures": sorted(fails)}))
    assert se.lint_check(sk, base) == []                               # all pre-existing -> pass
    base.write_text(json.dumps({"failures": sorted(fails - {"long: body-too-long"})}))
    assert se.lint_check(sk, base) == ["lint: long: body-too-long"]    # new failure fails
    base.write_text(json.dumps({"failures": sorted(fails | {"good: name-not-dir"})}))
    assert se.lint_check(sk, base) == ["lint baseline is stale, remove: good: name-not-dir"]   # baseline cannot keep fixed items


def test_repo_lint_and_limits_clean():
    assert se.check_description_limits(ROOT / "skills") == []
    assert se.lint_check(ROOT / "skills", ROOT / "evals" / "lint-baseline.json") == []


cspec = importlib.util.spec_from_file_location("skill_collisions", ROOT / "scripts" / "skill_collisions.py")
sc = importlib.util.module_from_spec(cspec)
sys.modules["skill_collisions"] = sc
cspec.loader.exec_module(sc)


def test_collisions_threshold_allowlist_and_exit_codes(tmp_path):
    _skill(tmp_path, "scan-web-apps", "Scan web applications for XSS and CSRF problems in browser forms.")
    _skill(tmp_path, "scan-web-sites", "Scan web applications for XSS and CSRF problems in browser pages.")
    _skill(tmp_path, "rotate-keys", "Rotate encryption keys in the vault on a schedule with audit logs.")
    sk, al = tmp_path / "skills", tmp_path / "allow.json"
    code, rep = sc.run(sk, 0.45, al, 0)
    assert [r["pair"] for r in rep["pairs"]] == [["scan-web-apps", "scan-web-sites"]] and code == 1
    assert sc.run(sk, 0.45, al, None)[0] == 0                           # no limit -> report only
    assert sc.run(sk, 0.999, al, 0)[0] == 0
    al.write_text(json.dumps({"allowed": [{"pair": ["scan-web-sites", "scan-web-apps"], "reason": "intentional siblings"}]}))
    code, rep = sc.run(sk, 0.45, al, 0)
    assert code == 0 and rep["unreviewed"] == 0 and rep["pairs"][0]["reviewed"]
    al.write_text(json.dumps({"allowed": [{"pair": ["a", "b"]}]}))
    import pytest
    with pytest.raises(ValueError):
        sc.load_allowlist(al)
    assert sc.main(["--skills", str(sk), "--allowlist", str(al)]) == 2


def test_collisions_repo_default_threshold_has_no_unreviewed():
    code, rep = sc.run(ROOT / "skills", 0.45, ROOT / "evals" / "collision-allowlist.json", 0)
    assert code == 0, rep["pairs"]
