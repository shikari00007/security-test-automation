"""AI/LLM rule tests (SEC-AI-001..003): metadata, fixtures, and heuristic regressions.
Adversarial accuracy cases live in fixtures/accuracy/ai-llm/cases.json (run by test_rule_accuracy.py)."""
import json
import tempfile
import unittest
from pathlib import Path

from security_runner.adapters import RULES, ScanContext, load_all

ROOT = Path(__file__).resolve().parents[1]
CHECKS = json.loads((ROOT / "security_runner" / "data" / "checks" / "ai-llm.json").read_text())["checks"]
FIX = ROOT / "fixtures" / "ai-llm-app"
load_all()


def ctx_for(root: Path) -> ScanContext:
    files = [p.relative_to(root).as_posix() for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()]
    return ScanContext(root, files)


def run(rid, files):
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        for rel, txt in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(txt)
        return RULES[rid](ctx_for(d))


HDR = "from openai import OpenAI\nclient = OpenAI()\n"


class AiMetadataTests(unittest.TestCase):
    def test_all_ai_checks_experimental_or_unimplemented(self):
        for c in CHECKS:
            if c["mode"] == "static":
                self.assertEqual(c["maturity"], "experimental", c["id"])
            else:
                self.assertEqual(c["maturity"], "unimplemented", c["id"])
        self.assertTrue({"SEC-AI-050", "SEC-AI-051"} <= {c["id"] for c in CHECKS})

    def test_methodology_doc_is_marked_draft(self):
        doc = (ROOT / "docs" / "methodology" / "ai-llm.md").read_text()
        self.assertIn("Status: REVIEWED WITH CHANGES - experimental", doc)
        for cid in ("SEC-AI-001", "SEC-AI-002", "SEC-AI-003", "SEC-AI-004", "SEC-AI-050", "SEC-AI-051"):
            self.assertIn(cid, doc)


class AiFixtureTests(unittest.TestCase):
    def test_fixture_lines_and_secure_clean(self):
        exp = json.loads((FIX / "expected.json").read_text())
        v, s = ctx_for(FIX / "vulnerable"), ctx_for(FIX / "secure")
        for rid, locs in exp["vulnerable"].items():
            res = RULES[rid](v)
            self.assertEqual(sorted({(o.file, o.line) for o in res.observations}), sorted(map(tuple, locs)), rid)
        for rid in exp["secure_clean"]:
            res = RULES[rid](s)
            self.assertTrue(res is None or not res.observations, rid)

    def test_not_applicable_without_relevant_files(self):
        for rid in ("SEC-AI-001", "SEC-AI-002", "SEC-AI-003", "SEC-AI-004"):
            self.assertIsNone(run(rid, {"readme.txt": "x"}), rid)


class AiHeuristicTests(unittest.TestCase):
    def test_line_numbers_not_shifted_by_comments_and_blank_lines(self):
        src = HDR + "\n\n# c\n\nimport os\ndef f():\n    r = client.chat.completions.create(model='m')\n    os.system(r.choices[0].message.content)\n"
        res = run("SEC-AI-001", {"a.py": src})
        want = src.splitlines().index("    os.system(r.choices[0].message.content)") + 1
        self.assertEqual([o.line for o in res.observations], [want])

    def test_list_wrapped_argument_is_not_treated_as_index_lookup(self):
        src = HDR + "import subprocess\ndef f():\n    c = client.chat.completions.create(model='m').choices[0].message.content\n    subprocess.run([c])\n"
        self.assertEqual(len(run("SEC-AI-001", {"a.py": src}).observations), 1)

    def test_taint_does_not_leak_across_functions(self):
        src = HDR + "import os\ndef a():\n    t = client.chat.completions.create(model='m')\n    return t\ndef b(t):\n    os.system(t)\n"
        self.assertEqual(run("SEC-AI-001", {"a.py": src}).observations, [])

    def test_mcp_literal_secret_requires_secretlike_key_and_value(self):
        cfg = {"mcpServers": {"s": {"command": "node", "args": ["a.js"], "env": {"SSH_KEY": "/home/u/.ssh/id", "AUTH_MODE": "basic-auth", "MY_TOKEN": "${T}"}}}}
        self.assertEqual(run("SEC-AI-002", {".mcp.json": json.dumps(cfg, indent=1)}).observations, [])

    def test_mcp_findings_never_echo_secret_values(self):
        cfg = {"mcpServers": {"s": {"command": "node", "args": [], "env": {"API_KEY": "sk-EXAMPLEEXAMPLEEXAMPLE"}}}}
        res = run("SEC-AI-002", {".mcp.json": json.dumps(cfg, indent=1)})
        self.assertEqual(len(res.observations), 1)
        self.assertNotIn("sk-", res.observations[0].detail)

    def test_shell_tool_with_approval_or_sandbox_is_quiet_but_unguarded_is_flagged(self):
        bad = "from langchain.agents import initialize_agent\nt = ShellTool()\n"
        self.assertEqual(len(run("SEC-AI-003", {"a.py": bad}).observations), 1)
        self.assertEqual(run("SEC-AI-003", {"a.py": bad + "x = ShellTool(needs_approval=True)\n"}).observations, [])
        self.assertEqual(run("SEC-AI-003", {"a.py": bad + "# sandbox = docker\nsandbox=True\n"}).observations, [])

    def test_mcp_ranges_and_dist_tags_are_not_pins(self):
        for pkg in ("p@^1.2.0", "p@~1.2", "p@>=1", "p@*", "p@next", "p@latest", "p@1", "p"):
            cfg = {"mcpServers": {"s": {"command": "npx", "args": ["-y", pkg]}}}
            self.assertEqual(len(run("SEC-AI-002", {".mcp.json": json.dumps(cfg, indent=1)}).observations), 1, pkg)
        for pkg in ("p@1.2.3", "@s/p@1.2.3", "p@" + "a" * 40):
            cfg = {"mcpServers": {"s": {"command": "npx", "args": ["-y", pkg]}}}
            self.assertEqual(run("SEC-AI-002", {".mcp.json": json.dumps(cfg, indent=1)}).observations, [], pkg)

    def test_sql_quoted_fstring_placeholder_flagged(self):
        src = HDR + "def f(cur):\n    n = client.chat.completions.create(model='m').choices[0].message.content\n    cur.execute(f\"SELECT 1 WHERE a = '{n}'\")\n"
        self.assertEqual(len(run("SEC-AI-001", {"a.py": src}).observations), 1)

    def test_testing_directory_is_not_skipped(self):
        src = HDR + "import os\ndef f():\n    o = client.chat.completions.create(model='m').choices[0].message.content\n    os.system(o)\n"
        self.assertEqual(len(run("SEC-AI-001", {"src/testing/a.py": src}).observations), 1)

    def test_check_confidence_low_for_heuristic_rules(self):
        by = {c["id"]: c for c in CHECKS}
        for cid in ("SEC-AI-001", "SEC-AI-003", "SEC-AI-004"):
            self.assertEqual(by[cid]["confidence"], "low", cid)
        self.assertIn("CWE-1426", by["SEC-AI-001"]["standards"]["cwe"])
        self.assertNotIn("CWE-732", by["SEC-AI-002"]["standards"]["cwe"])

    def test_test_files_are_skipped(self):
        res = run("SEC-AI-003", {"tests/test_a.py": "from langchain import x\nt = ShellTool()\n", "a.py": "from langchain import x\n"})
        self.assertEqual(res.observations, [])


if __name__ == "__main__":
    unittest.main()
