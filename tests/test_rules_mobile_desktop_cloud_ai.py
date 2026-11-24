"""Rule/fixture/metadata tests for android, ios, desktop, cloud-kubernetes and ai-llm."""
import json
import tempfile
import unittest
from pathlib import Path

from security_runner.adapters import RULES, ScanContext, load_all

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CHECKS = ROOT / "security_runner" / "data" / "checks"
SCHEMA = json.loads((ROOT / "security_runner" / "data" / "schemas" / "check.schema.json").read_text())
FILES = {"android": "android.json", "ios": "ios.json", "desktop": "desktop.json",
         "cloud-kubernetes": "cloud-kubernetes.json", "ai-llm": "ai-llm.json"}
PREFIXES = ("SEC-AND-", "SEC-IOS-", "SEC-DSK-", "SEC-K8S-", "SEC-AI-")
FIXTURE_NAMES = ["android-app", "ios-app", "electron-app", "cloud-k8s", "ai-llm-app"]

load_all()


def build_ctx(root: Path) -> ScanContext:
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        files.append(p.relative_to(root).as_posix())
    return ScanContext(root, files)


def all_checks():
    out = []
    for domain, fn in FILES.items():
        data = json.loads((CHECKS / fn).read_text())
        assert data["schema_version"] == "1.0"
        for c in data["checks"]:
            assert c["domain"] == domain
            out.append(c)
    return out


class MetadataTests(unittest.TestCase):
    def test_schema_validity(self):
        try:
            import jsonschema
        except ImportError:
            jsonschema = None
        for c in all_checks():
            if jsonschema:
                jsonschema.validate(c, SCHEMA)
            else:
                for k in SCHEMA["required"]:
                    self.assertIn(k, c)

    def test_rule_metadata_parity(self):
        static = {c["id"] for c in all_checks() if c["mode"] == "static" and c["executor"] == "builtin"}
        registered = {r for r in RULES if r.startswith(PREFIXES)}
        self.assertEqual(static, registered)

    def test_expected_ids_and_planned_only(self):
        ids = {c["id"] for c in all_checks()}
        for must in ("SEC-AND-050", "SEC-AND-051", "SEC-IOS-050", "SEC-IOS-051", "SEC-DSK-050",
                     "SEC-DSK-051", "SEC-K8S-050", "SEC-AI-050", "SEC-AI-051"):
            self.assertIn(must, ids)
        for c in all_checks():
            if c["mode"] != "static":
                self.assertEqual(c["profiles"], ["deep"])
                self.assertEqual(c["executor"], "none")
            elif c["confidence"] == "high":
                self.assertEqual(c["profiles"], ["quick", "standard", "deep"])


class FixtureTests(unittest.TestCase):
    def test_vulnerable_exact_lines_and_secure_clean(self):
        for name in FIXTURE_NAMES:
            exp = json.loads((FIXTURES / name / "expected.json").read_text())
            vctx = build_ctx(FIXTURES / name / "vulnerable")
            sctx = build_ctx(FIXTURES / name / "secure")
            for rid, locs in exp["vulnerable"].items():
                if not rid.startswith(PREFIXES):
                    continue  # other workstreams may add their own entries to shared fixtures
                res = RULES[rid](vctx)
                self.assertIsNotNone(res, rid)
                self.assertFalse(res.inconclusive, rid)
                got = sorted({(o.file, o.line) for o in res.observations})
                self.assertEqual(got, sorted(tuple(x) for x in locs), f"{name} {rid}")
                for o in res.observations:
                    self.assertNotIn("Sup3rSecret", o.detail)
                    self.assertNotIn("ghp_", o.detail)
            for rid in [r for r in exp["secure_clean"] if r.startswith(PREFIXES)]:
                res = RULES[rid](sctx)
                self.assertTrue(res is None or not res.observations, f"{name} secure {rid}: {res}")
            # reads are recorded for passes
            
    def test_not_applicable_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "readme.txt").write_text("nothing relevant")
            ctx = build_ctx(Path(tmp))
            for rid in RULES:
                if rid.startswith(PREFIXES):
                    self.assertIsNone(RULES[rid](ctx), rid)

    def test_every_static_rule_covered_by_vulnerable_fixture(self):
        covered = set()
        for name in FIXTURE_NAMES:
            covered |= {r for r in json.loads((FIXTURES / name / "expected.json").read_text())["vulnerable"]
                        if r.startswith(PREFIXES)}
        self.assertEqual(covered, {r for r in RULES if r.startswith(PREFIXES)})


class XxeTests(unittest.TestCase):
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="&xxe;"/></manifest>',
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        '<manifest><application/></manifest>',
        "<manifest><application",  # malformed
    ]

    def test_doctype_entity_refused_not_crash(self):
        for payload in self.PAYLOADS:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                (d / "AndroidManifest.xml").write_text(payload)
                ctx = build_ctx(d)
                for rid in ("SEC-AND-001", "SEC-AND-002", "SEC-AND-003", "SEC-AND-004"):
                    res = RULES[rid](ctx)
                    self.assertIsNotNone(res)
                    self.assertTrue(res.inconclusive, rid)
                    self.assertEqual(res.observations, [])


class HeuristicTests(unittest.TestCase):
    def run_rule(self, rid, files):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for rel, content in files.items():
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                (d / rel).write_text(content)
            return RULES[rid](build_ctx(d))

    def test_k8s_secret_without_data_not_flagged(self):
        res = self.run_rule("SEC-K8S-005", {"s.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\ntype: Opaque\n"})
        self.assertEqual(res.observations, [])

    def test_ai_sql_parameterised_not_flagged(self):
        src = ("from openai import OpenAI\nc = OpenAI()\n"
               "def f(db):\n    r = c.chat.completions.create(model='m')\n    t = r.choices[0].message.content\n"
               "    return db.execute('SELECT 1 WHERE a = ?', (t,))\n")
        self.assertEqual(self.run_rule("SEC-AI-001", {"a.py": src}).observations, [])

    def test_symlink_not_scanned(self):
        # fixtures walk skips symlinks; build_ctx must never list one
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "real.txt").write_text("x")
            (d / "AndroidManifest.xml").symlink_to(d / "real.txt")
            self.assertEqual(build_ctx(d).files, ["real.txt"])


class StripperLinePreservation(unittest.TestCase):
    """Every comment/string stripper must keep the line count so reported line numbers stay exact."""

    SAMPLES = ("a=1\n\n\n# c\nb=2\n  # indented\n\nx\n",
               "x\n/* multi\nline\n*/\n// c\ny = 'http://z' // t\n\n\nz\n",
               "<a>\n<!-- c\n\n -->\n<b/>\n\n</a>\n",
               'f("s")\n\n\n"unterminated\n\nq\n')

    def test_line_counts_preserved(self):
        from security_runner.adapters.android import blank_strings, strip_c, strip_hash, strip_xml_comments
        for fn in (strip_c, strip_hash, strip_xml_comments, blank_strings):
            for text in self.SAMPLES:
                self.assertEqual(len(fn(text).splitlines()), len(text.splitlines()), (fn.__name__, text))
                self.assertEqual(fn(text).count("\n"), text.count("\n"), (fn.__name__, text))


if __name__ == "__main__":
    unittest.main()
