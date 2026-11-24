import json
import tempfile
import unittest
from pathlib import Path

from security_runner import adapters
from security_runner.adapters.base import RULES, ScanContext

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
CHECKS = ROOT / "security_runner" / "data" / "checks"
SCHEMA = ROOT / "security_runner" / "data" / "schemas" / "check.schema.json"
FIXTURES = {"web-app": "SEC-WEB", "api-spec": "SEC-API", "supply-chain": "SEC-SC"}
DOMAIN_FILES = ["web.json", "api.json", "supply-chain.json"]
PREFIXES = tuple(FIXTURES.values())

adapters.load_all()


def make_ctx(root: Path) -> ScanContext:
    root = root.resolve()
    files = [p.relative_to(root).as_posix() for p in root.rglob("*")
             if p.is_file() and not p.is_symlink()]
    return ScanContext(root, files)


def load_checks():
    out = []
    for name in DOMAIN_FILES:
        out += json.loads((CHECKS / name).read_text())["checks"]
    return out


class FixtureTests(unittest.TestCase):
    def test_vulnerable_exact_and_secure_clean(self):
        for fx in FIXTURES:
            exp = json.loads((FIX / fx / "expected.json").read_text())
            vctx = make_ctx(FIX / fx / "vulnerable")
            sctx = make_ctx(FIX / fx / "secure")
            for cid, locs in exp["vulnerable"].items():
                with self.subTest(fixture=fx, check=cid):
                    res = RULES[cid](vctx)
                    self.assertIsNotNone(res)
                    got = sorted([o.file, o.line] for o in res.observations)
                    self.assertEqual(got, sorted(map(list, locs)))
            for cid in exp["secure_clean"]:
                with self.subTest(fixture=fx, secure=cid):
                    res = RULES[cid](sctx)
                    if res is not None:
                        self.assertEqual(res.observations, [], res.observations)
                        self.assertFalse(res.inconclusive)

    def test_every_rule_flags_something_in_vulnerable(self):
        for fx, prefix in FIXTURES.items():
            exp = json.loads((FIX / fx / "expected.json").read_text())
            rules = {k for k in RULES if k.startswith(prefix)}
            self.assertEqual(rules, set(exp["vulnerable"]), fx)
            for cid, locs in exp["vulnerable"].items():
                self.assertTrue(locs, cid)

    def test_no_secret_in_observation_detail(self):
        ctx = make_ctx(FIX / "supply-chain" / "vulnerable")
        res = RULES["SEC-SC-006"](ctx)
        for o in res.observations:
            for frag in ("AKIAIOSFODNN7EXAMPLE", "Sup3rS3cret", "xoxb-", "ghp_", "EXAMPLEEXAMPLE", "ZXhhbXBs"):
                self.assertNotIn(frag, o.detail)


class NotApplicableTests(unittest.TestCase):
    def test_none_when_no_relevant_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "notes.md").write_text("nothing here\n")
            ctx = make_ctx(Path(d))
            for cid, fn in RULES.items():
                if cid.startswith(PREFIXES):
                    self.assertIsNone(fn(ctx), cid)

    def test_comments_are_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.js").write_text("// el.innerHTML = userInput;\n/* eval(x) */\n// rejectUnauthorized: false\n")
            (Path(d) / "b.py").write_text('# os.system(f"rm {x}")\n"""\nDEBUG = True\n"""\n')
            ctx = make_ctx(Path(d))
            for cid in ("SEC-WEB-002", "SEC-WEB-005", "SEC-WEB-007", "SEC-WEB-003"):
                res = RULES[cid](ctx)
                self.assertEqual(res.observations, [], cid)


class MetadataTests(unittest.TestCase):
    def test_schema_valid(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads(SCHEMA.read_text())
        for chk in load_checks():
            with self.subTest(check=chk["id"]):
                jsonschema.validate(chk, schema)

    def test_unique_ids_and_domains(self):
        checks = load_checks()
        ids = [c["id"] for c in checks]
        self.assertEqual(len(ids), len(set(ids)))
        for c in checks:
            self.assertTrue(c["id"].startswith(PREFIXES))
            self.assertEqual(c["review_state"], "reviewed")

    def test_builtin_static_checks_have_rules_and_vice_versa(self):
        checks = load_checks()
        builtin = {c["id"] for c in checks if c["mode"] == "static" and c["executor"] == "builtin"}
        rules = {k for k in RULES if k.startswith(PREFIXES)}
        self.assertEqual(builtin, rules)

    def test_planned_and_external(self):
        by = {c["id"]: c for c in load_checks()}
        for cid in ("SEC-WEB-050", "SEC-WEB-051", "SEC-WEB-052", "SEC-API-050", "SEC-API-051"):
            self.assertEqual(by[cid]["executor"], "none")
            self.assertEqual(by[cid]["profiles"], ["deep"])
        self.assertEqual(by["SEC-WEB-051"]["mode"], "hybrid")
        sc20 = by["SEC-SC-020"]
        self.assertEqual((sc20["mode"], sc20["executor"], sc20["rule"]), ("static", "external", "osv-scanner"))
        self.assertNotIn("SEC-SC-020", RULES)


if __name__ == "__main__":
    unittest.main()
