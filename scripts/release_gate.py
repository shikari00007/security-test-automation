"""Release-gate suite: builds the public tree and exercises it from CLEAN installs.

Usage: python scripts/release_gate.py [--rc dist/release-candidate] [--report dist/release-gate-report] [--skip-npx]
Everything runs on a copy of the release tree in a temp dir; the RC tree itself is hash-checked before/after.
Nothing is published. The published-repo install check is a separate manual step (scripts/verify_published.sh).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS: list[dict] = []


def record(gate, name, status, detail=""):
    RESULTS.append({"gate": gate, "check": name, "status": status, "detail": str(detail)[:600]})
    print(f"[{status:7}] {gate}: {name}" + (f" - {str(detail)[:160]}" if status != "PASS" else ""), flush=True)


def check(gate, name, cond, detail=""):
    record(gate, name, "PASS" if cond else "FAIL", detail if not cond else "")
    return bool(cond)


def run(cmd, cwd=None, env=None, timeout=900):
    e = {**os.environ, **(env or {})}
    return subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)


def tree_digest(p: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(x for x in p.rglob("*") if x.is_file()):
        h.update(f.relative_to(p).as_posix().encode() + f.read_bytes())
    return h.hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc", default=str(ROOT / "dist" / "release-candidate"))
    ap.add_argument("--report", default=str(ROOT / "dist" / "release-gate-report"))
    ap.add_argument("--skip-npx", action="store_true")
    ap.add_argument("--raw", default=str(ROOT / "catalog" / "raw"),
                    help="private raw checklist inventory used by the restricted-content scan (maintainers only)")
    ap.add_argument("--require-restricted-scan", action="store_true",
                    help="fail (instead of skip) when the private raw inventory is unavailable")
    a = ap.parse_args(argv)
    rc = Path(a.rc).resolve()
    t0 = time.time()
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_release, scan_restricted

    # ---- G1 content / provenance ----------------------------------------------------------------
    files = build_release.build(rc)
    digest_before = tree_digest(rc)
    forbidden = [f for f in files if f.startswith(("catalog/", "docs/baseline/", "security_runner/catalogtool/"))]
    check("G1-content", "allowlist build excludes catalog/raw*, canonical, baseline docs, catalog tooling", not forbidden, forbidden)
    man = {l.split()[-1]: l.split()[0] for l in (rc / "RELEASE-MANIFEST.txt").read_text().splitlines()}
    check("G1-content", "manifest lists every published file with a matching sha256",
          set(man) == set(files) and all(hashlib.sha256((rc / f).read_bytes()).hexdigest() == h for f, h in man.items()))
    scan = scan_restricted.scan(rc, Path(a.raw))
    skipped = "FAIL" if a.require_restricted_scan else "SKIPPED"
    record("G1-content", "no reproduced checklist text (10-word runs / full entries vs private raw inventory)",
           {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": skipped}[scan["status"]],
           scan.get("reason") or scan["hits"][:3])
    check("G1-content", "no *.zip/*.jsonl/raw checklist filenames in release",
          not [f for f in files if f.endswith((".zip", ".jsonl")) or f.rsplit("/", 1)[-1] in
               ("API.txt", "Android.txt", "IOS.txt", "Thick-Client.txt", "WEB -1.txt", "WEB -2.txt", "web-seclist.txt", "supplychainsecurity.md")])
    third = (rc / "docs/THIRD-PARTY.md").read_text()
    check("G1-licence", "LICENSE is MIT (Copyright 2026 shikari00007), NOTICE present, upstream SHAs pinned",
          (rc / "LICENSE").read_text().startswith("MIT License\n") and "Copyright (c) 2026 shikari00007" in (rc / "LICENSE").read_text()
          and (rc / "NOTICE").is_file()
          and all(s in third for s in ("5087a3461d49da76b1e794d9b0bfbd23f38dc75b", "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
                                       "6196ba7464662de34e8744d359f175d1a7bca530")))
    readme = (rc / "README.md").read_text()
    check("G1-content", "README labelled Developer Preview and not claiming production readiness",
          "Developer Preview" in readme and "production-ready" not in readme.replace("not production-ready", ""))

    with tempfile.TemporaryDirectory(prefix="stax-gate-") as tmp:
        tmp = Path(tmp)
        work = tmp / "rc"
        shutil.copytree(rc, work)
        # ---- G2 packaging ---------------------------------------------------------------------------
        va = tmp / "venv-build"
        run([sys.executable, "-m", "venv", str(va)])
        r = run([str(va / "bin/pip"), "install", "-q", "build"])
        check("G2-packaging", "build tooling installs in clean venv", r.returncode == 0, r.stderr[-300:])
        out = tmp / "dist"
        r = run([str(va / "bin/python"), "-m", "build", "--outdir", str(out), str(work)])
        check("G2-packaging", "sdist+wheel build from the release tree", r.returncode == 0, r.stderr[-400:] + r.stdout[-300:])
        wheels, sdists = list(out.glob("*.whl")), list(out.glob("*.tar.gz"))
        if wheels and sdists:
            names = zipfile.ZipFile(wheels[0]).namelist()
            check("G2-packaging", "wheel contains package data (domains, profiles, schema, 8 check files)",
                  all(any(n.endswith(x) for n in names) for x in ("data/domains.json", "data/profiles.json", "data/schemas/check.schema.json"))
                  and sum(1 for n in names if "data/checks/" in n and n.endswith(".json")) == 8)
            meta_name = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
            meta_txt = zipfile.ZipFile(wheels[0]).read(meta_name).decode() if meta_name else ""
            headers = meta_txt.split("\n\n", 1)[0]   # the README (long description) may legitimately cite the historical release
            check("G2-packaging", "wheel METADATA declares License-Expression: MIT (and not Apache)",
                  "License-Expression: MIT" in headers and "Apache" not in headers, headers[:300])
            lic_in_wheel = next((n for n in names if n.endswith("licenses/LICENSE") or n.endswith("dist-info/LICENSE")), None)
            check("G2-packaging", "LICENSE inside the wheel is the MIT text",
                  bool(lic_in_wheel) and zipfile.ZipFile(wheels[0]).read(lic_in_wheel).decode().startswith("MIT License"))
            check("G2-packaging", "wheel ships LICENSE+NOTICE and no tests/fixtures/catalog/catalogtool",
                  any(n.endswith("licenses/LICENSE") or n.endswith("dist-info/LICENSE") for n in names)
                  and not [n for n in names if n.startswith(("tests/", "fixtures/", "catalog/")) or "catalogtool" in n],
                  [n for n in names if "licen" in n.lower()][:4])
            import tarfile
            snames = tarfile.open(sdists[0]).getnames()
            sd = tarfile.open(sdists[0])
            lic_member = next((m for m in sd.getmembers() if m.name.endswith("/LICENSE")), None)
            check("G2-packaging", "sdist contains the MIT LICENSE and NOTICE",
                  bool(lic_member) and sd.extractfile(lic_member).read().decode().startswith("MIT License")
                  and any(n.endswith("/NOTICE") for n in snames))
            check("G2-packaging", "sdist has no restricted/internal paths",
                  not [n for n in snames if "/catalog/" in n or "baseline" in n or n.endswith(".jsonl")])
        # ---- G3 clean install, runtime behaviour --------------------------------------------------------
        vb = tmp / "venv-clean"
        run([sys.executable, "-m", "venv", str(vb)])
        r = run([str(vb / "bin/pip"), "install", "-q", str(wheels[0])]) if wheels else None
        check("G3-install", "wheel installs into clean venv with no network-fetched runtime deps",
              bool(r) and r.returncode == 0 and "Requires:" not in run([str(vb / "bin/pip"), "show", "security-test-automation"]).stdout.replace("Requires: \n", ""),
              r and r.stderr[-300:])
        cli = str(vb / "bin/security-skills")
        neutral = tmp / "neutral"
        neutral.mkdir()
        import tomllib
        ver = tomllib.loads((rc / "pyproject.toml").read_text())["project"]["version"]
        r = run([cli, "--version"], cwd=neutral)
        check("G3-install", "installed CLI reports package version", r.stdout.strip() == ver, r.stdout + r.stderr)
        r = run([cli, "skills", "validate", str(rc / "skills")], cwd=neutral)
        check("G3-install", "installed CLI validates 16 skills", r.returncode == 0 and len(json.loads(r.stdout)["skills"]) == 16, r.stdout[-300:])
        r = run([cli, "catalog", "validate-checks"], cwd=neutral)
        j = json.loads(r.stdout) if r.stdout.strip().startswith("{") else {}
        check("G3-install", "reviewed checks load from installed package data (62+ checks, parity ok)",
              r.returncode == 0 and j.get("checks", 0) >= 62, r.stdout[-300:] + r.stderr[-200:])
        fx = rc / "fixtures"
        cases = sorted(p.parent.name for p in fx.glob("*/expected.json"))
        offline_ok = True
        unshare = shutil.which("unshare") and run(["unshare", "-rn", "true"]).returncode == 0
        for name in cases:
            spec = json.loads((fx / name / "expected.json").read_text())
            outv, outs = tmp / f"o-{name}-v", tmp / f"o-{name}-s"
            pre = ["unshare", "-rn"] if unshare else []
            rv = run(pre + [cli, "audit", str(fx / name / "vulnerable"), "--profile", "deep", "--output-dir", str(outv), "--fail-on", "never"], cwd=neutral)
            rs = run(pre + [cli, "audit", str(fx / name / "secure"), "--profile", "deep", "--output-dir", str(outs), "--fail-on", "never"], cwd=neutral)
            offline_ok &= rv.returncode == 0 and rs.returncode == 0
            if rv.returncode != 0 or rs.returncode != 0:
                record("G3-runtime", f"audit {name} (offline namespace)", "FAIL", rv.stderr[-200:] + rs.stderr[-200:])
                continue
            runv = json.loads((outv / "run.json").read_text())
            runs = json.loads((outs / "run.json").read_text())
            got = {e["check_id"] for e in runv["executions"] if e["outcome"] == "fail"}
            miss = set(spec["vulnerable"]) - got
            fps = [e["check_id"] for e in runs["executions"] if e["outcome"] == "fail"]
            check("G3-runtime", f"{name}: vulnerable fixture flags expected checks; secure fixture has zero failures",
                  not miss and not fps, f"missing={sorted(miss)} secure_fp={fps}")
            check("G3-runtime", f"{name}: no static match auto-promoted to confirmed",
                  all(f["status"] != "confirmed" for f in runv["findings"]))
            vv = run([cli, "verify", str(outv / "run.json"), "--target", str(fx / name / "vulnerable")], cwd=neutral)
            check("G3-evidence", f"{name}: run manifest verifies against target", vv.returncode == 0, vv.stdout[-300:])
        check("G3-offline", f"all fixture audits succeeded {'inside a no-network namespace (unshare -rn)' if unshare else '(NO namespace available: not proven)'}",
              offline_ok and bool(unshare))
        # evidence integrity
        base = "web-app"
        o = tmp / f"o-{base}-v"
        run_json = json.loads((o / "run.json").read_text())
        t1 = json.loads(json.dumps(run_json))
        victim = next(e for e in t1["executions"] if e["status"] == "blocked")
        victim.update(status="executed", outcome="pass")
        (tmp / "t1.json").write_text(json.dumps(t1))
        check("G3-evidence", "fabricated 'executed' result is rejected (exit 3)",
              run([cli, "verify", str(tmp / "t1.json"), "--target", str(fx / base / "vulnerable")], cwd=neutral).returncode == 3)
        t2 = json.loads(json.dumps(run_json))
        t2["executions"][0]["evidence"] = ["fake"]
        (tmp / "t2.json").write_text(json.dumps(t2))
        check("G3-evidence", "non-empty evidence string alone is rejected (exit 3)",
              run([cli, "verify", str(tmp / "t2.json"), "--target", str(fx / base / "vulnerable")], cwd=neutral).returncode == 3)
        mutated = tmp / "mutated"
        shutil.copytree(fx / base / "vulnerable", mutated)
        examined = next(a["path"] for e in run_json["executions"] if e["status"] == "executed" for a in e["assets"])
        victim_file = mutated / examined
        victim_file.write_text(victim_file.read_text() + "\n// changed after the run\n")
        check("G3-evidence", "target modified after the run is detected (exit 3)",
              run([cli, "verify", str(o / "run.json"), "--target", str(mutated)], cwd=neutral).returncode == 3)
        # path security
        proj = tmp / "proj"
        proj.mkdir()
        (proj / "requirements.txt").write_text("flask==3.0.0\n")
        check("G3-path", "output inside target tree is refused (exit 2)",
              run([cli, "audit", str(proj), "--output-dir", str(proj / "out")], cwd=neutral).returncode == 2)
        link = tmp / "lnk"
        link.symlink_to(proj, target_is_directory=True)
        check("G3-path", "output via symlinked directory into target is refused (exit 2)",
              run([cli, "audit", str(proj), "--output-dir", str(link / "out2")], cwd=neutral).returncode == 2)
        (proj / "AndroidManifest.xml").symlink_to("/etc/hostname")
        (proj / "leak").symlink_to("/etc", target_is_directory=True)
        d = json.loads(run([cli, "detect", str(proj)], cwd=neutral).stdout)
        check("G3-path", "symlinks inside the target are not followed or read", "android" not in d["domains"])
        check("G3-path", "nonexistent / file targets are rejected",
              run([cli, "audit", str(tmp / "nope")], cwd=neutral).returncode == 2
              and run([cli, "audit", str(proj / "requirements.txt")], cwd=neutral).returncode == 2)
        # policy / dynamic
        check("G3-policy", "--mode lab without a scope file is refused (exit 2)",
              run([cli, "plan", str(proj), "--mode", "lab"], cwd=neutral).returncode == 2)
        prod = tmp / "prod.json"
        prod.write_text(json.dumps({"authorized_by": "x", "environment": "production", "targets": ["a.example.test"],
                                    "expires": "2099-01-01T00:00:00Z", "isolation_confirmed": True}))
        check("G3-policy", "production scope is always refused",
              run([cli, "plan", str(proj), "--mode", "lab", "--scope", str(prod)], cwd=neutral).returncode == 2)
        good = tmp / "scope.json"
        good.write_text(json.dumps({"authorized_by": "qa lead", "environment": "lab", "targets": ["lab.internal"],
                                    "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat(),
                                    "isolation_confirmed": True}))
        r = run([cli, "plan", str(fx / "api-spec" / "vulnerable"), "--mode", "lab", "--scope", str(good), "--profile", "deep"], cwd=neutral)
        plan = json.loads(r.stdout) if r.returncode == 0 else {"items": []}
        dyn = [i for i in plan["items"] if i["mode"] in ("dynamic", "hybrid", "manual") and i["status"] != "not_applicable"]
        check("G3-policy", "with a valid scope, dynamic/manual checks remain blocked and labelled 'unimplemented'",
              dyn and all(i["status"] in ("blocked", "deferred") for i in dyn) and any("unimplemented" in i["reason"] for i in dyn),
              [i for i in dyn][:2])
        # regression red/green
        run([str(vb / "bin/pip"), "install", "-q", "pytest"])
        o = tmp / "o-web-app-v"
        rj = json.loads((o / "run.json").read_text())
        f = next((x for x in rj["findings"] if x["status"] == "candidate" and x["check_id"] == "SEC-WEB-003"), None) or \
            next(x for x in rj["findings"] if x["status"] == "candidate")
        r = run([cli, "regression", "generate", "--results", str(o / "run.json"), "--finding", f["id"], "--accept-candidate",
                 "--output-dir", str(tmp / "reg")], cwd=neutral)
        gen = next((tmp / "reg").glob("test_*.py"), None)
        check("G3-regression", "regression test generated from candidate only with explicit opt-in and labelled",
              r.returncode == 0 and gen and "CANDIDATE" in gen.read_text(), r.stderr[-300:])
        if gen:
            r = run([cli, "regression", "verify", "--test", str(gen), "--vulnerable", str(fx / "web-app" / "vulnerable"),
                     "--fixed", str(fx / "web-app" / "secure")], cwd=neutral)
            check("G3-regression", "generated test is red on vulnerable fixture and green on secure fixture", r.returncode == 0, r.stdout[-300:])
        r = run([cli, "regression", "generate", "--results", str(o / "run.json"), "--finding", f["id"], "--output-dir", str(tmp / "reg2")], cwd=neutral)
        check("G3-regression", "generation without --accept-candidate is refused for unconfirmed findings", r.returncode == 2)
        # ---- G4 full test-suite on a clean env -----------------------------------------------------------
        vc = tmp / "venv-test"
        run([sys.executable, "-m", "venv", str(vc)])
        r = run([str(vc / "bin/pip"), "install", "-q", f"{work}[dev]"])
        check("G4-tests", "dev extras install in clean venv", r.returncode == 0, r.stderr[-300:])
        r = run([str(vc / "bin/python"), "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x"], cwd=work,
                env={"STAX_INSTALL_TEST": "0" if a.skip_npx else "1"})
        tail = (r.stdout.strip().splitlines() or [""])[-1]
        check("G4-tests", "full pytest suite passes on the release tree", r.returncode == 0, tail + r.stderr[-200:])
        record("G4-tests", "pytest summary", "INFO", tail)
        # ---- G5 multi-agent skill discovery -----------------------------------------------------------------
        if a.skip_npx:
            record("G5-agents", "multi-agent install", "SKIPPED", "--skip-npx")
        else:
            sys.path.insert(0, str(ROOT))
            from security_runner.skillcheck import validate_dir
            agents = ["claude-code", "codex", "cursor", "gemini-cli", "github-copilot"]
            home, proj2 = tmp / "home", tmp / "proj2"
            home.mkdir(); proj2.mkdir()
            cmd = ["npx", "-y", "skills", "add", str(rc)] + [x for ag in agents for x in ("-a", ag)] + ["-y", "--copy"]
            r = run(cmd, cwd=proj2, env={"HOME": str(home)}, timeout=400)
            check("G5-agents", f"`npx skills add <release tree> -a {' -a '.join(agents)}` exits 0", r.returncode == 0, r.stderr[-300:] + r.stdout[-300:])
            installed = sorted({p.parent.parent.relative_to(proj2).as_posix() for p in proj2.rglob("SKILL.md")})
            record("G5-agents", "agent skill directories created", "INFO", installed)
            src = {p.name for p in (rc / "skills").iterdir() if p.is_dir()}
            for d in installed:
                v = validate_dir(proj2 / d)
                same = all((proj2 / d / s / "SKILL.md").read_bytes() == (rc / "skills" / s / "SKILL.md").read_bytes() for s in src if (proj2 / d / s).is_dir())
                check("G5-agents", f"{d}: 16 spec-valid skills, byte-identical to release tree", v["valid"] and len(v["skills"]) == 16 and same, v["errors"][:2])
            lst = run(["npx", "-y", "skills", "list"], cwd=proj2, env={"HOME": str(home)}, timeout=120)
            check("G5-agents", "`skills list` shows all 16 skills", all(s in lst.stdout for s in src), lst.stdout[-200:])
            proj2b = tmp / "proj2b"
            proj2b.mkdir()
            r = run(["npx", "-y", "skills", "add", str(rc), "--skill", "security-start", "-a", "claude-code", "-y", "--copy"],
                    cwd=proj2b, env={"HOME": str(home)}, timeout=300)
            check("G5-agents", "single-skill install (--skill security-start) works", r.returncode == 0, r.stderr[-200:])
        record("G6-published", "`npx skills add shikari00007/security-test-automation` from the PUBLISHED repo",
               "SKIPPED", "network check against GitHub; run scripts/verify_published.sh separately after each publication")
        # RC tree untouched by the gate
        check("G1-content", "release tree unchanged by gate run", tree_digest(rc) == digest_before)

    dur = round(time.time() - t0)
    fails = [r for r in RESULTS if r["status"] == "FAIL"]
    summary = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "duration_s": dur,
               "pass": sum(r["status"] == "PASS" for r in RESULTS), "fail": len(fails),
               "pending_or_skipped": [r["check"] for r in RESULTS if r["status"] in ("PENDING", "SKIPPED")],
               "results": RESULTS}
    rp = Path(a.report)
    rp.with_suffix(".json").write_text(json.dumps(summary, indent=2) + "\n")
    md = [f"# Release gate report ({summary['generated']})", "", f"PASS {summary['pass']} | FAIL {summary['fail']} | duration {dur}s", "",
          "| Gate | Check | Status | Detail |", "|---|---|---|---|"]
    md += [f"| {r['gate']} | {r['check']} | {r['status']} | {r['detail'][:120].replace('|', '/')} |" for r in RESULTS]
    rp.with_suffix(".md").write_text("\n".join(md) + "\n")
    print(f"\nPASS {summary['pass']}  FAIL {summary['fail']}  ({dur}s) -> {rp}.md")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
