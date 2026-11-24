"""Opt-in install smoke test using the real `skills` CLI (needs network for npx). Run with STAX_INSTALL_TEST=1.
Optionally set STAX_INSTALL_SOURCE=shikari00007/security-test-automation to test the published repo."""
import os
import subprocess
from pathlib import Path

import pytest

from security_runner.skillcheck import validate_dir

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("STAX_INSTALL_TEST") != "1", reason="set STAX_INSTALL_TEST=1")


def test_npx_skills_install_for_multiple_agents(tmp_path):
    proj, home = tmp_path / "proj", tmp_path / "home"
    proj.mkdir(); home.mkdir()
    src = os.environ.get("STAX_INSTALL_SOURCE", str(ROOT))
    r = subprocess.run(["npx", "-y", "skills", "add", src, "-a", "claude-code", "-a", "codex", "-a", "cursor",
                        "-a", "gemini-cli", "-y", "--copy"], cwd=proj, env={**os.environ, "HOME": str(home)},
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    for d in (".claude/skills", ".agents/skills"):
        res = validate_dir(proj / d)
        assert res["valid"] and len(res["skills"]) == 16, (d, res)
