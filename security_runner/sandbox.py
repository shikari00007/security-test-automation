"""Safe subprocess execution: argv only (no shell), allow-listed binaries, scrubbed env,
wall-clock timeout, output cap, POSIX resource limits, process-group kill."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field

SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR")


class SandboxError(RuntimeError):
    pass


@dataclass
class RunResult:
    argv: list[str]
    tool_path: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    elapsed_s: float
    limits: dict = field(default_factory=dict)


def _limits(cpu_s: int, mem_mb: int, fsize_mb: int):
    def apply():
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_mb << 20, fsize_mb << 20))
        resource.setrlimit(resource.RLIMIT_NPROC, (256, 256)) if hasattr(resource, "RLIMIT_NPROC") else None
    return apply


def safe_run(argv: list[str], *, allowed: set[str], cwd: str | None = None, timeout: float = 60.0,
             max_output: int = 1_000_000, mem_mb: int = 2048, fsize_mb: int = 64,
             extra_env: dict | None = None, no_network: bool = False,
             allowed_paths: set[str] | None = None) -> RunResult:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise SandboxError("argv must be a non-empty list of strings (no shell strings)")
    name = os.path.basename(argv[0])
    if name not in allowed:
        raise SandboxError(f"binary {argv[0]!r} is not on the allow-list")
    if "/" in argv[0]:
        ok = {os.path.realpath(x) for x in (allowed_paths or set())} | {os.path.realpath(shutil.which(name) or "")}
        if os.path.realpath(argv[0]) not in ok:
            raise SandboxError(f"binary path {argv[0]!r} is not an allowed location")
        path = argv[0]
    else:
        path = shutil.which(name)
    if not path:
        raise SandboxError(f"binary {name!r} not found")
    cmd = [path] + argv[1:]
    if no_network:
        unshare = shutil.which("unshare")
        if not unshare or subprocess.run([unshare, "-rn", "true"], capture_output=True).returncode != 0:
            raise SandboxError("network isolation requested but unshare -rn is unavailable")
        cmd = [unshare, "-rn"] + cmd
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env.update(extra_env or {})
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True,
                         preexec_fn=_limits(int(timeout) + 5, mem_mb, fsize_mb))
    timed_out = False
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = p.communicate()
    trunc = len(out) > max_output or len(err) > max_output
    return RunResult(argv=argv, tool_path=path, exit_code=None if timed_out else p.returncode,
                     stdout=out[:max_output].decode("utf-8", "replace"),
                     stderr=err[:max_output].decode("utf-8", "replace"),
                     timed_out=timed_out, truncated=trunc, elapsed_s=round(time.monotonic() - t0, 3),
                     limits={"timeout_s": timeout, "max_output": max_output, "mem_mb": mem_mb,
                             "no_network": no_network})
