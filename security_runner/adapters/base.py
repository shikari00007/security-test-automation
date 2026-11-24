"""Rule registry and the read-only ScanContext handed to every static rule.

Design guarantees (tested):
* Rules never touch the filesystem directly. They call ``ctx.read`` which only serves
  files discovered under the confined root, caps size, never follows symlinks and
  *records the SHA-256 of every file actually read*. That record - not anything the rule
  returns - is what later proves a check examined real assets.
* A rule that reads no files cannot produce an ``executed`` result.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

MAX_READ_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Observation:
    """One location where a rule saw the insecure pattern."""
    file: str      # root-relative posix path
    line: int      # 1-based
    detail: str    # human explanation (must not contain raw secrets)


@dataclass
class RuleResult:
    observations: list[Observation] = field(default_factory=list)
    notes: str = ""
    inconclusive: bool = False   # set when the rule could not reach a verdict


RuleFn = Callable[["ScanContext"], "RuleResult | None"]
RULES: dict[str, RuleFn] = {}


def rule(check_id: str) -> Callable[[RuleFn], RuleFn]:
    """Register ``fn`` as the implementation of reviewed check ``check_id``."""
    def deco(fn: RuleFn) -> RuleFn:
        if check_id in RULES:
            raise RuntimeError(f"duplicate rule registration: {check_id}")
        RULES[check_id] = fn
        return fn
    return deco


class ScanContext:
    """Read-only, hash-recording view of the target project."""

    def __init__(self, root: Path, files: list[str], detected_domains: dict | None = None):
        self.root = root.resolve()
        self.files = sorted(files)
        self._fileset = set(self.files)
        self.detected = detected_domains or {}
        self._read: dict[str, tuple[str, int]] = {}      # rel -> (sha256, bytes) across whole run
        self._rule_reads: set[str] = set()               # reads during the current rule
        self._cache: dict[str, str] = {}

    # -- selection -------------------------------------------------------------------
    def match(self, *globs: str) -> list[str]:
        """Root-relative files matching any glob. Globs without '/' match the basename."""
        out = []
        for rel in self.files:
            base = rel.rsplit("/", 1)[-1]
            for g in globs:
                if fnmatch.fnmatch(base if "/" not in g else rel, g):
                    out.append(rel)
                    break
        return out

    # -- reading ---------------------------------------------------------------------
    def read(self, rel: str) -> str:
        if rel not in self._fileset:
            raise PermissionError(f"path not in confined file set: {rel!r}")
        self._rule_reads.add(rel)
        if rel in self._cache:
            return self._cache[rel]
        full = self.root / rel
        if full.is_symlink() or not full.is_file():
            raise PermissionError(f"refusing non-regular file: {rel!r}")
        with open(full, "rb") as fh:
            data = fh.read(MAX_READ_BYTES + 1)
        truncated = len(data) > MAX_READ_BYTES
        data = data[:MAX_READ_BYTES]
        # Hash what we read (bounded). Truncated reads are recorded with their byte count.
        self._read[rel] = (hashlib.sha256(data).hexdigest(), len(data))
        text = data.decode("utf-8", errors="replace")
        if truncated:
            text += "\n"
        self._cache[rel] = text
        return text

    def grep(self, rel: str, pattern: "re.Pattern[str] | str", detail: str,
             skip_comments: bool = False) -> list[Observation]:
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        hits = []
        for i, line in enumerate(self.read(rel).splitlines(), 1):
            if skip_comments and re.match(r"\s*(//|#|\*|/\*|<!--)", line):
                continue
            if rx.search(line):
                hits.append(Observation(rel, i, detail))
        return hits

    def grep_files(self, globs: Iterable[str], pattern: "re.Pattern[str] | str", detail: str,
                   skip_comments: bool = True) -> RuleResult | None:
        """Convenience: scan every file matching ``globs``. Returns None if there are none."""
        files = self.match(*globs)
        if not files:
            return None
        obs: list[Observation] = []
        for rel in files:
            obs.extend(self.grep(rel, pattern, detail, skip_comments=skip_comments))
        return RuleResult(obs)

    # -- bookkeeping used by the engine ----------------------------------------------
    def begin_rule(self) -> None:
        self._rule_reads = set()

    def rule_assets(self) -> list[dict]:
        return [{"path": p, "sha256": self._read[p][0], "bytes": self._read[p][1]}
                for p in sorted(self._rule_reads) if p in self._read]
