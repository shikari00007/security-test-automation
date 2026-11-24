"""Execution policy: offline/read-only by default; active work needs a valid, recorded scope."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

MODES = ("offline", "lab", "staging")
FORBIDDEN_ENVS = {"production", "prod", "live"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    authorized_by: str
    environment: str
    targets: tuple[str, ...]
    expires: str
    isolation_confirmed: bool
    raw_sha256: str = ""


@dataclass(frozen=True)
class Policy:
    mode: str = "offline"
    scope: Scope | None = None
    allowed_tools: frozenset[str] = frozenset()

    def decide(self, check: dict) -> tuple[bool, str]:
        """(runnable_now, reason). Static builtin checks always run; others need explicit gating."""
        mode, executor = check["mode"], check["executor"]
        if executor == "none":
            return False, "unimplemented: planned/manual check, no automation exists in this release"
        if mode in ("dynamic", "hybrid"):
            if self.mode == "offline":
                return False, "dynamic testing requires --mode lab|staging with a valid scope file"
            if self.scope is None:
                return False, "dynamic testing requires an authorized scope"
            return False, "unimplemented: no dynamic adapter exists in this release (scope accepted, nothing executed)"
        if executor == "external" and check.get("rule") not in self.allowed_tools:
            return False, f"external tool '{check.get('rule')}' not allowed/available"
        return True, ""

    def describe(self) -> dict:
        return {"mode": self.mode, "network_access": False,
                "scope": None if not self.scope else {"authorized_by": self.scope.authorized_by,
                                                      "environment": self.scope.environment,
                                                      "targets": list(self.scope.targets),
                                                      "expires": self.scope.expires,
                                                      "sha256": self.scope.raw_sha256},
                "allowed_tools": sorted(self.allowed_tools)}


def load_scope(path: str | Path, now: dt.datetime | None = None) -> Scope:
    import hashlib
    raw = Path(path).read_bytes()
    try:
        d = json.loads(raw)
    except ValueError as e:
        raise PolicyError(f"scope file is not valid JSON: {e}")
    if not isinstance(d, dict):
        raise PolicyError("scope file must be a JSON object")
    env = str(d.get("environment", "")).lower()
    if env in FORBIDDEN_ENVS or env not in ("lab", "staging"):
        raise PolicyError("scope.environment must be 'lab' or 'staging'; production is never permitted")
    targets = d.get("targets")
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t.strip() for t in targets):
        raise PolicyError("scope.targets must be a non-empty list of explicit hosts")
    if any("*" in t and t.strip("*.") == "" for t in targets) or "0.0.0.0/0" in targets:
        raise PolicyError("scope.targets must not be a blanket wildcard")
    if not str(d.get("authorized_by", "")).strip():
        raise PolicyError("scope.authorized_by is required")
    if d.get("isolation_confirmed") is not True:
        raise PolicyError("scope.isolation_confirmed must be true (isolated environment, test accounts)")
    try:
        exp = dt.datetime.fromisoformat(str(d["expires"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        raise PolicyError("scope.expires must be an ISO-8601 timestamp")
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=dt.timezone.utc)
    if exp <= (now or dt.datetime.now(dt.timezone.utc)):
        raise PolicyError("scope has expired")
    return Scope(str(d["authorized_by"]), env, tuple(targets), exp.isoformat(), True,
                 hashlib.sha256(raw).hexdigest())
