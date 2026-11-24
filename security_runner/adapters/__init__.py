"""Check implementations. Importing this package registers every built-in rule."""
from __future__ import annotations

import importlib

from .base import RULES, RuleResult, Observation, ScanContext, rule  # noqa: F401

# Modules are imported lazily-but-eagerly here so the registry is complete. A module that
# is missing (not yet shipped) is skipped; a module that *fails to import* is an error.
_MODULES = ["web", "api", "supply_chain", "android", "ios", "desktop", "cloud_k8s", "ai_llm"]


def load_all() -> None:
    for name in _MODULES:
        try:
            importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as exc:  # only swallow "this adapter module doesn't exist"
            if exc.name != f"{__name__}.{name}":
                raise
