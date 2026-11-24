"""Loading and validating the domain registry, profiles and reviewed checks."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache

from .paths import CHECKS_DIR, DATA_DIR, SCHEMAS_DIR


def read_json(p):
    return json.loads(p.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def domains() -> dict[str, dict]:
    return {d["id"]: d for d in read_json(DATA_DIR / "domains.json")["domains"]}


@lru_cache(maxsize=1)
def profiles() -> dict[str, dict]:
    return read_json(DATA_DIR / "profiles.json")


@lru_cache(maxsize=1)
def checks() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in sorted(CHECKS_DIR.glob("*.json")):
        for c in read_json(f)["checks"]:
            if c["id"] in out:
                raise ValueError(f"duplicate check id {c['id']}")
            out[c["id"]] = c
    return out


def catalog_sha256() -> str:
    h = hashlib.sha256()
    for f in sorted(CHECKS_DIR.glob("*.json")):
        h.update(f.name.encode() + f.read_bytes())
    return h.hexdigest()


def validate_checks() -> list[str]:
    """Return a list of problems (empty = valid). Uses jsonschema when installed."""
    problems: list[str] = []
    try:
        import jsonschema
        schema = read_json(SCHEMAS_DIR / "check.schema.json")
        v = jsonschema.Draft202012Validator(schema)
    except ImportError:
        v = None
    dom = domains()
    for cid, c in checks().items():
        if v is not None:
            for e in v.iter_errors(c):
                problems.append(f"{cid}: {e.message}")
        if c.get("domain") not in dom:
            problems.append(f"{cid}: unknown domain")
    from . import adapters
    adapters.load_all()
    for cid, c in checks().items():
        impl = cid in adapters.RULES
        if c["mode"] == "static" and c["executor"] == "builtin" and not impl:
            problems.append(f"{cid}: builtin static check has no registered rule")
        if impl and not (c["mode"] == "static" and c["executor"] == "builtin"):
            problems.append(f"{cid}: rule registered but metadata is not static/builtin")
    for rid in adapters.RULES:
        if rid not in checks():
            problems.append(f"{rid}: rule has no reviewed metadata")
    return problems
