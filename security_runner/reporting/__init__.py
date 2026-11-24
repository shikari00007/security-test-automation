from __future__ import annotations

import json
from pathlib import Path

from . import junit, markdown, sarif

WRITERS = {"json": ("results.json", lambda run, cov: json.dumps({**run, "coverage": cov}, indent=2, ensure_ascii=False) + "\n"),
           "sarif": ("results.sarif", sarif.render),
           "junit": ("junit.xml", junit.render),
           "markdown": ("REPORT.md", markdown.render)}
ALIASES = {"md": "markdown", "xml": "junit"}


def parse_formats(spec: str) -> list[str]:
    out = []
    for s in (x.strip().lower() for x in spec.split(",") if x.strip()):
        s = ALIASES.get(s, s)
        if s not in WRITERS:
            raise ValueError(f"unknown report format {s!r}; choose from json,sarif,junit,markdown")
        if s not in out:
            out.append(s)
    return out


def write_reports(run: dict, cov: dict, outdir: Path, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = []
    for f in formats:
        name, fn = WRITERS[f]
        p = outdir / name
        p.write_text(fn(run, cov), encoding="utf-8")
        paths.append(p)
    return paths
