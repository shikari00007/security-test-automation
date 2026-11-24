"""Filesystem locations and path-confinement helpers."""
from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
CHECKS_DIR = DATA_DIR / "checks"
SCHEMAS_DIR = DATA_DIR / "schemas"


def is_within(child: Path, parent: Path) -> bool:
    """True if ``child`` is ``parent`` or lies beneath it (both fully resolved)."""
    child = child.resolve()
    parent = parent.resolve()
    return child == parent or parent in child.parents


def confine_output(out: str | Path, forbidden_roots: list[Path]) -> Path:
    """Resolve an output path and refuse anything that lands inside a forbidden root.

    The *parent directory* is resolved (following symlinks) before comparison so a
    symlinked directory cannot be used to write into a scanned source tree.
    """
    p = Path(out).expanduser()
    if p.is_symlink():
        raise ValueError("output path must not be a symlink")
    parent = p.parent.resolve(strict=False)
    if not parent.is_dir():
        raise ValueError("output parent directory must exist")
    final = parent / p.name
    for root in forbidden_roots:
        if is_within(final, root):
            raise ValueError("output must be outside the target source tree (no unapproved source writes)")
    return final
