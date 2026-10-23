"""Repository walking shared by all collectors."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    "site-packages", "dist", "build", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".aiwatch", ".idea", ".cache",
}
MAX_TEXT_BYTES = 2_000_000


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            yield Path(dirpath) / fn


def rel(root: Path, p: Path) -> str:
    if root.is_file():
        return p.name
    return p.relative_to(root).as_posix()


def read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > MAX_TEXT_BYTES:
            return None
        return p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
