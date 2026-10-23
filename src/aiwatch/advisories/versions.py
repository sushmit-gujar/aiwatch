"""Version ordering for PyPI (PEP 440) and npm (SemVer 2.0)."""

from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


class SemVer:
    __slots__ = ("major", "minor", "patch", "pre")

    def __init__(self, s: str) -> None:
        m = _SEMVER.match(s.strip())
        if not m:
            raise ValueError(f"not semver: {s!r}")
        self.major, self.minor, self.patch = (int(m.group(i) or 0) for i in (1, 2, 3))
        self.pre = tuple(m.group(4).split(".")) if m.group(4) else ()

    @property
    def is_prerelease(self) -> bool:
        return bool(self.pre)

    def _cmp(self, o: SemVer) -> int:
        a, b = (self.major, self.minor, self.patch), (o.major, o.minor, o.patch)
        if a != b:
            return -1 if a < b else 1
        if self.pre == o.pre:
            return 0
        if not self.pre:
            return 1
        if not o.pre:
            return -1
        for x, y in zip(self.pre, o.pre):
            if x == y:
                continue
            xd, yd = x.isdigit(), y.isdigit()
            if xd and yd:
                return -1 if int(x) < int(y) else 1
            if xd != yd:
                return -1 if xd else 1
            return -1 if x < y else 1
        return -1 if len(self.pre) < len(o.pre) else 1

    def __lt__(self, o: SemVer) -> bool:
        return self._cmp(o) < 0

    def __le__(self, o: SemVer) -> bool:
        return self._cmp(o) <= 0

    def __gt__(self, o: SemVer) -> bool:
        return self._cmp(o) > 0

    def __ge__(self, o: SemVer) -> bool:
        return self._cmp(o) >= 0

    def __eq__(self, o: object) -> bool:
        return isinstance(o, SemVer) and self._cmp(o) == 0

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.pre))


def parse(ecosystem: str, v: str) -> Any:
    """Parse a version; returns None when it cannot be ordered."""
    try:
        return SemVer(v) if ecosystem == "npm" else Version(v)
    except (InvalidVersion, ValueError):
        return None


def is_prerelease(ecosystem: str, v: str) -> bool:
    p = parse(ecosystem, v)
    return bool(p is not None and p.is_prerelease)


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    parsed = [(parse(ecosystem, v), v) for v in versions]
    ok = [(p, v) for p, v in parsed if p is not None]

    def cmp(a: tuple[Any, str], b: tuple[Any, str]) -> int:
        return -1 if a[0] < b[0] else (1 if a[0] > b[0] else 0)

    return [v for _, v in sorted(ok, key=cmp_to_key(cmp))]


def bump_kind(ecosystem: str, old: str, new: str) -> str:
    a, b = parse(ecosystem, old), parse(ecosystem, new)
    if a is None or b is None:
        return "unknown"
    ra = (a.major, a.minor) if ecosystem == "npm" else (a.release + (0, 0))[:2]
    rb = (b.major, b.minor) if ecosystem == "npm" else (b.release + (0, 0))[:2]
    if ra[0] != rb[0]:
        return "major"
    if ra[1] != rb[1]:
        return "minor"
    return "patch"
