"""OSV affected-range evaluation and minimal-safe-version selection."""

from __future__ import annotations

from typing import Any

from packaging.utils import canonicalize_name

from . import versions as V
from .db import AdvisoryDB


def _norm(eco: str, name: str) -> str:
    return canonicalize_name(name) if eco == "PyPI" else name


def _in_range(eco: str, ver: Any, events: list[dict[str, str]]) -> bool:
    """OSV range semantics: walk sorted events, introduced opens, fixed/last_affected close."""
    evs: list[tuple[Any, str, int]] = []
    for e in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in e:
                raw = e[kind]
                if kind == "introduced" and raw == "0":
                    evs.append((None, kind, 0))
                else:
                    p = V.parse(eco, raw)
                    if p is None:
                        return False
                    evs.append((p, kind, 1))
    affected = False
    # "introduced: 0" first, then by version; on ties process closing events after opening.
    order = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}
    for p, kind, _ in _sort(evs, order):
        if kind == "introduced":
            if p is None or ver >= p:
                affected = True
        elif kind == "fixed" or kind == "limit":
            if ver >= p:
                affected = False
        elif kind == "last_affected" and ver > p:
            affected = False
    return affected


def _sort(evs: list[tuple[Any, str, int]], order: dict[str, int]) -> list[tuple[Any, str, int]]:
    zero = [e for e in evs if e[0] is None]
    rest = [e for e in evs if e[0] is not None]
    # insertion sort with rich comparison (SemVer / Version are both orderable)
    out: list[tuple[Any, str, int]] = []
    for e in rest:
        i = len(out)
        while i > 0 and (out[i - 1][0] > e[0] or
                         (out[i - 1][0] == e[0] and order[out[i - 1][1]] > order[e[1]])):
            i -= 1
        out.insert(i, e)
    return zero + out


def is_affected(eco: str, name: str, version: str, vuln: dict[str, Any]) -> bool:
    ver = V.parse(eco, version)
    n = _norm(eco, name)
    for a in vuln.get("affected", []):
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != eco or _norm(eco, pkg.get("name") or "") != n:
            continue
        if version in (a.get("versions") or []):
            return True
        if ver is None:
            continue
        for r in a.get("ranges") or []:
            if _in_range(eco, ver, r.get("events", [])):
                return True
    return False


def fixed_in(eco: str, name: str, vuln: dict[str, Any]) -> list[str]:
    n = _norm(eco, name)
    out = []
    for a in vuln.get("affected", []):
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != eco or _norm(eco, pkg.get("name") or "") != n:
            continue
        for r in a.get("ranges") or []:
            out += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return V.sort_versions(eco, sorted(set(out)))


def match(db: AdvisoryDB, eco: str, name: str, version: str) -> list[dict[str, Any]]:
    return [v for v in db.vulns(eco, name) if is_affected(eco, name, version, v)]


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "UNKNOWN": 2, "LOW": 1}


def minimal_safe(db: AdvisoryDB, eco: str, name: str, version: str,
                 current: list[dict[str, Any]] | None = None,
                 min_severity: int = 0) -> tuple[str | None, list[str]]:
    """Smallest release > version that clears the most advisories.

    Returns (target_version, ids_still_affecting_target). Pre-releases are skipped unless the
    current version is one. Candidates come from the package index so yanked releases and
    versions that never shipped are excluded; when the index is unavailable the advisories'
    own ``fixed`` versions are used.
    """
    vulns = [v for v in db.vulns(eco, name) if SEV_RANK.get(v["severity"], 2) >= min_severity]
    if current is None:
        current = [v for v in vulns if is_affected(eco, name, version, v)]
    current = [v for v in current if SEV_RANK.get(v["severity"], 2) >= min_severity]
    if not current:
        return None, []
    cur = V.parse(eco, version)
    allow_pre = V.is_prerelease(eco, version)
    cands = db.releases(eco, name)
    if not cands:
        cands = sorted({f for v in current for f in fixed_in(eco, name, v)})
    cands = [c for c in V.sort_versions(eco, cands)
             if (allow_pre or not V.is_prerelease(eco, c)) and cur is not None
             and V.parse(eco, c) > cur]
    fixes = {v["id"]: [V.parse(eco, f) for f in fixed_in(eco, name, v)] for v in current}

    def confirmed(c: str) -> bool:
        # c must be at/after a published fix for every advisory that has one. Avoids picking
        # versions that are merely absent from a range (e.g. a scheme change 2025.7.1 -> 1.0.0).
        pc = V.parse(eco, c)
        return all(any(f is not None and pc >= f for f in fs) for fs in fixes.values() if fs)

    best: tuple[int, str] | None = None
    best_remaining: list[str] = []
    for pool in ([c for c in cands if confirmed(c)], cands):
        for c in pool:
            remaining = [v["id"] for v in vulns if is_affected(eco, name, c, v)]
            if best is None or len(remaining) < best[0]:
                best, best_remaining = (len(remaining), c), remaining
                if not remaining:
                    break
        if best is not None and best[0] == 0:
            break
    if best is None or best[0] >= len(current):
        return None, [v["id"] for v in current]
    return best[1], best_remaining
