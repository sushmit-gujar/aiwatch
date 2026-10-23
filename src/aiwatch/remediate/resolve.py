"""Resolver-aware remediation.

Per-package "minimal safe version" bumps are often mutually incompatible (e.g.
``langchain-community 0.3.27`` requires ``langchain<1``). With ``--resolve`` each manifest
is re-resolved by uv with ``--resolution lowest-direct``: vulnerable packages get a floor
(``>=minimal_safe``), other pins stay exact (relaxed to ``>=current`` only if needed), so
the resolver returns the *smallest consistent* set. Resolved versions are re-checked
against the advisories and floors are raised until nothing fixable remains (max 5 rounds).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..advisories import matcher
from ..advisories import versions as V
from ..advisories.db import AdvisoryDB
from ..models import Component, Edit, Finding, Fix

RESOLVABLE = ("requirements", "pyproject")


@dataclass
class Resolution:
    file: str
    ok: bool
    versions: dict[str, str] = field(default_factory=dict)  # name -> resolved (changed only)
    relaxed: list[str] = field(default_factory=list)  # non-vulnerable pins that had to move
    rounds: int = 0
    error: str = ""


def uv_available() -> bool:
    return shutil.which("uv") is not None


def _line(c: Component, op: str | None, ver: str | None) -> str:
    try:
        r = Requirement(c.spec)
    except InvalidRequirement:
        return c.spec
    extras = f"[{','.join(sorted(r.extras))}]" if r.extras else ""
    spec = f"{op}{ver}" if op and ver else str(r.specifier)
    marker = f" ; {r.marker}" if r.marker else ""
    return f"{r.name}{extras}{spec}{marker}"


def _compile(lines: list[str], python: str, platform: str) -> tuple[dict[str, str] | None, str]:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "requirements.in"
        p.write_text("\n".join(lines) + "\n")
        cmd = ["uv", "pip", "compile", str(p), "--resolution", "lowest-direct", "--python-version",
               python, "--python-platform", platform, "--no-header", "--no-annotate", "-q"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        err = [ln.strip() for ln in r.stderr.splitlines() if ln.strip()]
        return None, " ".join(err)[:600]
    out: dict[str, str] = {}
    for ln in r.stdout.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if "==" in ln:
            n, _, v = ln.partition("==")
            out[str(canonicalize_name(n.split("[", 1)[0]))] = v.split(";", 1)[0].strip()
    return out, ""


def co_resolve(db: AdvisoryDB, file: str, comps: list[Component], floors: dict[str, str],
               python: str = "3.12", platform: str = "x86_64-manylinux_2_28",
               max_rounds: int = 5) -> Resolution:
    res = Resolution(file=file, ok=False)
    floors = dict(floors)
    relax = False
    resolved: dict[str, str] | None = None
    for rnd in range(1, max_rounds + 1):
        res.rounds = rnd
        lines = []
        for c in comps:
            if c.name in floors:
                lines.append(_line(c, ">=", floors[c.name]))
            elif c.pinned:
                lines.append(_line(c, ">=" if relax else "==", c.version))
            else:
                lines.append(_line(c, None, None))
        resolved, err = _compile(lines, python, platform)
        if resolved is None:
            if not relax:
                relax = True
                continue
            res.error = err
            return res
        raised = False
        for c in comps:
            nv = resolved.get(c.name)
            if not (c.pinned and nv):
                continue
            hits = matcher.match(db, c.ecosystem, c.name, nv)
            if hits:
                t, _ = matcher.minimal_safe(db, c.ecosystem, c.name, nv, hits)
                if t and t != floors.get(c.name):
                    floors[c.name] = t
                    raised = True
        if not raised:
            break
    assert resolved is not None
    res.ok = True
    for c in comps:
        nv = resolved.get(c.name)
        if c.pinned and nv and nv != c.version:
            res.versions[c.name] = nv
            if c.name not in floors:
                res.relaxed.append(c.name)
    return res


def apply_resolution(findings: list[Finding], comps: list[Component], db: AdvisoryDB,
                     python: str = "3.12", platform: str = "x86_64-manylinux_2_28"
                     ) -> tuple[list[Resolution], list[Fix]]:
    """Rewrite dependency fixes so each manifest's bumps form one resolvable set."""
    by_file: dict[str, list[Component]] = {}
    for c in comps:
        if c.kind in RESOLVABLE and c.direct and c.ecosystem == "PyPI":
            by_file.setdefault(c.file, []).append(c)
    dep_findings: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.rule_id == "AW100" and f.file in by_file:
            dep_findings.setdefault((f.file, str(f.details["package"])), []).append(f)
    results, extra = [], []
    for file, cs in sorted(by_file.items()):
        floors = {}
        for (ff, name), fs in dep_findings.items():
            if ff == file:
                t = next((f.fix.to_version for f in fs if f.fix and f.fix.to_version), None)
                if t:
                    floors[name] = t
        if not floors:
            continue
        r = co_resolve(db, file, cs, floors, python, platform)
        results.append(r)
        if not r.ok:
            continue
        for c in cs:
            nv = r.versions.get(c.name)
            if not nv or c.span is None:
                continue
            kind = V.bump_kind("PyPI", c.version or "", nv)
            fs = dep_findings.get((file, c.name), [])
            fix = Fix(f"bump {c.name} {c.version} -> {nv} ({kind}, co-resolved"
                      + (", required by the resolver" if c.name in r.relaxed else "") + ")",
                      [Edit(c.file, c.span[0], c.span[1], nv)],
                      "safe" if kind == "patch" else "review", nv)
            if fs:
                for f in fs:
                    adv = next((v for v in db.vulns("PyPI", c.name)
                                if v["id"] == f.details.get("advisory")), None)
                    f.fix = None if adv and matcher.is_affected("PyPI", c.name, nv, adv) else fix
            else:
                extra.append(fix)
    return results, extra
