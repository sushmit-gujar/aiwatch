"""Orchestration: inventory a repo, match advisories, attach fixes."""

from __future__ import annotations

import datetime as _dt
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.version import Version

from . import __version__
from .advisories import matcher
from .advisories import versions as V
from .advisories.db import AdvisoryDB
from .inventory import deps as depmod
from .inventory.artifacts import is_artifact, scan_artifacts
from .inventory.code import CodeContext, scan_config_text, scan_notebook, scan_python
from .inventory.mcp import is_mcp_config, scan_mcp
from .inventory.secrets import scan_secrets, wants
from .inventory.walk import iter_files, read_text, rel
from .models import Component, Edit, Finding, Fix, Severity, count_by_severity
from .rules import make

CONFIG_EXT = (".yaml", ".yml", ".toml", ".sh", ".cfg", ".ini", ".env", ".conf")
CONFIG_NAMES = ("Dockerfile", "Makefile", "Procfile", "docker-compose.yml", "compose.yaml")


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        by_cat: dict[str, int] = {}
        for f in self.findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        adv = {f.details.get("advisory") for f in self.findings if f.rule_id in ("AW100", "AW102")}
        return {
            "findings": len(self.findings),
            "by_severity": count_by_severity(self.findings),
            "by_category": dict(sorted(by_cat.items())),
            "advisories": len(adv - {None}),
            "vulnerable_packages": len({(f.details.get("ecosystem"), f.details.get("package"))
                                        for f in self.findings
                                        if f.rule_id in ("AW100", "AW102")}),
            "fixable": sum(1 for f in self.findings if f.fix),
            "components": len(self.components),
            "pinned_components": sum(1 for c in self.components if c.pinned),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "aiwatch", "version": __version__},
            "root": self.root,
            "meta": self.meta,
            "summary": self.summary(),
            "components": [
                {"ecosystem": c.ecosystem, "name": c.name, "version": c.version, "file": c.file,
                 "line": c.line, "kind": c.kind, "direct": c.direct}
                for c in self.components
            ],
            "findings": [f.to_dict() for f in self.findings],
        }


def _dep_fix(c: Component, target: str | None) -> Fix | None:
    if not target:
        return None
    if c.span is None:
        return Fix(f"upgrade {c.name} to {target} (lockfile: regenerate, e.g. "
                   f"`uv lock --upgrade-package {c.name}=={target}`)", [], "manual", target)
    kind = V.bump_kind(c.ecosystem, c.version or "", target)
    return Fix(f"bump {c.name} {c.version} -> {target} ({kind})",
               [Edit(c.file, c.span[0], c.span[1], target)], "safe" if kind == "patch" else
               "review", target)


def scan(target: str | Path, db: AdvisoryDB | None = None, *, artifacts: bool = True,
         secrets: bool = True, fix_min_severity: Severity = Severity.INFO) -> ScanResult:
    """Scan a repo. ``fix_min_severity`` limits which advisories drive the version target."""
    t0 = time.perf_counter()
    root = Path(target)
    db = db or AdvisoryDB()
    files = list(iter_files(root))
    res = ScanResult(root=str(target))

    # 1. dependencies -------------------------------------------------------------------------
    comps = depmod.collect(root, files)
    # 2. MCP configs (also yields npm/PyPI components) -------------------------------------
    mcp_files: list[tuple[str, str]] = []
    for p in files:
        r = rel(root, p)
        if p.suffix == ".json" or "mcp" in p.name:
            text = read_text(p)
            if text and is_mcp_config(r, text):
                mcp_files.append((r, text))

    # Prefetch advisories for everything we will look up (parallel, live mode only).
    keys = sorted({(c.ecosystem, c.name) for c in comps if c.pinned})
    db.prefetch(keys)
    t_fetch = time.perf_counter()

    for r, text in mcp_files:
        fs, cs = scan_mcp(text, r, db)
        res.findings += fs
        comps += cs
    db.prefetch(sorted({(c.ecosystem, c.name) for c in comps if c.pinned and c.kind == "mcp"}))
    res.components = comps

    locked = {c.name for c in comps if not c.direct}
    for c in comps:
        if not c.pinned:
            if c.ecosystem == "PyPI" and c.name in depmod.AI_PACKAGES and c.name not in locked:
                res.findings.append(make("AW101", f"{c.spec!r} is not pinned", c.file, c.line,
                                         key=c.name, package=c.name))
            continue
        hits = matcher.match(db, c.ecosystem, c.name, c.version or "")
        if not hits:
            continue
        target_v, remaining = matcher.minimal_safe(db, c.ecosystem, c.name, c.version or "",
                                                   hits, int(fix_min_severity))
        if target_v:  # advisories below the threshold may still be open at the target
            remaining = [v["id"] for v in hits
                         if matcher.is_affected(c.ecosystem, c.name, target_v, v)]
        else:
            remaining = [v["id"] for v in hits]
        fix = _dep_fix(c, target_v)
        rule = "AW102" if c.kind == "mcp" else "AW100"
        for v in hits:
            sev = Severity.parse(v["severity"]) if v["severity"] != "UNKNOWN" else Severity.MEDIUM
            fixed = matcher.fixed_in(c.ecosystem, c.name, v)
            f = make(rule, f"{c.name} {c.version}: {v['summary'] or v['id']}", c.file, c.line,
                     key=f"{c.key}|{v['id']}", severity=sev, advisory=v["id"],
                     aliases=v["aliases"][:6], package=c.name, ecosystem=c.ecosystem,
                     version=c.version, fixed_in=fixed[:4], published=v["published"][:10],
                     cvss=v.get("cvss"), references=v["references"],
                     unfixed_at_target=v["id"] in remaining)
            if v.get("cwe"):
                f.cwe = tuple(v["cwe"])
            f.fix = fix if v["id"] not in remaining else None
            res.findings.append(f)

    # 3. code + configs + secrets + artifacts -------------------------------------------
    torch_safe = any(c.name == "torch" and c.version and V.parse("PyPI", c.version) is not None
                     and V.parse("PyPI", c.version) >= Version("2.6") for c in comps)
    ctx = CodeContext(root if root.is_dir() else None, db, torch_safe)
    arts: list[tuple[Path, str]] = []
    n_code = 0
    for p in files:
        r = rel(root, p)
        if artifacts and is_artifact(p):
            arts.append((p, r))
            continue
        is_py = p.suffix == ".py"
        is_nb = p.suffix == ".ipynb"
        is_cfg = p.suffix in CONFIG_EXT or p.name in CONFIG_NAMES or p.name.startswith(".env")
        is_sec = secrets and wants(r)
        if not (is_py or is_nb or is_cfg or is_sec):
            continue
        text = read_text(p)
        if text is None:
            continue
        if is_py:
            n_code += 1
            res.findings += scan_python(text, r, ctx)
        elif is_nb:
            n_code += 1
            res.findings += scan_notebook(text, r, ctx)
        if is_cfg and not depmod.is_requirements(r) and p.name not in ("pyproject.toml",):
            res.findings += scan_config_text(text, r)
        if is_sec:
            res.findings += scan_secrets(text, r)
    art_findings, art_meta = scan_artifacts(root, arts) if artifacts else ([], {})
    res.findings += art_findings

    uniq: dict[str, Finding] = {}
    for f in res.findings:
        uniq.setdefault(f.fingerprint, f)
    res.findings = list(uniq.values())
    res.findings.sort(key=lambda f: (-int(f.severity), f.category, f.file, f.line, f.rule_id,
                                     f.key))
    elapsed = time.perf_counter() - t0
    res.meta = {
        "scanned_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(elapsed, 3),
        "advisory_fetch_seconds": round(t_fetch - t0, 3),
        "advisory_source": db.source,
        "as_of": db.as_of,
        "files": len(files),
        "python_files": n_code,
        "mcp_configs": len(mcp_files),
        "artifacts": art_meta,
        "hf_refs": sorted(ctx.hf_refs),
        "unpinned_components": sum(1 for c in comps if not c.pinned),
        "fetch_errors": db.errors[:10],
    }
    return res
