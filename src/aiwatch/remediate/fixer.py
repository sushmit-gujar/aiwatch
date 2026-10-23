"""Plan, preview (unified diff), apply, or commit fixes on a branch."""

from __future__ import annotations

import datetime as _dt
import difflib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Edit, Finding, Fix

SAFETY_LEVELS = {"safe": 0, "review": 1, "manual": 2}


@dataclass
class Plan:
    fixes: list[tuple[Fix, list[Finding]]] = field(default_factory=list)
    skipped: list[tuple[Fix, str]] = field(default_factory=list)
    manual: list[Finding] = field(default_factory=list)  # findings without an automatic fix
    edits: dict[str, list[Edit]] = field(default_factory=dict)

    @property
    def files(self) -> list[str]:
        return sorted(self.edits)

    def resolves(self) -> int:
        return sum(len(fs) for _, fs in self.fixes)


def plan(findings: list[Finding], max_safety: str = "review",
         extra: list[Fix] | None = None) -> Plan:
    pl = Plan()
    limit = SAFETY_LEVELS[max_safety]
    grouped: dict[int, tuple[Fix, list[Finding]]] = {}
    for f in findings:
        if f.fix is None or not f.fix.edits:
            pl.manual.append(f)
            continue
        if SAFETY_LEVELS.get(f.fix.safety, 2) > limit:
            pl.skipped.append((f.fix, f"safety={f.fix.safety} > {max_safety}"))
            continue
        grouped.setdefault(id(f.fix), (f.fix, []))[1].append(f)
    for fx in extra or []:
        if SAFETY_LEVELS.get(fx.safety, 2) <= limit:
            grouped[id(fx)] = (fx, [])
    seen: set[tuple[str, int, int, str]] = set()
    for fix, fs in grouped.values():
        new_edits = []
        conflict = False
        for e in fix.edits:
            k = (e.file, e.start, e.end, e.new)
            if k in seen:
                continue
            for o in pl.edits.get(e.file, []):
                if e.start < o.end and o.start < e.end or (e.start == e.end == o.start):
                    conflict = True
            new_edits.append(e)
        if conflict:
            pl.skipped.append((fix, "overlaps another fix; re-run after applying"))
            continue
        for e in new_edits:
            seen.add((e.file, e.start, e.end, e.new))
            pl.edits.setdefault(e.file, []).append(e)
        pl.fixes.append((fix, fs))
    return pl


def _apply_text(text: str, edits: list[Edit]) -> str:
    for e in sorted(edits, key=lambda e: (e.start, e.end), reverse=True):
        text = text[: e.start] + e.new + text[e.end:]
    return text


def render(root: Path, pl: Plan) -> dict[str, tuple[str, str]]:
    out = {}
    for f, edits in pl.edits.items():
        p = root / f if root.is_dir() else root
        old = p.read_text(encoding="utf-8")
        out[f] = (old, _apply_text(old, edits))
    return out


def diff(root: Path, pl: Plan) -> str:
    chunks: list[str] = []
    for f, (old, new) in render(root, pl).items():
        chunks += difflib.unified_diff(old.splitlines(keepends=True),
                                       new.splitlines(keepends=True), f"a/{f}", f"b/{f}")
    return "".join(chunks)


def apply(root: Path, pl: Plan) -> list[str]:
    changed = []
    for f, (old, new) in render(root, pl).items():
        if old != new:
            p = root / f if root.is_dir() else root
            p.write_text(new, encoding="utf-8")
            changed.append(f)
    return changed


def summary_markdown(pl: Plan) -> str:
    lines = ["## aiwatch automated fixes", ""]
    for fix, fs in pl.fixes:
        ids = sorted({str(f.details.get("advisory") or f.rule_id) for f in fs})
        lines.append(f"- **{fix.description}** · `{fix.safety}` · resolves {len(fs)} finding(s): "
                     + ", ".join(ids[:8]) + (" …" if len(ids) > 8 else ""))
    if pl.manual:
        lines += ["", f"{len(pl.manual)} finding(s) need manual action (no safe automatic fix)."]
    if pl.skipped:
        lines += [f"{len(pl.skipped)} fix(es) skipped (safety level or overlap)."]
    lines += ["", "Review `review`-level changes (minor/major bumps, loader flags) before merging;"
              " run your test suite."]
    return "\n".join(lines) + "\n"


def commit_branch(root: Path, pl: Plan, branch: str | None = None) -> str:
    """Apply on a new git branch and commit (PR-ready). Never pushes."""
    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True,
                              text=True).stdout.strip()

    branch = branch or f"aiwatch/fix-{_dt.date.today().isoformat()}"
    git("rev-parse", "--is-inside-work-tree")
    git("checkout", "-b", branch)
    changed = apply(root, pl)
    if changed:
        git("add", "--", *changed)
        msg = f"fix(security): aiwatch remediation ({pl.resolves()} findings)\n\n" + \
            summary_markdown(pl)
        git("commit", "-m", msg)
    return branch
