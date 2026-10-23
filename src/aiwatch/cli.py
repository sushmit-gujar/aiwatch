"""Command-line interface: scan · fix · monitor · db snapshot · rules."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .advisories.db import AdvisoryDB
from .models import Severity
from .remediate import fixer
from .report import html as html_report
from .report import markdown, sarif, text
from .rules import ATLAS_NAMES, RULES
from .scanner import ScanResult, scan


def _db_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("advisory data")
    g.add_argument("--db", help="offline snapshot (.json.gz) from `aiwatch db snapshot`")
    g.add_argument("--offline", action="store_true", help="use only --db; no network")
    g.add_argument("--as-of", metavar="YYYY-MM-DD",
                   help="ignore advisories published after this date (time-travel / testing)")
    g.add_argument("--cache-dir", help="HTTP cache dir (default ~/.cache/aiwatch)")
    p.add_argument("--no-artifacts", action="store_true", help="skip model-artifact scanning")
    p.add_argument("--fix-min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="only advisories at/above this severity drive the version target "
                   "(e.g. high = smallest bump that clears all high+critical)")


def _make_db(a: argparse.Namespace) -> AdvisoryDB:
    return AdvisoryDB(snapshot=a.db, offline=a.offline, cache_dir=a.cache_dir, as_of=a.as_of)


def _git_prefix(path: Path) -> str:
    """Path of the scan root relative to its git work tree (for SARIF URIs)."""
    p = path.resolve()
    if p.is_file():
        p = p.parent
    try:
        top = subprocess.run(["git", "-C", str(p), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""
    r = p.relative_to(Path(top).resolve()).as_posix()
    return "" if r == "." else r


def _write(path: str | None, content: str) -> None:
    if not path or path == "-":
        sys.stdout.write(content)
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def _outputs(res: ScanResult, a: argparse.Namespace, delta=None, runs=None) -> None:  # noqa: ANN001
    if getattr(a, "sarif", None):
        _write(a.sarif, json.dumps(sarif.render(res, _git_prefix(Path(a.path))), indent=1))
    if getattr(a, "html", None):
        _write(a.html, html_report.render(res, delta, runs, getattr(a, "title", None)))
    if getattr(a, "json", None):
        d = res.to_dict()
        if delta is not None:
            d["monitor"] = {"run_id": delta.run_id, "first_run": delta.first_run,
                            **delta.counts(),
                            "resolved_findings": delta.resolved}
        _write(a.json, json.dumps(d, indent=1))
    if getattr(a, "md", None):
        _write(a.md, markdown.render(res, delta, getattr(a, "dashboard_url", None)))


def cmd_scan(a: argparse.Namespace) -> int:
    db = _make_db(a)
    res = scan(a.path, db, artifacts=not a.no_artifacts,
               fix_min_severity=Severity.parse(a.fix_min_severity))
    fmt = a.format
    if fmt == "text":
        _write(a.output, text.render(res, color=sys.stdout.isatty() and not a.output))
    elif fmt == "json":
        _write(a.output, json.dumps(res.to_dict(), indent=1))
    elif fmt == "sarif":
        _write(a.output, json.dumps(sarif.render(res, _git_prefix(Path(a.path))), indent=1))
    elif fmt == "md":
        _write(a.output, markdown.render(res, None))
    elif fmt == "html":
        _write(a.output, html_report.render(res, title=a.title))
    _outputs(res, a)
    if a.fail_on != "none":
        th = Severity.parse(a.fail_on)
        if any(f.severity >= th for f in res.findings):
            return 1
    return 0


def cmd_fix(a: argparse.Namespace) -> int:
    root = Path(a.path)
    db = _make_db(a)
    before = scan(root, db, artifacts=not a.no_artifacts,
                 fix_min_severity=Severity.parse(a.fix_min_severity))
    extra: list = []
    if a.resolve:
        from .remediate import resolve as rs

        if not rs.uv_available():
            print("--resolve needs `uv` on PATH (pip install uv)", file=sys.stderr)
            return 2
        results, extra = rs.apply_resolution(before.findings, before.components, db,
                                             a.python_version, a.python_platform)
        for r in results:
            if r.ok:
                print(f"co-resolved {r.file} in {r.rounds} round(s)"
                      + (f"; also moved {', '.join(r.relaxed)}" if r.relaxed else ""),
                      file=sys.stderr)
            else:
                print(f"could not co-resolve {r.file}: {r.error}", file=sys.stderr)
    pl = fixer.plan(before.findings, a.max_safety, extra)
    d = fixer.diff(root, pl)
    print(f"aiwatch fix: {len(pl.fixes)} fix(es) over {len(pl.files)} file(s) resolve "
          f"{pl.resolves()} of {len(before.findings)} findings · {len(pl.manual)} need manual "
          f"action · {len(pl.skipped)} skipped", file=sys.stderr)
    for fix, fs in pl.fixes:
        print(f"  [{fix.safety}] {fix.description} ({len(fs)} finding(s))", file=sys.stderr)
    if a.patch:
        _write(a.patch, d)
    if a.pr_body:
        _write(a.pr_body, fixer.summary_markdown(pl))
    if a.branch is not None:
        b = fixer.commit_branch(root, pl, a.branch or None)
        print(f"committed on branch {b} (not pushed)", file=sys.stderr)
    elif a.apply:
        changed = fixer.apply(root, pl)
        print(f"applied to {len(changed)} file(s)", file=sys.stderr)
    else:
        if not a.patch:
            sys.stdout.write(d)
        print("(dry run: nothing written; use --apply, --patch FILE or --branch)",
              file=sys.stderr)
        return 0
    after = scan(root, db, artifacts=not a.no_artifacts,
                 fix_min_severity=Severity.parse(a.fix_min_severity))
    bs, as_ = before.summary(), after.summary()
    print(f"re-scan: findings {bs['findings']} -> {as_['findings']} · advisories "
          f"{bs['advisories']} -> {as_['advisories']} · critical+high "
          f"{bs['by_severity']['critical'] + bs['by_severity']['high']} -> "
          f"{as_['by_severity']['critical'] + as_['by_severity']['high']}", file=sys.stderr)
    return 0


def cmd_monitor(a: argparse.Namespace) -> int:
    from .monitor.state import State

    db = _make_db(a)
    res = scan(a.path, db, artifacts=not a.no_artifacts,
               fix_min_severity=Severity.parse(a.fix_min_severity))
    st = State(a.state)
    delta = st.record(res)
    runs = st.runs()
    st.close()
    _write(a.output, text.render(res, delta, color=sys.stdout.isatty() and not a.output))
    _outputs(res, a, delta, runs)
    c = delta.counts()
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"new={c['new']}\nknown={c['known']}\nresolved={c['resolved']}\n"
                     f"total={len(res.findings)}\nfirst_run={str(delta.first_run).lower()}\n"
                     f"run_id={delta.run_id}\n")
    if a.fail_on_new != "none":
        th = Severity.parse(a.fail_on_new)
        if any(f.severity >= th for f in delta.new):
            return 1
    return 0


def cmd_snapshot(a: argparse.Namespace) -> int:
    db = AdvisoryDB(cache_dir=a.cache_dir)
    keys: set[str] = set()
    for p in a.paths:
        res = scan(p, db, artifacts=False, secrets=False)
        for c in res.components:
            keys.add(f"{c.ecosystem}:{c.name}")
        for f in res.findings:
            if f.rule_id == "AW300":
                keys.add(f"{f.details['ecosystem']}:{f.details['package']}")
    for k in a.package or []:
        eco, _, name = k.partition(":")
        db.vulns(eco, name)
        db.releases(eco, name)
        keys.add(k)
    for k in sorted(keys):
        eco, _, name = k.partition(":")
        db.releases(eco, name)  # minimal-safe-version candidates
    counts = db.save_snapshot(Path(a.out), keys)
    n_adv = sum(len(v or []) for v in {**db.data["osv"], **db.fetched["osv"]}.values())
    print(f"snapshot {a.out}: {counts['osv']} packages, {n_adv} advisories (deduplicated), "
          f"{counts['hf']} HF models", file=sys.stderr)
    return 0


def cmd_rules(a: argparse.Namespace) -> int:
    for r in RULES.values():
        tags = ", ".join([*(o.split(" ")[0] for o in r.owasp),
                          *(f"{x} ({ATLAS_NAMES.get(x, '')})" for x in r.atlas), *r.cwe])
        print(f"{r.id}  {r.default_severity.label:8} {r.category:10} {r.title}\n"
              f"        {tags}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiwatch", description="Find, fix and continuously monitor "
                                "vulnerabilities in AI/LLM application stacks.")
    p.add_argument("--version", action="version", version=f"aiwatch {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="inventory + match advisories + risky patterns")
    s.add_argument("path")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "md", "html"],
                   default="text")
    s.add_argument("-o", "--output")
    s.add_argument("--sarif")
    s.add_argument("--html")
    s.add_argument("--json")
    s.add_argument("--title")
    s.add_argument("--fail-on", default="none",
                   choices=["none", "info", "low", "medium", "high", "critical"])
    _db_args(s)
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="compute fixes; dry-run diff by default")
    f.add_argument("path")
    f.add_argument("--apply", action="store_true", help="write changes in place")
    f.add_argument("--patch", help="write a unified diff to this file")
    f.add_argument("--branch", nargs="?", const="", default=None,
                   help="apply on a new git branch and commit (PR-ready; never pushes)")
    f.add_argument("--pr-body", help="write a Markdown PR description")
    f.add_argument("--max-safety", choices=["safe", "review"], default="review",
                   help="safe = patch bumps + pins only; review (default) adds minor/major "
                   "bumps and loader-flag rewrites")
    f.add_argument("--resolve", action="store_true",
                   help="co-resolve bumps per manifest with uv (lowest-direct) so the fixed "
                   "set installs together")
    f.add_argument("--python-version", default="3.12")
    f.add_argument("--python-platform", default="x86_64-manylinux_2_28")
    _db_args(f)
    f.set_defaults(func=cmd_fix)

    m = sub.add_parser("monitor", help="scan, diff against stored state, report new vs known")
    m.add_argument("path")
    m.add_argument("--state", default=".aiwatch/state.db")
    m.add_argument("-o", "--output")
    m.add_argument("--sarif")
    m.add_argument("--html")
    m.add_argument("--json")
    m.add_argument("--md", help="Markdown summary (issue body)")
    m.add_argument("--title")
    m.add_argument("--dashboard-url")
    m.add_argument("--fail-on-new", default="none",
                   choices=["none", "info", "low", "medium", "high", "critical"])
    _db_args(m)
    m.set_defaults(func=cmd_monitor)

    d = sub.add_parser("db", help="advisory data utilities")
    dsub = d.add_subparsers(dest="dbcmd", required=True)
    sn = dsub.add_parser("snapshot", help="fetch live data for the packages in PATHS and save it")
    sn.add_argument("paths", nargs="*")
    sn.add_argument("--package", action="append", metavar="ECOSYSTEM:NAME")
    sn.add_argument("--out", required=True)
    sn.add_argument("--cache-dir")
    sn.set_defaults(func=cmd_snapshot)

    r = sub.add_parser("rules", help="list rules with OWASP LLM / MITRE ATLAS / CWE mappings")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return int(a.func(a))
