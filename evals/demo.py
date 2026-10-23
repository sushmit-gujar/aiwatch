"""Reproducible find -> monitor -> drift -> fix -> re-scan demo on the vulnerable fixture.

Runs fully offline against the committed OSV snapshot (data/osv-snapshot.json.gz), so every
number in results/demo.json is reproducible:  python evals/demo.py
With --live it also times a cold-cache live scan (api.osv.dev) and, if `uv` is installed,
verifies that the resolver-aware fix (`aiwatch fix --resolve`) installs as one set.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from aiwatch import __version__
from aiwatch.advisories.db import AdvisoryDB
from aiwatch.monitor.state import State
from aiwatch.remediate import fixer
from aiwatch.report import html
from aiwatch.scanner import scan

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "vulnerable-llm-app"
SNAP = ROOT / "data" / "osv-snapshot.json.gz"
OUT = ROOT / "results"
BASELINE_AS_OF = "2025-06-30"

DRIFT_PY = '''"""Added later: fine-tuning helper (drift)."""
import torch
from transformers import AutoModelForCausalLM

base = AutoModelForCausalLM.from_pretrained("microsoft/Phi-3-mini-4k-instruct", trust_remote_code=True)


def resume(path):
    return torch.load(path, weights_only=False)
'''


def summ(res, delta=None):
    s = res.summary()
    d = {"findings": s["findings"], "advisories": s["advisories"],
         "vulnerable_packages": s["vulnerable_packages"],
         "critical_high": s["by_severity"]["critical"] + s["by_severity"]["high"],
         "by_severity": s["by_severity"], "by_category": s["by_category"],
         "fixable": s["fixable"], "scan_seconds": res.meta["seconds"]}
    if delta is not None:
        d["monitor"] = delta.counts()
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp()) / "vulnerable-llm-app"
    shutil.copytree(FIXTURE, work)
    st = State(work.parent / "state.db")
    old_db = AdvisoryDB(snapshot=SNAP, offline=True, as_of=BASELINE_AS_OF)
    db = AdvisoryDB(snapshot=SNAP, offline=True)
    steps = {}

    r1 = scan(work, old_db)
    d1 = st.record(r1)
    steps["1_baseline"] = {"note": f"advisories published <= {BASELINE_AS_OF}", **summ(r1, d1)}

    r2 = scan(work, db)
    d2 = st.record(r2)
    steps["2_rescan_new_advisories"] = {
        "note": "same code, advisory data as of the snapshot date",
        **summ(r2, d2),
        "new_by_package": _by_pkg(d2.new)}

    (work / "app" / "finetune.py").write_text(DRIFT_PY)
    with open(work / "requirements.txt", "a") as fh:
        fh.write("llama-cpp-python==0.2.71\n")
    r3 = scan(work, db)
    d3 = st.record(r3)
    steps["3_drift"] = {"note": "added app/finetune.py and llama-cpp-python==0.2.71",
                        **summ(r3, d3),
                        "new": [{"rule": f.rule_id, "change": f.change, "file": f.file,
                                 "line": f.line, "message": f.message[:120]} for f in d3.new]}
    (OUT / "dashboard-before-fix.html").write_text(
        html.render(r3, d3, st.runs(), "examples/vulnerable-llm-app (demo, run 3: drift)"))

    pl = fixer.plan(r3.findings)
    patch = fixer.diff(work, pl)
    (OUT / "demo-fix.patch").write_text(patch)
    fixer.apply(work, pl)
    r4 = scan(work, db)
    d4 = st.record(r4)
    remaining: dict[str, int] = {}
    for f in r4.findings:
        remaining[f.rule_id] = remaining.get(f.rule_id, 0) + 1
    steps["4_after_fix"] = {
        "note": "aiwatch fix (default --max-safety review), then re-scan",
        "fixes_applied": len(pl.fixes), "files_changed": len(pl.files),
        "findings_resolved_by_fix": pl.resolves(),
        "patch_lines": patch.count("\n"),
        **summ(r4, d4), "remaining_by_rule": dict(sorted(remaining.items()))}
    (OUT / "dashboard.html").write_text(
        html.render(r4, d4, st.runs(), "examples/vulnerable-llm-app (demo, run 4: after fix)"))
    st.close()

    out = {"tool": f"aiwatch {__version__}", "python": platform.python_version(),
           "platform": f"{platform.system()} {platform.machine()}",
           "snapshot": db.snapshot_meta, "baseline_as_of": BASELINE_AS_OF, "steps": steps}

    if a.live:
        live = {}
        with tempfile.TemporaryDirectory() as cache:
            t = time.perf_counter()
            res = scan(FIXTURE, AdvisoryDB(cache_dir=cache))
            live["cold_cache_seconds"] = round(time.perf_counter() - t, 2)
            live["advisory_fetch_seconds"] = res.meta["advisory_fetch_seconds"]
            live["findings"] = len(res.findings)
            live["advisories"] = res.summary()["advisories"]
            t = time.perf_counter()
            scan(FIXTURE, AdvisoryDB(cache_dir=cache))
            live["warm_cache_seconds"] = round(time.perf_counter() - t, 2)
        if shutil.which("uv"):
            w2 = Path(tempfile.mkdtemp()) / "app"
            shutil.copytree(FIXTURE, w2)
            t = time.perf_counter()
            p = subprocess.run([sys.executable, "-m", "aiwatch", "fix", str(w2), "--resolve",
                                "--apply", "--db", str(SNAP)], capture_output=True, text=True)
            live["resolve_fix_seconds"] = round(time.perf_counter() - t, 2)
            live["resolve_log"] = [ln for ln in p.stderr.splitlines()
                                   if ln.startswith(("co-resolved", "could not", "re-scan"))]
            checks = {}
            for f in ("requirements.txt", "serving/pyproject.toml"):
                c = subprocess.run(["uv", "pip", "compile", f, "--python-version", "3.12",
                                    "--python-platform", "x86_64-manylinux_2_28", "-q", "-o",
                                    "/dev/null"], cwd=w2, capture_output=True, text=True)
                checks[f] = "resolves" if c.returncode == 0 else c.stderr.strip()[:300]
            # the naive per-package bump for comparison
            w3 = Path(tempfile.mkdtemp()) / "app"
            shutil.copytree(FIXTURE, w3)
            fixer.apply(w3, fixer.plan(scan(w3, db).findings))
            c = subprocess.run(["uv", "pip", "compile", "requirements.txt", "--python-version",
                                "3.12", "--python-platform", "x86_64-manylinux_2_28", "-q", "-o",
                                "/dev/null"], cwd=w3, capture_output=True, text=True)
            checks["naive_per_package_requirements.txt"] = "resolves" if c.returncode == 0 \
                else c.stderr.strip().splitlines()[-1][:300]
            live["install_check_uv_py312"] = checks
            live["resolved_requirements"] = (w2 / "requirements.txt").read_text().splitlines()
        out["live"] = live
    (OUT / "demo.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0


def _by_pkg(fs):
    c: dict[str, int] = {}
    for f in fs:
        k = str(f.details.get("package", f.rule_id))
        c[k] = c.get(k, 0) + 1
    return dict(sorted(c.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
