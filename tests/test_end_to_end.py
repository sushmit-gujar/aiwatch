"""End-to-end on the committed vulnerable fixture, fully offline (committed OSV snapshot)."""

import ast
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aiwatch import cli
from aiwatch.advisories.db import AdvisoryDB
from aiwatch.monitor.state import State
from aiwatch.remediate import fixer
from aiwatch.report import html, markdown, sarif
from aiwatch.scanner import scan

from .conftest import SNAPSHOT


def test_fixture_scan_finds_every_surface(fixture_copy, snapshot_db):
    res = scan(fixture_copy, snapshot_db)
    s = res.summary()
    cats = s["by_category"]
    for c in ("dependency", "code", "config", "mcp", "secret", "model"):
        assert cats.get(c, 0) > 0, c
    assert s["advisories"] >= 200 and s["vulnerable_packages"] >= 12
    pk = {f.details.get("package") for f in res.findings if f.rule_id in ("AW100", "AW102")}
    for p in ("torch", "transformers", "langchain", "vllm", "mlflow", "gradio", "llama-index",
              "mcp-remote", "@modelcontextprotocol/server-filesystem"):
        assert p in pk
    torch_ids = {f.details["advisory"] for f in res.findings
                 if f.details.get("package") == "torch"}
    assert "GHSA-53q9-r3pm-6pq6" in torch_ids  # CVE-2025-32434 torch.load weights_only RCE
    for f in res.findings:
        assert f.owasp or f.cwe


def test_fix_then_rescan(fixture_copy, snapshot_db):
    before = scan(fixture_copy, snapshot_db)
    pl = fixer.plan(before.findings)
    changed = fixer.apply(fixture_copy, pl)
    assert set(changed) >= {"requirements.txt", "serving/pyproject.toml", ".cursor/mcp.json",
                            "app/model.py", "app/rag.py", "app/ui.py"}
    for p in fixture_copy.rglob("*.py"):
        ast.parse(p.read_text())
    json.loads((fixture_copy / ".cursor/mcp.json").read_text())
    after = scan(fixture_copy, snapshot_db)
    assert after.summary()["advisories"] == 0
    assert len(after.findings) == len(pl.manual)
    # idempotent
    assert fixer.plan(after.findings).edits == {}


def test_monitor_new_vs_known_drift_and_resolved(fixture_copy, tmp_path):
    st = State(tmp_path / "state.db")
    old = AdvisoryDB(snapshot=SNAPSHOT, offline=True, as_of="2025-06-30")
    d1 = st.record(scan(fixture_copy, old))
    assert d1.first_run and d1.known == [] and len(d1.new) > 0
    now = AdvisoryDB(snapshot=SNAPSHOT, offline=True)
    d2 = st.record(scan(fixture_copy, now))
    c2 = d2.counts()
    assert c2["new"] > 0 and c2["known"] == len(d1.new) and c2["resolved"] == 0
    assert set(f.change for f in d2.new) == {"newly-disclosed"}
    # drift: a new risky pattern + a moved (not changed) existing line
    p = fixture_copy / "app" / "model.py"
    p.write_text("# moved\n\n" + p.read_text())
    (fixture_copy / "app" / "extra.py").write_text(
        "import torch\nw = torch.load('w.pt', weights_only=False)\n")
    d3 = st.record(scan(fixture_copy, now))
    assert [(f.rule_id, f.change) for f in d3.new] == [("AW200", "drift")]
    # fix -> resolved
    res = scan(fixture_copy, now)
    fixer.apply(fixture_copy, fixer.plan(res.findings))
    d4 = st.record(scan(fixture_copy, now))
    assert d4.counts()["new"] == 0 and d4.counts()["resolved"] > 200
    # regression: revert one fix
    shutil.copy(Path(__file__).resolve().parents[1] / "examples/vulnerable-llm-app/app/ui.py",
                fixture_copy / "app/ui.py")
    d5 = st.record(scan(fixture_copy, now))
    assert [(f.rule_id, f.change) for f in d5.new] == [("AW208", "regressed")]
    assert len(st.runs()) == 5
    st.close()


def test_reports(fixture_copy, snapshot_db, tmp_path):
    res = scan(fixture_copy, snapshot_db)
    st = State(tmp_path / "s.db")
    delta = st.record(res)
    doc = sarif.render(res, "examples/app")
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and len(run["results"]) == len(res.findings)
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for r in run["results"]:
        assert r["ruleId"] in ids and r["partialFingerprints"]["aiwatch/v1"]
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].startswith("examples/app/")
        assert loc["region"]["startLine"] >= 1
    page = html.render(res, delta, st.runs())
    assert "<script" in page and "aw-data" in page and "LLM03" in page
    md = markdown.render(res, delta, "https://example.org/dash")
    assert md.startswith("<!-- aiwatch-monitor -->") and "| new |" in md
    st.close()


def test_cli_scan_fix_monitor(fixture_copy, tmp_path, capsys):
    db = ["--db", str(SNAPSHOT), "--offline"]
    assert cli.main(["scan", str(fixture_copy), *db, "--fail-on", "critical"]) == 1
    assert cli.main(["scan", str(fixture_copy), *db, "-f", "sarif", "-o",
                     str(tmp_path / "o.sarif")]) == 0
    json.loads((tmp_path / "o.sarif").read_text())
    orig = (fixture_copy / "requirements.txt").read_text()
    assert cli.main(["fix", str(fixture_copy), *db]) == 0
    assert "+torch==" in capsys.readouterr().out
    assert (fixture_copy / "requirements.txt").read_text() == orig  # dry run
    assert cli.main(["fix", str(fixture_copy), *db, "--patch", str(tmp_path / "f.patch"),
                     "--max-safety", "safe"]) == 0
    patch = (tmp_path / "f.patch").read_text()
    assert "jinja2==3.1.6" in patch and "torch==" not in patch  # minor bumps need review
    state = tmp_path / "st.db"
    args = ["monitor", str(fixture_copy), "--state", str(state), *db, "--json",
            str(tmp_path / "m.json"), "--md", str(tmp_path / "m.md"), "--html",
            str(tmp_path / "m.html")]
    assert cli.main(args) == 0
    assert cli.main([*args, "--fail-on-new", "low"]) == 0  # nothing new on second run
    m = json.loads((tmp_path / "m.json").read_text())["monitor"]
    assert m["new"] == 0 and m["known"] > 0


@pytest.mark.skipif(shutil.which("git") is None, reason="git missing")
def test_fix_branch_is_pr_ready(fixture_copy):
    g = lambda *a: subprocess.run(["git", "-C", str(fixture_copy), *a], check=True,  # noqa: E731
                                  capture_output=True, text=True).stdout
    g("init", "-q", "-b", "main")
    g("-c", "user.name=t", "-c", "user.email=t@e", "add", "-A")
    g("-c", "user.name=t", "-c", "user.email=t@e", "commit", "-qm", "init")
    g("config", "user.name", "t")
    g("config", "user.email", "t@e")
    assert cli.main(["fix", str(fixture_copy), "--db", str(SNAPSHOT), "--offline", "--branch",
                     "aiwatch/test"]) == 0
    assert g("rev-parse", "--abbrev-ref", "HEAD").strip() == "aiwatch/test"
    assert "aiwatch remediation" in g("log", "-1", "--format=%s")
    assert g("status", "--porcelain").strip() == ""
