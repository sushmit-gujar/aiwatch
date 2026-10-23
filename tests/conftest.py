from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path

import pytest

from aiwatch.advisories.db import AdvisoryDB

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "vulnerable-llm-app"
SNAPSHOT = ROOT / "data" / "osv-snapshot.json.gz"


def vuln(vid, name, events, eco="PyPI", severity="HIGH", published="2024-01-01T00:00:00Z",
         versions=(), aliases=()):
    return {"id": vid, "aliases": list(aliases), "summary": f"{vid} summary",
            "published": published, "modified": published, "withdrawn": None,
            "severity": severity, "cvss": None, "cwe": [], "references": [],
            "affected": [{"package": {"name": name, "ecosystem": eco},
                          "ranges": [{"type": "ECOSYSTEM" if eco == "PyPI" else "SEMVER",
                                      "events": ev} for ev in events],
                          "versions": list(versions)}]}


def make_db(tmp_path: Path, osv=None, releases=None, hf=None, npm_latest=None, **kw) -> AdvisoryDB:
    snap = {"format": 1, "created": "2026-01-01T00:00:00Z", "osv": osv or {},
            "releases": releases or {}, "hf": hf or {}, "npm_latest": npm_latest or {}}
    p = tmp_path / "snap.json.gz"
    with gzip.open(p, "wt") as fh:
        json.dump(snap, fh)
    return AdvisoryDB(snapshot=p, offline=True, **kw)


@pytest.fixture
def snapshot_db() -> AdvisoryDB:
    return AdvisoryDB(snapshot=SNAPSHOT, offline=True)


@pytest.fixture
def fixture_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "app"
    shutil.copytree(FIXTURE, dst)
    return dst
