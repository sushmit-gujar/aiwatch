"""SQLite-backed state. One file, safe to cache between CI runs."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Finding
from ..scanner import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  root TEXT, advisory_source TEXT, seconds REAL,
  summary TEXT, new INTEGER, known INTEGER, resolved INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  rule_id TEXT, severity TEXT, category TEXT, file TEXT, title TEXT, message TEXT,
  first_seen INTEGER, last_seen INTEGER, status TEXT, resolved_at INTEGER, data TEXT
);
CREATE TABLE IF NOT EXISTS components (
  run_id INTEGER, ecosystem TEXT, name TEXT, version TEXT, file TEXT
);
CREATE INDEX IF NOT EXISTS components_run ON components(run_id);
"""


@dataclass
class Delta:
    run_id: int
    first_run: bool
    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        by_change: dict[str, int] = {}
        for f in self.new:
            by_change[f.change] = by_change.get(f.change, 0) + 1
        return {"new": len(self.new), "known": len(self.known), "resolved": len(self.resolved),
                **{f"new_{k.replace('-', '_')}": v for k, v in sorted(by_change.items())}}


class State:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def last_run_id(self) -> int | None:
        row = self.db.execute("SELECT max(id) FROM runs").fetchone()
        return row[0] if row and row[0] is not None else None

    def runs(self) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT id, started_at, advisory_source, seconds, summary, new, "
                              "known, resolved FROM runs ORDER BY id")
        return [{"id": r[0], "started_at": r[1], "advisory_source": r[2], "seconds": r[3],
                 "summary": json.loads(r[4] or "{}"), "new": r[5], "known": r[6],
                 "resolved": r[7]} for r in cur]

    def open_findings(self) -> dict[str, dict[str, Any]]:
        cur = self.db.execute("SELECT fingerprint, first_seen, data FROM findings "
                              "WHERE status='open'")
        return {r[0]: {"first_seen": r[1], **json.loads(r[2])} for r in cur}

    def first_seen(self) -> dict[str, int]:
        return {r[0]: r[1] for r in self.db.execute("SELECT fingerprint, first_seen FROM findings")}

    def record(self, res: ScanResult) -> Delta:
        prev_run = self.last_run_id()
        prev_open = self.open_findings()
        all_prev = {r[0]: r[1] for r in self.db.execute(
            "SELECT fingerprint, status FROM findings")}
        prev_comps = set()
        if prev_run is not None:
            prev_comps = {tuple(r) for r in self.db.execute(
                "SELECT ecosystem, name, version, file FROM components WHERE run_id=?",
                (prev_run,))}
        cur = self.db.execute(
            "INSERT INTO runs(started_at, root, advisory_source, seconds, summary) "
            "VALUES (?,?,?,?,?)",
            (res.meta.get("scanned_at"), res.root, res.meta.get("advisory_source"),
             res.meta.get("seconds"), json.dumps(res.summary())))
        run_id = int(cur.lastrowid or 0)
        delta = Delta(run_id=run_id, first_run=prev_run is None)
        seen = set()
        for f in res.findings:
            fp = f.fingerprint
            if fp in seen:
                continue
            seen.add(fp)
            if fp in prev_open:
                f.status, f.change = "known", ""
                delta.known.append(f)
            else:
                f.status = "new"
                if prev_run is None:
                    f.change = "baseline"
                elif all_prev.get(fp) == "resolved":
                    f.change = "regressed"
                elif f.rule_id in ("AW100", "AW102"):
                    d = f.details
                    same = (d.get("ecosystem"), d.get("package"), d.get("version"), f.file) in \
                        prev_comps
                    f.change = "newly-disclosed" if same else "introduced"
                else:
                    f.change = "drift"
                delta.new.append(f)
            data = json.dumps(f.to_dict())
            self.db.execute(
                "INSERT INTO findings(fingerprint, rule_id, severity, category, file, title, "
                "message, first_seen, last_seen, status, data) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity, "
                "message=excluded.message, last_seen=excluded.last_seen, status='open', "
                "resolved_at=NULL, data=excluded.data",
                (fp, f.rule_id, f.severity.label, f.category, f.file, f.title, f.message,
                 run_id, run_id, "open", data))
        for fp, info in prev_open.items():
            if fp not in seen:
                self.db.execute("UPDATE findings SET status='resolved', resolved_at=? "
                                "WHERE fingerprint=?", (run_id, fp))
                delta.resolved.append(info)
        self.db.executemany(
            "INSERT INTO components(run_id, ecosystem, name, version, file) VALUES (?,?,?,?,?)",
            [(run_id, c.ecosystem, c.name, c.version, c.file) for c in res.components])
        c = delta.counts()
        self.db.execute("UPDATE runs SET new=?, known=?, resolved=? WHERE id=?",
                        (c["new"], c["known"], c["resolved"], run_id))
        self.db.commit()
        return delta
