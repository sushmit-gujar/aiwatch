"""Core data model: severities, components (inventory), findings and fixes."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        v = value.strip().upper()
        if v == "MODERATE":  # GHSA wording
            v = "MEDIUM"
        try:
            return cls[v]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Component:
    """One inventoried dependency (PyPI or npm package) found in a manifest."""

    ecosystem: str  # "PyPI" | "npm"
    name: str  # normalised name
    version: str | None  # exact version when pinned / locked, else None
    spec: str  # original specifier text, e.g. "torch==2.5.1" or ">=2.0"
    file: str  # repo-relative path of the manifest
    line: int  # 1-based line in the manifest (0 when unknown)
    kind: str  # requirements | pyproject | uv.lock | poetry.lock | mcp | ...
    direct: bool = True
    span: tuple[int, int] | None = None  # char offsets of the version text (rewritable pins)

    @property
    def pinned(self) -> bool:
        return self.version is not None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"


@dataclass
class Edit:
    """A text replacement in one file: replace [start, end) character offsets."""

    file: str
    start: int
    end: int
    new: str


@dataclass
class Fix:
    """A machine-applicable remediation for a finding."""

    description: str
    edits: list[Edit] = field(default_factory=list)
    safety: str = "safe"  # safe: behaviour-preserving · review: may change behaviour
    to_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "safety": self.safety,
            "to_version": self.to_version,
            "files": sorted({e.file for e in self.edits}),
        }


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    file: str
    line: int = 0
    category: str = "config"  # dependency | config | code | mcp | secret | artifact | model
    key: str = ""  # stable identity inside the file (advisory id, normalised snippet ...)
    details: dict[str, Any] = field(default_factory=dict)
    fix: Fix | None = None
    owasp: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    # Set by the monitor: new | known | (resolved is tracked in state)
    status: str = ""
    change: str = ""  # newly-disclosed | introduced | drift

    @property
    def fingerprint(self) -> str:
        """Line-independent identity so edits elsewhere in a file do not create 'new' findings."""
        raw = f"{self.rule_id}|{self.file}|{self.key or self.message}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        d["fix"] = self.fix.to_dict() if self.fix else None
        d["owasp"] = list(self.owasp)
        d["atlas"] = list(self.atlas)
        d["cwe"] = list(self.cwe)
        return d


SEV_ORDER = [s for s in sorted(Severity, reverse=True)]


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {s.label: 0 for s in SEV_ORDER}
    for f in findings:
        out[f.severity.label] += 1
    return out
