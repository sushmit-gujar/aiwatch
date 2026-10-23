"""SARIF 2.1.0 for GitHub code scanning (partialFingerprints keep alerts stable across runs)."""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..rules import ATLAS_NAMES, RULES
from ..scanner import ScanResult

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
         "info": "note"}
SEC_SEV = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def render(res: ScanResult, prefix: str = "") -> dict[str, Any]:
    used = sorted({f.rule_id for f in res.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        tags = ["security", "ai-security", *r.owasp, *(f"{a} {ATLAS_NAMES.get(a, '')}".strip()
                                                      for a in r.atlas), *r.cwe]
        rules.append({
            "id": rid,
            "name": r.title,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.help},
            "help": {"text": r.help, "markdown": r.help},
            "defaultConfiguration": {"level": LEVEL[r.default_severity.label]},
            "properties": {"tags": tags, "security-severity": SEC_SEV[r.default_severity.label],
                           "precision": "high"},
        })
    idx = {rid: i for i, rid in enumerate(used)}
    results = []
    for f in res.findings:
        uri = (prefix.rstrip("/") + "/" + f.file) if prefix else f.file
        sev = f.severity.label
        msg = f.message
        if f.fix:
            msg += f" Fix: {f.fix.description}."
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": idx[f.rule_id],
            "level": LEVEL[sev],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(f.line, 1)},
            }}],
            "partialFingerprints": {"aiwatch/v1": f.fingerprint},
            "properties": {"security-severity": SEC_SEV[sev], "category": f.category,
                           "status": f.status or None, "change": f.change or None,
                           "advisory": f.details.get("advisory"),
                           "owasp": list(f.owasp), "atlas": list(f.atlas)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "aiwatch", "version": __version__,
                                "informationUri": "https://github.com/sushmit-gujar/aiwatch",
                                "rules": rules}},
            "results": results,
        }],
    }
