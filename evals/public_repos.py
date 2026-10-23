"""Read-only scan of dependency manifests from well-known open-source LLM apps.

Downloads only the listed manifest files at pinned commits (raw.githubusercontent.com),
scans them with live OSV data, and writes results/public-repos.json. Nothing is installed,
and no issues or PRs are opened anywhere.  python evals/public_repos.py
"""

from __future__ import annotations

import json
import tempfile
import time
import urllib.request
from pathlib import Path

from aiwatch.advisories.db import AdvisoryDB
from aiwatch.remediate import fixer
from aiwatch.scanner import scan

ROOT = Path(__file__).resolve().parents[1]
REPOS = [
    ("open-webui/open-webui", "91ea4e3421d1d8069f13d4a463fcb5986d94ea60",
     ["backend/requirements.txt"]),
    ("oobabooga/text-generation-webui", "c93f8871239550de2ccfe1e95d469aa82616f07e",
     ["requirements/full/requirements.txt"]),
    ("AUTOMATIC1111/stable-diffusion-webui", "82a973c04367123ae98bd9abdf80d9eda9b910e2",
     ["requirements_versions.txt"]),
    ("zylon-ai/private-gpt", "0f6a2de226374a7ccc7ac5e739054be8da9929d9",
     ["pyproject.toml", "uv.lock"]),
    ("langgenius/dify", "2b35144b2098f8f6ad6af31bf72356a42f813d58",
     ["api/pyproject.toml", "api/uv.lock"]),
]


def fetch(repo: str, sha: str, path: str, dest: Path) -> None:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "aiwatch-eval"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    out = dest / path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)


def main() -> int:
    rows = []
    with tempfile.TemporaryDirectory() as cache:
        db = AdvisoryDB(cache_dir=cache)
        for repo, sha, files in REPOS:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                for f in files:
                    fetch(repo, sha, f, d)
                t = time.perf_counter()
                res = scan(d, db, artifacts=False, secrets=False)
                secs = time.perf_counter() - t
                s = res.summary()
                pl = fixer.plan(res.findings)
                pk: dict[str, set[str]] = {}
                for f in res.findings:
                    if f.rule_id == "AW100":
                        pk.setdefault(f"{f.details['package']}=={f.details['version']}",
                                      set()).add(f.details["advisory"])
                top = sorted(pk.items(), key=lambda kv: -len(kv[1]))[:6]
                rows.append({
                    "repo": repo, "commit": sha, "files": files,
                    "components": s["components"], "pinned": s["pinned_components"],
                    "vulnerable_packages": s["vulnerable_packages"],
                    "advisories": s["advisories"],
                    "dependency_findings": s["by_category"].get("dependency", 0),
                    "critical": s["by_severity"]["critical"], "high": s["by_severity"]["high"],
                    "auto_fixable_in_manifest": pl.resolves(),
                    "lockfile_only_fixes": sum(1 for f in res.findings
                                               if f.fix and f.fix.safety == "manual"),
                    "top": [{"package": k, "advisories": len(v)} for k, v in top],
                    "scan_seconds_cold": round(secs, 2),
                })
                print(json.dumps(rows[-1]))
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "advisory_source": "live api.osv.dev (cold cache)", "repos": rows}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "public-repos.json").write_text(json.dumps(out, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
