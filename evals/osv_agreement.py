"""Accuracy check: aiwatch's local OSV range evaluation vs OSV.dev's server-side matching.

For every pinned (package, version) in the demo fixture and the public-repo manifests, compare
the advisories aiwatch matches locally (after GHSA/PYSEC alias de-duplication) with the IDs
returned by POST https://api.osv.dev/v1/querybatch for that exact version. A pair agrees when
both sides describe the same set of issues (every server ID is covered by a local group's
id/aliases and every local group has a server ID).  python evals/osv_agreement.py
"""

from __future__ import annotations

import json
import tempfile
import time
import urllib.request
from pathlib import Path

from aiwatch.advisories import matcher
from aiwatch.advisories.db import AdvisoryDB
from aiwatch.scanner import scan

from public_repos import REPOS, fetch  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]


def querybatch(pairs: list[tuple[str, str, str]]) -> list[set[str]]:
    out: list[set[str]] = []
    for i in range(0, len(pairs), 500):
        chunk = pairs[i:i + 500]
        body = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                            for e, n, v in chunk]}
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.load(r)["results"]
        for j, x in enumerate(res):
            ids = {v["id"] for v in x.get("vulns", [])}
            if x.get("next_page_token"):  # rare; fall back to single query
                e, n, v = chunk[j]
                q = json.dumps({"package": {"name": n, "ecosystem": e}, "version": v}).encode()
                with urllib.request.urlopen(urllib.request.Request(
                        "https://api.osv.dev/v1/query", data=q,
                        headers={"Content-Type": "application/json"}), timeout=120) as r2:
                    ids = {v["id"] for v in json.load(r2).get("vulns", [])}
            out.append(ids)
    return out


def main() -> int:
    pairs: set[tuple[str, str, str]] = set()
    with tempfile.TemporaryDirectory() as cache, tempfile.TemporaryDirectory() as td:
        db = AdvisoryDB(cache_dir=cache)
        roots = [ROOT / "examples" / "vulnerable-llm-app"]
        for k, (repo, sha, files) in enumerate(REPOS):
            d = Path(td) / str(k)
            for f in files:
                fetch(repo, sha, f, d)
            roots.append(d)
        for r in roots:
            res = scan(r, db, artifacts=False, secrets=False)
            pairs |= {(c.ecosystem, c.name, c.version) for c in res.components
                      if c.pinned and c.version}
        plist = sorted(pairs)
        db.prefetch(sorted({(e, n) for e, n, _ in plist}))
        server = querybatch(plist)
        agree = 0
        vulnerable_pairs = 0
        mismatches = []
        local_total = server_total = 0
        for (e, n, v), sids in zip(plist, server):
            groups = matcher.match(db, e, n, v)
            withdrawn = set()
            covered = set().union(*({g["id"], *g["aliases"]} for g in groups)) if groups else set()
            # server may return withdrawn records that we drop by design
            for vv in db.fetched["osv"].get(f"{e}:{n}") or []:
                if vv.get("withdrawn"):
                    withdrawn |= {vv["id"], *vv["aliases"]}
            s = sids - withdrawn
            ok = s <= covered and all({g["id"], *g["aliases"]} & s for g in groups)
            local_total += len(groups)
            server_total += len(s)
            vulnerable_pairs += bool(groups or s)
            if ok:
                agree += 1
            else:
                mismatches.append({"package": f"{e}:{n}=={v}",
                                   "server_only": sorted(s - covered)[:8],
                                   "local_only": sorted(g["id"] for g in groups
                                                        if not ({g["id"], *g["aliases"]} & s))[:8]})
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "pairs": len(plist), "pairs_with_any_advisory": vulnerable_pairs,
           "agree": agree, "agreement": round(agree / max(1, len(plist)), 4),
           "local_advisory_groups": local_total, "server_records": server_total,
           "mismatches": mismatches}
    (ROOT / "results" / "osv-agreement.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "mismatches"}, indent=1))
    print(json.dumps(mismatches[:20], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
