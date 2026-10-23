"""Advisory + metadata store.

Sources:
* OSV.dev ``POST /v1/query`` (keyless) for PyPI and npm advisories (GHSA, PYSEC, ...).
* PyPI JSON API / npm registry for release lists (used to compute the minimal safe bump).
* Hugging Face Hub ``/api/models/<id>`` for commit SHAs and weight file names.

Everything fetched is recorded so it can be written out as an offline snapshot
(``aiwatch db snapshot``); ``--offline --db snapshot.json.gz`` then gives fully
deterministic scans for tests and CI.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .. import __version__
from . import cvss

OSV_URL = "https://api.osv.dev/v1/query"
UA = f"aiwatch/{__version__} (+https://github.com/sushmit-gujar/aiwatch)"
SNAPSHOT_FORMAT = 1


class FetchError(RuntimeError):
    pass


def _http(url: str, data: dict[str, Any] | None = None, headers: dict[str, str] | None = None,
          retries: int = 3, timeout: float = 30.0) -> Any:
    body = json.dumps(data).encode() if data is not None else None
    h = {"User-Agent": UA, "Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                return None
            last = e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
        time.sleep(0.5 * 2**attempt)
    raise FetchError(f"{url}: {last}")


def _sev_of(v: dict[str, Any]) -> tuple[str, float | None]:
    ds = (v.get("database_specific") or {}).get("severity")
    score = None
    for s in v.get("severity") or []:
        if s.get("type", "").startswith("CVSS_V3"):
            score = cvss.base_score(s.get("score", ""))
            if score is not None:
                break
    if isinstance(ds, str) and ds.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return ("MEDIUM" if ds.upper() == "MODERATE" else ds.upper()), score
    if score is not None:
        return cvss.label(score), score
    return "UNKNOWN", None


def trim(v: dict[str, Any]) -> dict[str, Any]:
    """Keep only what matching, fixing and reporting need (keeps snapshots small)."""
    sev, score = _sev_of(v)
    refs = v.get("references") or []
    pref = [r["url"] for r in refs if r.get("type") in ("ADVISORY", "WEB")][:2]
    if not pref:
        pref = [r["url"] for r in refs][:2]
    return {
        "id": v["id"],
        "aliases": sorted(set(v.get("aliases") or [])),
        "summary": (v.get("summary") or (v.get("details") or "").split("\n")[0])[:240],
        "published": v.get("published", ""),
        "modified": v.get("modified", ""),
        "withdrawn": v.get("withdrawn"),
        "severity": sev,
        "cvss": score,
        "cwe": (v.get("database_specific") or {}).get("cwe_ids") or [],
        "references": pref,
        "affected": [
            {
                "package": {
                    "name": a.get("package", {}).get("name"),
                    "ecosystem": a.get("package", {}).get("ecosystem"),
                },
                "ranges": [
                    {"type": r.get("type"), "events": r.get("events", [])}
                    for r in a.get("ranges") or []
                    if r.get("type") in ("ECOSYSTEM", "SEMVER")
                ],
                "versions": a.get("versions") or [],
            }
            for a in v.get("affected") or []
        ],
    }


def dedupe(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge records describing the same issue (GHSA / PYSEC / CVE aliases), prefer GHSA."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in vulns:
        for a in v["aliases"]:
            parent[find(a)] = find(v["id"])
    groups: dict[str, list[dict[str, Any]]] = {}
    for v in vulns:
        groups.setdefault(find(v["id"]), []).append(v)
    out = []
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    for members in groups.values():
        members.sort(key=lambda m: (not m["id"].startswith("GHSA-"), m["id"]))
        best = dict(members[0])
        ids = {m["id"] for m in members}
        best["aliases"] = sorted((set().union(*(set(m["aliases"]) for m in members)) | ids)
                                 - {best["id"]})
        # Union of affected ranges: if GHSA and PYSEC disagree on a fix version, stay
        # conservative (a false negative is worse than an extra bump).
        best["affected"] = [a for m in members for a in m["affected"]]
        best["severity"] = max((m["severity"] for m in members), key=lambda s: rank.get(s, 0))
        best["published"] = min(m["published"] for m in members if m["published"]) \
            if any(m["published"] for m in members) else ""
        if best.get("withdrawn") and not all(m.get("withdrawn") for m in members):
            best["withdrawn"] = None
        out.append(best)
    return sorted(out, key=lambda v: v["id"])


class AdvisoryDB:
    def __init__(self, snapshot: str | Path | None = None, offline: bool = False,
                 cache_dir: str | Path | None = None, as_of: str | None = None,
                 ttl_hours: float = 6.0) -> None:
        self.offline = offline
        self.as_of = as_of
        self.ttl = ttl_hours * 3600
        self.data: dict[str, Any] = {"osv": {}, "releases": {}, "hf": {}, "npm_latest": {}}
        self.source = "live: api.osv.dev"
        self.snapshot_meta: dict[str, Any] = {}
        if snapshot:
            self._load_snapshot(Path(snapshot))
        if offline and not snapshot:
            raise ValueError("--offline needs --db <snapshot.json.gz>")
        cd = cache_dir or os.environ.get("AIWATCH_CACHE") or Path.home() / ".cache" / "aiwatch"
        self.cache_dir = Path(cd)
        self.fetched: dict[str, Any] = {"osv": {}, "releases": {}, "hf": {}, "npm_latest": {}}
        self.errors: list[str] = []

    # snapshot ----------------------------------------------------------------------------
    def _load_snapshot(self, path: Path) -> None:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as fh:
            snap = json.load(fh)
        if snap.get("format") != SNAPSHOT_FORMAT:
            raise ValueError(f"unsupported snapshot format in {path}")
        for k in self.data:
            self.data[k].update(snap.get(k, {}))
        self.snapshot_meta = {k: snap.get(k) for k in ("created", "source", "packages")}
        self.source = f"snapshot {path.name} ({snap.get('created', '?')})"
        if not self.offline:
            self.source = "live: api.osv.dev (snapshot fallback)"

    def save_snapshot(self, path: Path, keys: set[str] | None = None) -> dict[str, int]:
        merged = {k: {**self.data[k], **self.fetched[k]} for k in self.data}
        if keys is not None:
            merged["osv"] = {k: v for k, v in merged["osv"].items() if k in keys}
            merged["releases"] = {k: v for k, v in merged["releases"].items() if k in keys}
            merged["npm_latest"] = {k: v for k, v in merged["npm_latest"].items()
                                    if f"npm:{k}" in keys}
        snap = {
            "format": SNAPSHOT_FORMAT,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "https://api.osv.dev/v1/query + pypi.org + registry.npmjs.org + "
                      "huggingface.co/api",
            "packages": len(merged["osv"]),
            **merged,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as fh:
            json.dump(snap, fh, sort_keys=True, separators=(",", ":"))
        return {k: len(merged[k]) for k in merged}

    # cache -------------------------------------------------------------------------------
    def _cache_get(self, kind: str, key: str) -> Any:
        p = self.cache_dir / kind / (urllib.parse.quote(key, safe="") + ".json")
        try:
            if time.time() - p.stat().st_mtime < self.ttl:
                return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _cache_put(self, kind: str, key: str, value: Any) -> None:
        p = self.cache_dir / kind / (urllib.parse.quote(key, safe="") + ".json")
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(value))
        except OSError:
            pass

    def _get(self, kind: str, key: str, fetch: Any) -> Any:
        if key in self.fetched[kind]:
            return self.fetched[kind][key]
        if self.offline:
            return self.data[kind].get(key)
        cached = self._cache_get(kind, key)
        if cached is None:
            try:
                cached = fetch()
            except FetchError as e:
                self.errors.append(str(e))
                return self.data[kind].get(key)  # snapshot fallback
            if cached is not None:
                self._cache_put(kind, key, cached)
        self.fetched[kind][key] = cached
        return cached

    # OSV -----------------------------------------------------------------------------------
    def _fetch_osv(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        token = None
        while True:
            q: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
            if token:
                q["page_token"] = token
            r = _http(OSV_URL, q) or {}
            vulns += [trim(v) for v in r.get("vulns", [])]
            token = r.get("next_page_token")
            if not token:
                break
        return dedupe(vulns)

    def vulns(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        key = f"{ecosystem}:{name}"
        vs = self._get("osv", key, lambda: self._fetch_osv(ecosystem, name)) or []
        vs = [v for v in vs if not v.get("withdrawn")]
        if self.as_of:
            vs = [v for v in vs if v.get("published", "")[:10] <= self.as_of]
        return vs

    # releases ------------------------------------------------------------------------------
    def _fetch_releases(self, ecosystem: str, name: str) -> list[str] | None:
        if ecosystem == "PyPI":
            r = _http(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            if not r:
                return None
            return sorted(v for v, files in r.get("releases", {}).items()
                          if files and not all(f.get("yanked") for f in files))
        r = _http(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                  headers={"Accept": "application/vnd.npm.install-v1+json"})
        if not r:
            return None
        return sorted((r.get("versions") or {}).keys())

    def releases(self, ecosystem: str, name: str) -> list[str]:
        key = f"{ecosystem}:{name}"
        return self._get("releases", key, lambda: self._fetch_releases(ecosystem, name)) or []

    def _fetch_npm_latest(self, name: str) -> str | None:
        r = _http(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                  headers={"Accept": "application/vnd.npm.install-v1+json"})
        return ((r or {}).get("dist-tags") or {}).get("latest")

    def npm_latest(self, name: str) -> str | None:
        v = self._get("npm_latest", name, lambda: self._fetch_npm_latest(name))
        return v if isinstance(v, str) else None

    # Hugging Face --------------------------------------------------------------------------
    def _fetch_hf(self, repo_id: str) -> dict[str, Any] | None:
        r = _http(f"https://huggingface.co/api/models/{repo_id}")
        if not r or "sha" not in r:
            return None
        names = [s.get("rfilename", "") for s in r.get("siblings") or []]
        weights = [n for n in names if n.endswith((".safetensors", ".bin", ".pt", ".pth",
                                                   ".ckpt", ".pkl", ".gguf", ".onnx", ".h5"))]
        return {"id": r.get("id", repo_id), "sha": r["sha"], "weights": weights[:200],
                "gated": bool(r.get("gated"))}

    def hf_model(self, repo_id: str) -> dict[str, Any] | None:
        info = self._get("hf", repo_id, lambda: self._fetch_hf(repo_id))
        return info if isinstance(info, dict) else None

    # prefetch ------------------------------------------------------------------------------
    def prefetch(self, keys: list[tuple[str, str]], hf_ids: list[str] | None = None,
                 workers: int = 8) -> None:
        if self.offline:
            return
        jobs: list[Any] = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for eco, name in keys:
                jobs.append(ex.submit(self.vulns, eco, name))
            for rid in hf_ids or []:
                jobs.append(ex.submit(self.hf_model, rid))
            for j in jobs:
                j.result()
