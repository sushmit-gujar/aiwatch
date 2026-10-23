from aiwatch.advisories import cvss, matcher
from aiwatch.advisories import versions as V
from aiwatch.advisories.db import dedupe

from .conftest import make_db, vuln


def test_semver_ordering():
    vs = ["1.0.0", "1.0.0-rc.1", "0.6.2", "2025.7.1", "1.0.0-alpha", "1.0.0-alpha.1", "0.10.0"]
    assert V.sort_versions("npm", vs) == ["0.6.2", "0.10.0", "1.0.0-alpha", "1.0.0-alpha.1",
                                          "1.0.0-rc.1", "1.0.0", "2025.7.1"]


def test_pep440_and_bump_kind():
    assert V.sort_versions("PyPI", ["2.10.0", "2.9.1", "2.10.0rc1", "bogus"]) == [
        "2.9.1", "2.10.0rc1", "2.10.0"]
    assert V.bump_kind("PyPI", "2.5.1", "2.5.3") == "patch"
    assert V.bump_kind("PyPI", "2.5.1", "2.6.0") == "minor"
    assert V.bump_kind("npm", "0.6.2", "2025.7.1") == "major"


def test_ranges_fixed_last_affected_and_versions_list():
    v = vuln("GHSA-1", "pkg", [[{"introduced": "0"}, {"fixed": "1.2.0"}],
                               [{"introduced": "2.0"}, {"last_affected": "2.1"}]],
             versions=["3.0.0"])
    aff = lambda x: matcher.is_affected("PyPI", "pkg", x, v)  # noqa: E731
    assert aff("1.1.9") and not aff("1.2.0") and not aff("1.9")
    assert aff("2.0") and aff("2.1") and not aff("2.1.1")
    assert aff("3.0.0")  # explicit versions list
    assert matcher.is_affected("PyPI", "PKG", "1.0", v)  # PEP 503 normalisation


def test_minimal_safe_prefers_smallest_clean_release(tmp_path):
    osv = {"PyPI:pkg": [
        vuln("A", "pkg", [[{"introduced": "0"}, {"fixed": "1.2.0"}]]),
        vuln("B", "pkg", [[{"introduced": "1.0"}, {"fixed": "1.3.1"}]]),
        vuln("C", "pkg", [[{"introduced": "0"}]], severity="LOW"),  # never fixed
    ]}
    rel = {"PyPI:pkg": ["1.0", "1.2.0", "1.3.0", "1.3.1", "1.4.0", "2.0.0rc1"]}
    db = make_db(tmp_path, osv, rel)
    t, remaining = matcher.minimal_safe(db, "PyPI", "pkg", "1.1")
    assert t == "1.3.1" and remaining == ["C"]
    # Only high+ drive the target
    t, _ = matcher.minimal_safe(db, "PyPI", "pkg", "1.1", min_severity=3)
    assert t == "1.3.1"


def test_minimal_safe_requires_confirmed_fix_across_scheme_change(tmp_path):
    # Real-world shape: @modelcontextprotocol/server-filesystem moved CalVer -> SemVer.
    osv = {"npm:fs": [vuln("X", "fs", [[{"introduced": "0"}, {"last_affected": "0.6.2"}],
                                      [{"introduced": "2025.1.14"}, {"fixed": "2025.7.1"}]],
                           eco="npm")]}
    db = make_db(tmp_path, osv, {"npm:fs": ["0.6.2", "1.0.0", "2025.1.14", "2025.7.1"]})
    assert matcher.minimal_safe(db, "npm", "fs", "0.6.2")[0] == "2025.7.1"


def test_as_of_filters_by_published(tmp_path):
    osv = {"PyPI:p": [vuln("OLD", "p", [[{"introduced": "0"}]], published="2023-05-01T00:00:00Z"),
                      vuln("NEW", "p", [[{"introduced": "0"}]], published="2026-02-01T00:00:00Z")]}
    db = make_db(tmp_path, osv, as_of="2024-12-31")
    assert [v["id"] for v in db.vulns("PyPI", "p")] == ["OLD"]


def test_dedupe_prefers_ghsa_and_merges_aliases():
    a = vuln("PYSEC-1", "p", [[{"introduced": "0"}]], aliases=["CVE-1", "GHSA-x"],
             severity="MEDIUM")
    b = vuln("GHSA-x", "p", [[{"introduced": "0"}]], aliases=["CVE-1"], severity="HIGH")
    out = dedupe([a, b])
    assert len(out) == 1 and out[0]["id"] == "GHSA-x"
    assert set(out[0]["aliases"]) == {"CVE-1", "PYSEC-1"} and out[0]["severity"] == "HIGH"


def test_cvss_v3():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert cvss.label(7.8) == "HIGH" and cvss.base_score("CVSS:4.0/AV:N") is None


def test_dedupe_uses_union_of_affected_ranges():
    # Real case: mlflow CVE-2023-6568 -- GHSA says fixed 2.9.0, PYSEC says fixed 2.9.1.
    ghsa = vuln("GHSA-v", "mlflow", [[{"introduced": "0"}, {"fixed": "2.9.0"}]],
                aliases=["CVE-2023-6568"])
    pysec = vuln("PYSEC-1", "mlflow", [[{"introduced": "0"}, {"fixed": "2.9.1"}]],
                 aliases=["CVE-2023-6568", "GHSA-v"])
    (g,) = dedupe([ghsa, pysec])
    assert matcher.is_affected("PyPI", "mlflow", "2.9.0", g)
    assert not matcher.is_affected("PyPI", "mlflow", "2.9.1", g)
