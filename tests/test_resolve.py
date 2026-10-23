"""Resolver-aware fixes need uv + network (PyPI metadata): opt in with AIWATCH_NETWORK=1."""

import os
import shutil

import pytest

from aiwatch.remediate import fixer
from aiwatch.remediate.resolve import apply_resolution
from aiwatch.scanner import scan

pytestmark = pytest.mark.skipif(
    not (os.environ.get("AIWATCH_NETWORK") and shutil.which("uv")),
    reason="set AIWATCH_NETWORK=1 with uv installed")


def test_co_resolved_fix_installs_together(fixture_copy, snapshot_db):
    res = scan(fixture_copy, snapshot_db)
    results, extra = apply_resolution(res.findings, res.components, snapshot_db)
    assert results and all(r.ok for r in results), [r.error for r in results]
    fixer.apply(fixture_copy, fixer.plan(res.findings, extra=extra))
    after = scan(fixture_copy, snapshot_db)
    assert after.summary()["advisories"] == 0
