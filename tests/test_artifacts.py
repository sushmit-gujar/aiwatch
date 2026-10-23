import pytest

from aiwatch.inventory import artifacts
from aiwatch.scanner import scan


def test_builtin_fallback_without_loadsafe(fixture_copy, snapshot_db, monkeypatch):
    monkeypatch.setattr(artifacts, "loadsafe_available", lambda: False)
    res = scan(fixture_copy, snapshot_db)
    art = [f for f in res.findings if f.category == "artifact"]
    assert [f.rule_id for f in art] == ["AW210"] and art[0].file == "models/classifier.pkl"


@pytest.mark.skipif(not artifacts.loadsafe_available(), reason="loadsafe not installed")
def test_loadsafe_flags_poc_pickle_but_not_safetensors(fixture_copy, snapshot_db):
    res = scan(fixture_copy, snapshot_db)
    art = [f for f in res.findings if f.category == "artifact"]
    assert any(f.details["loadsafe_rule"] == "LS100" and f.severity.label == "critical"
               for f in art)
    assert all(f.file == "models/classifier.pkl" for f in art)
