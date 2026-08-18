"""Tests for safeshell-core IPC communication."""

from safeshell.executor import call_core
from safeshell.schemas import CoreRequest


def test_snapshot_not_implemented(core_bin) -> None:
    """call_core(snapshot) returns ok=False with NotImplemented error."""
    req = CoreRequest(op="snapshot", params={})
    resp = call_core(req)
    assert resp.ok is False
    assert "NotImplemented" in (resp.error or "")
    assert "snapshot" in (resp.error or "")
