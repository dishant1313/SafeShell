"""Tests for safeshell-core IPC communication."""

from safeshell.executor import call_core
from safeshell.schemas import CoreRequest


def test_snapshot_invalid_params(core_bin) -> None:
    """call_core(snapshot) returns ok=False with Invalid params error."""
    req = CoreRequest(op="snapshot", params={})
    resp = call_core(req)
    assert resp.ok is False
    assert "Invalid params" in (resp.error or "")
