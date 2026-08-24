import os

import pytest

from safeshell.planner_cascade import NoVerifiedPlan, make_plan


def test_cascade_template(monkeypatch):
    monkeypatch.setattr("safeshell.planner.get_client", lambda: None)  # Should not be called
    try:
        res = make_plan("mv a b")
        assert res.path == "template"
    except NoVerifiedPlan:
        # Template was found but simulate() failed (requires root).
        # This is expected when running without root privileges.
        if os.geteuid() != 0:
            pytest.skip("template simulate requires root")
        else:
            raise


def test_cascade_denied():
    res = make_plan("rm -rf /")
    assert res.path == "denied"


def test_cascade_ai(monkeypatch):
    if not os.environ.get("RUN_LLM"):
        pytest.skip("LLM tests require RUN_LLM=1")
    res = make_plan("rm -rf ./build")
    assert res.path == "ai_generated"
    assert len(res.candidates) > 0
    assert res.candidates[res.selected_index].validated is True
