import os

import pytest

from safeshell.schemas import ActionType, ParsedCommand, PlanSource, RollbackAction, RollbackPlan
from safeshell.simulation import simulation_select


@pytest.mark.root
def test_sim_judge():
    tgt = "/tmp/ss_judge"
    os.makedirs(tgt, exist_ok=True)
    with open(os.path.join(tgt, "test.txt"), "w") as f:
        f.write("hello")

    parsed = ParsedCommand(
        executable="rm",
        arguments=["-rf", tgt],
        resolved_paths=[tgt],
        effect_graph={"deletes": [tgt]},
    )

    cand1 = RollbackPlan(
        plan_id="p1",
        command_id="c1",
        source=PlanSource.ai_generated,
        confidence=0.8,
        actions=[RollbackAction(type=ActionType.no_op_external_flag, target="nothing", order=1)],
        requires_snapshot=False,
    )

    cand2 = RollbackPlan(
        plan_id="p2",
        command_id="c2",
        source=PlanSource.ai_generated,
        confidence=0.9,
        actions=[RollbackAction(type=ActionType.restore_directory, target=tgt, order=1)],
        requires_snapshot=True,
    )

    selected = simulation_select(parsed, [cand1, cand2])
    assert selected is not None
    assert selected.plan_id == "p2"
