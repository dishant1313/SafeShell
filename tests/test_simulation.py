import os

import pytest

from safeshell.schemas import ActionType, ParsedCommand, PlanSource, RollbackAction, RollbackPlan
from safeshell.simulation import DegradationTier, simulate


@pytest.mark.root
def test_simulate_t1():
    tgt = "/tmp/safeshell_test_sim_8"
    os.makedirs(tgt, exist_ok=True)
    with open(os.path.join(tgt, "test.txt"), "w") as f:
        f.write("hello")

    parsed = ParsedCommand(
        executable="rm",
        arguments=["-rf", tgt],
        resolved_paths=[tgt],
        effect_graph={"deletes": [tgt]},
    )
    plan = RollbackPlan(
        plan_id="p1",
        command_id="c1",
        source=PlanSource.ai_generated,
        confidence=0.9,
        actions=[RollbackAction(type=ActionType.restore_directory, target=tgt, order=1)],
        requires_snapshot=True,
    )

    report = simulate(parsed, plan)

    assert report.rollback_verified is True
    assert report.degradation_tier == DegradationTier.T1_full_verification
    assert report.predicted_changes.files_deleted > 0
    assert report.matches_pre_execution_hash is True
