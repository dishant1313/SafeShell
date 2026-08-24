import pytest

from safeshell.parser import parse_command
from safeshell.schemas import RollbackAction, RollbackPlan
from safeshell.validator import PlanInvalid, sign_plan, validate, verify_plan


def test_validator_success():
    parsed = parse_command("rm f")
    plan = RollbackPlan(
        plan_id="p1",
        command_id="c1",
        source="ai_generated",
        requires_snapshot=True,
        confidence=0.9,
        actions=[RollbackAction(type="restore_file", target="f", order=1)],
    )
    validated = validate(plan, parsed)
    assert validated.validated is True


def test_validator_boot_denied():
    parsed = parse_command("rm f")
    plan = RollbackPlan(
        plan_id="p1",
        command_id="c1",
        source="ai_generated",
        requires_snapshot=True,
        confidence=0.9,
        actions=[RollbackAction(type="restore_file", target="/boot/vmlinuz", order=1)],
    )
    with pytest.raises(PlanInvalid):
        validate(plan, parsed)


def test_sign_and_verify():
    parsed = parse_command("rm f")
    plan = RollbackPlan(
        plan_id="p1",
        command_id="c1",
        source="ai_generated",
        requires_snapshot=True,
        confidence=0.9,
        actions=[RollbackAction(type="restore_file", target="f", order=1)],
    )
    sign_plan(plan)
    assert plan.signature is not None
    assert verify_plan(plan) is True

    # Tamper
    plan.actions[0].target = "x"
    assert verify_plan(plan) is False
