from safeshell.parser import parse_command
from safeshell.templates import lookup


def test_template_mv():
    parsed = parse_command("mv a b")
    plan = lookup(parsed)
    assert plan is not None
    assert plan.source == "template"
    assert len(plan.actions) == 2
    assert plan.actions[0].type == "restore_file"
    assert plan.actions[0].target == "a"
    assert plan.actions[0].order == 1
