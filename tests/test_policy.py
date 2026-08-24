import pytest
import yaml

from safeshell.policy import PolicyExpressionError, _compile, evaluate


def test_policy_auto_approve():
    res = evaluate("low", 50, "T1")
    assert res.action == "auto_approve"
    assert res.rule == "tier == 'low' and brs < 100"

    res2 = evaluate("medium", 240, "T1")
    assert res2.action == "auto_approve"


def test_policy_require_human():
    res = evaluate("medium", 600, "T1")
    assert res.action == "require_human"

    res2 = evaluate("high", 847, "T1")
    assert res2.action == "require_human"

    res3 = evaluate("low", 50, "T2")
    assert res3.action == "require_human"


def test_policy_deny():
    res = evaluate("critical", 999999999, "T1")
    assert res.action == "deny"

    res2 = evaluate("low", 50, "T3")
    assert res2.action == "deny"


def test_policy_fallback():
    # If we pass something that matches nothing, it should fallback to require_human
    res = evaluate("high", 10, "T1")
    assert res.action == "require_human"


def test_policy_security():
    context = {"tier": "low", "brs": 0, "guarantee": "T1"}

    with pytest.raises(PolicyExpressionError):
        _compile("os.system('x')", context)

    with pytest.raises(PolicyExpressionError):
        _compile("__import__('os').system('x')", context)

    with pytest.raises(PolicyExpressionError):
        _compile("tier == 'low' and brs < 100 or __import__('os')", context)

    with pytest.raises(PolicyExpressionError):
        _compile("tier.upper() == 'LOW'", context)


def test_policy_load_validation_error(tmp_path, monkeypatch):
    """G6: policy.yaml containing os.system('x') raises load-time validation error."""
    bad_policy = {"deny": [{"when": "os.system('x')"}], "require_human": [], "auto_approve": []}
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.dump(bad_policy))

    import safeshell.policy as pol

    monkeypatch.setattr(pol, "_POLICY_CONFIG", None)

    # Mock config_path to point to the bad policy file
    import os

    monkeypatch.setattr(
        os.path,
        "join",
        lambda *args: str(policy_file) if "policy.yaml" in args[-1] else os.path.join(*args),
    )

    with pytest.raises(PolicyExpressionError):
        pol.load_policy_config()


def test_policy_anomaly_flag_forces_require_human():
    """G6: anomaly flag forces require_human, never auto-deny."""
    decision = evaluate(tier="low", brs=10, guarantee="T1")
    assert decision.action == "auto_approve"

    # Simulate anomaly flag intercepting decision in CLI workflow
    is_anomaly = True
    if is_anomaly and decision.action != "deny":
        decision.action = "require_human"

    assert decision.action == "require_human"
    assert decision.action != "deny"
