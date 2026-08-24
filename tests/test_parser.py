import time

from safeshell.parser import parse_command, split_segments, tokenize


def test_tokenize():
    tokens = tokenize("sudo rm -rf /tmp/test")
    assert tokens == ["sudo", "rm", "-rf", "/tmp/test"]


def test_split_segments():
    tokens = ["mkdir", "-p", "/opt/app", "&&", "chmod", "777", "/opt/app"]
    segments = split_segments(tokens)
    assert len(segments) == 2
    assert segments[0] == ["mkdir", "-p", "/opt/app"]
    assert segments[1] == ["chmod", "777", "/opt/app"]


def test_parse_command_sudo_rm():
    cmd = parse_command("sudo rm -rf /tmp/test")
    assert cmd.executable == "rm"
    assert cmd.privilege_escalation is True
    assert cmd.flags == ["-rf"]
    assert cmd.arguments == ["/tmp/test"]
    assert "/tmp/test" in cmd.effect_graph["deletes"]


def test_parse_command_pipes():
    cmd = parse_command("cat /var/log/syslog | grep error | wc -l")
    assert cmd.executable == "cat"
    assert cmd.pipes == ["grep", "wc"]
    assert cmd.effect_graph["process_spawn"] == ["cat", "grep", "wc"]


def test_performance_guard():
    start = time.perf_counter()
    parse_command("sudo apt-get install nginx -y && systemctl start nginx")
    duration = time.perf_counter() - start
    # Should be under 10ms (0.01s)
    assert duration < 0.01, f"Parsing took too long: {duration * 1000:.2f}ms"
