from safeshell.schemas import ActionType, RollbackAction
from safeshell.simulation import render_rollback_argv


def test_render_tar():
    actions = [
        RollbackAction(type=ActionType.restore_directory, target="/etc", order=1),
        RollbackAction(type=ActionType.restore_file, target="/var/log/syslog", order=2),
    ]
    commands = render_rollback_argv(actions, "/tmp/snap.tar")
    assert len(commands) == 1
    assert commands[0] == ["tar", "-xzpf", "/tmp/snap.tar", "-C", "/", "etc", "var/log/syslog"]


def test_render_mixed():
    actions = [
        RollbackAction(type=ActionType.restore_directory, target="/etc", order=1),
        RollbackAction(type=ActionType.restart_service, target="nginx", order=2),
        RollbackAction(type=ActionType.restore_file, target="/var/log", order=3),
    ]
    commands = render_rollback_argv(actions, "/tmp/snap.tar")
    assert len(commands) == 3
    assert commands[0] == ["tar", "-xzpf", "/tmp/snap.tar", "-C", "/", "etc"]
    assert commands[1] == ["systemctl", "restart", "nginx"]
    assert commands[2] == ["tar", "-xzpf", "/tmp/snap.tar", "-C", "/", "var/log"]
