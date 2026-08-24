import os

import pytest

from safeshell import executor


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_isolation():
    host_file = "/pwned7"
    if os.path.exists(host_file):
        os.remove(host_file)

    res = executor.sandbox_exec(
        argv=["sh", "-c", f"echo pwned > {host_file}"], scope_paths=["/tmp"]
    )
    assert res["exit_code"] == 0
    assert not os.path.exists(host_file)


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_namespace():
    host_ns = os.readlink("/proc/self/ns/mnt")
    res = executor.sandbox_exec(
        argv=["sh", "-c", "readlink /proc/self/ns/mnt"], scope_paths=["/tmp"]
    )
    assert host_ns not in res["stdout_tail"]


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_network():
    res = executor.sandbox_exec(
        argv=["sh", "-c", "wget -q -T2 http://1.0.0.1/ || echo NETBLOCKED"],
        scope_paths=["/tmp"],
        allow_network=False,
        timeout_s=3,
    )
    assert "NETBLOCKED" in res["stdout_tail"]


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_timeout():
    res = executor.sandbox_exec(argv=["sleep", "30"], scope_paths=["/tmp"], timeout_s=2)
    assert 1900 <= res["duration_ms"] <= 5000
    assert res["exit_code"] in {124, 137, -9}


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_diff():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        f1 = os.path.join(d, "f1.txt")
        f2 = os.path.join(d, "f2.txt")
        with open(f1, "w") as f:
            f.write("pre")
        with open(f2, "w") as f:
            f.write("pre")

        # Command creates f3, modifies f1, removes f2
        f3 = os.path.join(d, "f3.txt")
        f4 = os.path.join(d, "f4.txt")
        with open(f4, "w") as f:
            f.write("pre")

        cmd = f"echo edit > {f1} && rm {f2} && echo new > {f3} && chmod 777 {f4}"

        res = executor.sandbox_exec(argv=["sh", "-c", cmd], scope_paths=[d])

        diff = res["predicted_changes"]
        assert diff["files_deleted"] == 1
        assert diff["files_modified"] == 2  # 1 modified, 1 new
        assert diff["permissions_changed"] == 1


@pytest.mark.root
@pytest.mark.skipif(os.geteuid() != 0, reason="sandbox_exec requires root")
def test_sandbox_monitor():
    res = executor.sandbox_exec(argv=["sh", "-c", "sleep 0.3 & wait"], scope_paths=["/tmp"])
    events = res["events"]
    commands = [e["detail"] for e in events if e["kind"] == "exec"]
    assert any("sleep" in c for c in commands)
    assert res["monitor_mode"] in {"ebpf", "polling"}
    print(f"Monitor mode used: {res['monitor_mode']}")


def test_sandbox_non_root_failclosed():
    if os.geteuid() == 0:
        pytest.skip("Test requires non-root user")

    with pytest.raises(executor.CoreError) as exc:
        executor.sandbox_exec(argv=["true"], scope_paths=["/tmp"])
    assert "CAP_SYS_ADMIN" in str(exc.value)
