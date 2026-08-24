import os
import tempfile

from safeshell import executor, state


def test_backend_detection():
    # Make sure core binary exists for tests
    assert state.backend() == "core"


def test_collect_state_cross_validation():
    # Create temp dir
    with tempfile.TemporaryDirectory() as tempdir:
        f1 = os.path.join(tempdir, "f1.txt")
        with open(f1, "w") as f:
            f.write("test content")

        sym = os.path.join(tempdir, "sym.txt")
        os.symlink(f1, sym)

        # Collect with Python
        man_py = state.collect_state_python([tempdir])

        # Collect with Core
        man_core = state.collect_state_core([tempdir])

        assert len(man_py.files) == len(man_core.files)

        # Compare hashes (excluding timestamps and generated IDs)
        for f_py, f_core in zip(man_py.files, man_core.files):
            assert f_py.path == f_core.path
            assert f_py.sha256 == f_core.sha256
            assert f_py.exists == f_core.exists
            # mode might differ slightly in output formatting but sizes match
            assert f_py.size == f_core.size


def test_snapshot_roundtrip():
    with tempfile.TemporaryDirectory() as rootdir:
        workdir = os.path.join(rootdir, "work")
        os.makedirs(workdir)
        snapdir = os.path.join(rootdir, "snaps")

        f1 = os.path.join(workdir, "f1.txt")
        with open(f1, "w") as f:
            f.write("original")

        # Take snapshot
        res = executor.take_snapshot([workdir], "snap1", snapdir)
        assert res["files"] == 1

        # Tamper
        with open(f1, "w") as f:
            f.write("tampered")

        # Restore
        res = executor.restore_snapshot("snap1", snapdir)
        assert res["verified"] is True

        # Check content
        with open(f1, "r") as f:
            assert f.read() == "original"
