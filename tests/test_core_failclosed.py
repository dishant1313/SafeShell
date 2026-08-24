import os
import tempfile

import pytest

from safeshell import executor


def test_snapshot_insufficient_space_or_truncation():
    with tempfile.TemporaryDirectory() as rootdir:
        workdir = os.path.join(rootdir, "work")
        os.makedirs(workdir)
        snapdir = os.path.join(rootdir, "snaps")

        for i in range(10):
            with open(os.path.join(workdir, f"f{i}.txt"), "w") as f:
                f.write("x")

        # Expect fail closed due to max files
        with pytest.raises(executor.CoreError) as exc:
            executor.take_snapshot([workdir], "snap1", snapdir, max_files=5)

        assert "truncate" in str(exc.value).lower()


def test_restore_missing():
    with tempfile.TemporaryDirectory() as rootdir:
        with pytest.raises(executor.CoreError) as exc:
            executor.restore_snapshot("missing", rootdir)
        assert "no such file" in str(exc.value).lower()


def test_restore_mismatch():
    with tempfile.TemporaryDirectory() as rootdir:
        workdir = os.path.join(rootdir, "work")
        os.makedirs(workdir)
        snapdir = os.path.join(rootdir, "snaps")

        f1 = os.path.join(workdir, "f1.txt")
        with open(f1, "w") as f:
            f.write("original")

        executor.take_snapshot([workdir], "snap1", snapdir)

        # Tamper the manifest intentionally to trigger verification failure
        import json

        man_path = os.path.join(snapdir, "snap1.manifest.json")
        with open(man_path, "r") as f:
            man = json.load(f)
        man["files"][0]["sha256"] = "invalidhash"
        with open(man_path, "w") as f:
            json.dump(man, f)

        with pytest.raises(executor.CoreError) as exc:
            executor.restore_snapshot("snap1", snapdir)

        # The first arg is msg, second is data
        assert "mismatch" in str(exc.value).lower()
        assert len(exc.value.args) > 1
        assert "mismatched" in exc.value.args[1]
