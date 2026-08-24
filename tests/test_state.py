import hashlib
import os
import tempfile

from safeshell.state import collect_state


def test_collect_state_deterministic_and_hash():
    with tempfile.TemporaryDirectory() as td:
        f1 = os.path.join(td, "a.txt")
        f2 = os.path.join(td, "b.txt")
        missing = os.path.join(td, "missing.txt")

        with open(f1, "w") as f:
            f.write("hello")
        with open(f2, "w") as f:
            f.write("world")

        manifest = collect_state([f2, f1, missing])

        assert len(manifest.files) == 3
        assert manifest.files[0].path == f1
        assert manifest.files[1].path == f2
        assert manifest.files[2].path == missing

        assert manifest.files[0].exists is True
        assert manifest.files[2].exists is False

        # manual hash
        h = hashlib.sha256(b"hello").hexdigest()
        assert manifest.files[0].sha256 == h

        # second call identical
        m2 = collect_state([f2, f1, missing])
        assert manifest.files[0].sha256 == m2.files[0].sha256


def test_max_files_truncation():
    with tempfile.TemporaryDirectory() as td:
        f1 = os.path.join(td, "a.txt")
        f2 = os.path.join(td, "b.txt")
        f3 = os.path.join(td, "c.txt")

        with open(f1, "w") as f:
            f.write("1")
        with open(f2, "w") as f:
            f.write("2")
        with open(f3, "w") as f:
            f.write("3")

        manifest = collect_state([td], max_files=2)
        assert manifest.truncated is True
        assert len(manifest.files) == 2
