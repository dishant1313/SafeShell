import subprocess
import sys

import pytest

from safeshell.ledger import tail


@pytest.mark.root
def test_e2e_run_and_undo(tmp_path):
    """End-to-end test of running a transaction and undoing it."""

    # Use the same Python interpreter that is running the tests (the venv one)
    python = sys.executable

    # Prepare test file
    test_dir = tmp_path / "e2e_dir"
    test_dir.mkdir()
    file_path = test_dir / "test.txt"
    file_path.write_text("hello e2e")

    target_path = test_dir / "test_moved.txt"

    cmd = f"mv {file_path} {target_path}"

    # Run the transaction
    # --yes auto-approves if safe
    res = subprocess.run(
        [python, "-m", "safeshell", "run", cmd, "--yes", "--no-color"],
        capture_output=True,
        text=True,
    )

    # 0 is success for execution
    assert res.returncode == 0, f"Run failed: {res.stdout} {res.stderr}"
    assert target_path.exists(), "File was not moved"
    assert not file_path.exists(), "Original file still exists"

    # Get last transaction from ledger
    ledger_entries = tail(1)
    assert len(ledger_entries) == 1
    txn_id = ledger_entries[0]["transaction_id"]

    # Undo the transaction
    res = subprocess.run(
        [python, "-m", "safeshell", "undo", txn_id, "--no-color"], capture_output=True, text=True
    )

    assert res.returncode == 0, f"Undo failed: {res.stdout} {res.stderr}"
    assert file_path.exists(), "File was not restored"
    assert not target_path.exists(), "Moved file was not removed"
    assert file_path.read_text() == "hello e2e", "Restored content does not match"
