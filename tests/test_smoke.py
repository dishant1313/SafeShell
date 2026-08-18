"""Smoke tests for SafeShell basics."""

import subprocess
import sys

from safeshell.config import ensure_dirs


def test_ensure_dirs_creates_directories(tmp_path, monkeypatch) -> None:
    """ensure_dirs creates all required runtime directories."""
    import safeshell.config as cfg

    monkeypatch.setattr(cfg, "RUNTIME_DIR", tmp_path / ".safeshell")
    monkeypatch.setattr(cfg, "SNAPSHOTS_DIR", tmp_path / ".safeshell" / "snapshots")
    monkeypatch.setattr(cfg, "TXNS_DIR", tmp_path / ".safeshell" / "txns")
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(cfg, "MODELS_DIR", tmp_path / "models")
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path / "config")
    ensure_dirs()
    assert (tmp_path / ".safeshell").is_dir()
    assert (tmp_path / ".safeshell" / "snapshots").is_dir()
    assert (tmp_path / ".safeshell" / "txns").is_dir()


def test_version_command() -> None:
    """python -m safeshell version exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "safeshell", "version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "safeshell" in result.stdout.lower()
