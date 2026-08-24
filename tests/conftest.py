"""Shared test fixtures for SafeShell."""

import os

import pytest

from safeshell.config import CORE_BIN


def pytest_collection_modifyitems(config, items):
    """Auto-skip tests marked @pytest.mark.root when not running as root."""
    if os.geteuid() != 0:
        skip_root = pytest.mark.skip(reason="requires root (run with sudo)")
        for item in items:
            if "root" in item.keywords:
                item.add_marker(skip_root)


@pytest.fixture
def core_bin():
    """Skip test if safeshell-core binary is not built."""
    if not CORE_BIN.exists():
        pytest.skip(f"safeshell-core not found at {CORE_BIN}; run `make build`")
    return CORE_BIN
