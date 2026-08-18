"""Shared test fixtures for SafeShell."""

import pytest

from safeshell.config import CORE_BIN


@pytest.fixture
def core_bin():
    """Skip test if safeshell-core binary is not built."""
    if not CORE_BIN.exists():
        pytest.skip(f"safeshell-core not found at {CORE_BIN}; run `make build`")
    return CORE_BIN
