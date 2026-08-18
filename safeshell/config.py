"""SafeShell configuration and path constants.

Centralises all filesystem paths, model identifiers, and environment overrides.
Every module imports paths from here rather than constructing them ad-hoc.
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIR = REPO_ROOT / ".safeshell"
SNAPSHOTS_DIR = RUNTIME_DIR / "snapshots"
TXNS_DIR = RUNTIME_DIR / "txns"
LEDGER_PATH = RUNTIME_DIR / "ledger.jsonl"
DATA_DIR = REPO_ROOT / "data"
MODELS_DIR = REPO_ROOT / "models"
CONFIG_DIR = REPO_ROOT / "config"
CORE_BIN = REPO_ROOT / "core" / "target" / "release" / "safeshell-core"

OLLAMA_BASE_URL = os.environ.get("SAFESHELL_OLLAMA_URL", "http://localhost:11434/v1")
PLANNER_MODEL = os.environ.get("SAFESHELL_PLANNER_MODEL", "safeshell-planner-3b")
FALLBACK_MODEL = os.environ.get("SAFESHELL_FALLBACK_MODEL", "qwen2.5-coder:1.5b")


def ensure_dirs() -> None:
    """Create all required runtime directories if they do not exist."""
    for d in (RUNTIME_DIR, SNAPSHOTS_DIR, TXNS_DIR, DATA_DIR, MODELS_DIR, CONFIG_DIR):
        d.mkdir(parents=True, exist_ok=True)
