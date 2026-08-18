"""SafeShell IPC executor.

Bridges the Python orchestrator to the Rust safeshell-core binary via
stdin/stdout JSON-lines IPC. Every core operation — state collection,
snapshots, sandbox execution, simulation — flows through call_core().
"""

import json
import subprocess
from pathlib import Path

from safeshell.config import CORE_BIN
from safeshell.schemas import CoreRequest, CoreResponse


class CoreBinaryMissing(FileNotFoundError):
    """Raised when the safeshell-core binary is not found."""


class CoreError(RuntimeError):
    """Raised on IPC failures (bad JSON, timeout, non-zero exit)."""


def call_core(request: CoreRequest, timeout: int = 30) -> CoreResponse:
    """Send a JSON-lines request to safeshell-core and return the parsed response.

    Args:
        request: The CoreRequest to send.
        timeout: Maximum seconds to wait for a response.

    Returns:
        A CoreResponse parsed from the binary's stdout.

    Raises:
        CoreBinaryMissing: If the safeshell-core binary does not exist.
        CoreError: On JSON parse failure or subprocess timeout.
    """
    bin_path = Path(CORE_BIN)
    if not bin_path.exists():
        raise CoreBinaryMissing(
            f"safeshell-core not found at {bin_path}; run `make build`"
        )

    payload = request.model_dump_json() + "\n"

    try:
        result = subprocess.run(
            [str(bin_path)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise CoreError(f"safeshell-core timed out after {timeout}s") from exc

    stdout = result.stdout.strip()
    if not stdout:
        raise CoreError("safeshell-core produced no output")

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CoreError(f"safeshell-core returned invalid JSON: {stdout!r}") from exc

    return CoreResponse.model_validate(data)


def raise_for_error(response: CoreResponse) -> None:
    """Raise CoreError if the response indicates failure.

    Args:
        response: The CoreResponse to check.

    Raises:
        CoreError: If response.ok is False.
    """
    if not response.ok:
        raise CoreError(response.error or "Unknown core error")
