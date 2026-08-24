"""SafeShell IPC executor."""

import json
import subprocess
from pathlib import Path

from safeshell.config import CORE_BIN
from safeshell.schemas import CoreRequest, CoreResponse


class CoreBinaryMissing(FileNotFoundError):
    pass


class CoreError(RuntimeError):
    pass


def call_core(request: CoreRequest, timeout: int = 30) -> CoreResponse:
    bin_path = Path(CORE_BIN)
    debug_bin_path = Path(__file__).parent.parent / "core" / "target" / "debug" / "safeshell-core"

    if not bin_path.exists():
        if debug_bin_path.exists():
            bin_path = debug_bin_path
        else:
            raise CoreBinaryMissing(f"safeshell-core not found at {bin_path}")

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
        raise CoreError(f"safeshell-core produced no output. stderr: {result.stderr}")

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CoreError(f"safeshell-core returned invalid JSON: {stdout!r}") from exc

    return CoreResponse.model_validate(data)


def raise_for_error(response: CoreResponse) -> None:
    if not response.ok:
        raise CoreError(response.error or "Unknown core error", response.data)


def take_snapshot(
    paths: list[str],
    snapshot_id: str,
    snapshots_dir: str,
    services: list[str] = None,
    max_files: int = 5000,
) -> dict:
    params = {
        "paths": paths,
        "snapshot_id": snapshot_id,
        "snapshots_dir": snapshots_dir,
        "services": services or [],
        "max_files": max_files,
    }
    req = CoreRequest(op="snapshot", params=params)
    resp = call_core(req)
    raise_for_error(resp)
    return resp.data


def restore_snapshot(snapshot_id: str, snapshots_dir: str) -> dict:
    params = {"snapshot_id": snapshot_id, "snapshots_dir": snapshots_dir}
    req = CoreRequest(op="restore", params=params)
    resp = call_core(req)
    raise_for_error(resp)
    return resp.data


def sandbox_exec(
    argv: list[str],
    scope_paths: list[str],
    timeout_s: int = 10,
    allow_network: bool = False,
    monitor_policy: dict | None = None,
) -> dict:
    req = CoreRequest(
        op="sandbox_exec",
        params={
            "argv": argv,
            "scope_paths": scope_paths,
            "timeout_s": timeout_s,
            "allow_network": allow_network,
            "monitor_policy": monitor_policy,
        },
    )
    resp = call_core(req)
    if not resp.ok:
        raise CoreError(resp.error or "Unknown sandbox error", resp.data)
    return resp.data


from typing import Any, Dict

from safeshell.parser import parse_bundle
from safeshell.recovery import rollback
from safeshell.schemas import RollbackPlan
from safeshell.state import collect_state


class ExecutionAborted(Exception):
    pass


class ExecutionFailed(Exception):
    pass


def execute_transaction(plan: RollbackPlan, raw: str) -> Dict[str, Any]:
    steps = parse_bundle(raw)
    paths = set()
    for s in steps:
        paths.update(s.resolved_paths)

    current_state = collect_state(list(paths))

    if plan.simulation and plan.simulation.pre_manifest:
        sim_pre = plan.simulation.pre_manifest
        for f in current_state.files:
            sim_f = next((x for x in sim_pre.files if x.path == f.path), None)
            if sim_f and sim_f.sha256 != f.sha256:
                raise ExecutionAborted(f"TOCTOU abort: State changed for {f.path}")

    results = []
    failed = False

    for step in steps:
        argv = []
        if step.privilege_escalation:
            pass  # We run as root anyway in backend usually
        argv.append(step.executable)
        argv.extend(step.flags)
        argv.extend(step.arguments)

        try:
            from safeshell.schemas import CoreRequest

            req = CoreRequest(op="execute", params={"argv": argv, "timeout_s": 30})
            res = call_core(req)
            if res.ok:
                results.append(res.data)
                if res.data.get("exit_code", -1) != 0:
                    failed = True
                    break
            else:
                results.append({"error": res.error})
                failed = True
                break
        except Exception as e:
            results.append({"error": str(e)})
            failed = True
            break

    if failed:
        rollback(plan, current_state)
        raise ExecutionFailed("Transaction failed and rolled back.")

    return {"status": "success", "results": results}
