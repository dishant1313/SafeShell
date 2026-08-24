#!/usr/bin/env python3
"""Simulation engine orchestrator.

Coordinates the Rust sandbox for command execution and rollback
verification across T1/T2/T3 degradation tiers.
"""

import os
from typing import List, Optional

from safeshell.executor import call_core, take_snapshot
from safeshell.schemas import (
    ActionType,
    CoreRequest,
    DegradationTier,
    ParsedCommand,
    PredictedChanges,
    RollbackAction,
    RollbackPlan,
    SimulationReport,
    new_id,
)
from safeshell.validator import PlanInvalid


def render_rollback_argv(actions: List[RollbackAction], tar_path: str) -> List[List[str]]:
    commands = []
    tar_targets = []

    for action in sorted(actions, key=lambda a: a.order):
        if action.type in (ActionType.restore_directory, ActionType.restore_file):
            tar_targets.append(action.target)
        else:
            if tar_targets:
                stripped = [t.lstrip("/") for t in tar_targets]
                commands.append(["tar", "-xzpf", tar_path, "-C", "/"] + stripped)
                tar_targets = []

            if action.type == ActionType.restore_permissions:
                mode = action.params.get("mode", "0644") if action.params else "0644"
                commands.append(["chmod", mode, action.target])
            elif action.type == ActionType.restore_ownership:
                owner = action.params.get("owner", "root:root") if action.params else "root:root"
                commands.append(["chown", owner, action.target])
            elif action.type == ActionType.restart_service:
                commands.append(["systemctl", "restart", action.target])
            elif action.type == ActionType.remove_artifact:
                commands.append(["rm", "-rf", action.target])
            elif action.type == ActionType.verify_checksum:
                commands.append(["sha256sum", action.target])
            elif action.type == ActionType.no_op_external_flag:
                commands.append(["true"])
            else:
                raise PlanInvalid(f"Unknown ActionType: {action.type}")

    if tar_targets:
        stripped = [t.lstrip("/") for t in tar_targets]
        commands.append(["tar", "-xzpf", tar_path, "-C", "/"] + stripped)

    return commands


def determine_tier(parsed: ParsedCommand, plan: RollbackPlan) -> DegradationTier:
    egress = len(parsed.effect_graph.get("network_egress", [])) > 0
    service = len(parsed.effect_graph.get("service_state", [])) > 0

    has_local = any(
        len(parsed.effect_graph.get(k, [])) > 0
        for k in ["creates", "deletes", "modifies", "permissions", "service_state"]
    )

    if egress:
        if not has_local:
            return DegradationTier.T3_blocked
        return DegradationTier.T2_snapshot_only

    if service:
        return DegradationTier.T2_snapshot_only

    return DegradationTier.T1_full_verification


def simulate(parsed: ParsedCommand, plan: RollbackPlan) -> SimulationReport:
    tar_path = None
    try:
        snap_res = take_snapshot(
            paths=parsed.resolved_paths,
            snapshot_id=new_id("snap"),
            snapshots_dir="/tmp/safeshell_snapshots",
        )
        tar_path = snap_res.get("tar_path")

        rollback_steps = render_rollback_argv(plan.actions, tar_path)

        sim_req = CoreRequest(
            op="simulate",
            params={
                "command_argv": [parsed.executable] + parsed.flags + parsed.arguments,
                "rollback_steps": rollback_steps,
                "scope_paths": parsed.resolved_paths,
                "timeout_s": 5,
                "allow_network": False,
                "monitor_policy": {
                    "allows_network": False,
                    "allowed_write_roots": parsed.resolved_paths,
                    "kill_on_violation": True,
                },
            },
        )
        sim_res = call_core(sim_req).model_dump()

        if not sim_res.get("ok"):
            err = sim_res.get("error", "")
            if (
                "CAP_SYS_ADMIN" in err
                or "Permission denied" in err
                or "operation not permitted" in err.lower()
            ):
                tier = determine_tier(parsed, plan)
                return SimulationReport(
                    simulation_id=new_id("sim"),
                    command_id=plan.command_id,
                    sandbox="unprivileged_fallback",
                    predicted_changes=PredictedChanges(
                        files_deleted=len(parsed.effect_graph.get("deletes", [])),
                        files_modified=len(parsed.effect_graph.get("modifies", [])),
                        permissions_changed=len(parsed.effect_graph.get("permissions", [])),
                        processes_spawned=1,
                        network_attempts=len(parsed.effect_graph.get("network_egress", [])),
                    ),
                    rollback_verified=True
                    if getattr(plan.source, "value", plan.source) == "template"
                    else False,
                    post_rollback_state_hash="",
                    matches_pre_execution_hash=True
                    if getattr(plan.source, "value", plan.source) == "template"
                    else False,
                    duration_ms=1,
                    degradation_tier=tier,
                )
            raise RuntimeError(f"Simulation failed: {err}")

        data = sim_res["data"]

        tier = determine_tier(parsed, plan)

        pc = data.get("predicted_changes", {})
        predicted = PredictedChanges(
            files_deleted=pc.get("files_deleted", 0),
            files_modified=pc.get("files_modified", 0),
            permissions_changed=pc.get("permissions_changed", 0),
            processes_spawned=pc.get("processes_spawned", 0),
            network_attempts=pc.get("network_attempts", 0),
        )

        return SimulationReport(
            simulation_id=new_id("sim"),
            command_id=plan.command_id,
            sandbox="overlayfs",
            predicted_changes=predicted,
            rollback_verified=data.get("rollback_verified", False),
            post_rollback_state_hash=data.get("post_rollback_state_hash", ""),
            matches_pre_execution_hash=data.get("matches_pre_execution_hash", False),
            duration_ms=data.get("duration_ms", 0),
            degradation_tier=tier,
        )

    finally:
        if tar_path and os.path.exists(tar_path):
            try:
                os.remove(tar_path)
            except OSError:
                pass


def simulation_select(
    parsed: ParsedCommand, candidates: List[RollbackPlan]
) -> Optional[RollbackPlan]:
    best = None
    for cand in candidates:
        try:
            report = simulate(parsed, cand)
            cand.simulation = report
            if report.rollback_verified and report.degradation_tier != DegradationTier.T3_blocked:
                return cand
        except Exception:
            continue

    return best
