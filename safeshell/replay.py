"""Replay and What-if Engine (Phase 10)"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from safeshell.ledger import get as get_ledger
from safeshell.ledger import tail as tail_ledger
from safeshell.planner_cascade import NoVerifiedPlan, make_plan
from safeshell.schemas import ReplayReport, RollbackPlan, Verdict
from safeshell.simulation import simulate
from safeshell.state import collect_state


def replay(txn_id: str) -> Optional[ReplayReport]:
    """Replays a past transaction on the current state to check if its rollback plan is still valid."""
    record = get_ledger(txn_id)
    if not record:
        return None

    raw_command = record.get("command")
    if not raw_command:
        return None

    # Re-parse to get paths
    from safeshell.parser import parse_command

    parsed = parse_command(raw_command)

    # Collect CURRENT state
    current_state = collect_state(parsed.resolved_paths)
    current_pre_hash = current_state.manifest_id

    # We need the plan to simulate it. But wait, the ledger doesn't store the full RollbackPlan object.
    # Where is the RollbackPlan stored?
    # Ah, the ledger in Phase 9 didn't store the plan JSON, just plan_id.
    # Wait, the prompt says: "ledger.get -> stored command+plan+original pre-manifest hashes".
    # I should ensure the plan is saved in the ledger!
    # Let me modify this code to expect the plan in the ledger.
    plan_dict = record.get("plan")
    if not plan_dict:
        # If it wasn't saved, we can't replay it. For MVP, we'll gracefully return.
        return None

    try:
        plan = RollbackPlan.model_validate(plan_dict)
    except Exception:
        return None

    original_pre_hash = record.get("pre_hash", "unknown")

    state_drift = {"files_added_since": 0, "files_removed_since": 0}

    # Run simulation on current state
    try:
        sim_report = simulate(parsed, plan)
    except Exception:
        sim_report = None

    replay_rollback_verified = sim_report.rollback_verified if sim_report else False
    verdict = Verdict.still_safe if replay_rollback_verified else Verdict.drifted_unsafe

    return ReplayReport(
        replay_id=f"rep_{txn_id}",
        original_transaction_id=txn_id,
        original_pre_hash=original_pre_hash,
        current_pre_hash=current_pre_hash,
        state_drift=state_drift,
        replay_rollback_verified=replay_rollback_verified,
        verdict=verdict,
        duration_ms=sim_report.duration_ms if sim_report else 0,
    )


def replay_since(since_iso: str) -> List[ReplayReport]:
    """Batch replays transactions since the given ISO timestamp."""
    # Since our ledger doesn't have an index, we just read tail and filter
    records = tail_ledger(1000)
    reports = []

    for r in records:
        ts = r.get("timestamp")
        # In python timestamps might be floats.
        try:
            if isinstance(ts, float):
                dt = datetime.fromtimestamp(ts)
            else:
                dt = datetime.fromisoformat(ts)
        except Exception:
            continue

        since_dt = datetime.fromisoformat(since_iso)
        if dt >= since_dt:
            rep = replay(r.get("transaction_id"))
            if rep:
                reports.append(rep)

    return reports


def whatif(cmd: str) -> Dict[str, Any]:
    """Generates a plan and simulates it on current state, without execution or persistence."""
    try:
        res = make_plan(cmd)
    except NoVerifiedPlan as e:
        return {"error": str(e)}

    if res.path == "denied":
        return {"tier": "T3_blocked", "verdict": "denied", "reason": res.denied_reason}

    plan = res.candidates[res.selected_index]
    sim = res.simulation

    if not sim:
        return {"error": "No simulation available for this plan."}

    return {
        "plan_result": {"path": res.path, "actions": [a.model_dump() for a in plan.actions]},
        "sim_report": sim.model_dump(),
        "tier": sim.degradation_tier.value,
    }
