"""Transaction flow. (Phase 9)"""

import sys

from safeshell.executor import ExecutionAborted, ExecutionFailed, execute_transaction
from safeshell.planner_cascade import NoVerifiedPlan, make_plan


def run_transaction(command: str, accept_irreversible: bool = False, print_output: bool = True):
    try:
        res = make_plan(command, accept_irreversible=accept_irreversible)
    except NoVerifiedPlan as e:
        if print_output:
            print(f"Transaction denied: {e}")
        sys.exit(2)

    if res.path == "denied":
        if print_output:
            print(f"Transaction denied: {res.denied_reason}")
        sys.exit(2)

    if print_output:
        print(f"Generated {res.path} plan")
    plan = res.candidates[res.selected_index]
    if print_output:
        print(f"Executing plan: {plan.plan_id}")

    from datetime import datetime, timezone

    from safeshell.learn import maybe_writeback
    from safeshell.ledger import append as append_ledger

    execution_info = {
        "status": "committed",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "divergence_detected": False,
    }

    try:
        result = execute_transaction(plan, command)
        execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
        if print_output:
            print("Transaction succeeded.")
    except ExecutionAborted as e:
        execution_info["status"] = "blocked"
        execution_info["divergence_detected"] = True
        execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
        if print_output:
            print(f"Transaction aborted: {e}")
    except ExecutionFailed as e:
        execution_info["status"] = "rolled_back"
        execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
        if print_output:
            print(f"Transaction failed and rolled back: {e}")

    analysis = res.analysis

    # build minimal dict representing TransactionRecord initially
    record_dict = {
        "transaction_id": plan.plan_id,
        "command_id": analysis.command_id if analysis else plan.command_id,
        "plan_id": plan.plan_id,
        "simulation_id": plan.simulation.simulation_id if plan.simulation else "none",
        "approval": {
            "required": True,
            "mode": "human",
            "approved_by": "user",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        },
        "execution": execution_info,
        "learning": {"template_written_back": False, "template_id": None},
        "brs": analysis.blast_radius.score if analysis and hasattr(analysis, "blast_radius") else 0,
        "brs_version": analysis.blast_radius.brs_version
        if analysis and hasattr(analysis, "blast_radius")
        else "v1",
        "plan": plan.model_dump(),
        "pre_hash": plan.simulation.pre_manifest.manifest_id
        if (
            plan.simulation
            and hasattr(plan.simulation, "pre_manifest")
            and plan.simulation.pre_manifest
        )
        else "unknown",
        "prev_hash": "",
        "entry_hash": "",
    }

    if analysis and plan.simulation:
        record_dict = maybe_writeback(record_dict, plan, analysis, plan.simulation)

    append_ledger(record_dict)

    if execution_info["status"] != "committed":
        sys.exit(1)
