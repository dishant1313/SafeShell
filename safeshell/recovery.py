"""Recovery execution engine. (Phase 9)"""

import os
import subprocess

from safeshell.executor import call_core
from safeshell.schemas import ActionType, RollbackPlan, StateManifest


class ManualInterventionRequired(Exception):
    pass


def rollback(plan: RollbackPlan, pre_state: StateManifest):
    # Sort actions by order
    actions = sorted(plan.actions, key=lambda a: a.order)

    # 3-tier recovery (L1 Render/Execute plan, L2 Snapshot, L3 Manual console)
    # Actually if snapshot is required we do L2
    if plan.requires_snapshot:
        # L2 Snapshot
        # get snapshot ref. We should have taken it during plan generation or simulation.
        # If no snapshot ref, we might fail to L3.
        ref = actions[0].snapshot_ref if actions and actions[0].snapshot_ref else None
        if not ref:
            if plan.simulation and plan.simulation.snapshot_id:
                ref = plan.simulation.snapshot_id

        if ref:
            res = call_core("restore", {"snapshot_id": ref})
            if res.get("error"):
                raise ManualInterventionRequired(
                    "L2 Snapshot restore failed, manual intervention required"
                )
            return

    # L1 Render/Execute plan
    for action in actions:
        if action.type == ActionType.restore_file:
            # We don't have L1 file restore if not in snapshot?
            # Unless we have a backup. Usually requires snapshot.
            if plan.requires_snapshot:
                continue
        elif action.type == ActionType.remove_artifact:
            # L1 rm
            try:
                if os.path.isdir(action.target):
                    subprocess.run(["rm", "-rf", action.target], check=False)
                else:
                    os.remove(action.target)
            except Exception:
                pass
        elif action.type == ActionType.restart_service:
            was_active = action.params.get("was_active", False) if action.params else False
            if was_active:
                subprocess.run(["systemctl", "start", action.target], check=False)
            else:
                subprocess.run(["systemctl", "stop", action.target], check=False)
        elif action.type == ActionType.restore_permissions:
            mode = action.params.get("mode") if action.params else None
            if mode is not None:
                try:
                    os.chmod(action.target, mode)
                except:
                    pass
        elif action.type == ActionType.restore_ownership:
            uid = action.params.get("uid") if action.params else None
            gid = action.params.get("gid") if action.params else None
            if uid is not None and gid is not None:
                try:
                    os.chown(action.target, uid, gid)
                except:
                    pass
