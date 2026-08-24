"""Deterministic rollback templates. (Phase 5)"""

import os
import subprocess
from typing import Optional

from safeshell.schemas import ParsedCommand, RollbackAction, RollbackPlan, new_id


def lookup(parsed: ParsedCommand) -> Optional[RollbackPlan]:
    """Pattern match standard commands and output verified template plans."""
    if parsed.bundle_steps and parsed.bundle_steps > 1:
        return None

    exe = parsed.executable
    args = parsed.arguments
    flags = parsed.flags
    resolved = parsed.resolved_paths

    actions = []

    def get_mode(path):
        try:
            return os.lstat(path).st_mode
        except:
            return None

    def get_owner(path):
        try:
            st = os.lstat(path)
            return st.st_uid, st.st_gid
        except:
            return None, None

    if exe == "mv" and len(args) == 2:
        src, dst = args
        actions.append(RollbackAction(type="restore_file", target=src, order=1, params={}))
        actions.append(
            RollbackAction(
                type="remove_artifact", target=dst, order=2, params={"only_if_created": True}
            )
        )

    elif exe == "cp" and len(args) == 2:
        src, dst = args
        b_new = not os.path.exists(dst)
        if b_new:
            actions.append(
                RollbackAction(
                    type="remove_artifact", target=dst, order=2, params={"only_if_created": True}
                )
            )
        else:
            actions.append(RollbackAction(type="restore_file", target=dst, order=len(actions) + 1))

    elif exe == "rm":
        # Check recursive
        is_rec = any(f in ("-r", "-R", "--recursive") for f in flags) or any(
            f.startswith("-") and not f.startswith("--") and ("r" in f or "R" in f) for f in flags
        )
        for t in resolved:
            if is_rec and os.path.isdir(t):
                actions.append(
                    RollbackAction(type="restore_directory", target=t, order=len(actions) + 1)
                )
            else:
                actions.append(
                    RollbackAction(type="restore_file", target=t, order=len(actions) + 1)
                )

    elif exe == "touch":
        for t in resolved:
            f_new = not os.path.exists(t)
            if f_new:
                actions.append(
                    RollbackAction(
                        type="remove_artifact",
                        target=t,
                        params={"only_if_created": True},
                        order=len(actions) + 1,
                    )
                )
            else:
                actions.append(
                    RollbackAction(type="verify_checksum", target=t, order=len(actions) + 1)
                )

    elif exe == "chmod":
        for t in resolved:
            pre_mode = get_mode(t)
            actions.append(
                RollbackAction(
                    type="restore_permissions",
                    target=t,
                    params={"mode": pre_mode},
                    order=len(actions) + 1,
                )
            )

    elif exe == "chown":
        for t in resolved:
            uid, gid = get_owner(t)
            actions.append(
                RollbackAction(
                    type="restore_ownership",
                    target=t,
                    params={"uid": uid, "gid": gid},
                    order=len(actions) + 1,
                )
            )

    elif exe == "mkdir":
        for t in resolved:
            actions.append(
                RollbackAction(
                    type="remove_artifact",
                    target=t,
                    params={"only_if_created": True},
                    order=len(actions) + 1,
                )
            )

    elif exe == "ln":
        if len(args) >= 2:
            l = args[-1]
            actions.append(
                RollbackAction(
                    type="remove_artifact",
                    target=l,
                    params={"only_if_created": True},
                    order=len(actions) + 1,
                )
            )

    elif exe == "systemctl" and len(args) >= 1:
        verb = args[0]
        if verb == "stop" and len(args) >= 2:
            srv = args[1]
            # get current state
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", srv], capture_output=True, text=True, timeout=2
                )
                was_active = res.stdout.strip() == "active"
            except:
                was_active = False
            actions.append(
                RollbackAction(
                    type="restart_service",
                    target=srv,
                    params={"was_active": was_active},
                    order=len(actions) + 1,
                )
            )
        elif verb == "start" and len(args) >= 2:
            srv = args[1]
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", srv], capture_output=True, text=True, timeout=2
                )
                was_inactive = res.stdout.strip() != "active"
            except:
                was_inactive = True
            if was_inactive:
                actions.append(
                    RollbackAction(type="no_op_external_flag", target=srv, order=len(actions) + 1)
                )

    if not actions:
        return None

    return RollbackPlan(
        plan_id=new_id("pln"),
        command_id=new_id("cmd"),
        source="template",
        confidence=1.0,
        actions=actions,
        validated=False,
        signature=None,
        requires_snapshot=any(a.type in ("restore_directory", "restore_file") for a in actions),
    )
