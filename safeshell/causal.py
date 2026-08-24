"""Causal undo ordering and graph generation. (Phase 9)"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from safeshell.schemas import ActionType, ParsedCommand, RollbackAction, StateManifest
from safeshell.templates import lookup


class ExternalEffect(Exception):
    """Raised when an external effect (like network egress) is detected in the causal graph."""

    def __init__(self, msg, partial_actions=None):
        super().__init__(msg)
        self.partial_actions = partial_actions or []


@dataclass
class EffectGraph:
    nodes: List[ParsedCommand]
    edges: Dict[int, List[Tuple[int, str]]] = field(default_factory=dict)


def build_graph(steps: List[ParsedCommand]) -> EffectGraph:
    graph = EffectGraph(nodes=steps, edges={i: [] for i in range(len(steps))})
    last_created = {}
    last_written = {}
    last_deleted = {}

    for j, step in enumerate(steps):
        creates = set(step.effect_graph.get("creates", []))
        deletes = set(step.effect_graph.get("deletes", []))
        modifies = set(step.effect_graph.get("modifies", []))

        consumes = set()
        if step.executable in ("cp", "tar", "cat"):
            for path in step.resolved_paths:
                if path not in creates and path not in deletes and path not in modifies:
                    consumes.add(path)

        for idx, arg in enumerate(step.arguments):
            if arg == "<" and idx + 1 < len(step.arguments):
                consumes.add(step.arguments[idx + 1])
            elif arg.startswith("<") and len(arg) > 1:
                consumes.add(arg[1:])

        for path in creates:
            if path in last_deleted:
                graph.edges[j].append((last_deleted[path], "created_by"))
        for path in deletes:
            if path in last_created:
                graph.edges[j].append((last_created[path], "deleted_after_create"))
            elif path in last_written:
                graph.edges[j].append((last_written[path], "deleted_after_write"))
        for path in modifies:
            if path in last_created:
                graph.edges[j].append((last_created[path], "modified_after_create"))
            elif path in last_written:
                graph.edges[j].append((last_written[path], "modified_after_write"))
        for path in consumes:
            if path in last_created:
                graph.edges[j].append((last_created[path], "consumed_by"))
            elif path in last_written:
                graph.edges[j].append((last_written[path], "consumed_by"))

        for path in creates:
            last_created[path] = j
            last_written[path] = j
            if path in last_deleted:
                del last_deleted[path]
        for path in modifies:
            last_written[path] = j
        for path in deletes:
            last_deleted[path] = j
            if path in last_created:
                del last_created[path]
            if path in last_written:
                del last_written[path]

    return graph


def _is_path_contained(parent: str, child: str) -> bool:
    try:
        parent_real = os.path.realpath(parent)
        child_real = os.path.realpath(child)
        return child_real.startswith(parent_real + os.sep) or parent_real == child_real
    except Exception:
        return child.startswith(parent + "/") or parent == child


def order_undo(graph: EffectGraph, pre_state: StateManifest) -> List[RollbackAction]:
    actions = []
    covered_steps = set()
    external_found = False
    external_msg = ""

    for i in range(len(graph.nodes) - 1, -1, -1):
        if i in covered_steps:
            continue

        step = graph.nodes[i]

        if step.effect_graph.get("network_egress"):
            external_found = True
            external_msg = f"Step {i} ({step.executable}) performs external network egress"

        creates = step.effect_graph.get("creates", [])
        deletes = step.effect_graph.get("deletes", [])
        modifies = step.effect_graph.get("modifies", [])

        step_plan = lookup(step)
        step_actions = step_plan.actions if step_plan else []

        if not step_actions:
            if step.executable in ("rm", "unlink"):
                for path in deletes:
                    is_dir = False
                    for f in pre_state.files:
                        if f.path == path and f.mode & 0o40000:
                            is_dir = True
                            break
                    if is_dir:
                        step_actions.append(
                            RollbackAction(type=ActionType.restore_directory, target=path, order=0)
                        )
                    else:
                        step_actions.append(
                            RollbackAction(type=ActionType.restore_file, target=path, order=0)
                        )
            elif step.executable in ("mkdir", "touch"):
                for path in creates:
                    step_actions.append(
                        RollbackAction(type=ActionType.remove_artifact, target=path, order=0)
                    )
            elif step.executable in ("cp", "mv"):
                for path in creates:
                    step_actions.append(
                        RollbackAction(type=ActionType.remove_artifact, target=path, order=0)
                    )
                for path in modifies:
                    step_actions.append(
                        RollbackAction(type=ActionType.restore_file, target=path, order=0)
                    )
                for path in deletes:
                    step_actions.append(
                        RollbackAction(type=ActionType.restore_file, target=path, order=0)
                    )
            else:
                for path in modifies:
                    step_actions.append(
                        RollbackAction(type=ActionType.restore_file, target=path, order=0)
                    )
                for path in deletes:
                    step_actions.append(
                        RollbackAction(type=ActionType.restore_file, target=path, order=0)
                    )
                for path in creates:
                    step_actions.append(
                        RollbackAction(type=ActionType.remove_artifact, target=path, order=0)
                    )

        for action in step_actions:
            if action.type == ActionType.restore_directory:
                for k in range(i - 1, -1, -1):
                    if k in covered_steps:
                        continue
                    prev_step = graph.nodes[k]
                    all_targets = (
                        prev_step.effect_graph.get("creates", [])
                        + prev_step.effect_graph.get("deletes", [])
                        + prev_step.effect_graph.get("modifies", [])
                    )
                    if all_targets and all(
                        _is_path_contained(action.target, t) for t in all_targets
                    ):
                        covered_steps.add(k)
                        if action.undoes_steps is None:
                            action.undoes_steps = []
                        action.undoes_steps.append(str(k))

            action.order = len(actions) + 1
            actions.append(action)

    if external_found:
        raise ExternalEffect(external_msg, partial_actions=actions)

    return actions
