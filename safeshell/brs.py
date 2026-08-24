"""Blast Radius Score (BRS) calculator."""

import glob
import os
from typing import List

import yaml
from pydantic import BaseModel, ValidationError

from safeshell.schemas import ParsedCommand, RiskInfo, RiskLevel
from safeshell.state import collect_state


class BrsConfig(BaseModel):
    brs_version: str
    size_weight: float
    system_path_multiplier: float
    system_paths: List[str]
    no_snapshot_multiplier: float
    recursive_delete_per_file: float
    service_dependent_weight: float
    network_egress: float
    privilege_escalation: float
    wildcard_over_100: float
    critical_sentinel: int


_BRS_CONFIG = None

from safeshell.schemas import BlastRadius


def load_brs_config() -> BrsConfig:
    global _BRS_CONFIG
    if _BRS_CONFIG is not None:
        return _BRS_CONFIG

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "brs.yaml")
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    try:
        _BRS_CONFIG = BrsConfig(**data)
    except ValidationError as e:
        raise ValueError(f"Invalid BRS config: {e}")

    return _BRS_CONFIG


def snapshot_coverage(path: str) -> bool:
    """Phase 6 wires real snapshot coverage; until then irreversibility multiplier always applies — conservative/fail-closed"""
    return False


def service_dependents(unit: str) -> int:
    try:
        wants = glob.glob(f"/etc/systemd/system/*.wants/{unit}")
        requires = glob.glob(f"/etc/systemd/system/*.requires/{unit}")
        return len(wants) + len(requires)
    except FileNotFoundError:
        return 0


def wildcard_matches(parsed: ParsedCommand) -> int:
    count = 0
    for arg in parsed.arguments:
        if "*" in arg or "?" in arg:
            matches = glob.glob(arg)
            count += len(matches)
            if count > 100:
                return 101
    return count


def blast_radius(parsed: ParsedCommand, risk: RiskInfo) -> BlastRadius:
    config = load_brs_config()

    if risk.level == RiskLevel.critical:
        signal = "hard_deny:unknown"
        for s in risk.signals:
            if s.startswith("denylist:"):
                signal = f"hard_deny:{s.split(':', 1)[1]}"
                break
        return BlastRadius(
            score=config.critical_sentinel, brs_version=config.brs_version, top_signals=[signal]
        )

    score_total = 0.0
    signal_contributions = []

    targets = (
        parsed.effect_graph.get("deletes", [])
        + parsed.effect_graph.get("modifies", [])
        + parsed.effect_graph.get("permissions", [])
    )
    targets = list(set(targets))

    if targets:
        manifest = collect_state(targets)
        file_counts = {}
        for fe in manifest.files:
            if fe.exists:
                # Group by top-level target
                for t in targets:
                    if fe.path == t or fe.path.startswith(t + "/"):
                        file_counts[t] = file_counts.get(t, 0) + 1

        for target in targets:
            fc = file_counts.get(target, 1) if os.path.exists(target) else 0
            irr = config.no_snapshot_multiplier if not snapshot_coverage(target) else 1.0
            mult = (
                config.system_path_multiplier
                if any(target.startswith(sp) for sp in config.system_paths)
                else 1.0
            )

            is_recursive = False
            # recursive deletes get extra multiplier per file
            if target in parsed.effect_graph.get("deletes", []):
                is_recursive = any(f in ("-r", "-R", "--recursive") for f in parsed.flags) or any(
                    f.startswith("-") and not f.startswith("--") and ("r" in f or "R" in f)
                    for f in parsed.flags
                )
                if is_recursive:
                    fc *= config.recursive_delete_per_file

            term = fc * config.size_weight * irr * mult
            if term > 0:
                score_total += term
                basename = os.path.basename(target) if os.path.basename(target) else target
                kind = "del" if target in parsed.effect_graph.get("deletes", []) else "mod"
                signal_contributions.append((f"{kind}_{basename}(+{int(term)})", term))
                if is_recursive and target in parsed.effect_graph.get("deletes", []):
                    signal_contributions.append((f"recursive_{basename}(+{int(term)})", term))

    for unit_verb in parsed.effect_graph.get("service_state", []):
        parts = unit_verb.split()
        if len(parts) >= 2:
            unit = parts[1]
        else:
            unit = unit_verb
            deps = service_dependents(unit)
            term = config.service_dependent_weight * (1 + deps)
            score_total += term
            signal_contributions.append((f"service_{unit}_fanout(+{int(term)})", term))

    if parsed.effect_graph.get("network_egress", []):
        score_total += config.network_egress
        signal_contributions.append(
            (f"network_egress(+{int(config.network_egress)})", config.network_egress)
        )

    if parsed.privilege_escalation:
        score_total += config.privilege_escalation
        signal_contributions.append(
            (f"priv_esc(+{int(config.privilege_escalation)})", config.privilege_escalation)
        )

    wc_matches = wildcard_matches(parsed)
    if wc_matches > 100:
        score_total += config.wildcard_over_100
        signal_contributions.append(
            (f"wildcard>100(+{int(config.wildcard_over_100)})", config.wildcard_over_100)
        )

    signal_contributions.sort(key=lambda x: x[1], reverse=True)
    top_signals = [s[0] for s in signal_contributions[:3]]

    return BlastRadius(
        score=int(score_total), brs_version=config.brs_version, top_signals=top_signals
    )
