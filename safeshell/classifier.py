"""SafeShell Phase 3 - Risk Classification Module.

Handles deterministic risk evaluation via DENY_RULES and ML-based classification
via XGBoost for fuzzy cases.
"""

import logging
import os
import re
import warnings
from typing import List, Tuple

import joblib

from safeshell.schemas import ParsedCommand, RiskInfo, RiskLevel

logger = logging.getLogger(__name__)

FAMILY_TABLE = [
    "rm",
    "mv",
    "cp",
    "touch",
    "chmod",
    "chown",
    "mkdir",
    "ln",
    "systemctl",
    "tar",
    "dd",
    "apt",
    "apt-get",
    "curl",
    "wget",
    "cat",
    "ls",
    "sh",
    "bash",
]

_MODEL_CACHE = None
_MODEL_LOADED = False


def get_model():
    global _MODEL_CACHE, _MODEL_LOADED
    if not _MODEL_LOADED:
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "models", "risk_model.joblib"
        )
        if os.path.exists(model_path):
            try:
                _MODEL_CACHE = joblib.load(model_path)
            except Exception as e:
                logger.warning(f"Failed to load risk model: {e}")
        else:
            logger.warning("Models directory missing risk_model.joblib; using rules-only fallback.")
        _MODEL_LOADED = True
    return _MODEL_CACHE


def _count_target_files(targets: list[str], cap: int = 5000) -> int:
    count = 0
    for target in targets:
        if not os.path.exists(target):
            continue
        if os.path.isfile(target):
            count += 1
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                count += len(files)
                if count >= cap:
                    return cap
    return min(count, cap)


def featurize(parsed: ParsedCommand, raw: str) -> list[float]:
    recursive_flag = False
    force_flag = False
    for f in parsed.flags:
        if f in ("-r", "-R", "--recursive"):
            recursive_flag = True
        elif f.startswith("-") and not f.startswith("--") and ("r" in f or "R" in f):
            recursive_flag = True

        if f in ("-f", "--force"):
            force_flag = True
        elif f.startswith("-") and not f.startswith("--") and "f" in f:
            force_flag = True

    recursive = 1.0 if recursive_flag else 0.0
    force = 1.0 if force_flag else 0.0
    wildcards = 1.0 if "*" in raw or "?" in raw else 0.0

    pipe_to_shell = 1.0 if any(p in ("sh", "bash", "dash", "zsh") for p in parsed.pipes) else 0.0
    redirect_write = 1.0 if ">" in raw or ">>" in raw else 0.0
    priv_esc = 1.0 if parsed.privilege_escalation else 0.0

    path_etc = 1.0 if any(p.startswith("/etc") for p in parsed.resolved_paths) else 0.0
    path_boot = 1.0 if any(p.startswith("/boot") for p in parsed.resolved_paths) else 0.0
    path_dev = 1.0 if any(p.startswith("/dev") for p in parsed.resolved_paths) else 0.0
    path_var = 1.0 if any(p.startswith("/var") for p in parsed.resolved_paths) else 0.0
    path_usr = 1.0 if any(p.startswith("/usr") for p in parsed.resolved_paths) else 0.0

    directory_target = (
        1.0 if any(os.path.isdir(p) for p in parsed.resolved_paths if os.path.exists(p)) else 0.0
    )
    compound_ops = (
        1.0
        if parsed.bundle_steps > 1 or len(parsed.pipes) > 0 or "&&" in raw or ";" in raw
        else 0.0
    )

    unknown_effects = 1.0 if len(parsed.effect_graph.get("process_spawn", [])) > 0 else 0.0

    deletes_count = float(len(parsed.effect_graph.get("deletes", [])))
    creates_count = float(len(parsed.effect_graph.get("creates", [])))
    modifies_count = float(len(parsed.effect_graph.get("modifies", [])))
    permissions_count = float(len(parsed.effect_graph.get("permissions", [])))
    service_count = float(len(parsed.effect_graph.get("service_state", [])))
    network_count = float(len(parsed.effect_graph.get("network_egress", [])))

    targets = parsed.effect_graph.get("deletes", []) + parsed.effect_graph.get("modifies", [])
    target_file_count = float(_count_target_files(targets))

    try:
        exec_family_id = float(FAMILY_TABLE.index(parsed.executable))
    except ValueError:
        exec_family_id = float(len(FAMILY_TABLE))

    return [
        recursive,
        force,
        wildcards,
        pipe_to_shell,
        redirect_write,
        priv_esc,
        path_etc,
        path_boot,
        path_dev,
        path_var,
        path_usr,
        directory_target,
        compound_ops,
        unknown_effects,
        deletes_count,
        creates_count,
        modifies_count,
        permissions_count,
        service_count,
        network_count,
        target_file_count,
        exec_family_id,
    ]


# DENY_RULES predicates
def _is_rm_root(parsed: ParsedCommand, raw: str) -> bool:
    if parsed.executable != "rm":
        return False
    critical_paths = {"/", "/bin", "/etc", "/usr", "/var", "/boot", "/dev", "~", "/*"}
    return any(p in critical_paths for p in parsed.resolved_paths) or any(
        arg in critical_paths for arg in parsed.arguments
    )


def _is_mkfs(parsed: ParsedCommand, raw: str) -> bool:
    return parsed.executable.startswith("mkfs.")


def _is_dd_dev(parsed: ParsedCommand, raw: str) -> bool:
    if parsed.executable != "dd":
        return False
    return any(arg.startswith("of=/dev/") for arg in parsed.arguments)


def _is_fork_bomb(parsed: ParsedCommand, raw: str) -> bool:
    return bool(re.search(r":?\(\)\s*\{.*\|.*&.*\};", raw))


def _is_chmod_777_root(parsed: ParsedCommand, raw: str) -> bool:
    if parsed.executable != "chmod":
        return False
    recursive = any(f in ("-R", "--recursive") for f in parsed.flags) or any(
        f.startswith("-") and not f.startswith("--") and ("r" in f or "R" in f)
        for f in parsed.flags
    )
    has_777 = "777" in parsed.arguments
    has_root = "/" in parsed.resolved_paths or "/" in parsed.arguments
    return recursive and has_777 and has_root


def _is_pipe_to_shell(parsed: ParsedCommand, raw: str) -> bool:
    return any(p in ("sh", "bash", "dash", "zsh") for p in parsed.pipes)


def _is_shutdown(parsed: ParsedCommand, raw: str) -> bool:
    return parsed.executable in ("shutdown", "reboot")


def _is_redirect_dev_sd(parsed: ParsedCommand, raw: str) -> bool:
    return bool(re.search(r">\s*/dev/sd", raw))


DENY_RULES = [
    ("rm_root", _is_rm_root),
    ("mkfs", _is_mkfs),
    ("dd_dev", _is_dd_dev),
    ("fork_bomb", _is_fork_bomb),
    ("chmod_777_root", _is_chmod_777_root),
    ("pipe_to_shell", _is_pipe_to_shell),
    ("shutdown", _is_shutdown),
    ("redirect_dev_sd", _is_redirect_dev_sd),
]


def rules_tier(parsed: ParsedCommand, raw: str) -> Tuple[RiskLevel, List[str]]:
    signals = []
    is_critical = False

    # Evaluate DENY_RULES
    for name, predicate in DENY_RULES:
        if predicate(parsed, raw):
            signals.append(f"denylist:{name}")
            is_critical = True

    if is_critical:
        return RiskLevel.critical, signals

    features = featurize(parsed, raw)
    (
        recursive,
        force,
        wildcards,
        pipe_to_shell,
        redirect_write,
        priv_esc,
        path_etc,
        path_boot,
        path_dev,
        path_var,
        path_usr,
        directory_target,
        compound_ops,
        unknown_effects,
    ) = features[:14]

    deletes_present = len(parsed.effect_graph.get("deletes", [])) > 0
    modifies_present = len(parsed.effect_graph.get("modifies", [])) > 0
    service_impact = len(parsed.effect_graph.get("service_state", [])) > 0
    system_path = path_etc or path_boot or path_dev or path_var or path_usr
    network_egress = len(parsed.effect_graph.get("network_egress", [])) > 0

    if recursive:
        signals.append("recursive_flag")
    if force:
        signals.append("force_flag")
    if wildcards:
        signals.append("wildcards")
    if redirect_write:
        signals.append("redirect_write")
    if priv_esc:
        signals.append("privilege_escalation")
    if system_path:
        signals.append("system_path")
    if directory_target:
        signals.append("directory_target")
    if compound_ops:
        signals.append("compound_ops")
    if unknown_effects:
        signals.append("unknown_effects")
    if network_egress:
        signals.append("network_egress")
    if service_impact:
        signals.append("service_impact")
    if deletes_present:
        signals.append("deletes_present")

    if (
        (recursive and deletes_present)
        or (priv_esc and deletes_present)
        or (unknown_effects and (deletes_present or modifies_present))
    ):
        return RiskLevel.high, signals

    if (
        system_path
        or service_impact
        or redirect_write
        or (wildcards and deletes_present)
        or compound_ops
    ):
        return RiskLevel.medium, signals

    return RiskLevel.low, signals


def classify(parsed: ParsedCommand, raw: str) -> RiskInfo:
    r_tier, signals = rules_tier(parsed, raw)

    if r_tier == RiskLevel.critical:
        return RiskInfo(level=RiskLevel.critical, signals=signals, score=1.0)

    model = get_model()
    if model:
        features = featurize(parsed, raw)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            probas = model.predict_proba([features])[0]

        s = probas[2] + 0.5 * probas[1]

        if s >= 0.65:
            model_tier = RiskLevel.high
        elif s >= 0.35:
            model_tier = RiskLevel.medium
        else:
            model_tier = RiskLevel.low

        signals.append(f"model:{model_tier.value}")

        ordinals = {RiskLevel.low: 0, RiskLevel.medium: 1, RiskLevel.high: 2}
        final_tier = r_tier if ordinals[r_tier] >= ordinals[model_tier] else model_tier
        return RiskInfo(level=final_tier, signals=signals, score=float(s))
    else:
        score = 0.9 if r_tier == RiskLevel.high else (0.5 if r_tier == RiskLevel.medium else 0.2)
        return RiskInfo(level=r_tier, signals=signals, score=score)
