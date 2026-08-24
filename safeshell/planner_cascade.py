"""Planner orchestration cascade. (Phase 5, 8 & 9)"""

from typing import List, Optional

from safeshell.brs import blast_radius, load_brs_config
from safeshell.causal import ExternalEffect, build_graph, order_undo
from safeshell.classifier import classify
from safeshell.parser import parse_bundle, parse_command
from safeshell.planner import PlannerUnavailable, llm_plan_n
from safeshell.policy import evaluate
from safeshell.rag import retrieve
from safeshell.schemas import ParsedCommand, PlanResult, RollbackPlan, new_id
from safeshell.simulation import simulate, simulation_select
from safeshell.state import collect_state
from safeshell.templates import lookup
from safeshell.validator import PlanInvalid, sign_plan, validate


class NoVerifiedPlan(Exception):
    pass


def make_bundle_plan(
    steps: List[ParsedCommand],
    raw: str,
    n_override: Optional[int] = None,
    accept_irreversible: bool = False,
) -> PlanResult:
    # Scope is union of resolved_paths
    paths = set()
    for s in steps:
        paths.update(s.resolved_paths)
    manifest = collect_state(list(paths))

    graph = build_graph(steps)
    import os
    from datetime import datetime, timezone

    from safeshell.schemas import BlastRadius, CommandAnalysis, RiskInfo, RiskLevel

    # create a combined parsed for analysis
    combined_parsed = ParsedCommand(
        executable="bundle",
        flags=[],
        arguments=[raw],
        resolved_paths=list(paths),
        privilege_escalation=any(s.privilege_escalation for s in steps),
        effect_graph={"bundle": True},
        bundle_steps=len(steps),
    )
    analysis = CommandAnalysis(
        command_id=new_id("cmd"),
        raw_command=raw,
        parsed=combined_parsed,
        risk=RiskInfo(level=RiskLevel.high, signals=["bundle"], score=0.8),
        blast_radius=BlastRadius(score=len(paths) * 10, brs_version="v1", top_signals=["bundle"]),
        timestamp=datetime.now(timezone.utc),
        user=os.environ.get("USER", "unknown"),
    )

    tier = "T1"
    try:
        actions = order_undo(graph, manifest)
    except ExternalEffect as e:
        actions = getattr(e, "partial_actions", [])
        tier = "T2"  # caller flags tier T2/T3

    # We create a single RollbackPlan for the bundle
    # source template|rag|ai per step composition, but for simplicity we assume 'template' if all came from template
    # (actually we just used template logic in order_undo fallback)

    plan = RollbackPlan(
        plan_id=new_id("pln"),
        command_id=new_id("cmd"),
        source="template" if tier == "T1" else "ai",
        confidence=1.0 if tier == "T1" else 0.8,
        actions=actions,
        validated=False,
        signature=None,
        requires_snapshot=any(a.type in ("restore_directory", "restore_file") for a in actions),
    )

    # We simulate WHOLE bundle (command steps sequential + rollback steps)
    # The current `simulate(parsed, plan)` expects a single parsed command.
    # We will pass the first step but give it the combined plan. The `simulate` engine in Phase 8
    # uses `parsed` to get executable/args. We should probably merge them or just pass the base step.
    # The prompt says: "simulate WHOLE bundle (command steps sequential + rollback steps) via extended simulate"
    # Wait, Phase 8 simulate accepts a single ParsedCommand. To make it execute the bundle sequentially,
    # we would need to pass a special bundle ParsedCommand.
    # Fortunately, parse_command() merges everything if using `&&`, `|` etc, but parse_bundle() creates a list.
    # Let's create a combined ParsedCommand.

    combined = ParsedCommand(
        executable="bundle",
        flags=[],
        arguments=[raw],
        resolved_paths=list(paths),
        privilege_escalation=any(s.privilege_escalation for s in steps),
        effect_graph={"bundle": True},
        bundle_steps=len(steps),
    )

    try:
        plan = validate(plan, combined)
        plan.simulation = simulate(combined, plan)
        sign_plan(plan)
        if plan.simulation.degradation_tier.value == "T3_blocked" and not accept_irreversible:
            return PlanResult(
                path="denied",
                analysis=analysis,
                denied_reason="T3 irreversible without explicit flag",
                candidates=[plan],
            )
        return PlanResult(
            path="template",
            analysis=analysis if tier == "T1" else "ai",
            candidates=[plan],
            selected_index=0,
            simulation=plan.simulation,
        )
    except Exception as e:
        if not accept_irreversible:
            return PlanResult(
                path="denied",
                analysis=analysis,
                denied_reason=f"Bundle validation/simulation failed: {e}",
            )
        # fallback
        return PlanResult(
            path="denied",
            analysis=analysis,
            denied_reason="Failed simulation but irreversible flag set",
            candidates=[plan],
        )


def make_plan(
    raw: str, file=None, n_override: Optional[int] = None, accept_irreversible: bool = False
) -> PlanResult:
    if file:
        with open(file, "r") as f:
            raw = f.read()

    if "\n" in raw or file:
        steps = parse_bundle(raw)
        if len(steps) > 1:
            return make_bundle_plan(steps, raw, n_override, accept_irreversible)

    parsed = parse_command(raw)

    if parsed.bundle_steps > 1:
        # If it was chained with && or ;, it might be parsed as one command with bundle_steps set.
        pass

    risk = classify(parsed, raw)
    brs = blast_radius(parsed, risk)
    import os
    from datetime import datetime, timezone

    from safeshell.schemas import CommandAnalysis

    analysis = CommandAnalysis(
        command_id=new_id("cmd"),
        raw_command=raw,
        parsed=parsed,
        risk=risk,
        blast_radius=brs,
        timestamp=datetime.now(timezone.utc),
        user=os.environ.get("USER", "unknown"),
    )

    config = load_brs_config()
    decision = evaluate(tier=risk.level.value, brs=brs.score, guarantee="T1")

    if (
        decision.action == "deny"
        or risk.level.value == "critical"
        or brs.score == config.critical_sentinel
    ):
        return PlanResult(
            path="denied", analysis=analysis, denied_reason="Policy denied or critical risk"
        )

    # Templates
    t = lookup(parsed)
    if t:
        try:
            t = validate(t, parsed)
            t.simulation = simulate(parsed, t)
            sign_plan(t)
            if t.simulation.degradation_tier.value == "T3_blocked" and not accept_irreversible:
                return PlanResult(
                    path="denied",
                    analysis=analysis,
                    denied_reason="T3 irreversible without explicit flag",
                    candidates=[t],
                )
            return PlanResult(
                path="template",
                analysis=analysis,
                candidates=[t],
                selected_index=0,
                simulation=t.simulation,
            )
        except PlanInvalid:
            pass
        except Exception:
            pass

    # RAG
    r = retrieve(parsed)
    if r.exact:
        try:
            ex = validate(r.exact, parsed)
            ex.simulation = simulate(parsed, ex)
            sign_plan(ex)
            if ex.simulation.degradation_tier.value == "T3_blocked" and not accept_irreversible:
                return PlanResult(
                    path="denied",
                    analysis=analysis,
                    denied_reason="T3 irreversible without explicit flag",
                    candidates=[ex],
                )
            return PlanResult(
                path="rag",
                analysis=analysis,
                candidates=[ex],
                selected_index=0,
                simulation=ex.simulation,
            )
        except PlanInvalid:
            pass
        except Exception:
            pass

    # LLM
    n = n_override or (3 if risk.level.value == "high" else 1)
    manifest = collect_state(parsed.resolved_paths)
    try:
        cands = llm_plan_n(parsed, manifest, r.top3, n)
    except PlannerUnavailable:
        raise NoVerifiedPlan("Planner unavailable")

    validated = []
    for c in cands:
        try:
            cv = validate(c, parsed)
            validated.append(cv)
        except PlanInvalid:
            pass

    if not validated:
        raise NoVerifiedPlan("No AI plans passed validation")

    best = simulation_select(parsed, validated)
    if best:
        sign_plan(best)
        idx = validated.index(best)
        return PlanResult(
            path="ai",
            analysis=analysis,
            candidates=validated,
            selected_index=idx,
            simulation=best.simulation,
        )

    if not accept_irreversible:
        return PlanResult(
            path="denied",
            analysis=analysis,
            denied_reason="No verified plan or irreversible without flag",
            candidates=validated,
        )

    best_cand = validated[0]
    try:
        if not hasattr(best_cand, "simulation") or not best_cand.simulation:
            best_cand.simulation = simulate(parsed, best_cand)
    except Exception:
        pass
    sign_plan(best_cand)
    return PlanResult(
        path="ai",
        analysis=analysis,
        candidates=validated,
        selected_index=0,
        simulation=getattr(best_cand, "simulation", None),
    )
