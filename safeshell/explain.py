"""Explanation Engine (Phase 10)"""

from safeshell.schemas import CommandAnalysis, RollbackPlan


def explain(analysis: CommandAnalysis, plan: RollbackPlan) -> str:
    """Generate a plain-English explanation of the command and its rollback plan."""

    parts = []

    # 1. Action Summary
    if analysis.parsed.executable == "rm":
        if any(f in ("-r", "-R", "--recursive") for f in analysis.parsed.flags):
            parts.append(f"Recursively deletes {len(analysis.parsed.resolved_paths)} paths.")
        else:
            parts.append(f"Deletes {len(analysis.parsed.resolved_paths)} files.")
    elif analysis.parsed.executable == "mv":
        parts.append(f"Moves or renames files: {' '.join(analysis.parsed.resolved_paths)}")
    elif analysis.parsed.executable == "chown":
        parts.append(f"Changes ownership of {len(analysis.parsed.resolved_paths)} paths.")
    elif analysis.parsed.executable == "chmod":
        parts.append(f"Changes permissions of {len(analysis.parsed.resolved_paths)} paths.")
    elif analysis.parsed.executable == "bundle":
        parts.append(f"Executes a bundle of {analysis.parsed.bundle_steps} steps.")
    else:
        parts.append(
            f"Executes {analysis.parsed.executable} on {len(analysis.parsed.resolved_paths)} paths."
        )

    # 2. Rollback capability
    if plan.requires_snapshot:
        parts.append("SafeShell can fully restore it from a filesystem snapshot.")
    else:
        parts.append("SafeShell can roll this back deterministically without a snapshot.")

    # 3. Guarantee Tier
    if plan.simulation:
        tier = plan.simulation.degradation_tier.value
        if tier == "T1_full_verification":
            parts.append("Guarantee: T1 full verification.")
        elif tier == "T2_snapshot_only":
            parts.append("Guarantee: T2 snapshot fallback.")
        elif tier == "T3_blocked":
            parts.append("Guarantee: T3 blocked (irreversible without bypass).")
    else:
        parts.append("Guarantee: Unknown (No simulation).")

    # 4. Blast Radius
    brs = analysis.blast_radius
    signals = ", ".join(brs.top_signals[:3])
    parts.append(f"Blast radius {brs.score}, driven by: {signals}.")

    return " ".join(parts)
