"""Learning loop module. (Phase 10)"""

import json
import os
import sqlite3
from typing import Dict, List

from safeshell.rag import DB_PATH
from safeshell.schemas import (
    CommandAnalysis,
    RollbackPlan,
    SimulationReport,
    new_id,
)

SSR_ROWS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "ssrd", "learned_rows.jsonl"
)


def insert_learned_template(
    template_id: str,
    pattern: str,
    description: str,
    undo_json: str,
    confidence: float,
    provenance: dict,
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO templates (template_id, pattern, description, undo_json, source, confidence) VALUES (?, ?, ?, ?, ?, ?)",
        (template_id, pattern, description, undo_json, "learned", confidence),
    )

    # Save provenance in a separate table or just in template_health
    c.execute(
        "CREATE TABLE IF NOT EXISTS template_health (template_id TEXT PRIMARY KEY, failures INTEGER, status TEXT, provenance TEXT)"
    )
    c.execute(
        "INSERT INTO template_health (template_id, failures, status, provenance) VALUES (?, 0, 'active', ?)",
        (template_id, json.dumps(provenance)),
    )

    conn.commit()
    conn.close()


def record_simulation_failure(template_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS template_health (template_id TEXT PRIMARY KEY, failures INTEGER, status TEXT, provenance TEXT)"
    )
    c.execute("SELECT failures FROM template_health WHERE template_id=?", (template_id,))
    row = c.fetchone()
    if row:
        failures = row[0] + 1
        status = "quarantined" if failures >= 2 else "active"
        c.execute(
            "UPDATE template_health SET failures=?, status=? WHERE template_id=?",
            (failures, status, template_id),
        )
    conn.commit()
    conn.close()


def generalize_plan(parsed, plan: RollbackPlan) -> tuple[str, List[Dict]]:
    # Map concrete resolved paths to <p1>, <p2>
    path_map = {}
    tokens = []
    idx = 1
    for p in parsed.resolved_paths:
        if p not in path_map:
            path_map[p] = f"<p{idx}>"
            idx += 1

    # Construct pattern string
    pattern_parts = [parsed.executable]
    for flag in parsed.flags:
        pattern_parts.append(flag)
    for p in parsed.resolved_paths:
        pattern_parts.append(path_map[p])

    pattern = " ".join(pattern_parts)

    # Generalize actions
    gen_actions = []
    for a in plan.actions:
        a_dict = a.model_dump()
        target = a_dict["target"]
        if target in path_map:
            a_dict["target"] = path_map[target]
        # Remove snapshot_ref as it's specific to the execution
        if "snapshot_ref" in a_dict:
            del a_dict["snapshot_ref"]
        gen_actions.append(a_dict)

    return pattern, gen_actions


def maybe_writeback(
    record_dict: dict, plan: RollbackPlan, analysis: CommandAnalysis, sim_report: SimulationReport
) -> dict:
    if not sim_report.rollback_verified:
        return record_dict

    if record_dict.get("status") not in ("committed", "success"):
        return record_dict

    # check divergence
    if record_dict.get("divergence_detected", False):
        return record_dict

    # Ensure it's not already from templates
    if plan.source in ("template", "learned"):
        return record_dict

    template_id = new_id("tmpl")
    pattern, gen_actions = generalize_plan(analysis.parsed, plan)

    provenance = {
        "origin": "learned",
        "txn_id": record_dict.get("transaction_id"),
        "brs_at_commit": record_dict.get("brs"),
        "written_at": record_dict.get("timestamp"),
    }

    insert_learned_template(
        template_id, pattern, f"Learned from {pattern}", json.dumps(gen_actions), 1.0, provenance
    )

    # Append raw row
    os.makedirs(os.path.dirname(SSR_ROWS_PATH), exist_ok=True)
    with open(SSR_ROWS_PATH, "a") as f:
        f.write(
            json.dumps(
                {
                    "command": analysis.raw_command,
                    "parsed": analysis.parsed.model_dump(),
                    "plan": [a.model_dump() for a in plan.actions],
                }
            )
            + "\\n"
        )

    record_dict["learning"] = {"template_written_back": True, "template_id": template_id}
    return record_dict
