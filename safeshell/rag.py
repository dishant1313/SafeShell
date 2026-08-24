"""FTS5 SQLite store for templates and manpages. (Phase 5)"""

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Optional

from safeshell.schemas import ParsedCommand, RollbackPlan
from safeshell.templates import lookup as template_lookup

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "templates.db")


@dataclass
class RAGResult:
    exact: Optional[RollbackPlan]
    top3: List[Dict]


def seed():
    """Create and seed the FTS5 database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS templates USING fts5(template_id UNINDEXED, pattern, description, undo_json UNINDEXED, source UNINDEXED, confidence UNINDEXED);"
    )
    c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS manpages USING fts5(page, excerpt);")

    # Check if seeded
    c.execute("SELECT count(*) FROM templates")
    if c.fetchone()[0] == 0:
        tmpls = [
            (
                "mv_1",
                "mv <src> <dst>",
                "Move or rename files",
                json.dumps(
                    [
                        {"type": "restore_file", "target": "<src>", "requires_snapshot": True},
                        {
                            "type": "remove_artifact",
                            "target": "<dst>",
                            "requires_snapshot": False,
                            "params": {"only_if_created": True},
                        },
                    ]
                ),
                "template",
                1.0,
            ),
            (
                "rm_1",
                "rm -rf <dir>",
                "Remove directories and their contents recursively",
                json.dumps(
                    [{"type": "restore_directory", "target": "<dir>", "requires_snapshot": True}]
                ),
                "template",
                1.0,
            ),
            (
                "chown_1",
                "chown <owner> <file>",
                "Change file owner and group",
                json.dumps(
                    [
                        {
                            "type": "restore_ownership",
                            "target": "<file>",
                            "requires_snapshot": False,
                            "params": {"uid": 0, "gid": 0},
                        }
                    ]
                ),
                "template",
                1.0,
            ),
        ]
        for t in tmpls:
            c.execute(
                "INSERT INTO templates (template_id, pattern, description, undo_json, source, confidence) VALUES (?, ?, ?, ?, ?, ?)",
                t,
            )

    c.execute("SELECT count(*) FROM manpages")
    if c.fetchone()[0] == 0:
        man_dir = os.path.join(os.path.dirname(DB_PATH), "manpages")
        if os.path.exists(man_dir):
            for f in os.listdir(man_dir):
                with open(os.path.join(man_dir, f), "r") as mf:
                    excerpt = mf.read()
                    c.execute(
                        "INSERT INTO manpages (page, excerpt) VALUES (?, ?)",
                        (f.replace(".txt", ""), excerpt),
                    )
    conn.commit()
    conn.close()


def retrieve(parsed: ParsedCommand, k: int = 3) -> RAGResult:
    """Retrieve exact matches and top k FTS5 semantic matches. ADVISORY ONLY."""
    seed()

    exact = template_lookup(parsed)
    if exact:
        exact.source = "rag"

    top3 = []
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # FTS query construction
    query_parts = [parsed.executable] + parsed.flags
    effs = []
    for k_eff, v in parsed.effect_graph.items():
        if v:
            effs.append(k_eff)
    query_parts += effs
    query_str = " OR ".join([p.replace("-", "") for p in query_parts if p.strip("-")])
    if not query_str:
        query_str = parsed.executable

    # We do a basic MATCH
    try:
        c.execute(
            """
            SELECT t.pattern, t.description, t.undo_json, bm25(t) as rank 
            FROM templates t
            LEFT JOIN template_health h ON t.template_id = h.template_id
            WHERE t MATCH ? AND (h.status IS NULL OR h.status != 'quarantined')
            ORDER BY rank LIMIT ?
        """,
            (query_str, k),
        )
        for row in c.fetchall():
            score = abs(row[3])
            if score > 0.0:  # confidence floor logic can be refined
                top3.append(
                    {"pattern": row[0], "description": row[1], "undo_json": json.loads(row[2])}
                )
    except sqlite3.OperationalError:
        pass

    conn.close()
    return RAGResult(exact=exact, top3=top3)
