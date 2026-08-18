"""SafeShell v3 frozen contract schemas.

This module defines all Pydantic v2 models that constitute the SafeShell data contract.
Every component in the pipeline — parser, classifier, planner, simulator, executor,
and ledger — communicates through these schemas. They are frozen at v3 and must not
be modified without a full migration plan.
"""

import secrets
from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Threat classification levels for parsed commands."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ActionType(str, Enum):
    """Closed vocabulary for rollback actions (Safety Invariant A6.1).

    Models may ONLY emit actions from this enum. Any other action type
    is rejected at validation time.
    """

    restore_directory = "restore_directory"
    restore_file = "restore_file"
    restore_permissions = "restore_permissions"
    restore_ownership = "restore_ownership"
    restart_service = "restart_service"
    remove_artifact = "remove_artifact"
    verify_checksum = "verify_checksum"
    no_op_external_flag = "no_op_external_flag"


class PlanSource(str, Enum):
    """Origin of a rollback plan."""

    template = "template"
    rag = "rag"
    ai_generated = "ai_generated"
    ai_generated_sim_selected = "ai_generated_sim_selected"
    learned = "learned"


class DegradationTier(str, Enum):
    """Simulation capability tiers."""

    T1_full_verification = "T1_full_verification"
    T2_snapshot_only = "T2_snapshot_only"
    T3_blocked = "T3_blocked"


class Verdict(str, Enum):
    """Post-replay state verdict."""

    still_safe = "still_safe"
    drifted_unsafe = "drifted_unsafe"


ExecStatus = Literal["committed", "rolled_back", "blocked", "manual_required"]
ApprovalMode = Literal["human", "policy_auto"]


class ParsedCommand(BaseModel):
    """Structured representation of a shell command after parsing.

    Produced by the parser (Phase 2) from raw command strings using shlex
    and script-to-effect-graph conversion.
    """

    executable: str
    flags: list[str] = []
    arguments: list[str] = []
    resolved_paths: list[str] = []
    pipes: list[str] = []
    redirects: list[str] = []
    subshells: list[str] = []
    privilege_escalation: bool = False
    bundle_steps: int = 1
    effect_graph: dict = Field(
        default_factory=lambda: {
            "creates": [],
            "deletes": [],
            "modifies": [],
            "permissions": [],
            "service_state": [],
            "network_egress": [],
            "process_spawn": [],
        }
    )


class RiskInfo(BaseModel):
    """Risk assessment output from the classifier (Phase 3)."""

    level: RiskLevel
    signals: list[str]
    score: float = Field(ge=0.0, le=1.0)


class BlastRadius(BaseModel):
    """Blast Radius Score computed by the BRS engine (Phase 4)."""

    score: int = Field(ge=0)
    brs_version: str
    top_signals: list[str]


class CommandAnalysis(BaseModel):
    """Complete analysis record for a single command."""

    command_id: str
    raw_command: str
    parsed: ParsedCommand
    risk: RiskInfo
    blast_radius: BlastRadius
    timestamp: datetime
    user: str


class RollbackAction(BaseModel):
    """A single step within a rollback plan."""

    type: ActionType
    target: str
    snapshot_ref: Optional[str] = None
    order: int
    undoes_steps: list[str] = []


class Signature(BaseModel):
    """Ed25519 signature block for plan integrity (Safety Invariant A6.9)."""

    alg: Literal["ed25519"]
    key_id: str
    sig: str


class RollbackPlan(BaseModel):
    """AI-generated or template-based rollback plan for a command."""

    plan_id: str
    command_id: str
    source: PlanSource
    confidence: float = Field(ge=0.0, le=1.0)
    actions: list[RollbackAction]
    requires_snapshot: bool
    validated: bool = False
    candidates_tried: Optional[int] = None
    selected_index: Optional[int] = None
    signature: Optional[Signature] = None


class PredictedChanges(BaseModel):
    """Predicted filesystem and process changes from simulation."""

    files_deleted: int
    files_modified: int
    permissions_changed: int
    processes_spawned: int
    network_attempts: int = 0


class SimulationReport(BaseModel):
    """Report from the simulation engine (Phase 8) after sandbox execution."""

    simulation_id: str
    command_id: str
    sandbox: str
    predicted_changes: PredictedChanges
    rollback_verified: bool
    post_rollback_state_hash: str
    matches_pre_execution_hash: bool
    duration_ms: int = Field(ge=0)
    degradation_tier: DegradationTier


class ReplayReport(BaseModel):
    """Report from the replay engine (Phase 10) for undo operations."""

    replay_id: str
    original_transaction_id: str
    original_pre_hash: str
    current_pre_hash: str
    state_drift: dict
    replay_rollback_verified: bool
    verdict: Verdict
    duration_ms: int


class ApprovalInfo(BaseModel):
    """Approval metadata for a transaction."""

    required: bool
    mode: ApprovalMode
    policy_rule: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class ExecutionInfo(BaseModel):
    """Execution outcome metadata."""

    status: ExecStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    divergence_detected: bool = False


class LearningInfo(BaseModel):
    """Learning loop metadata."""

    template_written_back: bool
    template_id: Optional[str] = None


class TransactionRecord(BaseModel):
    """Immutable ledger entry for a completed transaction.

    Forms the hash-chained append-only ledger (Safety Invariant A6.10).
    entry_hash = sha256(prev_hash + canonical_json(payload)).
    """

    transaction_id: str
    command_id: str
    plan_id: str
    simulation_id: str
    approval: ApprovalInfo
    execution: ExecutionInfo
    learning: LearningInfo
    brs: int
    brs_version: str
    prev_hash: str
    entry_hash: str


class CoreRequest(BaseModel):
    """JSON-lines IPC request to safeshell-core Rust binary."""

    op: Literal["collect_state", "snapshot", "restore", "sandbox_exec", "simulate"]
    params: dict = {}


class CoreResponse(BaseModel):
    """JSON-lines IPC response from safeshell-core Rust binary."""

    ok: bool
    data: dict = {}
    error: Optional[str] = None


def new_id(prefix: str) -> str:
    """Generate a short unique ID with the given prefix.

    Returns a string of the form \'{prefix}_{6 hex chars}\'.
    """
    return f"{prefix}_{secrets.token_hex(3)}"
