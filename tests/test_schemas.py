"""Tests for SafeShell v3 frozen schemas."""

import re
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from safeshell.schemas import (
    ActionType,
    ApprovalInfo,
    BlastRadius,
    CommandAnalysis,
    DegradationTier,
    ExecutionInfo,
    LearningInfo,
    ParsedCommand,
    PlanSource,
    PredictedChanges,
    ReplayReport,
    RiskInfo,
    RiskLevel,
    RollbackAction,
    RollbackPlan,
    Signature,
    SimulationReport,
    TransactionRecord,
    Verdict,
    new_id,
)

NOW = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestCommandAnalysis:
    """Round-trip CommandAnalysis with blast radius."""

    def test_round_trip(self) -> None:
        obj = CommandAnalysis(
            command_id="cmd_8f3a1c",
            raw_command="rm -rf /tmp/build",
            parsed=ParsedCommand(
                executable="rm",
                flags=["-r", "-f"],
                arguments=["/tmp/build"],
                resolved_paths=["/tmp/build"],
            ),
            risk=RiskInfo(
                level=RiskLevel.high,
                signals=["recursive_delete", "force_flag"],
                score=0.87,
            ),
            blast_radius=BlastRadius(
                score=847,
                brs_version="1.0",
                top_signals=["recursive", "force", "wide_scope"],
            ),
            timestamp=NOW,
            user="dishant",
        )
        data = obj.model_dump()
        restored = CommandAnalysis.model_validate(data)
        assert restored.command_id == "cmd_8f3a1c"
        assert restored.blast_radius.score == 847
        assert len(restored.blast_radius.top_signals) == 3
        assert restored == obj


class TestRollbackPlan:
    """Round-trip signed RollbackPlan."""

    def test_round_trip(self) -> None:
        obj = RollbackPlan(
            plan_id="plan_2b91e0",
            command_id="cmd_8f3a1c",
            source=PlanSource.ai_generated_sim_selected,
            confidence=0.92,
            actions=[
                RollbackAction(
                    type=ActionType.restore_directory,
                    target="/tmp/build",
                    snapshot_ref="snap_abc123",
                    order=1,
                ),
            ],
            requires_snapshot=True,
            validated=True,
            candidates_tried=3,
            selected_index=1,
            signature=Signature(
                alg="ed25519",
                key_id="host-key-001",
                sig="deadbeef" * 8,
            ),
        )
        data = obj.model_dump()
        restored = RollbackPlan.model_validate(data)
        assert restored.plan_id == "plan_2b91e0"
        assert restored.source == PlanSource.ai_generated_sim_selected
        assert restored.candidates_tried == 3
        assert restored.selected_index == 1
        assert restored.signature is not None
        assert restored.signature.alg == "ed25519"
        assert restored == obj


class TestSimulationReport:
    """Round-trip SimulationReport."""

    def test_round_trip(self) -> None:
        obj = SimulationReport(
            simulation_id="sim_c71d9a",
            command_id="cmd_8f3a1c",
            sandbox="/tmp/.safeshell/sandbox_001",
            predicted_changes=PredictedChanges(
                files_deleted=3,
                files_modified=0,
                permissions_changed=0,
                processes_spawned=1,
                network_attempts=0,
            ),
            rollback_verified=True,
            post_rollback_state_hash="abc123def456",
            matches_pre_execution_hash=True,
            duration_ms=450,
            degradation_tier=DegradationTier.T1_full_verification,
        )
        data = obj.model_dump()
        restored = SimulationReport.model_validate(data)
        assert restored.simulation_id == "sim_c71d9a"
        assert restored.degradation_tier == DegradationTier.T1_full_verification
        assert restored.predicted_changes.network_attempts == 0
        assert restored == obj


class TestReplayReport:
    """Round-trip ReplayReport."""

    def test_round_trip(self) -> None:
        obj = ReplayReport(
            replay_id="rpl_55d0aa",
            original_transaction_id="txn_9e02f1",
            original_pre_hash="aaa111",
            current_pre_hash="aaa111",
            state_drift={"files_added_since": 0, "files_removed_since": 0},
            replay_rollback_verified=True,
            verdict=Verdict.still_safe,
            duration_ms=120,
        )
        data = obj.model_dump()
        restored = ReplayReport.model_validate(data)
        assert restored.replay_id == "rpl_55d0aa"
        assert restored.verdict == Verdict.still_safe
        assert restored == obj


class TestTransactionRecord:
    """Round-trip TransactionRecord."""

    def test_round_trip(self) -> None:
        obj = TransactionRecord(
            transaction_id="txn_9e02f1",
            command_id="cmd_8f3a1c",
            plan_id="plan_2b91e0",
            simulation_id="sim_c71d9a",
            approval=ApprovalInfo(
                required=True,
                mode="policy_auto",
                policy_rule="auto_approve_low_brs",
                approved_by="policy_engine",
                approved_at=NOW,
            ),
            execution=ExecutionInfo(
                status="committed",
                started_at=NOW,
                completed_at=NOW,
                divergence_detected=False,
            ),
            learning=LearningInfo(
                template_written_back=True,
                template_id="tpl_rm_dir_001",
            ),
            brs=847,
            brs_version="1.0",
            prev_hash="0000000000",
            entry_hash="abcdef123456",
        )
        data = obj.model_dump()
        restored = TransactionRecord.model_validate(data)
        assert restored.transaction_id == "txn_9e02f1"
        assert restored.approval.mode == "policy_auto"
        assert restored.learning.template_written_back is True
        assert restored == obj


class TestActionTypeMembers:
    """Verify ActionType enum completeness."""

    def test_exactly_eight_members(self) -> None:
        members = list(ActionType)
        assert len(members) == 8
        expected = {
            "restore_directory",
            "restore_file",
            "restore_permissions",
            "restore_ownership",
            "restart_service",
            "remove_artifact",
            "verify_checksum",
            "no_op_external_flag",
        }
        assert {m.value for m in members} == expected


class TestRiskInfoValidation:
    """Verify schema validation constraints."""

    def test_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            RiskInfo(level=RiskLevel.high, signals=["test"], score=1.5)


class TestNewId:
    """Verify new_id helper."""

    def test_format(self) -> None:
        result = new_id("prefix")
        assert re.match(r"^prefix_[0-9a-f]{6}$", result)

    def test_uniqueness(self) -> None:
        ids = {new_id("x") for _ in range(100)}
        assert len(ids) > 90
