"""Twelve-case synthetic acceptance matrix for the RightRail financial owner.

The expected values are imported only from the fixed, application-independent fixture.  This
module never derives expected balances from owner code or reaches the database through SQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager, nullcontext, redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_engine as financial_engine
from app import right_rail_financial_owner as owner
from app.right_rail_financial_owner import (
    ControlPack,
    FinancialAuthorityError,
    FinancialConflictError,
    FinancialContinuityError,
    FinancialDispatchError,
    FinancialInputError,
    FinancialIntegrityError,
    FinancialOwner,
    FinancialOwnerConfig,
    PopulationManifest,
    FinancialRevisionError,
    PopulationItem,
    ProgramFundingReceipt,
    SyntheticTrustedAuthority,
)
from app.right_rail_financial_mirror import FinancialMirror
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_owner_independent import (
    IndependentFinancialError,
    continuity_package_digest,
    verify_database,
    verify_database_connection,
    verify_decision_package,
    verify_continuity_package,
    verify_obligation_connection,
)
from tests import rightrail_financial_expected_cases as expected


_CORRECTION_ENGINE_PATH = (
    Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "blind_financial_correction.exe"
)
_CORRECTION_VECTOR_DIR = (
    Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "vectors"
)
_EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES = 6_279_168
_EXPECTED_CORRECTION_ARTIFACT_SHA256 = bytes.fromhex(
    "1A7A18333726484A0737DA7B005EC699F73E99EA0CFACFB409B000F964BED3AF"
)
_EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256 = bytes.fromhex(
    "B658DCEE04138FDCBA6C9D72F3D2D044E5F596AA5794B3562A8312FBB57AD067"
)
_EXPECTED_CORRECTION_RESULT_VECTOR_SHA256 = bytes.fromhex(
    "83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6"
)
_RETIRED_CORRECTION_ARTIFACT_SHA256 = "E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9"
_B2_CORRECTION_ARTIFACT_SHA256 = "88D853961AB127EE33C65A57F6E35D03244FB5CCE2067F4A0FDF592ECC730992"
_ACTION_B = "action:obligation-item-h:correction-b"
_EXPECTED_PRIVATE_INDEX_SET_VERSION = 2
_EXPECTED_PRIVATE_INDEXES = (
    (
        "rr_financial_v1_evidence_item_id",
        "evidence",
        ("item_id", "evidence_id"),
        "CREATE INDEX rr_financial_v1_evidence_item_id ON evidence(item_id,evidence_id)",
    ),
    (
        "rr_financial_v1_claims_obligation_id",
        "claimed_adjustments",
        ("obligation_id", "claim_id"),
        "CREATE INDEX rr_financial_v1_claims_obligation_id ON claimed_adjustments(obligation_id,claim_id)",
    ),
    (
        "rr_financial_v1_cases_obligation_id",
        "cases",
        ("obligation_id", "case_id"),
        "CREATE INDEX rr_financial_v1_cases_obligation_id ON cases(obligation_id,case_id)",
    ),
    (
        "rr_financial_v1_actions_obligation_id",
        "actions",
        ("obligation_id", "action_id"),
        "CREATE INDEX rr_financial_v1_actions_obligation_id ON actions(obligation_id,action_id)",
    ),
    (
        "rr_financial_v1_conflicts_obligation_id",
        "financial_conflicts",
        ("obligation_id", "conflict_id"),
        "CREATE INDEX rr_financial_v1_conflicts_obligation_id ON financial_conflicts(obligation_id,conflict_id)",
    ),
    (
        "rr_financial_v1_evaluations_obligation_revision",
        "evaluations",
        ("obligation_id", "revision"),
        "CREATE INDEX rr_financial_v1_evaluations_obligation_revision ON evaluations(obligation_id,revision)",
    ),
    (
        "rr_financial_v1_determinations_obligation_id",
        "determinations",
        ("obligation_id", "determination_id"),
        "CREATE INDEX rr_financial_v1_determinations_obligation_id ON determinations(obligation_id,determination_id)",
    ),
    (
        "rr_financial_v2_events_aggregate_kind",
        "financial_events",
        ("aggregate_type", "aggregate_id", "kind"),
        "CREATE INDEX rr_financial_v2_events_aggregate_kind ON financial_events(aggregate_type,aggregate_id,kind)",
    ),
)


def _correction_transition_test_release(
    *,
    workspace: Path,
) -> financial_engine.FinancialCorrectionTransitionRelease:
    if financial_engine.CORRECTION_TRANSITION_ARTIFACT_SIZE_BYTES != _EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES:
        raise AssertionError("correction_transition_artifact_size_pin_mismatch")
    if financial_engine.CORRECTION_TRANSITION_ARTIFACT_SHA256 != _EXPECTED_CORRECTION_ARTIFACT_SHA256:
        raise AssertionError("correction_transition_artifact_pin_mismatch")
    if financial_engine.CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256 != _EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256:
        raise AssertionError("correction_transition_request_pin_mismatch")
    if financial_engine.CORRECTION_TRANSITION_RESULT_VECTOR_SHA256 != _EXPECTED_CORRECTION_RESULT_VECTOR_SHA256:
        raise AssertionError("correction_transition_result_pin_mismatch")

    artifact_path = Path(os.environ.get("RR_FINANCIAL_CORRECTION_ENGINE_PATH", _CORRECTION_ENGINE_PATH))
    vector_dir = Path(os.environ.get("RR_FINANCIAL_CORRECTION_VECTOR_DIR", _CORRECTION_VECTOR_DIR))
    artifact = artifact_path.read_bytes()
    if (
        len(artifact) != _EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES
        or hashlib.sha256(artifact).digest() != _EXPECTED_CORRECTION_ARTIFACT_SHA256
    ):
        raise AssertionError("correction_transition_artifact_bytes_mismatch")

    request = (vector_dir / "request.bin").read_bytes()
    expected_result = (vector_dir / "result.expected.bin").read_bytes()
    actual_result = (vector_dir / "result.actual.bin").read_bytes()
    if hashlib.sha256(request).digest() != _EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256:
        raise AssertionError("correction_transition_request_vector_bytes_mismatch")
    if hashlib.sha256(expected_result).digest() != _EXPECTED_CORRECTION_RESULT_VECTOR_SHA256:
        raise AssertionError("correction_transition_result_vector_bytes_mismatch")
    if actual_result != expected_result:
        raise AssertionError("correction_transition_result_vector_not_byte_equal")
    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise AssertionError("correction_transition_test_workspace_not_empty")

    return financial_engine.FinancialCorrectionTransitionRelease(
        executable=artifact_path,
        executable_size_bytes=_EXPECTED_CORRECTION_ARTIFACT_SIZE_BYTES,
        executable_sha256=_EXPECTED_CORRECTION_ARTIFACT_SHA256,
        request_vector_sha256=_EXPECTED_CORRECTION_REQUEST_VECTOR_SHA256,
        result_vector_sha256=_EXPECTED_CORRECTION_RESULT_VECTOR_SHA256,
        timeout_seconds=30.0,
        input_max_bytes=financial_engine.MAX_CORRECTION_TRANSITION_BYTES,
        output_max_bytes=financial_engine.MAX_CORRECTION_TRANSITION_BYTES,
        stderr_max_bytes=financial_engine.process.MAX_STDERR_BYTES,
        workspace=workspace,
        job_memory_cap_bytes=1_000_000_000,
    )


class _Clock:
    def __init__(self, initial: int | None = None) -> None:
        self.value = expected.CASH_EVENT_MS if initial is None else initial

    def now_ms(self) -> int:
        self.value += 1
        return self.value


def _independent_canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _independent_digest(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _independent_hex(value: bytes) -> str:
    return value.hex().upper()


_V8_COMMAND_KINDS = frozenset({
    "CONTROL_PACK", "POPULATION_MANIFEST", "SUPPORT_EVIDENCE", "PAYMENT", "PAYMENT_REVERSAL",
    "OFFSET_CLAIM", "OFFSET_DECISION", "ACTION_ACKNOWLEDGMENT", "REPORT",
})


_COMMAND_TRIGGER_BODY = "BEFORE {} ON commands BEGIN SELECT RAISE(ABORT,'command_immutable'); END"


def _independent_evidence_digest(row: dict[str, object]) -> str:
    evidence_domain = b"RR/FINANCIAL/EVIDENCE/v1\x00"
    content_digest = _independent_digest(
        evidence_domain,
        _independent_canonical(
            {
                "source_id": row["source_id"],
                "source_version": row["source_version"],
                "local_ref": row["local_ref"],
                "common_origin_id": row["common_origin_id"],
                "kind": row["kind"],
            }
        ),
    )
    return _independent_hex(
        _independent_digest(
            evidence_domain,
            _independent_canonical(
                {
                    "evidence_id": row["evidence_id"],
                    "item_id": row["item_id"],
                    "kind": row["kind"],
                    "common_origin_id": row["common_origin_id"],
                    "source_id": row["source_id"],
                    "source_version": row["source_version"],
                    "local_ref": row["local_ref"],
                    "applicable_at_ms": row["applicable_at_ms"],
                    "event_at_ms": row["event_at_ms"],
                    "received_at_ms": row["received_at_ms"],
                    "content_digest": _independent_hex(content_digest),
                    "amount_cents": row["amount_cents"],
                    "reversal_of": row["reversal_of"],
                    "supersedes": row["supersedes"],
                }
            ),
        )
    )


def _independent_pack_digest(pack: expected.ControlPackExpectation) -> str:
    scope = pack.scope
    return _independent_hex(
        _independent_digest(
            b"RR/FINANCIAL/EVIDENCE/v1\x00",
            _independent_canonical(
                {
                    "pack_id": pack.pack_id,
                    "state_id": scope.state_id,
                    "deployment_id": scope.deployment_id,
                    "program_id": scope.program_id,
                    "period_id": scope.period_id,
                    "version": pack.version,
                    "source_refs": list(pack.source_refs),
                    "effective_start_ms": pack.effective_start_ms,
                    "effective_end_ms": pack.effective_end_ms,
                    "recorded_at_ms": pack.recorded_at_ms,
                    "approved_at_ms": pack.approved_at_ms,
                    "calculation_rule_id": pack.calculation_rule_id,
                    "adjustment_rule_id": pack.adjustment_rule_id,
                    "authorized_roles": list(pack.authorized_roles),
                    "expected_tests": list(pack.expected_tests),
                }
            ),
        )
    )


class _WriteBoundaryOwner(FinancialOwner):
    """Test-local interruption at the real owner transaction boundaries."""

    def __init__(
        self,
        *,
        path: Path,
        config: FinancialOwnerConfig,
        trusted_authority: SyntheticTrustedAuthority,
        clock: _Clock,
        fault: str,
        correction_transition_release: object | None = None,
    ) -> None:
        self._fault = fault
        super().__init__(
            path=path,
            config=config,
            trusted_authority=trusted_authority,
            clock=clock,
            correction_transition_release=correction_transition_release,
        )

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        fault = self._fault
        with super()._write() as connection:
            yield connection
            if fault == "precommit":
                self._fault = "consumed"
                raise RuntimeError("synthetic_financial_precommit_interrupt")
            if fault == "process_precommit":
                self._fault = "consumed"
                print("PHASE=PRECOMMIT_AFTER_MUTATION", flush=True)
                os._exit(73)
        if fault == "postcommit":
            self._fault = "consumed"
            raise RuntimeError("synthetic_financial_result_lost_after_commit")
        if fault == "process_postcommit":
            self._fault = "consumed"
            print("PHASE=POSTCOMMIT_AFTER_COMMIT", flush=True)
            os._exit(74)


_PROCESS_BOUNDARY_CHILD = """
import sys
from pathlib import Path

from app.right_rail_financial_owner import FinancialOwnerConfig, SyntheticTrustedAuthority
from tests import rightrail_financial_expected_cases as expected
from tests.test_right_rail_financial_acceptance import _Clock, _WriteBoundaryOwner, _correction_transition_test_release

path = Path(sys.argv[1])
claim_id = sys.argv[2]
fault = sys.argv[3]
clock = _Clock(int(sys.argv[4]))
config = FinancialOwnerConfig(
    state_id=expected.STATE_ID,
    deployment_id=expected.DEPLOYMENT_ID,
    program_id=expected.PROGRAM_ID,
    period_id=expected.PERIOD_ONE_ID,
    currency=expected.CURRENCY,
)
store = _WriteBoundaryOwner(
    path=path,
    config=config,
    trusted_authority=SyntheticTrustedAuthority(),
    clock=clock,
    fault=fault,
    correction_transition_release=_correction_transition_test_release(
        workspace=path.parent / "correction-engine-workspace",
    ),
)
receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
revision = receipt["revision"]
print("PHASE=BEFORE_REJECT", flush=True)
store.reject_offset_and_authorize_correction(
    item_id=expected.H_ITEM_ID,
    claim_id=claim_id,
    expected_revision=revision,
    action_id=expected.ACTION_CORRECTION_ID,
    decision_at_ms=expected.CORRECTION_AUTH_MS,
    evaluation_id=receipt["evaluation_id"],
    evaluation_result_digest=receipt["result_digest"],
)
raise SystemExit(99)
"""


_PROCESS_FUNDING_BOUNDARY_CHILD = """
import sys
from pathlib import Path

from app.right_rail_financial_owner import FinancialOwnerConfig, ProgramFundingReceipt, SyntheticTrustedAuthority
from tests import rightrail_financial_expected_cases as expected
from tests.test_right_rail_financial_acceptance import _Clock, _WriteBoundaryOwner

path = Path(sys.argv[1])
fault = sys.argv[2]
clock = _Clock(int(sys.argv[3]))
config = FinancialOwnerConfig(
    state_id=expected.STATE_ID,
    deployment_id=expected.DEPLOYMENT_ID,
    program_id=expected.PROGRAM_ID,
    period_id=expected.PERIOD_ONE_ID,
    currency=expected.CURRENCY,
)
store = _WriteBoundaryOwner(
    path=path,
    config=config,
    trusted_authority=SyntheticTrustedAuthority(),
    clock=clock,
    fault=fault,
)
fixture = expected.PROGRAM_FUNDING_RECEIPT
receipt = ProgramFundingReceipt(
    receipt_id=fixture.receipt_id,
    state_id=fixture.scope.state_id,
    deployment_id=fixture.scope.deployment_id,
    program_id=fixture.scope.program_id,
    period_id=fixture.scope.period_id,
    currency=fixture.scope.currency,
    source_record_ref=fixture.source_record_ref,
    amount_cents=fixture.amount_cents,
    event_at_ms=fixture.event_at_ms,
)
print("PHASE=BEFORE_FUNDING_RECORD", flush=True)
store.record_program_funding_receipt(receipt)
raise SystemExit(99)
"""


def _control_pack_from_fixture(value: expected.ControlPackExpectation) -> ControlPack:
    return ControlPack(
        pack_id=value.pack_id,
        state_id=value.scope.state_id,
        deployment_id=value.scope.deployment_id,
        program_id=value.scope.program_id,
        period_id=value.scope.period_id,
        version=value.version,
        source_refs=value.source_refs,
        effective_start_ms=value.effective_start_ms,
        effective_end_ms=value.effective_end_ms,
        recorded_at_ms=value.recorded_at_ms,
        approved_at_ms=value.approved_at_ms,
        calculation_rule_id=value.calculation_rule_id,
        adjustment_rule_id=value.adjustment_rule_id,
        authorized_roles=value.authorized_roles,
        expected_tests=value.expected_tests,
    )


def _items_from_fixture(
    items: tuple[expected.PopulationItemExpectation, ...], population_id: str | None,
) -> tuple[PopulationItem, ...]:
    return tuple(
        PopulationItem(
            population_id=item.population_id if population_id is None else population_id,
            item_id=item.item_id,
            display_label=item.display_label,
            owed_cents=item.owed_cents,
            due_at_ms=item.due_at_ms,
            currency=item.currency,
        )
        for item in items
    )


def _population_manifest_from_fixture(
    fixture: expected.PopulationManifestExpectation,
    authority: SyntheticTrustedAuthority,
    *,
    manifest_id: str | None = None,
    source_owner_id: str | None = None,
    member_ids: tuple[str, ...] | None = None,
    manifest_version: int | None = None,
    supersedes: PopulationManifest | None = None,
    approved_by: str | None = None,
    approval_ref: str | None = None,
    inclusion_rules: tuple[str, ...] | None = None,
    cutoff_ms: int | None = None,
) -> PopulationManifest:
    scope = fixture.scope
    version = manifest_version
    if version is None:
        version = supersedes.manifest_version + 1 if supersedes is not None else fixture.manifest_version
    return PopulationManifest(
        manifest_id=manifest_id or fixture.manifest_id,
        manifest_version=version,
        state_id=scope.state_id,
        deployment_id=scope.deployment_id,
        program_id=scope.program_id,
        period_id=scope.period_id,
        currency=scope.currency,
        pack_id=fixture.pack_id,
        cutoff_ms=fixture.cutoff_ms if cutoff_ms is None else cutoff_ms,
        inclusion_rules=fixture.inclusion_rules if inclusion_rules is None else inclusion_rules,
        source_owner_id=source_owner_id or fixture.source_owner_id,
        authority_id=authority.authority_id,
        authority_epoch=authority.epoch,
        authority_digest=authority.digest,
        approved_by=approved_by or fixture.approved_by,
        approval_ref=approval_ref or fixture.approval_ref,
        source_id=fixture.source_id,
        source_version=fixture.source_version,
        source_digest=bytes.fromhex(fixture.source_digest_hex),
        member_ids=fixture.member_ids if member_ids is None else member_ids,
        supersedes_manifest_id=None if supersedes is None else supersedes.manifest_id,
        supersedes_digest=None if supersedes is None else supersedes.digest,
    )


def _record_fixture_support(store: FinancialOwner, evidence: expected.EvidenceExpectation) -> None:
    store.record_support_evidence(
        item_id=evidence.item_id,
        evidence_id=evidence.evidence_id,
        common_origin_id=evidence.common_origin_id,
        source_id=evidence.source_id,
        source_version=evidence.source_version,
        local_ref=evidence.local_ref,
        applicable_at_ms=evidence.applicable_at_ms,
        event_at_ms=evidence.event_at_ms,
    )


class RightRailFinancialAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-financial-acceptance-")
        self.addCleanup(self.temp_dir.cleanup)
        self._path_counter = 0
        self.authority = SyntheticTrustedAuthority()

    def _path(self, name: str | None = None) -> Path:
        self._path_counter += 1
        return Path(self.temp_dir.name) / (name or f"owner-{self._path_counter}.sqlite")

    def _private_index_fixture_row(
        self,
        table: str,
        ordinal: int,
        *,
        per_obligation: int = 20,
    ) -> tuple[object, ...]:
        obligation_number = ordinal % 20
        values: dict[str, object] = {
            "obligation_id": f"obligation:{obligation_number:02d}",
            "item_id": f"item:{obligation_number:02d}",
            "evidence_id": f"evidence:{ordinal:04d}",
            "payment_id": f"payment:{ordinal:04d}",
            "claim_id": f"claim:{ordinal:04d}",
            "case_id": f"case:{ordinal:04d}",
            "action_id": f"action:{ordinal:04d}",
            "conflict_id": f"conflict:{ordinal:04d}",
            "evaluation_id": f"evaluation:{ordinal:04d}",
            "determination_id": f"determination:{ordinal:04d}",
            "input_evaluation_id": f"evaluation:{ordinal:04d}",
            "revision": ordinal // per_obligation,
            "existing_payment_id": f"payment:{ordinal:04d}",
            "candidate_evidence_id": f"evidence:{ordinal:04d}",
            "authority_id": self.authority.authority_id,
            "authority_digest": self.authority.digest,
            "contract_version": owner._EVALUATION_RECEIPT_CONTRACT,
            "control_pack_id": "pack:plan",
            "pack_id": "pack:plan",
            "population_id": "population:plan",
            "current_evaluation_id": None,
            "validation_digest": None,
            "source_complete": 1,
            "currency": "USD",
            "status": {
                "claimed_adjustments": "CLAIMED",
                "control_packs": "APPROVED",
                "population_imports": "PUBLISHED",
            }.get(table, "READY"),
            "decision": "REJECT_OFFSET",
            "owner_role": "FINANCE_DECISION",
            "actor_role": "FINANCE_DECISION",
            "verification_status": "VERIFIED",
            "case_status": "OPEN",
            "delivery_status": "READY",
            "kind": "PLAN_FIXTURE",
            "common_origin_id": f"origin:{ordinal:04d}",
            "reason": "PLAN_FIXTURE",
            "content_digest": b"d" * 64,
            "record_digest": b"d" * 64,
            "determination_digest": b"d" * 64,
            "input_evaluation_result_digest": b"d" * 64,
            "result_digest": b"d" * 64,
            "control_pack_digest": b"d" * 64,
            "input_snapshot_digest": b"d" * 64,
            "receipt_digest": b"d" * 64,
            "payload_digest": b"d" * 64,
            "idempotency_key": b"d" * 64,
            "evidence_ids_json": '{"evidence_ids":[]}',
            "evidence_bindings_json": '{"bindings":[]}',
            "scope_json": "{}",
            "input_snapshot_json": "{}",
            "supporting_evidence_json": "{\"bindings\":[]}",
            "payload_json": "{}",
            "completion_conditions_json": "{}",
            "reversal_of": None,
            "supersedes": None,
            "reversed_by_evidence_id": None,
            "acknowledgment_ref": None,
        }
        integer_columns = {
            "active", "amount_cents", "amount_satisfied", "attempt", "authority_epoch",
            "approved_at_ms", "effective_end_ms", "effective_start_ms", "expected_count",
            "imported_count", "owed_cents", "recorded_at_ms", "validated_count", "version",
            "cash_satisfied", "claimed_adjustment_cents", "control_pack_version",
            "created_at_ms", "deadline_ms", "due_at_ms", "event_at_ms", "evaluated_at_ms",
            "expected_revision", "lawful_adjustment_cents", "overage_cents", "received_at_ms",
            "received_cash_cents", "reporting_complete", "resulting_revision", "revision",
            "rule_version", "shortfall_cents", "timely", "updated_at_ms", "visible_at_ms",
        }
        columns = owner._TABLE_COLUMNS[table]
        row: list[object] = []
        for column in columns:
            if column in values:
                value = values[column]
            elif column in integer_columns:
                value = 1
            elif column.endswith("_json"):
                value = "{}"
            elif column.endswith("_digest"):
                value = b"d" * 64
            else:
                value = f"plan:{table}:{ordinal:04d}:{column}"
            row.append(value)
        return tuple(row)

    def _populate_private_index_fixture(self, store: FinancialOwner, *, per_obligation: int = 20) -> int:
        tables = (
            "evidence", "payments", "claimed_adjustments", "cases", "actions",
            "action_outbox", "financial_conflicts", "evaluations", "determinations",
        )
        rows_per_table = per_obligation * 20
        # v8 declares foreign keys: the SQL-shaped rows get the parents they name.
        parents = (("control_packs", 1), ("population_imports", 1), ("population_items", 20), ("obligations", 20))
        with store._write() as connection:
            for table, count in parents:
                columns = owner._TABLE_COLUMNS[table]
                connection.executemany(
                    f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                    (self._private_index_fixture_row(table, ordinal) for ordinal in range(count)),
                )
            for table in tables:
                columns = owner._TABLE_COLUMNS[table]
                statement = (
                    f"INSERT INTO {table} ({','.join(columns)}) "
                    f"VALUES ({','.join('?' for _ in columns)})"
                )
                connection.executemany(
                    statement,
                    (
                        self._private_index_fixture_row(table, ordinal, per_obligation=per_obligation)
                        for ordinal in range(rows_per_table)
                    ),
                )
            connection.execute("DELETE FROM temp.rr_captured_rows")  # plan-only rows: no event carries them
        return rows_per_table

    def _assert_private_index_schema(self, path: Path) -> None:
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                _EXPECTED_PRIVATE_INDEX_SET_VERSION,
            )
            actual = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
                )
            }
        expected_indexes = {name: sql for name, _table, _columns, sql in _EXPECTED_PRIVATE_INDEXES}
        self.assertEqual(actual, expected_indexes)

    def _make_owner(
        self,
        *,
        period_id: str = expected.PERIOD_ONE_ID,
        path: Path | None = None,
        clock: _Clock | None = None,
        schema_version: int = 8,
        correction_transition_release: object | None = None,
    ) -> FinancialOwner:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=period_id,
            currency=expected.CURRENCY,
            schema_version=schema_version,
        )
        return FinancialOwner(
            path=path or self._path(),
            config=config,
            trusted_authority=self.authority,
            clock=clock or _Clock(),
            correction_transition_release=correction_transition_release,
        )

    def _make_write_boundary_owner(
        self,
        *,
        fault: str,
        period_id: str = expected.PERIOD_ONE_ID,
        path: Path,
        clock: _Clock | None = None,
        schema_version: int = 8,
        correction_transition_release: object | None = None,
    ) -> _WriteBoundaryOwner:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=period_id,
            currency=expected.CURRENCY,
            schema_version=schema_version,
        )
        return _WriteBoundaryOwner(
            path=path,
            config=config,
            trusted_authority=self.authority,
            clock=clock or _Clock(),
            fault=fault,
            correction_transition_release=correction_transition_release,
        )

    @staticmethod
    def _durable_counts(path: Path) -> dict[str, int]:
        tables = (
            "financial_meta",
            "financial_events",
            "obligations",
            "evidence",
            "claimed_adjustments",
            "cases",
            "determinations",
            "actions",
            "action_outbox",
            "evaluations",
        )
        with closing(sqlite3.connect(str(path))) as connection:
            available = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            selected = [table for table in tables if table in available]
            selected.extend(
                table
                for table in ("program_funding_receipts", "program_funding_projection")
                if table in available
            )
            return {table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in selected}

    @staticmethod
    def _durable_meta(path: Path) -> tuple[object, ...]:
        with closing(sqlite3.connect(str(path))) as connection:
            row = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
            if row is None:
                raise AssertionError("financial_meta row missing")
            return tuple(row)

    def _run_process_boundary(
        self,
        *,
        store: FinancialOwner,
        claim_id: str,
        fault: str,
        clock_value: int,
    ) -> subprocess.CompletedProcess[str]:
        return RightRailFinancialAcceptanceTests._run_boundary_child(
            self, _PROCESS_BOUNDARY_CHILD, [str(store.path), claim_id, fault, str(clock_value)], "process_boundary"
        )

    def _run_funding_process_boundary(
        self,
        *,
        store: FinancialOwner,
        fault: str,
        clock_value: int,
    ) -> subprocess.CompletedProcess[str]:
        return RightRailFinancialAcceptanceTests._run_boundary_child(
            self, _PROCESS_FUNDING_BOUNDARY_CHILD, [str(store.path), fault, str(clock_value)], "funding_process_boundary"
        )

    def _run_boundary_child(self, script: str, arguments: list[str], label: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [sys.executable, "-c", script, *arguments],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            self.fail(f"{label}_timeout stdout={stdout!r} stderr={stderr!r}")
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    @staticmethod
    def _pack(value: expected.ControlPackExpectation) -> ControlPack:
        return _control_pack_from_fixture(value)

    @staticmethod
    def _items(population_id: str) -> tuple[PopulationItem, ...]:
        return _items_from_fixture(expected.PROGRAM_ITEMS, population_id)

    def _population_manifest(
        self,
        fixture: expected.PopulationManifestExpectation = expected.POPULATION_MANIFEST_V1,
        *,
        manifest_id: str | None = None,
        source_owner_id: str | None = None,
        member_ids: tuple[str, ...] | None = None,
        manifest_version: int | None = None,
        supersedes: PopulationManifest | None = None,
        approved_by: str | None = None,
        approval_ref: str | None = None,
        inclusion_rules: tuple[str, ...] | None = None,
        cutoff_ms: int | None = None,
    ) -> PopulationManifest:
        return _population_manifest_from_fixture(
            fixture, self.authority, manifest_id=manifest_id, source_owner_id=source_owner_id,
            member_ids=member_ids, manifest_version=manifest_version, supersedes=supersedes,
            approved_by=approved_by, approval_ref=approval_ref,
            inclusion_rules=inclusion_rules, cutoff_ms=cutoff_ms,
        )

    @staticmethod
    def _funding_receipt(
        *,
        receipt_id: str | None = None,
        state_id: str | None = None,
        source_record_ref: str | None = None,
        amount_cents: int | None = None,
        event_at_ms: int | None = None,
        supersedes_receipt_id: str | None = None,
    ) -> ProgramFundingReceipt:
        fixture = expected.PROGRAM_FUNDING_RECEIPT
        return ProgramFundingReceipt(
            receipt_id=receipt_id or fixture.receipt_id,
            state_id=state_id or fixture.scope.state_id,
            deployment_id=fixture.scope.deployment_id,
            program_id=fixture.scope.program_id,
            period_id=fixture.scope.period_id,
            currency=fixture.scope.currency,
            source_record_ref=source_record_ref or fixture.source_record_ref,
            amount_cents=fixture.amount_cents if amount_cents is None else amount_cents,
            event_at_ms=fixture.event_at_ms if event_at_ms is None else event_at_ms,
            supersedes_receipt_id=supersedes_receipt_id,
            confirmation_class=fixture.confirmation_class,
            evidence_status=fixture.evidence_status,
        )

    def _build_base(
        self,
        *,
        period_id: str = expected.PERIOD_ONE_ID,
        population_id: str = expected.POPULATION_ONE_ID,
        clock: _Clock | None = None,
        schema_version: int = 8,
        correction_transition_release: object | None = None,
    ) -> FinancialOwner:
        owner = self._make_owner(
            period_id=period_id,
            clock=clock,
            schema_version=schema_version,
            correction_transition_release=correction_transition_release,
        )
        pack_expectation = expected.CONTROL_PACK_V1 if period_id == expected.PERIOD_ONE_ID else expected.CONTROL_PACK_V2
        pack = self._pack(pack_expectation)
        owner.publish_control_pack(pack)
        manifest_fixture = expected.POPULATION_MANIFEST_V1 if period_id == expected.PERIOD_ONE_ID else expected.POPULATION_MANIFEST_V2
        manifest = self._population_manifest(manifest_fixture)
        owner.register_population_manifest(manifest)
        owner.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack_expectation.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=len(expected.PROGRAM_ITEMS),
            items=self._items(population_id),
            chunk_size=5,
        )
        owner.validate_population(population_id)
        owner.publish_population(population_id)
        for evidence in expected.OTHER_SUPPORT_EVIDENCE:
            self._record_support(owner, evidence)
        return owner

    def _build_base_for_correction(
        self,
        *,
        period_id: str = expected.PERIOD_ONE_ID,
        population_id: str = expected.POPULATION_ONE_ID,
        clock: _Clock | None = None,
        schema_version: int = 8,
    ) -> FinancialOwner:
        return self._build_base(
            period_id=period_id,
            population_id=population_id,
            clock=clock,
            schema_version=schema_version,
            correction_transition_release=_correction_transition_test_release(
                workspace=Path(self.temp_dir.name) / "correction-engine-workspace",
            ),
        )

    @staticmethod
    def _record_support(store: FinancialOwner, evidence: expected.EvidenceExpectation) -> None:
        _record_fixture_support(store, evidence)

    @staticmethod
    def _record_h_support(store: FinancialOwner) -> None:
        evidence = expected.OFFSET_SUPPORT_EVIDENCE
        RightRailFinancialAcceptanceTests._record_support(store, evidence)

    @staticmethod
    def _record_cash(store: FinancialOwner) -> None:
        evidence = expected.H_CASH_EVIDENCE
        RightRailFinancialAcceptanceTests._record_fixture_payment(store, evidence, payment_id="payment:h:cash")

    @staticmethod
    def _advance_clock(store: FinancialOwner, at_ms: int) -> None:
        clock = getattr(store, "clock", None)
        if isinstance(clock, _Clock):
            clock.value = max(clock.value, at_ms)

    @staticmethod
    def _record_claim(store: FinancialOwner) -> str:
        claim_id = "claim:obligation-item-h:offset-v1"
        evidence = expected.OFFSET_CLAIM_EVIDENCE
        store.record_offset_claim(
            item_id=evidence.item_id,
            claim_id=claim_id,
            amount_cents=evidence.amount_cents or 0,
            evidence_id=evidence.evidence_id,
            owner_role="CASE_OWNER",
            deadline_ms=expected.H_DUE_AT_MS,
        )
        return claim_id

    @staticmethod
    def _authorize(store: FinancialOwner, claim_id: str) -> dict[str, object]:
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        RightRailFinancialAcceptanceTests._advance_clock(store, expected.OFFSET_DECISION_MS - 1)  # recorded when decided
        return store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id=expected.ACTION_OFFSET_ID,
            decision_at_ms=expected.OFFSET_DECISION_MS,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    @staticmethod
    def _reject(store: FinancialOwner, claim_id: str, receipt: dict[str, object] | None = None) -> dict[str, object]:
        receipt = receipt or store.current_evaluation_receipt(expected.H_ITEM_ID)
        RightRailFinancialAcceptanceTests._advance_clock(store, expected.CORRECTION_AUTH_MS - 1)  # recorded when decided
        return store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id=expected.ACTION_CORRECTION_ID,
            decision_at_ms=expected.CORRECTION_AUTH_MS,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    @staticmethod
    def _ack(store: FinancialOwner) -> dict[str, object]:
        return store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:v1")

    @staticmethod
    def _record_p2(store: FinancialOwner) -> None:
        evidence = expected.P2_PAYMENT_EVIDENCE
        RightRailFinancialAcceptanceTests._advance_clock(store, evidence.event_at_ms)
        RightRailFinancialAcceptanceTests._record_fixture_payment(store, evidence, payment_id="payment:h:p2")

    @staticmethod
    def _record_report(store: FinancialOwner) -> None:
        original = expected.REPORT_ORIGINAL_EVIDENCE
        RightRailFinancialAcceptanceTests._advance_clock(store, original.event_at_ms)
        store.record_reporting_evidence(
            item_id=original.item_id,
            report_id="report:h:v1",
            evidence_id=original.evidence_id,
            event_at_ms=original.event_at_ms,
        )
        evidence = expected.REPORT_CORRECTION_EVIDENCE
        RightRailFinancialAcceptanceTests._advance_clock(store, evidence.event_at_ms)
        store.record_reporting_correction(
            item_id=evidence.item_id,
            report_id="report:h:v2",
            evidence_id=evidence.evidence_id,
            event_at_ms=evidence.event_at_ms,
            supersedes=expected.REPORT_ORIGINAL_EVIDENCE.evidence_id,
        )

    def _prepare_rejected(self, store: FinancialOwner) -> str:
        self._record_cash(store)
        claim_id = self._record_claim(store)
        self._reject(store, claim_id)
        return claim_id

    def _prepare_acknowledged(self, store: FinancialOwner) -> str:
        claim_id = self._prepare_rejected(store)
        self._ack(store)
        return claim_id

    def _prepare_reported(self, store: FinancialOwner) -> str:
        claim_id = self._prepare_acknowledged(store)
        self._record_p2(store)
        self._record_report(store)
        return claim_id

    def _finish_after_acknowledgment(self, store: FinancialOwner) -> None:
        self._record_p2(store)
        self._record_report(store)
        duplicate = expected.P2_CONFIRMATION_EVIDENCE
        duplicate_result = RightRailFinancialAcceptanceTests._record_fixture_payment(store, duplicate, payment_id="payment:h:p2-confirmation")
        self.assertEqual(duplicate_result["status"], "DUPLICATE")
        conflict = expected.P2_CONFLICT_EVIDENCE
        conflict_result = RightRailFinancialAcceptanceTests._record_fixture_payment(store, conflict, payment_id="payment:h:p2-conflict")
        self.assertEqual(conflict_result["status"], "CONFLICT")
        reversal = expected.P2_REVERSAL_EVIDENCE
        self._advance_clock(store, reversal.event_at_ms)
        store.reverse_payment(
            item_id=reversal.item_id,
            payment_id="payment:h:p2",
            evidence_id=reversal.evidence_id,
            common_origin_id=reversal.common_origin_id,
            event_at_ms=reversal.event_at_ms,
        )
        replacement = expected.P3_REPLACEMENT_EVIDENCE
        self._advance_clock(store, replacement.event_at_ms)
        RightRailFinancialAcceptanceTests._record_fixture_payment(store, replacement, payment_id="payment:h:p3")

    def _prepare_final(self, store: FinancialOwner) -> str:
        claim_id = self._prepare_acknowledged(store)
        self._finish_after_acknowledgment(store)
        return claim_id

    def _assert_snapshot(self, store: FinancialOwner, value: expected.BalanceExpectation) -> None:
        actual = store.obligation_detail(expected.H_ITEM_ID)
        fields = (
            "owed_cents", "received_cash_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
            "shortfall_cents", "overage_cents", "verification_status", "case_status", "delivery_status",
        )
        expected_values = (
            value.owed_cents, value.received_cash_cents, value.claimed_adjustment_cents,
            value.lawful_adjustment_cents, value.shortfall_cents, value.overage_cents,
            value.verification_status, value.case_status, value.delivery_status,
        )
        for field, expected_value in zip(fields, expected_values):
            with self.subTest(stage=value.stage, field=field):
                self.assertEqual(actual[field], expected_value)
        bools = (
            ("cash_satisfied", value.cash_satisfied),
            ("amount_satisfied", value.amount_satisfied),
            ("timely", value.timely),
            ("reporting_complete", value.reporting_complete),
        )
        for field, expected_value in bools:
            with self.subTest(stage=value.stage, field=field):
                self.assertEqual(bool(actual[field]), expected_value)

    def _assert_population(self, store: FinancialOwner, expected_evidence_items: int) -> None:
        summary = store.summary()
        self.assertEqual(summary["population_count"], 1)
        self.assertEqual(summary["obligation_count"], 20)
        self.assertEqual(summary["owed_cents"], expected.PROGRAM_TOTAL_CENTS)
        rows = store.list_obligations(status="ALL", limit=100)
        item_ids_with_evidence = {
            row["item_id"]
            for row in rows
            if store.obligation_detail(row["item_id"])["evidence"]
        }
        self.assertEqual(len(item_ids_with_evidence), expected_evidence_items)

    @staticmethod
    def _record_fixture_payment(
        store: FinancialOwner | FinancialMirror,
        evidence: expected.EvidenceExpectation | expected.RecipientPaymentExpectation,
        *,
        payment_id: str,
    ) -> dict[str, object]:
        return store.record_payment_evidence(
            item_id=evidence.item_id,
            payment_id=payment_id,
            common_origin_id=evidence.common_origin_id,
            amount_cents=evidence.amount_cents or 0,
            evidence_id=evidence.evidence_id,
            event_at_ms=evidence.event_at_ms,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            local_ref=evidence.local_ref,
        )

    def _first_service_decision_package(self, mirror: FinancialMirror) -> dict[str, object]:
        """Assemble a test-only view from existing owner-backed Mirror references."""

        summary = mirror.summary()
        obligation_page = mirror.list_obligations(status="ALL", limit=100)
        rows = obligation_page["items"]
        detail = mirror.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(detail["case_references"]), 1)
        self.assertEqual(len(detail["determination_references"]), 1)
        self.assertEqual(len(detail["action_references"]), 1)
        case = detail["case_references"][0]
        determination = detail["determination_references"][0]
        action = detail["action_references"][0]
        claim_evidence = next(
            row for row in detail["evidence_references"]
            if row["evidence_id"] == expected.OFFSET_CLAIM_EVIDENCE.evidence_id
        )
        action_payload = mirror.action_payload(str(action["action_id"]))["payload_fields"]
        other_recipient_cash = sum(
            int(row["received_cash_cents"])
            for row in rows
            if row["item_id"] != expected.H_ITEM_ID
        )
        active_payments = sorted(
            (
                {
                    "payment_id": str(row["payment_id"]),
                    "evidence_id": str(row["evidence_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "event_at_ms": int(row["event_at_ms"]),
                }
                for row in detail["payment_references"]
                if int(row["active"]) == 1
            ),
            key=lambda row: row["payment_id"],
        )
        acknowledged_action_ids = sorted(
            str(row["action_id"])
            for row in detail["action_references"]
            if row["status"] == "ACKNOWLEDGED"
        )
        reporting_evidence = sorted(
            str(row["evidence_id"])
            for row in detail["evidence_references"]
            if row["kind"] in {"REPORT", "REPORT_CORRECTION"}
        )
        return {
            "journey_id": expected.FIRST_SERVICE_JOURNEY_ID,
            "scope": {
                key: summary[key]
                for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")
            },
            "nonactivation": {
                "production_usable": summary["production_usable"],
                "activation": summary["activation"],
                "proof_suite_id": summary["proof_suite_id"],
                "dispatch_enabled": summary["dispatch_enabled"],
                "egress_enabled": summary["egress_enabled"],
            },
            "funding_receipt": mirror.program_funding_summary(),
            "program": {
                "denominator_basis": "published_obligations",
                "population_count": summary["population_count"],
                "recipient_count": summary["obligation_count"],
                "owed_cents": summary["owed_cents"],
                "recipient_cash_cents": summary["received_cash_cents"],
                "other_recipient_cash_cents": other_recipient_cash,
            },
            "hospital_h": {
                "obligation_id": detail["obligation_id"],
                "owed_cents": detail["owed_cents"],
                "received_cash_cents": detail["received_cash_cents"],
                "offset_claim_cents": claim_evidence["amount_cents"],
                "shortfall_cents": detail["shortfall_cents"],
                "timely": detail["timely"],
                "reporting_complete": detail["reporting_complete"],
                "case_id": case["case_id"],
                "case_status": case["status"],
                "owner_role": case["next_action_owner"],
                "deadline_ms": case["due_at_ms"],
                "completion_conditions": case["completion_conditions"],
                "decision": determination["decision"],
                "decision_amount_cents": determination["amount_cents"],
                "decision_actor_role": determination["actor_role"],
                "decision_supporting_evidence_ids": determination["supporting_evidence_ids"],
                "next_action": {
                    "action_id": action["action_id"],
                    "kind": action_payload["kind"],
                    "amount_cents": action_payload["amount_cents"],
                    "status": action["status"],
                    "dispatch": action_payload["dispatch"],
                },
                "completion_references": {
                    "acknowledged_action_ids": acknowledged_action_ids,
                    "active_payments": active_payments,
                    "reporting_evidence_ids": reporting_evidence,
                },
            },
        }

    def _assert_verified(
        self,
        store: FinancialOwner,
        *,
        current_snapshot_package: bytes | None = None,
        restore_source_package: bytes | None = None,
    ) -> dict[str, object]:
        result = verify_database(
            store.path,
            expected_config=store.config,
            expected_authority=self.authority,
            expected_mode=store.mode,
            expected_owner_id=store.owner_id,
            current_snapshot_package=current_snapshot_package,
            restore_source_package=restore_source_package,
        )
        self.assertEqual(result["scope"]["period_id"], store.config.period_id)
        return result

    def _assert_decision_package_verified(
        self,
        store: FinancialOwner,
        package: dict[str, object],
    ) -> dict[str, object]:
        return verify_decision_package(
            store.path,
            expected.H_ITEM_ID,
            package,
            expected_config=store.config,
            expected_authority=self.authority,
            expected_mode=store.mode,
            expected_owner_id=store.owner_id,
        )

    def test_case_01_publish_and_missing_h(self) -> None:
        self.assertEqual(expected.CASE_01.number, 1)
        store = self._build_base()
        self._assert_population(store, expected.CASE_01.expected_population_evidence_count)
        self._assert_snapshot(store, expected.H_MISSING)
        self._assert_verified(store)

    def test_case_02_cash_and_offset_claim(self) -> None:
        self.assertEqual(expected.CASE_02.number, 2)
        store = self._build_base()
        self._record_cash(store)
        self._record_claim(store)
        self._assert_population(store, expected.CASE_02.expected_population_evidence_count)
        self._assert_snapshot(store, expected.H_CASH_AND_CLAIM)
        self._assert_verified(store)

    def test_case_03_authorized_offset(self) -> None:
        self.assertEqual(expected.CASE_03.number, 3)
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        self._record_h_support(store)
        result = self._authorize(store, claim_id)
        self.assertEqual(result["status"], "AUTHORIZED")
        self._assert_population(store, expected.CASE_03.expected_population_evidence_count)
        self._assert_snapshot(store, expected.H_AUTHORIZED_OFFSET)
        self._assert_verified(store)

    def test_case_04_reject_and_authorize_correction(self) -> None:
        self.assertEqual(expected.CASE_04.number, 4)
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        before = receipt["revision"]
        self._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided
        with self.assertRaisesRegex(FinancialAuthorityError, expected.UNAUTHORIZED_REJECTION.expected_error):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                actor_id="not-authorized",
                expected_revision=before,
                action_id="action:unauthorized",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["revision"], before)
        with self.assertRaisesRegex(FinancialRevisionError, expected.STALE_REJECTION.expected_error):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=0,
                action_id="action:stale",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self._reject(store, claim_id)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        self._assert_verified(store)

    def test_case_05_ack_without_cash_and_immutable_action_retry(self) -> None:
        self.assertEqual(expected.CASE_05.number, 5)
        store = self._build_base_for_correction()
        self._prepare_rejected(store)
        payload = store.action_payload(expected.ACTION_CORRECTION_ID)["payload"]
        retry = store.retry_action(expected.ACTION_CORRECTION_ID, payload=payload)
        self.assertEqual(retry["status"], "DUPLICATE")
        changed = dict(payload)
        changed["amount_cents"] = expected.CORRECTION_PAYMENT_CENTS + 1
        with self.assertRaisesRegex(FinancialConflictError, expected.ACTION_PAYLOAD_REJECTION.expected_error):
            store.retry_action(expected.ACTION_CORRECTION_ID, payload=changed)
        self._ack(store)
        self._assert_snapshot(store, expected.H_ACKNOWLEDGED)
        self._assert_verified(store)

    def test_corrupt_stored_action_payload_fails_closed_with_typed_error(self) -> None:
        for corrupt in ("not-json", "[]"):
            with self.subTest(corrupt=corrupt):
                store = self._build_base_for_correction()
                self._prepare_rejected(store)
                with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
                    connection.execute("DROP TRIGGER action_payload_immutable")
                    connection.execute(
                        "UPDATE actions SET payload_json=? WHERE action_id=?",
                        (corrupt, expected.ACTION_CORRECTION_ID),
                    )
                with self.assertRaisesRegex(FinancialIntegrityError, "action_payload_integrity"):
                    store.action_payload(expected.ACTION_CORRECTION_ID)
                with self.assertRaisesRegex(FinancialIntegrityError, "action_payload_integrity"):
                    store.retry_action(expected.ACTION_CORRECTION_ID)

    def test_case_06_late_payment_and_report_correction(self) -> None:
        self.assertEqual(expected.CASE_06.number, 6)
        store = self._build_base_for_correction()
        self._prepare_acknowledged(store)
        self._record_p2(store)
        self._assert_snapshot(store, expected.H_P2_RECEIVED_LATE)
        self._record_report(store)
        self._assert_snapshot(store, expected.H_REPORT_CORRECTED_LATE)
        self._assert_verified(store)

    def test_case_07_duplicates_conflict_reversal_and_replacement(self) -> None:
        self.assertEqual(expected.CASE_07.number, 7)
        store = self._build_base_for_correction()
        self._prepare_reported(store)
        duplicate = expected.P2_CONFIRMATION_EVIDENCE
        result = RightRailFinancialAcceptanceTests._record_fixture_payment(store, duplicate, payment_id="payment:h:p2-confirmation")
        self.assertEqual(result["status"], "DUPLICATE")
        self._assert_snapshot(store, expected.H_P2_DUPLICATE_UNCHANGED)
        conflict = expected.P2_CONFLICT_EVIDENCE
        result = RightRailFinancialAcceptanceTests._record_fixture_payment(store, conflict, payment_id="payment:h:p2-conflict")
        self.assertEqual(result["status"], "CONFLICT")
        self._assert_snapshot(store, expected.H_P2_CONFLICT_VISIBLE)
        reversal = expected.P2_REVERSAL_EVIDENCE
        self._advance_clock(store, reversal.event_at_ms)
        store.reverse_payment(
            item_id=reversal.item_id,
            payment_id="payment:h:p2",
            evidence_id=reversal.evidence_id,
            common_origin_id=reversal.common_origin_id,
            event_at_ms=reversal.event_at_ms,
        )
        self._assert_snapshot(store, expected.H_P2_REVERSED)
        replacement = expected.P3_REPLACEMENT_EVIDENCE
        self._advance_clock(store, replacement.event_at_ms)
        RightRailFinancialAcceptanceTests._record_fixture_payment(store, replacement, payment_id="payment:h:p3")
        self._assert_snapshot(store, expected.H_P3_REPLACED)
        self._assert_verified(store)

    def test_case_08_revision_race_one_winner_one_stale_loser(self) -> None:
        self.assertEqual(expected.CASE_08.number, 8)
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        expected_revision = receipt["revision"]
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[tuple[type[BaseException], str]] = []
        self._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided

        def attempt(action_id: str) -> None:
            try:
                barrier.wait(timeout=5)
                result = store.reject_offset_and_authorize_correction(
                    item_id=expected.H_ITEM_ID,
                    claim_id=claim_id,
                    expected_revision=expected_revision,
                    action_id=action_id,
                    decision_at_ms=expected.CORRECTION_AUTH_MS,
                    evaluation_id=receipt["evaluation_id"],
                    evaluation_result_digest=receipt["result_digest"],
                )
                outcomes.append(str(result["status"]))
            except BaseException as error:  # preserve the exact loser class/message for the gate
                errors.append((type(error), str(error)))

        threads = [
            threading.Thread(target=attempt, args=("action:race:one",)),
            threading.Thread(target=attempt, args=("action:race:two",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(outcomes, ["CORRECTION_AUTHORIZED"])
        self.assertEqual(errors, [(FinancialRevisionError, expected.REVISION_RACE.loser_error)])
        detail = store.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(detail["actions"]), 1)
        self.assertEqual(len(detail["cases"]), 1)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        self._assert_verified(store)

    def test_case_09_second_period_rule_change_isolated_and_complete(self) -> None:
        self.assertEqual(expected.CASE_09.number, 9)
        store = self._build_base_for_correction(
            period_id=expected.PERIOD_TWO_ID,
            population_id=expected.POPULATION_TWO_ID,
        )
        self._prepare_final(store)
        self._assert_snapshot(store, expected.H_P3_REPLACED)
        result = self._assert_verified(store)
        self.assertEqual(result["scope"]["period_id"], expected.PERIOD_TWO_ID)
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["period_id"], expected.PERIOD_TWO_ID)

    def test_case_10_interrupted_import_restart_and_disabled_dispatch(self) -> None:
        self.assertEqual(expected.CASE_10.number, 10)
        correction_release = _correction_transition_test_release(
            workspace=Path(self.temp_dir.name) / "correction-engine-workspace",
        )
        store = self._build_base_for_correction()
        self._prepare_rejected(store)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        interrupted_population = "population:fixture-interrupted"
        interrupted_manifest = self._population_manifest(
            manifest_id="population-manifest:fixture-interrupted:v1",
            source_owner_id="source-owner:fixture-interrupted",
        )
        store.register_population_manifest(interrupted_manifest)

        def interrupted_items() -> Iterator[PopulationItem]:
            for index, item in enumerate(self._items(interrupted_population)):
                if index == 4:
                    raise RuntimeError("synthetic_import_interrupt")
                yield item

        with self.assertRaisesRegex(RuntimeError, "synthetic_import_interrupt"):
            store.stage_population(
                population_id=interrupted_population,
                manifest_id=interrupted_manifest.manifest_id,
                pack_id=expected.CONTROL_PACK_V1.pack_id,
                cutoff_ms=expected.PERIOD_ONE_START_MS,
                inclusion_rules=("included:synthetic",),
                expected_count=20,
                items=interrupted_items(),
                chunk_size=4,
            )
        with self.assertRaisesRegex(FinancialIntegrityError, "population_source_incomplete"):
            store.validate_population(interrupted_population)
        with store._read_snapshot() as connection:
            source_complete = connection.execute(
                "SELECT source_complete FROM population_imports WHERE population_id=?",
                (interrupted_population,),
            ).fetchone()
        assert source_complete is not None
        self.assertEqual(int(source_complete[0]), 0)
        before = store.summary()
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            store.dispatch_outbox()
        reopened = self._make_owner(path=store.path)
        self.assertEqual(reopened.summary(), before)
        self._assert_verified(reopened)

        precommit_store = self._build_base_for_correction()
        self._record_cash(precommit_store)
        precommit_claim = self._record_claim(precommit_store)
        precommit_receipt = precommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        precommit_package = precommit_store.export_continuity()
        precommit_summary = precommit_store.summary()
        precommit_counts = self._durable_counts(precommit_store.path)
        precommit_fault = self._make_write_boundary_owner(
            path=precommit_store.path,
            fault="precommit",
            clock=precommit_store.clock,
            correction_transition_release=correction_release,
        )
        with self.assertRaisesRegex(RuntimeError, "synthetic_financial_precommit_interrupt"):
            self._reject(precommit_fault, precommit_claim, precommit_receipt)

        reopened_precommit = self._make_owner(
            path=precommit_store.path,
            clock=precommit_store.clock,
            correction_transition_release=correction_release,
        )
        self.assertEqual(reopened_precommit.summary(), precommit_summary)
        self.assertEqual(reopened_precommit.export_continuity(), precommit_package)
        self.assertEqual(self._durable_counts(reopened_precommit.path), precommit_counts)
        self._assert_snapshot(reopened_precommit, expected.H_CASH_AND_CLAIM)
        self._assert_verified(reopened_precommit)

        committed_after_retry = self._reject(reopened_precommit, precommit_claim, precommit_receipt)
        self.assertEqual(committed_after_retry["status"], "CORRECTION_AUTHORIZED")
        self._assert_snapshot(reopened_precommit, expected.H_REJECTED_CORRECTION)
        self._assert_verified(reopened_precommit)
        committed_package = reopened_precommit.export_continuity()
        committed_counts = self._durable_counts(reopened_precommit.path)
        duplicate_after_retry = self._reject(reopened_precommit, precommit_claim, precommit_receipt)
        self.assertEqual(duplicate_after_retry["status"], "DUPLICATE")
        self.assertEqual(reopened_precommit.export_continuity(), committed_package)
        self.assertEqual(self._durable_counts(reopened_precommit.path), committed_counts)
        detail_after_duplicate = reopened_precommit.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(detail_after_duplicate["determinations"]), 1)
        self.assertEqual(len(detail_after_duplicate["actions"]), 1)
        self._assert_verified(reopened_precommit)

        postcommit_store = self._build_base_for_correction()
        self._record_cash(postcommit_store)
        postcommit_claim = self._record_claim(postcommit_store)
        postcommit_receipt = postcommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        postcommit_fault = self._make_write_boundary_owner(
            path=postcommit_store.path,
            fault="postcommit",
            clock=postcommit_store.clock,
            correction_transition_release=correction_release,
        )
        with self.assertRaisesRegex(RuntimeError, "synthetic_financial_result_lost_after_commit"):
            self._reject(postcommit_fault, postcommit_claim, postcommit_receipt)

        reopened_postcommit = self._make_owner(
            path=postcommit_store.path,
            clock=postcommit_store.clock,
            correction_transition_release=correction_release,
        )
        self._assert_snapshot(reopened_postcommit, expected.H_REJECTED_CORRECTION)
        self._assert_verified(reopened_postcommit)
        postcommit_package = reopened_postcommit.export_continuity()
        postcommit_counts = self._durable_counts(reopened_postcommit.path)
        duplicate_after_commit = self._reject(reopened_postcommit, postcommit_claim, postcommit_receipt)
        self.assertEqual(duplicate_after_commit["status"], "DUPLICATE")
        self.assertEqual(reopened_postcommit.export_continuity(), postcommit_package)
        self.assertEqual(self._durable_counts(reopened_postcommit.path), postcommit_counts)
        postcommit_detail = reopened_postcommit.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(postcommit_detail["determinations"]), 1)
        self.assertEqual(len(postcommit_detail["actions"]), 1)
        self._assert_verified(reopened_postcommit)

        process_precommit_store = self._build_base_for_correction()
        self._record_cash(process_precommit_store)
        process_precommit_claim = self._record_claim(process_precommit_store)
        process_precommit_receipt = process_precommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        process_precommit_package = process_precommit_store.export_continuity()
        process_precommit_summary = process_precommit_store.summary()
        process_precommit_counts = self._durable_counts(process_precommit_store.path)
        process_precommit_clock = max(process_precommit_store.clock.value + 1_000_000, expected.CORRECTION_AUTH_MS)  # not before the decision
        process_precommit = self._run_process_boundary(
            store=process_precommit_store,
            claim_id=process_precommit_claim,
            fault="process_precommit",
            clock_value=process_precommit_clock,
        )
        self.assertEqual(process_precommit.returncode, 73)
        self.assertEqual(process_precommit.stdout, "PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n")
        self.assertEqual(process_precommit.stderr, "")
        print(
            f"PROCESS_BOUNDARY precommit returncode={process_precommit.returncode} "
            f"stdout={process_precommit.stdout!r} stderr={process_precommit.stderr!r}"
        )

        reopened_process_precommit = self._make_owner(
            path=process_precommit_store.path,
            clock=_Clock(process_precommit_clock + 1),
            correction_transition_release=correction_release,
        )
        self.assertEqual(reopened_process_precommit.summary(), process_precommit_summary)
        self.assertEqual(reopened_process_precommit.export_continuity(), process_precommit_package)
        self.assertEqual(self._durable_counts(reopened_process_precommit.path), process_precommit_counts)
        self._assert_snapshot(reopened_process_precommit, expected.H_CASH_AND_CLAIM)
        self._assert_verified(reopened_process_precommit)
        process_precommit_retry = self._reject(reopened_process_precommit, process_precommit_claim, process_precommit_receipt)
        self.assertEqual(process_precommit_retry["status"], "CORRECTION_AUTHORIZED")
        process_precommit_committed_package = reopened_process_precommit.export_continuity()
        process_precommit_committed_counts = self._durable_counts(reopened_process_precommit.path)
        process_precommit_duplicate = self._reject(reopened_process_precommit, process_precommit_claim, process_precommit_receipt)
        self.assertEqual(process_precommit_duplicate["status"], "DUPLICATE")
        self.assertEqual(reopened_process_precommit.export_continuity(), process_precommit_committed_package)
        self.assertEqual(self._durable_counts(reopened_process_precommit.path), process_precommit_committed_counts)
        process_precommit_detail = reopened_process_precommit.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(process_precommit_detail["determinations"]), 1)
        self.assertEqual(len(process_precommit_detail["actions"]), 1)
        self.assertEqual(process_precommit_committed_counts["action_outbox"], 1)
        self._assert_verified(reopened_process_precommit)

        process_postcommit_store = self._build_base_for_correction()
        self._record_cash(process_postcommit_store)
        process_postcommit_claim = self._record_claim(process_postcommit_store)
        process_postcommit_receipt = process_postcommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        process_postcommit_clock = max(process_postcommit_store.clock.value + 1_000_000, expected.CORRECTION_AUTH_MS)
        process_postcommit = self._run_process_boundary(
            store=process_postcommit_store,
            claim_id=process_postcommit_claim,
            fault="process_postcommit",
            clock_value=process_postcommit_clock,
        )
        self.assertEqual(process_postcommit.returncode, 74)
        self.assertEqual(process_postcommit.stdout, "PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n")
        self.assertEqual(process_postcommit.stderr, "")
        print(
            f"PROCESS_BOUNDARY postcommit returncode={process_postcommit.returncode} "
            f"stdout={process_postcommit.stdout!r} stderr={process_postcommit.stderr!r}"
        )

        reopened_process_postcommit = self._make_owner(
            path=process_postcommit_store.path,
            clock=_Clock(process_postcommit_clock + 1),
            correction_transition_release=correction_release,
        )
        self._assert_snapshot(reopened_process_postcommit, expected.H_REJECTED_CORRECTION)
        self._assert_verified(reopened_process_postcommit)
        process_postcommit_detail = reopened_process_postcommit.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(process_postcommit_detail["determinations"]), 1)
        self.assertEqual(len(process_postcommit_detail["actions"]), 1)
        self.assertEqual(process_postcommit_detail["actions"][0]["action_id"], expected.ACTION_CORRECTION_ID)
        self.assertEqual(process_postcommit_detail["actions"][0]["kind"], "CORRECTION_PAYMENT_REQUEST")
        process_postcommit_counts = self._durable_counts(reopened_process_postcommit.path)
        self.assertEqual(process_postcommit_counts["determinations"], 1)
        self.assertEqual(process_postcommit_counts["actions"], 1)
        self.assertEqual(process_postcommit_counts["action_outbox"], 1)
        recovered_followup_snapshot = reopened_process_postcommit.export_continuity()
        first_followup_page = reopened_process_postcommit.drain_correction_followups(limit=10)
        self.assertEqual(first_followup_page["count"], 1)
        self.assertFalse(first_followup_page["has_more"])
        self.assertEqual(first_followup_page["items"][0]["followup_status"], "CURRENT")
        self.assertEqual(
            first_followup_page["items"][0]["work_id"],
            expected.ACTION_CORRECTION_ID,
        )
        self.assertEqual(
            reopened_process_postcommit.drain_correction_followups(limit=10),
            first_followup_page,
        )
        self.assertEqual(
            reopened_process_postcommit.export_continuity(),
            recovered_followup_snapshot,
        )
        other_item_id = next(
            item.item_id
            for item in expected.PROGRAM_ITEMS
            if item.item_id != expected.H_ITEM_ID
        )
        reopened_process_postcommit.evaluate_obligation(other_item_id)
        self.assertEqual(
            reopened_process_postcommit.correction_followup_outputs(
                expected.H_ITEM_ID,
                expected.ACTION_CORRECTION_ID,
            )["followup_status"],
            "CURRENT",
        )
        reopened_process_postcommit.acknowledge_action(
            expected.ACTION_CORRECTION_ID,
            "ack:process-postcommit-correction",
        )
        # G2: an acknowledgment moves no dependency value, so the correction stays closed.
        acknowledged_outputs = reopened_process_postcommit.correction_followup_outputs(
            expected.H_ITEM_ID,
            expected.ACTION_CORRECTION_ID,
        )
        self.assertEqual(acknowledged_outputs["followup_status"], "CURRENT")
        self.assertEqual(acknowledged_outputs["corporate_support"]["error_class"], "NONE")
        process_postcommit_package = reopened_process_postcommit.export_continuity()
        process_postcommit_counts = self._durable_counts(reopened_process_postcommit.path)
        process_postcommit_duplicate = self._reject(reopened_process_postcommit, process_postcommit_claim, process_postcommit_receipt)
        self.assertEqual(process_postcommit_duplicate["status"], "DUPLICATE")
        self.assertEqual(reopened_process_postcommit.export_continuity(), process_postcommit_package)
        self.assertEqual(self._durable_counts(reopened_process_postcommit.path), process_postcommit_counts)
        self._assert_verified(reopened_process_postcommit)

    def test_case_11_shadow_export_restore_and_test_owner_continuation(self) -> None:
        self.assertEqual(expected.CASE_11.number, 11)
        store = self._build_base_for_correction()
        self._prepare_acknowledged(store)
        self._assert_snapshot(store, expected.H_ACKNOWLEDGED)
        source_before_restore = store.path.read_bytes()
        package = store.export_continuity()
        package_result = verify_continuity_package(
            package,
            expected_scope={
                "state_id": expected.STATE_ID,
                "deployment_id": expected.DEPLOYMENT_ID,
                "program_id": expected.PROGRAM_ID,
                "period_id": expected.PERIOD_ONE_ID,
                "currency": expected.CURRENCY,
            },
            expected_authority=self.authority,
        )
        self.assertEqual(package_result["package_digest"], package_result["package_digest"].upper())
        destination = self._path("shadow.sqlite")
        shadow = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=destination,
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        self.assertEqual(shadow.mode, "SHADOW")
        self.assertEqual(shadow.owner_id, "continuity-shadow-owner-v1")
        self._assert_snapshot(shadow, expected.H_ACKNOWLEDGED)
        self.assertTrue(shadow.obligation_detail(expected.H_ITEM_ID)["evidence"])
        self.assertEqual(shadow.action_payload(expected.ACTION_CORRECTION_ID), store.action_payload(expected.ACTION_CORRECTION_ID))
        with self.assertRaisesRegex(FinancialDispatchError, "shadow_owner_read_only"):
            shadow.retry_action(expected.ACTION_CORRECTION_ID)
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            shadow.dispatch_outbox()
        self._assert_verified(shadow)
        self.assertEqual(store.path.read_bytes(), source_before_restore)
        source_mirror = FinancialMirror(store)
        test_destination = self._path("test-continuation.sqlite")
        test_mirror = source_mirror.restore_test_continuity(package, test_destination)
        test_store = test_mirror.owner
        self.assertEqual(test_store.mode, "TEST")
        self.assertEqual(test_store.owner_id, owner._TEST_OWNER_ID)
        self.assertFalse(test_store.summary()["dispatch_enabled"])
        self.assertFalse(test_store.summary()["egress_enabled"])
        self.assertEqual(test_store.verify_integrity()["mode"], "TEST")
        self._assert_snapshot(test_store, expected.H_ACKNOWLEDGED)
        test_package = test_store.export_continuity()
        self.assertEqual(FinancialOwner.validate_continuity_package(test_package)["mode"], "TEST")
        self._assert_verified(test_store, restore_source_package=package)
        self._assert_verified(test_store, current_snapshot_package=test_package)
        test_sequence = test_store.summary()["sequence"]
        duplicate_action = test_store.retry_action(
            expected.ACTION_CORRECTION_ID,
            payload=test_store.action_payload(expected.ACTION_CORRECTION_ID)["payload"],
        )
        self.assertEqual(duplicate_action["status"], "DUPLICATE")
        self.assertEqual(test_store.summary()["sequence"], test_sequence)
        self.assertEqual(store.path.read_bytes(), source_before_restore)
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            test_store.dispatch_outbox()
        self._finish_after_acknowledgment(test_store)
        self._assert_snapshot(test_store, expected.H_P3_REPLACED)
        self._assert_verified(test_store, restore_source_package=package)
        self._assert_verified(test_store)
        test_bytes_after_completion = test_destination.read_bytes()
        test_config = test_store.config
        roundtrip_package = test_store.export_continuity()
        test_store.close()
        with self.assertRaisesRegex(FinancialIntegrityError, "nonactivating_boundary"):
            FinancialOwner(
                path=test_destination,
                config=test_config,
                trusted_authority=self.authority,
                clock=_Clock(),
                mode="LIVE",
                owner_id=owner._TEST_OWNER_ID,
            )
        reopened_test = FinancialOwner(
            path=test_destination,
            config=test_config,
            trusted_authority=self.authority,
            clock=_Clock(),
            mode="TEST",
            owner_id=owner._TEST_OWNER_ID,
        )
        self.assertEqual(reopened_test.verify_integrity()["mode"], "TEST")
        self._assert_snapshot(reopened_test, expected.H_P3_REPLACED)
        self._assert_verified(reopened_test, restore_source_package=package)
        with self.assertRaisesRegex(IndependentFinancialError, "continuity:restore-source-digest"):
            self._assert_verified(reopened_test, restore_source_package=roundtrip_package)
        self._assert_verified(reopened_test)
        reopened_test.close()
        self.assertEqual(test_destination.read_bytes(), test_bytes_after_completion)

        roundtrip_destination = self._path("test-roundtrip.sqlite")
        roundtrip = FinancialOwner.restore_continuity(
            package_bytes=roundtrip_package,
            recovered_path=roundtrip_destination,
            trusted_authority=self.authority,
            clock=_Clock(),
            restore_mode="TEST",
        )
        self._assert_verified(roundtrip, restore_source_package=roundtrip_package)
        roundtrip_current_package = roundtrip.export_continuity()
        self._assert_verified(roundtrip, current_snapshot_package=roundtrip_current_package)
        roundtrip.close()

        def _tamper_restore_identity(bound_mode: str, bound_owner_id: str) -> bytes:
            candidate = json.loads(roundtrip_current_package.decode("ascii"))
            identity_row = candidate["tables"]["financial_identity"][0]
            identity_row["bound_mode"] = bound_mode
            identity_row["bound_owner_id"] = bound_owner_id
            identity_row["identity_digest"] = {
                "hex": owner._hex(
                    owner._identity_digest(
                        provenance=identity_row["provenance"],
                        bound_mode=bound_mode,
                        bound_owner_id=bound_owner_id,
                        anchor_sequence=identity_row["anchor_sequence"],
                        source_package_digest=bytes.fromhex(identity_row["source_package_digest"]["hex"]),
                    )
                )
            }
            candidate["mode"] = bound_mode
            meta_row = candidate["tables"]["financial_meta"][0]
            meta_row["mode"] = bound_mode
            meta_row["owner_id"] = bound_owner_id
            body = dict(candidate)
            del body["package_digest"]
            candidate["package_digest"] = owner._hex(owner._digest(owner._CONTINUITY_DOMAIN, owner._canonical(body)))
            return owner._canonical(candidate)

        restore_scope = {key: getattr(test_config, key) for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")}
        for mode, owner_id, reason in (("LIVE", "financial-owner-v1", "restore-live"), ("SHADOW", owner._TEST_OWNER_ID, "restore-owner")):
            with self.subTest(identity=reason):
                candidate = _tamper_restore_identity(mode, owner_id)
                with self.assertRaisesRegex(FinancialContinuityError, "continuity_identity:" + reason):
                    FinancialOwner.validate_continuity_package(candidate)
                with self.assertRaisesRegex(IndependentFinancialError, "continuity:identity:" + reason):
                    verify_continuity_package(candidate, expected_scope=restore_scope, expected_authority=self.authority)

        mode_only = self._path("test-promotion-mode-only.sqlite")
        mode_only.write_bytes(test_bytes_after_completion)
        with closing(sqlite3.connect(mode_only, isolation_level=None)) as connection:
            connection.execute("UPDATE financial_meta SET mode='LIVE' WHERE id=1")
        with self.assertRaisesRegex(FinancialIntegrityError, "identity"):
            FinancialOwner(
                path=mode_only,
                config=test_config,
                trusted_authority=self.authority,
                clock=_Clock(),
                mode="LIVE",
                owner_id=owner._TEST_OWNER_ID,
            )
        with self.assertRaisesRegex(IndependentFinancialError, "identity"):
            verify_database(
                mode_only,
                expected_config=test_config,
                expected_authority=self.authority,
                expected_mode="LIVE",
                expected_owner_id=owner._TEST_OWNER_ID,
            )

        mode_and_owner = self._path("test-promotion-mode-and-owner.sqlite")
        mode_and_owner.write_bytes(test_bytes_after_completion)
        with closing(sqlite3.connect(mode_and_owner, isolation_level=None)) as connection:
            connection.execute("PRAGMA recursive_triggers=OFF")
            identity_columns = owner._TABLE_COLUMNS["financial_identity"]
            identity_row = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchone()
            assert identity_row is not None
            replacement = dict(zip(identity_columns, identity_row))
            replacement["bound_mode"] = "LIVE"
            replacement["bound_owner_id"] = "financial-owner-v1"
            replacement["identity_digest"] = owner._identity_digest(
                provenance=replacement["provenance"],
                bound_mode=replacement["bound_mode"],
                bound_owner_id=replacement["bound_owner_id"],
                anchor_sequence=replacement["anchor_sequence"],
                source_package_digest=replacement["source_package_digest"],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "financial_identity_immutable"):
                connection.execute(
                    f"INSERT OR REPLACE INTO financial_identity ({','.join(identity_columns)}) VALUES ({','.join('?' for _ in identity_columns)})",
                    tuple(replacement[column] for column in identity_columns),
                )
            connection.execute("UPDATE financial_meta SET mode='LIVE',owner_id='financial-owner-v1' WHERE id=1")
        with self.assertRaisesRegex(FinancialIntegrityError, "identity"):
            FinancialOwner(
                path=mode_and_owner,
                config=test_config,
                trusted_authority=self.authority,
                clock=_Clock(),
                mode="LIVE",
                owner_id="financial-owner-v1",
            )
        with self.assertRaisesRegex(IndependentFinancialError, "identity"):
            verify_database(
                mode_and_owner,
                expected_config=test_config,
                expected_authority=self.authority,
                expected_mode="LIVE",
                expected_owner_id="financial-owner-v1",
            )
        self.assertEqual(store.path.read_bytes(), source_before_restore)

    def test_program_funding_receipt_identity_supersession_and_test_restore(self) -> None:
        store = self._make_owner()
        mirror = FinancialMirror(store)
        original_package = store.export_continuity()
        original_counts = self._durable_counts(store.path)
        receipt = self._funding_receipt()

        wrong_scope = self._funding_receipt(state_id="another-synthetic-state")
        with self.assertRaisesRegex(FinancialInputError, "program_funding_scope"):
            mirror.record_program_funding_receipt(wrong_scope)
        self.assertEqual(store.export_continuity(), original_package)
        self.assertEqual(self._durable_counts(store.path), original_counts)

        recorded = mirror.record_program_funding_receipt(receipt)
        self.assertEqual(recorded["status"], "RECORDED")
        self.assertEqual(store.summary()["sequence"], 1)
        first_package = store.export_continuity()
        first_counts = self._durable_counts(store.path)
        first_summary = mirror.program_funding_summary()
        self.assertEqual(first_summary["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(first_summary["current_receipt_count"], 1)
        self.assertEqual(first_summary["historical_receipt_count"], 1)
        self.assertEqual(first_summary["current_receipts"][0]["receipt_id"], receipt.receipt_id)
        self.assertEqual(store.summary()["owed_cents"], 0)
        self.assertEqual(store.summary()["received_cash_cents"], 0)

        duplicate = mirror.record_program_funding_receipt(receipt)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(store.export_continuity(), first_package)
        self.assertEqual(self._durable_counts(store.path), first_counts)

        refused = (
            ("identity_conflict", replace(receipt, amount_cents=receipt.amount_cents + 1)),
            ("identity_conflict", replace(receipt, supersedes_receipt_id="funding-receipt:unrelated")),
            ("supersession_required", self._funding_receipt(receipt_id="funding-receipt:state:period-01:missing-supersession")),
            ("supersession_missing", self._funding_receipt(receipt_id="funding-receipt:state:period-01:missing-parent", supersedes_receipt_id="funding-receipt:state:period-01:does-not-exist")),
        )
        for reason, candidate in refused:
            code = "program_funding_receipt_identity_conflict" if reason == "identity_conflict" else "program_funding_" + reason
            with self.subTest(receipt=candidate), self.assertRaisesRegex(FinancialConflictError, code):
                mirror.record_program_funding_receipt(candidate)
            self.assertEqual(store.export_continuity(), first_package)
            self.assertEqual(self._durable_counts(store.path), first_counts)

        replacement = self._funding_receipt(
            receipt_id="funding-receipt:state:period-01:v2",
            amount_cents=99_000_000,
            event_at_ms=expected.PROGRAM_FUNDING_RECEIPT.event_at_ms + 1,
            supersedes_receipt_id=receipt.receipt_id,
        )
        superseded = mirror.record_program_funding_receipt(replacement)
        self.assertEqual(superseded["status"], "RECORDED")
        second_package = store.export_continuity()
        second_counts = self._durable_counts(store.path)
        current_summary = mirror.program_funding_summary()
        self.assertEqual(current_summary["reported_funding_cents"], 99_000_000)
        self.assertEqual(current_summary["current_receipt_count"], 1)
        self.assertEqual(current_summary["historical_receipt_count"], 2)
        self.assertEqual(current_summary["current_receipts"][0]["receipt_id"], replacement.receipt_id)
        self.assertEqual(store.summary()["received_cash_cents"], 0)

        replayed_original = mirror.record_program_funding_receipt(receipt)
        self.assertEqual(replayed_original["status"], "DUPLICATE")
        self.assertEqual(mirror.program_funding_summary(), current_summary)
        self.assertEqual(store.export_continuity(), second_package)
        self.assertEqual(self._durable_counts(store.path), second_counts)

        stale_fork = self._funding_receipt(
            receipt_id="funding-receipt:state:period-01:stale-fork",
            supersedes_receipt_id=receipt.receipt_id,
        )
        with self.assertRaisesRegex(FinancialConflictError, "program_funding_supersession_stale"):
            mirror.record_program_funding_receipt(stale_fork)
        self.assertEqual(store.export_continuity(), second_package)

        package_identity = json.loads(second_package.decode("ascii"))
        independent_package = verify_continuity_package(
            second_package,
            expected_scope=package_identity["scope"],
            expected_authority=self.authority,
            expected_schema_version=8,
        )
        self.assertEqual(independent_package["version"], 8)
        self.assertEqual(independent_package["program_funding"]["reported_funding_cents"], 99_000_000)
        tampered_package = json.loads(second_package.decode("ascii"))
        tampered_package["tables"]["program_funding_projection"][0]["amount_cents"] += 1
        tampered_body = dict(tampered_package)
        del tampered_body["package_digest"]
        tampered_package["package_digest"] = continuity_package_digest(tampered_body)
        with self.assertRaisesRegex(IndependentFinancialError, "funding:projection-reconstruction"):
            verify_continuity_package(
                _independent_canonical(tampered_package),
                expected_scope=package_identity["scope"],
                expected_authority=self.authority,
                expected_schema_version=8,
            )
        restored_mirror = mirror.restore_test_continuity(
            second_package,
            self._path("funding-test-restore.sqlite"),
        )
        restored = restored_mirror.owner
        self.assertEqual(restored.mode, "TEST")
        self.assertEqual(restored_mirror.program_funding_summary(), current_summary)
        self.assertEqual(restored_mirror.verify_integrity()["program_funding"]["reported_funding_cents"], 99_000_000)
        restored_package_before_retry = restored.export_continuity()
        restored_duplicate = restored_mirror.record_program_funding_receipt(receipt)
        self.assertEqual(restored_duplicate["status"], "DUPLICATE")
        self.assertEqual(restored_mirror.program_funding_summary(), current_summary)
        self.assertEqual(restored.export_continuity(), restored_package_before_retry)
        self._assert_verified(restored, restore_source_package=second_package)

        bounded = self._make_owner()
        maximum = self._funding_receipt(
            receipt_id="funding-receipt:bounded:maximum",
            source_record_ref="state-payment-record:maximum",
            amount_cents=(1 << 63) - 1,
        )
        self.assertEqual(bounded.record_program_funding_receipt(maximum)["status"], "RECORDED")
        bounded_package = bounded.export_continuity()
        overflow = self._funding_receipt(
            receipt_id="funding-receipt:bounded:overflow",
            source_record_ref="state-payment-record:overflow",
            amount_cents=1,
        )
        with self.assertRaisesRegex(FinancialInputError, "program_funding_total_cents"):
            bounded.record_program_funding_receipt(overflow)
        self.assertEqual(bounded.export_continuity(), bounded_package)
        self.assertEqual(bounded.program_funding_summary()["reported_funding_cents"], (1 << 63) - 1)
        self._assert_verified(bounded)

    def test_program_funding_supersession_clock_rollback_rejects_atomically(self) -> None:
        clock = _Clock(initial=1_700_000_000_000)
        store = self._make_owner(clock=clock)
        mirror = FinancialMirror(store)
        parent_receipt = self._funding_receipt()
        recorded = mirror.record_program_funding_receipt(parent_receipt)
        self.assertEqual(recorded["status"], "RECORDED")
        parent_recorded_at = int(recorded["receipt"]["recorded_at_ms"])

        before_package = store.export_continuity()
        before_counts = self._durable_counts(store.path)
        before_meta = self._durable_meta(store.path)
        clock.value = parent_recorded_at - 2
        rolled_back_child = self._funding_receipt(
            receipt_id="funding-receipt:state:period-01:clock-rollback",
            event_at_ms=parent_receipt.event_at_ms + 1,
            supersedes_receipt_id=parent_receipt.receipt_id,
        )
        with self.assertRaisesRegex(FinancialInputError, "program_funding_supersession_chronology"):
            mirror.record_program_funding_receipt(rolled_back_child)
        self.assertEqual(clock.value, parent_recorded_at - 1)
        self.assertEqual(store.export_continuity(), before_package)
        self.assertEqual(self._durable_counts(store.path), before_counts)
        self.assertEqual(self._durable_meta(store.path), before_meta)
        self._assert_verified(store)

        retry_clock_value = clock.value
        self.assertEqual(mirror.record_program_funding_receipt(parent_receipt)["status"], "DUPLICATE")
        self.assertEqual(clock.value, retry_clock_value)
        self.assertEqual(store.export_continuity(), before_package)
        self._assert_verified(store)

    def test_private_snapshot_index_migration_prevalidates_identity_and_preserves_restore(self) -> None:
        source = self._make_owner()
        source_package = source.export_continuity()
        legacy_path = self._path("private-index-legacy.sqlite")
        legacy_path.write_bytes(source.path.read_bytes())
        with closing(sqlite3.connect(str(legacy_path), isolation_level=None)) as connection:
            for name, _table, _columns, _sql in _EXPECTED_PRIVATE_INDEXES:
                connection.execute(f'DROP INDEX "{name}"')
            connection.execute("PRAGMA user_version=0")
        legacy_bytes = legacy_path.read_bytes()

        wrong_config = replace(source.config, state_id="state:wrong-private-index-scope")
        with self.assertRaisesRegex(FinancialIntegrityError, "schema_identity"):
            FinancialOwner(
                path=legacy_path,
                config=wrong_config,
                trusted_authority=self.authority,
                clock=_Clock(initial=1_700_000_000_000),
            )
        self.assertEqual(legacy_path.read_bytes(), legacy_bytes)

        migrated = self._make_owner(path=legacy_path)
        self._assert_private_index_schema(legacy_path)
        self.assertEqual(migrated.export_continuity(), source_package)
        migrated.verify_integrity()

        reopened = self._make_owner(path=legacy_path)
        self._assert_private_index_schema(legacy_path)
        self.assertEqual(reopened.export_continuity(), source_package)
        reopened.verify_integrity()

        restored_path = self._path("private-index-restored.sqlite")
        restored = FinancialOwner.restore_continuity(
            package_bytes=source_package,
            recovered_path=restored_path,
            trusted_authority=self.authority,
            clock=_Clock(initial=1_700_000_000_000),
            restore_mode="TEST",
        )
        self._assert_private_index_schema(restored_path)
        restored.verify_integrity()

    def test_owner_open_replays_history_and_refuses_same_length_projection_edit(self) -> None:
        store = self._build_base()
        self._assert_verified(store)
        tampered_path = self._path("open-replay-projection-tamper.sqlite")
        tampered_path.write_bytes(store.path.read_bytes())
        with closing(sqlite3.connect(str(tampered_path), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute(
                "UPDATE obligations SET owed_cents=owed_cents+1 WHERE obligation_id=?",
                (expected.H_OBLIGATION_ID,),
            )
        with self.assertRaises(IndependentFinancialError) as checker:
            verify_database(tampered_path, expected_config=store.config, expected_authority=self.authority)
        expected_code = f"open_verification:{checker.exception}"
        tampered_bytes = tampered_path.read_bytes()
        with self.assertRaises(FinancialIntegrityError) as refused:
            self._make_owner(path=tampered_path)
        self.assertEqual(str(refused.exception), expected_code)
        self.assertEqual(tampered_path.read_bytes(), tampered_bytes)

        # The same edit in a store written before the history triggers existed:
        # the refused open rolls back its migration too, so nothing is written.
        legacy_path = self._path("open-replay-projection-tamper-legacy.sqlite")
        legacy_path.write_bytes(tampered_bytes)
        with closing(sqlite3.connect(str(legacy_path), isolation_level=None)) as connection:
            for name in owner._HISTORY_APPEND_ONLY_TRIGGERS:
                connection.execute(f"DROP TRIGGER {name}")
        legacy_bytes = legacy_path.read_bytes()
        with self.assertRaises(FinancialIntegrityError) as legacy_refused:
            self._make_owner(path=legacy_path)
        self.assertEqual(str(legacy_refused.exception), expected_code)
        self.assertEqual(legacy_path.read_bytes(), legacy_bytes)
        with closing(sqlite3.connect(str(legacy_path))) as connection:
            triggers = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='financial_events'")
            }
        self.assertTrue(triggers.isdisjoint(owner._HISTORY_APPEND_ONLY_TRIGGERS))

    def test_financial_history_is_append_only_in_new_and_migrated_stores(self) -> None:
        store = self._build_base()
        package = store.export_continuity()
        history_triggers = tuple(owner._HISTORY_APPEND_ONLY_TRIGGERS)
        store_before = store.path.read_bytes()
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            event_count = connection.execute("SELECT COUNT(*) FROM financial_events").fetchone()[0]
            self.assertGreater(event_count, 0)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "financial_event_immutable"):
                connection.execute("UPDATE financial_events SET payload_json='{}' WHERE event_sequence=1")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "financial_event_immutable"):
                connection.execute("DELETE FROM financial_events WHERE event_sequence=?", (event_count,))
        self.assertEqual(store.path.read_bytes(), store_before)
        self._assert_verified(store)

        # A store written before the triggers existed: the checker refuses it,
        # a wrong-scope opener leaves it untouched, and the owner installs the
        # triggers once without changing any exported fact.
        legacy_path = self._path("history-append-only-legacy.sqlite")
        legacy_path.write_bytes(store_before)
        with closing(sqlite3.connect(str(legacy_path), isolation_level=None)) as connection:
            for name in history_triggers:
                connection.execute(f"DROP TRIGGER {name}")
        legacy_bytes = legacy_path.read_bytes()
        with self.assertRaisesRegex(IndependentFinancialError, "schema:triggers"):
            verify_database(legacy_path, expected_config=store.config, expected_authority=self.authority)
        wrong_config = replace(store.config, state_id="state:wrong-history-trigger-scope")
        with self.assertRaisesRegex(FinancialIntegrityError, "schema_identity"):
            FinancialOwner(
                path=legacy_path,
                config=wrong_config,
                trusted_authority=self.authority,
                clock=_Clock(),
            )
        self.assertEqual(legacy_path.read_bytes(), legacy_bytes)
        migrated = self._make_owner(path=legacy_path)
        self.assertEqual(migrated.export_continuity(), package)
        self._assert_verified(migrated)
        with closing(sqlite3.connect(str(legacy_path), isolation_level=None)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "financial_event_immutable"):
                connection.execute("DELETE FROM financial_events")

        # A weakened trigger is refused, not repaired.
        weakened_path = self._path("history-append-only-weakened.sqlite")
        weakened_path.write_bytes(store_before)
        with closing(sqlite3.connect(str(weakened_path), isolation_level=None)) as connection:
            connection.execute("DROP TRIGGER financial_event_update_immutable")
            connection.execute(
                "CREATE TRIGGER financial_event_update_immutable BEFORE UPDATE OF head ON financial_events "
                "BEGIN SELECT RAISE(ABORT,'financial_event_immutable'); END"
            )
        weakened_bytes = weakened_path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "schema_history_triggers"):
            self._make_owner(path=weakened_path)
        self.assertEqual(weakened_path.read_bytes(), weakened_bytes)
        with self.assertRaisesRegex(IndependentFinancialError, "schema:trigger:financial_event_update_immutable"):
            verify_database(weakened_path, expected_config=store.config, expected_authority=self.authority)
        self.assertEqual(weakened_path.read_bytes(), weakened_bytes)

    def test_a_v1_private_index_set_stays_valid_and_upgrades_to_v2_on_open(self) -> None:
        source = self._make_owner()
        source_package = source.export_continuity()
        v1_path = self._path("private-index-v1.sqlite")
        v1_path.write_bytes(source.path.read_bytes())
        with closing(sqlite3.connect(str(v1_path), isolation_level=None)) as connection:
            connection.execute('DROP INDEX "rr_financial_v2_events_aggregate_kind"')
            connection.execute("PRAGMA user_version=1")
        verify_database(v1_path, expected_config=source.config, expected_authority=self.authority)
        with closing(sqlite3.connect(str(v1_path), isolation_level=None)) as connection:
            connection.execute("PRAGMA user_version=2")  # v2 claimed without its index
        with self.assertRaisesRegex(IndependentFinancialError, "schema:private-indexes"):
            verify_database(v1_path, expected_config=source.config, expected_authority=self.authority)
        with self.assertRaisesRegex(FinancialIntegrityError, "schema_private_indexes"):
            self._make_owner(path=v1_path)
        with closing(sqlite3.connect(str(v1_path), isolation_level=None)) as connection:
            connection.execute("PRAGMA user_version=1")
        upgraded = self._make_owner(path=v1_path)
        self._assert_private_index_schema(v1_path)
        self.assertEqual(upgraded.export_continuity(), source_package)
        verify_database(v1_path, expected_config=source.config, expected_authority=self.authority)

    def test_a_shadow_open_never_writes(self) -> None:
        source = self._make_owner()
        package = source.export_continuity()
        stores = {  # a v1 index set is read as it is; a store a writing owner would migrate is refused
            None: ('DROP INDEX "rr_financial_v2_events_aggregate_kind"', "PRAGMA user_version=1"),
            "pre-segment": tuple(f"DROP TABLE {table}" for table in ("history_segments", "history_pending", "history_open")),
            "no-append-only": tuple(f'DROP TRIGGER "{name}"' for name in owner._HISTORY_APPEND_ONLY_TRIGGERS),
            "no-index-set": (*(f'DROP INDEX "{name}"' for name, _table, _columns in owner._PRIVATE_INDEX_SETS[2]), "PRAGMA user_version=0"),
        }
        for refusal, statements in stores.items():
            with self.subTest(refusal=refusal):
                path = self._path(f"shadow-{refusal}.sqlite")
                FinancialOwner.restore_continuity(package_bytes=package, recovered_path=path, trusted_authority=self.authority, clock=_Clock())
                with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
                    for statement in statements:
                        connection.execute(statement)
                before = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaisesRegex(FinancialIntegrityError, "^shadow_requires_migration$") if refusal else nullcontext():
                    FinancialOwner(path=path, config=source.config, trusted_authority=self.authority, clock=_Clock(), mode="SHADOW", owner_id=owner._SHADOW_OWNER_ID)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
                with closing(sqlite3.connect(str(path))) as connection:
                    self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0 if refusal == "no-index-set" else 1 if refusal is None else 2)

    def test_private_snapshot_index_upgrade_serializes_concurrent_openers(self) -> None:
        source = self._make_owner(schema_version=8)
        source_package = source.export_continuity()
        legacy_path = self._path("v7-private-index-concurrent-legacy.sqlite")
        legacy_path.write_bytes(source.path.read_bytes())
        with closing(sqlite3.connect(str(legacy_path), isolation_level=None)) as connection:
            for name, _table, _columns, _sql in _EXPECTED_PRIVATE_INDEXES:
                connection.execute(f'DROP INDEX "{name}"')
            connection.execute("PRAGMA user_version=0")

        barrier = threading.Barrier(2)
        results: list[bytes] = []
        errors: list[BaseException] = []

        def open_owner() -> None:
            try:
                barrier.wait(timeout=5)
                store = self._make_owner(
                    schema_version=8,
                    path=legacy_path,
                    clock=_Clock(initial=1_700_000_000_000),
                )
                results.append(store.export_continuity())
            except BaseException as error:
                errors.append(error)

        workers = [threading.Thread(target=open_owner) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=15)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(results, [source_package, source_package])
        self._assert_private_index_schema(legacy_path)

    def test_owner_rejects_unapproved_or_mismatched_private_indexes_without_repair(self) -> None:
        source = self._make_owner(schema_version=8)
        corruptions = (
            ("extra-index", "CREATE INDEX unapproved_plan_index ON evidence(source_id)"),
            (
                "wrong-definition",
                "DROP INDEX rr_financial_v1_evidence_item_id; "
                "CREATE INDEX rr_financial_v1_evidence_item_id ON evidence(source_id)",
            ),
        )
        for label, statement in corruptions:
            with self.subTest(label=label):
                target = self._path(f"private-index-{label}.sqlite")
                target.write_bytes(source.path.read_bytes())
                with closing(sqlite3.connect(str(target), isolation_level=None)) as connection:
                    for sql in statement.split("; "):
                        connection.execute(sql)
                before = target.read_bytes()
                with self.assertRaisesRegex(FinancialIntegrityError, "schema_private_indexes"):
                    self._make_owner(schema_version=8, path=target)
                self.assertEqual(target.read_bytes(), before)

    def test_v7_private_snapshot_indexes_avoid_scans_in_bounded_fixture(self) -> None:
        # These SQL-shaped rows exercise plans and index cost only; this fixture
        # does not claim event-history or financial-semantic validity.
        store = self._make_owner(schema_version=8)
        rows_per_table = self._populate_private_index_fixture(store)
        self.assertEqual(rows_per_table, 400)

        queries = (
            (
                "evidence_by_item",
                "evidence",
                "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes FROM evidence WHERE item_id=? ORDER BY evidence_id",
                ("item:00",),
                "rr_financial_v1_evidence_item_id",
            ),
            (
                "payments_by_obligation",
                "payments",
                "SELECT payment_id,obligation_id,item_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id FROM payments WHERE obligation_id=? ORDER BY payment_id",
                ("obligation:00",),
                None,
            ),
            (
                "claims_by_obligation",
                "claimed_adjustments",
                "SELECT claim_id,obligation_id,evidence_id,amount_cents,owner_role,deadline_ms,status,created_at_ms,updated_at_ms FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
                ("obligation:00",),
                "rr_financial_v1_claims_obligation_id",
            ),
            (
                "cases_by_obligation",
                "cases",
                "SELECT case_id,obligation_id,reason,contractual_accountability,next_action_owner,due_at_ms,completion_conditions_json,status,updated_at_ms FROM cases WHERE obligation_id=? ORDER BY case_id",
                ("obligation:00",),
                "rr_financial_v1_cases_obligation_id",
            ),
            (
                "actions_by_obligation",
                "actions",
                "SELECT action_id,obligation_id,determination_id,kind,status,revision,payload_json,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
                ("obligation:00",),
                "rr_financial_v1_actions_obligation_id",
            ),
            (
                "outbox_by_obligation_actions",
                "actions",
                "SELECT action_id,status,attempt,payload_digest,acknowledgment_ref,updated_at_ms FROM action_outbox WHERE action_id IN (SELECT action_id FROM actions WHERE obligation_id=?) ORDER BY action_id",
                ("obligation:00",),
                "rr_financial_v1_actions_obligation_id",
            ),
            (
                "conflicts_by_obligation",
                "financial_conflicts",
                "SELECT conflict_id,obligation_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
                ("obligation:00",),
                "rr_financial_v1_conflicts_obligation_id",
            ),
            (
                "evaluations_by_obligation",
                "evaluations",
                "SELECT evaluation_id,obligation_id,revision,rule_version,evidence_ids_json,authority_id,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest,contract_version,scope_json,control_pack_id,control_pack_version,control_pack_digest,authority_epoch,authority_digest,evidence_bindings_json,input_snapshot_json,input_snapshot_digest,receipt_digest FROM evaluations WHERE obligation_id=? ORDER BY revision",
                ("obligation:00",),
                "rr_financial_v1_evaluations_obligation_revision",
            ),
            (
                "determinations_by_obligation",
                "determinations",
                "SELECT determination_id,obligation_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,authority_digest,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest,input_evaluation_id,input_evaluation_result_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id",
                ("obligation:00",),
                "rr_financial_v1_determinations_obligation_id",
            ),
            (
                "determination_by_input_evaluation",
                "determinations",
                "SELECT determination_id FROM determinations WHERE input_evaluation_id=?",
                ("evaluation:0000",),
                None,
            ),
        )

        baseline_path = self._path("v7-private-index-plan-baseline.sqlite")
        baseline_path.write_bytes(store.path.read_bytes())
        with closing(sqlite3.connect(str(baseline_path), isolation_level=None)) as connection:
            for name, _table, _columns, _sql in _EXPECTED_PRIVATE_INDEXES:
                connection.execute(f'DROP INDEX "{name}"')
            connection.execute("PRAGMA user_version=0")

        def prepare_statistics(path: Path) -> int:
            with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
                connection.execute("ANALYZE")
                connection.execute("VACUUM")
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                return page_count * page_size

        baseline_storage = prepare_statistics(baseline_path)
        indexed_storage = prepare_statistics(store.path)

        def plans_and_read_samples(path: Path) -> tuple[dict[str, list[str]], dict[str, list[float]]]:
            query_plans: dict[str, list[str]] = {}
            read_samples: dict[str, list[float]] = {}
            with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
                connection.execute("PRAGMA automatic_index=OFF")
                for label, _table, sql, params, _index in queries:
                    query_plans[label] = [
                        str(row[3])
                        for row in connection.execute(f"EXPLAIN QUERY PLAN {sql}", params)
                    ]
                    samples: list[float] = []
                    for _ in range(3):
                        started = time.perf_counter_ns()
                        connection.execute(sql, params).fetchall()
                        samples.append((time.perf_counter_ns() - started) / 1_000_000)
                    read_samples[label] = samples
            return query_plans, read_samples

        baseline_plans, baseline_reads = plans_and_read_samples(baseline_path)
        indexed_plans, indexed_reads = plans_and_read_samples(store.path)
        for label, table, _sql, _params, index_name in queries:
            before = baseline_plans[label]
            after = indexed_plans[label]
            if index_name is not None:
                self.assertTrue(
                    any("SCAN" in detail.upper() and table.upper() in detail.upper() for detail in before),
                    (label, before),
                )
                self.assertTrue(any(index_name in detail for detail in after), (label, after))
            else:
                self.assertTrue(
                    any("SEARCH" in detail.upper() and table.upper() in detail.upper() for detail in before),
                    (label, before),
                )
                self.assertTrue(
                    any("SEARCH" in detail.upper() and table.upper() in detail.upper() for detail in after),
                    (label, after),
                )

        write_tables = (
            "evidence", "payments", "claimed_adjustments", "cases", "actions",
            "action_outbox", "financial_conflicts", "evaluations", "determinations",
        )

        def write_samples(path: Path) -> list[float]:
            samples: list[float] = []
            with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
                for sample in range(3):
                    connection.execute("BEGIN IMMEDIATE")
                    started = time.perf_counter_ns()
                    try:
                        for table in write_tables:
                            columns = owner._TABLE_COLUMNS[table]
                            statement = (
                                f"INSERT INTO {table} ({','.join(columns)}) "
                                f"VALUES ({','.join('?' for _ in columns)})"
                            )
                            first = 10_000 + sample * 10
                            connection.executemany(
                                statement,
                                (
                                    self._private_index_fixture_row(table, ordinal)
                                    for ordinal in range(first, first + 10)
                                ),
                            )
                        connection.execute("COMMIT")
                    except BaseException:
                        if connection.in_transaction:
                            connection.execute("ROLLBACK")
                        raise
                    samples.append((time.perf_counter_ns() - started) / 1_000_000)
            return samples

        baseline_writes = write_samples(baseline_path)
        indexed_writes = write_samples(store.path)
        print(
            "FINANCIAL_PRIVATE_INDEX_PROFILE "
            + json.dumps(
                {
                    "fixture": {
                        "obligations": 20,
                        "rows_per_obligation_per_table": 20,
                        "rows_per_table": rows_per_table,
                    },
                    "storage_bytes": {
                        "without_private_indexes": baseline_storage,
                        "with_private_indexes": indexed_storage,
                        "delta": indexed_storage - baseline_storage,
                    },
                    "query_plan_before": baseline_plans,
                    "query_plan_after": indexed_plans,
                    "read_ms_samples_before": baseline_reads,
                    "read_ms_samples_after": indexed_reads,
                    "insert_transaction_ms_samples_before": baseline_writes,
                    "insert_transaction_ms_samples_after": indexed_writes,
                },
                sort_keys=True,
            )
        )

    def test_history_segment_migration_prevalidates_identity(self) -> None:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=expected.PERIOD_ONE_ID,
            currency=expected.CURRENCY,
        )
        source = FinancialOwner(
            path=self._path("admission-migration-source.sqlite"),
            config=config,
            trusted_authority=self.authority,
            clock=_Clock(initial=1_700_000_000_000),
        )
        source_package = source.export_continuity()
        legacy_path = self._path("admission-migration-legacy.sqlite")
        legacy_path.write_bytes(source.path.read_bytes())
        with closing(sqlite3.connect(legacy_path, isolation_level=None)) as connection:
            for table in ("history_segments", "history_pending", "history_open"):
                connection.execute(f"DROP TABLE {table}")
        legacy_bytes = legacy_path.read_bytes()
        wrong_config = FinancialOwnerConfig(
            state_id="state:wrong-admission-scope",
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=expected.PERIOD_ONE_ID,
            currency=expected.CURRENCY,
        )
        with self.assertRaisesRegex(FinancialIntegrityError, "schema_identity"):
            FinancialOwner(
                path=legacy_path,
                config=wrong_config,
                trusted_authority=self.authority,
                clock=_Clock(initial=1_700_000_000_000),
            )
        self.assertEqual(legacy_path.read_bytes(), legacy_bytes)

        migrated = FinancialOwner(
            path=legacy_path,
            config=config,
            trusted_authority=self.authority,
            clock=_Clock(initial=1_700_000_000_000),
        )
        self.assertEqual(migrated.export_continuity(), source_package)
        self._assert_verified(migrated)

    def test_per_write_cost_tracks_changed_work(self) -> None:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=expected.PERIOD_ONE_ID,
            currency=expected.CURRENCY,
        )
        measurements: list[dict[str, object]] = []

        def receipt_for(index: int) -> ProgramFundingReceipt:
            return ProgramFundingReceipt(
                receipt_id=f"funding-measure:{index:06d}",
                state_id=config.state_id,
                deployment_id=config.deployment_id,
                program_id=config.program_id,
                period_id=config.period_id,
                currency=config.currency,
                source_record_ref=f"state-funding-measure:{index:06d}",
                amount_cents=1,
                event_at_ms=1_700_000_000_000 + index,
            )

        class _RollbackMeasurement(Exception):
            pass

        # IX.3: a commit tracks only its own rows for the next history segment.
        for history_size in (0, 250, 1_000, 3_000):
            store = FinancialOwner(
                path=self._path(f"admission-measure-{history_size}.sqlite"),
                config=config,
                trusted_authority=self.authority,
                clock=_Clock(initial=1_700_100_000_000),
            )
            if history_size:
                with store._write() as connection:
                    for index in range(history_size):
                        status, _value = store._record_program_funding_receipt_in_transaction(
                            connection,
                            receipt_for(index),
                        )
                        self.assertEqual(status, "RECORDED")
            package_before = store.export_continuity()
            full_package_ms: list[float] = []
            incremental_commit_ms: list[float] = []
            first_index = history_size
            for sample in range(3):
                receipt = receipt_for(first_index + sample)
                started = time.perf_counter()
                try:
                    with store._write() as connection:
                        status, _value = store._record_program_funding_receipt_in_transaction(
                            connection,
                            receipt,
                        )
                        self.assertEqual(status, "RECORDED")
                        store._continuity_package_bytes(connection)
                        raise _RollbackMeasurement()
                except _RollbackMeasurement:
                    pass
                full_package_ms.append((time.perf_counter() - started) * 1_000)

                started = time.perf_counter()
                result = store.record_program_funding_receipt(receipt)
                incremental_commit_ms.append((time.perf_counter() - started) * 1_000)
                self.assertEqual(result["status"], "RECORDED")
            measurements.append(
                {
                    "unrelated_funding_records_before_samples": history_size,
                    "package_bytes_before_samples": len(package_before),
                    "full_package_preview_ms": [round(value, 3) for value in full_package_ms],
                    "incremental_commit_ms": [round(value, 3) for value in incremental_commit_ms],
                    "full_package_preview_median_ms": round(statistics.median(full_package_ms), 3),
                    "incremental_commit_median_ms": round(statistics.median(incremental_commit_ms), 3),
                }
            )
            self._assert_verified(store)
        print("PER_WRITE_COST_MEASUREMENT " + json.dumps(measurements, sort_keys=True))

    def test_writes_continue_past_the_continuity_package_cap(self) -> None:
        # Writes no longer re-check the whole-history package: past its 8 MiB cap the package export
        # refuses, while writes and the segmented history export (docs/CORE_REDESIGN.md) continue.
        scope = {
            "state_id": "s" * 128,
            "deployment_id": "d" * 128,
            "program_id": "p" * 128,
            "period_id": "r" * 128,
            "currency": expected.CURRENCY,
        }
        store = FinancialOwner(
            path=self._path("continuity-cap.sqlite"),
            config=FinancialOwnerConfig(**scope),
            trusted_authority=self.authority,
            clock=_Clock(initial=1_700_000_000_000),
            owner_id="o" * 128,
        )

        def receipt_for(index: int) -> ProgramFundingReceipt:
            receipt_prefix = f"funding-cap-receipt:{index:05d}:"
            source_prefix = f"state-payment-record-cap:{index:05d}:"
            return ProgramFundingReceipt(
                receipt_id=receipt_prefix + "r" * (128 - len(receipt_prefix)),
                source_record_ref=source_prefix + "x" * (128 - len(source_prefix)),
                amount_cents=1,
                event_at_ms=1_700_000_000_000,
                **scope,
            )

        index, batch = 0, 256
        while batch:  # a batch whose package would pass the cap rolls back and halves: stop one receipt short
            try:
                with store._write() as connection:
                    for offset in range(batch):
                        self.assertEqual(store._record_program_funding_receipt_in_transaction(connection, receipt_for(index + offset))[0], "RECORDED")
                    store._continuity_package_bytes(connection)
            except FinancialContinuityError as error:
                self.assertEqual(str(error), "continuity_package_size")
                batch //= 2
            else:
                index += batch
        package = store.export_continuity()  # the largest package, one receipt under the cap, restores and verifies
        self.assertLess(owner._MAX_PACKAGE_BYTES - len(package), 8_000)
        verify_continuity_package(package, expected_scope=json.loads(package)["scope"], expected_authority=self.authority)
        restored_package = FinancialMirror(store).restore_test_continuity(package, self._path("continuity-cap-largest.sqlite")).owner.export_continuity()
        self.assertLessEqual(len(restored_package), owner._MAX_PACKAGE_BYTES)
        self.assertEqual(store.record_program_funding_receipt(receipt_for(index))["status"], "RECORDED")
        with self.assertRaisesRegex(FinancialContinuityError, "^continuity_package_size$"):
            store.export_continuity()
        self._assert_verified(store)
        history = self._path("continuity-cap-history")
        manifest = json.loads(store.export_history(history))
        restored = FinancialOwner.restore_continuity(
            history=history,
            recovered_path=self._path("continuity-cap-restored.sqlite"),
            trusted_authority=self.authority,
        )
        self.assertEqual(restored.verify_integrity()["sequence"], manifest["meta"]["sequence"])

    def test_history_stops_at_lean_max_rows_before_commit(self) -> None:
        # Lean's maxRows (Types.lean): a correction at sequence 9,999 commits event 10,000; one at 10,000 is refused.
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        index = 0

        def fill(target: int, owner_store: FinancialOwner) -> None:
            nonlocal index
            while (sequence := owner_store.summary()["sequence"]) < target:
                with owner_store._write() as connection:  # batches keep each open segment under its hard bound
                    for _ in range(min(2_000, target - sequence)):
                        receipt = self._funding_receipt(receipt_id=f"funding:cap:{index:05d}", supersedes_receipt_id=f"funding:cap:{index - 1:05d}" if index else None)
                        self.assertEqual(owner_store._record_program_funding_receipt_in_transaction(connection, receipt)[0], "RECORDED")
                        index += 1

        fill(owner._MAX_ROWS - 1, store)
        full_path = self._path("history-full.sqlite")
        full_path.write_bytes(store.path.read_bytes())
        full = self._make_owner(
            path=full_path,
            clock=_Clock(initial=store.clock.value),
            correction_transition_release=_correction_transition_test_release(workspace=Path(self.temp_dir.name) / "history-full-engine"),
        )
        fill(owner._MAX_ROWS, full)
        before = full.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^history_capacity$"):
            self._reject(full, claim_id)
        self.assertEqual(full.path.read_bytes(), before)
        self._assert_verified(full)
        self.assertEqual(self._reject(store, claim_id)["status"], "CORRECTION_AUTHORIZED")
        self.assertEqual(store.summary()["sequence"], owner._MAX_ROWS)
        self._assert_verified(store)
        index -= 1  # the copy's last receipt is not in this store
        with patch.object(owner, "_MAX_ROWS", owner._MAX_ROWS + 1):  # an Owner past the cap: its 10,001-event export does not restore
            fill(owner._MAX_ROWS, store)
            store.export_history(history := self._path("history-past-cap"))
        with self.assertRaisesRegex(FinancialContinuityError, "^history_export:history:row-cap$"):
            FinancialOwner.restore_continuity(history=history, recovered_path=self._path("history-past-cap.sqlite"), trusted_authority=self.authority)

    def test_revision_past_lean_max_revision_is_refused_before_commit(self) -> None:
        # Each revision step is its own event, so the event cap reaches first; the revision guard is exercised directly.
        store = self._make_owner()
        before = store.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^history_capacity$"):
            with store._write() as connection:
                store._append_event(connection, aggregate_type="CONTROL_PACK", aggregate_id="pack:revision-cap", kind="CONTROL_PACK_PUBLISHED", before_revision=owner._MAX_ROWS, after_revision=owner._MAX_ROWS + 1, payload={}, committed_at_ms=1)
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)

    def test_control_pack_version_past_max_rows_is_refused(self) -> None:
        # The checker reads pack versions up to maxRows.
        self.assertEqual(replace(self._pack(expected.CONTROL_PACK_V1), version=owner._MAX_ROWS).version, owner._MAX_ROWS)
        with self.assertRaisesRegex(FinancialInputError, "^pack_version$"):
            replace(self._pack(expected.CONTROL_PACK_V1), version=owner._MAX_ROWS + 1)

    def test_population_manifest_members_stop_at_max_rows_before_commit(self) -> None:
        # The checker caps each manifest table at maxRows: two 6,000-member versions would hold 12,000 member rows.
        store = self._make_owner()
        store.publish_control_pack(self._pack(expected.CONTROL_PACK_V1))
        members = tuple(f"member:{index:05d}" for index in range(6_000))
        root = self._population_manifest(member_ids=members)
        store.register_population_manifest(root)
        before = store.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^history_capacity$"):
            store.register_population_manifest(self._population_manifest(manifest_id="population-manifest:fixture-2026-01:v2", supersedes=root, member_ids=members))
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)
        # The Owner's cached row counts keep the cap exact: 10,000 member rows are accepted and the next is refused,
        # by the Owner that counted them and by a fresh one.
        full = self._population_manifest(manifest_id="population-manifest:fixture-2026-01:v2", supersedes=root, member_ids=members[:4_000])
        self.assertEqual(store.register_population_manifest(full)["status"], "SUPERSEDED")
        before = store.path.read_bytes()
        for owner_at_cap in (store, self._make_owner(path=store.path, clock=store.clock)):
            with self.subTest(fresh=owner_at_cap is not store), self.assertRaisesRegex(FinancialIntegrityError, "^history_capacity$"):
                owner_at_cap.register_population_manifest(self._population_manifest(manifest_id="population-manifest:fixture-2026-01:v3", supersedes=full, member_ids=members[:1]))
            self.assertEqual(store.path.read_bytes(), before)
        with closing(sqlite3.connect(str(store.path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM population_manifest_members").fetchone()[0], owner._MAX_ROWS)

    def test_program_funding_receipt_process_crash_boundaries(self) -> None:
        receipt = self._funding_receipt()
        initial_clock = receipt.event_at_ms

        precommit_store = self._make_owner(
            path=self._path("funding-precommit.sqlite"),
            clock=_Clock(initial_clock),
        )
        before_precommit_package = precommit_store.export_continuity()
        before_precommit_counts = self._durable_counts(precommit_store.path)
        precommit = self._run_funding_process_boundary(
            store=precommit_store,
            fault="process_precommit",
            clock_value=initial_clock,
        )
        self.assertEqual(precommit.returncode, 73)
        self.assertEqual(
            precommit.stdout,
            "PHASE=BEFORE_FUNDING_RECORD\nPHASE=PRECOMMIT_AFTER_MUTATION\n",
        )
        self.assertEqual(precommit.stderr, "")
        reopened_precommit = self._make_owner(
            path=precommit_store.path,
            clock=_Clock(initial_clock + 1),
        )
        self.assertEqual(reopened_precommit.export_continuity(), before_precommit_package)
        self.assertEqual(self._durable_counts(reopened_precommit.path), before_precommit_counts)
        self.assertEqual(reopened_precommit.program_funding_summary()["historical_receipt_count"], 0)
        self._assert_verified(reopened_precommit)
        committed_retry = reopened_precommit.record_program_funding_receipt(receipt)
        self.assertEqual(committed_retry["status"], "RECORDED")
        committed_precommit_package = reopened_precommit.export_continuity()
        committed_precommit_counts = self._durable_counts(reopened_precommit.path)

        postcommit_store = self._make_owner(
            path=self._path("funding-postcommit.sqlite"),
            clock=_Clock(initial_clock),
        )
        pre_postcommit_package = postcommit_store.export_continuity()
        postcommit = self._run_funding_process_boundary(
            store=postcommit_store,
            fault="process_postcommit",
            clock_value=initial_clock,
        )
        self.assertEqual(postcommit.returncode, 74)
        self.assertEqual(
            postcommit.stdout,
            "PHASE=BEFORE_FUNDING_RECORD\nPHASE=POSTCOMMIT_AFTER_COMMIT\n",
        )
        self.assertEqual(postcommit.stderr, "")
        self.assertNotEqual(pre_postcommit_package, postcommit_store.export_continuity())
        reopened_postcommit = self._make_owner(
            path=postcommit_store.path,
            clock=_Clock(initial_clock + 1),
        )
        self.assertEqual(reopened_postcommit.program_funding_summary()["historical_receipt_count"], 1)
        self._assert_verified(reopened_postcommit)
        committed_postcommit_package = reopened_postcommit.export_continuity()
        committed_postcommit_counts = self._durable_counts(reopened_postcommit.path)
        duplicate = reopened_postcommit.record_program_funding_receipt(receipt)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(reopened_postcommit.export_continuity(), committed_postcommit_package)
        self.assertEqual(self._durable_counts(reopened_postcommit.path), committed_postcommit_counts)
        self.assertNotEqual(committed_precommit_package, before_precommit_package)
        self.assertNotEqual(committed_precommit_counts, before_precommit_counts)
        self._assert_verified(reopened_postcommit)

    def test_first_service_acceptance_journey_and_effective_rule_change(self) -> None:
        # The funding receipt is reported separately; $1,000,000 remains the published-obligation denominator.
        self.assertEqual(len(expected.PROGRAM_ITEMS), 20)
        self.assertEqual(sum(item.owed_cents for item in expected.PROGRAM_ITEMS), expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(len(expected.OTHER_RECIPIENT_PAYMENTS), 19)
        self.assertEqual(sum(item.amount_cents for item in expected.OTHER_RECIPIENT_PAYMENTS), expected.OTHER_TOTAL_CENTS)
        self.assertEqual(
            sum(item.amount_cents for item in expected.OTHER_RECIPIENT_PAYMENTS[:18]),
            expected.PARTIAL_OTHER_RECIPIENT_CASH_CENTS,
        )

        # The journey authorizes a correction, which runs only through the pinned
        # Lean release (Art. V.2); an owner without one fails closed.
        store = self._build_base_for_correction(schema_version=8)
        mirror = FinancialMirror(store)
        funding_fixture = expected.PROGRAM_FUNDING_RECEIPT
        funding_record = self._funding_receipt()
        owner_summary_before_funding = store.summary()
        funding_result = mirror.record_program_funding_receipt(funding_record)
        self.assertEqual(funding_result["status"], "RECORDED")
        funding_summary = mirror.program_funding_summary()
        self.assertEqual(funding_summary["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(funding_summary["current_receipt_count"], 1)
        self.assertEqual(funding_summary["historical_receipt_count"], 1)
        self.assertEqual(funding_summary["confirmation_class"], funding_fixture.confirmation_class)
        self.assertEqual(funding_summary["evidence_status"], funding_fixture.evidence_status)
        self.assertFalse(funding_summary["money_movement_effect"])
        self.assertFalse(funding_summary["recipient_cash_effect"])
        self.assertFalse(funding_summary["payment_authorization_effect"])
        owner_summary_after_funding = store.summary()
        self.assertEqual(owner_summary_after_funding["owed_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(owner_summary_after_funding["received_cash_cents"], 0)
        for field in ("obligation_count", "owed_cents", "received_cash_cents"):
            self.assertEqual(owner_summary_after_funding[field], owner_summary_before_funding[field])
        self.assertEqual(funding_result["program_funding"]["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self._assert_population(store, expected.CASE_01.expected_population_evidence_count)
        self._assert_snapshot(store, expected.H_MISSING)
        for payment in expected.OTHER_RECIPIENT_PAYMENTS[:18]:
            result = self._record_fixture_payment(mirror, payment, payment_id=payment.payment_id)
            self.assertEqual(result["status"], "RECORDED")

        partial = mirror.summary()
        self.assertEqual(partial["obligation_count"], 20)
        self.assertEqual(partial["owed_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(partial["received_cash_cents"], expected.PARTIAL_OTHER_RECIPIENT_CASH_CENTS)
        partial_rows = {row["item_id"]: row for row in mirror.list_obligations(status="ALL", limit=100)["items"]}
        self.assertEqual(partial_rows["item-19"]["received_cash_cents"], 0)
        self.assertEqual(partial_rows[expected.H_ITEM_ID]["received_cash_cents"], 0)
        self.assertEqual(mirror.obligation_detail(expected.H_ITEM_ID)["verification_status"], "MISSING_EVIDENCE")

        final_payment = expected.OTHER_RECIPIENT_PAYMENTS[18]
        final_other = self._record_fixture_payment(mirror, final_payment, payment_id=final_payment.payment_id)
        self.assertEqual(final_other["status"], "RECORDED")
        self.assertEqual(mirror.summary()["received_cash_cents"], expected.OTHER_TOTAL_CENTS)
        self.assertEqual(mirror.obligation_detail(expected.H_ITEM_ID)["verification_status"], "MISSING_EVIDENCE")

        h_cash = expected.H_CASH_EVIDENCE
        h_cash_result = RightRailFinancialAcceptanceTests._record_fixture_payment(mirror, h_cash, payment_id=expected.H_INITIAL_PAYMENT_ID)
        self.assertEqual(h_cash_result["status"], "RECORDED")
        claim = expected.OFFSET_CLAIM_EVIDENCE
        claim_result = store.record_offset_claim(
            item_id=claim.item_id,
            claim_id=expected.H_CLAIM_ID,
            amount_cents=claim.amount_cents or 0,
            evidence_id=claim.evidence_id,
            owner_role="CASE_OWNER",
            deadline_ms=expected.H_DUE_AT_MS,
        )
        self.assertEqual(claim_result["status"], "CLAIMED")
        receipt = mirror.current_evaluation_receipt(expected.H_ITEM_ID)
        self._advance_clock(store, expected.CORRECTION_AUTH_MS - 1)  # recorded when decided
        rejection = mirror.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=expected.H_CLAIM_ID,
            expected_revision=receipt["revision"],
            action_id=expected.ACTION_CORRECTION_ID,
            decision_at_ms=expected.CORRECTION_AUTH_MS,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )
        self.assertEqual(rejection["status"], "CORRECTION_AUTHORIZED")
        self.assertEqual(rejection["action_id"], expected.ACTION_CORRECTION_ID)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        rejected_view = self._first_service_decision_package(mirror)
        self.assertEqual(rejected_view["funding_receipt"]["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(rejected_view["funding_receipt"]["current_receipt_count"], 1)
        self.assertEqual(rejected_view["journey_id"], expected.FIRST_SERVICE_JOURNEY_ID)
        self.assertEqual(rejected_view["program"]["denominator_basis"], "published_obligations")
        self.assertEqual(rejected_view["program"]["owed_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(rejected_view["program"]["population_count"], 1)
        self.assertEqual(rejected_view["program"]["recipient_count"], 20)
        self.assertEqual(rejected_view["program"]["other_recipient_cash_cents"], expected.OTHER_TOTAL_CENTS)
        self.assertEqual(rejected_view["program"]["recipient_cash_cents"], expected.OTHER_TOTAL_CENTS + expected.H_CASH_CENTS)
        h_view = rejected_view["hospital_h"]
        self.assertEqual(h_view["case_id"], expected.H_CASE_ID)
        self.assertEqual(h_view["case_status"], "CORRECTION_REQUIRED")
        self.assertEqual(h_view["owner_role"], "CASE_OWNER")
        self.assertEqual(h_view["deadline_ms"], expected.H_DUE_AT_MS)
        self.assertEqual(h_view["decision"], "OFFSET_REJECTED_CORRECTION_AUTHORIZED")
        self.assertEqual(h_view["decision_amount_cents"], expected.CORRECTION_PAYMENT_CENTS)
        self.assertEqual(h_view["decision_actor_role"], "FINANCE_DECISION")
        self.assertIn(claim.evidence_id, h_view["decision_supporting_evidence_ids"])
        self.assertEqual(h_view["next_action"]["action_id"], expected.ACTION_CORRECTION_ID)
        self.assertEqual(h_view["next_action"]["kind"], "CORRECTION_PAYMENT_REQUEST")
        self.assertEqual(h_view["next_action"]["amount_cents"], expected.CORRECTION_PAYMENT_CENTS)
        self.assertEqual(h_view["next_action"]["dispatch"], "SYNTHETIC_RECORD_ONLY")
        self.assertEqual(
            h_view["completion_conditions"],
            {"amount_satisfied": True, "delivery_acknowledged_or_not_required": True, "reporting_complete": True},
        )

        sequence_before_ack = store.summary()["sequence"]
        acknowledgment = mirror.acknowledge_action(expected.ACTION_CORRECTION_ID, expected.H_ACKNOWLEDGMENT_REF)
        self.assertEqual(acknowledgment["status"], "ACKNOWLEDGED")
        self.assertEqual(store.summary()["sequence"], sequence_before_ack + 1)
        self._assert_snapshot(store, expected.H_ACKNOWLEDGED)
        acknowledged_view = self._first_service_decision_package(mirror)
        self.assertEqual(acknowledged_view["hospital_h"]["received_cash_cents"], expected.H_CASH_CENTS)
        self.assertEqual(acknowledged_view["hospital_h"]["shortfall_cents"], expected.CORRECTION_PAYMENT_CENTS)
        self.assertEqual(
            acknowledged_view["hospital_h"]["next_action"]["status"],
            "ACKNOWLEDGED",
        )
        self.assertEqual(
            acknowledged_view["hospital_h"]["completion_references"]["acknowledged_action_ids"],
            [expected.ACTION_CORRECTION_ID],
        )
        source_bytes_before_restore = store.path.read_bytes()
        source_package = mirror.export_continuity()
        source_package_result = verify_continuity_package(
            source_package,
            expected_scope={
                "state_id": expected.STATE_ID,
                "deployment_id": expected.DEPLOYMENT_ID,
                "program_id": expected.PROGRAM_ID,
                "period_id": expected.PERIOD_ONE_ID,
                "currency": expected.CURRENCY,
            },
            expected_authority=self.authority,
        )
        self.assertEqual(source_package_result["schema"], "RR/FINANCIAL/CONTINUITY/v8")
        self.assertEqual(source_package_result["program_funding"]["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        source_package_view = mirror.validate_owner_continuity_package(source_package)
        self.assertEqual(source_package_view["version"], 8)
        self.assertEqual(source_package_view["program_funding"]["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertFalse(source_package_view["dispatch_enabled"])
        self.assertFalse(source_package_view["egress_enabled"])

        test_mirror = mirror.restore_test_continuity(source_package, self._path("first-service-test-restore.sqlite"))
        test_store = test_mirror.owner
        self.assertEqual(test_store.mode, "TEST")
        self.assertEqual(test_store.owner_id, owner._TEST_OWNER_ID)
        self.assertFalse(test_mirror.summary()["dispatch_enabled"])
        self.assertFalse(test_mirror.summary()["egress_enabled"])
        self.assertEqual(test_mirror.verify_integrity()["integrity"], "VERIFIED")
        self._assert_snapshot(test_store, expected.H_ACKNOWLEDGED)
        self.assertEqual(self._first_service_decision_package(test_mirror), acknowledged_view)
        self.assertEqual(test_mirror.program_funding_summary(), funding_summary)
        funding_retry_after_restore = test_mirror.record_program_funding_receipt(funding_record)
        self.assertEqual(funding_retry_after_restore["status"], "DUPLICATE")
        self.assertEqual(test_mirror.program_funding_summary(), funding_summary)
        self._assert_verified(test_store, restore_source_package=source_package)
        self.assertEqual(store.path.read_bytes(), source_bytes_before_restore)

        sequence_before_retry = test_store.summary()["sequence"]
        exact_retry = test_mirror.retry_action(
            expected.ACTION_CORRECTION_ID,
            payload=test_store.action_payload(expected.ACTION_CORRECTION_ID)["payload"],
        )
        self.assertEqual(exact_retry["status"], "DUPLICATE")
        self.assertEqual(test_store.summary()["sequence"], sequence_before_retry)
        changed_payload = dict(test_store.action_payload(expected.ACTION_CORRECTION_ID)["payload"])
        changed_payload["amount_cents"] = expected.CORRECTION_PAYMENT_CENTS + 1
        with self.assertRaisesRegex(FinancialConflictError, expected.ACTION_PAYLOAD_REJECTION.expected_error):
            test_mirror.retry_action(expected.ACTION_CORRECTION_ID, payload=changed_payload)
        self.assertEqual(test_store.summary()["sequence"], sequence_before_retry)
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            test_store.dispatch_outbox()

        late_payment = expected.P2_PAYMENT_EVIDENCE
        self._advance_clock(test_store, late_payment.event_at_ms)
        late_result = RightRailFinancialAcceptanceTests._record_fixture_payment(test_mirror, late_payment, payment_id="payment:h:p2")
        self.assertEqual(late_result["status"], "RECORDED")
        self._assert_snapshot(test_store, expected.H_P2_RECEIVED_LATE)

        duplicate = expected.P2_CONFIRMATION_EVIDENCE
        cash_before_duplicate = test_store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"]
        duplicate_result = RightRailFinancialAcceptanceTests._record_fixture_payment(test_mirror, duplicate, payment_id="payment:h:p2-confirmation")
        self.assertEqual(duplicate_result["status"], "DUPLICATE")
        self.assertEqual(test_store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"], cash_before_duplicate)

        conflict = expected.P2_CONFLICT_EVIDENCE
        conflict_result = RightRailFinancialAcceptanceTests._record_fixture_payment(test_mirror, conflict, payment_id="payment:h:p2-conflict")
        self.assertEqual(conflict_result["status"], "CONFLICT")
        self.assertEqual(test_store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"], cash_before_duplicate)
        self.assertEqual(test_store.obligation_detail(expected.H_ITEM_ID)["timely"], 0)
        self.assertEqual(test_store.obligation_detail(expected.H_ITEM_ID)["reporting_complete"], 0)

        original_report = expected.REPORT_ORIGINAL_EVIDENCE
        self._advance_clock(test_store, original_report.event_at_ms)
        report_result = test_mirror.record_reporting_evidence(
            item_id=original_report.item_id,
            report_id="report:h:v1",
            evidence_id=original_report.evidence_id,
            event_at_ms=original_report.event_at_ms,
        )
        self.assertEqual(report_result["status"], "RECORDED")
        corrected_report = expected.REPORT_CORRECTION_EVIDENCE
        self._advance_clock(test_store, corrected_report.event_at_ms)
        correction_result = test_mirror.record_reporting_correction(
            item_id=corrected_report.item_id,
            report_id="report:h:v2",
            evidence_id=corrected_report.evidence_id,
            event_at_ms=corrected_report.event_at_ms,
            supersedes=original_report.evidence_id,
        )
        self.assertEqual(correction_result["status"], "RECORDED")
        self._assert_snapshot(test_store, expected.H_P2_CONFLICT_VISIBLE)
        final_view = self._first_service_decision_package(test_mirror)
        final_h = final_view["hospital_h"]
        self.assertEqual(final_view["program"]["recipient_cash_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(final_view["program"]["other_recipient_cash_cents"], expected.OTHER_TOTAL_CENTS)
        self.assertEqual(final_h["received_cash_cents"], expected.H_OWED_CENTS)
        self.assertFalse(final_h["timely"])
        self.assertTrue(final_h["reporting_complete"])
        self.assertEqual(final_h["case_status"], "RESOLVED")
        self.assertEqual(final_h["completion_references"]["acknowledged_action_ids"], [expected.ACTION_CORRECTION_ID])
        self.assertEqual(
            final_h["completion_references"]["reporting_evidence_ids"],
            sorted((original_report.evidence_id, corrected_report.evidence_id)),
        )
        self.assertEqual(
            {row["payment_id"]: row["amount_cents"] for row in final_h["completion_references"]["active_payments"]},
            {expected.H_INITIAL_PAYMENT_ID: expected.H_CASH_CENTS, "payment:h:p2": expected.CORRECTION_PAYMENT_CENTS},
        )
        self.assertEqual(final_h["deadline_ms"], expected.H_DUE_AT_MS)
        self.assertEqual(final_h["owner_role"], "CASE_OWNER")
        self.assertEqual(final_view["funding_receipt"]["reported_funding_cents"], expected.PROGRAM_TOTAL_CENTS)
        self.assertEqual(final_view["funding_receipt"]["current_receipt_count"], 1)
        self.assertEqual(final_view["funding_receipt"]["historical_receipt_count"], 1)
        self.assertFalse(final_view["nonactivation"]["production_usable"])
        self.assertFalse(final_view["nonactivation"]["activation"])
        self.assertIsNone(final_view["nonactivation"]["proof_suite_id"])
        self.assertFalse(final_view["nonactivation"]["dispatch_enabled"])
        self.assertFalse(final_view["nonactivation"]["egress_enabled"])
        self.assertEqual(store.path.read_bytes(), source_bytes_before_restore)

        final_test_package = test_mirror.export_continuity()
        self._assert_verified(test_store, restore_source_package=source_package)
        self._assert_verified(test_store, current_snapshot_package=final_test_package)

        v1_history_before_rule_change = tuple(
            (
                row["evaluation_id"],
                row["revision"],
                row["control_pack_id"],
                row["control_pack_version"],
                row["control_pack_digest"],
                row["result_digest"],
            )
            for row in store.obligation_detail(expected.H_ITEM_ID)["evaluations"]
        )
        v1_receipt_before_rule_change = mirror.current_evaluation_receipt(expected.H_ITEM_ID)
        self.assertEqual(v1_receipt_before_rule_change["control_pack"]["pack_id"], expected.CONTROL_PACK_V1.pack_id)
        self.assertEqual(v1_receipt_before_rule_change["control_pack"]["version"], 1)
        self.assertEqual(v1_receipt_before_rule_change["rule_version"], 1)
        self.assertEqual(expected.CONTROL_PACK_V1.effective_end_ms, expected.CONTROL_PACK_V2.effective_start_ms)

        period_two = self._build_base(period_id=expected.PERIOD_TWO_ID, population_id=expected.POPULATION_TWO_ID)
        period_two_mirror = FinancialMirror(period_two)
        v2_receipt = period_two_mirror.current_evaluation_receipt(expected.H_ITEM_ID)
        self.assertEqual(v2_receipt["control_pack"]["pack_id"], expected.CONTROL_PACK_V2.pack_id)
        self.assertEqual(v2_receipt["control_pack"]["version"], 2)
        self.assertEqual(v2_receipt["rule_version"], 2)
        self.assertEqual(v2_receipt["scope"]["period_id"], expected.PERIOD_TWO_ID)
        self.assertEqual(mirror.current_evaluation_receipt(expected.H_ITEM_ID), v1_receipt_before_rule_change)
        v1_history_after_rule_change = tuple(
            (
                row["evaluation_id"],
                row["revision"],
                row["control_pack_id"],
                row["control_pack_version"],
                row["control_pack_digest"],
                row["result_digest"],
            )
            for row in store.obligation_detail(expected.H_ITEM_ID)["evaluations"]
        )
        self.assertEqual(v1_history_after_rule_change, v1_history_before_rule_change)
        self.assertTrue(
            all(row["control_pack_id"] == expected.CONTROL_PACK_V1.pack_id for row in store.obligation_detail(expected.H_ITEM_ID)["evaluations"])
        )
        self._assert_verified(store)
        self._assert_verified(period_two)

    def test_case_12_scope_oversize_and_egress_boundaries(self) -> None:
        self.assertEqual(expected.CASE_12.number, 12)
        store = self._build_base()
        before = store.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "period_scope"):
            store.publish_control_pack(self._pack(expected.CONTROL_PACK_V2))
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_package_size"):
            FinancialOwner.validate_continuity_package(b"x" * expected.BOUNDARY_EXPECTATIONS.oversized_input_bytes)
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            store.dispatch_outbox()
        self.assertEqual(store.path.read_bytes(), before)
        package = store.export_continuity()
        self.assertNotIn(expected.BOUNDARY_EXPECTATIONS.synthetic_canary.encode("ascii"), package)
        self._assert_verified(store)

    def test_continuity_restore_rejects_header_tamper_with_recomputed_package_digest(self) -> None:
        store = self._build_base()
        package = json.loads(store.export_continuity().decode("ascii"))
        completion = next(
            row for row in package["tables"]["financial_events"]
            if row["kind"] == "POPULATION_SOURCE_COMPLETED"
        )
        completion["after_revision"] += 1
        body = dict(package)
        del body["package_digest"]
        # Recompute the digest under the (only restorable) v8 package domain, so the digest
        # check passes and the restore integrity check must reject.
        self.assertEqual(package["version"], 8)
        package["package_digest"] = owner._hex(owner._digest(owner._CONTINUITY_DOMAIN, owner._canonical(body)))
        tampered = owner._canonical(package)
        destination = self._path("tampered-continuity.sqlite")
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_restore_integrity"):
            FinancialOwner.restore_continuity(
                package_bytes=tampered,
                recovered_path=destination,
                trusted_authority=self.authority,
                clock=_Clock(),
            )
        self.assertFalse(destination.exists())
        self.assertTrue(store.path.exists())
        self.assertEqual(list(destination.parent.glob(f".{destination.name}.restore-*")), [])

    def test_continuity_restore_destination_race_preserves_foreign_database_and_sidecars(self) -> None:
        self._assert_restore_race_preserves_foreign_files(after_link=False)

    def test_continuity_restore_post_link_replacement_preserves_foreign_database_and_sidecars(self) -> None:
        self._assert_restore_race_preserves_foreign_files(after_link=True)

    def _assert_restore_race_preserves_foreign_files(self, *, after_link: bool) -> None:
        store = self._build_base()
        package = store.export_continuity()
        destination = self._path(f"raced-continuity-{after_link}.sqlite")
        sidecars = (Path(f"{destination}-wal"), Path(f"{destination}-shm"))
        foreign_database, foreign_wal, foreign_shm = b"foreign-database", b"foreign-wal", b"foreign-shm"
        original_link = owner.os.link

        def race_at_link(source: str | os.PathLike[str], target: str | os.PathLike[str], *args: object, **kwargs: object) -> None:
            if after_link:
                original_link(source, target, *args, **kwargs)
                Path(target).unlink()
            destination.write_bytes(foreign_database)
            sidecars[0].write_bytes(foreign_wal)
            sidecars[1].write_bytes(foreign_shm)
            if not after_link:
                original_link(source, target, *args, **kwargs)

        with patch.object(owner.os, "link", race_at_link):
            with self.assertRaisesRegex(FinancialContinuityError, "continuity_destination"):
                FinancialOwner.restore_continuity(
                    package_bytes=package,
                    recovered_path=destination,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
        self.assertEqual(destination.read_bytes(), foreign_database)
        self.assertEqual(sidecars[0].read_bytes(), foreign_wal)
        self.assertEqual(sidecars[1].read_bytes(), foreign_shm)
        self.assertEqual(list(destination.parent.glob(f".{destination.name}.restore-*")), [])
        self._assert_verified(store)

    def test_control_pack_policy_and_wildcard_periods_fail_closed(self) -> None:
        with self.assertRaisesRegex(FinancialInputError, "period_scope_required"):
            FinancialOwnerConfig(
                state_id=expected.STATE_ID,
                deployment_id=expected.DEPLOYMENT_ID,
                program_id=expected.PROGRAM_ID,
                period_id="PROGRAM",
                currency=expected.CURRENCY,
            )
        store = self._make_owner()
        unsupported_rule = replace(self._pack(expected.CONTROL_PACK_V1), calculation_rule_id="calculation:unsupported:v1")
        with self.assertRaisesRegex(FinancialIntegrityError, "control_pack_policy_unsupported"):
            store.publish_control_pack(unsupported_rule)
        missing_receiver = replace(
            self._pack(expected.CONTROL_PACK_V1),
            authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR"),
        )
        with self.assertRaisesRegex(FinancialIntegrityError, "control_pack_roles_unsupported"):
            store.publish_control_pack(missing_receiver)

    def test_population_import_requires_manifest_without_mutation(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        before_package = store.export_continuity()
        before_counts = self._durable_counts(store.path)
        population_id = "population:fixture:no-manifest"
        with self.assertRaisesRegex(FinancialInputError, "population_manifest_required"):
            store.stage_population(
                population_id=population_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=len(expected.PROGRAM_ITEMS),
                items=self._items(population_id),
            )
        self.assertEqual(store.export_continuity(), before_package)
        self.assertEqual(self._durable_counts(store.path), before_counts)
        self.assertEqual(store.summary()["obligation_count"], 0)
        self._assert_verified(store)

    def test_population_same_count_substitution_stays_incomplete_and_unpublishable(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture:substitution"
        manifest = self._population_manifest(
            manifest_id="population-manifest:fixture:substitution:v1",
        )
        store.register_population_manifest(manifest)
        expected_items = self._items(population_id)
        substituted_items = (*expected_items[:-1], replace(expected_items[-1], item_id="item-z"))
        with self.assertRaisesRegex(FinancialIntegrityError, "population_manifest_extra_member"):
            store.stage_population(
                population_id=population_id,
                manifest_id=manifest.manifest_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=len(expected.PROGRAM_ITEMS),
                items=substituted_items,
                chunk_size=len(expected_items) - 1,
            )
        status = store.population_status(population_id)
        self.assertEqual(status["imported_count"], len(expected_items) - 1)
        self.assertEqual(status["expected_count"], len(expected_items))
        self.assertEqual(status["manifest_status"], "CURRENT")
        self.assertEqual(status["completeness"], "INCOMPLETE")
        self.assertFalse(status["source_complete"])
        before_validation = store.export_continuity()
        with self.assertRaisesRegex(FinancialIntegrityError, "population_source_incomplete"):
            store.validate_population(population_id)
        self.assertEqual(store.export_continuity(), before_validation)
        self.assertEqual(store.summary()["obligation_count"], 0)
        self._assert_verified(store)

    def test_exact_roster_completeness_is_not_source_authentication(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture:caller-asserted-roster"
        items = self._items(population_id)
        unrelated_source_bytes = b"source bytes not supplied to the owner"
        asserted_source_digest = bytes.fromhex("A5" * 64)
        self.assertNotEqual(
            hashlib.sha3_512(unrelated_source_bytes).digest(),
            asserted_source_digest,
        )
        manifest = replace(
            self._population_manifest(
                manifest_id="population-manifest:fixture:caller-asserted-roster:v1",
                member_ids=tuple(sorted(item.item_id for item in items)),
            ),
            source_id="source:caller-asserted",
            source_version="caller-asserted-v1",
            source_digest=asserted_source_digest,
        )
        store.register_population_manifest(manifest)
        # Exactness here is only relative to this caller-supplied roster; neither
        # the owner nor checker receives source bytes or an external attestation.
        store.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=len(items),
            items=items,
            chunk_size=len(items),
        )
        status = store.population_status(population_id)
        self.assertEqual(status["completeness"], "EXACT")
        self.assertTrue(status["source_complete"])
        with closing(sqlite3.connect(str(store.path))) as connection:
            row = connection.execute(
                "SELECT source_digest FROM population_manifests WHERE manifest_id=?",
                (manifest.manifest_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(bytes(row[0]), asserted_source_digest)
        self.assertNotEqual(
            bytes(row[0]),
            hashlib.sha3_512(unrelated_source_bytes).digest(),
        )
        self._assert_verified(store)

    def test_population_manifest_retry_authorization_supersession_and_binding(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        root = self._population_manifest()
        self.assertEqual(store.register_population_manifest(root)["status"], "REGISTERED")
        registered_package = store.export_continuity()
        self.assertEqual(store.register_population_manifest(root)["status"], "DUPLICATE")
        self.assertEqual(store.export_continuity(), registered_package)

        conflicting_identity = replace(root, source_digest=bytes.fromhex("FF" * 64))
        with self.assertRaisesRegex(FinancialConflictError, "population_manifest_identity_conflict"):
            store.register_population_manifest(conflicting_identity)
        unauthorized = self._population_manifest(
            manifest_id="population-manifest:fixture:unauthorized:v1",
            source_owner_id="source-owner:fixture:unauthorized",
            approved_by="synthetic-reporter",
        )
        with self.assertRaisesRegex(FinancialAuthorityError, "authority_actor_not_authorized"):
            store.register_population_manifest(unauthorized)
        wrong_parent = replace(
            self._population_manifest(
                manifest_id="population-manifest:fixture:wrong-parent:v2",
                supersedes=root,
            ),
            supersedes_digest=bytes.fromhex("00" * 64),
        )
        with self.assertRaisesRegex(FinancialConflictError, "population_manifest_supersession_conflict"):
            store.register_population_manifest(wrong_parent)
        self.assertEqual(store.export_continuity(), registered_package)

        population_id = "population:fixture:superseded-before-publish"
        store.stage_population(
            population_id=population_id,
            manifest_id=root.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=len(root.member_ids),
            items=self._items(population_id),
            chunk_size=5,
        )
        store.validate_population(population_id)
        child = self._population_manifest(
            manifest_id="population-manifest:fixture-2026-01:v2",
            supersedes=root,
        )
        self.assertEqual(store.register_population_manifest(child)["status"], "SUPERSEDED")
        stale = store.population_status(population_id)
        self.assertEqual(stale["manifest_status"], "SUPERSEDED")
        self.assertEqual(stale["completeness"], "STALE")
        self.assertFalse(stale["source_complete"])
        stale_package = store.export_continuity()
        with self.assertRaisesRegex(FinancialConflictError, "population_manifest_binding_conflict"):
            store.stage_population(
                population_id=population_id,
                manifest_id=child.manifest_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=len(child.member_ids),
                items=self._items(population_id),
            )
        with self.assertRaisesRegex(FinancialConflictError, "population_manifest_stale"):
            store.publish_population(population_id)
        self.assertEqual(store.export_continuity(), stale_package)
        self.assertEqual(store.summary()["obligation_count"], 0)
        self._assert_verified(store)

        published_store = self._build_base()
        published_root = self._population_manifest()
        after_publish = self._population_manifest(
            manifest_id="population-manifest:fixture-2026-01:after-publish:v2",
            supersedes=published_root,
        )
        before_rejected_supersession = published_store.export_continuity()
        with self.assertRaisesRegex(FinancialConflictError, "population_manifest_supersede_after_publish"):
            published_store.register_population_manifest(after_publish)
        self.assertEqual(published_store.export_continuity(), before_rejected_supersession)
        self._assert_verified(published_store)

    def test_concurrent_population_manifest_supersession_has_one_winner(self) -> None:
        store = self._make_owner()
        store.publish_control_pack(self._pack(expected.CONTROL_PACK_V1))
        root = self._population_manifest()
        store.register_population_manifest(root)
        children = (
            self._population_manifest(
                manifest_id="population-manifest:fixture:race-a:v2",
                supersedes=root,
            ),
            self._population_manifest(
                manifest_id="population-manifest:fixture:race-b:v2",
                supersedes=root,
            ),
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[tuple[type[BaseException], str]] = []

        def register(manifest: PopulationManifest) -> None:
            try:
                barrier.wait(timeout=5)
                outcomes.append(str(store.register_population_manifest(manifest)["status"]))
            except BaseException as error:
                errors.append((type(error), str(error)))

        threads = [threading.Thread(target=register, args=(manifest,)) for manifest in children]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(outcomes, ["SUPERSEDED"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], FinancialConflictError)
        self.assertIn("population_manifest_supersession_conflict", errors[0][1])
        with store._read_snapshot() as connection:
            manifests = int(connection.execute("SELECT COUNT(*) FROM population_manifests").fetchone()[0])
            events = int(connection.execute("SELECT COUNT(*) FROM financial_events WHERE aggregate_type='POPULATION_MANIFEST'").fetchone()[0])
            heads = int(connection.execute("SELECT COUNT(*) FROM population_manifest_heads").fetchone()[0])
        self.assertEqual((manifests, events, heads), (2, 2, 1))
        self._assert_verified(store)

    def test_continuity_v7_reconstructs_manifest_and_rejects_tampered_rows(self) -> None:
        store = self._build_base()
        package_bytes = store.export_continuity()
        package = json.loads(package_bytes.decode("ascii"))
        verified = verify_continuity_package(
            package_bytes,
            expected_scope=package["scope"],
            expected_authority=self.authority,
            expected_schema_version=8,
        )
        self.assertEqual(verified["version"], 8)
        self.assertEqual(verified["table_counts"]["population_manifests"], 1)
        self.assertEqual(verified["table_counts"]["population_manifest_members"], len(expected.POPULATION_MANIFEST_MEMBER_IDS))
        self.assertEqual(verified["table_counts"]["population_manifest_bindings"], 1)

        def tamper_and_rehash(mutator) -> bytes:
            altered = json.loads(package_bytes.decode("ascii"))
            mutator(altered)
            body = dict(altered)
            del body["package_digest"]
            altered["package_digest"] = continuity_package_digest(body)
            return _independent_canonical(altered)

        tampered_member = tamper_and_rehash(
            lambda value: value["tables"]["population_manifest_members"][0].__setitem__("member_id", "item-z")
        )
        tampered_binding = tamper_and_rehash(
            lambda value: value["tables"]["population_manifest_bindings"][0].__setitem__("manifest_digest", "00" * 64)
        )
        tampered_head = tamper_and_rehash(
            lambda value: value["tables"]["population_manifest_heads"][0].__setitem__("manifest_id", "population-manifest:not-the-head")
        )
        tampered_event = tamper_and_rehash(
            lambda value: next(
                row for row in value["tables"]["financial_events"]
                if row["aggregate_type"] == "POPULATION_MANIFEST"
            ).__setitem__("payload_json", "{}")
        )
        for altered in (tampered_member, tampered_binding, tampered_head, tampered_event):
            with self.subTest(package="tampered_manifest_continuity"):
                with self.assertRaises(IndependentFinancialError):
                    verify_continuity_package(
                        altered,
                        expected_scope=package["scope"],
                        expected_authority=self.authority,
                        expected_schema_version=8,
                    )
        self._assert_verified(store)

    def test_population_staging_rejects_imported_count_projection_drift(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture:imported-count-drift"
        items = self._items(population_id)
        manifest = self._population_manifest(
            manifest_id="population-manifest:fixture:imported-count-drift:v1",
            member_ids=tuple(sorted(item.item_id for item in items[:2])),
        )
        store.register_population_manifest(manifest)
        store.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=2,
            items=items[:1],
            chunk_size=1,
        )
        with closing(sqlite3.connect(str(store.path))) as connection:
            connection.execute(
                "UPDATE population_imports SET imported_count=0 WHERE population_id=?",
                (population_id,),
            )
            connection.commit()
        before = store.export_continuity()
        with self.assertRaisesRegex(FinancialIntegrityError, "population_manifest_imported_count"):
            store.stage_population(
                population_id=population_id,
                manifest_id=manifest.manifest_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=2,
                items=items[1:2],
                chunk_size=1,
            )
        self.assertEqual(store.export_continuity(), before)
        with store._read_snapshot() as connection:
            imported = connection.execute(
                "SELECT imported_count,source_complete FROM population_imports WHERE population_id=?",
                (population_id,),
            ).fetchone()
            item_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM population_items WHERE population_id=?",
                    (population_id,),
                ).fetchone()[0]
            )
            events = [
                str(row[0])
                for row in connection.execute(
                    "SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence",
                    (population_id,),
                )
            ]
        assert imported is not None
        self.assertEqual(tuple(imported), (0, 0))
        self.assertEqual(item_count, 1)
        self.assertEqual(events, ["POPULATION_IMPORT_OPENED", "POPULATION_STAGED"])
        self.assertEqual(store.summary()["obligation_count"], 0)

    def test_population_count_backpressure_preserves_prior_chunks(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture-overflow"
        items = self._items(population_id)
        manifest = self._population_manifest(
            manifest_id="population-manifest:fixture-overflow:v1",
            member_ids=tuple(sorted(item.item_id for item in items[:3])),
        )
        store.register_population_manifest(manifest)
        with self.assertRaisesRegex(FinancialIntegrityError, "population_manifest_extra_member"):
            store.stage_population(
                population_id=population_id,
                manifest_id=manifest.manifest_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=3,
                items=items[:4],
                chunk_size=3,
            )
        with store._read_snapshot() as connection:
            imported = connection.execute(
                "SELECT imported_count,status,source_complete FROM population_imports WHERE population_id=?",
                (population_id,),
            ).fetchone()
            item_count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
        assert imported is not None
        self.assertEqual(tuple(imported), (3, "STAGED", 0))
        self.assertEqual(item_count, 3)
        with self.assertRaisesRegex(FinancialIntegrityError, "population_source_incomplete"):
            store.validate_population(population_id)
        self._assert_verified(store)
        with store._read_snapshot() as connection:
            before_resume_events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        resumed = store.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=3,
            items=items[:3],
            chunk_size=3,
        )
        self.assertTrue(resumed["source_complete"])
        with store._read_snapshot() as connection:
            after_resume_events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        self.assertEqual(before_resume_events, ["POPULATION_IMPORT_OPENED", "POPULATION_STAGED"])
        self.assertEqual(
            after_resume_events,
            ["POPULATION_IMPORT_OPENED", "POPULATION_STAGED", "POPULATION_SOURCE_COMPLETED"],
        )
        validated = store.validate_population(population_id)
        self.assertEqual(validated["status"], "VALIDATED")
        self.assertEqual(validated["validated_count"], 3)
        published = store.publish_population(population_id)
        self.assertEqual(published["item_count"], 3)
        self._assert_verified(store)

    def test_population_duplicate_member_is_rejected_before_source_completion(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture-duplicate-input-limit"
        item = self._items(population_id)[0]
        manifest = self._population_manifest(
            manifest_id="population-manifest:fixture-duplicate-input-limit:v1",
            member_ids=(item.item_id,),
        )
        store.register_population_manifest(manifest)
        with self.assertRaisesRegex(FinancialIntegrityError, "population_manifest_duplicate_member"):
            store.stage_population(
                population_id=population_id,
                manifest_id=manifest.manifest_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=1,
                items=(item,) * 258,
                chunk_size=1,
            )
        with store._read_snapshot() as connection:
            imported = connection.execute(
                "SELECT imported_count,source_complete FROM population_imports WHERE population_id=?",
                (population_id,),
            ).fetchone()
            events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        assert imported is not None
        self.assertEqual(tuple(imported), (1, 0))
        self.assertEqual(events, ["POPULATION_IMPORT_OPENED", "POPULATION_STAGED"])
        self.assertEqual(store.summary()["obligation_count"], 0)
        self._assert_verified(store)

    def test_reporting_correction_requires_bound_prior_report(self) -> None:
        store = self._build_base()
        before = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        self._advance_clock(store, expected.REPORT_CORRECTION_MS)
        with self.assertRaisesRegex(FinancialIntegrityError, "report_supersedes_missing"):
            store.record_reporting_correction(
                item_id=expected.H_ITEM_ID,
                report_id="report:missing-target",
                evidence_id="evidence:report:missing-target",
                expected_revision=before,
                event_at_ms=expected.REPORT_CORRECTION_MS,
                supersedes="evidence:report:not-present",
            )
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["revision"], before)
        self._advance_clock(store, expected.P2_EVENT_MS)
        store.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:original-bound",
            evidence_id="evidence:report:original-bound",
            event_at_ms=expected.P2_EVENT_MS,
        )
        h_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        item_revision = store.obligation_detail("item-01")["revision"]
        with self.assertRaisesRegex(FinancialIntegrityError, "report_supersedes_item"):
            store.record_reporting_correction(
                item_id="item-01",
                report_id="report:cross-item",
                evidence_id="evidence:report:cross-item",
                expected_revision=item_revision,
                event_at_ms=expected.REPORT_CORRECTION_MS,
                supersedes="evidence:report:original-bound",
            )
        with self.assertRaisesRegex(FinancialIntegrityError, "report_supersedes_chronology"):
            store.record_reporting_correction(
                item_id=expected.H_ITEM_ID,
                report_id="report:too-early",
                evidence_id="evidence:report:too-early",
                expected_revision=h_revision,
                event_at_ms=expected.P2_EVENT_MS,
                supersedes="evidence:report:original-bound",
            )
        self._advance_clock(store, expected.REPORT_CORRECTION_MS)
        store.record_payment_evidence(
            item_id=expected.H_ITEM_ID,
            payment_id="payment:report-lineage-incompatible",
            common_origin_id="origin:report-lineage-incompatible",
            amount_cents=1,
            evidence_id="evidence:payment:report-lineage-incompatible",
            event_at_ms=expected.REPORT_CORRECTION_MS,
        )
        h_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        with self.assertRaisesRegex(FinancialIntegrityError, "report_supersedes_kind"):
            store.record_reporting_correction(
                item_id=expected.H_ITEM_ID,
                report_id="report:incompatible-target",
                evidence_id="evidence:report:incompatible-target",
                expected_revision=h_revision,
                event_at_ms=expected.REPORT_CORRECTION_MS + 1,
                supersedes="evidence:payment:report-lineage-incompatible",
            )
        self._assert_verified(store)

    def test_reporting_correction_retry_is_identity_stable_and_side_effect_free(self) -> None:
        store = self._build_base()
        self._advance_clock(store, expected.P2_EVENT_MS)
        store.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-original",
            evidence_id="evidence:report:retry-original",
            event_at_ms=expected.P2_EVENT_MS,
        )
        original_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        first = store.record_reporting_correction(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-correction",
            evidence_id="evidence:report:retry-correction",
            expected_revision=original_revision,
            supersedes="evidence:report:retry-original",
        )
        self.assertEqual(first["status"], "RECORDED")
        before_detail = store.obligation_detail(expected.H_ITEM_ID)
        before_summary = store.summary()
        correction_row = next(row for row in before_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-correction")
        before_digest = correction_row["record_digest"]
        before_event_at = correction_row["event_at_ms"]
        before_event_count = before_summary["sequence"]
        before_evaluation_count = len(before_detail["evaluations"])
        store.close()
        reopened = self._make_owner(path=store.path)
        retry = reopened.record_reporting_correction(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-correction",
            evidence_id="evidence:report:retry-correction",
            expected_revision=original_revision,
            supersedes="evidence:report:retry-original",
        )
        self.assertEqual(retry["status"], "DUPLICATE")
        after_detail = reopened.obligation_detail(expected.H_ITEM_ID)
        after_summary = reopened.summary()
        after_row = next(row for row in after_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-correction")
        self.assertEqual(after_row["record_digest"], before_digest)
        self.assertEqual(after_row["event_at_ms"], before_event_at)
        self.assertEqual(after_summary["sequence"], before_event_count)
        self.assertEqual(len(after_detail["evaluations"]), before_evaluation_count)
        self.assertEqual(after_detail["revision"], before_detail["revision"])
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            reopened.record_reporting_correction(
                item_id=expected.H_ITEM_ID,
                report_id="report:retry-correction",
                evidence_id="evidence:report:retry-correction",
                expected_revision=original_revision,
                event_at_ms=before_event_at + 1,
                supersedes="evidence:report:retry-original",
            )
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            reopened.record_reporting_correction(
                item_id=expected.H_ITEM_ID,
                report_id="report:retry-correction-rebound",
                evidence_id="evidence:report:retry-correction",
                expected_revision=original_revision,
                event_at_ms=expected.REPORT_CORRECTION_MS,
                supersedes="evidence:report:retry-original",
            )
        self.assertEqual(reopened.summary()["sequence"], before_event_count)
        self._assert_verified(reopened)

    def test_reporting_evidence_default_retry_is_identity_stable_after_reopen(self) -> None:
        store = self._build_base()
        original_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        request = dict(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-default-original",
            evidence_id="evidence:report:retry-default-original",
            expected_revision=original_revision,
        )
        first = store.record_reporting_evidence(**request)
        self.assertEqual(first["status"], "RECORDED")
        before_detail = store.obligation_detail(expected.H_ITEM_ID)
        before_sequence = store.summary()["sequence"]
        before_row = next(row for row in before_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-default-original")
        store.close()
        reopened = self._make_owner(path=store.path)
        retry = reopened.record_reporting_evidence(**request)
        self.assertEqual(retry["status"], "DUPLICATE")
        after_detail = reopened.obligation_detail(expected.H_ITEM_ID)
        after_row = next(row for row in after_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-default-original")
        self.assertEqual(after_row["record_digest"], before_row["record_digest"])
        self.assertEqual(after_row["event_at_ms"], before_row["event_at_ms"])
        self.assertEqual(reopened.summary()["sequence"], before_sequence)
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            reopened.record_reporting_evidence(
                **request,
                event_at_ms=int(before_row["event_at_ms"]) + 1,
            )
        self._assert_verified(reopened)

    def test_reporting_correction_chain_survives_restart_and_shadow_restore(self) -> None:
        store = self._build_base()
        self._advance_clock(store, expected.P2_EVENT_MS)
        store.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:chain-original",
            evidence_id="evidence:report:chain-original",
            event_at_ms=expected.P2_EVENT_MS,
        )
        first_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        self._advance_clock(store, expected.REPORT_CORRECTION_MS)
        store.record_reporting_correction(
            item_id=expected.H_ITEM_ID,
            report_id="report:chain-correction-1",
            evidence_id="evidence:report:chain-correction-1",
            expected_revision=first_revision,
            event_at_ms=expected.REPORT_CORRECTION_MS,
            supersedes="evidence:report:chain-original",
        )
        second_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        self._advance_clock(store, expected.REPORT_CORRECTION_MS + 1)
        store.record_reporting_correction(
            item_id=expected.H_ITEM_ID,
            report_id="report:chain-correction-2",
            evidence_id="evidence:report:chain-correction-2",
            expected_revision=second_revision,
            event_at_ms=expected.REPORT_CORRECTION_MS + 1,
            supersedes="evidence:report:chain-correction-1",
        )
        self._assert_verified(store)
        reopened = self._make_owner(path=store.path)
        self._assert_verified(reopened)
        package = reopened.export_continuity()
        shadow = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("chain-shadow.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        self._assert_verified(shadow, restore_source_package=package)

    def test_c05_decision_package_tracks_evidence_and_keeps_ack_separate_from_cash(self) -> None:
        store = self._build_base_for_correction()
        mirror = FinancialMirror(store)
        fixture = expected.DECISION_PACKAGE_EXPECTATION
        program = store.summary()
        self.assertEqual(program["obligation_count"], fixture["recipient_count"])
        self.assertEqual(program["owed_cents"], fixture["program_owed_cents"])
        self.assertEqual(fixture["program_owed_dollars"], 1_000_000)

        initial = store.decision_package(expected.H_ITEM_ID)
        self.assertEqual(initial["evaluation_receipt"], store.current_evaluation_receipt(expected.H_ITEM_ID))
        self.assertEqual(initial["references"]["evidence"]["total"], 0)
        self.assertEqual(initial["conclusions"]["case_resolution"]["assessment"], "NOT_RESOLVED")
        self.assertEqual(initial["conclusions"]["case_resolution"]["missing_requirements"], [
            "amount_satisfied", "delivery_acknowledged_or_not_required", "reporting_complete",
        ])
        self.assertEqual(self._assert_decision_package_verified(store, initial)["integrity"], "VERIFIED")
        with self.assertRaisesRegex(FinancialRevisionError, "evaluation_reference_conflict"):
            store.decision_package(
                expected.H_ITEM_ID,
                expected_evaluation_id=str(initial["evaluation_receipt"]["evaluation_id"]),
                expected_evaluation_result_digest="00" * 64,
            )

        self._prepare_rejected(store)
        rejected = store.decision_package(expected.H_ITEM_ID)
        self.assertEqual(rejected["case"]["case_id"], expected.H_CASE_ID)
        self.assertEqual(rejected["case"]["status"], "CORRECTION_REQUIRED")
        self.assertEqual(rejected["cash"]["recorded_received_cash_cents"], fixture["item_h_initial_cash_cents"])
        self.assertEqual(rejected["cash"]["shortfall_cents"], fixture["item_h_shortfall_cents"])
        with self.assertRaisesRegex(FinancialRevisionError, "evaluation_revision_conflict"):
            store.decision_package(
                expected.H_ITEM_ID,
                expected_evaluation_id=str(initial["evaluation_receipt"]["evaluation_id"]),
                expected_evaluation_result_digest=str(initial["evaluation_receipt"]["result_digest"]),
            )

        sequence_before_ack = store.summary()["sequence"]
        self._ack(store)
        self.assertEqual(store.summary()["sequence"], sequence_before_ack + 1)
        acknowledged = store.decision_package(
            expected.H_ITEM_ID,
            expected_evaluation_id=str(store.current_evaluation_receipt(expected.H_ITEM_ID)["evaluation_id"]),
            expected_evaluation_result_digest=str(store.current_evaluation_receipt(expected.H_ITEM_ID)["result_digest"]),
        )
        self.assertEqual(acknowledged["cash"]["recorded_received_cash_cents"], fixture["item_h_initial_cash_cents"])
        self.assertEqual(acknowledged["cash"]["shortfall_cents"], fixture["item_h_shortfall_cents"])
        self.assertEqual(acknowledged["current_action"]["status"], "ACKNOWLEDGED")
        self.assertEqual(acknowledged["current_action"]["acknowledgment"]["reference"], expected.H_ACKNOWLEDGMENT_REF)
        self.assertEqual(acknowledged["current_action"]["acknowledgment"]["cash_effect_cents"], 0)
        self.assertEqual(acknowledged["conclusions"]["action_acknowledgment"]["cash_effect_cents"], 0)
        self.assertEqual(acknowledged["conclusions"]["cash_satisfaction"]["result"], "NOT_SATISFIED")
        self.assertEqual(acknowledged["conclusions"]["case_resolution"]["required_conditions"]["amount_satisfied"], "NOT_SATISFIED")
        self.assertEqual(self._assert_decision_package_verified(store, acknowledged)["integrity"], "VERIFIED")

        self._record_p2(store)
        self._record_report(store)
        conflict = expected.P2_CONFLICT_EVIDENCE
        conflict_result = RightRailFinancialAcceptanceTests._record_fixture_payment(store, conflict, payment_id="payment:h:p2-conflict")
        self.assertEqual(conflict_result["status"], "CONFLICT")
        final_package = store.decision_package(expected.H_ITEM_ID)
        self.assertEqual(final_package["case"]["status"], "RESOLVED")
        self.assertEqual(final_package["cash"]["recorded_received_cash_cents"], fixture["item_h_cash_after_correction_cents"])
        self.assertEqual(final_package["reporting"]["complete"], True)
        self.assertEqual(final_package["evaluation_receipt"]["verification_status"], "CONFLICT_VISIBLE")
        self.assertEqual(final_package["conclusions"]["case_resolution"]["assessment"], "CONFLICTED")
        self.assertEqual(final_package["conclusions"]["case_resolution"]["conflict_count"], 1)
        conflict_reference = final_package["references"]["conflicts"]["items"][0]
        self.assertEqual(conflict_reference["candidate_evidence_id"], expected.P2_CONFLICT_EVIDENCE.evidence_id)
        self.assertEqual(conflict_reference["existing_amount_cents"], expected.CORRECTION_PAYMENT_CENTS)
        self.assertEqual(conflict_reference["candidate_amount_cents"], expected.CONFLICTING_P2_CENTS)
        self.assertEqual(final_package["conclusions"]["case_resolution"]["case_id"], expected.H_CASE_ID)
        self.assertTrue(final_package["conclusions"]["case_resolution"]["supporting_references_complete"])
        self.assertEqual(final_package["control_pack"]["pack_id"], expected.CONTROL_PACK_V1.pack_id)
        self.assertEqual(final_package["control_pack"]["version"], expected.CONTROL_PACK_V1.version)
        self.assertEqual(final_package["control_pack"]["calculation_rule_id"], expected.CONTROL_PACK_V1.calculation_rule_id)
        self.assertEqual(final_package["control_pack"]["adjustment_rule_id"], expected.CONTROL_PACK_V1.adjustment_rule_id)
        self.assertEqual(final_package["control_pack"]["digest"], final_package["evaluation_receipt"]["control_pack"]["digest"])
        self.assertEqual(final_package["evaluation_receipt"]["authority"]["authority_id"], self.authority.authority_id)
        self.assertEqual(final_package["evaluation_receipt"]["authority"]["epoch"], self.authority.epoch)
        self.assertEqual(final_package["evaluation_receipt"]["authority"]["digest"], _independent_hex(self.authority.digest))
        self.assertTrue(all(row["item_id"] == expected.H_ITEM_ID for row in final_package["references"]["evidence"]["items"]))
        self.assertTrue(all(type(row["record_digest"]) is str for row in final_package["references"]["evidence"]["items"]))
        self.assertEqual(final_package["current_determination"]["decision"], "OFFSET_REJECTED_CORRECTION_AUTHORIZED")
        self.assertIn(expected.OFFSET_CLAIM_EVIDENCE.evidence_id, [
            row["evidence_id"] for row in final_package["current_determination"]["supporting_evidence"]
        ])
        payment_evidence_ids = {
            row["evidence_id"] for row in final_package["references"]["payments"]["items"] if row["active"]
        }
        report_evidence_ids = {
            row["evidence_id"] for row in final_package["references"]["reporting_evidence"]["items"]
        }
        resolution_support = set(final_package["conclusions"]["case_resolution"]["supporting_evidence_ids"])
        self.assertTrue(payment_evidence_ids.issubset(resolution_support))
        self.assertTrue(report_evidence_ids.issubset(resolution_support))
        self.assertTrue(resolution_support)
        self.assertEqual(self._assert_decision_package_verified(store, final_package)["integrity"], "VERIFIED")
        omitted = json.loads(_independent_canonical(final_package))
        omitted["references"]["payments"]["items"].pop()
        with self.assertRaisesRegex(IndependentFinancialError, "decision-package:payments"):
            verify_decision_package(
                store.path,
                expected.H_ITEM_ID,
                omitted,
                expected_config=store.config,
                expected_authority=self.authority,
                expected_mode=store.mode,
                expected_owner_id=store.owner_id,
            )

        sequence_before_reads = store.summary()["sequence"]
        durable_snapshot_before = store.export_continuity()
        first = mirror.decision_package(expected.H_ITEM_ID, limit=2, offset=0)
        second = mirror.decision_package(expected.H_ITEM_ID, limit=2, offset=2)
        first_ids = {row["evidence_id"] for row in first["references"]["evidence"]["items"]}
        second_ids = {row["evidence_id"] for row in second["references"]["evidence"]["items"]}
        self.assertEqual(first["references"]["evidence"]["next_offset"], 2)
        self.assertEqual(second["references"]["evidence"]["offset"], 2)
        self.assertTrue(first_ids.isdisjoint(second_ids))
        self.assertEqual(store.summary()["sequence"], sequence_before_reads)
        self.assertEqual(store.export_continuity(), durable_snapshot_before)
        with self.assertRaisesRegex(FinancialInputError, "decision_package_page"):
            store.decision_package(expected.H_ITEM_ID, limit=201)
        with self.assertRaisesRegex(FinancialInputError, "decision_package_page"):
            store.decision_package(expected.H_ITEM_ID, offset=10_001)

    def test_c05_v7_decision_package_survives_test_restore(self) -> None:
        store = self._build_base_for_correction(schema_version=8)
        self._prepare_acknowledged(store)
        mirror = FinancialMirror(store)
        source_package = store.decision_package(expected.H_ITEM_ID)
        continuity = mirror.export_continuity()
        restored = mirror.restore_test_continuity(
            continuity,
            self._path("decision-package-test-restore.sqlite"),
        )
        restored_package = restored.owner.decision_package(expected.H_ITEM_ID)
        self.assertEqual(restored_package, source_package)
        result = verify_decision_package(
            restored.owner.path,
            expected.H_ITEM_ID,
            restored_package,
            expected_config=restored.owner.config,
            expected_authority=self.authority,
            expected_mode="TEST",
            expected_owner_id=owner._TEST_OWNER_ID,
        )
        self.assertEqual(result["integrity"], "VERIFIED")
        self.assertEqual(restored_package["cash"]["recorded_received_cash_cents"], expected.DECISION_PACKAGE_EXPECTATION["item_h_initial_cash_cents"])
        self.assertEqual(restored_package["current_action"]["status"], "ACKNOWLEDGED")

    def test_c05_v7_population_revision_binding_is_verified_and_restored(self) -> None:
        store = self._build_base_for_correction(schema_version=8)
        self._prepare_acknowledged(store)
        package = store.decision_package(expected.H_ITEM_ID)
        manifest = self._population_manifest()
        expected_binding = {
            "population_id": expected.POPULATION_ONE_ID,
            "status": "PUBLISHED",
            "completeness": "EXACT",
            "source_complete": True,
            "manifest_id": manifest.manifest_id,
            "manifest_version": manifest.manifest_version,
            "manifest_digest": _independent_hex(manifest.digest),
            "member_id": expected.H_ITEM_ID,
            "member_count": len(expected.POPULATION_MANIFEST_MEMBER_IDS),
            "member_digest": _independent_hex(manifest.member_digest),
        }
        self.assertEqual(package["contract"], "RR/FINANCIAL/DECISION-PACKAGE/v2")
        self.assertEqual(package["population_binding"], expected_binding)
        obligation_id = package["obligation"]["obligation_id"]
        self.assertEqual(package["obligation"]["population_id"], expected_binding["population_id"])
        self.assertEqual(package["current_determination"]["obligation_id"], obligation_id)
        self.assertEqual(package["current_action"]["obligation_id"], obligation_id)
        self.assertEqual(package["current_action"]["acknowledgment"]["status"], "ACKNOWLEDGED")
        self.assertEqual(package["references"]["actions"]["items"][0]["obligation_id"], obligation_id)
        self.assertEqual(self._assert_decision_package_verified(store, package)["integrity"], "VERIFIED")

        for field, value in (
            ("manifest_version", expected_binding["manifest_version"] + 1),
            ("manifest_digest", "00" * 64),
            ("member_id", "item-19"),
        ):
            altered = json.loads(_independent_canonical(package).decode("ascii"))
            altered["population_binding"][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(IndependentFinancialError, "decision-package:mismatch"):
                    self._assert_decision_package_verified(store, altered)

        continuity = store.export_continuity()
        restored = FinancialMirror(store).restore_test_continuity(
            continuity,
            self._path("population-revision-test-restore.sqlite"),
        )
        restored_package = restored.owner.decision_package(expected.H_ITEM_ID)
        self.assertEqual(restored_package, package)
        self.assertEqual(self._assert_decision_package_verified(restored.owner, restored_package)["integrity"], "VERIFIED")

    def test_c05_a_clock_behind_the_history_writes_nothing(self) -> None:
        clock = _Clock()
        store = self._build_base(clock=clock)
        self._record_cash(store)

        first_claim_id = "claim:clock-rollback:first"
        first_action_id = "action:clock-rollback:first"
        store.record_offset_claim(
            item_id=expected.H_ITEM_ID,
            claim_id=first_claim_id,
            amount_cents=200_000,
            evidence_id="evidence:clock-rollback:first",
            owner_role="CASE_OWNER",
            deadline_ms=expected.H_DUE_AT_MS,
        )
        first_receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        low_clock_value = clock.value
        clock.value = low_clock_value + 10_000
        first_result = store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=first_claim_id,
            expected_revision=int(first_receipt["revision"]),
            action_id=first_action_id,
            evaluation_id=str(first_receipt["evaluation_id"]),
            evaluation_result_digest=str(first_receipt["result_digest"]),
        )
        self.assertEqual(first_result["action_id"], first_action_id)

        before = store.export_continuity()
        clock.value = low_clock_value  # the checker refuses a history whose commit times run backward
        with self.assertRaisesRegex(FinancialIntegrityError, "event_commit_order"):
            store.record_offset_claim(
                item_id=expected.H_ITEM_ID,
                claim_id="claim:clock-rollback:second",
                amount_cents=100_000,
                evidence_id="evidence:clock-rollback:second",
                owner_role="CASE_OWNER",
                deadline_ms=expected.H_DUE_AT_MS,
            )
        self.assertEqual(store.export_continuity(), before)
        self._assert_verified(store)
        clock.value = low_clock_value + 10_000  # the host clock recovers
        first_determination = next(
            row for row in store.obligation_detail(expected.H_ITEM_ID)["determinations"]
            if row["determination_id"] == first_result["determination_id"]
        )
        duplicate = store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=first_claim_id,
            expected_revision=int(first_receipt["revision"]),
            action_id=first_action_id,
            evaluation_id=str(first_receipt["evaluation_id"]),
            evaluation_result_digest=str(first_receipt["result_digest"]),
        )
        self.assertEqual(duplicate["status"], "DUPLICATE")
        with self.assertRaisesRegex(FinancialConflictError, "determination_request_conflict"):
            store.authorize_offset(
                item_id=expected.H_ITEM_ID,
                claim_id=first_claim_id,
                expected_revision=int(first_receipt["revision"]),
                action_id=first_action_id,
                decision_at_ms=int(first_determination["decided_at_ms"]) - 1,
                evaluation_id=str(first_receipt["evaluation_id"]),
                evaluation_result_digest=str(first_receipt["result_digest"]),
            )
        self.assertEqual(store.export_continuity(), before)

    def test_future_decision_time_is_refused_and_a_later_honest_write_succeeds(self) -> None:
        clock = _Clock()
        store = self._build_base_for_correction(clock=clock)
        self._record_cash(store)
        store.record_offset_claim(
            item_id=expected.H_ITEM_ID, claim_id="claim:future-decision", amount_cents=200_000,
            evidence_id="evidence:future-decision", owner_role="CASE_OWNER", deadline_ms=expected.H_DUE_AT_MS,
        )
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        request = {
            "item_id": expected.H_ITEM_ID, "claim_id": "claim:future-decision", "expected_revision": int(receipt["revision"]),
            "action_id": "action:future-decision", "evaluation_id": str(receipt["evaluation_id"]),
            "evaluation_result_digest": str(receipt["result_digest"]),
        }
        before = store.export_continuity()
        for future in (lambda: clock.value + 2, lambda: 2**63 - 1):  # each write reads the clock once, at value + 1
            with self.assertRaisesRegex(FinancialInputError, "decision_time_future"):
                store.authorize_offset(**request, decision_at_ms=future())
            with self.assertRaisesRegex(FinancialInputError, "decision_time_future"):
                store.reject_offset_and_authorize_correction(**request, decision_at_ms=future())
        self.assertEqual(store.export_continuity(), before)
        self.assertEqual(store.authorize_offset(**request, decision_at_ms=clock.value)["action_id"], "action:future-decision")
        store.evaluate_obligation(expected.H_ITEM_ID)  # the clock was never held ahead of the honest writes
        self._assert_verified(store)

    def test_c05_independent_package_input_is_bounded_before_database_open(self) -> None:
        store = self._build_base()
        package = store.decision_package(expected.H_ITEM_ID)
        continuity_before = store.export_continuity()
        missing_database = self._path("missing-decision-package-input.sqlite")
        self.assertFalse(missing_database.exists())

        def assert_rejected_before_open(value: object) -> None:
            with self.assertRaisesRegex(IndependentFinancialError, "decision-package:input-limit"):
                verify_decision_package(missing_database, expected.H_ITEM_ID, value)

        oversized = dict(package)
        oversized["untrusted_extra"] = "x" * (8 * 1024 * 1024)
        assert_rejected_before_open(oversized)

        nested: object = None
        for _ in range(33):
            nested = [nested]
        too_deep = dict(package)
        too_deep["untrusted_extra"] = nested
        assert_rejected_before_open(too_deep)

        cycle: list[object] = []
        cycle.append(cycle)
        cyclic = dict(package)
        cyclic["untrusted_extra"] = cycle
        assert_rejected_before_open(cyclic)

        self.assertFalse(missing_database.exists())
        self.assertEqual(store.export_continuity(), continuity_before)

    def test_v5_evaluation_receipt_is_durable_and_returned_by_evaluate(self) -> None:
        store = self._build_base()
        before = store.current_evaluation_receipt(expected.H_ITEM_ID)
        evaluated = store.evaluate_obligation(expected.H_ITEM_ID, expected_revision=before["revision"])
        receipt = evaluated["evaluation_receipt"]
        self.assertEqual(receipt["evaluation_id"], evaluated["current_evaluation_id"])
        self.assertEqual(receipt["revision"], evaluated["revision"])
        self.assertEqual(receipt["evaluation_result_digest"], receipt["result_digest"])
        self.assertEqual(receipt, store.current_evaluation_receipt(expected.H_ITEM_ID))
        self.assertEqual(receipt["scope"]["period_id"], expected.PERIOD_ONE_ID)
        self.assertEqual(receipt["evidence_bindings"], [])
        self.assertNotIn("raw_evidence", receipt)
        self.assertNotIn("signatures", receipt)
        store.close()
        reopened = self._make_owner(path=store.path, clock=store.clock)
        self.assertEqual(reopened.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        self._assert_verified(reopened)

    def test_v5_populated_evaluation_receipt_is_independent_and_boundary_stable(self) -> None:
        from tools import right_rail_financial_cli as cli

        clock = _Clock(expected.CASH_EVENT_MS - 1_000)
        store = self._build_base(clock=clock)
        clock.value = expected.CASH_EVENT_MS - 1
        self._record_cash(store)
        claim_id = self._record_claim(store)
        before_evaluate = store.current_evaluation_receipt(expected.H_ITEM_ID)
        evaluated = store.evaluate_obligation(expected.H_ITEM_ID, expected_revision=int(before_evaluate["revision"]))
        receipt = evaluated["evaluation_receipt"]
        detail = store.obligation_detail(expected.H_ITEM_ID)
        evidence_rows = {
            str(row["evidence_id"]): {"item_id": expected.H_ITEM_ID, **row}
            for row in detail["evidence"]
        }
        cash_row = evidence_rows[expected.H_CASH_EVIDENCE.evidence_id]
        claim_row = evidence_rows[expected.OFFSET_CLAIM_EVIDENCE.evidence_id]
        self.assertEqual(
            {key: cash_row[key] for key in ("item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "amount_cents", "reversal_of", "supersedes")},
            {
                "item_id": expected.H_ITEM_ID,
                "kind": "PAYMENT_CONFIRMATION",
                "common_origin_id": "origin:cash:h:v1",
                "source_id": "fixture-payment-file",
                "source_version": "cash-v1",
                "local_ref": "ref:cash:h:v1",
                "applicable_at_ms": expected.CASH_EVENT_MS,
                "event_at_ms": expected.CASH_EVENT_MS,
                "received_at_ms": expected.CASH_EVENT_MS,
                "amount_cents": expected.H_CASH_CENTS,
                "reversal_of": None,
                "supersedes": None,
            },
        )
        self.assertEqual(
            {key: claim_row[key] for key in ("item_id", "kind", "common_origin_id", "source_id", "source_version", "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "amount_cents", "reversal_of", "supersedes")},
            {
                "item_id": expected.H_ITEM_ID,
                "kind": "OFFSET_CLAIM",
                "common_origin_id": claim_id,
                "source_id": "synthetic-offset-source",
                "source_version": "fixture-v1",
                "local_ref": f"offset:{claim_id}",
                "applicable_at_ms": expected.CASH_EVENT_MS + 1,
                "event_at_ms": expected.CASH_EVENT_MS + 1,
                "received_at_ms": expected.CASH_EVENT_MS + 1,
                "amount_cents": expected.UNAPPROVED_OFFSET_CENTS,
                "reversal_of": None,
                "supersedes": None,
            },
        )
        evidence_bindings = [
            {"evidence_id": evidence_id, "record_digest": _independent_evidence_digest(evidence_rows[evidence_id])}
            for evidence_id in sorted(evidence_rows)
        ]
        self.assertEqual(receipt["evidence_bindings"], evidence_bindings)
        scope = {
            "state_id": expected.STATE_ID,
            "deployment_id": expected.DEPLOYMENT_ID,
            "program_id": expected.PROGRAM_ID,
            "period_id": expected.PERIOD_ONE_ID,
            "currency": expected.CURRENCY,
        }
        input_snapshot = {
            "pre_revision": int(before_evaluate["revision"]),
            "obligation": {
                "obligation_id": expected.H_OBLIGATION_ID,
                "item_id": expected.H_ITEM_ID,
                "revision": int(before_evaluate["revision"]),
                "rule_version": 1,
                "owed_cents": expected.H_OWED_CENTS,
                "due_at_ms": expected.H_DUE_AT_MS,
                "reporting_complete": 0,
            },
            "evidence": [
                {
                    "evidence_id": binding["evidence_id"],
                    "record_digest": binding["record_digest"],
                    "event_at_ms": evidence_rows[binding["evidence_id"]]["event_at_ms"],
                    "received_at_ms": evidence_rows[binding["evidence_id"]]["received_at_ms"],
                }
                for binding in evidence_bindings
            ],
            "payments": [{"payment_id": "payment:h:cash", "amount_cents": expected.H_CASH_CENTS, "event_at_ms": expected.CASH_EVENT_MS, "active": 1}],
            "claims": [{"claim_id": claim_id, "amount_cents": expected.UNAPPROVED_OFFSET_CENTS, "status": "CLAIMED"}],
            "determinations": [],
            "cases": [{"case_id": f"case:{expected.H_OBLIGATION_ID}", "status": "OPEN"}],
            "actions": [],
            "conflicts": [],
        }
        evaluation_row = next(row for row in detail["evaluations"] if row["evaluation_id"] == receipt["evaluation_id"])
        self.assertEqual(json.loads(str(evaluation_row["input_snapshot_json"])), input_snapshot)
        input_snapshot_digest = _independent_hex(
            _independent_digest(b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00", _independent_canonical(input_snapshot))
        )
        self.assertEqual(receipt["input_snapshot_digest"], input_snapshot_digest)
        result_fields = {
            "evaluation_id": f"evaluation:{expected.H_OBLIGATION_ID}:r{int(before_evaluate['revision']) + 1}",
            "obligation_id": expected.H_OBLIGATION_ID,
            "revision": int(before_evaluate["revision"]) + 1,
            "rule_version": 1,
            "evidence_ids": [binding["evidence_id"] for binding in evidence_bindings],
            "authority_id": self.authority.authority_id,
            "evaluated_at_ms": clock.value,
            "owed_cents": expected.H_OWED_CENTS,
            "claimed_adjustment_cents": expected.UNAPPROVED_OFFSET_CENTS,
            "lawful_adjustment_cents": 0,
            "received_cash_cents": expected.H_CASH_CENTS,
            "shortfall_cents": expected.UNAPPROVED_OFFSET_CENTS,
            "overage_cents": 0,
            "cash_satisfied": 0,
            "amount_satisfied": 0,
            "timely": 0,
            "reporting_complete": 0,
            "verification_status": "SUPPORTED",
            "case_status": "OPEN",
            "delivery_status": "NONE",
        }
        result_digest = _independent_hex(
            _independent_digest(b"RR/FINANCIAL/EVALUATION/v5\x00", _independent_canonical(result_fields))
        )
        receipt_body = {
            "contract_version": "RR/FINANCIAL/EVALUATION-RECEIPT/v1",
            "scope": scope,
            "evaluation_id": result_fields["evaluation_id"],
            "obligation_id": result_fields["obligation_id"],
            "revision": result_fields["revision"],
            "control_pack": {"pack_id": expected.CONTROL_PACK_V1.pack_id, "version": 1, "digest": _independent_pack_digest(expected.CONTROL_PACK_V1)},
            "evidence_bindings": evidence_bindings,
            "input_snapshot_digest": input_snapshot_digest,
            "authority": {"authority_id": self.authority.authority_id, "epoch": self.authority.epoch, "digest": _independent_hex(self.authority.digest)},
            **result_fields,
            "result_digest": result_digest,
        }
        expected_receipt = {
            **receipt_body,
            "receipt_digest": _independent_hex(
                _independent_digest(b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00", _independent_canonical(receipt_body))
            ),
            "evaluation_result_digest": result_digest,
        }
        self.assertEqual(receipt, expected_receipt)
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        package = store.export_continuity()
        store.close()
        reopened = self._make_owner(path=store.path, clock=clock)
        self.assertEqual(reopened.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        mirror_receipt = FinancialMirror(reopened).current_evaluation_receipt(expected.H_ITEM_ID)
        self.assertEqual({key: value for key, value in mirror_receipt.items() if key not in {"schema", "resource"}}, receipt)
        authority_file = self._path("trusted-authority.json")
        authority_file.write_text(json.dumps(cli.authority_file_record(self.authority)), encoding="ascii")
        common = [
            "--database", str(reopened.path),
            "--authority-file", str(authority_file),
            "--state-id", expected.STATE_ID,
            "--deployment-id", expected.DEPLOYMENT_ID,
            "--program-id", expected.PROGRAM_ID,
            "--period-id", expected.PERIOD_ONE_ID,
            "current-evaluation-receipt", "--item-id", expected.H_ITEM_ID,
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cli.main(common), 0)
        self.assertEqual(stderr.getvalue(), "")
        cli_receipt = json.loads(stdout.getvalue())
        self.assertEqual({key: value for key, value in cli_receipt.items() if key not in {"schema", "resource"}}, receipt)
        shadow = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("populated-receipt-shadow.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        self.assertEqual(shadow.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        self._assert_verified(reopened)
        self._assert_verified(shadow, restore_source_package=package)

    def test_v5_action_requires_current_evaluation_and_exact_retry_identity(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        self._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided
        with self.assertRaisesRegex(FinancialInputError, "evaluation_reference_required"):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=receipt["revision"],
                action_id="action:missing-evaluation-reference",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
            )
        foreign = store.current_evaluation_receipt("item-01")
        with self.assertRaisesRegex(FinancialRevisionError, "evaluation_revision_conflict"):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=receipt["revision"],
                action_id="action:foreign-evaluation-reference",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
                evaluation_id=foreign["evaluation_id"],
                evaluation_result_digest=foreign["result_digest"],
            )
        command = {
            "item_id": expected.H_ITEM_ID,
            "claim_id": claim_id,
            "expected_revision": receipt["revision"],
            "action_id": "action:exact-retry-v5",
            "decision_at_ms": expected.CORRECTION_AUTH_MS,
            "evaluation_id": receipt["evaluation_id"],
            "evaluation_result_digest": receipt["result_digest"],
        }
        reject = store.reject_offset_and_authorize_correction
        self._advance_clock(store, expected.CORRECTION_AUTH_MS - 1)  # recorded when decided

        def lose_response_after_commit(**kwargs: object) -> None:
            reject(**kwargs)
            raise RuntimeError("simulated_postcommit_response_loss")

        with patch.object(
            store,
            "reject_offset_and_authorize_correction",
            side_effect=lose_response_after_commit,
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated_postcommit_response_loss"):
                store.reject_offset_and_authorize_correction(**command)
        detail = store.obligation_detail(expected.H_ITEM_ID)
        determination = next(row for row in detail["determinations"] if row["determination_id"] == "determination:action:exact-retry-v5")
        decision_time = int(determination["decided_at_ms"])
        self.assertEqual(decision_time, expected.CORRECTION_AUTH_MS)
        before_retry = store.export_continuity()
        retry = store.reject_offset_and_authorize_correction(**command)
        self.assertEqual(retry["status"], "DUPLICATE")
        self.assertEqual(store.export_continuity(), before_retry)
        with self.assertRaisesRegex(FinancialConflictError, "determination_request_conflict"):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=receipt["revision"],
                action_id="action:exact-retry-v5",
                decision_at_ms=decision_time + 1,
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self.assertEqual(store.export_continuity(), before_retry)
        cash_before_ack = store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"]
        store.acknowledge_action("action:exact-retry-v5", "ack:exact-retry-v5")
        after_ack = store.export_continuity()
        acknowledged_retry = store.reject_offset_and_authorize_correction(**command)
        self.assertEqual(acknowledged_retry["status"], "DUPLICATE")
        self.assertEqual(store.export_continuity(), after_ack)
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"], cash_before_ack)
        with self.assertRaisesRegex(FinancialConflictError, "determination_request_conflict"):
            store.reject_offset_and_authorize_correction(
                item_id="item-01",
                claim_id=claim_id,
                action_id="action:exact-retry-v5",
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self._assert_verified(store)

    def test_v5_determination_bad_stale_and_consumed_references_are_side_effect_free(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)

        def request(*, action_id: str, evaluation_id: str | None, evaluation_result_digest: str | None, expected_revision: int | None, decision_at_ms: int | None = None) -> dict[str, object]:
            return store.authorize_offset(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=expected_revision,
                action_id=action_id,
                decision_at_ms=decision_at_ms,
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
            )

        reference = dict(evaluation_id=str(receipt["evaluation_id"]), evaluation_result_digest=str(receipt["result_digest"]), expected_revision=int(receipt["revision"]))
        refusals = (
            ("malformed-evaluation-reference", FinancialInputError, "evaluation_result_digest", {"evaluation_result_digest": "not-a-digest"}),
            ("bad-evaluation-digest", FinancialRevisionError, "evaluation_reference_conflict", {"evaluation_result_digest": "0" * 128}),
            ("decision-before-evaluation-reference", FinancialInputError, "evaluation_reference_required", {"evaluation_id": None, "evaluation_result_digest": None}),
            ("decision-before-evaluation-chronology", FinancialIntegrityError, "evaluation_chronology", {"decision_at_ms": int(receipt["evaluated_at_ms"]) - 1}),
        )
        for label, error, code, changes in refusals:
            with self.subTest(refusal=label):
                before = store.export_continuity()
                with self.assertRaisesRegex(error, code):
                    request(action_id="action:" + label, **{**reference, **changes})
                self.assertEqual(store.export_continuity(), before)

        store.record_support_evidence(
            item_id=expected.H_ITEM_ID,
            evidence_id="evidence:stale-reference-support",
            common_origin_id="origin:stale-reference-support",
            expected_revision=int(receipt["revision"]),
        )
        before_stale = store.export_continuity()
        with self.assertRaisesRegex(FinancialRevisionError, "obligation_revision_conflict"):
            request(
                action_id="action:stale-evaluation-reference",
                evaluation_id=str(receipt["evaluation_id"]),
                evaluation_result_digest=str(receipt["result_digest"]),
                expected_revision=int(receipt["revision"]),
            )
        self.assertEqual(store.export_continuity(), before_stale)

        current = store.current_evaluation_receipt(expected.H_ITEM_ID)
        first = request(
            action_id="action:consumed-reference-one",
            evaluation_id=str(current["evaluation_id"]),
            evaluation_result_digest=str(current["result_digest"]),
            expected_revision=int(current["revision"]),
        )
        self.assertEqual(first["status"], "AUTHORIZED")
        after_first = store.export_continuity()
        with self.assertRaisesRegex(FinancialRevisionError, "evaluation_revision_conflict"):
            request(
                action_id="action:consumed-reference-two",
                evaluation_id=str(current["evaluation_id"]),
                evaluation_result_digest=str(current["result_digest"]),
                expected_revision=int(store.current_evaluation_receipt(expected.H_ITEM_ID)["revision"]),
            )
        self.assertEqual(store.export_continuity(), after_first)
        self._assert_verified(store)

    def test_clock_behind_received_evidence_is_rejected_without_clamping(self) -> None:
        clock = _Clock()
        store = self._build_base(clock=clock)
        self._record_h_support(store)
        before = store.path.read_bytes()
        clock.value -= 10_000  # the owner clock steps back behind evidence it already received
        with self.assertRaisesRegex(FinancialIntegrityError, "evaluation_evidence_chronology"):
            store.evaluate_obligation(expected.H_ITEM_ID)
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)

    def test_continuity_restore_rejects_meta_header_mismatch_before_creation(self) -> None:
        store = self._build_base()
        package = json.loads(store.export_continuity().decode("ascii"))
        package["tables"]["financial_meta"][0]["sequence"] += 1
        body = dict(package)
        del body["package_digest"]
        package["package_digest"] = owner._hex(owner._digest(owner._CONTINUITY_DOMAIN, owner._canonical(body)))
        destination = self._path("meta-mismatch-continuity.sqlite")
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_meta_binding"):
            FinancialOwner.restore_continuity(
                package_bytes=owner._canonical(package),
                recovered_path=destination,
                trusted_authority=self.authority,
                clock=_Clock(),
            )
        self.assertFalse(destination.exists())
        self._assert_verified(store)

    def test_old_continuity_version_is_rejected_without_mutating_source(self) -> None:
        store = self._build_base()
        before = store.path.read_bytes()
        package = json.loads(store.export_continuity().decode("ascii"))
        package["schema"] = "RR/FINANCIAL/CONTINUITY/v4"
        package["version"] = 4
        old_package = owner._canonical(package)
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_package_schema"):
            FinancialOwner.validate_continuity_package(old_package)
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)

    def test_retired_v2_to_v7_tagged_store_and_package_inputs_reject_without_creation(self) -> None:
        store = self._build_base()
        source_before = store.path.read_bytes()
        for version in (2, 3, 4, 5, 6, 7):
            target = self._path(f"tag-only-owner-v{version}.sqlite")
            target.write_bytes(source_before)
            with closing(sqlite3.connect(target, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE financial_meta SET schema_version=?,schema=? WHERE id=1",
                    (version, f"RR/FINANCIAL/OWNER/v{version}"),
                )
            target_before = target.read_bytes()
            with self.assertRaisesRegex(FinancialIntegrityError, "^unsupported_store_version$"):
                FinancialOwner(
                    path=target,
                    config=store.config,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
            self.assertEqual(target.read_bytes(), target_before)
            with self.assertRaisesRegex(IndependentFinancialError, "schema:version"):
                verify_database(target, expected_config=store.config, expected_authority=self.authority)
            self.assertEqual(target.read_bytes(), target_before)
            with self.assertRaises(FinancialInputError):
                replace(store.config, schema_version=version)

            package = json.loads(store.export_continuity().decode("ascii"))
            package["schema"] = f"RR/FINANCIAL/CONTINUITY/v{version}"
            package["version"] = version
            body = dict(package)
            del body["package_digest"]
            package["package_digest"] = _independent_hex(
                _independent_digest(f"RR/FINANCIAL/CONTINUITY/v{version}\x00".encode("ascii"), _independent_canonical(body))
            )
            old_package = _independent_canonical(package)
            with self.assertRaisesRegex(FinancialContinuityError, "continuity_package_schema"):
                FinancialOwner.validate_continuity_package(old_package)
            with self.assertRaisesRegex(IndependentFinancialError, "continuity:schema"):
                verify_continuity_package(
                    old_package,
                    expected_scope=package["scope"],
                    expected_authority=self.authority,
                )
            destination = self._path(f"tag-only-restore-v{version}.sqlite")
            with self.assertRaisesRegex(FinancialContinuityError, "continuity_package_schema"):
                FinancialOwner.restore_continuity(
                    package_bytes=old_package,
                    recovered_path=destination,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.glob(f".{destination.name}.restore-*")), [])
        self.assertEqual(store.path.read_bytes(), source_before)
        self._assert_verified(store)

    def test_command_log_is_derived_from_history_and_recomputed_by_the_checker(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_final(store)
        package = store.export_continuity()
        self.assertNotIn("commands", json.loads(package.decode("ascii"))["tables"])
        with closing(sqlite3.connect(str(store.path))) as connection:
            commands = connection.execute("SELECT * FROM commands ORDER BY event_sequence").fetchall()
        self.assertEqual(len(commands), len({row[0] for row in commands}))
        self.assertTrue(_V8_COMMAND_KINDS <= {row[1] for row in commands})
        restored = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("command-log-restore.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        history = self._path("command-log-history")
        store.export_history(history)  # the full journey also restores by replaying its history segments
        replayed = FinancialOwner.restore_continuity(history=history, recovered_path=self._path("command-log-replay.sqlite"), trusted_authority=self.authority, clock=_Clock())
        for copy in (restored, replayed):
            with closing(sqlite3.connect(str(copy.path))) as connection:
                self.assertEqual(connection.execute("SELECT * FROM commands ORDER BY event_sequence").fetchall(), commands)
        self._assert_verified(replayed)
        first = "(SELECT min(event_sequence) FROM commands)"
        edits = {
            "request": f"UPDATE commands SET request_json=replace(request_json,'\"key\"','\"key\" ') WHERE event_sequence={first}",
            "sequence": "UPDATE commands SET event_sequence=(SELECT min(event_sequence) FROM financial_events"
            f" WHERE event_sequence NOT IN (SELECT event_sequence FROM commands)) WHERE event_sequence={first}",
            "dropped": f"DELETE FROM commands WHERE event_sequence={first}",
        }
        source_bytes = store.path.read_bytes()
        for label, statement in edits.items():
            with self.subTest(label=label):
                tampered = self._path(f"command-log-{label}.sqlite")
                tampered.write_bytes(source_bytes)
                with closing(sqlite3.connect(str(tampered), isolation_level=None)) as connection:
                    connection.execute("DROP TRIGGER command_update_immutable")
                    connection.execute("DROP TRIGGER command_delete_immutable")
                    connection.execute(statement)
                    connection.execute(f"CREATE TRIGGER command_update_immutable {_COMMAND_TRIGGER_BODY.format('UPDATE')}")
                    connection.execute(f"CREATE TRIGGER command_delete_immutable {_COMMAND_TRIGGER_BODY.format('DELETE')}")
                with self.assertRaisesRegex(IndependentFinancialError, "^commands:"):
                    verify_database(tampered, expected_config=store.config, expected_authority=self.authority)
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "command_immutable"):
                connection.execute("DELETE FROM commands")

    def test_a_row_write_without_its_event_is_refused_before_commit(self) -> None:
        store = self._build_base()
        before = store.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^captured_rows_without_event$"):
            with store._write() as connection:
                connection.execute("UPDATE cases SET due_at_ms=due_at_ms+1")
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)

    def test_row_edits_the_history_does_not_explain_are_refused(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_final(store)
        self._assert_verified(store)
        source = store.path.read_bytes()
        # Review 466178b finding 4: same-length edits, with the command log and the size cache
        # rewritten to match, passed both checkers; every write is now replayed from the chain.
        reversal = expected.P2_REVERSAL_EVIDENCE
        orphan = store._new_evidence(
            evidence_id="evidence:orphan-reversal", item_id=reversal.item_id, kind="PAYMENT_REVERSAL",
            common_origin_id="origin:orphan-reversal", source_id="synthetic-payment-source", source_version="fixture-v1",
            local_ref="reversal:orphan", applicable_at_ms=reversal.event_at_ms, event_at_ms=reversal.event_at_ms,
            received_at_ms=reversal.event_at_ms, amount_cents=reversal.amount_cents, reversal_of="payment:h:p2",
        )
        tampers = (
            # Final review 75a5517 finding 3: the case row is now recomputed before replay, so these fail there first.
            ("case:derived", lambda c: c.execute("UPDATE claimed_adjustments SET deadline_ms=deadline_ms+1")),
            ("replay:action_outbox", lambda c: c.execute(
                "UPDATE action_outbox SET acknowledgment_ref=substr(acknowledgment_ref,1,length(acknowledgment_ref)-1)||'9'")),
            # Review 466178b: a second reversal's evidence row, digest-valid, that no event names.
            # Final review 75a5517 finding 5: every current evaluation is now compared with the rows first.
            ("obligation:exact-input:evidence", lambda c: store._insert_evidence(c, orphan)),
            ("case:derived", lambda c: c.execute("UPDATE cases SET due_at_ms=due_at_ms+1")),
            # One clock reading per command: visible_at_ms now equals its event's commit time, so this fails before replay.
            ("conflict:visible", lambda c: c.execute("UPDATE financial_conflicts SET visible_at_ms=visible_at_ms+1")),
            # Not carried as rows: bound to their evaluation, their population's history, and the only epoch.
            ("projection:updated-at", lambda c: c.execute("UPDATE obligations SET updated_at_ms=updated_at_ms+1")),
            ("history:population-updated-at", lambda c: c.execute("UPDATE population_imports SET updated_at_ms=updated_at_ms+1")),
            ("meta:continuity-epoch", lambda c: c.execute("UPDATE financial_meta SET continuity_epoch=2")),
        )
        for code, tamper in tampers:
            with self.subTest(code=code):
                tampered = self._path(f"row-edit-{code.replace(':', '-')}.sqlite")
                tampered.write_bytes(source)
                with closing(sqlite3.connect(str(tampered), isolation_level=None)) as connection:
                    connection.row_factory = sqlite3.Row
                    connection.execute("DROP TRIGGER command_update_immutable")
                    connection.execute("DROP TRIGGER command_delete_immutable")
                    tamper(connection)
                    connection.execute("DELETE FROM commands")
                    store._derive_command_log(connection)
                    connection.execute(f"CREATE TRIGGER command_update_immutable {_COMMAND_TRIGGER_BODY.format('UPDATE')}")
                    connection.execute(f"CREATE TRIGGER command_delete_immutable {_COMMAND_TRIGGER_BODY.format('DELETE')}")
                tampered_bytes = tampered.read_bytes()
                with self.assertRaisesRegex(IndependentFinancialError, f"^{code}$"):
                    verify_database(tampered, expected_config=store.config, expected_authority=self.authority)
                with self.assertRaisesRegex(FinancialIntegrityError, f"^open_verification:{code}$"):
                    self._make_owner(path=tampered)
                self.assertEqual(tampered.read_bytes(), tampered_bytes)

    def test_a_wrong_lean_correction_result_is_refused_before_commit(self) -> None:
        from app import right_rail_financial_semantic_adapter as semantic

        real_run, real_encode = financial_engine.run_correction_transition_v1, semantic.encode_blfin02_input
        # Each wrong result still passes the Engine decoder's own consistency checks.
        tampers = (
            ("evaluation:input-projection:claimed_adjustment_cents", lambda r, m: {"claimed_adjustment_cents": r.claimed_adjustment_cents + m["determination"]["amount_cents"]}),
            ("evaluation:input-projection:received_cash_cents", lambda r, m: {"received_cash_cents": r.received_cash_cents + 1}),
            ("evaluation:input-projection:shortfall_cents", lambda r, m: {"shortfall_cents": r.shortfall_cents - 1}),
            ("evaluation:input-projection:timely", lambda r, m: {"timely": not r.timely}),
            ("evaluation:input-projection:verification_status", lambda r, m: {"verification_status": "MISSING_EVIDENCE"}),
            ("evaluation:input-projection:case_status", lambda r, m: {"case_status": "RESOLVED"}),
            # Review 75a5517 finding 1: an unsatisfied correction stays CORRECTION_REQUIRED; the
            # checker derives that from the decision, not from the case status Lean wrote.
            ("evaluation:input-projection:case_status", lambda r, m: {"case_status": "OPEN"}),
            ("evaluation:input-projection:case_status", lambda r, m: {"case_status": "AUTHORIZED"}),
            # Refused before the checker now: the post-state binding covers the result's evidence ids.
            ("post_state:result_evidence_ids", lambda r, m: {"evidence_ids": ()}),
        )
        for index, (code, change) in enumerate(tampers):
            with self.subTest(index=index, code=code):
                store = self._build_base_for_correction()
                self._record_cash(store)
                claim_id = self._record_claim(store)
                before = store.path.read_bytes()
                declared: dict = {}

                def encode(snapshot: object, **options: object) -> bytes:
                    # Lean also declares the post-state the wrong rows encode, so the checker's own
                    # derivation is what stands between them and COMMIT.
                    wire = real_encode(snapshot, **options)
                    if "mutation" in declared:
                        declared["mutation"]["resulting_input_wire"] = wire
                    return wire

                def run(release: object, *, request: bytes, change: object = change) -> object:
                    execution = real_run(release, request=request)
                    mutation = declared["mutation"] = execution.result["mutation"]
                    wrong = replace(mutation["resulting_result"], **change(mutation["resulting_result"], mutation))
                    mutation["resulting_result"] = wrong
                    mutation["resulting_result_wire"] = semantic.encode_blfres02_result(wrong)
                    mutation["case_delta"]["record"]["status"] = wrong.case_status
                    financial_engine._validate_correction_result_shape(execution.result)
                    return execution

                with patch.object(financial_engine, "run_correction_transition_v1", run), patch.object(semantic, "encode_blfin02_input", encode):
                    with self.assertRaises(FinancialIntegrityError) as caught:
                        self._reject(store, claim_id)
                # Before step 5 the Python re-derivation refused all seven as correction_result_input_binding.
                self.assertEqual(str(caught.exception), f"correction_{code if code.startswith('post_state:') else 'verification:' + code}")
                self.assertEqual(store.path.read_bytes(), before)
                self._assert_verified(store)

    def test_lean_must_declare_the_post_state_it_produced(self) -> None:
        # Final review of 75a5517, finding 2: these pass the Engine decoder but name another state or item.
        from app import right_rail_financial_semantic_adapter as semantic

        real_run = financial_engine.run_correction_transition_v1
        wire = "resulting_input_wire"
        tampers = (
            ("resulting_input", wire, lambda w: semantic.BLFIN02_MAGIC + b"\x00" * 32),
            ("resulting_input", wire, lambda w: w[:-1]),
            ("resulting_input", wire, lambda w: w[:-1] + bytes([w[-1] ^ 1])),
            ("result_context_binding", "item_id", lambda r: expected.OTHER_ITEM_IDS[0]),
            ("result_context_binding", "population_id", lambda r: "population:other"),
            ("result_context_binding", "provenance", lambda r: next(tag for tag in semantic._PROVENANCE_TAGS if tag != r)),
            ("result_context_binding", "owner_id", lambda r: "owner:other"),
            ("result_authority_binding", "authority_epoch", lambda r: r + 1),
            ("result_pack_binding", "pack_id", lambda r: "pack:other"),
            ("result_completion", "completion_at_ms", lambda r: (r or 0) + 1),
            ("result_completion", "completion_at_ms", lambda r: None if r is not None else 1),
        )
        for index, (code, field, change) in enumerate(tampers):
            with self.subTest(index=index, field=field):
                store = self._build_base_for_correction()
                self._record_cash(store)
                claim_id = self._record_claim(store)
                before = store.path.read_bytes()

                def run(release: object, *, request: bytes, field: str = field, change: object = change) -> object:
                    execution = real_run(release, request=request)
                    mutation = execution.result["mutation"]
                    if field == wire:
                        mutation[wire] = change(mutation[wire])
                    else:
                        result = mutation["resulting_result"]
                        mutation["resulting_result"] = replace(result, **{field: change(getattr(result, field))})
                        mutation["resulting_result_wire"] = semantic.encode_blfres02_result(mutation["resulting_result"])
                    financial_engine._validate_correction_result_shape(execution.result)
                    return execution

                with patch.object(financial_engine, "run_correction_transition_v1", run):
                    with self.assertRaises(FinancialIntegrityError) as caught:
                        self._reject(store, claim_id)
                self.assertEqual(str(caught.exception), f"correction_post_state:{code}")
                self.assertEqual(store.path.read_bytes(), before)
                self._assert_verified(store)

    def test_per_obligation_mode_checks_the_exact_current_inputs(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_final(store)
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            obligation_ids = [str(row[0]) for row in connection.execute("SELECT obligation_id FROM obligations ORDER BY obligation_id")]
            self.assertGreater(len(obligation_ids), 1)
            for obligation_id in obligation_ids:
                self.assertEqual(
                    verify_obligation_connection(connection, obligation_id, expected_config=store.config, expected_authority=self.authority)["obligation_id"],
                    obligation_id,
                )
            corrected = str(connection.execute("SELECT obligation_id FROM claimed_adjustments WHERE status='REJECTED'").fetchone()[0])
            current = "(SELECT current_evaluation_id FROM obligations WHERE obligation_id=:o)"
            tampers = (
                # The current evaluation was computed from a state that is not the one being committed.
                ("obligation:exact-input:claims", "UPDATE claimed_adjustments SET status='CLAIMED' WHERE obligation_id=:o AND status='REJECTED'"),
                ("case:derived", "UPDATE cases SET status='OPEN' WHERE obligation_id=:o"),
                ("obligation:exact-input:actions", "UPDATE actions SET status='CANCELLED' WHERE obligation_id=:o"),
                # A row the evaluation never saw.
                ("obligation:exact-input:evidence", lambda c: store._insert_evidence(c, store._new_evidence(
                    evidence_id="evidence:unseen", item_id=str(c.execute("SELECT item_id FROM obligations WHERE obligation_id=?", (corrected,)).fetchone()[0]),
                    kind="PAYMENT_REVERSAL", common_origin_id="origin:unseen", source_id="synthetic-payment-source",
                    source_version="fixture-v1", local_ref="reversal:unseen", applicable_at_ms=1, event_at_ms=1, received_at_ms=1,
                    amount_cents=1, reversal_of="payment:h:p2"))),
                # Values that the exact inputs do not produce.
                ("evaluation:input-projection:claimed_adjustment_cents", f"UPDATE evaluations SET claimed_adjustment_cents=claimed_adjustment_cents+1 WHERE evaluation_id={current}"),
                ("obligation:projection:shortfall_cents", "UPDATE obligations SET shortfall_cents=shortfall_cents+1 WHERE obligation_id=:o"),
                ("obligation:projection:updated_at_ms", "UPDATE obligations SET updated_at_ms=updated_at_ms+1 WHERE obligation_id=:o"),
            )
            for code, statement in tampers:
                with self.subTest(code=code):
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        if callable(statement):
                            statement(connection)
                        else:
                            self.assertGreaterEqual(connection.execute(statement, {"o": corrected}).rowcount, 1)
                        with self.assertRaisesRegex(IndependentFinancialError, f"^{code}$"):
                            verify_obligation_connection(connection, corrected, expected_config=store.config, expected_authority=self.authority)
                    finally:
                        connection.execute("ROLLBACK")
            with self.assertRaisesRegex(IndependentFinancialError, "^obligation:missing$"):
                verify_obligation_connection(connection, "obligation:absent", expected_config=store.config, expected_authority=self.authority)
        self._assert_verified(store)

    def test_rows_history_does_not_carry_are_recomputed_or_bounded(self) -> None:
        # Final review of 75a5517, finding 3: same-length edits to these fields passed v7 conversion
        # and were sealed. The checker (run before replay) now recomputes each one or bounds it by history
        # (an acknowledgment or a conflict no later than its event; the gap is the one edit room left).
        store = self._build_base_for_correction()
        self._prepare_final(store)
        ack = "(SELECT committed_at_ms FROM financial_events WHERE kind='ACTION_ACKNOWLEDGED')"
        tampers = (
            ("case:derived", "UPDATE cases SET reason='CORRECTION_REQUIREE' WHERE reason='CORRECTION_REQUIRED'"),
            ("case:derived", "UPDATE cases SET reason='INITIAL_ACCOUNTABILITZ' WHERE rowid=1"),
            ("case:derived", "UPDATE cases SET contractual_accountability='PROGRAM_ACCOUNTABILITZ' WHERE rowid=1"),
            ("case:derived", "UPDATE cases SET next_action_owner='CASE_OWNES' WHERE rowid=1"),
            ("case:derived", "UPDATE cases SET due_at_ms=due_at_ms+1 WHERE rowid=1"),
            ("case:derived", "UPDATE cases SET updated_at_ms=updated_at_ms+1 WHERE rowid=1"),
            ("case:derived", "UPDATE claimed_adjustments SET deadline_ms=deadline_ms+1"),
            ("claim:owner", "UPDATE claimed_adjustments SET owner_role='CASE_OWNES'"),
            ("claim:chronology", "UPDATE claimed_adjustments SET created_at_ms=created_at_ms+1"),
            ("claim:chronology", "UPDATE claimed_adjustments SET updated_at_ms=updated_at_ms+1"),
            ("outbox:acknowledged", f"UPDATE action_outbox SET updated_at_ms={ack}+1 WHERE status='ACKNOWLEDGED'"),
            ("outbox:acknowledged", "UPDATE action_outbox SET attempt=2 WHERE status='ACKNOWLEDGED'"),
            ("conflict:visible", "UPDATE financial_conflicts SET visible_at_ms=visible_at_ms+1000"),
        )
        tampered = self._path("rows-tampered.sqlite")
        for index, (code, statement) in enumerate(tampers):
            with self.subTest(index=index, code=code):
                tampered.write_bytes(store.path.read_bytes())
                with closing(sqlite3.connect(str(tampered), isolation_level=None)) as connection:
                    self.assertEqual(connection.execute(statement).rowcount, 1)
                with self.assertRaisesRegex(IndependentFinancialError, f"^{code}$"):
                    verify_database(tampered, expected_config=store.config, expected_authority=self.authority)

    def test_a_forged_opening_balance_event_is_refused_on_a_native_store(self) -> None:
        # Final review of 75a5517, finding 4, kept after C3: an OPENING_BALANCE event appended to a native
        # store would restart replay from rows of the writer's choosing. The kind no longer exists.
        store = self._build_base_for_correction()
        self._prepare_acknowledged(store)
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            self.assertEqual(connection.execute("UPDATE action_outbox SET updated_at_ms=updated_at_ms-1 WHERE status='ACKNOWLEDGED'").rowcount, 1)
        with closing(store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            images = [{"table": table, "row": {column: store._export_value(row[column]) for column in owner._TABLE_COLUMNS[table]}} for table in owner._CAPTURED_TABLES for row in connection.execute(f"SELECT * FROM {table}")]
            last = int(connection.execute("SELECT max(committed_at_ms) FROM financial_events").fetchone()[0])
            store._append_event(connection, aggregate_type="OPENING_BALANCE", aggregate_id="opening-balance", kind="OPENING_BALANCE", before_revision=0, after_revision=0, payload={"rows": images}, committed_at_ms=last)
            connection.execute("COMMIT")
        with self.assertRaisesRegex(IndependentFinancialError, "^history:event-kind$"):
            self._assert_verified(store)
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:history:event-kind$"):
            self._make_owner(path=store.path)

    @staticmethod
    def _rehash_history(path: Path, edit) -> int:
        """Apply ``edit`` to every event payload and re-hash the chain, as a writer with file access could,
        moving a correction follow-up's observed history head along with the chain."""
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            triggers = connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='financial_events'").fetchall()
            for name, _sql in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            events = connection.execute("SELECT event_sequence,aggregate_type,aggregate_id,kind,before_revision,after_revision,payload_json,previous_head,committed_at_ms FROM financial_events ORDER BY event_sequence").fetchall()
            previous, edited = bytes(events[0][7]), 0
            for sequence, aggregate_type, aggregate_id, kind, before, after, payload_json, _previous, committed_at in events:
                payload = json.loads(payload_json)
                edited += bool(edit(payload))
                for observation in payload.get("correction_followup", {}).get("read_observations", {}).values():
                    if observation.get("version_head") == bytes(_previous).hex().upper():
                        observation["version_head"] = previous.hex().upper()
                payload_bytes = owner._canonical(payload)
                payload_digest = owner._digest(owner._EVENT_DOMAIN, payload_bytes)
                header = b"".join(value.to_bytes(8, "big") for value in (before, after, committed_at))
                event_id = owner._digest(owner._EVENT_DOMAIN, sequence.to_bytes(8, "big"), aggregate_type.encode("ascii"), aggregate_id.encode("ascii"), kind.encode("ascii"), header, payload_digest)
                head = owner._digest(owner._HEAD_DOMAIN, previous, event_id, header, payload_digest)
                connection.execute("UPDATE financial_events SET event_id=?,payload_json=?,payload_digest=?,previous_head=?,head=? WHERE event_sequence=?", (event_id, payload_bytes.decode("ascii"), payload_digest, previous, head, sequence))
                previous = head
            connection.execute("UPDATE financial_meta SET history_head=? WHERE id=1", (previous,))
            for _name, sql in triggers:
                connection.execute(sql)
        return edited

    def test_a_rehashed_row_image_cannot_change_the_accepted_acknowledgment(self) -> None:
        # The acknowledgment event names the reference it accepted; the stored row must match it even
        # when the row and its history image are edited together and the chain is re-hashed.
        store = self._build_base_for_correction()
        self._prepare_acknowledged(store)
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            ref = connection.execute("SELECT acknowledgment_ref FROM action_outbox WHERE status='ACKNOWLEDGED'").fetchone()[0]
            forged = ref[:-1] + ("8" if ref.endswith("9") else "9")
            connection.execute("UPDATE action_outbox SET acknowledgment_ref=? WHERE acknowledgment_ref=?", (forged, ref))

        def forge(payload: dict) -> bool:
            images = [image.get("row") or image.get("set") for image in payload.get("rows", ()) if image["table"] == "action_outbox"]
            for values in images:
                if values.get("acknowledgment_ref") == ref:
                    values["acknowledgment_ref"] = forged
            return any(values.get("acknowledgment_ref") == forged for values in images)

        self.assertGreaterEqual(self._rehash_history(store.path, forge), 1)
        with self.assertRaisesRegex(IndependentFinancialError, "^replay:acknowledgment$"):
            self._assert_verified(store)
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:replay:acknowledgment$"):
            self._make_owner(path=store.path)

    def _correction_decided_by_engine(self, sha256: str) -> FinancialOwner:
        # A correction as an earlier pinned engine committed it: the follow-up names that engine.
        store = self._build_base_for_correction()
        self._prepare_rejected(store)

        def name_engine(payload: dict) -> bool:
            artifact = payload.get("correction_followup", {}).get("artifact")
            if artifact is not None:
                artifact["sha256"] = sha256
            return artifact is not None

        self.assertEqual(self._rehash_history(store.path, name_engine), 1)
        return store

    def test_a_correction_decided_by_a_retired_engine_pin_still_opens(self) -> None:
        store = self._correction_decided_by_engine(_RETIRED_CORRECTION_ARTIFACT_SHA256)
        self._assert_verified(store)
        outputs = self._make_owner(path=store.path).correction_followup_outputs(expected.H_ITEM_ID, expected.ACTION_CORRECTION_ID)
        self.assertEqual(outputs["followup_status"], "CURRENT")
        self.assertEqual(outputs["corporate_support"]["artifact"]["sha256"], _RETIRED_CORRECTION_ARTIFACT_SHA256)
        self.assertEqual(outputs["corporate_support"]["reproduction"], "NONE")  # only the pinned engine has a published vector

    def test_a_correction_naming_an_unknown_engine_is_refused(self) -> None:
        store = self._correction_decided_by_engine("AB" * 32)
        self.assertEqual(store.correction_followup_outputs(expected.H_ITEM_ID, expected.ACTION_CORRECTION_ID)["followup_status"], "REVIEW_REQUIRED")
        with self.assertRaisesRegex(IndependentFinancialError, "^history:correction-followup-artifact-binding$"):
            self._assert_verified(store)
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:history:correction-followup-artifact-binding$"):
            self._make_owner(path=store.path)

    def test_a_retired_pin_registry_with_an_extra_line_is_refused(self) -> None:
        store = self._correction_decided_by_engine(_RETIRED_CORRECTION_ARTIFACT_SHA256)
        registry = self._path("RETIRED_PINS")
        registry.write_bytes(independent.RETIRED_PINS_PATH.read_bytes() + b"AB" * 32 + b"\t2026-09-26\tforged\tcorrection-rule-v1\tforged\n")
        with patch.object(independent, "RETIRED_PINS_PATH", registry):
            with self.assertRaisesRegex(IndependentFinancialError, "^history:correction-retired-pins$"):
                self._assert_verified(store)
            with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:history:correction-retired-pins$"):
                self._make_owner(path=store.path)

    def test_a_malformed_retired_pin_registry_is_refused_even_when_pinned(self) -> None:
        store = self._correction_decided_by_engine(_RETIRED_CORRECTION_ARTIFACT_SHA256)
        current = financial_engine.CORRECTION_TRANSITION_ARTIFACT_SHA256.hex().upper().encode("ascii")
        original = independent.RETIRED_PINS_PATH.read_bytes()
        for name, content in (
            ("four-fields", original + b"AB" * 32 + b"\t2026-09-26\tforged\tb2-v1\n"),
            ("unknown-rule", original + b"AB" * 32 + b"\t2026-09-26\tforged\tforged-rule\tforged\n"),
            ("lower-case-sha", original + b"ab" * 32 + b"\t2026-09-26\tforged\tb2-v1\tforged\n"),
            ("duplicate", original + original.splitlines(keepends=True)[0]),
            ("lists-current", original + current + b"\t2026-09-26\tforged\tb2-v1\tforged\n"),
            ("not-ascii", original + "\u00e9".encode("utf-8")),
        ):
            with self.subTest(name):
                registry = self._path(f"RETIRED_PINS-{name}")
                registry.write_bytes(content)
                with patch.object(independent, "RETIRED_PINS_PATH", registry), patch.object(independent, "RETIRED_PINS_SHA256", hashlib.sha256(content).hexdigest()):
                    with self.assertRaisesRegex(IndependentFinancialError, "^history:correction-retired-pins$"):
                        self._assert_verified(store)
                    with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:history:correction-retired-pins$"):
                        self._make_owner(path=store.path)

    def test_a_retired_engine_pin_never_decides_a_new_correction(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        retired = replace(
            _correction_transition_test_release(workspace=Path(self.temp_dir.name) / "correction-engine-workspace"),
            executable_sha256=bytes.fromhex(_RETIRED_CORRECTION_ARTIFACT_SHA256),
        )
        counts = self._durable_counts(store.path)
        with self.assertRaisesRegex(FinancialIntegrityError, "^correction_transition_failed$"):
            self._reject(self._make_owner(path=store.path, correction_transition_release=retired), claim_id)
        self.assertEqual(self._durable_counts(store.path), counts)

    def _as_decided(self, path: Path, sha256: str, requested_cents: int, action_id: str = expected.ACTION_CORRECTION_ID) -> None:
        """Rewrite correction ``action_id`` as engine ``sha256`` decided it, requesting ``requested_cents``: rows, row images, chain."""
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            (payload_json,) = connection.execute("SELECT payload_json FROM actions WHERE action_id=?", (action_id,)).fetchone()
            payload_text = owner._canonical({**json.loads(payload_json), "amount_cents": requested_cents}).decode("ascii")
            digest = owner._digest(owner._ACTION_DOMAIN, payload_text.encode("ascii"))
            triggers = connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('actions','action_outbox')").fetchall()
            for name, _sql in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            connection.execute("UPDATE actions SET payload_json=?,payload_digest=? WHERE action_id=?", (payload_text, digest, action_id))
            connection.execute("UPDATE action_outbox SET payload_digest=? WHERE action_id=?", (digest, action_id))
            for _name, sql in triggers:
                connection.execute(sql)

        def as_decided(payload: dict) -> bool:
            for image in payload.get("rows", ()):
                values = image.get("row", {})
                if image["table"] == "action_outbox" and values.get("action_id") == action_id:
                    values["payload_digest"] = {"hex": digest.hex().upper()}
            artifact = payload.get("correction_followup", {}).get("artifact") if payload.get("action_id") == action_id else None
            if artifact is not None:
                artifact["sha256"] = sha256
            return artifact is not None

        self.assertEqual(self._rehash_history(path, as_decided), 1)

    def test_history_is_judged_by_the_amount_rule_of_the_engine_that_decided_it(self) -> None:
        # rr-review M1: E911 requested the whole claim (correction-rule-v1), 88D8 the unpaid balance (b2-v1).
        # A 300,000 claim rejected on 100,000 unpaid is valid history only as the engine it names decided it,
        # and never requesting more than was requestable: E911's whole claim is refused (round 3 #1).
        store = self._build_base_for_correction()
        cash = expected.H_CASH_EVIDENCE
        store.record_payment_evidence(
            item_id=cash.item_id, payment_id="payment:h:cash", common_origin_id=cash.common_origin_id,
            amount_cents=expected.H_OWED_CENTS - 100_000, evidence_id=cash.evidence_id, event_at_ms=cash.event_at_ms,
            source_id=cash.source_id, source_version=cash.source_version, local_ref=cash.local_ref,
        )
        self._reject(store, self._record_claim(store))
        current = financial_engine.CORRECTION_TRANSITION_ARTIFACT_SHA256.hex().upper()
        for name, sha256, requested_cents, refusal in (
            ("e911-whole-claim", _RETIRED_CORRECTION_ARTIFACT_SHA256, 300_000, "action:requestable"),
            ("e911-unpaid-balance", _RETIRED_CORRECTION_ARTIFACT_SHA256, 100_000, "action:payload-binding"),
            ("88d8-unpaid-balance", _B2_CORRECTION_ARTIFACT_SHA256, 100_000, None),
            ("current-whole-claim", current, 300_000, "action:payload-binding"),
        ):
            with self.subTest(name):
                path = self._path(f"{name}.sqlite")
                path.write_bytes(store.path.read_bytes())
                self._as_decided(path, sha256, requested_cents)
                if refusal is None:
                    verify_database(path, expected_config=store.config, expected_authority=self.authority)
                    self._make_owner(path=path)
                else:
                    with self.assertRaisesRegex(IndependentFinancialError, f"^{refusal}$"):
                        verify_database(path, expected_config=store.config, expected_authority=self.authority)

    def _two_claim_corrections(self, first_cents: int, second_cents: int, unpaid_cents: int = expected.UNAPPROVED_OFFSET_CENTS) -> tuple[FinancialOwner, object]:
        """``unpaid_cents`` unpaid with claims A and B; A is rejected with a correction; returns B's rejection to call."""
        store = self._build_base_for_correction()
        cash = expected.H_CASH_EVIDENCE
        store.record_payment_evidence(
            item_id=cash.item_id, payment_id="payment:h:cash", common_origin_id=cash.common_origin_id,
            amount_cents=expected.H_OWED_CENTS - unpaid_cents, evidence_id=cash.evidence_id, event_at_ms=cash.event_at_ms,
            source_id=cash.source_id, source_version=cash.source_version, local_ref=cash.local_ref,
        )
        for suffix, cents in (("a", first_cents), ("b", second_cents)):
            store.record_offset_claim(
                item_id=expected.H_ITEM_ID, claim_id=f"claim:obligation-item-h:offset-{suffix}", amount_cents=cents,
                evidence_id=f"evidence:offset-h:claim-{suffix}", owner_role="CASE_OWNER", deadline_ms=expected.H_DUE_AT_MS,
            )
        self._reject(store, "claim:obligation-item-h:offset-a")
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID)["shortfall_cents"], unpaid_cents)  # rejecting A leaves it unpaid

        def reject_b() -> dict[str, object]:
            receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
            self._advance_clock(store, expected.CORRECTION_AUTH_MS + 1_000)  # B is decided after A committed
            return store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID, claim_id="claim:obligation-item-h:offset-b", expected_revision=receipt["revision"],
                action_id=_ACTION_B, decision_at_ms=expected.CORRECTION_AUTH_MS + 1_000,
                evaluation_id=receipt["evaluation_id"], evaluation_result_digest=receipt["result_digest"],
            )

        return store, reject_b

    @staticmethod
    def _pay_a(store: FinancialOwner, cents: int, suffix: str = "p2", *, linked: bool = True) -> dict[str, object]:
        """A cash payment of ``cents`` after A's decision, answering A's correction request when ``linked``."""
        RightRailFinancialAcceptanceTests._advance_clock(store, expected.CORRECTION_AUTH_MS + 500)
        return store.record_payment_evidence(
            item_id=expected.H_ITEM_ID, payment_id=f"payment:h:{suffix}", common_origin_id=f"origin:payment:h:{suffix}",
            amount_cents=cents, evidence_id=f"evidence:payment-h:{suffix}", event_at_ms=expected.CORRECTION_AUTH_MS + 500,
            source_id="fixture-payment-file", source_version="payment-v2", local_ref=f"ref:payment:h:{suffix}",
            pays_action_id=expected.ACTION_CORRECTION_ID if linked else None,
        )

    @staticmethod
    def _requested_and_claimed(store: FinancialOwner) -> tuple[list[int], list[int]]:
        """Correction request amounts (action rows) and decision event amounts, in decision order."""
        with closing(sqlite3.connect(str(store.path))) as connection:
            requested = [json.loads(row[0])["amount_cents"] for row in connection.execute("SELECT payload_json FROM actions WHERE kind='CORRECTION_PAYMENT_REQUEST' ORDER BY revision")]
            claimed = [row[0] for row in connection.execute("SELECT json_extract(payload_json,'$.amount_cents') FROM financial_events WHERE kind='OFFSET_REJECTED_CORRECTION_AUTHORIZED' ORDER BY event_sequence")]
        return requested, claimed

    def test_a_second_correction_on_a_fully_requested_balance_is_refused(self) -> None:
        # rr-review H1: two 300,000 claims on 300,000 unpaid requested 600,000; the second now requests nothing.
        store, reject_b = self._two_claim_corrections(300_000, 300_000)
        counts = self._durable_counts(store.path)
        with self.assertRaisesRegex(FinancialConflictError, "^correction_no_requestable_balance$"):
            reject_b()
        self.assertEqual(self._durable_counts(store.path), counts)
        self.assertEqual(self._requested_and_claimed(store), ([300_000], [300_000]))
        self._assert_verified(store)
        self._make_owner(path=store.path)

    def test_a_second_correction_requests_only_what_is_left(self) -> None:
        # rr-review H1: claims of 200,000 and 200,000 on 300,000 unpaid request 200,000, then the 100,000 left.
        # The decision events keep each claim's amount (L4); only the action rows carry the request.
        store, reject_b = self._two_claim_corrections(200_000, 200_000)
        reject_b()
        self.assertEqual(self._requested_and_claimed(store), ([200_000, 100_000], [200_000, 200_000]))
        self._assert_verified(store)
        self._make_owner(path=store.path)

    def test_a_paid_correction_request_no_longer_blocks_the_next(self) -> None:
        # rr-review round 3 #2: 600,000 unpaid, claims A and B of 300,000. A requests 300,000 and is paid;
        # 300,000 is still unpaid and no unpaid request covers it, so B requests it. A payment that
        # names no request is plain cash: A still looks unpaid and B has nothing left to request. A
        # reversed payment pays nothing: 600,000 is unpaid again, A asks for 300,000, so B's 400,000
        # claim requests the other 300,000.
        for linked, reversed_, b_cents, requested in ((True, False, 300_000, [300_000, 300_000]), (False, False, 300_000, [300_000]), (True, True, 400_000, [300_000, 300_000])):
            with self.subTest(linked=linked, reversed=reversed_):
                store, reject_b = self._two_claim_corrections(300_000, b_cents, unpaid_cents=600_000)
                self._pay_a(store, 300_000, linked=linked)
                if reversed_:
                    store.reverse_payment(item_id=expected.H_ITEM_ID, payment_id="payment:h:p2", evidence_id="evidence:reversal-h:p2")
                if linked:
                    reject_b()
                else:
                    with self.assertRaisesRegex(FinancialConflictError, "^correction_no_requestable_balance$"):
                        reject_b()
                self.assertEqual(self._requested_and_claimed(store)[0], requested)
                self._assert_verified(store)
                self._make_owner(path=store.path)

    def test_a_partly_paid_correction_request_counts_only_its_unpaid_part(self) -> None:
        # 600,000 unpaid; A requests 300,000 and 100,000 of it is paid; B's 400,000 claim requests the
        # 500,000 still unpaid less A's unpaid 200,000.
        store, reject_b = self._two_claim_corrections(300_000, 400_000, unpaid_cents=600_000)
        self._pay_a(store, 100_000)
        reject_b()
        self.assertEqual(self._requested_and_claimed(store), ([300_000, 300_000], [300_000, 400_000]))
        self._assert_verified(store)
        self._make_owner(path=store.path)

    def test_a_payment_never_pays_more_than_its_request_leaves_unpaid(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        self._reject(store, self._record_claim(store))
        self.assertEqual(self._pay_a(store, 200_000)["status"], "RECORDED")
        counts = self._durable_counts(store.path)
        with self.assertRaisesRegex(FinancialConflictError, "^payment_exceeds_unpaid_request$"):
            self._pay_a(store, 100_001, "p3")
        with self.assertRaisesRegex(FinancialConflictError, "^payment_request_unknown$"):
            store.record_payment_evidence(
                item_id=expected.H_ITEM_ID, payment_id="payment:h:p4", common_origin_id="origin:payment:h:p4", amount_cents=1,
                evidence_id="evidence:payment-h:p4", event_at_ms=expected.CORRECTION_AUTH_MS + 500, pays_action_id=_ACTION_B,
            )
        self.assertEqual(self._durable_counts(store.path), counts)
        self.assertEqual(self._pay_a(store, 100_000, "p3")["status"], "RECORDED")  # exactly what is left
        self._assert_verified(store)
        # The checker refuses a link the Owner would not have written.

        def link_cash(payload: dict) -> bool:  # the cash paid before the request existed
            if payload.get("payment_id") == "payment:h:cash" and "common_origin_id" in payload:
                payload["pays_action_id"] = expected.ACTION_CORRECTION_ID
                return True
            return False

        early = self._path("early-link.sqlite")
        early.write_bytes(store.path.read_bytes())
        self.assertEqual(self._rehash_history(early, link_cash), 1)
        with self.assertRaisesRegex(IndependentFinancialError, "^payment:link$"):
            verify_database(early, expected_config=store.config, expected_authority=self.authority)

    def test_a_resent_payment_source_cannot_change_its_link(self) -> None:
        # rr-review round 3 LOW #3: a source already recorded is a duplicate only if the link it carries matches.
        store = self._build_base_for_correction()
        self._record_cash(store)
        self._reject(store, self._record_claim(store))
        self._pay_a(store, 100_000)
        self._pay_a(store, 50_000, "p3", linked=False)

        def resend(suffix: str, pays_action_id: str | None, document: str = "") -> dict[str, object]:
            return store.record_payment_evidence(
                item_id=expected.H_ITEM_ID, payment_id=f"payment:h:resent-{suffix}", common_origin_id=f"origin:payment:h:{suffix}",
                amount_cents=100_000 if suffix == "p2" else 50_000, evidence_id=f"evidence:payment-h:resent-{suffix}{document}",
                event_at_ms=expected.CORRECTION_AUTH_MS + 500, pays_action_id=pays_action_id,
            )

        counts = self._durable_counts(store.path)
        for suffix, link in (("p2", _ACTION_B), ("p3", expected.ACTION_CORRECTION_ID), ("p3", _ACTION_B)):
            with self.subTest(suffix=suffix, link=link), self.assertRaisesRegex(FinancialConflictError, "^payment_request_conflict$"):
                resend(suffix, link)
        self.assertEqual(self._durable_counts(store.path), counts)
        self.assertEqual(resend("p2", expected.ACTION_CORRECTION_ID)["status"], "DUPLICATE")
        # A bank confirmation of a linked payment is its own document and does not know the internal link:
        # it corroborates, never conflicts.
        self.assertEqual(resend("p2", None, ":bank")["status"], "DUPLICATE")
        self.assertEqual(resend("p3", None, ":bank")["status"], "DUPLICATE")
        self._assert_verified(store)

    def test_a_forged_duplicate_label_cannot_hide_a_new_payment(self) -> None:
        # rr-review H1: a PAYMENT_DUPLICATE_EVIDENCE event appended over a real new payment's confirmation
        # neither closes the correction's follow-up nor passes the checker.
        store = self._build_base_for_correction()
        self._record_cash(store)
        self._reject(store, self._record_claim(store))
        self._pay_a(store, 1, linked=False)
        with store._write() as connection:
            obligation_id, revision, origin = connection.execute(
                "SELECT obligation_id,o.revision,p.common_origin_id FROM obligations o JOIN payments p USING(obligation_id) WHERE p.payment_id='payment:h:cash'"
            ).fetchone()
            store._append_event(
                connection, aggregate_type="OBLIGATION", aggregate_id=obligation_id, kind="PAYMENT_DUPLICATE_EVIDENCE", before_revision=revision,
                after_revision=revision, committed_at_ms=store._now(),
                payload={"candidate_evidence_id": "evidence:payment-h:p2", "existing_payment_id": "payment:h:cash", "common_origin_id": origin},
            )
        outputs = store.correction_followup_outputs(expected.H_ITEM_ID, expected.ACTION_CORRECTION_ID)
        self.assertEqual((outputs["followup_status"], outputs["state_report"]["changed_dependencies"]), ("REOPENED", [f"COLLECTION(PAYMENT_EVIDENCE, {expected.H_ITEM_ID})"]))
        with self.assertRaisesRegex(IndependentFinancialError, "^duplicate-evidence:binding$"):
            self._assert_verified(store)
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:duplicate-evidence:binding$"):
            self._make_owner(path=store.path)

    def test_a_relabelled_second_correction_is_refused(self) -> None:
        # rr-review round 3 #1: 300,000 unpaid, claims A and B of 200,000; honest requests are 200,000
        # then 100,000. Relabelling B as decided by a retired engine that requests 200,000 (400,000 on
        # 300,000) is refused whichever retired engine it names, and so is a retired engine deciding
        # after a newer one even when the amount fits (only the engine-order check sees that).
        store, reject_b = self._two_claim_corrections(200_000, 200_000)
        reject_b()
        for name, sha256, cents, refusal in (
            ("b2-v1", _B2_CORRECTION_ARTIFACT_SHA256, 200_000, "action:engine-order"),
            ("e911", _RETIRED_CORRECTION_ARTIFACT_SHA256, 200_000, "action:engine-order"),
        ):
            with self.subTest(name):
                path = self._path(f"relabel-{name}.sqlite")
                path.write_bytes(store.path.read_bytes())
                self._as_decided(path, sha256, cents, _ACTION_B)
                with self.assertRaisesRegex(IndependentFinancialError, f"^{refusal}$"):
                    verify_database(path, expected_config=store.config, expected_authority=self.authority)
        order_only, reject_b = self._two_claim_corrections(200_000, 100_000)
        reject_b()
        self.assertEqual(self._requested_and_claimed(order_only)[0], [200_000, 100_000])
        path = self._path("relabel-order-only.sqlite")
        path.write_bytes(order_only.path.read_bytes())
        self._as_decided(path, _B2_CORRECTION_ARTIFACT_SHA256, 100_000, _ACTION_B)
        with self.assertRaisesRegex(IndependentFinancialError, "^action:engine-order$"):
            verify_database(path, expected_config=order_only.config, expected_authority=self.authority)
        # Retired before current is the order history really has: A as E911 decided it, then B.
        path = self._path("retired-then-current.sqlite")
        path.write_bytes(store.path.read_bytes())
        self._as_decided(path, _RETIRED_CORRECTION_ARTIFACT_SHA256, 200_000)
        verify_database(path, expected_config=store.config, expected_authority=self.authority)
        self._make_owner(path=path)

    def test_a_cancelled_correction_or_changed_decision_amount_is_refused(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_rejected(store)
        cancelled = self._path("cancelled.sqlite")
        cancelled.write_bytes(store.path.read_bytes())
        with closing(sqlite3.connect(str(cancelled), isolation_level=None)) as connection:  # actions rows carry no history image
            self.assertEqual(connection.execute("UPDATE actions SET status='CANCELLED' WHERE action_id=?", (expected.ACTION_CORRECTION_ID,)).rowcount, 1)
        with self.assertRaisesRegex(IndependentFinancialError, "^action:status$"):
            verify_database(cancelled, expected_config=store.config, expected_authority=self.authority)

        def change_amount(payload: dict) -> bool:
            if payload.get("action_id") == expected.ACTION_CORRECTION_ID and "correction_followup" in payload:
                payload["amount_cents"] += 1
                return True
            return False

        changed = self._path("decision-amount.sqlite")
        changed.write_bytes(store.path.read_bytes())
        self.assertEqual(self._rehash_history(changed, change_amount), 1)
        with self.assertRaisesRegex(IndependentFinancialError, "^action:event-amount$"):
            verify_database(changed, expected_config=store.config, expected_authority=self.authority)

    def test_every_current_evaluation_saw_the_rows_as_they_are(self) -> None:
        # Final review of 75a5517, finding 5: publish opened the case after the first evaluation,
        # and only the per-obligation mode compared a current evaluation with the current rows.
        store = self._build_base_for_correction()
        self._prepare_final(store)
        with closing(sqlite3.connect(str(store.path))) as connection:
            obligation_id, snapshot = connection.execute(
                "SELECT obligation_id,input_snapshot_json FROM evaluations WHERE revision=0 ORDER BY obligation_id LIMIT 1"
            ).fetchone()
        self.assertEqual(json.loads(snapshot)["cases"], [{"case_id": f"case:{obligation_id}", "status": "OPEN"}])
        tampered = self._path("unseen-evidence.sqlite")
        tampered.write_bytes(store.path.read_bytes())
        with closing(sqlite3.connect(str(tampered), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            store._insert_evidence(connection, store._new_evidence(
                evidence_id="evidence:unseen", item_id=expected.H_ITEM_ID, kind="SUPPORT", common_origin_id="origin:unseen",
                source_id="synthetic-support-source", source_version="fixture-v1", local_ref="support:unseen",
                applicable_at_ms=1, event_at_ms=1, received_at_ms=1))
        with self.assertRaisesRegex(IndependentFinancialError, "^obligation:exact-input:evidence$"):
            verify_database(tampered, expected_config=store.config, expected_authority=self.authority)
        # A repeated payment confirmation is stored without a new evaluation and stays verifiable.
        repeat = expected.P2_CONFIRMATION_EVIDENCE
        self.assertEqual(store.record_payment_evidence(
            item_id=repeat.item_id, payment_id="payment:h:p2-repeat", common_origin_id=repeat.common_origin_id,
            amount_cents=repeat.amount_cents or 0, evidence_id="evidence:p2-repeat", event_at_ms=repeat.event_at_ms,
            source_id=repeat.source_id, source_version=repeat.source_version, local_ref="ref:p2-repeat",
        )["status"], "DUPLICATE")
        with closing(sqlite3.connect(str(store.path))) as connection:
            self.assertEqual(connection.execute("SELECT kind FROM financial_events ORDER BY event_sequence DESC LIMIT 1").fetchone(), ("PAYMENT_DUPLICATE_EVIDENCE",))
        self._assert_verified(store)

    def test_a_new_claim_does_not_hide_an_outstanding_correction(self) -> None:
        # B1: a later claim reset the case to OPEN with the claimant's owner and deadline while the correction was READY.
        claim_b = {"item_id": expected.H_ITEM_ID, "claim_id": "claim:obligation-item-h:offset-b", "amount_cents": 1000,
                   "evidence_id": "evidence:offset-h:claim-b", "owner_role": "RECEIVER", "deadline_ms": expected.H_DUE_AT_MS + 86_400_000}
        query = "SELECT reason,next_action_owner,due_at_ms,status FROM cases WHERE obligation_id=?"

        def corrected() -> FinancialOwner:
            store = self._build_base_for_correction()
            self._record_cash(store)
            self._reject(store, self._record_claim(store))
            self._advance_clock(store, expected.CORRECTION_AUTH_MS + 60_000)
            return store

        store = corrected()
        with closing(sqlite3.connect(str(store.path))) as connection:
            before = connection.execute(query, (expected.H_OBLIGATION_ID,)).fetchone()
        self.assertEqual((before[0], before[3]), ("CORRECTION_REQUIRED", "CORRECTION_REQUIRED"))
        self.assertEqual(store.record_offset_claim(**claim_b)["status"], "CLAIMED")
        with closing(sqlite3.connect(str(store.path))) as connection:
            self.assertEqual(connection.execute(query, (expected.H_OBLIGATION_ID,)).fetchone(), before)
            self.assertEqual(connection.execute("SELECT status FROM claimed_adjustments WHERE claim_id=?", (claim_b["claim_id"],)).fetchone(), ("CLAIMED",))
            self.assertEqual(connection.execute("SELECT status FROM actions WHERE action_id=?", (expected.ACTION_CORRECTION_ID,)).fetchone(), ("READY",))
        self._assert_verified(store)

        def reset(_owner, connection, *, obligation_id, reason, owner, due_at_ms, status, now_ms):  # the old rule
            connection.execute("UPDATE cases SET reason=?,next_action_owner=?,due_at_ms=?,status=?,updated_at_ms=? WHERE obligation_id=?", (reason, owner, due_at_ms, status, now_ms, obligation_id))

        hidden = corrected()
        with patch.object(FinancialOwner, "_ensure_case", reset):
            hidden.record_offset_claim(**claim_b)
        with self.assertRaisesRegex(IndependentFinancialError, "^evaluation:input-projection:case_status$"):
            self._assert_verified(hidden)

    def test_retries_are_answered_from_the_command_log(self) -> None:
        store = self._build_base_for_correction()
        claim_id = self._prepare_acknowledged(store)
        receipt = self._funding_receipt()
        self.assertEqual(store.record_program_funding_receipt(receipt)["status"], "RECORDED")
        pack = self._pack(expected.CONTROL_PACK_V1)
        manifest = self._population_manifest()
        with closing(sqlite3.connect(str(store.path))) as connection:
            decision = json.loads(connection.execute(
                "SELECT request_json FROM commands WHERE command_id=?",
                (f"OFFSET_DECISION:{expected.ACTION_CORRECTION_ID}",),
            ).fetchone()[0])

        def reject(**changes: object) -> dict[str, object]:
            request = {
                "item_id": expected.H_ITEM_ID,
                "claim_id": claim_id,
                "action_id": expected.ACTION_CORRECTION_ID,
                "actor_id": decision["actor_id"],
                "actor_role": decision["actor_role"],
                "expected_revision": decision["expected_revision"],
                "decision_at_ms": decision["decided_at_ms"],
                "evaluation_id": decision["evaluation_id"],
                "evaluation_result_digest": decision["evaluation_result_digest"],
            }
            return store.reject_offset_and_authorize_correction(**{**request, **changes})

        def claim(**changes: object) -> dict[str, object]:
            request = {
                "item_id": expected.H_ITEM_ID,
                "claim_id": claim_id,
                "amount_cents": expected.OFFSET_CLAIM_EVIDENCE.amount_cents or 0,
                "evidence_id": expected.OFFSET_CLAIM_EVIDENCE.evidence_id,
                "owner_role": "CASE_OWNER",
                "deadline_ms": expected.H_DUE_AT_MS,
            }
            return store.record_offset_claim(**{**request, **changes})

        cases = (
            ("control-pack", lambda: store.publish_control_pack(pack),
             lambda: store.publish_control_pack(replace(pack, recorded_at_ms=pack.recorded_at_ms - 1)),
             "control_pack_identity_conflict"),
            ("manifest", lambda: store.register_population_manifest(manifest),
             lambda: store.register_population_manifest(replace(manifest, source_digest=bytes.fromhex("FF" * 64))),
             "population_manifest_identity_conflict"),
            ("funding", lambda: store.record_program_funding_receipt(receipt),
             lambda: store.record_program_funding_receipt(replace(receipt, amount_cents=receipt.amount_cents + 1)),
             "program_funding_receipt_identity_conflict"),
            ("acknowledgment", lambda: store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:v1"),
             lambda: store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:other"),
             "acknowledgment_conflict"),
            ("decision", reject,
             lambda: reject(decision_at_ms=decision["decided_at_ms"] + 1),
             "determination_request_conflict"),
            # Review 466178b: a None claim or actor is a changed request, not an omitted optional field.
            ("decision-claim-none", reject, lambda: reject(claim_id=None), "determination_request_conflict"),
            ("decision-actor-none", reject, lambda: reject(actor_id=None, actor_role=None), "determination_request_conflict"),
            # Review 466178b: an offset-claim retry must match every logged field.
            ("claim-deadline", claim, lambda: claim(deadline_ms=expected.H_DUE_AT_MS + 999), "offset_claim_identity_conflict"),
            ("claim-evidence", claim, lambda: claim(evidence_id="evidence:other-claim"), "offset_claim_identity_conflict"),
            ("claim-amount", claim,
             lambda: claim(amount_cents=(expected.OFFSET_CLAIM_EVIDENCE.amount_cents or 0) + 1),
             "offset_claim_identity_conflict"),
        )
        package = store.export_continuity()
        for label, retry, changed, code in cases:
            with self.subTest(label=label):
                self.assertEqual(retry()["status"], "DUPLICATE")
                self.assertEqual(store.export_continuity(), package)
                with self.assertRaisesRegex(FinancialConflictError, f"^{code}$"):
                    changed()
                self.assertEqual(store.export_continuity(), package)
        self._assert_verified(store)

    def test_fresh_reversal_of_a_reversed_payment_is_refused_without_writing(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_reported(store)
        reversal = expected.P2_REVERSAL_EVIDENCE
        self._advance_clock(store, reversal.event_at_ms)
        store.reverse_payment(
            item_id=reversal.item_id,
            payment_id="payment:h:p2",
            evidence_id=reversal.evidence_id,
            common_origin_id=reversal.common_origin_id,
            event_at_ms=reversal.event_at_ms,
        )
        before = store.path.read_bytes()
        # Review 466178b: this answered DUPLICATE yet wrote an evidence row no event explains.
        with self.assertRaisesRegex(FinancialConflictError, "^payment_already_reversed$"):
            store.reverse_payment(item_id=reversal.item_id, payment_id="payment:h:p2", evidence_id="evidence:second-reversal")
        self.assertEqual(store.path.read_bytes(), before)
        self._assert_verified(store)

    def test_parent_removed_by_an_outside_writer_is_an_integrity_failure(self) -> None:
        store = self._build_base_for_correction()
        self._prepare_rejected(store)
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.execute("DELETE FROM obligations WHERE obligation_id=?", (expected.H_OBLIGATION_ID,))
        for label, call in (
            ("retry", lambda: store.retry_action(expected.ACTION_CORRECTION_ID)),
            ("acknowledge", lambda: store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:v1")),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(FinancialIntegrityError, "^obligation_missing$"):
                call()

    def test_checker_requires_every_foreign_key_to_be_deferred(self) -> None:
        store = self._build_base()
        self._assert_verified(store)
        # PRAGMA foreign_key_list cannot show deferral; the checker reads the table SQL.
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute(
                "UPDATE sqlite_master SET sql=replace(sql,' DEFERRABLE INITIALLY DEFERRED','') WHERE type='table' AND name='commands'"
            )
        with self.assertRaisesRegex(IndependentFinancialError, "^schema:foreign-keys:commands$"):
            verify_database(store.path, expected_config=store.config, expected_authority=self.authority)

    def test_checker_refuses_a_hidden_partial_index(self) -> None:
        # The checker's event lookups use an index the Owner wrote: one that silently omits rows must not pass.
        store = self._build_base()
        name, table, columns = "rr_financial_v2_events_aggregate_kind", "financial_events", ("aggregate_type", "aggregate_id", "kind")
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.execute(f'DROP INDEX "{name}"')
            connection.execute(owner._private_index_sql(name, table, columns) + " WHERE aggregate_type<>'OBLIGATION'")
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute("UPDATE sqlite_master SET sql=? WHERE name=?", (owner._private_index_sql(name, table, columns), name))
        with self.assertRaisesRegex(IndependentFinancialError, "^schema:index-integrity$"):
            verify_database(store.path, expected_config=store.config, expected_authority=self.authority)

    def test_owner_open_refuses_an_index_whose_keys_do_not_match_its_rows(self) -> None:
        # Right entry count, wrong keys, canonical SQL: quick_check passes it and the index answers without one evidence row.
        store = self._build_base()
        name, hidden = "rr_financial_v1_evidence_item_id", expected.OTHER_SUPPORT_EVIDENCE[0]
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.execute(f'DROP INDEX "{name}"')
            connection.execute(f"CREATE INDEX {name} ON evidence(CASE WHEN evidence_id='{hidden.evidence_id}' THEN '' ELSE item_id END,evidence_id)")
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute("UPDATE sqlite_master SET sql=? WHERE name=?", (owner._private_index_sql(name, "evidence", ("item_id", "evidence_id")), name))
        with closing(sqlite3.connect(str(store.path))) as connection:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertNotIn((hidden.evidence_id,), connection.execute("SELECT evidence_id FROM evidence WHERE item_id=?", (hidden.item_id,)).fetchall())
        before = store.path.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification:schema:index-integrity$"):
            self._make_owner(path=store.path)
        self.assertEqual(store.path.read_bytes(), before)

    def test_per_obligation_mode_runs_no_file_level_check(self) -> None:
        # It runs inside a correction's write lock; the file-wide integrity_check belongs to the open and whole-store modes.
        store = self._build_base()
        statements: list[str] = []
        file_checks = lambda: [statement for statement in statements if "integrity_check" in statement or "quick_check" in statement]
        with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            connection.set_trace_callback(statements.append)
            obligation_id = str(connection.execute("SELECT obligation_id FROM obligations ORDER BY obligation_id").fetchone()[0])
            self.assertEqual(verify_obligation_connection(connection, obligation_id, expected_config=store.config, expected_authority=self.authority)["obligation_id"], obligation_id)
            self.assertEqual(file_checks(), [])
            verify_database_connection(connection, expected_config=store.config, expected_authority=self.authority)
            self.assertEqual(file_checks(), ["PRAGMA integrity_check"])  # the trace does see the whole-store check

    def test_fixture_has_twelve_cases_and_no_production_import(self) -> None:
        self.assertEqual(tuple(case.number for case in expected.ACCEPTANCE_CASES), tuple(range(1, 13)))
        fixture_source = Path(expected.__file__).read_text(encoding="utf-8")
        self.assertNotIn("right_rail_financial_owner", fixture_source)
        self.assertNotIn("sqlite3", fixture_source)
        self.assertEqual(expected.PROGRAM_TOTAL_CENTS, expected.H_OWED_CENTS + expected.OTHER_TOTAL_CENTS)


if __name__ == "__main__":
    unittest.main()
