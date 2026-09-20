"""Twelve-case synthetic acceptance matrix for the RightRail financial owner.

The expected values are imported only from the fixed, application-independent fixture.  This
module never derives expected balances from owner code or reaches the database through SQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

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
    FinancialRevisionError,
    PopulationItem,
    SyntheticTrustedAuthority,
)
from app.right_rail_financial_mirror import FinancialMirror
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_database, verify_continuity_package
from tests import rightrail_financial_expected_cases as expected


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
    ) -> None:
        self._fault = fault
        super().__init__(
            path=path,
            config=config,
            trusted_authority=trusted_authority,
            clock=clock,
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
from tests.test_right_rail_financial_acceptance import _Clock, _WriteBoundaryOwner

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


class RightRailFinancialAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-financial-acceptance-")
        self.addCleanup(self.temp_dir.cleanup)
        self._path_counter = 0
        self.authority = SyntheticTrustedAuthority()

    def _path(self, name: str | None = None) -> Path:
        self._path_counter += 1
        return Path(self.temp_dir.name) / (name or f"owner-{self._path_counter}.sqlite")

    def _make_owner(
        self,
        *,
        period_id: str = expected.PERIOD_ONE_ID,
        path: Path | None = None,
        clock: _Clock | None = None,
    ) -> FinancialOwner:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=period_id,
            currency=expected.CURRENCY,
        )
        return FinancialOwner(
            path=path or self._path(),
            config=config,
            trusted_authority=self.authority,
            clock=clock or _Clock(),
        )

    def _make_write_boundary_owner(
        self,
        *,
        fault: str,
        period_id: str = expected.PERIOD_ONE_ID,
        path: Path,
        clock: _Clock | None = None,
    ) -> _WriteBoundaryOwner:
        config = FinancialOwnerConfig(
            state_id=expected.STATE_ID,
            deployment_id=expected.DEPLOYMENT_ID,
            program_id=expected.PROGRAM_ID,
            period_id=period_id,
            currency=expected.CURRENCY,
        )
        return _WriteBoundaryOwner(
            path=path,
            config=config,
            trusted_authority=self.authority,
            clock=clock or _Clock(),
            fault=fault,
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
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in tables
            }

    def _run_process_boundary(
        self,
        *,
        store: FinancialOwner,
        claim_id: str,
        fault: str,
        clock_value: int,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _PROCESS_BOUNDARY_CHILD,
                str(store.path),
                claim_id,
                fault,
                str(clock_value),
            ],
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
            self.fail(f"process_boundary_timeout stdout={stdout!r} stderr={stderr!r}")
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    @staticmethod
    def _pack(value: expected.ControlPackExpectation) -> ControlPack:
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

    @staticmethod
    def _items(population_id: str) -> tuple[PopulationItem, ...]:
        return tuple(
            PopulationItem(
                population_id=population_id,
                item_id=item.item_id,
                display_label=item.display_label,
                owed_cents=item.owed_cents,
                due_at_ms=item.due_at_ms,
                currency=item.currency,
            )
            for item in expected.PROGRAM_ITEMS
        )

    def _build_base(
        self,
        *,
        period_id: str = expected.PERIOD_ONE_ID,
        population_id: str = expected.POPULATION_ONE_ID,
        clock: _Clock | None = None,
    ) -> FinancialOwner:
        owner = self._make_owner(period_id=period_id, clock=clock)
        pack_expectation = expected.CONTROL_PACK_V1 if period_id == expected.PERIOD_ONE_ID else expected.CONTROL_PACK_V2
        pack = self._pack(pack_expectation)
        owner.publish_control_pack(pack)
        owner.stage_population(
            population_id=population_id,
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

    @staticmethod
    def _record_support(store: FinancialOwner, evidence: expected.EvidenceExpectation) -> None:
        store.record_support_evidence(
            item_id=evidence.item_id,
            evidence_id=evidence.evidence_id,
            common_origin_id=evidence.common_origin_id,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            local_ref=evidence.local_ref,
            applicable_at_ms=evidence.applicable_at_ms,
            event_at_ms=evidence.event_at_ms,
            received_at_ms=evidence.received_at_ms,
        )

    @staticmethod
    def _record_h_support(store: FinancialOwner) -> None:
        evidence = expected.OFFSET_SUPPORT_EVIDENCE
        RightRailFinancialAcceptanceTests._record_support(store, evidence)

    @staticmethod
    def _record_cash(store: FinancialOwner) -> None:
        evidence = expected.H_CASH_EVIDENCE
        store.record_payment_evidence(
            item_id=evidence.item_id,
            payment_id="payment:h:cash",
            common_origin_id=evidence.common_origin_id,
            amount_cents=evidence.amount_cents or 0,
            evidence_id=evidence.evidence_id,
            event_at_ms=evidence.event_at_ms,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            local_ref=evidence.local_ref,
        )

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
        store.record_payment_evidence(
            item_id=evidence.item_id,
            payment_id="payment:h:p2",
            common_origin_id=evidence.common_origin_id,
            amount_cents=evidence.amount_cents or 0,
            evidence_id=evidence.evidence_id,
            event_at_ms=evidence.event_at_ms,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            local_ref=evidence.local_ref,
        )

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
        duplicate_result = store.record_payment_evidence(
            item_id=duplicate.item_id,
            payment_id="payment:h:p2-confirmation",
            common_origin_id=duplicate.common_origin_id,
            amount_cents=duplicate.amount_cents or 0,
            evidence_id=duplicate.evidence_id,
            event_at_ms=duplicate.event_at_ms,
            source_id=duplicate.source_id,
            source_version=duplicate.source_version,
            local_ref=duplicate.local_ref,
        )
        self.assertEqual(duplicate_result["status"], "DUPLICATE")
        conflict = expected.P2_CONFLICT_EVIDENCE
        conflict_result = store.record_payment_evidence(
            item_id=conflict.item_id,
            payment_id="payment:h:p2-conflict",
            common_origin_id=conflict.common_origin_id,
            amount_cents=conflict.amount_cents or 0,
            evidence_id=conflict.evidence_id,
            event_at_ms=conflict.event_at_ms,
            source_id=conflict.source_id,
            source_version=conflict.source_version,
            local_ref=conflict.local_ref,
        )
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
        store.record_payment_evidence(
            item_id=replacement.item_id,
            payment_id="payment:h:p3",
            common_origin_id=replacement.common_origin_id,
            amount_cents=replacement.amount_cents or 0,
            evidence_id=replacement.evidence_id,
            event_at_ms=replacement.event_at_ms,
            source_id=replacement.source_id,
            source_version=replacement.source_version,
            local_ref=replacement.local_ref,
        )

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
            expected_authority={
                "authority_id": self.authority.authority_id,
                "epoch": self.authority.epoch,
                "digest": self.authority.digest,
            },
            expected_mode=store.mode,
            expected_owner_id=store.owner_id,
            current_snapshot_package=current_snapshot_package,
            restore_source_package=restore_source_package,
        )
        self.assertEqual(result["scope"]["period_id"], store.config.period_id)
        return result

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
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        before = receipt["revision"]
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
        store = self._build_base()
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

    def test_case_06_late_payment_and_report_correction(self) -> None:
        self.assertEqual(expected.CASE_06.number, 6)
        store = self._build_base()
        self._prepare_acknowledged(store)
        self._record_p2(store)
        self._assert_snapshot(store, expected.H_P2_RECEIVED_LATE)
        self._record_report(store)
        self._assert_snapshot(store, expected.H_REPORT_CORRECTED_LATE)
        self._assert_verified(store)

    def test_case_07_duplicates_conflict_reversal_and_replacement(self) -> None:
        self.assertEqual(expected.CASE_07.number, 7)
        store = self._build_base()
        self._prepare_reported(store)
        duplicate = expected.P2_CONFIRMATION_EVIDENCE
        result = store.record_payment_evidence(
            item_id=duplicate.item_id,
            payment_id="payment:h:p2-confirmation",
            common_origin_id=duplicate.common_origin_id,
            amount_cents=duplicate.amount_cents or 0,
            evidence_id=duplicate.evidence_id,
            event_at_ms=duplicate.event_at_ms,
            source_id=duplicate.source_id,
            source_version=duplicate.source_version,
            local_ref=duplicate.local_ref,
        )
        self.assertEqual(result["status"], "DUPLICATE")
        self._assert_snapshot(store, expected.H_P2_DUPLICATE_UNCHANGED)
        conflict = expected.P2_CONFLICT_EVIDENCE
        result = store.record_payment_evidence(
            item_id=conflict.item_id,
            payment_id="payment:h:p2-conflict",
            common_origin_id=conflict.common_origin_id,
            amount_cents=conflict.amount_cents or 0,
            evidence_id=conflict.evidence_id,
            event_at_ms=conflict.event_at_ms,
            source_id=conflict.source_id,
            source_version=conflict.source_version,
            local_ref=conflict.local_ref,
        )
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
        store.record_payment_evidence(
            item_id=replacement.item_id,
            payment_id="payment:h:p3",
            common_origin_id=replacement.common_origin_id,
            amount_cents=replacement.amount_cents or 0,
            evidence_id=replacement.evidence_id,
            event_at_ms=replacement.event_at_ms,
            source_id=replacement.source_id,
            source_version=replacement.source_version,
            local_ref=replacement.local_ref,
        )
        self._assert_snapshot(store, expected.H_P3_REPLACED)
        self._assert_verified(store)

    def test_case_08_revision_race_one_winner_one_stale_loser(self) -> None:
        self.assertEqual(expected.CASE_08.number, 8)
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        expected_revision = receipt["revision"]
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[tuple[type[BaseException], str]] = []

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
        store = self._build_base(period_id=expected.PERIOD_TWO_ID, population_id=expected.POPULATION_TWO_ID)
        self._prepare_final(store)
        self._assert_snapshot(store, expected.H_P3_REPLACED)
        result = self._assert_verified(store)
        self.assertEqual(result["scope"]["period_id"], expected.PERIOD_TWO_ID)
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["period_id"], expected.PERIOD_TWO_ID)

    def test_case_10_interrupted_import_restart_and_disabled_dispatch(self) -> None:
        self.assertEqual(expected.CASE_10.number, 10)
        store = self._build_base()
        self._prepare_rejected(store)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        interrupted_population = "population:fixture-interrupted"

        def interrupted_items() -> Iterator[PopulationItem]:
            for index, item in enumerate(self._items(interrupted_population)):
                if index == 4:
                    raise RuntimeError("synthetic_import_interrupt")
                yield item

        with self.assertRaisesRegex(RuntimeError, "synthetic_import_interrupt"):
            store.stage_population(
                population_id=interrupted_population,
                pack_id=expected.CONTROL_PACK_V1.pack_id,
                cutoff_ms=expected.PERIOD_ONE_START_MS,
                inclusion_rules=("included:synthetic",),
                expected_count=20,
                items=interrupted_items(),
                chunk_size=4,
            )
        with self.assertRaisesRegex(FinancialIntegrityError, "population_source_incomplete"):
            store.validate_population(interrupted_population)
        with store._read() as connection:
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

        precommit_store = self._build_base()
        self._record_cash(precommit_store)
        precommit_claim = self._record_claim(precommit_store)
        precommit_receipt = precommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        precommit_package = precommit_store.export_continuity()
        precommit_summary = precommit_store.summary()
        precommit_counts = self._durable_counts(precommit_store.path)
        precommit_fault = self._make_write_boundary_owner(path=precommit_store.path, fault="precommit", clock=precommit_store.clock)
        with self.assertRaisesRegex(RuntimeError, "synthetic_financial_precommit_interrupt"):
            self._reject(precommit_fault, precommit_claim, precommit_receipt)

        reopened_precommit = self._make_owner(path=precommit_store.path, clock=precommit_store.clock)
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

        postcommit_store = self._build_base()
        self._record_cash(postcommit_store)
        postcommit_claim = self._record_claim(postcommit_store)
        postcommit_receipt = postcommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        postcommit_fault = self._make_write_boundary_owner(path=postcommit_store.path, fault="postcommit", clock=postcommit_store.clock)
        with self.assertRaisesRegex(RuntimeError, "synthetic_financial_result_lost_after_commit"):
            self._reject(postcommit_fault, postcommit_claim, postcommit_receipt)

        reopened_postcommit = self._make_owner(path=postcommit_store.path, clock=postcommit_store.clock)
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

        process_precommit_store = self._build_base()
        self._record_cash(process_precommit_store)
        process_precommit_claim = self._record_claim(process_precommit_store)
        process_precommit_receipt = process_precommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        process_precommit_package = process_precommit_store.export_continuity()
        process_precommit_summary = process_precommit_store.summary()
        process_precommit_counts = self._durable_counts(process_precommit_store.path)
        process_precommit_clock = process_precommit_store.clock.value + 1_000_000
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

        process_postcommit_store = self._build_base()
        self._record_cash(process_postcommit_store)
        process_postcommit_claim = self._record_claim(process_postcommit_store)
        process_postcommit_receipt = process_postcommit_store.current_evaluation_receipt(expected.H_ITEM_ID)
        process_postcommit_clock = process_postcommit_store.clock.value + 1_000_000
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
        process_postcommit_package = reopened_process_postcommit.export_continuity()
        process_postcommit_duplicate = self._reject(reopened_process_postcommit, process_postcommit_claim, process_postcommit_receipt)
        self.assertEqual(process_postcommit_duplicate["status"], "DUPLICATE")
        self.assertEqual(reopened_process_postcommit.export_continuity(), process_postcommit_package)
        self.assertEqual(self._durable_counts(reopened_process_postcommit.path), process_postcommit_counts)
        self._assert_verified(reopened_process_postcommit)

    def test_case_11_shadow_export_restore_and_test_owner_continuation(self) -> None:
        self.assertEqual(expected.CASE_11.number, 11)
        store = self._build_base()
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
            expected_authority={
                "authority_id": self.authority.authority_id,
                "epoch": self.authority.epoch,
                "digest": self.authority.digest,
            },
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
        roundtrip = FinancialOwner.restore_test_continuity(
            package_bytes=roundtrip_package,
            recovered_path=roundtrip_destination,
            trusted_authority=self.authority,
            clock=_Clock(),
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

        live_restore = _tamper_restore_identity("LIVE", "financial-owner-v1")
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_identity:restore-live"):
            FinancialOwner.validate_continuity_package(live_restore)
        with self.assertRaisesRegex(IndependentFinancialError, "continuity:identity:restore-live"):
            verify_continuity_package(
                live_restore,
                expected_scope={
                    "state_id": test_config.state_id,
                    "deployment_id": test_config.deployment_id,
                    "program_id": test_config.program_id,
                    "period_id": test_config.period_id,
                    "currency": test_config.currency,
                },
                expected_authority={
                    "authority_id": self.authority.authority_id,
                    "epoch": self.authority.epoch,
                    "digest": self.authority.digest,
                },
            )
        wrong_restore_owner = _tamper_restore_identity("SHADOW", owner._TEST_OWNER_ID)
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_identity:restore-owner"):
            FinancialOwner.validate_continuity_package(wrong_restore_owner)
        with self.assertRaisesRegex(IndependentFinancialError, "continuity:identity:restore-owner"):
            verify_continuity_package(
                wrong_restore_owner,
                expected_scope={
                    "state_id": test_config.state_id,
                    "deployment_id": test_config.deployment_id,
                    "program_id": test_config.program_id,
                    "period_id": test_config.period_id,
                    "currency": test_config.currency,
                },
                expected_authority={
                    "authority_id": self.authority.authority_id,
                    "epoch": self.authority.epoch,
                    "digest": self.authority.digest,
                },
            )

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
                expected_authority={
                    "authority_id": self.authority.authority_id,
                    "epoch": self.authority.epoch,
                    "digest": self.authority.digest,
                },
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
                expected_authority={
                    "authority_id": self.authority.authority_id,
                    "epoch": self.authority.epoch,
                    "digest": self.authority.digest,
                },
                expected_mode="LIVE",
                expected_owner_id="financial-owner-v1",
            )
        self.assertEqual(store.path.read_bytes(), source_before_restore)

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
        store = self._build_base()
        package = store.export_continuity()
        destination = self._path("raced-continuity.sqlite")
        sidecars = (Path(f"{destination}-wal"), Path(f"{destination}-shm"))
        foreign_database = b"foreign-destination-bytes"
        foreign_wal = b"foreign-wal-bytes"
        foreign_shm = b"foreign-shm-bytes"
        original_link = owner.os.link

        def create_foreign_destination(source: str | os.PathLike[str], target: str | os.PathLike[str], *args: object, **kwargs: object) -> None:
            destination.write_bytes(foreign_database)
            sidecars[0].write_bytes(foreign_wal)
            sidecars[1].write_bytes(foreign_shm)
            original_link(source, target, *args, **kwargs)

        owner.os.link = create_foreign_destination
        try:
            with self.assertRaisesRegex(FinancialContinuityError, "continuity_destination"):
                FinancialOwner.restore_continuity(
                    package_bytes=package,
                    recovered_path=destination,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
        finally:
            owner.os.link = original_link
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

    def test_population_count_backpressure_preserves_prior_chunks(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture-overflow"
        with self.assertRaisesRegex(FinancialIntegrityError, "population_count_exceeded"):
            store.stage_population(
                population_id=population_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=3,
                items=self._items(population_id)[:4],
                chunk_size=3,
            )
        with store._read() as connection:
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
        with store._read() as connection:
            before_resume_events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        resumed = store.stage_population(
            population_id=population_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=3,
            items=self._items(population_id)[:3],
            chunk_size=3,
        )
        self.assertTrue(resumed["source_complete"])
        with store._read() as connection:
            after_resume_events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        self.assertEqual(before_resume_events, ["POPULATION_STAGED"])
        self.assertEqual(after_resume_events, ["POPULATION_STAGED", "POPULATION_SOURCE_COMPLETED"])
        validated = store.validate_population(population_id)
        self.assertEqual(validated["status"], "VALIDATED")
        self.assertEqual(validated["validated_count"], 3)
        published = store.publish_population(population_id)
        self.assertEqual(published["item_count"], 3)
        self._assert_verified(store)

    def test_population_duplicate_input_limit_preserves_verifiable_prefix(self) -> None:
        store = self._make_owner()
        pack = self._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        population_id = "population:fixture-duplicate-input-limit"
        item = self._items(population_id)[0]
        with self.assertRaisesRegex(FinancialIntegrityError, "population_input_limit"):
            store.stage_population(
                population_id=population_id,
                pack_id=pack.pack_id,
                cutoff_ms=pack.effective_start_ms,
                inclusion_rules=("included:synthetic",),
                expected_count=1,
                items=(item,) * 258,
                chunk_size=1,
            )
        with store._read() as connection:
            imported = connection.execute(
                "SELECT imported_count,source_complete FROM population_imports WHERE population_id=?",
                (population_id,),
            ).fetchone()
            events = [str(row[0]) for row in connection.execute("SELECT kind FROM financial_events WHERE aggregate_type='POPULATION' AND aggregate_id=? ORDER BY event_sequence", (population_id,))]
        assert imported is not None
        self.assertEqual(tuple(imported), (1, 0))
        self.assertEqual(events, ["POPULATION_STAGED"])
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
        first = store.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-default-original",
            evidence_id="evidence:report:retry-default-original",
            expected_revision=original_revision,
        )
        self.assertEqual(first["status"], "RECORDED")
        before_detail = store.obligation_detail(expected.H_ITEM_ID)
        before_sequence = store.summary()["sequence"]
        before_row = next(row for row in before_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-default-original")
        store.close()
        reopened = self._make_owner(path=store.path)
        retry = reopened.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:retry-default-original",
            evidence_id="evidence:report:retry-default-original",
            expected_revision=original_revision,
        )
        self.assertEqual(retry["status"], "DUPLICATE")
        after_detail = reopened.obligation_detail(expected.H_ITEM_ID)
        after_row = next(row for row in after_detail["evidence"] if row["evidence_id"] == "evidence:report:retry-default-original")
        self.assertEqual(after_row["record_digest"], before_row["record_digest"])
        self.assertEqual(after_row["event_at_ms"], before_row["event_at_ms"])
        self.assertEqual(reopened.summary()["sequence"], before_sequence)
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            reopened.record_reporting_evidence(
                item_id=expected.H_ITEM_ID,
                report_id="report:retry-default-original",
                evidence_id="evidence:report:retry-default-original",
                expected_revision=original_revision,
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

        clock = _Clock()
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
                "applicable_at_ms": expected.CASH_EVENT_MS + 2,
                "event_at_ms": expected.CASH_EVENT_MS + 3,
                "received_at_ms": expected.CASH_EVENT_MS + 4,
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
        common = [
            "--database", str(reopened.path),
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
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
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
        first = store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id="action:exact-retry-v5",
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )
        self.assertEqual(first["status"], "CORRECTION_AUTHORIZED")
        detail = store.obligation_detail(expected.H_ITEM_ID)
        determination = next(row for row in detail["determinations"] if row["determination_id"] == "determination:action:exact-retry-v5")
        decision_time = int(determination["decided_at_ms"])
        before_retry = store.export_continuity()
        retry = store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id="action:exact-retry-v5",
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )
        self.assertEqual(retry["status"], "DUPLICATE")
        explicit_retry = store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id="action:exact-retry-v5",
            decision_at_ms=decision_time,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )
        self.assertEqual(explicit_retry["status"], "DUPLICATE")
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
        with self.assertRaisesRegex(FinancialConflictError, "determination_request_conflict"):
            store.reject_offset_and_authorize_correction(
                item_id="item-01",
                claim_id=claim_id,
                action_id="action:exact-retry-v5",
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self.assertEqual(store.export_continuity(), before_retry)
        self._assert_verified(store)

    def test_v5_determination_bad_stale_and_consumed_references_are_side_effect_free(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)

        def request(*, action_id: str, evaluation_id: str | None, evaluation_result_digest: str | None, expected_revision: int | None) -> dict[str, object]:
            return store.authorize_offset(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=expected_revision,
                action_id=action_id,
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
            )

        before_malformed = store.export_continuity()
        with self.assertRaisesRegex(FinancialInputError, "evaluation_result_digest"):
            request(
                action_id="action:malformed-evaluation-reference",
                evaluation_id=str(receipt["evaluation_id"]),
                evaluation_result_digest="not-a-digest",
                expected_revision=int(receipt["revision"]),
            )
        self.assertEqual(store.export_continuity(), before_malformed)

        before_bad_digest = store.export_continuity()
        with self.assertRaisesRegex(FinancialRevisionError, "evaluation_reference_conflict"):
            request(
                action_id="action:bad-evaluation-digest",
                evaluation_id=str(receipt["evaluation_id"]),
                evaluation_result_digest="0" * 128,
                expected_revision=int(receipt["revision"]),
            )
        self.assertEqual(store.export_continuity(), before_bad_digest)

        before_missing_reference = store.export_continuity()
        with self.assertRaisesRegex(FinancialInputError, "evaluation_reference_required"):
            request(
                action_id="action:decision-before-evaluation-reference",
                evaluation_id=None,
                evaluation_result_digest=None,
                expected_revision=int(receipt["revision"]),
            )
        self.assertEqual(store.export_continuity(), before_missing_reference)

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

    def test_future_received_evidence_is_rejected_without_clamping(self) -> None:
        clock = _Clock()
        store = self._build_base(clock=clock)
        before = store.path.read_bytes()
        future_received_at_ms = clock.value + 10_000
        with self.assertRaisesRegex(FinancialIntegrityError, "evaluation_evidence_chronology"):
            store.record_support_evidence(
                item_id=expected.H_ITEM_ID,
                evidence_id="evidence:future-received",
                common_origin_id="future-received",
                applicable_at_ms=clock.value,
                event_at_ms=clock.value,
                received_at_ms=future_received_at_ms,
            )
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

    def test_v5_old_continuity_version_is_rejected_without_mutating_source(self) -> None:
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

    def test_v2_v3_v4_tagged_store_and_package_inputs_reject_without_creation(self) -> None:
        store = self._build_base()
        source_before = store.path.read_bytes()
        for version in (2, 3, 4):
            target = self._path(f"tag-only-owner-v{version}.sqlite")
            target.write_bytes(source_before)
            with closing(sqlite3.connect(target, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE financial_meta SET schema_version=?,schema=? WHERE id=1",
                    (version, f"RR/FINANCIAL/OWNER/v{version}"),
                )
            target_before = target.read_bytes()
            with self.assertRaisesRegex(FinancialIntegrityError, "schema_identity"):
                FinancialOwner(
                    path=target,
                    config=store.config,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
            self.assertEqual(target.read_bytes(), target_before)

            package = json.loads(store.export_continuity().decode("ascii"))
            package["schema"] = f"RR/FINANCIAL/CONTINUITY/v{version}"
            package["version"] = version
            body = dict(package)
            del body["package_digest"]
            package["package_digest"] = _independent_hex(
                _independent_digest(b"RR/FINANCIAL/CONTINUITY/v5\x00", _independent_canonical(body))
            )
            old_package = _independent_canonical(package)
            with self.assertRaisesRegex(FinancialContinuityError, "continuity_package_schema"):
                FinancialOwner.validate_continuity_package(old_package)
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

    def test_fixture_has_twelve_cases_and_no_production_import(self) -> None:
        self.assertEqual(tuple(case.number for case in expected.ACCEPTANCE_CASES), tuple(range(1, 13)))
        fixture_source = Path(expected.__file__).read_text(encoding="utf-8")
        self.assertNotIn("right_rail_financial_owner", fixture_source)
        self.assertNotIn("sqlite3", fixture_source)
        self.assertEqual(expected.PROGRAM_TOTAL_CENTS, expected.H_OWED_CENTS + expected.OTHER_TOTAL_CENTS)


if __name__ == "__main__":
    unittest.main()
