"""Twelve-case synthetic acceptance matrix for the RightRail financial owner.

The expected values are imported only from the fixed, application-independent fixture.  This
module never derives expected balances from owner code or reaches the database through SQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
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
    def __init__(self) -> None:
        self.value = expected.P3_EVENT_MS + 1_000_000

    def now_ms(self) -> int:
        self.value += 1
        return self.value


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
            clock=_Clock(),
        )

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
    ) -> FinancialOwner:
        owner = self._make_owner(period_id=period_id)
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
        revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        return store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=revision,
            action_id=expected.ACTION_OFFSET_ID,
            decision_at_ms=expected.OFFSET_DECISION_MS,
        )

    @staticmethod
    def _reject(store: FinancialOwner, claim_id: str) -> dict[str, object]:
        revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        return store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=revision,
            action_id=expected.ACTION_CORRECTION_ID,
            decision_at_ms=expected.CORRECTION_AUTH_MS,
        )

    @staticmethod
    def _ack(store: FinancialOwner) -> dict[str, object]:
        return store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:v1")

    @staticmethod
    def _record_p2(store: FinancialOwner) -> None:
        evidence = expected.P2_PAYMENT_EVIDENCE
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
        store.record_reporting_evidence(
            item_id=original.item_id,
            report_id="report:h:v1",
            evidence_id=original.evidence_id,
            event_at_ms=original.event_at_ms,
        )
        evidence = expected.REPORT_CORRECTION_EVIDENCE
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
        store.reverse_payment(
            item_id=reversal.item_id,
            payment_id="payment:h:p2",
            evidence_id=reversal.evidence_id,
            common_origin_id=reversal.common_origin_id,
            event_at_ms=reversal.event_at_ms,
        )
        replacement = expected.P3_REPLACEMENT_EVIDENCE
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
        before = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        with self.assertRaisesRegex(FinancialAuthorityError, expected.UNAUTHORIZED_REJECTION.expected_error):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                actor_id="not-authorized",
                expected_revision=before,
                action_id="action:unauthorized",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
            )
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["revision"], before)
        with self.assertRaisesRegex(FinancialRevisionError, expected.STALE_REJECTION.expected_error):
            store.reject_offset_and_authorize_correction(
                item_id=expected.H_ITEM_ID,
                claim_id=claim_id,
                expected_revision=0,
                action_id="action:stale",
                decision_at_ms=expected.CORRECTION_AUTH_MS,
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
        store.reverse_payment(
            item_id=reversal.item_id,
            payment_id="payment:h:p2",
            evidence_id=reversal.evidence_id,
            common_origin_id=reversal.common_origin_id,
            event_at_ms=reversal.event_at_ms,
        )
        self._assert_snapshot(store, expected.H_P2_REVERSED)
        replacement = expected.P3_REPLACEMENT_EVIDENCE
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
        expected_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
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
        store.record_reporting_evidence(
            item_id=expected.H_ITEM_ID,
            report_id="report:chain-original",
            evidence_id="evidence:report:chain-original",
            event_at_ms=expected.P2_EVENT_MS,
        )
        first_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        store.record_reporting_correction(
            item_id=expected.H_ITEM_ID,
            report_id="report:chain-correction-1",
            evidence_id="evidence:report:chain-correction-1",
            expected_revision=first_revision,
            event_at_ms=expected.REPORT_CORRECTION_MS,
            supersedes="evidence:report:chain-original",
        )
        second_revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
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

    def test_fixture_has_twelve_cases_and_no_production_import(self) -> None:
        self.assertEqual(tuple(case.number for case in expected.ACCEPTANCE_CASES), tuple(range(1, 13)))
        fixture_source = Path(expected.__file__).read_text(encoding="utf-8")
        self.assertNotIn("right_rail_financial_owner", fixture_source)
        self.assertNotIn("sqlite3", fixture_source)
        self.assertEqual(expected.PROGRAM_TOTAL_CENTS, expected.H_OWED_CENTS + expected.OTHER_TOTAL_CENTS)


if __name__ == "__main__":
    unittest.main()
