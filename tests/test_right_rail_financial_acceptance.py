"""Twelve-case synthetic acceptance matrix for the RightRail financial owner.

The expected values are imported only from the fixed, application-independent fixture.  This
module never derives expected balances from owner code or reaches the database through SQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import tempfile
import threading
import unittest

from app.right_rail_financial_owner import (
    ControlPack,
    FinancialAuthorityError,
    FinancialConflictError,
    FinancialContinuityError,
    FinancialDispatchError,
    FinancialIntegrityError,
    FinancialOwner,
    FinancialOwnerConfig,
    FinancialRevisionError,
    PopulationItem,
    SyntheticTrustedAuthority,
)
from app.right_rail_financial_owner_independent import verify_database, verify_continuity_package
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

    def _prepare_final(self, store: FinancialOwner) -> str:
        claim_id = self._prepare_reported(store)
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

    def _assert_verified(self, store: FinancialOwner, *, package: bytes | None = None) -> dict[str, object]:
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
            continuity_package=package,
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
        with self.assertRaisesRegex(FinancialIntegrityError, "population_incomplete"):
            store.validate_population(interrupted_population)
        before = store.summary()
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            store.dispatch_outbox()
        reopened = self._make_owner(path=store.path)
        self.assertEqual(reopened.summary(), before)
        self._assert_verified(reopened)

    def test_case_11_shadow_export_restore_preserves_references_without_writer(self) -> None:
        self.assertEqual(expected.CASE_11.number, 11)
        store = self._build_base()
        self._prepare_acknowledged(store)
        self._assert_snapshot(store, expected.H_ACKNOWLEDGED)
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
        self.assertEqual(shadow.action_payload(expected.ACTION_CORRECTION_ID), store.action_payload(expected.ACTION_CORRECTION_ID))
        with self.assertRaisesRegex(FinancialDispatchError, "shadow_owner_read_only"):
            shadow.retry_action(expected.ACTION_CORRECTION_ID)
        with self.assertRaisesRegex(FinancialDispatchError, "dispatch_disabled"):
            shadow.dispatch_outbox()
        self._assert_verified(shadow)

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

    def test_fixture_has_twelve_cases_and_no_production_import(self) -> None:
        self.assertEqual(tuple(case.number for case in expected.ACCEPTANCE_CASES), tuple(range(1, 13)))
        fixture_source = Path(expected.__file__).read_text(encoding="utf-8")
        self.assertNotIn("right_rail_financial_owner", fixture_source)
        self.assertNotIn("sqlite3", fixture_source)
        self.assertEqual(expected.PROGRAM_TOTAL_CENTS, expected.H_OWED_CENTS + expected.OTHER_TOTAL_CENTS)


if __name__ == "__main__":
    unittest.main()
