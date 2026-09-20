"""Independent owner-history compatibility tests for the semantic adapter.

These tests drive the real v5 owner operations and assert facts independently
from the adapter's derived output.  The adapter is exercised only with an
already-open transaction connection; the source database is hashed before and
after every read and failed codec operation.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from app import right_rail_financial_owner as owner
from app import right_rail_financial_semantic_adapter as adapter
from app.right_rail_financial_owner import (
    ControlPack,
    FinancialOwner,
    FinancialOwnerConfig,
    PopulationItem,
    SyntheticTrustedAuthority,
)
from tests import rightrail_financial_expected_cases as expected


EXPECTED_PROGRAM_TOTAL_CENTS = 100_000_000
EXPECTED_H_OWED_CENTS = 10_000_000
EXPECTED_H_CASH_CENTS = 9_700_000
EXPECTED_OFFSET_CENTS = 300_000
EXPECTED_HOSPITAL_COUNT = 20


@dataclass
class _Clock:
    value: int = expected.CASH_EVENT_MS

    def now_ms(self) -> int:
        self.value += 1
        return self.value


class RightRailFinancialSemanticAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-semantic-adapter-")
        self.addCleanup(self.temp_dir.cleanup)
        self.authority = SyntheticTrustedAuthority()
        self.path_counter = 0

    def _path(self, name: str | None = None) -> Path:
        self.path_counter += 1
        return Path(self.temp_dir.name) / (name or f"owner-{self.path_counter}.sqlite")

    def _make_owner(
        self,
        *,
        path: Path | None = None,
        period_id: str = expected.PERIOD_ONE_ID,
        clock: _Clock | None = None,
        mode: str = "LIVE",
        owner_id: str = "financial-owner-v1",
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
            mode=mode,
            owner_id=owner_id,
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

    def _build_base(self, *, path: Path | None = None) -> FinancialOwner:
        store = self._make_owner(path=path)
        pack_expectation = expected.CONTROL_PACK_V1
        pack = self._pack(pack_expectation)
        store.publish_control_pack(pack)
        store.stage_population(
            population_id=expected.POPULATION_ONE_ID,
            pack_id=pack.pack_id,
            cutoff_ms=pack_expectation.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=EXPECTED_HOSPITAL_COUNT,
            items=self._items(expected.POPULATION_ONE_ID),
            chunk_size=5,
        )
        store.validate_population(expected.POPULATION_ONE_ID)
        store.publish_population(expected.POPULATION_ONE_ID)
        for evidence in expected.OTHER_SUPPORT_EVIDENCE:
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
        return store

    @staticmethod
    def _advance_clock(store: FinancialOwner, at_ms: int) -> None:
        clock = getattr(store, "clock", None)
        if isinstance(clock, _Clock):
            clock.value = max(clock.value, at_ms)

    @staticmethod
    def _record_cash(store: FinancialOwner) -> None:
        evidence = expected.H_CASH_EVIDENCE
        store.record_payment_evidence(
            item_id=evidence.item_id,
            payment_id="payment:h:cash",
            common_origin_id=evidence.common_origin_id,
            amount_cents=EXPECTED_H_CASH_CENTS,
            evidence_id=evidence.evidence_id,
            event_at_ms=evidence.event_at_ms,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            local_ref=evidence.local_ref,
        )

    @staticmethod
    def _record_claim(store: FinancialOwner) -> str:
        evidence = expected.OFFSET_CLAIM_EVIDENCE
        claim_id = "claim:obligation-item-h:offset-v1"
        store.record_offset_claim(
            item_id=evidence.item_id,
            claim_id=claim_id,
            amount_cents=EXPECTED_OFFSET_CENTS,
            evidence_id=evidence.evidence_id,
            owner_role="CASE_OWNER",
            deadline_ms=expected.H_DUE_AT_MS,
        )
        return claim_id

    @staticmethod
    def _record_h_support(store: FinancialOwner) -> None:
        evidence = expected.OFFSET_SUPPORT_EVIDENCE
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
    def _authorize(store: FinancialOwner, claim_id: str) -> None:
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id=expected.ACTION_OFFSET_ID,
            decision_at_ms=expected.OFFSET_DECISION_MS,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    @staticmethod
    def _reject(store: FinancialOwner, claim_id: str) -> None:
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=claim_id,
            expected_revision=receipt["revision"],
            action_id=expected.ACTION_CORRECTION_ID,
            decision_at_ms=expected.CORRECTION_AUTH_MS,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    @staticmethod
    def _ack(store: FinancialOwner) -> None:
        store.acknowledge_action(expected.ACTION_CORRECTION_ID, "ack:correction:h:v1")

    def _prepare_acknowledged(self, store: FinancialOwner) -> str:
        self._record_cash(store)
        claim_id = self._record_claim(store)
        self._reject(store, claim_id)
        self._ack(store)
        return claim_id

    def _prepare_final(self, store: FinancialOwner) -> str:
        claim_id = self._prepare_acknowledged(store)
        payment = expected.P2_PAYMENT_EVIDENCE
        self._advance_clock(store, payment.event_at_ms)
        store.record_payment_evidence(
            item_id=payment.item_id,
            payment_id="payment:h:p2",
            common_origin_id=payment.common_origin_id,
            amount_cents=EXPECTED_OFFSET_CENTS,
            evidence_id=payment.evidence_id,
            event_at_ms=payment.event_at_ms,
            source_id=payment.source_id,
            source_version=payment.source_version,
            local_ref=payment.local_ref,
        )
        original = expected.REPORT_ORIGINAL_EVIDENCE
        self._advance_clock(store, original.event_at_ms)
        store.record_reporting_evidence(
            item_id=original.item_id,
            report_id="report:h:v1",
            evidence_id=original.evidence_id,
            event_at_ms=original.event_at_ms,
        )
        correction = expected.REPORT_CORRECTION_EVIDENCE
        self._advance_clock(store, correction.event_at_ms)
        store.record_reporting_correction(
            item_id=correction.item_id,
            report_id="report:h:v2",
            evidence_id=correction.evidence_id,
            event_at_ms=correction.event_at_ms,
            supersedes=original.evidence_id,
        )
        return claim_id

    @staticmethod
    def _snapshot(
        store: FinancialOwner,
        *,
        context: adapter.TrustedAuthorityContext | None = None,
        evaluation_time_ms: int | None = None,
    ) -> adapter.LockedSemanticSnapshot:
        clock = getattr(store, "clock", None)
        if evaluation_time_ms is None:
            evaluation_time_ms = 2**63 - 2
        authority_context = context or adapter.TrustedAuthorityContext.from_authority(store.trusted_authority)
        with closing(store._connect()) as connection:
            connection.execute("BEGIN")
            try:
                return adapter.build_locked_semantic_snapshot(
                    connection,
                    obligation_id=expected.H_OBLIGATION_ID,
                    authority_context=authority_context,
                    evaluation_time_ms=evaluation_time_ms,
                )
            finally:
                connection.rollback()

    @staticmethod
    def _hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _assert_no_source_mutation(self, store: FinancialOwner, before_hash: str) -> None:
        self.assertEqual(self._hash(store.path), before_hash)

    def _copy_store(self, store: FinancialOwner, name: str) -> Path:
        target = self._path(name)
        shutil.copy2(store.path, target)
        return target

    def _snapshot_on_path(self, path: Path, *, context: adapter.TrustedAuthorityContext | None = None) -> adapter.LockedSemanticSnapshot:
        store = self._make_owner(path=path)
        return self._snapshot(store, context=context)

    def test_cash_claim_snapshot_is_locked_canonical_and_read_only(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        before_hash = self._hash(store.path)
        snapshot = self._snapshot(store)
        data = snapshot.data

        self.assertEqual(data["scope"], {
            "state_id": expected.STATE_ID,
            "deployment_id": expected.DEPLOYMENT_ID,
            "program_id": expected.PROGRAM_ID,
            "period_id": expected.PERIOD_ONE_ID,
            "currency": "USD",
        })
        self.assertEqual(data["owner"]["mode"], "LIVE")
        self.assertEqual(data["owner"]["provenance"], "ROOT")
        self.assertEqual(data["authority"]["context"], "CURRENT")
        self.assertEqual(data["population"]["expected_count"], EXPECTED_HOSPITAL_COUNT)
        self.assertEqual(data["population_item"]["owed_cents"], EXPECTED_H_OWED_CENTS)
        self.assertEqual(data["obligation"]["received_cash_cents"], EXPECTED_H_CASH_CENTS)
        self.assertEqual(data["obligation"]["claimed_adjustment_cents"], EXPECTED_OFFSET_CENTS)
        self.assertEqual(data["obligation"]["lawful_adjustment_cents"], 0)
        self.assertEqual([row["claim_id"] for row in data["claims"]], [claim_id])
        self.assertEqual(data["claims"][0]["status"], "CLAIMED")
        self.assertEqual(data["payments"][0]["amount_cents"], EXPECTED_H_CASH_CENTS)
        self.assertEqual(data["determinations"], [])
        self.assertEqual(data["actions"], [])
        self.assertEqual(data["action_outbox"], [])
        self.assertEqual(data["current_evaluation"]["receipt"]["revision"], data["obligation"]["revision"])
        self.assertEqual(
            adapter.decode_locked_snapshot(adapter.encode_locked_snapshot(snapshot)).data,
            data,
        )
        self._assert_no_source_mutation(store, before_hash)

        # The fixed fixture remains an independently stated arithmetic fact.
        self.assertEqual(sum(item.owed_cents for item in expected.PROGRAM_ITEMS), EXPECTED_PROGRAM_TOTAL_CENTS)
        self.assertEqual(len(expected.PROGRAM_ITEMS), EXPECTED_HOSPITAL_COUNT)

    def test_authorized_rejected_and_acknowledged_histories_are_explicit(self) -> None:
        authorized = self._build_base()
        self._record_cash(authorized)
        claim_id = self._record_claim(authorized)
        self._record_h_support(authorized)
        self._authorize(authorized, claim_id)
        authorized_data = self._snapshot(authorized).data
        self.assertEqual(authorized_data["claims"][0]["status"], "AUTHORIZED")
        self.assertEqual(authorized_data["determinations"][0]["decision"], "OFFSET_AUTHORIZED")
        self.assertEqual(authorized_data["determinations"][0]["actor_role"], "FINANCE_DECISION")
        self.assertEqual(authorized_data["actions"][0]["status"], "READY")
        self.assertEqual(authorized_data["action_outbox"][0]["status"], "READY")
        self.assertEqual(authorized_data["obligation"]["received_cash_cents"], EXPECTED_H_CASH_CENTS)
        self.assertEqual(authorized_data["obligation"]["lawful_adjustment_cents"], EXPECTED_OFFSET_CENTS)

        rejected = self._build_base()
        self._record_cash(rejected)
        rejected_claim = self._record_claim(rejected)
        self._reject(rejected, rejected_claim)
        rejected_data = self._snapshot(rejected).data
        self.assertEqual(rejected_data["claims"][0]["status"], "REJECTED")
        self.assertEqual(rejected_data["determinations"][0]["decision"], "OFFSET_REJECTED_CORRECTION_AUTHORIZED")
        self.assertEqual(rejected_data["actions"][0]["kind"], "CORRECTION_PAYMENT_REQUEST")
        self.assertEqual(rejected_data["cases"][-1]["status"], "CORRECTION_REQUIRED")
        self.assertEqual(rejected_data["obligation"]["lawful_adjustment_cents"], 0)

        acknowledged = self._build_base()
        self._prepare_acknowledged(acknowledged)
        acknowledged_data = self._snapshot(acknowledged).data
        self.assertEqual(acknowledged_data["actions"][0]["status"], "ACKNOWLEDGED")
        self.assertEqual(acknowledged_data["action_outbox"][0]["status"], "ACKNOWLEDGED")
        self.assertEqual(acknowledged_data["obligation"]["received_cash_cents"], EXPECTED_H_CASH_CENTS)
        self.assertNotIn("evidence:correction-h:cash", {row["evidence_id"] for row in acknowledged_data["evidence"]})

    def _record_duplicate_conflict_reversal_replacement(self, store: FinancialOwner) -> None:
        payment = expected.P2_PAYMENT_EVIDENCE
        duplicate = expected.P2_CONFIRMATION_EVIDENCE
        conflict = expected.P2_CONFLICT_EVIDENCE
        self._advance_clock(store, duplicate.event_at_ms)
        self.assertEqual(
            store.record_payment_evidence(
                item_id=duplicate.item_id,
                payment_id="payment:h:p2-confirmation",
                common_origin_id=duplicate.common_origin_id,
                amount_cents=EXPECTED_OFFSET_CENTS,
                evidence_id=duplicate.evidence_id,
                event_at_ms=duplicate.event_at_ms,
                source_id=duplicate.source_id,
                source_version=duplicate.source_version,
                local_ref=duplicate.local_ref,
            )["status"],
            "DUPLICATE",
        )
        self.assertEqual(
            store.record_payment_evidence(
                item_id=conflict.item_id,
                payment_id="payment:h:p2-conflict",
                common_origin_id=conflict.common_origin_id,
                amount_cents=conflict.amount_cents or EXPECTED_OFFSET_CENTS + 1,
                evidence_id=conflict.evidence_id,
                event_at_ms=conflict.event_at_ms,
                source_id=conflict.source_id,
                source_version=conflict.source_version,
                local_ref=conflict.local_ref,
            )["status"],
            "CONFLICT",
        )
        reversal = expected.P2_REVERSAL_EVIDENCE
        self._advance_clock(store, reversal.event_at_ms)
        self.assertEqual(
            store.reverse_payment(
                item_id=reversal.item_id,
                payment_id="payment:h:p2",
                evidence_id=reversal.evidence_id,
                common_origin_id=reversal.common_origin_id,
                event_at_ms=reversal.event_at_ms,
            )["status"],
            "REVERSED",
        )
        with closing(store._connect()) as connection:
            received_at_ms = int(connection.execute("SELECT received_at_ms FROM evidence WHERE evidence_id=?", (reversal.evidence_id,)).fetchone()[0])
        if isinstance(store.clock, _Clock):
            store.clock.value = received_at_ms - 1
        self.assertEqual(
            store.reverse_payment(
                item_id=reversal.item_id,
                payment_id="payment:h:p2",
                evidence_id=reversal.evidence_id,
                common_origin_id=reversal.common_origin_id,
                event_at_ms=reversal.event_at_ms,
            )["status"],
            "DUPLICATE",
        )
        replacement = expected.P3_REPLACEMENT_EVIDENCE
        self._advance_clock(store, replacement.event_at_ms)
        store.record_payment_evidence(
            item_id=replacement.item_id,
            payment_id="payment:h:p3",
            common_origin_id=replacement.common_origin_id,
            amount_cents=EXPECTED_OFFSET_CENTS,
            evidence_id=replacement.evidence_id,
            event_at_ms=replacement.event_at_ms,
            source_id=replacement.source_id,
            source_version=replacement.source_version,
            local_ref=replacement.local_ref,
        )

    def test_duplicate_conflict_reversal_replacement_and_reporting_are_real_facts(self) -> None:
        store = self._build_base()
        self._prepare_acknowledged(store)
        payment = expected.P2_PAYMENT_EVIDENCE
        self._advance_clock(store, payment.event_at_ms)
        store.record_payment_evidence(
            item_id=payment.item_id,
            payment_id="payment:h:p2",
            common_origin_id=payment.common_origin_id,
            amount_cents=EXPECTED_OFFSET_CENTS,
            evidence_id=payment.evidence_id,
            event_at_ms=payment.event_at_ms,
            source_id=payment.source_id,
            source_version=payment.source_version,
            local_ref=payment.local_ref,
        )
        original = expected.REPORT_ORIGINAL_EVIDENCE
        self._advance_clock(store, original.event_at_ms)
        store.record_reporting_evidence(item_id=original.item_id, report_id="report:h:v1", evidence_id=original.evidence_id, event_at_ms=original.event_at_ms)
        correction = expected.REPORT_CORRECTION_EVIDENCE
        self._advance_clock(store, correction.event_at_ms)
        store.record_reporting_correction(item_id=correction.item_id, report_id="report:h:v2", evidence_id=correction.evidence_id, event_at_ms=correction.event_at_ms, supersedes=original.evidence_id)
        self._record_duplicate_conflict_reversal_replacement(store)

        before_hash = self._hash(store.path)
        data = self._snapshot(store).data
        payments = {row["payment_id"]: row for row in data["payments"]}
        self.assertEqual(set(payments), {"payment:h:cash", "payment:h:p2", "payment:h:p3"})
        self.assertEqual(payments["payment:h:p2"]["active"], 0)
        self.assertEqual(payments["payment:h:p3"]["active"], 1)
        self.assertEqual(data["obligation"]["received_cash_cents"], EXPECTED_H_OWED_CENTS)
        self.assertTrue(any(row["evidence_id"] == expected.P2_CONFIRMATION_EVIDENCE.evidence_id for row in data["evidence"]))
        self.assertEqual(len(data["conflicts"]), 1)
        self.assertEqual(data["conflicts"][0]["existing_amount_cents"], EXPECTED_OFFSET_CENTS)
        self.assertEqual(data["conflicts"][0]["candidate_amount_cents"], EXPECTED_OFFSET_CENTS + 1)
        reversal_rows = [row for row in data["evidence"] if row["kind"] == "PAYMENT_REVERSAL"]
        self.assertEqual(len(reversal_rows), 1)
        self.assertEqual(reversal_rows[0]["reversal_of"], "payment:h:p2")
        self.assertEqual(data["obligation"]["reporting_complete"], True)
        self.assertEqual(data["actions"][0]["status"], "ACKNOWLEDGED")
        self._assert_no_source_mutation(store, before_hash)

    def test_historical_context_reopen_and_shadow_test_restore(self) -> None:
        store = self._build_base()
        claim_id = self._record_claim(store)
        self._record_cash(store)
        self._record_h_support(store)
        self._authorize(store, claim_id)
        reopened = self._make_owner(path=store.path, clock=store.clock)
        historical_context = adapter.TrustedAuthorityContext.from_authority(self.authority, source="HISTORICAL")
        historical = self._snapshot(reopened, context=historical_context)
        self.assertEqual(historical.data["authority"]["context"], "HISTORICAL")
        self.assertGreaterEqual(len(historical.data["evaluations"]), 2)
        self.assertEqual(historical.data["evaluations"][0]["receipt"]["revision"], 0)
        package = reopened.export_continuity()
        shadow = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("shadow.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
            restore_mode="SHADOW",
        )
        test_owner = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("test.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
            restore_mode="TEST",
        )
        shadow_data = self._snapshot(shadow).data
        test_data = self._snapshot(test_owner).data
        self.assertEqual(shadow_data["owner"]["mode"], "SHADOW")
        self.assertEqual(shadow_data["owner"]["provenance"], "CONTINUITY_RESTORE")
        self.assertEqual(shadow_data["owner"]["bound_owner_id"], owner._SHADOW_OWNER_ID)
        self.assertEqual(test_data["owner"]["mode"], "TEST")
        self.assertEqual(test_data["owner"]["provenance"], "CONTINUITY_RESTORE")
        self.assertEqual(test_data["owner"]["bound_owner_id"], owner._TEST_OWNER_ID)

    def test_malformed_cross_scope_authority_evidence_role_status_and_overflow_fail_closed(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        self._record_h_support(store)
        self._authorize(store, claim_id)
        source_hash = self._hash(store.path)

        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "current_authority_mismatch"):
            self._snapshot(store, context=adapter.TrustedAuthorityContext.from_authority(SyntheticTrustedAuthority(epoch=2)))
        self._assert_no_source_mutation(store, source_hash)

        with closing(store._connect()) as connection:
            connection.execute("BEGIN")
            with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "evaluation_time_binding|obligation_after_evaluation"):
                adapter.build_locked_semantic_snapshot(
                    connection,
                    obligation_id=expected.H_OBLIGATION_ID,
                    authority_context=adapter.TrustedAuthorityContext.from_authority(self.authority),
                    evaluation_time_ms=expected.CASH_EVENT_MS,
                )
            connection.rollback()
        self._assert_no_source_mutation(store, source_hash)

        tampered_evidence = self._copy_store(store, "tampered-evidence.sqlite")
        with closing(sqlite3.connect(str(tampered_evidence))) as connection:
            connection.execute("DELETE FROM evidence WHERE evidence_id=?", (expected.H_CASH_EVIDENCE.evidence_id,))
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "payment_evidence_binding"):
            self._snapshot_on_path(tampered_evidence)

        tampered_role = self._copy_store(store, "tampered-role.sqlite")
        with closing(sqlite3.connect(str(tampered_role))) as connection:
            connection.execute("UPDATE determinations SET actor_role='REPORTING_EDITOR' WHERE determination_id=?", (f"determination:{expected.ACTION_OFFSET_ID}",))
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "determination_actor_role"):
            self._snapshot_on_path(tampered_role)

        tampered_status = self._copy_store(store, "tampered-status.sqlite")
        with closing(sqlite3.connect(str(tampered_status))) as connection:
            connection.execute("DELETE FROM determinations WHERE determination_id=?", (f"determination:{expected.ACTION_OFFSET_ID}",))
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "claim_without_determination"):
            self._snapshot_on_path(tampered_status)

        overflow = self._copy_store(store, "tampered-overflow.sqlite")
        with closing(sqlite3.connect(str(overflow))) as connection:
            original = connection.execute("SELECT received_at_ms FROM evidence WHERE evidence_id=?", (expected.H_CASH_EVIDENCE.evidence_id,)).fetchone()
            self.assertIsNotNone(original)
            overflow_evidence_id = "evidence:overflow"
            overflow_origin = "origin:overflow"
            giant = owner.EvidenceRecord(
                overflow_evidence_id,
                expected.H_ITEM_ID,
                "PAYMENT_CONFIRMATION",
                overflow_origin,
                "synthetic-overflow-source",
                "overflow-v1",
                "ref:overflow",
                expected.CASH_EVENT_MS,
                expected.CASH_EVENT_MS,
                int(original[0]),
                owner._digest(owner._EVIDENCE_DOMAIN, owner._canonical({"source_id": "synthetic-overflow-source", "source_version": "overflow-v1", "local_ref": "ref:overflow", "common_origin_id": overflow_origin, "kind": "PAYMENT_CONFIRMATION"})),
                owner._MAX_CENTS,
            )
            connection.execute(
                "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    giant.evidence_id, expected.H_ITEM_ID, giant.kind, giant.common_origin_id, giant.source_id, giant.source_version,
                    giant.local_ref, giant.applicable_at_ms, giant.event_at_ms, giant.received_at_ms, giant.content_digest,
                    giant.record_digest, owner._MAX_CENTS, None, None,
                ),
            )
            connection.execute(
                "INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?)",
                ("payment:overflow", expected.H_OBLIGATION_ID, expected.H_ITEM_ID, giant.evidence_id, overflow_origin, owner._MAX_CENTS, expected.CASH_EVENT_MS, 1, None),
            )
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "cents_overflow"):
            self._snapshot_on_path(overflow)

        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "snapshot_json"):
            adapter.decode_locked_snapshot(b"not-json")
        self._assert_no_source_mutation(store, source_hash)

    def test_blfin02_input_and_blfres02_result_are_frozen_and_bound(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        self._record_claim(store)
        snapshot = self._snapshot(store)
        data = snapshot.data
        scope = data["scope"]
        owner_body = data["owner"]
        authority = data["authority"]
        pack = data["control_pack"]
        pack_fields = pack["canonical_fields"]
        pre = data["pre_evaluation"]
        obligation = data["obligation"]
        receipt = data["current_evaluation"]["receipt"]

        input_wire = adapter.encode_blfin02_input(snapshot)
        self.assertEqual(input_wire[: len(adapter.BLFIN02_MAGIC)], adapter.BLFIN02_MAGIC)
        self.assertEqual(input_wire, adapter.encode_lean_input(snapshot))
        self.assertLessEqual(len(input_wire), adapter.MAX_WIRE_BYTES)

        result = adapter.DecodedLeanResult(
            owner_id=owner_body["owner_id"],
            mode=owner_body["mode"],
            provenance=owner_body["provenance"],
            state_id=scope["state_id"],
            deployment_id=scope["deployment_id"],
            program_id=scope["program_id"],
            period_id=scope["period_id"],
            population_id=data["population"]["population_id"],
            item_id=pre["item_id"],
            obligation_id=pre["obligation_id"],
            currency=scope["currency"],
            authority_id=authority["authority_id"],
            authority_epoch=authority["epoch"],
            authority_digest=bytes.fromhex(authority["digest"]),
            pack_id=pack_fields["pack_id"],
            pack_digest=bytes.fromhex(pack["digest"]),
            before_revision=pre["revision"],
            after_revision=pre["revision"] + 1,
            evaluated_at_ms=data["evaluation_time_ms"],
            rule_version=pack_fields["version"],
            evidence_ids=tuple(receipt["evidence_ids"]),
            completion_at_ms=None,
            owed_cents=EXPECTED_H_OWED_CENTS,
            claimed_adjustment_cents=EXPECTED_OFFSET_CENTS,
            lawful_adjustment_cents=0,
            received_cash_cents=EXPECTED_H_CASH_CENTS,
            shortfall_cents=EXPECTED_H_OWED_CENTS - EXPECTED_H_CASH_CENTS,
            overage_cents=0,
            cash_satisfied=False,
            amount_satisfied=False,
            timely=False,
            reporting_complete=False,
            verification_status="SUPPORTED",
            case_status="OPEN",
            delivery_status="NONE",
        )
        encoded = adapter.encode_blfres02_result(result)
        self.assertEqual(encoded[: len(adapter.BLFRES02_MAGIC)], adapter.BLFRES02_MAGIC)
        decoded = adapter.decode_blfres02_result(encoded, expected_snapshot=snapshot)
        self.assertEqual(decoded, result)

        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "result_magic"):
            adapter.decode_blfres02_result(b"BLFRES01" + encoded[len(adapter.BLFRES02_MAGIC) :], expected_snapshot=snapshot)
        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "wire_trailing_bytes"):
            adapter.decode_blfres02_result(encoded + b"\x00", expected_snapshot=snapshot)
        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "result_authority_binding"):
            adapter.decode_blfres02_result(
                adapter.encode_blfres02_result(replace(result, authority_epoch=result.authority_epoch + 1)),
                expected_snapshot=snapshot,
            )
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "result_received_cash_cents"):
            adapter.decode_blfres02_result(
                adapter.encode_blfres02_result(replace(result, received_cash_cents=EXPECTED_H_CASH_CENTS + 1)),
                expected_snapshot=snapshot,
            )
        bad_tag = bytearray(encoded)
        bad_tag[-1] = 0x7F
        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "delivery_status"):
            adapter.decode_blfres02_result(bytes(bad_tag), expected_snapshot=snapshot)
        self.assertEqual(obligation["received_cash_cents"], EXPECTED_H_CASH_CENTS)


if __name__ == "__main__":
    unittest.main()
