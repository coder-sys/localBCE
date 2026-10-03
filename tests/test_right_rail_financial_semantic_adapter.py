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
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_owner as owner
from app import right_rail_financial_engine as financial_engine
from app import right_rail_financial_semantic_adapter as adapter
from app.right_rail_financial_owner import (
    FinancialOwner,
    FinancialOwnerConfig,
    SyntheticTrustedAuthority,
)
from tests import rightrail_financial_expected_cases as expected
from tests.test_right_rail_financial_acceptance import (
    _control_pack_from_fixture,
    _image,
    _items_from_fixture,
    _population_manifest_from_fixture,
    _record_fixture_support,
)


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
        owner = FinancialOwner(
            path=path or self._path(),
            config=config,
            trusted_authority=self.authority,
            clock=clock or _Clock(),
            mode=mode,
            owner_id=owner_id,
        )
        self.addCleanup(owner.close)  # R1a: the owner's writer holds the file open until closed
        return owner

    def _build_base(self, *, path: Path | None = None) -> FinancialOwner:
        store = self._make_owner(path=path)
        pack_expectation = expected.CONTROL_PACK_V1
        pack = _control_pack_from_fixture(pack_expectation)
        store.publish_control_pack(pack)
        manifest_fixture = expected.POPULATION_MANIFEST_V1
        authority = store.trusted_authority
        manifest = _population_manifest_from_fixture(manifest_fixture, authority)
        store.register_population_manifest(manifest)
        store.stage_population(
            population_id=expected.POPULATION_ONE_ID,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=pack_expectation.effective_start_ms,
            inclusion_rules=("included:synthetic",),
            expected_count=EXPECTED_HOSPITAL_COUNT,
            items=_items_from_fixture(expected.PROGRAM_ITEMS, expected.POPULATION_ONE_ID),
            chunk_size=5,
        )
        store.validate_population(expected.POPULATION_ONE_ID)
        store.publish_population(expected.POPULATION_ONE_ID)
        for evidence in expected.OTHER_SUPPORT_EVIDENCE:
            _record_fixture_support(store, evidence)
        return store

    @staticmethod
    def _advance_clock(store: FinancialOwner, at_ms: int) -> None:
        clock = getattr(store, "clock", None)
        if isinstance(clock, _Clock):
            clock.value = max(clock.value, at_ms)

    @staticmethod
    def _record_cash(store: FinancialOwner, cents: int = EXPECTED_H_CASH_CENTS) -> None:
        evidence = expected.H_CASH_EVIDENCE
        store.record_payment_evidence(
            item_id=evidence.item_id,
            payment_id="payment:h:cash",
            common_origin_id=evidence.common_origin_id,
            amount_cents=cents,
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
        _record_fixture_support(store, expected.OFFSET_SUPPORT_EVIDENCE)

    @staticmethod
    def _authorize(store: FinancialOwner, claim_id: str) -> None:
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        RightRailFinancialSemanticAdapterTests._advance_clock(store, expected.OFFSET_DECISION_MS)  # recorded when decided
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
        RightRailFinancialSemanticAdapterTests._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided
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
                    expected_config=store.config,
                    expected_scope=store.config,
                    expected_mode=store.mode,
                    expected_owner_id=store.owner_id,
                )
            finally:
                connection.rollback()

    @staticmethod
    def _hash(path: Path) -> str:
        return hashlib.sha256(_image(path)).hexdigest()  # R0.5/R1a: the committed content, whichever connection closed last

    def _assert_no_source_mutation(self, store: FinancialOwner, before_hash: str) -> None:
        self.assertEqual(self._hash(store.path), before_hash)

    def _assert_fresh_engine_history_result(
        self,
        store: FinancialOwner,
        expectation: expected.BalanceExpectation,
        *,
        completion_at_ms: int | None,
    ) -> None:
        before_hash = self._hash(store.path)
        snapshot = self._snapshot(store)
        result = adapter.decode_live_result(
            financial_engine._evaluate_wire(adapter.encode_blfin02_input(snapshot)), snapshot.data
        )
        self._assert_no_source_mutation(store, before_hash)
        data = snapshot.data
        owner_data = data["owner"]
        scope = data["scope"]
        authority = data["authority"]
        pack = data["control_pack"]
        pre_evaluation = data["pre_evaluation"]
        expected_bindings = {
            "owner_id": owner_data["owner_id"],
            "mode": owner_data["mode"],
            "provenance": owner_data["provenance"],
            "state_id": scope["state_id"],
            "deployment_id": scope["deployment_id"],
            "program_id": scope["program_id"],
            "period_id": scope["period_id"],
            "population_id": data["population"]["population_id"],
            "item_id": pre_evaluation["item_id"],
            "obligation_id": pre_evaluation["obligation_id"],
            "currency": scope["currency"],
            "authority_id": authority["authority_id"],
            "authority_epoch": authority["epoch"],
            "authority_digest": bytes.fromhex(authority["digest"]),
            "pack_id": pack["canonical_fields"]["pack_id"],
            "pack_digest": bytes.fromhex(pack["digest"]),
            "before_revision": pre_evaluation["revision"],
            "after_revision": pre_evaluation["revision"] + 1,
            "evaluated_at_ms": data["evaluation_time_ms"],
            "rule_version": pack["canonical_fields"]["version"],
            "evidence_ids": tuple(row["evidence_id"] for row in data["evidence"]),
            "completion_at_ms": completion_at_ms,
        }
        for field_name, expected_value in expected_bindings.items():
            self.assertEqual(getattr(result, field_name), expected_value, field_name)
        expected_values = {
            "owed_cents": expectation.owed_cents,
            "claimed_adjustment_cents": expectation.claimed_adjustment_cents,
            "lawful_adjustment_cents": expectation.lawful_adjustment_cents,
            "received_cash_cents": expectation.received_cash_cents,
            "shortfall_cents": expectation.shortfall_cents,
            "overage_cents": expectation.overage_cents,
            "cash_satisfied": expectation.cash_satisfied,
            "amount_satisfied": expectation.amount_satisfied,
            "timely": expectation.timely,
            "reporting_complete": expectation.reporting_complete,
            "verification_status": expectation.verification_status,
            "case_status": expectation.case_status,
            "delivery_status": expectation.delivery_status,
        }
        for field_name, expected_value in expected_values.items():
            self.assertEqual(getattr(result, field_name), expected_value, f"{expectation.stage}:{field_name}")

    def _copy_store(self, store: FinancialOwner, name: str) -> Path:
        target = self._path(name)
        target.write_bytes(_image(store.path))
        return target

    def _snapshot_on_tampered_path(self, path: Path, source: FinancialOwner) -> None:
        # Layer 1: Owner open replays the history against the projections and
        # refuses the tampered facts before any read or write.
        before_open = path.read_bytes()
        with self.assertRaises(owner.FinancialIntegrityError) as refused:
            self._make_owner(path=path)
        self.assertEqual(path.read_bytes(), before_open)
        open_code = str(refused.exception)
        self.assertTrue(open_code.startswith("open_verification:"), open_code)
        # Layer 2: the adapter's own verifier, reading the file with no Owner at
        # all, must reject the same facts for the same reason.
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            try:
                adapter.build_locked_semantic_snapshot(
                    connection,
                    obligation_id=expected.H_OBLIGATION_ID,
                    authority_context=adapter.TrustedAuthorityContext.from_authority(source.trusted_authority),
                    evaluation_time_ms=2**63 - 2,
                    expected_config=source.config,
                    expected_scope=source.config,
                    expected_mode=source.mode,
                    expected_owner_id=source.owner_id,
                )
            except adapter.SemanticAdapterIntegrityError as error:
                self.assertEqual(str(error), "owner_verifier:" + open_code.removeprefix("open_verification:"))
                raise
            finally:
                connection.rollback()
        self.fail("the adapter accepted a tampered store")

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
        self.assertEqual(
            set(data["population"]),
            {
                "population_id",
                "pack_id",
                "cutoff_ms",
                "inclusion_rules",
                "expected_count",
                "source_complete",
                "imported_count",
                "validated_count",
                "validation_digest",
                "status",
            },
        )
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
        # Rebuilding from the same owner transaction state is byte-identical.
        self.assertEqual(self._snapshot(store).canonical_bytes, snapshot.canonical_bytes)
        self._assert_no_source_mutation(store, before_hash)

        # The fixed fixture remains an independently stated arithmetic fact.
        self.assertEqual(sum(item.owed_cents for item in expected.PROGRAM_ITEMS), EXPECTED_PROGRAM_TOTAL_CENTS)
        self.assertEqual(len(expected.PROGRAM_ITEMS), EXPECTED_HOSPITAL_COUNT)

    def test_snapshot_cannot_be_constructed_without_owner_validation(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        self._record_claim(store)
        snapshot = self._snapshot(store)
        source_hash = self._hash(store.path)

        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "snapshot_unverified"):
            adapter.LockedSemanticSnapshot(
                snapshot.canonical_bytes,
                snapshot.snapshot_digest,
                snapshot.obligation_id,
                snapshot.pre_evaluation_revision,
                snapshot.evaluation_time_ms,
            )
        self._assert_no_source_mutation(store, source_hash)

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

    def test_delivery_projection_uses_latest_action_creation_time_not_action_id(self) -> None:
        store = self._build_base()
        self._record_cash(store, EXPECTED_H_CASH_CENTS - EXPECTED_OFFSET_CENTS)  # 600,000 unpaid: request A (300,000) is open, so a second 300,000 offset still fits
        first_claim = self._record_claim(store)
        self._record_h_support(store)
        first_receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        self._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided
        store.reject_offset_and_authorize_correction(
            item_id=expected.H_ITEM_ID,
            claim_id=first_claim,
            expected_revision=first_receipt["revision"],
            action_id="action:z-old",
            decision_at_ms=expected.CORRECTION_AUTH_MS,
            evaluation_id=first_receipt["evaluation_id"],
            evaluation_result_digest=first_receipt["result_digest"],
        )
        store.acknowledge_action("action:z-old", "ack:z-old")

        self._advance_clock(store, expected.CORRECTION_AUTH_MS + 10)
        second_claim = "claim:obligation-item-h:new-v1"
        store.record_offset_claim(
            item_id=expected.H_ITEM_ID,
            claim_id=second_claim,
            amount_cents=EXPECTED_OFFSET_CENTS,
            evidence_id="evidence:offset-h:new",
            owner_role="CASE_OWNER",
            deadline_ms=expected.H_DUE_AT_MS,
        )
        self._advance_clock(store, expected.CORRECTION_AUTH_MS + 20)
        second_receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        store.authorize_offset(
            item_id=expected.H_ITEM_ID,
            claim_id=second_claim,
            expected_revision=second_receipt["revision"],
            action_id="action:a-new",
            decision_at_ms=expected.CORRECTION_AUTH_MS + 20,
            evaluation_id=second_receipt["evaluation_id"],
            evaluation_result_digest=second_receipt["result_digest"],
        )

        before_hash = self._hash(store.path)
        data = self._snapshot(store).data
        actions = {row["action_id"]: row for row in data["actions"]}
        self.assertLess("action:a-new", "action:z-old")
        self.assertLess(actions["action:z-old"]["created_at_ms"], actions["action:a-new"]["created_at_ms"])
        self.assertEqual(actions["action:z-old"]["status"], "ACKNOWLEDGED")
        self.assertEqual(actions["action:a-new"]["status"], "READY")
        self.assertEqual(data["obligation"]["delivery_status"], "READY")
        outbox = {row["action_id"]: row for row in data["action_outbox"]}
        self.assertEqual((outbox["action:z-old"]["status"], outbox["action:z-old"]["attempt"]), ("ACKNOWLEDGED", 1))
        self.assertEqual((outbox["action:a-new"]["status"], outbox["action:a-new"]["attempt"]), ("READY", 0))
        self._assert_no_source_mutation(store, before_hash)

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
        self._prepare_final(store)
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

    def test_real_owner_histories_conform_to_lean_worker(self) -> None:
        authorized = self._build_base()
        self._record_cash(authorized)
        authorized_claim = self._record_claim(authorized)
        self._record_h_support(authorized)
        self._authorize(authorized, authorized_claim)
        self._assert_fresh_engine_history_result(
            authorized,
            expected.H_AUTHORIZED_OFFSET,
            completion_at_ms=expected.OFFSET_DECISION_MS,
        )

        package = authorized.export_continuity()
        shadow = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("engine-shadow.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
            restore_mode="SHADOW",
        )
        test_owner = FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=self._path("engine-test.sqlite"),
            trusted_authority=self.authority,
            clock=_Clock(),
            restore_mode="TEST",
        )
        self._assert_fresh_engine_history_result(
            shadow,
            expected.H_AUTHORIZED_OFFSET,
            completion_at_ms=expected.OFFSET_DECISION_MS,
        )
        self._assert_fresh_engine_history_result(
            test_owner,
            expected.H_AUTHORIZED_OFFSET,
            completion_at_ms=expected.OFFSET_DECISION_MS,
        )

        acknowledged = self._build_base()
        self._prepare_acknowledged(acknowledged)
        self._assert_fresh_engine_history_result(
            acknowledged,
            expected.H_ACKNOWLEDGED,
            completion_at_ms=None,
        )

        final = self._build_base()
        self._prepare_final(final)
        self._record_duplicate_conflict_reversal_replacement(final)
        self._assert_fresh_engine_history_result(
            final,
            expected.H_P3_REPLACED,
            completion_at_ms=expected.P3_EVENT_MS,
        )

    def test_correction_refuses_an_unavailable_worker_without_mutation(self) -> None:
        store = self._build_base()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        before_hash = self._hash(store.path)
        before_package = store.export_continuity()
        before_data = self._snapshot(store).data

        command = {
            "item_id": expected.H_ITEM_ID,
            "claim_id": claim_id,
            "expected_revision": receipt["revision"],
            "action_id": expected.ACTION_CORRECTION_ID,
            "decision_at_ms": expected.CORRECTION_AUTH_MS,
            "evaluation_id": receipt["evaluation_id"],
            "evaluation_result_digest": receipt["result_digest"],
        }
        self._advance_clock(store, expected.CORRECTION_AUTH_MS)  # recorded when decided

        with (
            patch.object(financial_engine, "_running_evaluator", side_effect=process.VerifierProcessError("worker_unavailable")),
            patch.object(financial_engine, "evaluate_live", return_value=object()) as projection_bypass,
        ):
            with self.assertRaisesRegex(
                owner.FinancialIntegrityError,
                "correction_transition_failed",
            ):
                store.reject_offset_and_authorize_correction(**command)
            projection_bypass.assert_not_called()

        self._assert_no_source_mutation(store, before_hash)
        self.assertEqual(store.export_continuity(), before_package)
        after_data = self._snapshot(store).data
        self.assertEqual(after_data["obligation"]["revision"], before_data["obligation"]["revision"])
        self.assertEqual(after_data["claims"], before_data["claims"])
        self.assertEqual(after_data["determinations"], before_data["determinations"])
        self.assertEqual(after_data["actions"], before_data["actions"])
        self.assertEqual(after_data["action_outbox"], before_data["action_outbox"])

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

        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "owner_verifier:meta:authority-binding"):
            self._snapshot(
                store,
                context=adapter.TrustedAuthorityContext.from_authority(
                    SyntheticTrustedAuthority(epoch=2),
                    source="HISTORICAL",
                ),
            )
        self._assert_no_source_mutation(store, source_hash)

        with closing(store._connect()) as connection:
            connection.execute("BEGIN")
            with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "evaluation_time_binding|obligation_after_evaluation"):
                adapter.build_locked_semantic_snapshot(
                    connection,
                    obligation_id=expected.H_OBLIGATION_ID,
                    authority_context=adapter.TrustedAuthorityContext.from_authority(self.authority),
                    evaluation_time_ms=expected.CASH_EVENT_MS,
                    expected_config=store.config,
                    expected_scope=store.config,
                    expected_mode=store.mode,
                    expected_owner_id=store.owner_id,
                )
            connection.rollback()
        self._assert_no_source_mutation(store, source_hash)

        tampered_evidence = self._copy_store(store, "tampered-evidence.sqlite")
        with closing(sqlite3.connect(str(tampered_evidence))) as connection:
            connection.execute("DELETE FROM evidence WHERE evidence_id=?", (expected.H_CASH_EVIDENCE.evidence_id,))
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "owner_verifier:foreign-keys:payments"):
            self._snapshot_on_tampered_path(tampered_evidence, store)

        tampered_role = self._copy_store(store, "tampered-role.sqlite")
        with closing(sqlite3.connect(str(tampered_role))) as connection:
            connection.execute("UPDATE determinations SET actor_role='REPORTING_EDITOR' WHERE determination_id=?", (f"determination:{expected.ACTION_OFFSET_ID}",))
            connection.commit()
        # Since 62f1671 the checker's actor-role gate always fires against the
        # digest-bound roster (it was fail-open before), so a role the actor
        # does not hold is rejected ahead of the determination digest check.
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "owner_verifier:determination:actor-role"):
            self._snapshot_on_tampered_path(tampered_role, store)

        tampered_status = self._copy_store(store, "tampered-status.sqlite")
        with closing(sqlite3.connect(str(tampered_status))) as connection:
            connection.execute("DELETE FROM determinations WHERE determination_id=?", (f"determination:{expected.ACTION_OFFSET_ID}",))
            connection.commit()
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "owner_verifier:foreign-keys:actions"):
            self._snapshot_on_tampered_path(tampered_status, store)

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
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "owner_verifier:projection:cash:overflow"):
            self._snapshot_on_tampered_path(overflow, store)

        deeply_nested = "0"
        for _ in range(40):
            deeply_nested = f"[{deeply_nested}]"
        with self.assertRaisesRegex(adapter.SemanticAdapterIntegrityError, "json_depth"):
            adapter._parse_json_column(deeply_nested, "deep_json")
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
        encoded = adapter._encode_blfres02_result(result)
        self.assertEqual(encoded[: len(adapter.BLFRES02_MAGIC)], adapter.BLFRES02_MAGIC)
        decoded = adapter.decode_live_result(encoded, data)
        self.assertEqual(decoded, result)

        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "result_magic"):
            adapter.decode_live_result(b"BLFRES01" + encoded[len(adapter.BLFRES02_MAGIC) :], data)
        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "wire_trailing_bytes"):
            adapter.decode_live_result(encoded + b"\x00", data)
        with self.assertRaisesRegex(adapter.SemanticAdapterAuthorityError, "result_authority_binding"):
            adapter.decode_live_result(
                adapter._encode_blfres02_result(replace(result, authority_epoch=result.authority_epoch + 1)), data
            )
        bad_tag = bytearray(encoded)
        bad_tag[-1] = 0x7F
        with self.assertRaisesRegex(adapter.SemanticAdapterCodecError, "delivery_status"):
            adapter.decode_live_result(bytes(bad_tag), data)
        self.assertEqual(obligation["received_cash_cents"], EXPECTED_H_CASH_CENTS)

    def test_record_cache_leaves_history_and_refusals_as_without_it(self) -> None:
        """Six payments on one item on two identical stores, without and with the record cache, export identical
        history; a record the encoder refuses fails under its own label either way."""
        histories = []
        for encode in (adapter._record_wire.__wrapped__, adapter._record_wire):
            adapter._record_wire.cache_clear()
            store = self._build_base()
            with patch.object(adapter, "_record_wire", encode):
                for number in range(6):
                    store.record_payment_evidence(item_id=expected.H_ITEM_ID, payment_id=f"cache-payment-{number}", common_origin_id=f"cache-origin-{number}",
                                                  amount_cents=100, evidence_id=f"cache-evidence-{number}", event_at_ms=expected.CASH_EVENT_MS)
            directory = self._path(f"history-{len(histories)}")
            store.export_history(directory)
            histories.append({path.name: path.read_bytes() for path in directory.iterdir()})
        self.assertGreater(adapter._record_wire.cache_info().hits, 0)
        self.assertEqual(histories[0], histories[1])
        data = self._snapshot(store).data
        for key, value, code in (("amount_cents", True, "evidence_0_amount"), ("kind", ["unhashable"], "evidence_0_kind")):
            refused = dict(data, evidence=[dict(data["evidence"][0], **{key: value}), *data["evidence"][1:]])
            for encode in (adapter._record_wire.__wrapped__, adapter._record_wire):
                with patch.object(adapter, "_record_wire", encode), self.assertRaisesRegex(adapter.SemanticAdapterCodecError, f"^{code}$"):
                    adapter._encode_blfin02(refused)


if __name__ == "__main__":
    unittest.main()
