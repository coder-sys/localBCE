"""Focused adversarial tests for the synthetic Transaction Mirror V1 seam."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import contract_mirror as contract
from app.mirror import denominator_ledger as denominator
from app.mirror import denominator_ledger_independent as denominator_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import source_reconciliation as reconciliation
from app.mirror import support_boundary as support
from app.mirror import transaction_mirror as transaction
from app.mirror import transaction_mirror_independent as transaction_independent
from tests.test_mirror_source_evidence_custody import _approved_store, _envelope


def _payload(instance: store.ContinuityStore, receipt: store.AdmissionReceipt) -> bytes:
    connection = sqlite3.connect(instance.path)
    try:
        row = connection.execute(
            "SELECT a.payload FROM artifacts a JOIN operations o ON o.artifact_kind=a.kind AND o.artifact_id=a.artifact_id WHERE o.operation_id=?",
            (receipt.operation_id,),
        ).fetchone()
        if row is None:
            raise AssertionError("receipt has no artifact")
        return bytes(row[0])
    finally:
        connection.close()


def _rebind(value: dict[str, object], identity_values) -> bytes:
    body = deepcopy(value)
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id, stage_id, transition_id = identity_values(body)
    return json.dumps(
        {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class MirrorTransactionMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mirror-transaction-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _setup(self, name: str = "state.db") -> tuple[store.ContinuityStore, dict[str, object], str, transaction.TransactionMirrorService]:
        database_root = self.root / name.replace(".db", "")
        database_root.mkdir()
        instance, registry, _ = _approved_store(database_root)
        source_admission = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry).ingest(_envelope())
        if source_admission.graph_receipt is None:
            raise AssertionError("fixture graph was not admitted")
        source_raw = _payload(instance, source_admission.custody_receipt)
        source_id = custody_independent._parse(source_raw)["artifact_id"]
        denominator_service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        denominator_service.create_baseline(str(source_id))
        baseline_row = next(
            row for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == denominator_independent.ARTIFACT_KIND
            and json.loads(row["payload"].decode("ascii")).get("stage_kind") == denominator_independent.STAGE_BASELINE
        )
        narrowed = denominator_service.narrow(str(baseline_row["artifact_id"]))
        narrowed_value = json.loads(_payload(instance, narrowed).decode("ascii"))
        reconciliation_receipt = reconciliation.SourceReconciliationService(instance, graph_profile_registry=registry).reconcile(source_raw)
        reconciliation_value = json.loads(_payload(instance, reconciliation_receipt).decode("ascii"))
        graph_id = narrowed_value["source_binding"]["graph_artifact_id"]
        graph_row = next(row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == store.ARTIFACT_GRAPH and row["artifact_id"] == graph_id)
        finding_id = json.loads(bytes(graph_row["payload"]).decode("ascii"))["findings"][0]["finding_id"]
        contract_receipt = contract.ContractMirrorService(instance, graph_profile_registry=registry).evaluate(
            str(narrowed_value["artifact_id"]),
            str(reconciliation_value["artifact_id"]),
            str(finding_id),
        )
        contract_value = json.loads(_payload(instance, contract_receipt).decode("ascii"))
        return instance, registry, str(contract_value["artifact_id"]), transaction.TransactionMirrorService(instance, graph_profile_registry=registry)

    def test_full_trace_binds_each_phase_and_exact_retry(self) -> None:
        instance, registry, contract_id, service = self._setup()
        first = service.trace(contract_id)
        retry = service.trace(contract_id)
        self.assertEqual(first.raw, retry.raw)
        value = transaction_independent._parse(_payload(instance, first))
        self.assertEqual(transaction_independent.TRACE_STAGES[0], value["stage_kind"])
        self.assertEqual(transaction_independent.BASE_PHASES, tuple(item["name"] for item in value["phases"]))
        self.assertEqual([transaction_independent.STATUS_OBSERVED] * 5, [item["status"] for item in value["phases"]])
        self.assertEqual(transaction_independent.DIVERGENCE_NONE, value["divergence"]["status"])
        self.assertFalse(value["flags"]["payment_movement"])
        self.assertFalse(value["authority"]["payment_authority"])
        observation_row = next(
            row for row in instance._snapshot_rows()["artifacts"] if row["kind"] == store.ARTIFACT_TRANSACTION_OBSERVATION
        )
        self.assertEqual(12_500, json.loads(bytes(observation_row["payload"]).decode("ascii"))["evidence"]["official"]["amount_minor"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_gapped_and_mismatched_outcomes_are_explicit(self) -> None:
        gapped, registry, contract_id, service = self._setup("gapped.db")
        gapped_receipt = service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_GAPPED)
        gapped_value = transaction_independent._parse(_payload(gapped, gapped_receipt))
        self.assertEqual(transaction_independent.STATUS_GAPPED, gapped_value["phases"][3]["status"])
        self.assertEqual(transaction_independent.STATUS_GAPPED, gapped_value["phases"][4]["status"])
        self.assertEqual(transaction_independent.DIVERGENCE_UNKNOWN, gapped_value["divergence"]["status"])
        self.assertIsNone(gapped_value["case_link"])

        mismatched, registry, contract_id, service = self._setup("mismatched.db")
        mismatch_receipt = service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_MISMATCHED)
        mismatch_value = transaction_independent._parse(_payload(mismatched, mismatch_receipt))
        self.assertEqual(transaction_independent.DIVERGENCE_OBSERVED, mismatch_value["divergence"]["status"])
        self.assertIsNotNone(mismatch_value["case_link"])
        self.assertTrue(store_independent.verify_database(mismatched.path, registry)["accepted"])

    def test_correction_and_appeal_append_immutable_trace_history(self) -> None:
        instance, registry, contract_id, service = self._setup()
        initial = service.trace(contract_id)
        initial_raw = _payload(instance, initial)
        initial_value = transaction_independent._parse(initial_raw)
        corrected = service.correct(transaction_independent._parse(initial_raw)["artifact_id"])
        corrected_retry = service.correct(transaction_independent._parse(initial_raw)["artifact_id"])
        self.assertEqual(corrected.raw, corrected_retry.raw)
        corrected_value = transaction_independent._parse(_payload(instance, corrected))
        self.assertEqual(transaction_independent.TRACE_STAGES[1], corrected_value["stage_kind"])
        self.assertEqual(transaction_independent.PHASE_CORRECTION, corrected_value["phases"][-1]["name"])
        self.assertEqual(initial_value, transaction_independent._parse(initial_raw))
        appealed = service.appeal(corrected_value["artifact_id"])
        appealed_value = transaction_independent._parse(_payload(instance, appealed))
        self.assertEqual(transaction_independent.TRACE_STAGES[2], appealed_value["stage_kind"])
        self.assertEqual(transaction_independent.PHASE_APPEAL, appealed_value["phases"][-1]["name"])
        self.assertEqual(corrected_value["artifact_id"], appealed_value["prior_artifact_id"])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_independent_verifier_rejects_role_phase_and_divergence_rebinding(self) -> None:
        instance, registry, contract_id, service = self._setup()
        receipt = service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_MISMATCHED)
        raw = _payload(instance, receipt)
        before = store_independent.verify_database(instance.path, registry)
        connection = instance._connect()
        try:
            context = instance._transaction_context_for_raw(connection, raw, require_contract_head=False)
            original = transaction_independent._parse(raw)
            def remove_phase(value: dict[str, object]) -> dict[str, object]:
                value["phases"].pop()
                return value

            def change_role(value: dict[str, object]) -> dict[str, object]:
                value["phases"][3]["evidence"]["role"] = "PROCESSOR"
                return value

            def change_divergence(value: dict[str, object]) -> dict[str, object]:
                value["divergence"] = {
                    "status": transaction_independent.DIVERGENCE_NONE,
                    "reason": "BOUNDARY_RESULTS_MATCHED",
                    "dimensions": [],
                }
                return value

            for mutation in (
                change_role,
                change_divergence,
                remove_phase,
            ):
                forged = mutation(deepcopy(original))
                candidate = _rebind(forged, transaction_independent._identity_values)
                with self.assertRaises(transaction_independent.IndependentTransactionMirrorError):
                    transaction_independent.verify_trace_artifact(
                        candidate,
                        source_raw=context["source_raw"],
                        contract_raw=context["contract_raw"],
                        contract_context=context["contract_context"],
                        observation_raw=context["observation_raw"],
                        registry=registry,
                        prior_trace_raw=context.get("prior_trace_raw"),
                        prior_observation_raw=context.get("prior_observation_raw"),
                    )
        finally:
            connection.close()
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

    def test_binding_phase_and_boundary_mutations_fail_closed(self) -> None:
        instance, registry, contract_id, service = self._setup()
        receipt = service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_MISMATCHED)
        raw = _payload(instance, receipt)
        original = transaction_independent._parse(raw)
        connection = instance._connect()
        try:
            context = instance._transaction_context_for_raw(connection, raw, require_contract_head=False)
            verify_kwargs = {
                "source_raw": context["source_raw"],
                "contract_raw": context["contract_raw"],
                "contract_context": context["contract_context"],
                "observation_raw": context["observation_raw"],
                "registry": registry,
                "prior_trace_raw": context.get("prior_trace_raw"),
                "prior_observation_raw": context.get("prior_observation_raw"),
            }
            trace_mutations = {
                "wrong-input": lambda value: value["input_binding"].__setitem__("artifact_id", "0" * 128),
                "wrong-denominator": lambda value: value["contract_binding"].__setitem__("denominator_population_root", "0" * 128),
                "wrong-profile": lambda value: value["profile_binding"].__setitem__("profile_digest", "0" * 128),
                "wrong-effective-interval": lambda value: value["contract_binding"].__setitem__("effective_start", 7_999),
                "reordered-time": lambda value: value["chronology"].__setitem__("observed_times", list(reversed(value["chronology"]["observed_times"]))),
                "missing-phase": lambda value: value["phases"].pop(3),
                "case-substitution": lambda value: value["case_link"].__setitem__("case_id", "0" * 128),
            }
            for label, mutate in trace_mutations.items():
                with self.subTest(label=label):
                    forged = deepcopy(original)
                    mutate(forged)
                    candidate = _rebind(forged, transaction_independent._identity_values)
                    with self.assertRaises(transaction_independent.IndependentTransactionMirrorError):
                        transaction_independent.verify_trace_artifact(candidate, **verify_kwargs)

            observation_raw = verify_kwargs["observation_raw"]
            observation_value = transaction_independent._parse(observation_raw)
            observation_mutations = {
                "official-amount": lambda value: value["evidence"]["official"].__setitem__("amount_minor", 1),
                "official-currency": lambda value: value["evidence"]["official"].__setitem__("currency", "EUR"),
                "official-status": lambda value: value["evidence"]["official"].__setitem__("status", transaction_independent.STATUS_UNKNOWN),
                "processor-official-role": lambda value: value["evidence"]["official"].__setitem__("boundary_id", "SYNTH_PROCESSOR_BOUNDARY_V1"),
            }
            for label, mutate in observation_mutations.items():
                with self.subTest(label=label):
                    forged_observation = deepcopy(observation_value)
                    mutate(forged_observation)
                    forged_observation_raw = _rebind(forged_observation, transaction_independent._identity_values)
                    with self.assertRaises(transaction_independent.IndependentTransactionMirrorError):
                        transaction_independent.verify_observation_artifact(
                            forged_observation_raw,
                            source_raw=context["source_raw"],
                            contract_raw=context["contract_raw"],
                            contract_context=context["contract_context"],
                            registry=registry,
                            prior_observation_raw=None,
                        )
        finally:
            connection.close()
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_missing_predecessor_parser_caps_and_fork_replay_fail_closed(self) -> None:
        instance, registry, contract_id, service = self._setup()
        initial = service.trace(contract_id)
        initial_raw = _payload(instance, initial)
        initial_value = transaction_independent._parse(initial_raw)
        connection = instance._connect()
        try:
            context = instance._transaction_contract_context(connection, contract_id, require_head=False)
            correction_raw = transaction.build_observation_artifact(
                transaction_independent.FIXTURE_CORRECTION,
                source_raw=context["source_raw"],
                contract_raw=context["contract_raw"],
            )
            with self.assertRaises(transaction_independent.IndependentTransactionMirrorError):
                transaction_independent.verify_observation_artifact(
                    correction_raw,
                    source_raw=context["source_raw"],
                    contract_raw=context["contract_raw"],
                    contract_context=context["contract_context"],
                    registry=registry,
                    prior_observation_raw=None,
                )
        finally:
            connection.close()

        corrected = service.correct(initial_value["artifact_id"])
        before = store_independent.verify_database(instance.path, registry)
        corrected_value = transaction_independent._parse(_payload(instance, corrected))
        with self.assertRaises(store.ArtifactAdmissionError):
            service.correct(corrected_value["artifact_id"])
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))

        for raw in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":1.0}',
            b'{"x":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
            b'{"x":"' + b"a" * transaction_independent.MAX_ARTIFACT_BYTES + b'"}',
        ):
            with self.assertRaises(transaction_independent.IndependentTransactionMirrorError):
                transaction_independent._parse(raw)

    def test_database_and_export_corruption_are_rejected(self) -> None:
        instance, registry, contract_id, service = self._setup()
        service.trace(contract_id)
        exported = export.export_database(instance.path, registry)
        corrupted_export = bytearray(exported)
        corrupted_export[-1] = ord("0") if corrupted_export[-1] != ord("0") else ord("1")
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(bytes(corrupted_export), registry)

        connection = sqlite3.connect(instance.path)
        try:
            connection.execute(
                "UPDATE artifacts SET payload=? WHERE kind=?",
                (b"{}", store.ARTIFACT_TRANSACTION_TRACE),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(store_independent.IndependentStoreError):
            store_independent.verify_database(instance.path, registry)

    def test_fault_rollback_and_direct_admission_rejection(self) -> None:
        instance, registry, contract_id, service = self._setup()
        with self.assertRaisesRegex(store.StoreConflictError, "transaction-required"):
            instance.admit(store.ARTIFACT_TRANSACTION_TRACE, b"not-a-direct-admission")
        before = store_independent.verify_database(instance.path, registry)
        instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            service.trace(contract_id)
        self.assertEqual(before, store_independent.verify_database(instance.path, registry))
        self.assertTrue(service.trace(contract_id).raw)

    def test_same_trace_converges_under_concurrency(self) -> None:
        instance, registry, contract_id, service = self._setup()
        results: list[bytes] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                results.append(service.trace(contract_id).raw)
            except BaseException as exc:  # test evidence only
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(failures)
        self.assertEqual(2, len(results))
        self.assertEqual(results[0], results[1])
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_withdrawal_preserves_history_but_blocks_new_correction(self) -> None:
        instance, registry, contract_id, service = self._setup()
        initial = service.trace(contract_id)
        initial_value = transaction_independent._parse(_payload(instance, initial))
        approval_row = next(
            row for row in instance._snapshot_rows()["artifacts"]
            if row["kind"] == store.ARTIFACT_GOVERNANCE
            and json.loads(row["payload"].decode("ascii")).get("current_stage_kind") == governance.STAGE_APPROVED
        )
        approval_raw = bytes(approval_row["payload"])
        auth = governance.build_withdrawal_authorization(approval_raw, profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
        withdrawal, _ = governance.build_withdrawal(approval_raw, auth, profile.NC_MEDICAID_GRAPH_PROFILE)
        instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
        self.assertEqual(initial.raw, service.trace(contract_id).raw)
        with self.assertRaises(store.GovernanceObservationOnly):
            service.correct(initial_value["artifact_id"])
        with self.assertRaises(store.GovernanceObservationOnly):
            service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_GAPPED)
        self.assertTrue(store_independent.verify_database(instance.path, registry)["accepted"])

    def test_export_restore_support_and_no_raw_fixture_identifiers(self) -> None:
        instance, registry, contract_id, service = self._setup()
        service.trace(contract_id, fixture_id=transaction_independent.FIXTURE_MISMATCHED)
        support_raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        support_result = support.verify_support_bytes(support_raw)
        self.assertTrue(support_result["accepted"])
        self.assertNotIn(transaction_independent.TRACE_SCHEMA.encode("ascii"), support_raw)
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID.encode("ascii"), support_raw)
        exported = export.export_database(instance.path, registry)
        self.assertTrue(export.verify_export_bytes(exported, registry)["accepted"])
        restored = self.root / "restored.db"
        self.assertTrue(export.import_export(exported, restored, registry)["restored"])
        self.assertEqual(
            store_independent.verify_database(instance.path, registry),
            store_independent.verify_database(restored, registry),
        )


if __name__ == "__main__":
    unittest.main()
