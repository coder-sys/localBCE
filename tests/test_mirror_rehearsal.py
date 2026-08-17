from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
from threading import Barrier
import unittest

from tests.test_nc_medicaid_fhir_source import _envelope

from app.mirror import continuity_export
from app.mirror import continuity_store_independent
from app.mirror import rehearsal
from app.mirror import rehearsal_independent
from app.mirror import support_boundary
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_GRAPH_PROFILE_REGISTRY


class MirrorRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = dict(NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        cls.tempdir = tempfile.TemporaryDirectory(prefix="mirror-rehearsal-tests-")
        cls.path = Path(cls.tempdir.name) / "state.db"
        cls.source = _envelope()
        cls.result = rehearsal.run_rehearsal(cls.source, cls.path)
        cls.receipt_value = json.loads(cls.result.receipt_raw.decode("ascii"))
        cls.ledger_value = json.loads(cls.result.evidence_ledger_raw.decode("ascii"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def test_full_chain_is_independently_reconstructed_and_nonactivating(self) -> None:
        verified = rehearsal_independent.verify_receipt(
            self.result.receipt_raw,
            self.result.export_raw,
            graph_profile_registry=self.registry,
        )
        ledger = rehearsal_independent.verify_evidence_ledger(
            self.result.evidence_ledger_raw,
            self.result.receipt_raw,
        )
        database = continuity_store_independent.verify_database(self.path, self.registry)
        continuity_export.verify_export_bytes(self.result.export_raw, self.registry)
        support_boundary.verify_support_bytes(self.result.support_raw)

        self.assertEqual(24, verified["artifact_count"])
        self.assertEqual(24, verified["event_count"])
        self.assertEqual(verified["receipt_id"], ledger["receipt_id"])
        self.assertEqual(24, database["artifact_count"])
        self.assertEqual(24, database["event_count"])
        self.assertEqual(24, database["receipt_count"])
        self.assertEqual(13, database["head_count"])
        self.assertEqual("SYNTHETIC_REHEARSAL_READY", verified["qualification_claim"])
        self.assertFalse(self.receipt_value["authority"]["controlled_shadow_ready"])
        self.assertFalse(self.receipt_value["authority"]["production_ready"])
        self.assertFalse(self.receipt_value["authority"]["activation"])
        self.assertFalse(self.receipt_value["authority"]["economic_mutation"])
        self.assertEqual("SYNTHETIC_REHEARSAL_READY", self.receipt_value["outcomes"]["qualification_claim"])

    def test_component_owners_and_canonical_roots_are_recorded(self) -> None:
        identities = self.ledger_value["canonical_identities"]
        self.assertEqual(
            {
                "governance", "source_custody", "provider_trust_graph", "source_reconciliation",
                "denominator", "case_lifecycle", "contract", "transaction", "money", "transition",
                "state_value", "qualification",
            },
            set(identities),
        )
        self.assertEqual(3, len(identities["governance"]))
        self.assertEqual(6, len(identities["case_lifecycle"]))
        self.assertEqual(2, len(identities["denominator"]))
        self.assertEqual(self.receipt_value["chain"]["state_root"], self.ledger_value["canonical_roots"]["state_root"])
        self.assertEqual(
            self.receipt_value["export_binding"]["export_root"],
            self.ledger_value["canonical_roots"]["export_root"],
        )

    def test_exact_retry_is_byte_identical(self) -> None:
        retry = rehearsal.run_rehearsal(self.source, self.path)
        self.assertEqual(self.result.receipt_raw, retry.receipt_raw)
        self.assertEqual(self.result.evidence_ledger_raw, retry.evidence_ledger_raw)
        self.assertEqual(self.result.export_raw, retry.export_raw)
        self.assertEqual(self.result.support_raw, retry.support_raw)
        verified = continuity_store_independent.verify_database(self.path, self.registry)
        self.assertEqual(24, verified["artifact_count"])
        self.assertEqual(24, verified["event_count"])

    def test_two_exact_concurrent_rehearsals_converge_to_one_chain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-concurrent-") as temporary:
            path = Path(temporary) / "state.db"
            barrier = Barrier(2)

            def worker() -> rehearsal.RehearsalResult:
                barrier.wait()
                return rehearsal.run_rehearsal(self.source, path)

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker) for _ in range(2)]
                results = [future.result() for future in futures]

            self.assertEqual(results[0].receipt_raw, results[1].receipt_raw)
            self.assertEqual(results[0].export_raw, results[1].export_raw)
            verified = continuity_store_independent.verify_database(path, self.registry)
            self.assertEqual(24, verified["artifact_count"])
            self.assertEqual(24, verified["event_count"])
            self.assertEqual(24, verified["receipt_count"])
            self.assertEqual(13, verified["head_count"])

    def test_receipt_export_and_ledger_rebinding_fail_closed(self) -> None:
        forged_receipt = dict(self.receipt_value)
        forged_receipt["outcomes"] = dict(forged_receipt["outcomes"])
        forged_receipt["outcomes"]["qualification_claim"] = "CONTROLLED_SHADOW_READY"
        forged_body = dict(forged_receipt)
        forged_body.pop("receipt_id")
        forged_receipt["receipt_id"] = rehearsal_independent._digest("receipt-id", forged_body)
        with self.assertRaises(rehearsal_independent.IndependentRehearsalError):
            rehearsal_independent.verify_receipt(
                rehearsal_independent._canonical(forged_receipt),
                self.result.export_raw,
                graph_profile_registry=self.registry,
            )

        corrupted_export = bytearray(self.result.export_raw)
        corrupted_export[len(corrupted_export) // 2] ^= 1
        with self.assertRaises(Exception):
            rehearsal_independent.verify_receipt(
                self.result.receipt_raw,
                bytes(corrupted_export),
                graph_profile_registry=self.registry,
            )

        forged_ledger = dict(self.ledger_value)
        forged_ledger["canonical_roots"] = dict(forged_ledger["canonical_roots"])
        forged_ledger["canonical_roots"]["state_root"] = "0" * 128
        forged_body = dict(forged_ledger)
        forged_body.pop("ledger_id")
        forged_ledger["ledger_id"] = rehearsal_independent._digest("ledger-id", forged_body)
        with self.assertRaises(rehearsal_independent.IndependentRehearsalError):
            rehearsal_independent.verify_evidence_ledger(
                rehearsal_independent._canonical(forged_ledger),
                self.result.receipt_raw,
            )

    def test_restore_corruption_and_registry_substitution_fail_without_claim_upgrade(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-restore-test-") as temporary:
            restored = Path(temporary) / "restored.db"
            continuity_export.import_export(self.result.export_raw, restored, self.registry)
            self.assertEqual(
                continuity_store_independent.verify_database(self.path, self.registry),
                continuity_store_independent.verify_database(restored, self.registry),
            )
            bad = bytearray(self.result.export_raw)
            bad[-17] ^= 1
            with self.assertRaises(Exception):
                continuity_export.import_export(bytes(bad), Path(temporary) / "bad.db", self.registry)

        with self.assertRaises(Exception):
            rehearsal_independent.verify_receipt(
                self.result.receipt_raw,
                self.result.export_raw,
                graph_profile_registry={},
            )
        self.assertFalse(self.result.recovery["production_ha"])
        self.assertFalse(self.result.recovery["production_dr"])

    def test_invalid_source_fails_before_material_admission(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-invalid-") as temporary:
            path = Path(temporary) / "state.db"
            with self.assertRaises(rehearsal.RehearsalError):
                rehearsal.run_rehearsal(self.source[:-1] + b"x", path)
            verified = continuity_store_independent.verify_database(path, self.registry)
            self.assertEqual(0, verified["artifact_count"])
            self.assertEqual(0, verified["event_count"])
            self.assertEqual(0, verified["receipt_count"])
            self.assertEqual(0, verified["head_count"])

    def test_support_and_receipt_surfaces_do_not_repeat_fixture_record_values(self) -> None:
        forbidden = (b"NCPROV-001", b"NCROLE-001", b"NCLOC-001", b"Synthetic NC Site", b"1 Synthetic Way")
        public_surfaces = self.result.receipt_raw + self.result.evidence_ledger_raw + self.result.support_raw
        for value in forbidden:
            self.assertNotIn(value, public_surfaces)
        self.assertNotIn(b"CONTROLLED_SHADOW_READY", self.result.receipt_raw)
        self.assertNotIn(b"PRODUCTION_READY", self.result.receipt_raw)

    def test_machine_ledger_accepts_explicit_run_evidence_and_bounded_telemetry(self) -> None:
        ledger_raw = rehearsal.build_evidence_ledger(
            self.result.receipt_raw,
            artifact_count=24,
            event_count=24,
            transition_count=24,
            mutation_cases=7,
            fault_cases=5,
            recovery_cases=4,
            concurrency_cases=2,
            worker_commands=({"command": "focused-rehearsal-suite", "exit_code": 0},),
            warnings=({"scope": "resource-telemetry", "reason": "process-tree-counter-not-measured"},),
            skips=({"scope": "live-network", "reason": "live transport is disabled"},),
            process_tree_peak_bytes=None,
            measured_process_tree=False,
        )
        verified = rehearsal_independent.verify_evidence_ledger(ledger_raw, self.result.receipt_raw)
        self.assertEqual(7, verified["counts"]["mutation_cases"])
        value = json.loads(ledger_raw.decode("ascii"))
        self.assertEqual("complete_process_tree_peak_bytes", value["resource_telemetry"]["counter_name"])
        self.assertFalse(value["resource_telemetry"]["measured"])


if __name__ == "__main__":
    unittest.main()
