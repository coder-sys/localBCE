from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import ctypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from threading import Barrier
from typing import Callable
import unittest
from unittest.mock import patch

from tests.test_nc_medicaid_fhir_source import _envelope, _rebind

from app.governance import provider_continuity_control_pack_v2 as governance_v2
from app.mirror import continuity_export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent
from app.mirror import provider_trust_graph as graph
from app.mirror import qualification_fixtures
from app.mirror import rehearsal
from app.mirror import rehearsal_independent
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import support_boundary
from app.mirror import nc_medicaid_fhir_profile as source_profile
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_GRAPH_PROFILE_REGISTRY
from tests.rehearsal_job_object import run_job_object
from tests import rehearsal_job_object


@dataclass(frozen=True)
class _MatrixCase:
    category: str
    name: str
    operation: str


class RehearsalJobObjectAbiTests(unittest.TestCase):
    def test_extended_limit_information_matches_windows_abi_order(self) -> None:
        fields = [name for name, _field_type in rehearsal_job_object._ExtendedLimitInformation._fields_]
        self.assertEqual(
            [
                "BasicLimitInformation",
                "IoInfo",
                "ProcessMemoryLimit",
                "JobMemoryLimit",
                "PeakProcessMemoryUsed",
                "PeakJobMemoryUsed",
            ],
            fields,
        )
        size = ctypes.sizeof(ctypes.c_size_t)
        offsets = {
            name: getattr(rehearsal_job_object._ExtendedLimitInformation, name).offset
            for name in fields
        }
        self.assertEqual(offsets["ProcessMemoryLimit"] + size, offsets["JobMemoryLimit"])
        self.assertEqual(offsets["JobMemoryLimit"] + size, offsets["PeakProcessMemoryUsed"])
        self.assertEqual(offsets["PeakProcessMemoryUsed"] + size, offsets["PeakJobMemoryUsed"])


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

    def test_job_object_failures_are_explicit_and_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        cases = {
            "invalid-spawn": ([str(root / "does-not-exist-job-child.exe")], {}),
            "configuration": ([sys.executable, "-c", "import sys; sys.exit(0)"], {"_inject_failure": "configure"}),
            "assignment": ([sys.executable, "-c", "import sys; sys.exit(0)"], {"_inject_failure": "assign"}),
            "query": ([sys.executable, "-c", "import sys; sys.exit(0)"], {"_inject_failure": "query"}),
            "timeout": ([sys.executable, "-c", "import time; time.sleep(2)"], {}),
            "nonzero": ([sys.executable, "-c", "import sys; sys.exit(7)"], {}),
        }
        for label, (command, options) in cases.items():
            value = run_job_object(command, cwd=root, timeout_seconds=0.2, **options)
            print("JOB_OBJECT_FAILURE_EVIDENCE " + json.dumps({"case": label, **value}, sort_keys=True))
            self.assertTrue(isinstance(value["blocker"], str) and value["blocker"], (label, value))
            if label in {"invalid-spawn", "configuration", "assignment", "query"} or value["cap_enforced"] is not True:
                self.assertFalse(value["measured"], (label, value))
            self.assertEqual("PeakJobMemoryUsed", value["counter_name"])
            self.assertEqual("job_commit_charge_bytes", value["semantics"])
            self.assertEqual(5_000_000_000, value["cap_bytes"])

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
            execution_scope="matrix",
            case_results=self._contract_case_results(),
            resource_telemetry={
                "counter_name": "PeakJobMemoryUsed",
                "semantics": "job_commit_charge_bytes",
                "cap_bytes": 5_000_000_000,
                "cap_enforced": True,
                "measured": True,
                "process_tree_peak_bytes": 1,
                "exit_code": 0,
            },
            worker_commands=({"command": "focused-rehearsal-suite", "exit_code": 0},),
        )
        verified = rehearsal_independent.verify_evidence_ledger(ledger_raw, self.result.receipt_raw)
        self.assertEqual(39, verified["counts"]["mutation_cases"])
        value = json.loads(ledger_raw.decode("ascii"))
        self.assertEqual("PeakJobMemoryUsed", value["resource_telemetry"]["counter_name"])
        self.assertTrue(value["resource_telemetry"]["measured"])
        for label, mutate in (
            ("duplicate-case-id", lambda item: item.__setitem__("case_results", [item["case_results"][0], *item["case_results"][:-1]])),
            ("missing-case-id", lambda item: item.__setitem__("case_results", item["case_results"][:-1])),
            ("unknown-kind", lambda item: item["case_results"][0].__setitem__("kind", "unknown")),
            ("category-relabel", lambda item: item["case_results"][0].__setitem__("category", "wrong")),
            ("outcome-relabel", lambda item: item["case_results"][0].__setitem__("outcome", "ACCEPTED")),
            ("claimed-count", lambda item: item["counts"].__setitem__("mutation_cases", item["counts"]["mutation_cases"] + 1)),
        ):
            with self.subTest(ledger_mutation=label):
                forged = deepcopy(value)
                mutate(forged)
                forged_body = dict(forged)
                forged_body.pop("ledger_id")
                forged["ledger_id"] = rehearsal_independent._digest("ledger-id", forged_body)
                with self.assertRaises(rehearsal_independent.IndependentRehearsalError):
                    rehearsal_independent.verify_evidence_ledger(
                        rehearsal_independent._canonical(forged), self.result.receipt_raw
                    )

    @staticmethod
    def _rebind_export(value: dict[str, object]) -> bytes:
        body = dict(value)
        body.pop("export_root", None)
        return continuity_export._canonical({**body, "export_root": continuity_export._digest("export-root", body)})

    @staticmethod
    def _rebind_receipt(value: dict[str, object]) -> bytes:
        body = dict(value)
        body.pop("receipt_id", None)
        return rehearsal_independent._canonical({**body, "receipt_id": rehearsal_independent._digest("receipt-id", body)})

    @staticmethod
    def _forged_value(value: object) -> object:
        if isinstance(value, bool):
            return not value
        if type(value) is int:
            return value + 1
        if isinstance(value, dict):
            return {**value, "forged_matrix_field": "FORGED"}
        if isinstance(value, list):
            return [*value, "FORGED"]
        return "FORGED_MATRIX_VALUE"

    def _mutated_export_payload(self, kind: str, mutate: Callable[[dict[str, object]], None]) -> bytes:
        value = json.loads(self.result.export_raw.decode("ascii"))
        rows = value["artifacts"]
        self.assertIsInstance(rows, list)
        row = next(item for item in rows if item["kind"] == kind)
        payload = json.loads(bytes.fromhex(row["payload_hex"]).decode("ascii"))
        self.assertIsInstance(payload, dict)
        mutate(payload)
        row["payload_hex"] = rehearsal_independent._canonical(payload).hex()
        return self._rebind_export(value)

    def _mutated_receipt(self, mutate: Callable[[dict[str, object]], None]) -> bytes:
        value = deepcopy(self.receipt_value)
        mutate(value)
        return self._rebind_receipt(value)

    def _assert_matrix_reject(self, operation: Callable[[], object]) -> str:
        accepted = (
            rehearsal_independent.IndependentRehearsalError,
            continuity_export.ContinuityExportError,
            store.ContinuityStoreError,
            ValueError,
        )
        try:
            operation()
        except accepted as exc:
            return str(exc)
        self.fail("matrix mutation unexpectedly accepted")

    @staticmethod
    def _case_result(
        case_id: str,
        category: str,
        kind: str,
        outcome: str,
        status: str,
        error_code: str,
    ) -> dict[str, object]:
        return {
            "case_id": case_id,
            "category": category,
            "kind": kind,
            "outcome": outcome,
            "verifier_result": {"status": status, "error_code": error_code[:512] or "none"},
        }

    @classmethod
    def _contract_case_results(cls) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        for case_id in rehearsal_independent.REQUIRED_CASE_IDS:
            if case_id.startswith("matrix:"):
                operation = case_id.removeprefix("matrix:")
                records.append(cls._case_result(case_id, rehearsal_independent.MATRIX_CASE_CATEGORIES[operation], "mutation", "REJECTED", "REJECTED", "fixture-rejection"))
            elif case_id == "concurrency:IDENTICAL_CONVERGENCE":
                records.append(cls._case_result(case_id, "concurrency", "concurrency", "CONVERGED", "CONVERGED", "none"))
            elif case_id == "concurrency:CONFLICTING_SINGLE_WINNER":
                records.append(cls._case_result(case_id, "concurrency", "concurrency", "SINGLE_WINNER", "SINGLE_WINNER", "custody:fixed-envelope-conflict"))
            elif case_id.startswith("fault:"):
                records.append(cls._case_result(case_id, "fault", "fault", "FAULT_HANDLED", "FAULT_HANDLED", case_id.removeprefix("fault:")))
            elif case_id.startswith("recovery:"):
                records.append(cls._case_result(case_id, "recovery", "recovery", "RECOVERED", "RECOVERED", case_id.removeprefix("recovery:")))
            else:
                raise AssertionError(case_id)
        return records

    def _matrix_cases(self) -> tuple[_MatrixCase, ...]:
        return (
            _MatrixCase("artifact-chain", "omitted", "export_omitted"),
            _MatrixCase("artifact-chain", "duplicated", "export_duplicated"),
            _MatrixCase("artifact-chain", "reordered", "export_reordered"),
            _MatrixCase("artifact-chain", "substituted", "export_substituted"),
            _MatrixCase("artifact-chain", "truncated", "export_truncated"),
            _MatrixCase("artifact-chain", "corrupt", "export_corrupt"),
            _MatrixCase("artifact-chain", "stale-state-root", "export_stale"),
            _MatrixCase("artifact-chain", "cross-profile", "export_cross_profile"),
            _MatrixCase("artifact-chain", "cross-subject", "export_cross_subject"),
            _MatrixCase("artifact-chain", "cross-rehearsal", "receipt_cross_rehearsal"),
            _MatrixCase("artifact-chain", "duplicate-json-key", "duplicate_json_key"),
            _MatrixCase("artifact-chain", "oversized-receipt", "oversized_receipt"),
            _MatrixCase("artifact-chain", "deep-receipt", "deep_receipt"),
            _MatrixCase("governance-source", "wrong-control-pack-version", "wrong_control_pack_version"),
            _MatrixCase("governance-source", "withdrawn-approval", "withdrawn_approval"),
            _MatrixCase("governance-source", "incomplete-source", "incomplete_source"),
            _MatrixCase("governance-source", "forged-absence", "forged_absence"),
            _MatrixCase("lifecycle", "responsibility-mismatch", "responsibility_mismatch"),
            _MatrixCase("lifecycle", "remediation-mismatch", "remediation_mismatch"),
            _MatrixCase("lifecycle", "deterministic-retest-mismatch", "retest_mismatch"),
            _MatrixCase("lifecycle", "parity-mismatch", "parity_mismatch"),
            _MatrixCase("economic-views", "transaction-identity", "transaction_identity"),
            _MatrixCase("economic-views", "money-counting", "money_counting"),
            _MatrixCase("economic-views", "transition-identity", "transition_identity"),
            _MatrixCase("economic-views", "contract-identity", "contract_identity"),
            _MatrixCase("economic-views", "denominator-conservation", "denominator_conservation"),
            _MatrixCase("economic-views", "state-value-counting", "state_value_counting"),
            _MatrixCase("qualification", "controlled-shadow-relabel", "controlled_relabel"),
            _MatrixCase("qualification", "production-relabel", "production_relabel"),
            _MatrixCase("backup-restore", "backup-corrupt", "backup_corrupt"),
            _MatrixCase("backup-restore", "backup-truncated", "backup_truncated"),
            _MatrixCase("backup-restore", "stale-backup-target", "stale_backup_target"),
            _MatrixCase("backup-restore", "wrong-database-registry", "wrong_database_registry"),
            _MatrixCase("backup-restore", "custody-key-rotation-revocation", "custody_key_rotation_revocation"),
            _MatrixCase("cap-selector", "33rd-artifact", "cap_33"),
            _MatrixCase("cap-selector", "wrong-kind", "selector_wrong_kind"),
            _MatrixCase("cap-selector", "wrong-id", "selector_wrong_id"),
            _MatrixCase("cap-selector", "selector-cap", "selector_cap"),
            _MatrixCase("cap-selector", "corrupt-payload", "selector_corrupt"),
        )

    def _run_matrix_operation(self, operation: str) -> object:
        if operation.startswith("export_"):
            value = json.loads(self.result.export_raw.decode("ascii"))
            rows = value["artifacts"]
            if operation == "export_omitted":
                value["artifacts"] = rows[:-1]
            elif operation == "export_duplicated":
                value["artifacts"] = sorted([*rows, deepcopy(rows[0])], key=lambda item: (item["kind"], item["artifact_id"]))
            elif operation == "export_reordered":
                value["artifacts"] = list(reversed(rows))
            elif operation == "export_substituted":
                value["artifacts"][0]["payload_hex"] = rows[-1]["payload_hex"]
            elif operation == "export_stale":
                value["state_root"] = "0" * 128
            elif operation == "export_cross_profile":
                software = dict(value["software"])
                first = next(iter(software))
                software[first] = "FOREIGN_PROFILE"
                value["software"] = software
            elif operation == "export_cross_subject":
                value["artifacts"][0]["subject"] = "FOREIGN_SUBJECT"
            elif operation in {"export_truncated", "export_corrupt"}:
                pass
            else:
                raise AssertionError(operation)
            if operation in {"export_truncated", "export_corrupt"}:
                raw = self.result.export_raw
                if operation == "export_truncated":
                    return rehearsal_independent.verify_receipt(self.result.receipt_raw, raw[:-1], graph_profile_registry=self.registry)
                corrupted = bytearray(raw)
                corrupted[len(corrupted) // 2] ^= 1
                return rehearsal_independent.verify_receipt(self.result.receipt_raw, bytes(corrupted), graph_profile_registry=self.registry)
            return rehearsal_independent.verify_receipt(
                self.result.receipt_raw,
                self._rebind_export(value),
                graph_profile_registry=self.registry,
            )
        if operation == "receipt_cross_rehearsal":
            return rehearsal_independent.verify_receipt(
                self._mutated_receipt(lambda value: value.__setitem__("subject", "FOREIGN_REHEARSAL_SCOPE")),
                self.result.export_raw,
                graph_profile_registry=self.registry,
            )
        if operation == "duplicate_json_key":
            return rehearsal_independent.verify_receipt(
                b'{"schema":"mirror-end-to-end-rehearsal-receipt-v1","schema":"forged"}',
                self.result.export_raw,
                graph_profile_registry=self.registry,
            )
        if operation == "oversized_receipt":
            return rehearsal_independent.verify_receipt(
                self.result.receipt_raw + (b" " * (rehearsal_independent.MAX_RECEIPT_BYTES + 1)),
                self.result.export_raw,
                graph_profile_registry=self.registry,
            )
        if operation == "deep_receipt":
            nested: object = "leaf"
            for _ in range(32):
                nested = [nested]
            return rehearsal_independent.verify_receipt(
                json.dumps({"nested": nested}, separators=(",", ":")).encode("ascii"),
                self.result.export_raw,
                graph_profile_registry=self.registry,
            )
        if operation == "wrong_control_pack_version":
            def mutate(payload: dict[str, object]) -> None:
                profile = payload.get("profile")
                if isinstance(profile, dict):
                    profile["version"] = 999
                else:
                    payload["schema"] = "wrong-control-pack-version"
            raw = self._mutated_export_payload(store.ARTIFACT_GOVERNANCE, mutate)
            return rehearsal_independent.verify_receipt(self.result.receipt_raw, raw, graph_profile_registry=self.registry)
        if operation == "withdrawn_approval":
            graph_row = next(item for item in json.loads(self.result.export_raw.decode("ascii"))["artifacts"] if item["kind"] == store.ARTIFACT_GRAPH)
            graph_raw = bytes.fromhex(graph_row["payload_hex"])
            with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-withdrawn-") as temporary:
                instance = store.ContinuityStore(Path(temporary) / "state.db", graph_profile_registry=self.registry)
                rehearsal._admit_governance(instance, graph_raw)
                profile = source_profile.NC_MEDICAID_PROFILE.graph_profile
                approved_raw = instance.artifact_head_raw(store.ARTIFACT_GOVERNANCE, profile.subject, profile.scope, profile.profile_id)
                self.assertIsNotNone(approved_raw)
                assert approved_raw is not None
                authorization = governance_v2.build_withdrawal_authorization(approved_raw, profile, withdrawal_time=7_400)
                withdrawal_raw, _ = governance_v2.build_withdrawal(approved_raw, authorization, profile)
                instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal_raw)
                return instance.admit(store.ARTIFACT_GRAPH, graph_raw)
        if operation == "incomplete_source":
            raw = self._mutated_export_payload(
                store.ARTIFACT_SOURCE_EVIDENCE,
                lambda payload: payload.__setitem__("source_status", "PARTIAL"),
            )
            return rehearsal_independent.verify_receipt(self.result.receipt_raw, raw, graph_profile_registry=self.registry)
        if operation == "forged_absence":
            raw = self._mutated_receipt(
                lambda value: value["outcomes"].__setitem__("allow_nonmembership", True),
            )
            return rehearsal_independent.verify_receipt(raw, self.result.export_raw, graph_profile_registry=self.registry)
        lifecycle_fields = {
            "responsibility_mismatch": (store.ARTIFACT_CASE, ("responsibility", "resolution")),
            "remediation_mismatch": (store.ARTIFACT_CASE, ("remediation", "resolution")),
            "retest_mismatch": (store.ARTIFACT_CASE, ("retest", "resolution")),
            "parity_mismatch": (store.ARTIFACT_CASE, ("retest", "resolution")),
            "transaction_identity": (store.ARTIFACT_TRANSACTION_TRACE, ("trace_id", "phase_roots", "schema")),
            "money_counting": (store.ARTIFACT_MONEY_OBSERVATION, ("terms", "comparisons", "schema")),
            "transition_identity": (store.ARTIFACT_TRANSITION, ("comparison", "trace_id", "schema")),
            "contract_identity": (store.ARTIFACT_CONTRACT, ("obligation", "evaluation", "schema")),
            "denominator_conservation": (store.ARTIFACT_DENOMINATOR, ("outcome_counts", "narrowing", "schema")),
            "state_value_counting": (store.ARTIFACT_STATE_VALUE, ("aggregate", "entries", "schema")),
        }
        if operation in lifecycle_fields:
            kind, preferred = lifecycle_fields[operation]
            def mutate(payload: dict[str, object]) -> None:
                for key in preferred:
                    if key in payload:
                        payload[key] = self._forged_value(payload[key])
                        return
                payload["schema"] = "forged-matrix-schema"
            raw = self._mutated_export_payload(kind, mutate)
            return rehearsal_independent.verify_receipt(self.result.receipt_raw, raw, graph_profile_registry=self.registry)
        if operation in {"controlled_relabel", "production_relabel"}:
            claim = "CONTROLLED_SHADOW_READY" if operation == "controlled_relabel" else "PRODUCTION_READY"
            raw = self._mutated_receipt(lambda value: value["outcomes"].__setitem__("qualification_claim", claim))
            return rehearsal_independent.verify_receipt(raw, self.result.export_raw, graph_profile_registry=self.registry)
        if operation in {"backup_corrupt", "backup_truncated"}:
            raw = self.result.export_raw
            if operation == "backup_truncated":
                raw = raw[:-1]
            else:
                corrupted = bytearray(raw)
                corrupted[-17] ^= 1
                raw = bytes(corrupted)
            return continuity_export.verify_export_bytes(raw, self.registry)
        if operation == "stale_backup_target":
            with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-stale-backup-") as temporary:
                target = Path(temporary) / "state.db"
                target.write_bytes(b"STALE_BACKUP")
                return continuity_export.import_export(self.result.export_raw, target, self.registry)
        if operation == "wrong_database_registry":
            return rehearsal_independent.verify_receipt(self.result.receipt_raw, self.result.export_raw, graph_profile_registry={})
        if operation == "custody_key_rotation_revocation":
            custody = qualification_fixtures.SyntheticEnvelopeCustody()
            sealed = custody.seal({"fixture": "bounded"})
            custody.rotate()
            wrong = deepcopy(sealed)
            wrong["key_id"] = "SYNTHETIC_QUALIFICATION_KEY_V99"
            try:
                custody.open(wrong)
            except ValueError:
                pass
            custody.revoke()
            return custody.seal({"fixture": "revoked"})
        if operation == "cap_33":
            value = json.loads(self.result.export_raw.decode("ascii"))
            rows = list(value["artifacts"])
            value["artifacts"] = sorted(rows + [deepcopy(row) for row in rows[:9]], key=lambda item: (item["kind"], item["artifact_id"]))
            raw = continuity_export._canonical(value)
            with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-cap-33-") as temporary:
                root = Path(temporary)
                target = root / "state.db"
                try:
                    continuity_export.import_export(raw, target, self.registry)
                except continuity_export.ContinuityExportError:
                    self.assertFalse(target.exists())
                    self.assertEqual([], list(root.iterdir()))
                    raise
                self.fail("33rd bounded artifact unexpectedly restored")
        if operation in {"selector_wrong_kind", "selector_wrong_id", "selector_cap"}:
            instance = store.ContinuityStore(self.path, graph_profile_registry=self.registry)
            graph_id = self.receipt_value["components"]["provider_trust_graph"][0]["artifact_id"]
            if operation == "selector_wrong_kind":
                return instance.artifact_raw("FOREIGN_KIND", graph_id)
            if operation == "selector_wrong_id":
                return instance.artifact_raw(store.ARTIFACT_GRAPH, "0" * 128)
            return instance.artifact_raw(store.ARTIFACT_GRAPH, "x" * (store.MAX_SELECTOR_BYTES + 1))
        if operation == "selector_corrupt":
            with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-selector-corrupt-") as temporary:
                path = Path(temporary) / "state.db"
                continuity_export.import_export(self.result.export_raw, path, self.registry)
                instance = store.ContinuityStore(path, graph_profile_registry=self.registry)
                connection = sqlite3.connect(path)
                try:
                    connection.execute(
                        "UPDATE artifacts SET payload_hash=? WHERE kind=? AND artifact_id=?",
                        ("0" * 127 + "1", store.ARTIFACT_GRAPH, self.receipt_value["components"]["provider_trust_graph"][0]["artifact_id"]),
                    )
                    connection.commit()
                finally:
                    connection.close()
                return instance.artifact_raw(store.ARTIFACT_GRAPH, self.receipt_value["components"]["provider_trust_graph"][0]["artifact_id"])
        raise AssertionError(operation)

    def _run_store_fault_matrix(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        raw, _ = graph.build_demo_report("confirmed")
        faults: list[dict[str, object]] = []
        recoveries: list[dict[str, object]] = []
        for point in store.FAULT_POINTS:
            with self.subTest(store_fault=point):
                with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-store-fault-") as temporary:
                    path = Path(temporary) / "state.db"
                    instance = store.ContinuityStore(path)
                    instance._fault_point = point
                    if point == "after_commit_before_response":
                        with self.assertRaises(store.IndeterminateCommitError):
                            instance.admit(store.ARTIFACT_GRAPH, raw)
                        replay = instance.admit(store.ARTIFACT_GRAPH, raw)
                        self.assertEqual(128, len(replay.operation_id))
                    else:
                        with self.assertRaises(store.InjectedFault):
                            instance.admit(store.ARTIFACT_GRAPH, raw)
                    result = continuity_store_independent.verify_database(path)
                    if point == "after_commit_before_response":
                        self.assertEqual(1, result["artifact_count"])
                        self.assertEqual(1, result["event_count"])
                    else:
                        self.assertEqual(0, result["artifact_count"])
                        self.assertEqual(0, result["event_count"])
                    faults.append(self._case_result(f"fault:store:{point}", "fault", "fault", "FAULT_HANDLED", "FAULT_HANDLED", point))
                    recoveries.append(self._case_result(f"recovery:store:{point}", "recovery", "recovery", "RECOVERED", "RECOVERED", point))
        return faults, recoveries

    def _run_restore_fault_matrix(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        faults: list[dict[str, object]] = []
        recoveries: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-restore-faults-") as temporary:
            root = Path(temporary)
            for point in continuity_export.RESTORE_FAULT_POINTS:
                target = root / f"restore-{point}.db"
                continuity_export._restore_fault_point = point
                try:
                    with self.assertRaises(continuity_export.InjectedRestoreFault):
                        continuity_export.import_export(self.result.export_raw, target, self.registry)
                finally:
                    continuity_export._restore_fault_point = None
                faults.append(self._case_result(f"fault:restore:{point}", "fault", "fault", "FAULT_HANDLED", "FAULT_HANDLED", point))
                recoveries.append(self._case_result(f"recovery:restore:{point}", "recovery", "recovery", "RECOVERED", "RECOVERED", point))
        return faults, recoveries

    def _run_concurrent_full_rehearsals(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-matrix-concurrent-") as temporary:
            path = Path(temporary) / "state.db"
            barrier = Barrier(2)

            def worker() -> rehearsal.RehearsalResult:
                barrier.wait()
                return rehearsal.run_rehearsal(self.source, path)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = [pool.submit(worker) for _ in range(2)]
                first, second = (item.result() for item in results)
            self.assertEqual(first.receipt_raw, second.receipt_raw)
            self.assertEqual(first.export_raw, second.export_raw)
            verified = continuity_store_independent.verify_database(path, self.registry)
            self.assertEqual(24, verified["artifact_count"])
            self.assertEqual(24, verified["event_count"])
            self.assertEqual(24, verified["receipt_count"])
            self.assertEqual(13, verified["head_count"])
        return self._case_result(
            "concurrency:IDENTICAL_CONVERGENCE",
            "concurrency",
            "concurrency",
            "CONVERGED",
            "CONVERGED",
            "none",
        )

    def _run_conflicting_concurrent_rehearsals(self) -> dict[str, object]:
        alternate_value = json.loads(self.source.decode("ascii"))
        alternate_resource = alternate_value["pages"][0]["bundle"]["entry"][0]["resource"]
        alternate_resource["name"][0]["family"] = "Alternate"
        alternate_source = _rebind(alternate_value)
        for order in ((self.source, alternate_source), (alternate_source, self.source)):
            with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-conflicting-concurrent-") as temporary:
                path = Path(temporary) / "state.db"
                launch = Barrier(2)
                atomic_boundary = Barrier(2)
                original = store.ContinuityStore._admit_source_evidence

                def hooked(
                    instance: store.ContinuityStore,
                    custody_raw: bytes,
                    graph_raw: bytes | None,
                    graph_profile_registry: object,
                    *,
                    observation_raw: bytes | None,
                    fixed_envelope_digest: str | None,
                ) -> object:
                    if fixed_envelope_digest is not None:
                        atomic_boundary.wait(timeout=120)
                    return original(
                        instance,
                        custody_raw,
                        graph_raw,
                        graph_profile_registry,
                        observation_raw=observation_raw,
                        fixed_envelope_digest=fixed_envelope_digest,
                    )

                def worker(source: bytes) -> tuple[str, object]:
                    launch.wait(timeout=120)
                    try:
                        return ("ok", rehearsal.run_rehearsal(source, path))
                    except BaseException as exc:  # retain the typed losing outcome for the assertion below
                        return ("error", exc)

                with patch.object(store.ContinuityStore, "_admit_source_evidence", hooked):
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures = [pool.submit(worker, source) for source in order]
                        first, second = (future.result() for future in futures)
                outcomes = (first, second)
                successes = [value for kind, value in outcomes if kind == "ok"]
                failures = [value for kind, value in outcomes if kind == "error"]
                self.assertEqual(1, len(successes), outcomes)
                self.assertEqual(1, len(failures), outcomes)
                self.assertIsInstance(failures[0], store.StoreConflictError, outcomes)
                self.assertEqual("custody:fixed-envelope-conflict", str(failures[0]), outcomes)
                winner_source = order[0] if outcomes[0][0] == "ok" else order[1]
                winner_result = successes[0]
                self.assertIsInstance(winner_result, rehearsal.RehearsalResult)
                verified = continuity_store_independent.verify_database(path, self.registry)
                self.assertEqual(24, verified["artifact_count"])
                self.assertEqual(24, verified["event_count"])
                self.assertEqual(24, verified["receipt_count"])
                self.assertEqual(13, verified["head_count"])
                exported = continuity_export.export_database(path, self.registry)
                export_value = json.loads(exported.decode("ascii"))
                source_rows = [row for row in export_value["artifacts"] if row["kind"] == store.ARTIFACT_SOURCE_EVIDENCE]
                self.assertEqual(1, len(source_rows))
                source_payload = json.loads(bytes.fromhex(source_rows[0]["payload_hex"]).decode("ascii"))
                winner_digest = custody_independent._raw_digest("envelope", winner_source)
                loser_digest = custody_independent._raw_digest("envelope", alternate_source if winner_source == self.source else self.source)
                self.assertEqual(winner_digest, source_payload["envelope_digest"])
                self.assertNotEqual(loser_digest, source_payload["envelope_digest"])
                self.assertNotIn((alternate_source if winner_source == self.source else self.source).hex().encode("ascii"), exported)
                print("MIRROR_REHEARSAL_CONFLICT_RACE " + json.dumps({
                    "order": ["baseline" if item == self.source else "alternate" for item in order],
                    "outcomes": [
                        {"kind": kind, "error": str(value) if kind == "error" else "ok"}
                        for kind, value in outcomes
                    ],
                    "winner_envelope_digest": winner_digest,
                    "loser_envelope_digest": loser_digest,
                    "artifact_count": verified["artifact_count"],
                    "event_count": verified["event_count"],
                    "receipt_count": verified["receipt_count"],
                    "head_count": verified["head_count"],
                }, sort_keys=True))
                reopened = store.ContinuityStore(path, graph_profile_registry=self.registry)
                self.assertEqual(verified, continuity_store_independent.verify_database(reopened.path, self.registry))
                retry = rehearsal.run_rehearsal(winner_source, path)
                self.assertEqual(winner_result.receipt_raw, retry.receipt_raw)
                with self.assertRaises(store.StoreConflictError) as conflict:
                    rehearsal.run_rehearsal(alternate_source if winner_source == self.source else self.source, path)
                self.assertEqual("custody:fixed-envelope-conflict", str(conflict.exception))
        return self._case_result(
            "concurrency:CONFLICTING_SINGLE_WINNER",
            "concurrency",
            "concurrency",
            "SINGLE_WINNER",
            "SINGLE_WINNER",
            "custody:fixed-envelope-conflict",
        )

    def test_matrix_adversarial_cases_and_machine_ledger(self) -> None:
        case_results: list[dict[str, object]] = []
        decisive_errors: dict[str, str] = {}
        for case in self._matrix_cases():
            with self.subTest(category=case.category, case=case.name):
                error_code = self._assert_matrix_reject(lambda case=case: self._run_matrix_operation(case.operation))
                decisive_errors[case.name] = error_code
                case_results.append(self._case_result(f"matrix:{case.operation}", case.category, "mutation", "REJECTED", "REJECTED", error_code))

        case_results.append(self._run_concurrent_full_rehearsals())
        case_results.append(self._run_conflicting_concurrent_rehearsals())

        fault_records, fault_recoveries = self._run_store_fault_matrix()
        restore_fault_records, restore_recoveries = self._run_restore_fault_matrix()
        case_results.extend(fault_records)
        case_results.extend(restore_fault_records)
        case_results.extend(fault_recoveries)
        case_results.extend(restore_recoveries)

        reopened = store.ContinuityStore(self.path, graph_profile_registry=self.registry)
        self.assertEqual(
            continuity_store_independent.verify_database(self.path, self.registry),
            continuity_store_independent.verify_database(reopened.path, self.registry),
        )
        case_results.append(self._case_result("recovery:reopen", "recovery", "recovery", "RECOVERED", "RECOVERED", "reopen"))
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-matrix-restore-") as temporary:
            restored = Path(temporary) / "state.db"
            continuity_export.import_export(self.result.export_raw, restored, self.registry)
            self.assertEqual(
                continuity_store_independent.verify_database(self.path, self.registry),
                continuity_store_independent.verify_database(restored, self.registry),
            )
        case_results.append(self._case_result("recovery:restore-roundtrip", "recovery", "recovery", "RECOVERED", "RECOVERED", "restore-roundtrip"))

        command = [
            sys.executable,
            "-B",
            "-c",
            "import tempfile; from pathlib import Path; from tests.test_nc_medicaid_fhir_source import _envelope; from app.mirror import rehearsal; d=tempfile.TemporaryDirectory(prefix='mirror-job-object-'); rehearsal.run_rehearsal(_envelope(), Path(d.name) / 'state.db'); d.cleanup()",
        ]
        job = run_job_object(command, cwd=Path(__file__).resolve().parents[1], timeout_seconds=420.0)
        print("JOB_OBJECT_EVIDENCE " + json.dumps(job, sort_keys=True))
        if job["cap_enforced"] is not True or job["measured"] is not True:
            blocked_ledger_raw = rehearsal.build_evidence_ledger(
                self.result.receipt_raw,
                execution_scope="matrix",
                case_results=case_results,
                resource_telemetry={
                    "counter_name": job["counter_name"],
                    "semantics": job["semantics"],
                    "cap_bytes": job["cap_bytes"],
                    "cap_enforced": job["cap_enforced"],
                    "measured": job["measured"],
                    "process_tree_peak_bytes": job["peak_bytes"],
                    "exit_code": job["exit_code"] if type(job["exit_code"]) is int else -1,
                },
                worker_commands=(
                    {"command": "python -m unittest tests.test_mirror_rehearsal", "exit_code": 0},
                    {"command": "windows-job-object-full-rehearsal", "exit_code": 1},
                ),
                warnings=({"scope": "complete-process-tree", "reason": str(job["blocker"])},),
                skips=(),
            )
            blocked_value = json.loads(blocked_ledger_raw.decode("ascii"))
            with self.assertRaises(rehearsal_independent.IndependentRehearsalError) as blocked:
                rehearsal_independent.verify_evidence_ledger(blocked_ledger_raw, self.result.receipt_raw)
            print("MIRROR_REHEARSAL_MATRIX_GATE_OPEN " + json.dumps({
                "ledger_id": blocked_value["ledger_id"],
                "counts": blocked_value["counts"],
                "category_counts": blocked_value["category_counts"],
                "resource": blocked_value["resource_telemetry"],
                "verifier_error": str(blocked.exception),
            }, sort_keys=True))
            self.assertEqual("ledger:telemetry-unmeasured", str(blocked.exception))
            self.assertEqual([], self.ledger_value["skips"])
            self.assertEqual(39, len(self._matrix_cases()))
            self.assertGreaterEqual(len(decisive_errors), 39)
            self.assertEqual(len(rehearsal_independent.REQUIRED_CASE_IDS), len(case_results))
            return
        self.assertIsInstance(job["peak_bytes"], int)
        self.assertLessEqual(job["peak_bytes"], 5_000_000_000)
        self.assertEqual(0, job["exit_code"], job)
        self.assertIsNone(job["blocker"], job)

        ledger_raw = rehearsal.build_evidence_ledger(
            self.result.receipt_raw,
            execution_scope="matrix",
            case_results=case_results,
            resource_telemetry={
                "counter_name": job["counter_name"],
                "semantics": job["semantics"],
                "cap_bytes": job["cap_bytes"],
                "cap_enforced": job["cap_enforced"],
                "measured": job["measured"],
                "process_tree_peak_bytes": job["peak_bytes"],
                "exit_code": job["exit_code"],
            },
            worker_commands=(
                {"command": "python -m unittest tests.test_mirror_rehearsal", "exit_code": 0},
                {"command": "windows-job-object-full-rehearsal", "exit_code": int(job["exit_code"])},
            ),
            skips=(),
        )
        ledger = rehearsal_independent.verify_evidence_ledger(ledger_raw, self.result.receipt_raw)
        print("MIRROR_REHEARSAL_MATRIX_COUNTS " + json.dumps(ledger["category_counts"], sort_keys=True))
        print("MIRROR_REHEARSAL_MATRIX_LEDGER " + json.dumps({"ledger_id": ledger["ledger_id"], "counts": ledger["counts"], "category_counts": ledger["category_counts"], "resource": json.loads(ledger_raw.decode("ascii"))["resource_telemetry"]}, sort_keys=True))
        self.assertEqual([], self.ledger_value["skips"])
        self.assertEqual(39, len(self._matrix_cases()))
        self.assertGreaterEqual(len(decisive_errors), 39)
        self.assertEqual(len(rehearsal_independent.REQUIRED_CASE_IDS), len(case_results))

    def test_matrix_positive_caps_selector_and_separation(self) -> None:
        baseline = continuity_export.verify_export_bytes(self.result.export_raw, self.registry)
        self.assertEqual(24, baseline["artifact_count"])
        value = json.loads(self.result.export_raw.decode("ascii"))
        rows = list(value["artifacts"])
        value["artifacts"] = sorted(rows + [deepcopy(row) for row in rows[:8]], key=lambda item: (item["kind"], item["artifact_id"]))
        decoded = continuity_export._decode_rows(value)
        self.assertEqual(32, len(decoded["artifacts"]))

        legacy = graph.build_demo_report("confirmed")[0]
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-legacy-cap-") as temporary:
            path = Path(temporary) / "legacy.db"
            instance = store.ContinuityStore(path)
            instance.admit(store.ARTIFACT_GRAPH, legacy)
            self.assertEqual(1, continuity_export.verify_export_bytes(continuity_export.export_database(path))["artifact_count"])

        instance = store.ContinuityStore(self.path, graph_profile_registry=self.registry)
        graph_id = self.receipt_value["components"]["provider_trust_graph"][0]["artifact_id"]
        payload = instance.artifact_raw(store.ARTIFACT_GRAPH, graph_id)
        self.assertIs(type(payload), bytes)
        copied = bytearray(payload)
        copied[0] ^= 1
        self.assertEqual(payload, instance.artifact_raw(store.ARTIFACT_GRAPH, graph_id))
        self.assertFalse(self.receipt_value["authority"]["clearance_authority"])
        self.assertFalse(self.receipt_value["authority"]["payment_authority"])
        self.assertFalse(self.receipt_value["authority"]["economic_mutation"])
        self.assertNotIn(b"CLEAR", self.result.receipt_raw + self.result.evidence_ledger_raw + self.result.support_raw)
        self.assertNotIn(b"effectiveDirective", self.result.receipt_raw + self.result.evidence_ledger_raw + self.result.support_raw)
        aggregate = self.receipt_value["outcomes"]["state_value_aggregate"]
        for key, value in aggregate.items():
            if key.endswith("_minor") or key.endswith("_entries"):
                self.assertIs(type(value), int)
                self.assertGreaterEqual(value, 0)
        print("MIRROR_REHEARSAL_CAP_SELECTOR baseline=24 exact_parser_bound=32")


if __name__ == "__main__":
    unittest.main()
