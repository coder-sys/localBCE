from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest

from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import qualification
from app.mirror import qualification_independent as independent


class MirrorQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Path(self.tempdir.name) / "qualification.db"
        self.instance = store.ContinuityStore(self.database)
        self.service = qualification.QualificationService(self.instance)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _evidence(*, valid_until: int = 9_000) -> dict[str, dict[str, object]]:
        issuer = qualification.SyntheticEvidenceAuthority()
        return {dependency_id: issuer.issue(dependency_id, valid_until=valid_until) for dependency_id in independent.DEPENDENCY_IDS}

    @staticmethod
    def _operations() -> dict[str, dict[str, object]]:
        return {operation_id: qualification.SyntheticOperationsEvidence.issue(operation_id) for operation_id in independent.OPERATION_IDS}

    @staticmethod
    def _json(raw: bytes) -> dict[str, object]:
        return json.loads(raw.decode("ascii"))

    @staticmethod
    def _raw(value: dict[str, object]) -> bytes:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")

    def test_missing_readiness_fails_closed_and_every_dependency_state_is_bounded(self) -> None:
        receipt = self.service.initialize()
        self.assertTrue(receipt.raw)
        current = self.service.current_raw()
        assert current is not None
        verified = independent.verify_artifact(current)
        self.assertEqual(independent.PILOT_NOT_READY, verified["readiness_state"])
        self.assertEqual(set(verified["dependency_states"].values()), {"MISSING"})
        before = self.instance._snapshot_rows()
        with self.assertRaises(store.StoreConflictError):
            self.service.advance(independent.PILOT_READY)
        self.assertEqual(before, self.instance._snapshot_rows())

        states = ("PRESENT_UNVERIFIED", "EXPIRED", "REVOKED")
        for state in states:
            evidence = self._evidence()
            if state == "REVOKED":
                evidence["PRIVACY"] = qualification.SyntheticEvidenceAuthority.issue("PRIVACY", state=state, revoked=True)
            elif state == "EXPIRED":
                evidence["PRIVACY"] = qualification.SyntheticEvidenceAuthority.issue("PRIVACY", state=state, valid_until=9_000)
            else:
                evidence["PRIVACY"] = qualification.SyntheticEvidenceAuthority.issue("PRIVACY", state=state)
            raw = qualification.build_manifest(evidence=evidence, operations=self._operations())
            normalized = independent.verify_artifact(raw)
            self.assertEqual(state, normalized["dependency_states"]["PRIVACY"])
            self.assertEqual(independent.PILOT_NOT_READY, normalized["readiness_state"])

    def test_complete_synthetic_lifecycle_and_independent_database_verification(self) -> None:
        self.service.initialize(evidence=self._evidence(), operations=self._operations())
        raw = self.service.current_raw()
        assert raw is not None
        self.assertEqual(independent.PILOT_NOT_READY, independent.verify_artifact(raw)["stage_kind"])
        self.service.advance(independent.PILOT_READY)
        self.service.advance(independent.PILOT_RUNNING)
        self.service.advance(independent.PILOT_PAUSED)
        self.service.advance(independent.PILOT_ROLLED_BACK)
        self.service.advance(independent.PILOT_COMPLETED)
        current = self.service.current_raw()
        assert current is not None
        self.assertEqual(independent.PILOT_COMPLETED, independent.inspect_artifact(current)["stage_kind"])
        result = store_independent.verify_database(self.database)
        self.assertTrue(result["accepted"])
        self.assertEqual(6, result["event_count"])
        self.assertFalse(self._json(current)["flags"]["controlled_shadow_pilot"])
        self.assertFalse(self._json(current)["authority"]["production_usable"])

    def test_exact_concurrent_transition_converges_and_conflict_does_not_mutate(self) -> None:
        self.service.initialize(evidence=self._evidence(), operations=self._operations())
        self.service.advance(independent.PILOT_READY)
        prior = self.service.current_raw()
        assert prior is not None
        prior_value = self._json(prior)
        evidence, operations = self.service._maps(prior)
        candidate = qualification.build_manifest(
            evidence=evidence,
            operations=operations,
            as_of=prior_value["as_of"],
            prior_raw=prior,
            pilot_state=independent.PILOT_RUNNING,
            custody=qualification.SyntheticEnvelopeCustody(),
        )
        barrier = threading.Barrier(2)

        def admit() -> bytes:
            barrier.wait()
            return self.instance.admit(store.ARTIFACT_QUALIFICATION, candidate).raw

        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = [future.result() for future in (pool.submit(admit), pool.submit(admit))]
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual(3, store_independent.verify_database(self.database)["event_count"])

        before = self.instance._snapshot_rows()
        conflicting = qualification.build_manifest(
            evidence=evidence,
            operations=operations,
            as_of=prior_value["as_of"],
            prior_raw=prior,
            pilot_state=independent.PILOT_PAUSED,
            custody=qualification.SyntheticEnvelopeCustody(),
        )
        with self.assertRaises(store.StoreConflictError):
            self.instance.admit(store.ARTIFACT_QUALIFICATION, conflicting)
        self.assertEqual(before, self.instance._snapshot_rows())

    def test_custody_rotation_revocation_and_wrong_key_fail_closed(self) -> None:
        custody = qualification.SyntheticEnvelopeCustody()
        seed = {"profile_id": independent.PROFILE_ID, "manifest_core_digest": "x", "purpose": "MIRROR_QUALIFICATION_MANIFEST"}
        envelope = custody.seal(seed)
        self.assertEqual(custody.open(envelope), qualification._canonical(seed))
        rotated = custody.rotate()
        self.assertEqual("SYNTHETIC_QUALIFICATION_KEY_V2", rotated["key_id"])
        rotated_envelope = custody.seal(seed)
        self.assertNotEqual(envelope["envelope"]["key_id"], rotated_envelope["envelope"]["key_id"])
        custody.revoke()
        with self.assertRaises(qualification.QualificationError):
            custody.seal(seed)
        wrong = dict(rotated_envelope)
        wrong_body = dict(wrong["envelope"])
        wrong_body["ciphertext"] = "00" + wrong_body["ciphertext"][2:]
        wrong["envelope"] = wrong_body
        with self.assertRaises(qualification.QualificationError):
            custody.open(wrong)

    def test_forged_manifest_fields_and_duplicate_or_noncanonical_json_reject(self) -> None:
        raw = qualification.build_manifest()
        value = self._json(raw)
        before = self.instance._snapshot_rows()
        value["readiness"]["verified_checks"] = 99
        with self.assertRaises(independent.IndependentQualificationError):
            independent.verify_artifact(self._raw(value))
        value = self._json(raw)
        value["authority"]["payment_authority"] = True
        with self.assertRaises(independent.IndependentQualificationError):
            independent.verify_artifact(self._raw(value))
        mutations = []
        value = self._json(raw)
        value["profile_binding"]["version"] = 2
        mutations.append(value)
        value = self._json(raw)
        value["owners"]["privacy"] = "CALLER"
        mutations.append(value)
        value = self._json(raw)
        value["components"][0]["owner"] = "CALLER"
        mutations.append(value)
        value = self._json(raw)
        value["gap_ledger"]["software_gaps"][0]["status"] = "VERIFIED"
        mutations.append(value)
        value = self._json(raw)
        value["dependencies"][0]["owner"] = "CALLER"
        mutations.append(value)
        for mutation in mutations:
            with self.assertRaises(independent.IndependentQualificationError):
                independent.verify_artifact(self._raw(mutation))
        with self.assertRaises(independent.IndependentQualificationError):
            independent.verify_artifact(b'{"schema":"x","schema":"y"}')
        with self.assertRaises(independent.IndependentQualificationError):
            independent.verify_artifact(raw + b"\n")
        with self.assertRaises((store.StoreConflictError, store.ArtifactAdmissionError)):
            self.instance.admit(store.ARTIFACT_QUALIFICATION, self._raw(value))
        self.assertEqual(before, self.instance._snapshot_rows())

    def test_profile_expiry_and_operation_state_are_explicit_not_upgraded(self) -> None:
        evidence = self._evidence(valid_until=1_001)
        raw = qualification.build_manifest(evidence=evidence, operations=self._operations(), as_of=2_000)
        result = independent.verify_artifact(raw)
        self.assertEqual(independent.PILOT_NOT_READY, result["readiness_state"])
        self.assertEqual("EXPIRED", result["dependency_states"]["CADENCE"])
        operations = self._operations()
        operations["BACKUP_RESTORE"] = qualification.SyntheticOperationsEvidence.issue("BACKUP_RESTORE", state="PRESENT_UNVERIFIED", observed_rpo_seconds=None, observed_rto_ms=None)
        raw = qualification.build_manifest(evidence=self._evidence(), operations=operations)
        result = independent.verify_artifact(raw)
        self.assertEqual(independent.PILOT_NOT_READY, result["readiness_state"])

    def test_fault_rollback_export_restore_corruption_and_support_privacy(self) -> None:
        self.service.initialize(evidence=self._evidence(), operations=self._operations())
        prior = self.service.current_raw()
        assert prior is not None
        before = self.instance._snapshot_rows()
        self.instance._fault_point = "after_event_receipt_before_commit"
        with self.assertRaises(store.InjectedFault):
            self.service.advance(independent.PILOT_READY)
        self.assertEqual(before, self.instance._snapshot_rows())
        self.service.advance(independent.PILOT_READY)
        exported = export.export_database(self.database)
        self.assertTrue(export.verify_export_bytes(exported)["accepted"])
        restored = Path(self.tempdir.name) / "restored.db"
        self.assertTrue(export.import_export(exported, restored)["restored"])
        self.assertEqual(store_independent.verify_database(self.database), store_independent.verify_database(restored))
        with self.assertRaises(export.ContinuityExportError):
            export.verify_export_bytes(exported[:-1] + bytes([exported[-1] ^ 1]))

        support = qualification.build_support_bundle(self.service.current_raw())
        self.assertTrue(qualification.verify_support_bytes(support)["accepted"])
        text = support.decode("ascii")
        self.assertNotIn(independent.PROFILE_ID, text)
        self.assertNotIn(independent.SUBJECT, text)
        self.assertNotIn("SYNTHETIC_QUALIFICATION_KEY", text)
        self.assertIsNone(re.search(r"[0-9a-f]{128}", text))

    def test_operations_harness_reports_local_evidence_without_ha_or_dr_claim(self) -> None:
        self.service.initialize()
        result = qualification.QualificationOperationsHarness.observe(self.database)
        self.assertTrue(result["synthetic_only"])
        self.assertFalse(result["production_usable"])
        self.assertEqual("PRESENT_UNVERIFIED", result["ha"])
        self.assertEqual("PRESENT_UNVERIFIED", result["backup_dr"])
        self.assertIn(result["database_integrity"], {"VERIFIED", "FAILED"})


if __name__ == "__main__":
    unittest.main()
