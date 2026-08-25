from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import operational_owner as operational
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from app.mirror import source_admission
from tests.test_mirror_v2_consolidation import _Custody, _Storage, _hex
from tests.test_nc_medicaid_fhir_source import _envelope


class MirrorSanitizedCleanBreakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=r"C:\Temp", prefix="mirror-cleanbreak-test-")
        self.root = Path(self.temp.name)
        self.ingress_path = self.root / "ingress.sqlite"
        self.core_path = self.root / "core.sqlite"
        self.recovery_path = self.root / "recovery.sqlite"
        self.clock = lambda: profile.FIXTURE_FETCHED_AT + 1
        self.ingress_config = ingress.IngressConfigV2(
            database_id="ingress-cleanbreak-synthetic",
            chain_id="ingress-cleanbreak-chain",
            policy_digest=_hex("cleanbreak-policy"),
            authorization_digest=_hex("cleanbreak-authorization"),
            terms_digest=_hex("cleanbreak-terms"),
            effective_start=profile.FIXTURE_OBSERVATION_TIME,
            effective_end=profile.FIXTURE_OBSERVATION_TIME + 3600,
            cadence_seconds=60,
            max_slots=8,
        )
        self.raw = _envelope()
        self.admission = source_admission.SourceAdmissionService(
            profile.NC_MEDICAID_GRAPH_PROFILE,
            fhir_independent.NcMedicaidFhirVerifier(),
        ).admit(self.raw)
        self.observation = self.admission.observation
        self.verification_receipt = self.admission.verification_receipt

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _fingerprint(service: ingress.IngressServiceV2) -> tuple[object, ...]:
        result = service.verify()
        return (
            result["sequence"], result["head_root"], result["event_count"],
            result["artifact_count"], result["slot_count"],
        )

    @staticmethod
    def _raw_surfaces(root: Path, *, logical: tuple[bytes, ...], storage: tuple[bytes, ...]) -> tuple[bytes, ...]:
        files = tuple(path.read_bytes() for path in (root / "ingress.sqlite", root / "core.sqlite", root / "recovery.sqlite") if path.exists())
        return files + logical + storage

    def test_source_to_recovery_is_sanitized_and_fail_closed(self) -> None:
        canary = b"CANARY-RAW-FHIR-ZZZZZZZZZZZZZZZZZZZZZZZZ"
        self.assertFalse(hasattr(operational, "AcquisitionPayloadV1"))
        with self.assertRaises(operational.OperationalOwnerError):
            operational.SanitizedObservationPayloadV1(self.raw, self.raw)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(source_admission.SourceAdmissionError):
                source_admission.SourceAdmissionService(
                    profile.NC_MEDICAID_GRAPH_PROFILE,
                    fhir_independent.NcMedicaidFhirVerifier(),
                ).admit(self.raw + canary)
        self.assertNotIn(canary.decode("ascii"), stdout.getvalue() + stderr.getvalue())
        self.assertFalse(self.ingress_path.exists())

        service = ingress.IngressServiceV2(self.ingress_path, self.ingress_config, clock=self.clock)
        created = service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        lease_token = "cleanbreak-synthetic-lease-token-000000000000"
        service.claim_slot(slot_id, lease_token=lease_token)
        admitted = service.admit_observation(
            self.observation,
            self.verification_receipt,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=lease_token,
        )
        self.assertEqual("QUARANTINED", admitted.next_state)
        self.assertEqual("mirror-ingress-v5", service.verify()["schema"])
        before = self._fingerprint(service)

        mutated = json.loads(self.observation.decode("ascii"))
        mutated["record_count"] += 1
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:observation-reject"):
            service.admit_observation(
                ingress_independent._canonical(mutated), self.verification_receipt,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token,
            )
        reordered = dict(reversed(list(json.loads(self.observation.decode("ascii")).items())))
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:observation-reject"):
            service.admit_observation(
                json.dumps(reordered, ensure_ascii=True, separators=(",", ":")).encode("ascii"),
                self.verification_receipt,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token,
            )
        unknown = json.loads(self.observation.decode("ascii"))
        unknown["unauthorized_raw_field"] = "CANARY-UNKNOWN"
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:observation-reject"):
            service.admit_observation(
                ingress_independent._canonical(unknown), self.verification_receipt,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token,
            )
        bad_receipt = json.loads(self.verification_receipt.decode("ascii"))
        bad_receipt["observation_digest"] = "0" * 128
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:observation-reject"):
            service.admit_observation(
                self.observation, ingress_independent._canonical(bad_receipt),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token,
            )
        self.assertEqual(before, self._fingerprint(service))

        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:legacy-raw-api"):
            service.admit_observation(
                self.observation, self.verification_receipt,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token, envelope_raw=self.raw,
            )
        self.assertEqual(before, self._fingerprint(service))

        retry = service.admit_observation(
            self.observation, self.verification_receipt,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1, lease_token=lease_token,
        )
        self.assertEqual(admitted.raw, retry.raw)
        self.assertEqual(before, self._fingerprint(service))

        reopened = ingress.IngressServiceV2(self.ingress_path, self.ingress_config, clock=self.clock)
        self.assertEqual(before, self._fingerprint(reopened))
        retry_after_restart = reopened.admit_observation(
            self.observation, self.verification_receipt,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1, lease_token=lease_token,
        )
        self.assertEqual(admitted.raw, retry_after_restart.raw)

        changed_admission = source_admission.SourceAdmissionService(
            profile.NC_MEDICAID_GRAPH_PROFILE,
            fhir_independent.NcMedicaidFhirVerifier(),
        ).admit(_envelope(two_pages=True))
        self.assertNotEqual(self.observation, changed_admission.observation)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:slot"):
            service.admit_observation(
                changed_admission.observation,
                changed_admission.verification_receipt,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1, lease_token=lease_token,
            )
        self.assertEqual(before, self._fingerprint(service))

        old_path = self.root / "old-raw.sqlite"
        connection = sqlite3.connect(old_path)
        try:
            connection.execute("CREATE TABLE ingress_artifacts(raw BLOB)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress.IngressError, "ingress:legacy-schema"):
            ingress.IngressServiceV2(old_path, self.ingress_config, clock=self.clock)

        future_path = self.root / "future.sqlite"
        future_service = ingress.IngressServiceV2(future_path, self.ingress_config, clock=lambda: profile.FIXTURE_OBSERVATION_TIME - 1)
        future_created = future_service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        future_slot_id = json.loads(future_created.raw.decode("ascii"))["slot_id"]
        future_before = self._fingerprint(future_service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:lease"):
            future_service.claim_slot(future_slot_id, lease_token=lease_token)
        self.assertEqual(future_before, self._fingerprint(future_service))

        fault_path = self.root / "precommit-fault.sqlite"
        fault_service = ingress.IngressServiceV2(fault_path, self.ingress_config, clock=self.clock)
        fault_created = fault_service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        fault_slot_id = json.loads(fault_created.raw.decode("ascii"))["slot_id"]
        fault_service.claim_slot(fault_slot_id, lease_token=lease_token)
        fault_before = self._fingerprint(fault_service)
        real_connection = sqlite3.connect(str(fault_path), isolation_level=None, timeout=0.25)
        real_connection.row_factory = sqlite3.Row
        real_connection.execute("PRAGMA foreign_keys=ON")

        class FailingConnection:
            def execute(self, sql: str, *parameters: object):
                if "UPDATE ingress_meta SET sequence" in sql:
                    raise RuntimeError("PRECOMMIT-RAW-CANARY")
                return real_connection.execute(sql, *parameters)

            def rollback(self) -> None:
                real_connection.rollback()

            def close(self) -> None:
                real_connection.close()

            def __getattr__(self, name: str) -> object:
                return getattr(real_connection, name)

        with mock.patch.object(ingress, "_connection", return_value=FailingConnection()):
            with self.assertRaisesRegex(ingress.IngressIndeterminateError, "ingress:transaction-indeterminate"):
                fault_service.admit_observation(
                    self.observation, self.verification_receipt,
                    scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                    attempt=1, lease_token=lease_token,
                )
        self.assertEqual(fault_before, self._fingerprint(fault_service))

        core_config = core.CoreConfigV2(
            database_id="core-cleanbreak-synthetic",
            chain_id="core-cleanbreak-chain",
            ingress_database_id=self.ingress_config.database_id,
            ingress_chain_id=self.ingress_config.chain_id,
            runtime_profile_digest=profile.NC_MEDICAID_PROFILE.profile_digest,
            governance_policy_digest=_hex("cleanbreak-governance"),
            privacy_policy_digest=_hex("cleanbreak-privacy"),
            ingress_config_digest=self.ingress_config.digest,
            corrective_action_control_digest=_hex("cleanbreak-corrective-action"),
        )
        core_service = core.CoreServiceV2(self.core_path, core_config, clock=self.clock)
        core_result = core_service.ingest_source(self.ingress_path, admitted.artifact_id or "")
        self.assertEqual("INCOMPLETE", core_result["observation_status"])
        core_verified = core_service.verify(ingress_path=self.ingress_path)
        self.assertTrue(core_verified["structural_valid"])
        self.assertTrue(core_verified["ingress_bound"])

        custody = _Custody()
        storage = _Storage()
        recovery_config = recovery.RecoveryConfigV2(
            database_id="recovery-cleanbreak-synthetic",
            chain_id="recovery-cleanbreak-chain",
            profile_digest=_hex("cleanbreak-recovery"),
            custody_id=custody.custody_id,
            storage_id=storage.storage_id,
            ingress_database_id=self.ingress_config.database_id,
            core_database_id=core_config.database_id,
            ingress_config_digest=self.ingress_config.digest,
            core_config_digest=core_config.digest,
        )
        recovery_service = recovery.RecoveryServiceV2(self.recovery_path, recovery_config, custody, storage)
        point = recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", point.state)
        recovery_result = recovery_service.verify()
        self.assertEqual(1, recovery_result["point_count"])

        logical = (
            service.logical_export(),
            core_service.logical_export(),
            recovery_service.logical_export(),
            json.dumps(recovery_service.support(), sort_keys=True, separators=(",", ":")).encode("ascii"),
            recovery_service.bootstrap(point.point_id),
        )
        storage_bytes = tuple(storage.objects.values())
        surfaces = self._raw_surfaces(self.root, logical=logical, storage=storage_bytes)
        forbidden = (
            canary,
            self.raw,
            b"envelope_raw",
            b"external_evidence_raw",
            b"intake_frame",
            b"patient",
            b"claimant",
        )
        for surface in surfaces:
            for value in forbidden:
                self.assertNotIn(value, surface)
        self.assertNotIn(b"mirror-ingress-logical-export-v4", logical[0])
        self.assertIn(b"mirror-ingress-logical-export-v5", logical[0])

    def test_independent_pair_is_canonical_and_receipt_bound(self) -> None:
        checked = ingress_independent.verify_observation_pair(
            self.observation, self.verification_receipt,
            expected_profile_id=profile.SOURCE_PROFILE_ID,
            expected_profile_version=3,
        )
        self.assertEqual(
            hashlib.sha3_512(
                b"BL/MIRROR/INGRESS/V5/sanitized-observation\0" + self.observation
            ).hexdigest(),
            checked["verification_receipt"]["observation_digest"],
        )
        self.assertEqual(checked["observation_id"], ingress_independent._raw_digest("sanitized-observation", self.observation))
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_observation_pair(
                self.observation + b" ", self.verification_receipt,
            )


if __name__ == "__main__":
    unittest.main()
