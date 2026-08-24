from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import external_governance_approval as governance
from app.mirror import external_privacy_support_approval as privacy
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import recovery_v2 as recovery


def _hex(seed: str) -> str:
    return hashlib.sha3_512(seed.encode("ascii")).hexdigest()


class _Custody:
    custody_id = "synthetic-custody-v2"

    def __init__(self) -> None:
        self.epoch = 1
        self.revoked: set[tuple[str, int]] = set()

    def current_key(self) -> recovery.RecoveryKey:
        return recovery.RecoveryKey("synthetic-key", self.epoch, "ACTIVE")

    def state(self, key_id: str, key_epoch: int) -> str:
        return "REVOKED" if (key_id, key_epoch) in self.revoked else "ACTIVE"

    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes:
        if self.state(key_id, key_epoch) != "ACTIVE":
            raise RuntimeError("synthetic key unavailable")
        return bytes(byte ^ (key_epoch & 255) ^ 0x5A for byte in plaintext)

    def open(self, sealed: bytes, key_id: str, key_epoch: int) -> bytes:
        if self.state(key_id, key_epoch) != "ACTIVE":
            raise RuntimeError("synthetic key revoked")
        return bytes(byte ^ (key_epoch & 255) ^ 0x5A for byte in sealed)


class _Storage:
    storage_id = "synthetic-storage-v2"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def get(self, object_id: str) -> bytes:
        if object_id not in self.objects:
            raise recovery.StorageNotFound("not found")
        return self.objects[object_id]

    def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> recovery.StorageReceipt:
        if object_id in self.objects:
            result = "EXISTING_SAME" if self.objects[object_id] == sealed else "EXISTING_DIFFERENT"
        else:
            self.objects[object_id] = bytes(sealed)
            result = "CREATED"
        return recovery.StorageReceipt(
            storage_id=self.storage_id,
            object_id=object_id,
            result=result,
            byte_length=len(sealed),
            sealed_digest=recovery._raw_digest("sealed", sealed),
            key_id=key_id,
            key_epoch=key_epoch,
        )


class _GovernanceVerifier:
    verifier_id = "SYNTH_GOVERNANCE_VERIFIER"
    verifier_epoch = 1

    def __init__(self, policy: governance.ExternalGovernanceApprovalPolicyV1) -> None:
        self.policy = policy
        self.authority_evidence_digest = policy.authority_evidence_digest
        self.revocation_head_digest = policy.revocation_head_digest
        self.terms_digest = policy.terms_digest
        self.retention_policy_digest = policy.retention_policy_digest

    def verify(self, raw: bytes) -> governance.VerifiedGovernanceAssertionV1:
        digest = hashlib.sha3_512(raw).hexdigest()
        return governance.VerifiedGovernanceAssertionV1(
            policy_digest=self.policy.digest,
            approval_id=governance._approval_id_for_evidence(digest, len(raw)),
            evidence_sha3_512=digest,
            evidence_byte_length=len(raw),
            quarantine_policy_digest=self.policy.quarantine_policy_digest,
            quarantine_artifact_id=self.policy.quarantine_artifact_id,
            quarantine_head_artifact_id=self.policy.quarantine_head_artifact_id,
            quarantine_head_root=self.policy.quarantine_head_root,
            authority_evidence_digest=self.policy.authority_evidence_digest,
            revocation_head_digest=self.policy.revocation_head_digest,
            terms_digest=self.policy.terms_digest,
            retention_policy_digest=self.policy.retention_policy_digest,
            decision="GRANTED",
            issued_at=self.policy.effective_start,
            valid_from=self.policy.effective_start,
            valid_until=self.policy.effective_end - 1,
            observed_at=self.policy.effective_start + 1,
            verifier_id=self.verifier_id,
            verifier_epoch=self.verifier_epoch,
            zero_phi=True,
            state_owned=True,
        )


class _PrivacyVerifier:
    verifier_id = "SYNTH_PRIVACY_VERIFIER"
    verifier_epoch = 1

    def __init__(self, policy: privacy.ExternalPrivacySupportPolicyV1) -> None:
        self.policy = policy
        self.privacy_authority_evidence_digest = policy.privacy_authority_evidence_digest
        self.support_authority_evidence_digest = policy.support_authority_evidence_digest
        self.revocation_head_digest = policy.revocation_head_digest

    def verify(self, raw: bytes) -> privacy.VerifiedPrivacySupportAssertionV1:
        digest = hashlib.sha3_512(raw).hexdigest()
        return privacy.VerifiedPrivacySupportAssertionV1(
            policy_digest=self.policy.digest,
            assertion_id=privacy.assertion_id_for_evidence(digest, len(raw)),
            evidence_sha3_512=digest,
            evidence_byte_length=len(raw),
            quarantine_policy_digest=self.policy.quarantine_policy_digest,
            quarantine_artifact_id=self.policy.quarantine_artifact_id,
            quarantine_head_artifact_id=self.policy.quarantine_head_artifact_id,
            quarantine_head_root=self.policy.quarantine_head_root,
            governance_observation_artifact_id=self.policy.governance_observation_artifact_id,
            governance_evidence_digest=self.policy.governance_evidence_digest,
            governance_decision=self.policy.governance_decision,
            terms_digest=self.policy.terms_digest,
            retention_policy_digest=self.policy.retention_policy_digest,
            privacy_decision="GRANTED",
            support_decision="GRANTED",
            issued_at=self.policy.effective_start,
            valid_from=self.policy.effective_start,
            valid_until=self.policy.effective_end - 1,
            observed_at=self.policy.effective_start + 1,
            verifier_id=self.verifier_id,
            verifier_epoch=self.verifier_epoch,
            privacy_authority_evidence_digest=self.policy.privacy_authority_evidence_digest,
            support_authority_evidence_digest=self.policy.support_authority_evidence_digest,
            revocation_head_digest=self.policy.revocation_head_digest,
            coverage=tuple((key, True) for key in privacy.COVERAGE_KEYS),
            support_controls=tuple((key, True) for key in privacy.SUPPORT_CONTROL_KEYS),
            zero_phi=True,
            state_owned=True,
        )


class MirrorV2Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mirror-v2-test-")
        self.root = Path(self.temp.name)
        self.ingress_path = self.root / "ingress.db"
        self.core_path = self.root / "core.db"
        self.recovery_path = self.root / "recovery.db"
        self.ingress_config = ingress.IngressConfigV2(
            database_id="ingress-v2-synthetic",
            chain_id="ingress-chain-v2",
            policy_digest=_hex("ingress-policy"),
            authorization_digest=_hex("authorization"),
            terms_digest=_hex("terms"),
            effective_start=profile.FIXTURE_OBSERVATION_TIME,
            effective_end=profile.FIXTURE_OBSERVATION_TIME + 3600,
            cadence_seconds=60,
            max_slots=8,
        )
        self.ingress = ingress.IngressServiceV2(self.ingress_path, self.ingress_config)
        created = self.ingress.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        self.ingress.claim_slot(slot_id, now=profile.FIXTURE_OBSERVATION_TIME, lease_token="lease-v2")
        from tests.test_nc_medicaid_fhir_source import _envelope
        self.envelope = _envelope()
        self.ingress_receipt = self.ingress.admit_capture(
            self.envelope,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            lease_token="lease-v2",
            observed_at=profile.FIXTURE_OBSERVATION_TIME,
        )
        ing_snapshot = self.ingress.verify()
        self.governance_policy = governance.ExternalGovernanceApprovalPolicyV1(
            source_policy_digest=self.ingress_config.policy_digest,
            quarantine_policy_digest=self.ingress_config.policy_digest,
            quarantine_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_root=ing_snapshot["head_root"],
            verifier_id="SYNTH_GOVERNANCE_VERIFIER",
            verifier_epoch=1,
            scope=governance.SCOPE,
            effective_start=profile.FIXTURE_OBSERVATION_TIME,
            effective_end=profile.FIXTURE_OBSERVATION_TIME + 3600,
            max_evidence_bytes=1024,
            authority_evidence_digest=_hex("governance-authority"),
            revocation_head_digest=_hex("governance-revocation"),
            terms_digest=self.ingress_config.terms_digest,
            retention_policy_digest=_hex("retention"),
        )
        self.governance_raw = governance.ExternalGovernanceApprovalService(self.governance_policy, _GovernanceVerifier(self.governance_policy)).observe(b"synthetic governance assertion").raw
        self.privacy_policy = privacy.ExternalPrivacySupportPolicyV1(
            source_policy_digest=self.ingress_config.policy_digest,
            quarantine_policy_digest=self.ingress_config.policy_digest,
            quarantine_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_root=ing_snapshot["head_root"],
            governance_observation_artifact_id=json.loads(self.governance_raw.decode("ascii"))["artifact_id"],
            governance_evidence_digest=hashlib.sha3_512(b"synthetic governance assertion").hexdigest(),
            governance_decision="GRANTED",
            terms_digest=self.ingress_config.terms_digest,
            retention_policy_digest=self.governance_policy.retention_policy_digest,
            verifier_id="SYNTH_PRIVACY_VERIFIER",
            verifier_epoch=1,
            scope=privacy.SCOPE,
            effective_start=profile.FIXTURE_OBSERVATION_TIME,
            effective_end=profile.FIXTURE_OBSERVATION_TIME + 3600,
            max_evidence_bytes=1024,
            privacy_authority_evidence_digest=_hex("privacy-authority"),
            support_authority_evidence_digest=_hex("support-authority"),
            revocation_head_digest=_hex("privacy-revocation"),
        )
        self.privacy_raw = privacy.ExternalPrivacySupportApprovalService(self.privacy_policy, _PrivacyVerifier(self.privacy_policy)).observe(b"synthetic privacy assertion").raw
        self.core_config = core.CoreConfigV2(
            database_id="core-v2-synthetic", chain_id="core-chain-v2",
            ingress_database_id=self.ingress_config.database_id,
            runtime_profile_digest=_hex("runtime-profile"),
            governance_policy_digest=self.governance_policy.digest,
            privacy_policy_digest=self.privacy_policy.digest,
        )
        self.core = core.CoreServiceV2(self.core_path, self.core_config)
        self.source_result = self.core.ingest_source(self.ingress_path, self.ingress_receipt.artifact_id or "")
        self.gov_core_id = self.core.admit_governance(self.governance_raw, policy=self.governance_policy, evidence_raw=b"synthetic governance assertion")
        self.privacy_core_id = self.core.admit_privacy(self.privacy_raw, policy=self.privacy_policy, evidence_raw=b"synthetic privacy assertion")
        self.session_open = self.core.open_session(source_artifact_id=self.source_result["source_artifact_id"], governance_artifact_id=self.gov_core_id, privacy_artifact_id=self.privacy_core_id, now=profile.FIXTURE_OBSERVATION_TIME + 2)
        self.core.start_session(json.loads(self.session_open.raw.decode("ascii"))["subject_id"])
        self.session_id = json.loads(self.session_open.raw.decode("ascii"))["subject_id"]
        self.core.observe(self.session_id, 0, "PARITY", counts={"observed": 1, "changed": 0})
        self.custody = _Custody()
        self.storage = _Storage()
        self.recovery_config = recovery.RecoveryConfigV2(
            database_id="recovery-v2-synthetic", chain_id="recovery-chain-v2",
            profile_digest=_hex("recovery-profile"), custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id, ingress_database_id=self.ingress_config.database_id,
            core_database_id=self.core_config.database_id,
            ingress_config_digest=self.ingress_config.digest, core_config_digest=self.core_config.digest,
        )
        self.recovery_service = recovery.RecoveryServiceV2(self.recovery_path, self.recovery_config, self.custody, self.storage)

    def _fresh_ingress(self, name: str) -> tuple[ingress.IngressServiceV2, str]:
        service = ingress.IngressServiceV2(self.root / name, self.ingress_config)
        created = service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        return service, slot_id

    def _state_fingerprint(self, service: ingress.IngressServiceV2) -> tuple[object, ...]:
        value = service.verify()
        return (value["sequence"], value["head_root"], value["event_count"], value["artifact_count"], value["slot_count"])

    def test_capture_requires_active_lease_and_rejects_due_without_mutation(self) -> None:
        service, _slot_id = self._fresh_ingress("due-capture.db")
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:slot-state"):
            service.admit_capture(
                self.envelope,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                lease_token="not-held",
                observed_at=profile.FIXTURE_OBSERVATION_TIME,
            )
        self.assertEqual(before, self._state_fingerprint(service))

    def test_expired_and_stale_leases_reject_without_mutation(self) -> None:
        service, slot_id = self._fresh_ingress("expired-capture.db")
        service.claim_slot(slot_id, now=profile.FIXTURE_OBSERVATION_TIME, lease_token="lease-old")
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:lease-expired"):
            service.admit_capture(
                self.envelope,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                lease_token="lease-old",
                observed_at=profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds,
            )
        self.assertEqual(before, self._state_fingerprint(service))

        service.claim_slot(
            slot_id,
            now=profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds + 1,
            lease_token="lease-new",
        )
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:lease-token"):
            service.admit_capture(
                self.envelope,
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                lease_token="lease-old",
                observed_at=profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds + 1,
            )
        self.assertEqual(before, self._state_fingerprint(service))

    def test_committed_retry_after_lease_expiry_is_byte_identical(self) -> None:
        before = self.ingress_receipt
        state_before = self._state_fingerprint(self.ingress)
        retry = self.ingress.admit_capture(
            self.envelope,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            lease_token="lease-v2",
            observed_at=profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds + 1,
        )
        self.assertEqual(before.raw, retry.raw)
        self.assertEqual(state_before, self._state_fingerprint(self.ingress))

    def test_fetch_events_preserve_verifier_derived_retry_attempts(self) -> None:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle, _transport

        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        success = fhir.fixture_response(_bundle(), request_url)
        retry_envelope = fhir.build_fixture_envelope(
            _transport(_bundle(), retries={(request_url, 0): throttled, (request_url, 1): success})
        )
        service, slot_id = self._fresh_ingress("retry-capture.db")
        service.claim_slot(slot_id, now=profile.FIXTURE_OBSERVATION_TIME, lease_token="lease-retry")
        service.admit_capture(
            retry_envelope,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            lease_token="lease-retry",
            observed_at=profile.FIXTURE_OBSERVATION_TIME,
        )
        connection = sqlite3.connect(service.path)
        try:
            rows = connection.execute(
                "SELECT receipt_bytes FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' ORDER BY page_index,transport_attempt"
            ).fetchall()
        finally:
            connection.close()
        receipts = [json.loads(bytes(row[0]).decode("ascii")) for row in rows]
        self.assertEqual([429, 200], [value["status"] for value in receipts])
        self.assertEqual([2, None], [value["retry_after_seconds"] for value in receipts])
        self.assertEqual([False, True], [value["selected"] for value in receipts])
        self.assertEqual({"SYNTHETIC_FIXTURE_UNAUTHENTICATED"}, {value["evidence_class"] for value in receipts})
        self.assertNotIn("authenticated", receipts[0])
        self.assertTrue(service.verify()["attestation_count"] == 2)

    def test_failed_attempt_events_remain_failure_evidence(self) -> None:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle

        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        failed_envelope = fhir.build_fixture_envelope(fhir.SyntheticFhirTransport({(request_url, 0): throttled}))
        service, slot_id = self._fresh_ingress("failed-capture.db")
        service.claim_slot(slot_id, now=profile.FIXTURE_OBSERVATION_TIME, lease_token="lease-failed")
        receipt = service.admit_capture(
            failed_envelope,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            lease_token="lease-failed",
            observed_at=profile.FIXTURE_OBSERVATION_TIME,
        )
        self.assertEqual("HELD", receipt.next_state)
        connection = sqlite3.connect(service.path)
        try:
            rows = connection.execute(
                "SELECT receipt_bytes FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' ORDER BY page_index,transport_attempt"
            ).fetchall()
        finally:
            connection.close()
        receipts = [json.loads(bytes(row[0]).decode("ascii")) for row in rows]
        self.assertGreaterEqual(len(receipts), 2)
        self.assertTrue(any(value["status"] != 200 for value in receipts))
        self.assertTrue(all(value["evidence_class"] == "SYNTHETIC_FIXTURE_UNAUTHENTICATED" for value in receipts))
        self.assertEqual("FAILED", json.loads(failed_envelope.decode("ascii"))["source_status"])
        self.assertTrue(service.verify()["attestation_count"] == len(receipts))

    def test_independent_replay_rejects_observed_time_and_fetch_receipt_forgery(self) -> None:
        tampered_time = self.root / "tampered-time.db"
        shutil.copy2(self.ingress_path, tampered_time)
        connection = sqlite3.connect(tampered_time)
        try:
            connection.execute("UPDATE ingress_events SET observed_at=observed_at+1 WHERE event_kind='FETCH_ATTESTATION'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(tampered_time, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)

        tampered_lease = self.root / "tampered-lease.db"
        shutil.copy2(self.ingress_path, tampered_lease)
        connection = sqlite3.connect(tampered_lease)
        try:
            connection.execute(
                "UPDATE ingress_events SET lease_token=? WHERE event_kind='FETCH_ATTESTATION'",
                ("forged-lease-token",),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(tampered_lease, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)

        tampered_receipt = self.root / "tampered-receipt.db"
        shutil.copy2(self.ingress_path, tampered_receipt)
        connection = sqlite3.connect(tampered_receipt)
        try:
            row = connection.execute("SELECT sequence,receipt_bytes FROM ingress_events WHERE event_kind='FETCH_ATTESTATION'").fetchone()
            forged = json.loads(bytes(row[1]).decode("ascii"))
            forged["status"] = 201
            forged["evidence_class"] = "SYNTHETIC_FIXTURE_UNAUTHENTICATED"
            forged_raw = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode("ascii")
            connection.execute("UPDATE ingress_events SET receipt_bytes=? WHERE sequence=?", (forged_raw, row[0]))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(tampered_receipt, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)

    def test_independent_replay_rejects_omitted_and_reordered_attempts(self) -> None:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle, _transport

        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        success = fhir.fixture_response(_bundle(), request_url)
        raw = fhir.build_fixture_envelope(
            _transport(_bundle(), retries={(request_url, 0): throttled, (request_url, 1): success})
        )
        service, slot_id = self._fresh_ingress("attempt-order.db")
        service.claim_slot(slot_id, now=profile.FIXTURE_OBSERVATION_TIME, lease_token="lease-order")
        service.admit_capture(
            raw,
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            lease_token="lease-order",
            observed_at=profile.FIXTURE_OBSERVATION_TIME,
        )

        omitted = self.root / "omitted-attempt.db"
        shutil.copy2(service.path, omitted)
        connection = sqlite3.connect(omitted)
        try:
            connection.execute(
                "DELETE FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' AND transport_attempt=1"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(omitted, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)

        reordered = self.root / "reordered-attempt.db"
        shutil.copy2(service.path, reordered)
        connection = sqlite3.connect(reordered)
        try:
            rows = connection.execute(
                "SELECT sequence,receipt_bytes FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' ORDER BY transport_attempt"
            ).fetchall()
            connection.execute("UPDATE ingress_events SET receipt_bytes=? WHERE sequence=?", (rows[1][1], rows[0][0]))
            connection.execute("UPDATE ingress_events SET receipt_bytes=? WHERE sequence=?", (rows[0][1], rows[1][0]))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(reordered, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_three_owner_tables_and_full_chain(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1, now=profile.FIXTURE_OBSERVATION_TIME + 10)
        self.assertEqual(point.state, "VERIFIED")
        self.assertEqual(self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1, now=profile.FIXTURE_OBSERVATION_TIME + 10).raw, point.raw)
        restored_ingress = self.root / "restored-ingress.db"
        restored_core = self.root / "restored-core.db"
        restored = self.recovery_service.restore_point(point.point_id, restored_ingress, restored_core)
        self.assertEqual(restored.state, "PUBLISHED")
        self.assertEqual(self.recovery_service.verify()["states"]["PUBLISHED"], 1)
        self.assertEqual(ingress.IngressServiceV2(restored_ingress, self.ingress_config).verify()["head_root"], self.ingress.verify()["head_root"])
        self.assertEqual(core.CoreServiceV2(restored_core, self.core_config).verify(ingress_path=restored_ingress)["head_root"], self.core.verify(ingress_path=self.ingress_path)["head_root"])
        expected = {
            "ingress_meta", "ingress_slots", "ingress_artifacts", "ingress_heads", "ingress_events",
            "core_meta", "core_artifacts", "core_heads", "core_sessions", "core_slots", "core_events",
            "recovery_meta", "recovery_points", "recovery_events",
        }
        self.assertEqual(len(expected), 14)
        for path in (self.ingress_path, self.core_path, self.recovery_path):
            connection = sqlite3.connect(path)
            try:
                names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            finally:
                connection.close()
            if path == self.ingress_path:
                self.assertEqual(names, expected & {name for name in expected if name.startswith("ingress_")})
            elif path == self.core_path:
                self.assertEqual(names, expected & {name for name in expected if name.startswith("core_")})
            else:
                self.assertEqual(names, expected & {name for name in expected if name.startswith("recovery_")})

    def test_fetch_attestations_are_typed_events_and_delivery_is_durable(self) -> None:
        connection = sqlite3.connect(self.ingress_path)
        try:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertNotIn("ingress_attestations", names)
            fetches = connection.execute("SELECT source_id,slot_id,page_index,transport_attempt,receipt_bytes FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' ORDER BY page_index").fetchall()
            self.assertEqual(len(fetches), 1)
            self.assertTrue(all(bytes(row[4]) and self.envelope not in bytes(row[4]) for row in fetches))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='ingress_fetch_natural_key_idx'").fetchone()[0], 1)
            slot_id = connection.execute("SELECT slot_id FROM ingress_slots").fetchone()[0]
            heads = connection.execute("SELECT stream_kind,stream_id,artifact_id,head_root,event_sequence FROM ingress_heads ORDER BY stream_kind,stream_id").fetchall()
            self.assertEqual(
                {(row[0], row[1]) for row in heads},
                {("FETCH", slot_id), ("SLOT", slot_id), ("QUARANTINE", self.ingress_config.chain_id)},
            )
            self.assertTrue(all(row[2] is not None and len(row[3]) == 128 and row[4] > 0 for row in heads))
        finally:
            connection.close()
        intent = self.core.begin_delivery(self.session_id, "synthetic-job-v2", lease_token="delivery-lease", now=profile.FIXTURE_OBSERVATION_TIME + 20)
        self.assertEqual(
            self.core.begin_delivery(self.session_id, "synthetic-job-v2", lease_token="delivery-lease", now=profile.FIXTURE_OBSERVATION_TIME + 20).raw,
            intent.raw,
        )
        response_digest = _hex("receiver-ack")
        ack = self.core.acknowledge_delivery(self.session_id, job_id="synthetic-job-v2", lease_token="delivery-lease", response_digest=response_digest)
        self.assertEqual(
            self.core.acknowledge_delivery(self.session_id, job_id="synthetic-job-v2", lease_token="delivery-lease", response_digest=response_digest).raw,
            ack.raw,
        )
        self.assertEqual(self.core.verify(ingress_path=self.ingress_path)["event_count"], 10)

    def test_raw_envelope_is_ingress_only_and_exports_are_raw_free(self) -> None:
        connection = sqlite3.connect(self.ingress_path)
        try:
            rows = connection.execute("SELECT raw FROM ingress_artifacts").fetchall()
        finally:
            connection.close()
        self.assertEqual(sum(bytes(row[0]) == self.envelope for row in rows), 1)
        connection = sqlite3.connect(self.core_path)
        try:
            raw_values = [bytes(row[0]) for row in connection.execute("SELECT raw FROM core_artifacts")]
            event_values = [bytes(row[0]) for row in connection.execute("SELECT event_raw FROM core_events")]
        finally:
            connection.close()
        self.assertNotIn(self.envelope, raw_values)
        self.assertNotIn(self.envelope, event_values)
        self.assertNotIn(self.envelope, self.ingress.logical_export())
        self.assertNotIn(self.envelope, self.core.logical_export() if hasattr(self.core, "logical_export") else b"")
        self.assertNotIn(self.envelope, json.dumps(self.ingress.support(), sort_keys=True).encode("ascii"))
        self.assertNotIn(self.envelope, json.dumps(self.core.support(), sort_keys=True).encode("ascii"))

    def test_profile_owned_changed_observation_reaches_core_case_without_authority(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _envelope
        changed_path = self.root / "changed-ingress.db"
        changed_ingress = ingress.IngressServiceV2(changed_path, self.ingress_config)
        scheduled_at = profile.FIXTURE_OBSERVATION_TIME
        created = changed_ingress.ensure_slot(scheduled_at)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        changed_ingress.claim_slot(slot_id, now=scheduled_at, lease_token="lease-v2-changed")
        changed_receipt = changed_ingress.admit_capture(
            _envelope(location_variant="changed"),
            scheduled_at=scheduled_at,
            lease_token="lease-v2-changed",
            observed_at=scheduled_at,
        )
        result = self.core.ingest_source(changed_path, changed_receipt.artifact_id or "")
        self.assertEqual(result["observation_status"], "OBSERVED_CHANGED")
        case_id = self.core.admit_case(result["reconciliation_artifact_id"] or "")
        responsibility = self.core.advance_case(
            case_id,
            next_state="RESPONSIBILITY",
            responsibility="UNKNOWN",
        )
        remediation = self.core.advance_case(
            responsibility.subject_id,
            next_state="REMEDIATION",
            remediation="PROPOSED",
        )
        retest = self.core.advance_case(
            remediation.subject_id,
            next_state="RETEST",
            retest="EXECUTED",
        )
        persistence = self.core.advance_case(
            retest.subject_id,
            next_state="PERSISTENCE",
            parity="DIVERGENT",
        )
        self.assertEqual(
            self.core.advance_case(
                retest.subject_id,
                next_state="PERSISTENCE",
                parity="DIVERGENT",
            ).raw,
            persistence.raw,
        )
        verified = self.core.verify()
        self.assertGreaterEqual(verified["artifact_count"], 7)
        self.assertFalse(verified["flags"]["payment_authority"])
        self.assertEqual(persistence.subject_id, self.core.admit_case(result["reconciliation_artifact_id"] or ""))

    def test_old_or_wrong_database_schema_rejected_without_claim(self) -> None:
        old = self.root / "old.db"
        connection = sqlite3.connect(old)
        try:
            connection.execute("CREATE TABLE continuity_meta(value TEXT)")
        finally:
            connection.close()
        with self.assertRaises(recovery.RecoveryError):
            recovery.RecoveryServiceV2(old, self.recovery_config, self.custody, self.storage)
        old_ingress = self.root / "old-ingress.db"
        connection = sqlite3.connect(old_ingress)
        try:
            connection.execute("CREATE TABLE ingress_attestations(artifact_id TEXT)")
        finally:
            connection.close()
        with self.assertRaises(ingress.IngressError):
            ingress.IngressServiceV2(old_ingress, self.ingress_config)

    def test_independent_replay_rejects_root_tamper_and_query_plans_use_hot_indexes(self) -> None:
        bad_ingress = self.root / "bad-ingress.db"
        shutil.copy2(self.ingress_path, bad_ingress)
        connection = sqlite3.connect(bad_ingress)
        try:
            connection.execute("UPDATE ingress_events SET after_root=? WHERE sequence=(SELECT MAX(sequence) FROM ingress_events)", ("f" * 128,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress.IngressServiceV2(bad_ingress, self.ingress_config).verify()
        bad_core = self.root / "bad-core-state.db"
        shutil.copy2(self.core_path, bad_core)
        connection = sqlite3.connect(bad_core)
        try:
            connection.execute("UPDATE core_artifacts SET current_state='FORGED'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(core_independent.CoreVerificationError):
            core_independent.verify_database(
                bad_core,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
        bad_core_head = self.root / "bad-core-head.db"
        shutil.copy2(self.core_path, bad_core_head)
        connection = sqlite3.connect(bad_core_head)
        try:
            connection.execute("DELETE FROM core_heads WHERE stream_kind='SESSION'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(core_independent.CoreVerificationError):
            core_independent.verify_database(
                bad_core_head,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )
        connection = sqlite3.connect(self.ingress_path)
        try:
            plan = " ".join(str(row) for row in connection.execute("EXPLAIN QUERY PLAN SELECT slot_id FROM ingress_slots WHERE state='DUE' AND lease_until IS NULL ORDER BY slot_id"))
            self.assertIn("ingress_slots_due_idx", plan)
        finally:
            connection.close()
        connection = sqlite3.connect(self.core_path)
        try:
            plan = " ".join(str(row) for row in connection.execute("EXPLAIN QUERY PLAN SELECT session_id FROM core_sessions WHERE delivery_state='DUE' AND delivery_lease_until IS NULL ORDER BY delivery_job_id"))
            self.assertIn("core_delivery_state_idx", plan)
        finally:
            connection.close()

    def test_removed_later_views_are_not_core_artifact_kinds(self) -> None:
        for kind in ("DENOMINATOR", "CONTRACT", "TRANSACTION", "MONEY", "TRANSITION", "STATE_VALUE"):
            self.assertNotIn(kind, core.ARTIFACT_KINDS)
        self.assertFalse(core.FIXED_FLAGS.get("policyResult", False))
        self.assertFalse(core.FIXED_FLAGS.get("effectiveDirective", False))

    def test_delivery_response_loss_requeues_with_bounded_exhaustion(self) -> None:
        now = profile.FIXTURE_OBSERVATION_TIME + 100
        lease = "delivery-retry-1"
        self.core.begin_delivery(self.session_id, "retry-job-v2", lease_token=lease, now=now)
        self.core.mark_delivery_unknown(self.session_id, job_id="retry-job-v2", lease_token=lease)
        lease = "delivery-retry-2"
        self.core.begin_delivery(self.session_id, "retry-job-v2", lease_token=lease, now=now + self.core_config.cadence_seconds + 1)
        self.core.mark_delivery_unknown(self.session_id, job_id="retry-job-v2", lease_token=lease)
        lease = "delivery-retry-3"
        self.core.begin_delivery(self.session_id, "retry-job-v2", lease_token=lease, now=now + 2 * (self.core_config.cadence_seconds + 1))
        self.core.mark_delivery_unknown(self.session_id, job_id="retry-job-v2", lease_token=lease)
        with self.assertRaises(core.CoreConflictError) as context:
            self.core.begin_delivery(self.session_id, "retry-job-v2", lease_token="delivery-retry-4", now=now + 3 * (self.core_config.cadence_seconds + 1))
        self.assertEqual(str(context.exception), "core:delivery-exhausted")
        self.assertEqual(self.core.verify(ingress_path=self.ingress_path)["flags"]["payment_authority"], False)

    def test_key_revocation_blocks_restore_and_storage_corruption(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1, now=1)
        object_id = json.loads(point.raw.decode("ascii"))["payload_digest"]
        self.custody.revoked.add(("synthetic-key", 1))
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.restore_point(point.point_id, self.root / "bad-i.db", self.root / "bad-c.db")
        self.assertNotEqual(object_id, "")


if __name__ == "__main__":
    unittest.main()
