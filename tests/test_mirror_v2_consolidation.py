from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import traceback
import unittest
from unittest import mock

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import external_governance_approval as governance
from app.mirror import external_privacy_support_approval as privacy
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from app.mirror import restore_publication
from app.mirror import source_admission
from app.mirror import writer_authority
from tests.test_nc_medicaid_fhir_source import _envelope


def _hex(seed: str) -> str:
    return hashlib.sha3_512(seed.encode("ascii")).hexdigest()


def _ingress_token(seed: str) -> str:
    return (seed + "-ingress-token").ljust(32, "x")


class _ManualClock:
    def __init__(self, value: int) -> None:
        self.value = value
        self.calls = 0
        self.raise_on_read = False

    def __call__(self) -> int:
        self.calls += 1
        if self.raise_on_read:
            raise RuntimeError("clock read must not be needed")
        return self.value


class _Custody:
    custody_id = "synthetic-custody-v2"

    def __init__(self) -> None:
        self.epoch = 1
        self.revoked: set[tuple[str, int]] = set()
        self.fail_seal = False

    def current_key(self) -> recovery.RecoveryKey:
        return recovery.RecoveryKey("synthetic-key", self.epoch, "ACTIVE")

    def state(self, key_id: str, key_epoch: int) -> str:
        return "REVOKED" if (key_id, key_epoch) in self.revoked else "ACTIVE"

    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes:
        if self.fail_seal:
            raise RuntimeError("synthetic seal failure")
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

    def put_if_absent(
        self,
        object_id: str,
        sealed: bytes,
        *,
        key_id: str,
        key_epoch: int,
    ) -> recovery.StorageReceipt:
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


class _FailOnceStorage(_Storage):
    def __init__(self) -> None:
        super().__init__()
        self.fail_once = True

    def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> recovery.StorageReceipt:
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("indeterminate storage response")
        return super().put_if_absent(object_id, sealed, key_id=key_id, key_epoch=key_epoch)


class _InitializationFaultConnection:
    def __init__(
        self,
        inner: sqlite3.Connection,
        *,
        trigger: str | None = None,
        precommit_error: BaseException | None = None,
        fail_rollback: bool = False,
        fail_close: bool = False,
        fail_commit: bool = False,
    ) -> None:
        self.inner = inner
        self.trigger = trigger
        self.precommit_error = precommit_error
        self.fail_rollback = fail_rollback
        self.fail_close = fail_close
        self.fail_commit = fail_commit
        self.rollback_calls = 0
        self.close_calls = 0
        self.commit_calls = 0

    def execute(self, sql: str, *parameters: object):
        if self.trigger is not None and self.trigger in sql:
            if self.precommit_error is None:
                raise RuntimeError("initialization fault missing error")
            raise self.precommit_error
        return self.inner.execute(sql, *parameters)

    def rollback(self) -> None:
        self.rollback_calls += 1
        if self.fail_rollback:
            raise RuntimeError("CANARY_INIT_ROLLBACK_PHI_PATH")
        self.inner.rollback()

    def commit(self) -> None:
        self.commit_calls += 1
        self.inner.commit()
        if self.fail_commit:
            raise RuntimeError("CANARY_INIT_COMMIT_PHI_PATH")

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            self.inner.close()
            raise RuntimeError("CANARY_INIT_CLOSE_PHI_PATH")
        self.inner.close()

    def __getattr__(self, name: str) -> object:
        return getattr(self.inner, name)


class _RandomizedCustody(_Custody):
    def __init__(self) -> None:
        super().__init__()
        self.seal_count = 0

    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes:
        self.seal_count += 1
        return b"R" + self.seal_count.to_bytes(4, "big") + super().seal(plaintext, key_id, key_epoch)

    def open(self, sealed: bytes, key_id: str, key_epoch: int) -> bytes:
        if not sealed.startswith(b"R") or len(sealed) < 5:
            raise RuntimeError("invalid randomized fixture object")
        return super().open(sealed[5:], key_id, key_epoch)


class _OversizeStorage(_Storage):
    def __init__(self, size: int) -> None:
        super().__init__()
        self.size = size

    def get(self, object_id: str) -> bytes:
        return b"x" * self.size


class _NoOpenCustody(_Custody):
    def __init__(self, *, oversized_plaintext: bool = False) -> None:
        super().__init__()
        self.opened = False
        self.oversized_plaintext = oversized_plaintext

    def open(self, sealed: bytes, key_id: str, key_epoch: int) -> bytes:
        self.opened = True
        if self.oversized_plaintext:
            return b"x" * (16 * 1024 * 1024 + 1)
        raise AssertionError("custody.open was reached")


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


class _FailSealCustody(_Custody):
    def __init__(self) -> None:
        super().__init__()
        self.fail_seal = True

    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes:
        if self.fail_seal:
            raise RuntimeError("synthetic seal failure")
        return super().seal(plaintext, key_id, key_epoch)


class _ReentrantCustody(_Custody):
    def __init__(self) -> None:
        super().__init__()
        self.callback: object | None = None
        self.errors: list[BaseException] = []
        self.called = False

    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes:
        if not self.called and self.callback is not None:
            self.called = True
            try:
                self.callback()
            except BaseException as error:
                self.errors.append(error)
        return super().seal(plaintext, key_id, key_epoch)


class _ReentrantStorage(_Storage):
    def __init__(self) -> None:
        super().__init__()
        self.callback: object | None = None
        self.errors: list[BaseException] = []
        self.called = False

    def put_if_absent(
        self,
        object_id: str,
        sealed: bytes,
        *,
        key_id: str,
        key_epoch: int,
    ) -> recovery.StorageReceipt:
        if not self.called and self.callback is not None:
            self.called = True
            try:
                self.callback()
            except BaseException as error:
                self.errors.append(error)
        return super().put_if_absent(object_id, sealed, key_id=key_id, key_epoch=key_epoch)


def _sanitized_pair(envelope: bytes | None = None) -> tuple[bytes, bytes]:
    admission = source_admission.SourceAdmissionService(
        profile.NC_MEDICAID_GRAPH_PROFILE,
        fhir_independent.NcMedicaidFhirVerifier(),
    ).admit(envelope or _envelope())
    return admission.observation, admission.verification_receipt


def _rechain_ingress_observed_at(path: Path, replacements: dict[int, int]) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM ingress_events ORDER BY sequence").fetchall()
        previous = ingress_independent.GENESIS_ROOT
        stream_roots: dict[tuple[str, str], str] = {}
        stream_last: dict[tuple[str, str], int] = {}
        for row in rows:
            value = json.loads(bytes(row["event_raw"]).decode("ascii"))
            sequence = int(value["sequence"])
            if sequence in replacements:
                value["observed_at"] = replacements[sequence]
            value["before_root"] = previous
            stream_key = (str(value["stream_kind"]), str(value["stream_id"]))
            value["stream_before_root"] = stream_roots.get(stream_key, ingress_independent.GENESIS_ROOT)
            value["event_id"] = ingress_independent._digest(
                "event-id",
                {key: value[key] for key in ingress_independent.EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            value["after_root"] = ingress_independent._event_root(
                sequence=sequence,
                previous=value["before_root"],
                event_id=value["event_id"],
                event_kind=value["event_kind"],
                stream_kind=value["stream_kind"],
                stream_id=value["stream_id"],
                slot_id=value["slot_id"],
                next_state=value["next_state"],
                observed_at=value["observed_at"],
                material_digest=value["material_digest"],
            )
            value["stream_after_root"] = ingress_independent._stream_root(
                sequence=sequence,
                previous=value["stream_before_root"],
                event_id=value["event_id"],
                stream_kind=value["stream_kind"],
                stream_id=value["stream_id"],
                next_state=value["next_state"],
                observed_at=value["observed_at"],
                material_digest=value["material_digest"],
            )
            event_raw = ingress_independent._canonical(value)
            connection.execute(
                """
                UPDATE ingress_events SET event_id=?,observed_at=?,before_root=?,after_root=?,
                    stream_before_root=?,stream_after_root=?,event_raw=?,receipt_digest=?
                WHERE sequence=?
                """,
                (
                    value["event_id"],
                    value["observed_at"],
                    value["before_root"],
                    value["after_root"],
                    value["stream_before_root"],
                    value["stream_after_root"],
                    event_raw,
                    ingress_independent._raw_digest("receipt", event_raw),
                    sequence,
                ),
            )
            previous = value["after_root"]
            stream_roots[stream_key] = value["stream_after_root"]
            stream_last[stream_key] = sequence
        for (stream_kind, stream_id), head_root in stream_roots.items():
            connection.execute(
                "UPDATE ingress_heads SET head_root=?,event_sequence=? WHERE stream_kind=? AND stream_id=?",
                (head_root, stream_last[(stream_kind, stream_id)], stream_kind, stream_id),
            )
        connection.execute("UPDATE ingress_meta SET head_root=? WHERE meta_id=1", (previous,))
        connection.commit()
    finally:
        connection.close()


class MirrorV2Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mirror-v2-test-")
        self.root = Path(self.temp.name)
        self.authority = writer_authority.WriterAuthority(self.root)
        self.ingress_path = self.root / "ingress.db"
        self.core_path = self.root / "core.db"
        self.recovery_path = self.root / "recovery.db"
        now = profile.FIXTURE_OBSERVATION_TIME
        self.ingress_config = ingress.IngressConfigV2(
            database_id="ingress-v2-synthetic",
            chain_id="ingress-chain-v2",
            policy_digest=_hex("ingress-policy"),
            authorization_digest=_hex("authorization"),
            terms_digest=_hex("terms"),
            effective_start=now,
            effective_end=now + 3600,
            cadence_seconds=60,
            max_slots=8,
        )
        self.clock = _ManualClock(now)
        self.ingress = ingress.IngressServiceV2(
            self.ingress_path,
            self.ingress_config,
            clock=self.clock,
            authority=self.authority,
        )
        self.observation, self.verification_receipt = _sanitized_pair()
        created = self.ingress.ensure_slot(now)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        self.lease_token = _ingress_token("lease-v2")
        self.ingress.claim_slot(slot_id, lease_token=self.lease_token)
        self.ingress_receipt = self.ingress.admit_observation(
            self.observation,
            self.verification_receipt,
            scheduled_at=now,
            attempt=1,
            lease_token=self.lease_token,
        )
        ing_snapshot = self.ingress.verify()
        governance_evidence = b"synthetic governance assertion"
        self.governance_policy = governance.ExternalGovernanceApprovalPolicyV1(
            source_policy_digest=self.ingress_config.policy_digest,
            quarantine_policy_digest=self.ingress_config.policy_digest,
            quarantine_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_root=ing_snapshot["head_root"],
            verifier_id="SYNTH_GOVERNANCE_VERIFIER",
            verifier_epoch=1,
            scope=governance.SCOPE,
            effective_start=now,
            effective_end=now + 3600,
            max_evidence_bytes=1024,
            authority_evidence_digest=_hex("governance-authority"),
            revocation_head_digest=_hex("governance-revocation"),
            terms_digest=self.ingress_config.terms_digest,
            retention_policy_digest=_hex("retention"),
        )
        self.governance_raw = governance.ExternalGovernanceApprovalService(
            self.governance_policy,
            _GovernanceVerifier(self.governance_policy),
        ).observe(governance_evidence).raw
        self.privacy_policy = privacy.ExternalPrivacySupportPolicyV1(
            source_policy_digest=self.ingress_config.policy_digest,
            quarantine_policy_digest=self.ingress_config.policy_digest,
            quarantine_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_artifact_id=self.ingress_receipt.artifact_id or "0" * 128,
            quarantine_head_root=ing_snapshot["head_root"],
            governance_observation_artifact_id=json.loads(self.governance_raw.decode("ascii"))["artifact_id"],
            governance_evidence_digest=hashlib.sha3_512(governance_evidence).hexdigest(),
            governance_decision="GRANTED",
            terms_digest=self.ingress_config.terms_digest,
            retention_policy_digest=self.governance_policy.retention_policy_digest,
            verifier_id="SYNTH_PRIVACY_VERIFIER",
            verifier_epoch=1,
            scope=privacy.SCOPE,
            effective_start=now,
            effective_end=now + 3600,
            max_evidence_bytes=1024,
            privacy_authority_evidence_digest=_hex("privacy-authority"),
            support_authority_evidence_digest=_hex("support-authority"),
            revocation_head_digest=_hex("privacy-revocation"),
        )
        privacy_evidence = b"synthetic privacy assertion"
        self.privacy_raw = privacy.ExternalPrivacySupportApprovalService(
            self.privacy_policy,
            _PrivacyVerifier(self.privacy_policy),
        ).observe(privacy_evidence).raw
        self.core_config = core.CoreConfigV2(
            database_id="core-v2-synthetic",
            chain_id="core-chain-v2",
            ingress_database_id=self.ingress_config.database_id,
            ingress_chain_id=self.ingress_config.chain_id,
            runtime_profile_digest=self.ingress_config.source_contract_digest,
            governance_policy_digest=self.governance_policy.digest,
            privacy_policy_digest=self.privacy_policy.digest,
            ingress_config_digest=self.ingress_config.digest,
            corrective_action_control_digest=_hex("corrective-action"),
        )
        self.core_clock = _ManualClock(now + 2)
        self.core = core.CoreServiceV2(
            self.core_path,
            self.core_config,
            clock=self.core_clock,
            authority=self.authority,
        )
        self.source_result = self.core.ingest_source(
            self.ingress_path, self.ingress_receipt.artifact_id or ""
        )
        self.gov_core_id = self.core.admit_governance(
            self.governance_raw,
            policy=self.governance_policy,
            evidence_raw=governance_evidence,
        )
        self.privacy_core_id = self.core.admit_privacy(
            self.privacy_raw,
            policy=self.privacy_policy,
            evidence_raw=privacy_evidence,
        )
        self.session_open = self.core.open_session(
            source_artifact_id=self.source_result["source_artifact_id"],
            governance_artifact_id=self.gov_core_id,
            privacy_artifact_id=self.privacy_core_id,
        )
        self.session_id = json.loads(self.session_open.raw.decode("ascii"))["subject_id"]
        self.core.start_session(self.session_id)
        self.core.observe(self.session_id, 0, "PARITY", counts={"observed": 1, "changed": 0})
        self.custody = _Custody()
        self.storage = _Storage()
        self.recovery_config = recovery.RecoveryConfigV2(
            database_id="recovery-v2-synthetic",
            chain_id="recovery-chain-v2",
            profile_digest=_hex("recovery-profile"),
            custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id,
            ingress_database_id=self.ingress_config.database_id,
            core_database_id=self.core_config.database_id,
            ingress_config_digest=self.ingress_config.digest,
            core_config_digest=self.core_config.digest,
        )
        self.recovery_service = recovery.RecoveryServiceV2(
            self.recovery_path,
            self.recovery_config,
            self.custody,
            self.storage,
            authority=self.authority,
        )

    def tearDown(self) -> None:
        self.authority.close()
        self.temp.cleanup()

    @staticmethod
    def _fingerprint(service: ingress.IngressServiceV2) -> tuple[object, ...]:
        value = service.verify()
        return (
            value["sequence"],
            value["head_root"],
            value["event_count"],
            value["artifact_count"],
            value["slot_count"],
        )

    @staticmethod
    def _core_fingerprint(service: core.CoreServiceV2) -> tuple[object, ...]:
        value = service.verify()
        return value["sequence"], value["head_root"], value["event_count"], value["artifact_count"]

    @staticmethod
    def _event_values(path: Path, table: str, column: str = "event_raw") -> list[dict[str, object]]:
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(f"SELECT {column} FROM {table} ORDER BY sequence").fetchall()
            return [json.loads(bytes(row[0]).decode("ascii")) for row in rows]
        finally:
            connection.close()

    def test_v6_ingress_contract_and_three_admission_events_are_frozen(self) -> None:
        result = self.ingress.verify()
        self.assertEqual("mirror-ingress-v6", result["schema"])
        self.assertEqual(6, result["schema_version"])
        self.assertEqual(6, ingress_independent.SCHEMA_VERSION)
        self.assertEqual("BL/MIRROR/INGRESS/V6/", ingress_independent.DOMAIN)
        self.assertEqual(self.clock.value, result["latest_observed_at"])
        events = self._event_values(self.ingress_path, "ingress_events")
        self.assertEqual(
            ["CREATE_SLOT", "LEASE", "CAPTURE", "BEGIN_QUARANTINE", "ADMIT"],
            [str(event["event_kind"]) for event in events],
        )
        self.assertEqual({self.clock.value}, {int(event["observed_at"]) for event in events})
        logical = self.ingress.logical_export()
        self.assertIn(b"mirror-ingress-logical-export-v6", logical)
        self.assertNotIn(_envelope(), self.ingress_path.read_bytes())
        self.assertNotIn(_envelope(), logical)

    def test_explicit_writer_authority_and_scope_fail_closed_before_service_open(self) -> None:
        no_authority_path = self.root / "no-authority.sqlite"
        with self.assertRaises(TypeError):
            ingress.IngressServiceV2(no_authority_path, self.ingress_config, clock=self.clock)  # type: ignore[call-arg]
        self.assertFalse(no_authority_path.exists())

        wrong_root = self.root / "wrong-root"
        wrong_root.mkdir()
        wrong_authority = writer_authority.WriterAuthority(wrong_root)
        try:
            with self.assertRaises(writer_authority.WriterAuthorityError):
                ingress.IngressServiceV2(
                    self.root / "wrong-authority.sqlite",
                    self.ingress_config,
                    clock=self.clock,
                    authority=wrong_authority,
                )
        finally:
            wrong_authority.close()

        closed_root = self.root / "closed-root"
        closed_root.mkdir()
        closed_authority = writer_authority.WriterAuthority(closed_root)
        closed_authority.close()
        with self.assertRaises(writer_authority.WriterAuthorityError):
            ingress.IngressServiceV2(
                closed_root / "closed.sqlite",
                self.ingress_config,
                clock=self.clock,
                authority=closed_authority,
            )

        with self.assertRaisesRegex(writer_authority.WriterAuthorityError, "writer:lock"):
            writer_authority.WriterAuthority(self.root)

        with self.authority.run_scope():
            self.authority.set_run_time(self.clock.value)
            with self.assertRaisesRegex(writer_authority.WriterAuthorityError, "writer:run"):
                with self.authority.run_scope():
                    pass
            with self.authority.mutation_scope(self.ingress_path):
                pass

        with self.authority.mutation_scope(self.ingress_path):
            with self.assertRaisesRegex(writer_authority.WriterAuthorityError, "writer:mutation"):
                with self.authority.mutation_scope(self.ingress_path):
                    pass

        with self.authority.external_scope():
            with self.assertRaisesRegex(writer_authority.WriterAuthorityError, "writer:external-reentry"):
                with self.authority.mutation_scope(self.ingress_path):
                    pass

        errors: list[BaseException] = []
        with self.authority.run_scope():
            self.authority.set_run_time(self.clock.value)

            def contend() -> None:
                try:
                    with self.authority.run_scope():
                        pass
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=contend)
            thread.start()
            thread.join(timeout=2)
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], writer_authority.WriterAuthorityError)

    def test_ingress_public_rewind_and_core_public_rewind_preserve_state(self) -> None:
        high_clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME + 120)
        service = ingress.IngressServiceV2(
            self.root / "ingress-rewind.db",
            self.ingress_config,
            clock=high_clock,
            authority=self.authority,
        )
        created = service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        before = self._fingerprint(service)
        high_clock.value -= 10
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:clock-rewind"):
            service.claim_slot(slot_id, lease_token=_ingress_token("rewind"))
        self.assertEqual(before, self._fingerprint(service))

        before_core = self._core_fingerprint(self.core)
        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 1
        connection = self.core._open()
        try:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(core.CoreConflictError, "core:clock-rewind"):
                self.core._owner_now(connection)
        finally:
            connection.rollback()
            connection.close()
        self.assertEqual(before_core, self._core_fingerprint(self.core))

    def test_independent_replay_rejects_same_stream_and_cross_stream_rewind(self) -> None:
        same_path = self.root / "same-stream-rewind.db"
        shutil.copy2(self.ingress_path, same_path)
        _rechain_ingress_observed_at(same_path, {5: profile.FIXTURE_OBSERVATION_TIME - 1})
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(same_path)

        cross_path = self.root / "cross-stream-rewind.db"
        shutil.copy2(self.ingress_path, cross_path)
        cross_clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME + 60)
        cross_service = ingress.IngressServiceV2(
            cross_path,
            self.ingress_config,
            clock=cross_clock,
            authority=self.authority,
        )
        cross_service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME + 60)
        _rechain_ingress_observed_at(cross_path, {6: profile.FIXTURE_OBSERVATION_TIME - 1})
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_database(cross_path)

        core_events = self._event_values(self.core_path, "core_events")
        self.assertEqual(self.core_clock.value, int(core_events[-1]["observed_at"]))
        with mock.patch.object(core_independent, "verify_database", wraps=core_independent.verify_database) as verify:
            self.core.verify()
        self.assertEqual(1, verify.call_count)

    def test_core_correction_binds_source_identity_to_authoritative_ingress_id(self) -> None:
        source_id = str(self.source_result["source_artifact_id"])
        connection = sqlite3.connect(self.core_path)
        try:
            raw = connection.execute(
                "SELECT raw FROM core_artifacts WHERE artifact_id=?", (source_id,)
            ).fetchone()[0]
        finally:
            connection.close()
        source = core_independent._parse(raw, "core:source")
        ingress_snapshot = ingress_independent.read_artifact_snapshots(
            self.ingress_path, (self.ingress_receipt.artifact_id or "",)
        )[self.ingress_receipt.artifact_id or ""]
        self.assertEqual(source["observation_identity"], ingress_snapshot["observation_id"])
        self.assertNotEqual(source["observation_identity"], ingress_snapshot.get("observation_identity"))
        self.assertTrue(
            core_independent.verify_database(
                self.core_path,
                expected_config_digest=self.core_config.digest,
                ingress_path=self.ingress_path,
            )["ingress_bound"]
        )

    def test_recovery_pending_is_current_only_idempotent_and_retryable(self) -> None:
        custody = _FailSealCustody()
        storage = _Storage()
        path = self.root / "pending-recovery.db"
        service = recovery.RecoveryServiceV2(
            path,
            self.recovery_config,
            custody,
            storage,
            authority=self.authority,
        )
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        pending = service.verify()
        self.assertEqual(1, pending["object_pending_generation"])
        self.assertNotIn("pending_points", pending)
        with self.assertRaisesRegex(recovery.RecoveryConflictError, "recovery:pending"):
            service.create_point(self.ingress_path, self.core_path, generation=2)
        self.assertEqual(1, service.verify()["object_pending_generation"])

        custody.fail_seal = False
        completed = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", completed.state)
        retry = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual(completed.raw, retry.raw)
        self.assertIsNone(service.verify()["object_pending_generation"])
        self.assertEqual(1, service.verify()["point_count"])

    def test_recovery_custody_and_storage_callbacks_cannot_reenter_mutation(self) -> None:
        custody = _ReentrantCustody()
        storage = _ReentrantStorage()
        path = self.root / "reentrant-recovery.db"
        service = recovery.RecoveryServiceV2(
            path,
            self.recovery_config,
            custody,
            storage,
            authority=self.authority,
        )
        custody.callback = lambda: service.create_point(self.ingress_path, self.core_path, generation=1)
        storage.callback = lambda: service.create_point(self.ingress_path, self.core_path, generation=1)
        receipt = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", receipt.state)
        self.assertEqual(1, len(custody.errors))
        self.assertEqual(1, len(storage.errors))
        self.assertTrue(all(isinstance(error, writer_authority.WriterAuthorityError) for error in custody.errors + storage.errors))
        self.assertEqual(1, service.verify()["point_count"])


    def test_key_revocation_blocks_restore_and_storage_corruption(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        object_id = json.loads(point.raw.decode("ascii"))["payload_digest"]
        self.custody.revoked.add(("synthetic-key", 1))
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.restore_point(point.point_id, self.root / "bad-i.db", self.root / "bad-c.db")
        self.assertNotEqual(object_id, "")

    def test_recovery_event_material_and_selected_snapshot_bind_current_receipt(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        selected = recovery_independent.select_point(
            self.recovery_path,
            point_id=point.point_id,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
            allowed_states=("VERIFIED",),
        )
        self.assertEqual(point.raw, selected["receipt"])
        self.assertEqual(point.point_id, selected["point"]["point_id"])
        connection = sqlite3.connect(self.recovery_path)
        try:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertEqual(names, {"recovery_meta", "recovery_points", "recovery_events"})
            columns = {
                table: tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)))
                for table in names
            }
            self.assertEqual(columns["recovery_meta"], recovery_independent._META_COLUMNS)
            self.assertEqual(columns["recovery_points"], recovery_independent._POINT_COLUMNS)
            self.assertEqual(columns["recovery_events"], recovery_independent._EVENT_COLUMNS)
            indexes = tuple(sorted(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")))
            self.assertEqual(indexes, ("recovery_events_chain_idx", "recovery_events_operation_idx", "recovery_points_state_idx"))
            events = [json.loads(bytes(row[0]).decode("ascii")) for row in connection.execute("SELECT event_raw FROM recovery_events ORDER BY sequence")]
        finally:
            connection.close()
        self.assertEqual({value["event_kind"] for value in events}, {"PREPARE", "OBJECT_PENDING", "VERIFIED"})
        self.assertTrue(all("material" in value and value["material_digest"] == recovery_independent._digest("material", value["material"]) for value in events))

    def test_recovery_point_row_authority_fields_are_reconstructed(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        row = recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]
        changes: dict[str, object] = {
            "point_id": "f" * 128,
            "generation": 2,
            "state": "PREPARED",
            "object_id": "e" * 128,
            "bundle_digest": "d" * 128,
            "bundle_length": int(row["bundle_length"]) + 1,
            "ingress_database_id": "other-ingress",
            "ingress_config_digest": "c" * 128,
            "ingress_head_root": "b" * 128,
            "ingress_watermark": int(row["ingress_watermark"]) + 1,
            "core_database_id": "other-core",
            "core_config_digest": "a" * 128,
            "core_head_root": "9" * 128,
            "core_watermark": int(row["core_watermark"]) + 1,
            "key_id": "other-key",
            "key_epoch": int(row["key_epoch"]) + 1,
            "key_state": "REVOKED",
            "storage_id": "other-storage",
            "prior_point_id": "8" * 128,
            "prior_root": "7" * 128,
            "operation_id": "6" * 128,
            "request_digest": "5" * 128,
            "sequence": int(row["sequence"]) + 1,
            "updated_sequence": int(row["updated_sequence"]) + 1,
        }
        for field, value in changes.items():
            bad = self.root / ("recovery-row-" + field + ".db")
            shutil.copy2(self.recovery_path, bad)
            connection = sqlite3.connect(bad)
            try:
                connection.execute("UPDATE recovery_points SET " + field + "=?", (value,))
                connection.commit()
            finally:
                connection.close()
            with self.subTest(field=field):
                with self.assertRaises(recovery_independent.RecoveryVerificationError):
                    recovery_independent.verify_database(bad, expected_database_id=self.recovery_config.database_id, expected_config_digest=self.recovery_config.digest)

    def test_recovery_last_event_material_rebind_fails_after_root_rehash(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        bad = self.root / "recovery-material-rebound.db"
        shutil.copy2(self.recovery_path, bad)
        connection = sqlite3.connect(bad)
        try:
            row = connection.execute("SELECT sequence,event_raw FROM recovery_events ORDER BY sequence DESC LIMIT 1").fetchone()
            event = json.loads(bytes(row[1]).decode("ascii"))
            event["material"]["bundle_digest"] = "f" * 128
            event["material_digest"] = recovery_independent._digest("material", event["material"])
            event["event_id"] = recovery_independent._digest("event-id", {key: event[key] for key in recovery_independent._EVENT_RAW_KEYS if key not in {"event_id", "after_root"}})
            event["after_root"] = recovery_independent._event_root(event["sequence"], event["before_root"], event["event_id"], event["event_kind"], event["point_id"], event["next_state"], event["material_digest"], event["stream_kind"], event["stream_id"])
            raw = recovery_independent._canonical(event)
            connection.execute("UPDATE recovery_events SET event_id=?,after_root=?,material_digest=?,event_raw=?,receipt_digest=? WHERE sequence=?", (event["event_id"], event["after_root"], event["material_digest"], raw, recovery_independent._raw_digest("receipt", raw), row[0]))
            connection.execute("UPDATE recovery_meta SET head_root=? WHERE meta_id=1", (event["after_root"],))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(bad, expected_database_id=self.recovery_config.database_id, expected_config_digest=self.recovery_config.digest)

    def test_recovery_randomized_seal_retries_keep_one_logical_object(self) -> None:
        custody = _RandomizedCustody()
        storage = _FailOnceStorage()
        service = recovery.RecoveryServiceV2(self.root / "randomized-recovery.db", self.recovery_config, custody, storage, authority=self.authority)
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        pending = recovery_independent.select_point(service.path, generation=1)
        object_id = pending["point"]["object_id"]
        receipt = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual(receipt.state, "VERIFIED")
        self.assertEqual(len(storage.objects), 1)
        self.assertIn(object_id, storage.objects)
        self.assertGreaterEqual(custody.seal_count, 2)
        self.assertEqual(receipt.raw, service.create_point(self.ingress_path, self.core_path, generation=1).raw)

    def test_recovery_transaction_finalizer_redacts_rollback_and_close_failures(self) -> None:
        class FaultConnection:
            def __init__(self, inner: sqlite3.Connection, *, fail_rollback: bool = False, fail_close: bool = False) -> None:
                self.inner = inner
                self.fail_rollback = fail_rollback
                self.fail_close = fail_close

            def rollback(self) -> None:
                if self.fail_rollback:
                    raise RuntimeError("CANARY_ROLLBACK_PHI_PATH")
                self.inner.rollback()

            def close(self) -> None:
                if self.fail_close:
                    self.inner.close()
                    raise RuntimeError("CANARY_CLOSE_PHI_PATH")
                self.inner.close()

            def __getattr__(self, name: str) -> object:
                return getattr(self.inner, name)

        for fault in ("rollback", "close"):
            with self.subTest(fault=fault):
                service = recovery.RecoveryServiceV2(self.root / f"finalizer-{fault}.db", self.recovery_config, _Custody(), _Storage(), authority=self.authority)
                original_open = service._open

                def open_fault(*, _fault=fault):
                    return FaultConnection(original_open(), fail_rollback=_fault == "rollback", fail_close=_fault == "close")

                with mock.patch.object(service, "_open", side_effect=open_fault):
                    with mock.patch.object(service, "_append", side_effect=recovery.RecoveryError("recovery:precommit")):
                        with self.assertRaises(recovery.RecoveryIndeterminateError) as caught:
                            service.create_point(self.ingress_path, self.core_path, generation=1)
                self.assertEqual("recovery:transaction-indeterminate", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("CANARY_", repr(caught.exception))
                self.assertTrue(service.verify()["accepted"])
                self.assertEqual(0, service.verify()["point_count"])

    def test_recovery_commit_then_raise_retries_one_durable_generation(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "commit-then-raise-recovery.db", self.recovery_config, _Custody(), _Storage(), authority=self.authority)
        original_commit = service._commit
        calls = 0

        def commit_then_raise(connection: sqlite3.Connection) -> None:
            nonlocal calls
            calls += 1
            original_commit(connection)
            if calls == 2:
                raise RuntimeError("CANARY_COMMIT_PHI_PATH")

        with mock.patch.object(service, "_commit", side_effect=commit_then_raise):
            with self.assertRaises(recovery.RecoveryIndeterminateError) as caught:
                service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("recovery:transaction-indeterminate", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY_", repr(caught.exception))
        pending = recovery_independent.select_point(service.path, generation=1)
        self.assertEqual("OBJECT_PENDING", pending["point"]["state"])
        self.assertEqual(1, pending["summary"]["point_count"])
        self.assertEqual(2, pending["summary"]["event_count"])
        retry = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", retry.state)
        after = service.verify()
        self.assertEqual(1, after["point_count"])
        self.assertEqual(3, after["event_count"])
        self.assertEqual(retry.raw, service.create_point(self.ingress_path, self.core_path, generation=1).raw)
        self.assertEqual(after, service.verify())

    def test_recovery_precommit_failure_retries_without_durable_partial_effect(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "precommit-retry-recovery.db", self.recovery_config, _Custody(), _Storage(), authority=self.authority)
        original_append = service._append
        failed = True

        def fail_once(connection: sqlite3.Connection, **kwargs: object) -> bytes:
            nonlocal failed
            if failed:
                failed = False
                raise recovery.RecoveryError("recovery:precommit")
            return original_append(connection, **kwargs)

        with mock.patch.object(service, "_append", side_effect=fail_once):
            with self.assertRaises(recovery.RecoveryError) as caught:
                service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("recovery:precommit", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertTrue(service.verify()["accepted"])
        self.assertEqual(0, service.verify()["point_count"])
        receipt = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", receipt.state)
        snapshot = service.verify()
        self.assertEqual(1, snapshot["point_count"])
        self.assertEqual(3, snapshot["event_count"])
        self.assertEqual(receipt.raw, service.create_point(self.ingress_path, self.core_path, generation=1).raw)

    def test_recovery_pending_key_revocation_records_invalidated_state(self) -> None:
        custody = _Custody()
        storage = _FailOnceStorage()
        service = recovery.RecoveryServiceV2(self.root / "pending-revoked-recovery.db", self.recovery_config, custody, storage, authority=self.authority)
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        selected = recovery_independent.select_point(service.path, generation=1)
        point = selected["point"]
        ing, cor, ing_raw, core_raw = service._read_pair(self.ingress_path, self.core_path)
        bundle = service._bundle(ing, cor, ing_raw, core_raw, 1, str(point["prior_root"]))
        sealed = custody.seal(bundle, str(point["key_id"]), int(point["key_epoch"]))
        custody.revoked.add(("synthetic-key", 1))
        with self.assertRaises(recovery.RecoveryConflictError):
            service._complete_storage(point, bundle, sealed)
        selected = recovery_independent.select_point(service.path, generation=1)
        self.assertEqual("INVALIDATED", selected["point"]["state"])
        self.assertEqual(1, selected["summary"]["states"]["INVALIDATED"])

    def test_recovery_custody_and_storage_caps_fail_before_unbounded_work(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        oversized_storage = _OversizeStorage(self.recovery_config.max_bundle_bytes + recovery.MAX_CUSTODY_OVERHEAD_BYTES + 1)
        no_open = _NoOpenCustody()
        service = recovery.RecoveryServiceV2(self.root / "oversized-storage-recovery.db", self.recovery_config, no_open, oversized_storage, authority=self.authority)
        shutil.copy2(self.recovery_path, service.path)
        with self.assertRaises(recovery.RecoveryConflictError):
            service.restore_point(point.point_id, self.root / "oversized-i.db", self.root / "oversized-c.db")
        self.assertFalse(no_open.opened)
        plain_storage = _Storage()
        plain_storage.objects.update(self.storage.objects)
        oversized_plaintext = _NoOpenCustody(oversized_plaintext=True)
        plain_service = recovery.RecoveryServiceV2(self.root / "oversized-plaintext-recovery.db", self.recovery_config, oversized_plaintext, plain_storage, authority=self.authority)
        shutil.copy2(self.recovery_path, plain_service.path)
        with self.assertRaises(recovery.RecoveryConflictError):
            plain_service.restore_point(point.point_id, self.root / "oversized-plain-i.db", self.root / "oversized-plain-c.db")
        self.assertTrue(oversized_plaintext.opened)

    def test_recovery_image_event_and_generation_caps_are_executable(self) -> None:
        overcap = self.root / "over-cap-image.db"
        overcap.write_bytes(b"xx")
        with self.assertRaises(recovery.RecoveryError):
            recovery._bounded_image(overcap, 1, "recovery:test-image-cap")
        with self.assertRaises(recovery.RecoveryError):
            self.recovery_service.create_point(self.ingress_path, self.core_path, generation=recovery.MAX_RECOVERY_POINTS + 1)
        before = self.recovery_service.verify()["event_count"]
        connection = recovery._connection(self.recovery_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(recovery.RecoveryError):
                self.recovery_service._append(connection, kind="PUBLISHED", point_id="0" * 128, operation_id="1" * 128, request_digest="2" * 128, prior_state="VERIFIED", next_state="PUBLISHED", material={"oversized": "x" * recovery.MAX_EVENT_BYTES}, payload_digest="3" * 128, payload_length=0)
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(before, self.recovery_service.verify()["event_count"])

    def test_recovery_bundle_parser_and_catalog_capacity_fail_closed(self) -> None:
        ing, cor, ing_raw, core_raw = self.recovery_service._read_pair(self.ingress_path, self.core_path)
        bundle = self.recovery_service._bundle(ing, cor, ing_raw, core_raw, 1, recovery_independent.GENESIS_ROOT)
        value = json.loads(bundle.decode("ascii"))
        mutations: list[bytes] = [
            b'{"schema":"mirror-recovery-bundle-v2","schema":"duplicate"}',
            bundle + b" ",
        ]
        unknown = dict(value)
        unknown["unknown"] = True
        mutations.append(recovery._canonical(unknown))
        declared = dict(value)
        declared["ingress"] = dict(value["ingress"])
        declared["ingress"]["image_length"] += 1
        mutations.append(recovery._canonical(declared))
        malformed = dict(value)
        malformed["ingress_image"] = value["ingress_image"][:-1]
        mutations.append(recovery._canonical(malformed))
        for raw in mutations:
            with self.subTest(mutation=len(raw)):
                with self.assertRaises(recovery_independent.RecoveryVerificationError):
                    recovery_independent.parse_bundle(
                        raw,
                        max_bundle_bytes=self.recovery_config.max_bundle_bytes,
                        expected_generation=1,
                        expected_prior_root=recovery_independent.GENESIS_ROOT,
                    )
        oversized = self.root / "oversized-recovery-catalog.db"
        with oversized.open("wb") as handle:
            handle.truncate(recovery.MAX_DATABASE_BYTES + 1)
        before = oversized.stat().st_size
        with self.assertRaises(recovery.RecoveryError):
            recovery.RecoveryServiceV2(oversized, self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertEqual(before, oversized.stat().st_size)

    def test_recovery_initialization_finalization_faults_are_fixed_and_retryable(self) -> None:
        original_connection = recovery._connection

        def table_names(path: Path) -> tuple[str, ...]:
            connection = sqlite3.connect(path)
            try:
                return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"))
            finally:
                connection.close()

        for name, kwargs in (
            ("rollback", {"trigger": "CREATE TABLE recovery_points", "precommit_error": sqlite3.OperationalError("CANARY_INIT_PRECOMMIT"), "fail_rollback": True}),
            ("close", {"trigger": "CREATE TABLE recovery_points", "precommit_error": sqlite3.OperationalError("CANARY_INIT_PRECOMMIT"), "fail_close": True}),
        ):
            with self.subTest(fault=name):
                path = self.root / f"init-{name}-fault.db"
                faults: list[_InitializationFaultConnection] = []

                def open_fault(target: Path, *, _kwargs=kwargs):
                    fault = _InitializationFaultConnection(original_connection(target), **_kwargs)
                    faults.append(fault)
                    return fault

                with mock.patch.object(recovery, "_connection", side_effect=open_fault):
                    with self.assertRaises(recovery.RecoveryIndeterminateError) as caught:
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
                self.assertEqual("recovery:transaction-indeterminate", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("CANARY_INIT_", repr(caught.exception))
                self.assertEqual(1, faults[0].rollback_calls)
                self.assertEqual(1, faults[0].close_calls)
                self.assertEqual((), table_names(path))

        path = self.root / "init-commit-then-raise.db"
        faults = []
        with mock.patch.object(
            recovery,
            "_connection",
            side_effect=lambda target: faults.append(_InitializationFaultConnection(original_connection(target), fail_commit=True)) or faults[-1],
        ):
            with self.assertRaises(recovery.RecoveryIndeterminateError) as caught:
                recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertEqual("recovery:transaction-indeterminate", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY_INIT_", repr(caught.exception))
        self.assertEqual(1, faults[0].commit_calls)
        self.assertEqual(1, faults[0].close_calls)
        self.assertEqual(0, faults[0].rollback_calls)
        self.assertEqual(tuple(sorted(recovery.TABLES)), table_names(path))
        connection = sqlite3.connect(path)
        try:
            self.assertEqual((1,), tuple(connection.execute("SELECT COUNT(*) FROM recovery_meta").fetchone()))
            self.assertEqual((0, 0), tuple(connection.execute("SELECT sequence,current_generation FROM recovery_meta").fetchone()))
        finally:
            connection.close()
        reopened = recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertTrue(reopened.verify()["accepted"])
        self.assertEqual(0, reopened.verify()["point_count"])

        path = self.root / "init-close-after-commit.db"
        faults = []
        with mock.patch.object(
            recovery,
            "_connection",
            side_effect=lambda target: faults.append(_InitializationFaultConnection(original_connection(target), fail_close=True)) or faults[-1],
        ):
            with self.assertRaises(recovery.RecoveryIndeterminateError) as caught:
                recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertEqual("recovery:transaction-indeterminate", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY_INIT_", repr(caught.exception))
        self.assertEqual(1, faults[0].commit_calls)
        self.assertEqual(1, faults[0].close_calls)
        self.assertEqual(0, faults[0].rollback_calls)
        self.assertEqual(tuple(sorted(recovery.TABLES)), table_names(path))

        for name, injected in (("sqlite", sqlite3.OperationalError("CANARY_INIT_SQLITE")), ("unexpected", RuntimeError("CANARY_INIT_UNEXPECTED"))):
            with self.subTest(fault=name):
                path = self.root / f"init-{name}-precommit.db"
                faults = []
                kwargs = {"trigger": "CREATE TABLE recovery_points", "precommit_error": injected}

                def open_precommit(target: Path, *, _kwargs=kwargs):
                    fault = _InitializationFaultConnection(original_connection(target), **_kwargs)
                    faults.append(fault)
                    return fault

                with mock.patch.object(recovery, "_connection", side_effect=open_precommit):
                    with self.assertRaises(recovery.RecoveryError) as caught:
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
                self.assertEqual("recovery:database-initialize", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("CANARY_INIT_", repr(caught.exception))
                self.assertEqual(1, faults[0].rollback_calls)
                self.assertEqual(1, faults[0].close_calls)
                self.assertEqual((), table_names(path))
                retry = recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
                self.assertTrue(retry.verify()["accepted"])
                self.assertEqual(tuple(sorted(recovery.TABLES)), table_names(path))

        legacy = self.root / "init-deterministic-legacy.db"
        connection = sqlite3.connect(legacy)
        try:
            connection.execute("CREATE TABLE old_schema(value TEXT)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(recovery.RecoveryError) as caught:
            recovery.RecoveryServiceV2(legacy, self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertEqual("recovery:legacy-schema", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_recovery_catalog_reopens_and_ddl_failures_leave_no_partial_schema(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "reopen-recovery.db", self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertTrue(service.verify()["accepted"])
        reopened = recovery.RecoveryServiceV2(self.root / "reopen-recovery.db", self.recovery_config, self.custody, self.storage, authority=self.authority)
        self.assertEqual(service.verify(), reopened.verify())

        from unittest import mock

        original_connection = recovery._connection
        failure_points = (
            "CREATE TABLE recovery_meta",
            "CREATE TABLE recovery_points",
            "CREATE TABLE recovery_events",
            "CREATE INDEX recovery_points_state_idx",
            "CREATE UNIQUE INDEX recovery_events_chain_idx",
            "CREATE INDEX recovery_events_operation_idx",
            "INSERT INTO recovery_meta",
        )
        for index, needle in enumerate(failure_points):
            path = self.root / (f"ddl-failure-{index}.db")

            class FailingConnection:
                def __init__(self, inner: sqlite3.Connection) -> None:
                    self.inner = inner

                def execute(self, sql: str, *parameters: object):
                    if needle in sql:
                        raise sqlite3.OperationalError("synthetic DDL boundary failure")
                    return self.inner.execute(sql, *parameters)

                def __getattr__(self, name: str) -> object:
                    return getattr(self.inner, name)

            with self.subTest(failure=needle):
                with mock.patch.object(recovery, "_connection", side_effect=lambda target: FailingConnection(original_connection(target))):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage, authority=self.authority)
                connection = sqlite3.connect(path)
                try:
                    tables = tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"))
                finally:
                    connection.close()
                self.assertEqual((), tables)

    def test_recovery_generation_chain_is_contiguous_and_retry_is_source_free(self) -> None:
        empty_path = self.root / "generation-recovery.db"
        service = recovery.RecoveryServiceV2(empty_path, self.recovery_config, self.custody, self.storage, authority=self.authority)
        before = service.verify()
        with self.assertRaises(recovery.RecoveryConflictError):
            service.create_point(self.ingress_path, self.core_path, generation=2)
        self.assertEqual(before, service.verify())

        first = service.create_point(self.ingress_path, self.core_path, generation=1)
        with self.assertRaises(recovery.RecoveryConflictError):
            service.create_point(self.ingress_path, self.core_path, generation=3)
        second = service.create_point(self.ingress_path, self.core_path, generation=2)
        selected = recovery_independent.select_point(service.path, point_id=second.point_id)
        self.assertEqual(first.point_id, selected["point"]["prior_point_id"])
        self.assertEqual(first.after_root, selected["point"]["prior_root"])
        self.ingress_path.unlink()
        self.core_path.unlink()
        self.assertEqual(first.raw, service.create_point(self.ingress_path, self.core_path, generation=1).raw)

    def test_recovery_interleaved_pending_predecessor_retry_preserves_historical_chain(self) -> None:
        class PutThenLoseResponse(_Storage):
            def __init__(self) -> None:
                super().__init__()
                self.lost = True

            def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> recovery.StorageReceipt:
                receipt = super().put_if_absent(object_id, sealed, key_id=key_id, key_epoch=key_epoch)
                if self.lost:
                    self.lost = False
                    raise RuntimeError("response lost after storage commit")
                return receipt

        storage = PutThenLoseResponse()
        service = recovery.RecoveryServiceV2(self.root / "interleaved-pending-recovery.db", self.recovery_config, self.custody, storage, authority=self.authority)
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("OBJECT_PENDING", recovery_independent.select_point(service.path, generation=1)["point"]["state"])

        with self.assertRaisesRegex(recovery.RecoveryConflictError, "^recovery:pending$"):
            service.create_point(self.ingress_path, self.core_path, generation=2)
        self.ingress_path.unlink()
        self.core_path.unlink()
        first = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", first.state)
        snapshot = recovery_independent.verify_database(
            service.path,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
        )
        self.assertEqual(1, snapshot["point_count"])
        self.assertEqual(1, snapshot["states"]["VERIFIED"])

    def test_recovery_interleaved_predecessor_publish_preserves_historical_chain(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "interleaved-publish-recovery.db", self.recovery_config, self.custody, self.storage, authority=self.authority)
        first = service.create_point(self.ingress_path, self.core_path, generation=1)
        second = service.create_point(self.ingress_path, self.core_path, generation=2)
        self.assertEqual("VERIFIED", first.state)
        self.assertEqual("VERIFIED", second.state)

        published = service.restore_point(
            first.point_id,
            self.root / "interleaved-publish-ingress.db",
            self.root / "interleaved-publish-core.db",
        )
        self.assertEqual("PUBLISHED", published.state)
        snapshot = recovery_independent.verify_database(
            service.path,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
        )
        self.assertEqual(2, snapshot["point_count"])
        self.assertEqual(1, snapshot["states"]["PUBLISHED"])
        self.assertEqual(1, snapshot["states"]["VERIFIED"])

    def test_recovery_exact_images_are_verified_once_and_wrong_image_fails_before_catalog_mutation(self) -> None:
        before = self.recovery_service.verify()
        with self.assertRaises(ingress_independent.IngressVerificationError):
            self.recovery_service._read_pair(self.core_path, self.core_path)
        self.assertEqual(before, self.recovery_service.verify())
        ing, cor, ing_raw, core_raw = self.recovery_service._read_pair(self.ingress_path, self.core_path)
        self.assertEqual(ing["head_root"], ingress_independent.verify_bytes(ing_raw, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)["head_root"])
        self.assertEqual(cor["head_root"], core_independent.verify_bytes(core_raw, expected_database_id=self.core_config.database_id, expected_config_digest=self.core_config.digest, ingress_bytes=ing_raw)["head_root"])
        with self.assertRaises(ingress_independent.IngressVerificationError):
            ingress_independent.verify_bytes(core_raw)
        with self.assertRaises(core_independent.CoreVerificationError):
            core_independent.verify_bytes(ing_raw)

    def test_recovery_verified_retry_and_bootstrap_fail_closed_after_key_revocation(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        self.custody.revoked.add(("synthetic-key", 1))
        self.ingress_path.unlink()
        self.core_path.unlink()
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.bootstrap(point.point_id)
        self.assertEqual("VERIFIED", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])

    def test_recovery_object_pending_retry_uses_stored_object_without_source_reread(self) -> None:
        class PutThenLoseResponse(_Storage):
            def __init__(self) -> None:
                super().__init__()
                self.lost = True

            def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> recovery.StorageReceipt:
                receipt = super().put_if_absent(object_id, sealed, key_id=key_id, key_epoch=key_epoch)
                if self.lost:
                    self.lost = False
                    raise RuntimeError("response lost after storage commit")
                return receipt

        storage = PutThenLoseResponse()
        service = recovery.RecoveryServiceV2(self.root / "pending-stored-recovery.db", self.recovery_config, self.custody, storage, authority=self.authority)
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("OBJECT_PENDING", recovery_independent.select_point(service.path, generation=1)["point"]["state"])
        self.ingress_path.unlink()
        self.core_path.unlink()
        recovered = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", recovered.state)

    def test_recovery_event_raw_type_and_prepare_component_caps_fail_before_allocation(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        bad = self.root / "integer-event-raw.db"
        shutil.copy2(self.recovery_path, bad)
        connection = sqlite3.connect(bad)
        try:
            connection.execute("UPDATE recovery_events SET event_raw=123 WHERE sequence=1")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(bad, expected_database_id=self.recovery_config.database_id, expected_config_digest=self.recovery_config.digest)
        ingress_component = {"database_id": "i", "chain_id": "c", "config_digest": "0" * 128, "head_root": "0" * 128, "watermark": 0, "image_digest": "0" * 128, "image_length": ingress_independent.MAX_DATABASE_BYTES + 1}
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent._component(ingress_component, "recovery:prepare-ingress")
        self.assertEqual("VERIFIED", point.state)

    def test_recovery_bounded_image_rejects_hardlinks_symlinks_and_all_sidecars(self) -> None:
        hardlink = self.root / "recovery-hardlink.db"
        os.link(self.recovery_path, hardlink)
        with self.assertRaises(recovery.RecoveryError):
            recovery._bounded_image(hardlink, recovery.MAX_DATABASE_BYTES, "recovery:hardlink")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(os.fspath(self.recovery_path) + suffix)
            sidecar.write_bytes(b"synthetic sidecar")
            try:
                with self.assertRaises(recovery.RecoveryError):
                    recovery._bounded_image(self.recovery_path, recovery.MAX_DATABASE_BYTES, "recovery:sidecar")
            finally:
                sidecar.unlink()
        symlink = self.root / "recovery-symlink.db"
        try:
            os.symlink(self.recovery_path, symlink)
        except (OSError, NotImplementedError) as error:
            self.skipTest("symlink capability unavailable: " + type(error).__name__)
        try:
            with self.assertRaises(recovery.RecoveryError):
                recovery._bounded_image(symlink, recovery.MAX_DATABASE_BYTES, "recovery:symlink")
            dangling = Path(os.fspath(self.recovery_path) + "-wal")
            os.symlink(self.root / "missing-wal", dangling)
            try:
                with self.assertRaises(recovery.RecoveryError):
                    recovery._bounded_image(self.recovery_path, recovery.MAX_DATABASE_BYTES, "recovery:dangling-sidecar")
            finally:
                if os.path.lexists(dangling):
                    dangling.unlink()
        finally:
            if os.path.lexists(symlink):
                symlink.unlink()

    def test_restore_publication_pair_create_only_and_exact_retry_adopt(self) -> None:
        ingress_image = b"synthetic-ingress-image"
        core_image = b"synthetic-core-image"
        ingress_target = self.root / "pair-ingress.db"
        core_target = self.root / "pair-core.db"
        ingress_expected = {"database_id": "ingress", "head_root": "a" * 128}
        core_expected = {"database_id": "core", "head_root": "b" * 128}

        def verify_ingress(raw: bytes) -> dict[str, object]:
            self.assertEqual(ingress_image, raw)
            return {**ingress_expected, "accepted": True}

        def verify_core(raw: bytes, exact_ingress: bytes) -> dict[str, object]:
            self.assertEqual(core_image, raw)
            self.assertEqual(ingress_image, exact_ingress)
            return {**core_expected, "accepted": True}

        operation = _hex("pair-publication-retry")
        first = restore_publication.publish_pair_create_only(
            ingress_target=ingress_target,
            core_target=core_target,
            ingress_image=ingress_image,
            core_image=core_image,
            pair_operation_id=operation,
            ingress_expected=ingress_expected,
            core_expected=core_expected,
            verify_ingress=verify_ingress,
            verify_core=verify_core,
        )
        first_inodes = (os.stat(ingress_target).st_ino, os.stat(core_target).st_ino)
        self.assertEqual("CREATED_THIS_CALL", first.ingress.kind)
        self.assertEqual("CREATED_THIS_CALL", first.core.kind)
        self.assertTrue(first.ingress.created_by_this_call and first.core.created_by_this_call)
        second = restore_publication.publish_pair_create_only(
            ingress_target=ingress_target,
            core_target=core_target,
            ingress_image=ingress_image,
            core_image=core_image,
            pair_operation_id=operation,
            ingress_expected=ingress_expected,
            core_expected=core_expected,
            verify_ingress=verify_ingress,
            verify_core=verify_core,
        )
        self.assertEqual("ADOPTED_EXISTING", second.ingress.kind)
        self.assertEqual("ADOPTED_EXISTING", second.core.kind)
        self.assertFalse(second.ingress.created_by_this_call or second.core.created_by_this_call)
        self.assertEqual(first_inodes, (os.stat(ingress_target).st_ino, os.stat(core_target).st_ino))
        self.assertEqual(ingress_image, ingress_target.read_bytes())
        self.assertEqual(core_image, core_target.read_bytes())
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))

    def test_restore_publication_pair_preflights_both_and_never_rolls_back_first_target(self) -> None:
        ingress_image = b"ingress-preflight"
        core_image = b"core-preflight"
        ingress_target = self.root / "preflight-ingress.db"
        core_target = self.root / "preflight-core.db"
        core_target.write_bytes(b"different-existing-core")
        ingress_expected = {"database_id": "ingress", "head_root": "c" * 128}
        core_expected = {"database_id": "core", "head_root": "d" * 128}

        with self.assertRaises(restore_publication.RestorePublicationConflict):
            restore_publication.publish_pair_create_only(
                ingress_target=ingress_target,
                core_target=core_target,
                ingress_image=ingress_image,
                core_image=core_image,
                pair_operation_id=_hex("pair-preflight-conflict"),
                ingress_expected=ingress_expected,
                core_expected=core_expected,
                verify_ingress=lambda raw: dict(ingress_expected),
                verify_core=lambda raw, exact_ingress: dict(core_expected),
            )
        self.assertFalse(ingress_target.exists())
        self.assertEqual(b"different-existing-core", core_target.read_bytes())

    def test_restore_publication_pair_after_first_link_keeps_target_and_retries(self) -> None:
        ingress_image = b"ingress-link-fault"
        core_image = b"core-link-fault"
        ingress_target = self.root / "fault-ingress.db"
        core_target = self.root / "fault-core.db"
        ingress_expected = {"database_id": "ingress", "head_root": "e" * 128}
        core_expected = {"database_id": "core", "head_root": "f" * 128}

        def fault(point: str) -> None:
            if point == "after_core_link":
                raise RuntimeError("host path and credential canary")

        operation = _hex("pair-link-fault")
        with self.assertRaises(restore_publication.RestorePublicationError) as caught:
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                restore_publication.publish_pair_create_only(
                    ingress_target=ingress_target,
                    core_target=core_target,
                    ingress_image=ingress_image,
                    core_image=core_image,
                    pair_operation_id=operation,
                    ingress_expected=ingress_expected,
                    core_expected=core_expected,
                    verify_ingress=lambda raw: dict(ingress_expected),
                    verify_core=lambda raw, exact_ingress: dict(core_expected),
                )
        self.assertEqual("restore-publication:fault", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertFalse(ingress_target.exists())
        self.assertTrue(core_target.exists())
        receipt = restore_publication._namespace(core_target, operation) / "publication.json"
        receipt.write_bytes(receipt.read_bytes()[:17])
        retry = restore_publication.publish_pair_create_only(
            ingress_target=ingress_target,
            core_target=core_target,
            ingress_image=ingress_image,
            core_image=core_image,
            pair_operation_id=operation,
            ingress_expected=ingress_expected,
            core_expected=core_expected,
            verify_ingress=lambda raw: dict(ingress_expected),
            verify_core=lambda raw, exact_ingress: dict(core_expected),
        )
        self.assertEqual("CREATED_THIS_CALL", retry.ingress.kind)
        self.assertEqual("ADOPTED_EXISTING", retry.core.kind)
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))

    def test_restore_publication_rejects_all_target_sidecars_and_verifier_canary(self) -> None:
        ingress_image = b"ingress-sidecar"
        core_image = b"core-sidecar"
        ingress_target = self.root / "sidecar-ingress.db"
        core_target = self.root / "sidecar-core.db"
        expected_i = {"database_id": "ingress", "head_root": "1" * 128}
        expected_c = {"database_id": "core", "head_root": "2" * 128}
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(os.fspath(ingress_target) + suffix)
            sidecar.write_bytes(b"caller-owned sidecar")
            try:
                with self.assertRaises(restore_publication.RestorePublicationConflict):
                    restore_publication.publish_pair_create_only(
                        ingress_target=ingress_target,
                        core_target=core_target,
                        ingress_image=ingress_image,
                        core_image=core_image,
                        pair_operation_id=_hex("pair-sidecar-" + suffix),
                        ingress_expected=expected_i,
                        core_expected=expected_c,
                        verify_ingress=lambda raw: dict(expected_i),
                        verify_core=lambda raw, exact_ingress: dict(expected_c),
                    )
                self.assertFalse(ingress_target.exists())
                self.assertFalse(core_target.exists())
            finally:
                sidecar.unlink()

        def bad_verifier(raw: bytes) -> object:
            raise OSError("Bearer SECRET C:\\Users\\private\\raw")

        with self.assertRaises(restore_publication.RestorePublicationVerification) as caught:
            restore_publication.publish_pair_create_only(
                ingress_target=ingress_target,
                core_target=core_target,
                ingress_image=ingress_image,
                core_image=core_image,
                pair_operation_id=_hex("pair-verifier-canary"),
                ingress_expected=expected_i,
                core_expected=expected_c,
                verify_ingress=bad_verifier,
                verify_core=lambda raw, exact_ingress: dict(expected_c),
            )
        self.assertEqual("restore-publication:independent-verify", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("Bearer", repr(caught.exception))
        formatted = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn("Bearer", formatted)
        self.assertNotIn("C:\\Users\\private", formatted)

    def test_restore_publication_read_only_pair_rejects_unsafe_targets_and_callback_drift(self) -> None:
        ingress_image = b"read-only-ingress"
        core_image = b"read-only-core"
        expected_i = {"database_id": "ingress", "head_root": "7" * 128}
        expected_c = {"database_id": "core", "head_root": "8" * 128}

        def verify_pair(
            ingress_target: Path,
            core_target: Path,
            *,
            operation: str,
            ingress_bytes: bytes = ingress_image,
            core_bytes: bytes = core_image,
            verify_i: object | None = None,
            verify_c: object | None = None,
        ) -> None:
            def default_i(raw: bytes) -> dict[str, object]:
                self.assertEqual(ingress_bytes, raw)
                return dict(expected_i)

            def default_c(raw: bytes, exact_ingress: bytes) -> dict[str, object]:
                self.assertEqual(core_bytes, raw)
                self.assertEqual(ingress_bytes, exact_ingress)
                return dict(expected_c)

            with restore_publication._target_lock(ingress_target):
                pass
            with restore_publication._target_lock(core_target):
                pass
            restore_publication.verify_pair_read_only(
                ingress_target=ingress_target,
                core_target=core_target,
                ingress_image=ingress_bytes,
                core_image=core_bytes,
                pair_operation_id=operation,
                ingress_file_digest=restore_publication._file_digest(ingress_bytes),
                ingress_file_length=len(ingress_bytes),
                core_file_digest=restore_publication._file_digest(core_bytes),
                core_file_length=len(core_bytes),
                ingress_expected=expected_i,
                core_expected=expected_c,
                verify_ingress=verify_i or default_i,
                verify_core=verify_c or default_c,
            )

        sidecar_i = self.root / "read-only-sidecar-ingress.db"
        sidecar_c = self.root / "read-only-sidecar-core.db"
        sidecar_i.write_bytes(ingress_image)
        sidecar_c.write_bytes(core_image)
        sidecar = Path(os.fspath(sidecar_i) + "-wal")
        sidecar.write_bytes(b"caller-owned-sidecar")
        try:
            with self.assertRaises(restore_publication.RestorePublicationConflict) as caught:
                verify_pair(sidecar_i, sidecar_c, operation=_hex("read-only-sidecar"))
            self.assertEqual("restore-publication:target-sidecar", str(caught.exception))
            self.assertEqual(ingress_image, sidecar_i.read_bytes())
            self.assertEqual(core_image, sidecar_c.read_bytes())
        finally:
            sidecar.unlink()

        alias_i = self.root / "read-only-alias-ingress.db"
        alias_c = self.root / "read-only-alias-core.db"
        alias_image = b"read-only-hardlink-alias"
        alias_i.write_bytes(alias_image)
        os.link(alias_i, alias_c)
        alias_inode = os.stat(alias_i).st_ino
        try:
            with self.assertRaises(restore_publication.RestorePublicationError):
                verify_pair(
                    alias_i,
                    alias_c,
                    operation=_hex("read-only-hardlink-alias"),
                    ingress_bytes=alias_image,
                    core_bytes=alias_image,
                )
            self.assertEqual(alias_inode, os.stat(alias_c).st_ino)
        finally:
            alias_c.unlink()
            alias_i.unlink()

        mutation_i = self.root / "read-only-mutation-ingress.db"
        mutation_c = self.root / "read-only-mutation-core.db"
        mutation_i.write_bytes(ingress_image)
        mutation_c.write_bytes(core_image)

        def mutate_ingress(raw: bytes) -> dict[str, object]:
            self.assertEqual(ingress_image, raw)
            mutation_i.write_bytes(b"mutated-in-callback")
            return dict(expected_i)

        with self.assertRaises(restore_publication.RestorePublicationConflict) as caught:
            verify_pair(
                mutation_i,
                mutation_c,
                operation=_hex("read-only-mutation"),
                verify_i=mutate_ingress,
            )
        self.assertEqual("restore-publication:target-changed", str(caught.exception))
        self.assertEqual(b"mutated-in-callback", mutation_i.read_bytes())
        self.assertEqual(core_image, mutation_c.read_bytes())

        replacement_i = self.root / "read-only-replacement-ingress.db"
        replacement_c = self.root / "read-only-replacement-core.db"
        replacement_backup = self.root / "read-only-replacement-backup.db"
        replacement_i.write_bytes(ingress_image)
        replacement_c.write_bytes(core_image)

        def replace_ingress(raw: bytes) -> dict[str, object]:
            self.assertEqual(ingress_image, raw)
            os.replace(replacement_i, replacement_backup)
            replacement_i.write_bytes(raw)
            return dict(expected_i)

        with self.assertRaises(restore_publication.RestorePublicationConflict) as caught:
            verify_pair(
                replacement_i,
                replacement_c,
                operation=_hex("read-only-replacement"),
                verify_i=replace_ingress,
            )
        self.assertEqual("restore-publication:target-changed", str(caught.exception))
        self.assertTrue(replacement_backup.exists())
        self.assertEqual(ingress_image, replacement_i.read_bytes())
        self.assertEqual(core_image, replacement_c.read_bytes())

        bad_i = self.root / "read-only-redacted-ingress.db"
        bad_c = self.root / "read-only-redacted-core.db"
        bad_i.write_bytes(ingress_image)
        bad_c.write_bytes(core_image)

        def bad_verifier(raw: bytes) -> object:
            raise OSError("RAW_CAPTURE SECRET C:\\Users\\private\\mirror.db")

        with self.assertRaises(restore_publication.RestorePublicationVerification) as caught:
            verify_pair(
                bad_i,
                bad_c,
                operation=_hex("read-only-redacted"),
                verify_i=bad_verifier,
            )
        self.assertEqual("restore-publication:independent-verify", str(caught.exception))
        self.assertNotIn("RAW_CAPTURE", repr(caught.exception))
        self.assertNotIn("C:\\Users\\private", "".join(traceback.format_exception(caught.exception)))

    def test_restore_publication_marker_only_requires_and_can_reconcile_receipt(self) -> None:
        image = b"marker-only-image"
        target = self.root / "marker-only-target.db"
        core_target = self.root / "marker-only-core.db"
        expected_i = {"database_id": "ingress", "head_root": "9" * 128}
        expected_c = {"database_id": "core", "head_root": "a" * 128}
        operation = _hex("pair-marker-only")
        target.write_bytes(image)
        semantic = restore_publication._semantic_digest({**expected_i, "accepted": True})
        binding = restore_publication._binding_digest(expected_i)
        namespace = restore_publication._prepare_namespace(target, operation, role="ingress", image=image, semantic=semantic, binding=binding)
        verifier_i = lambda raw: {**expected_i, "accepted": True}
        verifier_c = lambda raw, exact_ingress: {**expected_c, "accepted": True}
        with self.assertRaises(restore_publication.RestorePublicationConflict):
            restore_publication.publish_pair_create_only(
                ingress_target=target,
                core_target=core_target,
                ingress_image=image,
                core_image=b"marker-only-core",
                pair_operation_id=operation,
                ingress_expected=expected_i,
                core_expected=expected_c,
                verify_ingress=verifier_i,
                verify_core=verifier_c,
            )
        identity = restore_publication._regular(target, allow_empty=False, nlinks=(1,))
        body = restore_publication._receipt_body(target, role="ingress", pair_operation_id=operation, semantic=semantic, binding=binding, image=image, identity=identity)
        restore_publication._persist_receipt(namespace, body)
        result = restore_publication.publish_pair_create_only(
            ingress_target=target,
            core_target=core_target,
            ingress_image=image,
            core_image=b"marker-only-core",
            pair_operation_id=operation,
            ingress_expected=expected_i,
            core_expected=expected_c,
            verify_ingress=verifier_i,
            verify_core=verifier_c,
        )
        self.assertEqual("ADOPTED_EXISTING", result.ingress.kind)
        self.assertEqual("CREATED_THIS_CALL", result.core.kind)
        self.assertFalse(namespace.exists())

    def test_restore_publication_after_cleanup_response_loss_adopts_without_rewrite(self) -> None:
        image_i = b"cleanup-loss-ingress"
        image_c = b"cleanup-loss-core"
        target_i = self.root / "cleanup-loss-ingress.db"
        target_c = self.root / "cleanup-loss-core.db"
        expected_i = {"database_id": "ingress", "head_root": "b" * 128}
        expected_c = {"database_id": "core", "head_root": "c" * 128}
        operation = _hex("pair-cleanup-loss")

        def fault(point: str) -> None:
            if point == "after_pair_cleanup":
                raise RuntimeError("response lost after cleanup")

        with self.assertRaises(restore_publication.RestorePublicationError):
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                restore_publication.publish_pair_create_only(
                    ingress_target=target_i,
                    core_target=target_c,
                    ingress_image=image_i,
                    core_image=image_c,
                    pair_operation_id=operation,
                    ingress_expected=expected_i,
                    core_expected=expected_c,
                    verify_ingress=lambda raw: dict(expected_i),
                    verify_core=lambda raw, exact_ingress: dict(expected_c),
                )
        inodes = (os.stat(target_i).st_ino, os.stat(target_c).st_ino)
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))
        retry = restore_publication.publish_pair_create_only(
            ingress_target=target_i,
            core_target=target_c,
            ingress_image=image_i,
            core_image=image_c,
            pair_operation_id=operation,
            ingress_expected=expected_i,
            core_expected=expected_c,
            verify_ingress=lambda raw: dict(expected_i),
            verify_core=lambda raw, exact_ingress: dict(expected_c),
        )
        self.assertEqual("ADOPTED_EXISTING", retry.ingress.kind)
        self.assertEqual("ADOPTED_EXISTING", retry.core.kind)
        self.assertEqual(inodes, (os.stat(target_i).st_ino, os.stat(target_c).st_ino))

    def test_restore_publication_adopts_one_existing_and_rejects_aliases(self) -> None:
        ingress_image = b"one-existing-ingress"
        core_image = b"one-existing-core"
        ingress_target = self.root / "one-existing-ingress.db"
        core_target = self.root / "one-existing-core.db"
        expected_i = {"database_id": "ingress", "head_root": "3" * 128}
        expected_c = {"database_id": "core", "head_root": "4" * 128}
        ingress_target.write_bytes(ingress_image)
        result = restore_publication.publish_pair_create_only(
            ingress_target=ingress_target,
            core_target=core_target,
            ingress_image=ingress_image,
            core_image=core_image,
            pair_operation_id=_hex("pair-one-existing"),
            ingress_expected=expected_i,
            core_expected=expected_c,
            verify_ingress=lambda raw: dict(expected_i),
            verify_core=lambda raw, exact_ingress: dict(expected_c),
        )
        self.assertEqual("ADOPTED_EXISTING", result.ingress.kind)
        self.assertEqual("CREATED_THIS_CALL", result.core.kind)
        self.assertEqual(ingress_image, ingress_target.read_bytes())
        self.assertEqual(core_image, core_target.read_bytes())

        alias_source = self.root / "alias-source.db"
        alias_target = self.root / "alias-target.db"
        alias_image = b"same-hardlink-image"
        alias_source.write_bytes(alias_image)
        os.link(alias_source, alias_target)
        before_inode = os.stat(alias_source).st_ino
        with self.assertRaises(restore_publication.RestorePublicationConflict):
            restore_publication.publish_pair_create_only(
                ingress_target=alias_source,
                core_target=alias_target,
                ingress_image=alias_image,
                core_image=alias_image,
                pair_operation_id=_hex("pair-hardlink-alias"),
                ingress_expected=expected_i,
                core_expected=expected_c,
                verify_ingress=lambda raw: dict(expected_i),
                verify_core=lambda raw, exact_ingress: dict(expected_c),
            )
        self.assertEqual(before_inode, os.stat(alias_source).st_ino)
        self.assertEqual(before_inode, os.stat(alias_target).st_ino)

        with self.assertRaises(restore_publication.RestorePublicationConflict):
            restore_publication.publish_pair_create_only(
                ingress_target=alias_source,
                core_target=alias_source,
                ingress_image=alias_image,
                core_image=alias_image,
                pair_operation_id=_hex("pair-same-target"),
                ingress_expected=expected_i,
                core_expected=expected_c,
                verify_ingress=lambda raw: dict(expected_i),
                verify_core=lambda raw, exact_ingress: dict(expected_c),
            )

    def test_restore_publication_resumes_owned_remnants_and_rejects_foreign_stage(self) -> None:
        expected_i = {"database_id": "ingress", "head_root": "5" * 128}
        expected_c = {"database_id": "core", "head_root": "6" * 128}
        cases = ("namespace", "marker", "stage-prefix", "stage-complete")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                image_i = ("remnant-ingress-" + case).encode("ascii")
                image_c = ("remnant-core-" + case).encode("ascii")
                target_i = self.root / ("remnant-ingress-" + str(index) + ".db")
                target_c = self.root / ("remnant-core-" + str(index) + ".db")
                operation = _hex("pair-remnant-" + case)
                namespace = restore_publication._namespace(target_i, operation)
                namespace.mkdir()
                if case != "namespace":
                    semantic = restore_publication._semantic_digest({**expected_i, "accepted": True})
                    binding = restore_publication._binding_digest(expected_i)
                    restore_publication._prepare_namespace(target_i, operation, role="ingress", image=image_i, semantic=semantic, binding=binding)
                if case == "marker":
                    marker = namespace / "marker.json"
                    marker.write_bytes(marker.read_bytes()[:13])
                elif case in {"stage-prefix", "stage-complete"}:
                    stage = namespace / "stage.db"
                    stage.write_bytes(image_i if case == "stage-complete" else image_i[:7])
                result = restore_publication.publish_pair_create_only(
                    ingress_target=target_i,
                    core_target=target_c,
                    ingress_image=image_i,
                    core_image=image_c,
                    pair_operation_id=operation,
                    ingress_expected=expected_i,
                    core_expected=expected_c,
                    verify_ingress=lambda raw, expected=expected_i: {**expected, "accepted": True},
                    verify_core=lambda raw, exact_ingress, expected=expected_c: {**expected, "accepted": True},
                )
                self.assertEqual("CREATED_THIS_CALL", result.ingress.kind)
                self.assertEqual("CREATED_THIS_CALL", result.core.kind)
                self.assertFalse(namespace.exists())
        sidecar_target = self.root / "stage-sidecar-ingress.db"
        sidecar_core = self.root / "stage-sidecar-core.db"
        sidecar_operation = _hex("pair-stage-sidecar")
        sidecar_namespace = restore_publication._prepare_namespace(
            sidecar_target,
            sidecar_operation,
            role="ingress",
            image=b"stage-sidecar-ingress",
            semantic=restore_publication._semantic_digest({**expected_i, "accepted": True}),
            binding=restore_publication._binding_digest(expected_i),
        )
        stage_sidecar = sidecar_namespace / "stage.db-wal"
        stage_sidecar.write_bytes(b"caller-owned stage sidecar")
        try:
            with self.assertRaises(restore_publication.RestorePublicationVerification):
                restore_publication.publish_pair_create_only(
                    ingress_target=sidecar_target,
                    core_target=sidecar_core,
                    ingress_image=b"stage-sidecar-ingress",
                    core_image=b"stage-sidecar-core",
                    pair_operation_id=sidecar_operation,
                    ingress_expected=expected_i,
                    core_expected=expected_c,
                    verify_ingress=lambda raw: {**expected_i, "accepted": True},
                    verify_core=lambda raw, exact_ingress: {**expected_c, "accepted": True},
                )
            self.assertFalse(sidecar_target.exists())
            self.assertEqual(b"caller-owned stage sidecar", stage_sidecar.read_bytes())
        finally:
            shutil.rmtree(sidecar_namespace)

        mismatch_target = self.root / "mismatched-remnant-ingress.db"
        mismatch_core = self.root / "mismatched-remnant-core.db"
        mismatch_operation = _hex("pair-mismatched-remnant")
        mismatch_namespace = restore_publication._namespace(mismatch_target, mismatch_operation)
        mismatch_namespace.mkdir()
        (mismatch_namespace / "marker.json").write_bytes(b"foreign marker bytes")
        try:
            with self.assertRaises(restore_publication.RestorePublicationVerification):
                restore_publication.publish_pair_create_only(
                    ingress_target=mismatch_target,
                    core_target=mismatch_core,
                    ingress_image=b"mismatched-ingress",
                    core_image=b"mismatched-core",
                    pair_operation_id=mismatch_operation,
                    ingress_expected=expected_i,
                    core_expected=expected_c,
                    verify_ingress=lambda raw: {**expected_i, "accepted": True},
                    verify_core=lambda raw, exact_ingress: {**expected_c, "accepted": True},
                )
            self.assertFalse(mismatch_target.exists())
            self.assertFalse(mismatch_core.exists())
        finally:
            shutil.rmtree(mismatch_namespace)
        foreign_target = self.root / "foreign-remnant-ingress.db"
        foreign_core = self.root / "foreign-remnant-core.db"
        foreign_operation = _hex("pair-foreign-remnant")
        foreign_namespace = restore_publication._namespace(foreign_target, foreign_operation)
        foreign_namespace.mkdir()
        try:
            with self.assertRaises(restore_publication.RestorePublicationConflict):
                restore_publication.publish_pair_create_only(
                    ingress_target=foreign_target,
                    core_target=foreign_core,
                    ingress_image=b"foreign-ingress",
                    core_image=b"foreign-core",
                    pair_operation_id=_hex("pair-other-remnant"),
                    ingress_expected=expected_i,
                    core_expected=expected_c,
                    verify_ingress=lambda raw: dict(expected_i),
                    verify_core=lambda raw, exact_ingress: dict(expected_c),
                )
            self.assertFalse(foreign_target.exists())
            self.assertFalse(foreign_core.exists())
        finally:
            foreign_namespace.rmdir()

    def test_restore_publication_reversed_lock_order_converges(self) -> None:
        target_a = self.root / "concurrent-a.db"
        target_b = self.root / "concurrent-b.db"
        image_a = b"concurrent-image-a"
        image_b = b"concurrent-image-b"
        expected_a = {"database_id": "a", "head_root": "7" * 128}
        expected_b = {"database_id": "b", "head_root": "8" * 128}
        operation = _hex("pair-reversed-order")
        barrier = threading.Barrier(2)
        results: list[restore_publication.PublicationPairResultV1] = []
        errors: list[BaseException] = []

        def publish(first: Path, second: Path, first_image: bytes, second_image: bytes, first_expected: dict[str, object], second_expected: dict[str, object]) -> None:
            try:
                barrier.wait(timeout=5)
                result = restore_publication.publish_pair_create_only(
                    ingress_target=first,
                    core_target=second,
                    ingress_image=first_image,
                    core_image=second_image,
                    pair_operation_id=operation,
                    ingress_expected=first_expected,
                    core_expected=second_expected,
                    verify_ingress=lambda raw, expected=first_expected: dict(expected),
                    verify_core=lambda raw, exact_ingress, expected=second_expected: dict(expected),
                )
                results.append(result)
            except BaseException as error:
                errors.append(error)

        first = threading.Thread(target=publish, args=(target_a, target_b, image_a, image_b, expected_a, expected_b))
        second = threading.Thread(target=publish, args=(target_b, target_a, image_b, image_a, expected_b, expected_a))
        first.start()
        second.start()
        first.join(timeout=10)
        second.join(timeout=10)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(image_a, target_a.read_bytes())
        self.assertEqual(image_b, target_b.read_bytes())
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))

    def test_restore_publication_contention_waits_past_legacy_window_and_converges(self) -> None:
        target_a = self.root / "contention-a.db"
        target_b = self.root / "contention-b.db"
        image_a = b"contention-image-a"
        image_b = b"contention-image-b"
        expected_a = {"database_id": "a", "head_root": "9" * 128}
        expected_b = {"database_id": "b", "head_root": "a" * 128}
        operation = _hex("pair-contention-deadline")
        holder_locked = threading.Event()
        release_holder = threading.Event()
        crossed_legacy_window = threading.Event()
        clock_lock = threading.Lock()
        clock = [100.0]
        sleep_calls = [0]
        results: list[restore_publication.PublicationPairResultV1] = []
        errors: list[BaseException] = []

        def fake_monotonic() -> float:
            with clock_lock:
                return clock[0]

        def fake_sleep(seconds: float) -> None:
            with clock_lock:
                clock[0] += seconds
                sleep_calls[0] += 1
                reached = sleep_calls[0] >= 81
                if reached:
                    crossed_legacy_window.set()
            if reached:
                if not release_holder.is_set():
                    release_holder.wait(timeout=5)
                threading.Event().wait(0.001)
            else:
                threading.Event().wait(0)

        def holder_ingress(raw: bytes) -> dict[str, object]:
            holder_locked.set()
            if not release_holder.wait(timeout=5):
                raise AssertionError("contention holder was not released")
            return dict(expected_a)

        def publish_holder() -> None:
            try:
                results.append(restore_publication.publish_pair_create_only(
                    ingress_target=target_a,
                    core_target=target_b,
                    ingress_image=image_a,
                    core_image=image_b,
                    pair_operation_id=operation,
                    ingress_expected=expected_a,
                    core_expected=expected_b,
                    verify_ingress=holder_ingress,
                    verify_core=lambda raw, exact_ingress: dict(expected_b),
                ))
            except BaseException as error:
                errors.append(error)

        def publish_contender() -> None:
            try:
                results.append(restore_publication.publish_pair_create_only(
                    ingress_target=target_b,
                    core_target=target_a,
                    ingress_image=image_b,
                    core_image=image_a,
                    pair_operation_id=operation,
                    ingress_expected=expected_b,
                    core_expected=expected_a,
                    verify_ingress=lambda raw: dict(expected_b),
                    verify_core=lambda raw, exact_ingress: dict(expected_a),
                ))
            except BaseException as error:
                errors.append(error)

        holder = threading.Thread(target=publish_holder)
        contender = threading.Thread(target=publish_contender)
        holder_started = False
        contender_started = False
        fake_time = mock.Mock(monotonic=fake_monotonic, sleep=fake_sleep)
        with mock.patch.object(restore_publication, "time", fake_time):
            holder.start()
            holder_started = True
            try:
                self.assertTrue(holder_locked.wait(timeout=5))
                contender.start()
                contender_started = True
                self.assertTrue(crossed_legacy_window.wait(timeout=5))
            finally:
                release_holder.set()
                if holder_started:
                    holder.join(timeout=5)
                if contender_started:
                    contender.join(timeout=5)

        self.assertFalse(holder.is_alive() or contender.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertGreaterEqual(sleep_calls[0], 81)
        self.assertGreaterEqual(clock[0] - 100.0, 0.81)
        self.assertEqual(image_a, target_a.read_bytes())
        self.assertEqual(image_b, target_b.read_bytes())
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))

    def test_restore_publication_short_deadline_lock_busy_without_target_mutation(self) -> None:
        target_a = self.root / "short-deadline-a.db"
        target_b = self.root / "short-deadline-b.db"
        image_a = b"short-deadline-image-a"
        image_b = b"short-deadline-image-b"
        expected_a = {"database_id": "a", "head_root": "b" * 128}
        expected_b = {"database_id": "b", "head_root": "c" * 128}
        operation = _hex("pair-short-deadline")
        holder_locked = threading.Event()
        release_holder = threading.Event()
        clock_lock = threading.Lock()
        clock = [200.0]
        sleep_calls = [0]
        holder_errors: list[BaseException] = []
        contender_errors: list[BaseException] = []
        before_targets = tuple((path.exists(), path.read_bytes() if path.exists() else None) for path in (target_a, target_b))
        before_namespaces = tuple(sorted(path.name for path in self.root.glob(".mirror-restore-pair-v1-*")))
        failed_targets: tuple[tuple[bool, bytes | None], ...] | None = None
        failed_namespaces: tuple[str, ...] | None = None

        def fake_monotonic() -> float:
            with clock_lock:
                return clock[0]

        def fake_sleep(seconds: float) -> None:
            with clock_lock:
                clock[0] += seconds
                sleep_calls[0] += 1
            threading.Event().wait(0)

        def holder_ingress(raw: bytes) -> dict[str, object]:
            holder_locked.set()
            if not release_holder.wait(timeout=5):
                raise AssertionError("short-deadline holder was not released")
            return dict(expected_a)

        def publish_holder() -> None:
            try:
                restore_publication.publish_pair_create_only(
                    ingress_target=target_a,
                    core_target=target_b,
                    ingress_image=image_a,
                    core_image=image_b,
                    pair_operation_id=operation,
                    ingress_expected=expected_a,
                    core_expected=expected_b,
                    verify_ingress=holder_ingress,
                    verify_core=lambda raw, exact_ingress: dict(expected_b),
                )
            except BaseException as error:
                holder_errors.append(error)

        def unexpected_contender_verifier(*args: object) -> dict[str, object]:
            raise AssertionError("contender verifier ran before lock-busy")

        def publish_contender() -> None:
            try:
                restore_publication.publish_pair_create_only(
                    ingress_target=target_b,
                    core_target=target_a,
                    ingress_image=image_b,
                    core_image=image_a,
                    pair_operation_id=operation,
                    ingress_expected=expected_b,
                    core_expected=expected_a,
                    verify_ingress=unexpected_contender_verifier,
                    verify_core=unexpected_contender_verifier,
                )
            except BaseException as error:
                contender_errors.append(error)

        holder = threading.Thread(target=publish_holder)
        contender = threading.Thread(target=publish_contender)
        contender_started = False
        fake_time = mock.Mock(monotonic=fake_monotonic, sleep=fake_sleep)
        holder.start()
        try:
            self.assertTrue(holder_locked.wait(timeout=5))
            with mock.patch.object(restore_publication, "time", fake_time), mock.patch.object(
                restore_publication, "LOCK_DEADLINE_SECONDS", 0.05
            ):
                contender.start()
                contender_started = True
                contender.join(timeout=2)
            failed_targets = tuple((path.exists(), path.read_bytes() if path.exists() else None) for path in (target_a, target_b))
            failed_namespaces = tuple(sorted(path.name for path in self.root.glob(".mirror-restore-pair-v1-*")))
        finally:
            release_holder.set()
            holder.join(timeout=5)
            if contender_started:
                contender.join(timeout=5)

        self.assertFalse(holder.is_alive() or contender.is_alive())
        self.assertEqual([], holder_errors)
        self.assertEqual(1, len(contender_errors))
        self.assertIs(type(contender_errors[0]), restore_publication.RestorePublicationError)
        self.assertEqual("restore-publication:lock-busy", str(contender_errors[0]))
        self.assertGreaterEqual(sleep_calls[0], 5)
        self.assertLessEqual(sleep_calls[0], 6)
        self.assertAlmostEqual(0.05, clock[0] - 200.0, places=9)
        self.assertEqual(before_targets, failed_targets)
        self.assertEqual(before_namespaces, failed_namespaces)
        self.assertEqual(image_a, target_a.read_bytes())
        self.assertEqual(image_b, target_b.read_bytes())
        self.assertEqual([], list(self.root.glob(".mirror-restore-pair-v1-*")))

    def test_recovery_fault_after_first_publish_keeps_target_and_revocation_closes_retry(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        target_i = self.root / "revoked-after-link-ingress.db"
        target_c = self.root / "revoked-after-link-core.db"
        original = restore_publication.publish_pair_create_only

        def publish_with_revocation(**kwargs: object) -> object:
            def fault(point_name: str) -> None:
                if point_name == "after_core_link":
                    self.custody.revoked.add(("synthetic-key", 1))
                    raise RuntimeError("revocation path credential canary")
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                return original(**kwargs)

        with mock.patch.object(restore_publication, "publish_pair_create_only", publish_with_revocation):
            with self.assertRaises(recovery.RecoveryError):
                self.recovery_service.restore_point(point.point_id, target_i, target_c)
        self.assertFalse(target_i.exists())
        self.assertTrue(target_c.exists())
        self.assertEqual("PUBLICATION_PENDING", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.restore_point(point.point_id, target_i, target_c)

    def test_recovery_publication_pending_fences_destination_pair_before_links(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        first_i = self.root / "pending-first-ingress.db"
        first_c = self.root / "pending-first-core.db"
        other_i = self.root / "pending-other-ingress.db"
        other_c = self.root / "pending-other-core.db"

        def fault(point_name: str) -> None:
            if point_name == "before_core_link":
                raise RuntimeError("response lost before first link")

        with self.assertRaises(recovery.RecoveryError):
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                self.recovery_service.restore_point(point.point_id, first_i, first_c)
        self.assertEqual("PUBLICATION_PENDING", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])
        self.assertFalse(first_i.exists())
        self.assertFalse(first_c.exists())
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.restore_point(point.point_id, other_i, other_c)
        self.assertFalse(other_i.exists())
        self.assertFalse(other_c.exists())
        resumed = self.recovery_service.restore_point(point.point_id, first_i, first_c)
        self.assertEqual("PUBLISHED", resumed.state)
        self.assertEqual("PUBLISHED", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])

    def test_recovery_publication_pending_after_first_link_preserves_target_and_fences_other_pair(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        first_i = self.root / "linked-first-ingress.db"
        first_c = self.root / "linked-first-core.db"
        other_i = self.root / "linked-other-ingress.db"
        other_c = self.root / "linked-other-core.db"

        def fault(point_name: str) -> None:
            if point_name == "after_core_link":
                raise RuntimeError("response lost after first link")

        with self.assertRaises(recovery.RecoveryError):
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                self.recovery_service.restore_point(point.point_id, first_i, first_c)
        first_inode = os.stat(first_c).st_ino
        self.assertFalse(first_i.exists())
        self.assertEqual("PUBLICATION_PENDING", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])
        with self.assertRaises(recovery.RecoveryConflictError):
            self.recovery_service.restore_point(point.point_id, other_i, other_c)
        self.assertFalse(other_i.exists())
        self.assertFalse(other_c.exists())
        resumed = self.recovery_service.restore_point(point.point_id, first_i, first_c)
        self.assertEqual("PUBLISHED", resumed.state)
        self.assertEqual(first_inode, os.stat(first_c).st_ino)
        self.assertEqual("PUBLISHED", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])

    def test_recovery_published_retry_is_destination_bound_and_path_free(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        ingress_target = self.root / "published-ingress-path-canary.db"
        core_target = self.root / "published-core-path-canary.db"
        first = self.recovery_service.restore_point(point.point_id, ingress_target, core_target)
        target_bytes_before = (ingress_target.read_bytes(), core_target.read_bytes())
        catalog_bytes_before = self.recovery_path.read_bytes()
        logical_export_before = self.recovery_service.logical_export()
        support_before = json.dumps(self.recovery_service.support(), sort_keys=True).encode("ascii")
        retry = self.recovery_service.restore_point(point.point_id, ingress_target, core_target)
        self.assertEqual(first.raw, retry.raw)
        self.assertEqual(target_bytes_before, (ingress_target.read_bytes(), core_target.read_bytes()))
        self.assertEqual(catalog_bytes_before, self.recovery_path.read_bytes())
        self.assertEqual(logical_export_before, self.recovery_service.logical_export())
        self.assertEqual(support_before, json.dumps(self.recovery_service.support(), sort_keys=True).encode("ascii"))
        other_i = self.root / "published-other-ingress-path-canary.db"
        other_c = self.root / "published-other-core-path-canary.db"
        with self.assertRaises(recovery.RecoveryConflictError) as caught:
            self.recovery_service.restore_point(point.point_id, other_i, other_c)
        self.assertEqual("recovery:publication-claim", str(caught.exception))
        self.assertFalse(other_i.exists())
        self.assertFalse(other_c.exists())
        database_bytes = self.recovery_path.read_bytes()
        logical_export = self.recovery_service.logical_export()
        support = json.dumps(self.recovery_service.support(), sort_keys=True).encode("ascii")
        for value in (database_bytes, logical_export, first.raw, support, str(caught.exception).encode("ascii")):
            self.assertNotIn(b"published-ingress-path-canary", value)
            self.assertNotIn(b"published-core-path-canary", value)
            self.assertNotIn(b"published-other-ingress-path-canary", value)
            self.assertNotIn(b"published-other-core-path-canary", value)

    def test_recovery_published_retry_rejects_missing_or_corrupt_member_without_recreating(self) -> None:
        for role in ("ingress", "core"):
            for action in ("missing", "corrupt"):
                with self.subTest(role=role, action=action):
                    service = recovery.RecoveryServiceV2(
                        self.root / f"published-damage-{role}-{action}-recovery.db",
                        self.recovery_config,
                        self.custody,
                        self.storage,
                        authority=self.authority,
                    )
                    point = service.create_point(self.ingress_path, self.core_path, generation=1)
                    ingress_target = self.root / f"published-damage-{role}-{action}-ingress.db"
                    core_target = self.root / f"published-damage-{role}-{action}-core.db"
                    first = service.restore_point(point.point_id, ingress_target, core_target)
                    target = ingress_target if role == "ingress" else core_target
                    peer = core_target if role == "ingress" else ingress_target
                    catalog_before = service.path.read_bytes()
                    logical_before = service.logical_export()
                    support_before = json.dumps(service.support(), sort_keys=True).encode("ascii")
                    if action == "missing":
                        target.unlink()
                    else:
                        target.write_bytes(b"corrupt")

                    with self.assertRaises(recovery.RecoveryError) as caught:
                        service.restore_point(point.point_id, ingress_target, core_target)
                    self.assertIn(str(caught.exception), {"recovery:publication", "recovery:publication-conflict"})
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
                    self.assertNotIn(str(target), str(caught.exception))
                    self.assertNotIn("corrupt", str(caught.exception))
                    self.assertEqual(first.state, "PUBLISHED")
                    self.assertEqual("PUBLISHED", recovery_independent.select_point(service.path, point_id=point.point_id)["point"]["state"])
                    self.assertEqual(catalog_before, service.path.read_bytes())
                    self.assertEqual(logical_before, service.logical_export())
                    self.assertEqual(support_before, json.dumps(service.support(), sort_keys=True).encode("ascii"))
                    if action == "corrupt":
                        self.assertEqual(b"corrupt", target.read_bytes())
                    else:
                        self.assertFalse(target.exists())
                        self.assertTrue(peer.exists())

    def test_recovery_published_retry_rejects_missing_or_bad_read_only_locks(self) -> None:
        for mode in ("missing", "truncated", "mismatched"):
            with self.subTest(mode=mode):
                service = recovery.RecoveryServiceV2(
                    self.root / f"published-read-only-lock-{mode}-recovery.db",
                    self.recovery_config,
                    self.custody,
                    self.storage,
                    authority=self.authority,
                )
                point = service.create_point(self.ingress_path, self.core_path, generation=1)
                ingress_target = self.root / f"published-read-only-lock-{mode}-ingress.db"
                core_target = self.root / f"published-read-only-lock-{mode}-core.db"
                service.restore_point(point.point_id, ingress_target, core_target)
                locks = (
                    restore_publication._lock_path(ingress_target),
                    restore_publication._lock_path(core_target),
                )
                catalog_before = service.path.read_bytes()
                target_before = (ingress_target.read_bytes(), core_target.read_bytes())
                marker_before = tuple(path.read_bytes() for path in locks)
                if mode == "missing":
                    for path in locks:
                        path.unlink()
                else:
                    locks[0].write_bytes(b"{" if mode == "truncated" else b"foreign-lock-marker")
                with self.assertRaises(recovery.RecoveryError):
                    service.restore_point(point.point_id, ingress_target, core_target)
                self.assertEqual(catalog_before, service.path.read_bytes())
                self.assertEqual(target_before, (ingress_target.read_bytes(), core_target.read_bytes()))
                if mode == "missing":
                    self.assertFalse(any(path.exists() for path in locks))
                else:
                    self.assertEqual(b"{" if mode == "truncated" else b"foreign-lock-marker", locks[0].read_bytes())
                    self.assertEqual(marker_before[1], locks[1].read_bytes())

    def test_recovery_first_publication_verifies_after_final_custody_callback_drift(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        ingress_target = self.root / "published-custody-drift-ingress.db"
        core_target = self.root / "published-custody-drift-core.db"
        original_state = self.custody.state
        injected = b"SYNTHETIC_CORRUPT_IN_POST_PUBLICATION_CUSTODY_CALLBACK"
        drifted = False

        def state_then_drift(key_id: str, key_epoch: int) -> str:
            nonlocal drifted
            if ingress_target.exists() and core_target.exists() and not drifted:
                core_target.write_bytes(injected)
                drifted = True
            return original_state(key_id, key_epoch)

        with mock.patch.object(self.custody, "state", side_effect=state_then_drift):
            with self.assertRaises(recovery.RecoveryError):
                self.recovery_service.restore_point(point.point_id, ingress_target, core_target)
        selected = recovery_independent.select_point(self.recovery_path, point_id=point.point_id)
        self.assertTrue(drifted)
        self.assertEqual("PUBLICATION_PENDING", selected["point"]["state"])
        self.assertEqual(self.ingress_path.read_bytes(), ingress_target.read_bytes())
        self.assertEqual(injected, core_target.read_bytes())

    def test_recovery_published_interleavings_verify_pair_before_return(self) -> None:
        def copy_published_tail(source: Path, destination: Path, point_id: str) -> None:
            source_connection = sqlite3.connect(source)
            destination_connection = sqlite3.connect(destination)
            try:
                source_point = source_connection.execute(
                    "SELECT point_id,state,updated_sequence FROM recovery_points WHERE point_id=?",
                    (point_id,),
                ).fetchone()
                source_meta = source_connection.execute(
                    "SELECT sequence,head_root,current_generation FROM recovery_meta WHERE meta_id=1"
                ).fetchone()
                destination_meta = destination_connection.execute(
                    "SELECT sequence FROM recovery_meta WHERE meta_id=1"
                ).fetchone()
                if source_point is None or source_meta is None or destination_meta is None or source_point[1] != "PUBLISHED":
                    raise AssertionError("expected a published source state")
                events = source_connection.execute(
                    "SELECT * FROM recovery_events WHERE sequence>? ORDER BY sequence",
                    (destination_meta[0],),
                ).fetchall()
                placeholders = ",".join("?" for _ in range(20))
                for event in events:
                    destination_connection.execute(
                        f"INSERT INTO recovery_events VALUES ({placeholders})", event
                    )
                destination_connection.execute(
                    "UPDATE recovery_points SET state=?,updated_sequence=? WHERE point_id=?",
                    (source_point[1], source_point[2], point_id),
                )
                destination_connection.execute(
                    "UPDATE recovery_meta SET sequence=?,head_root=?,current_generation=? WHERE meta_id=1",
                    source_meta,
                )
                destination_connection.commit()
            finally:
                source_connection.close()
                destination_connection.close()

        first_service = recovery.RecoveryServiceV2(
            self.root / "published-race-first-recovery.db",
            self.recovery_config,
            self.custody,
            self.storage,
            authority=self.authority,
        )
        first_auxiliary = recovery.RecoveryServiceV2(
            self.root / "published-race-first-auxiliary.db",
            self.recovery_config,
            self.custody,
            self.storage,
            authority=self.authority,
        )
        first_point = first_service.create_point(self.ingress_path, self.core_path, generation=1)
        first_auxiliary_point = first_auxiliary.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual(first_point.point_id, first_auxiliary_point.point_id)
        first_ingress = self.root / "published-race-first-ingress.db"
        first_core = self.root / "published-race-first-core.db"
        auxiliary_receipt = first_auxiliary.restore_point(
            first_auxiliary_point.point_id, first_ingress, first_core
        )
        original_first_open = first_service._open
        first_open_calls = 0

        def open_after_concurrent_publish() -> sqlite3.Connection:
            nonlocal first_open_calls
            connection = original_first_open()
            first_open_calls += 1
            if first_open_calls == 1:
                copy_published_tail(first_auxiliary.path, first_service.path, first_point.point_id)
            return connection

        with mock.patch.object(first_service, "_open", side_effect=open_after_concurrent_publish):
            with mock.patch.object(
                first_service,
                "_verify_published_targets",
                wraps=first_service._verify_published_targets,
            ) as verify_first:
                first_result = first_service.restore_point(first_point.point_id, first_ingress, first_core)
        self.assertEqual(1, first_open_calls)
        self.assertEqual(1, verify_first.call_count)
        self.assertEqual(auxiliary_receipt.raw, first_result.raw)

        second_service = recovery.RecoveryServiceV2(
            self.root / "published-race-second-recovery.db",
            self.recovery_config,
            self.custody,
            self.storage,
            authority=self.authority,
        )
        second_auxiliary = recovery.RecoveryServiceV2(
            self.root / "published-race-second-auxiliary.db",
            self.recovery_config,
            self.custody,
            self.storage,
            authority=self.authority,
        )
        second_point = second_service.create_point(self.ingress_path, self.core_path, generation=1)
        second_auxiliary_point = second_auxiliary.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual(second_point.point_id, second_auxiliary_point.point_id)
        second_ingress = self.root / "published-race-second-ingress.db"
        second_core = self.root / "published-race-second-core.db"
        second_auxiliary_receipt = second_auxiliary.restore_point(
            second_auxiliary_point.point_id, second_ingress, second_core
        )
        original_publish = restore_publication.publish_pair_create_only

        def publish_after_concurrent_publish(**kwargs: object) -> object:
            result = original_publish(**kwargs)
            copy_published_tail(second_auxiliary.path, second_service.path, second_point.point_id)
            return result

        with mock.patch.object(
            restore_publication,
            "publish_pair_create_only",
            side_effect=publish_after_concurrent_publish,
        ):
            with mock.patch.object(
                second_service,
                "_verify_published_targets",
                wraps=second_service._verify_published_targets,
            ) as verify_second:
                second_result = second_service.restore_point(second_point.point_id, second_ingress, second_core)
        self.assertEqual(2, verify_second.call_count)
        self.assertEqual(second_auxiliary_receipt.raw, second_result.raw)

    def test_recovery_publication_different_pair_concurrency_has_one_durable_claim(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        pairs = (
            (self.root / "concurrent-claim-a-ingress.db", self.root / "concurrent-claim-a-core.db"),
            (self.root / "concurrent-claim-b-ingress.db", self.root / "concurrent-claim-b-core.db"),
        )
        barrier = threading.Barrier(2)
        results: list[recovery.RecoveryReceipt] = []
        errors: list[BaseException] = []

        def restore(pair: tuple[Path, Path]) -> None:
            try:
                barrier.wait(timeout=5)
                results.append(self.recovery_service.restore_point(point.point_id, pair[0], pair[1]))
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=restore, args=(pair,)) for pair in pairs]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(1, len(results))
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], writer_authority.WriterAuthorityError)
        self.assertEqual("writer:mutation", str(errors[0]))
        self.assertEqual(2, sum(int(ingress_path.exists()) + int(core_path.exists()) for ingress_path, core_path in pairs))
        self.assertEqual("PUBLISHED", recovery_independent.select_point(self.recovery_path, point_id=point.point_id)["point"]["state"])

    def _rebind_recovery_tail(self, path: Path, mutate: object) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM recovery_events ORDER BY sequence DESC LIMIT 1").fetchone()
            value = recovery_independent._parse(bytes(row["event_raw"]), "recovery:test-event")
            value["material"] = mutate(value["material"])
            value["material_digest"] = recovery_independent._digest("material", value["material"])
            value["event_id"] = recovery_independent._digest("event-id", {key: value[key] for key in recovery_independent._EVENT_RAW_KEYS if key not in {"event_id", "after_root"}})
            value["after_root"] = recovery_independent._event_root(value["sequence"], value["before_root"], value["event_id"], value["event_kind"], value["point_id"], value["next_state"], value["material_digest"], value["stream_kind"], value["stream_id"])
            raw = recovery_independent._canonical(value)
            connection.execute("UPDATE recovery_events SET event_id=?,after_root=?,material_digest=?,event_raw=?,receipt_digest=? WHERE sequence=?", (value["event_id"], value["after_root"], value["material_digest"], raw, recovery_independent._raw_digest("receipt", raw), value["sequence"]))
            connection.execute("UPDATE recovery_meta SET head_root=? WHERE meta_id=1", (value["after_root"],))
            connection.commit()
        finally:
            connection.close()

    def test_recovery_publication_claim_replay_rejects_rebound_pending_and_published(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        pending_i = self.root / "rebound-pending-ingress.db"
        pending_c = self.root / "rebound-pending-core.db"

        def fault(point_name: str) -> None:
            if point_name == "before_core_link":
                raise RuntimeError("pending claim fault")

        with self.assertRaises(recovery.RecoveryError):
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                self.recovery_service.restore_point(point.point_id, pending_i, pending_c)
        bad_pending = self.root / "bad-pending-claim.db"
        shutil.copy2(self.recovery_path, bad_pending)
        self._rebind_recovery_tail(bad_pending, lambda material: {**material, "ingress_target_binding": "f" * 128})
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(bad_pending, expected_database_id=self.recovery_config.database_id, expected_config_digest=self.recovery_config.digest)

        self.recovery_service.restore_point(point.point_id, pending_i, pending_c)
        bad_published = self.root / "bad-published-claim.db"
        shutil.copy2(self.recovery_path, bad_published)
        self._rebind_recovery_tail(bad_published, lambda material: {**material, "core_target_binding": "e" * 128})
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(bad_published, expected_database_id=self.recovery_config.database_id, expected_config_digest=self.recovery_config.digest)

    def test_restore_publication_rejects_absent_case_alias_before_link(self) -> None:
        if os.name != "nt":
            self.skipTest("case-insensitive absent parent/leaf alias capability unavailable")
        parent = self.root / "case-alias-parent"
        parent.mkdir()
        first = parent / "AliasTarget.db"
        second = parent / "aliastarget.db"
        with self.assertRaises(restore_publication.RestorePublicationConflict):
            restore_publication.publish_pair_create_only(
                ingress_target=first,
                core_target=second,
                ingress_image=b"case-alias-ingress",
                core_image=b"case-alias-core",
                pair_operation_id=_hex("case-alias-pair"),
                ingress_expected={"database_id": "ingress", "head_root": "1" * 128},
                core_expected={"database_id": "core", "head_root": "2" * 128},
                verify_ingress=lambda raw: {"database_id": "ingress", "head_root": "1" * 128},
                verify_core=lambda raw, exact_ingress: {"database_id": "core", "head_root": "2" * 128},
            )
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())

    def test_ingress_transaction_finalizer_reconciles_commit_and_close_uncertainty(self) -> None:
        path = self.root / "ingress-finalizer-commit.db"
        service = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock, authority=self.authority)
        original_open = ingress._connection
        faults: list[_InitializationFaultConnection] = []

        def commit_then_raise(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(
                original_open(target, **kwargs),
                fail_commit=True,
            )
            faults.append(connection)
            return connection

        scheduled_at = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds
        with mock.patch.object(ingress, "_connection", side_effect=commit_then_raise):
            with self.assertRaisesRegex(ingress.IngressIndeterminateError, "^ingress:transaction-indeterminate$") as caught:
                service.ensure_slot(scheduled_at)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY", "".join(traceback.format_exception(caught.exception)))
        self.assertEqual(1, faults[0].commit_calls)
        restarted = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock, authority=self.authority)
        retry = restarted.ensure_slot(scheduled_at)
        self.assertEqual("DUE", retry.next_state)
        self.assertEqual(1, restarted.verify()["event_count"])

        close_path = self.root / "ingress-finalizer-close.db"
        close_service = ingress.IngressServiceV2(close_path, self.ingress_config, clock=self.clock, authority=self.authority)
        close_faults: list[_InitializationFaultConnection] = []

        def close_after_commit(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(
                original_open(target, **kwargs),
                fail_close=True,
            )
            close_faults.append(connection)
            return connection

        close_time = profile.FIXTURE_OBSERVATION_TIME + 2 * self.ingress_config.cadence_seconds
        with mock.patch.object(ingress, "_connection", side_effect=close_after_commit):
            with self.assertRaisesRegex(ingress.IngressIndeterminateError, "^ingress:transaction-indeterminate$"):
                close_service.ensure_slot(close_time)
        close_retry = ingress.IngressServiceV2(close_path, self.ingress_config, clock=self.clock, authority=self.authority).ensure_slot(close_time)
        self.assertEqual("DUE", close_retry.next_state)
        self.assertEqual(1, ingress_independent.verify_database(close_path)["event_count"])

    def test_ingress_transaction_finalizer_rejects_rollback_failure(self) -> None:
        path = self.root / "ingress-finalizer-rollback.db"
        service = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock, authority=self.authority)
        original_open = ingress._connection
        faults: list[_InitializationFaultConnection] = []

        def rollback_failure(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(
                original_open(target, **kwargs),
                fail_rollback=True,
            )
            faults.append(connection)
            return connection

        with mock.patch.object(service, "_append", side_effect=ingress.IngressError("ingress:precommit")):
            with mock.patch.object(ingress, "_connection", side_effect=rollback_failure):
                with self.assertRaisesRegex(ingress.IngressIndeterminateError, "^ingress:transaction-indeterminate$") as caught:
                    service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY", "".join(traceback.format_exception(caught.exception)))
        self.assertGreaterEqual(faults[0].rollback_calls, 1)

    def test_core_transaction_finalizer_reconciles_commit_close_and_rollback(self) -> None:
        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 62
        original_open = core._connection

        commit_faults: list[_InitializationFaultConnection] = []

        def commit_then_raise(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(original_open(target, **kwargs), fail_commit=True)
            commit_faults.append(connection)
            return connection

        with mock.patch.object(core, "_connection", side_effect=commit_then_raise):
            with self.assertRaisesRegex(core.CoreIndeterminateError, "^core:transaction-indeterminate$") as caught:
                self.core.observe(self.session_id, 1, "DISCREPANCY", counts={"observed": 1, "changed": 1})
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY", "".join(traceback.format_exception(caught.exception)))
        self.assertEqual(1, commit_faults[0].commit_calls)
        restarted = core.CoreServiceV2(self.core_path, self.core_config, clock=self.core_clock, authority=self.authority)
        retry = restarted.observe(self.session_id, 1, "DISCREPANCY", counts={"observed": 1, "changed": 1})
        self.assertEqual("OBSERVATION", json.loads(retry.raw.decode("ascii"))["event_kind"])
        self.assertEqual(self.core.verify()["event_count"], restarted.verify()["event_count"])

        close_path = self.root / "core-finalizer-close.db"
        shutil.copy2(self.core_path, close_path)
        close_service = core.CoreServiceV2(close_path, self.core_config, clock=self.core_clock, authority=self.authority)
        close_faults: list[_InitializationFaultConnection] = []

        def close_after_commit(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(original_open(target, **kwargs), fail_close=True)
            close_faults.append(connection)
            return connection

        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 124
        with mock.patch.object(core, "_connection", side_effect=close_after_commit):
            with self.assertRaisesRegex(core.CoreIndeterminateError, "^core:transaction-indeterminate$"):
                close_service.observe(self.session_id, 2, "PARITY", counts={"observed": 2, "changed": 0})
        self.assertEqual(1, close_faults[0].close_calls)
        close_retry = core.CoreServiceV2(close_path, self.core_config, clock=self.core_clock, authority=self.authority).observe(
            self.session_id, 2, "PARITY", counts={"observed": 2, "changed": 0}
        )
        self.assertEqual("OBSERVATION", json.loads(close_retry.raw.decode("ascii"))["event_kind"])

        rollback_path = self.root / "core-finalizer-rollback.db"
        shutil.copy2(self.core_path, rollback_path)
        rollback_service = core.CoreServiceV2(rollback_path, self.core_config, clock=self.core_clock, authority=self.authority)
        rollback_faults: list[_InitializationFaultConnection] = []

        def rollback_failure(target: Path, **kwargs: object):
            connection = _InitializationFaultConnection(original_open(target, **kwargs), fail_rollback=True)
            rollback_faults.append(connection)
            return connection

        with mock.patch.object(rollback_service, "_append", side_effect=core.CoreError("core:precommit")):
            with mock.patch.object(core, "_connection", side_effect=rollback_failure):
                with self.assertRaisesRegex(core.CoreIndeterminateError, "^core:transaction-indeterminate$") as caught:
                    rollback_service.observe(self.session_id, 2, "DISCREPANCY", counts={"observed": 1, "changed": 1})
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("CANARY", "".join(traceback.format_exception(caught.exception)))
        self.assertGreaterEqual(rollback_faults[0].rollback_calls, 1)

    def test_independent_verifier_cleanup_failures_are_fixed_and_redacted(self) -> None:
        canary = "CANARY-VERIFIER-CLEANUP-CREDENTIAL-C:/private"
        for module, path, error_type, code in (
            (ingress_independent, self.ingress_path, ingress_independent.IngressVerificationError, "ingress:database"),
            (core_independent, self.core_path, core_independent.CoreVerificationError, "core:database"),
        ):
            with self.subTest(module=module.__name__):
                real_connect = module.sqlite3.connect

                class ReadFault:
                    def __init__(self, inner: sqlite3.Connection) -> None:
                        self.inner = inner

                    def close(self) -> None:
                        self.inner.close()
                        raise RuntimeError(canary)

                    def __getattr__(self, name: str) -> object:
                        return getattr(self.inner, name)

                def open_fault(*args: object, **kwargs: object):
                    return ReadFault(real_connect(*args, **kwargs))

                with mock.patch.object(module.sqlite3, "connect", side_effect=open_fault):
                    with self.assertRaisesRegex(error_type, f"^{code}$") as caught:
                        module.verify_database(path)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn(canary, str(caught.exception))
                self.assertNotIn(canary, rendered)

if __name__ == "__main__":
    unittest.main()
