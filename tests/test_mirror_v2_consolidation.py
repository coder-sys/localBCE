from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import replace
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
from app.mirror import external_corrective_action as corrective_action
from app.mirror import external_corrective_action_independent as corrective_action_independent
from app.mirror import external_source_adapter as external_adapter
from app.mirror import external_governance_approval as governance
from app.mirror import external_privacy_support_approval as privacy
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from app.mirror import restore_publication


def _hex(seed: str) -> str:
    return hashlib.sha3_512(seed.encode("ascii")).hexdigest()


def _ingress_token(seed: str) -> str:
    return (seed + "-ingress-token").ljust(32, "x")


class _DeterministicExternalCaptureVerifier:
    """Test-only typed verifier entering through the normal adapter service."""

    def __init__(self, policy: external_adapter.ExternalSourcePolicyV2) -> None:
        self.verifier_id = policy.verifier_id
        self.verifier_epoch = policy.verifier_epoch
        self.policy = policy

    def verify(self, capture_raw: bytes) -> external_adapter.VerifiedExternalCaptureV2:
        result = fhir_independent.verify_bytes(capture_raw)
        payload = hashlib.sha3_512(capture_raw).hexdigest()
        context = result["capture_context"]
        pages = tuple(result["page_digests"])
        server_identity = external_adapter._expected_server_identity(self.policy)
        source_status = result.get("source_status")
        freshness = result.get("freshness")
        raw_failure = result.get("failure_code")
        if source_status == "PARTIAL":
            failure_code = "INCOMPLETE"
        elif source_status in {"FAILED", "STALE"}:
            failure_code = "STALE" if freshness == "STALE" else "SOURCE_FAILURE"
        elif raw_failure is None:
            failure_code = "NONE"
        else:
            failure_code = "SOURCE_FAILURE"
        verified = external_adapter.VerifiedExternalCaptureV2(
            policy_digest=self.policy.digest,
            verifier_id=self.verifier_id,
            verifier_epoch=self.verifier_epoch,
            capture_id=external_adapter._capture_id_for_payload(payload),
            payload_sha3_512=payload,
            observed_at=int(result["observation_time"]),
            fetched_at=int(result["fetched_at"]),
            page_digests=pages,
            page_count=len(pages),
            server_identity_digest=server_identity,
            transport_receipt_digest="0" * 128,
            transport_authenticated=False,
            complete=bool(result.get("page_complete") is True and source_status == "COMPLETE" and raw_failure is None),
            failure_code=failure_code,
            zero_phi=True,
            subject_id=str(context["subject_id"]),
            credential_id=str(context["credential_id"]),
            enrollment_id=str(context["enrollment_id"]),
            subject_locator_digest=str(context["subject_locator_digest"]),
        )
        object.__setattr__(
            verified,
            "transport_receipt_digest",
            external_adapter._expected_transport_receipt(self.policy, verified, server_identity),
        )
        return verified


def _external_evidence(config: ingress.IngressConfigV2, envelope: bytes) -> bytes:
    policy = config.external_policy()
    return external_adapter.build_artifact(
        policy, _DeterministicExternalCaptureVerifier(policy), envelope
    ).raw


def _rechain_ingress_with_fetch_capture_rebind(path: Path, replacements: dict[int, str]) -> None:
    """Rebind a copied ingress event chain so semantic fetch/capture checks are reached."""

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM ingress_events ORDER BY sequence").fetchall()
        previous = ingress_independent.GENESIS_ROOT
        stream_roots: dict[tuple[str, str], str] = {}
        stream_last: dict[tuple[str, str], int] = {}
        for row in rows:
            value = json.loads(bytes(row["event_raw"]).decode("ascii"))
            if row["sequence"] in replacements:
                material = dict(value["material"])
                material["capture_operation_id"] = replacements[row["sequence"]]
                value["material"] = material
                value["operation_id"] = ingress_independent._digest(
                    "fetch-operation",
                    {
                        "operation_id": material["capture_operation_id"],
                        "page_index": material["page_index"],
                        "transport_attempt": material["transport_attempt"],
                    },
                )
                value["material_digest"] = ingress_independent._digest("material", material)
                value["payload_digest"] = ingress_independent._digest("fetch-payload", material)
            value["before_root"] = previous
            stream_key = (value["stream_kind"], value["stream_id"])
            value["stream_before_root"] = stream_roots.get(stream_key, ingress_independent.GENESIS_ROOT)
            value["event_id"] = ingress_independent._digest(
                "event-id",
                {key: value[key] for key in ingress_independent.EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            value["after_root"] = ingress_independent._event_root(
                sequence=value["sequence"], previous=value["before_root"], event_id=value["event_id"],
                event_kind=value["event_kind"], stream_kind=value["stream_kind"], stream_id=value["stream_id"],
                slot_id=value["slot_id"], next_state=value["next_state"], observed_at=value["observed_at"],
                material_digest=value["material_digest"],
            )
            value["stream_after_root"] = ingress_independent._stream_root(
                sequence=value["sequence"], previous=value["stream_before_root"], event_id=value["event_id"],
                stream_kind=value["stream_kind"], stream_id=value["stream_id"], next_state=value["next_state"],
                observed_at=value["observed_at"], material_digest=value["material_digest"],
            )
            event_raw = ingress_independent._canonical(value)
            connection.execute(
                """UPDATE ingress_events SET event_id=?,operation_id=?,material_digest=?,payload_digest=?,
                   before_root=?,after_root=?,stream_before_root=?,stream_after_root=?,event_raw=?,receipt_digest=?
                   WHERE sequence=?""",
                (
                    value["event_id"], value["operation_id"], value["material_digest"], value["payload_digest"],
                    value["before_root"], value["after_root"], value["stream_before_root"], value["stream_after_root"],
                    event_raw, ingress_independent._raw_digest("receipt", event_raw), value["sequence"],
                ),
            )
            previous = value["after_root"]
            stream_roots[stream_key] = value["stream_after_root"]
            stream_last[stream_key] = value["sequence"]
        for (stream_kind, stream_id), head_root in stream_roots.items():
            connection.execute(
                "UPDATE ingress_heads SET head_root=?,event_sequence=? WHERE stream_kind=? AND stream_id=?",
                (head_root, stream_last[(stream_kind, stream_id)], stream_kind, stream_id),
            )
        connection.execute("UPDATE ingress_meta SET head_root=? WHERE meta_id=1", (previous,))
        connection.commit()
    finally:
        connection.close()


class _ManualClock:
    def __init__(self, value: int) -> None:
        self.value = value
        self.raise_on_read = False

    def __call__(self) -> int:
        if self.raise_on_read:
            raise RuntimeError("clock read must not be needed for exact retry")
        return self.value


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


class _CorrectiveActionVerifier:
    identity = "SYNTH_CORRECTIVE_ACTION_VERIFIER"
    epoch = 1
    authority_evidence_digest = _hex("corrective-action-authority")
    revocation_head_digest = _hex("corrective-action-revocation")
    terms_digest = _hex("corrective-action-terms")
    retention_policy_digest = _hex("corrective-action-retention")
    valid_from = profile.FIXTURE_OBSERVATION_TIME
    valid_until = profile.FIXTURE_OBSERVATION_TIME + 3600
    max_evidence_bytes = 1024

    def __init__(self, control: corrective_action.CorrectiveActionControlV1 | None = None) -> None:
        if control is not None:
            self.identity = control.verifier_id
            self.epoch = control.verifier_epoch
            self.authority_evidence_digest = control.authority_evidence_digest
            self.revocation_head_digest = control.revocation_head_digest
            self.terms_digest = control.terms_digest
            self.retention_policy_digest = control.retention_policy_digest
            self.valid_from = control.valid_from
            self.valid_until = control.valid_until
            self.max_evidence_bytes = control.max_evidence_bytes

    def verify(
        self,
        evidence_raw: bytes,
        policy: corrective_action.CorrectiveActionPolicyV1,
    ) -> corrective_action.VerifiedCorrectiveActionV1:
        evidence_digest = corrective_action._raw_digest(evidence_raw)
        observed_at = policy.valid_from + 1
        action_id = corrective_action._digest(
            "action-id",
            {
                "policy_digest": policy.digest,
                "evidence_sha3_512": evidence_digest,
                "action_code": "CORRECTIVE_ACTION_RECORDED",
                "observed_at": observed_at,
            },
        )
        return corrective_action.VerifiedCorrectiveActionV1(
            action_id=action_id,
            policy_digest=policy.digest,
            case_id=policy.case_id,
            current_case_artifact_id=policy.current_case_artifact_id,
            source_artifact_id=policy.source_artifact_id,
            graph_artifact_id=policy.graph_artifact_id,
            graph_report_id=policy.graph_report_id,
            target_finding_ids=policy.target_finding_ids,
            target_finding_kinds=policy.target_finding_kinds,
            action_code="CORRECTIVE_ACTION_RECORDED",
            observed_at=observed_at,
            valid_from=policy.valid_from,
            valid_until=policy.valid_until,
            verifier_id=self.identity,
            verifier_epoch=self.epoch,
            evidence_sha3_512=evidence_digest,
            evidence_byte_length=len(evidence_raw),
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
        self.clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME)
        self.ingress = ingress.IngressServiceV2(self.ingress_path, self.ingress_config, clock=self.clock)
        created = self.ingress.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        self.ingress.claim_slot(slot_id, lease_token=_ingress_token("lease-v2"))
        from tests.test_nc_medicaid_fhir_source import _envelope
        self.envelope = _envelope()
        self.ingress_receipt = self.ingress.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-v2"),
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
        self.corrective_action_control = corrective_action.CorrectiveActionControlV1(
            verifier_id=_CorrectiveActionVerifier.identity,
            verifier_epoch=_CorrectiveActionVerifier.epoch,
            authority_evidence_digest=_CorrectiveActionVerifier.authority_evidence_digest,
            revocation_head_digest=_CorrectiveActionVerifier.revocation_head_digest,
            terms_digest=_CorrectiveActionVerifier.terms_digest,
            retention_policy_digest=_CorrectiveActionVerifier.retention_policy_digest,
            valid_from=_CorrectiveActionVerifier.valid_from,
            valid_until=_CorrectiveActionVerifier.valid_until,
            max_evidence_bytes=_CorrectiveActionVerifier.max_evidence_bytes,
        )
        self.corrective_action_verifier = _CorrectiveActionVerifier(self.corrective_action_control)
        self.core_config = core.CoreConfigV2(
            database_id="core-v2-synthetic", chain_id="core-chain-v2",
            ingress_database_id=self.ingress_config.database_id, ingress_chain_id=self.ingress_config.chain_id, ingress_config_digest=self.ingress_config.digest,
            runtime_profile_digest=profile.NC_MEDICAID_PROFILE.profile_digest,
            governance_policy_digest=self.governance_policy.digest,
            privacy_policy_digest=self.privacy_policy.digest,
            corrective_action_control_digest=self.corrective_action_control.digest,
        )
        self.core_clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME + 2)
        self.core = core.CoreServiceV2(
            self.core_path,
            self.core_config,
            clock=self.core_clock,
            corrective_action_control=self.corrective_action_control,
            corrective_action_verifier=self.corrective_action_verifier,
        )
        self.source_result = self.core.ingest_source(self.ingress_path, self.ingress_receipt.artifact_id or "")
        self.gov_core_id = self.core.admit_governance(self.governance_raw, policy=self.governance_policy, evidence_raw=b"synthetic governance assertion")
        self.privacy_core_id = self.core.admit_privacy(self.privacy_raw, policy=self.privacy_policy, evidence_raw=b"synthetic privacy assertion")
        self.session_open = self.core.open_session(source_artifact_id=self.source_result["source_artifact_id"], governance_artifact_id=self.gov_core_id, privacy_artifact_id=self.privacy_core_id)
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
        service = ingress.IngressServiceV2(self.root / name, self.ingress_config, clock=self.clock)
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
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("not-held"),
            )
        self.assertEqual(before, self._state_fingerprint(service))

    def test_expired_and_stale_leases_reject_without_mutation(self) -> None:
        service, slot_id = self._fresh_ingress("expired-capture.db")
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-old"))
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:lease-expired"):
            service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("lease-old"),
            )
        self.assertEqual(before, self._state_fingerprint(service))

        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds + 1
        service.claim_slot(
            slot_id,
            lease_token=_ingress_token("lease-new"),
        )
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:attempt"):
            service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("lease-old"),
            )
        self.assertEqual(before, self._state_fingerprint(service))
        connection = sqlite3.connect(service.path)
        try:
            lease_events = connection.execute(
                "SELECT attempt, observed_at FROM ingress_events WHERE slot_id=? AND event_kind='LEASE' ORDER BY sequence",
                (slot_id,),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual([1, 2], [int(row[0]) for row in lease_events])
        self.assertEqual([profile.FIXTURE_OBSERVATION_TIME, self.clock.value], [int(row[1]) for row in lease_events])

    def test_public_ingress_operations_have_no_per_call_time_override(self) -> None:
        claim_parameters = inspect.signature(ingress.IngressServiceV2.claim_slot).parameters
        capture_parameters = inspect.signature(ingress.IngressServiceV2.admit_capture).parameters
        self.assertNotIn("now", claim_parameters)
        self.assertNotIn("observed_at", capture_parameters)
        self.assertIn("attempt", capture_parameters)
        self.assertIn("clock", inspect.signature(ingress.IngressServiceV2).parameters)

    def test_ingress_lease_and_operation_values_are_digest_only(self) -> None:
        service, slot_id = self._fresh_ingress("digest-only-ingress.db")
        raw_token = _ingress_token("lease-bearer-canary-raw")
        raw_operation = "caller-operation-canary-raw"
        service.claim_slot(slot_id, lease_token=raw_token)
        receipt = service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=raw_token,
            operation_id=raw_operation,
        )
        database_bytes = service.path.read_bytes()
        logical_export = service.logical_export()
        support = json.dumps(service.support(), sort_keys=True).encode("ascii")
        for surface in (database_bytes, logical_export, receipt.raw, support):
            self.assertNotIn(raw_token.encode("ascii"), surface)
            self.assertNotIn(raw_operation.encode("ascii"), surface)
        connection = sqlite3.connect(service.path)
        try:
            persisted = [bytes(row[0]) for row in connection.execute("SELECT event_raw FROM ingress_events")]
            lease_values = [row[0] for row in connection.execute("SELECT lease_token FROM ingress_events WHERE lease_token IS NOT NULL")]
        finally:
            connection.close()
        self.assertTrue(all(raw_token.encode("ascii") not in raw for raw in persisted))
        self.assertTrue(all(raw_operation.encode("ascii") not in raw for raw in persisted))
        self.assertTrue(all(type(value) is str and len(value) == 128 for value in lease_values))

    def test_claim_slot_lost_response_retries_exactly_and_fences_tokens(self) -> None:
        service, slot_id = self._fresh_ingress("claim-response-loss.db")
        first = service.claim_slot(slot_id, lease_token=_ingress_token("claim-response-loss"))
        before = self._state_fingerprint(service)
        retry = service.claim_slot(slot_id, lease_token=_ingress_token("claim-response-loss"))
        self.assertEqual(first.raw, retry.raw)
        self.assertEqual(before, self._state_fingerprint(service))
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:lease-token"):
            service.claim_slot(slot_id, lease_token=_ingress_token("claim-different-live"))
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds
        self.clock.value += 1
        next_receipt = service.claim_slot(slot_id, lease_token=_ingress_token("claim-response-loss"))
        self.assertEqual("LEASED", next_receipt.next_state)
        self.assertEqual(2, json.loads(next_receipt.raw.decode("ascii"))["attempt"])
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:attempt"):
            service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("claim-response-loss"),
            )
        self.assertEqual(before, self._state_fingerprint(service))
        admitted = service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=2,
            lease_token=_ingress_token("claim-response-loss"),
        )
        self.assertEqual("QUARANTINED", admitted.next_state)

    def test_expired_max_attempt_claim_is_slot_hold_without_artifact_authority(self) -> None:
        config = ingress.IngressConfigV2(
            database_id="ingress-hold-synthetic",
            chain_id="ingress-hold-chain",
            policy_digest=self.ingress_config.policy_digest,
            authorization_digest=self.ingress_config.authorization_digest,
            terms_digest=self.ingress_config.terms_digest,
            effective_start=self.ingress_config.effective_start,
            effective_end=self.ingress_config.effective_end,
            cadence_seconds=self.ingress_config.cadence_seconds,
            max_slots=1,
            max_attempts=1,
            lease_seconds=self.ingress_config.lease_seconds,
        )
        clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME)
        service = ingress.IngressServiceV2(self.root / "max-attempt-hold.db", config, clock=clock)
        created = service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        service.claim_slot(slot_id, lease_token=_ingress_token("same-hold-token"))
        clock.value += config.lease_seconds
        held = service.claim_slot(slot_id, lease_token=_ingress_token("same-hold-token"))
        self.assertEqual("HELD", held.next_state)
        self.assertIsNone(held.artifact_id)
        snapshot = service.verify()
        self.assertEqual(0, snapshot["artifact_count"])
        self.assertEqual({"HELD": 1}, {key: value for key, value in snapshot["state_counts"].items() if value})
        connection = sqlite3.connect(service.path)
        try:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM ingress_heads WHERE stream_kind='QUARANTINE'"
                ).fetchone()[0],
            )
            event = connection.execute(
                "SELECT event_kind,stream_kind,stream_id,payload_digest,receipt_bytes FROM ingress_events WHERE event_kind='HOLD'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual("HOLD", event[0])
        self.assertEqual("SLOT", event[1])
        self.assertEqual(slot_id, event[2])
        self.assertIsNone(event[4])

    def test_ingress_oversize_caller_strings_fail_before_mutation(self) -> None:
        service, slot_id = self._fresh_ingress("oversize-caller.db")
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressError, "ingress:lease"):
            service.claim_slot(slot_id, lease_token="x" * 1025)
        with self.assertRaisesRegex(ingress.IngressError, "ingress:operation"):
            service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("bounded-token"),
                operation_id="x" * 257,
            )
        self.assertEqual(before, self._state_fingerprint(service))

    def test_ingress_identity_and_minimum_secret_bounds_precede_storage(self) -> None:
        bad_path = self.root / "never-created-for-bad-config.db"
        for field, value in (
            ("database_id", "d" * (ingress.MAX_IDENTIFIER_BYTES + 1)),
            ("chain_id", "café"),
        ):
            values = dict(vars(self.ingress_config))
            values[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ingress.IngressError, "ingress:config"):
                    ingress.IngressServiceV2(bad_path, ingress.IngressConfigV2(**values), clock=self.clock)
                self.assertFalse(bad_path.exists())
        service, slot_id = self._fresh_ingress("short-secret.db")
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressError, "ingress:lease"):
            service.claim_slot(slot_id, lease_token="short-secret")
        self.assertEqual(before, self._state_fingerprint(service))

    def test_ingress_public_export_has_no_undefined_independent_symbol(self) -> None:
        namespace: dict[str, object] = {}
        exec("from app.mirror.ingress_v2 import *", namespace)
        self.assertNotIn("INDEX_DEFINITIONS", namespace)

    def test_ingress_constructor_replays_before_use_and_pins_file_identity(self) -> None:
        tampered = self.root / "constructor-tampered.db"
        shutil.copy2(self.ingress_path, tampered)
        connection = sqlite3.connect(tampered)
        try:
            connection.execute(
                "UPDATE ingress_events SET after_root=? WHERE sequence=(SELECT MAX(sequence) FROM ingress_events)",
                ("e" * 128,),
            )
            connection.commit()
        finally:
            connection.close()
        tampered_bytes = tampered.read_bytes()
        tampered_hash = hashlib.sha256(tampered_bytes).digest()
        with self.assertRaisesRegex(ingress.IngressError, "ingress:database"):
            ingress.IngressServiceV2(tampered, self.ingress_config, clock=self.clock)
        self.assertEqual(tampered_bytes, tampered.read_bytes())
        self.assertEqual(tampered_hash, hashlib.sha256(tampered.read_bytes()).digest())

        replacement = self.root / "replacement.db"
        shutil.copy2(self.ingress_path, replacement)
        self.ingress_path.unlink()
        shutil.copy2(replacement, self.ingress_path)
        with self.assertRaisesRegex(ingress.IngressError, "ingress:database-open"):
            self.ingress.ensure_slot(profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds)

    def test_ingress_pinned_missing_path_is_never_recreated(self) -> None:
        service, _slot_id = self._fresh_ingress("pinned-missing.db")
        service.path.unlink()
        with self.assertRaisesRegex(ingress.IngressError, "ingress:database-open"):
            service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds)
        self.assertFalse(service.path.exists())

    def test_ingress_identity_swap_is_rejected_before_sql_setup(self) -> None:
        service, _slot_id = self._fresh_ingress("preopen-swap.db")
        replacement = self.root / "preopen-swap-source.db"
        shutil.copy2(service.path, replacement)
        replacement_hash = hashlib.sha256(replacement.read_bytes()).digest()
        real_connect = ingress.sqlite3.connect
        holder: dict[str, object] = {}

        class RecordingConnection:
            def __init__(self, inner: sqlite3.Connection) -> None:
                self.inner = inner
                self.execute_calls: list[object] = []

            def __setattr__(self, name: str, value: object) -> None:
                if name in {"inner", "execute_calls"}:
                    object.__setattr__(self, name, value)
                else:
                    setattr(self.inner, name, value)

            def execute(self, *args: object, **kwargs: object) -> object:
                self.execute_calls.append((args, kwargs))
                return self.inner.execute(*args, **kwargs)

            def close(self) -> None:
                self.inner.close()

            def __getattr__(self, name: str) -> object:
                return getattr(self.inner, name)

        def swap_then_connect(*args: object, **kwargs: object) -> RecordingConnection:
            service.path.unlink()
            shutil.copy2(replacement, service.path)
            wrapped = RecordingConnection(real_connect(*args, **kwargs))
            holder["connection"] = wrapped
            return wrapped

        with mock.patch.object(ingress.sqlite3, "connect", side_effect=swap_then_connect):
            with self.assertRaisesRegex(ingress.IngressError, "ingress:database-open"):
                service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds)
        wrapped = holder["connection"]
        self.assertEqual([], wrapped.execute_calls)  # type: ignore[union-attr]
        self.assertEqual(replacement_hash, hashlib.sha256(service.path.read_bytes()).digest())

    def test_ingress_sqlite_full_rolls_back_capture_and_records_capacity_hold(self) -> None:
        service, slot_id = self._fresh_ingress("capacity-fallback.db")
        lease_token = _ingress_token("capacity-fallback")
        service.claim_slot(slot_id, lease_token=lease_token)
        original_append = service._append
        failed = False

        def fail_final(connection: sqlite3.Connection, *args: object, **kwargs: object) -> bytes:
            nonlocal failed
            if not failed and kwargs.get("kind") == "ADMIT":
                failed = True
                raise sqlite3.OperationalError("database or disk is full")
            return original_append(connection, *args, **kwargs)

        with mock.patch.object(service, "_append", side_effect=fail_final):
            receipt = service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=lease_token,
            )
        self.assertTrue(failed)
        self.assertEqual("HELD", receipt.next_state)
        self.assertEqual(3, service.verify()["event_count"])
        self.assertEqual(0, service.verify()["artifact_count"])
        self.clock.raise_on_read = True
        self.assertEqual(
            receipt.raw,
            service.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=lease_token,
            ).raw,
        )

    def test_artifact_watermark_is_reconstructed_from_terminal_event(self) -> None:
        artifact_id = self.ingress_receipt.artifact_id or ""
        connection = sqlite3.connect(self.ingress_path)
        try:
            terminal = connection.execute(
                "SELECT sequence FROM ingress_events WHERE event_kind='ADMIT' AND payload_digest=?",
                (artifact_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(terminal)
        terminal_sequence = int(terminal[0])
        selected = ingress_independent.read_artifact(self.ingress_path, artifact_id)
        self.assertEqual(terminal_sequence, selected["event_sequence"])
        self.assertEqual(terminal_sequence, selected["watermark"])
        selected_snapshot = ingress_independent.read_artifact_snapshot(self.ingress_path, artifact_id)
        self.assertEqual(terminal_sequence, selected_snapshot["watermark"])

        tampered = self.root / "artifact-watermark-tampered.db"
        shutil.copy2(self.ingress_path, tampered)
        connection = sqlite3.connect(tampered)
        try:
            connection.execute(
                "UPDATE ingress_artifacts SET event_sequence=? WHERE artifact_id=?",
                (terminal_sequence + 1, artifact_id),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:artifact-event-sequence"):
            ingress_independent.read_artifact(tampered, artifact_id)

    def test_capacity_hold_is_terminal_and_preserves_no_capture_bytes(self) -> None:
        service, slot_id = self._fresh_ingress("capacity-hold.db")
        service.claim_slot(slot_id, lease_token=_ingress_token("capacity-hold-token"))
        service._capacity_available = lambda *args, **kwargs: False
        receipt = service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("capacity-hold-token"),
        )
        self.assertEqual("HELD", receipt.next_state)
        self.clock.raise_on_read = True
        self.assertEqual(receipt.raw, service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("capacity-hold-token"),
        ).raw)
        snapshot = service.verify(include_raw=True)
        self.assertEqual(0, snapshot["artifact_count"])
        self.assertEqual(1, snapshot["slot_count"])
        self.assertEqual(1, snapshot["state_counts"]["HELD"])
        self.assertEqual(3, snapshot["event_count"])
        connection = sqlite3.connect(service.path)
        try:
            row = connection.execute(
                "SELECT state,lease_token,lease_until,artifact_id FROM ingress_slots WHERE slot_id=?",
                (slot_id,),
            ).fetchone()
            fetch_count = connection.execute(
                "SELECT COUNT(*) FROM ingress_events WHERE event_kind='FETCH_ATTESTATION'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(("HELD", None, None, None), tuple(row))
        self.assertEqual(0, fetch_count)

    def test_ingress_atomic_schema_failures_leave_no_partial_tables(self) -> None:
        original_ddl = ingress._SCHEMA_DDL
        for index in range(len(original_ddl)):
            path = self.root / f"ingress-ddl-failure-{index}.db"
            ingress._SCHEMA_DDL = original_ddl[:index] + ("THIS IS INVALID SQL",) + original_ddl[index + 1:]
            try:
                with self.assertRaisesRegex(ingress.IngressError, "ingress:database-initialize"):
                    ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock)
            finally:
                ingress._SCHEMA_DDL = original_ddl
            connection = sqlite3.connect(path)
            try:
                tables = tuple(row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ))
            finally:
                connection.close()
            self.assertEqual((), tables)
            ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock)

    def test_ingress_path_and_page_capacity_gates_are_executable(self) -> None:
        service, _slot_id = self._fresh_ingress("ingress-capacity-gates.db")
        connection = ingress._connection(service.path)
        try:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            max_pages = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
            self.assertLessEqual(page_size * max_pages, ingress.MAX_DATABASE_BYTES)
        finally:
            connection.close()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(os.fspath(service.path) + suffix)
            sidecar.write_bytes(b"sidecar")
            try:
                with self.assertRaisesRegex(ingress.IngressError, "ingress:database-open"):
                    ingress.IngressServiceV2(service.path, self.ingress_config, clock=self.clock)
            finally:
                sidecar.unlink()
        hardlink = self.root / "ingress-hardlink.db"
        os.link(service.path, hardlink)
        try:
            with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:database"):
                ingress_independent.verify_database(hardlink)
        finally:
            hardlink.unlink()
        oversized = self.root / "ingress-oversized.db"
        with oversized.open("wb") as stream:
            stream.seek(ingress.MAX_DATABASE_BYTES)
            stream.write(b"x")
        before_size = oversized.stat().st_size
        with self.assertRaisesRegex(ingress.IngressError, "ingress:database-open"):
            ingress.IngressServiceV2(oversized, self.ingress_config, clock=self.clock)
        self.assertEqual(before_size, oversized.stat().st_size)

    def test_core_v2_has_exact_six_tables_columns_and_one_explicit_index(self) -> None:
        self.assertIn("clock", inspect.signature(core.CoreServiceV2).parameters)
        self.assertNotIn("now", inspect.signature(core.CoreServiceV2.open_session).parameters)
        connection = sqlite3.connect(self.core_path)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            self.assertEqual(set(core_independent.TABLES), tables)
            for table, columns in core_independent.TABLE_COLUMNS.items():
                actual = tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)))
                self.assertEqual(columns, actual)
            indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")}
            self.assertEqual({"core_artifacts_kind_source_event_idx"}, indexes)
            self.assertNotIn("CASE_ADVANCE", {row[0] for row in connection.execute("SELECT DISTINCT event_kind FROM core_events")})
        finally:
            connection.close()

    def test_core_v4_identity_is_explicit_and_v3_state_is_rejected(self) -> None:
        self.assertEqual("mirror-core-v4", core_independent.SCHEMA)
        self.assertEqual(4, core_independent.SCHEMA_VERSION)
        self.assertEqual(core_independent.SCHEMA, core.SCHEMA)
        self.assertEqual(core_independent.SCHEMA_VERSION, core.SCHEMA_VERSION)
        connection = sqlite3.connect(self.core_path)
        connection.row_factory = sqlite3.Row
        try:
            meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
            event_raw = bytes(connection.execute("SELECT event_raw FROM core_events ORDER BY sequence LIMIT 1").fetchone()[0])
        finally:
            connection.close()
        config = json.loads(bytes(meta["config_raw"]).decode("ascii"))
        event = json.loads(event_raw.decode("ascii"))
        logical = json.loads(self.core.logical_export().decode("ascii"))
        for value in (meta, config, event):
            self.assertEqual(core_independent.SCHEMA, value["schema"])
            self.assertEqual(core_independent.SCHEMA_VERSION, value["schema_version"])
        self.assertEqual(f"mirror-core-logical-export-v{core_independent.SCHEMA_VERSION}", logical["schema"])
        self.assertEqual(core_independent.SCHEMA_VERSION, logical["schema_version"])

        v3_config = dict(config)
        v3_config["schema"] = "mirror-core-v3"
        v3_config["schema_version"] = 3
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:config"):
            core_independent._verify_config(v3_config)

        v3_path = self.root / "core-v3-rejected.db"
        shutil.copy2(self.core_path, v3_path)
        connection = sqlite3.connect(v3_path)
        try:
            v3_raw = core_independent._canonical(v3_config)
            v3_digest = core_independent._digest("config", v3_config)
            connection.execute(
                "UPDATE core_meta SET schema=?,schema_version=?,config_raw=?,config_digest=? WHERE meta_id=1",
                ("mirror-core-v3", 3, v3_raw, v3_digest),
            )
            connection.commit()
        finally:
            connection.close()
        before = v3_path.read_bytes()
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:meta"):
            core_independent.verify_database(
                v3_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
            )
        self.assertEqual(before, v3_path.read_bytes())
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:meta"):
            core.CoreServiceV2(v3_path, self.core_config)
        self.assertEqual(before, v3_path.read_bytes())

    def test_case_heads_are_lineage_scoped_and_interleaved_retries_converge(self) -> None:
        case_a = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        later = self._admit_later_source()
        case_b = self.core.admit_case(later["source_result"]["reconciliation_artifact_id"])
        a_action, a_action_id, a_evidence = self._record_case_action(case_a)
        b_action, b_action_id, b_evidence = self._record_case_action(case_b)
        self.assertEqual(
            a_action.raw,
            self.core.record_case_action(
                case_a,
                evidence_raw=a_evidence,
            ).raw,
        )
        self.assertEqual(
            b_action.raw,
            self.core.record_case_action(
                case_b,
                evidence_raw=b_evidence,
            ).raw,
        )
        self.assertNotEqual(a_action_id, b_action_id)
        verified = self.core.verify()
        self.assertGreaterEqual(verified["artifact_count"], 11)
        connection = sqlite3.connect(self.core_path)
        try:
            case_ids = []
            for artifact_id in (case_a, case_b):
                raw = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()[0]
                case_ids.append(json.loads(bytes(raw).decode("ascii"))["case_id"])
            heads = connection.execute("SELECT stream_id,head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id NOT IN ('GRAPH','SOURCE_OBSERVATION','RECONCILIATION','GOVERNANCE','PRIVACY') ORDER BY stream_id").fetchall()
        finally:
            connection.close()
        self.assertEqual({row[0] for row in heads}, set(case_ids))
        self.assertEqual({row[1] for row in heads}, {a_action_id, b_action_id})

    def test_independent_rejects_rehashed_case_semantics(self) -> None:
        case_row_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        tampered = self.root / "core-case-semantic.db"
        shutil.copy2(self.core_path, tampered)
        connection = sqlite3.connect(tampered)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=? AND kind='CASE'", (case_row_id,)).fetchone()
            event_row = connection.execute("SELECT sequence,event_raw FROM core_events WHERE event_kind='ARTIFACT' AND subject_id=?", (case_row_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(event_row)
            case = json.loads(bytes(row["raw"]).decode("ascii"))
            replacement_kind = "CREDENTIAL_EXPIRED" if case["target_finding_kinds"][0] != "CREDENTIAL_EXPIRED" else "ENROLLMENT_TERMINATED"
            case["target_finding_kinds"][0] = replacement_kind
            case["artifact_id"] = core._digest("case-artifact", {key: case[key] for key in case if key != "artifact_id"})
            case_raw = core._canonical(case)
            rebound_row_id = core._digest(
                "artifact-row-id",
                {
                    "kind": "CASE",
                    "raw": core._raw_digest("artifact-bytes", case_raw),
                    "profile_digest": row["profile_digest"],
                    "source_artifact_id": row["source_artifact_id"],
                    "predecessor_id": row["predecessor_id"],
                },
            )
            connection.execute("UPDATE core_artifacts SET artifact_id=?,raw=? WHERE artifact_id=?", (rebound_row_id, case_raw, case_row_id))
            event = json.loads(bytes(event_row["event_raw"]).decode("ascii"))
            event["material"]["artifact_id"] = rebound_row_id
            event["material"]["raw_digest"] = core._raw_digest("artifact-bytes", case_raw)
            event["material"]["raw_length"] = len(case_raw)
            event["material_digest"] = core._digest("material", event["material"])
            event["subject_id"] = rebound_row_id
            event["payload_digest"] = rebound_row_id
            event["payload_length"] = len(case_raw)
            event["event_id"] = core._digest("event-id", {key: event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
            event["after_root"] = core_independent._event_root(event)
            event["stream_after_root"] = core_independent._stream_root(event)
            event_raw = core._canonical(event)
            connection.execute("UPDATE core_events SET event_id=?,subject_id=?,event_raw=?,receipt_digest=? WHERE sequence=?", (event["event_id"], rebound_row_id, event_raw, core._raw_digest("receipt", event_raw), event_row["sequence"]))
            connection.execute("UPDATE core_meta SET head_root=? WHERE meta_id=1", (event["after_root"],))
            connection.execute("UPDATE core_heads SET head_ref=?,head_root=? WHERE stream_kind='ARTIFACT' AND stream_id=?", (rebound_row_id, event["stream_after_root"], case["case_id"]))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core_independent.CoreVerificationError, r"core:case-(?:chain|semantic)"):
            core_independent.verify_database(tampered, expected_database_id=self.core_config.database_id, expected_config_digest=self.core_config.digest)

    def test_case_action_and_retest_are_derived_and_raw_evidence_is_not_persisted(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        connection = sqlite3.connect(self.core_path)
        try:
            case = json.loads(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (case_id,)).fetchone()[0]).decode("ascii"))
        finally:
            connection.close()
        self.assertEqual(case["state"], "OPEN")
        self.assertEqual(case["responsibility"], "UNKNOWN")
        action_receipt, action_id, evidence = self._record_case_action(case_id)
        before_bytes = self.core_path.read_bytes()
        before_verify = self.core.verify(ingress_path=self.ingress_path)
        with self.assertRaisesRegex(core.CoreConflictError, "core:action-verification"):
            self.core.record_case_action(
                case_id,
                evidence_raw=b"different corrective evidence",
            )
        self.assertEqual(before_bytes, self.core_path.read_bytes())
        self.assertEqual(before_verify, self.core.verify(ingress_path=self.ingress_path))

        later = self._admit_later_source(subject_seed=None)
        evaluated = self.core.evaluate_case(action_receipt and json.loads(action_receipt.raw.decode("ascii"))["material"]["artifact_id"], later["source_result"]["source_artifact_id"])
        final_case_id = json.loads(evaluated.raw.decode("ascii"))["material"]["artifact_id"]
        connection = sqlite3.connect(self.core_path)
        try:
            final_case = json.loads(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (final_case_id,)).fetchone()[0]).decode("ascii"))
        finally:
            connection.close()
        self.assertEqual(final_case["state"], "RETEST_FAILED_OR_INDETERMINATE")
        self.assertIn(final_case["reason"], {"RETEST_INDETERMINATE", "TARGET_FINDINGS_REMAIN"})
        self.assertEqual(final_case["responsibility"], "UNKNOWN")
        self.assertEqual(final_case["retest_source_artifact_id"], later["source_result"]["source_artifact_id"])
        database_bytes = self.core_path.read_bytes()
        self.assertNotIn(evidence, database_bytes)
        self.assertNotIn(evidence, self.core.logical_export())
        self.assertNotIn(evidence.decode("ascii"), json.dumps(self.core.support(), sort_keys=True))
        self.assertNotEqual(action_id, final_case_id)
        core_independent.verify_database(self.core_path, expected_database_id=self.core_config.database_id, expected_config_digest=self.core_config.digest, ingress_path=self.ingress_path)

    def test_corrective_action_control_is_pinned_and_replayed(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        mismatches = (
            ("identity", "OTHER_CORRECTIVE_ACTION_VERIFIER"),
            ("epoch", self.corrective_action_control.verifier_epoch + 1),
            ("authority_evidence_digest", _hex("other-authority")),
            ("revocation_head_digest", _hex("other-revocation")),
            ("terms_digest", _hex("other-terms")),
            ("retention_policy_digest", _hex("other-retention")),
            ("valid_from", self.corrective_action_control.valid_from + 1),
            ("valid_until", self.corrective_action_control.valid_until - 1),
            ("max_evidence_bytes", self.corrective_action_control.max_evidence_bytes - 1),
        )
        for index, (attribute, value) in enumerate(mismatches):
            verifier = _CorrectiveActionVerifier(self.corrective_action_control)
            setattr(verifier, attribute, value)
            path = self.root / f"unbound-corrective-verifier-{index}.db"
            with self.assertRaisesRegex(core.CoreError, "core:action-control"):
                core.CoreServiceV2(
                    path,
                    self.core_config,
                    corrective_action_control=self.corrective_action_control,
                    corrective_action_verifier=verifier,
                )
            self.assertFalse(path.exists())

        wrong_config = replace(
            self.core_config,
            corrective_action_control_digest=_hex("wrong-control-config"),
        )
        wrong_config_path = self.root / "wrong-control-config.db"
        with self.assertRaisesRegex(core.CoreError, "core:action-control"):
            core.CoreServiceV2(
                wrong_config_path,
                wrong_config,
                corrective_action_control=self.corrective_action_control,
                corrective_action_verifier=self.corrective_action_verifier,
            )
        self.assertFalse(wrong_config_path.exists())

        before = self.core_path.read_bytes()
        self.corrective_action_verifier.authority_evidence_digest = _hex("mutated-after-init")
        with self.assertRaisesRegex(core.CoreConflictError, "core:action-control"):
            self.core.record_case_action(case_id, evidence_raw=b"synthetic corrective evidence")
        self.assertEqual(before, self.core_path.read_bytes())

    def test_corrective_action_independent_acceptance_requires_state_control(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        _receipt, _action_id, evidence = self._record_case_action(case_id)
        connection = sqlite3.connect(self.core_path)
        try:
            action_raw = bytes(connection.execute("SELECT raw FROM core_artifacts WHERE kind='CASE_ACTION'").fetchone()[0])
        finally:
            connection.close()
        expected = self.corrective_action_control.digest
        accepted = corrective_action_independent.verify_artifact(
            action_raw,
            control_digest=expected,
            evidence_raw=evidence,
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(
            accepted,
            corrective_action_independent.verify_bytes(
                action_raw,
                control_digest=expected,
                evidence_raw=evidence,
            ),
        )
        with self.assertRaises(TypeError):
            corrective_action_independent.verify_artifact(action_raw)
        with self.assertRaises(TypeError):
            corrective_action_independent.verify_bytes(action_raw)
        for invalid in (None, "0" * 127, "A" * 128, "0" * 128):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(corrective_action_independent.IndependentCorrectiveActionError, "action:control") as caught:
                    corrective_action_independent.verify_artifact(action_raw, control_digest=invalid)  # type: ignore[arg-type]
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

    def test_corrective_action_verifier_drift_after_verify_fails_before_core_write(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")

        class DriftingVerifier(_CorrectiveActionVerifier):
            def verify(
                self,
                evidence_raw: bytes,
                policy: corrective_action.CorrectiveActionPolicyV1,
            ) -> corrective_action.VerifiedCorrectiveActionV1:
                result = super().verify(evidence_raw, policy)
                self.terms_digest = _hex("drifted-corrective-action-terms")
                return result

        drifting = DriftingVerifier(self.corrective_action_control)
        self.core._corrective_action_verifier = drifting
        before = self.core_path.read_bytes()
        connection = sqlite3.connect(self.core_path)
        try:
            before_events = int(connection.execute("SELECT COUNT(*) FROM core_events").fetchone()[0])
        finally:
            connection.close()
        with self.assertRaisesRegex(core.CoreConflictError, "core:action-verification") as caught:
            self.core.record_case_action(case_id, evidence_raw=b"synthetic corrective evidence")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(before, self.core_path.read_bytes())
        connection = sqlite3.connect(self.core_path)
        try:
            self.assertEqual(before_events, int(connection.execute("SELECT COUNT(*) FROM core_events").fetchone()[0]))
        finally:
            connection.close()

    def test_independent_rejects_rehashed_case_action_with_alternative_control_lineage(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        _receipt, _successor_id, _evidence = self._record_case_action(case_id)
        tampered = self.root / "core-case-action-control.db"
        shutil.copy2(self.core_path, tampered)
        connection = sqlite3.connect(tampered)
        connection.row_factory = sqlite3.Row
        try:
            artifact_rows = connection.execute("SELECT * FROM core_artifacts ORDER BY created_event_sequence").fetchall()
            action_row = None
            case_successor_row = None
            for row in artifact_rows:
                value = json.loads(bytes(row["raw"]).decode("ascii"))
                if row["kind"] == "CASE_ACTION":
                    action_row = row
                elif row["kind"] == "CASE" and row["predecessor_id"] == case_id and value["state"] == "ACTION_RECORDED":
                    case_successor_row = row
            self.assertIsNotNone(action_row)
            self.assertIsNotNone(case_successor_row)
            action_value = json.loads(bytes(action_row["raw"]).decode("ascii"))
            policy = dict(action_value["policy"])
            policy["authority_evidence_digest"] = _hex("rebound-control-authority")
            action_value["policy"] = policy
            action_value["policy_digest"] = core_independent._digest("policy", policy)
            assertion = dict(action_value["assertion"])
            assertion["action_id"] = core_independent._digest(
                "action-id",
                {
                    "policy_digest": action_value["policy_digest"],
                    "evidence_sha3_512": assertion["evidence_sha3_512"],
                    "action_code": assertion["action_code"],
                    "observed_at": assertion["observed_at"],
                },
            )
            action_value["assertion"] = assertion
            action_value["artifact_id"] = core_independent._digest(
                "artifact-id",
                {key: action_value[key] for key in ("schema", "schema_version", "kind", "policy", "policy_digest", "assertion", "flags")},
            )
            action_raw = core_independent._canonical(action_value)
            action_row_id = core_independent._digest(
                "artifact-row-id",
                {
                    "kind": "CASE_ACTION",
                    "raw": core_independent._raw_digest("artifact-bytes", action_raw),
                    "profile_digest": action_row["profile_digest"],
                    "source_artifact_id": action_row["source_artifact_id"],
                    "predecessor_id": action_row["predecessor_id"],
                },
            )
            action_event = None
            successor_event = None
            for event_row in connection.execute("SELECT sequence,event_raw FROM core_events WHERE event_kind='ARTIFACT' ORDER BY sequence").fetchall():
                event = json.loads(bytes(event_row["event_raw"]).decode("ascii"))
                if event["material"].get("kind") == "CASE_ACTION":
                    action_event = (event_row["sequence"], event)
                elif event["material"].get("kind") == "CASE" and event["material"].get("predecessor_id") == case_id and event["material"].get("current_state") == "ACTION_RECORDED":
                    successor_event = (event_row["sequence"], event)
            self.assertIsNotNone(action_event)
            self.assertIsNotNone(successor_event)
            action_sequence, action_event = action_event
            successor_sequence, successor_event = successor_event
            action_event["subject_id"] = action_row_id
            action_event["operation_id"] = core_independent._digest(
                "case-action-operation",
                {"action_id": action_value["artifact_id"], "case_id": policy["case_id"]},
            )
            action_event["request_digest"] = core_independent._digest(
                "case-action-request",
                {"action_id": action_value["artifact_id"], "case_id": policy["case_id"], "evidence_digest": assertion["evidence_sha3_512"]},
            )
            action_event["material"].update(
                {
                    "artifact_id": action_row_id,
                    "raw_digest": core_independent._raw_digest("artifact-bytes", action_raw),
                    "raw_length": len(action_raw),
                }
            )
            action_event["payload_digest"] = action_row_id
            action_event["payload_length"] = len(action_raw)
            action_event["material_digest"] = core_independent._digest("material", action_event["material"])
            action_event["event_id"] = core_independent._digest(
                "event-id",
                {key: action_event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            action_event["after_root"] = core_independent._event_root(action_event)
            action_event["stream_after_root"] = core_independent._stream_root(action_event)
            action_raw_event = core_independent._canonical(action_event)

            successor_value = json.loads(bytes(case_successor_row["raw"]).decode("ascii"))
            successor_value["action_artifact_id"] = action_row_id
            successor_value["artifact_id"] = core_independent._digest(
                "case-artifact",
                {key: successor_value[key] for key in successor_value if key != "artifact_id"},
            )
            successor_raw = core_independent._canonical(successor_value)
            successor_row_id = core_independent._digest(
                "artifact-row-id",
                {
                    "kind": "CASE",
                    "raw": core_independent._raw_digest("artifact-bytes", successor_raw),
                    "profile_digest": case_successor_row["profile_digest"],
                    "source_artifact_id": case_successor_row["source_artifact_id"],
                    "predecessor_id": case_successor_row["predecessor_id"],
                },
            )
            successor_event["before_root"] = action_event["after_root"]
            successor_event["subject_id"] = successor_row_id
            successor_event["operation_id"] = core_independent._digest(
                "case-transition-operation",
                {"case_artifact_id": case_id, "action_artifact_id": action_row_id, "transition": "ACTION_RECORDED"},
            )
            successor_event["request_digest"] = core_independent._digest(
                "case-transition-request",
                {"case_artifact_id": case_id, "action_artifact_id": action_row_id, "transition": "ACTION_RECORDED"},
            )
            successor_event["material"].update(
                {
                    "artifact_id": successor_row_id,
                    "raw_digest": core_independent._raw_digest("artifact-bytes", successor_raw),
                    "raw_length": len(successor_raw),
                }
            )
            successor_event["payload_digest"] = successor_row_id
            successor_event["payload_length"] = len(successor_raw)
            successor_event["material_digest"] = core_independent._digest("material", successor_event["material"])
            successor_event["event_id"] = core_independent._digest(
                "event-id",
                {key: successor_event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            successor_event["after_root"] = core_independent._event_root(successor_event)
            successor_event["stream_after_root"] = core_independent._stream_root(successor_event)
            successor_raw_event = core_independent._canonical(successor_event)

            connection.execute("UPDATE core_artifacts SET artifact_id=?,raw=? WHERE artifact_id=?", (action_row_id, action_raw, action_row["artifact_id"]))
            connection.execute("UPDATE core_artifacts SET artifact_id=?,raw=? WHERE artifact_id=?", (successor_row_id, successor_raw, case_successor_row["artifact_id"]))
            connection.execute(
                "UPDATE core_events SET event_id=?,operation_id=?,subject_id=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                (action_event["event_id"], action_event["operation_id"], action_event["subject_id"], action_raw_event, core_independent._raw_digest("receipt", action_raw_event), action_sequence),
            )
            connection.execute(
                "UPDATE core_events SET event_id=?,operation_id=?,subject_id=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                (successor_event["event_id"], successor_event["operation_id"], successor_event["subject_id"], successor_raw_event, core_independent._raw_digest("receipt", successor_raw_event), successor_sequence),
            )
            connection.execute("UPDATE core_meta SET head_root=? WHERE meta_id=1", (successor_event["after_root"],))
            connection.execute(
                "UPDATE core_heads SET head_ref=?,head_root=? WHERE stream_kind='CASE_ACTION' AND stream_id=?",
                (action_row_id, action_event["stream_after_root"], policy["case_id"]),
            )
            connection.execute(
                "UPDATE core_heads SET head_ref=?,head_root=? WHERE stream_kind='ARTIFACT' AND stream_id=?",
                (successor_row_id, successor_event["stream_after_root"], policy["case_id"]),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:case-action"):
            core_independent.verify_database(
                tampered,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
            )

    def test_superseded_case_value_is_not_accepted(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        connection = sqlite3.connect(self.core_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=? AND kind='CASE'", (case_id,)).fetchone()
        finally:
            connection.close()
        value = json.loads(bytes(row["raw"]).decode("ascii"))
        value["state"] = "SUPERSEDED"
        value["artifact_id"] = core_independent._digest(
            "case-artifact",
            {key: value[key] for key in value if key != "artifact_id"},
        )
        rebound = {key: row[key] for key in core_independent.TABLE_COLUMNS["core_artifacts"]}
        rebound["raw"] = core_independent._canonical(value)
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:case"):
            core_independent._verify_artifact_value(rebound, self.core_config.material())

    def test_corrective_action_recovery_export_restore_parity(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        original, _successor_id, _evidence = self._record_case_action(case_id)
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        restored_ingress = self.root / "action-restored-ingress.db"
        restored_core = self.root / "action-restored-core.db"
        restored = self.recovery_service.restore_point(point.point_id, restored_ingress, restored_core)
        self.assertEqual(restored.state, "PUBLISHED")
        restored_core_service = core.CoreServiceV2(restored_core, self.core_config)
        self.assertEqual(restored_core_service.verify(ingress_path=restored_ingress)["head_root"], self.core.verify(ingress_path=self.ingress_path)["head_root"])
        self.assertEqual(original.next_state, "CASE")
        core_independent.verify_database(
            restored_core,
            expected_database_id=self.core_config.database_id,
            expected_config_digest=self.core_config.digest,
            ingress_path=restored_ingress,
        )

    def test_case_action_and_retest_concurrent_retries_are_idempotent(self) -> None:
        case_id = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        action_receipt, _action_id, evidence = self._record_case_action(case_id)
        action_results: list[core.CoreReceipt] = []
        action_errors: list[BaseException] = []

        def retry_action() -> None:
            try:
                action_results.append(self.core.record_case_action(case_id, evidence_raw=evidence))
            except BaseException as exc:
                action_errors.append(exc)

        action_threads = [threading.Thread(target=retry_action) for _ in range(2)]
        for thread in action_threads:
            thread.start()
        for thread in action_threads:
            thread.join()
        self.assertEqual([], action_errors)
        self.assertEqual(2, len(action_results))
        self.assertEqual({action_receipt.raw}, {result.raw for result in action_results})

        before_conflict = self.core.verify(ingress_path=self.ingress_path)
        with self.assertRaisesRegex(core.CoreConflictError, "core:action-verification"):
            self.core.record_case_action(case_id, evidence_raw=b"conflicting corrective evidence")
        self.assertEqual(before_conflict, self.core.verify(ingress_path=self.ingress_path))

        later = self._admit_later_source(subject_seed=None)
        current_case_id = json.loads(action_receipt.raw.decode("ascii"))["material"]["artifact_id"]
        retest_results: list[core.CoreReceipt] = []
        retest_errors: list[BaseException] = []

        def retry_retest() -> None:
            try:
                retest_results.append(self.core.evaluate_case(current_case_id, later["source_result"]["source_artifact_id"]))
            except BaseException as exc:
                retest_errors.append(exc)

        retest_threads = [threading.Thread(target=retry_retest) for _ in range(2)]
        for thread in retest_threads:
            thread.start()
        for thread in retest_threads:
            thread.join()
        self.assertEqual([], retest_errors)
        self.assertEqual(2, len(retest_results))
        self.assertEqual({retest_results[0].raw}, {result.raw for result in retest_results})

    def test_independent_rejects_cross_case_stream_rebinding_after_root_rebinding(self) -> None:
        case_a = self.core.admit_case(self.source_result["reconciliation_artifact_id"] or "")
        later = self._admit_later_source()
        case_b = self.core.admit_case(later["source_result"]["reconciliation_artifact_id"])
        _, b_action_id, _b_evidence = self._record_case_action(case_b)
        tampered = self.root / "core-cross-case-stream.db"
        shutil.copy2(self.core_path, tampered)
        connection = sqlite3.connect(tampered)
        try:
            event_row = connection.execute("SELECT sequence,event_raw FROM core_events WHERE event_kind='ARTIFACT' ORDER BY sequence DESC LIMIT 1").fetchone()
            event = json.loads(bytes(event_row[1]).decode("ascii"))
            self.assertEqual(event["material"]["artifact_id"], b_action_id)
            a_head = connection.execute("SELECT head_root FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (json.loads(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (case_a,)).fetchone()[0]).decode("ascii"))["case_id"],)).fetchone()[0]
            event["stream_id"] = json.loads(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (case_a,)).fetchone()[0]).decode("ascii"))["case_id"]
            event["stream_before_root"] = a_head
            event["event_id"] = core_independent._digest("event-id", {key: event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
            event["after_root"] = core_independent._event_root(event)
            event["stream_after_root"] = core_independent._stream_root(event)
            raw = core_independent._canonical(event)
            connection.execute("UPDATE core_events SET event_id=?,event_raw=?,receipt_digest=? WHERE sequence=?", (event["event_id"], raw, core_independent._raw_digest("receipt", raw), event_row[0]))
            connection.execute("UPDATE core_meta SET head_root=? WHERE meta_id=1", (event["after_root"],))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:case-stream"):
            core_independent.verify_database(tampered, expected_database_id=self.core_config.database_id, expected_config_digest=self.core_config.digest)

    def test_core_capacity_limits_are_executable_and_existing_oversize_refuses_service(self) -> None:
        self.assertEqual(core.MAX_DATABASE_BYTES, 64 * 1024 * 1024)
        self.assertEqual(core.MAX_ARTIFACT_BYTES, 262144)
        self.assertEqual(core.MAX_EVENT_BYTES, 786432)
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:event-raw"):
            core_independent._parse(b"x" * (core.MAX_EVENT_BYTES + 1), "core:event-raw")
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:artifact"):
            core_independent._parse(b"x" * (core.MAX_ARTIFACT_BYTES + 1), "core:artifact")
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:receipt"):
            core_independent._parse(b"x" * (core.MAX_EVENT_BYTES + 1), "core:receipt")
        before = self.core.verify()
        connection = core._connection(self.core_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(core.CoreConflictError, "core:capacity"):
                self.core._admit_artifact(connection, kind="CASE", raw=b"x" * (core.MAX_ARTIFACT_BYTES + 1), profile_digest=self.core_config.runtime_profile_digest, predecessor_id=None, source_artifact_id=None, operation_id=core._digest("oversize-artifact-operation", {"case": 1}), request_digest=core._digest("oversize-artifact-request", {"case": 1}), state="OPEN", observed_at=self.core_clock.value)
            with self.assertRaisesRegex(core.CoreConflictError, "core:capacity"):
                self.core._append(connection, kind="SESSION_OPEN", operation_id=core._digest("oversize-event-operation", {"event": 1}), subject_id="0" * 128, request_digest=core._digest("oversize-event-request", {"event": 1}), prior_state="NONE", next_state="OPEN", attempt=0, observed_at=self.core_clock.value, material={"oversize": "x" * core.MAX_EVENT_BYTES}, payload_digest="0" * 128, payload_length=0, stream_kind="SESSION", stream_id="0" * 128, head_ref="0" * 128)
            maximum_artifact_material = {
                "artifact_id": "0" * 128, "kind": "CASE",
                "raw_digest": core._raw_digest("artifact-bytes", b"\0" * core.MAX_ARTIFACT_BYTES),
                "raw_length": core.MAX_ARTIFACT_BYTES, "profile_digest": self.core_config.runtime_profile_digest,
                "source_artifact_id": None, "predecessor_id": None, "current_state": "OPEN", "ingress_watermark": 0,
            }
            maximum_event = self.core._append(connection, kind="ARTIFACT", operation_id=core._digest("maximum-artifact-event", {"case": 1}), subject_id="0" * 128, request_digest=core._digest("maximum-artifact-request", {"case": 1}), prior_state="NONE", next_state="CASE", attempt=0, observed_at=self.core_clock.value, material=maximum_artifact_material, payload_digest="0" * 128, payload_length=core.MAX_ARTIFACT_BYTES, stream_kind="ARTIFACT", stream_id="0" * 128, head_ref="0" * 128)
            self.assertLessEqual(len(maximum_event), core.MAX_EVENT_BYTES)
        finally:
            connection.rollback()
            connection.close()
        self.assertEqual(before, self.core.verify())
        oversized = self.root / "core-over-cap.db"
        shutil.copy2(self.core_path, oversized)
        with oversized.open("r+b") as stream:
            stream.seek(core.MAX_DATABASE_BYTES)
            stream.write(b"\0")
        before_bytes = oversized.read_bytes()
        with self.assertRaisesRegex(core.CoreError, "core:capacity"):
            core.CoreServiceV2(oversized, self.core_config, clock=self.core_clock)
        self.assertEqual(before_bytes, oversized.read_bytes())

    def test_open_session_enforces_inclusive_authority_windows_and_clock_free_retry(self) -> None:
        now = profile.FIXTURE_OBSERVATION_TIME + 100
        cases = (
            ("before-valid-from", now + 1, now + 10, False),
            ("at-valid-from", now, now + 10, True),
            ("at-valid-until", now - 10, now, True),
            ("after-valid-until", now - 10, now - 1, False),
        )
        for name, valid_from, valid_until, accepted in cases:
            service, _clock, source_id, governance_id, privacy_id = self._authority_only_service(name + ".db", now, valid_from, valid_until)
            if accepted:
                receipt = service.open_session(source_artifact_id=source_id, governance_artifact_id=governance_id, privacy_artifact_id=privacy_id)
                self.assertEqual("OPEN", receipt.next_state)
            else:
                with self.assertRaisesRegex(core.CoreConflictError, "core:authority-window"):
                    service.open_session(source_artifact_id=source_id, governance_artifact_id=governance_id, privacy_artifact_id=privacy_id)
        service, clock, source_id, governance_id, privacy_id = self._authority_only_service("expired-retry.db", now, now, now + 1)
        first = service.open_session(source_artifact_id=source_id, governance_artifact_id=governance_id, privacy_artifact_id=privacy_id)
        clock.value = now + 2
        clock.raise_on_read = True
        retry = service.open_session(source_artifact_id=source_id, governance_artifact_id=governance_id, privacy_artifact_id=privacy_id)
        self.assertEqual(first.raw, retry.raw)
        missing_service, _missing_clock, missing_source, missing_governance, missing_privacy = self._authority_only_service("missing-head.db", now, now, now + 10)
        connection = sqlite3.connect(missing_service.path)
        try:
            connection.execute("DELETE FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='GOVERNANCE'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core.CoreConflictError, "core:authority-head"):
            missing_service.open_session(source_artifact_id=missing_source, governance_artifact_id=missing_governance, privacy_artifact_id=missing_privacy)
        malformed_service, _malformed_clock, malformed_source, malformed_governance, malformed_privacy = self._authority_only_service("malformed-head.db", now, now, now + 10)
        connection = sqlite3.connect(malformed_service.path)
        try:
            connection.execute("UPDATE core_artifacts SET raw=? WHERE artifact_id=?", (b"{}", malformed_governance))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core.CoreConflictError, "core:authority"):
            malformed_service.open_session(source_artifact_id=malformed_source, governance_artifact_id=malformed_governance, privacy_artifact_id=malformed_privacy)

    def test_core_event_raw_reconstructs_material_and_rejects_rebound_session(self) -> None:
        tampered = self.root / "core-rebound-session.db"
        shutil.copy2(self.core_path, tampered)
        connection = sqlite3.connect(tampered)
        try:
            row = connection.execute("SELECT sequence,event_raw FROM core_events WHERE event_kind='OBSERVATION'").fetchone()
            event = json.loads(bytes(row[1]).decode("ascii"))
            event["material"]["observation"]["counts"]["observed"] = 99
            event["material_digest"] = core_independent._digest("material", event["material"])
            event["event_id"] = core_independent._digest(
                "event-id",
                {key: event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            event["after_root"] = core_independent._event_root(event)
            event["stream_after_root"] = core_independent._stream_root(event)
            raw = core_independent._canonical(event)
            connection.execute("UPDATE core_events SET event_id=?,event_raw=?,receipt_digest=? WHERE sequence=?", (event["event_id"], raw, core_independent._raw_digest("receipt", raw), row[0]))
            connection.execute("UPDATE core_meta SET head_root=? WHERE sequence=?", (event["after_root"], row[0]))
            connection.execute("UPDATE core_sessions SET head_root=? WHERE session_id=?", (event["stream_after_root"], self.session_id))
            connection.execute("UPDATE core_heads SET head_root=? WHERE stream_kind='SESSION' AND stream_id=?", (event["stream_after_root"], self.session_id))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(core_independent.CoreVerificationError):
            core_independent.verify_database(tampered, expected_database_id=self.core_config.database_id, expected_config_digest=self.core_config.digest)

    def test_core_global_clock_and_old_observation_retry_are_owner_bound(self) -> None:
        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 62
        second = self.core.observe(self.session_id, 1, "DISCREPANCY", counts={"observed": 1, "changed": 1})
        before = self.core.verify()
        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 61
        with self.assertRaisesRegex(core.CoreConflictError, "core:clock-rewind"):
            self.core.observe(self.session_id, 2, "PARITY", counts={"observed": 2, "changed": 0})
        self.assertEqual(before["head_root"], self.core.verify()["head_root"])
        self.core_clock.raise_on_read = True
        retry = self.core.observe(self.session_id, 0, "PARITY", counts={"observed": 1, "changed": 0})
        self.assertEqual(retry.raw, self.core.observe(self.session_id, 0, "PARITY", counts={"observed": 1, "changed": 0}).raw)
        self.assertNotEqual(second.raw, retry.raw)

    def test_core_observation_cadence_rejects_early_slot_without_mutation(self) -> None:
        before = self.core.verify()
        self.core_clock.value = profile.FIXTURE_OBSERVATION_TIME + 10
        with self.assertRaisesRegex(core.CoreConflictError, "core:observation-cadence"):
            self.core.observe(self.session_id, 1, "PARITY", counts={"observed": 1, "changed": 0})
        after = self.core.verify()
        self.assertEqual(before["head_root"], after["head_root"])
        self.assertEqual(before["event_count"], after["event_count"])

    def test_owner_clock_rewind_rejects_without_mutation(self) -> None:
        service, slot_id = self._fresh_ingress("clock-rewind.db")
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-clock"))
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME - 1
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:clock-rewind"):
            service.claim_slot(slot_id, lease_token=_ingress_token("lease-rewind"))
        self.assertEqual(before, self._state_fingerprint(service))

    def test_owner_clock_binds_all_capture_events_to_one_time(self) -> None:
        service, slot_id = self._fresh_ingress("owner-time.db")
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + 5
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-owner-time"))
        service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-owner-time"),
        )
        connection = sqlite3.connect(service.path)
        try:
            rows = connection.execute(
                "SELECT event_kind, observed_at, event_raw FROM ingress_events WHERE event_kind IN ('FETCH_ATTESTATION','CAPTURE','BEGIN_QUARANTINE','ADMIT') ORDER BY sequence"
            ).fetchall()
        finally:
            connection.close()
        self.assertTrue(rows)
        expected = profile.FIXTURE_OBSERVATION_TIME + 5
        self.assertEqual({expected}, {int(row[1]) for row in rows})
        self.assertTrue(all(json.loads(bytes(row[2]).decode("ascii"))["observed_at"] == expected for row in rows))

    def test_committed_retry_after_lease_expiry_is_byte_identical(self) -> None:
        before = self.ingress_receipt
        state_before = self._state_fingerprint(self.ingress)
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.lease_seconds + 1
        self.clock.raise_on_read = True
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:operation-conflict"):
            self.ingress.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=_ingress_token("wrong-after-commit"),
            )
        self.assertEqual(state_before, self._state_fingerprint(self.ingress))
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:operation-conflict"):
            self.ingress.admit_capture(
                self.envelope,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=2,
                lease_token=_ingress_token("lease-v2"),
            )
        self.assertEqual(state_before, self._state_fingerprint(self.ingress))
        retry = self.ingress.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-v2"),
        )
        self.assertEqual(before.raw, retry.raw)
        self.assertEqual(state_before, self._state_fingerprint(self.ingress))

    def test_cross_slot_owner_clock_rewind_reaches_global_independent_rule(self) -> None:
        self.clock.value = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds
        second_slot = self.ingress.ensure_slot(self.clock.value)
        second_slot_id = json.loads(second_slot.raw.decode("ascii"))["slot_id"]
        tampered = self.root / "global-clock-rewind.db"
        shutil.copy2(self.ingress_path, tampered)
        connection = sqlite3.connect(tampered)
        try:
            row = connection.execute(
                "SELECT sequence,event_raw FROM ingress_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            sequence = int(row[0])
            event = json.loads(bytes(row[1]).decode("ascii"))
            self.assertEqual(second_slot_id, event["slot_id"])
            event["observed_at"] = profile.FIXTURE_OBSERVATION_TIME - 1
            event["event_id"] = ingress_independent._digest(
                "event-id",
                {
                    key: event[key]
                    for key in ingress_independent.EVENT_KEYS
                    if key not in {"event_id", "after_root", "stream_after_root"}
                },
            )
            event["after_root"] = ingress_independent._event_root(
                sequence=event["sequence"],
                previous=event["before_root"],
                event_id=event["event_id"],
                event_kind=event["event_kind"],
                stream_kind=event["stream_kind"],
                stream_id=event["stream_id"],
                slot_id=event["slot_id"],
                next_state=event["next_state"],
                observed_at=event["observed_at"],
                material_digest=event["material_digest"],
            )
            event["stream_after_root"] = ingress_independent._stream_root(
                sequence=event["sequence"],
                previous=event["stream_before_root"],
                event_id=event["event_id"],
                stream_kind=event["stream_kind"],
                stream_id=event["stream_id"],
                next_state=event["next_state"],
                observed_at=event["observed_at"],
                material_digest=event["material_digest"],
            )
            event_raw = ingress_independent._canonical(event)
            receipt_digest = ingress_independent._raw_digest("receipt", event_raw)
            connection.execute(
                "UPDATE ingress_events SET event_id=?,observed_at=?,after_root=?,stream_after_root=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                (
                    event["event_id"], event["observed_at"], event["after_root"],
                    event["stream_after_root"], event_raw, receipt_digest, sequence,
                ),
            )
            connection.execute("UPDATE ingress_meta SET head_root=? WHERE sequence=?", (event["after_root"], sequence))
            connection.execute(
                "UPDATE ingress_heads SET head_root=? WHERE stream_kind=? AND stream_id=?",
                (event["stream_after_root"], event["stream_kind"], event["stream_id"]),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:event-chronology"):
            ingress_independent.verify_database(
                tampered,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )

    def test_cross_slot_owner_clock_rewind_rejects_without_mutation(self) -> None:
        base = profile.FIXTURE_OBSERVATION_TIME
        config = ingress.IngressConfigV2(
            database_id="ingress-global-clock-synthetic",
            chain_id="ingress-global-clock-chain",
            policy_digest=self.ingress_config.policy_digest,
            authorization_digest=self.ingress_config.authorization_digest,
            terms_digest=self.ingress_config.terms_digest,
            cadence_seconds=self.ingress_config.cadence_seconds,
            effective_start=self.ingress_config.effective_start,
            effective_end=self.ingress_config.effective_end,
            max_slots=self.ingress_config.max_slots,
            max_attempts=self.ingress_config.max_attempts,
            lease_seconds=300,
        )
        clock = _ManualClock(base)
        service = ingress.IngressServiceV2(self.root / "global-clock-owner.db", config, clock=clock)
        first = service.ensure_slot(base)
        first_slot_id = json.loads(first.raw.decode("ascii"))["slot_id"]
        service.claim_slot(first_slot_id, lease_token=_ingress_token("lease-first"))
        clock.value = base + self.ingress_config.cadence_seconds
        second = service.ensure_slot(clock.value)
        second_slot_id = json.loads(second.raw.decode("ascii"))["slot_id"]
        clock.value = base + 100
        service.admit_capture(self.envelope, evidence_raw=_external_evidence(self.ingress_config, self.envelope), scheduled_at=base, attempt=1, lease_token=_ingress_token("lease-first"))
        clock.value = base + 90
        before = self._state_fingerprint(service)
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:clock-rewind"):
            service.claim_slot(second_slot_id, lease_token=_ingress_token("lease-second"))
        self.assertEqual(before, self._state_fingerprint(service))

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
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-retry"))
        service.admit_capture(
            retry_envelope,
            evidence_raw=_external_evidence(self.ingress_config, retry_envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-retry"),
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

    def test_fetch_capture_operation_is_cross_bound_across_rehashed_event_chain(self) -> None:
        single = self.root / "rebound-fetch-capture.db"
        shutil.copy2(self.ingress_path, single)
        connection = sqlite3.connect(single)
        try:
            sequence = connection.execute(
                "SELECT sequence FROM ingress_events WHERE event_kind='FETCH_ATTESTATION'"
            ).fetchone()[0]
        finally:
            connection.close()
        _rechain_ingress_with_fetch_capture_rebind(single, {int(sequence): "f" * 128})
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:fetch-capture-binding"):
            ingress_independent.verify_database(
                single,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )

        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle, _transport

        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        success = fhir.fixture_response(_bundle(), request_url)
        retry_envelope = fhir.build_fixture_envelope(
            _transport(_bundle(), retries={(request_url, 0): throttled, (request_url, 1): success})
        )
        service, slot_id = self._fresh_ingress("rebound-fetch-attempts.db")
        token = _ingress_token("rebound-fetch-attempts")
        service.claim_slot(slot_id, lease_token=token)
        service.admit_capture(
            retry_envelope,
            evidence_raw=_external_evidence(self.ingress_config, retry_envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=token,
        )
        two_fetch = self.root / "rebound-two-fetch-operations.db"
        shutil.copy2(service.path, two_fetch)
        connection = sqlite3.connect(two_fetch)
        try:
            second = connection.execute(
                "SELECT sequence FROM ingress_events WHERE event_kind='FETCH_ATTESTATION' AND transport_attempt=1"
            ).fetchone()[0]
        finally:
            connection.close()
        _rechain_ingress_with_fetch_capture_rebind(two_fetch, {int(second): "e" * 128})
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:fetch-capture-binding"):
            ingress_independent.verify_database(
                two_fetch,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )

    def test_failed_attempt_events_remain_failure_evidence(self) -> None:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle

        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        failed_envelope = fhir.build_fixture_envelope(fhir.SyntheticFhirTransport({(request_url, 0): throttled}))
        service, slot_id = self._fresh_ingress("failed-capture.db")
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-failed"))
        receipt = service.admit_capture(
            failed_envelope,
            evidence_raw=_external_evidence(self.ingress_config, failed_envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-failed"),
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
        service.claim_slot(slot_id, lease_token=_ingress_token("lease-order"))
        service.admit_capture(
            raw,
            evidence_raw=_external_evidence(self.ingress_config, raw),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("lease-order"),
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

    def _authority_only_service(self, name: str, now: int, valid_from: int, valid_until: int) -> tuple[core.CoreServiceV2, _ManualClock, str, str, str]:
        path = self.root / name
        clock = _ManualClock(now)
        service = core.CoreServiceV2(path, self.core_config, clock=clock)
        connection = core._connection(path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            source_raw = core._canonical({"schema": "mirror-core-source-observation-v3", "schema_version": 3, "kind": "SOURCE_OBSERVATION", "artifact_id": "0" * 128, "runtime_profile_digest": self.core_config.runtime_profile_digest})
            governance_raw = core._canonical({"schema": "mirror-core-governance-v3", "schema_version": 3, "kind": "GOVERNANCE", "artifact_id": "0" * 128, "decision": "GRANTED", "policy_digest": self.core_config.governance_policy_digest, "valid_from": valid_from, "valid_until": valid_until, "flags": dict(core.FIXED_FLAGS)})
            privacy_raw = core._canonical({"schema": "mirror-core-privacy-v3", "schema_version": 3, "kind": "PRIVACY", "artifact_id": "0" * 128, "privacy_decision": "GRANTED", "support_decision": "GRANTED", "policy_digest": self.core_config.privacy_policy_digest, "valid_from": valid_from, "valid_until": valid_until, "flags": dict(core.FIXED_FLAGS)})
            source_id, _ = service._admit_artifact(connection, kind="SOURCE_OBSERVATION", raw=source_raw, profile_digest=self.core_config.runtime_profile_digest, predecessor_id=None, source_artifact_id=None, operation_id=core._digest("test-source-operation", {"name": name}), request_digest=core._digest("test-source-request", {"name": name}), state="OBSERVED_NEW", observed_at=now)
            governance_id, _ = service._admit_artifact(connection, kind="GOVERNANCE", raw=governance_raw, profile_digest=self.core_config.governance_policy_digest, predecessor_id=None, source_artifact_id=None, operation_id=core._digest("test-governance-operation", {"name": name}), request_digest=core._digest("test-governance-request", {"name": name}), state="GRANTED", observed_at=now)
            privacy_id, _ = service._admit_artifact(connection, kind="PRIVACY", raw=privacy_raw, profile_digest=self.core_config.privacy_policy_digest, predecessor_id=None, source_artifact_id=None, operation_id=core._digest("test-privacy-operation", {"name": name}), request_digest=core._digest("test-privacy-request", {"name": name}), state="GRANTED", observed_at=now)
            connection.commit()
            return service, clock, source_id, governance_id, privacy_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _admit_later_source(self, *, subject_seed: str | None = "case-second-subject", location_variant: str = "changed") -> dict[str, object]:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle

        observation_time = profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds
        if subject_seed is None:
            subject_id = profile.DEFAULT_CAPTURE_CONTEXT.subject_id
            credential_id = profile.DEFAULT_CAPTURE_CONTEXT.credential_id
            enrollment_id = profile.DEFAULT_CAPTURE_CONTEXT.enrollment_id
            locator_digest = profile.DEFAULT_CAPTURE_CONTEXT.subject_locator_digest
            lease_seed = "case-same-subject"
        else:
            subject_id = _hex(subject_seed)
            credential_id = _hex(subject_seed + "-credential")
            enrollment_id = _hex(subject_seed + "-enrollment")
            locator_digest = _hex(subject_seed + "-locator")
            lease_seed = subject_seed
        context = profile.DynamicCaptureContext(
            subject_id,
            credential_id,
            enrollment_id,
            locator_digest,
            observation_time,
            observation_time + 10,
        )
        request_url = profile.NC_MEDICAID_PROFILE.page_url(0, context)
        bundle = _bundle(location_variant=location_variant)
        bundle["link"] = [{"relation": "self", "url": request_url}]
        transport = fhir.SyntheticFhirTransport({
            (request_url, 0): fhir.fixture_response(bundle, request_url),
        })
        envelope = fhir.build_fixture_envelope(transport, context=context)
        self.clock.value = observation_time
        created = self.ingress.ensure_slot(observation_time)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        token = _ingress_token(lease_seed + "-lease")
        self.ingress.claim_slot(slot_id, lease_token=token)
        receipt = self.ingress.admit_capture(
            envelope,
            evidence_raw=_external_evidence(self.ingress_config, envelope),
            scheduled_at=observation_time,
            attempt=1,
            lease_token=token,
        )
        self.core_clock.value = observation_time + 2
        result = self.core.ingest_source(self.ingress_path, receipt.artifact_id or "")
        return {"source_result": result, "artifact_id": receipt.artifact_id or "", "observation_time": observation_time, "envelope": envelope}

    def _record_case_action(self, case_artifact_id: str) -> tuple[core.CoreReceipt, str, bytes]:
        evidence = b"synthetic corrective evidence"
        receipt = self.core.record_case_action(case_artifact_id, evidence_raw=evidence)
        action_value = json.loads(receipt.raw.decode("ascii"))["material"]
        return receipt, str(action_value["artifact_id"]), evidence

    def test_exact_three_owner_tables_and_full_chain(self) -> None:
        point = self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual(point.state, "VERIFIED")
        self.assertEqual(self.recovery_service.create_point(self.ingress_path, self.core_path, generation=1).raw, point.raw)
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

    def test_fetch_attestations_are_typed_events_and_core_has_no_delivery_subsystem(self) -> None:
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
        core_connection = sqlite3.connect(self.core_path)
        try:
            self.assertNotIn("DELIVERY", {row[0] for row in core_connection.execute("SELECT DISTINCT event_kind FROM core_events")})
        finally:
            core_connection.close()
        self.assertEqual(self.core.verify(ingress_path=self.ingress_path)["event_count"], 8)

    def test_raw_envelope_is_ingress_only_and_exports_are_raw_free(self) -> None:
        connection = sqlite3.connect(self.ingress_path)
        try:
            rows = connection.execute("SELECT raw FROM ingress_artifacts").fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 1)
        intake_frame = bytes(rows[0][0])
        self.assertEqual(intake_frame.count(self.envelope), 1)
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

    def test_default_ingress_projection_is_an_explicit_allowlist(self) -> None:
        artifact_id = self.ingress_receipt.artifact_id or ""
        internal = ingress_independent.read_artifact_snapshot(self.ingress_path, artifact_id)
        public = self.ingress.verify()
        current = public["current_artifact"]
        self.assertEqual(
            {
                "profile_id", "profile_version", "source_status", "failure_code",
                "freshness", "page_complete", "page_count", "resource_count",
                "event_sequence",
            },
            set(current),
        )
        logical = self.ingress.logical_export()
        self.assertIn(b"mirror-ingress-logical-export-v3", logical)
        context = internal["capture_context"]
        identity_canaries = tuple(str(context[key]) for key in (
            "subject_id", "credential_id", "enrollment_id", "subject_locator_digest",
        ))
        raw_canaries = (
            bytes(internal["raw"]), bytes(internal["envelope_raw"]),
            bytes(internal["external_evidence_raw"]),
        )
        public_surfaces = (
            repr(public).encode("ascii"), logical,
            json.dumps(self.ingress.support(), sort_keys=True).encode("ascii"),
            self.ingress_receipt.raw,
        )
        for canary in identity_canaries:
            with self.subTest(identity=canary):
                self.assertTrue(all(canary.encode("ascii") not in surface for surface in public_surfaces))
        for canary in raw_canaries:
            with self.subTest(raw_length=len(canary)):
                self.assertTrue(all(canary not in surface for surface in public_surfaces))
        for field in (
            "capture_context", "capture_id", "envelope_id", "envelope_digest",
            "snapshot_id", "snapshot_root", "content_root", "external_artifact_id",
            "raw", "intake_frame", "envelope_raw", "external_evidence_raw",
        ):
            self.assertNotIn(field, current)

    def test_core_reconciliation_predecessor_is_not_a_source_artifact(self) -> None:
        self._admit_later_source()
        path = self.root / "rebound-reconciliation-predecessor.db"
        shutil.copy2(self.core_path, path)
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(
                "SELECT artifact_id,source_artifact_id,raw,profile_digest,predecessor_id FROM core_artifacts WHERE kind='RECONCILIATION' ORDER BY created_event_sequence"
            ).fetchall()
            self.assertEqual(2, len(rows))
            second_id = rows[1][0]
            wrong_predecessor = rows[0][1]
            raw = bytes(rows[1][2])
            new_id = core_independent._digest(
                "artifact-row-id",
                {
                    "kind": "RECONCILIATION",
                    "raw": core_independent._raw_digest("artifact-bytes", raw),
                    "profile_digest": rows[1][3],
                    "source_artifact_id": rows[1][1],
                    "predecessor_id": wrong_predecessor,
                },
            )
            connection.execute(
                "UPDATE core_artifacts SET artifact_id=?,predecessor_id=? WHERE artifact_id=?",
                (new_id, wrong_predecessor, second_id),
            )
            event_row = None
            for candidate in connection.execute(
                "SELECT sequence,event_raw FROM core_events WHERE event_kind='ARTIFACT' ORDER BY sequence"
            ).fetchall():
                candidate_value = json.loads(bytes(candidate[1]).decode("ascii"))
                if candidate_value["material"]["artifact_id"] == second_id:
                    event_row = candidate
                    break
            self.assertIsNotNone(event_row)
            event = json.loads(bytes(event_row[1]).decode("ascii"))
            material = dict(event["material"])
            material["artifact_id"] = new_id
            material["predecessor_id"] = wrong_predecessor
            event["material"] = material
            event["material_digest"] = core_independent._digest("material", material)
            event["payload_digest"] = new_id
            event["event_id"] = core_independent._digest(
                "event-id",
                {key: event[key] for key in core_independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            event["after_root"] = core_independent._event_root(event)
            event["stream_after_root"] = core_independent._stream_root(event)
            event_raw = core_independent._canonical(event)
            connection.execute(
                "UPDATE core_events SET event_id=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                (
                    event["event_id"], event_raw,
                    core_independent._raw_digest("receipt", event_raw), event_row[0],
                ),
            )
            connection.execute(
                "UPDATE core_heads SET head_ref=?,head_root=? WHERE stream_kind='ARTIFACT' AND stream_id='RECONCILIATION'",
                (new_id, event["stream_after_root"]),
            )
            connection.execute("UPDATE core_meta SET head_root=? WHERE meta_id=1", (event["after_root"],))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:reconciliation-chain"):
            core_independent.verify_database(
                path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
            )

    def test_core_rejects_held_intake_before_first_mutation(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _rebind

        held_path = self.root / "held-intake.db"
        held_service = ingress.IngressServiceV2(held_path, self.ingress_config, clock=self.clock)
        created = held_service.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        held_service.claim_slot(slot_id, lease_token=_ingress_token("held-intake"))
        partial_value = json.loads(self.envelope.decode("ascii"))
        partial_value["source_status"] = "PARTIAL"
        partial_value["page_complete"] = False
        partial = _rebind(partial_value)
        held_receipt = held_service.admit_capture(
            partial,
            evidence_raw=_external_evidence(self.ingress_config, partial),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("held-intake"),
        )
        self.assertEqual("HELD", held_receipt.next_state)
        before = core.CoreServiceV2(self.root / "held-core.db", self.core_config, clock=self.core_clock).verify()
        held_core = core.CoreServiceV2(self.root / "held-core.db", self.core_config, clock=self.core_clock)
        with self.assertRaisesRegex(core.CoreConflictError, "core:source-lifecycle"):
            held_core.ingest_source(held_path, held_receipt.artifact_id or "")
        after = held_core.verify()
        self.assertEqual(before["sequence"], after["sequence"])
        self.assertEqual(before["artifact_count"], after["artifact_count"])

    def test_phi_rebound_is_rejected_before_ingress_mutation_or_persistence(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _rebind

        path = self.root / "phi-rebound-ingress.db"
        service, slot_id = self._fresh_ingress(path.name)
        token = _ingress_token("phi-rebound")
        service.claim_slot(slot_id, lease_token=token)
        before_state = self._state_fingerprint(service)
        before_bytes = path.read_bytes()
        value = json.loads(self.envelope.decode("ascii"))
        practitioner = value["pages"][0]["bundle"]["entry"][0]["resource"]
        practitioner["identifier"][0]["value"] = "REAL-PATIENT-123"
        practitioner["name"][0]["family"] = "Jane Patient SSN 123"
        practitioner["name"][0]["given"] = ["jane@example.com"]
        rebound = _rebind(value)
        canaries = (b"REAL-PATIENT-123", b"Jane Patient SSN 123", b"jane@example.com")
        with self.assertRaisesRegex(ingress.IngressError, "ingress:envelope-reject") as captured:
            service.admit_capture(
                rebound,
                evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=token,
            )
        self.assertTrue(all(canary.decode("ascii") not in str(captured.exception) for canary in canaries))
        self.assertEqual(before_state, self._state_fingerprint(service))
        self.assertEqual(before_bytes, path.read_bytes())
        self.assertTrue(all(canary not in path.read_bytes() for canary in canaries))
        self.assertTrue(all(canary not in service.logical_export() for canary in canaries))
        self.assertTrue(all(canary.decode("ascii") not in json.dumps(service.support(), sort_keys=True) for canary in canaries))

    def test_complete_frame_binding_and_concurrent_idempotency(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _envelope

        self.assertEqual(262_144, profile.COMPLETE_FRAME_CAP_BYTES)
        self.assertEqual(profile.COMPLETE_FRAME_CAP_BYTES, ingress.MAX_COMPLETE_FRAME_BYTES)
        self.assertEqual(profile.COMPLETE_FRAME_CAP_BYTES, ingress_independent.MAX_COMPLETE_FRAME_BYTES)
        self.assertEqual(profile.COMPLETE_FRAME_CAP_BYTES, core.MAX_COMPLETE_FRAME_BYTES)
        connection = sqlite3.connect(self.ingress_path)
        try:
            frame = bytes(connection.execute("SELECT raw FROM ingress_artifacts").fetchone()[0])
        finally:
            connection.close()
        self.assertLessEqual(len(frame), profile.COMPLETE_FRAME_CAP_BYTES)
        evidence_raw, envelope_raw, directory = ingress_independent._unpack_intake_frame(frame)
        self.assertEqual(envelope_raw, self.envelope)
        self.assertEqual(tuple(index for index, _offset, _length, _digest in directory), (0,))
        self.assertTrue(evidence_raw)
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:intake-frame"):
            ingress_independent._unpack_intake_frame(frame[:-1])
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:intake-frame"):
            ingress_independent._unpack_intake_frame(frame + b"\0")
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:artifact-raw"):
            ingress_independent._unpack_intake_frame(b"x" * (profile.COMPLETE_FRAME_CAP_BYTES + 1))

        service, slot_id = self._fresh_ingress("concurrent-frame.db")
        token = _ingress_token("concurrent-frame")
        service.claim_slot(slot_id, lease_token=token)
        barrier = threading.Barrier(2)
        receipts: list[ingress.IngressReceipt] = []
        errors: list[BaseException] = []

        def admit_same_frame() -> None:
            try:
                barrier.wait()
                receipts.append(service.admit_capture(
                    self.envelope,
                    evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                    scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                    attempt=1,
                    lease_token=token,
                ))
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=admit_same_frame) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        self.assertEqual(2, len(receipts))
        self.assertEqual(receipts[0].raw, receipts[1].raw)
        self.assertEqual(1, service.verify()["artifact_count"])

        conflict_service, conflict_slot = self._fresh_ingress("same-operation-different-frame.db")
        conflict_token = _ingress_token("same-operation-frame")
        conflict_service.claim_slot(conflict_slot, lease_token=conflict_token)
        operation_id = "same-operation-frame"
        conflict_service.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=conflict_token,
            operation_id=operation_id,
        )
        before = self._state_fingerprint(conflict_service)
        changed = _envelope(location_variant="changed")
        with self.assertRaisesRegex(ingress.IngressConflictError, "ingress:operation-conflict"):
            conflict_service.admit_capture(
                changed,
                evidence_raw=_external_evidence(self.ingress_config, changed),
                scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
                attempt=1,
                lease_token=conflict_token,
                operation_id=operation_id,
            )
        self.assertEqual(before, self._state_fingerprint(conflict_service))

    def test_two_dynamic_captures_share_static_contract_and_reach_core(self) -> None:
        from app.mirror import nc_medicaid_fhir as fhir
        from tests.test_nc_medicaid_fhir_source import _bundle

        context = profile.DynamicCaptureContext(
            "5" * 128, "6" * 128, "7" * 128, "8" * 128, 7_060, 7_070,
        )
        bundle = _bundle(location_variant="changed")
        request_url = profile.NC_MEDICAID_PROFILE.page_url(0, context)
        bundle["link"][0]["url"] = request_url
        dynamic_envelope = fhir.build_fixture_envelope(
            fhir.SyntheticFhirTransport({
                (request_url, 0): fhir.fixture_response(bundle, request_url),
            }),
            context=context,
        )
        self.assertEqual(
            profile.NC_MEDICAID_PROFILE.profile_digest,
            fhir_independent.verify_bytes(dynamic_envelope)["source_contract_digest"],
        )
        self.clock.value = context.observation_time
        created = self.ingress.ensure_slot(context.observation_time)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        token = _ingress_token("dynamic-second-capture")
        self.ingress.claim_slot(slot_id, lease_token=token)
        receipt = self.ingress.admit_capture(
            dynamic_envelope,
            evidence_raw=_external_evidence(self.ingress_config, dynamic_envelope),
            scheduled_at=context.observation_time,
            attempt=1,
            lease_token=token,
        )
        self.assertEqual("QUARANTINED", receipt.next_state)
        before_core = self.core.verify(ingress_path=self.ingress_path)
        result = self.core.ingest_source(self.ingress_path, receipt.artifact_id or "")
        self.assertEqual(profile.NC_MEDICAID_PROFILE.profile_digest, result["receipt"].raw.decode("ascii").split('"profile_digest":"', 1)[1].split('"', 1)[0])
        self.assertEqual("OBSERVED_CHANGED", result["observation_status"])
        self.assertEqual(before_core["artifact_count"] + 3, self.core.verify(ingress_path=self.ingress_path)["artifact_count"])

    def test_profile_owned_changed_observation_rejects_equal_time_without_authority(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _envelope
        changed_path = self.root / "changed-ingress.db"
        scheduled_at = profile.FIXTURE_OBSERVATION_TIME
        changed_clock = _ManualClock(scheduled_at)
        changed_ingress = ingress.IngressServiceV2(changed_path, self.ingress_config, clock=changed_clock)
        created = changed_ingress.ensure_slot(scheduled_at)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        changed_ingress.claim_slot(slot_id, lease_token=_ingress_token("lease-v2-changed"))
        changed_receipt = changed_ingress.admit_capture(
            _envelope(location_variant="changed"),
            evidence_raw=_external_evidence(self.ingress_config, _envelope(location_variant="changed")),
            scheduled_at=scheduled_at,
            attempt=1,
            lease_token=_ingress_token("lease-v2-changed"),
        )
        ingress_independent.verify_database(changed_path, expected_database_id=self.ingress_config.database_id, expected_config_digest=self.ingress_config.digest)
        before = self.core.verify()
        with self.assertRaisesRegex(core.CoreConflictError, "core:source-predecessor"):
            self.core.ingest_source(changed_path, changed_receipt.artifact_id or "")
        after = self.core.verify()
        self.assertEqual(before["sequence"], after["sequence"])
        self.assertEqual(before["head_root"], after["head_root"])
        self.assertFalse(after["flags"]["payment_authority"])

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

        with self.assertRaisesRegex(ingress.IngressError, "ingress:database"):
            ingress.IngressServiceV2(bad_ingress, self.ingress_config)
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
            observed_plan = " ".join(str(row) for row in connection.execute("EXPLAIN QUERY PLAN SELECT observed_at FROM ingress_events ORDER BY observed_at DESC,sequence DESC LIMIT 1"))
            self.assertIn("ingress_events_observed_at_idx", observed_plan)
            self.assertEqual(
                ingress_independent._index_definitions(connection),
                ingress_independent.INDEX_DEFINITIONS,
            )
        finally:
            connection.close()
        bad_index = self.root / "bad-observed-index.db"
        shutil.copy2(self.ingress_path, bad_index)
        connection = sqlite3.connect(bad_index)
        try:
            connection.execute("DROP INDEX ingress_events_observed_at_idx")
            connection.execute(
                "CREATE INDEX ingress_events_observed_at_idx ON ingress_events(sequence,observed_at)"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:indexes"):
            ingress_independent.verify_database(
                bad_index,
                expected_database_id=self.ingress_config.database_id,
                expected_config_digest=self.ingress_config.digest,
            )
        connection = sqlite3.connect(self.core_path)
        try:
            plan = " ".join(str(row) for row in connection.execute("EXPLAIN QUERY PLAN SELECT artifact_id FROM core_artifacts WHERE kind='SOURCE_OBSERVATION' AND source_artifact_id=? ORDER BY created_event_sequence", (self.source_result["source_artifact_id"],)))
            self.assertIn("core_artifacts_kind_source_event_idx", plan)
            explicit = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")}
            self.assertEqual({"core_artifacts_kind_source_event_idx"}, explicit)
        finally:
            connection.close()

    def test_ingress_config_material_slot_projection_and_rehashed_event_are_bound(self) -> None:
        connection = sqlite3.connect(self.ingress_path)
        try:
            meta = connection.execute("SELECT config_raw,config_digest FROM ingress_meta WHERE meta_id=1").fetchone()
            self.assertIsNotNone(meta)
            self.assertEqual(bytes(meta[0]), ingress_independent._canonical(self.ingress_config.material()))
            self.assertEqual(meta[1], ingress_independent._digest("config", self.ingress_config.material()))
        finally:
            connection.close()

        bad_config = self.root / "bad-ingress-config-material.db"
        shutil.copy2(self.ingress_path, bad_config)
        connection = sqlite3.connect(bad_config)
        try:
            raw, _digest_value = connection.execute("SELECT config_raw,config_digest FROM ingress_meta WHERE meta_id=1").fetchone()
            config_value = json.loads(bytes(raw).decode("ascii"))
            config_value["cadence_seconds"] = self.ingress_config.cadence_seconds * 2
            config_raw = ingress_independent._canonical(config_value)
            connection.execute(
                "UPDATE ingress_meta SET config_raw=?,config_digest=? WHERE meta_id=1",
                (config_raw, ingress_independent._digest("config", config_value)),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:(slot|event|config)"):
            ingress_independent.verify_database(bad_config)

        for field, replacement in (("scheduled_at", profile.FIXTURE_OBSERVATION_TIME + self.ingress_config.cadence_seconds), ("operation_id", "0" * 128)):
            bad_slot = self.root / ("bad-slot-" + field + ".db")
            shutil.copy2(self.ingress_path, bad_slot)
            connection = sqlite3.connect(bad_slot)
            try:
                connection.execute(f"UPDATE ingress_slots SET {field}=?", (replacement,))
                connection.commit()
            finally:
                connection.close()
            with self.subTest(field=field):
                with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:slot"):
                    ingress_independent.verify_database(bad_slot)

        bad_event = self.root / "bad-rehashed-ingress-material.db"
        shutil.copy2(self.ingress_path, bad_event)
        connection = sqlite3.connect(bad_event)
        try:
            row = connection.execute("SELECT sequence,event_raw FROM ingress_events WHERE event_kind='ADMIT'").fetchone()
            value = json.loads(bytes(row[1]).decode("ascii"))
            value["material"]["decision"] = "HELD"
            value["material_digest"] = ingress_independent._digest("material", value["material"])
            value["event_id"] = ingress_independent._digest(
                "event-id",
                {key: value[key] for key in ingress_independent.EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
            )
            value["after_root"] = ingress_independent._event_root(
                sequence=value["sequence"], previous=value["before_root"], event_id=value["event_id"],
                event_kind=value["event_kind"], stream_kind=value["stream_kind"], stream_id=value["stream_id"],
                slot_id=value["slot_id"], next_state=value["next_state"], observed_at=value["observed_at"],
                material_digest=value["material_digest"],
            )
            value["stream_after_root"] = ingress_independent._stream_root(
                sequence=value["sequence"], previous=value["stream_before_root"], event_id=value["event_id"],
                stream_kind=value["stream_kind"], stream_id=value["stream_id"], next_state=value["next_state"],
                observed_at=value["observed_at"], material_digest=value["material_digest"],
            )
            event_raw = ingress_independent._canonical(value)
            connection.execute(
                "UPDATE ingress_events SET event_id=?,material_digest=?,after_root=?,stream_after_root=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                (value["event_id"], value["material_digest"], value["after_root"], value["stream_after_root"], event_raw, ingress_independent._raw_digest("receipt", event_raw), row[0]),
            )
            connection.execute("UPDATE ingress_meta SET head_root=? WHERE meta_id=1", (value["after_root"],))
            connection.execute(
                "UPDATE ingress_heads SET head_root=? WHERE stream_kind='QUARANTINE' AND stream_id=?",
                (value["stream_after_root"], self.ingress_config.chain_id),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(ingress_independent.IngressVerificationError, "ingress:event-artifact"):
            ingress_independent.verify_database(bad_event)

    def test_core_rejects_valid_ingress_with_different_pinned_config(self) -> None:
        alternate_config = ingress.IngressConfigV2(
            database_id=self.ingress_config.database_id,
            chain_id=self.ingress_config.chain_id,
            policy_digest=self.ingress_config.policy_digest,
            authorization_digest=self.ingress_config.authorization_digest,
            terms_digest=_hex("alternate-ingress-terms"),
            effective_start=self.ingress_config.effective_start,
            effective_end=self.ingress_config.effective_end,
            cadence_seconds=self.ingress_config.cadence_seconds,
            max_slots=self.ingress_config.max_slots,
            max_attempts=self.ingress_config.max_attempts,
            lease_seconds=self.ingress_config.lease_seconds,
        )
        alternate_path = self.root / "alternate-ingress-config.db"
        alternate_clock = _ManualClock(profile.FIXTURE_OBSERVATION_TIME)
        alternate = ingress.IngressServiceV2(alternate_path, alternate_config, clock=alternate_clock)
        created = alternate.ensure_slot(profile.FIXTURE_OBSERVATION_TIME)
        slot_id = json.loads(created.raw.decode("ascii"))["slot_id"]
        alternate.claim_slot(slot_id, lease_token=_ingress_token("alternate-config"))
        alternate_receipt = alternate.admit_capture(
            self.envelope,
            evidence_raw=_external_evidence(alternate_config, self.envelope),
            scheduled_at=profile.FIXTURE_OBSERVATION_TIME,
            attempt=1,
            lease_token=_ingress_token("alternate-config"),
        )
        self.assertIsNotNone(alternate_receipt.artifact_id)
        ingress_independent.verify_database(alternate_path, expected_database_id=alternate_config.database_id, expected_config_digest=alternate_config.digest)
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:(config|ingress-binding|database)"):
            core_independent.verify_database(
                self.core_path,
                expected_database_id=self.core_config.database_id,
                expected_config_digest=self.core_config.digest,
                ingress_path=alternate_path,
            )

    def test_core_independent_binds_graph_artifact_to_envelope_derived_input(self) -> None:
        from app.mirror import nc_medicaid_fhir_independent as fhir_independent
        from app.mirror import provider_trust_graph as graph_producer
        from app.mirror import provider_trust_graph_independent as graph_independent
        from tests.test_nc_medicaid_fhir_source import _envelope

        envelope_b = _envelope(location_variant="changed")
        self.assertNotEqual(self.envelope, envelope_b)
        fhir_independent.verify_bytes(envelope_b)
        coverage_a = fhir_independent.to_verified_source_coverage(
            fhir_independent.verify_bytes(self.envelope)
        )
        registry = {coverage_a.graph_profile.profile_id: coverage_a.graph_profile}
        connection = sqlite3.connect(self.core_path)
        try:
            graph_raw = bytes(connection.execute("SELECT raw FROM core_artifacts WHERE kind='GRAPH'").fetchone()[0])
            source_raw = bytes(connection.execute("SELECT raw FROM core_artifacts WHERE kind='SOURCE_OBSERVATION'").fetchone()[0])
        finally:
            connection.close()
        source_value = json.loads(source_raw.decode("ascii"))
        verified_a = graph_independent.verify_artifact_v2(graph_raw, registry)
        self.assertTrue(
            graph_independent.verify_input_binding_v2(
                coverage_a.graph_input,
                graph_raw,
                registry,
            )["accepted"]
        )
        core_independent._replay_source_admission(
            self.envelope,
            graph_raw,
            source_value,
            verified_a,
            external_evidence_raw=_external_evidence(self.ingress_config, self.envelope),
            external_policy=self.ingress_config.external_policy().material(),
        )

        input_b_value = json.loads(coverage_a.graph_input.decode("utf-8"))
        input_b_value["sources"][0]["coverage_effective_end"] -= 1
        input_b_value["sources"][0]["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
            input_b_value["sources"][0], coverage_a.graph_profile
        )
        input_b = graph_producer.canonical_input(input_b_value)
        graph_b, _telemetry = graph_producer.build_report(input_b, profile=coverage_a.graph_profile)
        verified_b = graph_independent.verify_artifact_v2(graph_b, registry)
        self.assertTrue(
            graph_independent.verify_input_binding_v2(input_b, graph_b, registry)["accepted"]
        )
        with self.assertRaisesRegex(graph_independent.IndependentProviderTrustGraphError, "input:artifact-sources"):
            graph_independent.verify_input_binding_v2(coverage_a.graph_input, graph_b, registry)
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core:source-admission"):
            core_independent._replay_source_admission(
                self.envelope,
                graph_b,
                source_value,
                verified_b,
                external_evidence_raw=_external_evidence(self.ingress_config, self.envelope),
                external_policy=self.ingress_config.external_policy().material(),
            )

        for label, field, replacement, expected in (
            ("subject", "provider_graph_subject", "SYNTH_OTHER_PROVIDER", "input:subject"),
            ("scope", "scope", "SYNTH_OTHER_SCOPE", "input:scope"),
            ("profile", "profile_id", "SYNTH_OTHER_PROFILE", "input:profile"),
        ):
            with self.subTest(input_field=label):
                bad_input = json.loads(coverage_a.graph_input.decode("utf-8"))
                bad_input[field] = replacement
                with self.assertRaisesRegex(graph_independent.IndependentProviderTrustGraphError, expected):
                    graph_independent.verify_input_binding_v2(
                        graph_producer.canonical_input(bad_input), graph_raw, registry
                    )

        input_time_value = json.loads(coverage_a.graph_input.decode("utf-8"))
        time_profile = replace(coverage_a.graph_profile, observation_start=6999, observation_end=7002)
        time_registry = dict(registry)
        time_registry[time_profile.profile_id] = time_profile
        input_time_value["profile_digest"] = time_profile.profile_digest
        input_time_value["observation_time"] += 1
        for source in input_time_value["sources"]:
            source["coverage_observation_time"] += 1
            for record in source["records"]:
                record["observed_at"] += 1
            source["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
                source, time_profile
            )
        input_time = graph_producer.canonical_input(input_time_value)
        graph_time, _telemetry = graph_producer.build_report(input_time, profile=time_profile)
        self.assertTrue(graph_independent.verify_input_binding_v2(input_time, graph_time, time_registry)["accepted"])
        with self.assertRaisesRegex(graph_independent.IndependentProviderTrustGraphError, "input:(profile|artifact-time)"):
            graph_independent.verify_input_binding_v2(coverage_a.graph_input, graph_time, time_registry)

        input_record_value = json.loads(coverage_a.graph_input.decode("utf-8"))
        input_record_value["sources"][0]["records"][0]["record_id"] = _hex("rebound-record")
        input_record_value["sources"][0]["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
            input_record_value["sources"][0], coverage_a.graph_profile
        )
        input_record = graph_producer.canonical_input(input_record_value)
        graph_record, _telemetry = graph_producer.build_report(input_record, profile=coverage_a.graph_profile)
        self.assertTrue(graph_independent.verify_input_binding_v2(input_record, graph_record, registry)["accepted"])
        with self.assertRaisesRegex(graph_independent.IndependentProviderTrustGraphError, "input:artifact-sources"):
            graph_independent.verify_input_binding_v2(coverage_a.graph_input, graph_record, registry)

    def test_core_structural_only_verification_is_not_upstream_acceptance(self) -> None:
        structural = core_independent.verify_database(
            self.core_path,
            expected_database_id=self.core_config.database_id,
            expected_config_digest=self.core_config.digest,
        )
        self.assertTrue(structural["structural_valid"])
        self.assertFalse(structural["ingress_bound"])
        bound = core_independent.verify_database(
            self.core_path,
            expected_database_id=self.core_config.database_id,
            expected_config_digest=self.core_config.digest,
            ingress_path=self.ingress_path,
        )
        self.assertTrue(bound["structural_valid"])
        self.assertTrue(bound["ingress_bound"])

    def test_removed_later_views_are_not_core_artifact_kinds(self) -> None:
        for kind in ("DENOMINATOR", "CONTRACT", "TRANSACTION", "MONEY", "TRANSITION", "STATE_VALUE"):
            self.assertNotIn(kind, core.ARTIFACT_KINDS)
        self.assertFalse(core.FIXED_FLAGS.get("policyResult", False))
        self.assertFalse(core.FIXED_FLAGS.get("effectiveDirective", False))

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
        service = recovery.RecoveryServiceV2(self.root / "randomized-recovery.db", self.recovery_config, custody, storage)
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
                service = recovery.RecoveryServiceV2(self.root / f"finalizer-{fault}.db", self.recovery_config, _Custody(), _Storage())
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
        service = recovery.RecoveryServiceV2(self.root / "commit-then-raise-recovery.db", self.recovery_config, _Custody(), _Storage())
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
        service = recovery.RecoveryServiceV2(self.root / "precommit-retry-recovery.db", self.recovery_config, _Custody(), _Storage())
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
        service = recovery.RecoveryServiceV2(self.root / "pending-revoked-recovery.db", self.recovery_config, custody, storage)
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
        service = recovery.RecoveryServiceV2(self.root / "oversized-storage-recovery.db", self.recovery_config, no_open, oversized_storage)
        shutil.copy2(self.recovery_path, service.path)
        with self.assertRaises(recovery.RecoveryConflictError):
            service.restore_point(point.point_id, self.root / "oversized-i.db", self.root / "oversized-c.db")
        self.assertFalse(no_open.opened)
        plain_storage = _Storage()
        plain_storage.objects.update(self.storage.objects)
        oversized_plaintext = _NoOpenCustody(oversized_plaintext=True)
        plain_service = recovery.RecoveryServiceV2(self.root / "oversized-plaintext-recovery.db", self.recovery_config, oversized_plaintext, plain_storage)
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
            recovery.RecoveryServiceV2(oversized, self.recovery_config, self.custody, self.storage)
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
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
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
                recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
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
        reopened = recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
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
                recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
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
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
                self.assertEqual("recovery:database-initialize", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("CANARY_INIT_", repr(caught.exception))
                self.assertEqual(1, faults[0].rollback_calls)
                self.assertEqual(1, faults[0].close_calls)
                self.assertEqual((), table_names(path))
                retry = recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
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
            recovery.RecoveryServiceV2(legacy, self.recovery_config, self.custody, self.storage)
        self.assertEqual("recovery:legacy-schema", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_recovery_catalog_reopens_and_ddl_failures_leave_no_partial_schema(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "reopen-recovery.db", self.recovery_config, self.custody, self.storage)
        self.assertTrue(service.verify()["accepted"])
        reopened = recovery.RecoveryServiceV2(self.root / "reopen-recovery.db", self.recovery_config, self.custody, self.storage)
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
                        recovery.RecoveryServiceV2(path, self.recovery_config, self.custody, self.storage)
                connection = sqlite3.connect(path)
                try:
                    tables = tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"))
                finally:
                    connection.close()
                self.assertEqual((), tables)

    def test_recovery_generation_chain_is_contiguous_and_retry_is_source_free(self) -> None:
        empty_path = self.root / "generation-recovery.db"
        service = recovery.RecoveryServiceV2(empty_path, self.recovery_config, self.custody, self.storage)
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
        service = recovery.RecoveryServiceV2(self.root / "interleaved-pending-recovery.db", self.recovery_config, self.custody, storage)
        with self.assertRaises(recovery.RecoveryIndeterminateError):
            service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("OBJECT_PENDING", recovery_independent.select_point(service.path, generation=1)["point"]["state"])

        second = service.create_point(self.ingress_path, self.core_path, generation=2)
        self.assertEqual("VERIFIED", second.state)
        self.ingress_path.unlink()
        self.core_path.unlink()
        first = service.create_point(self.ingress_path, self.core_path, generation=1)
        self.assertEqual("VERIFIED", first.state)
        snapshot = recovery_independent.verify_database(
            service.path,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
        )
        self.assertEqual(2, snapshot["point_count"])
        self.assertEqual(2, snapshot["states"]["VERIFIED"])

    def test_recovery_interleaved_predecessor_publish_preserves_historical_chain(self) -> None:
        service = recovery.RecoveryServiceV2(self.root / "interleaved-publish-recovery.db", self.recovery_config, self.custody, self.storage)
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
        service = recovery.RecoveryServiceV2(self.root / "pending-stored-recovery.db", self.recovery_config, self.custody, storage)
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
        retry = self.recovery_service.restore_point(point.point_id, ingress_target, core_target)
        self.assertEqual(first.raw, retry.raw)
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
        self.assertIsInstance(errors[0], recovery.RecoveryError)
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
        service = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock)
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
        restarted = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock)
        retry = restarted.ensure_slot(scheduled_at)
        self.assertEqual("DUE", retry.next_state)
        self.assertEqual(1, restarted.verify()["event_count"])

        close_path = self.root / "ingress-finalizer-close.db"
        close_service = ingress.IngressServiceV2(close_path, self.ingress_config, clock=self.clock)
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
        close_retry = ingress.IngressServiceV2(close_path, self.ingress_config, clock=self.clock).ensure_slot(close_time)
        self.assertEqual("DUE", close_retry.next_state)
        self.assertEqual(1, ingress_independent.verify_database(close_path)["event_count"])

    def test_ingress_transaction_finalizer_rejects_rollback_failure(self) -> None:
        path = self.root / "ingress-finalizer-rollback.db"
        service = ingress.IngressServiceV2(path, self.ingress_config, clock=self.clock)
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
        restarted = core.CoreServiceV2(self.core_path, self.core_config, clock=self.core_clock)
        retry = restarted.observe(self.session_id, 1, "DISCREPANCY", counts={"observed": 1, "changed": 1})
        self.assertEqual("OBSERVATION", json.loads(retry.raw.decode("ascii"))["event_kind"])
        self.assertEqual(self.core.verify()["event_count"], restarted.verify()["event_count"])

        close_path = self.root / "core-finalizer-close.db"
        shutil.copy2(self.core_path, close_path)
        close_service = core.CoreServiceV2(close_path, self.core_config, clock=self.core_clock)
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
        close_retry = core.CoreServiceV2(close_path, self.core_config, clock=self.core_clock).observe(
            self.session_id, 2, "PARITY", counts={"observed": 2, "changed": 0}
        )
        self.assertEqual("OBSERVATION", json.loads(close_retry.raw.decode("ascii"))["event_kind"])

        rollback_path = self.root / "core-finalizer-rollback.db"
        shutil.copy2(self.core_path, rollback_path)
        rollback_service = core.CoreServiceV2(rollback_path, self.core_config, clock=self.core_clock)
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

    def test_owner_public_reads_reject_latched_identity_replacement(self) -> None:
        def replace_with_identical_copy(path: Path, label: str) -> None:
            replacement = self.root / f"{label}-replacement.db"
            shutil.copy2(path, replacement)
            os.replace(replacement, path)

        replace_with_identical_copy(self.ingress_path, "ingress-public")
        for operation in (self.ingress.verify, self.ingress.logical_export, self.ingress.support):
            with self.assertRaisesRegex(ingress.IngressError, "^ingress:database-open$") as caught:
                operation()
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

        replace_with_identical_copy(self.core_path, "core-public")
        for operation in (self.core.verify, self.core.logical_export, self.core.support):
            with self.assertRaisesRegex(core.CoreError, "^core:database-open$") as caught:
                operation()
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_owner_verify_rejects_replacement_after_independent_read(self) -> None:
        def replace_after_read(original, path: Path, label: str):
            def wrapped(*args: object, **kwargs: object):
                result = original(*args, **kwargs)
                replacement = self.root / f"{label}-after-read.db"
                shutil.copy2(path, replacement)
                os.replace(replacement, path)
                return result
            return wrapped

        with mock.patch.object(
            ingress.independent,
            "verify_database",
            side_effect=replace_after_read(ingress.independent.verify_database, self.ingress_path, "ingress"),
        ):
            with self.assertRaisesRegex(ingress.IngressError, "^ingress:database-open$") as caught:
                self.ingress.verify()
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

        with mock.patch.object(
            core.independent,
            "verify_database",
            side_effect=replace_after_read(core.independent.verify_database, self.core_path, "core"),
        ):
            with self.assertRaisesRegex(core.CoreError, "^core:database-open$") as caught:
                self.core.verify()
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_new_owner_init_rejects_postcommit_identity_replacement(self) -> None:
        root = self.root

        def swap_connection(original, target: Path, kwargs: dict[str, object]):
            class CommitSwap:
                def __init__(self, inner: sqlite3.Connection) -> None:
                    self.inner = inner

                @property
                def in_transaction(self) -> bool:
                    return False

                def execute(self, sql: str, *parameters: object):
                    return self.inner.execute(sql, *parameters)

                def commit(self) -> None:
                    self.inner.commit()
                    self.inner.close()
                    replacement = root / f"{target.stem}-postcommit.db"
                    shutil.copy2(target, replacement)
                    os.replace(replacement, target)

                def rollback(self) -> None:
                    self.inner.rollback()

                def close(self) -> None:
                    return None

                def __getattr__(self, name: str) -> object:
                    return getattr(self.inner, name)

            return CommitSwap(original(target, **kwargs))

        ingress_path = self.root / "ingress-postcommit-init.db"
        ingress_original_connection = ingress._connection
        with mock.patch.object(
            ingress,
            "_connection",
            side_effect=lambda target, **kwargs: swap_connection(ingress_original_connection, Path(target), kwargs),
        ):
            with self.assertRaisesRegex(ingress.IngressIndeterminateError, "^ingress:transaction-indeterminate$") as caught:
                ingress.IngressServiceV2(ingress_path, self.ingress_config, clock=self.clock)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(str(ingress_path), str(caught.exception))
        self.assertNotIn(str(ingress_path), "".join(traceback.format_exception(caught.exception)))
        self.assertIsNotNone(ingress.IngressServiceV2(ingress_path, self.ingress_config, clock=self.clock).verify())

        core_path = self.root / "core-postcommit-init.db"
        core_original_connection = core._connection
        with mock.patch.object(
            core,
            "_connection",
            side_effect=lambda target, **kwargs: swap_connection(core_original_connection, Path(target), kwargs),
        ):
            with self.assertRaisesRegex(core.CoreIndeterminateError, "^core:transaction-indeterminate$") as caught:
                core.CoreServiceV2(core_path, self.core_config, clock=self.core_clock)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(str(core_path), str(caught.exception))
        self.assertNotIn(str(core_path), "".join(traceback.format_exception(caught.exception)))
        self.assertIsNotNone(core.CoreServiceV2(core_path, self.core_config, clock=self.core_clock).verify())

    def test_existing_owner_init_rejects_postclose_identity_replacement(self) -> None:
        root = self.root

        def swap_on_close(original, target: Path, expected_identity):
            class CloseSwap:
                def __init__(self, inner: sqlite3.Connection) -> None:
                    self.inner = inner

                @property
                def in_transaction(self) -> bool:
                    return False

                def execute(self, sql: str, *parameters: object):
                    return self.inner.execute(sql, *parameters)

                def rollback(self) -> None:
                    self.inner.rollback()

                def close(self) -> None:
                    self.inner.close()
                    replacement = root / f"{target.stem}-postclose.db"
                    shutil.copy2(target, replacement)
                    os.replace(replacement, target)

                def __getattr__(self, name: str) -> object:
                    return getattr(self.inner, name)

            return CloseSwap(original(target, expected_identity=expected_identity))

        core_path = self.root / "core-postclose-init.db"
        shutil.copy2(self.core_path, core_path)
        core_original_connection = core._connection
        core_expected_identity = core._path_identity(core_path, allow_missing=False)
        with mock.patch.object(
            core,
            "_connection",
            side_effect=lambda target, **kwargs: swap_on_close(core_original_connection, Path(target), core_expected_identity),
        ):
            with self.assertRaisesRegex(core.CoreError, "^core:database-open$") as caught:
                core.CoreServiceV2(core_path, self.core_config, clock=self.core_clock)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

        ingress_path = self.root / "ingress-postclose-init.db"
        shutil.copy2(self.ingress_path, ingress_path)
        ingress_original_connection = ingress._connection
        ingress_path_identity = ingress._path_identity(ingress_path, allow_missing=False)
        ingress_expected_identity = (ingress_path_identity[0], ingress_path_identity[1])
        with mock.patch.object(
            ingress,
            "_connection",
            side_effect=lambda target, **kwargs: swap_on_close(ingress_original_connection, Path(target), ingress_expected_identity),
        ):
            with self.assertRaisesRegex(ingress.IngressError, "^ingress:database-open$") as caught:
                ingress.IngressServiceV2(ingress_path, self.ingress_config, clock=self.clock)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)


if __name__ == "__main__":
    unittest.main()
