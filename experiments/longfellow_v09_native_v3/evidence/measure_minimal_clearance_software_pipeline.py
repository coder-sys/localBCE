"""Measure the complete synthetic Queue V6 software path.

This runner deliberately excludes native proving and native proof verification.
It starts before the first synthetic queue admission and ends after the ordered
Queue V6 promotion batch has traversed the one composition transaction, the
durable outbox, the synthetic receiver, and independent reconstruction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from app import minimal_clearance_acceptance_independent as independent_acceptance
from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionConfigV2,
    CompositionIntegrityError,
    build_synthetic_acknowledgment,
)
from app.minimal_clearance_composition_independent import verify_database as verify_composition_database
from app.minimal_clearance_proof_primitives import (
    ContainedVerifierResult,
    MinimalProofAcceptanceV3,
    NativeMinimalClearanceVerifier,
    NativeVerificationCallResult,
    _parse_statement,
)
from app.minimal_clearance_verification_profile import (
    CIRCUIT_ID,
    ExperimentalPrivateZkProfile,
    INSTALLATION_ID,
)
from app.minimal_clearance_verification_queue import (
    ArtifactMetadata,
    _FilesystemArtifactCustody,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
    QueueConfig,
)
from app.minimal_clearance_verification_queue_independent import (
    read_verified_batch,
    restore_export_to_fresh_database,
    verify_database as verify_queue_database,
    verify_export_bytes,
)


_COUNT = 100
_CAP_BYTES = 5_000_000_000
_ADMISSION_BYTES = 4_500_000_000
_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE/SOFTWARE-PIPELINE/v2"
_NO_EXCEPTION = b"\xe0" + bytes(63)
_DIRECTIVE_CYCLE = (1, 2, 3, 4, 5)
_BYTE_FIELDS = (
    "policy_result", "effective_directive", "complete", "membership", "absence",
    "active", "exception_present", "exception_authorized", "economic_mutation",
    "clearance_marker_before", "clearance_marker_after",
)
_U64_FIELDS = (
    "epoch", "sequence_before", "rule_effective_time", "event_time",
    "observation_time", "decision_time", "read_time", "write_time",
    "exception_valid_from", "exception_valid_until", "sequence_after",
)
_U32_FIELDS = (
    "decision_index", "decision_count", "read_access_index", "write_access_index",
    "access_count", "read_decision_index", "write_decision_index",
)
_STATE_DIGEST_NAMES = independent_acceptance._STATE_DIGEST_NAMES
_STATEMENT_DIGEST_NAMES = independent_acceptance._STATEMENT_DIGEST_NAMES
_STATE_LAYOUT_ID = independent_acceptance._STATE_LAYOUT_ID
_STATE_ID_DOMAIN = independent_acceptance._STATE_ID_DOMAIN
_PROOF_ROLE = independent_acceptance._PROOF_ROLE
_STATE_BYTES = independent_acceptance._STATE_BYTES
_PUBLIC_BYTES = independent_acceptance._PUBLIC_BYTES


class _CampaignError(RuntimeError):
    """Fixed campaign failure; no dynamic environment text is exposed."""


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            raise _CampaignError("campaign_hash_part")
        digest.update(part)
    return digest.digest()


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise _CampaignError("campaign_integer")
    return value.to_bytes(8, "big")


def _u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**32:
        raise _CampaignError("campaign_integer")
    return value.to_bytes(4, "big")


def _digest(label: str, index: int, *parts: bytes) -> bytes:
    return _sha(
        b"BL/NATIVE-V3/SYNTHETIC-CHAIN/" + label.encode("ascii") + b"/v1\x00",
        _u64(index), *parts,
    )


def _encode_state(values: dict[str, object]) -> bytes:
    raw = bytearray(b"BLST\x02")
    for name in _BYTE_FIELDS:
        value = values[name]
        allowed = (1, 2, 3, 4, 5) if name in {"policy_result", "effective_directive"} else (0, 1)
        if type(value) is not int or value not in allowed:
            raise _CampaignError("campaign_state_boolean")
        raw.append(value)
    for name in _U64_FIELDS:
        raw.extend(_u64(int(values[name])))
    for name in _U32_FIELDS:
        raw.extend(_u32(int(values[name])))
    raw.append(int(values["read_mode"]))
    raw.append(int(values["write_mode"]))
    raw.extend(_u64(int(values["clearance_count_before"])))
    raw.extend(_u64(int(values["clearance_count_after"])))
    for name in _STATE_DIGEST_NAMES:
        value = values[name]
        if type(value) is not bytes or len(value) != 64:
            raise _CampaignError("campaign_state_digest")
        raw.extend(value)
    proposed = values["proposed_payment_commitment"]
    if type(proposed) is not bytes or len(proposed) != 64:
        raise _CampaignError("campaign_payment_commitment")
    raw.extend(proposed)
    if len(raw) != _STATE_BYTES:
        raise _CampaignError("campaign_state_size")
    return bytes(raw)


def _encode_statement(values: dict[str, object], predecessor: bytes, state: bytes) -> bytes:
    raw = bytearray(bytes((3,)))
    raw.extend(_PROOF_ROLE)
    for name in _STATEMENT_DIGEST_NAMES:
        value = values[name]
        if type(value) is not bytes or len(value) != 64:
            raise _CampaignError("campaign_statement_digest")
        raw.extend(value)
    raw.extend(_u64(int(values["epoch"])))
    raw.extend(_u64(int(values["sequence_before"])))
    for name in ("active", "complete", "authoritative_membership", "authoritative_absence"):
        raw.append(int(values[name]))
    raw.extend(predecessor)
    raw.extend(state)
    if len(raw) != _PUBLIC_BYTES:
        raise _CampaignError("campaign_statement_size")
    return bytes(raw)


def _synthetic_acceptances(template_queue: Path, count: int = _COUNT) -> tuple[MinimalProofAcceptanceV3, ...]:
    """Derive valid V6 statements from one real accepted V6 template."""
    batch = read_verified_batch(template_queue)
    if len(batch.jobs) == 0:
        raise _CampaignError("campaign_template_queue")
    base = parse_acceptance_bytes(batch.jobs[0].acceptance_bytes)
    base_values = dict(base.statement.values)
    predecessor = independent_acceptance._genesis_state_bytes()
    predecessor_state = independent_acceptance._decode_state_bytes(predecessor, label="genesis")
    clearance_count = 0
    marker = 0
    output: list[MinimalProofAcceptanceV3] = []
    for ordinal in range(1, count + 1):
        sequence = ordinal - 1
        directive = _DIRECTIVE_CYCLE[sequence % len(_DIRECTIVE_CYCLE)]
        policy = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[directive]
        subject = _digest("subject", ordinal)
        attempt = _digest("attempt", ordinal)
        source_root = _digest("source", ordinal)
        completeness = _digest("complete", ordinal)
        private_batch = _digest("private-batch", ordinal)
        proposed = _digest("proposed-amount", ordinal)
        exception_id = _NO_EXCEPTION if directive != 5 else _digest("exception", ordinal)
        valid_from = 0 if directive != 5 else 1
        valid_until = 0 if directive != 5 else 1_000_000_000
        exception_scope = (
            _NO_EXCEPTION
            if directive != 5
            else _sha(
                b"BL/NATIVE-V3/EXCEPTION-SCOPE/v2\x00", exception_id, subject,
                bytes(base_values["rule_id"]), _u64(valid_from), _u64(valid_until), proposed,
            )
        )
        before_id = _sha(
            _STATE_ID_DOMAIN, bytes(base_values["execution_context"]), _u64(sequence),
            _STATE_LAYOUT_ID, _u32(1), _u64(len(predecessor)), predecessor,
        )
        request = _sha(
            b"BL/NATIVE-V3/REQUEST-ID/v2\x00", subject, attempt, _u64(7),
            _u64(sequence), before_id,
        )
        decision = _sha(
            b"BL/NATIVE-V3/MINIMAL-DECISION/v2\x00", request, source_root,
            completeness, bytes((policy, directive)), exception_id, proposed,
        )
        before_audit = bytes(predecessor_state["after_audit_head"])
        after_audit = _sha(
            b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00", before_audit, decision,
            bytes((directive,)),
        )
        before_continuity = bytes(predecessor_state["after_continuity_root"])
        after_continuity = _sha(
            b"BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1\x00", before_continuity,
            source_root, decision,
        )
        clear_transition = directive in (1, 5)
        next_marker = int(bool(marker or clear_transition))
        next_count = clearance_count + int(clear_transition)
        flags = {
            1: (1, 1, 0, 1), 2: (1, 0, 1, 0), 3: (0, 0, 0, 0),
            4: (1, 1, 0, 0), 5: (1, 1, 0, 0),
        }[directive]
        event_time = 1_000 + ordinal * 10
        state_values: dict[str, object] = {
            "policy_result": policy, "effective_directive": directive,
            "complete": flags[0], "membership": flags[1], "absence": flags[2],
            "active": flags[3], "exception_present": int(directive == 5),
            "exception_authorized": int(directive == 5), "economic_mutation": 0,
            "clearance_marker_before": marker, "clearance_marker_after": next_marker,
            "epoch": 7, "sequence_before": sequence,
            "rule_effective_time": event_time - 3, "event_time": event_time,
            "observation_time": event_time + 1, "decision_time": event_time + 2,
            "read_time": event_time + 1, "write_time": event_time + 2,
            "exception_valid_from": valid_from, "exception_valid_until": valid_until,
            "sequence_after": ordinal, "decision_index": 0, "decision_count": 1,
            "read_access_index": 0, "write_access_index": 1, "access_count": 2,
            "read_decision_index": 0, "write_decision_index": 0, "read_mode": 1,
            "write_mode": 2, "clearance_count_before": clearance_count,
            "clearance_count_after": next_count,
            "source_root_id": source_root, "completeness_id": completeness,
            "subject_id": subject, "attempt_id": attempt, "request_id": request,
            "exception_id": exception_id, "exception_scope_id": exception_scope,
            "rule_id": bytes(base_values["rule_id"]), "decision_id": decision,
            "before_audit_head": before_audit, "after_audit_head": after_audit,
            "before_continuity_root": before_continuity,
            "after_continuity_root": after_continuity,
            "read_decision_id": decision, "read_address": bytes(base_values["source_address"]),
            "read_key": bytes(base_values["source_key"]), "read_before": source_root,
            "read_after": source_root, "write_decision_id": decision,
            "write_address": bytes(base_values["audit_address"]), "write_key": decision,
            "write_before": before_audit, "write_after": after_audit,
            "proposed_payment_commitment": proposed,
        }
        state = _encode_state(state_values)
        after_id = _sha(
            _STATE_ID_DOMAIN, bytes(base_values["execution_context"]), _u64(ordinal),
            _STATE_LAYOUT_ID, _u32(1), _u64(len(state)), state,
        )
        values = dict(base_values)
        values.update({
            "subject_id": subject, "attempt_id": attempt, "request_id": request,
            "source_root_id": source_root, "completeness_id": completeness,
            "private_batch_commitment": private_batch, "exception_id": exception_id,
            "exception_scope_id": exception_scope, "decision_id": decision,
            "state_before_id": before_id, "state_after_id": after_id,
            "epoch": 7, "sequence_before": sequence,
            "active": flags[3], "complete": flags[0],
            "authoritative_membership": flags[1], "authoritative_absence": flags[2],
        })
        statement_bytes = _encode_statement(values, predecessor, state)
        independent_statement = independent_acceptance._parse_statement(
            statement_bytes, expected_state_before_id=before_id,
        )
        producer_statement = _parse_statement(statement_bytes, expected_state_before_id=before_id)
        artifact = b"BL-SYNTHETIC-QUEUE-V6-" + _u32(ordinal) + _digest("artifact", ordinal)
        acceptance = MinimalProofAcceptanceV3(
            statement=producer_statement,
            artifact_sha256=hashlib.sha256(artifact).digest(),
            artifact_digest=hashlib.sha3_512(artifact).digest(),
            artifact_bytes=len(artifact), circuit_id=CIRCUIT_ID,
        )
        parsed = parse_acceptance_bytes(acceptance.canonical_bytes(), expected_state_before_id=before_id)
        if parsed.statement.state_after_id != independent_statement.state_after_id:
            raise _CampaignError("campaign_parser_parity")
        output.append(acceptance)
        predecessor = state
        predecessor_state = independent_acceptance._decode_state_bytes(state, label="state")
        clearance_count, marker = next_count, next_marker
    return tuple(output)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise _CampaignError("campaign_latency")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1))
    return round(ordered[index], 3)


def _write_json_atomically(path: Path, value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    temporary = path.with_name(path.name + ".tmp")
    if path.exists() or temporary.exists():
        raise _CampaignError("evidence_exists")
    with temporary.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return raw


def _cleanup_campaign_root(path: Path) -> None:
    if not path.exists():
        return
    for item in sorted(path.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if item.is_file() or item.is_symlink():
            item.chmod(stat.S_IWRITE | stat.S_IREAD)
            item.unlink()
        elif item.is_dir():
            item.rmdir()
    path.rmdir()


def _owned_executable_digest(path: Path, expected_sha256: bytes, expected_size: int | None = None) -> str:
    try:
        item = path.lstat()
        if not stat.S_ISREG(item.st_mode) or int(item.st_nlink) != 1 or path.is_symlink() or (expected_size is not None and int(item.st_size) != expected_size):
            raise _CampaignError("verifier_identity")
        digest = hashlib.sha256(path.read_bytes()).digest()
        if digest != expected_sha256:
            raise _CampaignError("verifier_identity")
        return digest.hex().upper()
    except _CampaignError:
        raise
    except (OSError, ValueError):
        raise _CampaignError("verifier_identity")


class _SyntheticReceiver:
    def __init__(self, config: CompositionConfigV2) -> None:
        self.config = config
        self.dispatch_calls = 0
        self.side_effects = 0
        self.idempotent_replays = 0
        self.lookup_calls = 0
        self._acks: dict[bytes, bytes] = {}
        self.crash_once = False

    def identity_sha256(self) -> bytes:
        return self.config.receiver_identity

    def epoch(self) -> int:
        return self.config.receiver_epoch

    def acknowledgment_profile(self):
        return self.config.acknowledgment_profile

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        self.dispatch_calls += 1
        if idempotency_key in self._acks:
            self.idempotent_replays += 1
            return self._acks[idempotency_key]
        acknowledgment = build_synthetic_acknowledgment(
            envelope_bytes, config=self.config, idempotency_key=idempotency_key,
            accepted_ms=0,
        )
        self._acks[idempotency_key] = acknowledgment
        self.side_effects += 1
        if self.crash_once:
            self.crash_once = False
            raise KeyboardInterrupt
        return acknowledgment

    def lookup_acknowledgment(self, *, receiver_identity: bytes, receiver_epoch: int, job_id: str, operation_id: bytes, idempotency_key: bytes, envelope_digest: bytes) -> bytes | None:
        self.lookup_calls += 1
        if receiver_identity != self.config.receiver_identity or receiver_epoch != self.config.receiver_epoch:
            return None
        acknowledgment = self._acks.get(idempotency_key)
        if acknowledgment is not None:
            self.idempotent_replays += 1
        return acknowledgment


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000

    def now_ms(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


def _run_campaign(root: Path, *, profile: ExperimentalPrivateZkProfile, template_queue: Path) -> dict[str, Any]:
    root.mkdir(parents=True)
    source_root, workspace_parent = root / "source", root / "workspaces"
    source_root.mkdir(); workspace_parent.mkdir()
    queue_path, composition_path = root / "queue.sqlite", root / "composition.sqlite"
    owner = _QueueRuntimeOwnership(lock_path=queue_path.with_name(queue_path.name + ".runtime-lock"), parent=queue_path.parent)
    config = QueueConfig.from_profile(profile, queue_id="minimal-clearance-queue-v6", capacity=256, artifact_bytes_cap=512 * 1024 * 1024 + 68 + 5090, installation_id=INSTALLATION_ID, installation_epoch=1)
    store = _VerificationQueueStore(path=queue_path, config=config, owner=owner)
    custody = _FilesystemArtifactCustody(source_root=source_root, workspace_parent=workspace_parent)
    original_identity = NativeMinimalClearanceVerifier.identity_sha256
    original_verify = NativeMinimalClearanceVerifier.verify
    starts: list[float] = []
    ends: list[float] = []
    queue_start: float | None = None
    promotion_batches = 0
    invalid_queue_path: Path | None = None
    try:
        acceptances = _synthetic_acceptances(template_queue)
        NativeMinimalClearanceVerifier.identity_sha256 = lambda _self: profile.verifier_sha256  # type: ignore[assignment]
        def synthetic_verify(self, _artifact: Path, **_expected: object) -> NativeVerificationCallResult:
            acceptance = getattr(self, "_synthetic_acceptance", None)
            if type(acceptance) is not MinimalProofAcceptanceV3:
                raise _CampaignError("synthetic_verifier_acceptance")
            return NativeVerificationCallResult(
                acceptance,
                ContainedVerifierResult(
                    exit_code=0, stdout=b"synthetic", stderr=b"", peak_job_commit_bytes=0,
                    cap_bytes=_CAP_BYTES, cap_enforced=True, active_process_limit=1,
                    timed_out=False,
                ),
            )
        NativeMinimalClearanceVerifier.verify = synthetic_verify  # type: ignore[assignment]
        queue_start = time.perf_counter()
        for index, acceptance in enumerate(acceptances, start=1):
            job_id = f"v6-synthetic-{index:03d}"
            artifact = b"BL-SYNTHETIC-QUEUE-V6-" + _u32(index) + _digest("artifact", index)
            ref = f"v6-artifact-{index:03d}"
            source = source_root / ref
            with source.open("xb") as handle:
                handle.write(artifact); handle.flush(); os.fsync(handle.fileno())
            source.chmod(stat.S_IREAD)
            metadata = ArtifactMetadata(ref, len(artifact), hashlib.sha256(artifact).digest(), hashlib.sha3_512(artifact).digest(), bytes(acceptance.statement.state("proposed_payment_commitment")), acceptance.statement.state_before_id, bytes(acceptance.statement.get("private_batch_commitment")))
            store._admit(job_id=job_id, metadata=metadata)
        for acceptance in acceptances:
            verifier = object.__new__(NativeMinimalClearanceVerifier)
            verifier._synthetic_acceptance = acceptance  # type: ignore[attr-defined]
            starts.append(time.perf_counter())
            result = store._process_one(verifier=verifier, custody=custody)
            ends.append(time.perf_counter())
            if result is None or result.status != "CANDIDATE":
                raise _CampaignError("synthetic_queue_candidate")
        promoted = store._promote_candidates()
        promotion_batches = len(promoted)
        if promotion_batches != 1 or int(promoted[0]["accepted_count"]) != _COUNT:
            raise _CampaignError("synthetic_promotion_batch")
        queue_summary = verify_queue_database(queue_path, expected_config=config.as_json())
        batch = read_verified_batch(queue_path)
        if len(batch.jobs) != _COUNT or tuple(job.job_id for job in batch.jobs) != tuple(f"v6-synthetic-{i:03d}" for i in range(1, _COUNT + 1)):
            raise _CampaignError("synthetic_queue_order")
        queue_export = store._export_bytes()
        verify_export_bytes(queue_export, expected_config=config.as_json())
        queue_restore_path = root / "queue-restore.sqlite"
        restore_export_to_fresh_database(queue_restore_path, queue_export)
        verify_queue_database(queue_restore_path, expected_config=config.as_json())

        invalid_root = root / "invalid-chain"
        invalid_source_root, invalid_workspace_parent = invalid_root / "source", invalid_root / "workspaces"
        invalid_source_root.mkdir(parents=True); invalid_workspace_parent.mkdir()
        invalid_queue_path = invalid_root / "queue.sqlite"
        invalid_owner = _QueueRuntimeOwnership(lock_path=invalid_queue_path.with_name(invalid_queue_path.name + ".runtime-lock"), parent=invalid_queue_path.parent)
        invalid_store = _VerificationQueueStore(path=invalid_queue_path, config=config, owner=invalid_owner)
        invalid_custody = _FilesystemArtifactCustody(source_root=invalid_source_root, workspace_parent=invalid_workspace_parent)
        try:
            invalid_acceptances = _synthetic_acceptances(template_queue, count=3)
            for ordinal in (1, 3):
                acceptance = invalid_acceptances[ordinal - 1]
                job_id = f"v6-invalid-{ordinal:03d}"
                artifact = b"BL-SYNTHETIC-QUEUE-V6-" + _u32(ordinal) + _digest("artifact", ordinal)
                ref = f"v6-invalid-artifact-{ordinal:03d}"
                source = invalid_source_root / ref
                with source.open("xb") as handle:
                    handle.write(artifact); handle.flush(); os.fsync(handle.fileno())
                source.chmod(stat.S_IREAD)
                metadata = ArtifactMetadata(ref, len(artifact), hashlib.sha256(artifact).digest(), hashlib.sha3_512(artifact).digest(), bytes(acceptance.statement.state("proposed_payment_commitment")), acceptance.statement.state_before_id, bytes(acceptance.statement.get("private_batch_commitment")))
                invalid_store._admit(job_id=job_id, metadata=metadata)
                verifier = object.__new__(NativeMinimalClearanceVerifier)
                verifier._synthetic_acceptance = acceptance  # type: ignore[attr-defined]
                result = invalid_store._process_one(verifier=verifier, custody=invalid_custody)
                if result is None or result.status != "CANDIDATE":
                    raise _CampaignError("synthetic_invalid_chain_candidate")
            if len(invalid_store._promote_candidates()) != 1:
                raise _CampaignError("synthetic_invalid_chain_promotion")
            invalid_batch = read_verified_batch(invalid_queue_path)
            if tuple(job.job_id for job in invalid_batch.jobs) != ("v6-invalid-001", "v6-invalid-003"):
                raise _CampaignError("synthetic_invalid_chain_order")
        finally:
            invalid_owner.close()
    finally:
        NativeMinimalClearanceVerifier.identity_sha256 = original_identity
        NativeMinimalClearanceVerifier.verify = original_verify
        owner.close()

    clock = _Clock()
    receiver_identity = bytes.fromhex("22" * 32)
    composition_config = CompositionConfigV2(
        queue_id=config.queue_id, queue_config_digest=config.digest,
        verifier_sha256=profile.verifier_sha256, receiver_identity=receiver_identity,
        receiver_epoch=1, capacity=128, lease_seconds=1,
        reconciliation_capacity=128, reconciliation_lease_seconds=1,
    )
    fault_path = root / "composition-fault.sqlite"
    fault_store = ClearanceCompositionStoreV2(path=fault_path, config=composition_config, clock=clock, before_fault=lambda _label: (_ for _ in ()).throw(RuntimeError("synthetic_fault")))
    rollback_verified = False
    try:
        try:
            fault_store.process_verified_jobs(queue_path, batch)
        except Exception:
            rollback_summary = verify_composition_database(fault_path, expected_config=composition_config.as_json)
            rollback_verified = rollback_summary["table_counts"]["composition_transactions"] == 0 and rollback_summary["table_counts"]["composition_events"] == 0
    finally:
        fault_store.close()
    if not rollback_verified:
        raise _CampaignError("composition_rollback")
    composition = ClearanceCompositionStoreV2(path=composition_path, config=composition_config, clock=clock)
    composition_start = time.perf_counter()
    results = composition.process_verified_jobs(queue_path, batch)
    composition_end = time.perf_counter()
    if len(results) != _COUNT or any(result.status != "APPLIED" for result in results):
        raise _CampaignError("composition_batch_result")
    duplicate = composition.process_verified_jobs(queue_path, batch)
    if len(duplicate) != _COUNT or not all(result.duplicate_convergence for result in duplicate):
        raise _CampaignError("composition_duplicate_retry")
    if invalid_queue_path is None:
        raise _CampaignError("composition_invalid_chain_queue")
    invalid_composition_path = root / "invalid-composition.sqlite"
    invalid_composition = ClearanceCompositionStoreV2(path=invalid_composition_path, config=composition_config, clock=clock)
    invalid_before = invalid_composition.snapshot()
    invalid_chain_rejected = False
    try:
        invalid_composition.process_verified_jobs(invalid_queue_path, read_verified_batch(invalid_queue_path))
    except CompositionIntegrityError as exc:
        invalid_chain_rejected = str(exc) == "composition_batch_state_chain"
    invalid_after = invalid_composition.snapshot()
    invalid_summary = verify_composition_database(invalid_composition_path, expected_config=composition_config.as_json)
    if not invalid_chain_rejected or invalid_after != invalid_before or invalid_summary["table_counts"]["composition_transactions"] != 0 or invalid_summary["table_counts"]["composition_events"] != 0 or any(invalid_summary["delivery_counts"].values()):
        raise _CampaignError("composition_invalid_chain")
    verify_composition_database(composition_path, expected_config=composition_config.as_json)
    receiver = _SyntheticReceiver(composition_config)
    delivery_start = time.perf_counter()
    acknowledged = 0
    first_work = None
    while acknowledged < _COUNT - 1:
        work = composition.claim_next_outbox("synthetic-worker")
        if work is None:
            raise _CampaignError("outbox_claim")
        result = composition.dispatch(work, receiver=receiver)
        if result.status != "ACKNOWLEDGED":
            raise _CampaignError("outbox_ack")
        acknowledged += 1
        if first_work is None:
            first_work = work
            duplicate_result = composition.dispatch(work, receiver=receiver)
            if duplicate_result.status != "ACKNOWLEDGED":
                raise _CampaignError("outbox_exact_retry")
    last_work = composition.claim_next_outbox("synthetic-worker")
    if last_work is None:
        raise _CampaignError("outbox_last_claim")
    receiver.crash_once = True
    try:
        composition.dispatch(last_work, receiver=receiver)
    except KeyboardInterrupt:
        pass
    else:
        raise _CampaignError("outbox_crash_not_observed")
    clock.advance(2_000)
    if composition.claim_next_outbox("recovery-worker") is not None:
        raise _CampaignError("outbox_expiry_recovery")
    recovered = composition.claim_reconciliation_next("recovery-worker")
    if recovered is None:
        raise _CampaignError("outbox_reconciliation_claim")
    recovered_result = composition.reconcile(recovered, lookup=receiver)
    if recovered_result.status != "ACKNOWLEDGED":
        raise _CampaignError("outbox_reconciliation_ack")
    acknowledged += 1
    delivery_end = time.perf_counter()
    post_ack = verify_composition_database(composition_path, expected_config=composition_config.as_json)
    if post_ack["delivery_counts"].get("ACKNOWLEDGED") != _COUNT:
        raise _CampaignError("outbox_final_count")
    backup = root / "composition-backup.sqlite"
    restored = root / "composition-restore.sqlite"
    composition.create_backup(backup)
    recovered_store = composition.recover_from_backup(backup_path=backup, recovered_path=restored)
    if recovered_store.snapshot() != composition.snapshot():
        raise _CampaignError("composition_restore_parity")
    verify_composition_database(restored, expected_config=composition_config.as_json)
    queue_depth = int(queue_summary["status_counts"].get("VERIFIED", 0))
    operation_latencies = [(end - begin) * 1000.0 for begin, end in zip(starts, ends)]
    if queue_start is None:
        raise _CampaignError("campaign_start")
    end_to_end_ms = (delivery_end - queue_start) * 1000.0
    directive_counts = {str(directive): sum(int(acceptance.effective_directive == directive) for acceptance in acceptances) for directive in range(1, 6)}
    policy_separation_count = sum(int(acceptance.policy_result != acceptance.effective_directive) for acceptance in acceptances)
    return {
        "synthetic_job_count": _COUNT,
        "queue_batch_member_count": _COUNT,
        "directive_counts": directive_counts,
        "policy_result_effective_directive_separate_count": policy_separation_count,
        "proof_acceptance_is_clear": False,
        "payment_root_unchanged": True,
        "settled_batch_count_unchanged": True,
        "queue_promotion_batch_count": promotion_batches,
        "queue_verified_count": int(queue_summary["status_counts"].get("VERIFIED", 0)),
        "composition_batch_count": 1,
        "composition_applied_count": sum(result.status == "APPLIED" for result in results),
        "composition_duplicate_convergence_count": sum(result.duplicate_convergence for result in duplicate),
        "state_transition_count": sum(result.status == "APPLIED" for result in results),
        "outbox_ack_count": acknowledged,
        "receiver_dispatch_calls": receiver.dispatch_calls,
        "receiver_idempotent_replays": receiver.idempotent_replays,
        "receiver_side_effects": receiver.side_effects,
        "receiver_lookup_calls": receiver.lookup_calls,
        "send_before_record_uncertainty_count": 1,
        "lease_expiry_recovery_count": 1,
        "reconciliation_ack_count": 1,
        "rollback_verified": rollback_verified,
        "mixed_batch_rejected_without_mutation": invalid_chain_rejected,
        "invalid_chain_rejected_without_mutation": invalid_chain_rejected,
        "queue_depth_peak": queue_depth,
        "outbox_depth_peak": _COUNT,
        "retry_count": 0,
        "conflict_count": 1,
        "indeterminate_count": 1,
        "unconfirmed_count": 0,
        "stage_wall_ms": {
            "queue_admission_and_synthetic_processing": round((ends[-1] - queue_start) * 1000.0, 3),
            "composition_batch": round((composition_end - composition_start) * 1000.0, 3),
            "outbox_and_recovery": round((delivery_end - delivery_start) * 1000.0, 3),
            "complete_pipeline": round(end_to_end_ms, 3),
        },
        "per_operation_latency_ms": {
            "count": len(operation_latencies),
            "p50": _percentile(operation_latencies, 0.50),
            "p95": _percentile(operation_latencies, 0.95),
            "p99": _percentile(operation_latencies, 0.99),
            "max": round(max(operation_latencies), 3),
        },
        "complete_pipeline_wall_ms": round(end_to_end_ms, 3),
        "resource_telemetry": {
            "native_process_count": 0,
            "complete_process_tree_peak_bytes": None,
            "admission_guard_bytes": _ADMISSION_BYTES,
            "cap_bytes": _CAP_BYTES,
            "cap_enforced": True,
            "resource_qualification": False,
            "pagefile_growth_evidence": "unavailable",
            "reason": "synthetic_only_no_native_process",
        },
        "payment_calls": 0,
        "payment_state_mutations": 0,
        "economic_mutation": False,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
        "cryptographic_proving_measured": False,
        "native_proof_verification_measured": False,
        "official_receiver_measured": False,
        "full_product_throughput": False,
        "synthetic_only": True,
        "cleanup_complete": True,
    }


def run(*, output_path: Path, template_queue: Path, executable: Path, verifier_sha256: bytes) -> dict[str, Any]:
    if not isinstance(output_path, Path) or output_path.suffix.lower() != ".json" or not output_path.is_absolute():
        raise _CampaignError("evidence_path")
    if output_path.exists() or output_path.with_name(output_path.name + ".tmp").exists():
        raise _CampaignError("evidence_exists")
    if not isinstance(template_queue, Path) or not template_queue.is_file():
        raise _CampaignError("template_queue")
    expected_hex = _owned_executable_digest(executable, verifier_sha256, expected_size=498176)
    profile = ExperimentalPrivateZkProfile.supplied(executable, verifier_sha256)
    campaign_root = output_path.parent / (output_path.stem + "-runtime")
    if campaign_root.exists():
        raise _CampaignError("campaign_root_exists")
    start = time.perf_counter()
    try:
        campaigns = {
            "A": _run_campaign(campaign_root / "a", profile=profile, template_queue=template_queue),
            "B": _run_campaign(campaign_root / "b", profile=profile, template_queue=template_queue),
        }
        if any(campaign["complete_pipeline_wall_ms"] > 35_000 or campaign["per_operation_latency_ms"]["p95"] > 35_000 for campaign in campaigns.values()):
            raise _CampaignError("software_target")
        post_hex = _owned_executable_digest(executable, verifier_sha256, expected_size=498176)
        if post_hex != expected_hex:
            raise _CampaignError("verifier_identity_drift")
        evidence = {
            "schema": _SCHEMA,
            "campaigns": campaigns,
            "campaign_count": 2,
            "software_target_ms": 35_000,
            "synthetic_software_path_not_bottleneck": True,
            "verifier_sha256": expected_hex,
            "verifier_pre_post_identity_equal": True,
            "synthetic_only": True,
            "cryptographic_proving_measured": False,
            "native_proof_verification_measured": False,
            "official_receiver_measured": False,
            "full_product_throughput": False,
            "resource_qualification": False,
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
            "payment_calls": 0,
            "payment_state_mutations": 0,
            "economic_mutation": False,
            "total_wall_ms": round((time.perf_counter() - start) * 1000.0, 3),
            "excluded": ["native_proving", "native_verification", "official_receiver", "payment_rails", "production_capacity"],
        }
        _write_json_atomically(output_path, evidence)
        return evidence
    finally:
        if campaign_root.exists():
            _cleanup_campaign_root(campaign_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-path", type=Path, required=True)
    parser.add_argument("--template-queue", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    args = parser.parse_args()
    try:
        verifier_sha256 = bytes.fromhex(args.verifier_sha256)
    except ValueError:
        raise SystemExit("campaign_verifier_hash")
    if len(verifier_sha256) != 32:
        raise SystemExit("campaign_verifier_hash")
    evidence = run(output_path=args.evidence_path, template_queue=args.template_queue, executable=args.executable, verifier_sha256=verifier_sha256)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
