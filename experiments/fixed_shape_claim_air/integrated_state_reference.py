"""Synthetic payment/verifier/state integration reference.

This module models one in-memory compare-and-swap over the complete candidate
identity tuple, legacy aliases, provisional wide replay state, composite
payment state, nonce registry, and batch registry.  It consumes only typed
outputs issued by :mod:`app.batch.pq_verifier_reference`.

It is not durable, crash-consistent, an authenticated payment-map transition,
or production state.  The payment subroots remain opaque REFERENCE/v0 inputs;
only their strict composite framing, sequence, and exact K256 operation-log
append are checked here.  Protected live settlement/state code is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
from itertools import islice
import os
import threading
from typing import Final, Iterable, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_replay_state_reference import (
    MAX_SYNTHETIC_REPLAY_KEYS,
    ProvisionalStrongReplayTransitionV1,
)
from app.batch.pq_state_reference import WideDigest, strong_nullifier_set_root
from app.batch.pq_verifier_reference import (
    SyntheticActiveSuiteTupleV1,
    SyntheticStrongVerifierAuthorityV1,
    SyntheticVerifiedStrongOutputsV1,
)

from .payment import SlotEconomics
from .payment_state import (
    PaymentStateRootPairReference,
    StrongPaymentStateV1Reference,
    append_reference_operation_log,
    build_reference_payment_root_pair,
    reference_payment_state_root,
)
from .semantics import StructuralError


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_COMPLETE_TUPLE_CAS_IN_MEMORY_NO_DURABILITY_NO_PAYMENT_MAP_PROOF"
)
PAYMENT_TRANSITION_STATUS: Final[str] = (
    "SYNTHETIC_K256_COMPOSITE_AND_OPERATION_LOG_ONLY_NO_AUTHENTICATED_MAPS"
)
SYNTHETIC_INTEGRATED_STATE_ENABLE_ENV: Final[str] = (
    "BL_ALLOW_SYNTHETIC_PQ_INTEGRATED_STATE_REFERENCE"
)
K256_OPERATION_COUNT: Final[int] = 256
WIDE_BYTES: Final[int] = 64
FELT_BYTES: Final[int] = 32

_UINT64_MAX: Final[int] = (1 << 64) - 1
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})
_NONCE_REGISTRY_DOMAIN: Final[bytes] = b"BL/PQ512/NONCE-REGISTRY/REFERENCE/v0"
_BATCH_REGISTRY_DOMAIN: Final[bytes] = b"BL/PQ512/BATCH-REGISTRY/REFERENCE/v0"
_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/COMPLETE-TUPLE-STATE/REFERENCE/v0"


def require_synthetic_integrated_state_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_INTEGRATED_STATE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_pq_integrated_state_reference_forbidden:"
            "requires_local_test_env_and_explicit_dev_flags"
        )


def _exact_bytes(
    label: str,
    value: object,
    *,
    length: int,
    nonzero: bool = False,
) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label}_must_be_exact_bytes")
    if len(value) != length:
        raise ValueError(f"{label}_length_invalid")
    if nonzero and not any(value):
        raise ValueError(f"{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise TypeError(f"{label}_must_be_integer")
    if value < 0 or value > _UINT64_MAX or (nonzero and value == 0):
        raise ValueError(f"{label}_out_of_range")
    return value


def _felt(label: str, value: object, *, nonzero: bool = False) -> bytes:
    raw = _exact_bytes(label, value, length=FELT_BYTES, nonzero=nonzero)
    if int.from_bytes(raw, "big") >= FIELD_MODULUS:
        raise ValueError(f"{label}_not_canonical_stark_felt")
    return raw


def _canonical_keys(values: Iterable[bytes], *, label: str) -> tuple[bytes, ...]:
    if type(values) is not tuple:
        raise TypeError(f"{label}s_must_be_exact_tuple")
    if len(values) > MAX_SYNTHETIC_REPLAY_KEYS:
        raise ValueError(f"{label}_capacity_exceeded")
    materialized = tuple(
        _exact_bytes(label, value, length=WIDE_BYTES, nonzero=True)
        for value in values
    )
    ordered = tuple(sorted(materialized))
    if len(set(ordered)) != len(ordered):
        raise ValueError(f"{label}_duplicate")
    return ordered


def _replay_root(keys: tuple[bytes, ...]) -> bytes:
    return strong_nullifier_set_root(
        tuple(WideDigest.from_bytes(value) for value in keys)
    ).to_bytes()


def _registry_root(domain: bytes, entries: tuple[bytes, ...], *, width: int) -> bytes:
    ordered = tuple(sorted(_exact_bytes("state_registry_entry", value, length=width) for value in entries))
    if len(set(ordered)) != len(ordered):
        raise ValueError("state_registry_entry_duplicate")
    return sha3_512(
        domain
        + len(ordered).to_bytes(8, "big")
        + b"".join(ordered)
    ).digest()


@dataclass(frozen=True, slots=True)
class ProvisionalPaymentTransitionV1:
    before: StrongPaymentStateV1Reference = field(repr=False)
    after: StrongPaymentStateV1Reference = field(repr=False)
    economics: tuple[SlotEconomics, ...] = field(repr=False)
    roots: PaymentStateRootPairReference = field(repr=False)
    reference_status: str = PAYMENT_TRANSITION_STATUS

    def __post_init__(self) -> None:
        require_synthetic_integrated_state_enabled()
        if self.reference_status != PAYMENT_TRANSITION_STATUS:
            raise StructuralError("integrated_payment_transition_status_invalid")
        if not isinstance(self.before, StrongPaymentStateV1Reference) or not isinstance(
            self.after, StrongPaymentStateV1Reference
        ):
            raise StructuralError("integrated_payment_state_type_invalid")
        if type(self.economics) is not tuple or len(self.economics) != K256_OPERATION_COUNT:
            raise StructuralError("integrated_payment_operation_count_mismatch")
        if any(
            not isinstance(operation, SlotEconomics)
            or operation.slot_index != position
            for position, operation in enumerate(self.economics)
        ):
            raise StructuralError("integrated_payment_operation_order_invalid")
        if not isinstance(self.roots, PaymentStateRootPairReference):
            raise StructuralError("integrated_payment_root_pair_type_invalid")
        expected_roots = build_reference_payment_root_pair(self.before, self.after)
        if self.roots != expected_roots:
            raise StructuralError("integrated_payment_root_pair_mismatch")
        expected_log = append_reference_operation_log(
            self.before.operation_log_root_512,
            self.economics,
            expected_count=K256_OPERATION_COUNT,
        )
        if self.after.operation_log_root_512 != expected_log:
            raise StructuralError("integrated_payment_operation_log_mismatch")


def build_provisional_payment_transition(
    before: StrongPaymentStateV1Reference,
    after: StrongPaymentStateV1Reference,
    economics: Sequence[SlotEconomics],
) -> ProvisionalPaymentTransitionV1:
    require_synthetic_integrated_state_enabled()
    try:
        materialized = tuple(islice(iter(economics), K256_OPERATION_COUNT + 1))
    except TypeError as exc:
        raise StructuralError("integrated_payment_operations_must_be_iterable") from exc
    if len(materialized) != K256_OPERATION_COUNT:
        raise StructuralError("integrated_payment_operation_count_mismatch")
    expected_log = append_reference_operation_log(
        before.operation_log_root_512,
        materialized,
        expected_count=K256_OPERATION_COUNT,
    )
    if after.operation_log_root_512 != expected_log:
        raise StructuralError("integrated_payment_operation_log_mismatch")
    roots = build_reference_payment_root_pair(before, after)
    return ProvisionalPaymentTransitionV1(before, after, materialized, roots)


@dataclass(frozen=True, slots=True)
class _CompleteStateData:
    sequence: int
    legacy_nullifier_root: bytes
    legacy_governed_roots: tuple[bytes, bytes, bytes, bytes]
    replay_keys_512: tuple[bytes, ...]
    strong_governance_commitment: bytes
    payment_state: StrongPaymentStateV1Reference
    consumed_nonces: tuple[bytes, ...]
    recorded_batch_commitments: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class SyntheticCompleteStateSnapshotV1:
    active_registry_commitment_sha3_512: bytes
    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    sequence: int
    legacy_protocol_version_alias: bytes
    legacy_settlement_domain_alias: bytes
    legacy_nullifier_root: bytes
    legacy_governed_roots: tuple[bytes, bytes, bytes, bytes]
    strong_nullifier_root: bytes
    strong_governance_commitment: bytes
    strong_payment_state_root: bytes
    nonce_registry_root: bytes
    batch_registry_root: bytes
    replay_key_count: int
    consumed_nonce_count: int
    recorded_batch_count: int
    state_commitment_sha3_512: bytes
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_integrated_state_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("synthetic_complete_state_snapshot_status_invalid")


def _snapshot_for(
    active: SyntheticActiveSuiteTupleV1,
    active_encoded: bytes,
    registry_commitment: bytes,
    data: _CompleteStateData,
) -> SyntheticCompleteStateSnapshotV1:
    if active.encode() != active_encoded:
        raise ValueError("synthetic_complete_state_pinned_identity_corrupted")
    replay_root = _replay_root(data.replay_keys_512)
    payment_root = reference_payment_state_root(data.payment_state)
    nonce_root = _registry_root(
        _NONCE_REGISTRY_DOMAIN,
        data.consumed_nonces,
        width=FELT_BYTES,
    )
    batch_root = _registry_root(
        _BATCH_REGISTRY_DOMAIN,
        data.recorded_batch_commitments,
        width=WIDE_BYTES,
    )
    state_preimage = b"".join(
        (
            _STATE_DOMAIN,
            registry_commitment,
            active_encoded,
            data.sequence.to_bytes(8, "big"),
            data.legacy_nullifier_root,
            b"".join(data.legacy_governed_roots),
            replay_root,
            data.strong_governance_commitment,
            payment_root,
            nonce_root,
            batch_root,
            len(data.replay_keys_512).to_bytes(8, "big"),
            len(data.consumed_nonces).to_bytes(8, "big"),
            len(data.recorded_batch_commitments).to_bytes(8, "big"),
        )
    )
    return SyntheticCompleteStateSnapshotV1(
        active_registry_commitment_sha3_512=registry_commitment,
        profile_id=active.profile_id,
        proof_suite_id=active.proof_suite_id,
        schema_id=active.schema_id,
        verifier_artifact_identity=active.verifier_artifact_identity,
        strong_settlement_domain_id=active.strong_settlement_domain_id,
        epoch=active.epoch,
        sequence=data.sequence,
        legacy_protocol_version_alias=active.legacy_protocol_version_alias,
        legacy_settlement_domain_alias=active.legacy_settlement_domain_alias,
        legacy_nullifier_root=data.legacy_nullifier_root,
        legacy_governed_roots=data.legacy_governed_roots,
        strong_nullifier_root=replay_root,
        strong_governance_commitment=data.strong_governance_commitment,
        strong_payment_state_root=payment_root,
        nonce_registry_root=nonce_root,
        batch_registry_root=batch_root,
        replay_key_count=len(data.replay_keys_512),
        consumed_nonce_count=len(data.consumed_nonces),
        recorded_batch_count=len(data.recorded_batch_commitments),
        state_commitment_sha3_512=sha3_512(state_preimage).digest(),
    )


class SyntheticCompleteTupleStateV1:
    """One immutable-pointer CAS under a lock; no durable transaction claim."""

    __slots__ = (
        "_authority",
        "_lock",
        "_data",
        "_pinned_active",
        "_pinned_active_encoded",
        "_pinned_registry_commitment",
        "_sealed",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("synthetic_complete_state_is_sealed")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        authority: SyntheticStrongVerifierAuthorityV1,
        sequence: int,
        legacy_nullifier_root: bytes,
        legacy_governed_roots: Sequence[bytes],
        replay_keys_512: Iterable[bytes],
        strong_governance_commitment: bytes,
        payment_state: StrongPaymentStateV1Reference,
    ) -> None:
        require_synthetic_integrated_state_enabled()
        if type(authority) is not SyntheticStrongVerifierAuthorityV1:
            raise TypeError("synthetic_complete_state_authority_required")
        sequence_value = _u64("synthetic_complete_state_sequence", sequence)
        legacy_root = _felt("synthetic_complete_state_legacy_nullifier_root", legacy_nullifier_root)
        try:
            governed_values = tuple(islice(iter(legacy_governed_roots), 5))
        except TypeError as exc:
            raise TypeError("synthetic_complete_state_governed_roots_must_be_iterable") from exc
        if len(governed_values) != 4:
            raise ValueError("synthetic_complete_state_governed_root_count_mismatch")
        governed = tuple(
            _felt(f"synthetic_complete_state_governed_root_{index}", value)
            for index, value in enumerate(governed_values)
        )
        replay = _canonical_keys(replay_keys_512, label="synthetic_complete_state_replay_key")
        governance = _exact_bytes(
            "synthetic_complete_state_strong_governance",
            strong_governance_commitment,
            length=WIDE_BYTES,
            nonzero=True,
        )
        if not isinstance(payment_state, StrongPaymentStateV1Reference):
            raise TypeError("synthetic_complete_state_payment_state_required")
        active_source = authority.registry.active
        active = SyntheticActiveSuiteTupleV1(
            profile_id=active_source.profile_id,
            proof_suite_id=active_source.proof_suite_id,
            schema_id=active_source.schema_id,
            verifier_artifact_identity=active_source.verifier_artifact_identity,
            strong_settlement_domain_id=active_source.strong_settlement_domain_id,
            epoch=active_source.epoch,
            legacy_protocol_version_alias=active_source.legacy_protocol_version_alias,
            legacy_settlement_domain_alias=active_source.legacy_settlement_domain_alias,
        )
        if payment_state.epoch != active.epoch:
            raise ValueError("synthetic_complete_state_payment_epoch_mismatch")
        if payment_state.sequence != sequence_value:
            raise ValueError("synthetic_complete_state_payment_sequence_mismatch")
        self._authority = authority
        self._lock = threading.Lock()
        self._pinned_active = active
        self._pinned_active_encoded = active.encode()
        self._pinned_registry_commitment = authority.registry.commitment_sha3_512
        self._data = _CompleteStateData(
            sequence=sequence_value,
            legacy_nullifier_root=legacy_root,
            legacy_governed_roots=governed,  # type: ignore[arg-type]
            replay_keys_512=replay,
            strong_governance_commitment=governance,
            payment_state=payment_state,
            consumed_nonces=(),
            recorded_batch_commitments=(),
        )
        self._sealed = True

    def _validate_authority_pin(self) -> None:
        if self._pinned_active.encode() != self._pinned_active_encoded:
            raise ValueError("synthetic_complete_state_pinned_identity_corrupted")
        registry = self._authority.registry
        if (
            registry.active.encode() != self._pinned_active_encoded
            or not hmac.compare_digest(
                registry.commitment_sha3_512,
                self._pinned_registry_commitment,
            )
        ):
            raise ValueError("synthetic_complete_state_authority_registry_drift")

    def _snapshot_locked(self, data: _CompleteStateData) -> SyntheticCompleteStateSnapshotV1:
        self._validate_authority_pin()
        return _snapshot_for(
            self._pinned_active,
            self._pinned_active_encoded,
            self._pinned_registry_commitment,
            data,
        )

    def snapshot(self) -> SyntheticCompleteStateSnapshotV1:
        require_synthetic_integrated_state_enabled()
        with self._lock:
            return self._snapshot_locked(self._data)

    def commit_verified_transition(
        self,
        receipt: SyntheticVerifiedStrongOutputsV1,
        replay: ProvisionalStrongReplayTransitionV1,
        payment: ProvisionalPaymentTransitionV1,
        *,
        expected_state_commitment_sha3_512: bytes,
    ) -> SyntheticCompleteStateSnapshotV1:
        require_synthetic_integrated_state_enabled()
        if type(replay) is not ProvisionalStrongReplayTransitionV1:
            raise TypeError("synthetic_complete_state_replay_transition_required")
        if type(payment) is not ProvisionalPaymentTransitionV1:
            raise TypeError("synthetic_complete_state_payment_transition_required")
        expected_cas = _exact_bytes(
            "synthetic_complete_state_expected_commitment",
            expected_state_commitment_sha3_512,
            length=WIDE_BYTES,
            nonzero=True,
        )
        authenticated_public, sidecar = self._authority.validate_verified_outputs(
            receipt,
            expected_salt_use_tag_512=replay.salt_use_tag_512,
        )

        with self._lock:
            replay.__post_init__()
            payment.__post_init__()
            self._validate_authority_pin()
            current = self._data
            current_snapshot = self._snapshot_locked(current)
            if current_snapshot.state_commitment_sha3_512 != expected_cas:
                raise ValueError("synthetic_complete_state_compare_and_swap_mismatch")
            active = self._pinned_active
            public = authenticated_public
            if sidecar.epoch != active.epoch:
                raise ValueError("synthetic_complete_state_epoch_mismatch")
            if sidecar.sequence_before != current.sequence:
                raise ValueError("synthetic_complete_state_stale_sequence")
            if current.sequence == _UINT64_MAX or sidecar.sequence_after != current.sequence + 1:
                raise ValueError("synthetic_complete_state_sequence_transition_invalid")
            if public[3] != current.legacy_nullifier_root:
                raise ValueError("synthetic_complete_state_stale_legacy_nullifier_root")
            if public[4] == public[3]:
                raise ValueError("synthetic_complete_state_legacy_nullifier_root_unchanged")
            if public[5:9] != current.legacy_governed_roots:
                raise ValueError("synthetic_complete_state_legacy_governed_roots_mismatch")
            if replay.existing_keys_512 != current.replay_keys_512:
                raise ValueError("synthetic_complete_state_replay_keys_before_mismatch")
            if len(replay.merged_keys_512) > MAX_SYNTHETIC_REPLAY_KEYS:
                raise ValueError("synthetic_complete_state_replay_key_capacity_exceeded")
            if replay.root_before_512 != current_snapshot.strong_nullifier_root:
                raise ValueError("synthetic_complete_state_strong_nullifier_root_before_mismatch")
            if sidecar.strong_nullifier_root_before != replay.root_before_512:
                raise ValueError("synthetic_complete_state_sidecar_nullifier_before_mismatch")
            if sidecar.strong_nullifier_root_after != replay.root_after_512:
                raise ValueError("synthetic_complete_state_sidecar_nullifier_after_mismatch")
            if sidecar.strong_governance_commitment != current.strong_governance_commitment:
                raise ValueError("synthetic_complete_state_governance_mismatch")
            if payment.before != current.payment_state:
                raise ValueError("synthetic_complete_state_payment_before_mismatch")
            if payment.before.sequence != current.sequence or payment.after.sequence != current.sequence + 1:
                raise ValueError("synthetic_complete_state_payment_sequence_mismatch")
            if payment.before.epoch != active.epoch or payment.after.epoch != active.epoch:
                raise ValueError("synthetic_complete_state_payment_epoch_mismatch")
            if sidecar.strong_payment_state_root_before != payment.roots.root_before_512:
                raise ValueError("synthetic_complete_state_sidecar_payment_before_mismatch")
            if sidecar.strong_payment_state_root_after != payment.roots.root_after_512:
                raise ValueError("synthetic_complete_state_sidecar_payment_after_mismatch")
            nonce = public[2]
            if nonce in current.consumed_nonces:
                raise ValueError("synthetic_complete_state_nonce_already_consumed")
            batch_commitment = sidecar.strong_batch_commitment
            if batch_commitment in current.recorded_batch_commitments:
                raise ValueError("synthetic_complete_state_batch_already_recorded")

            prospective = _CompleteStateData(
                sequence=current.sequence + 1,
                legacy_nullifier_root=public[4],
                legacy_governed_roots=current.legacy_governed_roots,
                replay_keys_512=replay.merged_keys_512,
                strong_governance_commitment=current.strong_governance_commitment,
                payment_state=payment.after,
                consumed_nonces=tuple(sorted((*current.consumed_nonces, nonce))),
                recorded_batch_commitments=tuple(
                    sorted((*current.recorded_batch_commitments, batch_commitment))
                ),
            )
            prospective_snapshot = self._snapshot_locked(prospective)
            if prospective_snapshot.strong_nullifier_root != sidecar.strong_nullifier_root_after:
                raise ValueError("synthetic_complete_state_prospective_nullifier_root_mismatch")
            if prospective_snapshot.strong_payment_state_root != sidecar.strong_payment_state_root_after:
                raise ValueError("synthetic_complete_state_prospective_payment_root_mismatch")
            object.__setattr__(self, "_data", prospective)
            return prospective_snapshot
