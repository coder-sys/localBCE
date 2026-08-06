"""Full internal Wave 3 boundary, still deliberately nonactivating.

The earlier Wave 3 module supplied useful P01-P12 reference objects but kept
the state owner at one-record granularity and did not provide a durable
registry or a canonical proof container.  This module closes those internal
engineering seams without pretending that the unselected global proof suite,
HSM/FIPS custody, or production activation exists.

Only digest-bearing metadata is persisted beside private synthetic A12
preimages.  The exact 12-field boundary remains an ordered tuple of canonical
32-byte felts.  A batch advances the full state tuple once, after replaying
all 256 fixed-shape slots and one context-free hidden salt-use key.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from hashlib import sha3_512
import hmac
import os
from pathlib import Path
import subprocess
import tempfile
from threading import RLock
from typing import Final, Mapping, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import (
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    candidate_salt_use_tag,
    validate_active_binding,
)
from experiments.bl_pq512_crypto_foundation.wave3_nullifier_authority import (
    RECORD_COVER,
    WIDE_BYTES,
    Wave3NullifierAuthorityV1,
    Wave3NullifierError,
    Wave3StateSnapshotV1,
    independently_verify_wave3_transition,
)
from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
    ActiveVerifierProfileV1,
    DUAL_PQ_SUITES,
    DualPqAuthorityV1,
    GovernedRootRecordV1,
    GovernedRootRegistryV1,
    PqSignatureEnvelopeV1,
    SIGNATURE_SIZES,
    Wave3BoundaryError,
    Wave3MigrationRecordV1,
    Wave3RollbackRecordV1,
    Wave3UpgradeRecordV1,
    Wave3VerifierV1,
    VerifiedProofContextV1,
    ZERO_ID_512,
)


MODULE_STATUS: Final[str] = "WAVE3_FULL_INTERNAL_BOUNDARY_NONACTIVATING"
ACTIVATION_ALLOWED: Final[bool] = False
PROOF_SUITE_ID: None = None

UINT64_MAX: Final[int] = (1 << 64) - 1
IDENTITY_BYTES: Final[int] = 64
FELT_BYTES: Final[int] = 32
PUBLIC_FIELD_COUNT: Final[int] = 12
BATCH_SLOT_COUNT: Final[int] = 256
MAX_BATCHES: Final[int] = 64
MAX_HISTORY: Final[int] = 16
MAX_BATCH_RECORD_BYTES: Final[int] = 8 * 1024 * 1024
MAX_AUTH_STATE_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PROOF_BODY_BYTES: Final[int] = 256 * 1024 * 1024
MAX_RUST_OUTPUT_BYTES: Final[int] = 4 * 1024 * 1024
STATE_BINDING_MAGIC: Final[bytes] = b"BLSB01"
STATE_BINDING_VERSION: Final[int] = 2
STATE_OPERATION_BYTES: Final[int] = 274
MAX_STATE_BINDING_OPERATIONS: Final[int] = 4096

CUSTODY_AUDIT_MAGIC: Final[bytes] = b"BLW3CA01"
CUSTODY_AUDIT_VERSION: Final[int] = 1
CUSTODY_COUNTER_MAGIC: Final[bytes] = b"BLW3CT01"
CUSTODY_COUNTER_VERSION: Final[int] = 1

FULL_BATCH_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/FULL-BATCH/v1\x00"
PAYMENT_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/PRIVATE-PAYMENT-STATE/v1\x00"
AUTH_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/AUTHORITATIVE-STATE/v1\x00"
AUTH_STATE_FILE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/AUTHORITATIVE-FILE/v1\x00"
AUTH_STATE_MAGIC: Final[bytes] = b"BLW3AT01"
AUTH_STATE_VERSION: Final[int] = 1
REGISTRY_STORE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/ROOT-REGISTRY-FILE/v1\x00"
REGISTRY_STORE_MAGIC: Final[bytes] = b"BLW3RG01"
REGISTRY_STORE_VERSION: Final[int] = 1
PROOF_ENVELOPE_MAGIC: Final[bytes] = b"BLPQEN01"
PROOF_ENVELOPE_VERSION: Final[int] = 1
PROOF_ENVELOPE_FLAGS: Final[int] = 0
PROOF_ENVELOPE_HEADER_BYTES: Final[int] = 24
RUST_VERIFIER_IDENTITY: Final[bytes] = sha3_512(
    b"BL/PQ512/WAVE3/RUST-STATE-BINDING-PORT/v1\x00"
).digest()
RECOVERY_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/AUTHORITATIVE-RECOVERY/v1\x00"
CUSTODY_AUDIT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/CUSTODY-AUDIT/v1\x00"
CUSTODY_AUDIT_PAYLOAD_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/CUSTODY-AUDIT-PAYLOAD/v1\x00"
CUSTODY_AUDIT_FILE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/CUSTODY-AUDIT-FILE/v1\x00"
CUSTODY_COUNTER_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/CUSTODY-COUNTER/v1\x00"
MAX_AUDIT_EVENTS: Final[int] = 100_000
MAX_AUDIT_EVENT_BYTES: Final[int] = 512


class Wave3FullBoundaryError(ValueError):
    """Stable fail-closed error for the full internal Wave 3 boundary."""


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise Wave3FullBoundaryError(f"wave3_full_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise Wave3FullBoundaryError(f"wave3_full_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise Wave3FullBoundaryError(f"wave3_full_{label}_out_of_range")
    if nonzero and value == 0:
        raise Wave3FullBoundaryError(f"wave3_full_{label}_must_be_nonzero")
    return value


def _felt(label: str, value: object, *, nonzero: bool = False) -> bytes:
    checked = _bytes(label, value, FELT_BYTES)
    integer = int.from_bytes(checked, "big")
    if integer >= FIELD_MODULUS or (nonzero and integer == 0):
        raise Wave3FullBoundaryError(f"wave3_full_{label}_not_canonical_felt")
    return checked


def _frame(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 0xFFFF:
        raise Wave3FullBoundaryError("wave3_full_domain_invalid")
    encoded = bytearray(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise Wave3FullBoundaryError("wave3_full_frame_part_invalid")
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha3_512(_frame(domain, *parts)).digest()


def _canonical_public_fields(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list) or len(values) != PUBLIC_FIELD_COUNT:
        raise Wave3FullBoundaryError("wave3_full_public_field_count_invalid")
    return tuple(_felt(f"public_field_{index}", value) for index, value in enumerate(values))


@dataclass(frozen=True, slots=True)
class Wave3ProofEnvelopeV1:
    """The sole portable sidecar/proof-body container; public fields stay out-of-band."""

    encoded_sidecar: bytes
    proof_body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        try:
            sidecar = CandidateSidecarV1.decode(self.encoded_sidecar)
        except (TypeError, ValueError) as exc:
            raise Wave3FullBoundaryError("wave3_full_envelope_sidecar_rejected") from exc
        if type(self.proof_body) is not bytes or not self.proof_body:
            raise Wave3FullBoundaryError("wave3_full_envelope_proof_body_invalid")
        if len(self.proof_body) > MAX_PROOF_BODY_BYTES:
            raise Wave3FullBoundaryError("wave3_full_envelope_proof_body_too_large")
        if sidecar.encode() != self.encoded_sidecar:
            raise Wave3FullBoundaryError("wave3_full_envelope_sidecar_noncanonical")

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                PROOF_ENVELOPE_MAGIC,
                PROOF_ENVELOPE_VERSION.to_bytes(2, "big"),
                PROOF_ENVELOPE_FLAGS.to_bytes(2, "big"),
                len(self.encoded_sidecar).to_bytes(4, "big"),
                len(self.proof_body).to_bytes(8, "big"),
                self.encoded_sidecar,
                self.proof_body,
            )
        )
        if len(encoded) > MAX_PROOF_BODY_BYTES + 1024:
            raise Wave3FullBoundaryError("wave3_full_envelope_size_limit_exceeded")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3ProofEnvelopeV1":
        if type(encoded) is not bytes or len(encoded) < PROOF_ENVELOPE_HEADER_BYTES:
            raise Wave3FullBoundaryError("wave3_full_envelope_length_invalid")
        if encoded[:8] != PROOF_ENVELOPE_MAGIC:
            raise Wave3FullBoundaryError("wave3_full_envelope_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != PROOF_ENVELOPE_VERSION:
            raise Wave3FullBoundaryError("wave3_full_envelope_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != PROOF_ENVELOPE_FLAGS:
            raise Wave3FullBoundaryError("wave3_full_envelope_flags_invalid")
        sidecar_length = int.from_bytes(encoded[12:16], "big")
        proof_length = int.from_bytes(encoded[16:24], "big")
        if sidecar_length != 744 or proof_length == 0 or proof_length > MAX_PROOF_BODY_BYTES:
            raise Wave3FullBoundaryError("wave3_full_envelope_declared_length_invalid")
        expected = PROOF_ENVELOPE_HEADER_BYTES + sidecar_length + proof_length
        if expected != len(encoded):
            raise Wave3FullBoundaryError("wave3_full_envelope_trailing_or_truncated")
        return cls(encoded[24 : 24 + sidecar_length], encoded[24 + sidecar_length :])


@dataclass(frozen=True, slots=True)
class Wave3FullBatchInputV1:
    """Ephemeral private inputs for one exact 256-slot batch."""

    raw_preimages: tuple[bytes, ...]
    master_salt_512: bytes = field(repr=False)
    canonical_private_batch_commitment_512: bytes
    hidden_strong_value_commitment_512: bytes

    def __post_init__(self) -> None:
        if type(self.raw_preimages) is not tuple or len(self.raw_preimages) != BATCH_SLOT_COUNT:
            raise Wave3FullBoundaryError("wave3_full_batch_slot_count_invalid")
        for index, raw in enumerate(self.raw_preimages):
            if type(raw) is not bytes or not raw or len(raw) > 16_384:
                raise Wave3FullBoundaryError(f"wave3_full_batch_preimage_{index}_invalid")
        _bytes("batch_master_salt", self.master_salt_512, IDENTITY_BYTES, nonzero=True)
        _bytes(
            "batch_private_commitment",
            self.canonical_private_batch_commitment_512,
            IDENTITY_BYTES,
            nonzero=True,
        )
        _bytes(
            "batch_value_commitment",
            self.hidden_strong_value_commitment_512,
            IDENTITY_BYTES,
            nonzero=True,
        )

    @property
    def salt_use_tag_512(self) -> bytes:
        return candidate_salt_use_tag(self.master_salt_512)


def _full_batch_commitment_from_salt_tag(
    *,
    encoded_sidecar_prefix: bytes,
    public_fields: Sequence[bytes],
    private_batch_commitment_512: bytes,
    hidden_strong_value_commitment_512: bytes,
    salt_use_tag_512: bytes,
) -> bytes:
    prefix = _bytes("batch_sidecar_prefix", encoded_sidecar_prefix, 680)
    public = _canonical_public_fields(public_fields)
    return _digest(
        FULL_BATCH_DOMAIN,
        prefix,
        b"".join(public),
        _bytes("batch_private_commitment", private_batch_commitment_512, 64, nonzero=True),
        _bytes("batch_value_commitment", hidden_strong_value_commitment_512, 64, nonzero=True),
        _bytes("batch_salt_use_tag", salt_use_tag_512, 64, nonzero=True),
    )


def full_batch_commitment(
    *,
    encoded_sidecar_prefix: bytes,
    public_fields: Sequence[bytes],
    private_batch_commitment_512: bytes,
    hidden_strong_value_commitment_512: bytes,
    master_salt_512: bytes,
) -> bytes:
    return _full_batch_commitment_from_salt_tag(
        encoded_sidecar_prefix=encoded_sidecar_prefix,
        public_fields=public_fields,
        private_batch_commitment_512=private_batch_commitment_512,
        hidden_strong_value_commitment_512=hidden_strong_value_commitment_512,
        salt_use_tag_512=candidate_salt_use_tag(
            _bytes("batch_master_salt", master_salt_512, IDENTITY_BYTES, nonzero=True)
        ),
    )


def derive_payment_state_after_512(
    *,
    payment_state_before_512: bytes,
    private_batch_commitment_512: bytes,
    hidden_strong_value_commitment_512: bytes,
    salt_use_tag_512: bytes,
) -> bytes:
    """Derive the hidden payment-state successor without exposing amounts."""

    return _digest(
        PAYMENT_STATE_DOMAIN,
        _bytes("payment_state_before", payment_state_before_512, IDENTITY_BYTES, nonzero=True),
        _bytes("payment_private_batch_commitment", private_batch_commitment_512, IDENTITY_BYTES, nonzero=True),
        _bytes("payment_hidden_value_commitment", hidden_strong_value_commitment_512, IDENTITY_BYTES, nonzero=True),
        _bytes("payment_salt_use_tag", salt_use_tag_512, IDENTITY_BYTES, nonzero=True),
    )


@dataclass(frozen=True, slots=True)
class Wave3BatchReplayResultV1:
    before: Wave3StateSnapshotV1
    after: Wave3StateSnapshotV1
    salt_use_tag_512: bytes

    def __post_init__(self) -> None:
        if type(self.before) is not Wave3StateSnapshotV1 or type(self.after) is not Wave3StateSnapshotV1:
            raise TypeError("wave3_full_batch_replay_snapshot_invalid")
        _bytes("batch_replay_salt_tag", self.salt_use_tag_512, 64, nonzero=True)
        if self.after.strong_nullifier_root_512 == self.before.strong_nullifier_root_512:
            raise Wave3FullBoundaryError("wave3_full_batch_replay_strong_root_unchanged")


def _replay_batch_on_authority(
    authority: Wave3NullifierAuthorityV1,
    private: Wave3FullBatchInputV1,
) -> Wave3BatchReplayResultV1:
    before = authority.snapshot()
    for raw in private.raw_preimages:
        transition = authority.prepare_transition(raw)
        independently_verify_wave3_transition(transition)
        authority.commit(transition)
    salt_transition = authority.prepare_strong_only_transition(
        private.salt_use_tag_512,
        record_type=RECORD_COVER,
    )
    after = authority.commit_strong_only(salt_transition)
    return Wave3BatchReplayResultV1(before, after, private.salt_use_tag_512)


def _replay_raw_batch_on_authority(
    authority: Wave3NullifierAuthorityV1,
    raw_preimages: Sequence[bytes],
    salt_use_tag_512: bytes,
) -> Wave3BatchReplayResultV1:
    before = authority.snapshot()
    if type(raw_preimages) not in (tuple, list) or len(raw_preimages) != BATCH_SLOT_COUNT:
        raise Wave3FullBoundaryError("wave3_full_replay_raw_batch_shape_invalid")
    for raw in raw_preimages:
        transition = authority.prepare_transition(raw)
        independently_verify_wave3_transition(transition)
        authority.commit(transition)
    salt_transition = authority.prepare_strong_only_transition(
        _bytes("replay_salt_use_tag", salt_use_tag_512, 64, nonzero=True),
        record_type=RECORD_COVER,
    )
    after = authority.commit_strong_only(salt_transition)
    return Wave3BatchReplayResultV1(before, after, salt_use_tag_512)


def replay_wave3_batch(
    private: Wave3FullBatchInputV1,
    *,
    epoch: int,
) -> Wave3BatchReplayResultV1:
    if type(private) is not Wave3FullBatchInputV1:
        raise TypeError("wave3_full_batch_private_inputs_required")
    authority = Wave3NullifierAuthorityV1(epoch=_u64("batch_epoch", epoch, nonzero=True))
    return _replay_batch_on_authority(authority, private)


@dataclass(frozen=True, slots=True)
class Wave3FullBatchAdmissionV1:
    context: VerifiedProofContextV1
    private: Wave3FullBatchInputV1

    def __post_init__(self) -> None:
        if type(self.context) is not VerifiedProofContextV1 or type(self.private) is not Wave3FullBatchInputV1:
            raise TypeError("wave3_full_batch_admission_types_invalid")
        public = _canonical_public_fields(self.context.public_fields)
        sidecar = self.context.sidecar
        expected = full_batch_commitment(
            encoded_sidecar_prefix=sidecar.encode()[:680],
            public_fields=public,
            private_batch_commitment_512=self.private.canonical_private_batch_commitment_512,
            hidden_strong_value_commitment_512=self.private.hidden_strong_value_commitment_512,
            master_salt_512=self.private.master_salt_512,
        )
        if not hmac.compare_digest(sidecar.strong_batch_commitment, expected):
            raise Wave3FullBoundaryError("wave3_full_batch_commitment_mismatch")
        expected_payment_after = derive_payment_state_after_512(
            payment_state_before_512=sidecar.strong_payment_state_root_before,
            private_batch_commitment_512=self.private.canonical_private_batch_commitment_512,
            hidden_strong_value_commitment_512=self.private.hidden_strong_value_commitment_512,
            salt_use_tag_512=self.private.salt_use_tag_512,
        )
        if sidecar.strong_payment_state_root_after != expected_payment_after:
            raise Wave3FullBoundaryError("wave3_full_payment_state_transition_mismatch")

    @property
    def public_fields(self) -> tuple[bytes, ...]:
        return _canonical_public_fields(self.context.public_fields)

    @property
    def sidecar(self) -> CandidateSidecarV1:
        return self.context.sidecar


@dataclass(frozen=True, slots=True)
class Wave3StateTupleV2:
    """The indivisible private authoritative state tuple from S10."""

    profile_id: bytes
    proof_suite_id_512: bytes | None
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    authority_id_512: bytes
    epoch: int
    legacy_protocol_version_alias: bytes
    legacy_settlement_domain_alias: bytes
    global_sequence: int
    legacy_nullifier_root: bytes
    strong_nullifier_root_512: bytes
    legacy_governed_root_aliases: tuple[bytes, ...]
    registry_commitment_512: bytes
    strong_payment_state_root_512: bytes
    consumed_batch_nonces: tuple[bytes, ...]
    recorded_strong_batch_commitments: tuple[bytes, ...]
    last_atomic_binding_512: bytes = ZERO_ID_512

    def __post_init__(self) -> None:
        for label, value in (
            ("state_profile_id", self.profile_id),
            ("state_schema_id", self.schema_id),
            ("state_verifier_identity", self.verifier_artifact_identity),
            ("state_strong_domain", self.strong_settlement_domain_id),
            ("state_authority_id", self.authority_id_512),
            ("state_registry_commitment", self.registry_commitment_512),
            ("state_strong_nullifier_root", self.strong_nullifier_root_512),
            ("state_payment_root", self.strong_payment_state_root_512),
        ):
            _bytes(label, value, IDENTITY_BYTES, nonzero=True)
        if self.proof_suite_id_512 is not None:
            _bytes("state_proof_suite_id", self.proof_suite_id_512, IDENTITY_BYTES, nonzero=True)
        _u64("state_epoch", self.epoch, nonzero=True)
        _u64("state_global_sequence", self.global_sequence)
        if self.legacy_protocol_version_alias != (2).to_bytes(FELT_BYTES, "big"):
            raise Wave3FullBoundaryError("wave3_full_state_protocol_alias_invalid")
        _felt("state_legacy_settlement_alias", self.legacy_settlement_domain_alias, nonzero=True)
        _felt("state_legacy_nullifier_root", self.legacy_nullifier_root)
        if type(self.legacy_governed_root_aliases) is not tuple or len(self.legacy_governed_root_aliases) != 4:
            raise Wave3FullBoundaryError("wave3_full_state_governed_alias_count_invalid")
        for index, value in enumerate(self.legacy_governed_root_aliases):
            _felt(f"state_governed_alias_{index}", value, nonzero=True)
        if type(self.consumed_batch_nonces) is not tuple or len(self.consumed_batch_nonces) > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_state_nonce_count_invalid")
        if type(self.recorded_strong_batch_commitments) is not tuple or len(self.recorded_strong_batch_commitments) != len(self.consumed_batch_nonces):
            raise Wave3FullBoundaryError("wave3_full_state_batch_commitment_count_invalid")
        for index, value in enumerate(self.consumed_batch_nonces):
            _felt(f"state_consumed_nonce_{index}", value, nonzero=True)
        for index, value in enumerate(self.recorded_strong_batch_commitments):
            _bytes(f"state_recorded_batch_commitment_{index}", value, IDENTITY_BYTES, nonzero=True)
        if len(set(self.consumed_batch_nonces)) != len(self.consumed_batch_nonces):
            raise Wave3FullBoundaryError("wave3_full_state_consumed_nonce_duplicate")
        if len(set(self.recorded_strong_batch_commitments)) != len(self.recorded_strong_batch_commitments):
            raise Wave3FullBoundaryError("wave3_full_state_batch_commitment_duplicate")
        if self.global_sequence != len(self.consumed_batch_nonces):
            raise Wave3FullBoundaryError("wave3_full_state_sequence_batch_count_mismatch")
        _bytes("state_last_atomic_binding", self.last_atomic_binding_512, IDENTITY_BYTES)
        if bool(self.consumed_batch_nonces) != bool(any(self.last_atomic_binding_512)):
            raise Wave3FullBoundaryError("wave3_full_state_last_binding_presence_mismatch")

    def canonical_bytes(self) -> bytes:
        suite = b"" if self.proof_suite_id_512 is None else self.proof_suite_id_512
        return b"".join(
            (
                AUTH_STATE_DOMAIN,
                self.profile_id,
                bytes((int(self.proof_suite_id_512 is not None),)),
                suite,
                self.schema_id,
                self.verifier_artifact_identity,
                self.strong_settlement_domain_id,
                self.authority_id_512,
                self.epoch.to_bytes(8, "big"),
                self.legacy_protocol_version_alias,
                self.legacy_settlement_domain_alias,
                self.global_sequence.to_bytes(8, "big"),
                self.legacy_nullifier_root,
                self.strong_nullifier_root_512,
                len(self.legacy_governed_root_aliases).to_bytes(2, "big"),
                b"".join(self.legacy_governed_root_aliases),
                self.registry_commitment_512,
                self.strong_payment_state_root_512,
                len(self.consumed_batch_nonces).to_bytes(4, "big"),
                b"".join(self.consumed_batch_nonces),
                len(self.recorded_strong_batch_commitments).to_bytes(4, "big"),
                b"".join(self.recorded_strong_batch_commitments),
                self.last_atomic_binding_512,
            )
        )

    @property
    def digest_512(self) -> bytes:
        return sha3_512(self.canonical_bytes()).digest()

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3StateTupleV2":
        if type(encoded) is not bytes or len(encoded) < 8 + 64 + 1 + 64 * 6:
            raise Wave3FullBoundaryError("wave3_full_state_tuple_encoding_invalid")
        if not encoded.startswith(AUTH_STATE_DOMAIN):
            raise Wave3FullBoundaryError("wave3_full_state_tuple_domain_invalid")
        cursor = len(AUTH_STATE_DOMAIN)

        def take(length: int, label: str) -> bytes:
            nonlocal cursor
            if length < 0 or cursor + length > len(encoded):
                raise Wave3FullBoundaryError(f"wave3_full_state_tuple_{label}_truncated")
            value = encoded[cursor : cursor + length]
            cursor += length
            return value

        profile = take(64, "profile")
        suite_flag = take(1, "suite_flag")
        if suite_flag not in (b"\x00", b"\x01"):
            raise Wave3FullBoundaryError("wave3_full_state_tuple_suite_flag_invalid")
        suite = take(64, "suite") if suite_flag == b"\x01" else None
        schema = take(64, "schema")
        verifier = take(64, "verifier")
        domain = take(64, "domain")
        authority = take(64, "authority")
        epoch = int.from_bytes(take(8, "epoch"), "big")
        protocol = take(32, "protocol")
        settlement = take(32, "settlement")
        sequence = int.from_bytes(take(8, "sequence"), "big")
        legacy_root = take(32, "legacy_root")
        strong_root = take(64, "strong_root")
        alias_count = int.from_bytes(take(2, "alias_count"), "big")
        if alias_count != 4:
            raise Wave3FullBoundaryError("wave3_full_state_tuple_alias_count_invalid")
        aliases = tuple(take(32, f"alias_{index}") for index in range(alias_count))
        registry = take(64, "registry")
        payment = take(64, "payment")
        nonce_count = int.from_bytes(take(4, "nonce_count"), "big")
        if nonce_count > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_state_tuple_nonce_count_invalid")
        nonces = tuple(take(32, f"nonce_{index}") for index in range(nonce_count))
        commitment_count = int.from_bytes(take(4, "commitment_count"), "big")
        if commitment_count != nonce_count:
            raise Wave3FullBoundaryError("wave3_full_state_tuple_commitment_count_invalid")
        commitments = tuple(take(64, f"commitment_{index}") for index in range(commitment_count))
        binding = take(64, "last_binding")
        if cursor != len(encoded):
            raise Wave3FullBoundaryError("wave3_full_state_tuple_trailing_bytes")
        observed = cls(
            profile,
            suite,
            schema,
            verifier,
            domain,
            authority,
            epoch,
            protocol,
            settlement,
            sequence,
            legacy_root,
            strong_root,
            aliases,
            registry,
            payment,
            nonces,
            commitments,
            binding,
        )
        if observed.canonical_bytes() != encoded:
            raise Wave3FullBoundaryError("wave3_full_state_tuple_noncanonical")
        return observed


@dataclass(frozen=True, slots=True)
class Wave3BatchRecordV1:
    encoded_sidecar: bytes
    public_fields: tuple[bytes, ...]
    raw_preimages: tuple[bytes, ...]
    canonical_private_batch_commitment_512: bytes
    hidden_strong_value_commitment_512: bytes
    salt_use_tag_512: bytes
    proof_digest_512: bytes
    atomic_binding_512: bytes

    def __post_init__(self) -> None:
        try:
            sidecar = CandidateSidecarV1.decode(self.encoded_sidecar)
        except (TypeError, ValueError) as exc:
            raise Wave3FullBoundaryError("wave3_full_batch_record_sidecar_invalid") from exc
        if sidecar.encode() != self.encoded_sidecar:
            raise Wave3FullBoundaryError("wave3_full_batch_record_sidecar_noncanonical")
        _canonical_public_fields(self.public_fields)
        if type(self.raw_preimages) is not tuple or len(self.raw_preimages) != BATCH_SLOT_COUNT:
            raise Wave3FullBoundaryError("wave3_full_batch_record_slot_count_invalid")
        for index, raw in enumerate(self.raw_preimages):
            if type(raw) is not bytes or not raw or len(raw) > 16_384:
                raise Wave3FullBoundaryError(f"wave3_full_batch_record_preimage_{index}_invalid")
        _bytes(
            "batch_record_private_commitment",
            self.canonical_private_batch_commitment_512,
            IDENTITY_BYTES,
            nonzero=True,
        )
        _bytes(
            "batch_record_value_commitment",
            self.hidden_strong_value_commitment_512,
            IDENTITY_BYTES,
            nonzero=True,
        )
        _bytes("batch_record_salt_tag", self.salt_use_tag_512, 64, nonzero=True)
        _bytes("batch_record_proof_digest", self.proof_digest_512, 64, nonzero=True)
        _bytes("batch_record_atomic_binding", self.atomic_binding_512, 64, nonzero=True)

    @property
    def batch_nonce_32(self) -> bytes:
        return self.public_fields[2]

    @property
    def strong_batch_commitment_512(self) -> bytes:
        return CandidateSidecarV1.decode(self.encoded_sidecar).strong_batch_commitment

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                self.encoded_sidecar,
                b"".join(self.public_fields),
                len(self.raw_preimages).to_bytes(2, "big"),
                b"".join(len(raw).to_bytes(4, "big") + raw for raw in self.raw_preimages),
                self.canonical_private_batch_commitment_512,
                self.hidden_strong_value_commitment_512,
                self.salt_use_tag_512,
                self.proof_digest_512,
                self.atomic_binding_512,
            )
        )

    @property
    def digest_512(self) -> bytes:
        return sha3_512(self.canonical_bytes()).digest()

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3BatchRecordV1":
        if type(encoded) is not bytes or len(encoded) < 744 + 384 + 2 + 64 * 5:
            raise Wave3FullBoundaryError("wave3_full_batch_record_encoding_invalid")
        cursor = 0

        def take(length: int, label: str) -> bytes:
            nonlocal cursor
            if cursor + length > len(encoded):
                raise Wave3FullBoundaryError(f"wave3_full_batch_record_{label}_truncated")
            value = encoded[cursor : cursor + length]
            cursor += length
            return value

        sidecar = take(744, "sidecar")
        public = tuple(_felt(f"batch_record_public_{index}", take(32, f"public_{index}")) for index in range(12))
        count = int.from_bytes(take(2, "preimage_count"), "big")
        if count != BATCH_SLOT_COUNT:
            raise Wave3FullBoundaryError("wave3_full_batch_record_preimage_count_invalid")
        raws = []
        for index in range(count):
            length = int.from_bytes(take(4, f"preimage_{index}_length"), "big")
            if length == 0 or length > 16_384:
                raise Wave3FullBoundaryError(f"wave3_full_batch_record_preimage_{index}_length_invalid")
            raws.append(take(length, f"preimage_{index}"))
        private_commitment = take(64, "private_commitment")
        value_commitment = take(64, "value_commitment")
        salt = take(64, "salt_tag")
        proof = take(64, "proof_digest")
        binding = take(64, "atomic_binding")
        if cursor != len(encoded):
            raise Wave3FullBoundaryError("wave3_full_batch_record_trailing_bytes")
        observed = cls(
            sidecar,
            public,
            tuple(raws),
            private_commitment,
            value_commitment,
            salt,
            proof,
            binding,
        )
        if observed.canonical_bytes() != encoded:
            raise Wave3FullBoundaryError("wave3_full_batch_record_noncanonical")
        return observed


ROOT_RECORD_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE3/GOVERNED-ROOT/v1\x00"


def _decode_governed_root_record(encoded: bytes) -> GovernedRootRecordV1:
    if type(encoded) is not bytes or not encoded.startswith(ROOT_RECORD_DOMAIN):
        raise Wave3FullBoundaryError("wave3_full_registry_record_domain_invalid")
    cursor = len(ROOT_RECORD_DOMAIN)

    def take(length: int, label: str) -> bytes:
        nonlocal cursor
        if cursor + length > len(encoded):
            raise Wave3FullBoundaryError(f"wave3_full_registry_record_{label}_truncated")
        value = encoded[cursor : cursor + length]
        cursor += length
        return value

    kind_length = int.from_bytes(take(2, "kind_length"), "big")
    if kind_length == 0 or kind_length > 64:
        raise Wave3FullBoundaryError("wave3_full_registry_record_kind_length_invalid")
    try:
        kind = take(kind_length, "kind").decode("ascii")
    except UnicodeDecodeError as exc:
        raise Wave3FullBoundaryError("wave3_full_registry_record_kind_ascii_invalid") from exc
    profile = take(64, "profile")
    epoch = int.from_bytes(take(8, "epoch"), "big")
    alias = take(32, "alias")
    root = take(64, "root")
    manifest = take(64, "manifest")
    schema = take(64, "schema")
    authority = take(64, "authority")
    signatures: list[PqSignatureEnvelopeV1] = []
    for index in range(2):
        suite_length = int.from_bytes(take(2, f"signature_{index}_suite_length"), "big")
        if suite_length == 0 or suite_length > 128:
            raise Wave3FullBoundaryError(f"wave3_full_registry_record_signature_{index}_suite_length_invalid")
        try:
            suite = take(suite_length, f"signature_{index}_suite").decode("ascii")
        except UnicodeDecodeError as exc:
            raise Wave3FullBoundaryError(f"wave3_full_registry_record_signature_{index}_suite_ascii_invalid") from exc
        key_id = take(64, f"signature_{index}_key_id")
        if suite not in SIGNATURE_SIZES:
            raise Wave3FullBoundaryError("wave3_full_registry_record_signature_suite_invalid")
        signature = take(SIGNATURE_SIZES[suite], f"signature_{index}")
        signatures.append(PqSignatureEnvelopeV1(suite, key_id, signature))
    if cursor != len(encoded):
        raise Wave3FullBoundaryError("wave3_full_registry_record_trailing_bytes")
    record = GovernedRootRecordV1(
        kind,
        profile,
        epoch,
        alias,
        root,
        manifest,
        schema,
        authority,
        tuple(signatures),
    )
    if record.canonical_bytes() != encoded:
        raise Wave3FullBoundaryError("wave3_full_registry_record_noncanonical")
    return record


@contextmanager
def _file_lock(path: Path):
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise Wave3FullBoundaryError("wave3_full_file_lock_busy") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_file_write(path: Path, encoded: bytes) -> None:
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    if temporary.exists():
        raise Wave3FullBoundaryError("wave3_full_temporary_path_exists")
    descriptor = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


class Wave3DurableGovernedRootRegistryV1:
    """Append-only durable registry with canonical record readback."""

    def __init__(self, path: Path, *, authority: DualPqAuthorityV1) -> None:
        if not isinstance(path, Path) or type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_full_registry_path_and_authority_required")
        if path.is_symlink() or not path.is_file():
            raise Wave3FullBoundaryError("wave3_full_registry_file_invalid")
        self.path = path
        self._authority = authority
        self._lock = RLock()
        self._registry = self._read_registry()

    @classmethod
    def create(cls, path: Path, *, authority: DualPqAuthorityV1) -> "Wave3DurableGovernedRootRegistryV1":
        if not isinstance(path, Path) or type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_full_registry_create_arguments_invalid")
        if path.exists():
            raise Wave3FullBoundaryError("wave3_full_registry_file_already_exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        registry = GovernedRootRegistryV1(authority=authority)
        with _file_lock(path):
            _atomic_file_write(path, cls._encode_registry(registry))
        return cls(path, authority=authority)

    @property
    def registry(self) -> GovernedRootRegistryV1:
        with self._lock:
            self._registry = self._read_registry()
            return self._registry

    @property
    def commitment_sha3_512(self) -> bytes:
        return self.registry.commitment_sha3_512

    def resolve(self, *, root_kind: str, epoch: int) -> GovernedRootRecordV1:
        return self.registry.resolve(root_kind=root_kind, epoch=epoch)

    @staticmethod
    def _encode_registry(registry: GovernedRootRegistryV1) -> bytes:
        records = registry.records
        body = b"".join(
            (
                REGISTRY_STORE_MAGIC,
                REGISTRY_STORE_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                len(records).to_bytes(4, "big"),
                b"".join(len(record.canonical_bytes()).to_bytes(4, "big") + record.canonical_bytes() for record in records),
            )
        )
        digest = sha3_512(REGISTRY_STORE_DOMAIN + body).digest()
        return body + digest

    def _read_registry(self) -> GovernedRootRegistryV1:
        try:
            encoded = self.path.read_bytes()
        except OSError as exc:
            raise Wave3FullBoundaryError("wave3_full_registry_read_failed") from exc
        if len(encoded) < 8 + 2 + 2 + 4 + 64 or len(encoded) > MAX_AUTH_STATE_FILE_BYTES:
            raise Wave3FullBoundaryError("wave3_full_registry_file_length_invalid")
        if encoded[:8] != REGISTRY_STORE_MAGIC:
            raise Wave3FullBoundaryError("wave3_full_registry_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != REGISTRY_STORE_VERSION:
            raise Wave3FullBoundaryError("wave3_full_registry_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != 0:
            raise Wave3FullBoundaryError("wave3_full_registry_flags_invalid")
        count = int.from_bytes(encoded[12:16], "big")
        cursor = 16
        registry = GovernedRootRegistryV1(authority=self._authority)
        for index in range(count):
            if cursor + 4 > len(encoded) - 64:
                raise Wave3FullBoundaryError(f"wave3_full_registry_record_{index}_length_truncated")
            length = int.from_bytes(encoded[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or length > MAX_BATCH_RECORD_BYTES or cursor + length > len(encoded) - 64:
                raise Wave3FullBoundaryError(f"wave3_full_registry_record_{index}_length_invalid")
            record = _decode_governed_root_record(encoded[cursor : cursor + length])
            cursor += length
            try:
                registry.register(record)
            except (TypeError, ValueError) as exc:
                raise Wave3FullBoundaryError("wave3_full_registry_record_rejected") from exc
        if cursor != len(encoded) - 64:
            raise Wave3FullBoundaryError("wave3_full_registry_trailing_bytes")
        expected_digest = sha3_512(REGISTRY_STORE_DOMAIN + encoded[:cursor]).digest()
        if not hmac.compare_digest(encoded[cursor:], expected_digest):
            raise Wave3FullBoundaryError("wave3_full_registry_digest_mismatch")
        return registry

    def register(self, record: GovernedRootRecordV1) -> bytes:
        if type(record) is not GovernedRootRecordV1:
            raise TypeError("wave3_full_registry_record_required")
        with self._lock, _file_lock(self.path):
            observed = self._read_registry()
            root_id = observed.register(record)
            _atomic_file_write(self.path, self._encode_registry(observed))
            readback = self._read_registry()
            if readback.commitment_sha3_512 != observed.commitment_sha3_512:
                raise Wave3FullBoundaryError("wave3_full_registry_readback_mismatch")
            self._registry = readback
            return root_id


Wave3RegistrySourceV1 = GovernedRootRegistryV1 | Wave3DurableGovernedRootRegistryV1


def _registry_view(registry: object, label: str) -> GovernedRootRegistryV1:
    if type(registry) is GovernedRootRegistryV1:
        return registry
    if type(registry) is Wave3DurableGovernedRootRegistryV1:
        return registry.registry
    raise TypeError(f"{label}_required")


@dataclass(frozen=True, slots=True)
class Wave3AuthoritativeCheckpointV1:
    state: Wave3StateTupleV2
    batches: tuple[Wave3BatchRecordV1, ...]

    def __post_init__(self) -> None:
        if type(self.state) is not Wave3StateTupleV2:
            raise TypeError("wave3_full_checkpoint_state_required")
        if type(self.batches) is not tuple or len(self.batches) > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_batch_count_invalid")
        if len(self.batches) != self.state.global_sequence:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_sequence_batch_mismatch")
        if any(type(item) is not Wave3BatchRecordV1 for item in self.batches):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_batch_type_invalid")
        if tuple(item.batch_nonce_32 for item in self.batches) != self.state.consumed_batch_nonces:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_nonce_projection_mismatch")
        if tuple(item.strong_batch_commitment_512 for item in self.batches) != self.state.recorded_strong_batch_commitments:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_commitment_projection_mismatch")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                self.state.canonical_bytes(),
                len(self.batches).to_bytes(4, "big"),
                b"".join(
                    len(item.canonical_bytes()).to_bytes(4, "big") + item.canonical_bytes()
                    for item in self.batches
                ),
            )
        )

    @property
    def digest_512(self) -> bytes:
        return sha3_512(AUTH_STATE_FILE_DOMAIN + self.canonical_bytes()).digest()

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3AuthoritativeCheckpointV1":
        if type(encoded) is not bytes:
            raise TypeError("wave3_full_checkpoint_encoding_bytes_required")
        state_domain_length = len(AUTH_STATE_DOMAIN)
        if len(encoded) < state_domain_length + 64 + 4:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_encoding_invalid")
        cursor = state_domain_length
        # The state tuple has no pointer table.  Decode it by walking its
        # fixed-width fields and variable collection counts, then pass the
        # exact prefix through the strict tuple decoder.
        minimum = state_domain_length + 64 + 1 + 64 * 5 + 8 + 32 + 32 + 8 + 32 + 64 + 2
        if len(encoded) < minimum:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_state_truncated")
        state_cursor = state_domain_length
        state_cursor += 64
        suite_flag = encoded[state_cursor]
        state_cursor += 1
        if suite_flag not in (0, 1):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_suite_flag_invalid")
        state_cursor += 64 if suite_flag else 0
        state_cursor += 64 * 4
        state_cursor += 8 + 32 + 32 + 8 + 32 + 64
        alias_count = int.from_bytes(encoded[state_cursor : state_cursor + 2], "big")
        if alias_count != 4:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_alias_count_invalid")
        state_cursor += 2 + 32 * alias_count + 64 + 64
        if state_cursor + 4 > len(encoded):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_nonce_count_truncated")
        nonce_count = int.from_bytes(encoded[state_cursor : state_cursor + 4], "big")
        if nonce_count > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_nonce_count_invalid")
        state_cursor += 4 + 32 * nonce_count
        if state_cursor + 4 > len(encoded):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_commitment_count_truncated")
        commitment_count = int.from_bytes(encoded[state_cursor : state_cursor + 4], "big")
        if commitment_count != nonce_count:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_commitment_count_invalid")
        state_cursor += 4 + 64 * commitment_count + 64
        if state_cursor + 4 > len(encoded):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_batch_count_truncated")
        state = Wave3StateTupleV2.decode(encoded[:state_cursor])
        cursor = state_cursor
        batch_count = int.from_bytes(encoded[cursor : cursor + 4], "big")
        cursor += 4
        if batch_count != state.global_sequence:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_batch_count_mismatch")
        batches = []
        for index in range(batch_count):
            if cursor + 4 > len(encoded):
                raise Wave3FullBoundaryError(f"wave3_full_checkpoint_batch_{index}_length_truncated")
            length = int.from_bytes(encoded[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or length > MAX_BATCH_RECORD_BYTES or cursor + length > len(encoded):
                raise Wave3FullBoundaryError(f"wave3_full_checkpoint_batch_{index}_length_invalid")
            batches.append(Wave3BatchRecordV1.decode(encoded[cursor : cursor + length]))
            cursor += length
        if cursor != len(encoded):
            raise Wave3FullBoundaryError("wave3_full_checkpoint_trailing_bytes")
        observed = cls(state, tuple(batches))
        if observed.canonical_bytes() != encoded:
            raise Wave3FullBoundaryError("wave3_full_checkpoint_noncanonical")
        return observed


@dataclass(frozen=True, slots=True)
class Wave3AuthoritativeEnvelopeV1:
    current: Wave3AuthoritativeCheckpointV1
    history: tuple[Wave3AuthoritativeCheckpointV1, ...] = ()

    def __post_init__(self) -> None:
        if type(self.current) is not Wave3AuthoritativeCheckpointV1:
            raise TypeError("wave3_full_envelope_current_checkpoint_invalid")
        if type(self.history) is not tuple or len(self.history) > 16:
            raise Wave3FullBoundaryError("wave3_full_envelope_history_invalid")
        if any(type(item) is not Wave3AuthoritativeCheckpointV1 for item in self.history):
            raise Wave3FullBoundaryError("wave3_full_envelope_history_checkpoint_invalid")
        digests = (self.current.digest_512, *(item.digest_512 for item in self.history))
        if len(set(digests)) != len(digests):
            raise Wave3FullBoundaryError("wave3_full_envelope_duplicate_checkpoint")
        current_position = (self.current.state.epoch, self.current.state.global_sequence)
        for item in self.history:
            position = (item.state.epoch, item.state.global_sequence)
            if position >= current_position:
                raise Wave3FullBoundaryError("wave3_full_envelope_history_order_invalid")
            current_position = position

    def encode(self) -> bytes:
        body = self.current.canonical_bytes()
        body += len(self.history).to_bytes(2, "big")
        body += b"".join(
            len(item.canonical_bytes()).to_bytes(4, "big") + item.canonical_bytes()
            for item in self.history
        )
        digest = sha3_512(AUTH_STATE_FILE_DOMAIN + body).digest()
        encoded = b"".join(
            (
                AUTH_STATE_MAGIC,
                AUTH_STATE_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                (20 + len(body) + len(digest)).to_bytes(8, "big"),
                body,
                digest,
            )
        )
        if len(encoded) > MAX_AUTH_STATE_FILE_BYTES:
            raise Wave3FullBoundaryError("wave3_full_state_file_size_limit_exceeded")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3AuthoritativeEnvelopeV1":
        if type(encoded) is not bytes or len(encoded) < 20 + 64:
            raise Wave3FullBoundaryError("wave3_full_state_file_length_invalid")
        if encoded[:8] != AUTH_STATE_MAGIC:
            raise Wave3FullBoundaryError("wave3_full_state_file_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != AUTH_STATE_VERSION:
            raise Wave3FullBoundaryError("wave3_full_state_file_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != 0:
            raise Wave3FullBoundaryError("wave3_full_state_file_flags_invalid")
        declared = int.from_bytes(encoded[12:20], "big")
        if declared != len(encoded) or declared > MAX_AUTH_STATE_FILE_BYTES:
            raise Wave3FullBoundaryError("wave3_full_state_file_declared_length_invalid")
        body = encoded[20:-64]
        expected = sha3_512(AUTH_STATE_FILE_DOMAIN + body).digest()
        if not hmac.compare_digest(encoded[-64:], expected):
            raise Wave3FullBoundaryError("wave3_full_state_file_digest_invalid")
        if len(body) < len(AUTH_STATE_DOMAIN) + 4 + 2:
            raise Wave3FullBoundaryError("wave3_full_state_file_body_invalid")
        # Decode the current checkpoint using its state sequence to locate the
        # following history count and length-delimited checkpoints.
        state_cursor = len(AUTH_STATE_DOMAIN) + 64
        if state_cursor >= len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_state_header_truncated")
        suite_flag = body[state_cursor]
        if suite_flag not in (0, 1):
            raise Wave3FullBoundaryError("wave3_full_state_file_suite_flag_invalid")
        state_cursor += 1 + (64 if suite_flag == 1 else 0) + 64 * 4
        state_cursor += 8 + 32 + 32 + 8 + 32 + 64
        if state_cursor + 2 > len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_alias_count_truncated")
        alias_count = int.from_bytes(body[state_cursor : state_cursor + 2], "big")
        if alias_count != 4:
            raise Wave3FullBoundaryError("wave3_full_state_file_alias_count_invalid")
        state_cursor += 2 + 32 * alias_count + 64 + 64
        if state_cursor + 4 > len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_nonce_count_truncated")
        nonce_count = int.from_bytes(body[state_cursor : state_cursor + 4], "big")
        if nonce_count > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_state_file_nonce_count_invalid")
        state_cursor += 4 + 32 * nonce_count
        if state_cursor + 4 > len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_commitment_count_truncated")
        commitment_count = int.from_bytes(body[state_cursor : state_cursor + 4], "big")
        if commitment_count != nonce_count:
            raise Wave3FullBoundaryError("wave3_full_state_file_commitment_count_invalid")
        state_cursor += 4 + 64 * commitment_count + 64
        state_len = state_cursor
        # The current checkpoint includes the state plus its batch count and
        # each batch record.  Read its exact length from the count table.
        cursor = state_len
        if cursor + 4 > len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_batch_count_truncated")
        batch_count = int.from_bytes(body[cursor : cursor + 4], "big")
        if batch_count > MAX_BATCHES:
            raise Wave3FullBoundaryError("wave3_full_state_file_batch_count_invalid")
        cursor += 4
        for index in range(batch_count):
            if cursor + 4 > len(body):
                raise Wave3FullBoundaryError(f"wave3_full_state_file_batch_{index}_truncated")
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4 + length
            if length == 0 or length > MAX_BATCH_RECORD_BYTES or cursor > len(body):
                raise Wave3FullBoundaryError(f"wave3_full_state_file_batch_{index}_invalid")
        current = Wave3AuthoritativeCheckpointV1.decode(body[:cursor])
        history_count = int.from_bytes(body[cursor : cursor + 2], "big")
        cursor += 2
        if history_count > 16:
            raise Wave3FullBoundaryError("wave3_full_state_file_history_count_invalid")
        history = []
        for index in range(history_count):
            if cursor + 4 > len(body):
                raise Wave3FullBoundaryError(f"wave3_full_state_file_history_{index}_truncated")
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or length > MAX_AUTH_STATE_FILE_BYTES or cursor + length > len(body):
                raise Wave3FullBoundaryError(f"wave3_full_state_file_history_{index}_invalid")
            history.append(Wave3AuthoritativeCheckpointV1.decode(body[cursor : cursor + length]))
            cursor += length
        if cursor != len(body):
            raise Wave3FullBoundaryError("wave3_full_state_file_trailing_bytes")
        return cls(current, tuple(history))


@dataclass(frozen=True, slots=True)
class Wave3AuthoritativeSnapshotV1:
    state: Wave3StateTupleV2
    checkpoint_digest_512: bytes
    batch_count: int

    def __post_init__(self) -> None:
        if type(self.state) is not Wave3StateTupleV2:
            raise TypeError("wave3_full_snapshot_state_required")
        _bytes("snapshot_checkpoint_digest", self.checkpoint_digest_512, 64, nonzero=True)
        if self.batch_count != self.state.global_sequence:
            raise Wave3FullBoundaryError("wave3_full_snapshot_batch_count_mismatch")


@dataclass(frozen=True, slots=True)
class Wave3AuthoritativeRecoveryAnchorV1:
    checkpoint_512: bytes
    state_digest_512: bytes
    authority_id_512: bytes
    registry_commitment_512: bytes
    epoch: int
    global_sequence: int
    strong_nullifier_root_512: bytes
    signatures: tuple[PqSignatureEnvelopeV1, ...] = field(repr=False)

    def __post_init__(self) -> None:
        for label, value in (
            ("recovery_checkpoint", self.checkpoint_512),
            ("recovery_state_digest", self.state_digest_512),
            ("recovery_authority", self.authority_id_512),
            ("recovery_registry", self.registry_commitment_512),
            ("recovery_strong_root", self.strong_nullifier_root_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        _u64("recovery_epoch", self.epoch, nonzero=True)
        _u64("recovery_sequence", self.global_sequence)
        if type(self.signatures) is not tuple or len(self.signatures) != 2:
            raise Wave3FullBoundaryError("wave3_full_recovery_signature_count_invalid")
        if any(type(item) is not PqSignatureEnvelopeV1 for item in self.signatures):
            raise Wave3FullBoundaryError("wave3_full_recovery_signature_type_invalid")

    def unsigned_bytes(self) -> bytes:
        return b"".join(
            (
                RECOVERY_DOMAIN,
                self.checkpoint_512,
                self.state_digest_512,
                self.authority_id_512,
                self.registry_commitment_512,
                self.epoch.to_bytes(8, "big"),
                self.global_sequence.to_bytes(8, "big"),
                self.strong_nullifier_root_512,
            )
        )

    @property
    def anchor_digest_512(self) -> bytes:
        return sha3_512(self.unsigned_bytes()).digest()

    @classmethod
    def issue(
        cls,
        checkpoint: Wave3AuthoritativeCheckpointV1,
        *,
        authority: DualPqAuthorityV1,
    ) -> "Wave3AuthoritativeRecoveryAnchorV1":
        if type(checkpoint) is not Wave3AuthoritativeCheckpointV1 or type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_full_recovery_checkpoint_and_authority_required")
        state = checkpoint.state
        unsigned = cls(
            checkpoint.digest_512,
            state.digest_512,
            state.authority_id_512,
            state.registry_commitment_512,
            state.epoch,
            state.global_sequence,
            state.strong_nullifier_root_512,
            tuple(
                PqSignatureEnvelopeV1(
                    suite,
                    authority.keys[index].key_id,
                    b"\x01" * SIGNATURE_SIZES[suite],
                )
                for index, suite in enumerate(DUAL_PQ_SUITES)
            ),
        )
        return replace(unsigned, signatures=authority.sign(unsigned_root=unsigned.anchor_digest_512))

    def verify(
        self,
        *,
        checkpoint: Wave3AuthoritativeCheckpointV1,
        authority: DualPqAuthorityV1,
        registry: GovernedRootRegistryV1,
    ) -> bool:
        if type(checkpoint) is not Wave3AuthoritativeCheckpointV1 or type(authority) is not DualPqAuthorityV1 or type(registry) is not GovernedRootRegistryV1:
            raise TypeError("wave3_full_recovery_arguments_invalid")
        state = checkpoint.state
        if (
            self.checkpoint_512 != checkpoint.digest_512
            or self.state_digest_512 != state.digest_512
            or self.authority_id_512 != authority.authority_id_512
            or self.registry_commitment_512 != registry.commitment_sha3_512
            or self.epoch != state.epoch
            or self.global_sequence != state.global_sequence
            or self.strong_nullifier_root_512 != state.strong_nullifier_root_512
        ):
            raise Wave3FullBoundaryError("wave3_full_recovery_anchor_identity_mismatch")
        authority.verify(unsigned_root=self.anchor_digest_512, signatures=self.signatures)
        return True


class Wave3AuthoritativeStateV1:
    """Durable batch-level state owner with one atomic full-tuple commit."""

    def __init__(
        self,
        path: Path,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError("wave3_full_state_path_and_registry_required")
        registry_view = _registry_view(registry, "wave3_full_state_registry")
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_state_candidate_identity_required")
        aliases = tuple(_felt(f"state_constructor_alias_{index}", value, nonzero=True) for index, value in enumerate(legacy_governed_root_aliases))
        if len(aliases) != 4:
            raise Wave3FullBoundaryError("wave3_full_state_constructor_alias_count_invalid")
        if path.is_symlink() or not path.is_file():
            raise Wave3FullBoundaryError("wave3_full_state_file_missing")
        self.path = path
        self._registry_source = registry
        self._registry = registry_view
        self._candidate_identity = candidate_identity
        self._aliases = aliases
        self._lock = RLock()
        self._validate_current(self._read().current)

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
        strong_payment_state_root_512: bytes,
    ) -> "Wave3AuthoritativeStateV1":
        if not isinstance(path, Path):
            raise TypeError("wave3_full_state_create_arguments_invalid")
        registry_view = _registry_view(registry, "wave3_full_state_registry")
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_state_create_identity_invalid")
        if path.exists():
            raise Wave3FullBoundaryError("wave3_full_state_file_already_exists")
        aliases = tuple(_felt(f"state_create_alias_{index}", value, nonzero=True) for index, value in enumerate(legacy_governed_root_aliases))
        if len(aliases) != 4:
            raise Wave3FullBoundaryError("wave3_full_state_create_alias_count_invalid")
        payment = _bytes("state_create_payment_root", strong_payment_state_root_512, 64, nonzero=True)
        empty = Wave3NullifierAuthorityV1(epoch=candidate_identity.epoch).snapshot()
        state = Wave3StateTupleV2(
            candidate_identity.profile_id,
            None,
            candidate_identity.schema_id,
            candidate_identity.verifier_artifact_identity,
            candidate_identity.strong_settlement_domain_id,
            registry_view.authority.authority_id_512,
            candidate_identity.epoch,
            candidate_identity.legacy_protocol_version_alias,
            candidate_identity.legacy_settlement_domain_alias,
            0,
            empty.legacy_root_felt.to_bytes(FELT_BYTES, "big"),
            empty.strong_nullifier_root_512,
            aliases,
            registry_view.commitment_sha3_512,
            payment,
            (),
            (),
            ZERO_ID_512,
        )
        checkpoint = Wave3AuthoritativeCheckpointV1(state, ())
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path):
            _atomic_file_write(path, Wave3AuthoritativeEnvelopeV1(checkpoint).encode())
        return cls(
            path,
            registry=registry,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=aliases,
        )

    def _read(self) -> Wave3AuthoritativeEnvelopeV1:
        try:
            encoded = self.path.read_bytes()
            return Wave3AuthoritativeEnvelopeV1.decode(encoded)
        except (OSError, TypeError, ValueError, IndexError, OverflowError) as exc:
            raise Wave3FullBoundaryError("wave3_full_state_file_rejected") from exc

    def _sync_registry(self) -> GovernedRootRegistryV1:
        self._registry = _registry_view(self._registry_source, "wave3_full_state_registry")
        return self._registry

    def _validate_identity(self, state: Wave3StateTupleV2) -> None:
        if (
            state.profile_id != self._candidate_identity.profile_id
            or state.schema_id != self._candidate_identity.schema_id
            or state.verifier_artifact_identity != self._candidate_identity.verifier_artifact_identity
            or state.strong_settlement_domain_id != self._candidate_identity.strong_settlement_domain_id
            or state.epoch != self._candidate_identity.epoch
            or state.authority_id_512 != self._registry.authority.authority_id_512
            or state.registry_commitment_512 != self._registry.commitment_sha3_512
            or state.legacy_protocol_version_alias != self._candidate_identity.legacy_protocol_version_alias
            or state.legacy_settlement_domain_alias != self._candidate_identity.legacy_settlement_domain_alias
            or state.legacy_governed_root_aliases != self._aliases
            or state.proof_suite_id_512 is not None
        ):
            raise Wave3FullBoundaryError("wave3_full_state_identity_mismatch")

    @staticmethod
    def _replay_checkpoint(checkpoint: Wave3AuthoritativeCheckpointV1) -> Wave3NullifierAuthorityV1:
        state = checkpoint.state
        authority = Wave3NullifierAuthorityV1(epoch=state.epoch)
        previous_payment: bytes | None = None
        previous_batch_epoch = 0
        for index, record in enumerate(checkpoint.batches):
            sidecar = CandidateSidecarV1.decode(record.encoded_sidecar)
            public = _canonical_public_fields(record.public_fields)
            expected_batch_commitment = _full_batch_commitment_from_salt_tag(
                encoded_sidecar_prefix=sidecar.encode()[:680],
                public_fields=public,
                private_batch_commitment_512=record.canonical_private_batch_commitment_512,
                hidden_strong_value_commitment_512=record.hidden_strong_value_commitment_512,
                salt_use_tag_512=record.salt_use_tag_512,
            )
            if not hmac.compare_digest(sidecar.strong_batch_commitment, expected_batch_commitment):
                raise Wave3FullBoundaryError("wave3_full_replay_batch_commitment_mismatch")
            try:
                replay_context = VerifiedProofContextV1(
                    sidecar,
                    public,
                    record.proof_digest_512,
                    sidecar.verifier_artifact_identity,
                )
            except (TypeError, ValueError) as exc:
                raise Wave3FullBoundaryError("wave3_full_replay_atomic_context_invalid") from exc
            if replay_context.atomic_binding_512 != record.atomic_binding_512:
                raise Wave3FullBoundaryError("wave3_full_replay_atomic_binding_mismatch")
            if sidecar.sequence_before != index or sidecar.sequence_after != index + 1:
                raise Wave3FullBoundaryError("wave3_full_replay_sequence_mismatch")
            if (
                sidecar.epoch == 0
                or sidecar.epoch > state.epoch
                or sidecar.epoch < previous_batch_epoch
                or public[2] == b"\x00" * FELT_BYTES
                or public[2] != record.batch_nonce_32
            ):
                raise Wave3FullBoundaryError("wave3_full_replay_nonce_mismatch")
            previous_batch_epoch = sidecar.epoch
            before = authority.snapshot()
            if sidecar.strong_nullifier_root_before != before.strong_nullifier_root_512:
                raise Wave3FullBoundaryError("wave3_full_replay_strong_before_mismatch")
            if public[3] != before.legacy_root_felt.to_bytes(FELT_BYTES, "big"):
                raise Wave3FullBoundaryError("wave3_full_replay_legacy_before_mismatch")
            if previous_payment is not None and sidecar.strong_payment_state_root_before != previous_payment:
                raise Wave3FullBoundaryError("wave3_full_replay_payment_chain_mismatch")
            try:
                replay = _replay_raw_batch_on_authority(
                    authority,
                    record.raw_preimages,
                    record.salt_use_tag_512,
                )
            except (TypeError, ValueError, Wave3NullifierError) as exc:
                raise Wave3FullBoundaryError("wave3_full_replay_authority_rejected") from exc
            expected_payment_after = derive_payment_state_after_512(
                payment_state_before_512=sidecar.strong_payment_state_root_before,
                private_batch_commitment_512=record.canonical_private_batch_commitment_512,
                hidden_strong_value_commitment_512=record.hidden_strong_value_commitment_512,
                salt_use_tag_512=record.salt_use_tag_512,
            )
            if (
                sidecar.strong_nullifier_root_after != replay.after.strong_nullifier_root_512
                or public[4] != replay.after.legacy_root_felt.to_bytes(FELT_BYTES, "big")
                or sidecar.strong_payment_state_root_before == sidecar.strong_payment_state_root_after
                or sidecar.strong_payment_state_root_after != expected_payment_after
            ):
                raise Wave3FullBoundaryError("wave3_full_replay_after_mismatch")
            previous_payment = sidecar.strong_payment_state_root_after
        final = authority.snapshot()
        if (
            state.global_sequence != len(checkpoint.batches)
            or state.legacy_nullifier_root != final.legacy_root_felt.to_bytes(FELT_BYTES, "big")
            or state.strong_nullifier_root_512 != final.strong_nullifier_root_512
            or (checkpoint.batches and state.strong_payment_state_root_512 != previous_payment)
            or (checkpoint.batches and state.last_atomic_binding_512 != checkpoint.batches[-1].atomic_binding_512)
            or (not checkpoint.batches and state.last_atomic_binding_512 != ZERO_ID_512)
        ):
            raise Wave3FullBoundaryError("wave3_full_replay_final_state_mismatch")
        return authority

    def _validate_current(self, checkpoint: Wave3AuthoritativeCheckpointV1) -> Wave3NullifierAuthorityV1:
        self._sync_registry()
        self._validate_identity(checkpoint.state)
        if checkpoint.state.registry_commitment_512 != self._registry.commitment_sha3_512:
            raise Wave3FullBoundaryError("wave3_full_state_registry_mismatch")
        return self._replay_checkpoint(checkpoint)

    def snapshot(self) -> Wave3AuthoritativeSnapshotV1:
        with self._lock:
            checkpoint = self._read().current
            self._validate_current(checkpoint)
            return Wave3AuthoritativeSnapshotV1(
                checkpoint.state,
                checkpoint.digest_512,
                len(checkpoint.batches),
            )

    def apply_verified_batch(
        self,
        context: VerifiedProofContextV1,
        private: Wave3FullBatchInputV1,
    ) -> Wave3AuthoritativeSnapshotV1:
        if type(context) is not VerifiedProofContextV1 or type(private) is not Wave3FullBatchInputV1:
            raise TypeError("wave3_full_state_verified_batch_arguments_invalid")
        admission = Wave3FullBatchAdmissionV1(context, private)
        sidecar = admission.sidecar
        public = admission.public_fields
        with self._lock, _file_lock(self.path):
            envelope = self._read()
            current_checkpoint = envelope.current
            current_authority = self._validate_current(current_checkpoint)
            current = current_checkpoint.state
            if (
                sidecar.profile_id != self._candidate_identity.profile_id
                or sidecar.schema_id != self._candidate_identity.schema_id
                or sidecar.verifier_artifact_identity != self._candidate_identity.verifier_artifact_identity
                or sidecar.strong_settlement_domain_id != self._candidate_identity.strong_settlement_domain_id
                or sidecar.epoch != current.epoch
                or sidecar.sequence_before != current.global_sequence
                or sidecar.strong_governance_commitment != current.registry_commitment_512
                or sidecar.strong_payment_state_root_before != current.strong_payment_state_root_512
                or public[0] != current.legacy_protocol_version_alias
                or public[1] != current.legacy_settlement_domain_alias
                or public[3] != current.legacy_nullifier_root
                or tuple(public[5:9]) != current.legacy_governed_root_aliases
                or public[2] in current.consumed_batch_nonces
                or sidecar.sequence_after != current.global_sequence + 1
            ):
                raise Wave3FullBoundaryError("wave3_full_state_before_tuple_mismatch")
            replay = _replay_raw_batch_on_authority(
                current_authority,
                private.raw_preimages,
                private.salt_use_tag_512,
            )
            if (
                sidecar.strong_nullifier_root_before != replay.before.strong_nullifier_root_512
                or sidecar.strong_nullifier_root_after != replay.after.strong_nullifier_root_512
                or public[4] != replay.after.legacy_root_felt.to_bytes(FELT_BYTES, "big")
            ):
                raise Wave3FullBoundaryError("wave3_full_state_replayed_root_mismatch")
            next_state = replace(
                current,
                global_sequence=current.global_sequence + 1,
                legacy_nullifier_root=public[4],
                strong_nullifier_root_512=sidecar.strong_nullifier_root_after,
                strong_payment_state_root_512=sidecar.strong_payment_state_root_after,
                consumed_batch_nonces=(*current.consumed_batch_nonces, public[2]),
                recorded_strong_batch_commitments=(*current.recorded_strong_batch_commitments, sidecar.strong_batch_commitment),
                last_atomic_binding_512=context.atomic_binding_512,
            )
            record = Wave3BatchRecordV1(
                sidecar.encode(),
                public,
                private.raw_preimages,
                private.canonical_private_batch_commitment_512,
                private.hidden_strong_value_commitment_512,
                private.salt_use_tag_512,
                context.proof_digest_512,
                context.atomic_binding_512,
            )
            next_checkpoint = Wave3AuthoritativeCheckpointV1(
                next_state,
                (*current_checkpoint.batches, record),
            )
            self._replay_checkpoint(next_checkpoint)
            next_envelope = Wave3AuthoritativeEnvelopeV1(
                next_checkpoint,
                (current_checkpoint, *envelope.history)[:16],
            )
            _atomic_file_write(self.path, next_envelope.encode())
            readback = self._read()
            self._validate_current(readback.current)
            if readback.current.digest_512 != next_checkpoint.digest_512:
                raise Wave3FullBoundaryError("wave3_full_state_readback_mismatch")
            return Wave3AuthoritativeSnapshotV1(
                readback.current.state,
                readback.current.digest_512,
                len(readback.current.batches),
            )

    @staticmethod
    def _checked_aliases(values: Sequence[bytes]) -> tuple[bytes, ...]:
        if type(values) not in (tuple, list) or len(values) != 4:
            raise Wave3FullBoundaryError("wave3_full_state_governed_alias_count_invalid")
        return tuple(
            _felt(f"state_context_alias_{index}", value, nonzero=True)
            for index, value in enumerate(values)
        )

    @staticmethod
    def _validate_checkpoint_context(
        checkpoint: Wave3AuthoritativeCheckpointV1,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
    ) -> Wave3NullifierAuthorityV1:
        if type(checkpoint) is not Wave3AuthoritativeCheckpointV1:
            raise TypeError("wave3_full_context_checkpoint_required")
        registry_view = _registry_view(registry, "wave3_full_context_registry")
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_context_identity_required")
        aliases = Wave3AuthoritativeStateV1._checked_aliases(legacy_governed_root_aliases)
        state = checkpoint.state
        if (
            state.profile_id != candidate_identity.profile_id
            or state.schema_id != candidate_identity.schema_id
            or state.verifier_artifact_identity != candidate_identity.verifier_artifact_identity
            or state.strong_settlement_domain_id != candidate_identity.strong_settlement_domain_id
            or state.epoch != candidate_identity.epoch
            or state.authority_id_512 != registry_view.authority.authority_id_512
            or state.registry_commitment_512 != registry_view.commitment_sha3_512
            or state.legacy_protocol_version_alias != candidate_identity.legacy_protocol_version_alias
            or state.legacy_settlement_domain_alias != candidate_identity.legacy_settlement_domain_alias
            or state.legacy_governed_root_aliases != aliases
            or state.proof_suite_id_512 is not None
        ):
            raise Wave3FullBoundaryError("wave3_full_state_identity_mismatch")
        return Wave3AuthoritativeStateV1._replay_checkpoint(checkpoint)

    @staticmethod
    def _successor_epoch(current: int, label: str) -> int:
        if current == UINT64_MAX:
            raise Wave3FullBoundaryError(f"wave3_full_{label}_epoch_exhausted")
        return current + 1

    def _publish_context_transition(
        self,
        *,
        current_envelope: Wave3AuthoritativeEnvelopeV1,
        next_checkpoint: Wave3AuthoritativeCheckpointV1,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: tuple[bytes, ...],
    ) -> Wave3AuthoritativeSnapshotV1:
        registry_view = _registry_view(registry, "wave3_full_context_registry")
        self._validate_checkpoint_context(
            next_checkpoint,
            registry=registry_view,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=legacy_governed_root_aliases,
        )
        next_envelope = Wave3AuthoritativeEnvelopeV1(
            next_checkpoint,
            (current_envelope.current, *current_envelope.history)[:MAX_HISTORY],
        )
        _atomic_file_write(self.path, next_envelope.encode())
        readback = self._read()
        self._validate_checkpoint_context(
            readback.current,
            registry=registry,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=legacy_governed_root_aliases,
        )
        if readback.current.digest_512 != next_checkpoint.digest_512:
            raise Wave3FullBoundaryError("wave3_full_context_readback_mismatch")
        self._registry_source = registry
        self._registry = registry_view
        self._candidate_identity = candidate_identity
        self._aliases = legacy_governed_root_aliases
        return Wave3AuthoritativeSnapshotV1(
            readback.current.state,
            readback.current.digest_512,
            len(readback.current.batches),
        )

    def _advance_context(
        self,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
        require_upgrade_change: bool,
    ) -> tuple[Wave3AuthoritativeCheckpointV1, Wave3AuthoritativeCheckpointV1]:
        registry_view = _registry_view(registry, "wave3_full_context_registry")
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_context_identity_required")
        aliases = self._checked_aliases(legacy_governed_root_aliases)
        with self._lock, _file_lock(self.path):
            envelope = self._read()
            current_checkpoint = envelope.current
            self._validate_current(current_checkpoint)
            current = current_checkpoint.state
            expected_epoch = self._successor_epoch(current.epoch, "context")
            if candidate_identity.epoch != expected_epoch:
                raise Wave3FullBoundaryError("wave3_full_context_epoch_not_successor")
            if require_upgrade_change and (
                candidate_identity.profile_id == current.profile_id
                or registry_view.authority.authority_id_512 == current.authority_id_512
            ):
                raise Wave3FullBoundaryError("wave3_full_upgrade_identity_change_required")
            next_state = replace(
                current,
                profile_id=candidate_identity.profile_id,
                proof_suite_id_512=None,
                schema_id=candidate_identity.schema_id,
                verifier_artifact_identity=candidate_identity.verifier_artifact_identity,
                strong_settlement_domain_id=candidate_identity.strong_settlement_domain_id,
                authority_id_512=registry_view.authority.authority_id_512,
                epoch=candidate_identity.epoch,
                legacy_protocol_version_alias=candidate_identity.legacy_protocol_version_alias,
                legacy_settlement_domain_alias=candidate_identity.legacy_settlement_domain_alias,
                legacy_governed_root_aliases=aliases,
                registry_commitment_512=registry_view.commitment_sha3_512,
            )
            next_checkpoint = Wave3AuthoritativeCheckpointV1(
                next_state,
                current_checkpoint.batches,
            )
            self._publish_context_transition(
                current_envelope=envelope,
                next_checkpoint=next_checkpoint,
                registry=registry,
                candidate_identity=candidate_identity,
                legacy_governed_root_aliases=aliases,
            )
            return current_checkpoint, next_checkpoint

    def migrate(
        self,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
    ) -> Wave3MigrationRecordV1:
        old, new = self._advance_context(
            registry=registry,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=legacy_governed_root_aliases,
            require_upgrade_change=False,
        )
        return Wave3MigrationRecordV1(
            old.digest_512,
            new.digest_512,
            old.state.epoch,
            new.state.epoch,
            new.state.global_sequence,
            new.state.strong_nullifier_root_512,
        )

    def upgrade(
        self,
        *,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
    ) -> Wave3UpgradeRecordV1:
        old, new = self._advance_context(
            registry=registry,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=legacy_governed_root_aliases,
            require_upgrade_change=True,
        )
        return Wave3UpgradeRecordV1(
            old.digest_512,
            new.digest_512,
            old.state.profile_id,
            new.state.profile_id,
            old.state.authority_id_512,
            new.state.authority_id_512,
            old.state.registry_commitment_512,
            new.state.registry_commitment_512,
            old.state.epoch,
            new.state.epoch,
            new.state.global_sequence,
            new.state.strong_nullifier_root_512,
        )

    def rollback(
        self,
        *,
        target_checkpoint_512: bytes,
        registry: Wave3RegistrySourceV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
    ) -> Wave3RollbackRecordV1:
        target_digest = _bytes(
            "rollback_target_checkpoint",
            target_checkpoint_512,
            IDENTITY_BYTES,
            nonzero=True,
        )
        registry_view = _registry_view(registry, "wave3_full_rollback_registry")
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_rollback_identity_required")
        aliases = self._checked_aliases(legacy_governed_root_aliases)
        with self._lock, _file_lock(self.path):
            envelope = self._read()
            current_checkpoint = envelope.current
            self._validate_current(current_checkpoint)
            target = next(
                (
                    item
                    for item in envelope.history
                    if hmac.compare_digest(item.digest_512, target_digest)
                ),
                None,
            )
            if target is None:
                raise Wave3FullBoundaryError("wave3_full_rollback_checkpoint_unknown")
            if target.state.registry_commitment_512 != registry_view.commitment_sha3_512:
                raise Wave3FullBoundaryError("wave3_full_rollback_registry_mismatch")
            expected_epoch = self._successor_epoch(current_checkpoint.state.epoch, "rollback")
            if candidate_identity.epoch != expected_epoch:
                raise Wave3FullBoundaryError("wave3_full_rollback_epoch_not_successor")
            next_state = replace(
                target.state,
                profile_id=candidate_identity.profile_id,
                proof_suite_id_512=None,
                schema_id=candidate_identity.schema_id,
                verifier_artifact_identity=candidate_identity.verifier_artifact_identity,
                strong_settlement_domain_id=candidate_identity.strong_settlement_domain_id,
                authority_id_512=registry_view.authority.authority_id_512,
                epoch=candidate_identity.epoch,
                legacy_protocol_version_alias=candidate_identity.legacy_protocol_version_alias,
                legacy_settlement_domain_alias=candidate_identity.legacy_settlement_domain_alias,
                legacy_governed_root_aliases=aliases,
                registry_commitment_512=registry_view.commitment_sha3_512,
            )
            next_checkpoint = Wave3AuthoritativeCheckpointV1(next_state, target.batches)
            self._publish_context_transition(
                current_envelope=envelope,
                next_checkpoint=next_checkpoint,
                registry=registry,
                candidate_identity=candidate_identity,
                legacy_governed_root_aliases=aliases,
            )
            return Wave3RollbackRecordV1(
                target.digest_512,
                next_checkpoint.digest_512,
                current_checkpoint.state.epoch,
                next_checkpoint.state.epoch,
                next_checkpoint.state.global_sequence,
                next_checkpoint.state.strong_nullifier_root_512,
            )

    @classmethod
    def recover(
        cls,
        path: Path,
        *,
        checkpoint: Wave3AuthoritativeCheckpointV1,
        anchor: Wave3AuthoritativeRecoveryAnchorV1,
        registry: Wave3RegistrySourceV1,
        authority: DualPqAuthorityV1,
        candidate_identity: ActiveSuiteIdentityV1,
        legacy_governed_root_aliases: Sequence[bytes],
        replace_existing: bool = False,
    ) -> "Wave3AuthoritativeStateV1":
        if not isinstance(path, Path) or type(checkpoint) is not Wave3AuthoritativeCheckpointV1:
            raise TypeError("wave3_full_recovery_path_and_checkpoint_required")
        if type(anchor) is not Wave3AuthoritativeRecoveryAnchorV1:
            raise TypeError("wave3_full_recovery_anchor_required")
        registry_view = _registry_view(registry, "wave3_full_recovery_registry")
        if type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_full_recovery_registry_and_authority_required")
        if type(candidate_identity) is not ActiveSuiteIdentityV1 or type(replace_existing) is not bool:
            raise TypeError("wave3_full_recovery_identity_and_replace_flag_invalid")
        if authority is not registry_view.authority:
            raise Wave3FullBoundaryError("wave3_full_recovery_authority_registry_mismatch")
        anchor.verify(checkpoint=checkpoint, authority=authority, registry=registry_view)
        aliases = cls._checked_aliases(legacy_governed_root_aliases)
        cls._validate_checkpoint_context(
            checkpoint,
            registry=registry_view,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=aliases,
        )
        if path.is_symlink() or (path.exists() and not replace_existing):
            raise Wave3FullBoundaryError("wave3_full_recovery_target_rejected")
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path):
            _atomic_file_write(path, Wave3AuthoritativeEnvelopeV1(checkpoint).encode())
        return cls(
            path,
            registry=registry,
            candidate_identity=candidate_identity,
            legacy_governed_root_aliases=aliases,
        )

    def issue_recovery_anchor(
        self,
        *,
        authority: DualPqAuthorityV1,
    ) -> Wave3AuthoritativeRecoveryAnchorV1:
        if type(authority) is not DualPqAuthorityV1:
            raise TypeError("wave3_full_recovery_authority_required")
        if authority is not self._registry.authority:
            raise Wave3FullBoundaryError("wave3_full_recovery_authority_mismatch")
        with self._lock:
            checkpoint = self._read().current
            self._validate_current(checkpoint)
            return Wave3AuthoritativeRecoveryAnchorV1.issue(
                checkpoint,
                authority=authority,
            )

    @property
    def checkpoint_history(self) -> tuple[bytes, ...]:
        with self._lock:
            envelope = self._read()
            self._validate_current(envelope.current)
            return tuple(item.digest_512 for item in envelope.history)

    @property
    def current_checkpoint(self) -> Wave3AuthoritativeCheckpointV1:
        with self._lock:
            checkpoint = self._read().current
            self._validate_current(checkpoint)
            return checkpoint


def _extract_state_binding_projection(binding: bytes) -> tuple[bytes, ...]:
    if type(binding) is not bytes or len(binding) == 0 or len(binding) > MAX_PROOF_BODY_BYTES:
        raise Wave3FullBoundaryError("wave3_full_rust_binding_size_invalid")
    if binding[:6] != STATE_BINDING_MAGIC or len(binding) < 7 or binding[6] != STATE_BINDING_VERSION:
        raise Wave3FullBoundaryError("wave3_full_rust_binding_version_invalid")
    cursor = 7

    def take(length: int, label: str) -> bytes:
        nonlocal cursor
        if length < 0 or cursor + length > len(binding):
            raise Wave3FullBoundaryError(f"wave3_full_rust_binding_{label}_truncated")
        value = binding[cursor : cursor + length]
        cursor += length
        return value

    before_length = int.from_bytes(take(4, "before_length"), "big")
    if before_length == 0 or before_length > MAX_PROOF_BODY_BYTES:
        raise Wave3FullBoundaryError("wave3_full_rust_binding_before_length_invalid")
    take(before_length, "before")
    after_length = int.from_bytes(take(4, "after_length"), "big")
    if after_length == 0 or after_length > MAX_PROOF_BODY_BYTES:
        raise Wave3FullBoundaryError("wave3_full_rust_binding_after_length_invalid")
    take(after_length, "after")
    operation_count = int.from_bytes(take(8, "operation_count"), "big")
    if operation_count == 0 or operation_count > MAX_STATE_BINDING_OPERATIONS:
        raise Wave3FullBoundaryError("wave3_full_rust_binding_operation_count_invalid")
    operations_length = operation_count * STATE_OPERATION_BYTES
    take(operations_length, "operations")
    projection = tuple(take(FELT_BYTES, f"projection_{index}") for index in range(PUBLIC_FIELD_COUNT))
    if any(value == b"\x00" * FELT_BYTES for value in projection):
        raise Wave3FullBoundaryError("wave3_full_rust_binding_projection_zero")
    return projection


class Wave3RustStateBindingVerifierV1:
    """Invoke the local Rust state-binding verifier as an untrusted component."""

    def __init__(self, executable: Path, *, timeout_seconds: float = 180.0) -> None:
        if not isinstance(executable, Path) or executable.is_symlink() or not executable.is_file():
            raise Wave3FullBoundaryError("wave3_full_rust_executable_invalid")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 900:
            raise Wave3FullBoundaryError("wave3_full_rust_timeout_invalid")
        self.executable = executable
        self.timeout_seconds = float(timeout_seconds)

    def verify(
        self,
        *,
        binding: bytes,
        public_fields: Sequence[bytes],
        sidecar: CandidateSidecarV1,
    ) -> bytes:
        if type(sidecar) is not CandidateSidecarV1:
            raise TypeError("wave3_full_rust_sidecar_required")
        if type(public_fields) not in (tuple, list) or len(public_fields) != PUBLIC_FIELD_COUNT:
            raise Wave3FullBoundaryError("wave3_full_rust_public_field_count_invalid")
        fields = tuple(
            _bytes(f"rust_public_field_{index}", value, FELT_BYTES)
            for index, value in enumerate(public_fields)
        )
        projection = _extract_state_binding_projection(binding)
        if projection != fields:
            raise Wave3FullBoundaryError("wave3_full_rust_projection_public_mismatch")
        with tempfile.TemporaryDirectory(prefix="bl-w3-rust-") as directory:
            binding_path = Path(directory) / "state-binding.bin"
            try:
                binding_path.write_bytes(binding)
                result = subprocess.run(
                    [str(self.executable), "--verify-state-binding", str(binding_path)],
                    cwd=str(self.executable.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise Wave3FullBoundaryError("wave3_full_rust_verifier_timeout") from exc
            except OSError as exc:
                raise Wave3FullBoundaryError("wave3_full_rust_verifier_spawn_failed") from exc
        if len(result.stdout) > MAX_RUST_OUTPUT_BYTES or len(result.stderr) > MAX_RUST_OUTPUT_BYTES:
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_output_limit")
        if result.returncode != 0 or result.stderr:
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_rejected")
        try:
            lines = result.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_output_encoding") from exc
        parsed: dict[str, str] = {}
        for line in lines:
            if not line or line.count("=") != 1:
                raise Wave3FullBoundaryError("wave3_full_rust_verifier_output_shape")
            key, value = line.split("=", 1)
            if not key or key in parsed or not value:
                raise Wave3FullBoundaryError("wave3_full_rust_verifier_output_duplicate")
            parsed[key] = value
        if parsed.get("state_plane_binding_verified") != "true":
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_binding_not_verified")
        encoded_digest = parsed.get("state_plane_binding_digest_sha3_512")
        if encoded_digest is None or len(encoded_digest) != 128:
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_digest_invalid")
        try:
            digest = bytes.fromhex(encoded_digest)
        except ValueError as exc:
            raise Wave3FullBoundaryError("wave3_full_rust_verifier_digest_encoding") from exc
        return _bytes("rust_binding_digest", digest, IDENTITY_BYTES, nonzero=True)


class Wave3FullVerifierV1:
    """Candidate verifier facade binding the 744-byte envelope to 12 fields."""

    def __init__(
        self,
        *,
        candidate_identity: ActiveSuiteIdentityV1,
        proof_verifier: object | None = None,
        rust_state_binding_verifier: Wave3RustStateBindingVerifierV1 | None = None,
    ) -> None:
        if type(candidate_identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave3_full_verifier_identity_required")
        if rust_state_binding_verifier is not None and type(rust_state_binding_verifier) is not Wave3RustStateBindingVerifierV1:
            raise TypeError("wave3_full_verifier_rust_port_invalid")
        if proof_verifier is not None and not callable(getattr(proof_verifier, "verify", None)):
            raise TypeError("wave3_full_verifier_proof_port_invalid")
        self.candidate_identity = candidate_identity
        self.proof_verifier = proof_verifier
        self.rust_state_binding_verifier = rust_state_binding_verifier

    def verify_envelope(
        self,
        *,
        encoded_envelope: bytes,
        public_fields: Sequence[bytes],
    ) -> VerifiedProofContextV1:
        try:
            envelope = Wave3ProofEnvelopeV1.decode(encoded_envelope)
            fields = _canonical_public_fields(public_fields)
            sidecar = validate_active_binding(
                envelope.encoded_sidecar,
                fields,
                self.candidate_identity,
            )
        except (TypeError, ValueError) as exc:
            raise Wave3FullBoundaryError("wave3_full_verifier_active_binding_rejected") from exc
        if self.rust_state_binding_verifier is not None:
            digest = self.rust_state_binding_verifier.verify(
                binding=envelope.proof_body,
                public_fields=fields,
                sidecar=sidecar,
            )
        elif self.proof_verifier is not None:
            verifier = Wave3VerifierV1(
                active_profile=ActiveVerifierProfileV1(self.candidate_identity),
                proof_verifier=self.proof_verifier,  # type: ignore[arg-type]
            )
            try:
                return verifier.verify_candidate(
                    encoded_sidecar=envelope.encoded_sidecar,
                    public_fields=fields,
                    proof=envelope.proof_body,
                )
            except (TypeError, ValueError) as exc:
                raise Wave3FullBoundaryError("wave3_full_verifier_proof_rejected") from exc
        else:
            raise Wave3FullBoundaryError("wave3_full_verifier_port_unavailable")
        return VerifiedProofContextV1(
            sidecar,
            fields,
            digest,
            self.candidate_identity.verifier_artifact_identity,
        )


@dataclass(frozen=True, slots=True)
class Wave3CustodyAuditEventV1:
    index: int
    event_kind: str
    payload_digest_512: bytes
    previous_event_digest_512: bytes
    event_digest_512: bytes = field(init=False)

    def __post_init__(self) -> None:
        _u64("audit_event_index", self.index)
        if type(self.event_kind) is not str:
            raise Wave3FullBoundaryError("wave3_full_audit_event_kind_invalid")
        try:
            kind = self.event_kind.encode("ascii")
        except UnicodeEncodeError as exc:
            raise Wave3FullBoundaryError("wave3_full_audit_event_kind_ascii_invalid") from exc
        if not kind or len(kind) > 128 or b"\x00" in kind:
            raise Wave3FullBoundaryError("wave3_full_audit_event_kind_length_invalid")
        _bytes("audit_payload_digest", self.payload_digest_512, IDENTITY_BYTES, nonzero=True)
        _bytes("audit_previous_digest", self.previous_event_digest_512, IDENTITY_BYTES)
        object.__setattr__(self, "event_digest_512", sha3_512(self.unsigned_bytes()).digest())

    def unsigned_bytes(self) -> bytes:
        kind = self.event_kind.encode("ascii")
        return b"".join(
            (
                CUSTODY_AUDIT_DOMAIN,
                self.index.to_bytes(8, "big"),
                len(kind).to_bytes(2, "big"),
                kind,
                self.previous_event_digest_512,
                self.payload_digest_512,
            )
        )

    def canonical_bytes(self) -> bytes:
        return self.unsigned_bytes() + self.event_digest_512

    @classmethod
    def decode(cls, encoded: bytes) -> "Wave3CustodyAuditEventV1":
        if type(encoded) is not bytes or not encoded.startswith(CUSTODY_AUDIT_DOMAIN):
            raise Wave3FullBoundaryError("wave3_full_audit_event_domain_invalid")
        cursor = len(CUSTODY_AUDIT_DOMAIN)
        if cursor + 8 + 2 > len(encoded):
            raise Wave3FullBoundaryError("wave3_full_audit_event_truncated")
        index = int.from_bytes(encoded[cursor : cursor + 8], "big")
        cursor += 8
        kind_length = int.from_bytes(encoded[cursor : cursor + 2], "big")
        cursor += 2
        if kind_length == 0 or kind_length > 128 or cursor + kind_length + 64 + 64 + 64 != len(encoded):
            raise Wave3FullBoundaryError("wave3_full_audit_event_length_invalid")
        try:
            kind = encoded[cursor : cursor + kind_length].decode("ascii")
        except UnicodeDecodeError as exc:
            raise Wave3FullBoundaryError("wave3_full_audit_event_kind_encoding_invalid") from exc
        cursor += kind_length
        previous = encoded[cursor : cursor + 64]
        cursor += 64
        payload = encoded[cursor : cursor + 64]
        cursor += 64
        observed = cls(index, kind, payload, previous)
        if observed.event_digest_512 != encoded[cursor : cursor + 64] or observed.canonical_bytes() != encoded:
            raise Wave3FullBoundaryError("wave3_full_audit_event_digest_invalid")
        return observed


class Wave3CustodyAuditLogV1:
    """Digest-only append-only local custody evidence; no keys or payloads persist."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
            raise Wave3FullBoundaryError("wave3_full_audit_file_invalid")
        self.path = path
        self._lock = RLock()
        self._events = self._read()

    @classmethod
    def create(cls, path: Path) -> "Wave3CustodyAuditLogV1":
        if not isinstance(path, Path) or path.exists():
            raise Wave3FullBoundaryError("wave3_full_audit_file_already_exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path):
            _atomic_file_write(path, cls._encode(()))
        return cls(path)

    @staticmethod
    def _encode(events: Sequence[Wave3CustodyAuditEventV1]) -> bytes:
        if type(events) not in (tuple, list) or len(events) > MAX_AUDIT_EVENTS:
            raise Wave3FullBoundaryError("wave3_full_audit_event_count_invalid")
        checked = tuple(events)
        body = b"".join(
            (
                CUSTODY_AUDIT_MAGIC,
                CUSTODY_AUDIT_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                len(checked).to_bytes(8, "big"),
                b"".join(
                    len(event.canonical_bytes()).to_bytes(4, "big") + event.canonical_bytes()
                    for event in checked
                ),
            )
        )
        return body + sha3_512(CUSTODY_AUDIT_FILE_DOMAIN + body).digest()

    def _read(self) -> tuple[Wave3CustodyAuditEventV1, ...]:
        try:
            encoded = self.path.read_bytes()
        except OSError as exc:
            raise Wave3FullBoundaryError("wave3_full_audit_read_failed") from exc
        if len(encoded) < 8 + 2 + 2 + 8 + 64 or len(encoded) > MAX_AUTH_STATE_FILE_BYTES:
            raise Wave3FullBoundaryError("wave3_full_audit_file_length_invalid")
        if encoded[:8] != CUSTODY_AUDIT_MAGIC:
            raise Wave3FullBoundaryError("wave3_full_audit_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != CUSTODY_AUDIT_VERSION:
            raise Wave3FullBoundaryError("wave3_full_audit_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != 0:
            raise Wave3FullBoundaryError("wave3_full_audit_flags_invalid")
        count = int.from_bytes(encoded[12:20], "big")
        if count > MAX_AUDIT_EVENTS:
            raise Wave3FullBoundaryError("wave3_full_audit_count_invalid")
        body_end = len(encoded) - 64
        cursor = 20
        events: list[Wave3CustodyAuditEventV1] = []
        previous = ZERO_ID_512
        for index in range(count):
            if cursor + 4 > body_end:
                raise Wave3FullBoundaryError("wave3_full_audit_event_length_truncated")
            length = int.from_bytes(encoded[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or length > MAX_AUDIT_EVENT_BYTES or cursor + length > body_end:
                raise Wave3FullBoundaryError("wave3_full_audit_event_length_invalid")
            event = Wave3CustodyAuditEventV1.decode(encoded[cursor : cursor + length])
            cursor += length
            if event.index != index or event.previous_event_digest_512 != previous:
                raise Wave3FullBoundaryError("wave3_full_audit_chain_invalid")
            events.append(event)
            previous = event.event_digest_512
        if cursor != body_end:
            raise Wave3FullBoundaryError("wave3_full_audit_trailing_bytes")
        expected = sha3_512(CUSTODY_AUDIT_FILE_DOMAIN + encoded[:body_end]).digest()
        if not hmac.compare_digest(encoded[body_end:], expected):
            raise Wave3FullBoundaryError("wave3_full_audit_file_digest_invalid")
        return tuple(events)

    @property
    def events(self) -> tuple[Wave3CustodyAuditEventV1, ...]:
        with self._lock:
            self._events = self._read()
            return self._events

    @property
    def head_digest_512(self) -> bytes:
        events = self.events
        return ZERO_ID_512 if not events else events[-1].event_digest_512

    def append(self, event_kind: str, payload: bytes) -> Wave3CustodyAuditEventV1:
        if type(payload) is not bytes or len(payload) > MAX_BATCH_RECORD_BYTES:
            raise Wave3FullBoundaryError("wave3_full_audit_payload_invalid")
        with self._lock, _file_lock(self.path):
            observed = self._read()
            if len(observed) >= MAX_AUDIT_EVENTS:
                raise Wave3FullBoundaryError("wave3_full_audit_event_limit_reached")
            previous = ZERO_ID_512 if not observed else observed[-1].event_digest_512
            event = Wave3CustodyAuditEventV1(
                len(observed),
                event_kind,
                _digest(CUSTODY_AUDIT_PAYLOAD_DOMAIN, payload),
                previous,
            )
            _atomic_file_write(self.path, self._encode((*observed, event)))
            readback = self._read()
            if not readback or readback[-1] != event:
                raise Wave3FullBoundaryError("wave3_full_audit_readback_mismatch")
            self._events = readback
            return event


class Wave3CustodyMonotonicCounterV1:
    """Durable nondecreasing marker for local anti-rollback checks."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
            raise Wave3FullBoundaryError("wave3_full_counter_file_invalid")
        self.path = path
        self._lock = RLock()
        self._value = self._read()

    @classmethod
    def create(cls, path: Path, *, initial_value: int = 0) -> "Wave3CustodyMonotonicCounterV1":
        if not isinstance(path, Path) or path.exists():
            raise Wave3FullBoundaryError("wave3_full_counter_file_already_exists")
        value = _u64("counter_initial_value", initial_value)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path):
            _atomic_file_write(path, cls._encode(value))
        return cls(path)

    @staticmethod
    def _encode(value: int) -> bytes:
        checked = _u64("counter_value", value)
        body = b"".join(
            (
                CUSTODY_COUNTER_MAGIC,
                CUSTODY_COUNTER_VERSION.to_bytes(2, "big"),
                (0).to_bytes(2, "big"),
                checked.to_bytes(8, "big"),
            )
        )
        return body + sha3_512(CUSTODY_COUNTER_DOMAIN + body).digest()

    def _read(self) -> int:
        try:
            encoded = self.path.read_bytes()
        except OSError as exc:
            raise Wave3FullBoundaryError("wave3_full_counter_read_failed") from exc
        if len(encoded) != 8 + 2 + 2 + 8 + 64:
            raise Wave3FullBoundaryError("wave3_full_counter_length_invalid")
        if encoded[:8] != CUSTODY_COUNTER_MAGIC:
            raise Wave3FullBoundaryError("wave3_full_counter_magic_invalid")
        if int.from_bytes(encoded[8:10], "big") != CUSTODY_COUNTER_VERSION:
            raise Wave3FullBoundaryError("wave3_full_counter_version_invalid")
        if int.from_bytes(encoded[10:12], "big") != 0:
            raise Wave3FullBoundaryError("wave3_full_counter_flags_invalid")
        expected = sha3_512(CUSTODY_COUNTER_DOMAIN + encoded[:20]).digest()
        if not hmac.compare_digest(encoded[20:], expected):
            raise Wave3FullBoundaryError("wave3_full_counter_digest_invalid")
        return int.from_bytes(encoded[12:20], "big")

    @property
    def value(self) -> int:
        with self._lock:
            self._value = self._read()
            return self._value

    def advance(self, next_value: int) -> int:
        checked = _u64("counter_next_value", next_value)
        with self._lock, _file_lock(self.path):
            current = self._read()
            if checked <= current:
                raise Wave3FullBoundaryError("wave3_full_counter_decrease_rejected")
            _atomic_file_write(self.path, self._encode(checked))
            observed = self._read()
            if observed != checked:
                raise Wave3FullBoundaryError("wave3_full_counter_readback_mismatch")
            self._value = observed
            return observed


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "BATCH_SLOT_COUNT",
    "MODULE_STATUS",
    "PROOF_SUITE_ID",
    "Wave3AuthoritativeCheckpointV1",
    "Wave3AuthoritativeEnvelopeV1",
    "Wave3AuthoritativeRecoveryAnchorV1",
    "Wave3AuthoritativeSnapshotV1",
    "Wave3AuthoritativeStateV1",
    "Wave3BatchRecordV1",
    "Wave3CustodyAuditEventV1",
    "Wave3CustodyAuditLogV1",
    "Wave3CustodyMonotonicCounterV1",
    "Wave3DurableGovernedRootRegistryV1",
    "Wave3FullBatchAdmissionV1",
    "Wave3FullBatchInputV1",
    "Wave3FullBoundaryError",
    "Wave3FullVerifierV1",
    "Wave3ProofEnvelopeV1",
    "Wave3RustStateBindingVerifierV1",
    "Wave3StateTupleV2",
    "derive_payment_state_after_512",
    "full_batch_commitment",
    "replay_wave3_batch",
)
