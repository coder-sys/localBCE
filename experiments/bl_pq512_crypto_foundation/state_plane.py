"""Small fixed-shape state and commitment plane for the Gate 2E boundary.

This module is intentionally independent of the synthetic S2/S3/S4 controls.
It implements the smallest useful state boundary that those controls lacked:

* fixed-width SHA3-512 roots over every slot in a bounded state layout;
* an exact all-slot old/new transition relation;
* a 512-bit pad-masked commitment with a SHA3-512 binding tag;
* an independent replay verifier; and
* crash-safe, compare-and-swap file publication.

The version-2 envelope remains independently replayable reference evidence,
not a zero-knowledge proof.  The separate state-air-proof module supplies the
version-3 composed envelope: a compact transition AIR, an authenticated
streamed FRI component, and native H4 cross-checking against these exact
operations.  Full custom-H4 GKR/PCS composition, backend admission, the
complete simulator/leakage ledger, and activation remain open.  This module
never selects a proof suite or enables activation.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha3_512
import os
from pathlib import Path
import tempfile
from typing import Final, Iterator, Sequence


STATUS: Final[str] = "STATE_PLANE_V1_IMPLEMENTED_NONACTIVATING_H4_PENDING"
COMMITMENT_STATUS: Final[str] = (
    "SHA3_512_HASH_PAD_COMMITMENT_V1_IMPLEMENTED_NONACTIVATING_REVIEW_PENDING"
)
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False

STATE_MAGIC: Final[bytes] = b"BLSP01"
STATE_VERSION: Final[int] = 1
STATE_BINDING_MAGIC: Final[bytes] = b"BLSB01"
STATE_BINDING_VERSION: Final[int] = 2
STATE_AIR_FRAGMENT_MAGIC: Final[bytes] = b"BLSA01"
STATE_AIR_FRAGMENT_VERSION: Final[int] = 1
COMMITMENT_MAGIC: Final[bytes] = b"BLHP01"
COMMITMENT_VERSION: Final[int] = 1
SHA3_512_LENGTH: Final[int] = 64
PUBLIC_PROJECTION_FIELD_COUNT: Final[int] = 12
PUBLIC_PROJECTION_FIELD_BYTES: Final[int] = 32
MAX_PROFILE_LENGTH: Final[int] = 64
MAX_PARAMETER_LENGTH: Final[int] = 64
MAX_STATE_CAPACITY: Final[int] = 1 << 20
ENTRY_WIDTH: Final[int] = 1 + 8 + SHA3_512_LENGTH + SHA3_512_LENGTH
ZERO_512: Final[bytes] = bytes(SHA3_512_LENGTH)

STATE_PARAMETER_IDENTITY: Final[str] = "BL-PQ512-STATE-PLANE-V1"
COMMITMENT_PARAMETER_IDENTITY: Final[str] = "BL-PQ512-SHA3-HASH-PAD-V1"
VERIFIER_IDENTITY_512: Final[bytes] = sha3_512(
    b"BL/PQ512/STATE-PLANE/INDEPENDENT-VERIFIER/v1\x00"
).digest()

_ROOT_DOMAIN = b"BL/PQ512/STATE-PLANE/ROOT/v1\x00"
_MANIFEST_DOMAIN = b"BL/PQ512/STATE-PLANE/MANIFEST/v1\x00"
_PROJECTION_DOMAIN = b"BL/PQ512/STATE-PLANE/PROJECTION/v1\x00"
_TRANSITION_DOMAIN = b"BL/PQ512/STATE-PLANE/TRANSITION/v1\x00"
_STATEMENT_DOMAIN = b"BL/PQ512/STATE-PLANE/STATEMENT/v1\x00"
_COMMITMENT_TAG_DOMAIN = b"BL/PQ512/SHA3-HASH-PAD/TAG/v1\x00"
_COMMITMENT_DIGEST_DOMAIN = b"BL/PQ512/SHA3-HASH-PAD/COMMITMENT/v1\x00"
_PROOF_DOMAIN = b"BL/PQ512/STATE-PLANE/PROOF/v1\x00"
_ATTEMPT_DOMAIN = b"BL/PQ512/STATE-PLANE/ATTEMPT/v1\x00"
_RECEIPT_DOMAIN = b"BL/PQ512/STATE-PLANE/RECEIPT/v1\x00"
_H4_BINDING_DOMAIN = b"BL/PQ512/STATE-PLANE/H4-BINDING-INPUT/v1\x00"
_STATE_AIR_FRAGMENT_DOMAIN = b"BL/PQ512/STATE-PLANE/AIR-FRAGMENT/v1\x00"
_H4_COMPOSITION_DOMAIN = b"BL/PQ512/STATE-PLANE/H4-COMPOSITION/v1\x00"
_MAX_STATE_BINDING_BYTES = 256 * 1024 * 1024


class StatePlaneError(ValueError):
    """Stable fail-closed error for malformed state-plane material."""


def _text(value: object, label: str, maximum: int) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise StatePlaneError(f"state_plane_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StatePlaneError(f"state_plane_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise StatePlaneError(f"state_plane_{label}_nul")
    return encoded


def _bytes(value: object, label: str, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise StatePlaneError(f"state_plane_{label}_length_invalid")
    if nonzero and value == bytes(length):
        raise StatePlaneError(f"state_plane_{label}_zero")
    return value


def _u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise StatePlaneError(f"state_plane_{label}_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise StatePlaneError("state_plane_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise StatePlaneError(f"state_plane_{label}_boolean_required")
    return value


def _projection(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list) or len(values) != PUBLIC_PROJECTION_FIELD_COUNT:
        raise StatePlaneError("state_plane_public_projection_count_invalid")
    return tuple(
        _bytes(value, f"public_projection_{index}", PUBLIC_PROJECTION_FIELD_BYTES, nonzero=True)
        for index, value in enumerate(values)
    )


@dataclass(frozen=True, slots=True)
class StateEntry:
    """One private fixed-width state slot."""

    index: int
    present: bool
    key: bytes = ZERO_512
    value: bytes = ZERO_512

    def __post_init__(self) -> None:
        _u64(self.index, "entry_index")
        _bool(self.present, "entry_present")
        _bytes(self.key, "entry_key", SHA3_512_LENGTH)
        _bytes(self.value, "entry_value", SHA3_512_LENGTH)
        if not self.present and (self.key != ZERO_512 or self.value != ZERO_512):
            raise StatePlaneError("state_plane_empty_entry_contains_private_bytes")

    @classmethod
    def empty(cls, index: int) -> "StateEntry":
        return cls(index, False)

    @property
    def encoded(self) -> bytes:
        return bytes((int(self.present),)) + self.index.to_bytes(8, "big") + self.key + self.value


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """A canonical bounded snapshot; private entries never appear in public output."""

    profile_id: str
    parameter_identity: str
    capacity: int
    epoch: int
    sequence: int
    entries: tuple[StateEntry, ...] = ()

    def __post_init__(self) -> None:
        _text(self.profile_id, "profile_id", MAX_PROFILE_LENGTH)
        _text(self.parameter_identity, "parameter_identity", MAX_PARAMETER_LENGTH)
        if type(self.capacity) is not int or not 0 < self.capacity <= MAX_STATE_CAPACITY:
            raise StatePlaneError("state_plane_capacity_invalid")
        _u64(self.epoch, "epoch")
        _u64(self.sequence, "sequence")
        if type(self.entries) is not tuple:
            raise StatePlaneError("state_plane_entries_tuple_required")
        previous = -1
        seen_keys: set[bytes] = set()
        for entry in self.entries:
            if type(entry) is not StateEntry or not entry.present:
                raise StatePlaneError("state_plane_snapshot_entry_invalid")
            if not previous < entry.index < self.capacity:
                raise StatePlaneError("state_plane_snapshot_entries_not_strictly_ordered")
            if entry.key in seen_keys:
                raise StatePlaneError("state_plane_snapshot_duplicate_key")
            seen_keys.add(entry.key)
            previous = entry.index

    @classmethod
    def empty(
        cls,
        profile_id: str,
        *,
        capacity: int,
        epoch: int = 1,
        sequence: int = 0,
        parameter_identity: str = STATE_PARAMETER_IDENTITY,
    ) -> "StateSnapshot":
        return cls(profile_id, parameter_identity, capacity, epoch, sequence)

    def _slot(self, index: int) -> StateEntry:
        for entry in self.entries:
            if entry.index == index:
                return entry
        return StateEntry.empty(index)

    @property
    def encoded(self) -> bytes:
        profile = _text(self.profile_id, "profile_id", MAX_PROFILE_LENGTH)
        parameter = _text(self.parameter_identity, "parameter_identity", MAX_PARAMETER_LENGTH)
        return b"".join(
            (
                STATE_MAGIC,
                bytes((STATE_VERSION, len(profile))),
                profile,
                bytes((len(parameter),)),
                parameter,
                self.capacity.to_bytes(8, "big"),
                self.epoch.to_bytes(8, "big"),
                self.sequence.to_bytes(8, "big"),
                b"".join(self._slot(index).encoded for index in range(self.capacity)),
            )
        )

    @property
    def root_512(self) -> bytes:
        return _hash(_ROOT_DOMAIN, self.encoded)

    @classmethod
    def decode(cls, encoded: bytes) -> "StateSnapshot":
        if type(encoded) is not bytes or len(encoded) < len(STATE_MAGIC) + 1 + 1 + 1 + 24:
            raise StatePlaneError("state_plane_snapshot_encoding_length_invalid")
        if encoded[: len(STATE_MAGIC)] != STATE_MAGIC:
            raise StatePlaneError("state_plane_snapshot_magic_invalid")
        cursor = len(STATE_MAGIC)
        if encoded[cursor] != STATE_VERSION:
            raise StatePlaneError("state_plane_snapshot_version_invalid")
        cursor += 1

        def read_text(label: str, maximum: int) -> str:
            nonlocal cursor
            if cursor >= len(encoded):
                raise StatePlaneError("state_plane_snapshot_truncated")
            length = encoded[cursor]
            cursor += 1
            if length == 0 or length > maximum or cursor + length > len(encoded):
                raise StatePlaneError(f"state_plane_snapshot_{label}_length_invalid")
            value = encoded[cursor : cursor + length]
            cursor += length
            try:
                return _text(value.decode("ascii"), label, maximum).decode("ascii")
            except UnicodeDecodeError as exc:
                raise StatePlaneError(f"state_plane_snapshot_{label}_not_ascii") from exc

        profile_id = read_text("profile_id", MAX_PROFILE_LENGTH)
        parameter_identity = read_text("parameter_identity", MAX_PARAMETER_LENGTH)
        if cursor + 24 > len(encoded):
            raise StatePlaneError("state_plane_snapshot_header_truncated")
        capacity = int.from_bytes(encoded[cursor : cursor + 8], "big")
        epoch = int.from_bytes(encoded[cursor + 8 : cursor + 16], "big")
        sequence = int.from_bytes(encoded[cursor + 16 : cursor + 24], "big")
        cursor += 24
        expected_length = cursor + capacity * ENTRY_WIDTH
        if capacity == 0 or capacity > MAX_STATE_CAPACITY or expected_length != len(encoded):
            raise StatePlaneError("state_plane_snapshot_fixed_shape_length_invalid")
        entries: list[StateEntry] = []
        for index in range(capacity):
            raw = encoded[cursor : cursor + ENTRY_WIDTH]
            cursor += ENTRY_WIDTH
            if raw[0] not in (0, 1):
                raise StatePlaneError("state_plane_snapshot_entry_presence_invalid")
            entry = StateEntry(
                index=int.from_bytes(raw[1:9], "big"),
                present=raw[0] == 1,
                key=raw[9:73],
                value=raw[73:137],
            )
            if entry.index != index:
                raise StatePlaneError("state_plane_snapshot_entry_index_mismatch")
            if entry.present:
                entries.append(entry)
        snapshot = cls(
            profile_id,
            parameter_identity,
            capacity,
            epoch,
            sequence,
            tuple(entries),
        )
        if snapshot.encoded != encoded:
            raise StatePlaneError("state_plane_snapshot_encoding_noncanonical")
        return snapshot


@dataclass(frozen=True, slots=True)
class StateOperation:
    """One fixed-shape private old/new slot relation."""

    index: int
    before: StateEntry
    after: StateEntry

    def __post_init__(self) -> None:
        _u64(self.index, "operation_index")
        if type(self.before) is not StateEntry or type(self.after) is not StateEntry:
            raise StatePlaneError("state_plane_operation_entry_type_invalid")
        if self.before.index != self.index or self.after.index != self.index:
            raise StatePlaneError("state_plane_operation_index_mismatch")

    @property
    def encoded(self) -> bytes:
        return self.before.encoded + self.after.encoded


@dataclass(frozen=True, slots=True)
class HashPadOpening:
    statement_digest_512: bytes
    mask_512: bytes

    def __post_init__(self) -> None:
        _bytes(self.statement_digest_512, "opening_statement", SHA3_512_LENGTH, nonzero=True)
        _bytes(self.mask_512, "opening_mask", SHA3_512_LENGTH)


@dataclass(frozen=True, slots=True)
class HashPadCommitment:
    """Public hash-pad commitment; the opening remains private."""

    parameter_identity: str
    public_coin_digest_512: bytes
    ciphertext_512: bytes
    tag_512: bytes
    commitment_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _text(self.parameter_identity, "commitment_parameter_identity", MAX_PARAMETER_LENGTH)
        _bytes(self.public_coin_digest_512, "commitment_public_coin", SHA3_512_LENGTH, nonzero=True)
        _bytes(self.ciphertext_512, "commitment_ciphertext", SHA3_512_LENGTH)
        _bytes(self.tag_512, "commitment_tag", SHA3_512_LENGTH, nonzero=True)
        expected = _hash(
            _COMMITMENT_DIGEST_DOMAIN,
            _text(self.parameter_identity, "commitment_parameter_identity", MAX_PARAMETER_LENGTH),
            self.public_coin_digest_512,
            self.ciphertext_512,
            self.tag_512,
        )
        if self.commitment_digest_512 not in (b"", expected):
            raise StatePlaneError("state_plane_commitment_digest_mismatch")
        object.__setattr__(self, "commitment_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        parameter = _text(self.parameter_identity, "commitment_parameter_identity", MAX_PARAMETER_LENGTH)
        return b"".join(
            (
                COMMITMENT_MAGIC,
                bytes((COMMITMENT_VERSION, len(parameter))),
                parameter,
                self.public_coin_digest_512,
                self.ciphertext_512,
                self.tag_512,
                self.commitment_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": COMMITMENT_STATUS,
            "parameter_identity": self.parameter_identity,
            "public_coin_digest_sha3_512_hex": self.public_coin_digest_512.hex(),
            "ciphertext_sha3_512_hex": self.ciphertext_512.hex(),
            "tag_sha3_512_hex": self.tag_512.hex(),
            "commitment_digest_sha3_512_hex": self.commitment_digest_512.hex(),
        }


def build_hash_pad_commitment(
    statement_digest_512: bytes,
    mask_512: bytes,
    public_coin_digest_512: bytes,
    *,
    parameter_identity: str = COMMITMENT_PARAMETER_IDENTITY,
) -> tuple[HashPadCommitment, HashPadOpening]:
    statement = _bytes(statement_digest_512, "statement", SHA3_512_LENGTH, nonzero=True)
    mask = _bytes(mask_512, "mask", SHA3_512_LENGTH)
    public_coin = _bytes(public_coin_digest_512, "public_coin", SHA3_512_LENGTH, nonzero=True)
    parameter = _text(parameter_identity, "commitment_parameter_identity", MAX_PARAMETER_LENGTH)
    ciphertext = bytes(left ^ right for left, right in zip(statement, mask, strict=True))
    tag = _hash(
        _COMMITMENT_TAG_DOMAIN,
        parameter,
        public_coin,
        ciphertext,
        statement,
        mask,
    )
    artifact = HashPadCommitment(parameter_identity, public_coin, ciphertext, tag)
    return artifact, HashPadOpening(statement, mask)


def verify_hash_pad_opening(artifact: HashPadCommitment, opening: HashPadOpening) -> None:
    if type(artifact) is not HashPadCommitment or type(opening) is not HashPadOpening:
        raise StatePlaneError("state_plane_commitment_opening_type_invalid")
    expected, _ = build_hash_pad_commitment(
        opening.statement_digest_512,
        opening.mask_512,
        artifact.public_coin_digest_512,
        parameter_identity=artifact.parameter_identity,
    )
    if expected != artifact:
        raise StatePlaneError("state_plane_commitment_opening_rejected")


def _slot_map(snapshot: StateSnapshot) -> dict[int, StateEntry]:
    return {entry.index: entry for entry in snapshot.entries}


def _apply_operations(
    before: StateSnapshot,
    operations: tuple[StateOperation, ...],
) -> StateSnapshot:
    if len(operations) != before.capacity or tuple(item.index for item in operations) != tuple(range(before.capacity)):
        raise StatePlaneError("state_plane_operation_shape_invalid")
    current = _slot_map(before)
    next_entries: list[StateEntry] = []
    for operation in operations:
        actual = current.get(operation.index, StateEntry.empty(operation.index))
        if actual != operation.before:
            raise StatePlaneError("state_plane_operation_before_mismatch")
        if operation.after.present:
            next_entries.append(operation.after)
    return StateSnapshot(
        before.profile_id,
        before.parameter_identity,
        before.capacity,
        before.epoch,
        before.sequence + 1,
        tuple(next_entries),
    )


def _manifest_digest(before: StateSnapshot, after: StateSnapshot, operations: tuple[StateOperation, ...]) -> bytes:
    return _hash(
        _MANIFEST_DOMAIN,
        before.root_512,
        after.root_512,
        len(operations).to_bytes(8, "big"),
        b"".join(operation.encoded for operation in operations),
    )


def _transition_bytes(
    before: StateSnapshot,
    after: StateSnapshot,
    manifest_digest_512: bytes,
    projection_digest_512: bytes,
) -> bytes:
    return b"".join(
        (
            _text(before.profile_id, "profile_id", MAX_PROFILE_LENGTH),
            _text(before.parameter_identity, "parameter_identity", MAX_PARAMETER_LENGTH),
            before.capacity.to_bytes(8, "big"),
            before.epoch.to_bytes(8, "big"),
            before.sequence.to_bytes(8, "big"),
            after.sequence.to_bytes(8, "big"),
            before.root_512,
            after.root_512,
            _bytes(manifest_digest_512, "manifest", SHA3_512_LENGTH, nonzero=True),
            _bytes(projection_digest_512, "projection_digest", SHA3_512_LENGTH, nonzero=True),
        )
    )


@dataclass(frozen=True, slots=True)
class AtomicStateReceipt:
    attempt_id_512: bytes
    transition_digest_512: bytes
    commitment_digest_512: bytes
    proof_identity_512: bytes
    verifier_identity_512: bytes
    receipt_digest_512: bytes = b""

    def __post_init__(self) -> None:
        values = (
            ("receipt_attempt", self.attempt_id_512),
            ("receipt_transition", self.transition_digest_512),
            ("receipt_commitment", self.commitment_digest_512),
            ("receipt_proof", self.proof_identity_512),
            ("receipt_verifier", self.verifier_identity_512),
        )
        for label, value in values:
            _bytes(value, label, SHA3_512_LENGTH, nonzero=True)
        expected = _hash(_RECEIPT_DOMAIN, *(value for _, value in values))
        if self.receipt_digest_512 not in (b"", expected):
            raise StatePlaneError("state_plane_receipt_digest_mismatch")
        object.__setattr__(self, "receipt_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BLRSP01",
                self.attempt_id_512,
                self.transition_digest_512,
                self.commitment_digest_512,
                self.proof_identity_512,
                self.verifier_identity_512,
                self.receipt_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "attempt_id_sha3_512_hex": self.attempt_id_512.hex(),
            "transition_digest_sha3_512_hex": self.transition_digest_512.hex(),
            "commitment_digest_sha3_512_hex": self.commitment_digest_512.hex(),
            "proof_identity_sha3_512_hex": self.proof_identity_512.hex(),
            "verifier_identity_sha3_512_hex": self.verifier_identity_512.hex(),
            "receipt_digest_sha3_512_hex": self.receipt_digest_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class StateTransitionProof:
    """Private replay witness plus the public identities bound by the receipt."""

    before: StateSnapshot
    after: StateSnapshot
    operations: tuple[StateOperation, ...]
    projection_12: tuple[bytes, ...]
    public_coin_digest_512: bytes
    commitment: HashPadCommitment
    opening: HashPadOpening
    manifest_digest_512: bytes = b""
    projection_digest_512: bytes = b""
    statement_digest_512: bytes = b""
    transition_digest_512: bytes = b""
    proof_identity_512: bytes = b""
    attempt_id_512: bytes = b""
    receipt: AtomicStateReceipt | None = None
    state_air_program_bytes: bytes = field(default=b"", init=False, repr=False, compare=False)
    state_air_execution_bytes: bytes = field(default=b"", init=False, repr=False, compare=False)
    state_air_program_commitment_512: bytes = field(
        default=b"", init=False, repr=False, compare=False
    )
    state_air_execution_commitment_512: bytes = field(
        default=b"", init=False, repr=False, compare=False
    )
    state_air_fragment_digest_512: bytes = field(
        default=b"", init=False, repr=False, compare=False
    )
    h4_composition_digest_512: bytes = field(
        default=b"", init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if type(self.before) is not StateSnapshot or type(self.after) is not StateSnapshot:
            raise StatePlaneError("state_plane_transition_snapshot_type_invalid")
        if self.after.profile_id != self.before.profile_id or self.after.parameter_identity != self.before.parameter_identity:
            raise StatePlaneError("state_plane_transition_layout_mismatch")
        if self.after.epoch != self.before.epoch or self.after.sequence != self.before.sequence + 1:
            raise StatePlaneError("state_plane_transition_sequence_invalid")
        if type(self.operations) is not tuple or len(self.operations) != self.before.capacity:
            raise StatePlaneError("state_plane_transition_operation_count_invalid")
        if any(type(item) is not StateOperation for item in self.operations):
            raise StatePlaneError("state_plane_transition_operation_type_invalid")
        _projection(self.projection_12)
        _bytes(self.public_coin_digest_512, "transition_public_coin", SHA3_512_LENGTH, nonzero=True)
        if type(self.commitment) is not HashPadCommitment or type(self.opening) is not HashPadOpening:
            raise StatePlaneError("state_plane_transition_commitment_type_invalid")
        if self.commitment.public_coin_digest_512 != self.public_coin_digest_512:
            raise StatePlaneError("state_plane_transition_public_coin_mismatch")
        verify_hash_pad_opening(self.commitment, self.opening)
        manifest = _manifest_digest(self.before, self.after, self.operations)
        projection_digest = _hash(_PROJECTION_DOMAIN, *self.projection_12)
        transition_bytes = _transition_bytes(self.before, self.after, manifest, projection_digest)
        transition_digest = _hash(_TRANSITION_DOMAIN, transition_bytes)
        statement = _hash(_STATEMENT_DOMAIN, transition_bytes, transition_digest)
        if self.opening.statement_digest_512 != statement:
            raise StatePlaneError("state_plane_transition_statement_opening_mismatch")
        proof_identity = _hash(
            _PROOF_DOMAIN,
            statement,
            transition_digest,
            self.commitment.commitment_digest_512,
            VERIFIER_IDENTITY_512,
        )
        attempt_id = _hash(
            _ATTEMPT_DOMAIN,
            _text(self.before.profile_id, "profile_id", MAX_PROFILE_LENGTH),
            _text(self.before.parameter_identity, "parameter_identity", MAX_PARAMETER_LENGTH),
            self.before.epoch.to_bytes(8, "big"),
            self.before.sequence.to_bytes(8, "big"),
            self.before.root_512,
            statement,
        )
        expected_receipt = AtomicStateReceipt(
            attempt_id,
            transition_digest,
            self.commitment.commitment_digest_512,
            proof_identity,
            VERIFIER_IDENTITY_512,
        )
        for label, supplied, expected in (
            ("manifest", self.manifest_digest_512, manifest),
            ("projection", self.projection_digest_512, projection_digest),
            ("statement", self.statement_digest_512, statement),
            ("transition", self.transition_digest_512, transition_digest),
            ("proof", self.proof_identity_512, proof_identity),
            ("attempt", self.attempt_id_512, attempt_id),
        ):
            if supplied not in (b"", expected):
                raise StatePlaneError(f"state_plane_transition_{label}_digest_mismatch")
        if self.receipt not in (None, expected_receipt):
            raise StatePlaneError("state_plane_transition_receipt_mismatch")
        object.__setattr__(self, "manifest_digest_512", manifest)
        object.__setattr__(self, "projection_digest_512", projection_digest)
        object.__setattr__(self, "statement_digest_512", statement)
        object.__setattr__(self, "transition_digest_512", transition_digest)
        object.__setattr__(self, "proof_identity_512", proof_identity)
        object.__setattr__(self, "attempt_id_512", attempt_id)
        object.__setattr__(self, "receipt", expected_receipt)
        for label, value in (
            ("state_air_program", self.state_air_program_bytes),
            ("state_air_execution", self.state_air_execution_bytes),
            ("state_air_program_commitment", self.state_air_program_commitment_512),
            ("state_air_execution_commitment", self.state_air_execution_commitment_512),
            ("state_air_fragment", self.state_air_fragment_digest_512),
            ("h4_composition", self.h4_composition_digest_512),
        ):
            if type(value) is not bytes or value:
                raise StatePlaneError(f"state_plane_{label}_type_invalid")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "profile_id": self.before.profile_id,
            "parameter_identity": self.before.parameter_identity,
            "capacity": self.before.capacity,
            "epoch": self.before.epoch,
            "sequence_before": self.before.sequence,
            "sequence_after": self.after.sequence,
            "old_root_sha3_512_hex": self.before.root_512.hex(),
            "new_root_sha3_512_hex": self.after.root_512.hex(),
            "manifest_digest_sha3_512_hex": self.manifest_digest_512.hex(),
            "projection_digest_sha3_512_hex": self.projection_digest_512.hex(),
            "statement_digest_sha3_512_hex": self.statement_digest_512.hex(),
            "commitment": self.commitment.as_public_dict(),
            "transition_digest_sha3_512_hex": self.transition_digest_512.hex(),
            "proof_identity_sha3_512_hex": self.proof_identity_512.hex(),
            "verifier_identity_sha3_512_hex": VERIFIER_IDENTITY_512.hex(),
            "attempt_id_sha3_512_hex": self.attempt_id_512.hex(),
            "receipt": self.receipt.as_public_dict(),
            "h4_parent_binding_status": (
                "NATIVE_STATE_AIR_CONSUMED_NONACTIVATING_H4_PROOF_PENDING"
            ),
        }

    @property
    def binding_bytes(self) -> bytes:
        """Canonical private envelope for the native H4 state verifier."""

        (
            state_air_program,
            state_air_execution,
            state_air_program_commitment,
            state_air_execution_commitment,
            state_air_fragment,
            h4_composition,
        ) = _state_air_artifacts(self)
        before = self.before.encoded
        after = self.after.encoded
        commitment = self.commitment.canonical_bytes
        encoded = b"".join(
            (
                STATE_BINDING_MAGIC,
                bytes((STATE_BINDING_VERSION,)),
                len(before).to_bytes(4, "big"),
                before,
                len(after).to_bytes(4, "big"),
                after,
                len(self.operations).to_bytes(8, "big"),
                b"".join(operation.encoded for operation in self.operations),
                b"".join(self.projection_12),
                self.public_coin_digest_512,
                len(commitment).to_bytes(4, "big"),
                commitment,
                self.opening.statement_digest_512,
                self.opening.mask_512,
                STATE_AIR_FRAGMENT_MAGIC,
                bytes((STATE_AIR_FRAGMENT_VERSION,)),
                len(state_air_program).to_bytes(4, "big"),
                state_air_program,
                len(state_air_execution).to_bytes(4, "big"),
                state_air_execution,
            )
        )
        if len(encoded) > _MAX_STATE_BINDING_BYTES:
            raise StatePlaneError("state_plane_binding_envelope_too_large")
        return encoded

    @property
    def binding_digest_512(self) -> bytes:
        _, _, _, _, state_air_fragment, h4_composition = _state_air_artifacts(self)
        return _hash(
            _H4_BINDING_DOMAIN,
            self.before.root_512,
            self.after.root_512,
            self.statement_digest_512,
            self.transition_digest_512,
            self.commitment.commitment_digest_512,
            self.proof_identity_512,
            self.receipt.receipt_digest_512,
            h4_composition,
            state_air_fragment,
        )


def _state_air_artifacts(
    proof: StateTransitionProof,
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    """Build and cache the exact executable state fragment and its identities."""

    if proof.state_air_program_bytes:
        return (
            proof.state_air_program_bytes,
            proof.state_air_execution_bytes,
            proof.state_air_program_commitment_512,
            proof.state_air_execution_commitment_512,
            proof.state_air_fragment_digest_512,
            proof.h4_composition_digest_512,
        )
    # These imports remain local because the executable AIR builder imports the
    # state proof type.  Keeping this edge lazy avoids a module-import cycle and
    # leaves ordinary state replay independent of AIR construction cost.
    from experiments.fixed_shape_claim_air.air_binary_ir import (
        air_binary_commitment,
        air_program_commitment,
        encode_air_execution,
        encode_air_program,
    )
    from experiments.fixed_shape_claim_air.state_plane_executable_air import (
        PROGRAM_ID,
        build_state_plane_air,
    )

    instance = build_state_plane_air(proof)
    if instance.program.program_id != PROGRAM_ID:
        raise StatePlaneError("state_plane_air_program_identity_invalid")
    program_bytes = encode_air_program(instance.program)
    execution_bytes = encode_air_execution(
        instance.program,
        instance.traces,
        instance.public_values,
    )
    program_commitment = air_program_commitment(program_bytes)
    execution_commitment = air_binary_commitment(execution_bytes)
    fragment_digest = _hash(
        _STATE_AIR_FRAGMENT_DOMAIN,
        proof.before.root_512,
        proof.after.root_512,
        proof.projection_digest_512,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        VERIFIER_IDENTITY_512,
        proof.attempt_id_512,
        proof.receipt.receipt_digest_512,
        program_commitment,
        execution_commitment,
    )
    composition_digest = _hash(
        _H4_COMPOSITION_DOMAIN,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.projection_digest_512,
        proof.public_coin_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        VERIFIER_IDENTITY_512,
        proof.attempt_id_512,
        proof.receipt.receipt_digest_512,
        program_commitment,
        execution_commitment,
        fragment_digest,
    )
    object.__setattr__(proof, "state_air_program_bytes", program_bytes)
    object.__setattr__(proof, "state_air_execution_bytes", execution_bytes)
    object.__setattr__(proof, "state_air_program_commitment_512", program_commitment)
    object.__setattr__(proof, "state_air_execution_commitment_512", execution_commitment)
    object.__setattr__(proof, "state_air_fragment_digest_512", fragment_digest)
    object.__setattr__(proof, "h4_composition_digest_512", composition_digest)
    return (
        program_bytes,
        execution_bytes,
        program_commitment,
        execution_commitment,
        fragment_digest,
        composition_digest,
    )


def build_state_transition(
    before: StateSnapshot,
    operations: Sequence[StateOperation],
    projection_12: Sequence[bytes],
    public_coin_digest_512: bytes,
    mask_512: bytes,
) -> StateTransitionProof:
    if type(before) is not StateSnapshot:
        raise StatePlaneError("state_plane_build_snapshot_type_invalid")
    if type(operations) not in (tuple, list):
        raise StatePlaneError("state_plane_build_operations_sequence_required")
    operations_tuple = tuple(operations)
    after = _apply_operations(before, operations_tuple)
    projection = _projection(projection_12)
    projection_digest = _hash(_PROJECTION_DOMAIN, *projection)
    manifest = _manifest_digest(before, after, operations_tuple)
    transition_bytes = _transition_bytes(before, after, manifest, projection_digest)
    transition_digest = _hash(_TRANSITION_DOMAIN, transition_bytes)
    statement = _hash(_STATEMENT_DOMAIN, transition_bytes, transition_digest)
    commitment, opening = build_hash_pad_commitment(
        statement,
        mask_512,
        public_coin_digest_512,
    )
    return StateTransitionProof(
        before,
        after,
        operations_tuple,
        projection,
        public_coin_digest_512,
        commitment,
        opening,
    )


def independently_verify_state_transition(proof: StateTransitionProof) -> None:
    """Recompute the relation from its private witness and reject host edits."""

    if type(proof) is not StateTransitionProof:
        raise StatePlaneError("state_plane_verifier_proof_type_invalid")
    expected_after = _apply_operations(proof.before, proof.operations)
    if expected_after != proof.after:
        raise StatePlaneError("state_plane_verifier_after_snapshot_mismatch")
    expected = build_state_transition(
        proof.before,
        proof.operations,
        proof.projection_12,
        proof.public_coin_digest_512,
        proof.opening.mask_512,
    )
    if expected != proof:
        raise StatePlaneError("state_plane_verifier_replay_mismatch")


def derive_h4_binding_input_digest(
    proof: StateTransitionProof,
    transcript_digest_512: bytes,
    execution_manifest_digest_512: bytes,
) -> bytes:
    """Produce the exact state/AIR digest consumed by the native H4 seam."""

    if type(proof) is not StateTransitionProof:
        raise StatePlaneError("state_plane_h4_binding_proof_type_invalid")
    _bytes(transcript_digest_512, "h4_transcript", SHA3_512_LENGTH, nonzero=True)
    _bytes(execution_manifest_digest_512, "h4_execution_manifest", SHA3_512_LENGTH, nonzero=True)
    _, _, _, _, state_air_fragment, h4_composition = _state_air_artifacts(proof)
    return _hash(
        _H4_BINDING_DOMAIN,
        proof.statement_digest_512,
        proof.transition_digest_512,
        proof.commitment.commitment_digest_512,
        proof.proof_identity_512,
        proof.receipt.receipt_digest_512,
        h4_composition,
        state_air_fragment,
        transcript_digest_512,
        execution_manifest_digest_512,
    )


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    """Take a non-blocking cross-process lock for the small CAS window."""

    try:
        handle = path.open("a+b")
    except OSError as exc:
        raise StatePlaneError("state_plane_lock_open_failed") from exc
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise StatePlaneError("state_plane_store_busy") from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise StatePlaneError("state_plane_store_busy") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _atomic_write(path: Path, encoded: bytes) -> None:
    if not path.parent.is_dir():
        raise StatePlaneError("state_plane_store_parent_missing")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise StatePlaneError("state_plane_store_atomic_write_failed") from exc


class FileStateStore:
    """Single authoritative file with cross-process non-blocking CAS."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or path.name in {"", ".", ".."}:
            raise StatePlaneError("state_plane_store_path_invalid")
        if path.is_symlink():
            raise StatePlaneError("state_plane_store_symlink_forbidden")
        self.path = path
        self.lock_path = path.with_name(f"{path.name}.lock")

    def initialize(self, snapshot: StateSnapshot) -> None:
        if type(snapshot) is not StateSnapshot:
            raise StatePlaneError("state_plane_store_initial_snapshot_invalid")
        with _exclusive_file_lock(self.lock_path):
            if self.path.exists():
                raise StatePlaneError("state_plane_store_already_initialized")
            _atomic_write(self.path, snapshot.encoded)

    def read(self) -> StateSnapshot:
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise StatePlaneError("state_plane_store_read_failed") from exc
        return StateSnapshot.decode(raw)

    def publish(self, proof: StateTransitionProof) -> AtomicStateReceipt:
        if type(proof) is not StateTransitionProof:
            raise StatePlaneError("state_plane_store_proof_invalid")
        independently_verify_state_transition(proof)
        with _exclusive_file_lock(self.lock_path):
            current = self.read()
            if current.root_512 != proof.before.root_512:
                raise StatePlaneError("state_plane_store_stale_root")
            _atomic_write(self.path, proof.after.encoded)
            if self.read().root_512 != proof.after.root_512:
                raise StatePlaneError("state_plane_store_readback_root_mismatch")
        return proof.receipt


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "COMMITMENT_PARAMETER_IDENTITY",
    "COMMITMENT_STATUS",
    "FileStateStore",
    "HashPadCommitment",
    "HashPadOpening",
    "PROOF_SUITE_ID",
    "PUBLIC_PROJECTION_FIELD_COUNT",
    "SHA3_512_LENGTH",
    "STATE_BINDING_MAGIC",
    "STATE_BINDING_VERSION",
    "STATE_AIR_FRAGMENT_MAGIC",
    "STATE_AIR_FRAGMENT_VERSION",
    "STATE_PARAMETER_IDENTITY",
    "STATUS",
    "StateEntry",
    "StateOperation",
    "StatePlaneError",
    "StateSnapshot",
    "StateTransitionProof",
    "VERIFIER_IDENTITY_512",
    "build_hash_pad_commitment",
    "build_state_transition",
    "derive_h4_binding_input_digest",
    "independently_verify_state_transition",
    "verify_hash_pad_opening",
)
