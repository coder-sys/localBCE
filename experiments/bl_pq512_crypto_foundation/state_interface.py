"""Gate 2E-1 narrow, replaceable state-plane interfaces.

This module owns only bounded interface metadata and canonical wire envelopes.
It intentionally imports no claim, payment, settlement, application, or proof
implementation. A future state relation or commitment backend can implement
these ports without changing claim semantics or the external 12-field ABI.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping


STATUS: Final[str] = "S1_NARROW_STATE_INTERFACE_V1_SYNTHETIC_NONPRODUCTION"
INTERFACE_WIRE_VERSION: Final[int] = 1
INTERFACE_MAGIC: Final[bytes] = b"BLSI"
INTERFACE_HEADER_LENGTH: Final[int] = 8
MAX_INTERFACE_PAYLOAD_LENGTH: Final[int] = 4096
MAX_INTERFACE_ENVELOPE_LENGTH: Final[int] = INTERFACE_HEADER_LENGTH + MAX_INTERFACE_PAYLOAD_LENGTH
MAX_PARAMETER_IDENTITY_LENGTH: Final[int] = 64
MAX_TRANSITION_PARAMETER_IDENTITY_LENGTH: Final[int] = 48
MAX_PROFILE_ID_LENGTH: Final[int] = 32
SHA3_512_LENGTH: Final[int] = 64
U64_MAX: Final[int] = (1 << 64) - 1
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False


def _ascii(value: str, field_name: str, maximum: int) -> None:
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError(f"state_interface_{field_name}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"state_interface_{field_name}_not_ascii") from exc
    if b"\x00" in encoded:
        raise ValueError(f"state_interface_{field_name}_nul")


def _tuple_of_text(values: tuple[str, ...], field_name: str) -> None:
    if type(values) is not tuple or not values or any(type(value) is not str or not value for value in values):
        raise ValueError(f"state_interface_{field_name}_invalid")


@dataclass(frozen=True, slots=True)
class StateInterfaceDescriptor:
    interface_id: str
    wire_code: int
    version: int
    producer: str
    consumers: tuple[str, ...]
    public_fields: tuple[str, ...]
    private_fields: tuple[str, ...]
    grammar: str
    max_payload_length: int
    domain: bytes
    parameter_identity: str
    canonical_decode_rule: str
    error_family: str
    retry_behavior: str
    crash_behavior: str
    mutation_cases: tuple[str, ...]

    def __post_init__(self) -> None:
        _ascii(self.interface_id, "interface_id", 48)
        if type(self.wire_code) is not int or not 1 <= self.wire_code <= 255:
            raise ValueError("state_interface_wire_code_invalid")
        if self.version != INTERFACE_WIRE_VERSION:
            raise ValueError("state_interface_version_invalid")
        _ascii(self.producer, "producer", 64)
        _tuple_of_text(self.consumers, "consumers")
        _tuple_of_text(self.public_fields, "public_fields")
        _tuple_of_text(self.private_fields, "private_fields")
        _ascii(self.grammar, "grammar", 512)
        if type(self.max_payload_length) is not int or not 1 <= self.max_payload_length <= MAX_INTERFACE_PAYLOAD_LENGTH:
            raise ValueError("state_interface_max_payload_length_invalid")
        if type(self.domain) is not bytes or not 8 <= len(self.domain) <= 96 or not self.domain.endswith(b"\x00"):
            raise ValueError("state_interface_domain_invalid")
        _ascii(self.parameter_identity, "parameter_identity", MAX_PARAMETER_IDENTITY_LENGTH)
        _ascii(self.canonical_decode_rule, "canonical_decode_rule", 512)
        _ascii(self.error_family, "error_family", 128)
        _ascii(self.retry_behavior, "retry_behavior", 512)
        _ascii(self.crash_behavior, "crash_behavior", 512)
        _tuple_of_text(self.mutation_cases, "mutation_cases")


def _descriptor(
    wire_code: int,
    interface_id: str,
    producer: str,
    consumers: tuple[str, ...],
    public_fields: tuple[str, ...],
    private_fields: tuple[str, ...],
    grammar: str,
    maximum: int,
    canonical_decode_rule: str,
    error_family: str,
    retry_behavior: str,
    crash_behavior: str,
    mutation_cases: tuple[str, ...],
) -> StateInterfaceDescriptor:
    return StateInterfaceDescriptor(
        interface_id,
        wire_code,
        INTERFACE_WIRE_VERSION,
        producer,
        consumers,
        public_fields,
        private_fields,
        grammar,
        maximum,
        f"BL/PQ512/STATE-INTERFACE/{interface_id}/v1\x00".encode("ascii"),
        f"BL-PQ512-STATE-{interface_id}-PARAM-V1",
        canonical_decode_rule,
        error_family,
        retry_behavior,
        crash_behavior,
        mutation_cases,
    )


INTERFACE_DESCRIPTORS: Final[tuple[StateInterfaceDescriptor, ...]] = (
    _descriptor(1, "state_layout", "state_plane", ("state_relation", "commitment_backend", "verifier"),
        ("layout_version", "capacity", "epoch", "parameter_identity"), ("layout_salt",),
        "layout_version:u8||capacity:u64be||epoch:u64be||parameter_identity:ascii8..48",
        128, "reject noncanonical ASCII, zero capacity, unknown version, or trailing bytes",
        "state_layout_decode", "same attempt may retry with identical layout bytes", "publish atomically or retain old layout",
        ("version_substitution", "capacity_change", "epoch_rebind", "trailing_byte")),
    _descriptor(2, "key_value_encoding", "state_relation", ("state_layout", "commitment_backend", "verifier"),
        ("key_width", "value_width", "encoding_version"), ("key", "value"),
        "encoding_version:u8||key_width:u16be||value_width:u16be||key:bytes||value:bytes",
        512, "require fixed widths from the versioned descriptor and consume exactly the payload",
        "state_key_value_decode", "retry preserves encoded key/value identity", "partial writes are discarded before publication",
        ("width_change", "key_swap", "value_swap", "truncation")),
    _descriptor(3, "membership", "state_relation", ("independent_verifier", "atomic_receipt"),
        ("layout_id", "epoch", "key_digest", "value_digest", "membership_bit"), ("opening", "path_witness"),
        "layout_id:bytes64||epoch:u64be||key_digest:bytes64||value_digest:bytes64||membership:u8||opening:bytes",
        512, "require 0/1 membership and exact digest widths before relation evaluation",
        "state_membership", "retry uses the same attempt identity and fresh proof randomness", "unpublished opening is discarded on crash",
        ("bit_flip", "key_substitution", "value_substitution", "root_substitution")),
    _descriptor(4, "absence", "state_relation", ("independent_verifier", "atomic_receipt"),
        ("layout_id", "epoch", "key_digest", "absence_bit"), ("neighbor_witness", "opening"),
        "layout_id:bytes64||epoch:u64be||key_digest:bytes64||absence:u8||neighbor:bytes||opening:bytes",
        768, "require absence=1 and canonical ordered neighbors; reject a member as absence",
        "state_absence", "retry preserves the queried key and attempt identity", "unpublished absence witness is discarded",
        ("membership_as_absence", "neighbor_reorder", "key_substitution", "truncation")),
    _descriptor(5, "ordered_access_manifest", "state_relation", ("transcript", "independent_verifier", "atomic_receipt"),
        ("manifest_digest", "row_count", "profile_shape"), ("ordered_rows", "keys", "values"),
        "manifest_digest:bytes64||row_count:u32be||profile_shape:bytes||rows:fixed_bounded_bytes",
        2048, "require canonical row order, fixed row count, exact digest, and no duplicate identity",
        "state_access_manifest", "retry reuses the manifest identity but fresh proof randomness", "incomplete manifest is not publishable",
        ("row_omission", "row_reorder", "duplicate_identity", "digest_substitution")),
    _descriptor(6, "memory_consistency", "state_relation", ("membership", "absence", "old_new_transition", "verifier"),
        ("manifest_digest", "read_digest", "write_digest", "consistency_bit"), ("read_rows", "write_rows", "shuffle_witness"),
        "manifest_digest:bytes64||read_digest:bytes64||write_digest:bytes64||consistent:u8||witness:bytes",
        2048, "require consistent=1 and exact manifest binding; host equality is not authoritative",
        "state_memory_consistency", "retry keeps operation order and refreshes hidden witness randomness", "reject any partial consistency record",
        ("read_stale", "write_omission", "write_reorder", "consistent_bit_flip")),
    _descriptor(7, "commitment_opening", "commitment_backend", ("state_relation", "transcript", "verifier"),
        ("commitment_id", "state_epoch", "opening_digest", "parameter_identity"), ("commitment", "opening_witness", "mask"),
        "commitment_id:bytes64||epoch:u64be||opening_digest:bytes64||parameter_identity:ascii||opening:bytes",
        2048, "decode only under the bound domain/version/parameter identity and exact length",
        "state_commitment_opening", "retry keeps state identity but uses fresh hidden randomness", "unpublished opening and mask are erased/discarded",
        ("commitment_swap", "opening_swap", "parameter_substitution", "domain_substitution")),
    _descriptor(8, "old_new_transition", "state_relation", ("transcript", "verifier", "atomic_receipt"),
        ("old_root", "new_root", "epoch", "sequence", "manifest_digest", "public_projection_digest"), ("transition_witness",),
        "BLTR||version:u8||profile:len8ascii||parameter:len8ascii||epoch:u64be||seq_before:u64be||seq_after:u64be||old_root:bytes64||new_root:bytes64||manifest:bytes64||projection:bytes64",
        512, "require seq_after=seq_before+1, fixed digest widths, and exact end-of-input",
        "state_transition", "retry preserves old/new state and attempt identity", "publish old and new state atomically or retain old state",
        ("old_root_swap", "new_root_swap", "sequence_replay", "manifest_substitution")),
    _descriptor(9, "sha3_512_public_identifier", "state_plane", ("transcript", "verifier", "atomic_receipt"),
        ("domain", "version", "parameter_identity", "identifier"), ("source_tuple",),
        "domain:bytes||version:u8||parameter_identity:ascii||source_tuple:bounded_bytes",
        512, "hash the exact domain-separated tuple with SHA3-512 and consume no private fields",
        "state_public_identifier", "retry keeps the source tuple identity", "identifier is not published until its source tuple is complete",
        ("domain_swap", "parameter_swap", "source_truncation", "identifier_replacement")),
    _descriptor(10, "migration_rollback", "migration_controller", ("state_layout", "state_relation", "verifier", "atomic_receipt"),
        ("old_layout", "new_layout", "old_root", "new_root", "migration_version"), ("equivalence_witness", "rollback_witness"),
        "version:u8||old_layout:bytes64||new_layout:bytes64||old_root:bytes64||new_root:bytes64||witness:bytes",
        1536, "require explicit old/new versions, equivalence evidence, and exact bounded payload",
        "state_migration", "retry keeps migration version and old root; no fresh interpretation of old bytes", "checkpoint atomically or roll back to the old layout",
        ("layout_downgrade", "root_substitution", "rollback_omission", "version_mix")),
    _descriptor(11, "transcript_contribution", "transcript", ("state_relation", "commitment_backend", "verifier"),
        ("round_ordinal", "domain", "message_digest", "module_identity"), ("message", "private_randomness"),
        "round:u32be||domain:bytes||message_digest:bytes64||module_identity:bytes64||message:bounded_bytes",
        1536, "require strictly increasing round ordinals and domain/module identity binding",
        "state_transcript", "retry preserves attempt identity and starts a fresh authenticated transcript", "incomplete transcript cannot authorize publication",
        ("round_reorder", "message_swap", "module_swap", "domain_swap")),
    _descriptor(12, "independent_verification", "independent_verifier", ("state_relation", "commitment_backend", "receipt"),
        ("statement_digest", "module_identity", "decision"), ("proof_bytes", "private_replay_state"),
        "statement_digest:bytes64||module_identity:bytes64||decision:u8||proof:bounded_bytes",
        2048, "recompute the statement and reject any non-0/1 decision or trailing bytes",
        "state_independent_verifier", "retry requires a fresh proof while keeping statement identity", "verifier failure leaves no accepted state transition",
        ("decision_flip", "statement_swap", "module_swap", "proof_trailing_byte")),
    _descriptor(13, "atomic_receipt", "receipt", ("state_relation", "commitment_backend", "verifier", "settlement_adapter"),
        ("attempt_id", "old_root", "new_root", "proof_id", "verifier_id", "receipt_digest"), ("receipt_body", "private_sidecar"),
        "attempt_id:bytes64||old_root:bytes64||new_root:bytes64||proof_id:bytes64||verifier_id:bytes64||receipt_digest:bytes64||body:bounded_bytes",
        3072, "require every bound identity exactly once and consume the entire bounded receipt",
        "state_atomic_receipt", "retry keeps attempt identity but uses fresh proof randomness and a new receipt id", "no partial receipt is reusable after crash",
        ("field_omission", "field_reorder", "proof_swap", "verifier_swap", "partial_receipt")),
)


_BY_ID: Mapping[str, StateInterfaceDescriptor] = MappingProxyType(
    {item.interface_id: item for item in INTERFACE_DESCRIPTORS}
)
_BY_CODE: Mapping[int, StateInterfaceDescriptor] = MappingProxyType(
    {item.wire_code: item for item in INTERFACE_DESCRIPTORS}
)


def interface_descriptor(interface_id: str) -> StateInterfaceDescriptor:
    if type(interface_id) is not str:
        raise ValueError("state_interface_id_type_invalid")
    try:
        return _BY_ID[interface_id]
    except KeyError as exc:
        raise ValueError("state_interface_id_unknown") from exc


def _descriptor_for_code(wire_code: int) -> StateInterfaceDescriptor:
    try:
        return _BY_CODE[wire_code]
    except KeyError as exc:
        raise ValueError("state_interface_wire_code_unknown") from exc


@dataclass(frozen=True, slots=True)
class InterfaceEnvelope:
    interface_id: str
    version: int
    payload: bytes

    def __post_init__(self) -> None:
        descriptor = interface_descriptor(self.interface_id)
        if self.version != descriptor.version:
            raise ValueError("state_interface_envelope_version_mismatch")
        if type(self.payload) is not bytes or not self.payload or len(self.payload) > descriptor.max_payload_length:
            raise ValueError("state_interface_envelope_payload_length_invalid")

    @property
    def descriptor(self) -> StateInterfaceDescriptor:
        return interface_descriptor(self.interface_id)

    @property
    def encoded(self) -> bytes:
        descriptor = self.descriptor
        if len(self.payload) > 0xFFFF:
            raise ValueError("state_interface_envelope_payload_u16_overflow")
        return (
            INTERFACE_MAGIC
            + bytes((self.version, descriptor.wire_code))
            + len(self.payload).to_bytes(2, "big")
            + self.payload
        )


def encode_interface_envelope(interface_id: str, payload: bytes) -> bytes:
    return InterfaceEnvelope(interface_id, INTERFACE_WIRE_VERSION, payload).encoded


def decode_interface_envelope(encoded: bytes) -> InterfaceEnvelope:
    if type(encoded) is not bytes or not INTERFACE_HEADER_LENGTH <= len(encoded) <= MAX_INTERFACE_ENVELOPE_LENGTH:
        raise ValueError("state_interface_envelope_length_invalid")
    if encoded[:4] != INTERFACE_MAGIC:
        raise ValueError("state_interface_envelope_magic_invalid")
    version = encoded[4]
    if version != INTERFACE_WIRE_VERSION:
        raise ValueError("state_interface_envelope_version_unsupported")
    descriptor = _descriptor_for_code(encoded[5])
    payload_length = int.from_bytes(encoded[6:8], "big")
    if payload_length != len(encoded) - INTERFACE_HEADER_LENGTH:
        raise ValueError("state_interface_envelope_length_mismatch")
    if payload_length > descriptor.max_payload_length:
        raise ValueError("state_interface_envelope_payload_length_invalid")
    return InterfaceEnvelope(descriptor.interface_id, version, encoded[8:])


def derive_sha3_512_public_identifier(source_tuple: bytes) -> bytes:
    descriptor = interface_descriptor("sha3_512_public_identifier")
    if type(source_tuple) is not bytes or not source_tuple or len(source_tuple) > descriptor.max_payload_length:
        raise ValueError("state_interface_public_identifier_source_length_invalid")
    return sha3_512(
        descriptor.domain
        + bytes((descriptor.version,))
        + descriptor.parameter_identity.encode("ascii")
        + source_tuple
    ).digest()


def _wide_digest(value: bytes, field_name: str) -> None:
    if type(value) is not bytes or len(value) != SHA3_512_LENGTH or value == b"\x00" * SHA3_512_LENGTH:
        raise ValueError(f"state_interface_{field_name}_digest_invalid")


def _bounded_u64(value: int, field_name: str) -> None:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(f"state_interface_{field_name}_u64_invalid")


@dataclass(frozen=True, slots=True)
class StateTransitionV1:
    profile_id: str
    parameter_identity: str
    epoch: int
    sequence_before: int
    sequence_after: int
    old_root: bytes
    new_root: bytes
    manifest_digest: bytes
    public_projection_digest: bytes

    def __post_init__(self) -> None:
        _ascii(self.profile_id, "profile_id", MAX_PROFILE_ID_LENGTH)
        _ascii(self.parameter_identity, "parameter_identity", MAX_TRANSITION_PARAMETER_IDENTITY_LENGTH)
        _bounded_u64(self.epoch, "epoch")
        _bounded_u64(self.sequence_before, "sequence_before")
        _bounded_u64(self.sequence_after, "sequence_after")
        if self.sequence_after != self.sequence_before + 1:
            raise ValueError("state_interface_sequence_not_sequential")
        _wide_digest(self.old_root, "old_root")
        _wide_digest(self.new_root, "new_root")
        _wide_digest(self.manifest_digest, "manifest")
        _wide_digest(self.public_projection_digest, "public_projection")

    @property
    def encoded(self) -> bytes:
        profile = self.profile_id.encode("ascii")
        parameter = self.parameter_identity.encode("ascii")
        result = (
            b"BLTR"
            + bytes((INTERFACE_WIRE_VERSION, len(profile)))
            + profile
            + bytes((len(parameter),))
            + parameter
            + self.epoch.to_bytes(8, "big")
            + self.sequence_before.to_bytes(8, "big")
            + self.sequence_after.to_bytes(8, "big")
            + self.old_root
            + self.new_root
            + self.manifest_digest
            + self.public_projection_digest
        )
        if len(result) > interface_descriptor("old_new_transition").max_payload_length:
            raise ValueError("state_interface_transition_length_invalid")
        return result

    @classmethod
    def decode(cls, encoded: bytes) -> "StateTransitionV1":
        if type(encoded) is not bytes or not 5 <= len(encoded) <= interface_descriptor("old_new_transition").max_payload_length:
            raise ValueError("state_interface_transition_length_invalid")
        if encoded[:4] != b"BLTR" or encoded[4] != INTERFACE_WIRE_VERSION:
            raise ValueError("state_interface_transition_header_invalid")
        cursor = 5

        def read_text(field_name: str, maximum: int) -> str:
            nonlocal cursor
            if cursor >= len(encoded):
                raise ValueError("state_interface_transition_truncated")
            length = encoded[cursor]
            cursor += 1
            if length == 0 or length > maximum or cursor + length > len(encoded):
                raise ValueError(f"state_interface_transition_{field_name}_length_invalid")
            value = encoded[cursor : cursor + length]
            cursor += length
            try:
                return value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError(f"state_interface_transition_{field_name}_not_ascii") from exc

        def read_u64(field_name: str) -> int:
            nonlocal cursor
            if cursor + 8 > len(encoded):
                raise ValueError("state_interface_transition_truncated")
            value = int.from_bytes(encoded[cursor : cursor + 8], "big")
            cursor += 8
            return value

        def read_digest(field_name: str) -> bytes:
            nonlocal cursor
            if cursor + SHA3_512_LENGTH > len(encoded):
                raise ValueError("state_interface_transition_truncated")
            value = encoded[cursor : cursor + SHA3_512_LENGTH]
            cursor += SHA3_512_LENGTH
            _wide_digest(value, field_name)
            return value

        profile_id = read_text("profile_id", MAX_PROFILE_ID_LENGTH)
        parameter_identity = read_text("parameter_identity", MAX_TRANSITION_PARAMETER_IDENTITY_LENGTH)
        epoch = read_u64("epoch")
        sequence_before = read_u64("sequence_before")
        sequence_after = read_u64("sequence_after")
        old_root = read_digest("old_root")
        new_root = read_digest("new_root")
        manifest_digest = read_digest("manifest")
        public_projection_digest = read_digest("public_projection")
        if cursor != len(encoded):
            raise ValueError("state_interface_transition_trailing_bytes")
        return cls(
            profile_id,
            parameter_identity,
            epoch,
            sequence_before,
            sequence_after,
            old_root,
            new_root,
            manifest_digest,
            public_projection_digest,
        )


def encode_transition_envelope(transition: StateTransitionV1) -> bytes:
    if type(transition) is not StateTransitionV1:
        raise ValueError("state_interface_transition_type_invalid")
    return encode_interface_envelope("old_new_transition", transition.encoded)


def decode_transition_envelope(encoded: bytes) -> StateTransitionV1:
    envelope = decode_interface_envelope(encoded)
    if envelope.interface_id != "old_new_transition":
        raise ValueError("state_interface_transition_interface_mismatch")
    return StateTransitionV1.decode(envelope.payload)


__all__ = (
    "ACTIVATION_ALLOWED",
    "INTERFACE_DESCRIPTORS",
    "INTERFACE_HEADER_LENGTH",
    "INTERFACE_MAGIC",
    "INTERFACE_WIRE_VERSION",
    "InterfaceEnvelope",
    "PROOF_SUITE_ID",
    "SHA3_512_LENGTH",
    "STATUS",
    "StateInterfaceDescriptor",
    "StateTransitionV1",
    "decode_interface_envelope",
    "decode_transition_envelope",
    "derive_sha3_512_public_identifier",
    "encode_interface_envelope",
    "encode_transition_envelope",
    "interface_descriptor",
)
