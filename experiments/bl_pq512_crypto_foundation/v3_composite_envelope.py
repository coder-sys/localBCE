"""Fixed-shape version-3 composite-envelope grammar (nonactivating).

This module parses and commits the outer grammar only.  It deliberately has
no aggregate-verification success path: the semantic, portable H4, and
composite-transcript verifier endpoints are not yet available.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import io
import os
from pathlib import Path
import stat
from typing import BinaryIO, Final, Sequence


V3_MAGIC: Final[bytes] = b"BLPQENV3"
V3_VERSION: Final[int] = 3
V3_FLAGS: Final[int] = 0
V3_HEADER_BYTES: Final[int] = 1_652
V3_PUBLIC_FIELD_COUNT: Final[int] = 12
V3_PUBLIC_FIELD_BYTES: Final[int] = 32
V3_PUBLIC_FIELDS_BYTES: Final[int] = 384
V3_SIDECAR_BYTES: Final[int] = 744
V3_DESCRIPTOR_COUNT: Final[int] = 4
V3_DESCRIPTOR_BYTES: Final[int] = 76
# K512 carries four fixed 192 MiB H4 shard bodies plus one shared transcript
# and the semantic/typed components. Parsing remains streaming and every
# profile still pins a much tighter exact length in its trusted layout.
V3_ABSOLUTE_MAX_BYTES: Final[int] = 2 * 1024 * 1024 * 1024

V3_LAYOUT_MAGIC: Final[bytes] = b"BLV3LY01"
V3_LAYOUT_VERSION: Final[int] = 2
V3_LAYOUT_FLAGS: Final[int] = 0
V3_LAYOUT_BYTES: Final[int] = 820
V3_LAYOUT_COMPONENT_BYTES: Final[int] = 148
V3_LAYOUT_COMMITMENT_DOMAIN: Final[bytes] = b"BL/PQ512/V3/LAYOUT/v2\x00"
V3_ENVELOPE_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/V3/COMPOSITE-ENVELOPE/v1\x00"
)

V3_TRANSCRIPT_MAGIC: Final[bytes] = b"BLV3TR01"
V3_TRANSCRIPT_GRAMMAR: Final[int] = 1
V3_TRANSCRIPT_FLAGS: Final[int] = 0
V3_TRANSCRIPT_PREFIX_BYTES: Final[int] = 20

SEMANTIC_KIND: Final[int] = 1
H4_KIND: Final[int] = 2
TYPED_STATE_KIND: Final[int] = 3
COMPOSITE_TRANSCRIPT_KIND: Final[int] = 4
V3_COMPONENT_ORDER: Final[tuple[int, ...]] = (
    SEMANTIC_KIND,
    H4_KIND,
    TYPED_STATE_KIND,
    COMPOSITE_TRANSCRIPT_KIND,
)

V3_STATUS: Final[str] = "V3_GRAMMAR_PARSED_AGGREGATE_UNQUALIFIED"

K128_PROFILE_CODE: Final[int] = 1
K512_PROFILE_CODE: Final[int] = 3
GOVERNED_PROFILE_LABELS: Final[dict[int, bytes]] = {
    K128_PROFILE_CODE: b"K128_CALIBRATION",
    K512_PROFILE_CODE: b"K512_CALIBRATION",
}


class V3EnvelopeError(ValueError):
    """Canonical grammar or trusted-layout rejection."""


class V3VerificationUnavailable(V3EnvelopeError):
    """The outer grammar parsed but aggregate verification is unavailable."""


def governed_profile_label(profile_code: int) -> bytes:
    if type(profile_code) is not int or profile_code not in GOVERNED_PROFILE_LABELS:
        raise V3EnvelopeError("v3_layout_profile_code_invalid")
    return GOVERNED_PROFILE_LABELS[profile_code]


def _u16(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise V3EnvelopeError("v3_u16_invalid")
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise V3EnvelopeError("v3_u32_invalid")
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise V3EnvelopeError("v3_u64_invalid")
    return value.to_bytes(8, "big")


def _wide(label: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise V3EnvelopeError(f"v3_{label}_shape_invalid")
    if nonzero and not any(value):
        raise V3EnvelopeError(f"v3_{label}_zero")
    return value


@dataclass(frozen=True, slots=True)
class V3ComponentLayout:
    kind: int
    grammar: int
    exact_length: int
    maximum_length: int
    expected_program_commitment: bytes
    expected_schedule_commitment: bytes

    def __post_init__(self) -> None:
        if self.kind not in V3_COMPONENT_ORDER:
            raise V3EnvelopeError("v3_layout_component_kind_invalid")
        _u16(self.grammar)
        if self.grammar == 0:
            raise V3EnvelopeError("v3_layout_component_grammar_zero")
        _u64(self.exact_length)
        _u64(self.maximum_length)
        if (
            self.exact_length <= 0
            or self.exact_length > self.maximum_length
            or self.maximum_length > V3_ABSOLUTE_MAX_BYTES
        ):
            raise V3EnvelopeError("v3_layout_component_length_invalid")
        if self.kind == COMPOSITE_TRANSCRIPT_KIND and (
            self.grammar != V3_TRANSCRIPT_GRAMMAR
            or self.exact_length < V3_TRANSCRIPT_PREFIX_BYTES + 1
        ):
            raise V3EnvelopeError("v3_layout_transcript_shape_invalid")
        _wide("expected_program_commitment", self.expected_program_commitment)
        _wide("expected_schedule_commitment", self.expected_schedule_commitment)

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _u16(self.kind),
                _u16(self.grammar),
                _u64(self.exact_length),
                _u64(self.maximum_length),
                self.expected_program_commitment,
                self.expected_schedule_commitment,
            )
        )


@dataclass(frozen=True, slots=True)
class V3ProfileLayout:
    profile_id: bytes
    profile_code: int
    candidate_descriptor_identity: bytes
    total_length: int
    maximum_total_length: int
    components: tuple[V3ComponentLayout, ...]
    layout_commitment: bytes

    def __post_init__(self) -> None:
        _wide("profile_id", self.profile_id)
        governed_profile_label(self.profile_code)
        _wide("candidate_descriptor_identity", self.candidate_descriptor_identity)
        _wide("layout_commitment", self.layout_commitment)
        if (
            type(self.components) is not tuple
            or len(self.components) != V3_DESCRIPTOR_COUNT
            or tuple(value.kind for value in self.components) != V3_COMPONENT_ORDER
        ):
            raise V3EnvelopeError("v3_layout_component_order_invalid")
        _u64(self.total_length)
        _u64(self.maximum_total_length)
        expected_total = V3_HEADER_BYTES + sum(
            component.exact_length for component in self.components
        )
        if (
            self.total_length != expected_total
            or self.total_length > self.maximum_total_length
            or self.maximum_total_length > V3_ABSOLUTE_MAX_BYTES
            or any(
                component.maximum_length > self.maximum_total_length
                for component in self.components
            )
        ):
            raise V3EnvelopeError("v3_layout_total_length_invalid")
        if self.layout_commitment != derive_layout_commitment(self):
            raise V3EnvelopeError("v3_layout_commitment_invalid")

    @classmethod
    def build(
        cls,
        *,
        profile_id: bytes,
        profile_code: int,
        candidate_descriptor_identity: bytes,
        maximum_total_length: int,
        components: Sequence[V3ComponentLayout],
    ) -> "V3ProfileLayout":
        materialized = tuple(components)
        total_length = V3_HEADER_BYTES + sum(
            component.exact_length for component in materialized
        )
        provisional = object.__new__(cls)
        object.__setattr__(provisional, "profile_id", profile_id)
        object.__setattr__(provisional, "profile_code", profile_code)
        object.__setattr__(
            provisional,
            "candidate_descriptor_identity",
            candidate_descriptor_identity,
        )
        object.__setattr__(provisional, "total_length", total_length)
        object.__setattr__(
            provisional, "maximum_total_length", maximum_total_length
        )
        object.__setattr__(provisional, "components", materialized)
        object.__setattr__(
            provisional, "layout_commitment", derive_layout_commitment(provisional)
        )
        provisional.__post_init__()
        return provisional

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                _layout_commitment_preimage(self),
                self.layout_commitment,
            )
        )
        if len(encoded) != V3_LAYOUT_BYTES:
            raise AssertionError("v3_layout_encoded_size")
        return encoded

    @classmethod
    def decode_trusted(cls, encoded: bytes) -> "V3ProfileLayout":
        if type(encoded) is not bytes or len(encoded) != V3_LAYOUT_BYTES:
            raise V3EnvelopeError("v3_layout_encoding_length_invalid")
        reader = _BytesReader(encoded)
        if reader.take(8) != V3_LAYOUT_MAGIC:
            raise V3EnvelopeError("v3_layout_magic_invalid")
        if reader.u16() != V3_LAYOUT_VERSION:
            raise V3EnvelopeError("v3_layout_version_invalid")
        if reader.u16() != V3_LAYOUT_FLAGS:
            raise V3EnvelopeError("v3_layout_flags_invalid")
        profile_id = reader.take(64)
        profile_code = reader.take(1)[0]
        if reader.take(7) != bytes(7):
            raise V3EnvelopeError("v3_layout_reserved_nonzero")
        candidate = reader.take(64)
        total_length = reader.u64()
        maximum_total_length = reader.u64()
        components = tuple(
            V3ComponentLayout(
                kind=reader.u16(),
                grammar=reader.u16(),
                exact_length=reader.u64(),
                maximum_length=reader.u64(),
                expected_program_commitment=reader.take(64),
                expected_schedule_commitment=reader.take(64),
            )
            for _ in range(V3_DESCRIPTOR_COUNT)
        )
        layout_commitment = reader.take(64)
        if reader.offset != len(encoded):
            raise V3EnvelopeError("v3_layout_trailing")
        return cls(
            profile_id=profile_id,
            profile_code=profile_code,
            candidate_descriptor_identity=candidate,
            total_length=total_length,
            maximum_total_length=maximum_total_length,
            components=components,
            layout_commitment=layout_commitment,
        )


def _layout_commitment_preimage(layout: V3ProfileLayout) -> bytes:
    return b"".join(
        (
            V3_LAYOUT_MAGIC,
            _u16(V3_LAYOUT_VERSION),
            _u16(V3_LAYOUT_FLAGS),
            _wide("profile_id", layout.profile_id),
            bytes((layout.profile_code,)),
            bytes(7),
            _wide(
                "candidate_descriptor_identity",
                layout.candidate_descriptor_identity,
            ),
            _u64(layout.total_length),
            _u64(layout.maximum_total_length),
            *(component.canonical_bytes() for component in layout.components),
        )
    )


def derive_layout_commitment(layout: V3ProfileLayout) -> bytes:
    return sha3_512(V3_LAYOUT_COMMITMENT_DOMAIN + _layout_commitment_preimage(layout)).digest()


@dataclass(frozen=True, slots=True)
class V3ComponentDescriptor:
    kind: int
    grammar: int
    length: int
    sha3_512: bytes

    def encode(self) -> bytes:
        if self.kind not in V3_COMPONENT_ORDER:
            raise V3EnvelopeError("v3_descriptor_kind_invalid")
        if self.grammar == 0:
            raise V3EnvelopeError("v3_descriptor_grammar_invalid")
        return b"".join(
            (
                _u16(self.kind),
                _u16(self.grammar),
                _u64(self.length),
                _wide("component_digest", self.sha3_512),
            )
        )


@dataclass(frozen=True, slots=True)
class V3ParsedEnvelope:
    profile_id: bytes
    profile_code: int
    candidate_descriptor_identity: bytes
    layout_commitment: bytes
    public_fields: tuple[bytes, ...]
    sidecar: bytes
    descriptors: tuple[V3ComponentDescriptor, ...]
    # Absolute component-body offsets derived from the authenticated header.
    # These are routing metadata only; component authority remains with each
    # native component verifier.
    component_offsets: tuple[int, ...]
    envelope_commitment: bytes
    status: str = V3_STATUS
    production_usable: bool = False
    activation_allowed: bool = False


class _BytesReader:
    def __init__(self, encoded: bytes):
        self.encoded = encoded
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        value = self.encoded[self.offset:end]
        if len(value) != length:
            raise V3EnvelopeError("v3_truncated")
        self.offset = end
        return value

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")


def _validate_sidecar(sidecar: bytes, profile_id: bytes) -> None:
    if (
        type(sidecar) is not bytes
        or len(sidecar) != V3_SIDECAR_BYTES
        or sidecar[:8] != b"BLPQSC01"
        or int.from_bytes(sidecar[8:10], "big") != 1
        or int.from_bytes(sidecar[10:12], "big") != 0
        or int.from_bytes(sidecar[12:16], "big") != V3_SIDECAR_BYTES
        or sidecar[16:80] != profile_id
        or any(sidecar[80:144])
    ):
        raise V3EnvelopeError("v3_sidecar_header_invalid")
    for start in (16, 144, 208, 272, 360, 424, 488, 552, 616, 680):
        if not any(sidecar[start : start + 64]):
            raise V3EnvelopeError("v3_sidecar_identity_zero")
    epoch = int.from_bytes(sidecar[336:344], "big")
    sequence_before = int.from_bytes(sidecar[344:352], "big")
    sequence_after = int.from_bytes(sidecar[352:360], "big")
    if (
        epoch == 0
        or sequence_before == 0xFFFFFFFFFFFFFFFF
        or sequence_after != sequence_before + 1
        or sidecar[360:424] == sidecar[424:488]
        or sidecar[552:616] == sidecar[616:680]
    ):
        raise V3EnvelopeError("v3_sidecar_transition_invalid")


def _parse_header(encoded: bytes, layout: V3ProfileLayout) -> tuple[
    tuple[bytes, ...], bytes, tuple[V3ComponentDescriptor, ...]
]:
    if type(encoded) is not bytes or len(encoded) != V3_HEADER_BYTES:
        raise V3EnvelopeError("v3_header_length_invalid")
    reader = _BytesReader(encoded)
    if reader.take(8) != V3_MAGIC:
        raise V3EnvelopeError("v3_magic_invalid")
    if reader.u16() != V3_VERSION:
        raise V3EnvelopeError("v3_version_invalid")
    if reader.u16() != V3_FLAGS:
        raise V3EnvelopeError("v3_flags_invalid")
    if reader.u32() != V3_HEADER_BYTES:
        raise V3EnvelopeError("v3_header_length_invalid")
    if reader.u64() != layout.total_length:
        raise V3EnvelopeError("v3_total_length_mismatch")
    if reader.take(64) != layout.profile_id:
        raise V3EnvelopeError("v3_profile_mismatch")
    if reader.take(64) != layout.candidate_descriptor_identity:
        raise V3EnvelopeError("v3_candidate_descriptor_mismatch")
    if reader.take(64) != layout.layout_commitment:
        raise V3EnvelopeError("v3_layout_commitment_mismatch")
    public_fields = tuple(
        reader.take(V3_PUBLIC_FIELD_BYTES) for _ in range(V3_PUBLIC_FIELD_COUNT)
    )
    sidecar = reader.take(V3_SIDECAR_BYTES)
    _validate_sidecar(sidecar, layout.profile_id)
    if reader.u16() != V3_DESCRIPTOR_COUNT or reader.u16() != 0:
        raise V3EnvelopeError("v3_descriptor_count_invalid")
    descriptors: list[V3ComponentDescriptor] = []
    for expected in layout.components:
        descriptor = V3ComponentDescriptor(
            kind=reader.u16(),
            grammar=reader.u16(),
            length=reader.u64(),
            sha3_512=reader.take(64),
        )
        if descriptor.kind != expected.kind:
            raise V3EnvelopeError("v3_component_order_invalid")
        if descriptor.grammar != expected.grammar:
            raise V3EnvelopeError("v3_component_grammar_mismatch")
        if descriptor.length != expected.exact_length:
            raise V3EnvelopeError("v3_component_length_mismatch")
        _wide("component_digest", descriptor.sha3_512)
        descriptors.append(descriptor)
    if reader.offset != V3_HEADER_BYTES:
        raise V3EnvelopeError("v3_header_trailing")
    return public_fields, sidecar, tuple(descriptors)


def build_composite_transcript_slot(payload: bytes, *, fixed_length: int) -> bytes:
    if type(payload) is not bytes or not payload:
        raise V3EnvelopeError("v3_transcript_payload_invalid")
    if (
        type(fixed_length) is not int
        or fixed_length < V3_TRANSCRIPT_PREFIX_BYTES + len(payload)
    ):
        raise V3EnvelopeError("v3_transcript_slot_length_invalid")
    return b"".join(
        (
            V3_TRANSCRIPT_MAGIC,
            _u16(V3_TRANSCRIPT_GRAMMAR),
            _u16(V3_TRANSCRIPT_FLAGS),
            _u64(len(payload)),
            payload,
            bytes(fixed_length - V3_TRANSCRIPT_PREFIX_BYTES - len(payload)),
        )
    )


def _validate_transcript_slot(encoded: bytes, expected_length: int) -> None:
    if len(encoded) != expected_length or len(encoded) < V3_TRANSCRIPT_PREFIX_BYTES + 1:
        raise V3EnvelopeError("v3_transcript_slot_length_invalid")
    if encoded[:8] != V3_TRANSCRIPT_MAGIC:
        raise V3EnvelopeError("v3_transcript_magic_invalid")
    if int.from_bytes(encoded[8:10], "big") != V3_TRANSCRIPT_GRAMMAR:
        raise V3EnvelopeError("v3_transcript_grammar_invalid")
    if int.from_bytes(encoded[10:12], "big") != V3_TRANSCRIPT_FLAGS:
        raise V3EnvelopeError("v3_transcript_flags_invalid")
    payload_length = int.from_bytes(encoded[12:20], "big")
    if not 0 < payload_length <= expected_length - V3_TRANSCRIPT_PREFIX_BYTES:
        raise V3EnvelopeError("v3_transcript_payload_length_invalid")
    if any(encoded[V3_TRANSCRIPT_PREFIX_BYTES + payload_length :]):
        raise V3EnvelopeError("v3_transcript_padding_nonzero")


def encode_v3_envelope(
    *,
    layout: V3ProfileLayout,
    public_fields: Sequence[bytes],
    sidecar: bytes,
    components: Sequence[bytes],
) -> bytes:
    fields = tuple(public_fields)
    bodies = tuple(components)
    if len(fields) != V3_PUBLIC_FIELD_COUNT or any(
        type(value) is not bytes or len(value) != V3_PUBLIC_FIELD_BYTES
        for value in fields
    ):
        raise V3EnvelopeError("v3_public_fields_invalid")
    _validate_sidecar(sidecar, layout.profile_id)
    if len(bodies) != V3_DESCRIPTOR_COUNT:
        raise V3EnvelopeError("v3_component_count_invalid")
    descriptors: list[V3ComponentDescriptor] = []
    for expected, body in zip(layout.components, bodies, strict=True):
        if type(body) is not bytes or len(body) != expected.exact_length:
            raise V3EnvelopeError("v3_component_length_mismatch")
        if expected.kind == COMPOSITE_TRANSCRIPT_KIND:
            _validate_transcript_slot(body, expected.exact_length)
        descriptors.append(
            V3ComponentDescriptor(
                expected.kind,
                expected.grammar,
                expected.exact_length,
                sha3_512(body).digest(),
            )
        )
    header = b"".join(
        (
            V3_MAGIC,
            _u16(V3_VERSION),
            _u16(V3_FLAGS),
            _u32(V3_HEADER_BYTES),
            _u64(layout.total_length),
            layout.profile_id,
            layout.candidate_descriptor_identity,
            layout.layout_commitment,
            *fields,
            sidecar,
            _u16(V3_DESCRIPTOR_COUNT),
            _u16(0),
            *(descriptor.encode() for descriptor in descriptors),
        )
    )
    if len(header) != V3_HEADER_BYTES:
        raise AssertionError("v3_header_encoded_size")
    encoded = header + b"".join(bodies)
    if len(encoded) != layout.total_length:
        raise AssertionError("v3_envelope_encoded_size")
    return encoded


def _read_exact(handle: BinaryIO, length: int) -> bytes:
    value = handle.read(length)
    if len(value) != length:
        raise V3EnvelopeError("v3_truncated")
    return value


def parse_v3_envelope(handle: BinaryIO, layout: V3ProfileLayout) -> V3ParsedEnvelope:
    if not all(hasattr(handle, name) for name in ("read", "seek", "tell")):
        raise TypeError("v3_read_seek_handle_required")
    handle.seek(0, io.SEEK_END)
    observed_length = handle.tell()
    if observed_length != layout.total_length:
        raise V3EnvelopeError("v3_file_length_mismatch")
    handle.seek(0)
    header = _read_exact(handle, V3_HEADER_BYTES)
    public_fields, sidecar, descriptors = _parse_header(header, layout)

    envelope_hash = sha3_512()
    envelope_hash.update(V3_ENVELOPE_COMMITMENT_DOMAIN)
    envelope_hash.update(_u64(layout.total_length))
    envelope_hash.update(header)
    component_offsets: list[int] = []
    for descriptor in descriptors:
        component_offsets.append(handle.tell())
        component_hash = sha3_512()
        remaining = descriptor.length
        transcript_prefix = b""
        transcript_payload_length: int | None = None
        transcript_consumed = 0
        while remaining:
            chunk = _read_exact(handle, min(1024 * 1024, remaining))
            remaining -= len(chunk)
            component_hash.update(chunk)
            envelope_hash.update(chunk)
            if descriptor.kind == COMPOSITE_TRANSCRIPT_KIND:
                combined = transcript_prefix + chunk
                if transcript_payload_length is None and len(combined) >= V3_TRANSCRIPT_PREFIX_BYTES:
                    prefix = combined[:V3_TRANSCRIPT_PREFIX_BYTES]
                    if prefix[:8] != V3_TRANSCRIPT_MAGIC:
                        raise V3EnvelopeError("v3_transcript_magic_invalid")
                    if int.from_bytes(prefix[8:10], "big") != descriptor.grammar:
                        raise V3EnvelopeError("v3_transcript_grammar_invalid")
                    if int.from_bytes(prefix[10:12], "big") != V3_TRANSCRIPT_FLAGS:
                        raise V3EnvelopeError("v3_transcript_flags_invalid")
                    transcript_payload_length = int.from_bytes(prefix[12:20], "big")
                    if not 0 < transcript_payload_length <= descriptor.length - V3_TRANSCRIPT_PREFIX_BYTES:
                        raise V3EnvelopeError("v3_transcript_payload_length_invalid")
                    combined = combined[V3_TRANSCRIPT_PREFIX_BYTES:]
                elif transcript_payload_length is None:
                    transcript_prefix = combined
                    continue
                assert transcript_payload_length is not None
                payload_remaining = max(0, transcript_payload_length - transcript_consumed)
                payload_bytes = min(payload_remaining, len(combined))
                transcript_consumed += payload_bytes
                if any(combined[payload_bytes:]):
                    raise V3EnvelopeError("v3_transcript_padding_nonzero")
                transcript_prefix = b""
        if component_hash.digest() != descriptor.sha3_512:
            raise V3EnvelopeError("v3_component_digest_mismatch")
    if handle.read(1):
        raise V3EnvelopeError("v3_trailing")
    return V3ParsedEnvelope(
        profile_id=layout.profile_id,
        profile_code=layout.profile_code,
        candidate_descriptor_identity=layout.candidate_descriptor_identity,
        layout_commitment=layout.layout_commitment,
        public_fields=public_fields,
        sidecar=sidecar,
        descriptors=descriptors,
        component_offsets=tuple(component_offsets),
        envelope_commitment=envelope_hash.digest(),
    )


def parse_v3_envelope_file(path: Path, layout: V3ProfileLayout) -> V3ParsedEnvelope:
    if not isinstance(path, Path) or not path.is_absolute():
        raise V3EnvelopeError("v3_envelope_path_invalid")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise V3EnvelopeError("v3_envelope_not_regular")
            parsed = parse_v3_envelope(handle, layout)
            after = os.fstat(handle.fileno())
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise V3EnvelopeError("v3_envelope_changed_during_read")
            return parsed
    except (OSError, MemoryError) as exc:
        raise V3EnvelopeError("v3_envelope_read_failed") from exc


def verify_v3_composite_file(path: Path, layout: V3ProfileLayout) -> None:
    parse_v3_envelope_file(path, layout)
    raise V3VerificationUnavailable(
        "v3_semantic_h4_composite_transcript_verifiers_unavailable"
    )


__all__ = (
    "COMPOSITE_TRANSCRIPT_KIND",
    "H4_KIND",
    "K128_PROFILE_CODE",
    "K512_PROFILE_CODE",
    "SEMANTIC_KIND",
    "TYPED_STATE_KIND",
    "V3ComponentLayout",
    "V3EnvelopeError",
    "V3ParsedEnvelope",
    "V3ProfileLayout",
    "V3VerificationUnavailable",
    "V3_ABSOLUTE_MAX_BYTES",
    "V3_COMPONENT_ORDER",
    "V3_ENVELOPE_COMMITMENT_DOMAIN",
    "V3_HEADER_BYTES",
    "V3_LAYOUT_BYTES",
    "V3_MAGIC",
    "V3_STATUS",
    "V3_TRANSCRIPT_PREFIX_BYTES",
    "build_composite_transcript_slot",
    "derive_layout_commitment",
    "encode_v3_envelope",
    "governed_profile_label",
    "parse_v3_envelope",
    "parse_v3_envelope_file",
    "verify_v3_composite_file",
)
