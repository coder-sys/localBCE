"""Strict, nonactivating BL-PQ512 proof-body grammar reference.

The candidate registry reserves ``BLPQPF01`` and an 88-byte proof-body
header, but the production PCS sections and their lengths are not frozen.
This module therefore accepts no in-band suite choice.  A caller must supply
both an exact, out-of-band :class:`ProofGrammar` and its authenticated active
identity.  An absent or unselected grammar always rejects.

The wire body deliberately contains neither the 384 public-output bytes nor
the 744-byte sidecar.  They remain separate verifier arguments.  This module
performs structural parsing and SHA3-512 integrity checks only; it does not
verify a proof, select a proof suite, authorize activation, or implement
production constant-time cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from typing import BinaryIO, Final, Sequence


PROOF_BODY_MAGIC: Final[bytes] = b"BLPQPF01"
PROOF_BODY_VERSION: Final[int] = 1
PROOF_BODY_FLAGS: Final[int] = 0
PROOF_BODY_HEADER_LENGTH: Final[int] = 88
SECTION_DESCRIPTOR_LENGTH: Final[int] = 88
SHA3_512_LENGTH: Final[int] = 64
WIDE_ID_LENGTH: Final[int] = 64

NONACTIVATING_REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_NONACTIVATING_PROOF_GRAMMAR_REFERENCE_V0"
)
UNSELECTED_GRAMMAR_STATUS: Final[str] = "UNSELECTED"

_GRAMMAR_DOMAIN: Final[bytes] = b"BL/PQ512/PROOF-GRAMMAR/REFERENCE/v0"
_UINT16_MAX: Final[int] = (1 << 16) - 1
_UINT32_MAX: Final[int] = (1 << 32) - 1
_UINT64_MAX: Final[int] = (1 << 64) - 1


def _checked_add_u64(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or left > _UINT64_MAX or right > _UINT64_MAX:
        raise ValueError(f"proof_body_{label}_not_u64")
    result = left + right
    if result > _UINT64_MAX:
        raise ValueError(f"proof_body_{label}_overflow")
    return result


def _checked_mul_u64(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or left > _UINT64_MAX or right > _UINT64_MAX:
        raise ValueError(f"proof_body_{label}_not_u64")
    if left != 0 and right > _UINT64_MAX // left:
        raise ValueError(f"proof_body_{label}_overflow")
    return left * right


def _exact_wide_id(label: str, value: object) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"proof_grammar_{label}_must_be_exact_bytes")
    if len(value) != WIDE_ID_LENGTH:
        raise ValueError(f"proof_grammar_{label}_length_invalid")
    if not any(value):
        raise ValueError(f"proof_grammar_{label}_must_be_nonzero")
    return value


def _u32(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise TypeError(f"proof_grammar_{label}_must_be_integer")
    if value < 0 or value > _UINT32_MAX or (nonzero and value == 0):
        raise ValueError(f"proof_grammar_{label}_out_of_range")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise TypeError(f"proof_grammar_{label}_must_be_integer")
    if value < 0 or value > _UINT64_MAX or (nonzero and value == 0):
        raise ValueError(f"proof_grammar_{label}_out_of_range")
    return value


@dataclass(frozen=True, slots=True)
class ProofIdentity:
    """Authenticated identity tuple supplied outside the untrusted proof."""

    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes

    def __post_init__(self) -> None:
        _exact_wide_id("profile_id", self.profile_id)
        _exact_wide_id("proof_suite_id", self.proof_suite_id)
        _exact_wide_id("schema_id", self.schema_id)
        _exact_wide_id("verifier_artifact_identity", self.verifier_artifact_identity)

    def encode(self) -> bytes:
        return b"".join(
            (
                self.profile_id,
                self.proof_suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
            )
        )


@dataclass(frozen=True, slots=True)
class SectionRule:
    """One exact section rule in the externally selected ordered grammar."""

    section_code: int
    name: str
    encoded_length: int
    max_length: int

    def __post_init__(self) -> None:
        _u32("section_code", self.section_code, nonzero=True)
        if type(self.name) is not str:
            raise TypeError("proof_grammar_section_name_must_be_string")
        try:
            encoded_name = self.name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("proof_grammar_section_name_must_be_ascii") from exc
        if not encoded_name or len(encoded_name) > _UINT16_MAX:
            raise ValueError("proof_grammar_section_name_length_invalid")
        length = _u64("section_encoded_length", self.encoded_length, nonzero=True)
        cap = _u64("section_max_length", self.max_length, nonzero=True)
        if length > cap:
            raise ValueError("proof_grammar_section_length_exceeds_cap")

    def grammar_encoding(self) -> bytes:
        name = self.name.encode("ascii")
        return b"".join(
            (
                self.section_code.to_bytes(4, "big"),
                len(name).to_bytes(2, "big"),
                name,
                self.encoded_length.to_bytes(8, "big"),
                self.max_length.to_bytes(8, "big"),
            )
        )


@dataclass(frozen=True, slots=True)
class ProofGrammar:
    """Out-of-band proof grammar; never an activation or verification object."""

    identity: ProofIdentity | None
    sections: tuple[SectionRule, ...]
    max_total_length: int | None
    status: str = NONACTIVATING_REFERENCE_STATUS

    def __post_init__(self) -> None:
        if type(self.sections) is not tuple:
            raise TypeError("proof_grammar_sections_must_be_tuple")
        if self.status == UNSELECTED_GRAMMAR_STATUS:
            if self.identity is not None or self.sections or self.max_total_length is not None:
                raise ValueError("proof_grammar_unselected_must_be_empty")
            return
        if self.status != NONACTIVATING_REFERENCE_STATUS:
            raise ValueError("proof_grammar_status_invalid")
        if type(self.identity) is not ProofIdentity:
            raise TypeError("proof_grammar_identity_required")
        if not self.sections:
            raise ValueError("proof_grammar_sections_required")
        if len(self.sections) > _UINT32_MAX:
            raise ValueError("proof_grammar_section_count_out_of_range")
        if any(type(rule) is not SectionRule for rule in self.sections):
            raise TypeError("proof_grammar_section_rule_required")
        codes = tuple(rule.section_code for rule in self.sections)
        names = tuple(rule.name for rule in self.sections)
        if len(codes) != len(set(codes)):
            raise ValueError("proof_grammar_section_code_duplicate")
        if len(names) != len(set(names)):
            raise ValueError("proof_grammar_section_name_duplicate")
        cap = _u64("max_total_length", self.max_total_length, nonzero=True)
        expected = self.expected_total_length
        if expected > cap:
            raise ValueError("proof_grammar_expected_total_exceeds_cap")

    @classmethod
    def unselected(cls) -> "ProofGrammar":
        return cls(
            identity=None,
            sections=(),
            max_total_length=None,
            status=UNSELECTED_GRAMMAR_STATUS,
        )

    @property
    def selected_for_reference_parsing(self) -> bool:
        return self.status == NONACTIVATING_REFERENCE_STATUS

    @property
    def expected_total_length(self) -> int:
        if not self.selected_for_reference_parsing:
            raise ValueError("proof_grammar_unselected")
        descriptor_bytes = _checked_mul_u64(
            len(self.sections), SECTION_DESCRIPTOR_LENGTH, "descriptor_table_length"
        )
        total = _checked_add_u64(
            PROOF_BODY_HEADER_LENGTH, descriptor_bytes, "metadata_length"
        )
        for rule in self.sections:
            total = _checked_add_u64(total, rule.encoded_length, "expected_total_length")
        return total

    @property
    def digest(self) -> bytes:
        if not self.selected_for_reference_parsing:
            raise ValueError("proof_grammar_unselected")
        assert self.identity is not None
        assert self.max_total_length is not None
        hasher = sha3_512()
        hasher.update(_GRAMMAR_DOMAIN)
        hasher.update(PROOF_BODY_MAGIC)
        hasher.update(PROOF_BODY_VERSION.to_bytes(2, "big"))
        hasher.update(PROOF_BODY_FLAGS.to_bytes(2, "big"))
        hasher.update(PROOF_BODY_HEADER_LENGTH.to_bytes(4, "big"))
        hasher.update(SECTION_DESCRIPTOR_LENGTH.to_bytes(4, "big"))
        hasher.update(self.identity.encode())
        hasher.update(len(self.sections).to_bytes(4, "big"))
        hasher.update(self.max_total_length.to_bytes(8, "big"))
        for rule in self.sections:
            hasher.update(rule.grammar_encoding())
        return hasher.digest()

    def require_identity(self, active_identity: object) -> None:
        if not self.selected_for_reference_parsing:
            raise ValueError("proof_grammar_unselected")
        if type(active_identity) is not ProofIdentity:
            raise TypeError("proof_body_active_identity_required")
        assert self.identity is not None
        for label, observed, expected in (
            ("profile_id", active_identity.profile_id, self.identity.profile_id),
            ("proof_suite_id", active_identity.proof_suite_id, self.identity.proof_suite_id),
            ("schema_id", active_identity.schema_id, self.identity.schema_id),
            (
                "verifier_artifact_identity",
                active_identity.verifier_artifact_identity,
                self.identity.verifier_artifact_identity,
            ),
        ):
            if not hmac.compare_digest(observed, expected):
                raise ValueError(f"proof_grammar_active_{label}_mismatch")


@dataclass(frozen=True, slots=True)
class SectionPayload:
    section_code: int
    data: bytes

    def __post_init__(self) -> None:
        _u32("payload_section_code", self.section_code, nonzero=True)
        if type(self.data) is not bytes:
            raise TypeError("proof_body_section_payload_must_be_exact_bytes")


@dataclass(frozen=True, slots=True)
class SectionDescriptor:
    section_code: int
    ordinal: int
    offset: int
    length: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class ParsedSection:
    rule: SectionRule
    descriptor: SectionDescriptor
    data: bytes


@dataclass(frozen=True, slots=True)
class ParsedProofBody:
    grammar_digest: bytes
    sections: tuple[ParsedSection, ...]
    encoded_length: int
    reference_status: str = NONACTIVATING_REFERENCE_STATUS


@dataclass(frozen=True, slots=True)
class ProofBodyPreflight:
    """Authenticated fixed-header result used to bound transport allocation."""

    declared_total_length: int
    remainder_length: int
    grammar_digest: bytes
    reference_status: str = NONACTIVATING_REFERENCE_STATUS


def _require_grammar(
    grammar: object,
    active_identity: object,
) -> ProofGrammar:
    if grammar is None:
        raise ValueError("proof_grammar_required")
    if type(grammar) is not ProofGrammar:
        raise TypeError("proof_grammar_exact_type_required")
    if not grammar.selected_for_reference_parsing:
        raise ValueError("proof_grammar_unselected")
    grammar.require_identity(active_identity)
    return grammar


def preflight_proof_body_header(
    header: bytes,
    *,
    grammar: ProofGrammar | None,
    active_identity: ProofIdentity,
) -> ProofBodyPreflight:
    """Authenticate exactly 88 header bytes before any body-size allocation."""

    checked_grammar = _require_grammar(grammar, active_identity)
    if type(header) is not bytes:
        raise TypeError("proof_body_header_must_be_exact_bytes")
    if len(header) != PROOF_BODY_HEADER_LENGTH:
        raise ValueError("proof_body_header_length_invalid")
    view = memoryview(header)
    if view[0:8] != PROOF_BODY_MAGIC:
        raise ValueError("proof_body_magic_mismatch")
    if int.from_bytes(view[8:10], "big") != PROOF_BODY_VERSION:
        raise ValueError("proof_body_version_mismatch")
    if int.from_bytes(view[10:12], "big") != PROOF_BODY_FLAGS:
        raise ValueError("proof_body_flags_mismatch")
    if int.from_bytes(view[12:16], "big") != PROOF_BODY_HEADER_LENGTH:
        raise ValueError("proof_body_header_length_mismatch")
    declared_total = int.from_bytes(view[16:24], "big")
    assert checked_grammar.max_total_length is not None
    if declared_total > checked_grammar.max_total_length:
        raise ValueError("proof_body_declared_total_cap_exceeded")
    expected_total = checked_grammar.expected_total_length
    if declared_total != expected_total:
        raise ValueError("proof_body_total_length_mismatch")
    encoded_grammar_digest = bytes(view[24:88])
    if not hmac.compare_digest(encoded_grammar_digest, checked_grammar.digest):
        raise ValueError("proof_body_grammar_digest_mismatch")
    remainder_length = declared_total - PROOF_BODY_HEADER_LENGTH
    return ProofBodyPreflight(
        declared_total_length=declared_total,
        remainder_length=remainder_length,
        grammar_digest=encoded_grammar_digest,
    )


def _read_exact_bounded(stream: BinaryIO, length: int, label: str) -> bytes:
    """Read an already validated bounded length without an unbounded read."""

    _u64(f"stream_{label}_length", length)
    buffer = bytearray(length)
    write_offset = 0
    while write_offset < length:
        remaining = length - write_offset
        chunk = stream.read(remaining)
        if type(chunk) is not bytes:
            raise TypeError(f"proof_body_stream_{label}_read_must_return_exact_bytes")
        if not chunk:
            raise ValueError(f"proof_body_stream_{label}_truncated")
        if len(chunk) > remaining:
            raise ValueError(f"proof_body_stream_{label}_read_exceeded_bound")
        chunk_end = write_offset + len(chunk)
        buffer[write_offset:chunk_end] = chunk
        write_offset = chunk_end
    return bytes(buffer)


def read_proof_body_stream(
    stream: BinaryIO,
    *,
    grammar: ProofGrammar | None,
    active_identity: ProofIdentity,
) -> ParsedProofBody:
    """Read a body from transport with strict header-first allocation bounds."""

    checked_grammar = _require_grammar(grammar, active_identity)
    if not hasattr(stream, "read") or not callable(stream.read):
        raise TypeError("proof_body_stream_readable_required")
    header = _read_exact_bounded(stream, PROOF_BODY_HEADER_LENGTH, "header")
    preflight = preflight_proof_body_header(
        header,
        grammar=checked_grammar,
        active_identity=active_identity,
    )
    remainder = _read_exact_bounded(stream, preflight.remainder_length, "remainder")
    trailing = stream.read(1)
    if type(trailing) is not bytes:
        raise TypeError("proof_body_stream_trailing_read_must_return_exact_bytes")
    if trailing:
        raise ValueError("proof_body_trailing_bytes")
    return parse_proof_body(
        header + remainder,
        grammar=checked_grammar,
        active_identity=active_identity,
    )


def encode_reference_proof_body(
    payloads: Sequence[SectionPayload],
    *,
    grammar: ProofGrammar,
    active_identity: ProofIdentity,
) -> bytes:
    """Encode a structurally valid synthetic body for reference tests only."""

    checked_grammar = _require_grammar(grammar, active_identity)
    if isinstance(payloads, (str, bytes, bytearray, memoryview)):
        raise TypeError("proof_body_payloads_must_be_sequence")
    materialized = tuple(payloads)
    if len(materialized) != len(checked_grammar.sections):
        raise ValueError("proof_body_section_count_mismatch")
    if any(type(payload) is not SectionPayload for payload in materialized):
        raise TypeError("proof_body_section_payload_required")

    total_length = checked_grammar.expected_total_length
    assert checked_grammar.max_total_length is not None
    if total_length > checked_grammar.max_total_length:
        raise ValueError("proof_body_total_cap_exceeded")
    descriptor_table_length = _checked_mul_u64(
        len(materialized), SECTION_DESCRIPTOR_LENGTH, "descriptor_table_length"
    )
    next_offset = _checked_add_u64(
        PROOF_BODY_HEADER_LENGTH, descriptor_table_length, "payload_offset"
    )
    descriptors: list[bytes] = []
    data_parts: list[bytes] = []
    for ordinal, (rule, payload) in enumerate(zip(checked_grammar.sections, materialized)):
        if payload.section_code != rule.section_code:
            raise ValueError("proof_body_section_order_mismatch")
        length = len(payload.data)
        if length == 0:
            raise ValueError("proof_body_section_zero_length")
        if length > rule.max_length:
            raise ValueError("proof_body_section_cap_exceeded")
        if length != rule.encoded_length:
            raise ValueError("proof_body_section_length_mismatch")
        section_end = _checked_add_u64(next_offset, length, "section_end")
        descriptors.append(
            b"".join(
                (
                    rule.section_code.to_bytes(4, "big"),
                    ordinal.to_bytes(4, "big"),
                    next_offset.to_bytes(8, "big"),
                    length.to_bytes(8, "big"),
                    sha3_512(payload.data).digest(),
                )
            )
        )
        data_parts.append(payload.data)
        next_offset = section_end
    if next_offset != total_length:
        raise AssertionError("proof_body_internal_total_length_mismatch")

    header = b"".join(
        (
            PROOF_BODY_MAGIC,
            PROOF_BODY_VERSION.to_bytes(2, "big"),
            PROOF_BODY_FLAGS.to_bytes(2, "big"),
            PROOF_BODY_HEADER_LENGTH.to_bytes(4, "big"),
            total_length.to_bytes(8, "big"),
            checked_grammar.digest,
        )
    )
    if len(header) != PROOF_BODY_HEADER_LENGTH:
        raise AssertionError("proof_body_internal_header_length_mismatch")
    encoded = b"".join((header, *descriptors, *data_parts))
    if len(encoded) != total_length:
        raise AssertionError("proof_body_internal_encoding_length_mismatch")
    return encoded


def parse_proof_body(
    encoded: bytes,
    *,
    grammar: ProofGrammar | None,
    active_identity: ProofIdentity,
) -> ParsedProofBody:
    """Parse one body strictly, validating all metadata before payload copies.

    Descriptor metadata is bounded by the out-of-band grammar.  Section bytes
    are not copied into return objects until the complete header and descriptor
    table have passed count, order, uniqueness, offset, length, cap, and
    checked-arithmetic validation, and every section digest has verified.
    """

    checked_grammar = _require_grammar(grammar, active_identity)
    if type(encoded) is not bytes:
        raise TypeError("proof_body_must_be_exact_bytes")
    assert checked_grammar.max_total_length is not None
    if len(encoded) > checked_grammar.max_total_length:
        raise ValueError("proof_body_total_cap_exceeded")
    if len(encoded) < PROOF_BODY_HEADER_LENGTH:
        raise ValueError("proof_body_header_truncated")

    view = memoryview(encoded)
    if view[0:8] != PROOF_BODY_MAGIC:
        raise ValueError("proof_body_magic_mismatch")
    if int.from_bytes(view[8:10], "big") != PROOF_BODY_VERSION:
        raise ValueError("proof_body_version_mismatch")
    if int.from_bytes(view[10:12], "big") != PROOF_BODY_FLAGS:
        raise ValueError("proof_body_flags_mismatch")
    if int.from_bytes(view[12:16], "big") != PROOF_BODY_HEADER_LENGTH:
        raise ValueError("proof_body_header_length_mismatch")
    declared_total = int.from_bytes(view[16:24], "big")
    if declared_total > checked_grammar.max_total_length:
        raise ValueError("proof_body_declared_total_cap_exceeded")
    if declared_total < len(encoded):
        raise ValueError("proof_body_trailing_bytes")
    if declared_total > len(encoded):
        raise ValueError("proof_body_truncated")
    expected_total = checked_grammar.expected_total_length
    if declared_total != expected_total:
        raise ValueError("proof_body_total_length_mismatch")
    encoded_grammar_digest = bytes(view[24:88])
    if not hmac.compare_digest(encoded_grammar_digest, checked_grammar.digest):
        raise ValueError("proof_body_grammar_digest_mismatch")

    descriptor_table_length = _checked_mul_u64(
        len(checked_grammar.sections),
        SECTION_DESCRIPTOR_LENGTH,
        "descriptor_table_length",
    )
    payload_offset = _checked_add_u64(
        PROOF_BODY_HEADER_LENGTH,
        descriptor_table_length,
        "payload_offset",
    )
    if payload_offset > declared_total:
        raise ValueError("proof_body_descriptor_table_truncated")

    descriptors: list[SectionDescriptor] = []
    known_codes = frozenset(rule.section_code for rule in checked_grammar.sections)
    seen_codes: set[int] = set()
    next_offset = payload_offset
    total_payload = 0
    for ordinal, rule in enumerate(checked_grammar.sections):
        descriptor_offset = _checked_add_u64(
            PROOF_BODY_HEADER_LENGTH,
            _checked_mul_u64(ordinal, SECTION_DESCRIPTOR_LENGTH, "descriptor_offset"),
            "descriptor_offset",
        )
        descriptor_end = _checked_add_u64(
            descriptor_offset, SECTION_DESCRIPTOR_LENGTH, "descriptor_end"
        )
        if descriptor_end > payload_offset:
            raise ValueError("proof_body_descriptor_table_truncated")
        section_code = int.from_bytes(view[descriptor_offset : descriptor_offset + 4], "big")
        observed_ordinal = int.from_bytes(
            view[descriptor_offset + 4 : descriptor_offset + 8], "big"
        )
        section_offset = int.from_bytes(
            view[descriptor_offset + 8 : descriptor_offset + 16], "big"
        )
        section_length = int.from_bytes(
            view[descriptor_offset + 16 : descriptor_offset + 24], "big"
        )
        section_digest = bytes(view[descriptor_offset + 24 : descriptor_end])

        if section_code in seen_codes:
            raise ValueError("proof_body_section_duplicate")
        if section_code not in known_codes:
            raise ValueError("proof_body_section_unknown")
        if section_code != rule.section_code:
            raise ValueError("proof_body_section_reordered")
        seen_codes.add(section_code)
        if observed_ordinal != ordinal:
            raise ValueError("proof_body_section_ordinal_mismatch")
        if section_offset < next_offset:
            raise ValueError("proof_body_section_overlap")
        if section_offset > next_offset:
            raise ValueError("proof_body_section_gap")
        if section_length == 0:
            raise ValueError("proof_body_section_zero_length")
        if section_length > rule.max_length:
            raise ValueError("proof_body_section_cap_exceeded")
        if section_length != rule.encoded_length:
            raise ValueError("proof_body_section_length_mismatch")
        section_end = _checked_add_u64(section_offset, section_length, "section_end")
        if section_end > declared_total:
            raise ValueError("proof_body_section_out_of_bounds")
        total_payload = _checked_add_u64(
            total_payload, section_length, "total_payload_length"
        )
        if _checked_add_u64(payload_offset, total_payload, "total_payload_end") > declared_total:
            raise ValueError("proof_body_total_cap_exceeded")
        descriptors.append(
            SectionDescriptor(
                section_code=section_code,
                ordinal=observed_ordinal,
                offset=section_offset,
                length=section_length,
                digest=section_digest,
            )
        )
        next_offset = section_end

    if next_offset < declared_total:
        raise ValueError("proof_body_trailing_bytes")
    if next_offset > declared_total:
        raise ValueError("proof_body_section_out_of_bounds")

    # Hash from bounded views first.  No payload bytes are copied until every
    # section has authenticated successfully.
    for descriptor in descriptors:
        section_end = _checked_add_u64(
            descriptor.offset, descriptor.length, "section_end"
        )
        observed_digest = sha3_512(view[descriptor.offset:section_end]).digest()
        if not hmac.compare_digest(observed_digest, descriptor.digest):
            raise ValueError("proof_body_section_digest_mismatch")

    parsed = tuple(
        ParsedSection(
            rule=rule,
            descriptor=descriptor,
            data=bytes(
                view[
                    descriptor.offset : _checked_add_u64(
                        descriptor.offset, descriptor.length, "section_end"
                    )
                ]
            ),
        )
        for rule, descriptor in zip(checked_grammar.sections, descriptors)
    )
    return ParsedProofBody(
        grammar_digest=encoded_grammar_digest,
        sections=parsed,
        encoded_length=declared_total,
    )
