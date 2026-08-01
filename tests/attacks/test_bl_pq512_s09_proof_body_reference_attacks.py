from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.proof_body_reference import (
    PROOF_BODY_HEADER_LENGTH,
    SECTION_DESCRIPTOR_LENGTH,
    ProofGrammar,
    ProofIdentity,
    SectionPayload,
    SectionRule,
    encode_reference_proof_body,
    parse_proof_body,
    read_proof_body_stream,
)


def _wide(label: bytes) -> bytes:
    return sha3_512(label).digest()


def _identity(prefix: bytes = b"ACTIVE") -> ProofIdentity:
    return ProofIdentity(
        profile_id=_wide(prefix + b"/PROFILE"),
        proof_suite_id=_wide(prefix + b"/SUITE"),
        schema_id=_wide(prefix + b"/SCHEMA"),
        verifier_artifact_identity=_wide(prefix + b"/VERIFIER"),
    )


def _fixture() -> tuple[bytes, ProofGrammar, ProofIdentity]:
    identity = _identity()
    grammar = ProofGrammar(
        identity=identity,
        sections=(
            SectionRule(0x101, "SYNTHETIC_TRACE_COMMITMENTS", 17, 32),
            SectionRule(0x207, "SYNTHETIC_FRI_OPENINGS", 23, 48),
        ),
        max_total_length=4096,
    )
    encoded = encode_reference_proof_body(
        (
            SectionPayload(0x101, b"trace-commitments"),
            SectionPayload(0x207, b"synthetic-fri-openings!"),
        ),
        grammar=grammar,
        active_identity=identity,
    )
    return encoded, grammar, identity


def _replace_uint(encoded: bytes, offset: int, length: int, value: int) -> bytes:
    mutated = bytearray(encoded)
    mutated[offset : offset + length] = value.to_bytes(length, "big")
    return bytes(mutated)


class _RecordingStream:
    def __init__(self, encoded: bytes) -> None:
        self._encoded = encoded
        self._offset = 0
        self.requested: list[int] = []

    def read(self, size: int) -> bytes:
        self.requested.append(size)
        result = self._encoded[self._offset : self._offset + size]
        self._offset += len(result)
        return result


class _OneByteAtATimeStream(_RecordingStream):
    def read(self, size: int) -> bytes:
        self.requested.append(size)
        if self._offset >= len(self._encoded):
            return b""
        result = self._encoded[self._offset : self._offset + 1]
        self._offset += 1
        return result


@pytest.mark.parametrize(
    ("offset", "length", "value", "error"),
    (
        (0, 8, int.from_bytes(b"BADMAGIC", "big"), "magic_mismatch"),
        (8, 2, 2, "version_mismatch"),
        (10, 2, 1, "flags_mismatch"),
        (12, 4, 87, "header_length_mismatch"),
    ),
)
def test_header_mutations_fail_closed(offset: int, length: int, value: int, error: str) -> None:
    encoded, grammar, identity = _fixture()
    with pytest.raises(ValueError, match=error):
        parse_proof_body(
            _replace_uint(encoded, offset, length, value),
            grammar=grammar,
            active_identity=identity,
        )


def test_truncation_trailing_separate_objects_and_total_caps_reject() -> None:
    encoded, grammar, identity = _fixture()
    with pytest.raises(ValueError, match="proof_body_truncated"):
        parse_proof_body(encoded[:-1], grammar=grammar, active_identity=identity)
    with pytest.raises(ValueError, match="proof_body_trailing_bytes"):
        parse_proof_body(encoded + b"x", grammar=grammar, active_identity=identity)
    with pytest.raises(ValueError, match="proof_body_trailing_bytes"):
        parse_proof_body(
            encoded + bytes(384), grammar=grammar, active_identity=identity
        )


def test_stream_rejects_oversized_declaration_after_only_88_byte_preflight() -> None:
    encoded, grammar, identity = _fixture()
    oversized_header = _replace_uint(
        encoded[:PROOF_BODY_HEADER_LENGTH],
        16,
        8,
        grammar.max_total_length + 1,
    )
    stream = _RecordingStream(oversized_header)
    with pytest.raises(ValueError, match="declared_total_cap_exceeded"):
        read_proof_body_stream(
            stream, grammar=grammar, active_identity=identity
        )
    assert stream.requested == [PROOF_BODY_HEADER_LENGTH]
    assert max(stream.requested) == 88


def test_stream_reads_only_bounded_remainder_and_rejects_truncation_or_trailing() -> None:
    encoded, grammar, identity = _fixture()
    valid_stream = _RecordingStream(encoded)
    parsed = read_proof_body_stream(
        valid_stream, grammar=grammar, active_identity=identity
    )
    assert parsed.encoded_length == len(encoded)
    assert valid_stream.requested == [88, len(encoded) - 88, 1]

    truncated = _RecordingStream(encoded[:-1])
    with pytest.raises(ValueError, match="stream_remainder_truncated"):
        read_proof_body_stream(
            truncated, grammar=grammar, active_identity=identity
        )
    assert truncated.requested[0] == 88
    assert truncated.requested[1] == len(encoded) - 88

    trailing = _RecordingStream(encoded + b"x")
    with pytest.raises(ValueError, match="proof_body_trailing_bytes"):
        read_proof_body_stream(
            trailing, grammar=grammar, active_identity=identity
        )
    assert trailing.requested == [88, len(encoded) - 88, 1]
    with pytest.raises(ValueError, match="proof_body_trailing_bytes"):
        parse_proof_body(
            encoded + bytes(744), grammar=grammar, active_identity=identity
        )
    with pytest.raises(ValueError, match="declared_total_cap_exceeded"):
        parse_proof_body(
            _replace_uint(encoded, 16, 8, grammar.max_total_length + 1),
            grammar=grammar,
            active_identity=identity,
        )


def test_one_byte_drip_feed_uses_bounded_reader_without_chunk_accumulation() -> None:
    encoded, grammar, identity = _fixture()
    stream = _OneByteAtATimeStream(encoded)
    parsed = read_proof_body_stream(
        stream, grammar=grammar, active_identity=identity
    )
    assert parsed.encoded_length == len(encoded)
    assert len(stream.requested) == len(encoded) + 1
    assert stream.requested[:88] == list(range(88, 0, -1))
    assert stream.requested[88] == len(encoded) - 88
    assert stream.requested[-1] == 1


def test_grammar_digest_and_payload_digest_tampering_reject() -> None:
    encoded, grammar, identity = _fixture()
    grammar_digest_mutation = bytearray(encoded)
    grammar_digest_mutation[24] ^= 1
    with pytest.raises(ValueError, match="grammar_digest_mismatch"):
        parse_proof_body(
            bytes(grammar_digest_mutation), grammar=grammar, active_identity=identity
        )

    descriptor_digest_mutation = bytearray(encoded)
    descriptor_digest_mutation[PROOF_BODY_HEADER_LENGTH + 24] ^= 1
    with pytest.raises(ValueError, match="section_digest_mismatch"):
        parse_proof_body(
            bytes(descriptor_digest_mutation), grammar=grammar, active_identity=identity
        )

    payload_mutation = bytearray(encoded)
    payload_mutation[-1] ^= 1
    with pytest.raises(ValueError, match="section_digest_mismatch"):
        parse_proof_body(
            bytes(payload_mutation), grammar=grammar, active_identity=identity
        )


def test_unknown_duplicate_reordered_and_bad_ordinal_sections_reject() -> None:
    encoded, grammar, identity = _fixture()
    first = PROOF_BODY_HEADER_LENGTH
    second = first + SECTION_DESCRIPTOR_LENGTH

    with pytest.raises(ValueError, match="section_unknown"):
        parse_proof_body(
            _replace_uint(encoded, first, 4, 0x999),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_duplicate"):
        parse_proof_body(
            _replace_uint(encoded, second, 4, 0x101),
            grammar=grammar,
            active_identity=identity,
        )

    reordered = bytearray(encoded)
    first_descriptor = bytes(reordered[first:second])
    second_descriptor = bytes(reordered[second : second + SECTION_DESCRIPTOR_LENGTH])
    reordered[first:second] = second_descriptor
    reordered[second : second + SECTION_DESCRIPTOR_LENGTH] = first_descriptor
    with pytest.raises(ValueError, match="section_reordered"):
        parse_proof_body(bytes(reordered), grammar=grammar, active_identity=identity)

    with pytest.raises(ValueError, match="section_ordinal_mismatch"):
        parse_proof_body(
            _replace_uint(encoded, first + 4, 4, 1),
            grammar=grammar,
            active_identity=identity,
        )


def test_overlap_gap_zero_length_cap_and_exact_length_reject() -> None:
    encoded, grammar, identity = _fixture()
    first = PROOF_BODY_HEADER_LENGTH
    second = first + SECTION_DESCRIPTOR_LENGTH
    payload_offset = PROOF_BODY_HEADER_LENGTH + 2 * SECTION_DESCRIPTOR_LENGTH
    first_end = payload_offset + grammar.sections[0].encoded_length

    with pytest.raises(ValueError, match="section_overlap"):
        parse_proof_body(
            _replace_uint(encoded, second + 8, 8, payload_offset),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_gap"):
        parse_proof_body(
            _replace_uint(encoded, second + 8, 8, first_end + 1),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_zero_length"):
        parse_proof_body(
            _replace_uint(encoded, first + 16, 8, 0),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_cap_exceeded"):
        parse_proof_body(
            _replace_uint(encoded, first + 16, 8, grammar.sections[0].max_length + 1),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_length_mismatch"):
        parse_proof_body(
            _replace_uint(encoded, first + 16, 8, 18),
            grammar=grammar,
            active_identity=identity,
        )


def test_proof_cannot_switch_suite_or_other_bound_identity() -> None:
    encoded, grammar, identity = _fixture()
    attacker = _identity(b"ATTACKER")
    with pytest.raises(ValueError, match="active_profile_id_mismatch"):
        parse_proof_body(encoded, grammar=grammar, active_identity=attacker)

    attacker_grammar = replace(grammar, identity=attacker)
    with pytest.raises(ValueError, match="grammar_digest_mismatch"):
        parse_proof_body(
            encoded, grammar=attacker_grammar, active_identity=attacker
        )
    assert identity.proof_suite_id not in encoded
    assert attacker.proof_suite_id not in encoded


def test_invalid_grammar_uniqueness_caps_and_checked_arithmetic_reject() -> None:
    identity = _identity()
    first = SectionRule(1, "FIRST", 1, 1)
    with pytest.raises(ValueError, match="section_code_duplicate"):
        ProofGrammar(
            identity=identity,
            sections=(first, SectionRule(1, "SECOND", 1, 1)),
            max_total_length=4096,
        )
    with pytest.raises(ValueError, match="section_name_duplicate"):
        ProofGrammar(
            identity=identity,
            sections=(first, SectionRule(2, "FIRST", 1, 1)),
            max_total_length=4096,
        )
    with pytest.raises(ValueError, match="section_length_exceeds_cap"):
        SectionRule(1, "FIRST", 2, 1)
    with pytest.raises(ValueError, match="expected_total_exceeds_cap"):
        ProofGrammar(identity=identity, sections=(first,), max_total_length=1)
    with pytest.raises(ValueError, match="expected_total_length_overflow"):
        ProofGrammar(
            identity=identity,
            sections=(SectionRule(1, "FIRST", (1 << 64) - 1, (1 << 64) - 1),),
            max_total_length=(1 << 64) - 1,
        )
