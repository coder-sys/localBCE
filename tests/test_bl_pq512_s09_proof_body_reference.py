from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
from io import BytesIO

import pytest

from experiments.bl_pq512_crypto_foundation.proof_body_reference import (
    NONACTIVATING_REFERENCE_STATUS,
    PROOF_BODY_FLAGS,
    PROOF_BODY_HEADER_LENGTH,
    PROOF_BODY_MAGIC,
    PROOF_BODY_VERSION,
    SECTION_DESCRIPTOR_LENGTH,
    ParsedProofBody,
    ProofGrammar,
    ProofIdentity,
    SectionPayload,
    SectionRule,
    encode_reference_proof_body,
    parse_proof_body,
    preflight_proof_body_header,
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


def _grammar(identity: ProofIdentity | None = None) -> ProofGrammar:
    return ProofGrammar(
        identity=identity or _identity(),
        sections=(
            SectionRule(0x101, "SYNTHETIC_TRACE_COMMITMENTS", 17, 32),
            SectionRule(0x207, "SYNTHETIC_FRI_OPENINGS", 23, 48),
        ),
        max_total_length=4096,
    )


def _payloads() -> tuple[SectionPayload, ...]:
    return (
        SectionPayload(0x101, b"trace-commitments"),
        SectionPayload(0x207, b"synthetic-fri-openings!"),
    )


def _encoded() -> tuple[bytes, ProofGrammar, ProofIdentity]:
    identity = _identity()
    grammar = _grammar(identity)
    return (
        encode_reference_proof_body(
            _payloads(), grammar=grammar, active_identity=identity
        ),
        grammar,
        identity,
    )


def test_fixed_header_big_endian_descriptors_and_round_trip() -> None:
    encoded, grammar, identity = _encoded()
    parsed = parse_proof_body(
        encoded, grammar=grammar, active_identity=identity
    )

    assert type(parsed) is ParsedProofBody
    assert parsed.reference_status == NONACTIVATING_REFERENCE_STATUS
    assert grammar.status == NONACTIVATING_REFERENCE_STATUS
    assert grammar.selected_for_reference_parsing
    assert encoded[:8] == PROOF_BODY_MAGIC == b"BLPQPF01"
    assert int.from_bytes(encoded[8:10], "big") == PROOF_BODY_VERSION == 1
    assert int.from_bytes(encoded[10:12], "big") == PROOF_BODY_FLAGS == 0
    assert int.from_bytes(encoded[12:16], "big") == PROOF_BODY_HEADER_LENGTH == 88
    assert int.from_bytes(encoded[16:24], "big") == len(encoded)
    assert encoded[24:88] == grammar.digest == parsed.grammar_digest
    assert len(encoded) == grammar.expected_total_length

    payload_offset = PROOF_BODY_HEADER_LENGTH + 2 * SECTION_DESCRIPTOR_LENGTH
    first_descriptor = encoded[88:176]
    second_descriptor = encoded[176:264]
    assert int.from_bytes(first_descriptor[0:4], "big") == 0x101
    assert int.from_bytes(first_descriptor[4:8], "big") == 0
    assert int.from_bytes(first_descriptor[8:16], "big") == payload_offset
    assert int.from_bytes(first_descriptor[16:24], "big") == 17
    assert first_descriptor[24:88] == sha3_512(_payloads()[0].data).digest()
    assert int.from_bytes(second_descriptor[0:4], "big") == 0x207
    assert int.from_bytes(second_descriptor[4:8], "big") == 1
    assert int.from_bytes(second_descriptor[8:16], "big") == payload_offset + 17
    assert int.from_bytes(second_descriptor[16:24], "big") == 23
    assert second_descriptor[24:88] == sha3_512(_payloads()[1].data).digest()
    assert tuple(section.data for section in parsed.sections) == tuple(
        payload.data for payload in _payloads()
    )


def test_grammar_is_bound_to_all_four_out_of_band_identities() -> None:
    encoded, grammar, identity = _encoded()
    identity_fields = (
        "profile_id",
        "proof_suite_id",
        "schema_id",
        "verifier_artifact_identity",
    )
    for field_name in identity_fields:
        changed = replace(identity, **{field_name: _wide(b"CHANGED/" + field_name.encode())})
        with pytest.raises(ValueError, match=f"active_{field_name}_mismatch"):
            parse_proof_body(encoded, grammar=grammar, active_identity=changed)
        assert _grammar(changed).digest != grammar.digest

    # The body has only a digest of the externally selected grammar.  None of
    # the raw profile/suite/schema/verifier IDs is an in-band selection field.
    for raw_id in (
        identity.profile_id,
        identity.proof_suite_id,
        identity.schema_id,
        identity.verifier_artifact_identity,
    ):
        assert raw_id not in encoded


def test_null_and_unselected_grammar_reject_before_body_parsing() -> None:
    identity = _identity()
    with pytest.raises(ValueError, match="proof_grammar_required"):
        parse_proof_body(b"not-a-proof", grammar=None, active_identity=identity)
    unselected = ProofGrammar.unselected()
    assert not unselected.selected_for_reference_parsing
    with pytest.raises(ValueError, match="proof_grammar_unselected"):
        parse_proof_body(b"not-a-proof", grammar=unselected, active_identity=identity)
    with pytest.raises(ValueError, match="proof_grammar_unselected"):
        encode_reference_proof_body((), grammar=unselected, active_identity=identity)


def test_encoder_requires_exact_order_count_lengths_and_caps() -> None:
    identity = _identity()
    grammar = _grammar(identity)
    with pytest.raises(ValueError, match="section_count_mismatch"):
        encode_reference_proof_body(
            _payloads()[:1], grammar=grammar, active_identity=identity
        )
    with pytest.raises(ValueError, match="section_order_mismatch"):
        encode_reference_proof_body(
            tuple(reversed(_payloads())), grammar=grammar, active_identity=identity
        )
    with pytest.raises(ValueError, match="section_zero_length"):
        encode_reference_proof_body(
            (SectionPayload(0x101, b""), _payloads()[1]),
            grammar=grammar,
            active_identity=identity,
        )
    with pytest.raises(ValueError, match="section_length_mismatch"):
        encode_reference_proof_body(
            (SectionPayload(0x101, b"x" * 18), _payloads()[1]),
            grammar=grammar,
            active_identity=identity,
        )
    tight = replace(
        grammar,
        sections=(
            SectionRule(0x101, "SYNTHETIC_TRACE_COMMITMENTS", 17, 17),
            grammar.sections[1],
        ),
    )
    with pytest.raises(ValueError, match="section_cap_exceeded"):
        encode_reference_proof_body(
            (SectionPayload(0x101, b"x" * 18), _payloads()[1]),
            grammar=tight,
            active_identity=identity,
        )


def test_public_outputs_and_744_byte_sidecar_are_not_proof_body_arguments() -> None:
    encoded, grammar, identity = _encoded()
    public_outputs = b"P" * 384
    sidecar = b"S" * 744
    assert public_outputs not in encoded
    assert sidecar not in encoded
    parsed = parse_proof_body(encoded, grammar=grammar, active_identity=identity)
    assert parsed.encoded_length == len(encoded)


def test_stream_reader_preflights_exact_header_then_bounded_remainder() -> None:
    encoded, grammar, identity = _encoded()
    preflight = preflight_proof_body_header(
        encoded[:PROOF_BODY_HEADER_LENGTH],
        grammar=grammar,
        active_identity=identity,
    )
    assert preflight.declared_total_length == len(encoded)
    assert preflight.remainder_length == len(encoded) - PROOF_BODY_HEADER_LENGTH
    assert preflight.grammar_digest == grammar.digest
    streamed = read_proof_body_stream(
        BytesIO(encoded), grammar=grammar, active_identity=identity
    )
    assert streamed == parse_proof_body(
        encoded, grammar=grammar, active_identity=identity
    )
