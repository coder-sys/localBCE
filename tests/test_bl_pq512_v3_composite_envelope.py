from __future__ import annotations

from hashlib import sha3_512
from io import BytesIO
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.v3_composite_envelope import (
    COMPOSITE_TRANSCRIPT_KIND,
    H4_KIND,
    K128_PROFILE_CODE,
    K512_PROFILE_CODE,
    SEMANTIC_KIND,
    TYPED_STATE_KIND,
    V3ComponentLayout,
    V3EnvelopeError,
    V3ProfileLayout,
    V3VerificationUnavailable,
    V3_ENVELOPE_COMMITMENT_DOMAIN,
    V3_HEADER_BYTES,
    V3_LAYOUT_BYTES,
    V3_STATUS,
    build_composite_transcript_slot,
    encode_v3_envelope,
    parse_v3_envelope,
    verify_v3_composite_file,
)


DESCRIPTOR_START = 1_348
DESCRIPTOR_BYTES = 76
SIDECAR_START = 600


def _wide(value: int) -> bytes:
    return bytes([value]) * 64


def _layout(
    *,
    profile: bytes | None = None,
    profile_code: int = K128_PROFILE_CODE,
    candidate: bytes | None = None,
) -> V3ProfileLayout:
    lengths = (31, 37, 41, 64)
    components = tuple(
        V3ComponentLayout(
            kind=kind,
            grammar=1,
            exact_length=length,
            maximum_length=length,
            expected_program_commitment=_wide(20 + kind),
            expected_schedule_commitment=_wide(30 + kind),
        )
        for kind, length in zip(
            (SEMANTIC_KIND, H4_KIND, TYPED_STATE_KIND, COMPOSITE_TRANSCRIPT_KIND),
            lengths,
            strict=True,
        )
    )
    return V3ProfileLayout.build(
        profile_id=profile or _wide(1),
        profile_code=profile_code,
        candidate_descriptor_identity=candidate or _wide(2),
        maximum_total_length=V3_HEADER_BYTES + sum(lengths),
        components=components,
    )


def _sidecar(profile: bytes) -> bytes:
    encoded = bytearray(744)
    encoded[:8] = b"BLPQSC01"
    encoded[8:10] = (1).to_bytes(2, "big")
    encoded[10:12] = (0).to_bytes(2, "big")
    encoded[12:16] = (744).to_bytes(4, "big")
    encoded[16:80] = profile
    # proofSuiteId at 80:144 remains canonical null for the v3 parser phase.
    for ordinal, start in enumerate((144, 208, 272), start=3):
        encoded[start : start + 64] = _wide(ordinal)
    encoded[336:344] = (7).to_bytes(8, "big")
    encoded[344:352] = (11).to_bytes(8, "big")
    encoded[352:360] = (12).to_bytes(8, "big")
    for ordinal, start in enumerate((360, 424, 488, 552, 616, 680), start=6):
        encoded[start : start + 64] = _wide(ordinal)
    return bytes(encoded)


def _fixture() -> tuple[V3ProfileLayout, bytes]:
    layout = _layout()
    components = (
        b"S" * 31,
        b"H" * 37,
        b"T" * 41,
        build_composite_transcript_slot(b"coin", fixed_length=64),
    )
    encoded = encode_v3_envelope(
        layout=layout,
        public_fields=tuple(bytes([index]) * 32 for index in range(12)),
        sidecar=_sidecar(layout.profile_id),
        components=components,
    )
    return layout, encoded


def _mutate(encoded: bytes, offset: int, replacement: bytes) -> bytes:
    changed = bytearray(encoded)
    changed[offset : offset + len(replacement)] = replacement
    return bytes(changed)


def _reject(encoded: bytes, layout: V3ProfileLayout, match: str) -> None:
    with pytest.raises(V3EnvelopeError, match=match):
        parse_v3_envelope(BytesIO(encoded), layout)


def test_v3_layout_and_envelope_roundtrip_is_parse_only() -> None:
    layout, encoded = _fixture()
    assert len(layout.encode()) == V3_LAYOUT_BYTES
    assert V3ProfileLayout.decode_trusted(layout.encode()) == layout
    parsed = parse_v3_envelope(BytesIO(encoded), layout)
    assert parsed.status == V3_STATUS
    assert parsed.production_usable is False
    assert parsed.activation_allowed is False
    assert parsed.profile_code == K128_PROFILE_CODE
    assert tuple(value.kind for value in parsed.descriptors) == (1, 2, 3, 4)
    assert parsed.component_offsets == (
        V3_HEADER_BYTES,
        V3_HEADER_BYTES + 31,
        V3_HEADER_BYTES + 31 + 37,
        V3_HEADER_BYTES + 31 + 37 + 41,
    )
    expected = sha3_512(
        V3_ENVELOPE_COMMITMENT_DOMAIN
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).digest()
    assert parsed.envelope_commitment == expected
    assert layout.layout_commitment.hex() == (
        "2ed0dea51624551e878baf09b72785c20b249d4b52302ab2ad39958f6cbd1239"
        "0cdeeecb2b533bcbaabde79a5c0cc36ba0f0969777c0a9e15c4985114319c3df"
    )
    assert parsed.envelope_commitment.hex() == (
        "099cd6e8489c7dc0274cb121c8f974cad13ceb6d083cac279c606da8f77d61c7"
        "5216531a55aac015eef9058959bf3559d467110806c07ed0943685c86cdcb24c"
    )


def test_v3_standalone_verification_remains_unavailable(
    tmp_path: Path,
) -> None:
    layout, encoded = _fixture()
    path = tmp_path / "v3-envelope.bin"
    path.write_bytes(encoded)
    with pytest.raises(
        V3VerificationUnavailable,
        match="semantic_h4_composite_transcript_verifiers_unavailable",
    ):
        verify_v3_composite_file(path.resolve(), layout)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda value: value[:-1], "file_length_mismatch"),
        (lambda value: value + b"\x00", "file_length_mismatch"),
        (lambda value: _mutate(value, 8, (2).to_bytes(2, "big")), "version_invalid"),
        (lambda value: _mutate(value, 10, (1).to_bytes(2, "big")), "flags_invalid"),
        (lambda value: _mutate(value, 12, (1_651).to_bytes(4, "big")), "header_length_invalid"),
        (lambda value: _mutate(value, 16, (2**64 - 1).to_bytes(8, "big")), "total_length_mismatch"),
        (lambda value: _mutate(value, 24, _wide(90)), "profile_mismatch"),
        (lambda value: _mutate(value, 88, _wide(91)), "candidate_descriptor_mismatch"),
        (lambda value: _mutate(value, 152, _wide(92)), "layout_commitment_mismatch"),
        (lambda value: _mutate(value, DESCRIPTOR_START, (2).to_bytes(2, "big")), "component_order_invalid"),
        (lambda value: _mutate(value, DESCRIPTOR_START, (9).to_bytes(2, "big")), "component_order_invalid"),
        (lambda value: _mutate(value, DESCRIPTOR_START + 2, (2).to_bytes(2, "big")), "component_grammar_mismatch"),
        (lambda value: _mutate(value, DESCRIPTOR_START + 4, (32).to_bytes(8, "big")), "component_length_mismatch"),
        (lambda value: _mutate(value, DESCRIPTOR_START + 12, _wide(93)), "component_digest_mismatch"),
    ),
)
def test_v3_header_and_shape_attacks_fail_closed(mutation, message: str) -> None:
    layout, encoded = _fixture()
    _reject(mutation(encoded), layout, message)


def test_v3_duplicate_kind_and_unknown_kind_fail_before_components() -> None:
    layout, encoded = _fixture()
    second_kind = DESCRIPTOR_START + DESCRIPTOR_BYTES
    _reject(_mutate(encoded, second_kind, (1).to_bytes(2, "big")), layout, "component_order_invalid")
    _reject(_mutate(encoded, second_kind, (99).to_bytes(2, "big")), layout, "component_order_invalid")


def test_v3_component_mutation_and_transcript_padding_fail_closed() -> None:
    layout, encoded = _fixture()
    semantic_start = V3_HEADER_BYTES
    _reject(_mutate(encoded, semantic_start + 5, b"X"), layout, "component_digest_mismatch")

    transcript_start = V3_HEADER_BYTES + 31 + 37 + 41
    transcript_padding = transcript_start + 20 + len(b"coin")
    _reject(_mutate(encoded, transcript_padding, b"\x01"), layout, "transcript_padding_nonzero")


def test_v3_profile_layout_and_candidate_swaps_fail_closed() -> None:
    layout, encoded = _fixture()
    swapped_profile = _layout(profile=_wide(70))
    swapped_candidate = _layout(candidate=_wide(71))
    _reject(encoded, swapped_profile, "profile_mismatch")
    _reject(encoded, swapped_candidate, "candidate_descriptor_mismatch")


def test_v3_governed_profile_code_is_trusted_and_not_inferred_from_opaque_id() -> None:
    layout, encoded = _fixture()
    swapped_code = _layout(profile=layout.profile_id, profile_code=K512_PROFILE_CODE)
    _reject(encoded, swapped_code, "layout_commitment_mismatch")
    with pytest.raises(V3EnvelopeError, match="layout_profile_code_invalid"):
        _layout(profile_code=2)


def test_v3_global_suite_is_null_by_schema() -> None:
    layout, encoded = _fixture()
    suite_offset = SIDECAR_START + 80
    _reject(_mutate(encoded, suite_offset, _wide(72)), layout, "sidecar_header_invalid")


def test_v3_header_public_field_change_changes_canonical_commitment() -> None:
    layout, encoded = _fixture()
    original = parse_v3_envelope(BytesIO(encoded), layout)
    changed_bytes = _mutate(encoded, 216, b"\xff")
    changed = parse_v3_envelope(BytesIO(changed_bytes), layout)
    assert changed.envelope_commitment != original.envelope_commitment


def test_v3_layout_encoding_mutation_fails_commitment() -> None:
    layout = _layout()
    changed = bytearray(layout.encode())
    changed[24] ^= 1
    with pytest.raises(V3EnvelopeError):
        V3ProfileLayout.decode_trusted(bytes(changed))


def test_v3_streaming_ceiling_can_hold_four_fixed_h4_shards() -> None:
    lengths = (
        84 * 1024 * 1024,
        4 * (192 * 1024 * 1024) + 16 * 1024 * 1024,
        84 * 1024 * 1024,
        16 * 1024 * 1024,
    )
    components = tuple(
        V3ComponentLayout(
            kind=kind,
            grammar=1,
            exact_length=length,
            maximum_length=length,
            expected_program_commitment=_wide(40 + kind),
            expected_schedule_commitment=_wide(50 + kind),
        )
        for kind, length in zip(
            (SEMANTIC_KIND, H4_KIND, TYPED_STATE_KIND, COMPOSITE_TRANSCRIPT_KIND),
            lengths,
            strict=True,
        )
    )
    layout = V3ProfileLayout.build(
        profile_id=_wide(60),
        profile_code=K512_PROFILE_CODE,
        candidate_descriptor_identity=_wide(61),
        maximum_total_length=V3_HEADER_BYTES + sum(lengths),
        components=components,
    )
    assert layout.total_length > 512 * 1024 * 1024


def test_v3_every_single_byte_mutation_is_rejected_or_changes_outer_commitment() -> None:
    layout, encoded = _fixture()
    original = parse_v3_envelope(BytesIO(encoded), layout)
    accepted = 0
    rejected = 0
    for offset in range(len(encoded)):
        mutated = bytearray(encoded)
        mutated[offset] ^= 1
        try:
            parsed = parse_v3_envelope(BytesIO(mutated), layout)
        except V3EnvelopeError:
            rejected += 1
        else:
            accepted += 1
            assert parsed.envelope_commitment != original.envelope_commitment
    assert accepted > 0
    assert rejected > 0
    assert accepted + rejected == len(encoded)


def test_v3_every_truncation_and_bounded_extension_fails_before_component_use() -> None:
    layout, encoded = _fixture()
    for length in range(len(encoded)):
        with pytest.raises(V3EnvelopeError, match="file_length_mismatch"):
            parse_v3_envelope(BytesIO(encoded[:length]), layout)
    for extension in range(1, 65):
        with pytest.raises(V3EnvelopeError, match="file_length_mismatch"):
            parse_v3_envelope(BytesIO(encoded + bytes(extension)), layout)
