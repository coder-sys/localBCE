from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    Sha3ByteAirShape,
    block_absorb_lookup_rows,
    build_sha3_512_air_trace,
    padded_block_count,
    verify_round_witness,
    verify_sha3_512_air_trace,
)


def test_round_and_chain_mutations_fail_closed() -> None:
    trace = build_sha3_512_air_trace(b"attack mutation corpus")
    first = trace.rounds[0][0]
    corrupted_output = list(first.output_bytes)
    corrupted_output[73] ^= 1
    bad_round = replace(first, output_bytes=tuple(corrupted_output))
    with pytest.raises(ValueError, match="round_witness_constraint_mismatch"):
        verify_round_witness(bad_round)

    block_rounds = list(trace.rounds[0])
    block_rounds[0] = bad_round
    bad_trace = replace(trace, rounds=(tuple(block_rounds),))
    with pytest.raises(ValueError, match="constraint_mismatch"):
        verify_sha3_512_air_trace(b"attack mutation corpus", bad_trace)


def test_padding_digest_and_message_substitution_fail_closed() -> None:
    trace = build_sha3_512_air_trace(b"abc")
    with pytest.raises(ValueError, match="message_or_padding_mismatch"):
        verify_sha3_512_air_trace(b"abd", trace)
    with pytest.raises(ValueError, match="digest_trace_mismatch"):
        verify_sha3_512_air_trace(b"abc", replace(trace, digest=bytes(64)))
    with pytest.raises(ValueError, match="message_length_invalid"):
        padded_block_count(-1)
    with pytest.raises(TypeError, match="message_must_be_exact_bytes"):
        build_sha3_512_air_trace(bytearray(b"abc"))  # type: ignore[arg-type]


def test_shape_cannot_claim_activation_or_selected_interaction_packing() -> None:
    with pytest.raises(ValueError, match="exact_shape_mismatch"):
        replace(
            Sha3ByteAirShape(),
            round_xor_lookups=607,
            round_and_not_lookups=201,
        )
    with pytest.raises(ValueError, match="absorb_block_length_invalid"):
        block_absorb_lookup_rows(bytes(200), bytes(71))
    with pytest.raises(ValueError, match="nonactivating_boundary_violated"):
        replace(Sha3ByteAirShape(), activation_allowed=True)
    with pytest.raises(ValueError, match="nonactivating_boundary_violated"):
        replace(Sha3ByteAirShape(), interaction_packing_selected=True)
