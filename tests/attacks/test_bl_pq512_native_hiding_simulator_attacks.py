from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.native_hiding_simulator import (
    MaskSession,
    NativeHidingError,
    PROFILE_SHAPES,
    build_hiding_transcript,
    verify_hiding_transcript,
)


def _columns(profile: int) -> tuple[tuple[int, ...], ...]:
    rows, columns = PROFILE_SHAPES[profile]
    return tuple(
        tuple((column + row + 1) % ((1 << 31) - 1) for row in range(rows))
        for column in range(columns)
    )


def _proof():
    session_id = b"s" * 64
    columns = _columns(128)
    return build_hiding_transcript(
        128,
        columns,
        public_statement=b"t" * 64,
        session_id=session_id,
        mask_session=MaskSession(session_id),
    ), columns


def test_masked_trace_mutation_cannot_pass_private_replay() -> None:
    proof, columns = _proof()
    mutated = replace(
        proof,
        columns=(
            replace(
                proof.columns[0],
                masked_values=(
                    (proof.columns[0].masked_values[0] + 1) % ((1 << 31) - 1),
                    *proof.columns[0].masked_values[1:],
                ),
            ),
            *proof.columns[1:],
        ),
    )
    with pytest.raises(NativeHidingError, match="masked_trace_commitment|masked_trace_mismatch"):
        verify_hiding_transcript(mutated, columns)


def test_private_trace_mutation_cannot_pass_commitment_replay() -> None:
    proof, columns = _proof()
    mutated = list(columns)
    mutated[0] = (mutated[0][0] + 1, *mutated[0][1:])
    with pytest.raises(NativeHidingError, match="private_trace"):
        verify_hiding_transcript(proof, tuple(mutated))


def test_mask_seed_reuse_is_rejected_within_one_session() -> None:
    session = MaskSession(b"s" * 64)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("BL_ENV", "test")
        patch.setenv("BL_DETERMINISTIC_TEST_ONLY", "1")
        session.issue("K128_NATIVE_HIDING_FIXTURE", 0, deterministic_seed=b"m" * 64)
        with pytest.raises(NativeHidingError, match="seed_reuse"):
            session.issue("K128_NATIVE_HIDING_FIXTURE", 0, deterministic_seed=b"m" * 64)


def test_wrong_column_order_cannot_construct_a_public_transcript() -> None:
    proof, _ = _proof()
    with pytest.raises(NativeHidingError, match="column_order"):
        replace(proof, columns=tuple(reversed(proof.columns)))
