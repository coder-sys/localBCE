from __future__ import annotations

import json

import pytest

from experiments.bl_pq512_crypto_foundation.native_hiding_simulator import (
    M31_MODULUS,
    PROFILE_SHAPES,
    MaskSession,
    NativeHidingError,
    build_hiding_transcript,
    run_native_hiding_simulator_suite,
    simulate_hiding_transcript,
    verify_hiding_transcript,
    zeroize,
)


def _columns(profile: int, offset: int = 0) -> tuple[tuple[int, ...], ...]:
    rows, columns = PROFILE_SHAPES[profile]
    return tuple(
        tuple((offset + column + row + 1) % M31_MODULUS for row in range(rows))
        for column in range(columns)
    )


def test_reference_hiding_suite_masks_private_columns_and_keeps_fixed_shapes() -> None:
    result = run_native_hiding_simulator_suite()
    assert result["status"].endswith("NONACTIVATING")
    assert result["profile_count"] == 2
    assert result["record_count"] == 4
    assert result["fixed_shape_verified"] is True
    assert result["private_opening_verified"] is True
    assert result["simulator_shape_verified"] is True
    assert result["error_shape_verified"] is True
    assert result["proofSuiteId"] is None
    assert result["activationAllowed"] is False


def test_private_opening_is_replayable_under_an_explicit_test_only_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BL_ENV", "test")
    monkeypatch.setenv("BL_DETERMINISTIC_TEST_ONLY", "1")
    session_id = b"s" * 64
    statement = b"t" * 64
    first = build_hiding_transcript(
        128,
        _columns(128),
        public_statement=statement,
        session_id=session_id,
        mask_session=MaskSession(session_id),
        deterministic_seed=b"m" * 64,
    )
    second = build_hiding_transcript(
        128,
        _columns(128),
        public_statement=statement,
        session_id=session_id,
        mask_session=MaskSession(session_id),
        deterministic_seed=b"m" * 64,
    )
    verify_hiding_transcript(first, _columns(128))
    assert first.transcript_digest == second.transcript_digest
    assert json.dumps(first.as_public_dict(), sort_keys=True)


def test_non_test_deterministic_seed_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BL_ENV", raising=False)
    monkeypatch.delenv("BL_DETERMINISTIC_TEST_ONLY", raising=False)
    with pytest.raises(NativeHidingError, match="test_guard"):
        build_hiding_transcript(
            128,
            _columns(128),
            public_statement=b"t" * 64,
            session_id=b"s" * 64,
            mask_session=MaskSession(b"s" * 64),
            deterministic_seed=b"m" * 64,
        )


def test_simulator_has_the_same_observable_shape_without_private_columns() -> None:
    actual = run_native_hiding_simulator_suite()
    simulated = simulate_hiding_transcript(
        512,
        public_statement=b"t" * 64,
        session_id=b"s" * 64,
    )
    assert simulated.simulated is True
    assert simulated.observable_shape == (8, 128, 4, 128)
    assert actual["records"]


def test_zeroization_is_explicit_and_bounded() -> None:
    value = bytearray(b"synthetic-private-mask")
    zeroize(value)
    assert value == bytearray(len(value))
