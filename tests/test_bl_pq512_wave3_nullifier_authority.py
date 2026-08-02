from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    CoverReplayContextV1,
    CoverReplayContextV2,
    NullifierDerivationAuthorityV1,
    derive_attempt_nullifiers_v1,
    derive_cover_nullifiers_v1,
    derive_cover_nullifiers_v2,
)
from experiments.bl_pq512_crypto_foundation.wave3_nullifier_authority import (
    ACTIVATION_ALLOWED,
    CANDIDATE_STATUS,
    PROOF_SUITE_ID,
    RECORD_ATTEMPT,
    RECORD_COVER,
    Wave3DualDerivedRecordV1,
    Wave3NullifierAuthorityV1,
    Wave3NullifierError,
    Wave3NullifierRecordV1,
    Wave3WideLeafV1,
    derive_dual_record,
    independently_verify_wave3_transition,
)


def _authority() -> NullifierDerivationAuthorityV1:
    return NullifierDerivationAuthorityV1.from_secret(b"A" * 64, b"P" * 64)


def _attempt_raw(label: str) -> bytes:
    return derive_attempt_nullifiers_v1(
        AttemptReplayIdentityV1(f"AUTH-{label}", f"CLAIM-{label}", 1, 1, 0),
        _authority(),
    ).canonical_preimage


def _cover_raw() -> bytes:
    derived = derive_cover_nullifiers_v2(
        CoverReplayContextV2(
            "BL-PQ512-v1",
            b"D" * 64,
            1,
            b"B" * 64,
            7,
        ),
        b"N" * 64,
    )
    return derived.canonical_preimage


def test_p01_p02_derivation_uses_same_raw_bytes_independently() -> None:
    raw = _attempt_raw("ONE")
    derived = derive_dual_record(raw)
    application = derive_attempt_nullifiers_v1(
        AttemptReplayIdentityV1("AUTH-ONE", "CLAIM-ONE", 1, 1, 0),
        _authority(),
    )

    assert derived.record == Wave3NullifierRecordV1(raw)
    assert derived.record.record_type == RECORD_ATTEMPT
    assert derived.legacy_felt == application.legacy_felt
    assert derived.strong_key_512 == hashlib.sha3_512(raw).digest()
    assert derived.strong_key_512 != derived.legacy_felt.to_bytes(32, "big")

    cover = derive_dual_record(_cover_raw())
    assert cover.record.record_type == RECORD_COVER


def test_a12_header_match_is_not_enough_for_canonical_admission() -> None:
    raw = _attempt_raw("GRAMMAR")
    forged = raw[:12] + (len(raw) + 1).to_bytes(4, "big") + raw[16:] + b"x"

    with pytest.raises(Wave3NullifierError, match="body_length"):
        derive_dual_record(forged)


def test_p01_encoding_binds_type_position_and_empty_shape() -> None:
    first = Wave3WideLeafV1(2, b"A" * 64, b"B" * 64, 3, RECORD_ATTEMPT)
    different_position = replace(first, index=3)
    different_type = replace(first, record_type=RECORD_COVER)

    assert first.digest != different_position.digest
    assert first.digest != different_type.digest
    with pytest.raises(Wave3NullifierError, match="successor_zero"):
        Wave3WideLeafV1(2, b"A" * 64, bytes(64), 3, RECORD_ATTEMPT)


def test_p03_authority_verifies_and_atomically_commits_dual_roots() -> None:
    state = Wave3NullifierAuthorityV1(epoch=9)
    initial = state.snapshot()
    assert initial.record_count == 0
    assert initial.next_append_index == 2

    for label in ("ONE", "TWO", "THREE"):
        transition = state.prepare_transition(_attempt_raw(label))
        assert independently_verify_wave3_transition(transition)
        committed = state.commit(transition)
        assert committed == state.snapshot()

    final = state.snapshot()
    assert final.epoch == 9
    assert final.sequence == 3
    assert final.record_count == 3
    assert final.next_append_index == 5
    assert final.strong_nullifier_root_512 != initial.strong_nullifier_root_512
    assert final.legacy_root_felt != initial.legacy_root_felt
    assert CANDIDATE_STATUS == final.status
    assert ACTIVATION_ALLOWED is False
    assert PROOF_SUITE_ID is None


def test_p03_stale_transition_and_path_mutation_fail_closed() -> None:
    state = Wave3NullifierAuthorityV1()
    first = state.prepare_transition(_attempt_raw("ONE"))
    second = state.prepare_transition(_attempt_raw("TWO"))
    state.commit(first)
    with pytest.raises(Wave3NullifierError, match="stale_snapshot"):
        state.commit(second)

    fresh = state.prepare_transition(_attempt_raw("THREE"))
    path = fresh.wide_witness.predecessor_path
    forged_path = (bytes((path[0][0] ^ 1,)) + path[0][1:], *path[1:])
    forged_witness = replace(fresh.wide_witness, predecessor_path=forged_path)
    with pytest.raises(Wave3NullifierError, match="root|sibling|mismatch"):
        independently_verify_wave3_transition(replace(fresh, wide_witness=forged_witness))


def test_historical_cover_v1_and_forged_dual_digest_are_rejected() -> None:
    historical = derive_cover_nullifiers_v1(
        CoverReplayContextV1("BL-PQ512-v1", b"D" * 64, 1, 7, 1),
        b"N" * 64,
    )
    with pytest.raises(Wave3NullifierError, match="profile_or_domain"):
        derive_dual_record(historical.canonical_preimage)

    record = Wave3NullifierRecordV1(_attempt_raw("ONE"))
    with pytest.raises(Wave3NullifierError, match="strong_derivation"):
        Wave3DualDerivedRecordV1(record, record.legacy_felt, b"F" * 64)
