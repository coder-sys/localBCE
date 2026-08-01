from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    OutputKind,
    ProverMessageKind,
    PublicCoinSession,
    RoundDescriptor,
    RoundKind,
    TheoremProverMessage,
    TheoremRoundSchedule,
    validate_theorem_prover_message,
)


_PQ_SUITES = ("FIPS204-ML-DSA-87", "FIPS205-SLH-DSA-SHAKE-256F")


class _SyntheticOnlyVerifier:
    synthetic_only = True

    def __init__(self, suite_id: str) -> None:
        self.suite_id = suite_id

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return signature == sha3_512(public_key + message).digest()


def _theorem_session() -> PublicCoinSession:
    theorem_schedule = _schedule()
    contributors = (
        Contributor(bytes([1]) * 64, bytes([2]) * 64, _PQ_SUITES[0], b"A" * 64),
        Contributor(bytes([3]) * 64, bytes([4]) * 64, _PQ_SUITES[1], b"B" * 64),
    )
    verifiers = {suite: _SyntheticOnlyVerifier(suite) for suite in _PQ_SUITES}
    return PublicCoinSession(
        session_id=sha3_512(b"THEOREM-ATTACK-SESSION").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        candidate_descriptor_sha3_512=sha3_512(b"THEOREM-ATTACK-CANDIDATE").digest(),
        schedule=theorem_schedule.descriptors,
        contributors=contributors,
        verifiers=verifiers,
        production_mode=False,
        theorem_schedule=theorem_schedule,
    )


def _descriptors() -> tuple[RoundDescriptor, ...]:
    return (
        RoundDescriptor(RoundKind.INTERACTION_CHALLENGE, 0, OutputKind.FIELD16, 2),
        RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.OODS_POINT_PARAMETER, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.FRI_BATCH_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.FRI_FOLD_COEFFICIENT, 0, OutputKind.FIELD16, 1),
        RoundDescriptor(RoundKind.QUERY_POSITIONS, 0, OutputKind.QUERY_SEED, 1),
    )


def _schedule() -> TheoremRoundSchedule:
    return TheoremRoundSchedule(_descriptors(), 1 << 20, 926, True, 1)


def test_schedule_cannot_claim_selection_final_expansion_or_activation() -> None:
    schedule = _schedule()
    with pytest.raises(ValueError, match="cannot_claim_selection"):
        replace(schedule, selected=True)
    with pytest.raises(ValueError, match="cannot_claim_selection"):
        replace(schedule, final_expansion_substituted=True)
    with pytest.raises(ValueError, match="cannot_activate"):
        replace(schedule, activation_allowed=True)


def test_query_replacement_policy_and_attempt_cap_fail_closed() -> None:
    schedule = _schedule()
    with pytest.raises(ValueError, match="must_use_replacement"):
        replace(schedule, query_with_replacement=False)
    with pytest.raises(ValueError, match="attempt_cap_must_be_one"):
        replace(schedule, maximum_attempts_per_query=0)


def test_duplicate_round_descriptor_is_rejected() -> None:
    descriptors = _descriptors()
    with pytest.raises(ValueError, match="descriptor_duplicate"):
        TheoremRoundSchedule(descriptors + (descriptors[0],), 1 << 20, 926, True, 1)


def test_reordered_or_skipped_protocol_rounds_are_rejected() -> None:
    schedule = _schedule()
    descriptors = schedule.descriptors
    with pytest.raises(ValueError, match="prefix_invalid"):
        replace(schedule, descriptors=(descriptors[1], descriptors[0], *descriptors[2:]))
    with pytest.raises(ValueError, match="fold_sequence_invalid"):
        replace(
            schedule,
            descriptors=(*descriptors[:4], replace(descriptors[4], ordinal=1), descriptors[-1]),
        )
    with pytest.raises(ValueError, match="suffix_invalid"):
        replace(
            schedule,
            descriptors=descriptors[:-1]
            + (RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 1, OutputKind.FIELD16, 1),),
        )


def test_batch_challenge_cannot_precede_a_nonzero_mask_root() -> None:
    batch_descriptor = _schedule().descriptors[3]
    with pytest.raises(ValueError, match="fri_batch_mask_root_required"):
        TheoremProverMessage(
            ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT,
            0,
            bytes([1]) * 64,
        )
    wrong = TheoremProverMessage(
        ProverMessageKind.COMPOSITION_ROOT, 0, bytes([1]) * 64
    )
    with pytest.raises(ValueError, match="prover_message_order_mismatch"):
        validate_theorem_prover_message(
            batch_descriptor,
            fold_round_count=1,
            encoded=wrong.encode(),
        )


def test_prover_message_flags_length_and_fold_ordinals_fail_closed() -> None:
    schedule = _schedule()
    first_fold = schedule.descriptors[4]
    wrong = TheoremProverMessage(
        ProverMessageKind.FRI_LAYER_ROOT, 0, bytes([2]) * 64
    ).encode()
    with pytest.raises(ValueError, match="prover_message_order_mismatch"):
        validate_theorem_prover_message(
            first_fold,
            fold_round_count=1,
            encoded=wrong,
        )
    valid = bytearray(
        TheoremProverMessage(
            ProverMessageKind.FRI_BATCH_DERIVATION, 0, bytes([3]) * 64
        ).encode()
    )
    valid[15] = 1
    with pytest.raises(ValueError, match="flags_nonzero"):
        validate_theorem_prover_message(
            first_fold,
            fold_round_count=1,
            encoded=bytes(valid),
        )
    with pytest.raises(ValueError, match="length_invalid"):
        validate_theorem_prover_message(
            first_fold,
            fold_round_count=1,
            encoded=bytes(valid[:-1]),
        )


def test_public_coin_session_aborts_before_commit_on_generic_prover_bytes() -> None:
    session = _theorem_session()

    with pytest.raises(ValueError, match="prover_message_length_invalid"):
        session.begin_round(session.schedule[0], b"GENERIC-PROVER-MESSAGE")

    assert session.phase == "ABORTED"
    assert session.abort_reason == "invalid_theorem_prover_message"
    PublicCoinSession,
