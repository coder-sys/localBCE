from __future__ import annotations

import os
from hashlib import sha3_512

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    OutputKind,
    ProverMessageKind,
    PublicCoinSession,
    RoundKind,
    THEOREM_PROVER_MESSAGE_LENGTH,
    TheoremProverMessage,
    build_theorem_round_schedule,
    validate_theorem_prover_message,
)
from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    InterfaceTableDimensions,
    InterfaceTheoremEnvelope,
    build_candidate_sweep,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


_PQ_SUITES = ("FIPS204-ML-DSA-87", "FIPS205-SLH-DSA-SHAKE-256F")


class _SyntheticOnlyVerifier:
    synthetic_only = True

    def __init__(self, suite_id: str) -> None:
        self.suite_id = suite_id

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return signature == sha3_512(public_key + message).digest()


def _theorem_session():
    theorem_schedule = build_theorem_round_schedule(_candidate())
    contributors = tuple(
        sorted(
            (
                Contributor(bytes([1]) * 64, bytes([2]) * 64, _PQ_SUITES[0], b"A" * 64),
                Contributor(bytes([3]) * 64, bytes([4]) * 64, _PQ_SUITES[1], b"B" * 64),
            ),
            key=lambda contributor: contributor.contributor_id,
        )
    )
    verifiers = {suite: _SyntheticOnlyVerifier(suite) for suite in _PQ_SUITES}
    return PublicCoinSession(
        session_id=sha3_512(b"THEOREM-SESSION").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        candidate_descriptor_sha3_512=sha3_512(b"THEOREM-CANDIDATE").digest(),
        schedule=theorem_schedule.descriptors,
        contributors=contributors,
        verifiers=verifiers,
        production_mode=False,
        theorem_schedule=theorem_schedule,
    )


def _candidate(log_blowup: int = 1):
    program = build_wave1a_physical_air_program(PROFILES["K512_CALIBRATION"])
    envelope = InterfaceTheoremEnvelope(
        program.profile_id,
        tuple(
            InterfaceTableDimensions(
                table.name,
                table.padded_rows,
                table.trace_columns,
                table.constraint_count,
                table.maximum_degree,
                table.lookup_message_width,
            )
            for table in program.tables
        ),
        program.commitment_count,
    )
    return build_candidate_sweep(envelope, (log_blowup,))[0]


def test_theorem_schedule_has_exact_protocol_round_order() -> None:
    candidate = _candidate()
    schedule = build_theorem_round_schedule(candidate)

    assert len(schedule.descriptors) == 21
    assert [descriptor.kind for descriptor in schedule.descriptors[:4]] == [
        RoundKind.INTERACTION_CHALLENGE,
        RoundKind.COMPOSITION_COEFFICIENT,
        RoundKind.OODS_POINT_PARAMETER,
        RoundKind.FRI_BATCH_COEFFICIENT,
    ]
    assert schedule.descriptors[0].output_count == 2
    assert [descriptor.ordinal for descriptor in schedule.descriptors[4:-1]] == list(range(16))
    assert all(
        descriptor.kind is RoundKind.FRI_FOLD_COEFFICIENT
        for descriptor in schedule.descriptors[4:-1]
    )
    assert schedule.descriptors[-1].kind is RoundKind.QUERY_POSITIONS
    assert schedule.descriptors[-1].output_kind is OutputKind.QUERY_SEED
    assert schedule.fold_round_count == candidate.fold_round_count == 16
    assert schedule.query_count == candidate.query_count == 617
    assert schedule.query_domain_size == candidate.evaluation_domain_size == 1 << 20
    assert schedule.query_with_replacement is True
    assert schedule.maximum_attempts_per_query == 1
    assert schedule.final_line_domain_size == candidate.final_line_domain_size == 16
    assert schedule.final_expansion_substituted is False
    assert schedule.selected is False
    assert schedule.proof_suite_id is None
    assert schedule.activation_allowed is False
    assert len(schedule.digest) == 64


def test_all_rate_candidates_retain_same_protocol_shape_but_bind_distinct_parameters() -> None:
    schedules = [build_theorem_round_schedule(_candidate(beta)) for beta in range(1, 7)]
    assert [schedule.fold_round_count for schedule in schedules] == [16] * 6
    assert [schedule.query_count for schedule in schedules] == [617, 378, 309, 281, 268, 262]
    assert [schedule.query_domain_size for schedule in schedules] == [
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 23,
        1 << 24,
        1 << 25,
    ]
    assert [schedule.final_line_domain_size for schedule in schedules] == [
        16,
        32,
        64,
        128,
        256,
        512,
    ]
    # Descriptor order is intentionally identical; candidate parameters are
    # bound separately by the final candidate descriptor, still null today.
    assert len({schedule.digest for schedule in schedules}) == 1


def test_every_challenge_has_an_exact_preceding_prover_message_kind() -> None:
    schedule = build_theorem_round_schedule(_candidate())
    roots = [bytes([index + 1]) * 64 for index in range(len(schedule.descriptors) + 1)]
    messages = [
        TheoremProverMessage(ProverMessageKind.MAIN_TRACE_ROOT, 0, roots[0]),
        TheoremProverMessage(ProverMessageKind.INTERACTION_TRACE_ROOT, 0, roots[1]),
        TheoremProverMessage(ProverMessageKind.COMPOSITION_ROOT, 0, roots[2]),
        TheoremProverMessage(
            ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT,
            0,
            roots[3],
            roots[4],
        ),
        TheoremProverMessage(ProverMessageKind.FRI_BATCH_DERIVATION, 0, roots[5]),
        *(
            TheoremProverMessage(ProverMessageKind.FRI_LAYER_ROOT, ordinal, roots[6 + ordinal])
            for ordinal in range(schedule.fold_round_count - 1)
        ),
        TheoremProverMessage(
            ProverMessageKind.FRI_LAYER_ROOT,
            schedule.fold_round_count - 1,
            roots[-1],
        ),
    ]
    assert len(messages) == len(schedule.descriptors)
    for descriptor, message in zip(schedule.descriptors, messages, strict=True):
        encoded = message.encode()
        assert len(encoded) == THEOREM_PROVER_MESSAGE_LENGTH == 144
        assert (
            validate_theorem_prover_message(
                descriptor,
                fold_round_count=schedule.fold_round_count,
                encoded=encoded,
            )
            == message
        )

    batch_message = messages[3]
    assert batch_message.kind is ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT
    assert batch_message.secondary_digest == roots[4]


def test_public_coin_session_enforces_theorem_message_before_randomness_commitments() -> None:
    session = _theorem_session()
    descriptor = session.schedule[0]
    message = TheoremProverMessage(
        ProverMessageKind.MAIN_TRACE_ROOT,
        0,
        bytes([5]) * 64,
    )

    session.begin_round(descriptor, message.encode())

    assert session.phase == "COMMIT"
    assert session.abort_reason is None
