from fractions import Fraction

import pytest

from experiments.bl_pq512_hint_mlwe_392.parameter_gate import (
    EXPECTED_UPSTREAM_COMMIT,
    MAX_COMPOSED_TERMS_AT_FLOOR,
    CandidateEvidence,
    Provenance,
    SecurityTerm,
    TranscriptProfile,
    evaluate_candidate,
    minimum_independent_repetitions,
    power_of_two_failure,
)
from experiments.bl_pq512_hint_mlwe_392.challenge_space import (
    challenge_meets_eta,
    conservative_challenge_bits,
    derive_single_challenge_candidates,
)
from experiments.bl_pq512_hint_mlwe_392.candidate_geometry import (
    D256_BOX4_Q68_K29,
    PUBLISHED_SET1,
    derive_geometry,
)
from experiments.bl_pq512_hint_mlwe_392.source_audit import (
    challenge_sampler_enforces_norm,
    inspect_source_texts,
)
from experiments.bl_pq512_hint_mlwe_392.theorem_ledger import (
    SIMULATABILITY_EPSILON_MULTIPLIER,
    completeness_dimension_floor,
    derive_published_proof_floor,
    minimum_epsilon_bits,
    relation_false_positive_bits,
)
from experiments.bl_pq512_hint_mlwe_392.relation_expressibility import (
    MAPPINGS,
    RelationMapping,
    evaluate_blind_ledger_claim_mapping,
)
from experiments.bl_pq512_hint_mlwe_392.interactive_public_coin import (
    COIN_BLOCK_BYTES,
    COIN_BLOCK_COUNT,
    CoinEnvelope,
    CoinProfile,
    InteractivePublicCoinTranscript,
    sample_exact_challenge,
    signed_coin_payload,
)
from experiments.bl_pq512_hint_mlwe_392.relation_cost_screen import (
    K128_MODEL,
    K512_MODEL,
    maximum_current_candidate_message_rank,
    screen_direct_hint_mlwe,
)
from experiments.bl_pq512_hint_mlwe_392.compact_hybrid_capacity import (
    PRIVATE_MASTER_SCALARS_PER_SLOT,
    screen_workspace_master_record,
)
from experiments.bl_pq512_hint_mlwe_392.message_rank_options import (
    OPTIONS,
    screen_option,
)
from experiments.bl_pq512_hint_mlwe_392.state_access_capacity import (
    screen_state_access_capacity,
)
from experiments.bl_pq512_hint_mlwe_392.hidden_state_workload_derivation import (
    derive_hidden_state_workload,
)
from experiments.bl_pq512_hint_mlwe_392.persistent_memory_capacity_screen import (
    screen_sparse_persistent_memory,
)
from experiments.bl_pq512_hint_mlwe_392.projection_ram_capacity_screen import (
    screen_projection_ram,
)
from experiments.bl_pq512_hint_mlwe_392.two_shuffles_capacity_screen import (
    screen_two_shuffles,
)
from experiments.bl_pq512_hint_mlwe_392.irondict_capacity_screen import (
    screen_irondict_current_pcs,
)


def _candidate(
    *,
    term_bits: int = 395,
    invocation_count: int = 1,
    transcript: TranscriptProfile | None = None,
    provenance: Provenance | None = None,
) -> CandidateEvidence:
    names = (
        "challenge_knowledge_error",
        "hint_mlwe_to_mlwe_reduction_loss",
        "mlwe_quantum_attack",
        "msis_binding_quantum_attack",
        "msis_knowledge_quantum_attack",
        "statistical_hiding_and_simulation",
    )
    return CandidateEvidence(
        candidate_id="synthetic-test-only",
        terms=tuple(
            SecurityTerm(
                name,
                power_of_two_failure(term_bits),
                f"theorem:{name}",
                f"artifact:{name}",
            )
            for name in names
        ),
        transcript=transcript
        or TranscriptProfile(
            mode="interactive",
            authoritative_hash="sha3-512",
            digest_bytes=64,
            authenticated_public_coin=True,
            fiat_shamir_used=False,
            public_coin_security_bits=512,
        ),
        provenance=provenance
        or Provenance(
            upstream_commit=EXPECTED_UPSTREAM_COMMIT,
            parameter_generator_commit="1" * 40,
            estimator_name="reviewed-estimator",
            estimator_commit="2" * 40,
            estimator_input_artifact="sha3-512:input",
            estimator_output_artifact="sha3-512:output",
            estimator_model_reviewed=True,
        ),
        composed_invocation_count=invocation_count,
    )


def test_complete_synthetic_evidence_is_feasibility_only() -> None:
    result = evaluate_candidate(_candidate())
    assert result.status == "FEASIBILITY_ONLY"
    assert result.failures == ()
    assert result.minimum_term_bits == 395
    assert result.total_bits == 392


def test_one_391_bit_term_fails_closed() -> None:
    candidate = _candidate(term_bits=392)
    weak = SecurityTerm(
        candidate.terms[0].name,
        power_of_two_failure(391),
        candidate.terms[0].theorem_reference,
        candidate.terms[0].derivation_artifact,
    )
    result = evaluate_candidate(
        CandidateEvidence(
            candidate.candidate_id,
            (weak, *candidate.terms[1:]),
            candidate.transcript,
            candidate.provenance,
            candidate.composed_invocation_count,
        )
    )
    assert result.status == "BLOCKED"
    assert "security_term_below_392:challenge_knowledge_error:391" in result.failures


def test_published_transcript_profile_gets_zero_credit() -> None:
    result = evaluate_candidate(
        _candidate(
            transcript=TranscriptProfile(
                mode="fiat-shamir",
                authoritative_hash="shake128",
                digest_bytes=32,
                authenticated_public_coin=False,
                fiat_shamir_used=True,
                public_coin_security_bits=128,
            )
        )
    )
    assert result.status == "BLOCKED"
    assert {
        "transcript_not_interactive",
        "authoritative_hash_not_sha3_512",
        "authoritative_digest_not_64_bytes",
        "public_coin_not_authenticated",
        "fiat_shamir_forbidden",
        "public_coin_below_392:128",
    }.issubset(result.failures)


def test_missing_estimator_provenance_fails_closed() -> None:
    result = evaluate_candidate(
        _candidate(
            provenance=Provenance(
                upstream_commit=EXPECTED_UPSTREAM_COMMIT,
                parameter_generator_commit="1" * 40,
                estimator_name="",
                estimator_commit="",
                estimator_input_artifact="",
                estimator_output_artifact="",
                estimator_model_reviewed=False,
            )
        )
    )
    assert result.status == "BLOCKED"
    assert "estimator_commit_missing" in result.failures
    assert "estimator_model_not_reviewed" in result.failures


def test_repetition_arithmetic_lower_bounds_are_not_qualification() -> None:
    assert minimum_independent_repetitions(129) == 4
    assert minimum_independent_repetitions(147) == 3


def test_composition_boundary_is_exact() -> None:
    one_term = (power_of_two_failure(392),)
    at_boundary = sum(one_term * MAX_COMPOSED_TERMS_AT_FLOOR, Fraction())
    over_boundary = sum(
        one_term * (MAX_COMPOSED_TERMS_AT_FLOOR + 1), Fraction()
    )
    assert at_boundary == power_of_two_failure(384)
    assert over_boundary > power_of_two_failure(384)


def test_source_text_audit_detects_published_constants() -> None:
    audit = inspect_source_texts(
        (
            "LAMBDA = 128\nCsize = 2 ** 129\n",
            "LAMBDA = 128\nCsize = 2 ** 147\n",
        ),
        (
            "shake128_state_t hstate;\n"
            "/* update fiat-shamir hash */\n"
            "shake128_init(hstate);\n",
        ),
    )
    assert audit == ((128,), (129, 147), 2, 1, False)


def test_source_text_audit_detects_repetition_formula_bug() -> None:
    audit = inspect_source_texts(
        ("lmbda = 2 * ceil(param_sec/(2*log2q))\n",),
        (),
    )
    assert audit[-1] is True


def test_source_audit_detects_sampler_without_eta_check() -> None:
    source = """
    _intvec_urandom_autostable (intvec_t r, int64_t bnd)
    {
      _urandom_i64 (coeffs, n, mod, log2, seed, dom);
    }
    """
    assert challenge_sampler_enforces_norm(source) is False


def test_primary_theorem_loss_floor_is_exact() -> None:
    assert SIMULATABILITY_EPSILON_MULTIPLIER == 20
    assert minimum_epsilon_bits(20) == 397
    floor = derive_published_proof_floor()
    assert floor.epsilon_bits == 397
    assert floor.simulatable_statistical_bits == 392
    assert floor.completeness_dimension == 393
    assert floor.d64_sequential_repetitions_arithmetic_only == 4
    assert floor.d128_sequential_repetitions_arithmetic_only == 3
    assert floor.repetition_theorem_supplied is False


def test_completeness_and_relation_error_helpers() -> None:
    assert completeness_dimension_floor() == 393
    assert relation_false_positive_bits((1 << 60) - 1, 64) >= 1_919


def test_published_challenge_bits_match_source_convention() -> None:
    assert conservative_challenge_bits(64, 8) == 129
    assert conservative_challenge_bits(128, 2) == 147


def test_released_sampler_box_contains_d64_eta_counterexample() -> None:
    independent = (
        8, 1, 4, 1, -4, 6, 0, 8, -3, 1, -2, -1, -4, 3, 8, -2,
        -8, 7, 4, -4, -5, 7, 2, 5, -6, -3, 6, 8, 5, -8, 4, 8,
    )
    assert challenge_meets_eta(independent, 140) is False


def test_released_sampler_box_contains_d128_eta_counterexample() -> None:
    independent = (
        -2, 2, 0, -2, 0, 1, 2, -2, 0, 0, 0, 2, -1, 1, 2, 0,
        -2, 1, 2, 0, 1, -2, 1, 2, -2, 1, 0, -1, 0, 2, -1, -1,
        0, 1, 0, 0, 1, 0, 0, -2, 2, 0, -2, 0, -2, -1, -2, 2,
        0, 0, 1, -2, 0, 1, -2, 2, 1, 2, -1, -1, 0, -2, 2, 2,
    )
    assert challenge_meets_eta(independent, 59) is False


def test_degree_512_ternary_is_smallest_box_candidate() -> None:
    candidates = derive_single_challenge_candidates()
    by_degree = {candidate.degree: candidate for candidate in candidates}
    assert by_degree[64].omega > 2_000
    assert by_degree[128].omega == 35
    assert by_degree[256].omega == 4
    assert by_degree[512].omega == 1
    assert by_degree[512].conservative_bits >= 392
    assert by_degree[512].fixed_shape_eta_upper == 511
    assert by_degree[512].encoded_bytes_upper == 128


def test_blind_ledger_claim_is_quadratically_expressible() -> None:
    report = evaluate_blind_ledger_claim_mapping()
    assert report.answer == "YES"
    assert report.failures == ()
    assert len(report.components) == 9
    assert report.qualification_status == (
        "EXPRESSIBLE_ONLY_NOT_IMPLEMENTED_OR_QUALIFIED"
    )


def test_expressibility_fails_closed_above_quadratic() -> None:
    invalid = RelationMapping(
        claim_component="unlowered cubic",
        workspace_source="synthetic-test-only",
        hint_mlwe_mapping="x*y*z",
        lowered_max_degree=3,
        fixed_shape=True,
    )
    report = evaluate_blind_ledger_claim_mapping((*MAPPINGS, invalid))
    assert report.answer == "NO"
    assert "component_above_quadratic:unlowered cubic" in report.failures


def test_geometry_reproduces_published_set1() -> None:
    result = derive_geometry(PUBLISHED_SET1)
    assert result.randomness_rank == 69
    assert result.sigma1 == 6
    assert result.sigma2 == 12
    assert result.simulation_sigma == 9
    assert result.frak_s1_squared_ceiling == 500_970
    assert result.frak_s2_squared_ceiling == 37_748_736
    assert 1_785_380_000_000 <= result.binding_bound_ceiling <= 1_785_390_000_000
    assert 111_362_000_000_000_000 <= result.knowledge_bound_ceiling <= (
        111_363_000_000_000_000
    )
    assert result.proof_kib == "25.42"


def test_k29_candidate_geometry_is_internally_consistent() -> None:
    result = derive_geometry(D256_BOX4_Q68_K29)
    assert result.randomness_rank == 64
    assert result.sigma1 == 10
    assert result.sigma2 == 20
    assert result.simulation_sigma == 15
    assert result.binding_below_modulus is True
    assert result.knowledge_below_modulus is True
    assert result.compression_divides_modulus_minus_one is True
    assert result.compression_inequality_holds is True
    assert result.modulus_limbs_64 == 2


class _ExactEvidenceTestAuthenticator:
    def __init__(self, evidence: bytes) -> None:
        self._evidence = evidence

    def verify(
        self,
        authenticator_id: bytes,
        parameter_id: bytes,
        signed_payload: bytes,
        authentication_evidence: bytes,
    ) -> bool:
        return (
            len(authenticator_id) == 64
            and len(parameter_id) == 64
            and signed_payload
            and authentication_evidence == self._evidence
        )


def _coin_transcript(evidence: bytes = b"A" * 96):
    profile = CoinProfile(
        degree=256,
        omega=4,
        prover_commitment_bytes=128,
        authentication_evidence_bytes=len(evidence),
    )
    transcript = InteractivePublicCoinTranscript(
        profile=profile,
        session_id=b"S" * 64,
        statement_digest=b"T" * 64,
        authenticator=_ExactEvidenceTestAuthenticator(evidence),
    )
    transcript.absorb_prover_commitment(b"P" * 128)
    envelope = CoinEnvelope(
        session_id=b"S" * 64,
        prior_transcript_digest=transcript.digest,
        authenticator_id=b"A" * 64,
        parameter_id=b"I" * 64,
        round_index=0,
        coin_blocks=(b"\0" * COIN_BLOCK_BYTES,) * COIN_BLOCK_COUNT,
        authentication_evidence=evidence,
    )
    return transcript, envelope


def test_interactive_public_coin_is_fixed_shape_and_exact() -> None:
    transcript, envelope = _coin_transcript()
    challenge = transcript.accept_coin(envelope)
    assert transcript.state == "challenge_accepted"
    assert challenge.selected_block_index == 0
    assert challenge.conservative_bits == 404
    assert len(challenge.independent_coefficients) == 128
    assert len(challenge.autostable_coefficients) == 256
    assert challenge.all_blocks_rejected_probability < Fraction(
        1, 1 << 392
    )


def test_interactive_public_coin_rejects_bad_authentication() -> None:
    transcript, envelope = _coin_transcript()
    tampered = CoinEnvelope(
        envelope.session_id,
        envelope.prior_transcript_digest,
        envelope.authenticator_id,
        envelope.parameter_id,
        envelope.round_index,
        envelope.coin_blocks,
        b"B" * len(envelope.authentication_evidence),
    )
    with pytest.raises(ValueError, match="public_coin_authentication_failed"):
        transcript.accept_coin(tampered)


def test_interactive_public_coin_rejects_replay() -> None:
    transcript, envelope = _coin_transcript()
    transcript.accept_coin(envelope)
    with pytest.raises(ValueError, match="public_coin_wrong_transcript_state"):
        transcript.accept_coin(envelope)


def test_interactive_public_coin_rejects_stale_digest() -> None:
    transcript, envelope = _coin_transcript()
    stale = CoinEnvelope(
        envelope.session_id,
        b"X" * 64,
        envelope.authenticator_id,
        envelope.parameter_id,
        envelope.round_index,
        envelope.coin_blocks,
        envelope.authentication_evidence,
    )
    with pytest.raises(ValueError, match="public_coin_prior_digest_mismatch"):
        transcript.accept_coin(stale)


def test_all_public_coin_blocks_rejected_fails_closed() -> None:
    with pytest.raises(ValueError, match="all_public_coin_blocks_rejected"):
        sample_exact_challenge(
            (b"\xff" * COIN_BLOCK_BYTES,) * COIN_BLOCK_COUNT,
            degree=256,
            omega=4,
        )


def test_signed_coin_payload_has_no_authentication_evidence_cycle() -> None:
    _, envelope = _coin_transcript()
    payload = signed_coin_payload(envelope)
    assert envelope.authentication_evidence not in payload


def test_current_candidate_geometry_stops_at_message_rank_twelve() -> None:
    assert maximum_current_candidate_message_rank() == 12


def test_direct_hint_mlwe_k128_sha3_lane_is_rejected() -> None:
    result = screen_direct_hint_mlwe(K128_MODEL)
    assert result.quadratic_relations == 180_172_800
    assert result.linear_relations == 180_172_800
    assert result.state_snapshot_bits == 31_280_000
    assert result.state_only_message_rank_lower_bound == 122_188
    assert result.generated_message_rank == 1_801_728
    assert result.generated_geometry.proof_bytes_ceiling == 5_831_378_549
    assert (
        result.generated_matrix_bytes_current_upstream
        == 487_080_591_360
    )
    assert result.verdict == "DIRECT_HINT_MLWE_REJECTED"
    assert result.blockers == (
        "state_only_knowledge_bound_not_below_modulus",
        "generated_relation_knowledge_bound_not_below_modulus",
        "current_upstream_dense_matrix_exceeds_3gb_ram",
        "proof_alone_exceeds_5gb_scratch",
    )


def test_direct_hint_mlwe_k512_sha3_lane_is_rejected() -> None:
    result = screen_direct_hint_mlwe(K512_MODEL)
    assert result.quadratic_relations == 205_977_600
    assert result.linear_relations == 205_977_600
    assert result.state_snapshot_bits == 35_760_000
    assert result.state_only_message_rank_lower_bound == 139_688
    assert result.generated_message_rank == 2_059_776
    assert result.generated_geometry.proof_bytes_ceiling == 6_666_545_740
    assert (
        result.generated_matrix_bytes_current_upstream
        == 556_840_255_488
    )
    assert result.verdict == "DIRECT_HINT_MLWE_REJECTED"


def test_compact_k128_workspace_record_has_only_unallocated_headroom() -> None:
    result = screen_workspace_master_record("K128_CALIBRATION", 128)
    assert PRIVATE_MASTER_SCALARS_PER_SLOT == (
        "decision",
        "failure_code",
        "allowed_cents",
        "payment_cents",
        "raw_gate_bits",
        "effective_gate_bits",
    )
    assert result.base_private_coefficients == 768
    assert result.base_message_rank == 3
    assert result.remaining_coefficients == 2_304
    assert result.maximum_per_slot_scalars_with_one_fixed_coefficient == 23
    assert result.verdict == "CAPACITY_HEADROOM_ONLY_NOT_ADMITTED"


def test_compact_k512_workspace_record_exhausts_current_m1() -> None:
    result = screen_workspace_master_record("K512_CALIBRATION", 512)
    assert result.base_private_coefficients == 3_072
    assert result.base_message_rank == 12
    assert result.remaining_coefficients == 0
    assert result.maximum_per_slot_scalars_with_one_fixed_coefficient == 5
    assert result.verdict == "REJECTED_CURRENT_M1"
    assert result.blockers == (
        "no_coefficient_room_for_hidden_state_or_auxiliaries",
        "exact_compact_relation_manifest_missing",
        "semantic_equivalence_delegation_boundary_unproved",
    )


def test_larger_message_rank_options_preserve_measured_limiting_floor() -> None:
    screens = tuple(screen_option(option) for option in OPTIONS)
    assert tuple(screen.coefficient_capacity for screen in screens) == (
        3_328,
        4_096,
        6_144,
        8_192,
    )
    assert tuple(screen.option.proof_bytes for screen in screens) == (
        163_986,
        173_696,
        200_707,
        228_647,
    )
    assert all(
        screen.status == "LIMITING_ATTACKS_PASS_FULL_ATTACKS_PENDING"
        for screen in screens
    )
    assert min(
        float(screen.option.simulatability_usvp_bits)
        for screen in screens
    ) == 395.91


@pytest.mark.parametrize(
    ("profile_id", "operations", "coefficients", "message_rank"),
    (
        ("K128_CALIBRATION", 641, 15_384, 61),
        ("K512_CALIBRATION", 2_561, 61_464, 241),
    ),
)
def test_screened_compact_hint_options_cannot_hold_state_access_lower_bound(
    profile_id: str,
    operations: int,
    coefficients: int,
    message_rank: int,
) -> None:
    result = screen_state_access_capacity(profile_id)
    assert result.ordered_map_operations == operations
    assert result.payload_bits_per_hint_coefficient == 69
    assert result.hint_coefficients_per_state_word == 8
    assert result.coefficient_lower_bound == coefficients
    assert result.message_rank_lower_bound == message_rank
    assert result.largest_screened_message_rank == 32
    assert result.verdict == "REJECTED_SCREENED_COMPACT_HINT_OPTIONS"


@pytest.mark.parametrize(
    (
        "profile_id",
        "sealed",
        "state",
        "state_only",
        "truth",
        "admissible",
        "model_delta",
    ),
    (
        (
            "K128_CALIBRATION",
            113_730,
            96_900,
            16_830,
            16_124,
            706,
            76,
        ),
        (
            "K512_CALIBRATION",
            411_406,
            344_308,
            67_098,
            64_424,
            2_674,
            -1_780,
        ),
    ),
)
def test_hidden_state_workload_does_not_credit_random_nullifier_semantic_change(
    profile_id: str,
    sealed: int,
    state: int,
    state_only: int,
    truth: int,
    admissible: int,
    model_delta: int,
) -> None:
    result = derive_hidden_state_workload(profile_id)
    assert result.sealed_permutations == sealed
    assert result.state_permutations_removed == state
    assert result.state_only_replacement_permutations == state_only
    assert result.claim_truth_permutations_removed == truth
    assert result.admissible_lower_bound_permutations == admissible
    assert result.hard_coded_model_delta_from_admissible_lower_bound == model_delta
    assert result.random_nullifier_model_admissible is False
    assert result.exact_final_workload_known is False


@pytest.mark.parametrize(
    ("profile_id", "accesses", "constraints"),
    (
        ("K128_CALIBRATION", 641, 469_794_739),
        ("K512_CALIBRATION", 2_561, 469_892_659),
    ),
)
def test_sparse_persistent_memory_candidate_fails_raw_laptop_envelope(
    profile_id: str,
    accesses: int,
    constraints: int,
) -> None:
    result = screen_sparse_persistent_memory(profile_id)
    assert result.accesses == accesses
    assert result.total_capacity == 1 << 26
    assert result.published_constraint_estimate == constraints
    assert result.raw_state_vector_bytes == 17_179_869_184
    assert result.soundness_bits_floor >= 392
    assert result.verdict == "REJECTED_C1_REFERENCE_LAPTOP"
    assert "raw_committed_state_vectors_exceed_3gb_ram" in result.blockers


@pytest.mark.parametrize(
    ("profile_id", "operations", "touched_bits", "quadratic_scale"),
    (
        ("K128_CALIBRATION", 641, 328_192, 107_709_988_864),
        ("K512_CALIBRATION", 2_561, 1_311_232, 1_719_329_357_824),
    ),
)
def test_projection_ram_is_not_admitted_without_concrete_laptop_parameters(
    profile_id: str,
    operations: int,
    touched_bits: int,
    quadratic_scale: int,
) -> None:
    result = screen_projection_ram(profile_id)
    assert result.state_operations == operations
    assert result.qualification_touched_bits == touched_bits
    assert result.quadratic_projection_scale == quadratic_scale
    assert result.concrete_time_known is False
    assert result.concrete_ram_known is False
    assert result.concrete_scratch_known is False
    assert result.verdict == "NOT_ADMITTED_C3_NO_CONCRETE_LAPTOP_PARAMETERS"


@pytest.mark.parametrize(
    ("profile_id", "accesses", "input_gates", "latency_limit"),
    (
        ("K128_CALIBRATION", 641, 201_329_797, 60),
        ("K512_CALIBRATION", 2_561, 201_339_397, 180),
    ),
)
def test_two_shuffles_full_state_cost_fails_current_pcs_laptop_gate(
    profile_id: str,
    accesses: int,
    input_gates: int,
    latency_limit: int,
) -> None:
    result = screen_two_shuffles(profile_id)
    assert result.state_cells == 1 << 26
    assert result.accesses == accesses
    assert result.input_gates == input_gates
    assert result.minimum_pcs_shards == 49
    assert result.optimistic_concurrent_shards == 2
    assert result.optimistic_pcs_waves == 25
    assert result.optimistic_pcs_prove_seconds == pytest.approx(477.46046)
    assert result.optimistic_pcs_prove_seconds >= latency_limit
    assert result.verdict == "REJECTED_C4_CURRENT_PCS_REFERENCE_LAPTOP"


@pytest.mark.parametrize(
    ("profile_id", "gkr_seconds", "latency_limit", "combined_seconds"),
    (
        ("K128_CALIBRATION", 44.9440978, 60, 197.731445),
        ("K512_CALIBRATION", 124.8322177, 180, 277.6195649),
    ),
)
def test_irondict_current_transparent_pcs_fails_combined_latency_floor(
    profile_id: str,
    gkr_seconds: float,
    latency_limit: int,
    combined_seconds: float,
) -> None:
    result = screen_irondict_current_pcs(profile_id)
    assert result.state_cells == 1 << 26
    assert result.minimum_full_recommitment_shards == 16
    assert result.optimistic_concurrent_shards == 2
    assert result.optimistic_pcs_waves == 8
    assert result.optimistic_pcs_seconds == pytest.approx(152.7873472)
    assert result.measured_gkr_seconds == pytest.approx(gkr_seconds)
    assert result.optimistic_combined_seconds == pytest.approx(combined_seconds)
    assert result.optimistic_combined_seconds >= latency_limit
    assert result.verdict == "REJECTED_C2_CURRENT_TRANSPARENT_PCS_LATENCY"
