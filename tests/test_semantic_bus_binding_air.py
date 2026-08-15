from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.fixed_shape_claim_air.application_sha3_executable_air import Sha3Call
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantic_bus_binding_air import (
    H4_BRIDGE_MASK_COEFFICIENT_COUNT,
    H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK,
    H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP,
    H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM,
    H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP,
    H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS,
    H4_BRIDGE_MASK_PADDED_COUNT,
    H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP,
    H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY,
    H4CallTrace,
    H4_INPUT_BOOLEANITY_PREREQUISITE,
    MASK_RANK_STATUS,
    MAXIMUM_CONSTRAINT_DEGREE,
    PRIMITIVE_VECTOR_CONTRACT,
    QUOTIENT_COMPONENT_COUNT,
    PARENT_KIND901_MESSAGE_BYTES,
    PARENT_MAX_PROVER_MESSAGE_BYTES,
    SEMANTIC_PUBLIC_COIN_SPLIT,
    SemanticCallTrace,
    SyntheticQuotientChallenges,
    SyntheticQuotientMasks,
    build_semantic_bus_bridge_program,
    build_synthetic_semantic_h4_bridge,
    canonical_sha3_512_padded_blocks,
    derive_padded_row_selectors,
    honest_synthetic_quotient_claims,
    qualify_bridge_mask_rank,
    evaluate_synthetic_semantic_h4_bridge,
    verify_synthetic_quotient_identities,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


PROFILE = "SYNTHETIC_BRIDGE_KAT"
CALLS = (
    Sha3Call("empty", b"", 0),
    Sha3Call("short", b"abc", 144),
    Sha3Call("exact", bytes(range(72)), 144),
)
CAPACITIES = tuple(call.capacity for call in CALLS)


def _instance():
    return build_synthetic_semantic_h4_bridge(PROFILE, CALLS)


def _replace_semantic(instance, index: int, call: SemanticCallTrace):
    calls = list(instance.semantic_calls)
    calls[index] = call
    return replace(instance, semantic_calls=tuple(calls))


def _replace_h4_call(instance, index: int, call: H4CallTrace):
    calls = list(instance.h4_calls)
    calls[index] = call
    return replace(instance, h4_calls=tuple(calls))


def _mutate_boundary(instance, call_index: int, block_index: int, byte_index: int, mask: int):
    call = instance.h4_calls[call_index]
    boundaries = list(call.boundaries)
    boundary = boundaries[block_index]
    input_state = bytearray(boundary.input_state)
    input_state[byte_index] ^= mask
    boundaries[block_index] = replace(boundary, input_state=bytes(input_state))
    return _replace_h4_call(instance, call_index, replace(call, boundaries=tuple(boundaries)))


def _evaluate(instance):
    return evaluate_synthetic_semantic_h4_bridge(
        instance,
        expected_profile_id=PROFILE,
        expected_capacities=CAPACITIES,
    )


def test_k128_k512_virtual_layout_and_program_identity_kat() -> None:
    expected = {
        "K128_CALIBRATION": {
            "layout": (
                46_858,
                7_996_042,
                113_730,
                131_072,
                1,
                8_188_560,
                8_388_608,
                2_998_912,
                4_194_304,
                26,
                25,
                200_048,
                1_195_392,
                17_342,
            ),
                "commitment": (
                            "2b6c174d9ce183e1f6e5e2bc51e4c411f55ba5997aa2f87b81ca062c8473e33b"
                            "e60406d97d2dbd17958bf8fdbe89ab92b44cdb8acf48a09ca879310a635cd29f"
            ),
        },
        "K512_CALIBRATION": {
            "layout": (
                165_762,
                28_918_690,
                411_406,
                524_288,
                4,
                29_621_232,
                33_554_432,
                10_608_768,
                16_777_216,
                28,
                27,
                3_933_200,
                6_168_448,
                112_882,
            ),
                "commitment": (
                            "b1962cd2423238664861bc6f2551c0da9b362febcfc9b48e5ac8b2dda613973d"
                            "7ec080dd3ad4e5ffcc9978d3bd8b395a9677c9b7be0fefdfb9fdeed4b4d1c966"
            ),
        },
    }
    for profile_id, kat in expected.items():
        program = build_semantic_bus_bridge_program(PROFILES[profile_id])
        layout = program.layout
        assert (
            layout.call_count,
            layout.total_capacity_bytes,
            layout.total_permutations,
            layout.padded_permutations,
            layout.coprocessor_shards,
            layout.message_logical_rows,
            layout.message_trace_rows,
            layout.digest_logical_rows,
            layout.digest_trace_rows,
            layout.message_evaluation_log_size,
            layout.digest_evaluation_log_size,
            layout.semantic_trace_padding_rows,
            layout.digest_trace_padding_rows,
            layout.h4_global_padding_permutations,
        ) == kat["layout"]
        assert tuple(identity.group for identity in program.quotient_identities) == (
            "message",
            "digest",
        )
        assert all(
            identity.component_count == QUOTIENT_COMPONENT_COUNT
            for identity in program.quotient_identities
        )
        assert tuple(
            (
                identity.trace_log_size,
                identity.coefficient_count,
                identity.padded_coefficient_count,
                identity.component_count,
            )
            for identity in program.quotient_identities
        ) == (
            (layout.message_trace_rows.bit_length() - 1, 4_789, 8_192, 1),
            (layout.digest_trace_rows.bit_length() - 1, 4_789, 8_192, 1),
        )
        assert all(
            "Circle-FFT tensor basis in bit-reversed coefficient order"
            in identity["coefficientBasis"]
            for identity in program.canonical_object()["quotientIdentities"]
        )
        assert max(
            family.maximum_degree for family in program.constraint_families
        ) == MAXIMUM_CONSTRAINT_DEGREE
        assert program.canonical_object()["equationCount"] == {
            "K128_CALIBRATION": 309_708_708,
            "K512_CALIBRATION": 1_120_090_868,
        }[profile_id]
        assert program.canonical_object()["bridgeBatchingSoundnessBits"] == {
            "K128_CALIBRATION": 467.7937,
            "K512_CALIBRATION": 465.9390,
        }[profile_id]
        assert program.canonical_object()["selectedCircleQueryTerm"] == {
            "thetaNumerator": 4_294_967_295,
            "thetaDenominator": 17_179_869_184,
            "queryCount": 945,
            "soundnessBits": 392.2104367,
        }
        assert tuple(program.canonical_object()["semanticPublicCoinSplit"]) == SEMANTIC_PUBLIC_COIN_SPLIT
        assert any("only_z" in step for step in SEMANTIC_PUBLIC_COIN_SPLIT)
        assert all("native_child_oods_round_is_not_accepted" not in step or "not_accepted" in step for step in SEMANTIC_PUBLIC_COIN_SPLIT)
        assert program.h4_bridge_mask_coefficient_count == H4_BRIDGE_MASK_COEFFICIENT_COUNT
        assert H4_BRIDGE_MASK_PADDED_COUNT == 8_192
        assert H4_BRIDGE_MASK_DOMAIN_SEPARATED_EVALUATIONS == 8
        assert H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK_PER_GROUP == 2_438
        assert H4_BRIDGE_MASK_CONDITIONAL_OBSERVATION_RANK == 4_876
        assert H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM_PER_GROUP == 2_351
        assert H4_BRIDGE_MASK_CONDITIONAL_RESIDUAL_FREEDOM == 4_702
        assert H4_BRIDGE_MASK_RESIDUAL_BITS_FLOOR_PER_GROUP == 1_128_480
        assert MASK_RANK_STATUS.startswith("QUALIFIED_2351")
        assert program.canonical_object()["h4BridgeMaskPublicAnswerForm"] == "A_lane=B_lane+mu*R_lane"
        assert "C_message" in program.canonical_object()["h4BridgeMaskPolynomial"]
        assert "independent R" in program.canonical_object()["h4BridgeIndependentResponsePad"]
        assert (
            program.canonical_object()["h4BridgeMaskedFunctional"]
            == "H_hat_g=H_g+Z_H_g*N_g"
        )
        assert program.canonical_object()["bridgeMaskStandaloneZeroBaseAllowed"] is False
        assert program.canonical_object()["bridgeConstructionDirectBaseOpeningsPerLane"] == 1_218
        assert (
            program.canonical_object()["h4BridgeMaskJointRankEquation"]
            == "per_group_worst_case_M_sem_known:unknown(C,N,R_C,R_N)=4*4789;Q=4789;A_C,A_N=2*4789;direct=2*1218;C,N_z_conjugate_rank<=2;residual=2351_Fp16"
        )
        assert program.canonical_object()["authenticatedExistingSemanticMaskedSOpeningAllowed"] is True
        assert program.canonical_object()["rawOrUnmaskedSemanticSOpeningAllowed"] is False
        assert PARENT_KIND901_MESSAGE_BYTES == 613_220
        assert PARENT_KIND901_MESSAGE_BYTES < PARENT_MAX_PROVER_MESSAGE_BYTES
        assert (
            program.canonical_object()["bridgeMaskUnknownExtraFunctionalEffect"]
            == "FAIL_CLOSED_UNQUALIFIED"
        )
        assert H4_INPUT_BOOLEANITY_PREREQUISITE in program.canonical_object()[
            "prerequisites"
        ]
        assert program.proof_suite_id is None
        assert program.activation_allowed is False
        assert program.canonical_object()["publicBusOutput"] is None
        assert program.canonical_object()["rawBusOracleMaterialized"] is False
        assert program.canonical_object()["actualPcsAuthenticationAvailable"] is True
        assert program.canonical_object()["pythonReferenceMintsAcceptanceReceipt"] is False
        assert len(program.canonical_object()["primitiveVectorContract"]) == len(PRIMITIVE_VECTOR_CONTRACT)
        primitive_names = {value.name for value in PRIMITIVE_VECTOR_CONTRACT}
        assert {
            "h4_rate_input_times_predecessor_bits",
            "semantic_actual_last_times_h4_digest_output",
        }.issubset(primitive_names)
        assert len(program.canonical_bytes) < 16_384
        assert program.commitment_512.hex() == kat["commitment"]


def test_bridge_mask_rank_is_conditional_on_complete_h4_inventory() -> None:
    qualified = qualify_bridge_mask_rank(
        serialized_field_inventory=H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY,
    )
    assert (
        qualified.direct_base_openings,
        qualified.bridge_evaluations_per_group,
        qualified.observation_rank_per_group,
        qualified.observation_rank,
        qualified.residual_freedom_per_group,
        qualified.residual_freedom,
        qualified.residual_bits_floor_per_group,
    ) == (1_218, 4, 2_438, 4_876, 2_351, 4_702, 1_128_480)
    for inventory in (
        H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY[:-1],
        (*H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY, "unknown_M_functional:1"),
        tuple(reversed(H4_BRIDGE_SERIALIZED_FUNCTIONAL_INVENTORY)),
    ):
        with pytest.raises(
            StructuralError,
            match="semantic_bus_bridge_mask_rank_unqualified",
        ):
            qualify_bridge_mask_rank(
                serialized_field_inventory=inventory,
            )


def test_padded_row_selectors_cover_empty_partial_exact_and_next_block() -> None:
    cases = (
        (0, 0, (1,), (1,), 0),
        (71, 72, (1, 0), (1, 0), 71),
        (72, 144, (1, 1, 0), (0, 1, 0), 72),
        (73, 144, (1, 1, 0), (0, 1, 0), 73),
    )
    for length, capacity, active, actual_last, delimiter_position in cases:
        rows = (capacity // 72 + 1) * 72
        live = tuple(int(index < length) for index in range(rows))
        selectors = derive_padded_row_selectors(live, capacity)
        assert selectors.block_active == active
        assert selectors.actual_last == actual_last
        assert sum(selectors.delimiter) == 1
        assert selectors.delimiter[delimiter_position] == 1


def test_fips_202_padding_is_injective_for_trailing_zero_lengths_and_exact_block() -> None:
    messages = (b"", b"\0", b"\0\0", b"a", b"a\0", bytes(range(72)))
    encodings = tuple(b"".join(canonical_sha3_512_padded_blocks(value)) for value in messages)
    assert len(set(encodings)) == len(encodings)
    assert canonical_sha3_512_padded_blocks(b"")[0][0] == 0x06
    assert canonical_sha3_512_padded_blocks(b"")[0][-1] == 0x80
    exact = canonical_sha3_512_padded_blocks(bytes(range(72)))
    assert len(exact) == 2
    assert exact[1][0] == 0x06
    assert exact[1][-1] == 0x80


def test_synthetic_bridge_and_both_masked_quotient_identities_accept() -> None:
    instance = _instance()
    report = _evaluate(instance)
    assert report.call_count == 3
    assert report.permutation_count == 7
    assert report.message_rows == 504
    assert report.digest_rows == 192
    assert report.maximum_degree == 3
    assert report.h4_keccak_boundaries_verified == 7
    assert report.direct_h4_byte_states_checked is True
    assert report.primitive_vector_pcs_authenticated is False
    assert report.proof_suite_id is None
    assert report.activation_allowed is False

    challenges = SyntheticQuotientChallenges(17, 65_521, 65_519)
    masks = SyntheticQuotientMasks((3, 5, 7, 11), (13, 17, 19, 23))
    claims = honest_synthetic_quotient_claims(masks, challenges)
    verify_synthetic_quotient_identities(
        instance,
        expected_profile_id=PROFILE,
        expected_capacities=CAPACITIES,
        challenges=challenges,
        masks=masks,
        claims=claims,
    )


@pytest.mark.parametrize(
    ("mutation", "failure"),
    (
        ("live_boundary", "rate_absorb_byte"),
        ("delimiter", "rate_absorb_byte"),
        ("final_bit", "rate_absorb_byte"),
        ("prior_carry", "active_capacity_carry_bit"),
        ("inactive_input", "inactive_input_zero_bit"),
        ("digest", "digest_last_output_byte"),
    ),
)
def test_semantic_h4_mapping_mutations_reject(mutation: str, failure: str) -> None:
    instance = _instance()
    if mutation == "live_boundary":
        call = instance.semantic_calls[1]
        live = list(call.live)
        live[3] = 1
        forged = _replace_semantic(instance, 1, replace(call, live=tuple(live)))
    elif mutation == "delimiter":
        forged = _mutate_boundary(instance, 1, 0, 3, 0x01)
    elif mutation == "final_bit":
        forged = _mutate_boundary(instance, 1, 0, 71, 0x80)
    elif mutation == "prior_carry":
        forged = _mutate_boundary(instance, 2, 1, 72, 0x01)
    elif mutation == "inactive_input":
        forged = _mutate_boundary(instance, 1, 1, 0, 0x01)
    else:
        call = instance.semantic_calls[1]
        digest = bytearray(call.digest)
        digest[0] ^= 1
        forged = _replace_semantic(instance, 1, replace(call, digest=bytes(digest)))
    with pytest.raises(StructuralError, match=failure):
        _evaluate(forged)


def test_profile_call_capacity_and_order_mutations_reject() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="profile_mismatch"):
        evaluate_synthetic_semantic_h4_bridge(
            replace(instance, profile_id="WRONG_PROFILE"),
            expected_profile_id=PROFILE,
            expected_capacities=CAPACITIES,
        )
    call = instance.semantic_calls[1]
    with pytest.raises(StructuralError, match="call_order_mismatch"):
        _evaluate(_replace_semantic(instance, 1, replace(call, call_index=7)))
    with pytest.raises(StructuralError, match="capacity_mismatch"):
        evaluate_synthetic_semantic_h4_bridge(
            instance,
            expected_profile_id=PROFILE,
            expected_capacities=(0, 72, 144),
        )
    with pytest.raises(StructuralError, match="call_order_mismatch"):
        _evaluate(replace(instance, h4_calls=tuple(reversed(instance.h4_calls))))


def test_prechallenge_quotient_claim_does_not_absorb_delimiter_mutation() -> None:
    instance = _instance()
    challenges = SyntheticQuotientChallenges(29, 65_521, 65_519)
    masks = SyntheticQuotientMasks((31, 37, 41), (43, 47, 53))
    claims = honest_synthetic_quotient_claims(masks, challenges)
    forged = _mutate_boundary(instance, 1, 0, 3, 0x01)
    with pytest.raises(StructuralError, match="quotient_identity_failed:message"):
        verify_synthetic_quotient_identities(
            forged,
            expected_profile_id=PROFILE,
            expected_capacities=CAPACITIES,
            challenges=challenges,
            masks=masks,
            claims=claims,
        )
