"""Deterministic 19-claim fixture shared by current host verifier KATs."""

import cuda_fp16_zk_rs_interleaved_k128_prototype as core
from cuda_fp16_tower_kat import add, mul16, sub


INTERLEAVINGS = 512
WORDS_PER_BOUNDARY = 256
FP16_SIZE = 64
ZERO = (0,) * 16
ONE = (1,) + (0,) * 15
FIXTURE_POSITION_SLOPE = 2_654_435_761
FIXTURE_BOUNDARY_SLOPE = 32_452_843
FIXTURE_SEGMENT_SLOPE = 49_979_687
FIXTURE_WORD_SLOPE = 67_867_967
FIXTURE_COMPONENT_SLOPE = 86_028_121
FIXTURE_WORDS_PER_SEGMENT = 16


def fp16_value(value, coordinate=0):
    coordinates = [0] * 16
    coordinates[coordinate] = value % core.Q
    return tuple(coordinates)


def encode_fp16(value):
    return b"".join(coordinate.to_bytes(4, "big") for coordinate in value)


def decode_fp16(payload):
    if len(payload) != FP16_SIZE:
        raise AssertionError("fp16_payload_size")
    return tuple(
        int.from_bytes(payload[4 * index : 4 * index + 4], "big")
        for index in range(16)
    )


def full_fold_weights(point):
    weights = []
    for index in range(1 << len(point)):
        weight = ONE
        for variable, challenge in enumerate(point):
            weight = mul16(
                weight,
                challenge
                if index & (1 << variable)
                else sub(ONE, challenge),
            )
        weights.append(weight)
    return tuple(weights)


def encode_claim(claim):
    (
        boundary,
        coefficient,
        value,
        shard_query,
        point,
        component_evaluations,
    ) = claim
    if len(point) != 24:
        raise AssertionError("gkr_claim_point_dimension")
    if len(component_evaluations) != 16:
        raise AssertionError("gkr_claim_component_count")
    return (
        boundary.to_bytes(4, "big")
        + encode_fp16(coefficient)
        + encode_fp16(value)
        + encode_fp16(shard_query)
        + b"".join(encode_fp16(coordinate) for coordinate in point)
        + b"".join(
            encode_fp16(evaluation)
            for evaluation in component_evaluations
        )
    )


def lagrange_weights(query):
    weights = []
    for node in range(16):
        numerator = 1
        denominator = 1
        for other in range(16):
            if other == node:
                continue
            numerator = numerator * (query - other) % core.Q
            denominator = denominator * (node - other) % core.Q
        weights.append(
            numerator * pow(denominator, core.Q - 2, core.Q) % core.Q
        )
    return tuple(fp16_value(weight) for weight in weights)


def fixture_claims_and_rows():
    claims = []
    all_rows = []
    for ordinal in range(5):
        boundary = 0 if ordinal == 0 else 1
        point = tuple(
            fp16_value(
                101 + 1_009 * ordinal + 37 * coordinate,
                (ordinal + coordinate) % 16,
            )
            for coordinate in range(24)
        )
        low_slope = ZERO
        for variable, challenge in enumerate(point[:16]):
            low_slope = add(
                low_slope,
                mul16(
                    challenge,
                    fp16_value(
                        FIXTURE_POSITION_SLOPE * (1 << variable)
                    ),
                ),
            )
        rows = []
        for global_word in range(INTERLEAVINGS):
            source_boundary = global_word // WORDS_PER_BOUNDARY
            boundary_word = global_word % WORDS_PER_BOUNDARY
            segment = boundary_word // FIXTURE_WORDS_PER_SEGMENT
            local_word = boundary_word % FIXTURE_WORDS_PER_SEGMENT
            row = []
            for component in range(16):
                constant = (
                    17
                    + source_boundary * FIXTURE_BOUNDARY_SLOPE
                    + segment * FIXTURE_SEGMENT_SLOPE
                    + local_word * FIXTURE_WORD_SLOPE
                    + component * FIXTURE_COMPONENT_SLOPE
                )
                row.append(add(low_slope, fp16_value(constant)))
            rows.append(tuple(row))
        rows = tuple(rows)
        shard_scalar = 31 + 17 * ordinal
        shard_query = fp16_value(shard_scalar)
        high_weights = full_fold_weights(point[16:])
        component_evaluations = []
        for component in range(16):
            evaluation = ZERO
            for word, weight in enumerate(high_weights):
                evaluation = add(
                    evaluation,
                    mul16(
                        rows[boundary * WORDS_PER_BOUNDARY + word][
                            component
                        ],
                        weight,
                    ),
                )
            component_evaluations.append(evaluation)
        component_evaluations = tuple(component_evaluations)
        claim_value = ZERO
        for evaluation, weight in zip(
            component_evaluations,
            lagrange_weights(shard_scalar),
        ):
            claim_value = add(
                claim_value,
                mul16(evaluation, weight),
            )
        claims.append(
            (
                boundary,
                ONE if ordinal == 0 else fp16_value(701 + ordinal),
                claim_value,
                shard_query,
                point,
                component_evaluations,
            )
        )
        all_rows.append(rows)
    for _ in range(14):
        claims.append(
            (
                1,
                ONE,
                ZERO,
                ONE,
                (ZERO,) * 24,
                (ZERO,) * 16,
            )
        )
        all_rows.append(tuple((ZERO,) * 16 for _ in range(INTERLEAVINGS)))
    return tuple(claims), tuple(all_rows)
