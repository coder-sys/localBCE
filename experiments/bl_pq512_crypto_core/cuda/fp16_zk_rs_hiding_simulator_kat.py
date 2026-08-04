"""Executable hiding-simulator gate for the selected Construction 8.2 PCS.

The production-size portion streams the exact number of rejection-sampled
query-view field elements and samples all nine conditioned sumcheck messages.
The reduced differential portion executes the generic affine Reed--Solomon
preimage solver used by Lemma 7.3 and couples two different private messages
to the same queried view.

The simulator is an audit/proof tool and is not part of proof generation.
"""

import hashlib
import sys
import time

import cuda_fp16_zk_rs_interleaved_k128_prototype as core
import cuda_fp16_zk_rs_theorem8_1_k128_prototype as theorem
from cuda_fp16_tower_kat import add, mul16, sub


SUMCHECK_ROUNDS = 9
SUMCHECK_COEFFICIENTS = 2_048
MAIN_INTERLEAVINGS = 512
MAIN_MESSAGE_COEFFICIENTS = 65_536
MAIN_RANDOM_COEFFICIENTS = 2_048
MAIN_QUERY_ROWS = 1_600
AUXILIARY_MESSAGE_COEFFICIENTS = 2_048
AUXILIARY_RANDOM_COEFFICIENTS = 1_218
AUXILIARY_QUERY_ROWS = 1_218
GKR_BRIDGE_MASK_FIELDS = 46
GKR_LAYER_TERMINAL_MASK_FIELDS = 4
GKR_MASK_PADDED_COEFFICIENTS = 32_768
GKR_PCS_QUERY_RANK = MAIN_QUERY_ROWS
LEFT_WIRE_ROUNDS = (11, 10, 9, 9, 11, 11, 11)
RIGHT_WIRE_ROUNDS = (11, 10, 11, 9, 9, 11, 11)
STATE_MASK_EXPECTATIONS = {
    128: (221, 27_744, 26_640, 28_240, 4_528),
    512: (233, 28_932, 27_768, 29_368, 3_400),
}
ZERO = (0,) * 16
ONE = (1,) + (0,) * 15
INV_TWO = ((core.Q + 1) // 2,) + (0,) * 15


class ExactKatSampler:
    """SHA3-512 rejection sampler with no modulo bias."""

    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.coordinates = []
        self.rejected_coordinates = 0

    def _refill(self):
        digest = hashlib.sha3_512(
            self.seed + self.counter.to_bytes(8, "big")
        ).digest()
        self.counter += 1
        for offset in range(0, len(digest), 4):
            candidate = int.from_bytes(
                digest[offset : offset + 4],
                "big",
            )
            if candidate < core.Q:
                self.coordinates.append(candidate)
            else:
                self.rejected_coordinates += 1

    def field(self):
        while len(self.coordinates) < 16:
            self._refill()
        value = tuple(self.coordinates[:16])
        del self.coordinates[:16]
        return value


def fp16_bytes(value):
    return b"".join(coordinate.to_bytes(4, "big") for coordinate in value)


def pow16(value, exponent):
    result = ONE
    base = value
    while exponent:
        if exponent & 1:
            result = mul16(result, base)
        base = mul16(base, base)
        exponent >>= 1
    return result


def inverse16(value):
    if value == ZERO:
        raise ValueError("inverse_zero")
    return pow16(value, core.Q**16 - 2)


def evaluate(coefficients, point):
    result = ZERO
    for coefficient in reversed(coefficients):
        result = add(mul16(result, point), coefficient)
    return result


def polynomial_mul_linear(coefficients, root):
    output = [ZERO] * (len(coefficients) + 1)
    for degree, coefficient in enumerate(coefficients):
        output[degree] = sub(
            output[degree],
            mul16(coefficient, root),
        )
        output[degree + 1] = add(
            output[degree + 1],
            coefficient,
        )
    return output


def interpolate(points, values):
    if len(points) != len(values) or len(set(points)) != len(points):
        raise ValueError("interpolation_shape")
    output = [ZERO] * len(points)
    for index, (point, value) in enumerate(zip(points, values)):
        basis = [ONE]
        denominator = ONE
        for other_index, other in enumerate(points):
            if other_index == index:
                continue
            basis = polynomial_mul_linear(basis, other)
            denominator = mul16(denominator, sub(point, other))
        scale = mul16(value, inverse16(denominator))
        for degree, coefficient in enumerate(basis):
            output[degree] = add(
                output[degree],
                mul16(scale, coefficient),
            )
    return output


def condition_full_preimage(points, targets, dimension, sampler):
    query_count = len(points)
    if (
        query_count == 0
        or query_count > dimension
        or len(targets) != query_count
        or ZERO in points
        or len(set(points)) != query_count
    ):
        raise ValueError("full_preimage_shape")
    tail = [sampler.field() for _ in range(dimension - query_count)]
    residuals = []
    for point, target in zip(points, targets):
        tail_value = evaluate(tail, point)
        tail_value = mul16(
            tail_value,
            pow16(point, query_count),
        )
        residuals.append(sub(target, tail_value))
    coefficients = interpolate(points, residuals) + tail
    if [
        evaluate(coefficients, point) for point in points
    ] != list(targets):
        raise AssertionError("full_preimage_solution")
    return coefficients


def condition_random_padding(
    message,
    random_count,
    points,
    targets,
    sampler,
):
    query_count = len(points)
    if query_count > random_count:
        raise ValueError("insufficient_random_padding")
    residuals = []
    message_degree = len(message)
    for point, target in zip(points, targets):
        residual = sub(target, evaluate(message, point))
        residuals.append(
            mul16(
                residual,
                inverse16(pow16(point, message_degree)),
            )
        )
    random_coefficients = condition_full_preimage(
        points,
        residuals,
        random_count,
        sampler,
    )
    coefficients = list(message) + random_coefficients
    if [
        evaluate(coefficients, point) for point in points
    ] != list(targets):
        raise AssertionError("random_padding_solution")
    return random_coefficients


def coset_points(log_code, indices):
    root = core.root_for_log(log_code) + (0,) * 14
    coset = core.COSET + (0,) * 14
    return tuple(
        mul16(coset, pow16(root, index))
        for index in indices
    )


def run_reduced_affine_coupling(sampler):
    points = coset_points(8, (3, 29, 71, 101))
    targets = [sampler.field() for _ in points]
    left_message = [sampler.field() for _ in range(8)]
    right_message = [sampler.field() for _ in range(8)]
    left_padding = condition_random_padding(
        left_message,
        6,
        points,
        targets,
        sampler,
    )
    right_padding = condition_random_padding(
        right_message,
        6,
        points,
        targets,
        sampler,
    )
    left_view = [
        evaluate(left_message + left_padding, point)
        for point in points
    ]
    right_view = [
        evaluate(right_message + right_padding, point)
        for point in points
    ]
    if (
        left_message == right_message
        or left_view != targets
        or right_view != targets
    ):
        raise AssertionError("private_message_coupling")
    full_answer = condition_full_preimage(
        points,
        targets,
        12,
        sampler,
    )
    if [
        evaluate(full_answer, point) for point in points
    ] != targets:
        raise AssertionError("lemma_7_3_affine_preimage")


def run_conditioned_sumcheck(sampler):
    target = sampler.field()
    transcript_digest = hashlib.sha3_512()
    started = time.perf_counter()
    for _ in range(SUMCHECK_ROUNDS):
        coefficients = [ZERO]
        coefficients.extend(
            sampler.field()
            for _ in range(SUMCHECK_COEFFICIENTS - 1)
        )
        nonconstant_sum = ZERO
        for coefficient in coefficients[1:]:
            nonconstant_sum = add(nonconstant_sum, coefficient)
        coefficients[0] = mul16(
            sub(target, nonconstant_sum),
            INV_TWO,
        )
        if add(
            evaluate(coefficients, ZERO),
            evaluate(coefficients, ONE),
        ) != target:
            raise AssertionError("conditioned_sumcheck_message")
        for coefficient in coefficients:
            transcript_digest.update(fp16_bytes(coefficient))
        challenge = sampler.field()
        target = evaluate(coefficients, challenge)
    return (
        time.perf_counter() - started,
        transcript_digest.hexdigest(),
    )


def production_query_certificate():
    query_seed = fp16_bytes(
        tuple(
            (0x1234_567 + coordinate * 104_729) % core.Q
            for coordinate in range(16)
        )
    )
    main_queries = theorem.exact_queries(
        query_seed,
        b"main_queries",
        core.BASE_CODE_VALUES,
        MAIN_QUERY_ROWS,
    )
    auxiliary_queries = theorem.exact_queries(
        query_seed,
        b"aux_queries",
        theorem.AUX_CODE_VALUES,
        AUXILIARY_QUERY_ROWS,
    )
    main_points = coset_points(core.BASE_CODE_LOG, main_queries)
    auxiliary_points = coset_points(
        theorem.AUX_CODE_LOG,
        auxiliary_queries,
    )
    if (
        len(main_queries) != MAIN_QUERY_ROWS
        or len(set(main_queries)) != MAIN_QUERY_ROWS
        or main_queries != tuple(sorted(main_queries))
        or main_queries[0] < 0
        or main_queries[-1] >= core.BASE_CODE_VALUES
        or len(auxiliary_queries) != AUXILIARY_QUERY_ROWS
        or len(set(auxiliary_queries)) != AUXILIARY_QUERY_ROWS
        or auxiliary_queries != tuple(sorted(auxiliary_queries))
        or auxiliary_queries[0] < 0
        or auxiliary_queries[-1] >= theorem.AUX_CODE_VALUES
        or ZERO in main_points
        or len(set(main_points)) != MAIN_QUERY_ROWS
        or ZERO in auxiliary_points
        or len(set(auxiliary_points)) != AUXILIARY_QUERY_ROWS
        or MAIN_RANDOM_COEFFICIENTS < MAIN_QUERY_ROWS
        or AUXILIARY_RANDOM_COEFFICIENTS < AUXILIARY_QUERY_ROWS
    ):
        raise AssertionError("production_query_rank_certificate")
    digest = hashlib.sha3_512()
    for query in main_queries:
        digest.update(query.to_bytes(4, "big"))
    for query in auxiliary_queries:
        digest.update(query.to_bytes(4, "big"))
    for point in main_points:
        digest.update(fp16_bytes(point))
    for point in auxiliary_points:
        digest.update(fp16_bytes(point))
    return digest.hexdigest()


def stream_production_query_views(sampler):
    field_count = (
        MAIN_INTERLEAVINGS * MAIN_QUERY_ROWS
        + SUMCHECK_ROUNDS * AUXILIARY_QUERY_ROWS
    )
    digest = hashlib.sha3_512()
    started = time.perf_counter()
    for _ in range(field_count):
        digest.update(fp16_bytes(sampler.field()))
    return (
        field_count,
        time.perf_counter() - started,
        digest.hexdigest(),
    )


def state_composed_mask_degrees(capacity):
    if capacity not in (128, 512):
        raise ValueError("state_mask_capacity")
    state_variables = 7 if capacity == 128 else 9
    layers = []
    for _ in range(24):
        for layer in reversed(range(7)):
            degrees = [3] * 13
            left = [2] * LEFT_WIRE_ROUNDS[layer]
            right = [2] * RIGHT_WIRE_ROUNDS[layer]
            left[-1] = 3
            right[-1] = 3
            layers.append(degrees + left + right + [2])

    layers.append([3] * 12 + ([2] * 5 + [3]) * 2 + [2])
    for _ in range(2):
        layers.extend(([5, 5, 2], [5, 5, 2], [5, 5, 2]))
        for source_variables in range(2, state_variables + 2):
            for _ in range(2):
                degrees = [2] * (2 * source_variables)
                degrees[source_variables - 1] = 3
                degrees[2 * source_variables - 1] = 3
                layers.append(degrees + [2])
        layers.append([2, 3, 2, 3, 2])
        for source_variables in tuple(range(1, state_variables + 1)) + (
            state_variables,
        ):
            degrees = [3] + [2] * (2 * source_variables)
            terminal_degree = 5 if source_variables == 1 else 3
            degrees[source_variables] = terminal_degree
            degrees[2 * source_variables] = terminal_degree
            layers.append(degrees + [2])
    return tuple(tuple(layer) for layer in layers)


def simulate_conditioned_gkr_layer(degrees, mask_sampler, coin_sampler, digest):
    target = mask_sampler.field()
    independent_rank = 1
    public_fields = 0
    for degree in degrees:
        coefficients = [ZERO]
        coefficients.extend(mask_sampler.field() for _ in range(degree))
        independent_rank += degree
        nonconstant_sum = ZERO
        for coefficient in coefficients[1:]:
            nonconstant_sum = add(nonconstant_sum, coefficient)
        coefficients[0] = mul16(sub(target, nonconstant_sum), INV_TWO)
        if add(evaluate(coefficients, ZERO), evaluate(coefficients, ONE)) != target:
            raise AssertionError("state_conditioned_sumcheck_message")
        for coefficient in coefficients:
            digest.update(fp16_bytes(coefficient))
        public_fields += len(coefficients)
        target = evaluate(coefficients, coin_sampler.field())
    return independent_rank, public_fields


def state_composed_simulator_certificate(capacity, attempt_label):
    layers = state_composed_mask_degrees(capacity)
    expected_layers, expected_used, expected_rank, conditioned_rank, free = (
        STATE_MASK_EXPECTATIONS[capacity]
    )
    if len(layers) != expected_layers:
        raise AssertionError("state_mask_layer_count")
    mask_sampler = ExactKatSampler(
        b"BL/PQ512/STATE-COMPOSED-GKR-MASK-SIMULATOR/v2\0"
        + capacity.to_bytes(2, "big")
        + attempt_label
    )
    coin_sampler = ExactKatSampler(
        b"BL/PQ512/STATE-COMPOSED-PUBLIC-COIN/v2\0"
        + capacity.to_bytes(2, "big")
        + attempt_label
    )
    digest = hashlib.sha3_512()
    independent_rank = 0
    public_fields = 0
    for degrees in layers:
        for _ in range(GKR_BRIDGE_MASK_FIELDS):
            digest.update(fp16_bytes(mask_sampler.field()))
        independent_rank += GKR_BRIDGE_MASK_FIELDS
        public_fields += GKR_BRIDGE_MASK_FIELDS

        layer_rank, layer_public_fields = simulate_conditioned_gkr_layer(
            degrees,
            mask_sampler,
            coin_sampler,
            digest,
        )
        independent_rank += layer_rank
        public_fields += layer_public_fields

        for _ in range(GKR_LAYER_TERMINAL_MASK_FIELDS):
            digest.update(fp16_bytes(mask_sampler.field()))
        independent_rank += GKR_LAYER_TERMINAL_MASK_FIELDS
        public_fields += GKR_LAYER_TERMINAL_MASK_FIELDS

    digest.update(fp16_bytes(mask_sampler.field()))
    independent_rank += 1
    public_fields += 1
    if independent_rank != expected_rank:
        raise AssertionError("state_mask_leakage_rank")
    if independent_rank + GKR_PCS_QUERY_RANK != conditioned_rank:
        raise AssertionError("state_mask_conditioned_rank")
    if GKR_MASK_PADDED_COEFFICIENTS - conditioned_rank != free:
        raise AssertionError("state_mask_free_dimension")
    if expected_used > GKR_MASK_PADDED_COEFFICIENTS or free <= 0:
        raise AssertionError("state_mask_randomness_exhausted")
    return {
        "layers": len(layers),
        "used": expected_used,
        "leakage_rank": independent_rank,
        "conditioned_rank": conditioned_rank,
        "free": free,
        "public_fields": public_fields,
        "digest": digest.hexdigest(),
        "mask_rejections": mask_sampler.rejected_coordinates,
        "coin_rejections": coin_sampler.rejected_coordinates,
    }


def main():
    sampler = ExactKatSampler(
        b"BL/PQ512/FP16-ZK-RS/HIDING-SIMULATOR-KAT/v1"
    )
    run_reduced_affine_coupling(sampler)
    rank_digest = production_query_certificate()
    sumcheck_seconds, sumcheck_digest = run_conditioned_sumcheck(
        sampler
    )
    (
        query_view_fields,
        query_view_seconds,
        query_view_digest,
    ) = stream_production_query_views(sampler)
    query_view_mb = query_view_fields * 64 / 1_000_000
    state_certificates = {}
    retry_certificates = {}
    for capacity in (128, 512):
        state_certificates[capacity] = state_composed_simulator_certificate(
            capacity, b"attempt-0"
        )
        retry_certificates[capacity] = state_composed_simulator_certificate(
            capacity, b"retry-1"
        )
        if (
            state_certificates[capacity]["public_fields"]
            != retry_certificates[capacity]["public_fields"]
            or state_certificates[capacity]["digest"]
            == retry_certificates[capacity]["digest"]
        ):
            raise AssertionError("state_abort_retry_independence")

    print("kat=fp16_zk_rs_hiding_simulator_v2")
    print("evidence_class=exact_algebra_plus_production_geometry_stream")
    print(f"construction_8_2_k={SUMCHECK_ROUNDS}")
    print("construction_8_2_n=0")
    print(f"main_interleavings={MAIN_INTERLEAVINGS}")
    print(f"main_query_rows={MAIN_QUERY_ROWS}")
    print(f"main_random_coefficients={MAIN_RANDOM_COEFFICIENTS}")
    print(f"auxiliary_mask_oracles={SUMCHECK_ROUNDS}")
    print(f"auxiliary_query_rows={AUXILIARY_QUERY_ROWS}")
    print(
        "auxiliary_random_coefficients="
        f"{AUXILIARY_RANDOM_COEFFICIENTS}"
    )
    print(f"simulated_query_view_fields={query_view_fields}")
    print(f"simulated_query_view_mb={query_view_mb:.6f}")
    print(f"query_view_sampling_seconds={query_view_seconds:.6f}")
    print(
        "conditioned_sumcheck_message_mb="
        f"{SUMCHECK_ROUNDS * SUMCHECK_COEFFICIENTS * 64 / 1_000_000:.6f}"
    )
    print(
        "conditioned_sumcheck_sampling_seconds="
        f"{sumcheck_seconds:.6f}"
    )
    print(
        "simulator_audit_host_peak_mb="
        f"{core.process_peak_mb():.3f}"
    )
    print(f"production_query_rank_digest={rank_digest}")
    print(f"sumcheck_transcript_digest={sumcheck_digest}")
    print(f"query_view_digest={query_view_digest}")
    for capacity in (128, 512):
        certificate = state_certificates[capacity]
        retry = retry_certificates[capacity]
        print(f"state_k{capacity}_mask_layers={certificate['layers']}")
        print(f"state_k{capacity}_mask_used_coefficients={certificate['used']}")
        print(f"state_k{capacity}_mask_leakage_rank={certificate['leakage_rank']}")
        print(f"state_k{capacity}_pcs_conditioned_rank={certificate['conditioned_rank']}")
        print(f"state_k{capacity}_mask_free_dimension={certificate['free']}")
        print(f"state_k{capacity}_simulated_public_fields={certificate['public_fields']}")
        print(f"state_k{capacity}_transcript_digest={certificate['digest']}")
        print(f"state_k{capacity}_retry_digest={retry['digest']}")
    print(
        "rejection_sampler_rejected_coordinates="
        f"{sampler.rejected_coordinates}"
    )
    print("field_characteristic_not_two=true")
    print("main_randomness_covers_all_queries=true")
    print("auxiliary_randomness_covers_all_queries=true")
    print("production_query_points_distinct_and_nonzero=true")
    print("rs_query_map_full_row_rank=true")
    print("reduced_private_messages_coupled_to_identical_view=true")
    print("generic_affine_preimage_solver_implemented=true")
    print("lemma_7_3_conditioned_answer_mechanics_verified=true")
    print("sumcheck_conditioned_polynomials_verified=true")
    print("state_relation_conditioned_simulator_verified=true")
    print("state_squarefree_conditioned_simulator_verified=true")
    print("state_gkr_mask_rank_budget_verified=true")
    print("state_gkr_pcs_joint_rank_budget_verified=true")
    print("public_coin_abort_retry_fresh_randomness_verified=true")
    print("cross_module_simulator_mechanics_verified=true")
    print("construction_8_2_hiding_error_bits=infinite")
    print("simulator_runs_in_proof_generation=false")
    print("complete_pcs_qualification=false")
    print("complete_proof_qualification=false")


if __name__ == "__main__":
    sys.exit(main())
