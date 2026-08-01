"""Small full-Fp16 semantic KAT for Constructions 6.3, 7.2, and 8.2."""

import hashlib

from cuda_fp16_tower_kat import Q, add, mul16, sub


K = 3
INTERLEAVINGS = 1 << K
MAIN_MESSAGE = 8
MAIN_RANDOMNESS = 2
MAIN_CODE = 16
AUX_MESSAGE = 4
AUX_RANDOMNESS = 2
AUX_CODE = 8
ZERO = (0,) * 16
ONE = (1,) + (0,) * 15
TWO = (2,) + (0,) * 15
INV_TWO = ((Q + 1) // 2,) + (0,) * 15


def element(label, *indices):
    digest = hashlib.sha3_512()
    digest.update(b"BL/PQ512/FP16/THEOREM-8.1-SEMANTIC-KAT/v1")
    digest.update(label)
    for index in indices:
        digest.update(index.to_bytes(8, "big"))
    raw = digest.digest()
    value = tuple(
        int.from_bytes(raw[4 * coordinate : 4 * coordinate + 4], "big")
        % Q
        for coordinate in range(16)
    )
    return value if value != ZERO else ONE


def fp_sum(values):
    result = ZERO
    for value in values:
        result = add(result, value)
    return result


def scale(value, scalar):
    return mul16(value, scalar)


def interpolate(left, right, point):
    return add(left, scale(sub(right, left), point))


def inner(left, right):
    if len(left) != len(right):
        raise AssertionError("inner_product_length")
    return fp_sum(
        scale(left_value, right_value)
        for left_value, right_value in zip(left, right)
    )


def poly_eval(coefficients, point):
    result = ZERO
    for coefficient in reversed(coefficients):
        result = add(scale(result, point), coefficient)
    return result


def encode(message, randomness, code_length):
    coefficients = tuple(message) + tuple(randomness)
    if len(coefficients) > code_length:
        raise AssertionError("encoding_dimension")
    return tuple(
        poly_eval(
            coefficients,
            (position + 1,) + (0,) * 15,
        )
        for position in range(code_length)
    )


def fold_rows(rows, challenge):
    if len(rows) % 2:
        raise AssertionError("fold_rows_even")
    return tuple(
        tuple(
            interpolate(left_value, right_value, challenge)
            for left_value, right_value in zip(rows[index], rows[index + 1])
        )
        for index in range(0, len(rows), 2)
    )


def fold_scalars(values, challenge):
    if len(values) % 2:
        raise AssertionError("fold_scalars_even")
    return tuple(
        interpolate(values[index], values[index + 1], challenge)
        for index in range(0, len(values), 2)
    )


def constraint_at(current_f, current_sl, point):
    folded_f = fold_rows(current_f, point)
    folded_sl = fold_rows(current_sl, point)
    return fp_sum(
        inner(message, linear_form)
        for message, linear_form in zip(folded_f, folded_sl)
    )


def quadratic_coefficients(at_zero, at_one, at_two):
    coefficient_two = scale(
        add(sub(at_two, scale(at_one, TWO)), at_zero),
        INV_TWO,
    )
    coefficient_one = sub(sub(at_one, at_zero), coefficient_two)
    return at_zero, coefficient_one, coefficient_two


def sumcheck_polynomial(
    round_index,
    masks,
    challenges,
    current_f,
    current_sl,
    epsilon,
):
    remaining = K - round_index - 1
    coefficients = [ZERO] * AUX_MESSAGE
    repeated = (1 << remaining,) + (0,) * 15
    current_mask = masks[round_index]
    for degree, coefficient in enumerate(current_mask):
        coefficients[degree] = scale(coefficient, repeated)

    constant_terms = []
    for earlier in range(round_index):
        constant_terms.append(
            scale(
                poly_eval(masks[earlier], challenges[earlier]),
                repeated,
            )
        )
    if remaining:
        tail_repeated = (1 << (remaining - 1),) + (0,) * 15
        for later in range(round_index + 1, K):
            constant_terms.append(
                scale(
                    add(
                        poly_eval(masks[later], ZERO),
                        poly_eval(masks[later], ONE),
                    ),
                    tail_repeated,
                )
            )
    coefficients[0] = add(coefficients[0], fp_sum(constant_terms))

    constraint = quadratic_coefficients(
        constraint_at(current_f, current_sl, ZERO),
        constraint_at(current_f, current_sl, ONE),
        constraint_at(current_f, current_sl, TWO),
    )
    for degree, coefficient in enumerate(constraint):
        coefficients[degree] = add(
            coefficients[degree],
            scale(coefficient, epsilon),
        )
    return tuple(coefficients)


def main():
    messages = tuple(
        tuple(
            element(b"f", word, position)
            for position in range(MAIN_MESSAGE)
        )
        for word in range(INTERLEAVINGS)
    )
    randomness = tuple(
        tuple(
            element(b"r", word, position)
            for position in range(MAIN_RANDOMNESS)
        )
        for word in range(INTERLEAVINGS)
    )
    word_form = tuple(
        element(b"word-form", word)
        for word in range(INTERLEAVINGS)
    )
    position_form = tuple(
        element(b"position-form", position)
        for position in range(MAIN_MESSAGE)
    )
    linear_form = tuple(
        tuple(scale(value, word_form[word]) for value in position_form)
        for word in range(INTERLEAVINGS)
    )
    target = fp_sum(
        inner(message, form)
        for message, form in zip(messages, linear_form)
    )

    masks = tuple(
        tuple(
            element(b"sumcheck-mask", mask, coefficient)
            for coefficient in range(AUX_MESSAGE)
        )
        for mask in range(K)
    )
    mask_randomness = tuple(
        tuple(
            element(b"sumcheck-mask-r", mask, coefficient)
            for coefficient in range(AUX_RANDOMNESS)
        )
        for mask in range(K)
    )
    mask_oracles = tuple(
        encode(mask, random, AUX_CODE)
        for mask, random in zip(masks, mask_randomness)
    )
    mask_target = scale(
        fp_sum(
            poly_eval(mask, (bit,) + (0,) * 15)
            for mask in masks
            for bit in (0, 1)
        ),
        (1 << (K - 1),) + (0,) * 15,
    )

    epsilon = element(b"epsilon")
    challenges = []
    polynomials = []
    current_f = messages
    current_r = randomness
    current_sl = linear_form
    expected_sum = add(scale(target, epsilon), mask_target)
    for round_index in range(K):
        polynomial = sumcheck_polynomial(
            round_index,
            masks,
            challenges,
            current_f,
            current_sl,
            epsilon,
        )
        if add(
            poly_eval(polynomial, ZERO),
            poly_eval(polynomial, ONE),
        ) != expected_sum:
            raise SystemExit(
                f"sumcheck_chain_failed_round={round_index}"
            )
        challenge = element(b"gamma", round_index)
        challenges.append(challenge)
        polynomials.append(polynomial)
        expected_sum = poly_eval(polynomial, challenge)
        current_f = fold_rows(current_f, challenge)
        current_r = fold_rows(current_r, challenge)
        current_sl = fold_rows(current_sl, challenge)

    if len(current_f) != 1 or len(current_sl) != 1:
        raise AssertionError("terminal_fold_shape")
    folded_message = current_f[0]
    folded_randomness = current_r[0]
    folded_form = current_sl[0]
    terminal_target = add(
        scale(inner(folded_message, folded_form), epsilon),
        fp_sum(
            poly_eval(mask, challenge)
            for mask, challenge in zip(masks, challenges)
        ),
    )
    if terminal_target != expected_sum:
        raise SystemExit("terminal_sumcheck_target_failed")

    main_mask = tuple(
        element(b"base-main-mask", position)
        for position in range(MAIN_MESSAGE)
    )
    main_mask_randomness = tuple(
        element(b"base-main-mask-r", position)
        for position in range(MAIN_RANDOMNESS)
    )
    auxiliary_masks = tuple(
        tuple(
            element(b"base-aux-mask", mask, position)
            for position in range(AUX_MESSAGE)
        )
        for mask in range(K)
    )
    auxiliary_randomness = tuple(
        tuple(
            element(b"base-aux-mask-r", mask, position)
            for position in range(AUX_RANDOMNESS)
        )
        for mask in range(K)
    )
    new_target = add(
        scale(inner(main_mask, folded_form), epsilon),
        fp_sum(
            poly_eval(mask, challenge)
            for mask, challenge in zip(auxiliary_masks, challenges)
        ),
    )
    combination = element(b"base-combination")
    answer_message = tuple(
        add(mask, scale(value, combination))
        for mask, value in zip(main_mask, folded_message)
    )
    answer_randomness = tuple(
        add(mask, scale(value, combination))
        for mask, value in zip(
            main_mask_randomness,
            folded_randomness,
        )
    )
    auxiliary_answers = tuple(
        tuple(
            add(mask, scale(value, combination))
            for mask, value in zip(base_mask, sumcheck_mask)
        )
        for base_mask, sumcheck_mask in zip(auxiliary_masks, masks)
    )
    auxiliary_answer_randomness = tuple(
        tuple(
            add(mask, scale(value, combination))
            for mask, value in zip(base_random, sumcheck_random)
        )
        for base_random, sumcheck_random in zip(
            auxiliary_randomness,
            mask_randomness,
        )
    )
    answer_target = add(
        scale(inner(answer_message, folded_form), epsilon),
        fp_sum(
            poly_eval(answer, challenge)
            for answer, challenge in zip(
                auxiliary_answers,
                challenges,
            )
        ),
    )
    if answer_target != add(
        new_target,
        scale(terminal_target, combination),
    ):
        raise SystemExit("base_target_check_failed")

    initial_oracles = tuple(
        encode(message, random, MAIN_CODE)
        for message, random in zip(messages, randomness)
    )
    expected_folded_oracle = tuple(
        fold_scalars(
            tuple(oracle[position] for oracle in initial_oracles),
            challenges[0],
        )
        for position in range(MAIN_CODE)
    )
    for challenge in challenges[1:]:
        expected_folded_oracle = tuple(
            fold_scalars(values, challenge)
            for values in expected_folded_oracle
        )
    expected_folded_oracle = tuple(
        values[0] for values in expected_folded_oracle
    )
    if expected_folded_oracle != encode(
        folded_message,
        folded_randomness,
        MAIN_CODE,
    ):
        raise SystemExit("main_encoding_fold_linearity_failed")

    main_mask_oracle = encode(
        main_mask,
        main_mask_randomness,
        MAIN_CODE,
    )
    answer_oracle = encode(
        answer_message,
        answer_randomness,
        MAIN_CODE,
    )
    for query in (1, 7, 13):
        if answer_oracle[query] != add(
            main_mask_oracle[query],
            scale(expected_folded_oracle[query], combination),
        ):
            raise SystemExit("main_spotcheck_failed")
    for mask_index in range(K):
        base_oracle = encode(
            auxiliary_masks[mask_index],
            auxiliary_randomness[mask_index],
            AUX_CODE,
        )
        auxiliary_answer_oracle = encode(
            auxiliary_answers[mask_index],
            auxiliary_answer_randomness[mask_index],
            AUX_CODE,
        )
        for query in (0, 3, 6):
            if auxiliary_answer_oracle[query] != add(
                base_oracle[query],
                scale(mask_oracles[mask_index][query], combination),
            ):
                raise SystemExit("auxiliary_spotcheck_failed")

    print("kat=fp16_zk_rs_theorem8_1_semantics_v1")
    print("field=fp16_over_m31")
    print(f"sumcheck_rounds={K}")
    print(f"initial_interleaving={INTERLEAVINGS}")
    print("sumcheck_chain_verified=true")
    print("terminal_target_verified=true")
    print("base_target_verified=true")
    print("main_encoding_fold_linearity_verified=true")
    print("main_spotchecks_verified=true")
    print("auxiliary_spotchecks_verified=true")
    print("full_width_challenges=true")
    print("production_geometry=false")
    print("proof_system_qualification=false")


if __name__ == "__main__":
    main()
