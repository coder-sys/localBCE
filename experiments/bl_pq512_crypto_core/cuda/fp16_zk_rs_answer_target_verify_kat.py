"""Production-geometry KAT for the independent Construction 8.2 target gate.

The fixture uses one nonzero main answer coefficient and one nonzero GKR-mask
auxiliary coefficient, derives the exact mixed target independently in Python,
and checks both opening families.  The BLSQAB02 fixture additionally binds two
public masked coefficient claims to the pre-kind799 BLSQCL02 digest and to the
raw coefficient plus verifier-derived GKR-mask functional.

This is a host-only verifier gate.  It does not run CUDA and does not qualify a
complete PCS or proof.
"""

import hashlib
import struct
import subprocess
import sys
import time
from pathlib import Path

import cuda_fp16_zk_rs_interleaved_k128_prototype as core
import fp16_zk_rs_binding_fixture as binding_kat
from cuda_fp16_tower_kat import add, mul16, sub


MAIN_LOG = 17
MAIN_DIMENSION = 67_584
AUXILIARY_LOG = 13
AUXILIARY_DIMENSION = 3_266
AUXILIARY_WORDS = 10
SUMCHECK_WORDS = 9
GKR_MASK_WORDS = 64
GKR_MASK_DIMENSION = 64 * 512
QUERY_DOMAIN = 524
QUERY_MAX_DRAWS = 1 << 20
QUERY_MAX_RETRIES_PER_DRAW = 1 << 20
QUERY_SEED = binding_kat.encode_fp16(
    binding_kat.fp16_value(91_337, 5)
)


def exact_queries(state, label, bound, count):
    threshold = ((1 << 64) - bound) % bound
    queries = []
    seen = set()
    draw = 0
    while len(queries) < count:
        if draw >= QUERY_MAX_DRAWS:
            raise AssertionError("query_draw_limit")
        retry = 0
        while True:
            if retry >= QUERY_MAX_RETRIES_PER_DRAW:
                raise AssertionError("query_retry_limit")
            digest = core.sha3_parts(
                QUERY_DOMAIN,
                (
                    state,
                    label,
                    draw.to_bytes(8, "big"),
                    retry.to_bytes(8, "big"),
                ),
            )
            random_word = int.from_bytes(digest[:8], "little")
            product = random_word * bound
            if (product & ((1 << 64) - 1)) >= threshold:
                candidate = product >> 64
                if candidate not in seen:
                    seen.add(candidate)
                    queries.append(candidate)
                    break
            retry += 1
        draw += 1
    return tuple(sorted(queries))


MAIN_QUERIES = exact_queries(
    QUERY_SEED,
    b"main_queries",
    1 << MAIN_LOG,
    1_600,
)
AUXILIARY_QUERIES = exact_queries(
    QUERY_SEED,
    b"aux_queries",
    1 << AUXILIARY_LOG,
    1_218,
)
WORD_CHALLENGES = tuple(
    binding_kat.fp16_value(401 + 211 * ordinal, (5 * ordinal + 1) % 16)
    for ordinal in range(9)
)
CLAIM_CHALLENGE = binding_kat.fp16_value(17_111, 3)
COORDINATE_CHALLENGE = binding_kat.fp16_value(29_003, 7)
ZERO = binding_kat.ZERO
ONE = binding_kat.ONE
MAIN_SCALE = binding_kat.fp16_value(7, 2)
SQUAREFREE_CAPACITY = 128
SQUAREFREE_VALUES = tuple(
    binding_kat.fp16_value(value)
    for value in (2, 5)
)
SQUAREFREE_MIXING = tuple(
    binding_kat.fp16_value(value)
    for value in (11, 17)
)
SQUAREFREE_ROOT = bytes([0x5A]) * 64
SQUAREFREE_POINTS = tuple(
    tuple(
        binding_kat.fp16_value(101 + 17 * phase + coordinate)
        for coordinate in range(7)
    )
    + (ZERO, ZERO, binding_kat.fp16_value(211 + phase))
    + (ONE if phase else ZERO,)
    for phase in range(2)
)
SQUAREFREE_MASK_GLOBAL_COEFFICIENT = 27_735
H4_MASKED_SOURCE_FUNCTIONAL_BINDING_DOMAIN = (
    b"BL/PQ512/WAVE2/H4-MASKED-SOURCE-FUNCTIONAL-BINDING/v1\0"
)


def h4_masked_source_functional_binding():
    point = [ZERO] * 29
    # The sole nonzero main coefficient is at low index zero. Fixing the first
    # coefficient coordinate to one makes both tagged source functionals zero
    # for this KAT without encoding any raw source evaluation.
    point[4] = ONE
    left_challenge = binding_kat.fp16_value(2)
    right_challenge = binding_kat.fp16_value(3)
    w_challenge = binding_kat.fp16_value(5)
    complete_mask_challenge = binding_kat.fp16_value(7)
    padding_mix = binding_kat.fp16_value(11)
    masked_right = sub(ZERO, sub(ONE, right_challenge))
    encoded = bytearray(b"BLH4SF01")
    encoded.extend((1).to_bytes(2, "big"))
    encoded.extend(bytes((1, 2)))
    encoded.extend(b"\0" * 4)
    encoded.extend(bytes([0x31]) * 64)
    encoded.extend(bytes([0x52]) * 64)
    encoded.extend(bytes([0x73]) * 64)
    for coordinate in point:
        encoded.extend(binding_kat.encode_fp16(coordinate))
    for value in (
        left_challenge,
        right_challenge,
        w_challenge,
        ZERO,
        masked_right,
    ):
        encoded.extend(binding_kat.encode_fp16(value))
    encoded.extend(bytes([0x94]) * 64)
    for coordinate in point:
        encoded.extend(binding_kat.encode_fp16(coordinate))
    encoded.extend(binding_kat.encode_fp16(ZERO))
    encoded.extend(binding_kat.encode_fp16(padding_mix))
    encoded.extend(binding_kat.encode_fp16(complete_mask_challenge))
    encoded.extend(
        hashlib.sha3_512(
            H4_MASKED_SOURCE_FUNCTIONAL_BINDING_DOMAIN + encoded
        ).digest()
    )
    if len(encoded) != 4_560:
        raise AssertionError("h4_source_binding_size")
    return bytes(encoded)


def squarefree_claims_payload(
    root=SQUAREFREE_ROOT,
    capacity=SQUAREFREE_CAPACITY,
    points=SQUAREFREE_POINTS,
    values=SQUAREFREE_VALUES,
):
    preimage = bytearray(
        b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0"
        + root
        + capacity.to_bytes(2, "big")
        + len(points).to_bytes(2, "big")
    )
    for point, value in zip(points, values):
        preimage.extend(len(point).to_bytes(2, "big"))
        for coordinate in point:
            preimage.extend(binding_kat.encode_fp16(coordinate))
        preimage.extend(binding_kat.encode_fp16(value))
    return (
        b"BLSQCL02"
        + root
        + capacity.to_bytes(2, "big")
        + len(points).to_bytes(2, "big")
        + hashlib.sha3_512(preimage).digest()
    )


def squarefree_binding_payload(
    claims_payload=None,
    points=SQUAREFREE_POINTS,
    values=SQUAREFREE_VALUES,
    mixing=SQUAREFREE_MIXING,
):
    if claims_payload is None:
        claims_payload = squarefree_claims_payload(
            points=points,
            values=values,
        )
    encoded = bytearray(b"BLSQAB02" + claims_payload)
    for point, value in zip(points, values):
        encoded.extend(struct.pack(">H", 11))
        encoded.extend(b"\0" * 6)
        for coordinate in point:
            encoded.extend(binding_kat.encode_fp16(coordinate))
        encoded.extend(binding_kat.encode_fp16(value))
    for value in mixing:
        encoded.extend(binding_kat.encode_fp16(value))
    return bytes(encoded)


def squarefree_target():
    result = ZERO
    for value, mixing in zip(SQUAREFREE_VALUES, SQUAREFREE_MIXING):
        result = add(result, mul16(value, mixing))
    return result


def equality_weight(index, point):
    weight = ONE
    for variable, challenge in enumerate(point):
        weight = mul16(
            weight,
            challenge
            if index & (1 << variable)
            else sub(ONE, challenge),
        )
    return weight


def coordinate_batch(value):
    result = ZERO
    power = ONE
    for coordinate in value:
        result = add(
            result,
            mul16(
                power,
                binding_kat.fp16_value(coordinate),
            ),
        )
        power = mul16(power, COORDINATE_CHALLENGE)
    return result


def expected_main_target(claims):
    """Target for a main answer whose sole nonzero coefficient is one at 0."""
    result = ZERO
    claim_power = ONE
    for claim in claims:
        boundary, _, _, _, point, _ = claim
        boundary_weight = (
            sub(ONE, WORD_CHALLENGES[8])
            if boundary == 0
            else WORD_CHALLENGES[8]
        )
        low_weight = equality_weight(0, point[:16])
        high_sum = ZERO
        for word in range(256):
            folded_word = equality_weight(word, WORD_CHALLENGES[:8])
            high_weight = equality_weight(word, point[16:])
            high_sum = add(
                high_sum,
                mul16(
                    folded_word,
                    coordinate_batch(mul16(low_weight, high_weight)),
                ),
            )
        result = add(
            result,
            mul16(
                mul16(claim_power, boundary_weight),
                high_sum,
            ),
        )
        claim_power = mul16(claim_power, CLAIM_CHALLENGE)
    return result


def payload(
    claims,
    main_scale,
    expected_target,
    answer_value,
    gkr_relation_terminals,
    gkr_mask_answer_value,
    squarefree_mask_answer_value=ZERO,
    squarefree_raw_delta=ZERO,
    squarefree_binding=None,
    squarefree_claims=None,
    h4_source_binding=None,
):
    encoded = bytearray(b"BLRSCV07")
    encoded.extend(
        struct.pack(
            ">7I",
            MAIN_LOG,
            MAIN_DIMENSION,
            AUXILIARY_LOG,
            AUXILIARY_DIMENSION,
            AUXILIARY_WORDS,
            len(MAIN_QUERIES),
            len(AUXILIARY_QUERIES),
        )
    )
    encoded.extend(struct.pack(f">{len(MAIN_QUERIES)}I", *MAIN_QUERIES))
    encoded.extend(
        struct.pack(
            f">{len(AUXILIARY_QUERIES)}I",
            *AUXILIARY_QUERIES,
        )
    )
    encoded.extend(QUERY_SEED)
    encoded.extend(binding_kat.encode_fp16(CLAIM_CHALLENGE))
    encoded.extend(binding_kat.encode_fp16(COORDINATE_CHALLENGE))
    for claim in claims:
        encoded.extend(binding_kat.encode_claim(claim))
    for challenge in WORD_CHALLENGES:
        encoded.extend(binding_kat.encode_fp16(challenge))
    for terminal in gkr_relation_terminals:
        encoded.extend(binding_kat.encode_fp16(terminal))
    encoded.extend(binding_kat.encode_fp16(main_scale))
    binding = (
        squarefree_binding_payload()
        if squarefree_binding is None
        else squarefree_binding
    )
    claims = binding[8:148] if squarefree_claims is None else squarefree_claims
    encoded.extend(claims)
    encoded.extend(binding)
    encoded.extend(
        h4_masked_source_functional_binding()
        if h4_source_binding is None
        else h4_source_binding
    )
    # BLRSCV07 carries the base squarefree opening and the current opening
    # separately.  Keep the fixture's base state immutable so the mutation
    # cases still exercise the verifier's comparison instead of accidentally
    # mutating both sides together.
    encoded.extend(binding_kat.encode_fp16(ZERO))
    base_payload = coefficient_payload(ONE, ONE, ZERO, ZERO)
    # The base section has only the ten auxiliary vectors and the GKR mask;
    # its main vector is not part of the BLRSCV07 wire format.
    encoded.extend(base_payload[MAIN_DIMENSION * core.FP16_BYTES :])
    encoded.extend(binding_kat.encode_fp16(expected_target))
    encoded.extend(
        coefficient_payload(
            answer_value,
            gkr_mask_answer_value,
            squarefree_mask_answer_value,
            squarefree_raw_delta,
        )
    )
    return bytes(encoded)


def coefficient_payload(
    answer_value,
    gkr_mask_answer_value,
    squarefree_mask_answer_value=ZERO,
    squarefree_raw_delta=ZERO,
):
    encoded = bytearray(binding_kat.encode_fp16(answer_value))
    encoded.extend(b"\x00" * ((MAIN_DIMENSION - 1) * core.FP16_BYTES))
    ordinary_auxiliary = bytearray(
        AUXILIARY_WORDS
        * AUXILIARY_DIMENSION
        * core.FP16_BYTES
    )
    gkr_mask = bytearray(GKR_MASK_DIMENSION * core.FP16_BYTES)
    gkr_mask[
        : core.FP16_BYTES
    ] = binding_kat.encode_fp16(gkr_mask_answer_value)
    squarefree_mask_word, squarefree_mask_coefficient = divmod(
        SQUAREFREE_MASK_GLOBAL_COEFFICIENT,
        512,
    )
    squarefree_mask_offset = (
        squarefree_mask_word * 512 + squarefree_mask_coefficient
    ) * core.FP16_BYTES
    gkr_mask[
        squarefree_mask_offset : squarefree_mask_offset
        + core.FP16_BYTES
    ] = binding_kat.encode_fp16(squarefree_mask_answer_value)
    squarefree_offset = SUMCHECK_WORDS * AUXILIARY_DIMENSION * core.FP16_BYTES
    for phase, value in enumerate(SQUAREFREE_VALUES):
        source_value = add(value, squarefree_raw_delta) if phase == 0 else value
        for table in (2 * phase, 2 * phase + 1):
            offset = squarefree_offset + table * 512 * core.FP16_BYTES
            ordinary_auxiliary[
                offset : offset + 512 * core.FP16_BYTES
            ] = binding_kat.encode_fp16(source_value) * 512
    encoded.extend(ordinary_auxiliary)
    encoded.extend(gkr_mask)
    return bytes(encoded)


def target_payload(
    claims,
    main_scale,
    answer_value,
    gkr_relation_terminals,
    gkr_mask_answer_value,
    squarefree_mask_answer_value=ZERO,
    squarefree_raw_delta=ZERO,
    squarefree_binding=None,
    squarefree_claims=None,
    h4_source_binding=None,
):
    encoded = bytearray(b"BLRSTA05")
    encoded.extend(binding_kat.encode_fp16(CLAIM_CHALLENGE))
    encoded.extend(binding_kat.encode_fp16(COORDINATE_CHALLENGE))
    for claim in claims:
        encoded.extend(binding_kat.encode_claim(claim))
    for challenge in WORD_CHALLENGES:
        encoded.extend(binding_kat.encode_fp16(challenge))
    for terminal in gkr_relation_terminals:
        encoded.extend(binding_kat.encode_fp16(terminal))
    encoded.extend(binding_kat.encode_fp16(main_scale))
    binding = (
        squarefree_binding_payload()
        if squarefree_binding is None
        else squarefree_binding
    )
    claims = binding[8:148] if squarefree_claims is None else squarefree_claims
    encoded.extend(claims)
    encoded.extend(binding)
    encoded.extend(
        h4_masked_source_functional_binding()
        if h4_source_binding is None
        else h4_source_binding
    )
    encoded.extend(
        coefficient_payload(
            answer_value,
            gkr_mask_answer_value,
            squarefree_mask_answer_value,
            squarefree_raw_delta,
        )
    )
    return bytes(encoded)


def parse_output(encoded):
    expected_size = (
        84
        + len(MAIN_QUERIES) * core.FP16_BYTES
        + len(AUXILIARY_QUERIES)
        * (AUXILIARY_WORDS + 1)
        * core.FP16_BYTES
    )
    if len(encoded) != expected_size or encoded[:8] != b"BLRSCO02":
        raise SystemExit(
            "answer_output_shape="
            f"{len(encoded)}/{expected_size};magic={encoded[:8]!r}"
        )
    if not any(encoded[20:84]):
        raise SystemExit("answer_tensor_root_zero")
    main_end = 84 + len(MAIN_QUERIES) * core.FP16_BYTES
    if encoded[84:main_end] != (
        binding_kat.encode_fp16(ONE) * len(MAIN_QUERIES)
    ):
        raise SystemExit("main_opening_mismatch")
    expected_ordinary_auxiliary = bytearray(
        len(AUXILIARY_QUERIES)
        * AUXILIARY_WORDS
        * core.FP16_BYTES
    )
    ordinary_end = main_end + len(expected_ordinary_auxiliary)
    actual_ordinary_auxiliary = bytearray(encoded[main_end:ordinary_end])
    for query in range(len(AUXILIARY_QUERIES)):
        offset = (
            query * AUXILIARY_WORDS
            + SUMCHECK_WORDS
        ) * core.FP16_BYTES
        actual_ordinary_auxiliary[
            offset : offset + core.FP16_BYTES
        ] = b"\0" * core.FP16_BYTES
    if actual_ordinary_auxiliary != expected_ordinary_auxiliary:
        raise SystemExit("ordinary_auxiliary_opening_mismatch")
    if encoded[ordinary_end:] != (
        binding_kat.encode_fp16(ONE) * len(AUXILIARY_QUERIES)
    ):
        raise SystemExit("gkr_mask_tensor_opening_mismatch")
    return (
        struct.unpack(">d", encoded[8:16])[0],
        int.from_bytes(encoded[16:20], "big"),
    )


def run(
    executable,
    fixture,
    label,
    expect_success,
    expected_error=b"ERR:answer_target",
):
    started = time.perf_counter()
    process = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    memory = core.ProofPhaseMemorySampler(process.pid)
    memory.start()
    try:
        stdout, stderr = process.communicate(
            input=fixture,
            timeout=120,
        )
    finally:
        memory.stop()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    wall_seconds = time.perf_counter() - started
    if expect_success:
        if process.returncode != 0 or stderr:
            raise SystemExit(
                f"{label}_rejected={process.returncode};stderr={stderr!r}"
            )
    elif (
        process.returncode == 0
        or expected_error not in stderr
    ):
        raise SystemExit(
            f"{label}_accepted={process.returncode};stderr={stderr!r}"
        )
    return stdout, wall_seconds, memory.maximum_child_mb


def run_target(executable, fixture, expected_target):
    result = subprocess.run(
        [str(executable)],
        input=fixture,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) != 148
        or result.stdout[:8] != b"BLRSTO02"
        or binding_kat.decode_fp16(result.stdout[8:72])
        != expected_target
        or binding_kat.decode_fp16(result.stdout[72:136]) != ZERO
    ):
        raise SystemExit(
            "standalone_target_rejected="
            f"{result.returncode};stdout={result.stdout!r};"
            f"stderr={result.stderr!r}"
        )
    return struct.unpack(">d", result.stdout[136:144])[0]


def run_target_reject(executable, fixture, label, expected_error):
    result = subprocess.run(
        [str(executable)],
        input=fixture,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode == 0 or expected_error not in result.stderr:
        raise SystemExit(
            f"{label}_accepted={result.returncode};"
            f"stdout={result.stdout!r};stderr={result.stderr!r}"
        )


def main():
    executable = (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "fp16_zk_rs_answer_code_verify.exe"
    )
    if not executable.is_file():
        raise SystemExit(f"native_answer_verifier_missing={executable}")
    target_executable = (
        executable.parent / "fp16_zk_rs_answer_target.exe"
    )
    if not target_executable.is_file():
        raise SystemExit(
            f"native_answer_target_missing={target_executable}"
        )

    claims, _ = binding_kat.fixture_claims_and_rows()
    unscaled_target = expected_main_target(claims)
    if unscaled_target == ZERO:
        raise SystemExit("fixture_main_target_zero")
    gkr_relation_terminals = (ONE,) + (ZERO,) * (
        GKR_MASK_WORDS - 1
    )
    gkr_mask_target = equality_weight(0, WORD_CHALLENGES)
    target = add(
        mul16(
            add(unscaled_target, gkr_mask_target),
            MAIN_SCALE,
        ),
        squarefree_target(),
    )
    correct = payload(
        claims,
        MAIN_SCALE,
        target,
        ONE,
        gkr_relation_terminals,
        ONE,
    )
    stdout, wall_seconds, native_peak_mb = run(
        executable,
        correct,
        "correct_fixture",
        True,
    )
    native_seconds, workers = parse_output(stdout)
    standalone_target_seconds = run_target(
        target_executable,
        target_payload(
            claims,
            MAIN_SCALE,
            ONE,
            gkr_relation_terminals,
            ONE,
        ),
        target,
    )

    source_binding = h4_masked_source_functional_binding()
    for label, offset in (
        ("h4_source_root_mutation", 16),
        ("h4_booleanity_point_mutation", 464),
        ("h4_booleanity_terminal_mutation", 2_256),
        ("h4_padding_point_mutation", 2_704),
        ("h4_padding_terminal_mutation", 4_304),
    ):
        mutated_binding = bytearray(source_binding)
        mutated_binding[offset] ^= 1
        run(
            executable,
            payload(
                claims,
                MAIN_SCALE,
                target,
                ONE,
                gkr_relation_terminals,
                ONE,
                h4_source_binding=bytes(mutated_binding),
            ),
            label,
            False,
            b"ERR:h4_source_binding",
        )
        run_target_reject(
            target_executable,
            target_payload(
                claims,
                MAIN_SCALE,
                ONE,
                gkr_relation_terminals,
                ONE,
                h4_source_binding=bytes(mutated_binding),
            ),
            f"standalone_{label}",
            b"ERR:h4_source_binding",
        )

    wrong_target = add(target, ONE)
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            wrong_target,
            ONE,
            gkr_relation_terminals,
            ONE,
        ),
        "target_mutation",
        False,
    )

    answer_two = binding_kat.fp16_value(2)
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            answer_two,
            gkr_relation_terminals,
            ONE,
        ),
        "answer_mutation",
        False,
    )

    run(
        executable,
        payload(
            claims,
            add(MAIN_SCALE, ONE),
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
        ),
        "main_scale_mutation",
        False,
    )

    mutated_claims = list(claims)
    claim = list(mutated_claims[2])
    point = list(claim[4])
    point[3] = add(point[3], ONE)
    claim[4] = tuple(point)
    mutated_claims[2] = tuple(claim)
    run(
        executable,
        payload(
            tuple(mutated_claims),
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
        ),
        "gkr_point_mutation",
        False,
    )

    mutated_terminals = list(gkr_relation_terminals)
    mutated_terminals[0] = add(ONE, ONE)
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            tuple(mutated_terminals),
            ONE,
        ),
        "gkr_relation_terminal_mutation",
        False,
    )

    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            add(ONE, ONE),
        ),
        "gkr_mask_answer_mutation",
        False,
    )

    correct_squarefree_binding = squarefree_binding_payload()
    mismatched_prechallenge_claims = bytearray(
        correct_squarefree_binding[8:148]
    )
    mismatched_prechallenge_claims[8] ^= 1
    mismatch_fixture = payload(
        claims,
        MAIN_SCALE,
        target,
        ONE,
        gkr_relation_terminals,
        ONE,
        squarefree_binding=correct_squarefree_binding,
        squarefree_claims=bytes(mismatched_prechallenge_claims),
    )
    run(
        executable,
        mismatch_fixture,
        "prechallenge_squarefree_claim_byte_mismatch",
        False,
        b"ERR:squarefree_binding_claims",
    )
    run_target_reject(
        target_executable,
        target_payload(
            claims,
            MAIN_SCALE,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=correct_squarefree_binding,
            squarefree_claims=bytes(mismatched_prechallenge_claims),
        ),
        "standalone_prechallenge_squarefree_claim_byte_mismatch",
        b"ERR:squarefree_binding_claims",
    )
    legacy_binding = b"BLSQAB01" + correct_squarefree_binding[8:]
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=legacy_binding,
        ),
        "legacy_squarefree_binding",
        False,
        b"ERR:squarefree_binding_magic",
    )

    digest_mutation = bytearray(correct_squarefree_binding)
    digest_mutation[84] ^= 1
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(digest_mutation),
        ),
        "squarefree_digest_mutation",
        False,
        b"ERR:squarefree_binding_digest",
    )

    root_mutation = bytearray(correct_squarefree_binding)
    root_mutation[16] ^= 1
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(root_mutation),
        ),
        "squarefree_root_mutation",
        False,
        b"ERR:squarefree_binding_digest",
    )

    capacity_mutation = bytearray(correct_squarefree_binding)
    capacity_mutation[80:82] = (512).to_bytes(2, "big")
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(capacity_mutation),
        ),
        "squarefree_capacity_mutation",
        False,
        b"ERR:squarefree_binding_digest",
    )

    point_mutation = bytearray(correct_squarefree_binding)
    point_mutation[156:220] = binding_kat.encode_fp16(
        add(SQUAREFREE_POINTS[0][0], ONE)
    )
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(point_mutation),
        ),
        "squarefree_point_mutation",
        False,
        b"ERR:squarefree_binding_digest",
    )

    claim_substitution = bytearray(correct_squarefree_binding)
    claim_substitution[860:924] = binding_kat.encode_fp16(
        add(SQUAREFREE_VALUES[0], ONE)
    )
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(claim_substitution),
        ),
        "post_challenge_squarefree_claim_substitution",
        False,
        b"ERR:squarefree_binding_digest",
    )

    mix_mutation = bytearray(correct_squarefree_binding)
    mix_mutation[-128:-64] = binding_kat.encode_fp16(
        add(SQUAREFREE_MIXING[0], ONE)
    )
    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_binding=bytes(mix_mutation),
        ),
        "squarefree_mix_mutation",
        False,
    )

    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_mask_answer_value=ONE,
        ),
        "squarefree_mask_word_mutation",
        False,
        b"ERR:squarefree_masked_target",
    )

    run(
        executable,
        payload(
            claims,
            MAIN_SCALE,
            target,
            ONE,
            gkr_relation_terminals,
            ONE,
            squarefree_raw_delta=ONE,
        ),
        "squarefree_raw_coefficient_word_mutation",
        False,
        b"ERR:squarefree_masked_target",
    )

    print("kat=fp16_zk_rs_answer_target_verify_v7")
    print("evidence_class=production_geometry_independent_target")
    print(f"input_payload_mb={len(correct) / 1_000_000:.6f}")
    print(f"wall_seconds={wall_seconds:.6f}")
    print(f"native_verify_and_encode_seconds={native_seconds:.6f}")
    print(
        "standalone_target_seconds="
        f"{standalone_target_seconds:.6f}"
    )
    print(f"native_host_peak_mb={native_peak_mb:.3f}")
    print(f"native_workers={workers}")
    print("construction8_answer_target_verified=true")
    print("standalone_answer_target_verified=true")
    print("main_and_auxiliary_openings_verified=true")
    print("target_mutation_rejected=true")
    print("answer_mutation_rejected=true")
    print("main_scale_mutation_rejected=true")
    print("gkr_point_mutation_rejected=true")
    print("gkr_relation_terminal_mutation_rejected=true")
    print("gkr_mask_answer_mutation_rejected=true")
    print("h4_source_root_mutation_rejected=true")
    print("h4_booleanity_point_mutation_rejected=true")
    print("h4_booleanity_terminal_mutation_rejected=true")
    print("h4_padding_point_mutation_rejected=true")
    print("h4_padding_terminal_mutation_rejected=true")
    print("legacy_squarefree_binding_rejected=true")
    print("prechallenge_squarefree_claim_byte_mismatch_rejected=true")
    print("state_squarefree_digest_mutation_rejected=true")
    print("state_squarefree_root_mutation_rejected=true")
    print("state_squarefree_capacity_mutation_rejected=true")
    print("state_squarefree_point_mutation_rejected=true")
    print("post_challenge_squarefree_claim_substitution_rejected=true")
    print("state_squarefree_mix_mutation_rejected=true")
    print("state_squarefree_mask_word_mutation_rejected=true")
    print("state_squarefree_raw_coefficient_word_mutation_rejected=true")
    print("state_squarefree_answer_binding_v2_verified=true")
    print("state_squarefree_raw_plus_mask_equals_masked_target=true")
    print("state_squarefree_delta_not_serialized=true")
    print("state_squarefree_auxiliary_word_nonzero=true")
    print("complete_pcs_qualification=false")


if __name__ == "__main__":
    sys.exit(main())
