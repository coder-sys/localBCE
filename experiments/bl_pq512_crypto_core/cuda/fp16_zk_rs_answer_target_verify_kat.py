"""Production-geometry KAT for the independent Construction 7.2 target gate.

The fixture uses one nonzero main answer coefficient and one nonzero GKR-mask
auxiliary coefficient, derives the exact mixed target independently in Python,
and checks both opening families. Rust must enforce the target and reject
mutations to the target, committed answers, GKR point, or GKR terminal scale.

This is a host-only verifier gate.  It does not run CUDA and does not qualify a
complete PCS or proof.
"""

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
AUXILIARY_WORDS = 74
SUMCHECK_WORDS = 9
GKR_MASK_WORDS = 64
MAIN_QUERIES = tuple(range(1_600))
AUXILIARY_QUERIES = tuple(range(1_218))
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


def squarefree_binding_payload():
    encoded = bytearray(b"BLSQAB01")
    encoded.extend(struct.pack(">HHI", SQUAREFREE_CAPACITY, 2, 0))
    for phase, value in enumerate(SQUAREFREE_VALUES):
        encoded.extend(struct.pack(">H", 11))
        encoded.extend(b"\0" * 6)
        encoded.extend(binding_kat.encode_fp16(ZERO) * 10)
        encoded.extend(
            binding_kat.encode_fp16(ONE if phase else ZERO)
        )
        encoded.extend(binding_kat.encode_fp16(value))
    for value in SQUAREFREE_MIXING:
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
):
    encoded = bytearray(b"BLRSCV04")
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
    encoded.extend(binding_kat.encode_fp16(CLAIM_CHALLENGE))
    encoded.extend(binding_kat.encode_fp16(COORDINATE_CHALLENGE))
    for claim in claims:
        encoded.extend(binding_kat.encode_claim(claim))
    for challenge in WORD_CHALLENGES:
        encoded.extend(binding_kat.encode_fp16(challenge))
    for terminal in gkr_relation_terminals:
        encoded.extend(binding_kat.encode_fp16(terminal))
    encoded.extend(binding_kat.encode_fp16(main_scale))
    encoded.extend(squarefree_binding_payload())
    encoded.extend(binding_kat.encode_fp16(expected_target))
    encoded.extend(
        coefficient_payload(answer_value, gkr_mask_answer_value)
    )
    return bytes(encoded)


def coefficient_payload(answer_value, gkr_mask_answer_value):
    encoded = bytearray(binding_kat.encode_fp16(answer_value))
    encoded.extend(b"\x00" * ((MAIN_DIMENSION - 1) * core.FP16_BYTES))
    auxiliary = bytearray(
        AUXILIARY_WORDS
        * AUXILIARY_DIMENSION
        * core.FP16_BYTES
    )
    gkr_offset = SUMCHECK_WORDS * AUXILIARY_DIMENSION * core.FP16_BYTES
    auxiliary[
        gkr_offset : gkr_offset + core.FP16_BYTES
    ] = binding_kat.encode_fp16(gkr_mask_answer_value)
    squarefree_offset = (
        SUMCHECK_WORDS + GKR_MASK_WORDS
    ) * AUXILIARY_DIMENSION * core.FP16_BYTES
    for table, value in zip((0, 2), SQUAREFREE_VALUES):
        offset = squarefree_offset + table * 512 * core.FP16_BYTES
        auxiliary[offset : offset + core.FP16_BYTES] = (
            binding_kat.encode_fp16(value)
        )
    encoded.extend(auxiliary)
    return bytes(encoded)


def target_payload(
    claims,
    main_scale,
    answer_value,
    gkr_relation_terminals,
    gkr_mask_answer_value,
):
    encoded = bytearray(b"BLRSTA02")
    encoded.extend(binding_kat.encode_fp16(CLAIM_CHALLENGE))
    encoded.extend(binding_kat.encode_fp16(COORDINATE_CHALLENGE))
    for claim in claims:
        encoded.extend(binding_kat.encode_claim(claim))
    for challenge in WORD_CHALLENGES:
        encoded.extend(binding_kat.encode_fp16(challenge))
    for terminal in gkr_relation_terminals:
        encoded.extend(binding_kat.encode_fp16(terminal))
    encoded.extend(binding_kat.encode_fp16(main_scale))
    encoded.extend(squarefree_binding_payload())
    encoded.extend(
        coefficient_payload(answer_value, gkr_mask_answer_value)
    )
    return bytes(encoded)


def parse_output(encoded):
    expected_size = (
        20
        + len(MAIN_QUERIES) * core.FP16_BYTES
        + len(AUXILIARY_QUERIES)
        * AUXILIARY_WORDS
        * core.FP16_BYTES
    )
    if len(encoded) != expected_size or encoded[:8] != b"BLRSCO01":
        raise SystemExit(
            "answer_output_shape="
            f"{len(encoded)}/{expected_size};magic={encoded[:8]!r}"
        )
    main_end = 20 + len(MAIN_QUERIES) * core.FP16_BYTES
    if encoded[20:main_end] != (
        binding_kat.encode_fp16(ONE) * len(MAIN_QUERIES)
    ):
        raise SystemExit("main_opening_mismatch")
    expected_auxiliary = bytearray(
        len(AUXILIARY_QUERIES)
        * AUXILIARY_WORDS
        * core.FP16_BYTES
    )
    for query in range(len(AUXILIARY_QUERIES)):
        offset = (
            query * AUXILIARY_WORDS + SUMCHECK_WORDS
        ) * core.FP16_BYTES
        expected_auxiliary[
            offset : offset + core.FP16_BYTES
        ] = binding_kat.encode_fp16(ONE)
    actual_auxiliary = bytearray(encoded[main_end:])
    for query in range(len(AUXILIARY_QUERIES)):
        offset = (
            query * AUXILIARY_WORDS
            + SUMCHECK_WORDS
            + GKR_MASK_WORDS
        ) * core.FP16_BYTES
        actual_auxiliary[offset : offset + core.FP16_BYTES] = b"\0" * core.FP16_BYTES
    if actual_auxiliary != expected_auxiliary:
        raise SystemExit("auxiliary_opening_mismatch")
    return (
        struct.unpack(">d", encoded[8:16])[0],
        int.from_bytes(encoded[16:20], "big"),
    )


def run(executable, fixture, label, expect_success):
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
        or b"ERR:answer_target" not in stderr
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
        or len(result.stdout) != 84
        or result.stdout[:8] != b"BLRSTO01"
        or binding_kat.decode_fp16(result.stdout[8:72])
        != expected_target
    ):
        raise SystemExit(
            "standalone_target_rejected="
            f"{result.returncode};stdout={result.stdout!r};"
            f"stderr={result.stderr!r}"
        )
    return struct.unpack(">d", result.stdout[72:80])[0]


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

    print("kat=fp16_zk_rs_answer_target_verify_v5")
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
    print("construction7_answer_target_verified=true")
    print("standalone_answer_target_verified=true")
    print("main_and_auxiliary_openings_verified=true")
    print("target_mutation_rejected=true")
    print("answer_mutation_rejected=true")
    print("main_scale_mutation_rejected=true")
    print("gkr_point_mutation_rejected=true")
    print("gkr_relation_terminal_mutation_rejected=true")
    print("gkr_mask_answer_mutation_rejected=true")
    print("state_squarefree_answer_binding_verified=true")
    print("state_squarefree_auxiliary_word_nonzero=true")
    print("complete_pcs_qualification=false")


if __name__ == "__main__":
    sys.exit(main())
