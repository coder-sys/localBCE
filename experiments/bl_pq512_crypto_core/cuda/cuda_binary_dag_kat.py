"""Differential KATs for every CUDA kernel in the binary Keccak DAG benchmark."""

import array
import ctypes
import os
from pathlib import Path

from cuda_fp16_tower_kat import Runtime, ck
from cuda_dag_packed_accumulator_benchmark import copy
from cuda_binary_dag_full_benchmark import (
    KERNEL,
    THREADS,
    WIDTH,
    arguments,
    b16_lookup,
    deterministic_triples,
    function,
    gf_mul,
    launch,
    wiring,
)


def t_load(words, index):
    offset = 6 * index
    return tuple(
        words[offset + 2 * lane] | (words[offset + 2 * lane + 1] << 64)
        for lane in range(3)
    )


def t_store(words, index, value):
    offset = 6 * index
    for lane in range(3):
        words[offset + 2 * lane] = value[lane] & ((1 << 64) - 1)
        words[offset + 2 * lane + 1] = value[lane] >> 64


def t_add(left, right):
    return tuple(left[lane] ^ right[lane] for lane in range(3))


def t_mul(left, right):
    return tuple(gf_mul(left[lane], right[lane]) for lane in range(3))


ZERO = (0, 0, 0)


def upload(runtime, values, name):
    pointer = runtime.alloc(len(values) * values.itemsize)
    copy(runtime, pointer, values, name)
    return pointer


def packed_pattern(packed, theta, chi, output, group, layer_kind, salt):
    def word(wire):
        return (packed[wire] >> (16 * group)) & 65535

    if layer_kind == 0:
        value = 0
        for index in range(11):
            value ^= word(theta[11 * output + index])
        return value
    a = word(chi[3 * output])
    b = word(chi[3 * output + 1])
    c = word(chi[3 * output + 2])
    value = a ^ c ^ (b & c)
    if ((output + salt) & 127) == 0:
        value ^= 65535
    return value


def expected_theta_messages(
    source, theta, wire_weights, group_zero, group_delta, raw, groups, claims
):
    result = [ZERO, ZERO, ZERO, ZERO]
    suffixes = groups // 2
    for suffix in range(suffixes):
        for output in range(raw):
            q0, q1 = ZERO, ZERO
            for input_index in range(11):
                wire = theta[11 * output + input_index]
                v0 = t_load(source, wire * groups + 2 * suffix)
                v1 = t_load(source, wire * groups + 2 * suffix + 1)
                q0 = t_add(q0, v0)
                q1 = t_add(q1, t_add(v0, v1))
            w0, wd = ZERO, ZERO
            for claim in range(claims):
                wire = t_load(wire_weights, claim * raw + output)
                w0 = t_add(
                    w0,
                    t_mul(wire, t_load(group_zero, claim * suffixes + suffix)),
                )
                wd = t_add(
                    wd,
                    t_mul(wire, t_load(group_delta, claim * suffixes + suffix)),
                )
            coefficients = (
                t_mul(q0, w0),
                t_add(t_mul(q0, wd), t_mul(q1, w0)),
                t_mul(q1, wd),
            )
            for index, value in enumerate(coefficients):
                result[index] = t_add(result[index], value)
    return result


def expected_chi_messages(
    source, chi, wire_weights, group_zero, group_delta, raw, groups
):
    result = [ZERO, ZERO, ZERO, ZERO]
    suffixes = groups // 2
    for suffix in range(suffixes):
        for output in range(raw):
            values0 = []
            values_delta = []
            for input_index in range(3):
                wire = chi[3 * output + input_index]
                v0 = t_load(source, wire * groups + 2 * suffix)
                v1 = t_load(source, wire * groups + 2 * suffix + 1)
                values0.append(v0)
                values_delta.append(t_add(v0, v1))
            q0 = t_add(
                t_add(values0[0], values0[2]),
                t_mul(values0[1], values0[2]),
            )
            q1 = t_add(
                t_add(values_delta[0], values_delta[2]),
                t_add(
                    t_mul(values0[1], values_delta[2]),
                    t_mul(values_delta[1], values0[2]),
                ),
            )
            q2 = t_mul(values_delta[1], values_delta[2])
            wire = t_load(wire_weights, output)
            w0 = t_mul(wire, t_load(group_zero, suffix))
            wd = t_mul(wire, t_load(group_delta, suffix))
            coefficients = (
                t_mul(q0, w0),
                t_add(t_mul(q0, wd), t_mul(q1, w0)),
                t_add(t_mul(q1, wd), t_mul(q2, w0)),
                t_mul(q2, wd),
            )
            for index, value in enumerate(coefficients):
                result[index] = t_add(result[index], value)
    return result


def main():
    raw = 7
    groups = 4
    claims = 3
    salt = 5
    theta, chi = wiring()
    packed = array.array("Q")
    state = 0xA4093822299F31D0
    for _ in range(WIDTH):
        state = (
            state * 6364136223846793005 + 1442695040888963407
        ) & ((1 << 64) - 1)
        packed.append(state)
    lookup = b16_lookup()
    packed_wire_weights = deterministic_triples(claims * raw, 101)
    packed_group_weights = deterministic_triples(claims * groups, 103)
    source = deterministic_triples(WIDTH * 8, 107)
    theta_wire_weights = deterministic_triples(claims * raw, 109)
    theta_zero = deterministic_triples(claims * (8 // 2), 113)
    theta_delta = deterministic_triples(claims * (8 // 2), 127)
    chi_wire_weights = deterministic_triples(raw, 131)
    chi_zero = deterministic_triples(8 // 2, 137)
    chi_delta = deterministic_triples(8 // 2, 139)
    challenge = deterministic_triples(1, 149)

    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent / "cuda_nvrtc" / "nvidia" / "cuda_nvrtc" / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    runtime = Runtime(nvrtc)
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]
    try:
        runtime.compile(KERNEL, b"packed_histogram")
        packed_fn = function(runtime, "packed_histogram")
        materialize_fn = function(runtime, "materialize_b16")
        theta_fn = function(runtime, "theta_group_message")
        chi_fn = function(runtime, "chi_group_message")
        fold_fn = function(runtime, "fold_source")

        packed_d = upload(runtime, packed, "kat_packed")
        lookup_d = upload(runtime, lookup, "kat_lookup")
        theta_d = upload(runtime, theta, "kat_theta")
        chi_d = upload(runtime, chi, "kat_chi")
        packed_wire_d = upload(
            runtime, packed_wire_weights, "kat_packed_wire_weights"
        )
        packed_group_d = upload(
            runtime, packed_group_weights, "kat_packed_group_weights"
        )
        histogram_words = claims * 65536 * 6
        histogram_size = histogram_words * 8
        histogram_d = runtime.alloc(histogram_size)
        actual_histogram = array.array("Q", [0]) * histogram_words

        for layer_kind, layer_claims in ((0, 3), (1, 1)):
            ck(
                runtime.cuda.cuMemsetD8_v2(
                    histogram_d, 0, histogram_size
                ),
                "kat_histogram_zero",
            )
            params = arguments(
                ctypes.c_uint64(packed_d),
                ctypes.c_uint64(theta_d),
                ctypes.c_uint64(chi_d),
                ctypes.c_uint64(packed_wire_d),
                ctypes.c_uint64(packed_group_d),
                ctypes.c_uint64(histogram_d),
                ctypes.c_uint32(layer_kind),
                ctypes.c_uint32(layer_claims),
                ctypes.c_uint32(raw),
                ctypes.c_uint32(groups),
                ctypes.c_uint32(1),
                ctypes.c_uint32(salt),
            )
            launch(
                runtime,
                packed_fn,
                1,
                params,
                "kat_packed_histogram",
            )
            ck(runtime.cuda.cuCtxSynchronize(), "kat_packed_histogram_sync")
            actual_view = (ctypes.c_ubyte * histogram_size).from_buffer(
                actual_histogram
            )
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_view, ctypes.c_void_p),
                    histogram_d,
                    histogram_size,
                ),
                "kat_copy_histogram",
            )
            expected = array.array("Q", [0]) * histogram_words
            for group in range(groups):
                for output in range(raw):
                    pattern = packed_pattern(
                        packed, theta, chi, output, group, layer_kind, salt
                    )
                    for claim in range(layer_claims):
                        weight = t_mul(
                            t_load(
                                packed_wire_weights, claim * raw + output
                            ),
                            t_load(
                                packed_group_weights, claim * groups + group
                            ),
                        )
                        index = claim * 65536 + pattern
                        prior = t_load(expected, index)
                        t_store(expected, index, t_add(prior, weight))
            if actual_histogram != expected:
                raise SystemExit(f"packed_histogram_mismatch layer={layer_kind}")

        materialized_words = raw * groups * 6
        materialized_d = runtime.alloc(materialized_words * 8)
        params = arguments(
            ctypes.c_uint64(packed_d),
            ctypes.c_uint64(lookup_d),
            ctypes.c_uint64(materialized_d),
            ctypes.c_uint32(raw),
            ctypes.c_uint32(groups),
            ctypes.c_uint32(1),
        )
        launch(runtime, materialize_fn, 1, params, "kat_materialize")
        ck(runtime.cuda.cuCtxSynchronize(), "kat_materialize_sync")
        actual_materialized = array.array("Q", [0]) * materialized_words
        actual_view = (ctypes.c_ubyte * (materialized_words * 8)).from_buffer(
            actual_materialized
        )
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(actual_view, ctypes.c_void_p),
                materialized_d,
                materialized_words * 8,
            ),
            "kat_copy_materialized",
        )
        expected_materialized = array.array("Q", [0]) * materialized_words
        for wire in range(raw):
            for group in range(groups):
                pattern = (packed[wire] >> (16 * group)) & 65535
                t_store(
                    expected_materialized,
                    wire * groups + group,
                    t_load(lookup, pattern),
                )
        if actual_materialized != expected_materialized:
            raise SystemExit("materialize_mismatch")

        source_d = upload(runtime, source, "kat_source")
        messages_d = runtime.alloc(24 * 8)

        def run_message(
            fn, wiring_d, wire_values, zero_values, delta_values, is_theta
        ):
            wire_d = upload(runtime, wire_values, "kat_message_wire")
            zero_d = upload(runtime, zero_values, "kat_message_zero")
            delta_d = upload(runtime, delta_values, "kat_message_delta")
            ck(
                runtime.cuda.cuMemsetD8_v2(messages_d, 0, 24 * 8),
                "kat_message_zero_output",
            )
            common = (
                ctypes.c_uint64(source_d),
                ctypes.c_uint64(wiring_d),
                ctypes.c_uint64(wire_d),
                ctypes.c_uint64(zero_d),
                ctypes.c_uint64(delta_d),
                ctypes.c_uint64(messages_d),
                ctypes.c_uint32(raw),
                ctypes.c_uint32(8),
                ctypes.c_uint32(4),
                ctypes.c_uint32(4),
            )
            params = arguments(
                *(common + ((ctypes.c_uint32(claims),) if is_theta else ()))
            )
            launch(runtime, fn, 1, params, "kat_group_message")
            ck(runtime.cuda.cuCtxSynchronize(), "kat_group_message_sync")
            actual = array.array("Q", [0]) * 24
            actual_view = (ctypes.c_ubyte * (24 * 8)).from_buffer(actual)
            ck(
                runtime.cuda.cuMemcpyDtoH_v2(
                    ctypes.cast(actual_view, ctypes.c_void_p),
                    messages_d,
                    24 * 8,
                ),
                "kat_copy_message",
            )
            return [t_load(actual, index) for index in range(4)]

        actual_theta = run_message(
            theta_fn,
            theta_d,
            theta_wire_weights,
            theta_zero,
            theta_delta,
            True,
        )
        expected_theta = expected_theta_messages(
            source,
            theta,
            theta_wire_weights,
            theta_zero,
            theta_delta,
            raw,
            8,
            claims,
        )
        if actual_theta != expected_theta:
            raise SystemExit(
                f"theta_message_mismatch\nexpected={expected_theta}\n"
                f"actual={actual_theta}"
            )

        actual_chi = run_message(
            chi_fn,
            chi_d,
            chi_wire_weights,
            chi_zero,
            chi_delta,
            False,
        )
        expected_chi = expected_chi_messages(
            source,
            chi,
            chi_wire_weights,
            chi_zero,
            chi_delta,
            raw,
            8,
        )
        if actual_chi != expected_chi:
            raise SystemExit(
                f"chi_message_mismatch\nexpected={expected_chi}\n"
                f"actual={actual_chi}"
            )

        challenge_d = upload(runtime, challenge, "kat_challenge")
        fold_words = raw * 4 * 6
        fold_d = runtime.alloc(fold_words * 8)
        params = arguments(
            ctypes.c_uint64(source_d),
            ctypes.c_uint64(challenge_d),
            ctypes.c_uint64(fold_d),
            ctypes.c_uint32(raw),
            ctypes.c_uint32(8),
        )
        launch(runtime, fold_fn, 1, params, "kat_fold")
        ck(runtime.cuda.cuCtxSynchronize(), "kat_fold_sync")
        actual_fold = array.array("Q", [0]) * fold_words
        actual_view = (ctypes.c_ubyte * (fold_words * 8)).from_buffer(
            actual_fold
        )
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.cast(actual_view, ctypes.c_void_p),
                fold_d,
                fold_words * 8,
            ),
            "kat_copy_fold",
        )
        expected_fold = array.array("Q", [0]) * fold_words
        challenge_value = t_load(challenge, 0)
        for wire in range(raw):
            for suffix in range(4):
                v0 = t_load(source, wire * 8 + 2 * suffix)
                v1 = t_load(source, wire * 8 + 2 * suffix + 1)
                value = t_add(v0, t_mul(challenge_value, t_add(v0, v1)))
                t_store(expected_fold, wire * 4 + suffix, value)
        if actual_fold != expected_fold:
            raise SystemExit("fold_mismatch")

        print("packed_histogram_theta_match=true")
        print("packed_histogram_chi_match=true")
        print("materialize_b16_match=true")
        print("theta_group_message_match=true")
        print("chi_group_message_match=true")
        print("fold_source_match=true")
        print("kat_status=pass")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
