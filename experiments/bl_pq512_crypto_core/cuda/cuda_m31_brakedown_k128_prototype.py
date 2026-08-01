"""Integrated nonactivating K128 M31 Brakedown encoder prototype.

Two packed B=16 boundaries are encoded at the real 2^24-row geometry.  The
published 110-bit degrees are not used: the per-level factor/outer degrees are
the independently regenerated 392-bit schedule.  Full expanded source tables
and full top-level codewords are never allocated.

This prototype measures encoder mechanics and memory.  It is not yet the
FICS/ZO0K IOPP, a minimum-distance certificate, or a complete proof.
"""

import array
import ctypes
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import process_peak_mb
from cuda_fp16_tower_kat import Q, Runtime, ck
from cuda_m31_brakedown_factor_benchmark import (
    INTERLEAVE,
    THREADS,
    arguments,
    function,
    launch,
)
from cuda_m31_sha3_matrix_benchmark import (
    MATRIX_KERNEL,
    MATRIX_PREFIX,
    verify_reduced_kat as verify_sha3_matrix_kat,
)
from cuda_m31_segment_merkle import (
    KERNEL as SEGMENT_MERKLE_KERNEL,
    INNER_SEGMENT,
    LEAF_SIZE,
    OUTER_SEGMENT,
    PACKED_SEGMENT,
    Segment,
    commit_segments,
    functions as segment_merkle_functions,
    open_segments,
)
from cuda_pcs_sha3_merkle_benchmark import KERNEL as SHA3_KERNEL


RATE_NUMERATOR = 704
RATE_DENOMINATOR = 1000
ALPHA_NUMERATOR = 11
ALPHA_DENOMINATOR = 100
TOP_ROWS = 1 << 24
BASE_MAX_ROWS = 512
FACTOR_DEGREES = (26, 32, 42, 65, 116)
OUTER_DEGREES = (21, 21, 21, 23, 43)
SOURCE_SEEDS = (
    0x6A09_E667_F3BC_C908,
    0x510E_527F_ADE6_82D1,
)
FACTOR_ROLE = 1
OUTER_ROLE = 2
OPENING_QUERY_FIXTURE_COUNT = 392

EXTRA_KERNEL = r"""
extern "C" __global__ void base_cauchy_parity(
    const u32 *input,
    const u32 *coefficients,
    u32 *parity,
    u32 input_rows,
    u32 parity_rows
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    u64 count = (u64)parity_rows * 16ULL;
    if (index >= count) return;
    u32 parity_row = (u32)(index / 16ULL);
    u32 coordinate = (u32)(index % 16ULL);
    const u32 *coefficient_row =
        coefficients + (u64)parity_row * input_rows;
    u32 sum = 0U;
    for (u32 input_row = 0; input_row < input_rows; ++input_row) {
        u32 product = matrix_mulp(
            input[(u64)input_row * 16ULL + coordinate],
            coefficient_row[input_row]
        );
        u32 added = sum + product;
        sum = added >= 2147483647U
            ? added - 2147483647U
            : added;
    }
    parity[index] = sum;
}
"""


@dataclass
class DeviceBuffer:
    pointer: int
    size: int

    @property
    def size_mb(self):
        return self.size / 1_000_000.0


@dataclass
class EncodedBoundary:
    packed: DeviceBuffer
    inner: DeviceBuffer
    outer: DeviceBuffer
    input_rows: int
    inner_rows: int
    outer_rows: int
    encode_seconds: float

    @property
    def retained_mb(self):
        return self.packed.size_mb + self.inner.size_mb + self.outer.size_mb

    @property
    def codeword_rows(self):
        return self.input_rows + self.inner_rows + self.outer_rows


class Allocator:
    def __init__(self, runtime):
        self.runtime = runtime
        self.live = 0
        self.peak = 0
        self.sizes = {}

    @property
    def live_mb(self):
        return self.live / 1_000_000.0

    @property
    def peak_mb(self):
        return self.peak / 1_000_000.0

    def allocate(self, size):
        pointer = self.runtime.alloc(size)
        self.sizes[pointer] = size
        self.live += size
        self.peak = max(self.peak, self.live)
        return DeviceBuffer(pointer, size)

    def allocate_count(self, count, item_size):
        return self.allocate(count * item_size)

    def free(self, buffer):
        size = self.sizes.pop(buffer.pointer)
        ck(self.runtime.cuda.cuMemFree_v2(buffer.pointer), "free_buffer")
        self.runtime.allocs.remove(buffer.pointer)
        self.live -= size


def ceil_rate(rows):
    return (
        rows * RATE_DENOMINATOR + RATE_NUMERATOR - 1
    ) // RATE_NUMERATOR


def child_rows(rows):
    return (
        rows * ALPHA_NUMERATOR + ALPHA_DENOMINATOR // 2
    ) // ALPHA_DENOMINATOR


def schedule():
    rows = TOP_ROWS
    result = []
    level = 0
    while rows > BASE_MAX_ROWS:
        child = child_rows(rows)
        inner = ceil_rate(child)
        codeword = ceil_rate(rows)
        outer = codeword - rows - inner
        result.append(
            (
                rows,
                child,
                inner,
                outer,
                FACTOR_DEGREES[level],
                OUTER_DEGREES[level],
            )
        )
        rows = child
        level += 1
    if level != len(FACTOR_DEGREES):
        raise SystemExit("parameter_schedule_length_mismatch")
    return result, rows, ceil_rate(rows)


def bind_driver(runtime):
    runtime.cuda.cuMemsetD8_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_ubyte,
        ctypes.c_size_t,
    ]
    runtime.cuda.cuMemcpyDtoD_v2.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_size_t,
    ]


def memset(runtime, buffer):
    ck(
        runtime.cuda.cuMemsetD8_v2(buffer.pointer, 0, buffer.size),
        "zero_buffer",
    )


def copy_device(runtime, destination, source, size):
    ck(
        runtime.cuda.cuMemcpyDtoD_v2(destination, source, size),
        "copy_device",
    )


def matrix_context(level, role):
    return (role << 32) | level


def initialize_matrix_iv(runtime, allocator, initialize_function):
    prefix = array.array("B", MATRIX_PREFIX)
    prefix_buffer = allocator.allocate(len(prefix))
    iv_buffer = allocator.allocate_count(25, 8)
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            prefix_buffer.pointer,
            ctypes.c_void_p(prefix.buffer_info()[0]),
            len(prefix),
        ),
        "copy_matrix_prefix",
    )
    launch(
        runtime,
        initialize_function,
        1,
        arguments(
            ctypes.c_uint64(prefix_buffer.pointer),
            ctypes.c_uint64(iv_buffer.pointer),
        ),
        "initialize_matrix_iv",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "initialize_matrix_iv_sync")
    allocator.free(prefix_buffer)
    return iv_buffer


def factor_dense(
    runtime,
    allocator,
    functions,
    matrix_iv,
    source,
    input_rows,
    output_rows,
    degree,
    context,
):
    output_count = output_rows * INTERLEAVE
    accumulators = allocator.allocate_count(output_count, 8)
    output = allocator.allocate_count(output_count, 4)
    memset(runtime, accumulators)
    launch(
        runtime,
        functions[4],
        input_rows,
        arguments(
            ctypes.c_uint64(source.pointer),
            ctypes.c_uint64(accumulators.pointer),
            ctypes.c_uint64(matrix_iv.pointer),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(output_rows),
            ctypes.c_uint32(degree),
            ctypes.c_uint64(context),
        ),
        "factor_dense",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "factor_dense_sync")
    launch(
        runtime,
        functions[2],
        output_count,
        arguments(
            ctypes.c_uint64(accumulators.pointer),
            ctypes.c_uint64(output.pointer),
            ctypes.c_uint64(output_count),
        ),
        "reduce_dense",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "reduce_dense_sync")
    allocator.free(accumulators)
    return output


def factor_packed(
    runtime,
    allocator,
    functions,
    matrix_iv,
    packed,
    input_rows,
    output_rows,
    degree,
    context,
):
    output_count = output_rows * INTERLEAVE
    accumulators = allocator.allocate_count(output_count, 8)
    output = allocator.allocate_count(output_count, 4)
    memset(runtime, accumulators)
    launch(
        runtime,
        functions[1],
        input_rows,
        arguments(
            ctypes.c_uint64(packed.pointer),
            ctypes.c_uint64(accumulators.pointer),
            ctypes.c_uint64(matrix_iv.pointer),
            ctypes.c_uint64(input_rows),
            ctypes.c_uint64(output_rows),
            ctypes.c_uint32(degree),
            ctypes.c_uint64(context),
        ),
        "factor_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "factor_packed_sync")
    launch(
        runtime,
        functions[2],
        output_count,
        arguments(
            ctypes.c_uint64(accumulators.pointer),
            ctypes.c_uint64(output.pointer),
            ctypes.c_uint64(output_count),
        ),
        "reduce_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "reduce_packed_sync")
    allocator.free(accumulators)
    return output


def cauchy_coefficients(input_rows, parity_rows):
    coefficients = array.array("I")
    for parity_row in range(parity_rows):
        right = input_rows + parity_row
        for left in range(input_rows):
            difference = (left - right) % Q
            coefficients.append(pow(difference, Q - 2, Q))
    return coefficients


def encode_base(
    runtime,
    allocator,
    base_function,
    source,
    rows,
    codeword_rows,
):
    parity_rows = codeword_rows - rows
    coefficients = cauchy_coefficients(rows, parity_rows)
    coefficients_buffer = allocator.allocate_count(len(coefficients), 4)
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            coefficients_buffer.pointer,
            ctypes.c_void_p(coefficients.buffer_info()[0]),
            len(coefficients) * coefficients.itemsize,
        ),
        "copy_cauchy_coefficients",
    )
    parity = allocator.allocate_count(parity_rows * INTERLEAVE, 4)
    launch(
        runtime,
        base_function,
        parity_rows * INTERLEAVE,
        arguments(
            ctypes.c_uint64(source.pointer),
            ctypes.c_uint64(coefficients_buffer.pointer),
            ctypes.c_uint64(parity.pointer),
            ctypes.c_uint32(rows),
            ctypes.c_uint32(parity_rows),
        ),
        "base_cauchy_parity",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "base_cauchy_sync")
    codeword = allocator.allocate_count(codeword_rows * INTERLEAVE, 4)
    source_size = rows * INTERLEAVE * 4
    parity_size = parity_rows * INTERLEAVE * 4
    copy_device(runtime, codeword.pointer, source.pointer, source_size)
    copy_device(
        runtime,
        codeword.pointer + source_size,
        parity.pointer,
        parity_size,
    )
    allocator.free(parity)
    allocator.free(coefficients_buffer)
    return codeword


def encode_dense_recursive(
    runtime,
    allocator,
    functions,
    matrix_iv,
    base_function,
    source,
    level,
    records,
):
    rows, child, inner_rows, outer_rows, factor_degree, outer_degree = records[
        level
    ]
    child_source = factor_dense(
        runtime,
        allocator,
        functions,
        matrix_iv,
        source,
        rows,
        child,
        factor_degree,
        matrix_context(level, FACTOR_ROLE),
    )
    if level + 1 == len(records):
        inner = encode_base(
            runtime,
            allocator,
            base_function,
            child_source,
            child,
            inner_rows,
        )
    else:
        inner = encode_dense_recursive(
            runtime,
            allocator,
            functions,
            matrix_iv,
            base_function,
            child_source,
            level + 1,
            records,
        )
    allocator.free(child_source)
    outer = factor_dense(
        runtime,
        allocator,
        functions,
        matrix_iv,
        inner,
        inner_rows,
        outer_rows,
        outer_degree,
        matrix_context(level, OUTER_ROLE),
    )
    codeword_rows = rows + inner_rows + outer_rows
    codeword = allocator.allocate_count(codeword_rows * INTERLEAVE, 4)
    source_size = rows * INTERLEAVE * 4
    inner_size = inner_rows * INTERLEAVE * 4
    outer_size = outer_rows * INTERLEAVE * 4
    copy_device(runtime, codeword.pointer, source.pointer, source_size)
    copy_device(
        runtime,
        codeword.pointer + source_size,
        inner.pointer,
        inner_size,
    )
    copy_device(
        runtime,
        codeword.pointer + source_size + inner_size,
        outer.pointer,
        outer_size,
    )
    allocator.free(inner)
    allocator.free(outer)
    return codeword


def encode_top_boundary(
    runtime,
    allocator,
    matrix_functions,
    matrix_iv,
    base_function,
    fill_function,
    records,
    source_seed,
):
    started = time.perf_counter()
    rows, child, inner_rows, outer_rows, factor_degree, outer_degree = records[
        0
    ]
    packed = allocator.allocate_count(rows, 2)
    launch(
        runtime,
        fill_function,
        rows,
        arguments(
            ctypes.c_uint64(packed.pointer),
            ctypes.c_uint64(rows),
            ctypes.c_uint64(source_seed),
        ),
        "fill_top_packed",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "fill_top_packed_sync")
    child_source = factor_packed(
        runtime,
        allocator,
        matrix_functions,
        matrix_iv,
        packed,
        rows,
        child,
        factor_degree,
        matrix_context(0, FACTOR_ROLE),
    )
    inner = encode_dense_recursive(
        runtime,
        allocator,
        matrix_functions,
        matrix_iv,
        base_function,
        child_source,
        1,
        records,
    )
    allocator.free(child_source)
    outer = factor_dense(
        runtime,
        allocator,
        matrix_functions,
        matrix_iv,
        inner,
        inner_rows,
        outer_rows,
        outer_degree,
        matrix_context(0, OUTER_ROLE),
    )
    elapsed = time.perf_counter() - started
    return EncodedBoundary(
        packed,
        inner,
        outer,
        rows,
        inner_rows,
        outer_rows,
        elapsed,
    )


def verify_base_cauchy_kat(
    runtime,
    allocator,
    fill_function,
    base_function,
):
    rows = 17
    codeword_rows = 29
    count = rows * INTERLEAVE
    source = allocator.allocate_count(count, 4)
    launch(
        runtime,
        fill_function,
        count,
        arguments(
            ctypes.c_uint64(source.pointer),
            ctypes.c_uint64(count),
            ctypes.c_uint64(SOURCE_SEEDS[0]),
        ),
        "fill_base_kat",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "fill_base_kat_sync")
    codeword = encode_base(
        runtime,
        allocator,
        base_function,
        source,
        rows,
        codeword_rows,
    )
    source_type = ctypes.c_uint32 * count
    codeword_type = ctypes.c_uint32 * (codeword_rows * INTERLEAVE)
    source_host = source_type()
    codeword_host = codeword_type()
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(source_host, ctypes.c_void_p),
            source.pointer,
            ctypes.sizeof(source_host),
        ),
        "copy_base_kat_source",
    )
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(codeword_host, ctypes.c_void_p),
            codeword.pointer,
            ctypes.sizeof(codeword_host),
        ),
        "copy_base_kat_codeword",
    )
    if list(codeword_host[:count]) != list(source_host):
        raise SystemExit("base_systematic_prefix_mismatch")
    coefficients = cauchy_coefficients(rows, codeword_rows - rows)
    for parity_row in range(codeword_rows - rows):
        for coordinate in range(INTERLEAVE):
            expected = 0
            for input_row in range(rows):
                expected = (
                    expected
                    + source_host[input_row * INTERLEAVE + coordinate]
                    * coefficients[parity_row * rows + input_row]
                ) % Q
            actual = codeword_host[
                (rows + parity_row) * INTERLEAVE + coordinate
            ]
            if actual != expected:
                raise SystemExit(
                    f"base_cauchy_kat_mismatch_row={parity_row} "
                    f"coordinate={coordinate}"
                )
    allocator.free(codeword)
    allocator.free(source)


def main():
    if len(sys.argv) != 1:
        raise SystemExit("usage: cuda_m31_brakedown_k128_prototype.py")
    nvrtc = Path(
        os.environ.get(
            "BL_NVRTC_BIN",
            Path(__file__).parent
            / "cuda_nvrtc"
            / "nvidia"
            / "cuda_nvrtc"
            / "bin",
        )
    )
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    records, base_rows, base_codeword_rows = schedule()
    runtime = Runtime(nvrtc)
    try:
        bind_driver(runtime)
        allocator = Allocator(runtime)
        compile_started = time.perf_counter()
        runtime.compile(
            SHA3_KERNEL
            + MATRIX_KERNEL
            + SEGMENT_MERKLE_KERNEL
            + EXTRA_KERNEL,
            b"fill_matrix_packed_source",
        )
        compile_seconds = time.perf_counter() - compile_started
        matrix_functions = (
            function(runtime, "fill_matrix_packed_source"),
            function(runtime, "factor_sha3_packed"),
            function(runtime, "reduce_matrix_accumulators"),
            function(runtime, "fill_matrix_dense_source"),
            function(runtime, "factor_sha3_dense"),
        )
        initialize_function = function(runtime, "initialize_matrix_iv")
        merkle_functions = segment_merkle_functions(runtime)
        base_function = function(runtime, "base_cauchy_parity")
        matrix_iv = initialize_matrix_iv(
            runtime,
            allocator,
            initialize_function,
        )
        verify_sha3_matrix_kat(
            runtime,
            matrix_functions,
            matrix_iv.pointer,
        )
        verify_base_cauchy_kat(
            runtime,
            allocator,
            matrix_functions[3],
            base_function,
        )

        boundaries = []
        total_started = time.perf_counter()
        for source_seed in SOURCE_SEEDS:
            boundaries.append(
                encode_top_boundary(
                    runtime,
                    allocator,
                    matrix_functions,
                    matrix_iv,
                    base_function,
                    matrix_functions[0],
                    records,
                    source_seed,
                )
            )
        total_seconds = time.perf_counter() - total_started

        segments = []
        for boundary_index, boundary in enumerate(boundaries):
            segments.extend(
                (
                    Segment(
                        boundary_index,
                        PACKED_SEGMENT,
                        boundary.packed,
                    ),
                    Segment(
                        boundary_index,
                        INNER_SEGMENT,
                        boundary.inner,
                    ),
                    Segment(
                        boundary_index,
                        OUTER_SEGMENT,
                        boundary.outer,
                    ),
                )
            )
        committed_roots, commit_seconds = commit_segments(
            runtime,
            allocator,
            merkle_functions,
            segments,
        )
        (
            segment_set_root,
            openings,
            opening_seconds,
            independent_verify_seconds,
        ) = open_segments(
            runtime,
            allocator,
            merkle_functions,
            segments,
            committed_roots,
            OPENING_QUERY_FIXTURE_COUNT,
        )
        opening_fixture_mb = sum(
            opening.proof_mb for opening in openings
        )

        codeword_mb = (
            boundaries[0].codeword_rows * INTERLEAVE * 4 / 1_000_000.0
        )
        expanded_source_mb = TOP_ROWS * INTERLEAVE * 4 / 1_000_000.0
        packed_pair_mb = sum(boundary.packed.size_mb for boundary in boundaries)
        retained_pair_mb = sum(
            boundary.retained_mb for boundary in boundaries
        )
        print("prototype=m31_brakedown_k128_dual_boundary_v2")
        print(
            "evidence_class="
            "real_geometry_sha3_matrix_encoder_with_reduced_differential_kats"
        )
        print("activation=false")
        print("proof_suite_id=null")
        print("input_rows=16777216")
        print("interleave=16")
        print("logical_source_values=268435456")
        print(f"packed_boundary_pair_mb={packed_pair_mb:.6f}")
        print(f"forbidden_expanded_source_per_boundary_mb={expanded_source_mb:.6f}")
        print(f"logical_codeword_per_boundary_mb={codeword_mb:.6f}")
        print(f"retained_dual_boundary_encoder_state_mb={retained_pair_mb:.6f}")
        print(f"device_peak_mb={allocator.peak_mb:.6f}")
        print(f"device_live_after_encode_mb={allocator.live_mb:.6f}")
        print(f"host_peak_mb={process_peak_mb():.3f}")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        for index, boundary in enumerate(boundaries):
            print(
                f"boundary_{index}_encode_seconds="
                f"{boundary.encode_seconds:.6f}"
            )
        print(f"dual_boundary_encode_seconds={total_seconds:.6f}")
        print(f"sha3_512_commit_seconds={commit_seconds:.6f}")
        print(f"sha3_512_open_seconds={opening_seconds:.6f}")
        print(
            "independent_opening_verify_seconds="
            f"{independent_verify_seconds:.6f}"
        )
        print(
            "encoder_commit_open_seconds="
            f"{total_seconds + commit_seconds + opening_seconds:.6f}"
        )
        print(f"segment_count={len(segments)}")
        print(f"segment_leaf_mb={LEAF_SIZE / 1_000_000.0:.6f}")
        print(f"opening_query_fixture_count={OPENING_QUERY_FIXTURE_COUNT}")
        print(f"opening_fixture_mb={opening_fixture_mb:.6f}")
        print(f"segment_set_root_sha3_512={segment_set_root.hex()}")
        print("all_segment_roots_replayed=true")
        print("all_segment_openings_independently_verified=true")
        print("segment_leaf_mutations_rejected=6")
        print("segment_path_mutations_rejected=6")
        print("segment_root_mutations_rejected=6")
        print("authenticated_public_coin_simulated=true")
        print("launch_authenticated_public_coin=false")
        print(f"recursion_levels={len(records)}")
        print(f"base_rows={base_rows}")
        print(f"base_codeword_rows={base_codeword_rows}")
        print(
            "factor_degrees=" + ",".join(str(value) for value in FACTOR_DEGREES)
        )
        print(
            "outer_degrees=" + ",".join(str(value) for value in OUTER_DEGREES)
        )
        print("matrix_generator=sha3_512")
        print("support_sampling=uniform_without_replacement")
        print("entry_sampling=uniform_nonzero_m31")
        print("modulo_bias=false")
        print("sha3_matrix_packed_kat=true")
        print("sha3_matrix_dense_kat=true")
        print("base_cauchy_mds_kat=true")
        print("full_expanded_source_allocated=false")
        print("full_top_codeword_allocated=false")
        print("distance_parameter_generation_separate=true")
        print("iopp_attached=false")
        print("complete_proof_qualification=false")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
