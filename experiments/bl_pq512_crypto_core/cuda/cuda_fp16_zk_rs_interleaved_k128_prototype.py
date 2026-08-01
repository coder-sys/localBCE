"""Streamed K128 interleaved zero-knowledge RS initial-oracle prototype.

This nonactivating prototype encodes the two real 2^24-value packed GKR
boundaries as 256 independent Reed--Solomon messages per boundary.  It handles
16-codeword memory-fallback or 32-codeword throughput segments, commits
canonical big-endian Fp16 rows with SHA3-512, retains only authentication
trees, and re-encodes one segment at a time after queries are fixed.

The private RS coefficients are sampled independently from the Windows system
CSPRNG and mapped exactly uniformly into M31.  A small CPU/GPU differential
KAT checks the batched coset NTT and row transpose.  The production-geometry
pass checks every queried replay leaf against the retained commitment and runs
an independent Merkle verifier plus mutation tests.

This file does not implement the constrained-code IOPP, code switching,
constraint proof, extraction theorem, exact soundness ledger, authenticated
launch public coin, or an atomic Blind Ledger proof.  It therefore receives no
proof-suite, hiding-simulator, or complete-proof qualification credit.
"""

import array
import ctypes
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cuda_dag_packed_accumulator_benchmark import (
    ProcessMemoryCounters,
    process_memory_mb,
    process_peak_mb,
)
from cuda_fp16_tower_kat import (
    CUDA,
    Q,
    add,
    ck,
    mul16,
    mul2,
    sub,
)
from cuda_m31_brakedown_factor_benchmark import arguments, function, launch
from cuda_m31_brakedown_k128_prototype import (
    Allocator,
    DeviceBuffer,
    bind_driver,
)
from cuda_m31_segment_merkle import (
    KERNEL as SEGMENT_MERKLE_KERNEL,
    LEAF_SIZE,
    Segment,
    functions as segment_merkle_functions,
    leaf_digest,
    segment_set_root,
)
from cuda_pcs_sha3_merkle_benchmark import (
    KERNEL as SHA3_KERNEL,
    NODE_DOMAIN,
    ROOT_DOMAIN,
    sha3_parts,
)
from cuda_sparse_round_kat import EXTRA


ROOT25 = (1_905_033_081, 454_651_505)
COSET = (2, 1)
ROW_QUERY_DOMAIN = 521
BASE_MESSAGE_LOG = 16
BASE_CODE_LOG = 17
BASE_MESSAGE_VALUES = 1 << BASE_MESSAGE_LOG
BASE_CODE_VALUES = 1 << BASE_CODE_LOG
MASK_COEFFICIENTS = 2_048
RETAIN_LEAVES_PER_LAUNCH = 1 << 13
INTERLEAVINGS_PER_BOUNDARY = 256
INTERLEAVINGS_PER_SEGMENT = int(
    os.environ.get("BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT", "16")
)
if INTERLEAVINGS_PER_SEGMENT not in (16, 32):
    raise SystemExit(
        "BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT must be 16 or 32"
    )
SEGMENTS_PER_BOUNDARY = (
    INTERLEAVINGS_PER_BOUNDARY // INTERLEAVINGS_PER_SEGMENT
)
BOUNDARY_COUNT = 2
SEGMENT_KIND_BASE = 32
OPENING_ROW_FIXTURE_COUNT = 1_600
FP16_BYTES = 64
NTT_BUTTERFLIES_PER_LAUNCH = 1 << 18
ROW_BYTES = INTERLEAVINGS_PER_SEGMENT * FP16_BYTES
LEAVES_PER_ROW = ROW_BYTES // LEAF_SIZE
SEGMENT_DATA_SIZE = (
    BASE_CODE_VALUES * INTERLEAVINGS_PER_SEGMENT * FP16_BYTES
)
SIMULATED_AUTHENTICATED_COIN = hashlib.sha3_512(
    b"Blind Ledger ZK RS row-query fixture v1"
).digest()

if BASE_MESSAGE_VALUES + MASK_COEFFICIENTS > BASE_CODE_VALUES:
    raise AssertionError("mask_coefficients_exceed_rs_dimension")
if ROW_BYTES % LEAF_SIZE:
    raise AssertionError("row_must_span_whole_merkle_leaves")


RS_KERNEL = r"""
__device__ __forceinline__ F4 rs_m4f2(F4 x,F2 y){
    return {m2(x.a,y),m2(x.b,y)};
}
__device__ __forceinline__ F8 rs_m8f2(F8 x,F2 y){
    return {rs_m4f2(x.a,y),rs_m4f2(x.b,y)};
}
__device__ __forceinline__ F16 rs_m16f2(F16 x,F2 y){
    return {rs_m8f2(x.a,y),rs_m8f2(x.b,y)};
}

__device__ __forceinline__ u32 rs_message_fixture(
    u32 boundary,
    u32 segment,
    u32 word,
    u32 position,
    u32 coordinate
) {
    u64 value =
        17ULL
        + (u64)boundary * 32452843ULL
        + (u64)segment * 49979687ULL
        + (u64)word * 67867967ULL
        + (u64)position * 2654435761ULL
        + (u64)coordinate * 86028121ULL;
    return (u32)(value % 2147483647ULL);
}

extern "C" __global__ void canonicalize_rs_mask_randomness(
    u32 *values,
    u64 count,
    u32 *rejected
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u32 value = values[index] & 2147483647U;
    if (value == 2147483647U) {
        atomicAdd(rejected, 1U);
    } else {
        values[index] = value;
    }
}

extern "C" __global__ void initialize_batched_rs_coefficients(
    u32 *values,
    const u32 *masks,
    u32 log_code,
    u32 message_values,
    u32 mask_coefficients,
    u32 batch,
    u32 boundary,
    u32 segment
) {
    u64 code_values = 1ULL << log_code;
    u64 count = (u64)batch * code_values;
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u32 word = (u32)(index >> log_code);
    u32 position = (u32)(index & (code_values - 1ULL));
    u32 *output = values + 16ULL * index;
    #pragma unroll
    for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
        output[coordinate] = 0U;
    }
    if (position < message_values) {
        #pragma unroll
        for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
            output[coordinate] = rs_message_fixture(
                boundary,
                segment,
                word,
                position,
                coordinate
            );
        }
    } else if (position < message_values + mask_coefficients) {
        u32 coefficient = position - message_values;
        u64 mask_offset =
            ((u64)word * mask_coefficients + coefficient) * 16ULL;
        #pragma unroll
        for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
            output[coordinate] = masks[mask_offset + coordinate];
        }
    }
}

/*
 * Canonical nonactivating real-GKR witness used by the combined prototype.
 * Every fixed-shape shard starts from the all-zero Keccak state. Boundary zero
 * is the independently reproducible FIPS-202 Keccak-f[1600] permutation of
 * that state. The committed component axis uses the sixteen fixed Lagrange
 * shard nodes, so a constant zero or one is stored at every node.
 */
__device__ __constant__ u64 rs_keccak_f_zero[25] = {
    0xf1258f7940e1dde7ULL, 0x84d5ccf933c0478aULL,
    0xd598261ea65aa9eeULL, 0xbd1547306f80494dULL,
    0x8b284e056253d057ULL, 0xff97a42d7f8e6fd4ULL,
    0x90fee5a0a44647c4ULL, 0x8c5bda0cd6192e76ULL,
    0xad30a6f71b19059cULL, 0x30935ab7d08ffc64ULL,
    0xeb5aa93f2317d635ULL, 0xa9a6e6260d712103ULL,
    0x81a57c16dbcf555fULL, 0x43b831cd0347c826ULL,
    0x01f22f1a11a5569fULL, 0x05e5635a21d9ae61ULL,
    0x64befef28cc970f2ULL, 0x613670957bc46611ULL,
    0xb87c5a554fd00ecbULL, 0x8c3ee88a1ccf32c8ULL,
    0x940c7922ae3a2614ULL, 0x1841f924a2c509e4ULL,
    0x16f53526e70465c2ULL, 0x75f644e97f30a13bULL,
    0xeaf1ff7b5ceca249ULL
};

extern "C" __global__ void initialize_b16_zero_trace_rs_coefficients(
    u32 *values,
    const u32 *masks,
    u32 log_code,
    u32 message_values,
    u32 mask_coefficients,
    u32 batch,
    u32 boundary,
    u32 segment
) {
    u64 code_values = 1ULL << log_code;
    u64 count = (u64)batch * code_values;
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u32 word = (u32)(index >> log_code);
    u32 position = (u32)(index & (code_values - 1ULL));
    u32 *output = values + 16ULL * index;
    #pragma unroll
    for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
        output[coordinate] = 0U;
    }
    if (position < message_values) {
        u32 wire = position & 2047U;
        if (boundary == 0U && wire < 1600U) {
            u32 bit = (u32)(
                (rs_keccak_f_zero[wire >> 6] >> (wire & 63U)) & 1ULL
            );
            #pragma unroll
            for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
                output[coordinate] = bit;
            }
        }
    } else if (position < message_values + mask_coefficients) {
        u32 coefficient = position - message_values;
        u64 mask_offset =
            ((u64)word * mask_coefficients + coefficient) * 16ULL;
        #pragma unroll
        for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
            output[coordinate] = masks[mask_offset + coordinate];
        }
    }
    (void)segment;
}

extern "C" __global__ void expand_rs_powers(
    F2 *powers,
    u64 step,
    F2 factor
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index < step) {
        powers[step + index] = m2(powers[index], factor);
    }
}

extern "C" __global__ void apply_rs_coset(
    u32 *values,
    const F2 *coset_powers,
    u32 log_code,
    u64 count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 position = index & ((1ULL << log_code) - 1ULL);
    st16(
        values + 16ULL * index,
        rs_m16f2(
            l16(values + 16ULL * index),
            coset_powers[position]
        )
    );
}

extern "C" __global__ void bit_reverse_batched_rs(
    u32 *values,
    u32 log_code,
    u64 count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 code_values = 1ULL << log_code;
    u64 word = index >> log_code;
    u64 position = index & (code_values - 1ULL);
    u64 reversed = (u64)__brev((u32)position) >> (32U - log_code);
    if (position >= reversed) return;
    u64 other = word * code_values + reversed;
    #pragma unroll
    for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
        u32 temporary = values[16ULL * index + coordinate];
        values[16ULL * index + coordinate] =
            values[16ULL * other + coordinate];
        values[16ULL * other + coordinate] = temporary;
    }
}

extern "C" __global__ void ntt_stage_batched_rs(
    u32 *values,
    const F2 *powers,
    u32 log_code,
    u32 stage_log,
    u64 batch,
    u64 offset
) {
    u64 code_values = 1ULL << log_code;
    u64 butterflies_per_word = code_values >> 1U;
    u64 count = batch * butterflies_per_word;
    u64 index =
        offset + (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 word = index / butterflies_per_word;
    u64 butterfly = index - word * butterflies_per_word;
    u64 half = 1ULL << (stage_log - 1U);
    u64 local = butterfly & (half - 1ULL);
    u64 block = butterfly >> (stage_log - 1U);
    u64 left = word * code_values + (block << stage_log) + local;
    u64 right = left + half;
    u64 twiddle = local << (log_code - stage_log);
    F16 left_value = l16(values + 16ULL * left);
    F16 right_value = rs_m16f2(
        l16(values + 16ULL * right),
        powers[twiddle]
    );
    st16(values + 16ULL * left, a16(left_value, right_value));
    st16(values + 16ULL * right, s16(left_value, right_value));
}

__device__ __forceinline__ u32 rs_bswap32(u32 value) {
    return (value >> 24U)
        | ((value >> 8U) & 0x0000ff00U)
        | ((value << 8U) & 0x00ff0000U)
        | (value << 24U);
}

extern "C" __global__ void transpose_rs_rows_big_endian(
    const u32 *codeword_major,
    u32 *row_major,
    u32 log_code,
    u32 batch
) {
    u64 code_values = 1ULL << log_code;
    u64 count = (u64)batch * code_values;
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 word = index >> log_code;
    u64 row = index & (code_values - 1ULL);
    u64 destination = (row * batch + word) * 16ULL;
    u64 source = index * 16ULL;
    #pragma unroll
    for (u32 coordinate = 0U; coordinate < 16U; ++coordinate) {
        row_major[destination + coordinate] =
            rs_bswap32(codeword_major[source + coordinate]);
    }
}

extern "C" __global__ void gather_rs_nodes(
    const u8 *nodes,
    const u32 *indices,
    u8 *output,
    u32 count
) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    u64 output_size = (u64)count * 64ULL;
    if (index >= output_size) return;
    u32 node = (u32)(index >> 6U);
    u32 offset = (u32)(index & 63ULL);
    output[index] = nodes[(u64)indices[node] * 64ULL + offset];
}
"""


@dataclass(frozen=True)
class RetainedTree:
    segment: Segment
    root: bytes
    levels: tuple[DeviceBuffer, ...]


@dataclass(frozen=True)
class OracleSegment:
    boundary: int
    kind: int
    buffer: DeviceBuffer
    leaf_size: int

    @property
    def data_size(self):
        return self.buffer.size

    @property
    def actual_leaves(self):
        return (self.data_size + self.leaf_size - 1) // self.leaf_size

    @property
    def tree_leaves(self):
        return 1 << (self.actual_leaves - 1).bit_length()

    @property
    def depth(self):
        return self.tree_leaves.bit_length() - 1


def segment_leaf_size(segment):
    return getattr(segment, "leaf_size", LEAF_SIZE)


def external_process_memory_mb(process_id):
    open_process = ctypes.windll.kernel32.OpenProcess
    open_process.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    open_process.restype = ctypes.c_void_p
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCounters),
        ctypes.c_ulong,
    ]
    get_process_memory_info.restype = ctypes.c_int
    handle = open_process(0x1010, 0, process_id)
    if not handle:
        return None
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not get_process_memory_info(
            handle,
            ctypes.byref(counters),
            counters.cb,
        ):
            return None
        return (
            counters.working_set_size / 1_000_000,
            counters.peak_working_set_size / 1_000_000,
        )
    finally:
        close_handle(handle)


class ProofPhaseMemorySampler:
    def __init__(self, child_process_id=None):
        self.stop_event = threading.Event()
        self.maximum_mb = 0.0
        self.maximum_child_mb = 0.0
        self.child_process_id = child_process_id
        self.child_process_ids = ()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self):
        current_mb, _ = process_memory_mb()
        child_mb = 0.0
        process_ids = list(self.child_process_ids)
        if self.child_process_id is not None:
            process_ids.append(self.child_process_id)
        for process_id in dict.fromkeys(process_ids):
            child_memory = external_process_memory_mb(
                process_id
            )
            if child_memory is not None:
                child_mb += child_memory[0]
        self.maximum_child_mb = max(
            self.maximum_child_mb,
            child_mb,
        )
        self.maximum_mb = max(
            self.maximum_mb,
            current_mb + child_mb,
        )

    def _run(self):
        while not self.stop_event.wait(0.01):
            self._sample()

    def start(self):
        self._sample()
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()
        self._sample()


class NativeMultiproofVerifier:
    def __init__(
        self,
        executable,
        segment_count,
        deferred=False,
        mutation_kat=False,
    ):
        self.segment_count = segment_count
        self.next_segment = 0
        self.closed = False
        self.deferred = deferred
        self.mutation_kat = mutation_kat
        self.process = subprocess.Popen(
            [str(executable)]
            + (["--mutation-kat"] if mutation_kat else []),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.process.stdin.write(
            b"BLZKRSV1" + struct.pack(">I", segment_count)
        )
        self.process.stdin.flush()
        self.deferred_lines = []
        self.deferred_reader_error = None
        self.deferred_reader = None
        if self.deferred:
            self.deferred_reader = threading.Thread(
                target=self._read_deferred_responses,
                daemon=True,
            )
            self.deferred_reader.start()

    def _read_deferred_responses(self):
        try:
            response_count = (
                (2 if self.mutation_kat else 1) * self.segment_count
                + 1
            )
            for _ in range(response_count):
                line = self.process.stdout.readline()
                if not line:
                    raise EOFError("native verifier response EOF")
                self.deferred_lines.append(line)
        except BaseException as error:
            self.deferred_reader_error = error

    @staticmethod
    def _parse_response(line, expected_prefix, segment_ordinal):
        decoded = line.decode("ascii", errors="strict").rstrip("\r\n")
        fields = decoded.split()
        expected_segment = f"segment={segment_ordinal}"
        if (
            len(fields) < 3
            or fields[0] != expected_prefix
            or fields[1] != expected_segment
        ):
            raise SystemExit(
                "native_multiproof_verifier_response="
                f"{decoded!r}"
            )
        return {
            field.split("=", 1)[0]: field.split("=", 1)[1]
            for field in fields[2:]
            if "=" in field
        }

    def verify(
        self,
        segment,
        root,
        leaf_queries,
        leaves,
        frontier_indices,
        frontier_payloads,
    ):
        segment_ordinal = self.next_segment
        if segment_ordinal >= self.segment_count:
            raise SystemExit("native_multiproof_segment_overflow")
        frontier_count = sum(len(indices) for indices in frontier_indices)
        header = struct.pack(
            ">QQQQQII",
            segment.boundary,
            segment.kind,
            segment.data_size,
            segment.tree_leaves,
            segment_leaf_size(segment),
            len(leaf_queries),
            frontier_count,
        )
        index_payload = struct.pack(
            f">{len(leaf_queries)}I",
            *leaf_queries,
        )
        verify_started = time.perf_counter()
        try:
            self.process.stdin.write(header)
            self.process.stdin.write(root)
            self.process.stdin.write(index_payload)
            self.process.stdin.write(leaves)
            for payload in frontier_payloads:
                self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            self._raise_failure(f"pipe:{error}")
        if self.deferred:
            verify_roundtrip_seconds = (
                time.perf_counter() - verify_started
            )
            self.next_segment += 1
            return (
                verify_roundtrip_seconds,
                0.0,
                0.0,
                0.0,
            )
        response = self.process.stdout.readline()
        if not response:
            self._raise_failure("eof_before_verify")
        verify_roundtrip_seconds = time.perf_counter() - verify_started
        verify_fields = self._parse_response(
            response,
            "OK",
            segment_ordinal,
        )
        try:
            verify_compute_seconds = float(
                verify_fields["verify_seconds"]
            )
        except (KeyError, ValueError) as error:
            self._raise_failure(f"verify_fields:{error}")

        mutation_roundtrip_seconds = 0.0
        mutation_compute_seconds = 0.0
        if self.mutation_kat:
            mutation_started = time.perf_counter()
            mutation_response = self.process.stdout.readline()
            if not mutation_response:
                self._raise_failure("eof_before_mutation")
            mutation_roundtrip_seconds = (
                time.perf_counter() - mutation_started
            )
            mutation_fields = self._parse_response(
                mutation_response,
                "MUTATION",
                segment_ordinal,
            )
            required = (
                "leaf_mutation_rejected",
                "frontier_mutation_rejected",
                "root_mutation_rejected",
            )
            if any(
                mutation_fields.get(field) != "true"
                for field in required
            ):
                self._raise_failure(
                    f"mutation_fields:{mutation_fields!r}"
                )
            try:
                mutation_compute_seconds = float(
                    mutation_fields["mutation_seconds"]
                )
            except (KeyError, ValueError) as error:
                self._raise_failure(f"mutation_seconds:{error}")
        self.next_segment += 1
        return (
            verify_roundtrip_seconds,
            verify_compute_seconds,
            mutation_roundtrip_seconds,
            mutation_compute_seconds,
        )

    def finish(self):
        if self.closed:
            return
        if self.next_segment != self.segment_count:
            self._raise_failure(
                "segment_count="
                f"{self.next_segment}/{self.segment_count}"
            )
        finish_started = time.perf_counter()
        self.process.stdin.close()
        verify_compute_seconds = 0.0
        mutation_compute_seconds = 0.0
        if self.deferred:
            self.deferred_reader.join(timeout=30)
            if self.deferred_reader.is_alive():
                self._raise_failure("deferred_reader_timeout")
            if self.deferred_reader_error is not None:
                self._raise_failure(
                    f"deferred_reader:{self.deferred_reader_error}"
                )
            responses_per_segment = 2 if self.mutation_kat else 1
            expected_response_count = (
                responses_per_segment * self.segment_count + 1
            )
            if len(self.deferred_lines) != expected_response_count:
                self._raise_failure(
                    "deferred_response_count="
                    f"{len(self.deferred_lines)}"
                )
            for segment_ordinal in range(self.segment_count):
                verify_response = self.deferred_lines[
                    responses_per_segment * segment_ordinal
                ]
                verify_fields = self._parse_response(
                    verify_response,
                    "OK",
                    segment_ordinal,
                )
                try:
                    verify_compute_seconds += float(
                        verify_fields["verify_seconds"]
                    )
                except (KeyError, ValueError) as error:
                    self._raise_failure(
                        f"deferred_timing_fields:{error}"
                    )
                if self.mutation_kat:
                    mutation_response = self.deferred_lines[
                        responses_per_segment * segment_ordinal + 1
                    ]
                    mutation_fields = self._parse_response(
                        mutation_response,
                        "MUTATION",
                        segment_ordinal,
                    )
                    required = (
                        "leaf_mutation_rejected",
                        "frontier_mutation_rejected",
                        "root_mutation_rejected",
                    )
                    if any(
                        mutation_fields.get(field) != "true"
                        for field in required
                    ):
                        self._raise_failure(
                            f"mutation_fields:{mutation_fields!r}"
                        )
                    try:
                        mutation_compute_seconds += float(
                            mutation_fields["mutation_seconds"]
                        )
                    except (KeyError, ValueError) as error:
                        self._raise_failure(
                            f"deferred_mutation_timing_fields:{error}"
                        )
        done_payload = (
            self.deferred_lines[-1]
            if self.deferred
            else self.process.stdout.readline()
        )
        done = done_payload.decode(
            "ascii",
            errors="strict",
        ).rstrip("\r\n")
        status = self.process.wait(timeout=10)
        stderr = self.process.stderr.read().decode(
            "utf-8",
            errors="replace",
        )
        self.closed = True
        if (
            done != f"DONE segments={self.segment_count}"
            or status != 0
            or stderr
        ):
            raise SystemExit(
                "native_multiproof_verifier_finish="
                f"done={done!r};status={status};stderr={stderr!r}"
            )
        return {
            "tail_seconds": time.perf_counter() - finish_started,
            "verify_compute_seconds": verify_compute_seconds,
            "mutation_compute_seconds": mutation_compute_seconds,
        }

    def abort(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)

    def _raise_failure(self, reason):
        status = self.process.poll()
        stderr = b""
        if status is not None:
            stderr = self.process.stderr.read()
        raise SystemExit(
            "native_multiproof_verifier_failure="
            f"{reason};status={status};"
            f"stderr={stderr.decode('utf-8', errors='replace')!r}"
        )


def _compile_source_module(
    nvrtc_directory,
    source,
    output_path,
    module_format,
):
    """Compile PTX or an sm_89 CUBIN in a disposable child process."""

    ctypes.windll.kernel32.SetDllDirectoryW(str(nvrtc_directory))
    nvrtc = ctypes.WinDLL(
        str(nvrtc_directory / "nvrtc64_120_0.dll")
    )
    nvrtc.nvrtcCreateProgram.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    nvrtc.nvrtcCompileProgram.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    nvrtc.nvrtcGetProgramLogSize.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    nvrtc.nvrtcGetProgramLog.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    if module_format == "ptx":
        size_function = nvrtc.nvrtcGetPTXSize
        output_function = nvrtc.nvrtcGetPTX
        architecture = b"--gpu-architecture=compute_89"
    elif module_format == "cubin":
        size_function = nvrtc.nvrtcGetCUBINSize
        output_function = nvrtc.nvrtcGetCUBIN
        architecture = b"--gpu-architecture=sm_89"
    else:
        raise ValueError("cuda_module_format")
    size_function.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    output_function.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    nvrtc.nvrtcDestroyProgram.argtypes = [
        ctypes.POINTER(ctypes.c_void_p)
    ]

    program = ctypes.c_void_p()
    ck(
        nvrtc.nvrtcCreateProgram(
            ctypes.byref(program),
            source.encode(),
            b"fp16_zk_rs_interleaved_k128.cu",
            0,
            None,
            None,
        ),
        "nvrtc_create_program",
    )
    try:
        options = (ctypes.c_char_p * 2)(
            architecture,
            b"--std=c++17",
        )
        compile_status = nvrtc.nvrtcCompileProgram(
            program,
            len(options),
            options,
        )
        if compile_status:
            log_size = ctypes.c_size_t()
            log_status = nvrtc.nvrtcGetProgramLogSize(
                program,
                ctypes.byref(log_size),
            )
            if log_status:
                raise RuntimeError(
                    "nvrtc_compile="
                    f"{compile_status};nvrtc_log_size={log_status}"
                )
            log = ctypes.create_string_buffer(log_size.value)
            log_status = nvrtc.nvrtcGetProgramLog(program, log)
            if log_status:
                raise RuntimeError(
                    "nvrtc_compile="
                    f"{compile_status};nvrtc_log={log_status}"
                )
            raise RuntimeError(
                f"nvrtc_compile={compile_status}\n"
                + log.value.decode("utf-8", errors="replace")
            )
        module_size = ctypes.c_size_t()
        ck(
            size_function(program, ctypes.byref(module_size)),
            f"nvrtc_{module_format}_size",
        )
        module = ctypes.create_string_buffer(module_size.value)
        ck(
            output_function(program, module),
            f"nvrtc_get_{module_format}",
        )
        Path(output_path).write_bytes(module.raw[: module_size.value])
    finally:
        if program.value:
            ck(
                nvrtc.nvrtcDestroyProgram(ctypes.byref(program)),
                "nvrtc_destroy_program",
            )


def compile_source_to_ptx(nvrtc_directory, source, output_path):
    _compile_source_module(
        nvrtc_directory,
        source,
        output_path,
        "ptx",
    )


def compile_source_to_cubin(nvrtc_directory, source, output_path):
    _compile_source_module(
        nvrtc_directory,
        source,
        output_path,
        "cubin",
    )


class DriverRuntime:
    """CUDA driver runtime loaded from an isolated compiler artifact."""

    def __init__(self, module_image):
        self.cuda = ctypes.WinDLL("nvcuda.dll")
        self._bind()
        self.allocs = []
        self.ctx = ctypes.c_void_p()
        self.module = ctypes.c_void_p()
        self.closed = False
        try:
            ck(self.cuda.cuInit(0), "cuInit")
            device = ctypes.c_int()
            ck(
                self.cuda.cuDeviceGet(ctypes.byref(device), 0),
                "cuDeviceGet",
            )
            ck(
                self.cuda.cuCtxCreate_v2(
                    ctypes.byref(self.ctx),
                    0,
                    device,
                ),
                "cuCtxCreate",
            )
            module_pointer = ctypes.c_char_p(module_image)
            ck(
                self.cuda.cuModuleLoadData(
                    ctypes.byref(self.module),
                    ctypes.cast(module_pointer, ctypes.c_void_p),
                ),
                "cuModuleLoadData",
            )
        except BaseException:
            if self.ctx.value:
                self.cuda.cuCtxDestroy_v2(self.ctx)
                self.ctx = ctypes.c_void_p()
            raise

    def _bind(self):
        cuda = self.cuda
        cuda.cuInit.argtypes = [ctypes.c_uint]
        cuda.cuDeviceGet.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
        ]
        cuda.cuCtxCreate_v2.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint,
            ctypes.c_int,
        ]
        cuda.cuModuleLoadData.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        cuda.cuModuleGetFunction.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]
        cuda.cuMemAlloc_v2.argtypes = [
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        cuda.cuMemcpyHtoD_v2.argtypes = [
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        cuda.cuMemcpyDtoH_v2.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_size_t,
        ]
        cuda.cuLaunchKernel.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        cuda.cuCtxSynchronize.argtypes = []
        cuda.cuMemFree_v2.argtypes = [ctypes.c_uint64]
        cuda.cuModuleUnload.argtypes = [ctypes.c_void_p]
        cuda.cuCtxDestroy_v2.argtypes = [ctypes.c_void_p]

    def alloc(self, size):
        pointer = ctypes.c_uint64()
        ck(
            self.cuda.cuMemAlloc_v2(ctypes.byref(pointer), size),
            "cuMemAlloc",
        )
        self.allocs.append(pointer.value)
        return pointer.value

    def close(self):
        if self.closed:
            return
        self.closed = True
        active_exception = sys.exc_info()[0] is not None
        first_cleanup_error = None
        for pointer in reversed(self.allocs):
            status = self.cuda.cuMemFree_v2(pointer)
            if status and first_cleanup_error is None:
                first_cleanup_error = ("cuMemFree", status)
        self.allocs.clear()
        if self.module.value:
            status = self.cuda.cuModuleUnload(self.module)
            if status and first_cleanup_error is None:
                first_cleanup_error = ("cuModuleUnload", status)
            self.module = ctypes.c_void_p()
        if self.ctx.value:
            status = self.cuda.cuCtxDestroy_v2(self.ctx)
            if status and first_cleanup_error is None:
                first_cleanup_error = ("cuCtxDestroy", status)
            self.ctx = ctypes.c_void_p()
        if first_cleanup_error is not None and not active_exception:
            name, status = first_cleanup_error
            raise RuntimeError(f"{name}:{status}")


def fp2_square(value):
    return mul2(value, value)


def fp2_power(value, exponent):
    result = (1, 0)
    while exponent:
        if exponent & 1:
            result = mul2(result, value)
        value = fp2_square(value)
        exponent >>= 1
    return result


def root_for_log(log_size):
    root = ROOT25
    for _ in range(log_size, 25):
        root = fp2_square(root)
    return root


def cpu_ntt(values, root):
    count = len(values)
    log_size = count.bit_length() - 1
    for index in range(1, count):
        reversed_index = int(f"{index:0{log_size}b}"[::-1], 2)
        if index < reversed_index:
            values[index], values[reversed_index] = (
                values[reversed_index],
                values[index],
            )
    length = 2
    while length <= count:
        stage_log = length.bit_length() - 1
        stage_root = root
        for _ in range(stage_log, log_size):
            stage_root = fp2_square(stage_root)
        for base in range(0, count, length):
            twiddle = (1, 0)
            for offset in range(length // 2):
                left = values[base + offset]
                scalar = twiddle + (0,) * 14
                right = mul16(
                    values[base + length // 2 + offset],
                    scalar,
                )
                values[base + offset] = add(left, right)
                values[base + length // 2 + offset] = sub(left, right)
                twiddle = mul2(twiddle, stage_root)
        length *= 2
    return values


def message_fixture(boundary, segment, word, position, coordinate):
    return (
        17
        + boundary * 32_452_843
        + segment * 49_979_687
        + word * 67_867_967
        + position * 2_654_435_761
        + coordinate * 86_028_121
    ) % Q


def coefficient_fixture(
    masks,
    boundary,
    segment,
    word,
    position,
    coordinate,
    message_values,
    mask_coefficients,
):
    if position < message_values:
        return message_fixture(
            boundary,
            segment,
            word,
            position,
            coordinate,
        )
    if position < message_values + mask_coefficients:
        coefficient = position - message_values
        return masks[
            (word * mask_coefficients + coefficient) * 16 + coordinate
        ]
    return 0


def copy_to_host(runtime, buffer, name):
    output = (ctypes.c_ubyte * buffer.size)()
    ck(
        runtime.cuda.cuMemcpyDtoH_v2(
            ctypes.cast(output, ctypes.c_void_p),
            buffer.pointer,
            buffer.size,
        ),
        name,
    )
    return bytes(output)


def upload(runtime, allocator, payload, name):
    buffer = allocator.allocate(len(payload))
    host = ctypes.create_string_buffer(payload)
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            buffer.pointer,
            ctypes.cast(host, ctypes.c_void_p),
            len(payload),
        ),
        name,
    )
    return buffer


def fill_system_random_host_buffer(output):
    bcrypt_gen_random = ctypes.windll.bcrypt.BCryptGenRandom
    bcrypt_gen_random.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    bcrypt_gen_random.restype = ctypes.c_long
    status = bcrypt_gen_random(
        None,
        ctypes.cast(output, ctypes.c_void_p),
        ctypes.sizeof(output),
        2,
    )
    if status:
        raise SystemExit(f"system_csprng_failed={status}")


def exact_uniform_mask_buffer(
    runtime,
    allocator,
    canonicalize_function,
    batch,
    mask_coefficients,
    label,
    random_host,
):
    count = batch * mask_coefficients * 16
    size = count * 4
    attempts = 0
    while True:
        attempts += 1
        mask_buffer = allocator.allocate(size)
        for offset in range(0, size, ctypes.sizeof(random_host)):
            chunk_size = min(ctypes.sizeof(random_host), size - offset)
            fill_system_random_host_buffer(random_host)
            ck(
                runtime.cuda.cuMemcpyHtoD_v2(
                    mask_buffer.pointer + offset,
                    ctypes.cast(random_host, ctypes.c_void_p),
                    chunk_size,
                ),
                f"{label}_upload_{offset}",
            )
        rejected = allocator.allocate(4)
        ck(
            runtime.cuda.cuMemsetD8_v2(
                rejected.pointer,
                0,
                rejected.size,
            ),
            f"{label}_rejected_zero",
        )
        launch(
            runtime,
            canonicalize_function,
            count,
            arguments(
                ctypes.c_uint64(mask_buffer.pointer),
                ctypes.c_uint64(count),
                ctypes.c_uint64(rejected.pointer),
            ),
            f"{label}_canonicalize",
        )
        ck(runtime.cuda.cuCtxSynchronize(), f"{label}_sync")
        rejected_host = ctypes.c_uint32()
        ck(
            runtime.cuda.cuMemcpyDtoH_v2(
                ctypes.byref(rejected_host),
                rejected.pointer,
                ctypes.sizeof(rejected_host),
            ),
            f"{label}_rejected_copy",
        )
        allocator.free(rejected)
        if rejected_host.value == 0:
            return mask_buffer, attempts
        allocator.free(mask_buffer)


def power_table(
    runtime,
    allocator,
    expand_function,
    count,
    factor,
    name,
):
    table = allocator.allocate_count(count, 8)
    one = (ctypes.c_uint32 * 2)(1, 0)
    ck(
        runtime.cuda.cuMemcpyHtoD_v2(
            table.pointer,
            ctypes.cast(one, ctypes.c_void_p),
            ctypes.sizeof(one),
        ),
        f"{name}_one",
    )
    step = 1
    current_factor = factor
    while step < count:
        launch(
            runtime,
            expand_function,
            step,
            arguments(
                ctypes.c_uint64(table.pointer),
                ctypes.c_uint64(step),
                (ctypes.c_uint32 * 2)(*current_factor),
            ),
            f"{name}_{step}",
        )
        current_factor = fp2_square(current_factor)
        step *= 2
    ck(runtime.cuda.cuCtxSynchronize(), f"{name}_sync")
    return table


def encode_segment(
    runtime,
    allocator,
    kernel_functions,
    root_powers,
    coset_powers,
    mask_buffer,
    boundary,
    segment,
    log_code=BASE_CODE_LOG,
    message_values=BASE_MESSAGE_VALUES,
    mask_coefficients=MASK_COEFFICIENTS,
    batch=INTERLEAVINGS_PER_SEGMENT,
    initialized_callback=None,
    initializer=None,
    initializer_context=None,
):
    code_values = 1 << log_code
    value_count = batch * code_values
    value_bytes = value_count * FP16_BYTES
    values = allocator.allocate(value_bytes)
    row_major = allocator.allocate(value_bytes)

    started = time.perf_counter()
    initializer_arguments = [
        ctypes.c_uint64(values.pointer),
        ctypes.c_uint64(mask_buffer.pointer),
        ctypes.c_uint32(log_code),
        ctypes.c_uint32(message_values),
        ctypes.c_uint32(mask_coefficients),
        ctypes.c_uint32(batch),
        ctypes.c_uint32(boundary),
        ctypes.c_uint32(segment),
    ]
    if initializer_context is not None:
        initializer_arguments.append(
            ctypes.c_uint64(initializer_context)
        )
    launch(
        runtime,
        kernel_functions["initialize"] if initializer is None else initializer,
        value_count,
        arguments(*initializer_arguments),
        (
            "initialize_batched_rs_coefficients"
            if initializer is None
            else "initialize_selected_rs_coefficients"
        ),
    )
    if initialized_callback is not None:
        ck(
            runtime.cuda.cuCtxSynchronize(),
            f"rs_initialize_callback_sync_{boundary}_{segment}",
        )
        initialized_callback(values, code_values)
    launch(
        runtime,
        kernel_functions["coset"],
        value_count,
        arguments(
            ctypes.c_uint64(values.pointer),
            ctypes.c_uint64(coset_powers.pointer),
            ctypes.c_uint32(log_code),
            ctypes.c_uint64(value_count),
        ),
        "apply_rs_coset",
    )
    ck(
        runtime.cuda.cuCtxSynchronize(),
        f"rs_initialize_coset_sync_{boundary}_{segment}",
    )
    initialize_seconds = time.perf_counter() - started

    started = time.perf_counter()
    launch(
        runtime,
        kernel_functions["reverse"],
        value_count,
        arguments(
            ctypes.c_uint64(values.pointer),
            ctypes.c_uint32(log_code),
            ctypes.c_uint64(value_count),
        ),
        "bit_reverse_batched_rs",
    )
    butterflies = batch * (code_values // 2)
    for stage_log in range(1, log_code + 1):
        for offset in range(
            0,
            butterflies,
            NTT_BUTTERFLIES_PER_LAUNCH,
        ):
            chunk = min(
                NTT_BUTTERFLIES_PER_LAUNCH,
                butterflies - offset,
            )
            launch(
                runtime,
                kernel_functions["stage"],
                chunk,
                arguments(
                    ctypes.c_uint64(values.pointer),
                    ctypes.c_uint64(root_powers.pointer),
                    ctypes.c_uint32(log_code),
                    ctypes.c_uint32(stage_log),
                    ctypes.c_uint64(batch),
                    ctypes.c_uint64(offset),
                ),
                f"ntt_stage_batched_rs_{stage_log}_{offset}",
            )
            ck(
                runtime.cuda.cuCtxSynchronize(),
                "rs_ntt_chunk_sync_"
                f"{boundary}_{segment}_{stage_log}_{offset}",
            )
    ntt_seconds = time.perf_counter() - started

    started = time.perf_counter()
    launch(
        runtime,
        kernel_functions["transpose"],
        value_count,
        arguments(
            ctypes.c_uint64(values.pointer),
            ctypes.c_uint64(row_major.pointer),
            ctypes.c_uint32(log_code),
            ctypes.c_uint32(batch),
        ),
        "transpose_rs_rows_big_endian",
    )
    ck(
        runtime.cuda.cuCtxSynchronize(),
        f"rs_transpose_sync_{boundary}_{segment}",
    )
    transpose_seconds = time.perf_counter() - started
    allocator.free(values)
    return row_major, {
        "initialize": initialize_seconds,
        "ntt": ntt_seconds,
        "transpose": transpose_seconds,
        "total": initialize_seconds + ntt_seconds + transpose_seconds,
    }


def retain_tree(
    runtime,
    allocator,
    merkle_functions,
    segment,
):
    leaf_size = segment_leaf_size(segment)
    levels = []
    leaf_level = allocator.allocate_count(segment.tree_leaves, 64)
    levels.append(leaf_level)
    for leaf_offset in range(
        0,
        segment.tree_leaves,
        RETAIN_LEAVES_PER_LAUNCH,
    ):
        leaf_count = min(
            RETAIN_LEAVES_PER_LAUNCH,
            segment.tree_leaves - leaf_offset,
        )
        launch(
            runtime,
            merkle_functions["hash_leaves"],
            leaf_count,
            arguments(
                ctypes.c_uint64(segment.buffer.pointer),
                ctypes.c_uint64(leaf_level.pointer),
                ctypes.c_uint64(segment.data_size),
                ctypes.c_uint64(segment.tree_leaves),
                ctypes.c_uint32(leaf_size),
                ctypes.c_uint32(segment.boundary),
                ctypes.c_uint32(segment.kind),
                ctypes.c_uint64(leaf_offset),
            ),
            f"retain_rs_hash_leaves_{leaf_offset}",
        )
        ck(
            runtime.cuda.cuCtxSynchronize(),
            "retain_rs_hash_leaves_sync_"
            f"{segment.boundary}_{segment.kind}_{leaf_offset}",
        )
    current_count = segment.tree_leaves
    while current_count > 1:
        parent_count = current_count // 2
        parent = allocator.allocate_count(parent_count, 64)
        launch(
            runtime,
            merkle_functions["hash_nodes"],
            parent_count,
            arguments(
                ctypes.c_uint64(levels[-1].pointer),
                ctypes.c_uint64(parent.pointer),
                ctypes.c_uint64(parent_count),
            ),
            "retain_rs_hash_nodes",
        )
        ck(
            runtime.cuda.cuCtxSynchronize(),
            "retain_rs_hash_nodes_sync_"
            f"{segment.boundary}_{segment.kind}_{parent_count}",
        )
        levels.append(parent)
        current_count = parent_count
    root_buffer = allocator.allocate(64)
    launch(
        runtime,
        merkle_functions["hash_root"],
        1,
        arguments(
            ctypes.c_uint64(levels[-1].pointer),
            ctypes.c_uint64(root_buffer.pointer),
            ctypes.c_uint64(segment.tree_leaves),
        ),
        "retain_rs_hash_root",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "retain_rs_tree_sync")
    root = copy_to_host(runtime, root_buffer, "copy_retained_rs_root")
    allocator.free(root_buffer)
    return RetainedTree(segment, root, tuple(levels))


def derive_row_queries(set_root, count):
    rows = []
    seen = set()
    draw = 0
    while len(rows) < count:
        retry = 0
        while True:
            digest = sha3_parts(
                ROW_QUERY_DOMAIN,
                (
                    set_root,
                    SIMULATED_AUTHENTICATED_COIN,
                    draw.to_bytes(8, "big"),
                    retry.to_bytes(8, "big"),
                ),
            )
            random_word = int.from_bytes(digest[:8], "little")
            product = random_word * BASE_CODE_VALUES
            low = product & 0xFFFF_FFFF_FFFF_FFFF
            threshold = ((1 << 64) - BASE_CODE_VALUES) % BASE_CODE_VALUES
            candidate = product >> 64
            if low >= threshold and candidate not in seen:
                rows.append(candidate)
                seen.add(candidate)
                break
            retry += 1
        draw += 1
    return tuple(rows)


def canonical_frontier(leaf_queries, depth):
    current = set(leaf_queries)
    frontiers = []
    for _ in range(depth):
        frontiers.append(
            tuple(
                sorted(
                    index ^ 1
                    for index in current
                    if (index ^ 1) not in current
                )
            )
        )
        current = {index >> 1 for index in current}
    return tuple(frontiers)


def verify_canonical_multiproof(
    segment,
    root,
    leaf_queries,
    leaves,
    frontier_indices,
    frontier_payloads,
):
    if tuple(sorted(set(leaf_queries))) != tuple(leaf_queries):
        return False
    if len(leaves) != len(leaf_queries) * LEAF_SIZE:
        return False
    current = {}
    for position, leaf in enumerate(leaf_queries):
        start = position * LEAF_SIZE
        current[leaf] = leaf_digest(
            segment,
            leaf,
            leaves[start : start + LEAF_SIZE],
        )
    for level in range(segment.depth):
        indices = frontier_indices[level]
        payload = frontier_payloads[level]
        if len(payload) != len(indices) * 64:
            return False
        frontier = {
            index: payload[64 * position : 64 * position + 64]
            for position, index in enumerate(indices)
        }
        parents = sorted({index >> 1 for index in current})
        next_level = {}
        for parent in parents:
            left_index = 2 * parent
            right_index = left_index + 1
            left = current.get(left_index, frontier.get(left_index))
            right = current.get(right_index, frontier.get(right_index))
            if left is None or right is None:
                return False
            next_level[parent] = sha3_parts(NODE_DOMAIN, (left, right))
        current = next_level
    if set(current) != {0}:
        return False
    reconstructed = sha3_parts(
        ROOT_DOMAIN,
        (segment.tree_leaves.to_bytes(8, "big"), current[0]),
    )
    return reconstructed == root


def canonical_multiproof_mutations(
    segment,
    root,
    leaf_queries,
    leaves,
    frontier_indices,
    frontier_payloads,
):
    mutated_leaves = bytearray(leaves)
    mutated_leaves[0] ^= 1
    if verify_canonical_multiproof(
        segment,
        root,
        leaf_queries,
        bytes(mutated_leaves),
        frontier_indices,
        frontier_payloads,
    ):
        raise SystemExit("mutated_rs_multiproof_leaf_accepted")
    populated_level = next(
        index
        for index, payload in enumerate(frontier_payloads)
        if payload
    )
    mutated_frontiers = list(frontier_payloads)
    changed = bytearray(mutated_frontiers[populated_level])
    changed[0] ^= 1
    mutated_frontiers[populated_level] = bytes(changed)
    if verify_canonical_multiproof(
        segment,
        root,
        leaf_queries,
        leaves,
        frontier_indices,
        tuple(mutated_frontiers),
    ):
        raise SystemExit("mutated_rs_multiproof_frontier_accepted")
    mutated_root = bytearray(root)
    mutated_root[0] ^= 1
    if verify_canonical_multiproof(
        segment,
        bytes(mutated_root),
        leaf_queries,
        leaves,
        frontier_indices,
        frontier_payloads,
    ):
        raise SystemExit("mutated_rs_multiproof_root_accepted")


def open_retained_tree(
    runtime,
    allocator,
    gather_nodes_function,
    merkle_functions,
    native_verifier,
    tree,
    replay_segment,
    leaf_queries,
    return_leaves=False,
):
    leaf_size = segment_leaf_size(replay_segment)
    gather_started = time.perf_counter()
    query_words = array.array("I", leaf_queries)
    query_buffer = upload(
        runtime,
        allocator,
        query_words.tobytes(),
        "upload_rs_leaf_queries",
    )
    leaf_buffer = allocator.allocate_count(len(leaf_queries), leaf_size)
    launch(
        runtime,
        merkle_functions["gather_leaves"],
        len(leaf_queries) * leaf_size,
        arguments(
            ctypes.c_uint64(replay_segment.buffer.pointer),
            ctypes.c_uint64(leaf_buffer.pointer),
            ctypes.c_uint64(query_buffer.pointer),
            ctypes.c_uint64(replay_segment.data_size),
            ctypes.c_uint32(leaf_size),
            ctypes.c_uint32(len(leaf_queries)),
        ),
        "gather_replayed_rs_leaves",
    )
    ck(runtime.cuda.cuCtxSynchronize(), "gather_replayed_rs_leaves_sync")
    leaves = copy_to_host(
        runtime,
        leaf_buffer,
        "copy_replayed_rs_leaves",
    )
    allocator.free(leaf_buffer)
    allocator.free(query_buffer)

    frontier_indices = canonical_frontier(
        leaf_queries,
        replay_segment.depth,
    )
    frontier_payloads = []
    for level, indices in enumerate(frontier_indices):
        if not indices:
            frontier_payloads.append(b"")
            continue
        indices_array = array.array("I", indices)
        indices_buffer = upload(
            runtime,
            allocator,
            indices_array.tobytes(),
            f"upload_rs_frontier_indices_{level}",
        )
        nodes_buffer = allocator.allocate_count(len(indices), 64)
        launch(
            runtime,
            gather_nodes_function,
            len(indices) * 64,
            arguments(
                ctypes.c_uint64(tree.levels[level].pointer),
                ctypes.c_uint64(indices_buffer.pointer),
                ctypes.c_uint64(nodes_buffer.pointer),
                ctypes.c_uint32(len(indices)),
            ),
            f"gather_retained_rs_frontier_{level}",
        )
        ck(
            runtime.cuda.cuCtxSynchronize(),
            f"gather_retained_rs_frontier_{level}_sync",
        )
        frontier_payloads.append(
            copy_to_host(
                runtime,
                nodes_buffer,
                f"copy_retained_rs_frontier_{level}",
            )
        )
        allocator.free(nodes_buffer)
        allocator.free(indices_buffer)
    frontier_payloads = tuple(frontier_payloads)
    gather_seconds = time.perf_counter() - gather_started

    (
        verify_roundtrip_seconds,
        verify_compute_seconds,
        mutation_roundtrip_seconds,
        mutation_compute_seconds,
    ) = native_verifier.verify(
        replay_segment,
        tree.root,
        leaf_queries,
        leaves,
        frontier_indices,
        frontier_payloads,
    )
    proof_mb = (
        len(leaves)
        + sum(len(payload) for payload in frontier_payloads)
        + 64
    ) / 1_000_000.0
    frontier_nodes = sum(len(indices) for indices in frontier_indices)
    result = (
        proof_mb,
        frontier_nodes,
        gather_seconds,
        verify_roundtrip_seconds,
        verify_compute_seconds,
        mutation_roundtrip_seconds,
        mutation_compute_seconds,
    )
    if return_leaves:
        return result + (leaves,)
    return result


def verify_small_batched_kat(
    runtime,
    allocator,
    kernel_functions,
    expand_function,
):
    log_code = 8
    code_values = 1 << log_code
    message_values = 64
    mask_coefficients = 4
    batch = 2
    boundary = 1
    segment = 3
    mask_words = [
        (index * 1_103_515_245 + 12_345) % Q
        for index in range(batch * mask_coefficients * 16)
    ]
    mask_array = array.array("I", mask_words)
    mask_buffer = upload(
        runtime,
        allocator,
        mask_array.tobytes(),
        "upload_rs_kat_masks",
    )
    root = root_for_log(log_code)
    roots = power_table(
        runtime,
        allocator,
        expand_function,
        code_values // 2,
        root,
        "kat_root_powers",
    )
    cosets = power_table(
        runtime,
        allocator,
        expand_function,
        code_values,
        COSET,
        "kat_coset_powers",
    )
    row_major, _ = encode_segment(
        runtime,
        allocator,
        kernel_functions,
        roots,
        cosets,
        mask_buffer,
        boundary,
        segment,
        log_code,
        message_values,
        mask_coefficients,
        batch,
    )
    actual = copy_to_host(runtime, row_major, "copy_rs_kat")
    allocator.free(row_major)
    allocator.free(mask_buffer)
    allocator.free(cosets)
    allocator.free(roots)

    expected_words = []
    coset_powers = []
    current = (1, 0)
    for _ in range(code_values):
        coset_powers.append(current)
        current = mul2(current, COSET)
    for word in range(batch):
        coefficients = []
        for position in range(code_values):
            value = tuple(
                coefficient_fixture(
                    mask_words,
                    boundary,
                    segment,
                    word,
                    position,
                    coordinate,
                    message_values,
                    mask_coefficients,
                )
                for coordinate in range(16)
            )
            coefficients.append(
                mul16(
                    value,
                    coset_powers[position] + (0,) * 14,
                )
            )
        expected_words.append(cpu_ntt(coefficients, root))
    expected = bytearray()
    for row in range(code_values):
        for word in range(batch):
            for coordinate in expected_words[word][row]:
                expected.extend(coordinate.to_bytes(4, "big"))
    if actual != bytes(expected):
        mismatch = next(
            index
            for index, (left, right) in enumerate(zip(actual, expected))
            if left != right
        )
        raise SystemExit(f"batched_rs_ntt_kat_mismatch_byte={mismatch}")


def main():
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
    if len(sys.argv) == 3 and sys.argv[1] == "--compile-ptx":
        if not (nvrtc / "nvrtc64_120_0.dll").is_file():
            raise SystemExit("nvrtc_runtime_missing")
        compile_source_to_ptx(
            nvrtc,
            CUDA
            + EXTRA
            + SHA3_KERNEL
            + SEGMENT_MERKLE_KERNEL
            + RS_KERNEL,
            sys.argv[2],
        )
        return
    if len(sys.argv) != 1:
        raise SystemExit(
            "usage: cuda_fp16_zk_rs_interleaved_k128_prototype.py "
            "[--compile-ptx OUTPUT]"
        )
    if fp2_power(COSET, BASE_CODE_VALUES) == (1, 0):
        raise SystemExit("rs_coset_overlaps_evaluation_subgroup")
    if not (nvrtc / "nvrtc64_120_0.dll").is_file():
        raise SystemExit("nvrtc_runtime_missing")
    native_verifier_path = (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "fp16_zk_rs_interleaved_verify.exe"
    )
    if not native_verifier_path.is_file():
        raise SystemExit(
            "native_multiproof_verifier_missing="
            f"{native_verifier_path}"
        )
    with native_verifier_path.open("rb") as verifier_file:
        native_verifier_sha3_512 = hashlib.file_digest(
            verifier_file,
            "sha3_512",
        ).hexdigest()
    ptx_descriptor, ptx_name = tempfile.mkstemp(
        prefix="bl-fp16-zk-rs-",
        suffix=".ptx",
    )
    os.close(ptx_descriptor)
    ptx_path = Path(ptx_name)
    compile_started = time.perf_counter()
    try:
        compile_process = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--compile-ptx",
                str(ptx_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if compile_process.returncode:
            if compile_process.stdout:
                sys.stderr.write(compile_process.stdout)
            if compile_process.stderr:
                sys.stderr.write(compile_process.stderr)
            raise SystemExit(
                "isolated_nvrtc_compile_failed="
                f"{compile_process.returncode}"
            )
        ptx = ptx_path.read_bytes()
        if not ptx or ptx[-1] != 0:
            raise SystemExit("isolated_nvrtc_ptx_noncanonical")
    finally:
        ptx_path.unlink(missing_ok=True)
    compile_seconds = time.perf_counter() - compile_started
    runtime = DriverRuntime(ptx)
    del ptx
    del compile_process
    native_verifier = None
    try:
        bind_driver(runtime)
        allocator = Allocator(runtime)
        kernel_functions = {
            "initialize": function(
                runtime,
                "initialize_batched_rs_coefficients",
            ),
            "coset": function(runtime, "apply_rs_coset"),
            "reverse": function(runtime, "bit_reverse_batched_rs"),
            "stage": function(runtime, "ntt_stage_batched_rs"),
            "transpose": function(
                runtime,
                "transpose_rs_rows_big_endian",
            ),
            "gather_nodes": function(runtime, "gather_rs_nodes"),
            "canonicalize_masks": function(
                runtime,
                "canonicalize_rs_mask_randomness",
            ),
        }
        expand_function = function(runtime, "expand_rs_powers")
        merkle_functions = segment_merkle_functions(runtime)
        verify_small_batched_kat(
            runtime,
            allocator,
            kernel_functions,
            expand_function,
        )

        production_root = root_for_log(BASE_CODE_LOG)
        root_powers = power_table(
            runtime,
            allocator,
            expand_function,
            BASE_CODE_VALUES // 2,
            production_root,
            "production_root_powers",
        )
        coset_powers = power_table(
            runtime,
            allocator,
            expand_function,
            BASE_CODE_VALUES,
            COSET,
            "production_coset_powers",
        )
        mask_memory = ProofPhaseMemorySampler()
        mask_memory.start()
        mask_setup_started = time.perf_counter()
        mask_buffers = []
        mask_sampling_attempts = 0
        mask_random_host = (ctypes.c_ubyte * 65_536)()
        for mask_index in range(
            BOUNDARY_COUNT * SEGMENTS_PER_BOUNDARY
        ):
            mask_buffer, attempts = exact_uniform_mask_buffer(
                runtime,
                allocator,
                kernel_functions["canonicalize_masks"],
                INTERLEAVINGS_PER_SEGMENT,
                MASK_COEFFICIENTS,
                f"production_masks_{mask_index}",
                mask_random_host,
            )
            mask_buffers.append(mask_buffer)
            mask_sampling_attempts += attempts
        del mask_random_host
        mask_setup_seconds = time.perf_counter() - mask_setup_started
        mask_memory.stop()
        native_verifier = NativeMultiproofVerifier(
            native_verifier_path,
            BOUNDARY_COUNT * SEGMENTS_PER_BOUNDARY,
            mutation_kat=True,
        )
        proof_memory = ProofPhaseMemorySampler(
            native_verifier.process.pid
        )
        proof_memory.start()
        trees = []
        commit_encode_seconds = 0.0
        commit_hash_seconds = 0.0
        commit_initialize_seconds = 0.0
        commit_ntt_seconds = 0.0
        commit_transpose_seconds = 0.0
        seed_index = 0
        for boundary in range(BOUNDARY_COUNT):
            for segment_index in range(SEGMENTS_PER_BOUNDARY):
                row_major, timing = encode_segment(
                    runtime,
                    allocator,
                    kernel_functions,
                    root_powers,
                    coset_powers,
                    mask_buffers[seed_index],
                    boundary,
                    segment_index,
                )
                commit_encode_seconds += timing["total"]
                commit_initialize_seconds += timing["initialize"]
                commit_ntt_seconds += timing["ntt"]
                commit_transpose_seconds += timing["transpose"]
                segment = Segment(
                    boundary,
                    SEGMENT_KIND_BASE + segment_index,
                    row_major,
                )
                started = time.perf_counter()
                trees.append(
                    retain_tree(
                        runtime,
                        allocator,
                        merkle_functions,
                        segment,
                    )
                )
                commit_hash_seconds += time.perf_counter() - started
                allocator.free(row_major)
                seed_index += 1

        metadata_segments = tuple(tree.segment for tree in trees)
        roots = tuple(tree.root for tree in trees)
        set_root = segment_set_root(metadata_segments, roots)
        query_rows = derive_row_queries(
            set_root,
            OPENING_ROW_FIXTURE_COUNT,
        )
        leaf_queries = tuple(
            sorted(
                row * LEAVES_PER_ROW + leaf
                for row in query_rows
                for leaf in range(LEAVES_PER_ROW)
            )
        )

        replay_encode_seconds = 0.0
        replay_initialize_seconds = 0.0
        replay_ntt_seconds = 0.0
        replay_transpose_seconds = 0.0
        opening_gather_seconds = 0.0
        independent_verify_seconds = 0.0
        independent_verify_compute_seconds = 0.0
        mutation_test_seconds = 0.0
        mutation_compute_seconds = 0.0
        opening_mb = 0.0
        frontier_nodes = 0
        seed_index = 0
        for tree in trees:
            row_major, timing = encode_segment(
                runtime,
                allocator,
                kernel_functions,
                root_powers,
                coset_powers,
                mask_buffers[seed_index],
                tree.segment.boundary,
                tree.segment.kind - SEGMENT_KIND_BASE,
            )
            replay_encode_seconds += timing["total"]
            replay_initialize_seconds += timing["initialize"]
            replay_ntt_seconds += timing["ntt"]
            replay_transpose_seconds += timing["transpose"]
            replay_segment = Segment(
                tree.segment.boundary,
                tree.segment.kind,
                row_major,
            )
            (
                proof_mb,
                segment_frontier_nodes,
                gather_seconds,
                verify_seconds,
                verify_compute_seconds,
                mutations_seconds,
                mutations_compute_seconds,
            ) = open_retained_tree(
                runtime,
                allocator,
                kernel_functions["gather_nodes"],
                merkle_functions,
                native_verifier,
                tree,
                replay_segment,
                leaf_queries,
            )
            opening_gather_seconds += gather_seconds
            independent_verify_seconds += verify_seconds
            independent_verify_compute_seconds += (
                verify_compute_seconds
            )
            mutation_test_seconds += mutations_seconds
            mutation_compute_seconds += mutations_compute_seconds
            opening_mb += proof_mb
            frontier_nodes += segment_frontier_nodes
            allocator.free(row_major)
            seed_index += 1

        native_verifier.finish()
        proof_memory.stop()
        retained_tree_mb = sum(
            level.size
            for tree in trees
            for level in tree.levels
        ) / 1_000_000.0
        for tree in trees:
            for level in reversed(tree.levels):
                allocator.free(level)
        for mask_buffer in reversed(mask_buffers):
            allocator.free(mask_buffer)
        allocator.free(coset_powers)
        allocator.free(root_powers)
        initial_oracle_mechanics_seconds = (
            mask_setup_seconds
            + commit_encode_seconds
            + commit_hash_seconds
            + replay_encode_seconds
            + opening_gather_seconds
            + independent_verify_seconds
        )
        development_check_seconds = (
            initial_oracle_mechanics_seconds + mutation_test_seconds
        )

        print("prototype=fp16_zk_rs_interleaved_k128_initial_oracle_v1")
        print(
            "evidence_class="
            "real_k128_geometry_streamed_rs_commit_open_with_differential_kat"
        )
        print("activation=false")
        print("proof_suite_id=null")
        print("boundary_count=2")
        print("logical_message_values_per_boundary=16777216")
        print("interleavings_per_boundary=256")
        print(
            "interleavings_per_segment="
            f"{INTERLEAVINGS_PER_SEGMENT}"
        )
        print(f"segments_per_boundary={SEGMENTS_PER_BOUNDARY}")
        print(f"segment_count={len(trees)}")
        print("base_message_values=65536")
        print("base_code_values=131072")
        print("mask_coefficients_per_codeword=2048")
        print("mask_sampling=windows_system_csprng_exact_uniform_m31")
        print(f"mask_sampling_attempts={mask_sampling_attempts}")
        print(
            "retained_uniform_masks_mb="
            f"{sum(buffer.size for buffer in mask_buffers) / 1_000_000.0:.6f}"
        )
        print("evaluation_domain=disjoint_fp2_coset")
        print(f"coset={COSET[0]},{COSET[1]}")
        print("canonical_field_encoding=big_endian_u32_per_m31_coordinate")
        print(f"logical_codeword_per_boundary_mb={2 ** 25 * 64 / 1_000_000.0:.6f}")
        print(f"segment_codeword_mb={SEGMENT_DATA_SIZE / 1_000_000.0:.6f}")
        print(f"retained_authentication_trees_mb={retained_tree_mb:.6f}")
        print(f"tracked_device_peak_mb={allocator.peak_mb:.6f}")
        print(
            "proof_phase_host_peak_mb="
            f"{max(mask_memory.maximum_mb, proof_memory.maximum_mb):.3f}"
        )
        print(f"mask_setup_host_peak_mb={mask_memory.maximum_mb:.3f}")
        print(
            "native_verifier_peak_mb="
            f"{proof_memory.maximum_child_mb:.3f}"
        )
        print(
            "parent_process_lifetime_host_peak_mb="
            f"{process_peak_mb():.3f}"
        )
        print("scratch_mb=0.000000")
        print(f"nvrtc_compile_seconds={compile_seconds:.6f}")
        print("nvrtc_compiler_process_isolated=true")
        print("native_multiproof_verifier_process_isolated=true")
        print(
            "native_multiproof_verifier_sha3_512="
            f"{native_verifier_sha3_512}"
        )
        print(f"mask_entropy_setup_seconds={mask_setup_seconds:.6f}")
        print(f"commit_initialize_seconds={commit_initialize_seconds:.6f}")
        print(f"commit_ntt_seconds={commit_ntt_seconds:.6f}")
        print(f"commit_transpose_seconds={commit_transpose_seconds:.6f}")
        print(f"commit_encode_seconds={commit_encode_seconds:.6f}")
        print(f"sha3_512_commit_seconds={commit_hash_seconds:.6f}")
        print(f"replay_initialize_seconds={replay_initialize_seconds:.6f}")
        print(f"replay_ntt_seconds={replay_ntt_seconds:.6f}")
        print(f"replay_transpose_seconds={replay_transpose_seconds:.6f}")
        print(f"replay_encode_seconds={replay_encode_seconds:.6f}")
        print(f"opening_gather_seconds={opening_gather_seconds:.6f}")
        print(
            "independent_opening_verify_seconds="
            f"{independent_verify_seconds:.6f}"
        )
        print(
            "independent_opening_verify_compute_seconds="
            f"{independent_verify_compute_seconds:.6f}"
        )
        print(f"mutation_test_seconds={mutation_test_seconds:.6f}")
        print(
            "mutation_compute_seconds="
            f"{mutation_compute_seconds:.6f}"
        )
        print(
            "initial_oracle_mechanics_seconds="
            f"{initial_oracle_mechanics_seconds:.6f}"
        )
        print(
            "development_checks_inclusive_seconds="
            f"{development_check_seconds:.6f}"
        )
        print(f"opening_row_fixture_count={OPENING_ROW_FIXTURE_COUNT}")
        print(f"leaf_queries_per_segment={len(leaf_queries)}")
        print(f"canonical_frontier_nodes_total={frontier_nodes}")
        print(f"canonical_multiproof_fixture_mb={opening_mb:.6f}")
        print(f"segment_set_root_sha3_512={set_root.hex()}")
        print("small_cpu_gpu_coset_ntt_equal=true")
        print("small_row_transpose_big_endian_equal=true")
        print("rust_cuda_merkle_framing_equal=true")
        print("all_queried_leaves_replayed_and_root_verified=true")
        print(f"segment_leaf_mutations_rejected={len(trees)}")
        print(f"segment_frontier_mutations_rejected={len(trees)}")
        print(f"segment_root_mutations_rejected={len(trees)}")
        print("full_codeword_resident_per_boundary=false")
        print("full_dual_boundary_codewords_resident=false")
        print("retained_tree_strategy=true")
        print("canonical_global_multiproof_attached=true")
        print("constrained_code_iopp_attached=false")
        print("code_switching_attached=false")
        print("constraint_proof_attached=false")
        print("exact_soundness_ledger_closed=false")
        print("native_hiding_simulator_closed=false")
        print("launch_authenticated_public_coin=false")
        print("atomic_gkr_pcs_verifier_attached=false")
        print("complete_pcs_qualification=false")
        print("complete_proof_qualification=false")
    finally:
        if native_verifier is not None:
            native_verifier.abort()
        runtime.close()


if __name__ == "__main__":
    main()
