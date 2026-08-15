"""Cross-process K128-geometry KAT for the native interleaved-RS verifier."""

import hashlib
import os
import struct
import subprocess
import time
from pathlib import Path


PCS_MAGIC = b"BLPQPCS1"
PCS_VERSION = 1
LEAF_DOMAIN = 516
NODE_DOMAIN = 514
ROOT_DOMAIN = 515
INTERLEAVINGS_PER_SEGMENT = int(
    os.environ.get("BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT", "16")
)
if INTERLEAVINGS_PER_SEGMENT not in (16, 32):
    raise SystemExit(
        "BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT must be 16 or 32"
    )
SEGMENTS_PER_BOUNDARY = 256 // INTERLEAVINGS_PER_SEGMENT
INITIAL_SEGMENT_COUNT = 2 * SEGMENTS_PER_BOUNDARY
SEGMENT_COUNT = INITIAL_SEGMENT_COUNT + 5
SEGMENT_KIND_BASE = 32
INITIAL_TREE_LEAVES = 1 << 17
INITIAL_LEAF_SIZE = INTERLEAVINGS_PER_SEGMENT * 64
MAIN_OPENING_COUNT = 1_600
AUXILIARY_TREE_LEAVES = 1 << 13
SUMCHECK_LEAF_SIZE = 9 * 64
GKR_MASK_OUTER_VALUES = 1 << 7
GKR_MASK_TREE_LEAVES = (
    AUXILIARY_TREE_LEAVES * GKR_MASK_OUTER_VALUES
)
GKR_MASK_LEAF_SIZE = 64
COMPLETE_AUXILIARY_LEAF_SIZE = 74 * 64
AUXILIARY_OPENING_COUNT = 1_218
QUERY_DOMAIN = 524
GKR_MASK_OUTER_QUERY_DOMAIN = 526
GKR_MASK_OUTER_QUERY_LABEL = b"gkr_mask_outer_queries/v1"
QUERY_SEED = b"\0" * 64
QUERY_MAX_DRAWS = 1 << 20
QUERY_MAX_RETRIES_PER_DRAW = 1 << 20


def sha3_parts(domain, parts):
    digest = hashlib.sha3_512()
    digest.update(PCS_MAGIC)
    digest.update(PCS_VERSION.to_bytes(2, "big"))
    digest.update(domain.to_bytes(2, "big"))
    for part in parts:
        digest.update(part)
    return digest.digest()


def exact_queries(state, label, bound, count):
    queries = []
    seen = set()
    draw = 0
    threshold = ((1 << 64) - bound) % bound
    while len(queries) < count:
        if draw >= QUERY_MAX_DRAWS:
            raise AssertionError("query_draw_limit")
        retry = 0
        while True:
            if retry >= QUERY_MAX_RETRIES_PER_DRAW:
                raise AssertionError("query_retry_limit")
            digest = sha3_parts(
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
            if (product & 0xFFFF_FFFF_FFFF_FFFF) >= threshold:
                candidate = product >> 64
                if candidate not in seen:
                    queries.append(candidate)
                    seen.add(candidate)
                    break
            retry += 1
        draw += 1
    return tuple(sorted(queries))


MAIN_QUERIES = exact_queries(
    QUERY_SEED,
    b"main_queries",
    INITIAL_TREE_LEAVES,
    MAIN_OPENING_COUNT,
)
AUXILIARY_QUERIES = exact_queries(
    QUERY_SEED,
    b"aux_queries",
    AUXILIARY_TREE_LEAVES,
    AUXILIARY_OPENING_COUNT,
)


def gkr_mask_tensor_queries():
    queries = []
    for ordinal, inner_query in enumerate(AUXILIARY_QUERIES):
        digest = sha3_parts(
            GKR_MASK_OUTER_QUERY_DOMAIN,
            (
                QUERY_SEED,
                GKR_MASK_OUTER_QUERY_LABEL,
                ordinal.to_bytes(8, "big"),
                inner_query.to_bytes(4, "big"),
            ),
        )
        random_word = int.from_bytes(digest[:8], "little")
        outer_query = (random_word * GKR_MASK_OUTER_VALUES) >> 64
        queries.append(
            inner_query * GKR_MASK_OUTER_VALUES + outer_query
        )
    if tuple(queries) != tuple(sorted(set(queries))):
        raise AssertionError("gkr_mask_tensor_query_schedule")
    return tuple(queries)


GKR_MASK_QUERIES = gkr_mask_tensor_queries()


def leaf_digest(
    boundary,
    kind,
    data_size,
    leaf_size,
    leaf,
    payload,
):
    return sha3_parts(
        LEAF_DOMAIN,
        (
            boundary.to_bytes(8, "big"),
            kind.to_bytes(8, "big"),
            data_size.to_bytes(8, "big"),
            leaf_size.to_bytes(8, "big"),
            leaf.to_bytes(8, "big"),
            payload,
        ),
    )


def canonical_frontier(queries, tree_leaves):
    current = set(queries)
    levels = []
    for _ in range(tree_leaves.bit_length() - 1):
        levels.append(
            tuple(
                sorted(
                    index ^ 1
                    for index in current
                    if (index ^ 1) not in current
                )
            )
        )
        current = {index >> 1 for index in current}
    if current != {0}:
        raise AssertionError("canonical_frontier_did_not_reach_root")
    return tuple(levels)


def segment_geometry(segment_ordinal):
    if segment_ordinal < INITIAL_SEGMENT_COUNT:
        return (
            segment_ordinal // SEGMENTS_PER_BOUNDARY,
            SEGMENT_KIND_BASE
            + (segment_ordinal % SEGMENTS_PER_BOUNDARY),
            INITIAL_TREE_LEAVES,
            INITIAL_LEAF_SIZE,
            MAIN_OPENING_COUNT,
        )
    if segment_ordinal == INITIAL_SEGMENT_COUNT:
        return (
            2,
            64,
            AUXILIARY_TREE_LEAVES,
            SUMCHECK_LEAF_SIZE,
            AUXILIARY_OPENING_COUNT,
        )
    if segment_ordinal == INITIAL_SEGMENT_COUNT + 1:
        return (
            2,
            67,
            GKR_MASK_TREE_LEAVES,
            GKR_MASK_LEAF_SIZE,
            AUXILIARY_OPENING_COUNT,
        )
    if segment_ordinal == INITIAL_SEGMENT_COUNT + 2:
        return (
            2,
            65,
            INITIAL_TREE_LEAVES,
            64,
            MAIN_OPENING_COUNT,
        )
    if segment_ordinal == INITIAL_SEGMENT_COUNT + 3:
        return (
            2,
            66,
            AUXILIARY_TREE_LEAVES,
            COMPLETE_AUXILIARY_LEAF_SIZE,
            AUXILIARY_OPENING_COUNT,
        )
    return (
        2,
        68,
        AUXILIARY_TREE_LEAVES,
        64,
        AUXILIARY_OPENING_COUNT,
    )


def segment_fixture(segment_ordinal):
    (
        boundary,
        kind,
        tree_leaves,
        leaf_size,
        opening_count,
    ) = segment_geometry(segment_ordinal)
    data_size = tree_leaves * leaf_size
    if (
        segment_ordinal < INITIAL_SEGMENT_COUNT
        or segment_ordinal == INITIAL_SEGMENT_COUNT + 2
    ):
        queries = MAIN_QUERIES
    elif segment_ordinal == INITIAL_SEGMENT_COUNT + 1:
        queries = GKR_MASK_QUERIES
    else:
        queries = AUXILIARY_QUERIES
    if len(queries) != opening_count or queries[-1] >= tree_leaves:
        raise AssertionError("query_geometry")
    leaves = bytearray()
    current = {}
    for leaf in queries:
        seed = hashlib.sha3_512(
            b"BL/PQ512/FP16-ZK-RS/NATIVE-VERIFY-KAT/v1"
            + segment_ordinal.to_bytes(8, "big")
            + leaf.to_bytes(8, "big")
        ).digest()
        payload = seed * (leaf_size // len(seed))
        if len(payload) != leaf_size:
            raise AssertionError("fixture_leaf_size")
        leaves.extend(payload)
        current[leaf] = leaf_digest(
            boundary,
            kind,
            data_size,
            leaf_size,
            leaf,
            payload,
        )

    frontier_indices = canonical_frontier(queries, tree_leaves)
    frontier_payloads = []
    for level, indices in enumerate(frontier_indices):
        payload = b"".join(
            hashlib.sha3_512(
                b"BL/PQ512/FP16-ZK-RS/NATIVE-VERIFY-FRONTIER/v1"
                + segment_ordinal.to_bytes(8, "big")
                + level.to_bytes(8, "big")
                + index.to_bytes(8, "big")
            ).digest()
            for index in indices
        )
        frontier_payloads.append(payload)
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
                raise AssertionError("incomplete_canonical_frontier")
            next_level[parent] = sha3_parts(
                NODE_DOMAIN,
                (left, right),
            )
        current = next_level
    if set(current) != {0}:
        raise AssertionError("multiproof_did_not_reach_root")
    root = sha3_parts(
        ROOT_DOMAIN,
        (tree_leaves.to_bytes(8, "big"), current[0]),
    )
    frontier_count = sum(len(indices) for indices in frontier_indices)
    return (
        boundary,
        kind,
        data_size,
        tree_leaves,
        leaf_size,
        queries,
        root,
        bytes(leaves),
        tuple(frontier_payloads),
        frontier_count,
    )


def main():
    executable = (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "fp16_zk_rs_interleaved_verify.exe"
    )
    if not executable.is_file():
        raise SystemExit(f"native_verifier_missing={executable}")
    process = subprocess.Popen(
        [str(executable), "--mutation-kat"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    process.stdin.write(
        b"BLZKRSV3"
        + struct.pack(">I", SEGMENT_COUNT)
        + QUERY_SEED
    )
    process.stdin.flush()
    proof_mb = 0.0
    verify_seconds = 0.0
    mutation_seconds = 0.0
    started = time.perf_counter()
    try:
        for segment_ordinal in range(SEGMENT_COUNT):
            (
                boundary,
                kind,
                data_size,
                tree_leaves,
                leaf_size,
                queries,
                root,
                leaves,
                frontiers,
                frontier_count,
            ) = segment_fixture(segment_ordinal)
            header = struct.pack(
                ">QQQQQII",
                boundary,
                kind,
                data_size,
                tree_leaves,
                leaf_size,
                len(queries),
                frontier_count,
            )
            indices = struct.pack(f">{len(queries)}I", *queries)
            process.stdin.write(header)
            process.stdin.write(root)
            process.stdin.write(indices)
            process.stdin.write(leaves)
            for frontier in frontiers:
                process.stdin.write(frontier)
            process.stdin.flush()
            verify_line = process.stdout.readline().decode(
                "ascii",
                errors="strict",
            ).strip()
            mutation_line = process.stdout.readline().decode(
                "ascii",
                errors="strict",
            ).strip()
            if not verify_line.startswith(
                f"OK segment={segment_ordinal} "
            ):
                raise SystemExit(
                    f"native_verify_response={verify_line!r}"
                )
            if not mutation_line.startswith(
                f"MUTATION segment={segment_ordinal} "
            ):
                raise SystemExit(
                    f"native_mutation_response={mutation_line!r}"
                )
            verify_seconds += float(
                verify_line.split("verify_seconds=", 1)[1]
            )
            mutation_seconds += float(
                mutation_line.split("mutation_seconds=", 1)[1].split(
                    " ",
                    1,
                )[0]
            )
            if not all(
                f"{name}=true" in mutation_line
                for name in (
                    "leaf_mutation_rejected",
                    "frontier_mutation_rejected",
                    "root_mutation_rejected",
                )
            ):
                raise SystemExit(
                    f"native_mutation_acceptance={mutation_line!r}"
                )
            proof_mb += (
                len(root)
                + len(indices)
                + len(leaves)
                + sum(len(frontier) for frontier in frontiers)
            ) / 1_000_000
        process.stdin.close()
        done = process.stdout.readline().decode(
            "ascii",
            errors="strict",
        ).strip()
        status = process.wait(timeout=10)
        stderr = process.stderr.read().decode(
            "utf-8",
            errors="replace",
        )
        if (
            done != f"DONE segments={SEGMENT_COUNT}"
            or status != 0
            or stderr
        ):
            raise SystemExit(
                "native_verifier_finish="
                f"done={done!r};status={status};stderr={stderr!r}"
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    wall_seconds = time.perf_counter() - started
    print("kat=fp16_zk_rs_interleaved_native_verify_v3")
    print("evidence_class=deterministic_cross_language_k128_geometry")
    print(f"segment_count={SEGMENT_COUNT}")
    print("initial_tree_leaves=131072")
    print("initial_opening_count_per_segment=1600")
    print("auxiliary_tree_leaves=8192")
    print("gkr_mask_tensor_tree_leaves=1048576")
    print("gkr_mask_tensor_leaf_bytes=64")
    print("gkr_mask_outer_queries_verifier_derived=true")
    print("auxiliary_opening_count_per_segment=1218")
    print(f"proof_fixture_mb={proof_mb:.6f}")
    print(f"verify_compute_seconds={verify_seconds:.6f}")
    print(f"mutation_compute_seconds={mutation_seconds:.6f}")
    print(f"fixture_build_and_verify_wall_seconds={wall_seconds:.6f}")
    print("all_roots_verified=true")
    print("all_leaf_mutations_rejected=true")
    print("all_frontier_mutations_rejected=true")
    print("all_root_mutations_rejected=true")
    print("proof_system_qualification=false")


if __name__ == "__main__":
    main()
