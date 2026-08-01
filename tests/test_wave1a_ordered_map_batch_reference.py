from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
    build_ordered_map_batch_witness,
    build_ordered_map_hash_schedule,
    ordered_map_hash_schedule_commitment,
    require_ordered_map_batch_fits_schedule,
)
from experiments.fixed_shape_claim_air.ordered_map_reference import OrderedMapBuilder


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _batch():
    builder = OrderedMapBuilder(b"\x40")
    before = builder.snapshot()
    transitions = []
    for index in range(6):
        key = sha3_512(f"BATCH-KEY-{index % 4}".encode("ascii")).digest()
        value = sha3_512(f"BATCH-VALUE-{index}".encode("ascii")).digest()
        transition = builder.prove_upsert(key, value)
        builder.apply(transition)
        transitions.append(transition)
    return before, builder.snapshot(), tuple(transitions)


def test_batch_multiproof_matches_six_sequential_transitions() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        before, after, transitions = _batch()
        witness = build_ordered_map_batch_witness(before, after, transitions)

        assert witness.root_before == before.root
        assert witness.root_after == after.root
        assert witness.next_append_index_after == (
            witness.next_append_index_before
            + sum(value.mode == "insert" for value in transitions)
        )
        assert len(witness.memory_accesses) == 2 * len(transitions)
        assert len(witness.positions) == 6
        assert len(witness.proof_nodes) == 63
        assert witness.inner_node_hash_count == 136
        assert witness.inner_node_hash_count < len(transitions) * 4 * 64 // 10
        schedule = build_ordered_map_batch_schedule(len(transitions))
        require_ordered_map_batch_fits_schedule(witness, schedule)
        assert schedule.shard_index_bits == 24
        assert schedule.position_rows == schedule.memory_rows == 12
        hash_calls = build_ordered_map_hash_schedule(witness, schedule)
        assert len(hash_calls) == schedule.sha3_call_rows
        assert sum(value.family == "leaf" for value in hash_calls) == (
            schedule.leaf_hash_rows
        )
        assert sum(value.family == "node" for value in hash_calls) == (
            schedule.node_hash_rows
        )
        assert sum(value.family == "header" for value in hash_calls) == 2
        assert sum(value.live for value in hash_calls) == (
            sum(leaf is not None for leaf in witness.before_leaves)
            + sum(leaf is not None for leaf in witness.after_leaves)
            + witness.inner_node_hash_count
            + 2
        )
        assert ordered_map_hash_schedule_commitment(hash_calls).hex() == (
            "b0cd226fa3f63856c96c86e31e606b309899f3daf55dd2ba97919eca7c0949de"
            "89a0c5147f8d702a9f2c29801f3c9442e6ae9b5ba24d050b0b6d4805c635becb"
        )
