from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    OrderedMapHashCall,
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


def _witness():
    builder = OrderedMapBuilder(b"\x43")
    before = builder.snapshot()
    transitions = []
    for index in range(4):
        transition = builder.prove_upsert(
            sha3_512(f"ATTACK-KEY-{index % 3}".encode("ascii")).digest(),
            sha3_512(f"ATTACK-VALUE-{index}".encode("ascii")).digest(),
        )
        builder.apply(transition)
        transitions.append(transition)
    after = builder.snapshot()
    return build_ordered_map_batch_witness(before, after, tuple(transitions))


def test_mutated_multiproof_node_is_rejected() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        witness = _witness()
        proof = list(witness.proof_nodes)
        proof[7] = replace(
            proof[7], digest_512=sha3_512(proof[7].digest_512).digest()
        )
        with pytest.raises(ValueError, match="ordered_map_batch"):
            replace(witness, proof_nodes=tuple(proof))


def test_mutated_memory_chain_is_rejected() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        witness = _witness()
        accesses = list(witness.memory_accesses)
        index = next(
            index
            for index, value in enumerate(accesses)
            if value.before != value.after
        )
        access = accesses[index]
        accesses[index] = replace(access, before=access.after)
        with pytest.raises(ValueError, match="ordered_map_batch_memory"):
            replace(witness, memory_accesses=tuple(accesses))


def test_cursor_skip_and_redundant_proof_node_are_rejected() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        witness = _witness()
        with pytest.raises(ValueError, match="ordered_map_batch_cursor_span_invalid"):
            replace(
                witness,
                next_append_index_after=witness.next_append_index_after + 1,
            )
        with pytest.raises(ValueError, match="ordered_map_batch_proof"):
            replace(
                witness,
                proof_nodes=(*witness.proof_nodes, witness.proof_nodes[-1]),
            )


def test_witness_cannot_be_relabelled_into_smaller_fixed_schedule() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        witness = _witness()
        with pytest.raises(
            ValueError,
            match="ordered_map_batch_schedule_operation_count_mismatch",
        ):
            require_ordered_map_batch_fits_schedule(
                witness,
                build_ordered_map_batch_schedule(len(witness.operations) - 1),
            )


def test_hash_call_digest_substitution_is_rejected() -> None:
    with pytest.raises(ValueError, match="ordered_map_hash_call_digest_invalid"):
        OrderedMapHashCall(
            0,
            "node",
            True,
            b"N" * 141,
            sha3_512(b"different").digest(),
        )


def test_hash_schedule_reordering_is_rejected() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        witness = _witness()
        calls = build_ordered_map_hash_schedule(
            witness,
            build_ordered_map_batch_schedule(len(witness.operations)),
        )
        with pytest.raises(ValueError, match="ordered_map_hash_schedule_order_invalid"):
            ordered_map_hash_schedule_commitment(tuple(reversed(calls)))
