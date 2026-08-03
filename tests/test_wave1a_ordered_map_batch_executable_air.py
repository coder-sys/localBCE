from __future__ import annotations

from functools import lru_cache
from hashlib import sha3_512
import os
from unittest import mock

from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_executable_air import (
    build_ordered_map_batch_executable_air,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
    build_ordered_map_batch_witness,
)
from experiments.fixed_shape_claim_air.ordered_map_reference import OrderedMapBuilder


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@lru_cache(maxsize=1)
def ordered_map_air_instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(b"\x46")
        before = builder.snapshot()
        transitions = []
        keys = tuple(
            sha3_512(f"EXECUTABLE-MAP-KEY-{index}".encode("ascii")).digest()
            for index in range(2)
        )
        for index, key in enumerate((keys[0], keys[1], keys[0])):
            transition = builder.prove_upsert(
                key,
                sha3_512(f"EXECUTABLE-MAP-VALUE-{index}".encode("ascii")).digest(),
            )
            builder.apply(transition)
            transitions.append(transition)
        witness = build_ordered_map_batch_witness(
            before,
            builder.snapshot(),
            tuple(transitions),
        )
        return build_ordered_map_batch_executable_air(
            witness,
            build_ordered_map_batch_schedule(len(transitions)),
        )


def test_ordered_map_batch_air_evaluates_in_both_interpreters() -> None:
    instance = ordered_map_air_instance()

    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(),
        instance.traces,
    )

    assert direct == serialized
    assert direct.maximum_degree == 3
    assert len(instance.program.tables) == 8
    assert {table.name for table in instance.program.tables} == set(instance.traces)
    assert direct.identities_evaluated == 279_555
    assert direct.lookup_messages_evaluated == 396_316
    assert direct.program_commitment.hex() == (
        "b30d6d337c3ac813c84047d76ba67b5a76bc8c4ed7fe3d88c5de00bf77ee8e58"
        "58bd907f908306d1062b4c11d608df69d6e44ab541d09241d1b43688b0c93670"
    )
    assert direct.trace_commitment.hex() == (
        "1acc92228ec3263c39bc42cbe205c9cebc02f1bfde92eeee2c74b6b8f6b99a188"
        "30fc222ff2384d47f5a89a9ed1d4d3761932ac293a9b195c587b2789568f06d"
    )
    assert instance.hashes_constrained is False
    assert instance.traces["ordered_map_operation"].rows == 3
    assert instance.traces["ordered_map_endpoint"].rows == instance.schedule.position_rows
    assert instance.traces["ordered_map_proof"].rows == instance.schedule.proof_node_rows
    assert instance.traces["ordered_map_node"].rows == instance.schedule.node_hash_rows
    assert instance.traces["ordered_map_hash_port"].rows == instance.schedule.sha3_call_rows


def test_ordered_map_hash_families_are_fixed_and_separately_balanced() -> None:
    instance = ordered_map_air_instance()
    trace = instance.traces["ordered_map_hash_port"].columns
    leaf_stop = instance.schedule.leaf_hash_rows
    node_stop = leaf_stop + instance.schedule.node_hash_rows

    assert trace["family_leaf"] == (1,) * leaf_stop + (0,) * (
        instance.schedule.sha3_call_rows - leaf_stop
    )
    assert trace["family_node"] == (0,) * leaf_stop + (1,) * (
        node_stop - leaf_stop
    ) + (0,) * instance.schedule.header_hash_rows
    assert trace["family_header"] == (0,) * node_stop + (1,) * (
        instance.schedule.header_hash_rows
    )
    assert sum(trace["live"][:leaf_stop]) == sum(
        leaf is not None
        for leaves in (
            instance.witness.before_leaves,
            instance.witness.after_leaves,
        )
        for leaf in leaves
    )
    assert sum(trace["live"][leaf_stop:node_stop]) == (
        instance.witness.inner_node_hash_count
    )
    assert trace["live"][node_stop:] == (1, 1)
