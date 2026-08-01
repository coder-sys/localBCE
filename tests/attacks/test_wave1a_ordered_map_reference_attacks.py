from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.ordered_map_reference import (
    ORDERED_MAP_SHARD_CAPACITY,
    OrderedMapBuilder,
    OrderedMapSnapshot,
    require_ordered_map_upsert,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _insert():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        return OrderedMapBuilder(b"\x41").prove_upsert(
            sha3_512(b"KEY").digest(), sha3_512(b"VALUE").digest()
        )


def test_allocated_path_mutation_is_rejected() -> None:
    witness = _insert()
    path = list(witness.allocated_path)
    path[5] = sha3_512(path[5]).digest()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        mutated = replace(witness, allocated_path=tuple(path))
        with pytest.raises(ValueError, match="ordered_map"):
            require_ordered_map_upsert(mutated)


def test_target_path_mutation_is_rejected() -> None:
    witness = _insert()
    path = list(witness.target_path)
    path[19] = sha3_512(path[19]).digest()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        mutated = replace(witness, target_path=tuple(path))
        with pytest.raises(ValueError, match="ordered_map"):
            require_ordered_map_upsert(mutated)


def test_target_leaf_mutation_is_rejected() -> None:
    witness = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        target = replace(
            witness.target_before,
            value_512=sha3_512(b"MUTATED-TARGET-VALUE").digest(),
        )
        with pytest.raises(ValueError, match="ordered_map"):
            mutated = replace(witness, target_before=target)
            require_ordered_map_upsert(mutated)


def test_cross_domain_witness_replay_is_rejected() -> None:
    witness = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(ValueError, match="ordered_map"):
            replace(witness, map_domain=b"\x42")


def test_cursor_skip_is_rejected() -> None:
    witness = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(ValueError, match="ordered_map"):
            replace(
                witness,
                next_append_index_before=witness.next_append_index_before + 1,
            )


def test_cursor_outside_governed_shard_is_rejected() -> None:
    witness = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(ValueError, match="ordered_map_cursor_invalid"):
            replace(
                witness,
                next_append_index_before=ORDERED_MAP_SHARD_CAPACITY,
                next_append_index_after=ORDERED_MAP_SHARD_CAPACITY + 1,
            )


def test_update_allocated_path_mutation_is_rejected() -> None:
    insert = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(insert.map_domain)
        builder.apply(insert)
        update = builder.prove_upsert(
            insert.key_512,
            sha3_512(b"UPDATED-VALUE").digest(),
        )
        path = list(update.allocated_path)
        path[7] = sha3_512(path[7]).digest()
        mutated = replace(update, allocated_path=tuple(path))
        with pytest.raises(ValueError, match="ordered_map"):
            require_ordered_map_upsert(mutated)


def test_update_cannot_burn_or_skip_allocator_capacity() -> None:
    insert = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(insert.map_domain)
        builder.apply(insert)
        update = builder.prove_upsert(
            insert.key_512,
            sha3_512(b"UPDATED-WITHOUT-ALLOCATION").digest(),
        )
        assert update.next_append_index_after == update.next_append_index_before
        with pytest.raises(ValueError, match="ordered_map_cursor_transition_invalid"):
            replace(
                update,
                next_append_index_after=update.next_append_index_after + 1,
            )


def test_snapshot_bad_link_and_cursor_collision_are_rejected() -> None:
    insert = _insert()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(insert.map_domain)
        builder.apply(insert)
        snapshot = builder.snapshot()

        leaves = list(snapshot.leaves)
        leaves[0] = replace(leaves[0], next_index=1)
        with pytest.raises(ValueError, match="ordered_map_snapshot_link_invalid"):
            OrderedMapSnapshot(
                snapshot.map_domain,
                snapshot.next_append_index,
                tuple(leaves),
                snapshot.inner_root,
                snapshot.root,
            )

        with pytest.raises(ValueError, match="ordered_map_snapshot_index_not_below_cursor"):
            OrderedMapSnapshot(
                snapshot.map_domain,
                insert.next_append_index_before,
                snapshot.leaves,
                snapshot.inner_root,
                snapshot.root,
            )
