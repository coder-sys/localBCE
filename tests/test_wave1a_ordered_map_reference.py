from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

from experiments.fixed_shape_claim_air.ordered_map_reference import (
    ORDERED_MAP_DEPTH,
    OrderedMapBuilder,
    require_ordered_map_upsert,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def test_insert_consumes_cursor_while_update_proves_empty_cursor_without_bloat() -> None:
    key = sha3_512(b"BL-ORDERED-MAP-KEY").digest()
    first = sha3_512(b"BL-ORDERED-MAP-VALUE-1").digest()
    second = sha3_512(b"BL-ORDERED-MAP-VALUE-2").digest()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(b"\x40")
        insert = builder.prove_upsert(key, first)
        assert insert.mode == "insert"
        assert len(insert.target_path) == len(insert.allocated_path) == ORDERED_MAP_DEPTH
        require_ordered_map_upsert(insert)
        builder.apply(insert)

        update = builder.prove_upsert(key, second)
        assert update.mode == "update"
        assert update.allocated_after is None
        assert len(update.target_path) == len(update.allocated_path) == ORDERED_MAP_DEPTH
        require_ordered_map_upsert(update)
        builder.apply(update)

        assert builder.get(key) == second
        assert insert.next_append_index_before == 2
        assert update.next_append_index_before == 3
        snapshot = builder.snapshot()
        restored = OrderedMapBuilder(snapshot.map_domain, snapshot=snapshot)
        assert restored.root == builder.root
        assert update.next_append_index_after == update.next_append_index_before
        assert restored.next_append_index == 3
