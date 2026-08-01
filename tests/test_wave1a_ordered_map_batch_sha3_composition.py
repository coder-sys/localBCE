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
    build_ordered_map_batch_sha3_executable_air,
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
def ordered_map_sha3_air_instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        builder = OrderedMapBuilder(b"\x47")
        key = sha3_512(b"COMPOSED-KEY").digest()
        transition = builder.prove_upsert(key, sha3_512(b"INITIAL").digest())
        builder.apply(transition)
        before = builder.snapshot()
        transition = builder.prove_upsert(key, sha3_512(b"UPDATED").digest())
        builder.apply(transition)
        witness = build_ordered_map_batch_witness(
            before,
            builder.snapshot(),
            (transition,),
        )
        return build_ordered_map_batch_sha3_executable_air(
            witness,
            build_ordered_map_batch_schedule(1, shard_index_bits=2),
        )


def test_every_fixed_map_hash_row_is_composed_with_exact_sha3() -> None:
    instance = ordered_map_sha3_air_instance()

    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(),
        instance.traces,
    )

    assert direct == serialized
    assert instance.hashes_constrained is True
    assert instance.schedule.sha3_call_rows == 136
    assert instance.schedule.sha3_permutations == 276
    assert instance.traces["sha3_digest_batch"].rows == 136
    assert direct.maximum_degree == 3
    assert direct.identities_evaluated == 6_191_257
    assert direct.lookup_messages_evaluated == 13_914_320
    assert direct.program_commitment.hex() == (
        "8a9cfd72cd0787dc9dd08f757d4e8b16dd7184dca311e60de7cb975388704864"
        "8c3b4aa816cd7b0c7b5ef3f246cca5276db3e48cfb73c4fd07ddc59ba3e3ed5d"
    )
    assert direct.trace_commitment.hex() == (
        "1223369d19a69858599f6bb62d797fe1ccd0de257c19cf8d00bacc530a458432a"
        "2d45eeff52b1a7480b2603da06e358f697b24264f539bfc26afd3b076575742"
    )
