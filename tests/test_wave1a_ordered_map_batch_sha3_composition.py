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
    assert direct.identities_evaluated == 6_191_513
    assert direct.lookup_messages_evaluated == 13_931_600
    assert direct.program_commitment.hex() == (
        "706314e83f1e3895f76907a4a35fabec81cf289e3f54324464a0ddd0890dba2a"
        "ba9f8f44ea9eb079e9f97414aded7c88de64f9aa9d2dad8f0aec1bc6eb1b1ab9"
    )
    assert direct.trace_commitment.hex() == (
        "a34bb76c4c06ec7edf596d9c1a7a6a84ce169c694290e99832f9b50d0c0cdb94"
        "97f7b57559213ce361acc2747f1adbcd66d9eb24884d22907a4c48204b0cc1a7"
    )
