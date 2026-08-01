from __future__ import annotations

from hashlib import sha3_512
from types import MappingProxyType, SimpleNamespace

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    ClaimSourceCommitments,
    _node_preimage,
    _root_preimage,
)
from experiments.fixed_shape_claim_air.claim_source_commitment_executable_air import (
    _build,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    TraceTable,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)


def test_two_leaf_claim_source_tree_composes_every_digest_edge() -> None:
    bundles = (b"claim-source-zero", b"claim-source-one")
    leaves = tuple(sha3_512(value).digest() for value in bundles)
    top = sha3_512(
        _node_preimage(
            "K128_CALIBRATION",
            child_height=0,
            position=0,
            left=leaves[0],
            right=leaves[1],
        )
    ).digest()
    root = sha3_512(
        _root_preimage(
            "K128_CALIBRATION", tree_height=1, claim_slots=2, top=top
        )
    ).digest()
    commitments = ClaimSourceCommitments(
        "K128_CALIBRATION", leaves, root, (leaves, (top,))
    )
    columns = freeze_columns(
        {
            "slot_index": tuple(
                slot for slot, bundle in enumerate(bundles) for _ in bundle
            ),
            "byte_index": tuple(
                index for bundle in bundles for index in range(len(bundle))
            ),
            "value": tuple(value for bundle in bundles for value in bundle),
        }
    )
    trace = TraceTable("claim_source_bundle_byte", columns)
    table = AirTable(trace.name, tuple(columns), trace.rows, ())
    source = SimpleNamespace(
        program=AirProgram("claim-source-mini-encoding", (table,)),
        traces=MappingProxyType({trace.name: trace}),
    )
    profile = SimpleNamespace(
        profile_id="K128_CALIBRATION",
        claim_slots=2,
        claim_source_tree_depth=1,
    )
    instance = _build(
        profile, source, bundles=bundles, commitments=commitments
    )

    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(), instance.traces
    )
    assert direct == serialized
    assert instance.source_hashes_constrained is True
    assert instance.traces["sha3_digest_batch"].rows == 4
    assert direct.maximum_degree == 2
