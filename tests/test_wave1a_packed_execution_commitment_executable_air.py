from __future__ import annotations

from hashlib import sha3_512
from types import MappingProxyType, SimpleNamespace

from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    TraceTable,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.packed_execution_commitment_executable_air import (
    _build,
)


def test_two_bundle_execution_root_composes_leaf_digests_exactly() -> None:
    bundles = (b"bundle-zero", b"bundle-one")
    leaves = tuple(sha3_512(value).digest() for value in bundles)
    magic = b"BLPQPXR2"
    prefix = magic + b"\x01" + len(bundles).to_bytes(2, "big")
    execution_root = sha3_512(prefix + b"".join(leaves)).digest()
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
    trace = TraceTable("policy_bundle_byte", columns)
    table = AirTable(trace.name, tuple(columns), trace.rows, ())
    encoding = SimpleNamespace(
        program=AirProgram("packed-composition-mini-encoding", (table,)),
        traces=MappingProxyType({trace.name: trace}),
    )
    profile = SimpleNamespace(
        profile_id="K128_CALIBRATION", claim_slots=len(bundles)
    )
    instance = _build(
        profile,
        "policy",
        encoding,
        bundle_table=trace.name,
        bundles=bundles,
        leaves=leaves,
        execution_root=execution_root,
        audit_root=sha3_512(b"independent-audit-root").digest(),
        magic=magic,
    )

    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(), instance.traces
    )
    assert direct == serialized
    assert instance.execution_hashes_constrained is True
    assert instance.audit_root_dual_pq_signed is True
    assert instance.traces["sha3_digest_batch"].rows == 3
    assert direct.maximum_degree == 2
