from __future__ import annotations

from hashlib import sha3_512
from types import MappingProxyType, SimpleNamespace

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    ClaimSourceCommitments,
    _node_preimage,
    _root_preimage,
)
from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ClaimTruthAuthorityRegistryV1,
    ClaimTruthRootsV1,
    sign_claim_truth_roots,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.fixed_shape_claim_air.claim_source_commitment_executable_air import (
    _build as build_source,
)
from experiments.fixed_shape_claim_air.claim_truth_authority_executable_air import (
    build_claim_truth_authority_executable_air,
)
from experiments.fixed_shape_claim_air.claim_truth_global_executable_air import (
    build_claim_truth_global_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.packed_execution_commitment_executable_air import (
    _build as build_packed,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.ruleset_commitment_executable_air import (
    build_ruleset_commitment_executable_air,
)


def _encoding(name: str, bundles: tuple[bytes, ...]):
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
    trace = TraceTable(name, columns)
    table = AirTable(name, tuple(columns), trace.rows, ())
    return SimpleNamespace(
        program=AirProgram(f"{name}-mini", (table,)),
        traces=MappingProxyType({name: trace}),
    )


def _packed(
    kind: str, magic: bytes, offset: int, *, interface_only: bool = False
):
    bundles = (f"{kind}-zero".encode(), f"{kind}-one".encode())
    leaves = tuple(sha3_512(value).digest() for value in bundles)
    prefix = magic + b"\x01\x00\x02"
    return build_packed(
        SimpleNamespace(profile_id="K128_CALIBRATION", claim_slots=2),
        kind,
        _encoding(f"{kind}_bundle_byte", bundles),
        bundle_table=f"{kind}_bundle_byte",
        bundles=bundles,
        leaves=leaves,
        execution_root=sha3_512(prefix + b"".join(leaves)).digest(),
        audit_root=sha3_512(f"{kind}-audit-root".encode()).digest(),
        magic=magic,
        call_index_offset=offset,
        interface_only=interface_only,
    )


def test_global_truth_roots_share_one_engine_and_match_real_dual_pq_envelope() -> None:
    bundles = (b"source-zero", b"source-one")
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
    source_root = sha3_512(
        _root_preimage(
            "K128_CALIBRATION", tree_height=1, claim_slots=2, top=top
        )
    ).digest()
    source = build_source(
        SimpleNamespace(
            profile_id="K128_CALIBRATION",
            claim_slots=2,
            claim_source_tree_depth=1,
        ),
        _encoding("claim_source_bundle_byte", bundles),
        bundles=bundles,
        commitments=ClaimSourceCommitments(
            "K128_CALIBRATION", leaves, source_root, (leaves, (top,))
        ),
        call_index_offset=0,
        interface_only=True,
    )
    oracle = _packed("oracle", b"BLPQOXR2", 4, interface_only=True)
    policy = _packed("policy", b"BLPQPXR2", 7, interface_only=True)
    ruleset = build_ruleset_commitment_executable_air(
        get_profile("K128_CALIBRATION"), call_index_offset=10, interface_only=True
    )
    roots = ClaimTruthRootsV1(
        source_root,
        bytes(
            oracle.traces["oracle_execution_root"].columns[f"execution_{index}"][0]
            for index in range(64)
        ),
        bytes(
            oracle.traces["oracle_execution_root"].columns[f"audit_{index}"][0]
            for index in range(64)
        ),
        bytes(
            policy.traces["policy_execution_root"].columns[f"execution_{index}"][0]
            for index in range(64)
        ),
        bytes(
            policy.traces["policy_execution_root"].columns[f"audit_{index}"][0]
            for index in range(64)
        ),
        ruleset.root,
    )
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    ml_public, ml_secret = ml.generate_keypair()
    slh_public, slh_secret = slh.generate_keypair()
    registry = ClaimTruthAuthorityRegistryV1(
        "K128_CALIBRATION",
        "BL-SYNTH-GOV-INTAKE-V1",
        7,
        sha3_512(b"global-snapshot").digest(),
        ml_public,
        slh_public,
    )
    envelope = sign_claim_truth_roots(
        registry,
        roots,
        ml_adapter=ml,
        ml_secret_key=ml_secret,
        slh_adapter=slh,
        slh_secret_key=slh_secret,
    )
    authority = build_claim_truth_authority_executable_air(
        registry,
        envelope,
        ml_adapter=ml,
        slh_adapter=slh,
        call_index_offset=11,
        interface_only=True,
    )
    global_air = build_claim_truth_global_executable_air(
        source, oracle, policy, ruleset, authority
    )

    report = evaluate_program(
        global_air.composed.program,
        global_air.composed.traces,
        authority.public_input_bytes,
    )
    assert global_air.all_truth_roots_constrained is False
    assert global_air.truth_root_ports_constrained is True
    assert global_air.dual_pq_authority_constrained is True
    assert global_air.one_sha3_engine is False
    assert global_air.composed.traces["sha3_digest_batch"].rows == 12
    assert "sha3_truth_shared" not in global_air.composed.traces
    assert report.maximum_degree == 3
