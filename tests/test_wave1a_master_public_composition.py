from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    StructuralError,
    evaluate_program,
)
from experiments.fixed_shape_claim_air.master_public_composition import (
    build_master_public_composition,
    semantic_public_inputs_from_v3_sidecar,
)
from experiments.fixed_shape_claim_air.wide_public_executable_air import (
    build_wide_public_executable_air_v2,
)
from tests.test_bl_pq512_master_commitments_v2 import _inputs


@pytest.fixture(scope="module")
def instance():
    return build_master_public_composition(_inputs())


def _public_fields(instance) -> tuple[bytes, ...]:
    return tuple(value.to_bytes(32, "big") for value in instance.public.public_outputs)


def _sidecar(instance, governance: bytes) -> bytes:
    value = instance.master.inputs
    commitments = instance.master.commitments
    return b"".join(
        (
            b"BLPQSC01",
            (1).to_bytes(2, "big"),
            bytes(2),
            (744).to_bytes(4, "big"),
            sha3_512(b"v3-profile").digest(),
            bytes(64),
            sha3_512(b"v3-schema").digest(),
            sha3_512(b"v3-verifier").digest(),
            value.strong_settlement_domain_id_512,
            value.epoch.to_bytes(8, "big"),
            (0).to_bytes(8, "big"),
            (1).to_bytes(8, "big"),
            value.replay_root_before_512,
            value.replay_root_after_512,
            governance,
            value.payment_lane_roots_before_512[0],
            value.payment_lane_roots_after_512[0],
            commitments.batch_512,
        )
    )


def _old_four_alias_governance(public_fields: tuple[bytes, ...]) -> bytes:
    digest = sha3_512(b"BL/PQ512/V2/GOVERNED-ROOTS/v1\x00")
    for value in public_fields[5:9]:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.digest()


def test_master_public_composition_binds_all_512_bit_authorities(instance) -> None:
    public_inputs = semantic_public_inputs_from_v3_sidecar(
        _public_fields(instance),
        _sidecar(instance, instance.master.commitments.governance_512),
    )
    report = evaluate_program(
        instance.program,
        instance.traces,
        public_inputs,
    )
    assert instance.master_public_links_constrained is True
    assert instance.governance_public_binding_constrained is True
    assert len(instance.program.public_inputs) == 448
    assert public_inputs == instance.public_input_bytes
    assert public_inputs[:384] == instance.public.public_input_bytes
    assert bytes(public_inputs[384:]) == instance.master.commitments.governance_512
    assert report.identities_evaluated == 4_201_272
    assert report.lookup_messages_evaluated == 9_534_632
    assert report.maximum_degree == 2


def test_fully_self_consistent_but_wrong_public_replay_root_is_rejected(instance) -> None:
    value = instance.master.inputs
    commitments = instance.master.commitments
    wrong_public = build_wide_public_executable_air_v2(
        2,
        value.strong_settlement_domain_id_512,
        value.strong_batch_nonce_512,
        (
            sha3_512(b"wrong-replay-root").digest(),
            value.replay_root_after_512,
            value.claim_truth_roots_512[0],
            value.claim_truth_roots_512[1],
            value.claim_truth_roots_512[3],
            value.claim_truth_roots_512[5],
            commitments.batch_512,
            commitments.value_conservation_512,
            commitments.settlement_512,
        ),
    )
    traces = dict(instance.traces)
    traces.update(wrong_public.traces)
    public_inputs = (
        *wrong_public.public_input_bytes,
        *commitments.governance_512,
    )
    with pytest.raises(StructuralError, match="master_public_wide_value_links"):
        evaluate_program(instance.program, traces, public_inputs)


def test_old_four_alias_governance_formula_is_rejected_at_public_boundary(
    instance,
) -> None:
    public_fields = _public_fields(instance)
    old_governance = _old_four_alias_governance(public_fields)
    assert old_governance != instance.master.commitments.governance_512
    public_inputs = semantic_public_inputs_from_v3_sidecar(
        public_fields,
        _sidecar(instance, old_governance),
    )
    with pytest.raises(
        StructuralError,
        match="air_public_input_mismatch:sidecar.strongGovernanceCommitment.byte",
    ):
        evaluate_program(instance.program, instance.traces, public_inputs)


def test_v3_semantic_sidecar_rejects_nonnull_global_suite(instance) -> None:
    sidecar = bytearray(
        _sidecar(instance, instance.master.commitments.governance_512)
    )
    sidecar[80:144] = sha3_512(b"forbidden-global-suite").digest()
    with pytest.raises(
        StructuralError,
        match="master_public_v3_sidecar_header_invalid",
    ):
        semantic_public_inputs_from_v3_sidecar(
            _public_fields(instance),
            bytes(sidecar),
        )
