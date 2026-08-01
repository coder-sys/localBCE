from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    StructuralError,
    evaluate_program,
)
from experiments.fixed_shape_claim_air.master_public_composition import (
    build_master_public_composition,
)
from experiments.fixed_shape_claim_air.wide_public_executable_air import (
    build_wide_public_executable_air_v2,
)
from tests.test_bl_pq512_master_commitments_v2 import _inputs


@pytest.fixture(scope="module")
def instance():
    return build_master_public_composition(_inputs())


def test_master_public_composition_binds_all_512_bit_authorities(instance) -> None:
    report = evaluate_program(
        instance.program,
        instance.traces,
        instance.public.public_input_bytes,
    )
    assert instance.master_public_links_constrained is True
    assert len(instance.program.public_inputs) == 384
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
    with pytest.raises(StructuralError, match="master_public_wide_value_links"):
        evaluate_program(instance.program, traces, wrong_public.public_input_bytes)
