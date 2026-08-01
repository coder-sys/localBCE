from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.a12_replay_composition_executable_air import (
    build_a12_replay_composition_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import evaluate_program
from experiments.fixed_shape_claim_air.salt_use_tag_executable_air import (
    build_salt_use_tag_executable_air,
)
from tests.test_a12_nullifier_derivation import _authority, _cover_context_v2, _identity


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def test_a12_outputs_are_exact_insert_only_replay_keys() -> None:
    a12 = build_a12_nullifier_executable_air(
        (
            AttemptNullifierAirRequest("attempt", _identity()),
            CoverNullifierAirRequest(
                "cover",
                _cover_context_v2(),
                sha3_512(b"BL-A12-REPLAY-COVER-NONCE").digest(),
            ),
        ),
        _authority(),
        interface_only=True,
    )
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        salt_use = build_salt_use_tag_executable_air(
            sha3_512(b"BL-A12-REPLAY-MASTER-SALT").digest(),
            call_index_offset=len(a12.sha3.digests),
            interface_only=True,
        )
        instance = build_a12_replay_composition_executable_air(
            a12,
            (),
            compose_sha3=True,
            interface_only=True,
            salt_use=salt_use,
        )
    report = evaluate_program(instance.program, instance.traces)
    assert report.maximum_degree == 3
    operation = instance.traces["replay_map__ordered_map_operation"].columns
    assert tuple(
        bytes(operation[f"key_{byte}"][row] for byte in range(64))
        for row in range(3)
    ) == (*a12.strong_nullifiers, salt_use.tag_512)
    assert instance.nullifier_derivations_authenticated is True
    assert instance.replay_paths_constrained is True
    assert instance.replay_hashes_constrained is False
    assert instance.salt_use_constrained is False
    assert instance.hash_ports_constrained is True
