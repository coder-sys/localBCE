from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.fixed_shape_claim_air.application_sha3_executable_air import Sha3Call
from experiments.fixed_shape_claim_air.hash_bus_snapshot import (
    encode_hash_bus_snapshot,
    hash_bus_semantic_port_commitment,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)


def _empty_calls():
    profile = get_profile("K128_CALIBRATION")
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    calls = tuple(
        Sha3Call(f"snapshot_{index}", b"", capacity)
        for index, capacity in enumerate(schedule.capacities)
    )
    return profile, schedule, calls


def test_k128_snapshot_matches_frozen_rust_codec_vector() -> None:
    profile, schedule, calls = _empty_calls()
    program = bytes((7,)) * 64
    commitment = hash_bus_semantic_port_commitment(profile, program, calls)
    encoded = encode_hash_bus_snapshot(profile, program, calls)

    assert len(calls) == 46_858
    assert encoded[:8] == b"BLHBSN01"
    assert encoded[11:75] == program
    assert encoded[75:139] == schedule.descriptor_commitment_512
    assert encoded[139:203] == commitment
    assert sha3_512(encoded).hexdigest() == (
        "b3575b160e3d870671d23cd864f1dfedd7cefa87721f68598434c7bc36cd64a0"
        "f387c29babe0034dbb5ee496587eef208cc11581d3cc1d58038a4ffd224dc623"
    )


def test_snapshot_rejects_capacity_order_mutation() -> None:
    profile, _, calls = _empty_calls()
    forged = list(calls)
    forged[0] = Sha3Call(forged[0].call_id, forged[0].message, forged[0].capacity + 1)
    with pytest.raises(StructuralError, match="hash_bus_snapshot_call_invalid:0"):
        encode_hash_bus_snapshot(profile, bytes(64), forged)
