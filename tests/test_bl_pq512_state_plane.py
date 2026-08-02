from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.state_plane import (
    ACTIVATION_ALLOWED,
    COMMITMENT_STATUS,
    FileStateStore,
    PROOF_SUITE_ID,
    STATUS,
    StateEntry,
    StateOperation,
    StatePlaneError,
    StateSnapshot,
    build_state_transition,
    independently_verify_state_transition,
)


def _projection() -> tuple[bytes, ...]:
    return tuple(
        sha3_512(b"BL/state-plane/projection/" + bytes((index,))).digest()[:32]
        for index in range(12)
    )


def _operations(before: StateSnapshot) -> tuple[StateOperation, ...]:
    result: list[StateOperation] = []
    for index in range(before.capacity):
        old = StateEntry.empty(index)
        new = old
        if index == 0:
            new = StateEntry(index, True, b"K" * 64, b"V" * 64)
        result.append(StateOperation(index, old, new))
    return tuple(result)


def _proof():
    before = StateSnapshot.empty("K128_CALIBRATION", capacity=8, epoch=7)
    return build_state_transition(
        before,
        _operations(before),
        _projection(),
        sha3_512(b"authenticated-public-coin").digest(),
        sha3_512(b"private-mask").digest(),
    )


def test_state_plane_replays_fixed_shape_transition_and_keeps_activation_closed() -> None:
    proof = _proof()
    independently_verify_state_transition(proof)
    assert proof.before.sequence == 0
    assert proof.after.sequence == 1
    assert proof.after.entries == (StateEntry(0, True, b"K" * 64, b"V" * 64),)
    assert proof.as_public_dict()["status"] == STATUS
    assert proof.as_public_dict()["commitment"]["status"] == COMMITMENT_STATUS
    assert proof.as_public_dict()["h4_parent_binding_status"] == "PENDING_NATIVE_H4_CONSTRAINT"
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False


def test_public_state_receipt_contains_digests_only() -> None:
    proof = _proof()
    rendered = repr(proof.as_public_dict()).encode("ascii")
    assert (b"K" * 64).hex().encode("ascii") not in rendered
    assert (b"V" * 64).hex().encode("ascii") not in rendered
    assert proof.receipt.receipt_digest_512


def test_file_store_publishes_atomically_and_rejects_stale_root(tmp_path) -> None:
    proof = _proof()
    store = FileStateStore(tmp_path / "state.bin")
    store.initialize(proof.before)
    assert store.read() == proof.before
    assert store.publish(proof) == proof.receipt
    assert store.read() == proof.after
    with pytest.raises(StatePlaneError, match="state_plane_store_stale_root"):
        store.publish(proof)


def test_state_snapshot_encoding_is_fixed_shape_and_exact() -> None:
    proof = _proof()
    assert StateSnapshot.decode(proof.before.encoded) == proof.before
    with pytest.raises(StatePlaneError, match="fixed_shape|encoding_length"):
        StateSnapshot.decode(proof.before.encoded + b"x")


def test_native_state_binding_kat_is_stable_for_the_k128_shape() -> None:
    before = StateSnapshot.empty("K128_CALIBRATION", capacity=128, epoch=7)
    operations = tuple(
        StateOperation(index, StateEntry.empty(index), StateEntry.empty(index))
        for index in range(128)
    )
    proof = build_state_transition(
        before,
        operations,
        tuple(
            sha3_512(b"projection" + bytes((index,))).digest()[:32]
            for index in range(12)
        ),
        sha3_512(b"coin").digest(),
        sha3_512(b"mask").digest(),
    )
    assert len(proof.binding_bytes) == 71_180
    assert proof.statement_digest_512.hex() == (
        "f3c37c25e22d3e4d7b2500b553151bae34bca8fc84ecea1606af8532149cebfc"
        "13f33e014fa3c0a9c4505eacbcb303118965885416a8e634a3c461eb0517a0c7"
    )
    assert proof.binding_digest_512.hex() == (
        "c648d0382061c791c4cf599f0fa8d0a7d7b647ddf9b6fceb600254686a3287cf"
        "13aec483a2e26c8a0a8cdb76ea3de7c149c9da2362695ae2c019f2810d8a5ffb"
    )


def test_transition_witness_mutation_is_rejected() -> None:
    proof = _proof()
    forged_operation = replace(
        proof.operations[0],
        after=StateEntry(0, True, b"F" * 64, b"V" * 64),
    )
    with pytest.raises(StatePlaneError, match="manifest|verifier|transition"):
        replace(proof, operations=(forged_operation, *proof.operations[1:]))
