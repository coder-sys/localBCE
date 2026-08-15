from __future__ import annotations

from hashlib import sha3_512
import inspect

import pytest

from experiments.bl_pq512_crypto_foundation.state_air_proof import (
    PORTABLE_PACKAGE_BYTES,
    PORTABLE_PACKAGE_PREFIX_BYTES,
    PORTABLE_SIDECAR_MAGIC,
    _portable_public_outputs,
    _portable_sidecar,
    build_compact_state_proof_package_v1,
    validate_compact_state_portable_statement,
)
from experiments.bl_pq512_crypto_foundation.state_plane import (
    StateEntry,
    StateOperation,
    StateSnapshot,
    build_state_transition,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_program_commitment,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.state_relation_executable_air import (
    build_state_relation_air,
)


PROGRAM_KATS = {
    "K128_CALIBRATION": (
        128,
        "71ffe88d4773caa5417339650bc2d0c64ea3606af1b08a68859d13652ef482f9"
        "5bbdc8031a3d07fabf8e2a1311d01fcbe5ec9c6bb8774b42b2cb37e55d8553da",
        "c0cc43ce3a70682ce9632571a890fd767fb3f042ede92db571547e6bb91659d2c"
        "ae07a64845b94238e8455e01753ce14b0a942e75bcb44df9d98b001cae48d87",
        "109dc085fe828d6beff2e88455ed9960df453f311f405b9f8fc7213274668006d"
        "ee860b94d4aae547bcc4cb0506e20473673bc5d60932b48a465581c3c3af155",
    ),
    "K512_CALIBRATION": (
        512,
        "ee4e4f3aa32b2c176226fae6e5180c3898320494892b86f9e30cb5fdcc585ef2"
        "99e891bdaed1a99324bfc74253d13274f6a71d1fdbe92f102a12474fe4f54d3d",
        "9c8dcf868abe565d75bbaada77bccc771d2ff407bb5170bce7087d7ba0cf686fb"
        "d15bc7d9f2a4146724e7a73c00b4be61ee22c18df247ec59e56fae0ac23539f",
        "f9c7f5600bcec9a05fc1a3bbf5dc80d239eb0a05ca7aa098325165543b354d49"
        "77ecdb5b0ced68696583d958e87d056e5ed5b3ceccc70017026618050d7f9210",
    ),
}


def _proof(profile: str, capacity: int):
    before = StateSnapshot.empty(profile, capacity=capacity, epoch=7)
    operations = tuple(
        StateOperation(
            index,
            StateEntry.empty(index),
            (
                StateEntry(index, True, b"K" * 64, b"V" * 64)
                if index == 0
                else StateEntry.empty(index)
            ),
        )
        for index in range(capacity)
    )
    return build_state_transition(
        before,
        operations,
        tuple(
            sha3_512(b"compact-state-projection" + bytes((index,))).digest()[:32]
            for index in range(12)
        ),
        sha3_512(b"compact-state-coin").digest(),
        sha3_512(b"compact-state-mask").digest(),
    )


@pytest.mark.parametrize("profile", tuple(PROGRAM_KATS))
def test_compact_state_public_statement_is_exact_and_private_free(profile: str) -> None:
    capacity, commitment_hex, _, _ = PROGRAM_KATS[profile]
    proof = _proof(profile, capacity)
    instance = build_state_relation_air(proof)
    commitment = air_program_commitment(encode_air_program(instance.program))
    outputs = _portable_public_outputs(instance.public_values)
    sidecar = _portable_sidecar(proof, commitment, outputs)

    assert commitment.hex() == commitment_hex
    assert sidecar[:8] == PORTABLE_SIDECAR_MAGIC
    assert validate_compact_state_portable_statement(
        profile,
        commitment,
        instance.public_values,
        outputs,
        sidecar,
    ) == (proof.before.root_512, proof.after.root_512)
    assert b"K" * 64 not in outputs + sidecar
    assert b"V" * 64 not in outputs + sidecar
    assert PORTABLE_PACKAGE_PREFIX_BYTES == 1_156
    assert PORTABLE_PACKAGE_BYTES == 83_887_236


@pytest.mark.parametrize("profile", tuple(PROGRAM_KATS))
def test_compact_state_projection_and_sidecar_kats(profile: str) -> None:
    capacity, _, output_sha3, sidecar_sha3 = PROGRAM_KATS[profile]
    proof = _proof(profile, capacity)
    instance = build_state_relation_air(proof)
    commitment = air_program_commitment(encode_air_program(instance.program))
    outputs = _portable_public_outputs(instance.public_values)
    sidecar = _portable_sidecar(proof, commitment, outputs)

    # These KATs bind only public roots while the governed program identity is
    # independent of private slot contents.
    assert sha3_512(outputs).hexdigest() == output_sha3
    assert sha3_512(sidecar).hexdigest() == sidecar_sha3


def test_compact_state_statement_rejects_projection_profile_and_sidecar_mutations() -> None:
    proof = _proof("K128_CALIBRATION", 128)
    instance = build_state_relation_air(proof)
    commitment = air_program_commitment(encode_air_program(instance.program))
    outputs = _portable_public_outputs(instance.public_values)
    sidecar = _portable_sidecar(proof, commitment, outputs)

    bad_outputs = bytearray(outputs)
    bad_outputs[0] ^= 1
    with pytest.raises(StructuralError, match="projection_mismatch"):
        validate_compact_state_portable_statement(
            "K128_CALIBRATION",
            commitment,
            instance.public_values,
            bytes(bad_outputs),
            sidecar,
        )

    bad_sidecar = bytearray(sidecar)
    bad_sidecar[32 + 3 * 64] ^= 1
    with pytest.raises(StructuralError, match="sidecar_binding_mismatch"):
        validate_compact_state_portable_statement(
            "K128_CALIBRATION",
            commitment,
            instance.public_values,
            outputs,
            bytes(bad_sidecar),
        )

    with pytest.raises(StructuralError, match="sidecar_binding_mismatch"):
        validate_compact_state_portable_statement(
            "K512_CALIBRATION",
            commitment,
            instance.public_values,
            outputs,
            sidecar,
        )


def test_compact_state_portable_profile_rejects_k256_and_wrong_capacity() -> None:
    for profile, capacity in (("K256_DESIGN_POINT", 256), ("K128_CALIBRATION", 8)):
        proof = _proof(profile, capacity)
        instance = build_state_relation_air(proof)
        commitment = air_program_commitment(encode_air_program(instance.program))
        outputs = _portable_public_outputs(instance.public_values)
        with pytest.raises(StructuralError, match="profile_invalid"):
            _portable_sidecar(proof, commitment, outputs)


def test_compact_state_serializer_has_no_private_field_dependency() -> None:
    source = inspect.getsource(build_compact_state_proof_package_v1)
    for forbidden in (
        "state_air_execution_bytes",
        "state_air_program_bytes",
        "evidence.operations",
        "evidence.opening",
        "state_commitment_mask",
        "evidence.snapshot",
    ):
        assert forbidden not in source
    with pytest.raises(StructuralError, match="portable_evidence_required"):
        build_compact_state_proof_package_v1(object())  # type: ignore[arg-type]
