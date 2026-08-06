from __future__ import annotations

from dataclasses import replace

import pytest

from app.wave2_internal import (
    Wave2InternalError,
    Wave2ReferenceProofVerifierV1,
    build_reference_artifact,
    build_synthetic_schedule,
    synthetic_reference_environment,
)


def _artifact():
    with synthetic_reference_environment():
        return build_reference_artifact(
            build_synthetic_schedule(128, real_slot_indices=(0,), label="attack")
        )


def test_truncation_and_trailing_bytes_reject_before_reference_acceptance() -> None:
    artifact = _artifact()
    verifier = Wave2ReferenceProofVerifierV1(artifact.identity)
    with synthetic_reference_environment():
        for proof in (artifact.proof_body[:-1], artifact.proof_body + b"x"):
            with pytest.raises(Wave2InternalError, match="proof_rejected"):
                verifier.verify(
                    proof=proof,
                    public_fields=artifact.public_fields,
                    sidecar=artifact.sidecar,
                )


def test_mutated_public_field_rejects_even_when_sidecar_is_unchanged() -> None:
    artifact = _artifact()
    mutated = list(artifact.public_fields)
    mutated[9] = (int.from_bytes(mutated[9], "big") + 1).to_bytes(32, "big")
    verifier = Wave2ReferenceProofVerifierV1(artifact.identity)
    with synthetic_reference_environment(), pytest.raises(
        Wave2InternalError, match="proof_rejected|statement_binding"
    ):
        verifier.verify(
            proof=artifact.proof_body,
            public_fields=tuple(mutated),
            sidecar=artifact.sidecar,
        )


def test_mutated_sidecar_rejects_through_statement_binding() -> None:
    artifact = _artifact()
    mutated_sidecar = replace(
        artifact.sidecar,
        sequence_before=1,
        sequence_after=2,
    )
    verifier = Wave2ReferenceProofVerifierV1(artifact.identity)
    with synthetic_reference_environment(), pytest.raises(
        Wave2InternalError, match="statement_binding"
    ):
        verifier.verify(
            proof=artifact.proof_body,
            public_fields=artifact.public_fields,
            sidecar=mutated_sidecar,
        )


def test_mutated_transcript_section_rejects_by_digest_or_binding() -> None:
    artifact = _artifact()
    mutated = bytearray(artifact.proof_body)
    mutated[-1] ^= 1
    verifier = Wave2ReferenceProofVerifierV1(artifact.identity)
    with synthetic_reference_environment(), pytest.raises(
        Wave2InternalError, match="proof_rejected"
    ):
        verifier.verify(
            proof=bytes(mutated),
            public_fields=artifact.public_fields,
            sidecar=artifact.sidecar,
        )


def test_wrong_candidate_identity_rejects_without_fallback() -> None:
    artifact = _artifact()
    wrong = replace(
        artifact.identity,
        verifier_artifact_identity=bytes([artifact.identity.verifier_artifact_identity[0] ^ 1])
        + artifact.identity.verifier_artifact_identity[1:],
    )
    verifier = Wave2ReferenceProofVerifierV1(wrong)
    with synthetic_reference_environment(), pytest.raises(
        Wave2InternalError, match="proof_rejected"
    ):
        verifier.verify(
            proof=artifact.proof_body,
            public_fields=artifact.public_fields,
            sidecar=artifact.sidecar,
        )


def test_reference_path_is_guarded_outside_explicit_synthetic_environment() -> None:
    with pytest.raises(RuntimeError, match="reference_forbidden"):
        build_synthetic_schedule(128, label="guard")
