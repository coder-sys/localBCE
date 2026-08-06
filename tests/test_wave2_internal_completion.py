from __future__ import annotations

from dataclasses import replace
import json

import pytest

from app.wave2_internal import (
    ACTIVATION_ALLOWED,
    PRODUCTION_USABLE,
    PUBLIC_FIELD_COUNT,
    PUBLIC_FIELD_NAMES,
    SIDECAR_BYTES,
    Wave2InternalError,
    Wave2ReferenceProofVerifierV1,
    assert_activation_closed,
    build_reference_artifact,
    build_synthetic_schedule,
    fresh_synthetic_salt_512,
    synthetic_reference_environment,
    verify_reference_artifact,
)


def _artifact(fixed_k: int, real_slot_indices: tuple[int, ...] = ()):
    with synthetic_reference_environment():
        return build_reference_artifact(
            build_synthetic_schedule(
                fixed_k,
                real_slot_indices=real_slot_indices,
                label=f"test-k{fixed_k}-real-{len(real_slot_indices)}",
            )
        )


@pytest.mark.parametrize("fixed_k", [128, 512])
def test_fixed_k_reference_has_one_shape_for_cover_mixed_and_full_real(fixed_k: int) -> None:
    with synthetic_reference_environment():
        cases = (
            build_reference_artifact(
                build_synthetic_schedule(fixed_k, label=f"shape-{fixed_k}-cover")
            ),
            build_reference_artifact(
                build_synthetic_schedule(
                    fixed_k,
                    real_slot_indices=(0,),
                    label=f"shape-{fixed_k}-one",
                )
            ),
            build_reference_artifact(
                build_synthetic_schedule(
                    fixed_k,
                    real_slot_indices=tuple(range(fixed_k)),
                    label=f"shape-{fixed_k}-full",
                )
            ),
        )
        assert {artifact.fixed_k for artifact in cases} == {fixed_k}
        assert {len(artifact.proof_body) for artifact in cases} == {696}
        assert {len(artifact.sidecar.encode()) for artifact in cases} == {SIDECAR_BYTES}
        assert {len(artifact.public_fields) for artifact in cases} == {PUBLIC_FIELD_COUNT}
        assert len({artifact.schedule.private_wire_length for artifact in cases}) == 1


def test_public_receipt_is_exactly_twelve_commitment_fields_and_has_no_private_names() -> None:
    artifact = _artifact(128, (0,))
    receipt = artifact.public_receipt()
    assert tuple(receipt["public_fields"]) == PUBLIC_FIELD_NAMES
    assert receipt["public_field_count"] == PUBLIC_FIELD_COUNT
    assert receipt["sidecar_bytes"] == SIDECAR_BYTES
    assert receipt["private_witness_published"] is False
    assert receipt["private_amounts_published"] is False
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        "privateDataCommitment",
        "approvedAmountCents",
        "paymentAmountCents",
        "claimCount",
        "approvedCount",
        "deniedCount",
        "encryptedPayload",
    ):
        assert forbidden not in encoded
    assert '"witness":' not in encoded
    assert "12500" not in encoded


def test_reference_verifier_replays_public_grammar_and_binding() -> None:
    artifact = _artifact(128, (0, 7))
    with synthetic_reference_environment():
        digest = verify_reference_artifact(artifact)
        assert len(digest) == 64
        assert (
            Wave2ReferenceProofVerifierV1(artifact.identity).verify(
                proof=artifact.proof_body,
                public_fields=artifact.public_fields,
                sidecar=artifact.sidecar,
            )
            == digest
        )


def test_reference_artifact_does_not_contain_private_wire_bytes() -> None:
    artifact = _artifact(128, (0,))
    with synthetic_reference_environment():
        private_wire = artifact.schedule.private_bytes()
    assert private_wire not in artifact.proof_body
    assert private_wire not in artifact.sidecar.encode()
    assert private_wire.hex() not in json.dumps(artifact.public_receipt(), sort_keys=True)


def test_candidate_proof_cannot_be_activated() -> None:
    artifact = _artifact(128)
    assert ACTIVATION_ALLOWED is False
    assert PRODUCTION_USABLE is False
    assert_activation_closed()
    with synthetic_reference_environment(), pytest.raises(
        Wave2InternalError, match="activation_closed"
    ):
        Wave2ReferenceProofVerifierV1(artifact.identity).verify_activation(
            proof=artifact.proof_body,
            public_fields=artifact.public_fields,
            sidecar=artifact.sidecar,
        )


def test_entropy_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with synthetic_reference_environment():
        monkeypatch.setattr(
            "app.wave2_internal.secrets.token_bytes",
            lambda _length: (_ for _ in ()).throw(OSError("synthetic entropy failure")),
        )
        with pytest.raises(Wave2InternalError, match="entropy_failure_closed"):
            fresh_synthetic_salt_512()


def test_private_slot_mutation_cannot_change_kind_or_value_rules() -> None:
    artifact = _artifact(128, (0,))
    with synthetic_reference_environment():
        with pytest.raises(Wave2InternalError, match="approved_slot_value_mismatch"):
            replace(artifact.schedule.slots[0], payment_cents=1)
        with pytest.raises(Wave2InternalError, match="cover_slot_not_inert"):
            replace(artifact.schedule.slots[1], allowed_cents=1)
