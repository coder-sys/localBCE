from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
from pathlib import Path

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.native_public_input_projection import PublicInputProjectionV1
from app.production_boundary import (
    GovernanceAuthorityV2,
    NativeStarkVerifierConfig,
    NativeStarkVerifierPort,
    NativeVerificationResult,
    ProductionBoundaryError,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    build_v2_public_fields,
    native_verifier_artifact_identity,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    PROOF_PACKAGE_BYTES,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    statement_commitment,
)
from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    build_master_commitments_v2,
    governance_preimage,
)
from tests.test_bl_pq512_master_commitments_v2 import _inputs as _master_inputs
from app.batch.poseidon import FIELD_MODULUS


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(label: str) -> bytes:
    return (int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def _authority(label: str, *, epoch: int = 1, profile_code: int = 1) -> GovernanceAuthorityV2:
    return GovernanceAuthorityV2(
        profile_code=profile_code,
        epoch=epoch,
        claim_truth_roots_512=tuple(_wide(f"{label}-truth-{index}") for index in range(6)),
        claim_truth_authority_digest_512=_wide(f"{label}-truth-authority"),
        nullifier_authority_id_512=_wide(f"{label}-nullifier-authority"),
        pepper_commitment_512=_wide(f"{label}-pepper"),
    )


def _fixture() -> tuple[ProductionProofEnvelope, bytes, GovernanceAuthorityV2, bytes]:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    domain = _field("domain")
    nonce = _field("nonce")
    roots = _authority("governance")
    sidecar = CandidateSidecarV1(
        profile_id=_wide("profile"),
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        strong_settlement_domain_id=_digest(_SETTLEMENT_DOMAIN_BINDING, domain),
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=_wide("nullifier-before"),
        strong_nullifier_root_after=_wide("nullifier-after"),
        strong_governance_commitment=roots.commitment_512,
        strong_payment_state_root_before=_wide("payment-before"),
        strong_payment_state_root_after=_wide("payment-after"),
        strong_batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    ).encode()
    public_fields = build_v2_public_fields(
        settlement_domain=domain,
        batch_nonce=nonce,
        sidecar=sidecar,
        governance_authority=roots,
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
    )
    public_outputs = b"".join(public_fields)
    proof_package = b"selected-proof-package"
    transcript = b"selected-transcript"
    envelope = ProductionProofEnvelope(
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        public_outputs=public_outputs,
        sidecar=sidecar,
        proof_package=proof_package,
        transcript_evidence=transcript,
        evidence_commitment=_wide("evidence"),
    )
    return envelope, nonce, roots, domain


class _ReceiptVerifier:
    def __init__(self, *, reject: bool = False) -> None:
        self.calls = 0
        self.reject = reject

    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        self.calls += 1
        if self.reject:
            raise ProductionBoundaryError("native_verifier_rejected")
        envelope_bytes = envelope.encode()
        receipt = NativeVerificationReceipt(
            proof_suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
            envelope_commitment=sha3_512(envelope_bytes).digest(),
            statement_commitment=statement_commitment(envelope.public_outputs, envelope.sidecar),
            evidence_commitment=envelope.evidence_commitment,
            proof_package_commitment=sha3_512(
                PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
            ).digest(),
            transcript_commitment=sha3_512(
                TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
            ).digest(),
        )
        return NativeVerificationResult(
            receipt=receipt,
            envelope_commitment=receipt.envelope_commitment,
            statement_commitment=receipt.statement_commitment,
        )


class _ForgedCommitmentVerifier(_ReceiptVerifier):
    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        result = super().verify(envelope)
        return replace(result, envelope_commitment=_wide("forged-envelope"))


def test_native_verifier_config_pins_executable_and_program_bytes(tmp_path: Path) -> None:
    executable = tmp_path / "verifier.bin"
    program = tmp_path / "program.bin"
    executable.write_bytes(b"synthetic-native-verifier-binary")
    program.write_bytes(b"synthetic-air-program")
    projection = PublicInputProjectionV1(_wide("schema"))
    identity = native_verifier_artifact_identity(executable, program)
    config = NativeStarkVerifierConfig(
        executable=executable,
        program=program,
        suite_id=_wide("suite"),
        schema_id=_wide("schema"),
        verifier_artifact_identity=identity,
        public_input_projection=projection,
    )
    with pytest.raises(ProductionBoundaryError, match="verifier_artifact_identity_mismatch"):
        NativeStarkVerifierConfig(
            executable=executable,
            program=program,
            suite_id=_wide("suite"),
            schema_id=_wide("schema"),
            verifier_artifact_identity=_wide("wrong-verifier-artifact"),
            public_input_projection=projection,
        )
    program.write_bytes(b"mutated-air-program")
    with pytest.raises(ProductionBoundaryError, match="native_verifier_artifact_changed"):
        NativeStarkVerifierPort(config).verify_encoded(b"nonempty-envelope")


def test_governance_authority_exactly_matches_master_v2_formula_and_alias_order() -> None:
    master = _master_inputs()
    authority = GovernanceAuthorityV2(
        profile_code=1,
        epoch=master.epoch,
        claim_truth_roots_512=master.claim_truth_roots_512,  # type: ignore[arg-type]
        claim_truth_authority_digest_512=master.claim_truth_authority_digest_512,
        nullifier_authority_id_512=master.nullifier_authority_id_512,
        pepper_commitment_512=master.pepper_commitment_512,
    )
    assert authority.canonical_bytes == governance_preimage(master)
    assert authority.commitment_512 == build_master_commitments_v2(master).governance_512
    assert authority.public_aliases == tuple(
        (
            int.from_bytes(master.claim_truth_roots_512[index], "big")
            % (FIELD_MODULUS - 1)
            + 1
        ).to_bytes(32, "big")
        for index in (0, 1, 3, 5)
    )


def test_obsolete_four_alias_governance_digest_is_rejected() -> None:
    envelope, nonce, authority, domain = _fixture()
    old_digest = _digest(
        b"BL/PQ512/V2/GOVERNED-ROOTS/v1\x00",
        *authority.public_aliases,
    )
    assert old_digest != authority.commitment_512
    parsed = CandidateSidecarV1.decode(envelope.sidecar)
    obsolete = replace(parsed, strong_governance_commitment=old_digest).encode()
    with pytest.raises(ProductionBoundaryError, match="governance_authority_mismatch"):
        build_v2_public_fields(
            settlement_domain=domain,
            batch_nonce=nonce,
            sidecar=obsolete,
            governance_authority=authority,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )


def test_unprojected_full_root_substitution_cannot_hide_behind_same_alias_fields() -> None:
    envelope, nonce, authority, domain = _fixture()
    roots = list(authority.claim_truth_roots_512)
    roots[2] = _wide("substituted-unprojected-truth-root")
    substituted = replace(authority, claim_truth_roots_512=tuple(roots))
    assert substituted.public_aliases == authority.public_aliases
    assert substituted.commitment_512 != authority.commitment_512
    with pytest.raises(ProductionBoundaryError, match="governance_authority_mismatch"):
        build_v2_public_fields(
            settlement_domain=domain,
            batch_nonce=nonce,
            sidecar=envelope.sidecar,
            governance_authority=substituted,
            suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
        )

def test_production_envelope_decode_round_trips_after_receipt_binding() -> None:
    envelope, _, _, _ = _fixture()
    envelope = replace(
        envelope,
        proof_package=b"BLPQSPK1\x00\x02"
        + bytes(PROOF_PACKAGE_BYTES - len(b"BLPQSPK1\x00\x02")),
    )
    assert ProductionProofEnvelope.public_outputs_from_encoded(envelope.encode()) == envelope.public_outputs
    decoded = ProductionProofEnvelope.decode(
        envelope.encode(), evidence_commitment=envelope.evidence_commitment
    )
    assert decoded == envelope
    assert decoded.encode() == envelope.encode()
