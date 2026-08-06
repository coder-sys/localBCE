from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    GovernedRootsV2,
    LocalSettlementV2,
    NativeVerificationResult,
    ProductionBoundaryError,
    SettlementSnapshotV2,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    build_v2_public_fields,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    statement_commitment,
)
from app.batch.poseidon import FIELD_MODULUS


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(label: str) -> bytes:
    return (int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def _fixture() -> tuple[ProductionProofEnvelope, bytes, GovernedRootsV2, bytes]:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    domain = _field("domain")
    nonce = _field("nonce")
    roots = GovernedRootsV2(
        claim_source_root=_field("claim-source"),
        oracle_facts_root=_field("oracle-facts"),
        policy_root=_field("policy"),
        ruleset_root=_field("ruleset"),
    )
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
        governed_roots=roots,
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


def test_production_envelope_decode_round_trips_after_receipt_binding() -> None:
    envelope, _, _, _ = _fixture()
    assert ProductionProofEnvelope.public_outputs_from_encoded(envelope.encode()) == envelope.public_outputs
    decoded = ProductionProofEnvelope.decode(
        envelope.encode(), evidence_commitment=envelope.evidence_commitment
    )
    assert decoded == envelope
    assert decoded.encode() == envelope.encode()


def test_local_settlement_binds_projection_and_publishes_atomically() -> None:
    envelope, nonce, roots, domain = _fixture()
    verifier = _ReceiptVerifier()
    submitter = _wide("submitter")
    settlement = LocalSettlementV2(
        verifier=verifier,
        settlement_domain=domain,
        governed_roots=roots,
        initial_nullifier_root=(
            int.from_bytes(_wide("nullifier-before"), "big") % (FIELD_MODULUS - 1) + 1
        ).to_bytes(32, "big"),
        authorized_submitters=(submitter,),
    )
    before = settlement.snapshot()
    receipt = settlement.submit(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=submitter,
    )
    after = settlement.snapshot()
    assert isinstance(before, SettlementSnapshotV2)
    assert before.sequence == 0
    assert before.settled_batch_count == 0
    assert receipt.sequence_before == 0
    assert receipt.sequence_after == 1
    assert after.sequence == 1
    assert after.settled_batch_count == 1
    assert after.state_binding == receipt.state_binding
    assert verifier.calls == 1


def test_projection_mutation_is_rejected_before_native_verifier_or_state_change() -> None:
    envelope, nonce, roots, domain = _fixture()
    verifier = _ReceiptVerifier()
    submitter = _wide("submitter")
    settlement = LocalSettlementV2(
        verifier=verifier,
        settlement_domain=domain,
        governed_roots=roots,
        initial_nullifier_root=(
            int.from_bytes(_wide("nullifier-before"), "big") % (FIELD_MODULUS - 1) + 1
        ).to_bytes(32, "big"),
        authorized_submitters=(submitter,),
    )
    mutated = bytearray(envelope.public_outputs)
    mutated[9] ^= 1
    forged = replace(envelope, public_outputs=bytes(mutated))
    with pytest.raises(ProductionBoundaryError, match="v2_public_projection_mismatch"):
        settlement.submit(envelope=forged, batch_nonce=nonce, submitter=submitter)
    assert settlement.snapshot().sequence == 0
    assert verifier.calls == 0


def test_native_rejection_does_not_publish_state_and_replay_is_blocked() -> None:
    envelope, nonce, roots, domain = _fixture()
    submitter = _wide("submitter")
    verifier = _ReceiptVerifier(reject=True)
    settlement = LocalSettlementV2(
        verifier=verifier,
        settlement_domain=domain,
        governed_roots=roots,
        initial_nullifier_root=(
            int.from_bytes(_wide("nullifier-before"), "big") % (FIELD_MODULUS - 1) + 1
        ).to_bytes(32, "big"),
        authorized_submitters=(submitter,),
    )
    with pytest.raises(ProductionBoundaryError, match="native_verifier_rejected"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert settlement.snapshot().settled_batch_count == 0

    verifier.reject = False
    settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    with pytest.raises(ProductionBoundaryError, match="settlement_batch_nonce_replay"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)


def test_settlement_recomputes_native_receipt_binding_before_publication() -> None:
    envelope, nonce, roots, domain = _fixture()
    submitter = _wide("submitter")
    verifier = _ForgedCommitmentVerifier()
    settlement = LocalSettlementV2(
        verifier=verifier,
        settlement_domain=domain,
        governed_roots=roots,
        initial_nullifier_root=(
            int.from_bytes(_wide("nullifier-before"), "big") % (FIELD_MODULUS - 1) + 1
        ).to_bytes(32, "big"),
        authorized_submitters=(submitter,),
    )
    with pytest.raises(ProductionBoundaryError, match="settlement_verifier_binding_mismatch"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    snapshot = settlement.snapshot()
    assert snapshot.sequence == 0
    assert snapshot.settled_batch_count == 0
