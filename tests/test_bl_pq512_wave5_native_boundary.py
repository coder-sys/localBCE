from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    GovernedRootsV2,
    NativeVerificationResult,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    build_v2_public_fields,
)
from app.wave5_native_boundary import (
    NativeRollupClaimVerifier,
    build_native_claim_envelope,
)
from app.wave5_rollup import RollupClaimContext, RollupSuiteIdentity, Wave5RollupError
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    statement_commitment,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(label: str) -> bytes:
    return (int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def _fixture() -> tuple[ProductionProofEnvelope, RollupClaimContext, RollupSuiteIdentity]:
    profile = _wide("native-profile")
    suite = _wide("native-suite")
    schema = _wide("native-schema")
    verifier = _wide("native-verifier")
    settlement_domain = _field("native-settlement-domain")
    settlement_domain_id = _digest(_SETTLEMENT_DOMAIN_BINDING, settlement_domain)
    nonce = _field("native-batch-nonce")
    roots = GovernedRootsV2(
        claim_source_root=_field("native-claim-source"),
        oracle_facts_root=_field("native-oracle-facts"),
        policy_root=_field("native-policy"),
        ruleset_root=_field("native-ruleset"),
    )
    sidecar = CandidateSidecarV1(
        profile_id=profile,
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        strong_settlement_domain_id=settlement_domain_id,
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=_wide("native-nullifier-before"),
        strong_nullifier_root_after=_wide("native-nullifier-after"),
        strong_governance_commitment=roots.commitment_512,
        strong_payment_state_root_before=_wide("native-payment-before"),
        strong_payment_state_root_after=_wide("native-payment-after"),
        strong_batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    ).encode()
    fields = build_v2_public_fields(
        settlement_domain=settlement_domain,
        batch_nonce=nonce,
        sidecar=sidecar,
        governed_roots=roots,
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
    )
    native = ProductionProofEnvelope(
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        public_outputs=b"".join(fields),
        sidecar=sidecar,
        proof_package=b"native-proof-package",
        transcript_evidence=b"native-transcript-evidence",
        evidence_commitment=_wide("native-evidence"),
    )
    identity = RollupSuiteIdentity(
        profile_id_512=profile,
        candidate_suite_id_512=suite,
        schema_id_512=schema,
        verifier_artifact_identity_512=verifier,
        settlement_domain_id_512=settlement_domain_id,
        epoch=1,
    )
    context = RollupClaimContext(
        fork_id_512=_wide("native-fork"),
        l1_chain_id=7_531_512,
        l2_chain_id=7_531_513,
        state_before_digest_512=_wide("native-state-before"),
        da_commitment_512=_wide("native-da"),
        verifier_artifact_identity_512=verifier,
        schema_id_512=schema,
        candidate_suite_id_512=suite,
        settlement_domain_id_512=settlement_domain_id,
    )
    return native, context, identity


class _StubNativeVerifier:
    def __init__(self, expected: ProductionProofEnvelope) -> None:
        self.expected = expected
        self.calls = 0

    def verify_encoded(self, encoded: bytes) -> NativeVerificationResult:
        self.calls += 1
        if encoded != self.expected.encode():
            raise ValueError("encoded proof mutation")
        envelope_commitment = sha3_512(encoded).digest()
        receipt = NativeVerificationReceipt(
            proof_suite_id=self.expected.suite_id,
            schema_id=self.expected.schema_id,
            verifier_artifact_identity=self.expected.verifier_artifact_identity,
            envelope_commitment=envelope_commitment,
            statement_commitment=statement_commitment(
                self.expected.public_outputs,
                self.expected.sidecar,
            ),
            evidence_commitment=self.expected.evidence_commitment,
            proof_package_commitment=sha3_512(
                PROOF_PACKAGE_COMMITMENT_DOMAIN + self.expected.proof_package
            ).digest(),
            transcript_commitment=sha3_512(
                TRANSCRIPT_COMMITMENT_DOMAIN + self.expected.transcript_evidence
            ).digest(),
        )
        return NativeVerificationResult(
            receipt=receipt,
            envelope_commitment=envelope_commitment,
            statement_commitment=receipt.statement_commitment,
        )


def test_native_adapter_rechecks_exact_outer_bindings() -> None:
    native, context, identity = _fixture()
    envelope = build_native_claim_envelope(native_envelope=native, context=context)
    verifier = _StubNativeVerifier(native)
    receipt = NativeRollupClaimVerifier(verifier).verify(
        envelope=envelope,
        context=context,
        identity=identity,
    )
    assert receipt.proof_digest_512 == envelope.claim_proof_digest_512
    assert receipt.verifier_artifact_identity_512 == identity.verifier_artifact_identity_512
    assert verifier.calls == 1


def test_native_adapter_rejects_outer_public_field_mutation_before_native_call() -> None:
    native, context, identity = _fixture()
    envelope = build_native_claim_envelope(native_envelope=native, context=context)
    verifier = _StubNativeVerifier(native)
    mutated_fields = list(envelope.public_fields)
    mutated_fields[0] = (int.from_bytes(mutated_fields[0], "big") + 1).to_bytes(32, "big")
    with pytest.raises(Wave5RollupError, match="proof_digest_mismatch"):
        NativeRollupClaimVerifier(verifier).verify(
            envelope=replace(envelope, public_fields=tuple(mutated_fields)),
            context=context,
            identity=identity,
        )
    assert verifier.calls == 0


def test_native_adapter_rejects_proof_body_mutation_before_native_call() -> None:
    native, context, identity = _fixture()
    envelope = build_native_claim_envelope(native_envelope=native, context=context)
    verifier = _StubNativeVerifier(native)
    mutated_body = envelope.proof_body[:-1] + bytes([envelope.proof_body[-1] ^ 1])
    with pytest.raises(Wave5RollupError, match="proof_digest_mismatch"):
        NativeRollupClaimVerifier(verifier).verify(
            envelope=replace(envelope, proof_body=mutated_body),
            context=context,
            identity=identity,
        )
    assert verifier.calls == 0
