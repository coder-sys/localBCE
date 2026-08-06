"""Composite local/synthetic receipt for the complete nonactivating stack.

This is the narrow handoff between the native candidate verifier, Privacy V2
atomic settlement, and the based-rollup claim port.  It stores commitments and
status flags only.  It never stores private claim data, exact amounts, proof
bytes, credentials, or network state, and it cannot enable activation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    SettlementReceiptV2,
    public_fields_commitment,
)
from app.wave5_native_boundary import (
    native_claim_context_digest,
    native_claim_proof_digest,
    native_claim_sidecar_digest,
    native_claim_statement_digest,
)
from app.wave5_rollup import (
    ClaimVerificationReceipt,
    RollupClaimContext,
    RollupClaimEnvelope,
    RollupSuiteIdentity,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    BuiltAuditPendingSuite,
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    statement_commitment,
)


STATUS = "LOCAL_SYNTHETIC_NONACTIVATING"
_STACK_DOMAIN = b"BL/PQ512/LOCAL-STACK-RECEIPT/V1\x00"


class LocalStackCandidateError(ValueError):
    """Fail-closed error for a cross-layer local receipt mismatch."""


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise LocalStackCandidateError(f"local_stack_{label}_invalid")
    return value


def _digest(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 128:
        raise LocalStackCandidateError("local_stack_digest_domain_invalid")
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 512 * 1024 * 1024:
            raise LocalStackCandidateError("local_stack_digest_part_invalid")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _hex_digest(label: str, value: object) -> bytes:
    if type(value) is not str or len(value) != 128:
        raise LocalStackCandidateError(f"local_stack_{label}_digest_invalid")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise LocalStackCandidateError(f"local_stack_{label}_digest_invalid") from exc
    return _wide(label, decoded)


def _public_fields(envelope: ProductionProofEnvelope) -> tuple[bytes, ...]:
    return tuple(
        envelope.public_outputs[index : index + 32]
        for index in range(0, len(envelope.public_outputs), 32)
    )


@dataclass(frozen=True, slots=True)
class LocalStackReceipt:
    """Commitment-only receipt for one complete local stack execution."""

    proof_suite_id: bytes
    release_identity_sha3_512: str
    settlement_state_binding: bytes
    rollup_statement_digest_512: bytes
    rollup_proof_digest_512: bytes
    stack_identity_sha3_512: str
    status: str = STATUS
    global_proof_suite_id: None = None
    activation_allowed: bool = False
    production_usable: bool = False
    network_access: bool = False
    live_credentials: bool = False

    def __post_init__(self) -> None:
        _wide("proof_suite", self.proof_suite_id)
        _hex_digest("release_identity", self.release_identity_sha3_512)
        _wide("settlement_state_binding", self.settlement_state_binding)
        _wide("rollup_statement", self.rollup_statement_digest_512)
        _wide("rollup_proof", self.rollup_proof_digest_512)
        _hex_digest("stack_identity", self.stack_identity_sha3_512)
        if self.status != STATUS or self.global_proof_suite_id is not None:
            raise LocalStackCandidateError("local_stack_lifecycle_invalid")
        if (
            self.activation_allowed
            or self.production_usable
            or self.network_access
            or self.live_credentials
        ):
            raise LocalStackCandidateError("local_stack_activation_boundary_invalid")

    def as_public_dict(self) -> dict[str, object]:
        """Return only commitment and lifecycle metadata; no claim contents."""

        return {
            "status": self.status,
            "candidateProofSuiteId": self.proof_suite_id.hex(),
            "globalProofSuiteId": None,
            "releaseIdentitySha3_512": self.release_identity_sha3_512,
            "settlementStateBinding": self.settlement_state_binding.hex(),
            "rollupStatementDigestSha3_512": self.rollup_statement_digest_512.hex(),
            "rollupProofDigestSha3_512": self.rollup_proof_digest_512.hex(),
            "stackIdentitySha3_512": self.stack_identity_sha3_512,
            "activationAllowed": False,
            "productionUsable": False,
            "networkAccess": False,
            "liveCredentials": False,
        }


def build_local_stack_receipt(
    *,
    envelope: ProductionProofEnvelope,
    native_receipt: NativeVerificationReceipt,
    candidate: BuiltAuditPendingSuite,
    settlement_receipt: SettlementReceiptV2,
    rollup_envelope: RollupClaimEnvelope,
    rollup_context: RollupClaimContext,
    rollup_identity: RollupSuiteIdentity,
    rollup_receipt: ClaimVerificationReceipt,
) -> LocalStackReceipt:
    """Recompute and bind the local native→settlement→rollup handoff."""

    if type(envelope) is not ProductionProofEnvelope:
        raise TypeError("local_stack_envelope_required")
    if type(native_receipt) is not NativeVerificationReceipt:
        raise TypeError("local_stack_native_receipt_required")
    if type(candidate) is not BuiltAuditPendingSuite:
        raise TypeError("local_stack_candidate_required")
    if type(settlement_receipt) is not SettlementReceiptV2:
        raise TypeError("local_stack_settlement_receipt_required")
    if type(rollup_envelope) is not RollupClaimEnvelope:
        raise TypeError("local_stack_rollup_envelope_required")
    if type(rollup_context) is not RollupClaimContext:
        raise TypeError("local_stack_rollup_context_required")
    if type(rollup_identity) is not RollupSuiteIdentity:
        raise TypeError("local_stack_rollup_identity_required")
    if type(rollup_receipt) is not ClaimVerificationReceipt:
        raise TypeError("local_stack_rollup_receipt_required")

    encoded = envelope.encode()
    envelope_commitment = hashlib.sha3_512(encoded).digest()
    expected_statement = statement_commitment(envelope.public_outputs, envelope.sidecar)
    expected_package = hashlib.sha3_512(
        PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
    ).digest()
    expected_transcript = hashlib.sha3_512(
        TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
    ).digest()
    if (
        native_receipt.proof_suite_id != envelope.suite_id
        or native_receipt.schema_id != envelope.schema_id
        or native_receipt.verifier_artifact_identity != envelope.verifier_artifact_identity
        or native_receipt.envelope_commitment != envelope_commitment
        or native_receipt.statement_commitment != expected_statement
        or native_receipt.evidence_commitment != envelope.evidence_commitment
        or native_receipt.proof_package_commitment != expected_package
        or native_receipt.transcript_commitment != expected_transcript
    ):
        raise LocalStackCandidateError("local_stack_native_binding_mismatch")

    if (
        candidate.proof_suite_id != native_receipt.proof_suite_id
        or candidate.schema_id != native_receipt.schema_id
        or candidate.verifier_artifact_identity != native_receipt.verifier_artifact_identity
        or candidate.proof_package_sha3_512 != native_receipt.proof_package_commitment.hex()
        or candidate.transcript_evidence_sha3_512 != native_receipt.transcript_commitment.hex()
        or candidate.statement_commitment_sha3_512 != native_receipt.statement_commitment.hex()
        or candidate.evidence_commitment_sha3_512 != native_receipt.evidence_commitment.hex()
    ):
        raise LocalStackCandidateError("local_stack_candidate_binding_mismatch")

    fields = _public_fields(envelope)
    if (
        settlement_receipt.proof_suite_id != envelope.suite_id
        or settlement_receipt.envelope_commitment != envelope_commitment
        or settlement_receipt.native_statement_commitment != expected_statement
        or settlement_receipt.public_fields_commitment != public_fields_commitment(fields)
    ):
        raise LocalStackCandidateError("local_stack_settlement_binding_mismatch")

    sidecar = CandidateSidecarV1.decode(envelope.sidecar)
    if (
        sidecar.profile_id != rollup_identity.profile_id_512
        or sidecar.proof_suite_id != rollup_identity.candidate_suite_id_512
        or sidecar.schema_id != rollup_identity.schema_id_512
        or sidecar.verifier_artifact_identity != rollup_identity.verifier_artifact_identity_512
        or sidecar.strong_settlement_domain_id != rollup_identity.settlement_domain_id_512
        or envelope.suite_id != rollup_identity.candidate_suite_id_512
        or envelope.schema_id != rollup_identity.schema_id_512
        or envelope.verifier_artifact_identity != rollup_identity.verifier_artifact_identity_512
    ):
        raise LocalStackCandidateError("local_stack_rollup_identity_mismatch")
    if (
        rollup_context.verifier_artifact_identity_512
        != rollup_identity.verifier_artifact_identity_512
        or rollup_context.schema_id_512 != rollup_identity.schema_id_512
        or rollup_context.candidate_suite_id_512 != rollup_identity.candidate_suite_id_512
        or rollup_context.settlement_domain_id_512 != rollup_identity.settlement_domain_id_512
    ):
        raise LocalStackCandidateError("local_stack_rollup_context_mismatch")
    if (
        tuple(rollup_envelope.public_fields) != fields
        or rollup_envelope.encoded_sidecar != envelope.sidecar
        or rollup_envelope.proof_body != encoded
        or rollup_envelope.context_digest_512 != native_claim_context_digest(rollup_context)
        or rollup_envelope.claim_proof_digest_512
        != native_claim_proof_digest(
            proof_body=encoded,
            context=rollup_context,
            public_fields=fields,
            sidecar=envelope.sidecar,
        )
    ):
        raise LocalStackCandidateError("local_stack_rollup_envelope_mismatch")

    expected_rollup_statement = native_claim_statement_digest(
        sidecar=envelope.sidecar,
        public_fields=fields,
        context=rollup_context,
        native_statement_commitment=expected_statement,
        native_envelope_commitment=envelope_commitment,
    )
    if (
        rollup_receipt.statement_digest_512 != expected_rollup_statement
        or rollup_receipt.proof_digest_512 != rollup_envelope.claim_proof_digest_512
        or rollup_receipt.verifier_artifact_identity_512
        != rollup_identity.verifier_artifact_identity_512
        or rollup_receipt.sidecar_digest_512 != native_claim_sidecar_digest(envelope.sidecar)
    ):
        raise LocalStackCandidateError("local_stack_rollup_receipt_mismatch")

    stack_identity = _digest(
        _STACK_DOMAIN,
        _hex_digest("release_identity", candidate.release_identity_sha3_512),
        settlement_receipt.state_binding,
        settlement_receipt.public_fields_commitment,
        settlement_receipt.envelope_commitment,
        settlement_receipt.native_statement_commitment,
        settlement_receipt.proof_suite_id,
        rollup_receipt.canonical_bytes(),
        rollup_context.canonical_bytes(),
        rollup_envelope.canonical_bytes(),
    ).hex()
    return LocalStackReceipt(
        proof_suite_id=candidate.proof_suite_id,
        release_identity_sha3_512=candidate.release_identity_sha3_512,
        settlement_state_binding=settlement_receipt.state_binding,
        rollup_statement_digest_512=rollup_receipt.statement_digest_512,
        rollup_proof_digest_512=rollup_receipt.proof_digest_512,
        stack_identity_sha3_512=stack_identity,
    )


__all__ = (
    "LocalStackCandidateError",
    "LocalStackReceipt",
    "STATUS",
    "build_local_stack_receipt",
)
