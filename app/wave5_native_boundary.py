"""Rust-backed native claim adapter for the local Wave 5 rollup boundary.

The existing :mod:`app.wave5_rollup` reference verifier remains available as
synthetic conformance evidence.  This module is the separate native path: it
accepts only an encoded ``ProductionProofEnvelope``, asks the Rust verifier
port to validate that exact byte string, and then rechecks the outer Wave 5
context, sidecar, public fields, and receipt bindings.  It does not open a
network, call Ethereum, handle payment authority, or enable activation.
"""

from __future__ import annotations

from hashlib import sha3_512
from typing import Final

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.wave5_rollup import (
    ClaimVerificationReceipt,
    RollupClaimContext,
    RollupClaimEnvelope,
    RollupSuiteIdentity,
    Wave5RollupError,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    MAX_ENVELOPE_BYTES,
    ProductionProofEnvelope,
    PUBLIC_FIELD_BYTES,
    PUBLIC_OUTPUT_BYTES,
    SIDECAR_BYTES,
    statement_commitment,
)
from app.production_boundary import NativeVerificationResult


_CONTEXT_DOMAIN = b"BL/WAVE5/NATIVE/CLAIM-CONTEXT/V2\x00"
_PROOF_DOMAIN = b"BL/WAVE5/NATIVE/CLAIM-PROOF/V2\x00"
_STATEMENT_DOMAIN = b"BL/WAVE5/NATIVE/CLAIM-STATEMENT/V2\x00"
_SIDECAR_DOMAIN = b"BL/WAVE5/NATIVE/CLAIM-SIDECAR/V2\x00"
_DEFAULT_DIGEST_PART_BYTES: Final[int] = 2 * 1024 * 1024


def _digest(
    domain: bytes,
    *parts: bytes,
    maximum_part_bytes: int = _DEFAULT_DIGEST_PART_BYTES,
) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 128:
        raise Wave5RollupError("native_claim_digest_domain_invalid")
    if type(maximum_part_bytes) is not int or maximum_part_bytes <= 0:
        raise Wave5RollupError("native_claim_digest_bound_invalid")
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > maximum_part_bytes:
            raise Wave5RollupError("native_claim_digest_part_invalid")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _public_fields(public_outputs: bytes) -> tuple[bytes, ...]:
    if type(public_outputs) is not bytes or len(public_outputs) != PUBLIC_OUTPUT_BYTES:
        raise Wave5RollupError("native_claim_public_outputs_invalid")
    fields = tuple(
        public_outputs[index : index + PUBLIC_FIELD_BYTES]
        for index in range(0, PUBLIC_OUTPUT_BYTES, PUBLIC_FIELD_BYTES)
    )
    if any(int.from_bytes(value, "big") >= FIELD_MODULUS for value in fields):
        raise Wave5RollupError("native_claim_public_field_not_canonical")
    return fields


def _sidecar(encoded: bytes) -> CandidateSidecarV1:
    if type(encoded) is not bytes or len(encoded) != SIDECAR_BYTES:
        raise Wave5RollupError("native_claim_sidecar_shape_invalid")
    try:
        return CandidateSidecarV1.decode(encoded)
    except (TypeError, ValueError) as exc:
        raise Wave5RollupError("native_claim_sidecar_rejected") from exc


def _check_identity(
    *,
    sidecar: CandidateSidecarV1,
    context: RollupClaimContext,
    identity: RollupSuiteIdentity,
) -> None:
    expected = (
        sidecar.profile_id == identity.profile_id_512,
        sidecar.proof_suite_id == identity.candidate_suite_id_512,
        sidecar.schema_id == identity.schema_id_512,
        sidecar.verifier_artifact_identity == identity.verifier_artifact_identity_512,
        sidecar.strong_settlement_domain_id == identity.settlement_domain_id_512,
    )
    if not all(expected):
        raise Wave5RollupError("native_claim_identity_mismatch")
    if sidecar.epoch != identity.epoch:
        raise Wave5RollupError("native_claim_epoch_mismatch")
    if context.fork_id_512 == bytes(64):
        raise Wave5RollupError("native_claim_context_fork_invalid")
    if (
        context.verifier_artifact_identity_512 != identity.verifier_artifact_identity_512
        or context.schema_id_512 != identity.schema_id_512
        or context.candidate_suite_id_512 != identity.candidate_suite_id_512
        or context.settlement_domain_id_512 != identity.settlement_domain_id_512
    ):
        raise Wave5RollupError("native_claim_context_identity_mismatch")


def native_claim_context_digest(context: RollupClaimContext) -> bytes:
    if type(context) is not RollupClaimContext:
        raise TypeError("native_claim_context_required")
    return _digest(_CONTEXT_DOMAIN, context.canonical_bytes())


def native_claim_proof_digest(
    *,
    proof_body: bytes,
    context: RollupClaimContext,
    public_fields: tuple[bytes, ...],
    sidecar: bytes,
) -> bytes:
    if type(context) is not RollupClaimContext:
        raise TypeError("native_claim_context_required")
    return _digest(
        _PROOF_DOMAIN,
        proof_body,
        context.canonical_bytes(),
        b"".join(public_fields),
        sidecar,
        maximum_part_bytes=MAX_ENVELOPE_BYTES,
    )


def native_claim_statement_digest(
    *,
    sidecar: bytes,
    public_fields: tuple[bytes, ...],
    context: RollupClaimContext,
    native_statement_commitment: bytes,
    native_envelope_commitment: bytes,
) -> bytes:
    if type(context) is not RollupClaimContext:
        raise TypeError("native_claim_context_required")
    return _digest(
        _STATEMENT_DOMAIN,
        sidecar,
        b"".join(public_fields),
        context.canonical_bytes(),
        native_statement_commitment,
        native_envelope_commitment,
    )


def native_claim_sidecar_digest(sidecar: bytes) -> bytes:
    return _digest(_SIDECAR_DOMAIN, sidecar)


def build_native_claim_envelope(
    *,
    native_envelope: ProductionProofEnvelope,
    context: RollupClaimContext,
) -> RollupClaimEnvelope:
    """Wrap one canonical native envelope in the existing Wave 5 claim port."""

    if type(native_envelope) is not ProductionProofEnvelope:
        raise TypeError("native_claim_envelope_required")
    if type(context) is not RollupClaimContext:
        raise TypeError("native_claim_context_required")
    fields = _public_fields(native_envelope.public_outputs)
    encoded = native_envelope.encode()
    return RollupClaimEnvelope(
        public_fields=fields,
        encoded_sidecar=native_envelope.sidecar,
        proof_body=encoded,
        context_digest_512=native_claim_context_digest(context),
        claim_proof_digest_512=native_claim_proof_digest(
            proof_body=encoded,
            context=context,
            public_fields=fields,
            sidecar=native_envelope.sidecar,
        ),
    )


class NativeRollupClaimVerifier:
    """Adapt the Rust native verifier to the existing Wave 5 claim port."""

    def __init__(self, verifier: object) -> None:
        if not callable(getattr(verifier, "verify_encoded", None)):
            raise TypeError("native_rollup_encoded_verifier_required")
        self._verifier = verifier

    def verify(
        self,
        *,
        envelope: RollupClaimEnvelope,
        context: RollupClaimContext,
        identity: RollupSuiteIdentity,
    ) -> ClaimVerificationReceipt:
        if (
            type(envelope) is not RollupClaimEnvelope
            or type(context) is not RollupClaimContext
            or type(identity) is not RollupSuiteIdentity
        ):
            raise Wave5RollupError("native_claim_input_type_invalid")

        sidecar = _sidecar(envelope.encoded_sidecar)
        _check_identity(sidecar=sidecar, context=context, identity=identity)
        fields = _public_fields(b"".join(envelope.public_fields))
        expected_context = native_claim_context_digest(context)
        if envelope.context_digest_512 != expected_context:
            raise Wave5RollupError("native_claim_context_digest_mismatch")
        expected_proof = native_claim_proof_digest(
            proof_body=envelope.proof_body,
            context=context,
            public_fields=fields,
            sidecar=envelope.encoded_sidecar,
        )
        if envelope.claim_proof_digest_512 != expected_proof:
            raise Wave5RollupError("native_claim_proof_digest_mismatch")

        try:
            result = self._verifier.verify_encoded(envelope.proof_body)
        except Exception as exc:
            raise Wave5RollupError("native_claim_verifier_rejected") from exc
        if type(result) is not NativeVerificationResult:
            raise Wave5RollupError("native_claim_verifier_result_invalid")
        receipt = result.receipt
        if type(receipt) is not NativeVerificationReceipt:
            raise Wave5RollupError("native_claim_native_receipt_invalid")

        try:
            verified = ProductionProofEnvelope.decode(
                envelope.proof_body,
                evidence_commitment=receipt.evidence_commitment,
            )
        except ValueError as exc:
            raise Wave5RollupError("native_claim_proof_envelope_rejected") from exc
        if (
            verified.public_outputs != b"".join(fields)
            or verified.sidecar != envelope.encoded_sidecar
            or verified.suite_id != identity.candidate_suite_id_512
            or verified.schema_id != identity.schema_id_512
            or verified.verifier_artifact_identity != identity.verifier_artifact_identity_512
        ):
            raise Wave5RollupError("native_claim_outer_binding_mismatch")

        expected_statement = statement_commitment(
            verified.public_outputs,
            verified.sidecar,
        )
        expected_envelope = sha3_512(envelope.proof_body).digest()
        if (
            result.statement_commitment != expected_statement
            or receipt.statement_commitment != expected_statement
            or result.envelope_commitment != expected_envelope
            or receipt.envelope_commitment != expected_envelope
            or receipt.proof_suite_id != verified.suite_id
            or receipt.schema_id != verified.schema_id
            or receipt.verifier_artifact_identity != verified.verifier_artifact_identity
        ):
            raise Wave5RollupError("native_claim_receipt_binding_mismatch")

        statement = native_claim_statement_digest(
            sidecar=envelope.encoded_sidecar,
            public_fields=fields,
            context=context,
            native_statement_commitment=result.statement_commitment,
            native_envelope_commitment=result.envelope_commitment,
        )
        return ClaimVerificationReceipt(
            statement_digest_512=statement,
            proof_digest_512=expected_proof,
            verifier_artifact_identity_512=identity.verifier_artifact_identity_512,
            sidecar_digest_512=native_claim_sidecar_digest(envelope.encoded_sidecar),
        )


__all__ = (
    "NativeRollupClaimVerifier",
    "build_native_claim_envelope",
    "native_claim_context_digest",
    "native_claim_proof_digest",
    "native_claim_sidecar_digest",
    "native_claim_statement_digest",
)
