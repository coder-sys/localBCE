from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    ENVELOPE_MAGIC,
    ENVELOPE_PREFIX_BYTES,
    ENVELOPE_VERSION,
    NativeVerificationReceipt,
    PROOF_PACKAGE_BYTES,
    ProductionCandidateError,
    ProductionProofEnvelope,
    select_built_audit_pending_suite,
)


def _wide(label: str) -> bytes:
    return hashlib.sha3_512(label.encode("ascii")).digest()


def _sidecar(suite: bytes, schema: bytes, verifier: bytes) -> bytes:
    return CandidateSidecarV1(
        profile_id=_wide("profile"),
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        strong_settlement_domain_id=_wide("domain"),
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=_wide("nullifier-before"),
        strong_nullifier_root_after=_wide("nullifier-after"),
        strong_governance_commitment=_wide("governance"),
        strong_payment_state_root_before=_wide("payment-before"),
        strong_payment_state_root_after=_wide("payment-after"),
        strong_batch_commitment=_wide("batch"),
    ).encode()


def test_v2_file_parser_validates_lengths_before_variable_reads(tmp_path: Path) -> None:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    envelope = ProductionProofEnvelope(
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        public_outputs=bytes(12 * 32),
        sidecar=_sidecar(suite, schema, verifier),
        proof_package=b"BLPQSPK1\x00\x02"
        + bytes(PROOF_PACKAGE_BYTES - len(b"BLPQSPK1\x00\x02")),
        transcript_evidence=b"transcript",
        evidence_commitment=_wide("evidence"),
    )
    encoded = envelope.encode()
    assert encoded[:8] == ENVELOPE_MAGIC
    assert int.from_bytes(encoded[8:10], "big") == ENVELOPE_VERSION
    assert ENVELOPE_PREFIX_BYTES == 1342
    path = tmp_path / "envelope.bin"
    path.write_bytes(encoded)
    assert ProductionProofEnvelope.read_file(
        path,
        evidence_commitment=envelope.evidence_commitment,
        expected_suite_id=suite,
        expected_schema_id=schema,
        expected_verifier_artifact_identity=verifier,
    ) == envelope


def test_per_proof_selector_rejects_missing_aggregate_qualification() -> None:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    envelope = ProductionProofEnvelope(
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        public_outputs=bytes(12 * 32),
        sidecar=_sidecar(suite, schema, verifier),
        proof_package=b"proof",
        transcript_evidence=b"transcript",
        evidence_commitment=_wide("evidence"),
    )
    receipt = NativeVerificationReceipt(
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        envelope_commitment=hashlib.sha3_512(envelope.encode()).digest(),
        statement_commitment=_wide("statement"),
        evidence_commitment=envelope.evidence_commitment,
        proof_package_commitment=_wide("package"),
        transcript_commitment=_wide("transcript-commitment"),
    )
    with pytest.raises(
        ProductionCandidateError, match="candidate_aggregate_qualification_required"
    ):
        select_built_audit_pending_suite(envelope, verification=receipt)
