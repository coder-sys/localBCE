from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.built_audit_pending_release import (
    RELEASE_SCHEMA,
    ROOT,
    UNQUALIFIED_STATUS,
    build_release_candidate_identity,
    qualify_release_candidate,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    ENVELOPE_MAGIC,
    ENVELOPE_PREFIX_BYTES,
    ENVELOPE_VERSION,
    NativeVerificationReceipt,
    PROOF_PACKAGE_BYTES,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionCandidateError,
    ProductionProofEnvelope,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    select_built_audit_pending_suite,
    statement_commitment,
)


_LB010_RECEIPT_DOMAIN = b"BL/PQ512/LB010/QUALIFICATION-RECEIPT/v1\x00"


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


def _candidate(tmp_path: Path, *, release_contract_schema: Path = RELEASE_SCHEMA):
    artifacts = {}
    for name in (
        "parameters",
        "program",
        "prover",
        "verifier",
        "transcript",
        "toolchain",
    ):
        path = tmp_path / name
        if not path.exists():
            path.write_bytes(f"exact-{name}-bytes".encode("ascii"))
        artifacts[name] = path
    sources = tuple(
        sorted(
            (
                ROOT / "experiments" / "bl_pq512_crypto_core" / "src" / "production_verifier.rs",
                ROOT / "experiments" / "bl_pq512_crypto_foundation" / "production_candidate.py",
            ),
            key=lambda path: path.relative_to(ROOT).as_posix(),
        )
    )
    return build_release_candidate_identity(
        proof_suite_id=_wide("candidate-suite"),
        proof_parameters=artifacts["parameters"],
        air_program=artifacts["program"],
        prover_executable=artifacts["prover"],
        verifier_executable=artifacts["verifier"],
        transcript_contract=artifacts["transcript"],
        toolchain=artifacts["toolchain"],
        source_files=sources,
        release_contract_schema=release_contract_schema,
    )


def _receipt(candidate) -> bytes:
    return json.dumps(
        {
            "activationAllowed": False,
            "evidenceManifestSha3_512": _wide("lb010-evidence").hex(),
            "globalProofSuiteId": None,
            "productionUsable": False,
            "proofSuiteId": candidate.proof_suite_id.hex(),
            "receiptVersion": "BL-PQ512-LB010-QUALIFICATION-RECEIPT-v1",
            "releaseCandidateIdentitySha3_512": candidate.release_identity_sha3_512.hex(),
            "status": "QUALIFIED",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_v2_contract_identity_and_lb010_gate_are_nonactivating(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    assert candidate.status == UNQUALIFIED_STATUS
    assert candidate.global_proof_suite_id is None
    assert candidate.production_usable is False
    assert candidate.activation_allowed is False
    unqualified = qualify_release_candidate(candidate)
    assert unqualified.status == UNQUALIFIED_STATUS

    receipt = _receipt(candidate)
    receipt_digest = hashlib.sha3_512(_LB010_RECEIPT_DOMAIN + receipt).digest()
    with pytest.raises(
        ValueError, match="release_lb010_self_attested_receipt_forbidden"
    ):
        qualify_release_candidate(
            candidate,
            lb010_receipt=receipt,
            expected_receipt_sha3_512=receipt_digest,
        )


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


def test_release_identity_changes_on_any_pinned_artifact_change(tmp_path: Path) -> None:
    first = _candidate(tmp_path)
    (tmp_path / "program").write_bytes(b"changed-program-bytes")
    second = _candidate(tmp_path)
    assert second.release_identity_sha3_512 != first.release_identity_sha3_512
    assert second.source_set_sha3_512 == first.source_set_sha3_512


def test_caller_paired_lb010_receipt_is_forbidden(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    receipt = _receipt(candidate)
    with pytest.raises(ValueError, match="release_lb010_receipt_pair_required"):
        qualify_release_candidate(candidate, lb010_receipt=receipt)
    with pytest.raises(
        ValueError, match="release_lb010_self_attested_receipt_forbidden"
    ):
        qualify_release_candidate(
            candidate,
            lb010_receipt=receipt,
            expected_receipt_sha3_512=_wide("wrong-receipt"),
        )


def test_release_schema_semantic_substitution_is_rejected(tmp_path: Path) -> None:
    substituted = tmp_path / "substituted-release-schema.json"
    substituted.write_bytes(
        RELEASE_SCHEMA.read_bytes().replace(
            b'"maximumEnvelopeBytes": 536870912',
            b'"maximumEnvelopeBytes": 536870911',
        )
    )
    with pytest.raises(ValueError, match="release_contract_schema_semantics_invalid"):
        _candidate(tmp_path, release_contract_schema=substituted)


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


def test_per_proof_selector_rejects_current_unverified_aggregate(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    aggregate = qualify_release_candidate(
        candidate
    )
    suite = candidate.proof_suite_id
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
    native = NativeVerificationReceipt(
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        envelope_commitment=hashlib.sha3_512(envelope.encode()).digest(),
        statement_commitment=statement_commitment(
            envelope.public_outputs, envelope.sidecar
        ),
        evidence_commitment=envelope.evidence_commitment,
        proof_package_commitment=hashlib.sha3_512(
            PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
        ).digest(),
        transcript_commitment=hashlib.sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
        ).digest(),
    )
    with pytest.raises(
        ProductionCandidateError,
        match="candidate_complete_aggregate_qualification_unimplemented",
    ):
        select_built_audit_pending_suite(
            envelope,
            verification=native,
            aggregate_release=aggregate,
        )
