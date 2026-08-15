from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    ProductionCandidateError,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    build_production_envelope,
    select_built_audit_pending_suite,
    statement_commitment,
    statement_evidence_commitment,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedChallengeBundle,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _bundle(suite: bytes) -> SelectedChallengeBundle:
    values = [_wide(f"candidate-bundle-{index}") for index in range(13)]
    return SelectedChallengeBundle(
        proof_suite_id=suite,
        parameter_commitment=values[1],
        program_binary_commitment=values[2],
        schedule_commitment=values[3],
        session_id=values[4],
        final_transcript_root=values[5],
        evidence_commitment=values[6],
        main_trace_root=values[7],
        interaction_trace_root=values[8],
        composition_root=values[9],
        oods_claims_commitment=values[10],
        fri_mask_root=values[11],
        fri_batch_derivation_commitment=values[12],
        fri_layer_roots=(values[0],),
        logup_beta=Fp16.zero(),
        logup_gamma=Fp16.zero(),
        composition_alpha=Fp16.zero(),
        oods_point=CirclePoint(Fp16.zero(), Fp16.zero()),
        fri_batch_coefficient=Fp16.zero(),
        fri_fold_coefficients=(Fp16.zero(),),
        query_seed=_wide("candidate-query-seed"),
        query_positions=(0,),
    )


def _sidecar(suite: bytes, schema: bytes, verifier: bytes) -> bytes:
    return CandidateSidecarV1(
        profile_id=_wide("candidate-profile"),
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        strong_settlement_domain_id=_wide("candidate-domain"),
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=_wide("candidate-nullifier-before"),
        strong_nullifier_root_after=_wide("candidate-nullifier-after"),
        strong_governance_commitment=_wide("candidate-governance"),
        strong_payment_state_root_before=_wide("candidate-payment-before"),
        strong_payment_state_root_after=_wide("candidate-payment-after"),
        strong_batch_commitment=_wide("candidate-batch"),
    ).encode()


def test_candidate_envelope_binds_statement_but_remains_aggregate_unqualified() -> None:
    suite = _wide("candidate-suite")
    schema = _wide("candidate-schema")
    verifier = _wide("candidate-verifier")
    public_outputs = bytes(12 * 32)
    sidecar = _sidecar(suite, schema, verifier)
    base_bundle = _bundle(suite)
    evidence = statement_evidence_commitment(public_outputs, sidecar, base_bundle)
    bundle = replace(base_bundle, evidence_commitment=evidence)
    envelope = build_production_envelope(
        public_outputs=public_outputs,
        sidecar=sidecar,
        proof_package=b"opaque-proof-package",
        transcript_evidence=b"opaque-transcript",
        challenge_bundle=bundle,
    )
    verification = NativeVerificationReceipt(
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        envelope_commitment=sha3_512(envelope.encode()).digest(),
        statement_commitment=statement_commitment(public_outputs, sidecar),
        evidence_commitment=evidence,
        proof_package_commitment=sha3_512(
            PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
        ).digest(),
        transcript_commitment=sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
        ).digest(),
    )
    with pytest.raises(
        ProductionCandidateError, match="candidate_aggregate_qualification_required"
    ):
        select_built_audit_pending_suite(envelope, verification=verification)


def test_candidate_rejects_bundle_statement_swap() -> None:
    suite = _wide("candidate-suite")
    schema = _wide("candidate-schema")
    verifier = _wide("candidate-verifier")
    sidecar = _sidecar(suite, schema, verifier)
    bundle = _bundle(suite)
    with pytest.raises(ProductionCandidateError, match="candidate_statement_evidence"):
        build_production_envelope(
            public_outputs=bytes(12 * 32),
            sidecar=sidecar,
            proof_package=b"opaque-proof-package",
            transcript_evidence=b"opaque-transcript",
            challenge_bundle=bundle,
        )


def test_candidate_rejects_bundle_suite_mismatch() -> None:
    suite = _wide("candidate-suite")
    schema = _wide("candidate-schema")
    verifier = _wide("candidate-verifier")
    with pytest.raises(ProductionCandidateError, match="candidate_bundle_suite_mismatch"):
        build_production_envelope(
            public_outputs=bytes(12 * 32),
            sidecar=_sidecar(suite, schema, verifier),
            proof_package=b"opaque-proof-package",
            transcript_evidence=b"opaque-transcript",
            challenge_bundle=_bundle(_wide("candidate-other-suite")),
        )


@pytest.mark.parametrize(
    ("line", "error"),
    (
        ("NOT_OK", "candidate_native_receipt_header_invalid"),
        ("OK proof_suite_id=00", "candidate_native_receipt_field_set_invalid"),
        (
            "OK proof_suite_id=00 proof_suite_id=00",
            "candidate_native_receipt_field_invalid",
        ),
    ),
)
def test_native_receipt_parser_rejects_malformed_fields(line: str, error: str) -> None:
    with pytest.raises(ProductionCandidateError, match=error):
        NativeVerificationReceipt.from_native_line(line)


def test_candidate_rejects_bundle_suite_mismatch() -> None:
    suite = _wide("candidate-suite")
    schema = _wide("candidate-schema")
    verifier = _wide("candidate-verifier")
    with pytest.raises(ProductionCandidateError, match="candidate_bundle_suite_mismatch"):
        build_production_envelope(
            public_outputs=bytes(12 * 32),
            sidecar=_sidecar(suite, schema, verifier),
            proof_package=b"opaque-proof-package",
            transcript_evidence=b"opaque-transcript",
            challenge_bundle=_bundle(_wide("candidate-other-suite")),
        )


@pytest.mark.parametrize(
    ("line", "error"),
    (
        ("NOT_OK", "candidate_native_receipt_header_invalid"),
        ("OK proof_suite_id=00", "candidate_native_receipt_field_set_invalid"),
        (
            "OK proof_suite_id=00 proof_suite_id=00",
            "candidate_native_receipt_field_invalid",
        ),
    ),
)
def test_native_receipt_parser_rejects_malformed_fields(line: str, error: str) -> None:
    with pytest.raises(ProductionCandidateError, match=error):
        NativeVerificationReceipt.from_native_line(line)
