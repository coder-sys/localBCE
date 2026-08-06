from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from pathlib import Path
import subprocess

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    NativeStarkVerifierConfig,
    NativeStarkVerifierPort,
)
from app.native_public_input_projection import PublicInputProjectionV1
from experiments.bl_pq512_crypto_foundation.active_gkr_hiding import (
    HISTORICAL_CIRCLE_GAPS,
    build_active_gkr_hiding_certificate,
)
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    ProductionCandidateError,
    NativeVerificationReceipt,
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    build_production_envelope,
    select_built_audit_pending_suite,
    statement_commitment,
    statement_evidence_commitment,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedChallengeBundle,
    encode_selected_transcript_evidence,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    build_selected_theorem_round_schedule,
)
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    prove_selected_air_streaming,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    NativeSlhDsaAdapter,
)
from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_program
from experiments.fixed_shape_claim_air.executable_air import PublicInputBinding
from tests.test_wave1a_executable_air import _fixture
from experiments.bl_pq512_crypto_foundation.software_custody_candidate import (
    build_software_custody_certificate,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


@pytest.fixture(scope="module")
def production_candidate_binaries() -> tuple[Path, Path, Path]:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
    target = Path(r"C:\tmp\blpq-target-production-candidate")
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(target)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--release",
            "--offline",
            "--locked",
            "--features",
            "parallel",
            "--manifest-path",
            str(manifest),
            "--bin",
            "selected_streaming_prover_worker",
            "--bin",
            "production_candidate_verify",
            "--bin",
            "selected_slh_dsa_service",
        ],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
    )
    worker = target / "release" / "selected_streaming_prover_worker.exe"
    verifier = target / "release" / "production_candidate_verify.exe"
    slh_service = target / "release" / "selected_slh_dsa_service.exe"
    assert worker.is_file()
    assert verifier.is_file()
    assert slh_service.is_file()
    return worker, verifier, slh_service


def _bundle(suite: bytes) -> SelectedChallengeBundle:
    values = [_wide(f"bundle-{index}") for index in range(13)]
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
        query_seed=_wide("query-seed"),
        query_positions=(0,),
    )


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


def test_active_hiding_rebases_old_circle_gaps_without_deleting_them() -> None:
    certificate = build_active_gkr_hiding_certificate()
    assert certificate.coverage_gaps == ()
    assert certificate.superseded_historical_gaps == HISTORICAL_CIRCLE_GAPS
    assert certificate.activation_allowed is False
    assert certificate.production_usable is False


def test_candidate_envelope_binds_statement_and_selects_nonactivating_suite() -> None:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    public_outputs = bytes(12 * 32)
    sidecar = _sidecar(suite, schema, verifier)
    base_bundle = _bundle(suite)
    evidence = statement_evidence_commitment(public_outputs, sidecar, base_bundle)
    bundle = replace(base_bundle, evidence_commitment=evidence)
    envelope = build_production_envelope(
        public_outputs=public_outputs,
        sidecar=sidecar,
        proof_package=b"opaque-rust-package",
        transcript_evidence=b"opaque-selected-transcript",
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
    selected = select_built_audit_pending_suite(
        envelope,
        verification=verification,
        hiding=build_active_gkr_hiding_certificate(),
        custody=build_software_custody_certificate(),
    )
    assert selected.proof_suite_id == suite
    assert selected.status == "BUILT_AUDIT_PENDING"
    assert selected.activation_allowed is False
    assert selected.production_usable is False
    assert selected.as_public_dict()["proofSuiteId"] == suite.hex()


def test_native_fips205_slh_adapter_round_trips_and_rejects_message_mutation(
    production_candidate_binaries: tuple[Path, Path, Path],
) -> None:
    adapter = NativeSlhDsaAdapter(production_candidate_binaries[2])
    public_key, secret_key = adapter.generate_keypair()
    message = b"BL-PQ512/native-SLH-DSA/cross-language-KAT/v1"
    signature = adapter.sign(secret_key=secret_key, message=message)
    assert adapter.verify(public_key=public_key, message=message, signature=signature)
    assert not adapter.verify(
        public_key=public_key, message=message + b"-mutated", signature=signature
    )


def test_candidate_rejects_bundle_statement_swap() -> None:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    sidecar = _sidecar(suite, schema, verifier)
    bundle = _bundle(suite)
    with pytest.raises(ProductionCandidateError, match="statement_evidence"):
        build_production_envelope(
            public_outputs=bytes(12 * 32),
            sidecar=sidecar,
            proof_package=b"opaque-rust-package",
            transcript_evidence=b"opaque-selected-transcript",
            challenge_bundle=bundle,
        )


def test_real_rust_verifier_issues_only_built_audit_pending_suite(
    production_candidate_binaries: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    worker, verifier, slh_service = production_candidate_binaries
    program, traces = _fixture()
    public_output_bytes = bytes(384)
    program = replace(
        program,
        public_inputs=tuple(
            PublicInputBinding(f"public_live_{index}", "source", "value", 0)
            for index in range(108)
        ),
    )
    geometry = derive_selected_proof_geometry(program)
    schedule = build_selected_theorem_round_schedule(geometry)
    suite = schedule.proof_suite_id
    schema = _wide("production-schema")
    verifier_identity = _wide("production-verifier")
    sidecar = _sidecar(suite, schema, verifier_identity)
    ml_dsa = MlDsa87PqcryptoAdapter()
    slh_dsa = NativeSlhDsaAdapter(slh_service)
    adapters = {ml_dsa.suite_id: ml_dsa, slh_dsa.suite_id: slh_dsa}
    material = []
    for ordinal, adapter in enumerate((ml_dsa, slh_dsa), 1):
        public_key, secret_key = adapter.generate_keypair()
        material.append(
            (
                Contributor(
                    _wide(f"production-contributor-{ordinal}"),
                    _wide(f"production-key-{ordinal}"),
                    adapter.suite_id,
                    public_key,
                ),
                secret_key,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secret_keys = {item[0].contributor_id: item[1] for item in material}
    package_path = tmp_path / "selected-proof-package.bin"
    result = prove_selected_air_streaming(
        worker_executable=worker,
        scratch_parent=tmp_path,
        program=program,
        traces=traces,
        public_inputs=(0,) * 108,
        chunk_values=2,
        secret_mask_seed=_wide("production-mask-seed"),
        session_id=_wide("production-session"),
        public_outputs=public_output_bytes,
        sidecar=sidecar,
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
        proof_export_path=package_path,
    )
    package = package_path.read_bytes()
    package_path.unlink()
    transcript = encode_selected_transcript_evidence(result.transcript)
    envelope = build_production_envelope(
        public_outputs=bytes(384),
        sidecar=sidecar,
        proof_package=package,
        transcript_evidence=transcript,
        challenge_bundle=result.challenge_bundle,
    )
    envelope_path = tmp_path / "production-envelope.bin"
    program_path = tmp_path / "production-program.bin"
    public_inputs_path = tmp_path / "production-public-inputs.bin"
    envelope_path.write_bytes(envelope.encode())
    program_path.write_bytes(encode_air_program(program))
    projection = PublicInputProjectionV1(schema)
    public_inputs_path.write_bytes(projection.encode_file(public_output_bytes))
    verify_args = [
        str(verifier),
        str(envelope_path),
        str(program_path),
        str(public_inputs_path),
        suite.hex(),
        schema.hex(),
        verifier_identity.hex(),
    ]
    completed = subprocess.run(
        verify_args,
        cwd=verifier.parent,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    receipt = NativeVerificationReceipt.from_native_line(completed.stdout.strip())
    tampered_public_inputs_path = tmp_path / "tampered-production-public-inputs.bin"
    tampered_public_inputs = bytearray(public_inputs_path.read_bytes())
    tampered_public_inputs[14] = 1
    tampered_public_inputs_path.write_bytes(bytes(tampered_public_inputs))
    rejected_projection = subprocess.run(
        [
            str(verifier),
            str(envelope_path),
            str(program_path),
            str(tampered_public_inputs_path),
            suite.hex(),
            schema.hex(),
            verifier_identity.hex(),
            schema.hex(),
        ],
        cwd=verifier.parent,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected_projection.returncode != 0
    assert "PublicInputProjection" in rejected_projection.stderr
    port_result = NativeStarkVerifierPort(
        NativeStarkVerifierConfig(
            executable=verifier,
            program=program_path,
            public_inputs=None,
            suite_id=suite,
            schema_id=schema,
            verifier_artifact_identity=verifier_identity,
            public_input_projection=projection,
        )
    ).verify(envelope)
    assert port_result.receipt == receipt
    selected = select_built_audit_pending_suite(
        envelope,
        verification=receipt,
        hiding=build_active_gkr_hiding_certificate(),
        custody=build_software_custody_certificate(),
    )
    assert selected.proof_suite_id == suite
    assert selected.status == "BUILT_AUDIT_PENDING"
    assert selected.activation_allowed is False
    assert selected.production_usable is False

    encoded = envelope.encode()
    proof_offset = 8 + 2 + 64 * 3 + 384 + 4 + 744 + 8
    for offset in (10, proof_offset, len(encoded) - 1):
        mutated = bytearray(encoded)
        mutated[offset] ^= 1
        envelope_path.write_bytes(mutated)
        rejected = subprocess.run(
            verify_args,
            cwd=verifier.parent,
            check=False,
            capture_output=True,
            text=True,
        )
        assert rejected.returncode != 0
        assert rejected.stderr.startswith("ERR:verify_")
    envelope_path.write_bytes(encoded)
