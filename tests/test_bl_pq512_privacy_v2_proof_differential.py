from __future__ import annotations

from dataclasses import replace
import json
import inspect
from pathlib import Path

import pytest

from app.privacy_v2_migration import (
    ACTIVATION_ALLOWED,
    PRODUCTION_USABLE,
    PROOF_SUITE_ID,
    TransactionalPrivacyV2Migration,
    _build_privacy_v2_migration_evidence_with_salt,
    build_privacy_v2_migration_evidence,
    derive_migration_nonce,
    generate_migration_privacy_salt,
    public_migration_artifact,
)
from app.native_public_input_projection import PublicInputProjectionV1
from app.production_boundary import (
    NativeStarkVerifierConfig,
    NativeStarkVerifierPort,
    ProductionBoundaryError,
    _BATCH_NONCE_BINDING,
    _digest,
    build_v2_public_fields,
    native_verifier_artifact_identity,
)
from app.transactional_database_boundary import SQLiteSettlementStoreV2
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    NativeSlhDsaAdapter,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_BYTES,
    build_production_envelope,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    build_selected_theorem_round_schedule,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    prove_selected_air_streaming,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    encode_selected_transcript_evidence,
)
from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_program
from experiments.fixed_shape_claim_air.executable_air import (
    PublicInputBinding,
    TraceTable,
    freeze_columns,
)
from tests.test_bl_pq512_transactional_privacy_v2_migration import (
    _Config,
    _DOMAIN,
    _NEW,
    _NULLIFIER_0,
    _NULLIFIER_1,
    _PAYMENT_0,
    _PAYMENT_1,
    _ROOTS,
    _SUBMITTER,
    _ReceiptVerifier,
    _authority_for_epoch,
    _coordinator,
    _sidecar,
    _wide,
    _migration_inputs,
    _store,
    _target_authority_for_envelope,
)
from tests.test_bl_pq512_production_candidate import production_candidate_binaries
from tests.test_wave1a_executable_air import _fixture
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.privacy_v2_migration import PrivacyV2MigrationTarget


_PRIVATE_CASES = (
    (
        (b"phi:patient-ALPHA|amount:000001|decision:DENIED|cipher:alpha",),
        (b"v2:opaque-record-ALPHA",),
        (b"semantic-claim-ALPHA",),
    ),
    (
        (
            b"phi:patient-BRAVO|amount:999999|decision:PAID|cipher:bravo-1",
            b"phi:patient-CHARLIE|amount:000042|decision:PENDED|cipher:charlie-2",
            b"phi:patient-DELTA|amount:314159|decision:REJECTED|cipher:delta-3",
            b"phi:patient-ECHO|amount:271828|decision:APPROVED|cipher:echo-4",
        ),
        (
            b"v2:opaque-record-BRAVO",
            b"v2:opaque-record-CHARLIE",
            b"v2:opaque-record-DELTA",
            b"v2:opaque-record-ECHO",
        ),
        (
            b"semantic-claim-BRAVO",
            b"semantic-claim-CHARLIE",
            b"semantic-claim-DELTA",
            b"semantic-claim-ECHO",
        ),
    ),
)


def test_private_amount_phi_decision_ciphertext_and_record_count_do_not_change_artifact_shape(
    tmp_path: Path,
) -> None:
    observations = []
    for index, (old_private, new_private, semantics) in enumerate(_PRIVATE_CASES):
        store = _store(tmp_path / f"ledger-{index}.sqlite3")
        verifier = _ReceiptVerifier()
        coordinator = _coordinator(store, verifier)
        envelope, nonce, evidence = _migration_inputs(
            coordinator,
            label=f"differential-{index}",
            old_private_records=old_private,
            new_private_records=new_private,
            semantic_records=semantics,
        )
        operation = coordinator._prepare(
            envelope=envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=_target_authority_for_envelope(envelope),
        )
        artifact = public_migration_artifact(operation)
        artifact_payload = json.loads(artifact)
        evidence_json = json.dumps(
            evidence.as_public_dict(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        public_surface = b"|".join(
            (envelope.public_outputs, envelope.sidecar, artifact, evidence_json)
        )

        for private_value in old_private + new_private + semantics:
            assert private_value not in public_surface
        lowered = public_surface.lower()
        for forbidden_key in (
            b"patient-alpha",
            b"patient-bravo",
            b"patient-charlie",
            b"amount:000001",
            b"amount:999999",
            b"decision:denied",
            b"decision:paid",
            b"cipher:alpha",
            b"cipher:bravo",
        ):
            assert forbidden_key not in lowered

        assert verifier.calls == 1
        assert len(envelope.public_outputs) == 384
        assert len(envelope.public_outputs) // 32 == 12
        assert len(envelope.sidecar) == 744
        assert artifact_payload["proofSuiteId"] is None
        assert artifact_payload["productionUsable"] is False
        assert artifact_payload["activationAllowed"] is False
        assert evidence.as_public_dict()["proofSuiteId"] is None
        observations.append(
            (
                len(envelope.public_outputs),
                len(envelope.sidecar),
                len(envelope.encode()),
                len(artifact),
                len(evidence_json),
                tuple(sorted(artifact_payload)),
                tuple(sorted(evidence.as_public_dict())),
            )
        )

    assert observations[0] == observations[1]


def test_public_migration_surfaces_are_commitment_only_and_nonactivating(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, nonce, evidence = _migration_inputs(coordinator, label="public-surface")
    operation = coordinator._prepare(
        envelope=envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=_target_authority_for_envelope(envelope),
    )
    artifact = json.loads(public_migration_artifact(operation))
    evidence_public = evidence.as_public_dict()

    assert PROOF_SUITE_ID is None
    assert PRODUCTION_USABLE is False
    assert ACTIVATION_ALLOWED is False
    assert set(evidence_public) == {
        "status",
        "kind",
        "versionCommitment",
        "equivalenceCommitment",
        "sourceCheckpointCommitment",
        "targetStateCommitment",
        "knownTargetCheckpoint",
        "evidenceCommitment",
        "proofSuiteId",
        "activationAllowed",
        "productionUsable",
    }
    assert set(artifact) == {
        "status",
        "kind",
        "migrationCommitment",
        "evidenceCommitment",
        "sourceCheckpointCommitment",
        "targetStateCommitment",
        "epochBefore",
        "epochAfter",
        "sequenceBefore",
        "sequenceAfter",
        "profileIdAfter",
        "proofSuiteIdAfter",
        "schemaIdAfter",
        "verifierArtifactIdentityAfter",
        "proofSuiteId",
        "activationAllowed",
        "productionUsable",
    }
    forbidden_names = {"amount", "count", "decision", "phi", "ciphertext", "claim"}
    for key in set(evidence_public) | set(artifact):
        assert not any(name in key.lower() for name in forbidden_names)


def test_private_semantic_difference_fails_before_native_verification(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    verifier = _ReceiptVerifier()
    coordinator = _coordinator(store, verifier)

    with pytest.raises(ProductionBoundaryError, match="migration_semantic_equivalence_failed"):
        _migration_inputs(
            coordinator,
            label="semantic-mismatch",
            old_private_records=(b"old-private",),
            new_private_records=(b"new-private",),
            semantic_records=(b"old-semantics",),
            new_semantic_records=(b"different-new-semantics",),
        )
    assert verifier.calls == 0
    assert store.identity_snapshot().sequence == 0


def test_public_evidence_builder_owns_fresh_privacy_randomness(
    tmp_path: Path,
) -> None:
    assert "privacy_salt" not in inspect.signature(
        build_privacy_v2_migration_evidence
    ).parameters
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    source = coordinator.source_identity
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(
            _sidecar(
                source=source,
                target_config=_NEW,
                nullifier_after=_wide("rng-nullifier-after"),
                payment_after=_wide("rng-payment-after"),
                batch_commitment=_wide("rng-provisional-batch"),
            )
        ),
        settlement_domain=_DOMAIN,
        governance_authority=_authority_for_epoch(source.epoch + 1),
    )
    inputs = dict(
        kind="MIGRATION",
        migration_version="privacy-v2-rng-ownership",
        source=source,
        target=target,
        old_private_records=(b"old",),
        new_private_records=(b"new",),
        old_semantic_records=(b"same",),
        new_semantic_records=(b"same",),
    )
    first = build_privacy_v2_migration_evidence(**inputs)
    second = build_privacy_v2_migration_evidence(**inputs)
    assert first.equivalence_commitment != second.equivalence_commitment
    assert first.commitment != second.commitment


def test_migration_entropy_failure_is_bounded_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def all_zero_entropy(length: int) -> bytes:
        nonlocal calls
        calls += 1
        assert length == 64
        return bytes(64)

    monkeypatch.setattr(
        "app.privacy_v2_migration.secrets.token_bytes", all_zero_entropy
    )
    with pytest.raises(ProductionBoundaryError, match="migration_entropy_failure"):
        generate_migration_privacy_salt()
    assert calls == 4


def test_migration_evidence_known_answer_is_stable(tmp_path: Path) -> None:
    store = _store(tmp_path / "ledger.sqlite3")
    coordinator = _coordinator(store, _ReceiptVerifier())
    envelope, _, evidence = _migration_inputs(coordinator, label="kat-shape")
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(envelope.sidecar),
        settlement_domain=envelope.public_outputs[32:64],
        governance_authority=_target_authority_for_envelope(envelope),
    )
    deterministic = _build_privacy_v2_migration_evidence_with_salt(
        kind="MIGRATION",
        migration_version="privacy-v2-kat-v1",
        source=coordinator.source_identity,
        target=target,
        old_private_records=(b"old-private-record",),
        new_private_records=(b"new-private-record",),
        old_semantic_records=(b"same-private-semantics",),
        new_semantic_records=(b"same-private-semantics",),
        privacy_salt=bytes(range(64)),
    )
    assert evidence.commitment != deterministic.commitment
    assert deterministic.commitment.hex() == (
        "ce9e59897bcbdce1c560c6600bbe8efc737a61445f1014ed33e32c171235bd10"
        "be4f8a21844e530290b3293cdeafeed16b136b447a25dd124872093cf47dbf8e"
    )


def test_real_native_proof_differential_commits_one_migration_exactly_once(
    production_candidate_binaries: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """Different private traces retain one public shape and one DB winner."""

    worker, verifier_executable, slh_service = production_candidate_binaries
    program, base_traces = _fixture()
    source_table = program.tables[0]
    private_column = "private_migration_case"
    public_columns = tuple(f"migration_public_{index}" for index in range(108))
    program = replace(
        program,
        tables=(
            replace(
                source_table,
                columns=source_table.columns + (private_column,) + public_columns,
            ),
            *program.tables[1:],
        ),
        public_inputs=tuple(
            PublicInputBinding(name, "source", name, 0) for name in public_columns
        ),
    )
    program_path = tmp_path / "privacy-v2-migration-program.bin"
    program_path.write_bytes(encode_air_program(program))
    geometry = derive_selected_proof_geometry(program)
    schedule = build_selected_theorem_round_schedule(geometry)
    suite = schedule.proof_suite_id
    schema = _wide("privacy-v2-real-native-schema")
    verifier_identity = native_verifier_artifact_identity(
        verifier_executable, program_path
    )
    source_config = _Config(
        profile=_wide("privacy-v2-real-native-profile-before"),
        suite=suite,
        schema=schema,
        verifier=verifier_identity,
    )
    target_config = _Config(
        profile=_wide("privacy-v2-real-native-profile-after"),
        suite=suite,
        schema=schema,
        verifier=verifier_identity,
    )
    store = SQLiteSettlementStoreV2(
        path=tmp_path / "privacy-v2-real-native.sqlite3",
        settlement_domain=_DOMAIN,
        governance_authority=_ROOTS,
        initial_strong_nullifier_root=_NULLIFIER_0,
        initial_strong_payment_state_root=_PAYMENT_0,
        epoch=1,
        profile_id=source_config.profile,
        suite_id=source_config.suite,
        schema_id=source_config.schema,
        verifier_artifact_identity=source_config.verifier,
    )
    source = store.identity_snapshot()
    provisional_sidecar = _sidecar(
        source=source,
        target_config=target_config,
        nullifier_after=_NULLIFIER_1,
        payment_after=_PAYMENT_1,
        batch_commitment=_wide("privacy-v2-real-native-provisional-batch"),
    )
    target = PrivacyV2MigrationTarget.from_sidecar(
        CandidateSidecarV1.decode(provisional_sidecar),
        settlement_domain=_DOMAIN,
        governance_authority=_authority_for_epoch(source.epoch + 1),
    )
    private_records = (
        b"phi:synthetic-patient-OMEGA|amount:424242|decision:APPROVED|cipher:opaque",
    )
    replacement_records = (b"v2:synthetic-opaque-record-OMEGA",)
    semantic_records = (b"semantic:synthetic-claim-OMEGA",)
    evidence = build_privacy_v2_migration_evidence(
        kind="MIGRATION",
        migration_version="privacy-v2-real-native-differential-v1",
        source=source,
        target=target,
        old_private_records=private_records,
        new_private_records=replacement_records,
        old_semantic_records=semantic_records,
        new_semantic_records=semantic_records,
    )
    nonce = derive_migration_nonce(source, target, evidence)
    sidecar = _sidecar(
        source=source,
        target_config=target_config,
        nullifier_after=_NULLIFIER_1,
        payment_after=_PAYMENT_1,
        batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    )
    public_output_bytes = b"".join(
        build_v2_public_fields(
            settlement_domain=_DOMAIN,
            batch_nonce=nonce,
            sidecar=sidecar,
            governance_authority=target.governance_authority,
            suite_id=suite,
            schema_id=schema,
            verifier_artifact_identity=verifier_identity,
        )
    )
    projection = PublicInputProjectionV1(schema)
    projected_public_inputs = projection.project(public_output_bytes)

    ml_dsa = MlDsa87PqcryptoAdapter()
    slh_dsa = NativeSlhDsaAdapter(slh_service)
    adapters = {ml_dsa.suite_id: ml_dsa, slh_dsa.suite_id: slh_dsa}
    material = []
    for ordinal, adapter in enumerate((ml_dsa, slh_dsa), 1):
        public_key, secret_key = adapter.generate_keypair()
        material.append(
            (
                Contributor(
                    _wide(f"privacy-v2-real-native-contributor-{ordinal}"),
                    _wide(f"privacy-v2-real-native-key-{ordinal}"),
                    adapter.suite_id,
                    public_key,
                ),
                secret_key,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secret_keys = {item[0].contributor_id: item[1] for item in material}

    envelopes = []
    proof_core_lengths = []
    for ordinal, private_value in enumerate((7, 19), 1):
        traces = dict(base_traces)
        source_columns = dict(traces["source"].columns)
        source_row_count = len(next(iter(source_columns.values())))
        source_columns[private_column] = (private_value,) * source_row_count
        source_columns.update(
            {
                name: (value, 0, 0, 0)
                for name, value in zip(
                    public_columns, projected_public_inputs, strict=True
                )
            }
        )
        traces["source"] = TraceTable("source", freeze_columns(source_columns))
        package_path = tmp_path / f"privacy-v2-real-proof-{ordinal}.bin"
        result = prove_selected_air_streaming(
            worker_executable=worker,
            scratch_parent=tmp_path,
            program=program,
            traces=traces,
            public_inputs=projected_public_inputs,
            chunk_values=2,
            session_id=_wide(f"privacy-v2-real-native-session-{ordinal}"),
            public_outputs=public_output_bytes,
            sidecar=sidecar,
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            proof_export_path=package_path,
        )
        package = package_path.read_bytes()
        package_path.unlink()
        assert len(package) == PROOF_PACKAGE_BYTES
        assert package[:8] == b"BLPQSPK1"
        assert int.from_bytes(package[8:10], "big") == 2
        assert package[-1] == 0
        proof_core_lengths.append(result.proof_bytes)
        envelopes.append(
            build_production_envelope(
                public_outputs=public_output_bytes,
                sidecar=sidecar,
                proof_package=package,
                transcript_evidence=encode_selected_transcript_evidence(
                    result.transcript
                ),
                challenge_bundle=result.challenge_bundle,
            )
        )

    first_envelope, second_envelope = envelopes
    assert first_envelope.public_outputs == second_envelope.public_outputs
    assert first_envelope.sidecar == second_envelope.sidecar
    assert len(first_envelope.proof_package) == len(second_envelope.proof_package)
    assert len(first_envelope.proof_package) == PROOF_PACKAGE_BYTES
    assert all(0 < length < PROOF_PACKAGE_BYTES for length in proof_core_lengths)
    assert len(first_envelope.transcript_evidence) == len(
        second_envelope.transcript_evidence
    )
    assert len(first_envelope.encode()) == len(second_envelope.encode())
    assert first_envelope.proof_package != second_envelope.proof_package
    for candidate in (first_envelope, second_envelope):
        public_artifact = candidate.encode()
        for private_value in private_records + replacement_records + semantic_records:
            assert private_value not in public_artifact
        del public_artifact

    verifier = NativeStarkVerifierPort(
        NativeStarkVerifierConfig(
            executable=verifier_executable,
            program=program_path,
            suite_id=suite,
            schema_id=schema,
            verifier_artifact_identity=verifier_identity,
            public_input_projection=projection,
        )
    )
    first_native = verifier.verify(first_envelope)
    second_native = verifier.verify(second_envelope)
    assert first_native.statement_commitment == second_native.statement_commitment
    assert first_native.envelope_commitment != second_native.envelope_commitment

    def reject_invalid_package(invalid_package: bytes) -> None:
        with pytest.raises(ProductionBoundaryError, match="native_verifier_rejected"):
            verifier.verify(replace(first_envelope, proof_package=invalid_package))

    reject_invalid_package(first_envelope.proof_package[:-1])
    reject_invalid_package(first_envelope.proof_package + b"\x00")
    old_version = bytearray(first_envelope.proof_package)
    old_version[8:10] = (1).to_bytes(2, "big")
    reject_invalid_package(bytes(old_version))
    del old_version
    nonzero_padding = bytearray(first_envelope.proof_package)
    nonzero_padding[-1] = 1
    reject_invalid_package(bytes(nonzero_padding))
    del nonzero_padding

    migration = TransactionalPrivacyV2Migration(
        verifier=verifier,
        storage=store,
        settlement_domain=_DOMAIN,
        governance_authority=source.governance_authority,
        authorized_submitters=(_SUBMITTER,),
    )
    operation = migration._prepare(
        envelope=first_envelope,
        batch_nonce=nonce,
        submitter=_SUBMITTER,
        evidence=evidence,
        target_governance_authority=target.governance_authority,
    )
    public_artifact = public_migration_artifact(operation)
    for private_value in private_records + replacement_records + semantic_records:
        assert private_value not in public_artifact
    receipt = store._commit_verified_migration(operation)
    assert receipt.sequence_before == 0
    assert receipt.sequence_after == 1
    assert store.identity_snapshot().sequence == 1
    with pytest.raises(
        ProductionBoundaryError, match="database_migration_conflicting_retry"
    ):
        migration.submit(
            envelope=second_envelope,
            batch_nonce=nonce,
            submitter=_SUBMITTER,
            evidence=evidence,
            target_governance_authority=target.governance_authority,
        )
    assert store.identity_snapshot().sequence == 1
    store.verify_integrity()
