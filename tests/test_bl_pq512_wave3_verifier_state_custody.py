from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha3_512

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    NullifierDerivationAuthorityV1,
    derive_attempt_nullifiers_v1,
)
from app.batch.pq_suite_candidate import candidate_salt_use_tag
from app.batch.pq_suite_candidate import ActiveSuiteIdentityV1
from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    MasterCommitmentInputsV2,
    MasterEconomicTotalsV2,
    MasterSlotRecordV2,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.wave3_nullifier_authority import (
    Wave3NullifierAuthorityV1,
    Wave3NullifierError,
)
import experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody as custody_module
from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
    ActiveVerifierProfileV1,
    Wave3ActivationConfigV1,
    DUAL_PQ_SUITES,
    DualPqAuthorityV1,
    GovernedRootManifestV1,
    GovernedRootRecordV1,
    GovernedRootRegistryV1,
    MlKem1024Aes256ReferenceV1,
    PqAuthorityRotationV1,
    PqAuthorityKeyV1,
    PqProviderConformanceV1,
    PqSignatureEnvelopeV1,
    Wave3BoundaryError,
    Wave3RecoveryAnchorV1,
    Wave3DurableStateV1,
    Wave3StatePayloadV1,
    Wave3VerifierV1,
    build_wave3_commitments,
    build_wave3_sidecar,
    assess_pq_provider_port,
    wave3_batch_commitment,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _raw(label: str) -> bytes:
    authority = NullifierDerivationAuthorityV1.from_secret(b"A" * 64, b"P" * 64)
    return derive_attempt_nullifiers_v1(
        AttemptReplayIdentityV1(f"AUTH-{label}", f"CLAIM-{label}", 1, 1, 0),
        authority,
    ).canonical_preimage


@dataclass
class _SoftwarePort:
    adapter: object
    suite_id: str
    key_id: bytes
    public_key: bytes
    secret_key: bytes
    hsm_backed: bool = False
    fips_validated: bool = False

    @classmethod
    def create(cls, adapter: object, suite_id: str, key_id: bytes) -> "_SoftwarePort":
        public_key, secret_key = adapter.generate_keypair()  # type: ignore[attr-defined]
        return cls(adapter, suite_id, key_id, public_key, secret_key)

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self.adapter.verify(  # type: ignore[attr-defined]
            public_key=public_key,
            message=message,
            signature=signature,
        ) is True

    def sign(self, message: bytes) -> bytes:
        return self.adapter.sign(secret_key=self.secret_key, message=message)  # type: ignore[attr-defined]


def _dual_authority(label: str = "authority") -> tuple[DualPqAuthorityV1, dict[str, _SoftwarePort]]:
    ports = {
        ML_DSA_87_SUITE_ID: _SoftwarePort.create(
            MlDsa87PqcryptoAdapter(), ML_DSA_87_SUITE_ID, _wide(f"{label}-ml-dsa-key")
        ),
        SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: _SoftwarePort.create(
            SphincsShake256fSimplePqcryptoAdapter(),
            SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
            _wide(f"{label}-slh-dsa-key"),
        ),
    }
    authority = DualPqAuthorityV1(
        authority_id_512=_wide(label),
        keys=tuple(
            PqAuthorityKeyV1(suite_id, ports[suite_id].key_id, ports[suite_id].public_key)
            for suite_id in DUAL_PQ_SUITES
        ),
        verifiers=ports,
    )
    return authority, ports


def _root(
    authority: DualPqAuthorityV1,
    ports: dict[str, _SoftwarePort],
    *,
    epoch: int,
    root_kind: str = "CLAIM_SOURCE",
) -> GovernedRootRecordV1:
    root = _wide(f"root-{epoch}")
    record = GovernedRootRecordV1(
        root_kind=root_kind,
        profile_id=_wide("profile"),
        epoch=epoch,
        compatibility_alias=(int.from_bytes(root, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big"),
        root_512=root,
        manifest_id=_wide(f"manifest-{epoch}"),
        schema_id=_wide("schema"),
        authority_id_512=authority.authority_id_512,
        signatures=(
            PqSignatureEnvelopeV1(ML_DSA_87_SUITE_ID, ports[ML_DSA_87_SUITE_ID].key_id, b"\x01" * 4627),
            PqSignatureEnvelopeV1(
                SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
                ports[SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID].key_id,
                b"\x01" * 49856,
            ),
        ),
    )
    return replace(record, signatures=authority.sign(unsigned_root=record.root_id_512))


def test_governed_roots_require_dual_pq_authority_and_never_overwrite() -> None:
    authority, ports = _dual_authority()
    registry = GovernedRootRegistryV1(authority=authority)
    first = _root(authority, ports, epoch=1)
    second = _root(authority, ports, epoch=2)
    oracle = _root(authority, ports, epoch=2, root_kind="ORACLE_FACTS")
    registry.register(first)
    registry.register(second)
    registry.register(oracle)
    assert registry.resolve(root_kind="CLAIM_SOURCE", epoch=2) == second
    assert registry.commitment_sha3_512 != bytes(64)

    with pytest.raises(Wave3BoundaryError, match="overwrite"):
        registry.register(first)
    downgraded_oracle = _root(authority, ports, epoch=1, root_kind="ORACLE_FACTS")
    with pytest.raises(Wave3BoundaryError, match="downgrade"):
        registry.register(downgraded_oracle)

    forged_signature = bytes([first.signatures[0].signature[0] ^ 1]) + first.signatures[0].signature[1:]
    forged = replace(
        first,
        root_kind="ORACLE_FACTS",
        signatures=(replace(first.signatures[0], signature=forged_signature), first.signatures[1]),
    )
    with pytest.raises(Wave3BoundaryError, match="signature_invalid"):
        registry.register(forged)


def _commitment_inputs() -> MasterCommitmentInputsV2:
    slots = tuple(
        MasterSlotRecordV2(
            slot_index=index,
            decision=1,
            failure_code=0,
            allowed_cents=100,
            payment_cents=80,
            raw_gate_bits=(1 << 13) - 1,
            effective_gate_bits=(1 << 13) - 1,
            strong_nullifier_512=_wide(f"slot-{index}"),
        )
        for index in range(128)
    )
    return MasterCommitmentInputsV2(
        profile_id="K128_CALIBRATION",
        epoch=7,
        strong_settlement_domain_id_512=_wide("settlement"),
        strong_batch_nonce_512=_wide("nonce"),
        claim_truth_roots_512=tuple(_wide(f"truth-{index}") for index in range(6)),
        claim_truth_authority_digest_512=_wide("truth-authority"),
        nullifier_authority_id_512=_wide("nullifier-authority"),
        pepper_commitment_512=_wide("pepper"),
        replay_root_before_512=_wide("replay-before"),
        replay_root_after_512=_wide("replay-after"),
        payment_lane_roots_before_512=tuple(_wide(f"payment-before-{index}") for index in range(3)),
        payment_lane_roots_after_512=tuple(_wide(f"payment-after-{index}") for index in range(3)),
        operation_log_root_before_512=_wide("operation-before"),
        operation_log_root_after_512=_wide("operation-after"),
        salt_use_tag_512=_wide("salt-tag"),
        economic_totals=MasterEconomicTotalsV2(12_800, 2_560, 10_240, 10_240, 10_240),
        slots=slots,
    )


def test_fresh_master_salt_is_bound_without_becoming_public() -> None:
    salt = b"S" * 64
    inputs = replace(_commitment_inputs(), salt_use_tag_512=candidate_salt_use_tag(salt))
    bundle = build_wave3_commitments(inputs, master_salt_512=salt)
    assert bundle.bundle_digest_512 == sha3_512(bundle.canonical_bytes()).digest()
    assert salt not in bundle.canonical_bytes()
    with pytest.raises(Wave3BoundaryError, match="salt_use_tag"):
        build_wave3_commitments(inputs, master_salt_512=b"T" * 64)


def test_durable_state_is_atomic_and_migration_rollback_advances_epoch(tmp_path) -> None:
    authority, _ports = _dual_authority()
    registry = GovernedRootRegistryV1(authority=authority)
    path = tmp_path / "private-state.bin"
    state = Wave3DurableStateV1.create(
        path,
        registry=registry,
        profile_id=_wide("profile-v1"),
        authority_id_512=authority.authority_id_512,
    )
    initial = state.snapshot()
    state.apply(_raw("ONE"))
    state.apply(_raw("TWO"))
    progressed = state.snapshot()
    assert progressed.state.sequence == 2
    assert progressed.state.strong_nullifier_root_512 != initial.state.strong_nullifier_root_512
    checkpoint = state.checkpoint_history[0]

    migrated = state.migrate(
        registry=registry,
        profile_id=_wide("profile-v2"),
        authority_id_512=_wide("authority-v2"),
    )
    after_migration = state.snapshot()
    assert migrated.old_epoch == 1
    assert after_migration.state.epoch == 2
    assert after_migration.state.sequence == progressed.state.sequence
    assert after_migration.state.strong_nullifier_root_512 == progressed.state.strong_nullifier_root_512

    rolled_back = state.rollback(target_checkpoint_512=checkpoint, registry=registry)
    after_rollback = state.snapshot()
    assert rolled_back.new_epoch == 3
    assert after_rollback.state.epoch == 3
    assert after_rollback.state.sequence == 1
    assert after_rollback.state.strong_nullifier_root_512 != after_migration.state.strong_nullifier_root_512

    reopened = Wave3DurableStateV1(
        path,
        registry=registry,
        profile_id=_wide("profile-v1"),
        authority_id_512=authority.authority_id_512,
    )
    assert reopened.snapshot() == after_rollback
    with pytest.raises(Wave3NullifierError, match="already_present"):
        state.apply(_raw("ONE"))

    lock_path = path.with_name(path.name + ".lock")
    lock_path.write_bytes(b"synthetic-lock")
    try:
        with pytest.raises(Wave3BoundaryError, match="lock_busy"):
            state.apply(_raw("THREE"))
    finally:
        lock_path.unlink()

    corrupted = bytearray(path.read_bytes())
    corrupted[-1] ^= 1
    path.write_bytes(corrupted)
    with pytest.raises(Wave3BoundaryError, match="rejected|digest"):
        Wave3DurableStateV1(
            path,
            registry=registry,
            profile_id=_wide("profile-v1"),
            authority_id_512=authority.authority_id_512,
        )


def test_ml_kem_1024_aes256_envelope_is_private_and_tamper_rejecting() -> None:
    public_key, secret_key = MlKem1024Aes256ReferenceV1.generate_keypair()
    plaintext = b"synthetic private witness bytes"
    aad = b"BL/PQ512/WAVE3/test-boundary"
    key_id = _wide("kem-key")
    envelope = MlKem1024Aes256ReferenceV1.seal(
        key_id=key_id,
        public_key=public_key,
        plaintext=plaintext,
        associated_data=aad,
    )
    assert plaintext not in envelope
    assert MlKem1024Aes256ReferenceV1.open(
        secret_key=secret_key,
        envelope=envelope,
        associated_data=aad,
        expected_key_id=key_id,
    ) == plaintext
    with pytest.raises(Wave3BoundaryError, match="key_id_mismatch"):
        MlKem1024Aes256ReferenceV1.open(
            secret_key=secret_key,
            envelope=envelope,
            associated_data=aad,
            expected_key_id=_wide("wrong-kem-key"),
        )
    wrong_version = bytearray(envelope)
    wrong_version[8:10] = (0).to_bytes(2, "big")
    with pytest.raises(Wave3BoundaryError, match="version_invalid"):
        MlKem1024Aes256ReferenceV1.open(
            secret_key=secret_key,
            envelope=bytes(wrong_version),
            associated_data=aad,
            expected_key_id=key_id,
        )
    wrong_flags = bytearray(envelope)
    wrong_flags[10:12] = (1).to_bytes(2, "big")
    with pytest.raises(Wave3BoundaryError, match="flags_invalid"):
        MlKem1024Aes256ReferenceV1.open(
            secret_key=secret_key,
            envelope=bytes(wrong_flags),
            associated_data=aad,
            expected_key_id=key_id,
        )
    forged = bytearray(envelope)
    forged[-1] ^= 1
    with pytest.raises(Wave3BoundaryError, match="open_rejected"):
        MlKem1024Aes256ReferenceV1.open(
            secret_key=secret_key,
            envelope=bytes(forged),
            associated_data=aad,
            expected_key_id=key_id,
        )


def test_verifier_rejects_before_proof_work_while_suite_is_unselected() -> None:
    roots = [_wide(f"root-{index}") for index in range(4)]
    sidecar = build_wave3_sidecar(
        profile_id=_wide("profile"),
        proof_suite_id=_wide("unselected-suite-placeholder"),
        schema_id=_wide("schema"),
        verifier_artifact_identity=_wide("verifier"),
        strong_settlement_domain_id=_wide("domain"),
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=roots[0],
        strong_nullifier_root_after=roots[1],
        strong_governance_commitment=roots[2],
        strong_payment_state_root_before=roots[2],
        strong_payment_state_root_after=roots[3],
        strong_batch_commitment=_wide("batch"),
    )
    with pytest.raises(Wave3BoundaryError, match="proof_suite_unselected"):
        Wave3VerifierV1().verify(
            encoded_sidecar=sidecar.encode(),
            public_fields=tuple(index.to_bytes(32, "big") for index in range(12)),
            proof=b"opaque-proof",
        )


def test_manifest_derivation_and_registry_binding_are_canonical() -> None:
    authority, _ports = _dual_authority()
    registry = GovernedRootRegistryV1(authority=authority)
    manifest = GovernedRootManifestV1(
        "CLAIM_SOURCE",
        _wide("manifest-profile"),
        1,
        _wide("manifest-schema"),
        (b"synthetic-record-a", b"synthetic-record-b"),
    )
    root_id = registry.register_manifest(manifest)
    record = registry.resolve(root_kind="CLAIM_SOURCE", epoch=1)
    assert root_id == record.root_id_512
    changed = GovernedRootManifestV1(
        manifest.root_kind,
        manifest.profile_id,
        manifest.epoch,
        manifest.schema_id,
        (b"synthetic-record-a", b"synthetic-record-c"),
    )
    assert changed.manifest_id_512 != manifest.manifest_id_512
    assert changed.root_512 != manifest.root_512
    mismatched = GovernedRootRecordV1.from_manifest(changed, authority=authority)
    with pytest.raises(Wave3BoundaryError, match="manifest_mismatch"):
        registry.register_manifest(manifest, record=mismatched)


def test_authority_rotation_is_dual_signed_monotonic_and_provider_conformance_stays_nonproduction() -> None:
    old, old_ports = _dual_authority("old-authority")
    new, _new_ports = _dual_authority("new-authority")
    rotation = PqAuthorityRotationV1.issue(
        old_authority=old,
        new_authority=new,
        old_epoch=3,
        new_epoch=4,
    )
    assert rotation.verify(old_authority=old, new_authority=new)
    with pytest.raises(Wave3BoundaryError, match="successor"):
        PqAuthorityRotationV1.issue(
            old_authority=old,
            new_authority=new,
            old_epoch=3,
            new_epoch=3,
        )
    forged = replace(
        rotation,
        new_signatures=(
            replace(
                rotation.new_signatures[0],
                signature=bytes([rotation.new_signatures[0].signature[0] ^ 1])
                + rotation.new_signatures[0].signature[1:],
            ),
            rotation.new_signatures[1],
        ),
    )
    with pytest.raises(Wave3BoundaryError, match="signature_invalid"):
        forged.verify(old_authority=old, new_authority=new)
    report = assess_pq_provider_port(
        old_ports[ML_DSA_87_SUITE_ID],
        expected_suite_id=ML_DSA_87_SUITE_ID,
        expected_key_id=old.keys[0].key_id,
    )
    assert isinstance(report, PqProviderConformanceV1)
    assert report.production_usable is False
    assert report.failure_code == "hsm_backing_missing"


class _ReferenceProofVerifier:
    def verify(
        self,
        *,
        proof: bytes,
        public_fields: tuple[bytes, ...],
        sidecar: object,
    ) -> bytes:
        return sha3_512(proof + sidecar.encode() + b"".join(public_fields)).digest()  # type: ignore[attr-defined]


def _felt_alias(value: bytes) -> bytes:
    return (int.from_bytes(value, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def test_candidate_verifier_and_state_publish_bind_one_atomic_proof_context(tmp_path) -> None:
    authority, _ports = _dual_authority()
    registry = GovernedRootRegistryV1(authority=authority)
    path = tmp_path / "verified-state.bin"
    state = Wave3DurableStateV1.create(
        path,
        registry=registry,
        profile_id=_wide("verified-profile"),
        authority_id_512=authority.authority_id_512,
    )
    raw = _raw("VERIFIED")
    reference = Wave3NullifierAuthorityV1(epoch=1)
    transition = reference.prepare_transition(raw)
    domain = _wide("verified-domain")
    identity = ActiveSuiteIdentityV1(
        profile_id=_wide("verified-profile"),
        proof_suite_id=_wide("candidate-proof-suite"),
        schema_id=_wide("verified-schema"),
        verifier_artifact_identity=_wide("verified-verifier"),
        strong_settlement_domain_id=domain,
        epoch=1,
        legacy_protocol_version_alias=(2).to_bytes(32, "big"),
        legacy_settlement_domain_alias=_felt_alias(domain),
    )
    sidecar = build_wave3_sidecar(
        profile_id=identity.profile_id,
        proof_suite_id=identity.proof_suite_id,
        schema_id=identity.schema_id,
        verifier_artifact_identity=identity.verifier_artifact_identity,
        strong_settlement_domain_id=domain,
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=transition.before.strong_nullifier_root_512,
        strong_nullifier_root_after=transition.after.strong_nullifier_root_512,
        strong_governance_commitment=_wide("governance"),
        strong_payment_state_root_before=_wide("payment-before"),
        strong_payment_state_root_after=_wide("payment-after"),
        strong_batch_commitment=wave3_batch_commitment(raw),
    )
    public_fields = (
        (2).to_bytes(32, "big"),
        _felt_alias(domain),
        *(index.to_bytes(32, "big") for index in range(3, 13)),
    )
    verifier = Wave3VerifierV1(
        active_profile=ActiveVerifierProfileV1(identity),
        proof_verifier=_ReferenceProofVerifier(),
    )
    context = verifier.verify_candidate(
        encoded_sidecar=sidecar.encode(),
        public_fields=public_fields,
        proof=b"synthetic-proof",
    )
    assert context.strong_outputs.strong_nullifier_root_after == transition.after.strong_nullifier_root_512
    assert context.sidecar_digest_512 == sha3_512(sidecar.encode()).digest()
    stale_root_context = replace(
        context,
        sidecar=replace(context.sidecar, strong_nullifier_root_before=_wide("stale-root")),
    )
    with pytest.raises(Wave3BoundaryError, match="root_before_mismatch"):
        state.apply_verified_batch(stale_root_context, raw)
    mixed_profile_context = replace(
        context,
        sidecar=replace(context.sidecar, profile_id=_wide("wrong-profile")),
    )
    with pytest.raises(Wave3BoundaryError, match="identity_mismatch"):
        state.apply_verified_batch(mixed_profile_context, raw)
    published = state.apply_verified_batch(context, raw)
    assert published.state.sequence == 1
    assert published.atomic_binding_512 == context.atomic_binding_512
    with pytest.raises(Wave3BoundaryError, match="drop_atomic_binding"):
        state.apply(_raw("AFTER-VERIFIED"))

    with pytest.raises(Wave3BoundaryError, match="globally_closed"):
        Wave3ActivationConfigV1(
            identity,
            authority.authority_id_512,
            registry.commitment_sha3_512,
            True,
            True,
        ).validate_for_activation()


def test_recovery_anchor_upgrade_and_atomic_write_failure_preserve_invariants(tmp_path, monkeypatch) -> None:
    authority, _ports = _dual_authority()
    registry = GovernedRootRegistryV1(authority=authority)
    path = tmp_path / "recoverable-state.bin"
    state = Wave3DurableStateV1.create(
        path,
        registry=registry,
        profile_id=_wide("recover-profile"),
        authority_id_512=authority.authority_id_512,
    )
    state.apply(_raw("RECOVER"))
    payload = state._read().current  # type: ignore[attr-defined]
    anchor = Wave3RecoveryAnchorV1.issue(
        payload=payload,
        authority=authority,
        root_512=state.snapshot().state.strong_nullifier_root_512,
    )
    recovered_path = tmp_path / "recovered-state.bin"
    recovered = Wave3DurableStateV1.recover(
        recovered_path,
        payload=payload,
        anchor=anchor,
        registry=registry,
        authority=authority,
    )
    assert recovered.snapshot().state == state.snapshot().state
    forged = replace(
        anchor,
        signatures=(
            replace(
                anchor.signatures[0],
                signature=bytes([anchor.signatures[0].signature[0] ^ 1]) + anchor.signatures[0].signature[1:],
            ),
            anchor.signatures[1],
        ),
    )
    with pytest.raises(Wave3BoundaryError, match="signature_invalid"):
        Wave3DurableStateV1.recover(
            tmp_path / "forged-recovery.bin",
            payload=payload,
            anchor=forged,
            registry=registry,
            authority=authority,
        )

    root_before_upgrade = state.snapshot().state.strong_nullifier_root_512
    encoded_before_failed_write = path.read_bytes()

    def fail_atomic_write(_path, _encoded) -> None:
        raise Wave3BoundaryError("synthetic_write_failure")

    monkeypatch.setattr(custody_module, "_atomic_write", fail_atomic_write)
    with pytest.raises(Wave3BoundaryError, match="synthetic_write_failure"):
        state.apply(_raw("WRITE-FAIL"))
    assert path.read_bytes() == encoded_before_failed_write
    monkeypatch.undo()

    upgraded_authority, _upgraded_ports = _dual_authority("recover-authority-v2")
    upgraded_registry = GovernedRootRegistryV1(authority=upgraded_authority)
    upgraded = state.upgrade(
        registry=upgraded_registry,
        profile_id=_wide("recover-profile-v2"),
        authority_id_512=upgraded_authority.authority_id_512,
    )
    assert upgraded.new_epoch == 2
    assert state.snapshot().state.strong_nullifier_root_512 == root_before_upgrade
