from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha3_512
import os
from pathlib import Path
import subprocess

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    NullifierDerivationAuthorityV1,
    derive_attempt_nullifiers_v1,
)
from app.batch.pq_suite_candidate import ActiveSuiteIdentityV1, CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.wave3_nullifier_authority import (
    Wave3NullifierAuthorityV1,
)
from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import (
    DUAL_PQ_SUITES,
    DualPqAuthorityV1,
    GovernedRootManifestV1,
    PqAuthorityKeyV1,
)
from experiments.bl_pq512_crypto_foundation.wave3_full_internal import (
    Wave3AuthoritativeCheckpointV1,
    Wave3AuthoritativeEnvelopeV1,
    Wave3AuthoritativeStateV1,
    Wave3CustodyAuditLogV1,
    Wave3CustodyMonotonicCounterV1,
    Wave3DurableGovernedRootRegistryV1,
    Wave3FullBatchInputV1,
    Wave3FullBoundaryError,
    Wave3FullVerifierV1,
    Wave3ProofEnvelopeV1,
    Wave3RustStateBindingVerifierV1,
    derive_payment_state_after_512,
    full_batch_commitment,
    replay_wave3_batch,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _felt_alias(value: bytes) -> bytes:
    return (int.from_bytes(value, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


_RAW_AUTHORITY = NullifierDerivationAuthorityV1.from_secret(b"A" * 64, b"P" * 64)


def _raw(label: str) -> bytes:
    return derive_attempt_nullifiers_v1(
        AttemptReplayIdentityV1(f"AUTH-{label}", f"CLAIM-{label}", 1, 1, 0),
        _RAW_AUTHORITY,
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


def _dual_authority(label: str = "full-authority") -> tuple[DualPqAuthorityV1, dict[str, _SoftwarePort]]:
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
            PqAuthorityKeyV1(suite, ports[suite].key_id, ports[suite].public_key)
            for suite in DUAL_PQ_SUITES
        ),
        verifiers=ports,
    )
    return authority, ports


def _identity(epoch: int, label: str) -> ActiveSuiteIdentityV1:
    domain = _wide(f"{label}-domain")
    return ActiveSuiteIdentityV1(
        _wide(f"{label}-profile"),
        _wide(f"{label}-candidate-suite"),
        _wide(f"{label}-schema"),
        _wide(f"{label}-verifier"),
        domain,
        epoch,
        (2).to_bytes(32, "big"),
        _felt_alias(domain),
    )


def _aliases(label: str) -> tuple[bytes, ...]:
    return tuple(_felt_alias(_wide(f"{label}-alias-{index}")) for index in range(4))


class _ReferenceProofVerifier:
    def verify(self, *, proof: bytes, public_fields: tuple[bytes, ...], sidecar: CandidateSidecarV1) -> bytes:
        return sha3_512(proof + sidecar.encode() + b"".join(public_fields)).digest()


def _full_batch(identity: ActiveSuiteIdentityV1, registry_commitment: bytes) -> tuple[Wave3FullBatchInputV1, CandidateSidecarV1, tuple[bytes, ...]]:
    private = Wave3FullBatchInputV1(
        tuple(_raw(f"FULL-{index:03d}") for index in range(256)),
        b"S" * 64,
        _wide("private-batch-commitment"),
        _wide("hidden-value-commitment"),
    )
    initial = Wave3NullifierAuthorityV1(epoch=identity.epoch).snapshot()
    replay = replay_wave3_batch(private, epoch=identity.epoch)
    public = (
        identity.legacy_protocol_version_alias,
        identity.legacy_settlement_domain_alias,
        _felt_alias(_wide("batch-nonce")),
        initial.legacy_root_felt.to_bytes(32, "big"),
        replay.after.legacy_root_felt.to_bytes(32, "big"),
        *_aliases("state"),
        _felt_alias(_wide("public-field-9")),
        _felt_alias(_wide("public-field-10")),
        _felt_alias(_wide("public-field-11")),
    )
    payment_before = _wide("payment-before")
    sidecar = CandidateSidecarV1(
        identity.profile_id,
        identity.proof_suite_id,
        identity.schema_id,
        identity.verifier_artifact_identity,
        identity.strong_settlement_domain_id,
        identity.epoch,
        0,
        1,
        replay.before.strong_nullifier_root_512,
        replay.after.strong_nullifier_root_512,
        registry_commitment,
        payment_before,
        derive_payment_state_after_512(
            payment_state_before_512=payment_before,
            private_batch_commitment_512=private.canonical_private_batch_commitment_512,
            hidden_strong_value_commitment_512=private.hidden_strong_value_commitment_512,
            salt_use_tag_512=private.salt_use_tag_512,
        ),
        _wide("placeholder-batch-commitment"),
    )
    return (
        private,
        replace(
            sidecar,
            strong_batch_commitment=full_batch_commitment(
                encoded_sidecar_prefix=sidecar.encode()[:680],
                public_fields=public,
                private_batch_commitment_512=private.canonical_private_batch_commitment_512,
                hidden_strong_value_commitment_512=private.hidden_strong_value_commitment_512,
                master_salt_512=private.master_salt_512,
            ),
        ),
        public,
    )


def test_full_fixed_256_batch_publishes_atomic_state_and_reopens(tmp_path: Path) -> None:
    authority, _ports = _dual_authority()
    from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import GovernedRootRegistryV1

    registry = GovernedRootRegistryV1(authority=authority)
    identity = _identity(1, "full")
    aliases = _aliases("state")
    path = tmp_path / "authoritative-state.bin"
    state = Wave3AuthoritativeStateV1.create(
        path,
        registry=registry,
        candidate_identity=identity,
        legacy_governed_root_aliases=aliases,
        strong_payment_state_root_512=_wide("payment-before"),
    )
    private, sidecar, public = _full_batch(identity, registry.commitment_sha3_512)
    envelope = Wave3ProofEnvelopeV1(sidecar.encode(), b"synthetic-proof-body")
    context = Wave3FullVerifierV1(
        candidate_identity=identity,
        proof_verifier=_ReferenceProofVerifier(),
    ).verify_envelope(encoded_envelope=envelope.encode(), public_fields=public)
    published = state.apply_verified_batch(context, private)
    assert published.state.global_sequence == 1
    assert published.state.proof_suite_id_512 is None
    assert published.state.recorded_strong_batch_commitments == (sidecar.strong_batch_commitment,)
    persisted = path.read_bytes()
    assert private.master_salt_512 not in persisted
    assert private.master_salt_512 not in envelope.encode()
    assert private.canonical_private_batch_commitment_512 not in envelope.encode()
    assert private.hidden_strong_value_commitment_512 not in envelope.encode()
    reopened = Wave3AuthoritativeStateV1(
        path,
        registry=registry,
        candidate_identity=identity,
        legacy_governed_root_aliases=aliases,
    )
    assert reopened.snapshot() == published
    current = reopened.current_checkpoint
    tampered_sidecar = replace(
        CandidateSidecarV1.decode(current.batches[0].encoded_sidecar),
        strong_batch_commitment=_wide("tampered-batch-commitment"),
    )
    tampered_record = replace(current.batches[0], encoded_sidecar=tampered_sidecar.encode())
    tampered_state = replace(
        current.state,
        recorded_strong_batch_commitments=(tampered_record.strong_batch_commitment_512,),
    )
    path.write_bytes(
        Wave3AuthoritativeEnvelopeV1(
            Wave3AuthoritativeCheckpointV1(tampered_state, (tampered_record,))
        ).encode()
    )
    with pytest.raises(Wave3FullBoundaryError, match="batch_commitment"):
        Wave3AuthoritativeStateV1(
            path,
            registry=registry,
            candidate_identity=identity,
            legacy_governed_root_aliases=aliases,
        )
    malformed = bytearray(persisted)
    malformed[-1] ^= 1
    path.write_bytes(malformed)
    with pytest.raises(Wave3FullBoundaryError, match="file_rejected|digest"):
        Wave3AuthoritativeStateV1(
            path,
            registry=registry,
            candidate_identity=identity,
            legacy_governed_root_aliases=aliases,
        )


def test_context_migration_rollback_recovery_and_upgrade_are_monotonic(tmp_path: Path) -> None:
    authority, _ports = _dual_authority("context-authority")
    from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import GovernedRootRegistryV1

    registry = GovernedRootRegistryV1(authority=authority)
    identity1 = _identity(1, "context-v1")
    state_path = tmp_path / "context-state.bin"
    state = Wave3AuthoritativeStateV1.create(
        state_path,
        registry=registry,
        candidate_identity=identity1,
        legacy_governed_root_aliases=_aliases("context-v1"),
        strong_payment_state_root_512=_wide("context-payment"),
    )
    initial_checkpoint = state.current_checkpoint
    identity2 = _identity(2, "context-v2")
    migrated = state.migrate(
        registry=registry,
        candidate_identity=identity2,
        legacy_governed_root_aliases=_aliases("context-v2"),
    )
    assert migrated.new_epoch == 2
    identity3 = _identity(3, "context-v3")
    rolled_back = state.rollback(
        target_checkpoint_512=initial_checkpoint.digest_512,
        registry=registry,
        candidate_identity=identity3,
        legacy_governed_root_aliases=_aliases("context-v3"),
    )
    assert rolled_back.new_epoch == 3
    anchor = state.issue_recovery_anchor(authority=authority)
    recovered_path = tmp_path / "recovered-state.bin"
    recovered = Wave3AuthoritativeStateV1.recover(
        recovered_path,
        checkpoint=state.current_checkpoint,
        anchor=anchor,
        registry=registry,
        authority=authority,
        candidate_identity=identity3,
        legacy_governed_root_aliases=_aliases("context-v3"),
    )
    assert recovered.snapshot() == state.snapshot()

    upgraded_authority, _upgraded_ports = _dual_authority("context-authority-v2")
    upgraded_registry = GovernedRootRegistryV1(authority=upgraded_authority)
    identity4 = _identity(4, "context-v4")
    upgraded = state.upgrade(
        registry=upgraded_registry,
        candidate_identity=identity4,
        legacy_governed_root_aliases=_aliases("context-v4"),
    )
    assert upgraded.new_epoch == 4
    assert state.snapshot().state.authority_id_512 == upgraded_authority.authority_id_512


def test_durable_registry_envelope_audit_and_counter_reject_mutation(tmp_path: Path) -> None:
    authority, _ports = _dual_authority("durable-boundary")
    from experiments.bl_pq512_crypto_foundation.wave3_verifier_state_custody import GovernedRootRegistryV1
    from experiments.bl_pq512_crypto_foundation.wave3_full_internal import Wave3DurableGovernedRootRegistryV1

    manifest = GovernedRootManifestV1(
        "CLAIM_SOURCE",
        _wide("durable-profile"),
        1,
        _wide("durable-schema"),
        (b"synthetic-record-a", b"synthetic-record-b"),
    )
    source_registry = GovernedRootRegistryV1(authority=authority)
    record = source_registry.register_manifest(manifest)
    registry_path = tmp_path / "governed-registry.bin"
    durable = Wave3DurableGovernedRootRegistryV1.create(registry_path, authority=authority)
    durable.register(source_registry.resolve(root_kind="CLAIM_SOURCE", epoch=1))
    reopened = Wave3DurableGovernedRootRegistryV1(registry_path, authority=authority)
    assert reopened.resolve(root_kind="CLAIM_SOURCE", epoch=1).root_id_512 == record

    state_path = tmp_path / "durable-registry-state.bin"
    identity = _identity(1, "durable-state")
    aliases = _aliases("durable-state")
    state = Wave3AuthoritativeStateV1.create(
        state_path,
        registry=reopened,
        candidate_identity=identity,
        legacy_governed_root_aliases=aliases,
        strong_payment_state_root_512=_wide("durable-payment"),
    )
    reopened_state = Wave3AuthoritativeStateV1(
        state_path,
        registry=Wave3DurableGovernedRootRegistryV1(registry_path, authority=authority),
        candidate_identity=identity,
        legacy_governed_root_aliases=aliases,
    )
    assert reopened_state.snapshot() == state.snapshot()
    record_v2 = source_registry.register_manifest(
        GovernedRootManifestV1(
            "CLAIM_SOURCE",
            _wide("durable-profile-v2"),
            2,
            _wide("durable-schema-v2"),
            (b"synthetic-record-c",),
        )
    )
    durable.register(source_registry.resolve(root_kind="CLAIM_SOURCE", epoch=2))
    assert record_v2
    with pytest.raises(Wave3FullBoundaryError, match="identity|registry"):
        reopened_state.snapshot()

    audit_path = tmp_path / "custody-audit.bin"
    audit = Wave3CustodyAuditLogV1.create(audit_path)
    first = audit.append("STATE_COMMITTED", b"synthetic-state-digest")
    second = audit.append("PROOF_BOUND", b"synthetic-proof-digest")
    assert second.previous_event_digest_512 == first.event_digest_512
    assert Wave3CustodyAuditLogV1(audit_path).head_digest_512 == second.event_digest_512
    audit_bytes = bytearray(audit_path.read_bytes())
    audit_bytes[-1] ^= 1
    audit_path.write_bytes(audit_bytes)
    with pytest.raises(Wave3FullBoundaryError, match="audit_file_digest"):
        Wave3CustodyAuditLogV1(audit_path)

    counter_path = tmp_path / "custody-counter.bin"
    counter = Wave3CustodyMonotonicCounterV1.create(counter_path)
    assert counter.advance(1) == 1
    with pytest.raises(Wave3FullBoundaryError, match="decrease"):
        counter.advance(1)
    counter_bytes = bytearray(counter_path.read_bytes())
    counter_bytes[-1] ^= 1
    counter_path.write_bytes(counter_bytes)
    with pytest.raises(Wave3FullBoundaryError, match="counter_digest"):
        Wave3CustodyMonotonicCounterV1(counter_path)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET = Path(r"C:\blpq-target")


@pytest.fixture(scope="module")
def native_state_verifier() -> Path:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--offline",
            "--locked",
            "--features",
            "std",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "k512_atomic_semantic_prototype",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / "k512_atomic_semantic_prototype.exe"
    assert executable.is_file()
    return executable


def test_rust_state_binding_port_accepts_and_rejects_the_real_local_verifier(
    native_state_verifier: Path,
    tmp_path: Path,
) -> None:
    from tests.test_bl_pq512_state_plane import _proof

    proof = _proof()
    sidecar = CandidateSidecarV1(
        _wide("rust-profile"),
        _wide("rust-suite"),
        _wide("rust-schema"),
        _wide("rust-verifier"),
        _wide("rust-domain"),
        1,
        0,
        1,
        _wide("rust-before"),
        _wide("rust-after"),
        _wide("rust-governance"),
        _wide("rust-payment-before"),
        _wide("rust-payment-after"),
        _wide("rust-batch"),
    )
    verifier = Wave3RustStateBindingVerifierV1(native_state_verifier)
    digest = verifier.verify(
        binding=proof.binding_bytes,
        public_fields=proof.projection_12,
        sidecar=sidecar,
    )
    assert digest == proof.binding_digest_512
    mutated = bytearray(proof.binding_bytes)
    mutated[-1] ^= 1
    with pytest.raises(Wave3FullBoundaryError, match="rust_verifier_rejected"):
        verifier.verify(binding=bytes(mutated), public_fields=proof.projection_12, sidecar=sidecar)
