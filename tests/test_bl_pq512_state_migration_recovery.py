from __future__ import annotations

import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    independently_verify_composition,
)
from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    ACTIVATION_ALLOWED,
    MIGRATION_EQUIVALENCE_STATUS,
    PROOF_SUITE_ID,
    STATUS,
    AtomicStateStore,
    MigrationRecoveryError,
    checkpoint_from_composition,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from tests.test_bl_pq512_atomic_state_composition import _build_case


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def authority_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    material = {}
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        material[adapter.suite_id] = (
            sha3_512(b"BL/S5/authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def _case(authority_material, profile_id: str = "K128_CALIBRATION"):
    batch, result, _, _, opening, adapters, composition = _build_case(
        authority_material, profile_id, "TRANSPARENT_HASH_CODE"
    )
    independently_verify_composition(composition, batch, result, opening, adapters)
    before = checkpoint_from_composition(composition, stage="before")
    after = checkpoint_from_composition(composition, stage="after")
    return batch, result, opening, adapters, composition, before, after


def test_s5_atomic_composition_publication_is_cas_and_complete(authority_material) -> None:
    batch, result, opening, adapters, composition, before, after = _case(authority_material)
    store = AtomicStateStore(before)
    prepared = store.prepare_composition_publication(
        composition, batch, result, opening, adapters
    )
    assert store.current == before
    assert prepared.status == "PREPARED"
    published = store.publish_prepared_composition(prepared)
    assert published.status == "PUBLISHED"
    assert store.current == after
    assert store.current.state_manifest_digest_512 == composition.transition.manifest_digest
    assert store.current.as_public_dict()["status"] == STATUS
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False

    with pytest.raises(MigrationRecoveryError, match="unknown_pending_record"):
        store.publish_prepared_composition(prepared)


def test_s5_crash_before_publication_leaves_old_checkpoint(authority_material) -> None:
    batch, result, opening, adapters, composition, before, after = _case(authority_material)
    store = AtomicStateStore(before)
    prepared = store.prepare_composition_publication(
        composition, batch, result, opening, adapters
    )
    assert prepared.new_checkpoint == after
    assert store.current == before
    # Dropping a prepared plan models a crash before the atomic commit.
    assert store.history == (before,)


def test_s5_migration_preserves_logical_state_and_rotates_plane(authority_material) -> None:
    batch, result, opening, adapters, composition, before, after = _case(authority_material)
    store = AtomicStateStore(before)
    store.publish_composition(composition, batch, result, opening, adapters)
    current = store.current
    new_layout = sha3_512(b"BL/S5/layout/v2").digest()
    new_verifier = sha3_512(b"BL/S5/verifier/v2").digest()
    prepared = store.prepare_migration(
        new_layout_id_512=new_layout,
        new_parameter_identity="BL-S5-STATE-V2",
        new_verifier_identity_512=new_verifier,
        migration_version="BL-S5-MIGRATION-V1",
    )
    assert store.current == current
    assert prepared.new_checkpoint.epoch == current.epoch + 1
    assert prepared.new_checkpoint.sequence == current.sequence
    assert prepared.new_checkpoint.state_root_512 == current.state_root_512
    assert prepared.new_checkpoint.state_manifest_digest_512 == current.state_manifest_digest_512
    published = store.publish_migration(prepared)
    assert published.status == "PUBLISHED"
    assert store.current == prepared.new_checkpoint
    assert published.as_public_dict()["equivalence_status"] == MIGRATION_EQUIVALENCE_STATUS


def test_s5_rollback_and_recovery_use_new_epochs_and_reject_replay(authority_material) -> None:
    batch, result, opening, adapters, composition, before, after = _case(authority_material)
    store = AtomicStateStore(before)
    store.publish_composition(composition, batch, result, opening, adapters)
    migrated = store.migrate(
        new_layout_id_512=sha3_512(b"BL/S5/layout/v2").digest(),
        new_parameter_identity="BL-S5-STATE-V2",
        new_verifier_identity_512=sha3_512(b"BL/S5/verifier/v2").digest(),
        migration_version="BL-S5-MIGRATION-V1",
    )
    assert store.current == migrated.new_checkpoint
    rollback = store.rollback(
        before,
        expected_current_digest_512=store.current.checkpoint_digest_512,
        recovery_epoch=store.current.epoch + 1,
    )
    assert rollback.status == "PUBLISHED"
    assert rollback.recovery_kind == "ROLLBACK"
    assert store.current.state_root_512 == before.state_root_512
    assert store.current.sequence == before.sequence
    assert store.current.epoch > migrated.new_checkpoint.epoch

    with pytest.raises(MigrationRecoveryError, match="stale_epoch_or_sequence"):
        store.publish_composition(composition, batch, result, opening, adapters)

    recovered = store.recover(
        after,
        expected_current_digest_512=store.current.checkpoint_digest_512,
        recovery_epoch=store.current.epoch + 1,
    )
    assert recovered.status == "PUBLISHED"
    assert recovered.recovery_kind == "RECOVERY"
    assert store.current.state_root_512 == after.state_root_512
    assert store.current.sequence == after.sequence
    assert store.current.epoch > rollback.new_checkpoint.epoch
