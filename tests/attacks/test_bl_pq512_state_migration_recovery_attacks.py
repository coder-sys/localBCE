from __future__ import annotations

from dataclasses import replace
import os
from hashlib import sha3_512
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    AtomicStateStore,
    MigrationRecoveryError,
    MigrationRecord,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from tests.test_bl_pq512_state_migration_recovery import _case


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
            sha3_512(b"BL/S5/attack-authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def test_s5_forged_transition_plan_cannot_publish(authority_material) -> None:
    batch, result, opening, adapters, composition, before, _ = _case(authority_material)
    store = AtomicStateStore(before)
    prepared = store.prepare_composition_publication(
        composition, batch, result, opening, adapters
    )
    forged_transition = replace(
        prepared.transition,
        new_root=sha3_512(b"BL/S5/forged-new-root").digest(),
    )
    forged_checkpoint = replace(
        prepared.new_checkpoint,
        state_root_512=forged_transition.new_root,
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    with pytest.raises(MigrationRecoveryError, match="transition_digest_mismatch"):
        replace(
            prepared,
            transition=forged_transition,
            new_checkpoint=forged_checkpoint,
            transition_digest_512=sha3_512(b"BL/S5/forged-transition-digest").digest(),
            publication_digest_512=b"",
        )
    assert store.current == before


def test_s5_forged_pending_record_is_rejected_even_if_self_consistent(authority_material) -> None:
    batch, result, opening, adapters, composition, before, _ = _case(authority_material)
    store = AtomicStateStore(before)
    prepared = store.prepare_composition_publication(
        composition, batch, result, opening, adapters
    )
    forged_transition = replace(
        prepared.transition,
        new_root=sha3_512(b"BL/S5/forged-root").digest(),
    )
    forged_checkpoint = replace(
        prepared.new_checkpoint,
        state_root_512=forged_transition.new_root,
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    forged = replace(
        prepared,
        transition=forged_transition,
        new_checkpoint=forged_checkpoint,
        transition_digest_512=sha3_512(
            b"BL/PQ512/S5/TRANSITION/v1\x00"
            + len(forged_transition.encoded).to_bytes(4, "big")
            + forged_transition.encoded
        ).digest(),
        publication_digest_512=b"",
    )
    with pytest.raises(MigrationRecoveryError, match="unknown_pending_record"):
        store.publish_prepared_composition(forged)
    assert store.current == before


def test_s5_migration_root_manifest_and_identity_mutations_fail(authority_material) -> None:
    batch, result, opening, adapters, composition, before, _ = _case(authority_material)
    store = AtomicStateStore(before)
    store.publish_composition(composition, batch, result, opening, adapters)
    prepared = store.prepare_migration(
        new_layout_id_512=sha3_512(b"BL/S5/layout/v2").digest(),
        new_parameter_identity="BL-S5-STATE-V2",
        new_verifier_identity_512=sha3_512(b"BL/S5/verifier/v2").digest(),
        migration_version="BL-S5-MIGRATION-V1",
    )
    forged_root = replace(
        prepared.new_checkpoint,
        state_root_512=sha3_512(b"BL/S5/forged-migration-root").digest(),
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    with pytest.raises(MigrationRecoveryError, match="root_equivalence_failed"):
        MigrationRecord(
            prepared.old_checkpoint,
            forged_root,
            prepared.migration_version,
        )
    forged_manifest = replace(
        prepared.new_checkpoint,
        state_manifest_digest_512=sha3_512(b"BL/S5/forged-manifest").digest(),
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    with pytest.raises(MigrationRecoveryError, match="manifest_equivalence_failed"):
        MigrationRecord(
            prepared.old_checkpoint,
            forged_manifest,
            prepared.migration_version,
        )
    assert store.current == prepared.old_checkpoint


def test_s5_stale_migration_cas_and_downgrade_fail_without_mutation(authority_material) -> None:
    batch, result, opening, adapters, composition, before, _ = _case(authority_material)
    store = AtomicStateStore(before)
    store.publish_composition(composition, batch, result, opening, adapters)
    first = store.prepare_migration(
        new_layout_id_512=sha3_512(b"BL/S5/layout/first").digest(),
        new_parameter_identity="BL-S5-STATE-FIRST",
        new_verifier_identity_512=sha3_512(b"BL/S5/verifier/first").digest(),
        migration_version="BL-S5-MIGRATION-FIRST",
    )
    second = store.prepare_migration(
        new_layout_id_512=sha3_512(b"BL/S5/layout/second").digest(),
        new_parameter_identity="BL-S5-STATE-SECOND",
        new_verifier_identity_512=sha3_512(b"BL/S5/verifier/second").digest(),
        migration_version="BL-S5-MIGRATION-SECOND",
    )
    store.publish_migration(first)
    current = store.current
    with pytest.raises(MigrationRecoveryError, match="compare_and_swap_failed"):
        store.publish_migration(second)
    assert store.current == current

    with pytest.raises(MigrationRecoveryError, match="downgrade_rejected"):
        store.prepare_migration(
            new_layout_id_512=before.layout_id_512,
            new_parameter_identity=before.parameter_identity,
            new_verifier_identity_512=before.verifier_identity_512,
            migration_version="BL-S5-MIGRATION-DOWNGRADE",
        )
    assert store.current == current


def test_s5_corrupted_unknown_or_replayed_recovery_cannot_change_state(authority_material) -> None:
    batch, result, opening, adapters, composition, before, after = _case(authority_material)
    store = AtomicStateStore(before)
    store.publish_composition(composition, batch, result, opening, adapters)
    current = store.current
    with pytest.raises(MigrationRecoveryError, match="checkpoint_digest_mismatch"):
        replace(
            after,
            checkpoint_digest_512=sha3_512(b"BL/S5/corrupted-checkpoint").digest(),
        )
    forged_unknown = replace(
        after,
        state_root_512=sha3_512(b"BL/S5/unknown-root").digest(),
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    with pytest.raises(MigrationRecoveryError, match="checkpoint_not_known"):
        store.recover(
            forged_unknown,
            expected_current_digest_512=current.checkpoint_digest_512,
            recovery_epoch=current.epoch + 1,
        )
    with pytest.raises(MigrationRecoveryError, match="epoch_not_newer"):
        store.rollback(
            before,
            expected_current_digest_512=current.checkpoint_digest_512,
            recovery_epoch=current.epoch,
        )
    assert store.current == current


def test_s5_mixed_profile_and_stale_composition_are_rejected(authority_material) -> None:
    batch, result, opening, adapters, composition, before, _ = _case(authority_material)
    store = AtomicStateStore(before)
    mixed_batch, mixed_result, mixed_opening, mixed_adapters, mixed_composition, _, _ = _case(
        authority_material, "K512_CALIBRATION"
    )
    with pytest.raises(MigrationRecoveryError, match="profile_mismatch"):
        store.prepare_composition_publication(
            mixed_composition,
            mixed_batch,
            mixed_result,
            mixed_opening,
            mixed_adapters,
        )
    assert store.current == before
    store.publish_composition(composition, batch, result, opening, adapters)
    with pytest.raises(MigrationRecoveryError, match="stale_epoch_or_sequence"):
        store.prepare_composition_publication(
            composition, batch, result, opening, adapters
        )
    assert store.current.sequence == composition.transition.sequence_after
