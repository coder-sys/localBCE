"""Bounded state migration/rollback theorem checks for the H6 candidate."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
from typing import Final

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    AtomicStateStore,
    MigrationRecord,
    MigrationRecoveryError,
    RecoveryRecord,
    StateCheckpoint,
)


STATUS: Final[str] = "H6_MIGRATION_THEOREM_V1_NONACTIVATING"
PROFILES: Final[tuple[str, ...]] = ("K128_CALIBRATION", "K512_CALIBRATION")


def _digest(label: str, profile: str, ordinal: int) -> bytes:
    return sha3_512(
        b"BL/PQ512/H6/MIGRATION-THEOREM/v1\x00"
        + label.encode("ascii")
        + profile.encode("ascii")
        + ordinal.to_bytes(4, "big")
    ).digest()


def _checkpoint(profile: str, ordinal: int, *, epoch: int, variant: str) -> StateCheckpoint:
    return StateCheckpoint(
        profile_id=profile,
        layout_id_512=_digest("layout-" + variant, profile, ordinal),
        parameter_identity="BL-PQ512-PARAM-" + variant,
        verifier_identity_512=_digest("verifier-" + variant, profile, ordinal),
        epoch=epoch,
        sequence=41,
        state_root_512=_digest("root", profile, ordinal),
        state_manifest_digest_512=_digest("manifest", profile, ordinal),
    )


def run_h6_migration_theorem() -> dict[str, object]:
    require_synthetic_reference_enabled()
    migration_records: list[MigrationRecord] = []
    recovery_records: list[RecoveryRecord] = []
    cas_rejection_count = 0
    mixed_version_rejection = False
    for profile in PROFILES:
        for ordinal in range(2):
            old = _checkpoint(profile, ordinal, epoch=7, variant="v1")
            store = AtomicStateStore(old)
            first = store.prepare_migration(
                new_layout_id_512=_digest("layout-v2", profile, ordinal),
                new_parameter_identity="BL-PQ512-PARAM-v2",
                new_verifier_identity_512=_digest("verifier-v2", profile, ordinal),
                migration_version=f"migration-{profile}-{ordinal}",
            )
            stale = store.prepare_migration(
                new_layout_id_512=_digest("layout-v3", profile, ordinal),
                new_parameter_identity="BL-PQ512-PARAM-v3",
                new_verifier_identity_512=_digest("verifier-v3", profile, ordinal),
                migration_version=f"stale-{profile}-{ordinal}",
            )
            published = store.publish_migration(first)
            migration_records.append(first)
            if published.status != "PUBLISHED" or store.current != first.new_checkpoint:
                raise MigrationRecoveryError("h6_migration_theorem_publish_failed")
            try:
                store.publish_migration(stale)
            except MigrationRecoveryError as exc:
                if "compare_and_swap_failed" not in str(exc):
                    raise
                cas_rejection_count += 1
            else:
                raise MigrationRecoveryError("h6_migration_theorem_stale_cas_accepted")

            if ordinal == 0:
                recovery = store.rollback(
                    old,
                    expected_current_digest_512=store.current.checkpoint_digest_512,
                    recovery_epoch=store.current.epoch + 1,
                )
                expected_kind = "ROLLBACK"
            else:
                recovery = store.recover(
                    old,
                    expected_current_digest_512=store.current.checkpoint_digest_512,
                    recovery_epoch=store.current.epoch + 1,
                )
                expected_kind = "RECOVERY"
            recovery_records.append(recovery)
            if (
                recovery.status != "PUBLISHED"
                or recovery.recovery_kind != expected_kind
                or store.current.state_root_512 != old.state_root_512
                or store.current.state_manifest_digest_512 != old.state_manifest_digest_512
                or store.current.sequence != old.sequence
                or store.current.epoch <= first.new_checkpoint.epoch
            ):
                raise MigrationRecoveryError("h6_migration_theorem_recovery_failed")

            mixed_profile = (
                "K512_CALIBRATION"
                if profile == "K128_CALIBRATION"
                else "K128_CALIBRATION"
            )
            mixed = _checkpoint(mixed_profile, ordinal, epoch=8, variant="mixed")
            try:
                MigrationRecord(old, mixed, "mixed-version")
            except MigrationRecoveryError:
                mixed_version_rejection = True
            else:
                raise MigrationRecoveryError("h6_migration_theorem_mixed_version_accepted")

    if cas_rejection_count != len(migration_records) or not mixed_version_rejection:
        raise MigrationRecoveryError("h6_migration_theorem_cas_or_version_gap")
    return {
        "status": STATUS,
        "migration_record_count": len(migration_records),
        "recovery_record_count": len(recovery_records),
        "logical_root_equivalence_proved": all(
            record.old_checkpoint.state_root_512 == record.new_checkpoint.state_root_512
            for record in migration_records
        ),
        "manifest_equivalence_proved": all(
            record.old_checkpoint.state_manifest_digest_512
            == record.new_checkpoint.state_manifest_digest_512
            for record in migration_records
        ),
        "sequence_equivalence_proved": all(
            record.old_checkpoint.sequence == record.new_checkpoint.sequence
            for record in migration_records
        ),
        "epoch_monotonicity_proved": all(
            record.new_checkpoint.epoch == record.old_checkpoint.epoch + 1
            for record in migration_records
        ),
        "rollback_recovery_epoch_advance_proved": all(
            record.new_checkpoint.epoch > record.old_checkpoint.epoch
            for record in recovery_records
        ),
        "mixed_version_rejection_proved": mixed_version_rejection,
        "cas_publication_required": cas_rejection_count == len(migration_records),
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def verify_h6_migration_mutation_rejection() -> None:
    require_synthetic_reference_enabled()
    old = _checkpoint(PROFILES[0], 0, epoch=7, variant="v1")
    new = _checkpoint(PROFILES[0], 0, epoch=8, variant="v2")
    with_root_mutation = replace(
        new,
        state_root_512=_digest("mutated-root", PROFILES[0], 0),
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    try:
        MigrationRecord(old, with_root_mutation, "mutation")
    except MigrationRecoveryError:
        pass
    else:
        raise AssertionError("h6_migration_root_mutation_accepted")


__all__: tuple[str, ...] = (
    "STATUS",
    "run_h6_migration_theorem",
    "verify_h6_migration_mutation_rejection",
)
