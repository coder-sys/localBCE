from __future__ import annotations

import os

from experiments.bl_pq512_crypto_foundation.h6_migration_theorem import (
    run_h6_migration_theorem,
    verify_h6_migration_mutation_rejection,
)


os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")


def test_h6_migration_theorem_covers_rollback_and_mixed_versions() -> None:
    result = run_h6_migration_theorem()
    assert result["migration_record_count"] == 4
    assert result["recovery_record_count"] == 4
    for key in (
        "logical_root_equivalence_proved",
        "manifest_equivalence_proved",
        "sequence_equivalence_proved",
        "epoch_monotonicity_proved",
        "rollback_recovery_epoch_advance_proved",
        "mixed_version_rejection_proved",
        "cas_publication_required",
    ):
        assert result[key] is True
    assert result["proofSuiteId"] is None
    assert result["activationAllowed"] is False


def test_h6_migration_mutations_reject() -> None:
    verify_h6_migration_mutation_rejection()
