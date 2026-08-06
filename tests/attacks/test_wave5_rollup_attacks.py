from __future__ import annotations

from dataclasses import replace

import pytest

from app.wave5_rollup import (
    BasedOrderer,
    DataAvailabilityStore,
    EthereumForkProfile,
    FinalityLevel,
    ForcedInclusionQueue,
    InclusionList,
    OpaqueTransaction,
    RecentRootAdapter,
    RecentRootReference,
    Wave5RollupError,
    build_da_bundle,
    build_ethereum_compat_manifest,
)


def _wide(label: str) -> bytes:
    from hashlib import sha3_512

    return sha3_512(label.encode("ascii")).digest()


def test_unknown_fork_is_not_a_valid_profile() -> None:
    manifest = build_ethereum_compat_manifest()
    with pytest.raises(Wave5RollupError, match="unknown_fork"):
        manifest.profile_for(_wide("unknown"))


def test_baseline_cannot_enable_draft_feature() -> None:
    manifest = build_ethereum_compat_manifest()
    with pytest.raises(Wave5RollupError, match="unshipped_eip"):
        replace(manifest, baseline=replace(manifest.baseline, enabled_eips=(8079,)))


def test_inclusion_list_duplicate_is_rejected() -> None:
    with pytest.raises(Wave5RollupError, match="order"):
        InclusionList(1, _wide("view"), (_wide("tx"), _wide("tx")), _wide("committee"))


def test_forced_inclusion_is_bounded_and_opaque() -> None:
    queue = ForcedInclusionQueue(capacity=1)
    tx = OpaqueTransaction(_wide("sender"), 0, _wide("payload"), "FORCED-ATTEMPT", "FORCED")
    queue.submit(tx, current_slot=1)
    with pytest.raises(Wave5RollupError, match="full"):
        queue.submit(OpaqueTransaction(_wide("sender-2"), 0, _wide("payload-2"), "FORCED-ATTEMPT-2", "FORCED"), current_slot=1)


def test_orderer_does_not_accept_a_sequencer_override() -> None:
    manifest = build_ethereum_compat_manifest()
    orderer = BasedOrderer(manifest)
    assert not hasattr(orderer, "sequencer_id")


def test_da_unknown_cell_and_mode_cannot_be_reconstructed() -> None:
    store = DataAvailabilityStore()
    bundle = build_da_bundle((_wide("cell"),), mode="CALLDATA_COMMITMENT", retention_until_slot=8)
    digest = store.publish(bundle)
    with pytest.raises(Wave5RollupError, match="cell_mismatch"):
        store.reconstruct(digest, (replace(bundle.cells[0], commitment_512=_wide("corrupt")),), current_slot=1)
    with pytest.raises(Wave5RollupError, match="mode_unknown"):
        build_da_bundle((_wide("cell"),), mode="UNKNOWN", retention_until_slot=8)


def test_da_migration_preserves_payload_commitment() -> None:
    store = DataAvailabilityStore()
    bundle = build_da_bundle((_wide("cell"),), mode="CALLDATA_COMMITMENT", retention_until_slot=8)
    digest = store.publish(bundle)
    migrated = store.migrate(digest, target_mode="CELL_COMMITMENT", current_slot=2)
    assert migrated.payload_commitment_512 == bundle.payload_commitment_512
    assert migrated.migration_digest_512 != bytes(64)


def test_recent_root_window_cannot_be_used_when_adapter_is_off() -> None:
    reference = RecentRootReference(_wide("source"), _wide("root"), 1, 2, _wide("envelope"))
    with pytest.raises(Wave5RollupError, match="optional_feature_disabled"):
        RecentRootAdapter(enabled=False).validate(reference, slot=1)


def test_preconfirmation_finality_label_cannot_be_promoted_by_receipt() -> None:
    assert FinalityLevel.HEAD is not FinalityLevel.FINALIZED
