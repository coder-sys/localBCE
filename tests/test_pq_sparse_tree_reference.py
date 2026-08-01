from __future__ import annotations

import os
from unittest import mock

import pytest

from app.batch.pq_sparse_tree_reference import (
    MAX_SPARSE_REFERENCE_DEPTH,
    derive_sparse_dual_tree_reference,
)
from app.batch.pq_tree_reference import (
    CanonicalField,
    SYNTHETIC_BYTES_MAGIC,
    encode_canonical_record,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _record(slot_index: int, marker: bytes = b"A") -> bytes:
    return encode_canonical_record(
        "synthetic_claim_truth_policy",
        (
            CanonicalField.raw_bytes(
                "payload", SYNTHETIC_BYTES_MAGIC + marker
            ),
            CanonicalField.u32("slot_index", slot_index),
        ),
    )


def test_sparse_dual_tree_is_order_independent_and_binds_key_and_record() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        first = derive_sparse_dual_tree_reference(
            ((7, _record(7)), (2, _record(2))),
            tree_kind="claim_truth_policy",
            tree_depth=16,
        )
        reordered = derive_sparse_dual_tree_reference(
            ((2, _record(2)), (7, _record(7))),
            tree_kind="claim_truth_policy",
            tree_depth=16,
        )
        changed_key = derive_sparse_dual_tree_reference(
            ((3, _record(2)), (7, _record(7))),
            tree_kind="claim_truth_policy",
            tree_depth=16,
        )
        changed_record = derive_sparse_dual_tree_reference(
            ((2, _record(2, b"B")), (7, _record(7))),
            tree_kind="claim_truth_policy",
            tree_depth=16,
        )

    assert first == reordered
    assert first.legacy_root_felt != changed_key.legacy_root_felt
    assert first.wide_root_sha3_512 != changed_key.wide_root_sha3_512
    assert first.legacy_root_felt != changed_record.legacy_root_felt
    assert first.wide_root_sha3_512 != changed_record.wide_root_sha3_512


def test_sparse_empty_root_is_deterministic_and_depth_bound_is_fail_closed() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        empty_a = derive_sparse_dual_tree_reference(
            (), tree_kind="claim_truth_policy", tree_depth=16
        )
        empty_b = derive_sparse_dual_tree_reference(
            (), tree_kind="claim_truth_policy", tree_depth=16
        )
        assert empty_a == empty_b
        assert len(empty_a.wide_root_sha3_512) == 64

        with pytest.raises(ValueError, match="tree_depth_invalid"):
            derive_sparse_dual_tree_reference(
                (),
                tree_kind="claim_truth_policy",
                tree_depth=MAX_SPARSE_REFERENCE_DEPTH + 1,
            )


def test_sparse_tree_rejects_duplicate_and_out_of_range_keys() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(ValueError, match="key_duplicate"):
            derive_sparse_dual_tree_reference(
                ((1, _record(1)), (1, _record(2))),
                tree_kind="claim_truth_policy",
                tree_depth=4,
            )
        with pytest.raises(ValueError, match="key_out_of_range"):
            derive_sparse_dual_tree_reference(
                ((16, _record(1)),),
                tree_kind="claim_truth_policy",
                tree_depth=4,
            )


def test_sparse_tree_remains_disabled_without_explicit_synthetic_flags() -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_DEV": "0"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            derive_sparse_dual_tree_reference(
                (), tree_kind="claim_truth_policy", tree_depth=16
            )
