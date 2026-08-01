from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from app.batch.pq_sparse_tree_reference import (
    derive_sparse_dual_membership_proof,
    derive_sparse_dual_nonmembership_proof,
    derive_sparse_dual_tree_reference,
    verify_sparse_dual_membership_proof,
    verify_sparse_dual_nonmembership_proof,
)
from app.batch.pq_tree_reference import (
    CanonicalField,
    SYNTHETIC_BYTES_MAGIC,
    derive_dual_tree_membership_proof,
    derive_dual_tree_reference,
    encode_canonical_record,
    verify_dual_tree_membership_proof,
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


def test_dense_dual_membership_recomputes_both_paths_and_height_zero() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        records = tuple(_record(index, bytes((65 + index,))) for index in range(3))
        tree = derive_dual_tree_reference(
            records,
            tree_kind="claim_truth_policy",
            tree_height=2,
        )
        for record in records:
            proof = derive_dual_tree_membership_proof(tree, record)
            assert verify_dual_tree_membership_proof(
                proof,
                expected_legacy_root_felt=tree.legacy_root_felt,
                expected_wide_root_sha3_512=tree.wide_root_sha3_512,
            )

        singleton = derive_dual_tree_reference(
            (_record(9),),
            tree_kind="claim_truth_policy",
            tree_height=0,
        )
        singleton_proof = derive_dual_tree_membership_proof(
            singleton, singleton.canonical_records[0]
        )
        assert singleton_proof.legacy_siblings == ()
        assert verify_dual_tree_membership_proof(
            singleton_proof,
            expected_legacy_root_felt=singleton.legacy_root_felt,
            expected_wide_root_sha3_512=singleton.wide_root_sha3_512,
        )


def test_dense_dual_membership_rejects_record_path_position_and_governed_root_mutation() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = derive_dual_tree_reference(
            (_record(1), _record(2), _record(3)),
            tree_kind="claim_truth_policy",
            tree_height=2,
        )
        proof = derive_dual_tree_membership_proof(
            tree, tree.canonical_records[0]
        )
        cases = (
            replace(
                proof,
                legacy_siblings=(proof.legacy_siblings[0] ^ 1, *proof.legacy_siblings[1:]),
            ),
            replace(
                proof,
                wide_siblings_sha3_512=(
                    bytes((proof.wide_siblings_sha3_512[0][0] ^ 1,))
                    + proof.wide_siblings_sha3_512[0][1:],
                    *proof.wide_siblings_sha3_512[1:],
                ),
            ),
            replace(proof, position=1),
            replace(proof, canonical_record=_record(99)),
        )
        for changed in cases:
            with pytest.raises(ValueError):
                verify_dual_tree_membership_proof(
                    changed,
                    expected_legacy_root_felt=tree.legacy_root_felt,
                    expected_wide_root_sha3_512=tree.wide_root_sha3_512,
                )
        with pytest.raises(ValueError, match="governed_legacy_root"):
            verify_dual_tree_membership_proof(
                proof,
                expected_legacy_root_felt=tree.legacy_root_felt ^ 1,
                expected_wide_root_sha3_512=tree.wide_root_sha3_512,
            )


def test_sparse_membership_and_nonmembership_recompute_both_paths() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = derive_sparse_dual_tree_reference(
            ((2, _record(2)), (7, _record(7))),
            tree_kind="claim_truth_policy",
            tree_depth=4,
        )
        member = derive_sparse_dual_membership_proof(tree, 7)
        assert verify_sparse_dual_membership_proof(
            member,
            expected_legacy_root_felt=tree.legacy_root_felt,
            expected_wide_root_sha3_512=tree.wide_root_sha3_512,
        )
        absent = derive_sparse_dual_nonmembership_proof(tree, 6)
        assert verify_sparse_dual_nonmembership_proof(
            absent,
            expected_legacy_root_felt=tree.legacy_root_felt,
            expected_wide_root_sha3_512=tree.wide_root_sha3_512,
        )


def test_sparse_proofs_reject_path_key_record_and_occupancy_mutation() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = derive_sparse_dual_tree_reference(
            ((2, _record(2)), (7, _record(7))),
            tree_kind="claim_truth_policy",
            tree_depth=4,
        )
        member = derive_sparse_dual_membership_proof(tree, 7)
        changed_member = replace(
            member,
            wide_siblings_sha3_512=(
                bytes((member.wide_siblings_sha3_512[0][0] ^ 1,))
                + member.wide_siblings_sha3_512[0][1:],
                *member.wide_siblings_sha3_512[1:],
            ),
        )
        with pytest.raises(ValueError):
            verify_sparse_dual_membership_proof(
                changed_member,
                expected_legacy_root_felt=tree.legacy_root_felt,
                expected_wide_root_sha3_512=tree.wide_root_sha3_512,
            )
        with pytest.raises(ValueError):
            verify_sparse_dual_membership_proof(
                replace(member, canonical_record=_record(99)),
                expected_legacy_root_felt=tree.legacy_root_felt,
                expected_wide_root_sha3_512=tree.wide_root_sha3_512,
            )
        with pytest.raises(ValueError, match="key_occupied"):
            derive_sparse_dual_nonmembership_proof(tree, 2)
        with pytest.raises(ValueError, match="key_absent"):
            derive_sparse_dual_membership_proof(tree, 6)
