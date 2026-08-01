from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from app.batch.pq_strong_nullifier_reference import (
    DuplicateStrongNullifierError,
    StrongIndexedNullifierTree,
    verify_strong_nonmembership_witness,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _wide(value: int) -> bytes:
    return value.to_bytes(64, "big")


def test_strong_indexed_nullifier_transitions_chain_and_verify() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = StrongIndexedNullifierTree()
        prior_root = tree.root
        for value in (_wide(50), _wide(10), _wide(90), _wide(70)):
            witness = tree.prove_nonmembership(value)
            assert witness.root_before == prior_root
            assert verify_strong_nonmembership_witness(witness)
            tree.insert(value)
            assert tree.root == witness.root_after
            prior_root = tree.root


def test_strong_indexed_nullifier_rejects_duplicate_and_reserved_values() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = StrongIndexedNullifierTree((_wide(10),))
        with pytest.raises(DuplicateStrongNullifierError):
            tree.prove_nonmembership(_wide(10))
        with pytest.raises(DuplicateStrongNullifierError):
            tree.insert(_wide(10))
        with pytest.raises(ValueError, match="reserved"):
            tree.insert(bytes(64))
        with pytest.raises(ValueError, match="reserved"):
            tree.insert(b"\xff" * 64)


def test_strong_indexed_nullifier_rejects_path_and_root_mutation() -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        tree = StrongIndexedNullifierTree((_wide(10), _wide(90)))
        witness = tree.prove_nonmembership(_wide(50))
        first = witness.predecessor_path[0]
        changed_path = replace(
            witness,
            predecessor_path=(
                bytes((first[0] ^ 1,)) + first[1:],
                *witness.predecessor_path[1:],
            ),
        )
        with pytest.raises(ValueError):
            verify_strong_nonmembership_witness(changed_path)
        with pytest.raises(ValueError, match="membership_mismatch"):
            verify_strong_nonmembership_witness(
                replace(
                    witness,
                    root_after=bytes((witness.root_after[0] ^ 1,))
                    + witness.root_after[1:],
                )
            )


def test_strong_indexed_nullifier_is_synthetic_only() -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            StrongIndexedNullifierTree()
