"""Synthetic K256 replay-state integration reference.

The exact 256 slot operations and final context-free ``SALT_USE`` operation
are applied to one provisional full-width set transition.  The set-root helper
is intentionally not the unresolved depth-64 indexed production tree and
proves no path or nonmembership statement.  This module therefore cannot close
P03 or authorize state activation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Final, Iterable

from app.batch.pq_replay_schedule_r25 import (
    FixedReplaySchedule,
    ReplayOperation,
    ReplayOperationKind,
    SLOT_OPERATION_COUNT,
    TOTAL_OPERATION_COUNT,
    validate_fixed_replay_operations,
)
from app.batch.pq_state_reference import WideDigest, strong_nullifier_set_root
from app.batch.pq_suite_candidate import candidate_salt_use_tag


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_PROVISIONAL_SORTED_SET_ROOT_NOT_DEPTH64_NOT_P03"
)
SYNTHETIC_REPLAY_STATE_ENABLE_ENV: Final[str] = (
    "BL_ALLOW_SYNTHETIC_PQ_REPLAY_STATE_REFERENCE"
)
REPLAY_KEY_BYTES: Final[int] = 64
MAX_SYNTHETIC_REPLAY_KEYS: Final[int] = 1_048_576
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})


def require_synthetic_replay_state_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_REPLAY_STATE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_pq_replay_state_reference_forbidden:"
            "requires_local_test_env_and_explicit_dev_flags"
        )


def _key(label: str, value: object) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label}_must_be_exact_bytes")
    if len(value) != REPLAY_KEY_BYTES:
        raise ValueError(f"{label}_length_invalid")
    if not any(value):
        raise ValueError(f"{label}_must_be_nonzero")
    return value


def _canonical_existing(values: Iterable[bytes]) -> tuple[bytes, ...]:
    if type(values) is not tuple:
        raise TypeError("provisional_existing_replay_keys_must_be_exact_tuple")
    if len(values) > MAX_SYNTHETIC_REPLAY_KEYS:
        raise ValueError("provisional_existing_replay_key_capacity_exceeded")
    materialized = tuple(_key("provisional_existing_replay_key", value) for value in values)
    ordered = tuple(sorted(materialized))
    if len(set(ordered)) != len(ordered):
        raise ValueError("provisional_existing_replay_key_duplicate")
    return ordered


def _root(values: tuple[bytes, ...]) -> bytes:
    return strong_nullifier_set_root(
        tuple(WideDigest.from_bytes(value) for value in values)
    ).to_bytes()


@dataclass(frozen=True, slots=True)
class ProvisionalStrongReplayTransitionV1:
    existing_keys_512: tuple[bytes, ...] = field(repr=False)
    operations: tuple[ReplayOperation, ...] = field(repr=False)
    merged_keys_512: tuple[bytes, ...] = field(repr=False)
    root_before_512: bytes = field(repr=False)
    root_after_512: bytes = field(repr=False)
    salt_use_tag_512: bytes = field(repr=False)
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_replay_state_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("provisional_replay_reference_status_invalid")
        if type(self.existing_keys_512) is not tuple:
            raise TypeError("provisional_existing_replay_keys_must_be_tuple")
        if _canonical_existing(self.existing_keys_512) != self.existing_keys_512:
            raise ValueError("provisional_existing_replay_keys_not_canonical")
        if type(self.operations) is not tuple:
            raise TypeError("provisional_replay_operations_must_be_tuple")
        if validate_fixed_replay_operations(self.operations) != self.operations:
            raise ValueError("provisional_replay_operations_noncanonical")
        salt_use_tag = _key(
            "provisional_salt_use_tag", self.salt_use_tag_512
        )
        salt_operation = self.operations[SLOT_OPERATION_COUNT]
        if (
            salt_operation.position != SLOT_OPERATION_COUNT
            or salt_operation.kind is not ReplayOperationKind.SALT_USE
        ):
            raise ValueError("provisional_replay_salt_operation_invalid")
        if salt_operation.replay_key_512 != salt_use_tag:
            raise ValueError("provisional_replay_salt_use_tag_mismatch")
        if type(self.merged_keys_512) is not tuple:
            raise TypeError("provisional_merged_replay_keys_must_be_tuple")
        if _canonical_existing(self.merged_keys_512) != self.merged_keys_512:
            raise ValueError("provisional_merged_replay_keys_not_canonical")
        before = _key("provisional_replay_root_before", self.root_before_512)
        after = _key("provisional_replay_root_after", self.root_after_512)
        if before == after:
            raise ValueError("provisional_replay_root_unchanged")
        if _root(self.existing_keys_512) != before:
            raise ValueError("provisional_replay_root_before_mismatch")
        additions = tuple(operation.replay_key_512 for operation in self.operations)
        if tuple(sorted((*self.existing_keys_512, *additions))) != self.merged_keys_512:
            raise ValueError("provisional_replay_merged_keys_mismatch")
        if _root(self.merged_keys_512) != after:
            raise ValueError("provisional_replay_root_after_mismatch")


def build_provisional_strong_replay_transition(
    existing_keys_512: Iterable[bytes],
    schedule: FixedReplaySchedule,
    *,
    raw_master_salt: bytes,
) -> ProvisionalStrongReplayTransitionV1:
    """Apply all 257 typed keys, including the exact context-free salt-use tag."""

    require_synthetic_replay_state_enabled()
    existing = _canonical_existing(existing_keys_512)
    if type(schedule) is not FixedReplaySchedule:
        raise TypeError("provisional_fixed_replay_schedule_required")
    operations = validate_fixed_replay_operations(schedule.operations)
    if len(operations) != TOTAL_OPERATION_COUNT:
        raise ValueError("provisional_replay_operation_count_invalid")
    if any(
        operation.position != position
        for position, operation in enumerate(operations[:SLOT_OPERATION_COUNT])
    ):
        raise ValueError("provisional_replay_slot_alignment_invalid")
    salt_operation = operations[SLOT_OPERATION_COUNT]
    if (
        salt_operation.position != SLOT_OPERATION_COUNT
        or salt_operation.kind is not ReplayOperationKind.SALT_USE
    ):
        raise ValueError("provisional_replay_salt_operation_invalid")
    canonical_master_salt = _key("provisional_raw_master_salt", raw_master_salt)
    expected_salt_tag = candidate_salt_use_tag(canonical_master_salt)
    if salt_operation.replay_key_512 != expected_salt_tag:
        raise ValueError("provisional_replay_salt_use_tag_mismatch")
    additions = tuple(operation.replay_key_512 for operation in operations)
    existing_set = set(existing)
    if any(value in existing_set for value in additions):
        raise ValueError("provisional_replay_key_already_present")
    merged = tuple(sorted((*existing, *additions)))
    if len(merged) > MAX_SYNTHETIC_REPLAY_KEYS:
        raise ValueError("provisional_merged_replay_key_capacity_exceeded")
    return ProvisionalStrongReplayTransitionV1(
        existing_keys_512=existing,
        operations=operations,
        merged_keys_512=merged,
        root_before_512=_root(existing),
        root_after_512=_root(merged),
        salt_use_tag_512=expected_salt_tag,
    )
