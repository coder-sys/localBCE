"""Synthetic-only R25 fixed replay-operation schedule.

This module models only the typed order of one K256 replay transition:
256 ATTEMPT_NULLIFIER-or-COVER_NULLIFIER slot operations followed by one
SALT_USE operation. It computes no tree root, selects no final hash encoding,
proves no non-membership, and does not close P03.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import islice
import os
from typing import Final, Iterable


SLOT_OPERATION_COUNT: Final[int] = 256
SALT_USE_POSITION: Final[int] = SLOT_OPERATION_COUNT
TOTAL_OPERATION_COUNT: Final[int] = SLOT_OPERATION_COUNT + 1
REPLAY_KEY_BYTES: Final[int] = 64
ORIGINAL_ATTEMPT_VERSION: Final[int] = 1
ORIGINAL_PARENT_ATTEMPT_VERSION: Final[int] = 0
ORIGINAL_REVISION_KIND: Final[str] = "ORIGINAL"
REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_R25_FIXED_REPLAY_SCHEDULE_NO_ROOT_HASH_NOT_P03"
)
SYNTHETIC_REPLAY_SCHEDULE_ENABLE_ENV: Final[str] = (
    "BL_ALLOW_SYNTHETIC_PQ_REPLAY_SCHEDULE_R25"
)
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset(
    {"local", "test", "unit", "ci"}
)


class ReplayOperationKind(str, Enum):
    ATTEMPT_NULLIFIER = "ATTEMPT_NULLIFIER"
    COVER_NULLIFIER = "COVER_NULLIFIER"
    SALT_USE = "SALT_USE"


def require_synthetic_replay_schedule_enabled() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(
            SYNTHETIC_REPLAY_SCHEDULE_ENABLE_ENV
        )
        != "1"
    ):
        raise RuntimeError(
            "synthetic_r25_replay_schedule_forbidden:"
            "requires_local_test_env_and_explicit_dev_flags"
        )


def _position(value: object) -> int:
    if type(value) is not int:
        raise TypeError("r25_replay_position_must_be_integer")
    if value < 0 or value >= TOTAL_OPERATION_COUNT:
        raise ValueError("r25_replay_position_out_of_range")
    return value


def _replay_key(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("r25_replay_key_must_be_bytes")
    if len(value) != REPLAY_KEY_BYTES:
        raise ValueError("r25_replay_key_length_invalid")
    if not any(value):
        raise ValueError("r25_replay_key_must_be_nonzero")
    return value


@dataclass(frozen=True, slots=True)
class ReplayOperation:
    position: int
    kind: ReplayOperationKind
    replay_key_512: bytes
    attempt_version: int | None = None
    revision_kind: str | None = None
    parent_attempt_version: int | None = None

    def __post_init__(self) -> None:
        require_synthetic_replay_schedule_enabled()
        _position(self.position)
        if not isinstance(self.kind, ReplayOperationKind):
            raise TypeError("r25_replay_operation_kind_invalid")
        _replay_key(self.replay_key_512)
        if self.kind is ReplayOperationKind.ATTEMPT_NULLIFIER:
            if (
                type(self.attempt_version) is not int
                or self.attempt_version != ORIGINAL_ATTEMPT_VERSION
            ):
                raise ValueError(
                    "r25_attempt_version_must_be_original"
                )
            if self.revision_kind != ORIGINAL_REVISION_KIND:
                raise ValueError(
                    "r25_revision_kind_must_be_original"
                )
            if (
                type(self.parent_attempt_version) is not int
                or self.parent_attempt_version
                != ORIGINAL_PARENT_ATTEMPT_VERSION
            ):
                raise ValueError(
                    "r25_parent_attempt_version_must_be_zero"
                )
        elif (
            self.attempt_version is not None
            or self.revision_kind is not None
            or self.parent_attempt_version is not None
        ):
            raise ValueError(
                "r25_non_attempt_revision_metadata_forbidden"
            )


def _bounded_operations(
    operations: Iterable[ReplayOperation],
    *,
    maximum: int,
    label: str,
) -> tuple[ReplayOperation, ...]:
    try:
        iterator = iter(operations)
    except TypeError as exc:
        raise TypeError(f"{label}_must_be_iterable") from exc
    materialized = tuple(islice(iterator, maximum + 1))
    if len(materialized) > maximum:
        raise ValueError(f"{label}_count_invalid")
    return materialized


def validate_fixed_replay_operations(
    operations: Iterable[ReplayOperation],
) -> tuple[ReplayOperation, ...]:
    require_synthetic_replay_schedule_enabled()
    materialized = _bounded_operations(
        operations,
        maximum=TOTAL_OPERATION_COUNT,
        label="r25_replay_operations",
    )
    if len(materialized) != TOTAL_OPERATION_COUNT:
        raise ValueError("r25_replay_operations_count_invalid")
    for expected_position, operation in enumerate(materialized):
        if not isinstance(operation, ReplayOperation):
            raise TypeError(
                "r25_replay_operations_must_be_typed"
            )
        if operation.position != expected_position:
            raise ValueError("r25_replay_operation_order_invalid")
        if expected_position < SLOT_OPERATION_COUNT:
            if operation.kind not in {
                ReplayOperationKind.ATTEMPT_NULLIFIER,
                ReplayOperationKind.COVER_NULLIFIER,
            }:
                raise ValueError("r25_replay_slot_kind_invalid")
        elif operation.kind is not ReplayOperationKind.SALT_USE:
            raise ValueError(
                "r25_replay_final_operation_must_be_salt_use"
            )
    keys = tuple(
        operation.replay_key_512 for operation in materialized
    )
    if len(set(keys)) != TOTAL_OPERATION_COUNT:
        raise ValueError("r25_replay_key_duplicate")
    return materialized


@dataclass(frozen=True, slots=True)
class FixedReplaySchedule:
    operations: tuple[ReplayOperation, ...]
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_replay_schedule_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise ValueError("r25_replay_reference_status_invalid")
        object.__setattr__(
            self,
            "operations",
            validate_fixed_replay_operations(self.operations),
        )


def build_fixed_replay_schedule(
    slot_operations: Iterable[ReplayOperation],
    *,
    salt_use_tag_512: bytes,
) -> FixedReplaySchedule:
    require_synthetic_replay_schedule_enabled()
    slots = _bounded_operations(
        slot_operations,
        maximum=SLOT_OPERATION_COUNT,
        label="r25_replay_slot_operations",
    )
    if len(slots) != SLOT_OPERATION_COUNT:
        raise ValueError(
            "r25_replay_slot_operations_count_invalid"
        )
    for expected_position, operation in enumerate(slots):
        if not isinstance(operation, ReplayOperation):
            raise TypeError(
                "r25_replay_slot_operations_must_be_typed"
            )
        if operation.position != expected_position:
            raise ValueError("r25_replay_slot_order_invalid")
        if operation.kind not in {
            ReplayOperationKind.ATTEMPT_NULLIFIER,
            ReplayOperationKind.COVER_NULLIFIER,
        }:
            raise ValueError("r25_replay_slot_kind_invalid")
    salt_operation = ReplayOperation(
        position=SALT_USE_POSITION,
        kind=ReplayOperationKind.SALT_USE,
        replay_key_512=_replay_key(salt_use_tag_512),
    )
    return FixedReplaySchedule((*slots, salt_operation))
