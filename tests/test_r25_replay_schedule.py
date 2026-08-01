from __future__ import annotations

from dataclasses import replace
import os
import unittest
from unittest import mock

from app.batch.pq_replay_schedule_r25 import (
    ORIGINAL_REVISION_KIND,
    REFERENCE_STATUS,
    SALT_USE_POSITION,
    SLOT_OPERATION_COUNT,
    TOTAL_OPERATION_COUNT,
    FixedReplaySchedule,
    ReplayOperation,
    ReplayOperationKind,
    build_fixed_replay_schedule,
    validate_fixed_replay_operations,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.replay_alignment import (
    validate_k256_replay_alignment,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_r25_fixed_shape_trace import _cover, _real


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_REPLAY_SCHEDULE_R25": "1",
}


def _key(value: int) -> bytes:
    return value.to_bytes(64, "big")


def _slot(position: int) -> ReplayOperation:
    if position % 2 == 0:
        return ReplayOperation(
            position=position,
            kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
            replay_key_512=_key(position + 1),
            attempt_version=1,
            revision_kind=ORIGINAL_REVISION_KIND,
            parent_attempt_version=0,
        )
    return ReplayOperation(
        position=position,
        kind=ReplayOperationKind.COVER_NULLIFIER,
        replay_key_512=_key(position + 1),
    )


def _slots() -> tuple[ReplayOperation, ...]:
    return tuple(
        _slot(position) for position in range(SLOT_OPERATION_COUNT)
    )


class R25ReplayScheduleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(
            os.environ, FLAGS, clear=False
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def test_exact_256_slots_then_one_salt_use_without_root_claim(
        self,
    ) -> None:
        schedule = build_fixed_replay_schedule(
            _slots(), salt_use_tag_512=_key(257)
        )
        self.assertIsInstance(schedule, FixedReplaySchedule)
        self.assertEqual(schedule.reference_status, REFERENCE_STATUS)
        self.assertEqual(
            len(schedule.operations), TOTAL_OPERATION_COUNT
        )
        self.assertEqual(
            tuple(
                operation.position
                for operation in schedule.operations
            ),
            tuple(range(TOTAL_OPERATION_COUNT)),
        )
        self.assertTrue(
            all(
                operation.kind
                in {
                    ReplayOperationKind.ATTEMPT_NULLIFIER,
                    ReplayOperationKind.COVER_NULLIFIER,
                }
                for operation in schedule.operations[
                    :SLOT_OPERATION_COUNT
                ]
            )
        )
        self.assertEqual(
            schedule.operations[SALT_USE_POSITION].kind,
            ReplayOperationKind.SALT_USE,
        )
        self.assertFalse(hasattr(schedule, "root_before"))
        self.assertFalse(hasattr(schedule, "root_after"))

    def test_three_factor_synthetic_guard_fails_closed(self) -> None:
        for missing in FLAGS:
            incomplete = {
                key: value
                for key, value in FLAGS.items()
                if key != missing
            }
            with self.subTest(missing=missing), mock.patch.dict(
                os.environ, incomplete, clear=True
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "synthetic_r25_replay_schedule_forbidden",
                ):
                    ReplayOperation(
                        position=0,
                        kind=(
                            ReplayOperationKind.COVER_NULLIFIER
                        ),
                        replay_key_512=_key(1),
                    )

    def test_attempts_are_original_only_and_cover_has_no_revision_metadata(
        self,
    ) -> None:
        for version in (0, 2, True, None):
            with self.subTest(
                version=version
            ), self.assertRaisesRegex(
                ValueError, "attempt_version_must_be_original"
            ):
                ReplayOperation(
                    position=0,
                    kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
                    replay_key_512=_key(1),
                    attempt_version=version,
                    revision_kind="ORIGINAL",
                    parent_attempt_version=0,
                )
        for revision in (
            None,
            "RETRY",
            "CORRECTION",
            "REVERSAL",
        ):
            with self.subTest(
                revision=revision
            ), self.assertRaisesRegex(
                ValueError, "revision_kind_must_be_original"
            ):
                ReplayOperation(
                    position=0,
                    kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
                    replay_key_512=_key(1),
                    attempt_version=1,
                    revision_kind=revision,
                    parent_attempt_version=0,
                )
        for parent in (1, 2, True, None):
            with self.subTest(
                parent=parent
            ), self.assertRaisesRegex(
                ValueError,
                "parent_attempt_version_must_be_zero",
            ):
                ReplayOperation(
                    position=0,
                    kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
                    replay_key_512=_key(1),
                    attempt_version=1,
                    revision_kind="ORIGINAL",
                    parent_attempt_version=parent,
                )
        with self.assertRaisesRegex(
            ValueError, "non_attempt_revision_metadata_forbidden"
        ):
            ReplayOperation(
                position=0,
                kind=ReplayOperationKind.COVER_NULLIFIER,
                replay_key_512=_key(1),
                attempt_version=1,
                revision_kind="ORIGINAL",
                parent_attempt_version=0,
            )

    def test_count_order_and_final_salt_position_fail_closed(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValueError, "slot_operations_count_invalid"
        ):
            build_fixed_replay_schedule(
                _slots()[:-1], salt_use_tag_512=_key(257)
            )
        reordered = list(_slots())
        reordered[0], reordered[1] = (
            reordered[1],
            reordered[0],
        )
        with self.assertRaisesRegex(
            ValueError, "slot_order_invalid"
        ):
            build_fixed_replay_schedule(
                reordered, salt_use_tag_512=_key(257)
            )
        wrong_slot_kind = list(_slots())
        wrong_slot_kind[0] = ReplayOperation(
            position=0,
            kind=ReplayOperationKind.SALT_USE,
            replay_key_512=_key(1),
        )
        with self.assertRaisesRegex(
            ValueError, "slot_kind_invalid"
        ):
            build_fixed_replay_schedule(
                wrong_slot_kind, salt_use_tag_512=_key(257)
            )
        valid = build_fixed_replay_schedule(
            _slots(), salt_use_tag_512=_key(257)
        )
        wrong_final_kind = list(valid.operations)
        wrong_final_kind[-1] = ReplayOperation(
            position=SALT_USE_POSITION,
            kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
            replay_key_512=_key(257),
            attempt_version=1,
            revision_kind="ORIGINAL",
            parent_attempt_version=0,
        )
        with self.assertRaisesRegex(
            ValueError, "final_operation_must_be_salt_use"
        ):
            validate_fixed_replay_operations(wrong_final_kind)

    def test_keys_are_full_nonzero_unique_bytes(self) -> None:
        for value, error in (
            (bytes(64), "must_be_nonzero"),
            (bytes(63), "length_invalid"),
            (bytearray(64), "must_be_bytes"),
        ):
            with self.subTest(
                error=error
            ), self.assertRaisesRegex(
                (TypeError, ValueError), error
            ):
                ReplayOperation(
                    position=0,
                    kind=ReplayOperationKind.COVER_NULLIFIER,
                    replay_key_512=value,  # type: ignore[arg-type]
                )
        duplicate_slots = list(_slots())
        duplicate_slots[-1] = ReplayOperation(
            position=SLOT_OPERATION_COUNT - 1,
            kind=ReplayOperationKind.COVER_NULLIFIER,
            replay_key_512=_key(1),
        )
        with self.assertRaisesRegex(
            ValueError, "replay_key_duplicate"
        ):
            build_fixed_replay_schedule(
                duplicate_slots, salt_use_tag_512=_key(257)
            )
        with self.assertRaisesRegex(
            ValueError, "replay_key_duplicate"
        ):
            build_fixed_replay_schedule(
                _slots(), salt_use_tag_512=_key(1)
            )

    def test_typed_operation_mutations_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            TypeError, "position_must_be_integer"
        ):
            ReplayOperation(
                position=False,  # type: ignore[arg-type]
                kind=ReplayOperationKind.COVER_NULLIFIER,
                replay_key_512=_key(1),
            )
        with self.assertRaisesRegex(
            TypeError, "operation_kind_invalid"
        ):
            ReplayOperation(
                position=0,
                kind="ATTEMPT_NULLIFIER",  # type: ignore[arg-type]
                replay_key_512=_key(1),
                attempt_version=1,
                revision_kind="ORIGINAL",
                parent_attempt_version=0,
            )
        schedule = build_fixed_replay_schedule(
            _slots(), salt_use_tag_512=_key(257)
        )
        mutated = list(schedule.operations)
        mutated[10] = replace(mutated[10], position=11)
        with self.assertRaisesRegex(
            ValueError, "operation_order_invalid"
        ):
            validate_fixed_replay_operations(mutated)

    def test_claim_slot_kind_is_bound_to_position_matched_replay_kind(self) -> None:
        profile = get_profile("K256_DESIGN_POINT")
        slots = [_real(0)]
        slots.extend(_cover(index) for index in range(1, profile.claim_slots))
        operations = [
            ReplayOperation(
                position=position,
                kind=ReplayOperationKind.COVER_NULLIFIER,
                replay_key_512=_key(position + 1),
            )
            for position in range(SLOT_OPERATION_COUNT)
        ]
        operations[0] = ReplayOperation(
            position=0,
            kind=ReplayOperationKind.ATTEMPT_NULLIFIER,
            replay_key_512=_key(1),
            attempt_version=1,
            revision_kind=ORIGINAL_REVISION_KIND,
            parent_attempt_version=0,
        )
        schedule = build_fixed_replay_schedule(
            operations, salt_use_tag_512=_key(257)
        )
        validate_k256_replay_alignment(profile, slots, schedule)

        mismatched = list(operations)
        mismatched[0] = ReplayOperation(
            position=0,
            kind=ReplayOperationKind.COVER_NULLIFIER,
            replay_key_512=_key(1),
        )
        mismatched_schedule = build_fixed_replay_schedule(
            mismatched, salt_use_tag_512=_key(257)
        )
        with self.assertRaisesRegex(
            StructuralError, "replay_slot_kind_mismatch"
        ):
            validate_k256_replay_alignment(
                profile, slots, mismatched_schedule
            )


if __name__ == "__main__":
    unittest.main()
