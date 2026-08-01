from __future__ import annotations

from dataclasses import replace
import os
import unittest
from unittest import mock

from app.privacy_v2 import PRIVACY_V2_PUBLIC_OUTPUT_NAMES
from experiments.fixed_k_privacy_v2.reference import (
    FixedKPrivateSlot,
    SlotKind,
    build_synthetic_fixed_k_schedule,
    verify_synthetic_fixed_k_schedule,
)


_FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_FIXED_K_REFERENCE": "1",
}


def _digest(marker: int) -> bytes:
    return marker.to_bytes(64, "big")


def _public_fields() -> tuple[int, ...]:
    return (2, 7001, 9001, *range(103, 112))


def _real(index: int, marker: int, *, approved: bool = True) -> FixedKPrivateSlot:
    amount = 12500 if approved else 0
    return FixedKPrivateSlot(
        kind=SlotKind.REAL,
        approved=approved,
        slot_index=index,
        legacy_nullifier=marker,
        strong_nullifier=_digest(1000 + marker),
        private_claim_commitment=_digest(2000 + marker),
        allowed_cents=amount,
        payment_cents=amount,
    )


def _cover(index: int, marker: int) -> FixedKPrivateSlot:
    return FixedKPrivateSlot(
        kind=SlotKind.COVER,
        approved=False,
        slot_index=index,
        legacy_nullifier=marker,
        strong_nullifier=_digest(1000 + marker),
        private_claim_commitment=bytes(64),
        allowed_cents=0,
        payment_cents=0,
    )


class FixedKPrivacyReferenceTests(unittest.TestCase):
    def _schedule(self, slots: list[FixedKPrivateSlot], *, salt_marker: int = 7001):
        return build_synthetic_fixed_k_schedule(
            reviewed_fixed_k=4,
            reviewed_profile_digest=_digest(6001),
            settlement_domain=7001,
            batch_nonce=9001,
            fresh_private_salt=_digest(salt_marker),
            slots=slots,
            public_fields=_public_fields(),
        )

    def test_zero_one_and_four_real_claims_have_identical_private_witness_length(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            zero_real = self._schedule([_cover(index, 10 + index) for index in range(4)])
            one_real = self._schedule([_real(0, 20), *[_cover(index, 20 + index) for index in range(1, 4)]])
            four_real = self._schedule([_real(index, 30 + index) for index in range(4)])
            self.assertEqual(
                {len(zero_real.to_private_bytes()), len(one_real.to_private_bytes()), len(four_real.to_private_bytes())},
                {len(zero_real.to_private_bytes())},
            )
        self.assertEqual(4, len(zero_real.slots))
        self.assertEqual(4, len(one_real.slots))
        self.assertEqual(4, len(four_real.slots))

    def test_cover_kind_and_inert_values_are_bound_by_reference_commitment(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            baseline = self._schedule([_real(0, 40), *[_cover(index, 40 + index) for index in range(1, 4)]])
            changed_cover = replace(baseline.slots[3], legacy_nullifier=99, strong_nullifier=_digest(1099))
            changed = replace(baseline, slots=(*baseline.slots[:3], changed_cover))
            self.assertNotEqual(baseline.reference_commitment(), changed.reference_commitment())
            self.assertTrue(
                verify_synthetic_fixed_k_schedule(baseline, baseline.reference_commitment())
            )
            with self.assertRaisesRegex(ValueError, "authenticated_reference_commitment_mismatch"):
                verify_synthetic_fixed_k_schedule(changed, baseline.reference_commitment())

    def test_all_twelve_public_fields_and_fresh_salt_are_bound(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            baseline = self._schedule([_cover(index, 45 + index) for index in range(4)])
            changed_public_fields = list(baseline.public_fields)
            changed_public_fields[7] += 1
            changed_statement = replace(baseline, public_fields=tuple(changed_public_fields))
            changed_salt = replace(baseline, fresh_private_salt=_digest(7002))
            self.assertNotEqual(baseline.reference_commitment(), changed_statement.reference_commitment())
            self.assertNotEqual(baseline.reference_commitment(), changed_salt.reference_commitment())

    def test_real_cover_confusion_and_non_inert_cover_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "cover_slot_not_inert"):
            replace(_cover(0, 50), private_claim_commitment=_digest(2050))
        with self.assertRaisesRegex(ValueError, "real_slot_missing_claim_commitment"):
            replace(_real(0, 51), private_claim_commitment=bytes(64))
        with self.assertRaisesRegex(ValueError, "denied_slot_has_payment"):
            replace(_real(0, 52, approved=False), payment_cents=1)

    def test_cross_kind_nullifier_collision_and_slot_reordering_fail_closed(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            real = _real(0, 60)
            colliding_cover = replace(
                _cover(1, 61),
                legacy_nullifier=real.legacy_nullifier,
                strong_nullifier=real.strong_nullifier,
            )
            with self.assertRaisesRegex(ValueError, "duplicate_legacy_nullifier"):
                self._schedule([real, colliding_cover, _cover(2, 62), _cover(3, 63)])
            with self.assertRaisesRegex(ValueError, "slot_index_mismatch"):
                self._schedule([_cover(1, 70), _cover(0, 71), _cover(2, 72), _cover(3, 73)])

    def test_exact_twelve_field_abi_is_preserved_without_public_count(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            schedule = self._schedule([_cover(index, 80 + index) for index in range(4)])
        self.assertEqual(12, len(schedule.public_fields))
        self.assertEqual(12, len(PRIVACY_V2_PUBLIC_OUTPUT_NAMES))
        for forbidden in ("claimCount", "approvedCount", "deniedCount", "paddingCount"):
            self.assertNotIn(forbidden, PRIVACY_V2_PUBLIC_OUTPUT_NAMES)

    def test_public_context_and_canonical_integer_encoding_fail_closed(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            with self.assertRaisesRegex(ValueError, "public_settlement_domain_mismatch"):
                build_synthetic_fixed_k_schedule(
                    reviewed_fixed_k=1,
                    reviewed_profile_digest=_digest(6001),
                    settlement_domain=7002,
                    batch_nonce=9001,
                    fresh_private_salt=_digest(7001),
                    slots=[_cover(0, 88)],
                    public_fields=_public_fields(),
                )
            noncanonical = list(_public_fields())
            noncanonical[3] = "103"
            with self.assertRaisesRegex(ValueError, "public_field_3_not_canonical_felt"):
                build_synthetic_fixed_k_schedule(
                    reviewed_fixed_k=1,
                    reviewed_profile_digest=_digest(6001),
                    settlement_domain=7001,
                    batch_nonce=9001,
                    fresh_private_salt=_digest(7001),
                    slots=[_cover(0, 89)],
                    public_fields=noncanonical,
                )

    def test_reference_is_disabled_without_explicit_synthetic_guards(self) -> None:
        with mock.patch.dict(os.environ, {"BL_ENV": "production", "BL_DEV": "1", "BL_ALLOW_SYNTHETIC_FIXED_K_REFERENCE": "1"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "synthetic_fixed_k_reference_forbidden"):
                self._schedule([_cover(index, 90 + index) for index in range(4)])

    def test_created_reference_cannot_be_serialized_after_guard_is_removed(self) -> None:
        with mock.patch.dict(os.environ, _FLAGS, clear=False):
            schedule = self._schedule([_cover(index, 100 + index) for index in range(4)])
            slot = schedule.slots[0]
            commitment = schedule.reference_commitment()
        with mock.patch.dict(
            os.environ,
            {"BL_ENV": "production", "BL_DEV": "1", "BL_ALLOW_SYNTHETIC_FIXED_K_REFERENCE": "1"},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic_fixed_k_reference_forbidden"):
                slot.to_private_bytes()
            with self.assertRaisesRegex(RuntimeError, "synthetic_fixed_k_reference_forbidden"):
                schedule.to_private_bytes()
            with self.assertRaisesRegex(RuntimeError, "synthetic_fixed_k_reference_forbidden"):
                schedule.reference_commitment()
            with self.assertRaisesRegex(RuntimeError, "synthetic_fixed_k_reference_forbidden"):
                verify_synthetic_fixed_k_schedule(schedule, commitment)

    def test_slot_kind_rejects_raw_integer_and_bool_aliases(self) -> None:
        for ambiguous_kind in (0, 1, False, True):
            with self.subTest(kind=ambiguous_kind):
                with self.assertRaisesRegex(ValueError, "fixed_k_slot_kind_invalid"):
                    FixedKPrivateSlot(
                        kind=ambiguous_kind,  # type: ignore[arg-type]
                        approved=False,
                        slot_index=0,
                        legacy_nullifier=120,
                        strong_nullifier=_digest(1120),
                        private_claim_commitment=bytes(64),
                        allowed_cents=0,
                        payment_cents=0,
                    )


if __name__ == "__main__":
    unittest.main()
