from __future__ import annotations

from dataclasses import replace
import unittest

from app.batch.attempt import (
    GovernedClaimAttempt,
    REVISION_KIND_CORRECTION,
    REVISION_KIND_ORIGINAL,
    SYNTHETIC_SOURCE_AUTHORITY_ID,
    legacy_attempt_claim_snapshot_commitment,
    legacy_attempt_nullifier,
    legacy_attempt_record_commitment,
    synthetic_original_attempt,
)
from app.batch.leaf import duplicate_check_nullifier
from app.models import Patient, Provider, ServiceLine, SharedContext


PEPPER = "synthetic-governed-attempt-pepper-v1"


def sample_context() -> SharedContext:
    return SharedContext(
        claim_id="BL-SYNTH-ATTEMPT-001",
        transaction_set="837P",
        payer_id="SYNTH-PAYER",
        member_id="SYNTH-MEMBER",
        patient=Patient(name="Synthetic Patient", id="SYNTH-MEMBER"),
        provider=Provider(npi="1999999984", name="Synthetic Clinic"),
        service_date="2026-01-02",
        diagnoses=["Z00.00"],
        service_lines=[
            ServiceLine(
                line_id="1",
                procedure_code="99213",
                charge_amount=125.00,
                units=1.0,
            )
        ],
        total_charge=125.00,
        flags={},
    )


class GovernedAttemptNullifierTests(unittest.TestCase):
    def test_same_raw_attempt_and_pepper_is_deterministic(self):
        ctx = sample_context()
        attempt = synthetic_original_attempt(ctx)

        first = legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER)
        second = legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER)

        self.assertEqual(first, second)
        self.assertGreater(first, 0)

    def test_governed_pepper_is_bound(self):
        ctx = sample_context()
        attempt = synthetic_original_attempt(ctx)

        first = legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER)
        second = legacy_attempt_nullifier(attempt, ctx, governed_pepper=f"{PEPPER}-rotated")

        self.assertNotEqual(first, second)

    def test_authorized_next_version_has_a_distinct_attempt_nullifier(self):
        ctx = sample_context()
        original = synthetic_original_attempt(ctx)
        correction = GovernedClaimAttempt(
            source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
            source_claim_id=ctx.claim_id,
            attempt_version=2,
            revision_kind=REVISION_KIND_CORRECTION,
            parent_attempt_version=1,
        )
        correction.validate_for_claim(ctx, original_only=False)

        self.assertNotEqual(
            legacy_attempt_nullifier(original, ctx, governed_pepper=PEPPER),
            legacy_attempt_nullifier(correction, ctx, governed_pepper=PEPPER),
        )

    def test_business_frequency_label_cannot_mint_a_new_attempt(self):
        ctx = sample_context()
        caller_relabelled_ctx = replace(ctx, flags={"frequency_type": "replacement"})
        attempt = synthetic_original_attempt(ctx)

        self.assertEqual(
            legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER),
            legacy_attempt_nullifier(attempt, caller_relabelled_ctx, governed_pepper=PEPPER),
        )
        self.assertNotEqual(
            duplicate_check_nullifier(ctx, "original", PEPPER),
            duplicate_check_nullifier(ctx, "replacement", PEPPER),
        )

    def test_attempt_nullifier_is_separate_from_business_duplicate_nullifier(self):
        ctx = sample_context()
        attempt = synthetic_original_attempt(ctx)

        self.assertNotEqual(
            legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER),
            duplicate_check_nullifier(ctx, "original", PEPPER),
        )

    def test_claim_snapshot_mutation_changes_record_but_not_replay_identity(self):
        ctx = sample_context()
        altered = replace(ctx, total_charge=126.00)
        altered.service_lines = [replace(ctx.service_lines[0], charge_amount=126.00)]
        attempt = synthetic_original_attempt(ctx)

        self.assertNotEqual(
            legacy_attempt_claim_snapshot_commitment(ctx),
            legacy_attempt_claim_snapshot_commitment(altered),
        )
        self.assertNotEqual(
            legacy_attempt_record_commitment(attempt, ctx),
            legacy_attempt_record_commitment(attempt, altered),
        )
        self.assertEqual(
            legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER),
            legacy_attempt_nullifier(attempt, altered, governed_pepper=PEPPER),
        )

    def test_mutable_payer_provider_and_adjudication_context_cannot_mint_new_attempt(self):
        ctx = sample_context()
        attempt = synthetic_original_attempt(ctx)
        changed = replace(
            ctx,
            payer_id="OTHER-PAYER",
            flags={"eligibility_active": False, "frequency_type": "replacement"},
        )
        changed.provider = replace(ctx.provider, npi="1234567893")

        self.assertEqual(
            legacy_attempt_nullifier(attempt, ctx, governed_pepper=PEPPER),
            legacy_attempt_nullifier(attempt, changed, governed_pepper=PEPPER),
        )

    def test_original_lifecycle_must_be_exactly_version_one_without_parent(self):
        ctx = sample_context()
        for version, parent in ((2, 0), (1, 1), (2, 1)):
            with self.subTest(version=version, parent=parent):
                attempt = GovernedClaimAttempt(
                    source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
                    source_claim_id=ctx.claim_id,
                    attempt_version=version,
                    revision_kind=REVISION_KIND_ORIGINAL,
                    parent_attempt_version=parent,
                )
                with self.assertRaisesRegex(ValueError, "attempt_original_lifecycle_invalid"):
                    attempt.validate_for_claim(ctx, original_only=False)

    def test_revision_rejects_version_jump_or_wrong_parent(self):
        ctx = sample_context()
        for version, parent in ((3, 1), (3, 0), (2, 0), (1, 0)):
            with self.subTest(version=version, parent=parent):
                attempt = GovernedClaimAttempt(
                    source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
                    source_claim_id=ctx.claim_id,
                    attempt_version=version,
                    revision_kind=REVISION_KIND_CORRECTION,
                    parent_attempt_version=parent,
                )
                with self.assertRaisesRegex(ValueError, "attempt_revision_lifecycle_invalid"):
                    attempt.validate_for_claim(ctx, original_only=False)

    def test_non_original_revision_remains_disabled_without_lifecycle_authority(self):
        ctx = sample_context()
        correction = GovernedClaimAttempt(
            source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
            source_claim_id=ctx.claim_id,
            attempt_version=2,
            revision_kind=REVISION_KIND_CORRECTION,
            parent_attempt_version=1,
        )

        with self.assertRaisesRegex(ValueError, "attempt_revision_pending_lifecycle_authority"):
            correction.validate_for_claim(ctx)

    def test_boolean_lifecycle_values_are_rejected(self):
        ctx = sample_context()
        cases = (
            (True, REVISION_KIND_ORIGINAL, 0, "attempt_version_invalid"),
            (1, True, 0, "attempt_revision_kind_invalid"),
            (1, REVISION_KIND_ORIGINAL, False, "attempt_parent_version_invalid"),
        )
        for version, revision_kind, parent, error in cases:
            with self.subTest(error=error):
                attempt = GovernedClaimAttempt(
                    source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
                    source_claim_id=ctx.claim_id,
                    attempt_version=version,
                    revision_kind=revision_kind,
                    parent_attempt_version=parent,
                )
                with self.assertRaisesRegex(ValueError, error):
                    attempt.validate_for_claim(ctx, original_only=False)

    def test_source_claim_id_must_match_authenticated_claim(self):
        ctx = sample_context()
        attempt = GovernedClaimAttempt(
            source_authority_id=SYNTHETIC_SOURCE_AUTHORITY_ID,
            source_claim_id="BL-SYNTH-ATTEMPT-OTHER",
            attempt_version=1,
            revision_kind=REVISION_KIND_ORIGINAL,
            parent_attempt_version=0,
        )

        with self.assertRaisesRegex(ValueError, "attempt_source_claim_id_mismatch"):
            attempt.validate_for_claim(ctx)

    def test_empty_governed_pepper_is_rejected(self):
        ctx = sample_context()
        attempt = synthetic_original_attempt(ctx)

        with self.assertRaisesRegex(ValueError, "attempt_governed_pepper_empty"):
            legacy_attempt_nullifier(attempt, ctx, governed_pepper="")


if __name__ == "__main__":
    unittest.main()
