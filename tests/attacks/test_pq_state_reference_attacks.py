from __future__ import annotations

from dataclasses import replace
import os
import unittest
from unittest import mock

import app.batch.pq_state_reference as pq_reference
from app.batch.pq_suite_candidate import CandidateSidecarV1, SIDECAR_LENGTH
from app.batch.pq_state_reference import (
    LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH,
    LegacyInternalStateRecord,
    PROFILE_ID,
    REFERENCE_SCHEMA_ID,
    ReferenceTransition,
    SyntheticAuthoritativeState,
    WideDigest,
    build_reference_transition,
    canonical_reference_record,
    derive_strong_attempt_nullifier,
)


def _felt(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _attempt_nullifier(claim_number: int) -> WideDigest:
    record = canonical_reference_record(
        "synthetic_attempt",
        [
            ("attempt_version", (1).to_bytes(4, "big")),
            ("claim_id", f"SYNTH-CLAIM-{claim_number:04d}".encode("ascii")),
            ("payer_id", b"SYNTH-PAYER"),
        ],
    )
    pepper = bytes((index + claim_number) % 256 for index in range(64))
    return derive_strong_attempt_nullifier(
        record,
        governed_attempt_version=1,
        private_pepper=pepper,
    )


def _public_inputs(
    *,
    nonce: int = 9001,
    root_before: int = 101,
    root_after: int = 202,
    claim_source_root: int = 301,
    opaque_batch_commitment: int = 401,
) -> tuple[bytes, ...]:
    return tuple(
        _felt(value)
        for value in (
            2,
            7001,
            nonce,
            root_before,
            root_after,
            claim_source_root,
            302,
            303,
            304,
            opaque_batch_commitment,
            402,
            403,
        )
    )


_SYNTHETIC_FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE": "1",
}
with mock.patch.dict(os.environ, _SYNTHETIC_FLAGS, clear=False):
    GOVERNANCE = WideDigest(bytes([0x11]) * 32, bytes([0x22]) * 32)
    PRIVATE_BATCH = WideDigest(bytes([0x33]) * 32, bytes([0x44]) * 32)
    VERIFIER_ID = WideDigest(bytes([0x55]) * 32, bytes([0x66]) * 32)
    OTHER_VERIFIER_ID = WideDigest(bytes([0x77]) * 32, bytes([0x88]) * 32)


def _state(*, verifier_identity: WideDigest = VERIFIER_ID) -> SyntheticAuthoritativeState:
    public_inputs = _public_inputs()
    return SyntheticAuthoritativeState(
        epoch=7,
        sequence=0,
        settlement_domain=_felt(7001),
        legacy_nullifier_root=_felt(101),
        legacy_governed_roots=public_inputs[5:9],
        strong_nullifiers=(),
        strong_governance_commitment=GOVERNANCE,
        verifier_identity=verifier_identity,
    )


def _transition(
    *,
    existing: tuple[WideDigest, ...] = (),
    addition: WideDigest | None = None,
    public_inputs: tuple[bytes, ...] | None = None,
    sequence_before: int = 0,
    salt_byte: int = 0xA1,
    verifier_identity: WideDigest = VERIFIER_ID,
) -> object:
    return build_reference_transition(
        existing,
        (addition or _attempt_nullifier(1),),
        public_inputs or _public_inputs(),
        epoch=7,
        sequence_before=sequence_before,
        strong_governance_commitment=GOVERNANCE,
        canonical_private_batch_commitment=PRIVATE_BATCH,
        fresh_privacy_salt=bytes([salt_byte]) * 64,
        verifier_identity=verifier_identity,
    )


def _candidate_sidecar() -> CandidateSidecarV1:
    values = tuple(bytes([index]) * 64 for index in range(1, 13))
    return CandidateSidecarV1(
        profile_id=values[0],
        proof_suite_id=values[1],
        schema_id=values[2],
        verifier_artifact_identity=values[3],
        strong_settlement_domain_id=values[4],
        epoch=7,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=values[5],
        strong_nullifier_root_after=values[6],
        strong_governance_commitment=values[7],
        strong_payment_state_root_before=values[8],
        strong_payment_state_root_after=values[9],
        strong_batch_commitment=values[10],
    )


class PQStateReferenceAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._environment = mock.patch.dict(os.environ, _SYNTHETIC_FLAGS, clear=False)
        self._environment.start()

    def tearDown(self) -> None:
        self._environment.stop()

    def assert_state_unchanged_after_rejection(
        self,
        state: SyntheticAuthoritativeState,
        transition: object,
        error: str,
    ) -> None:
        before = state.snapshot()
        with self.assertRaisesRegex((TypeError, ValueError), error):
            state.commit_reference_transition(transition)  # type: ignore[arg-type]
        self.assertEqual(state.snapshot(), before)

    def test_three_factor_runtime_guard_and_imported_objects_fail_closed(self) -> None:
        state = _state()
        transition = _transition()
        imported_digest = transition.legacy_state_record.strong_batch_commitment  # type: ignore[union-attr]
        encoded_record = transition.legacy_state_record.encode()  # type: ignore[union-attr]
        forbidden_environments = (
            {
                "BL_ENV": "production",
                "BL_DEV": "1",
                "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE": "1",
            },
            {
                "BL_ENV": "test",
                "BL_DEV": "0",
                "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE": "1",
            },
            {
                "BL_ENV": "test",
                "BL_DEV": "1",
                "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE": "0",
            },
        )
        for environment in forbidden_environments:
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    canonical_reference_record(
                        "synthetic_attempt",
                        [("attempt_version", (1).to_bytes(4, "big"))],
                    )
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    WideDigest(bytes([1]) * 32, bytes([2]) * 32)
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    _state()
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    imported_digest.to_hex()
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    transition.legacy_state_record.encode()  # type: ignore[union-attr]
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    LegacyInternalStateRecord.decode(encoded_record)
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    state.snapshot()
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_state_reference_forbidden"):
                    state.commit_reference_transition(transition)  # type: ignore[arg-type]

    def test_public_input_alias_is_frozen_before_external_mutation(self) -> None:
        baseline = _transition()
        mutable_public_inputs = list(baseline.public_inputs)  # type: ignore[union-attr]
        aliased = ReferenceTransition(
            baseline.legacy_state_record,  # type: ignore[union-attr]
            mutable_public_inputs,  # type: ignore[arg-type]
            baseline.nullifier_additions,  # type: ignore[union-attr]
            baseline.canonical_private_batch_commitment,  # type: ignore[union-attr]
            baseline.fresh_privacy_salt,  # type: ignore[union-attr]
        )
        self.assertIsInstance(aliased.public_inputs, tuple)
        frozen = aliased.public_inputs
        mutable_public_inputs[3] = _felt(999)
        self.assertEqual(aliased.public_inputs, frozen)
        state = _state()
        state.commit_reference_transition(aliased)
        self.assertEqual(state.snapshot().legacy_nullifier_root, _felt(202))

    def test_raw_record_permutation_duplicate_and_malformed_typed_payloads_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical_reference_fields_not_strictly_sorted"):
            canonical_reference_record(
                "synthetic_attempt",
                [("claim_id", b"SYNTH-1"), ("attempt_version", (1).to_bytes(4, "big"))],
            )
        with self.assertRaisesRegex(ValueError, "canonical_reference_field_label_duplicate"):
            canonical_reference_record(
                "synthetic_attempt",
                [("claim_id", b"SYNTH-1"), ("claim_id", b"SYNTH-2")],
            )

        record = canonical_reference_record(
            "synthetic_attempt",
            [
                ("attempt_version", (1).to_bytes(4, "big")),
                ("claim_id", b"SYNTH-CLAIM-0001"),
                ("payer_id", b"SYNTH-PAYER"),
            ],
        )

        def mutate_field_tag(label: str, replacement: bytes) -> bytes:
            label_bytes = f"field.{label}".encode("ascii")
            marker = len(label_bytes).to_bytes(2, "big") + label_bytes
            offset = record.index(marker) + len(marker)
            return record[:offset] + replacement + record[offset + 1 :]

        malformed_cases = (
            (record[:-1], "canonical_record_payload_truncated"),
            (record + b"\x00", "canonical_record_trailing_data"),
            (mutate_field_tag("claim_id", b"x"), "canonical_record_type_tag_unknown"),
            (mutate_field_tag("claim_id", b"4"), "canonical_record_u32_payload_length_invalid"),
            (mutate_field_tag("payer_id", b"8"), "canonical_record_u64_payload_length_invalid"),
            (mutate_field_tag("attempt_version", b"h"), "canonical_record_wide_limb_payload_length_invalid"),
            (
                pq_reference._canonical_record(
                    pq_reference._RAW_RECORD_DOMAIN,
                    [
                        pq_reference._ascii_field("profile_id", PROFILE_ID),
                        pq_reference._ascii_field("schema_id", REFERENCE_SCHEMA_ID),
                        pq_reference._ascii_field("record_type", b"synthetic_attempt"),
                        pq_reference._bytes_field("field.", b"ambiguous-empty-suffix"),
                    ],
                ),
                "canonical_attempt_record_field_label_invalid",
            ),
        )
        for malformed, error in malformed_cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                derive_strong_attempt_nullifier(
                    malformed,
                    governed_attempt_version=1,
                    private_pepper=bytes([0xA1]) * 64,
                )

        profile_offset = record.index(PROFILE_ID)
        non_ascii = record[:profile_offset] + b"\xff" + record[profile_offset + 1 :]
        with self.assertRaisesRegex(ValueError, "canonical_record_ascii_payload_invalid"):
            derive_strong_attempt_nullifier(
                non_ascii,
                governed_attempt_version=1,
                private_pepper=bytes([0xA1]) * 64,
            )

    def test_legacy_record_rejects_truncation_trailing_data_and_limb_marker_mutation(self) -> None:
        transition = _transition()
        encoded = transition.legacy_state_record.encode()  # type: ignore[union-attr]
        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_length_mismatch"):
            LegacyInternalStateRecord.decode(encoded[:-1])
        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_length_mismatch"):
            LegacyInternalStateRecord.decode(encoded + b"\x00")
        marker = encoded.index(b"NH") + 1
        malformed = encoded[:marker] + b"X" + encoded[marker + 1 :]
        with self.assertRaisesRegex(
            ValueError,
            "legacy_internal_state_record_strong_root_before_high_limb_marker_mismatch",
        ):
            LegacyInternalStateRecord.decode(malformed)

    def test_legacy_record_rejects_unknown_profile_and_schema_without_alternate_encoding(self) -> None:
        transition = _transition()
        encoded = transition.legacy_state_record.encode()  # type: ignore[union-attr]
        profile_offset = encoded.index(PROFILE_ID)
        wrong_profile = encoded[:profile_offset] + b"XL-PQ512-v1" + encoded[profile_offset + len(PROFILE_ID) :]
        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_profile_mismatch"):
            LegacyInternalStateRecord.decode(wrong_profile)
        schema_offset = encoded.index(REFERENCE_SCHEMA_ID)
        wrong_schema = (
            encoded[:schema_offset]
            + b"XL-PQ512-REFERENCE-STATE-v1"
            + encoded[schema_offset + len(REFERENCE_SCHEMA_ID) :]
        )
        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_schema_mismatch"):
            LegacyInternalStateRecord.decode(wrong_schema)

    def test_legacy_record_and_candidate_sidecar_are_never_cross_accepted(self) -> None:
        legacy = _transition().legacy_state_record.encode()  # type: ignore[union-attr]
        candidate = _candidate_sidecar().encode()
        self.assertEqual(LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH, 434)
        self.assertEqual(SIDECAR_LENGTH, 744)
        self.assertEqual(len(legacy), 434)
        self.assertEqual(len(candidate), 744)

        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_length_mismatch"):
            LegacyInternalStateRecord.decode(candidate)
        with self.assertRaisesRegex(ValueError, "candidate_sidecar_length_mismatch"):
            CandidateSidecarV1.decode(legacy)
        with self.assertRaisesRegex(ValueError, "legacy_internal_state_record_magic_mismatch"):
            LegacyInternalStateRecord.decode(candidate[:434])
        padded_legacy = legacy + bytes(SIDECAR_LENGTH - len(legacy))
        with self.assertRaisesRegex(ValueError, "candidate_sidecar_magic_mismatch"):
            CandidateSidecarV1.decode(padded_legacy)

    def test_single_felt_or_single_limb_substitution_is_not_an_accepted_wide_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "wide_digest_length_invalid"):
            WideDigest.from_bytes(_felt(12345))
        with self.assertRaisesRegex(ValueError, "canonical_record_magic_mismatch"):
            derive_strong_attempt_nullifier(
                _felt(12345),
                governed_attempt_version=1,
                private_pepper=bytes([0xA1]) * 64,
            )
        with self.assertRaisesRegex(
            TypeError,
            "legacy_internal_state_record_strong_nullifier_root_before_must_be_wide_digest",
        ):
            LegacyInternalStateRecord(
                PROFILE_ID,
                REFERENCE_SCHEMA_ID,
                7,
                0,
                1,
                12345,  # type: ignore[arg-type]
                WideDigest(bytes([1]) * 32, bytes([2]) * 32),
                GOVERNANCE,
                VERIFIER_ID,
                PRIVATE_BATCH,
            )

    def test_swapped_high_and_low_limbs_fail_closed_without_state_change(self) -> None:
        state = _state()
        transition = _transition()
        root = transition.legacy_state_record.strong_nullifier_root_before  # type: ignore[union-attr]
        swapped = WideDigest(root.low_256, root.high_256)
        forged_record = replace(
            transition.legacy_state_record,
            strong_nullifier_root_before=swapped,
        )  # type: ignore[arg-type]
        forged = replace(transition, legacy_state_record=forged_record)  # type: ignore[arg-type]
        self.assert_state_unchanged_after_rejection(state, forged, "stale_strong_nullifier_root")

    def test_stale_sequence_replay_is_rejected_after_one_atomic_commit(self) -> None:
        state = _state()
        transition = _transition()
        state.commit_reference_transition(transition)  # type: ignore[arg-type]
        committed = state.snapshot()
        with self.assertRaisesRegex(ValueError, "stale_strong_state_sequence"):
            state.commit_reference_transition(transition)  # type: ignore[arg-type]
        self.assertEqual(state.snapshot(), committed)

    def test_competing_transitions_from_one_before_state_cannot_both_commit(self) -> None:
        state = _state()
        first = _transition(addition=_attempt_nullifier(1), salt_byte=0xA1)
        second = _transition(
            addition=_attempt_nullifier(2),
            public_inputs=_public_inputs(nonce=9002, root_after=203),
            salt_byte=0xA2,
        )
        state.commit_reference_transition(first)  # type: ignore[arg-type]
        after_first = state.snapshot()
        with self.assertRaisesRegex(ValueError, "stale_strong_state_sequence"):
            state.commit_reference_transition(second)  # type: ignore[arg-type]
        self.assertEqual(state.snapshot(), after_first)

    def test_forged_batch_commitment_and_old_commitment_new_inputs_are_rejected_atomically(self) -> None:
        state = _state()
        transition = _transition()
        forged_digest = WideDigest(bytes([0x91]) * 32, bytes([0x92]) * 32)
        forged_record = replace(
            transition.legacy_state_record,
            strong_batch_commitment=forged_digest,
        )  # type: ignore[arg-type]
        forged = replace(transition, legacy_state_record=forged_record)  # type: ignore[arg-type]
        self.assert_state_unchanged_after_rejection(state, forged, "strong_batch_commitment_mismatch")

        changed_inputs = list(transition.public_inputs)  # type: ignore[union-attr]
        changed_inputs[9] = _felt(499)
        old_commitment_new_inputs = replace(transition, public_inputs=tuple(changed_inputs))  # type: ignore[arg-type]
        self.assert_state_unchanged_after_rejection(
            state,
            old_commitment_new_inputs,
            "strong_batch_commitment_mismatch",
        )

    def test_stale_legacy_root_and_governed_root_are_rejected_atomically(self) -> None:
        state = _state()
        stale_legacy = _transition(public_inputs=_public_inputs(root_before=99))
        self.assert_state_unchanged_after_rejection(state, stale_legacy, "stale_legacy_nullifier_root")
        wrong_governance_alias = _transition(public_inputs=_public_inputs(claim_source_root=399))
        self.assert_state_unchanged_after_rejection(
            state,
            wrong_governance_alias,
            "state_legacy_governed_roots_mismatch",
        )

    def test_wrong_epoch_strong_governance_and_verifier_identity_are_rejected_atomically(self) -> None:
        state = _state()
        transition = _transition()
        wrong_epoch = replace(
            transition,
            legacy_state_record=replace(transition.legacy_state_record, epoch=8),
        )  # type: ignore[arg-type]
        self.assert_state_unchanged_after_rejection(state, wrong_epoch, "state_epoch_mismatch")

        other_governance = WideDigest(bytes([0x71]) * 32, bytes([0x72]) * 32)
        wrong_governance = replace(
            transition,
            legacy_state_record=replace(
                transition.legacy_state_record,
                strong_governance_commitment=other_governance,
            ),  # type: ignore[arg-type]
        )
        self.assert_state_unchanged_after_rejection(
            state,
            wrong_governance,
            "state_strong_governance_mismatch",
        )
        wrong_verifier = _transition(verifier_identity=OTHER_VERIFIER_ID)
        self.assert_state_unchanged_after_rejection(
            state,
            wrong_verifier,
            "state_verifier_identity_mismatch",
        )

    def test_legacy_record_and_batch_commitment_cannot_cross_verifier_states(self) -> None:
        transition = _transition(verifier_identity=VERIFIER_ID)
        other_state = _state(verifier_identity=OTHER_VERIFIER_ID)
        self.assert_state_unchanged_after_rejection(
            other_state,
            transition,
            "state_verifier_identity_mismatch",
        )
        swapped_record = replace(
            transition.legacy_state_record,
            verifier_identity=OTHER_VERIFIER_ID,
        )  # type: ignore[arg-type]
        swapped = replace(transition, legacy_state_record=swapped_record)  # type: ignore[arg-type]
        self.assert_state_unchanged_after_rejection(
            other_state,
            swapped,
            "strong_batch_commitment_mismatch",
        )

    def test_reused_nonce_and_reused_salt_are_rejected_without_partial_second_update(self) -> None:
        first_nullifier = _attempt_nullifier(1)

        nonce_state = _state()
        first = _transition(addition=first_nullifier, salt_byte=0xA1)
        nonce_state.commit_reference_transition(first)  # type: ignore[arg-type]
        nonce_snapshot = nonce_state.snapshot()
        reused_nonce = _transition(
            existing=(first_nullifier,),
            addition=_attempt_nullifier(2),
            public_inputs=_public_inputs(nonce=9001, root_before=202, root_after=203),
            sequence_before=1,
            salt_byte=0xA2,
        )
        with self.assertRaisesRegex(ValueError, "batch_nonce_already_consumed"):
            nonce_state.commit_reference_transition(reused_nonce)  # type: ignore[arg-type]
        self.assertEqual(nonce_state.snapshot(), nonce_snapshot)

        salt_state = _state()
        salt_state.commit_reference_transition(first)  # type: ignore[arg-type]
        salt_snapshot = salt_state.snapshot()
        reused_salt = _transition(
            existing=(first_nullifier,),
            addition=_attempt_nullifier(2),
            public_inputs=_public_inputs(nonce=9002, root_before=202, root_after=203),
            sequence_before=1,
            salt_byte=0xA1,
        )
        with self.assertRaisesRegex(ValueError, "privacy_salt_already_consumed"):
            salt_state.commit_reference_transition(reused_salt)  # type: ignore[arg-type]
        self.assertEqual(salt_state.snapshot(), salt_snapshot)

    def test_duplicate_or_empty_nullifier_operations_and_legacy_noop_are_rejected(self) -> None:
        first = _attempt_nullifier(1)
        with self.assertRaisesRegex(ValueError, "strong_nullifier_additions_contains_duplicate"):
            build_reference_transition(
                (),
                (first, first),
                _public_inputs(),
                epoch=7,
                sequence_before=0,
                strong_governance_commitment=GOVERNANCE,
                canonical_private_batch_commitment=PRIVATE_BATCH,
                fresh_privacy_salt=bytes([0xA1]) * 64,
                verifier_identity=VERIFIER_ID,
            )
        with self.assertRaisesRegex(ValueError, "strong_nullifier_additions_empty"):
            build_reference_transition(
                (),
                (),
                _public_inputs(),
                epoch=7,
                sequence_before=0,
                strong_governance_commitment=GOVERNANCE,
                canonical_private_batch_commitment=PRIVATE_BATCH,
                fresh_privacy_salt=bytes([0xA1]) * 64,
                verifier_identity=VERIFIER_ID,
            )
        with self.assertRaisesRegex(ValueError, "legacy_nullifier_root_unchanged"):
            _transition(public_inputs=_public_inputs(root_before=101, root_after=101))
        with self.assertRaisesRegex(ValueError, "fresh_privacy_salt_must_be_nonzero"):
            build_reference_transition(
                (),
                (first,),
                _public_inputs(),
                epoch=7,
                sequence_before=0,
                strong_governance_commitment=GOVERNANCE,
                canonical_private_batch_commitment=PRIVATE_BATCH,
                fresh_privacy_salt=bytes(64),
                verifier_identity=VERIFIER_ID,
            )


if __name__ == "__main__":
    unittest.main()
