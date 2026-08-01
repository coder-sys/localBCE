from __future__ import annotations

from hashlib import sha3_512
import os
import unittest
from unittest import mock

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.batch.pq_state_reference import (
    LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH,
    LEGACY_PUBLIC_FIELD_COUNT,
    LegacyInternalStateRecord,
    PROFILE_ID,
    REFERENCE_SCHEMA_ID,
    SyntheticAuthoritativeState,
    WideDigest,
    build_reference_transition,
    build_strong_nullifier_transition,
    canonical_legacy_public_inputs,
    canonical_reference_record,
    derive_strong_attempt_nullifier,
    strong_nullifier_set_root,
)


RECORD_HEX_KAT = (
    "424c2f50513531322f43414e4f4e4943414c2f5245464552454e43452f76310020424c2f50513531322f5241572d"
    "5245434f52442f5245464552454e43452f76310006000a70726f66696c655f6964610000000b424c2d50513531322d"
    "76310009736368656d615f6964610000001b424c2d50513531322d5245464552454e43452d53544154452d7631000b"
    "7265636f72645f74797065610000001173796e7468657469635f617474656d707400156669656c642e617474656d70"
    "745f76657273696f6e620000000400000001000e6669656c642e636c61696d5f6964620000001053594e54482d434c"
    "41494d2d30303031000e6669656c642e70617965725f6964620000000b53594e54482d5041594552"
)
RECORD_SHA3_512_KAT = (
    "f40ec25ab298f972fa627063da33db9cc0d81f2d488ab032da2b7fb081c73053"
    "7d229fcc7aac322a92a599d3fd2de1843a0cce41e23387d3ad5c35ef401d6a08"
)
NULLIFIER_ONE_KAT = (
    "10d29ee33385548195c6fc8ef4bbe524bd9d626507df71fe67df13f6b01f4f31"
    "bbe164bf19f95903ec8430864723338f8261df320b34c3dcd4d56ebc3bd2ecb8"
)
NULLIFIER_TWO_KAT = (
    "286c51a1864ceaaeb1b5b993096585ab9993371c335ff52a61aabdab768d1e00"
    "5d2afd1eac14c10f4e375e1fa226b936dd83c07d72856548cfdc917aa8a92ee8"
)
EMPTY_ROOT_KAT = (
    "f8fa8f0ec3c8252819553fb3aff615b8c6fd2ac42b2103255991c501bbcff656"
    "7659ac6ed794480052141cc280d9160815497c16062d6dec3c83c95573af228f"
)
ONE_ROOT_KAT = (
    "ff9c112eb5aef022f2a5ddb773f54bca8074398bb5e784de341a590ca79a99a3"
    "467416aa6d3b6530fe812981d37b2c8320ea1c6410f66f5e26e9b9e0f926eb90"
)
TWO_ROOT_KAT = (
    "3924ab1b07e7aa6bd0c090978b5a324208a42948067da3b7e8e69862534c58ae"
    "217980f48a08bc39269fc1760bcde935fdd06ff8ce79e167cb58e1c27502d123"
)
BATCH_COMMITMENT_KAT = (
    "f4ec910effe81c8487470f732332c1c243fa056c08049a52cc5424a45ac793a5"
    "f9878198533299cb4cbaf77e04192f466323fd2eccd4a68670a77bcb95e93d34"
)
LEGACY_INTERNAL_STATE_RECORD_SHA3_512_KAT = (
    "3132cc5f6d85aec2fed2cc4bd54d2b77b16c3a8424ea4b46e2db7369150da74d"
    "d6172d96b725d2942633d58797c1a8746f8fa9464abfa3f31187f51cace2192f"
)
STATE_BEFORE_KAT = (
    "01f10c87690632a3dcd7374a1bdd067da4a8ef819d532e3e0f66bad710bc6cf6"
    "3b9b001018d59ecd757749a3620b4454521af5f3f741e85071b88cd6b21948f0"
)
STATE_AFTER_KAT = (
    "dac0de744bbd454f612ff4cb245caa27279e25d481215c2a1f8d92418f460495"
    "7c707c82c75ed0102de3857b0d81546e18787ee1da73bb2d779e5dac2b62a86d"
)


def _felt(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _attempt_record(claim_id: str) -> bytes:
    return canonical_reference_record(
        "synthetic_attempt",
        [
            ("attempt_version", (1).to_bytes(4, "big")),
            ("claim_id", claim_id.encode("ascii")),
            ("payer_id", b"SYNTH-PAYER"),
        ],
    )


def _nullifier_one() -> WideDigest:
    return derive_strong_attempt_nullifier(
        _attempt_record("SYNTH-CLAIM-0001"),
        governed_attempt_version=1,
        private_pepper=bytes(range(64)),
    )


def _nullifier_two() -> WideDigest:
    return derive_strong_attempt_nullifier(
        _attempt_record("SYNTH-CLAIM-0002"),
        governed_attempt_version=1,
        private_pepper=bytes(reversed(range(64))),
    )


def _public_inputs(*, nonce: int = 9001, root_before: int = 101, root_after: int = 202) -> tuple[bytes, ...]:
    return tuple(
        _felt(value)
        for value in (
            2,
            7001,
            nonce,
            root_before,
            root_after,
            301,
            302,
            303,
            304,
            401,
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
PRIVACY_SALT = bytes(range(64))


class PQStateReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._environment = mock.patch.dict(os.environ, _SYNTHETIC_FLAGS, clear=False)
        self._environment.start()

    def tearDown(self) -> None:
        self._environment.stop()

    def test_wide_digest_is_two_unreduced_256_bit_limbs(self) -> None:
        digest = WideDigest(bytes([0xFF]) * 32, bytes([0xFE]) * 32)
        self.assertGreaterEqual(int.from_bytes(digest.high_256, "big"), FIELD_MODULUS)
        self.assertEqual(len(digest.to_bytes()), 64)
        self.assertEqual(digest.limbs, (bytes([0xFF]) * 32, bytes([0xFE]) * 32))
        self.assertEqual(WideDigest.from_bytes(digest.to_bytes()), digest)
        self.assertEqual(WideDigest.from_hex(digest.to_hex()), digest)
        with self.assertRaisesRegex(TypeError, "wide_digest_high_256_must_be_bytes"):
            WideDigest(1, bytes(32))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "wide_digest_length_invalid"):
            WideDigest.from_bytes(bytes(32))

    def test_canonical_raw_record_and_nullifier_kats_are_exact(self) -> None:
        record = _attempt_record("SYNTH-CLAIM-0001")
        self.assertEqual(record.hex(), RECORD_HEX_KAT)
        self.assertEqual(sha3_512(record).hexdigest(), RECORD_SHA3_512_KAT)
        self.assertEqual(_nullifier_one().to_hex(), NULLIFIER_ONE_KAT)
        self.assertEqual(_nullifier_two().to_hex(), NULLIFIER_TWO_KAT)

    def test_record_label_order_type_and_raw_content_are_bound(self) -> None:
        first = canonical_reference_record(
            "synthetic_attempt",
            [("left", b"ab"), ("right", b"c")],
        )
        regrouped = canonical_reference_record(
            "synthetic_attempt",
            [("left", b"a"), ("right", b"bc")],
        )
        other_type = canonical_reference_record(
            "synthetic_cover",
            [("left", b"ab"), ("right", b"c")],
        )
        self.assertEqual(len({first, regrouped, other_type}), 3)
        with self.assertRaisesRegex(ValueError, "canonical_reference_fields_not_strictly_sorted"):
            canonical_reference_record(
                "synthetic_attempt",
                [("right", b"c"), ("left", b"ab")],
            )
        with self.assertRaisesRegex(ValueError, "canonical_reference_field_label_duplicate"):
            canonical_reference_record(
                "synthetic_attempt",
                [("left", b"ab"), ("left", b"c")],
            )

    def test_strong_nullifier_set_root_and_transition_kats_are_exact(self) -> None:
        first = _nullifier_one()
        second = _nullifier_two()
        self.assertEqual(strong_nullifier_set_root(()).to_hex(), EMPTY_ROOT_KAT)
        self.assertEqual(strong_nullifier_set_root((first,)).to_hex(), ONE_ROOT_KAT)
        self.assertEqual(strong_nullifier_set_root((first, second)).to_hex(), TWO_ROOT_KAT)
        self.assertEqual(strong_nullifier_set_root((second, first)).to_hex(), TWO_ROOT_KAT)
        transition = build_strong_nullifier_transition((first,), (second,))
        self.assertEqual(transition.root_before.to_hex(), ONE_ROOT_KAT)
        self.assertEqual(transition.root_after.to_hex(), TWO_ROOT_KAT)
        with self.assertRaisesRegex(ValueError, "strong_nullifier_already_spent"):
            build_strong_nullifier_transition((first,), (first,))
        with self.assertRaisesRegex(ValueError, "strong_nullifier_additions_contains_duplicate"):
            build_strong_nullifier_transition((), (first, first))

    def test_external_statement_remains_exactly_twelve_canonical_felts(self) -> None:
        values = _public_inputs()
        self.assertEqual(len(values), LEGACY_PUBLIC_FIELD_COUNT)
        self.assertEqual(canonical_legacy_public_inputs(values), values)
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_field_count_mismatch"):
            canonical_legacy_public_inputs(values + (_felt(404),))
        malformed = list(values)
        malformed[8] = FIELD_MODULUS.to_bytes(32, "big")
        with self.assertRaisesRegex(ValueError, "privacy_v2_public_field_8_not_canonical_stark_field"):
            canonical_legacy_public_inputs(malformed)

    def test_legacy_internal_record_round_trip_and_commitment_kats_are_exact(self) -> None:
        transition = build_reference_transition(
            (),
            (_nullifier_one(),),
            _public_inputs(),
            epoch=7,
            sequence_before=0,
            strong_governance_commitment=GOVERNANCE,
            canonical_private_batch_commitment=PRIVATE_BATCH,
            fresh_privacy_salt=PRIVACY_SALT,
            verifier_identity=VERIFIER_ID,
        )
        encoded = transition.legacy_state_record.encode()
        self.assertEqual(transition.legacy_state_record.profile_id, PROFILE_ID)
        self.assertEqual(transition.legacy_state_record.schema_id, REFERENCE_SCHEMA_ID)
        self.assertEqual(len(encoded), LEGACY_INTERNAL_STATE_RECORD_ENCODED_LENGTH)
        self.assertEqual(len(encoded), 434)
        self.assertEqual(LegacyInternalStateRecord.decode(encoded), transition.legacy_state_record)
        self.assertEqual(
            sha3_512(encoded).hexdigest(),
            LEGACY_INTERNAL_STATE_RECORD_SHA3_512_KAT,
        )
        self.assertEqual(
            transition.legacy_state_record.strong_batch_commitment.to_hex(),
            BATCH_COMMITMENT_KAT,
        )
        self.assertEqual(len(transition.public_inputs), 12)
        with self.assertRaisesRegex(ValueError, "candidate_sidecar_length_mismatch"):
            CandidateSidecarV1.decode(encoded)

    def test_reference_state_transition_is_atomic_and_has_exact_kats(self) -> None:
        public_inputs = _public_inputs()
        state = SyntheticAuthoritativeState(
            epoch=7,
            sequence=0,
            settlement_domain=_felt(7001),
            legacy_nullifier_root=_felt(101),
            legacy_governed_roots=public_inputs[5:9],
            strong_nullifiers=(),
            strong_governance_commitment=GOVERNANCE,
            verifier_identity=VERIFIER_ID,
        )
        before = state.snapshot()
        transition = build_reference_transition(
            (),
            (_nullifier_one(),),
            public_inputs,
            epoch=7,
            sequence_before=0,
            strong_governance_commitment=GOVERNANCE,
            canonical_private_batch_commitment=PRIVATE_BATCH,
            fresh_privacy_salt=PRIVACY_SALT,
            verifier_identity=VERIFIER_ID,
        )
        after = state.commit_reference_transition(transition)
        self.assertEqual(before.state_commitment.to_hex(), STATE_BEFORE_KAT)
        self.assertEqual(after.state_commitment.to_hex(), STATE_AFTER_KAT)
        self.assertEqual(after.sequence, 1)
        self.assertEqual(after.legacy_nullifier_root, public_inputs[4])
        self.assertEqual(
            after.strong_nullifier_root,
            transition.legacy_state_record.strong_nullifier_root_after,
        )
        self.assertEqual(after.nullifier_count, 1)
        self.assertEqual(after.recorded_batch_count, 1)
        self.assertEqual(after.consumed_nonce_count, 1)

    def test_nullifier_derivation_rejects_non_raw_short_and_zero_secret_inputs(self) -> None:
        with self.assertRaisesRegex(TypeError, "canonical_attempt_record_must_be_bytes"):
            derive_strong_attempt_nullifier(123, governed_attempt_version=1, private_pepper=bytes(64))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "private_pepper_length_invalid"):
            derive_strong_attempt_nullifier(
                _attempt_record("SYNTH-CLAIM-0001"),
                governed_attempt_version=1,
                private_pepper=bytes(32),
            )
        with self.assertRaisesRegex(ValueError, "private_pepper_must_be_nonzero"):
            derive_strong_attempt_nullifier(
                _attempt_record("SYNTH-CLAIM-0001"),
                governed_attempt_version=1,
                private_pepper=bytes(64),
            )


if __name__ == "__main__":
    unittest.main()
