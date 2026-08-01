from __future__ import annotations

import os
from itertools import repeat
import unittest
from unittest import mock

from app.batch import pq_tree_reference as pq


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _record(record_id: str, *, record_type: str = "synthetic_claim") -> bytes:
    return pq.encode_canonical_record(
        record_type,
        (
            pq.CanonicalField.identifier("claim_id", record_id),
            pq.CanonicalField.boolean("verified", True),
            pq.CanonicalField.u64("total_cents", 12_500),
        ),
    )


class PQTreeReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(os.environ, FLAGS, clear=False)
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def test_reference_requires_all_synthetic_guards(self) -> None:
        for missing in FLAGS:
            incomplete = {key: value for key, value in FLAGS.items() if key != missing}
            with self.subTest(missing=missing), mock.patch.dict(os.environ, incomplete, clear=True):
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_tree_reference_forbidden"):
                    pq.CanonicalField.u64("value", 1)
        for key, wrong in (
            ("BL_ENV", "production"),
            ("BL_DEV", "0"),
            ("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "0"),
        ):
            invalid = {**FLAGS, key: wrong}
            with self.subTest(key=key), mock.patch.dict(os.environ, invalid, clear=True):
                with self.assertRaisesRegex(RuntimeError, "synthetic_pq_tree_reference_forbidden"):
                    pq.CanonicalField.u64("value", 1)

    def test_canonical_record_round_trip_is_typed_ordered_and_exact(self) -> None:
        encoded = _record("SYNTHETIC-CLAIM-0001")
        parsed = pq.parse_canonical_record(encoded)
        self.assertEqual(parsed.record_type, "synthetic_claim")
        self.assertEqual(parsed.encoded, encoded)
        self.assertEqual(tuple(field.type_name for field in parsed.fields), ("ascii", "bool", "u64"))
        length_first = pq.encode_canonical_record(
            "synthetic_claim",
            (pq.CanonicalField.u64("b", 1), pq.CanonicalField.u64("aa", 2)),
        )
        self.assertEqual(tuple(field.name for field in pq.parse_canonical_record(length_first).fields), ("b", "aa"))
        with self.assertRaisesRegex(ValueError, "fields_not_strictly_sorted"):
            pq.encode_canonical_record(
                "synthetic_claim",
                (pq.CanonicalField.u64("aa", 2), pq.CanonicalField.u64("b", 1)),
            )
        with self.assertRaisesRegex(ValueError, "fields_not_strictly_sorted"):
            pq.encode_canonical_record(
                "synthetic_claim",
                (
                    pq.CanonicalField.u64("z", 1),
                    pq.CanonicalField.u64("a", 2),
                ),
            )
        with self.assertRaisesRegex(ValueError, "field_duplicate"):
            pq.encode_canonical_record(
                "synthetic_claim",
                (
                    pq.CanonicalField.u64("same", 1),
                    pq.CanonicalField.u64("same", 2),
                ),
            )
        with self.assertRaisesRegex(ValueError, "trailing_data"):
            pq.parse_canonical_record(encoded + b"\x00")

    def test_sha3_leaf_node_empty_and_root_bind_all_structural_metadata(self) -> None:
        record = _record("SYNTHETIC-CLAIM-0001")
        leaf = pq.reference_wide_leaf(
            record,
            tree_kind="government_snapshot",
            position=0,
            length=1,
            tree_height=1,
        )
        changed_position = pq.reference_wide_leaf(
            record,
            tree_kind="government_snapshot",
            position=1,
            length=2,
            tree_height=1,
        )
        changed_length = pq.reference_wide_leaf(
            record,
            tree_kind="government_snapshot",
            position=0,
            length=2,
            tree_height=1,
        )
        changed_kind = pq.reference_wide_leaf(
            record,
            tree_kind="policy_snapshot",
            position=0,
            length=1,
            tree_height=1,
        )
        changed_type = pq.reference_wide_leaf(
            _record("SYNTHETIC-CLAIM-0001", record_type="synthetic_oracle"),
            tree_kind="government_snapshot",
            position=0,
            length=1,
            tree_height=1,
        )
        empty = pq.reference_wide_empty(
            tree_kind="government_snapshot", position=1, length=1, tree_height=1
        )
        self.assertEqual(len(leaf), 64)
        self.assertEqual(
            len({leaf, changed_position, changed_length, changed_kind, changed_type, empty}),
            6,
        )

        right = pq.reference_wide_empty(
            tree_kind="government_snapshot", position=1, length=1, tree_height=1
        )
        node = pq.reference_wide_node(
            leaf,
            right,
            tree_kind="government_snapshot",
            position=0,
            length=1,
            tree_height=1,
            child_height=0,
        )
        node_other_position = pq.reference_wide_node(
            leaf,
            right,
            tree_kind="government_snapshot",
            position=1,
            length=1,
            tree_height=2,
            child_height=0,
        )
        root = pq.reference_wide_root(
            node, tree_kind="government_snapshot", length=1, tree_height=1
        )
        self.assertNotEqual(node, node_other_position)
        self.assertNotEqual(root, node)

    def test_every_hash_domain_is_explicitly_reference_v0_and_distinct(self) -> None:
        domains = (
            pq.RAW_RECORD_DOMAIN,
            pq.WIDE_LEAF_DOMAIN,
            pq.WIDE_NODE_DOMAIN,
            pq.WIDE_EMPTY_DOMAIN,
            pq.WIDE_ROOT_DOMAIN,
            pq.RECORD_MANIFEST_DOMAIN,
            pq.LEGACY_REFERENCE_POSEIDON_DOMAIN,
        )
        self.assertEqual(len(domains), len(set(domains)))
        self.assertTrue(all(domain.endswith(b"REFERENCE/v0") for domain in domains))
        self.assertEqual(pq.MAX_REFERENCE_TREE_HEIGHT, 16)

    def test_bulk_legacy_hashing_is_exactly_scalar_equivalent(self) -> None:
        preimages = (b"A", b"B" * 31, bytes(range(96)))
        self.assertEqual(
            pq.reference_legacy_felts(preimages),
            tuple(pq.reference_legacy_felt(value) for value in preimages),
        )

    def test_identifier_and_ascii_boundaries_reject_truncation_and_embedded_zero(self) -> None:
        value = "SYNTHETIC-" + "A" * 54
        field = pq.CanonicalField.identifier("claim_id", value)
        self.assertEqual(len(field.payload), 64)
        with self.assertRaisesRegex(ValueError, "too_long"):
            pq.CanonicalField.identifier("claim_id", value + "A")
        with self.assertRaisesRegex(ValueError, "not_canonical_ascii_token"):
            pq.CanonicalField.identifier("claim_id", "synthetic-claim")
        with self.assertRaisesRegex(ValueError, "embedded_zero"):
            pq.CanonicalField.ascii("label", "A\x00B")
        with self.assertRaisesRegex(ValueError, "exceeds_64_bytes"):
            pq.CanonicalField.ascii("label", "A" * 65)

    def test_public_tree_primitives_reject_impossible_geometry(self) -> None:
        record = _record("SYNTHETIC-CLAIM-0001")
        leaf = pq.reference_wide_leaf(
            record,
            tree_kind="government_snapshot",
            position=0,
            length=1,
            tree_height=1,
        )
        empty = pq.reference_wide_empty(
            tree_kind="government_snapshot",
            position=1,
            length=1,
            tree_height=1,
        )
        with self.assertRaisesRegex(ValueError, "leaf_position_invalid"):
            pq.reference_wide_leaf(
                record,
                tree_kind="government_snapshot",
                position=1,
                length=1,
                tree_height=1,
            )
        with self.assertRaisesRegex(ValueError, "length_exceeds_capacity"):
            pq.reference_wide_leaf(
                record,
                tree_kind="government_snapshot",
                position=0,
                length=3,
                tree_height=1,
            )
        with self.assertRaisesRegex(ValueError, "empty_position_invalid"):
            pq.reference_wide_empty(
                tree_kind="government_snapshot",
                position=0,
                length=1,
                tree_height=1,
            )
        with self.assertRaisesRegex(ValueError, "node_child_height_invalid"):
            pq.reference_wide_node(
                leaf,
                empty,
                tree_kind="government_snapshot",
                position=0,
                length=1,
                tree_height=1,
                child_height=1,
            )
        with self.assertRaisesRegex(ValueError, "length_exceeds_capacity"):
            pq.reference_wide_root(
                leaf,
                tree_kind="government_snapshot",
                length=3,
                tree_height=1,
            )

    def test_public_leaf_and_tree_reject_nonallowlisted_synthetic_shapes(self) -> None:
        unmarked = pq.encode_canonical_record(
            "claim",
            (
                pq.CanonicalField.identifier("claim_id", "SYNTHETIC-CLAIM-0001"),
                pq.CanonicalField.boolean("verified", True),
                pq.CanonicalField.u64("total_cents", 12_500),
            ),
        )
        with self.assertRaisesRegex(ValueError, "profile_not_allowlisted"):
            pq.reference_wide_leaf(
                unmarked,
                tree_kind="government_snapshot",
                position=0,
                length=1,
                tree_height=1,
            )

        numeric_identifier = pq.encode_canonical_record(
            "synthetic_claim",
            (pq.CanonicalField.u64("ssn", 123_45_6789),),
        )
        with self.assertRaisesRegex(ValueError, "fields_not_allowlisted"):
            pq.derive_dual_tree_reference(
                (numeric_identifier,),
                tree_kind="government_snapshot",
                tree_height=1,
            )

        empty_required_identifier = pq.encode_canonical_record(
            "synthetic_claim",
            (
                pq.CanonicalField.ascii("claim_id", ""),
                pq.CanonicalField.boolean("verified", True),
                pq.CanonicalField.u64("total_cents", 12_500),
            ),
        )
        with self.assertRaisesRegex(ValueError, "synthetic_ascii_empty:claim_id"):
            pq.reference_wide_leaf(
                empty_required_identifier,
                tree_kind="government_snapshot",
                position=0,
                length=1,
                tree_height=1,
            )

    def test_dual_trees_use_one_sorted_raw_record_tuple_but_independent_hash_paths(self) -> None:
        records = (_record("SYNTHETIC-CLAIM-0002"), _record("SYNTHETIC-CLAIM-0001"))
        baseline = pq.derive_dual_tree_reference(
            records, tree_kind="government_snapshot", tree_height=2
        )
        self.assertEqual(baseline.canonical_records, tuple(sorted(records)))
        self.assertEqual(len(baseline.legacy_leaf_felts), 2)
        self.assertEqual(len(baseline.wide_leaf_digests), 2)
        with mock.patch.object(pq, "_legacy_felt", return_value=123456789):
            changed_legacy = pq.derive_dual_tree_reference(
                records, tree_kind="government_snapshot", tree_height=2
            )
        self.assertNotEqual(baseline.legacy_root_felt, changed_legacy.legacy_root_felt)
        self.assertEqual(baseline.wide_root_sha3_512, changed_legacy.wide_root_sha3_512)
        self.assertEqual(
            baseline.record_manifest_sha3_512,
            changed_legacy.record_manifest_sha3_512,
        )
        with mock.patch.object(pq, "_wide_digest", return_value=b"\xA5" * 64):
            changed_wide = pq.derive_dual_tree_reference(
                records, tree_kind="government_snapshot", tree_height=2
            )
        self.assertEqual(baseline.legacy_root_felt, changed_wide.legacy_root_felt)
        self.assertNotEqual(baseline.wide_root_sha3_512, changed_wide.wide_root_sha3_512)
        self.assertEqual(baseline.record_manifest_sha3_512, changed_wide.record_manifest_sha3_512)

    def test_empty_root_capacity_duplicates_and_height_fail_closed(self) -> None:
        empty = pq.derive_dual_tree_reference(
            (), tree_kind="government_snapshot", tree_height=1
        )
        self.assertEqual(
            empty.legacy_root_felt.to_bytes(32, "big").hex(),
            "072dbeb238c848ac57d4f8654b28f30cf97ca535370b66f6929f4dc548b7cbc5",
        )
        self.assertEqual(
            empty.wide_root_sha3_512.hex(),
            "24c95ff600c1e19835ad3bb35c9f72e61a61bec7bb247917ebf5af2ecb7888b0"
            "28dcc8be482631500ea37da645a30a8b5d4224cfb42eafafe82fbc498457e221",
        )
        nonempty = pq.derive_dual_tree_reference(
            (_record("SYNTHETIC-CLAIM-0001"),),
            tree_kind="government_snapshot",
            tree_height=1,
        )
        self.assertNotEqual(empty.wide_root_sha3_512, nonempty.wide_root_sha3_512)
        with self.assertRaisesRegex(ValueError, "duplicate_canonical_record"):
            pq.derive_dual_tree_reference(
                (_record("SYNTHETIC-CLAIM-0001"), _record("SYNTHETIC-CLAIM-0001")),
                tree_kind="government_snapshot",
                tree_height=1,
            )
        with self.assertRaisesRegex(ValueError, "capacity_exceeded"):
            pq.derive_dual_tree_reference(
                (_record("SYNTHETIC-CLAIM-0001"), _record("SYNTHETIC-CLAIM-0002")),
                tree_kind="government_snapshot",
                tree_height=0,
            )
        with self.assertRaisesRegex(ValueError, "capacity_exceeded"):
            pq.derive_dual_tree_reference(
                repeat(_record("SYNTHETIC-CLAIM-0001")),
                tree_kind="government_snapshot",
                tree_height=0,
            )
        with self.assertRaisesRegex(ValueError, "height_exceeds_synthetic_limit"):
            pq.derive_dual_tree_reference(
                (),
                tree_kind="government_snapshot",
                tree_height=pq.MAX_REFERENCE_TREE_HEIGHT + 1,
            )


if __name__ == "__main__":
    unittest.main()
