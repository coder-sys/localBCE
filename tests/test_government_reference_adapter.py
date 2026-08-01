from __future__ import annotations

import inspect
import os
import unittest
from unittest import mock

from app.batch.pq_tree_reference import CanonicalField, parse_canonical_record
from app.connectors.government_reference import (
    InMemorySyntheticGovernmentAdapter,
    GovernmentReferenceRecord,
    GovernmentReferenceSnapshot,
    MAX_REFERENCE_RECORDS,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def _records() -> tuple[GovernmentReferenceRecord, ...]:
    return (
        GovernmentReferenceRecord(
            "claim",
            "SYNTHETIC-CLAIM-0001",
            "SYNTHETIC-CLAIMS",
            (
                CanonicalField.identifier("claim_id", "SYNTHETIC-CLAIM-0001"),
                CanonicalField.u64("total_cents", 12_500),
            ),
        ),
        GovernmentReferenceRecord(
            "oracle",
            "SYNTHETIC-ORACLE-0001",
            "SYNTHETIC-ORACLE",
            (
                CanonicalField.boolean("provider_enrolled", True),
                CanonicalField.boolean("eligibility_active", True),
            ),
        ),
        GovernmentReferenceRecord(
            "policy",
            "SYNTHETIC-POLICY-0001",
            "SYNTHETIC-POLICY",
            (
                CanonicalField.u64("fee_cents", 12_500),
                CanonicalField.ascii("policy_version", "SYNTHETIC-POLICY-REFERENCE-V0"),
            ),
        ),
        GovernmentReferenceRecord(
            "auth",
            "SYNTHETIC-AUTH-0001",
            "SYNTHETIC-AUTH",
            (
                CanonicalField.boolean("authorization_present", True),
                CanonicalField.identifier("authorization_reference", "SYNTHETIC-AUTH-0001"),
            ),
        ),
    )


def _snapshot(records: tuple[GovernmentReferenceRecord, ...] | None = None) -> GovernmentReferenceSnapshot:
    return GovernmentReferenceSnapshot(
        "SYNTHETIC-FOUNDATION-0001",
        0,
        _records() if records is None else records,
    )


def _record_for_index(index: int) -> GovernmentReferenceRecord:
    record_type = ("auth", "claim", "oracle", "policy")[index % 4]
    record_id = f"SYNTHETIC-RECORD-{index:03d}"
    if record_type == "auth":
        fields = (
            CanonicalField.boolean("authorization_present", True),
            CanonicalField.identifier("authorization_reference", record_id),
        )
    elif record_type == "claim":
        fields = (
            CanonicalField.identifier("claim_id", record_id),
            CanonicalField.u64("total_cents", index),
        )
    elif record_type == "oracle":
        fields = (
            CanonicalField.boolean("provider_enrolled", True),
            CanonicalField.boolean("eligibility_active", True),
        )
    else:
        fields = (
            CanonicalField.u64("fee_cents", index),
            CanonicalField.identifier("policy_version", "SYNTHETIC-POLICY-REFERENCE-V0"),
        )
    return GovernmentReferenceRecord(
        record_type,
        record_id,
        "SYNTHETIC-SOURCE",
        fields,
    )


class GovernmentReferenceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(os.environ, FLAGS, clear=False)
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def test_adapter_is_explicitly_in_memory_networkless_and_credentialless(self) -> None:
        adapter = InMemorySyntheticGovernmentAdapter((_snapshot(),))
        self.assertEqual(adapter.transport_kind, "in_memory")
        self.assertFalse(adapter.network_access)
        self.assertFalse(adapter.accepts_credentials)
        parameters = set(inspect.signature(InMemorySyntheticGovernmentAdapter).parameters)
        self.assertEqual(parameters, {"snapshots", "adapter_id"})
        self.assertTrue(parameters.isdisjoint({"url", "token", "password", "credential", "secret"}))

    def test_snapshot_requires_claim_oracle_policy_and_auth_records(self) -> None:
        records = tuple(record for record in _records() if record.record_type != "auth")
        with self.assertRaisesRegex(ValueError, "record_types_incomplete_or_unknown"):
            _snapshot(records)
        with self.assertRaisesRegex(ValueError, "record_key_duplicate"):
            _snapshot((*_records(), _records()[0]))

    def test_snapshot_records_are_strictly_canonical_and_bind_adapter_metadata(self) -> None:
        adapter = InMemorySyntheticGovernmentAdapter((_snapshot(),))
        snapshot = adapter.fetch_snapshot("SYNTHETIC-FOUNDATION-0001")
        canonical = snapshot.canonical_records(adapter_id=adapter.adapter_id)
        self.assertEqual(canonical, tuple(sorted(canonical)))
        self.assertEqual(len(canonical), 4)
        parsed = [parse_canonical_record(item) for item in canonical]
        self.assertEqual(
            {record.record_type for record in parsed},
            {
                "synthetic_government_auth",
                "synthetic_government_claim",
                "synthetic_government_oracle",
                "synthetic_government_policy",
            },
        )
        for record in parsed:
            names = {field.name for field in record.fields}
            self.assertTrue(
                {
                    "meta.adapter_id",
                    "meta.record_id",
                    "meta.snapshot_id",
                    "meta.snapshot_version",
                    "meta.source_system",
                }.issubset(names)
            )

    def test_dual_root_derivation_uses_the_exact_same_canonical_snapshot(self) -> None:
        first = InMemorySyntheticGovernmentAdapter((_snapshot(),))
        reversed_snapshot = _snapshot(tuple(reversed(_records())))
        second = InMemorySyntheticGovernmentAdapter((reversed_snapshot,))
        first_result = first.derive_snapshot_roots(
            "SYNTHETIC-FOUNDATION-0001",
            tree_kind="government_snapshot",
            tree_height=2,
        )
        second_result = second.derive_snapshot_roots(
            "SYNTHETIC-FOUNDATION-0001",
            tree_kind="government_snapshot",
            tree_height=2,
        )
        self.assertEqual(first_result.canonical_records, second_result.canonical_records)
        self.assertEqual(first_result.legacy_root_felt, second_result.legacy_root_felt)
        self.assertEqual(first_result.wide_root_sha3_512, second_result.wide_root_sha3_512)
        self.assertEqual(len(first_result.legacy_leaf_felts), len(first_result.canonical_records))
        self.assertEqual(len(first_result.wide_leaf_digests), len(first_result.canonical_records))

    def test_unknown_snapshot_bounds_and_synthetic_guard_fail_closed(self) -> None:
        adapter = InMemorySyntheticGovernmentAdapter((_snapshot(),))
        with self.assertRaisesRegex(KeyError, "snapshot_not_found"):
            adapter.fetch_snapshot("SYNTHETIC-MISSING")
        too_many = tuple(_record_for_index(index) for index in range(MAX_REFERENCE_RECORDS + 1))
        with self.assertRaisesRegex(ValueError, "record_count_invalid"):
            _snapshot(too_many)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "synthetic_pq_tree_reference_forbidden"):
                adapter.fetch_snapshot("SYNTHETIC-FOUNDATION-0001")

    def test_adapter_snapshot_map_and_identity_are_immutable(self) -> None:
        adapter = InMemorySyntheticGovernmentAdapter((_snapshot(),))
        original = adapter.derive_snapshot_roots(
            "SYNTHETIC-FOUNDATION-0001",
            tree_kind="government_snapshot",
            tree_height=2,
        )
        with self.assertRaisesRegex(AttributeError, "immutable"):
            adapter.adapter_id = "SYNTHETIC-CHANGED"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            adapter._snapshots.clear()  # type: ignore[attr-defined]
        repeated = adapter.derive_snapshot_roots(
            "SYNTHETIC-FOUNDATION-0001",
            tree_kind="government_snapshot",
            tree_height=2,
        )
        self.assertEqual(repeated, original)

    def test_real_like_identifiers_payloads_and_boolean_version_reject(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_system_not_synthetic"):
            GovernmentReferenceRecord(
                "claim",
                "SYNTHETIC-CLAIM-0001",
                "MEDICARE-PROD",
                (CanonicalField.u64("value", 1),),
            )
        with self.assertRaisesRegex(ValueError, "fields_not_allowlisted"):
            GovernmentReferenceRecord(
                "claim",
                "SYNTHETIC-CLAIM-0001",
                "SYNTHETIC-SOURCE",
                (CanonicalField.ascii("patient_name", "Jane Doe"),),
            )
        with self.assertRaisesRegex(ValueError, "fields_not_allowlisted"):
            GovernmentReferenceRecord(
                "claim",
                "SYNTHETIC-CLAIM-0001",
                "SYNTHETIC-SOURCE",
                (CanonicalField.u64("ssn", 123_45_6789),),
            )
        with self.assertRaisesRegex(ValueError, "record_id_invalid"):
            GovernmentReferenceRecord(
                "claim",
                "SYNTHETIC-" + "A" * 55,
                "SYNTHETIC-SOURCE",
                (CanonicalField.u64("value", 1),),
            )
        with self.assertRaisesRegex(ValueError, "snapshot_version_invalid"):
            GovernmentReferenceSnapshot(
                "SYNTHETIC-FOUNDATION-0001",
                False,
                _records(),
            )

    def test_authenticated_authorization_absence_is_canonical_but_inconsistent_pairs_reject(self) -> None:
        absent = GovernmentReferenceRecord(
            "auth",
            "SYNTHETIC-AUTH-ABSENT-0001",
            "SYNTHETIC-AUTH",
            (
                CanonicalField.boolean("authorization_present", False),
                CanonicalField.ascii("authorization_reference", ""),
            ),
        )
        self.assertEqual(absent.fields[0].payload, b"\x00")
        with self.assertRaisesRegex(ValueError, "authorization_reference_inconsistent"):
            GovernmentReferenceRecord(
                "auth",
                "SYNTHETIC-AUTH-ABSENT-0001",
                "SYNTHETIC-AUTH",
                (
                    CanonicalField.boolean("authorization_present", False),
                    CanonicalField.identifier(
                        "authorization_reference", "SYNTHETIC-AUTH-0001"
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
