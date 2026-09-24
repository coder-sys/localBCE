"""Hand-derived negative cases for the standalone Continuity v7 receiver."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import unittest

from tools import continuity_successor_v7 as receiver


SCOPE = {
    "state_id": "state-test",
    "deployment_id": "deployment-test",
    "program_id": "program-test",
    "period_id": "period-test",
    "currency": "USD",
}
TABLE_NAMES = (
    "financial_identity",
    "financial_meta",
    "control_packs",
    "population_imports",
    "population_items",
    "obligations",
    "evidence",
    "payments",
    "claimed_adjustments",
    "cases",
    "determinations",
    "actions",
    "action_outbox",
    "financial_events",
    "financial_conflicts",
    "evaluations",
    "program_funding_receipts",
    "program_funding_projection",
    "population_manifests",
    "population_manifest_members",
    "population_manifest_heads",
    "population_manifest_bindings",
)
IDENTITY_DOMAIN = b"RR/FINANCIAL/IDENTITY/v1\x00"
GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v7\x00"
CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v7\x00"
EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(domain: bytes, *parts: bytes) -> bytes:
    hasher = hashlib.sha3_512(domain)
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


def blob(value: bytes) -> dict[str, str]:
    return {"hex": value.hex().upper()}


def seal(package: dict[str, object]) -> bytes:
    body = {key: value for key, value in package.items() if key != "package_digest"}
    package["package_digest"] = digest(CONTINUITY_DOMAIN, canonical(body)).hex().upper()
    return canonical(package)


def root_package() -> bytes:
    authority_digest = bytes.fromhex("A" * 128)
    identity_digest = digest(
        IDENTITY_DOMAIN,
        canonical(
            {
                "anchor_sequence": 0,
                "bound_mode": "LIVE",
                "bound_owner_id": "owner-v7",
                "provenance": "ROOT",
                "source_package_digest": bytes(64).hex().upper(),
            }
        ),
    )
    genesis = digest(
        GENESIS_DOMAIN,
        canonical(SCOPE),
        authority_digest,
        identity_digest,
    )
    tables: dict[str, object] = {name: [] for name in TABLE_NAMES}
    tables["financial_identity"] = [
        {
            "id": 1,
            "schema_version": 7,
            "provenance": "ROOT",
            "bound_mode": "LIVE",
            "bound_owner_id": "owner-v7",
            "anchor_sequence": 0,
            "anchor_head": blob(genesis),
            "genesis_head": blob(genesis),
            "source_package_digest": blob(bytes(64)),
            "identity_digest": blob(identity_digest),
        }
    ]
    tables["financial_meta"] = [
        {
            "id": 1,
            "schema_version": 7,
            "schema": "RR/FINANCIAL/OWNER/v7",
            **SCOPE,
            "sequence": 0,
            "history_head": blob(genesis),
            "continuity_epoch": 1,
            "dispatch_enabled": 0,
            "egress_enabled": 0,
            "trusted_authority_id": "synthetic-authority-v1",
            "trusted_authority_epoch": 1,
            "trusted_authority_digest": blob(authority_digest),
            "mode": "LIVE",
            "owner_id": "owner-v7",
        }
    ]
    package: dict[str, object] = {
        "schema": "RR/FINANCIAL/CONTINUITY/v7",
        "version": 7,
        "scope": dict(SCOPE),
        "authority": {
            "authority_id": "synthetic-authority-v1",
            "epoch": 1,
            "digest": authority_digest.hex().upper(),
        },
        "continuity_epoch": 1,
        "sequence": 0,
        "history_head": genesis.hex().upper(),
        "dispatch_enabled": False,
        "egress_enabled": False,
        "mode": "LIVE",
        "tables": tables,
        "package_digest": "",
    }
    return seal(package)


class ContinuitySuccessorV7Tests(unittest.TestCase):
    def test_minimal_root_reconstructs_only_an_unauthenticated_read_only_view(self) -> None:
        view = receiver.build_readonly_view(root_package(), SCOPE)

        self.assertEqual(view["schema"], "RR/FINANCIAL/CONTINUITY-SUCCESSOR/v7")
        self.assertEqual(view["verification"]["owner_history_chain_and_head"], "PASS")
        self.assertEqual(view["source"]["authentication"], "NOT_ESTABLISHED_UNSIGNED_PACKAGE")
        self.assertEqual(view["external_effects"]["status"], "UNKNOWN_FROM_CONTINUITY_PACKAGE")
        self.assertIsNone(view["proofSuiteId"])
        self.assertFalse(view["production_usable"])
        self.assertFalse(view["activation"])

    def test_wrong_version_is_rejected_even_when_outer_digest_is_recomputed(self) -> None:
        package = json.loads(root_package().decode("ascii"))
        package["version"] = 6
        package["schema"] = "RR/FINANCIAL/CONTINUITY/v6"
        with self.assertRaisesRegex(receiver.ContinuityError, "schema_version"):
            receiver.build_readonly_view(seal(package), SCOPE)

    def test_unallowlisted_table_is_rejected(self) -> None:
        package = json.loads(root_package().decode("ascii"))
        package["tables"]["unexpected_table"] = []

        with self.assertRaisesRegex(receiver.ContinuityError, "table_set"):
            receiver.build_readonly_view(seal(package), SCOPE)

    def test_event_head_mismatch_is_rejected_after_resealing_package(self) -> None:
        package = json.loads(root_package().decode("ascii"))
        tables = package["tables"]
        genesis = bytes.fromhex(package["history_head"])
        bad_head = b"\xff" * 64
        payload = {}
        payload_digest = digest(EVENT_DOMAIN, canonical(payload))
        header = struct.pack(">QQQ", 0, 1, 123)
        event_id = digest(
            EVENT_DOMAIN,
            (1).to_bytes(8, "big"),
            b"CONTROL_PACK",
            b"cp-test",
            b"CONTROL_PACK_PUBLISHED",
            header,
            payload_digest,
        )
        tables["financial_events"] = [
            {
                "event_sequence": 1,
                "event_id": blob(event_id),
                "aggregate_type": "CONTROL_PACK",
                "aggregate_id": "cp-test",
                "kind": "CONTROL_PACK_PUBLISHED",
                "before_revision": 0,
                "after_revision": 1,
                "payload_json": "{}",
                "payload_digest": blob(payload_digest),
                "previous_head": blob(genesis),
                "head": blob(bad_head),
                "committed_at_ms": 123,
            }
        ]
        package["sequence"] = 1
        package["history_head"] = bad_head.hex().upper()
        tables["financial_meta"][0]["sequence"] = 1
        tables["financial_meta"][0]["history_head"] = blob(bad_head)

        with self.assertRaisesRegex(receiver.ContinuityError, "history_head"):
            receiver.build_readonly_view(seal(package), SCOPE)

    def test_noncanonical_event_payload_text_is_rejected_with_valid_digest_and_head(self) -> None:
        package = json.loads(root_package().decode("ascii"))
        tables = package["tables"]
        genesis = bytes.fromhex(package["history_head"])
        payload_digest = digest(EVENT_DOMAIN, canonical({}))
        header = struct.pack(">QQQ", 0, 1, 123)
        event_id = digest(
            EVENT_DOMAIN,
            (1).to_bytes(8, "big"),
            b"CONTROL_PACK",
            b"cp-test",
            b"CONTROL_PACK_PUBLISHED",
            header,
            payload_digest,
        )
        head = digest(HEAD_DOMAIN, genesis, event_id, header, payload_digest)
        tables["financial_events"] = [
            {
                "event_sequence": 1,
                "event_id": blob(event_id),
                "aggregate_type": "CONTROL_PACK",
                "aggregate_id": "cp-test",
                "kind": "CONTROL_PACK_PUBLISHED",
                "before_revision": 0,
                "after_revision": 1,
                "payload_json": "{ }",
                "payload_digest": blob(payload_digest),
                "previous_head": blob(genesis),
                "head": blob(head),
                "committed_at_ms": 123,
            }
        ]
        package["sequence"] = 1
        package["history_head"] = head.hex().upper()
        tables["financial_meta"][0]["sequence"] = 1
        tables["financial_meta"][0]["history_head"] = blob(head)

        with self.assertRaisesRegex(receiver.ContinuityError, "history_payload_json_noncanonical"):
            receiver.build_readonly_view(seal(package), SCOPE)

    def test_action_payload_digest_is_recomputed(self) -> None:
        payload = {
            "action_id": "action:test",
            "obligation_id": "obligation:test",
            "determination_id": "determination:action:test",
            "kind": "OFFSET_AUTHORIZATION",
            "claim_id": "claim:test",
            "amount_cents": 1,
            "currency": "USD",
            "revision": 1,
            "input_evaluation_id": "evaluation:test:r0",
            "input_evaluation_result_digest": "A" * 128,
            "dispatch": "SYNTHETIC_RECORD_ONLY",
        }
        action = {
            "action_id": "action:test",
            "obligation_id": "obligation:test",
            "determination_id": "determination:action:test",
            "kind": "OFFSET_AUTHORIZATION",
            "status": "READY",
            "revision": 1,
            "payload_json": canonical(payload).decode("ascii"),
            "payload_digest": bytes(64),
            "idempotency_key": digest(receiver.IDEMPOTENCY_DOMAIN, b"action:test"),
            "created_at_ms": 1,
        }

        with self.assertRaisesRegex(receiver.ContinuityError, "action_payload_digest"):
            receiver._verify_action_payload(action)

    def test_evidence_content_digest_is_reconstructed_from_the_record(self) -> None:
        evidence = {
            "evidence_id": "evidence:1",
            "item_id": "item:1",
            "kind": "SUPPORTING_DOCUMENT",
            "common_origin_id": "origin:1",
            "source_id": "source:1",
            "source_version": "version:1",
            "local_ref": "ref:tampered",
            "applicable_at_ms": 1,
            "event_at_ms": 2,
            "received_at_ms": 3,
            "content_digest": blob(digest(
                receiver.EVIDENCE_DOMAIN,
                canonical({
                    "source_id": "source:1",
                    "source_version": "version:1",
                    "local_ref": "ref:original",
                    "common_origin_id": "origin:1",
                    "kind": "SUPPORTING_DOCUMENT",
                }),
            )),
            "record_digest": blob(bytes(64)),
            "amount_cents": None,
            "reversal_of": None,
            "supersedes": None,
        }
        tables = {
            "population_items": [{"item_id": "item:1"}],
            "obligations": [{"item_id": "item:1"}],
            "evidence": [evidence],
        }

        with self.assertRaisesRegex(receiver.ContinuityError, "evidence_content_digest"):
            receiver._verify_evidence_records(tables)

    def test_published_item_duplicate_detection_is_order_independent(self) -> None:
        populations = {
            "population:staged": {"status": "STAGED"},
            "population:published-1": {"status": "PUBLISHED"},
            "population:published-2": {"status": "PUBLISHED"},
        }
        item_populations: dict[str, set[str]] = {}
        receiver._check_population_item_identity(
            item_populations,
            item_id="item:1",
            population_id="population:staged",
            population_status="STAGED",
            populations=populations,
        )
        receiver._check_population_item_identity(
            item_populations,
            item_id="item:1",
            population_id="population:published-1",
            population_status="PUBLISHED",
            populations=populations,
        )

        with self.assertRaisesRegex(receiver.ContinuityError, "population_item_duplicate"):
            receiver._check_population_item_identity(
                item_populations,
                item_id="item:1",
                population_id="population:published-2",
                population_status="PUBLISHED",
                populations=populations,
            )

    def test_case_rows_must_match_the_obligation_and_current_evaluation(self) -> None:
        tables = {
            "obligations": [{
                "obligation_id": "obligation:1",
                "case_status": "OPEN",
                "current_evaluation_id": "evaluation:1",
            }],
            "cases": [{
                "case_id": "case:1",
                "obligation_id": "obligation:1",
                "reason": "shortfall",
                "contractual_accountability": "state-owned",
                "next_action_owner": "CASE_OWNER",
                "due_at_ms": 100,
                "completion_conditions_json": canonical(receiver.CASE_COMPLETION_CONDITIONS).decode("ascii"),
                "status": "RESOLVED",
                "updated_at_ms": 90,
            }],
            "actions": [],
        }
        evaluations = {"evaluation:1": {"case_status": "OPEN"}}

        with self.assertRaisesRegex(receiver.ContinuityError, "case_projection"):
            receiver._verify_cases(tables, evaluations)

    def test_orphan_manifest_member_is_rejected_after_resealing_package(self) -> None:
        package = json.loads(root_package().decode("ascii"))
        package["tables"]["population_manifest_members"] = [
            {"manifest_id": "missing-manifest", "position": 0, "member_id": "item-1"}
        ]

        with self.assertRaisesRegex(receiver.ContinuityError, "manifest_member_reference"):
            receiver.build_readonly_view(seal(package), SCOPE)

    def test_scope_mismatch_stops_before_view_creation(self) -> None:
        expected = copy.deepcopy(SCOPE)
        expected["program_id"] = "other-program"

        with self.assertRaisesRegex(receiver.ContinuityError, "scope_mismatch"):
            receiver.build_readonly_view(root_package(), expected)


if __name__ == "__main__":
    unittest.main()
