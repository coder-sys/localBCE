from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from gov_rules_kg.canonical_rules import (
    BLOCKER_CODES,
    BUNDLE_SCHEMA_VERSION,
    QUEUE_SCHEMA_VERSION,
    RULE_SCHEMA_VERSION,
    _candidate_blockers,
    _evidence_blockers,
    _mark_draft_duplicates,
    build_promotion_queue,
    canonical_sha256,
    detect_canonical_conflicts,
    validate_canonical_bundle,
    validate_canonical_rule,
    validate_promotion_queue,
)


REPO_WORKDIR = Path(__file__).resolve().parents[1]


class CanonicalRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.source_bytes = b"Official source fixture\nSection 1. Eligibility is active.\n"
        (self.evidence / "official-source.txt").write_bytes(self.source_bytes)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def valid_rule(self, rule_id: str = "test:eligibility", outcome_code: str = "decision.eligible") -> dict:
        return {
            "schema_version": RULE_SCHEMA_VERSION,
            "rule_id": rule_id,
            "version": "1.0.0",
            "program": "medicaid",
            "jurisdiction": {"country": "US", "level": "federal", "state": None},
            "authority": {
                "issuer": "Centers for Medicare and Medicaid Services",
                "level": "federal",
                "citation": "42 CFR 435.1",
            },
            "rule_type": "eligibility_rule",
            "conditions": {
                "op": "all",
                "conditions": [
                    {
                        "op": "compare",
                        "fact": "eligibility_active",
                        "fact_type": "boolean",
                        "operator": "eq",
                        "value": {"type": "boolean", "value": True},
                    },
                    {
                        "op": "compare",
                        "fact": "income",
                        "fact_type": "decimal",
                        "operator": "lte",
                        "value": {"type": "decimal", "value": "25000.00"},
                    },
                ],
            },
            "outcome": {
                "kind": "decision",
                "code": outcome_code,
                "parameters": {"approved": {"type": "boolean", "value": True}},
            },
            "effective_from": "2026-01-01",
            "effective_through": None,
            "source": {
                "url": "https://www.medicaid.gov/fixture",
                "citation_text": "Eligibility is active.",
                "artifact_path": "official-source.txt",
                "sha256": hashlib.sha256(self.source_bytes).hexdigest(),
            },
            "review_status": "approved",
            "legal_verification_status": "verified",
            "runtime_eligibility_status": "shadow_only",
        }

    def test_valid_rule_uses_exact_evidence_bytes_and_is_deterministic(self) -> None:
        rule = self.valid_rule()
        self.assertEqual(validate_canonical_rule(rule, self.evidence), [])
        self.assertEqual(canonical_sha256(rule), canonical_sha256(json.loads(json.dumps(rule))))

    def test_typed_values_cover_supported_fact_types(self) -> None:
        cases = [
            ("boolean", {"type": "boolean", "value": True}, "eq"),
            ("integer", {"type": "integer", "value": 18}, "gte"),
            ("decimal", {"type": "decimal", "value": "1.25"}, "lte"),
            ("string", {"type": "string", "value": "active"}, "eq"),
            ("date", {"type": "date", "value": "2026-01-01"}, "on_or_after"),
            (
                "list",
                {"type": "string", "value": "active"},
                "contains",
            ),
        ]
        for fact_type, value, operator in cases:
            with self.subTest(fact_type=fact_type):
                rule = self.valid_rule()
                rule["conditions"] = {
                    "op": "compare",
                    "fact": f"sample_{fact_type}",
                    "fact_type": fact_type,
                    "operator": operator,
                    "value": value,
                }
                self.assertEqual(validate_canonical_rule(rule, self.evidence), [])

    def test_typed_values_reject_wrong_string_and_membership_types(self) -> None:
        rule = self.valid_rule()
        rule["conditions"] = {
            "op": "compare",
            "fact": "status",
            "fact_type": "string",
            "operator": "eq",
            "value": {"type": "string", "value": 7},
        }
        self.assertTrue(
            any("non-empty string" in error for error in validate_canonical_rule(rule, self.evidence))
        )

        rule = self.valid_rule()
        rule["conditions"] = {
            "op": "compare",
            "fact": "age",
            "fact_type": "integer",
            "operator": "in",
            "value": {
                "type": "list",
                "value": [{"type": "string", "value": "18"}],
            },
        }
        self.assertTrue(
            any("member type must match" in error for error in validate_canonical_rule(rule, self.evidence))
        )

    def test_missing_provenance_and_evidence_are_rejected(self) -> None:
        rule = self.valid_rule()
        rule["source"]["citation_text"] = ""
        rule["source"]["artifact_path"] = "missing.txt"
        rule["source"]["sha256"] = ""
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertTrue(any("citation_text" in error for error in errors))
        self.assertTrue(any("artifact_path does not exist" in error for error in errors))
        self.assertTrue(any("source.sha256" in error for error in errors))

    def test_source_hash_mismatch_and_path_escape_are_rejected(self) -> None:
        rule = self.valid_rule()
        rule["source"]["sha256"] = "0" * 64
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertIn("source.sha256 does not match exact evidence bytes", errors)
        rule = self.valid_rule()
        rule["source"]["artifact_path"] = "../outside.txt"
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertTrue(any("safe relative evidence path" in error for error in errors))

    def test_unsupported_operator_and_free_text_condition_are_rejected(self) -> None:
        rule = self.valid_rule()
        rule["conditions"] = {
            "op": "compare",
            "fact": "income",
            "fact_type": "decimal",
            "operator": "approximately",
            "value": {"type": "decimal", "value": "100"},
            "condition_text": "income should usually be low",
        }
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertTrue(any("unsupported fields" in error for error in errors))
        self.assertTrue(any("operator is unsupported" in error for error in errors))

    def test_invalid_effective_dates_are_rejected(self) -> None:
        rule = self.valid_rule()
        rule["effective_from"] = "January 1, 2026"
        rule["effective_through"] = "2025-12-31"
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertTrue(any("effective_from" in error for error in errors))
        rule = self.valid_rule()
        rule["effective_through"] = "2025-12-31"
        self.assertIn("effective_through cannot precede effective_from", validate_canonical_rule(rule, self.evidence))

    def test_unverified_runtime_promotion_is_rejected(self) -> None:
        rule = self.valid_rule()
        rule["runtime_eligibility_status"] = "eligible"
        rule["review_status"] = "machine_reviewed"
        rule["legal_verification_status"] = "not_verified"
        errors = validate_canonical_rule(rule, self.evidence)
        self.assertIn("runtime eligibility is forbidden before Phase R5", errors)
        self.assertIn("runtime promotion requires approved review and legal verification", errors)

    def test_conflicting_duplicate_rules_are_rejected(self) -> None:
        left = self.valid_rule("test:left", "decision.eligible")
        right = self.valid_rule("test:right", "decision.ineligible")
        conflicts = detect_canonical_conflicts([left, right])
        self.assertEqual(len(conflicts), 1)
        bundle = {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "bundle_id": "test:bundle",
            "runtime_activation": False,
            "proof_binding": False,
            "rules": [left, right],
        }
        bundle["rules_sha256"] = canonical_sha256(bundle["rules"])
        errors = validate_canonical_bundle(bundle, self.evidence)
        self.assertTrue(any("conflicting duplicate rules" in error for error in errors))

    def test_non_overlapping_versions_do_not_conflict(self) -> None:
        left = self.valid_rule("test:left", "decision.eligible")
        left["effective_through"] = "2026-12-31"
        right = self.valid_rule("test:right", "decision.ineligible")
        right["effective_from"] = "2027-01-01"
        self.assertEqual(detect_canonical_conflicts([left, right]), [])

    def test_real_queue_covers_all_programs_and_preserves_lineage_counts(self) -> None:
        queue = build_promotion_queue(REPO_WORKDIR)
        summary = queue["summary"]
        self.assertEqual(queue["schema_version"], QUEUE_SCHEMA_VERSION)
        self.assertEqual(summary["source_candidates"], 226)
        self.assertEqual(summary["promotion_review_records"], 221)
        self.assertEqual(summary["mapping_records"], 221)
        self.assertEqual(summary["qa_pass_records"], 191)
        self.assertEqual(summary["program_count"], 51)
        self.assertEqual(summary["queue_items"], 226)
        self.assertEqual(summary["runtime_eligible"], 0)
        self.assertEqual(summary["by_blocker"]["missing_lineage"], 5)
        self.assertEqual(validate_promotion_queue(queue, REPO_WORKDIR / "evidence"), [])
        self.assertEqual(queue, build_promotion_queue(REPO_WORKDIR))

    def test_every_queue_item_is_non_runtime_and_explains_its_blockers(self) -> None:
        queue = build_promotion_queue(REPO_WORKDIR)
        seen_blockers = set()
        for item in queue["items"]:
            self.assertEqual(item["runtime_eligibility_status"], "blocked")
            self.assertEqual(item["legal_verification_status"], "not_verified")
            self.assertIsNone(item["canonical_rule"])
            self.assertTrue(item["blockers"])
            seen_blockers.update(item["blockers"])
        self.assertTrue(
            {
                "ambiguous_free_text_condition",
                "human_review_not_approved",
                "legal_not_verified",
                "missing_provenance",
                "missing_source_artifact",
            }.issubset(seen_blockers)
        )
        self.assertTrue(seen_blockers.issubset(BLOCKER_CODES))

    def test_queue_validator_rejects_hash_status_and_unknown_blocker(self) -> None:
        queue = build_promotion_queue(REPO_WORKDIR)
        invalid = copy.deepcopy(queue)
        invalid["runtime_activation"] = True
        invalid["summary"]["runtime_eligible"] = 1
        invalid["items"][0]["runtime_eligibility_status"] = "eligible"
        invalid["items"][0]["blockers"].append("unknown_blocker")
        errors = validate_promotion_queue(invalid, REPO_WORKDIR / "evidence")
        self.assertTrue(any("runtime_activation" in error for error in errors))
        self.assertTrue(any("items_sha256" in error for error in errors))
        self.assertTrue(any("unsupported codes" in error for error in errors))
        self.assertTrue(any("runtime_eligible" in error for error in errors))

    def test_candidate_blocker_rejections_cover_provenance_mapping_and_dates(self) -> None:
        candidate = {
            "source_url": "http://example.invalid/rule",
            "citation_text": "",
            "source_artifact_path": "missing.txt",
            "source_hash": "0" * 64,
        }
        mapping = {
            "operator": "approximately",
            "inputs_required": ["unknown_fact"],
            "qa_status": "qa_fail",
            "mapping_status": "incomplete_mapping",
            "effective_date": "June 3, 2024",
        }
        blockers = set(_candidate_blockers(candidate, mapping, {}, self.root))
        self.assertTrue(
            {
                "ambiguous_free_text_condition",
                "human_review_not_approved",
                "invalid_effective_date",
                "invalid_source_url",
                "legal_not_verified",
                "missing_provenance",
                "missing_source_artifact",
                "missing_typed_fact",
                "unsupported_operator",
            }.issubset(blockers)
        )

        missing_lineage = set(_candidate_blockers(candidate, None, None, self.root))
        self.assertIn("missing_lineage", missing_lineage)
        self.assertIn("missing_effective_date", missing_lineage)

        candidate["source_artifact_path"] = "official-source.txt"
        self.assertEqual(_evidence_blockers(candidate, self.root), ["source_hash_mismatch"])

    def test_draft_duplicate_rejections_distinguish_exact_semantic_and_conflicting(self) -> None:
        def item(candidate_id: str, url: str, outcome: str) -> dict:
            return {
                "candidate_id": candidate_id,
                "program": "medicaid",
                "jurisdiction": {"country": "US", "level": "federal", "state": None},
                "rule_type": "eligibility_rule",
                "source": {"url": url, "citation_text": "same", "artifact_path": None, "sha256": None},
                "draft": {
                    "condition_source_text": "Income is below the threshold.",
                    "outcome_kind_candidate": outcome,
                },
                "blockers": [],
            }

        exact = [
            item("candidate:1", "https://example.gov/rule", "decision"),
            item("candidate:2", "https://example.gov/rule", "decision"),
        ]
        _mark_draft_duplicates(exact)
        self.assertTrue(all("exact_duplicate" in entry["blockers"] for entry in exact))

        semantic = [
            item("candidate:1", "https://example.gov/rule-a", "decision"),
            item("candidate:2", "https://example.gov/rule-b", "decision"),
        ]
        _mark_draft_duplicates(semantic)
        self.assertTrue(all("semantic_duplicate" in entry["blockers"] for entry in semantic))

        conflicting = [
            item("candidate:1", "https://example.gov/rule-a", "decision"),
            item("candidate:2", "https://example.gov/rule-b", "obligation"),
        ]
        _mark_draft_duplicates(conflicting)
        self.assertTrue(all("conflicting_duplicate" in entry["blockers"] for entry in conflicting))


if __name__ == "__main__":
    unittest.main()
