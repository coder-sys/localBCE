from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from gov_rules_kg.claude_inference import ClaudeGroundedClient, ClaudeInferenceError, validate_recorded_fixture
from gov_rules_kg.canonical_rules import canonical_sha256
from gov_rules_kg.source_adapters import extract_source_text
from gov_rules_kg.scaled_corpus import (
    CLAUDE_MODEL,
    CORPUS_MILESTONES,
    INFERENCE_SCHEMA,
    all_programs,
    build_evidence_span,
    build_inference_request,
    build_release_manifest,
    build_shadow_bundle,
    build_source_snapshot,
    build_typed_rule_draft,
    candidate_id,
    draft_fingerprints,
    effective_periods_overlap,
    load_source_registry,
    program_quotas,
    quality_gate_report,
    restore_snapshot_bytes,
    segment_text,
    validate_typed_rule_draft,
    validate_inference_candidates,
)


WORKDIR = Path(__file__).resolve().parents[1]


class ScaledCorpusTests(unittest.TestCase):
    def section(self) -> dict:
        return segment_text(
            "a" * 64,
            "Section 1\nA person is eligible when income is at or below 100 percent.",
            parser_name="fixture",
        )[0]

    def candidate(self) -> dict:
        section = self.section()
        start = section["normalized_text"].index("A person")
        evidence = build_evidence_span(section, start, len(section["normalized_text"]))
        return {
            "program": "medicaid",
            "authority": {"issuer": "CMS", "citation": "42 CFR 435"},
            "rule_type": "eligibility_rule",
            "conditions": {"op": "compare", "fact": "income", "fact_type": "decimal", "operator": "lte", "value": {"type": "decimal", "value": "100"}},
            "outcome": {"kind": "decision", "code": "eligible"},
            "effective_from": "2026-01-01",
            "effective_through": None,
            "exceptions": [],
            "evidence": evidence,
        }

    def test_registry_covers_104_sources_and_all_51_programs(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.assertEqual(len(registry["sources"]), 104)
        self.assertEqual(len({item["program"] for item in registry["sources"]}), 51)
        self.assertFalse(registry["runtime_activation"])
        self.assertFalse(registry["proof_binding"])

    def test_balanced_600k_quotas_are_exact(self) -> None:
        quotas = program_quotas()
        self.assertEqual(len(quotas), 51)
        self.assertEqual(sum(quotas.values()), 600_000)
        self.assertEqual(max(quotas.values()) - min(quotas.values()), 1)
        self.assertEqual(set(quotas.values()), {11_764, 11_765})

    def test_each_release_milestone_has_balanced_quotas(self) -> None:
        for target in CORPUS_MILESTONES:
            with self.subTest(target=target):
                quotas = program_quotas(target)
                self.assertEqual(sum(quotas.values()), target)
                self.assertLessEqual(max(quotas.values()) - min(quotas.values()), 1)

    def test_snapshot_compression_round_trip_and_hash(self) -> None:
        registry = load_source_registry(WORKDIR)
        raw = b"official exact response bytes\n"
        snapshot = build_source_snapshot(
            registry["sources"][0],
            raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/plain; charset=utf-8",
        )
        self.assertEqual(snapshot["snapshot_hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(restore_snapshot_bytes(snapshot), raw)

    def test_snapshot_requires_timezone_and_nonempty_bytes(self) -> None:
        source = load_source_registry(WORKDIR)["sources"][0]
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            build_source_snapshot(source, b"", retrieved_at="2026-08-06T12:00:00Z", mime_type="text/plain")
        with self.assertRaisesRegex(ValueError, "timezone"):
            build_source_snapshot(source, b"x", retrieved_at="2026-08-06T12:00:00", mime_type="text/plain")

    def test_segmentation_and_unicode_offsets_are_deterministic(self) -> None:
        text = "Rule A\nCaf\u00e9 applicants must file.\nRule B\nAppeals are allowed."
        left = segment_text("b" * 64, text, parser_name="fixture", max_chars=35)
        right = segment_text("b" * 64, text, parser_name="fixture", max_chars=35)
        self.assertEqual(left, right)
        section = left[0]
        start = section["normalized_text"].index("Caf\u00e9")
        span = build_evidence_span(section, start, len(section["normalized_text"]))
        self.assertGreater(span["byte_end"] - span["byte_start"], span["char_end"] - span["char_start"])

    def test_html_and_xml_adapters_preserve_rule_blocks_and_tables(self) -> None:
        html = b"<html><body><h1>Eligibility</h1><p>(a) A person must file.</p><table><tr><th>Limit</th><td>100</td></tr></table><script>ignore()</script></body></html>"
        extracted_html = extract_source_text(
            html,
            mime_type="text/html",
            source_url="https://www.federalregister.gov/example",
        )
        self.assertEqual(extracted_html.parser_name, "federal_register_html")
        self.assertIn("(a) A person must file.", extracted_html.text)
        self.assertIn("Limit", extracted_html.text)
        self.assertNotIn("ignore()", extracted_html.text)

        xml = b"<ROOT><TITLE>Part 1</TITLE><SECTION><P>(b) Appeals are allowed.</P></SECTION></ROOT>"
        extracted_xml = extract_source_text(
            xml,
            mime_type="application/xml",
            source_url="https://www.ecfr.gov/api/versioner/v1/full/2026-08-06/title-42.xml",
        )
        self.assertEqual(extracted_xml.parser_name, "ecfr_xml")
        self.assertIn("(b) Appeals are allowed.", extracted_xml.text)

    def test_inference_request_is_pinned_and_fail_closed(self) -> None:
        section = self.section()
        request = build_inference_request(section, "medicaid", pass_number=1)
        self.assertEqual(request["model_version"], CLAUDE_MODEL)
        self.assertFalse(request["constraints"]["may_set_runtime_eligibility"])
        self.assertFalse(request["constraints"]["may_set_proof_binding"])
        self.assertEqual(request, build_inference_request(section, "medicaid", pass_number=1))
        with self.assertRaisesRegex(ValueError, "requires proposed"):
            build_inference_request(section, "medicaid", pass_number=2)

    def test_inference_rejects_status_injection_and_wrong_evidence(self) -> None:
        section = self.section()
        candidate = self.candidate()
        candidate["runtime_activation"] = True
        candidate["evidence"]["quote"] = "hallucinated"
        response = {"schema_version": INFERENCE_SCHEMA, "pass": 1, "candidates": [candidate]}
        errors = validate_inference_candidates(section, response, expected_pass=1)
        self.assertTrue(any("forbidden status" in error for error in errors))
        self.assertTrue(any("quote mismatch" in error for error in errors))

    def test_critique_requires_stable_candidate_id_and_structured_result(self) -> None:
        candidate = self.candidate()
        response = {"schema_version": INFERENCE_SCHEMA, "pass": 2, "candidates": [candidate]}
        errors = validate_inference_candidates(self.section(), response, expected_pass=2)
        self.assertTrue(any("candidate_id" in error for error in errors))
        self.assertTrue(any("critique result" in error for error in errors))
        candidate["candidate_id"] = "cand_" + "a" * 32
        candidate["critique"] = {"result": "accept", "findings": []}
        self.assertEqual(
            validate_inference_candidates(
                self.section(),
                {"schema_version": INFERENCE_SCHEMA, "pass": 2, "candidates": [candidate]},
                expected_pass=2,
            ),
            [],
        )

    def test_candidate_ids_are_stable_and_change_with_semantics(self) -> None:
        section = self.section()
        candidate = self.candidate()
        original = candidate_id(section, candidate)
        self.assertEqual(original, candidate_id(section, copy.deepcopy(candidate)))
        candidate["outcome"]["code"] = "ineligible"
        self.assertNotEqual(original, candidate_id(section, candidate))

    def test_grounded_candidate_becomes_nonbinding_typed_draft(self) -> None:
        section = self.section()
        payload = self.candidate()
        identifier = candidate_id(section, payload)
        record = {
            "candidate_id": identifier,
            "primary_program": "medicaid",
            "section_id": section["section_id"],
            "snapshot_hash": section["snapshot_hash"],
            "evidence_char_start": payload["evidence"]["char_start"],
            "evidence_char_end": payload["evidence"]["char_end"],
            "evidence_byte_start": payload["evidence"]["byte_start"],
            "evidence_byte_end": payload["evidence"]["byte_end"],
            "evidence_quote": payload["evidence"]["quote"],
            "evidence_hash": payload["evidence"]["evidence_hash"],
            "candidate_payload": payload,
            "canonical_url": "https://www.ecfr.gov/current/title-42",
        }
        draft = build_typed_rule_draft(record)
        self.assertEqual(validate_typed_rule_draft(draft), [])
        self.assertFalse(draft["runtime_activation"])
        self.assertFalse(draft["proof_binding"])
        draft["runtime_activation"] = True
        self.assertIn("runtime activation is forbidden before R5", validate_typed_rule_draft(draft))

    def test_duplicate_fingerprints_detect_overlapping_periods_and_outcomes(self) -> None:
        section = self.section()
        payload = self.candidate()
        record = {
            "candidate_id": candidate_id(section, payload),
            "primary_program": "medicaid",
            "section_id": section["section_id"],
            "snapshot_hash": section["snapshot_hash"],
            "evidence_char_start": payload["evidence"]["char_start"],
            "evidence_char_end": payload["evidence"]["char_end"],
            "evidence_byte_start": payload["evidence"]["byte_start"],
            "evidence_byte_end": payload["evidence"]["byte_end"],
            "evidence_quote": payload["evidence"]["quote"],
            "evidence_hash": payload["evidence"]["evidence_hash"],
            "candidate_payload": payload,
            "canonical_url": "https://www.ecfr.gov/current/title-42",
        }
        left = build_typed_rule_draft(record)
        left["effective_through"] = "2026-12-31"
        right = copy.deepcopy(left)
        right["effective_from"] = "2026-06-01"
        right["effective_through"] = "2027-01-01"
        self.assertTrue(effective_periods_overlap(left, right))
        left_hashes = draft_fingerprints(left)
        right_hashes = draft_fingerprints(right)
        self.assertNotEqual(left_hashes[1], right_hashes[1])
        self.assertEqual(left_hashes[2], right_hashes[2])
        right["effective_from"] = "2027-01-01"
        right["effective_through"] = None
        self.assertFalse(effective_periods_overlap(left, right))

    def test_claude_has_no_local_fallback_and_model_is_pinned(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ClaudeInferenceError, "no local fallback"):
                ClaudeGroundedClient()
        with self.assertRaisesRegex(ValueError, "pinned"):
            ClaudeGroundedClient(api_key="fixture", model="unversioned-model")

    def test_recorded_claude_fixture_validation(self) -> None:
        response = {"schema_version": INFERENCE_SCHEMA, "pass": 1, "candidates": [self.candidate()]}
        fixture = {"content": [{"type": "text", "text": json.dumps(response)}]}
        self.assertEqual(validate_recorded_fixture(self.section(), fixture, pass_number=1), [])
        malformed = {"content": [{"type": "text", "text": "not json"}]}
        self.assertTrue(validate_recorded_fixture(self.section(), malformed, pass_number=1))

    def test_quality_gate_requires_1020_samples_and_every_program(self) -> None:
        metrics = {
            program: {"classification_accuracy": 1.0, "sample_count": 20}
            for program in all_programs()
        }
        passing = quality_gate_report(
            candidate_count=5_100,
            sample_count=1_020,
            program_metrics=metrics,
            source_snapshot_coverage=1.0,
            citation_coverage=1.0,
            evidence_span_precision=0.99,
            typed_mapping_precision=0.98,
            program_classification_accuracy=0.95,
            silently_merged_conflicts=0,
            deterministic_rerun_match=True,
            mandatory_unsampled=0,
            two_role_sample_count=1_020,
        )
        self.assertTrue(passing["passed"])
        low_metrics = dict(metrics)
        low_metrics[all_programs()[0]] = {"classification_accuracy": 0.89, "sample_count": 19}
        failing = quality_gate_report(
            candidate_count=5_100,
            sample_count=1_019,
            program_metrics=low_metrics,
            source_snapshot_coverage=1.0,
            citation_coverage=1.0,
            evidence_span_precision=0.99,
            typed_mapping_precision=0.98,
            program_classification_accuracy=0.95,
            silently_merged_conflicts=0,
            deterministic_rerun_match=True,
            mandatory_unsampled=1,
            two_role_sample_count=1_019,
        )
        self.assertFalse(failing["passed"])
        self.assertFalse(failing["gates"]["minimum_release_sample"])
        self.assertFalse(failing["gates"]["minimum_program_accuracy"])
        self.assertFalse(failing["gates"]["minimum_20_samples_per_program"])
        self.assertFalse(failing["gates"]["two_role_gold_set"])
        self.assertFalse(failing["gates"]["all_mandatory_records_sampled"])

    def test_release_manifest_rejects_duplicates_and_stays_nonbinding(self) -> None:
        quality = {"passed": False}
        candidate = {"candidate_id": "cand_" + "1" * 32, "primary_program": all_programs()[0]}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            build_release_manifest(
                release_id="fixture",
                target_count=5_100,
                candidates=[candidate, candidate],
                source_manifest_hash="a" * 64,
                quality_report=quality,
                blocker_counts={},
                reviewer_evidence={},
            )
        release = build_release_manifest(
            release_id="fixture",
            target_count=5_100,
            candidates=[candidate],
            source_manifest_hash="a" * 64,
            quality_report=quality,
            blocker_counts={},
            reviewer_evidence={},
        )
        self.assertFalse(release["gates_passed"])
        self.assertFalse(release["runtime_activation"])
        self.assertFalse(release["proof_binding"])
        with self.assertRaisesRegex(ValueError, "fully gated"):
            build_shadow_bundle(release, [candidate])
        release["gates_passed"] = True
        release["canonical_release_hash"] = canonical_sha256(
            {key: value for key, value in release.items() if key != "canonical_release_hash"}
        )
        bundle = build_shadow_bundle(release, [candidate])
        self.assertFalse(bundle["adjudication_effect"])

    def test_migration_contract_is_postgres_only_and_concurrent_safe(self) -> None:
        sql = (WORKDIR / "migrations" / "0001_grounded_rules_corpus.sql").read_text(encoding="utf-8")
        for table in (
            "source_snapshots",
            "source_sections",
            "inference_jobs",
            "grounded_candidates",
            "reviewer_decisions",
            "corpus_releases",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", sql)
        self.assertIn("CHECK (NOT runtime_activation)", sql)
        self.assertIn("CHECK (NOT proof_binding)", sql)
        self.assertIn("review_audit_events_immutable", sql)
        self.assertIn("typed_rule_drafts_frozen_immutable", sql)
        self.assertNotIn("sqlite", sql.lower())
        store_source = (WORKDIR / "src" / "gov_rules_kg" / "postgres_corpus.py").read_text(encoding="utf-8")
        self.assertIn("FOR UPDATE SKIP LOCKED", store_source)
        self.assertIn("policy and legal reviewers must be different people", store_source)


if __name__ == "__main__":
    unittest.main()
