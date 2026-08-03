from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from gov_rules_kg.rules_corpus_audit import build_rules_corpus_audit, write_rules_corpus_audit


EXPECTED_RULES = [
    ("G1_IDENTITY_VERIFICATION", 10, "G1_IDENTITY_VERIFICATION_FAILED"),
    ("G2_PROGRAM_ELIGIBILITY", 20, "G2_PROGRAM_ELIGIBILITY_FAILED"),
    ("G2_BENEFIT_LEVEL", 30, "G2_BENEFIT_LEVEL_MISSING"),
    ("G3_MONTH_OF_SERVICE", 40, "G3_MONTH_OF_SERVICE_FAILED"),
    ("G4_SHARE_OF_COST", 50, "G4_SHARE_OF_COST_FAILED"),
    ("G5_PROVIDER_ENROLLMENT", 60, "G5_PROVIDER_NOT_ENROLLED"),
    ("G5_PROVIDER_TYPE", 70, "G5_PROVIDER_TYPE_INVALID"),
    ("G6_BILLING_CODE", 80, "G6_BILLING_CODE_INVALID"),
    ("G6_UNITS", 90, "G6_UNITS_INVALID"),
    ("G7_DUPLICATE", 100, "G7_DUPLICATE_CLAIM"),
    ("G8_DISABILITY", 110, "G8_DISABILITY_DETERMINATION_FAILED"),
    ("G9_RECIPIENT_LIFE_STATUS", 120, "G9_RECIPIENT_DECEASED"),
    ("G10_PHYSICIAN_CERTIFICATION", 130, "G10_PHYSICIAN_CERTIFICATION_FAILED"),
]


class RulesCorpusAuditTests(unittest.TestCase):
    def _write_json(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def _fixture(self, root: Path) -> Path:
        workdir = root / "gov-rules-kg-prototype"
        reports = workdir / "reports"
        rust = root / "rust-engine"
        rules = [
            {"id": rule_id, "priority": priority, "denial_reason": reason, "condition": {"op": "not_equal", "field": "x", "value": 1}}
            for rule_id, priority, reason in EXPECTED_RULES
        ]
        rules_hash = hashlib.sha256(json.dumps(rules, separators=(",", ":")).encode()).hexdigest()
        self._write_json(
            rust / "rules_active_v1.json",
            {"rules_sha256": rules_hash, "rules": rules},
        )
        expected_source = ",\n".join(
            f'    ("{rule_id}", {priority}, "{reason}")' for rule_id, priority, reason in EXPECTED_RULES
        )
        source = f'''pub const CURRENT_RULESET_SHA256: &str =\n    "{rules_hash}";
const EXPECTED_RULES: [(&str, u32, &str); 13] = [
{expected_source}
];
#[cfg(test)]
mod tests {{}}
'''
        (rust / "src").mkdir(parents=True)
        (rust / "src" / "rules_engine.rs").write_text(source, encoding="utf-8")
        self._write_json(rust / "config.json", {"proof_backend": "groth16"})
        reference = {
            "_meta": {"version": "test"},
            "L2_ELIGIBILITY_PROOF": {"gates": {"a": {}}},
            "L3_PROVIDER_ENROLLMENT": {"gates": {"b": {}}},
            "L4_CLAIMS_TAR_ADJUDICATION": {"adjudication_edits": {"c": {}}},
            "L5_APPEAL_EXCEPTION": {"tracks": {"d": {}}},
        }
        self._write_json(rust / "rules.json", reference)
        self._write_json(rust / "rules_v9.json", reference)

        legacy = [
            {"rule_id": "legacy:1", "program": "medicaid", "source_url": "https://example.gov/a", "citation": "42 CFR 1", "exact_source_text": "same"},
            {"rule_id": "legacy:2", "program": "medicaid", "source_url": "https://example.gov/b", "citation": "42 CFR 2", "exact_source_text": "same"},
        ]
        self._write_json(reports / "rules_by_program.json", {"medicaid": legacy})
        self._write_json(reports / "rule_inventory.json", {"total_graph_atomic_rules": 2})
        self._write_json(reports / "verified_rules_summary.json", {"total_rules_in_graph": 3})
        verified = {
            "root": [
                {"rule_id": "verified:1", "path": {"program": "medicaid"}, "source_url": "https://example.gov/a", "citation": "42 CFR 1", "statement": "same"},
                {"rule_id": "verified:2", "path": {"program": "medicaid"}, "source_url": "https://example.gov/b", "citation": "42 CFR 2", "statement": "same"},
            ]
        }
        self._write_json(reports / "verified_rules_clean_full_hierarchy.json", verified)

        raw = [
            {"candidate_id": "c1", "program": "p1", "source_url": "https://one.gov", "citation_text": "one", "statement": "one"},
            {"candidate_id": "c2", "program": "p1", "source_url": "https://two.gov", "citation_text": "two", "statement": "two"},
            {"candidate_id": "c3", "program": "p2", "source_url": "https://three.gov", "citation_text": "three", "statement": "three"},
        ]
        self._write_json(reports / "claude_web_candidate_corpus.json", {"candidate_rules": raw})
        self._write_json(reports / "claude_web_promotion_ready.json", raw[:2])
        executable = [
            {"source_candidate_id": item["candidate_id"], "program": item["program"], "source_url": item["source_url"], "citation_text": item["citation_text"], "normalized_condition": item["statement"], "outcome_text": "review"}
            for item in raw[:2]
        ]
        self._write_json(reports / "claude_web_executable_rule_candidates.json", executable)
        self._write_json(reports / "claude_web_deterministic_mapping_candidates.json", executable)
        shadow = [{**executable[0], "rule_id": "shadow:1", "runtime_compatible": False, "proof_bound": False}]
        self._write_json(reports / "claude_web_rust_shadow_rules.json", {"rules": shadow})
        self._write_json(reports / "executable_rule_candidates.json", [{"rule_id": "old:1", "candidate_only": True}])

        app = root / "blind-ledger-app-layer" / "rules-engine-rust" / "src"
        app.mkdir(parents=True)
        (app / "lib.rs").write_text(
            'gate("G1_ONE", true, ""); gate("G2_TWO", true, "");', encoding="utf-8"
        )
        return workdir

    def test_inventory_preserves_runtime_boundary_and_surfaces_lineage_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._fixture(Path(temp))
            audit = build_rules_corpus_audit(workdir)
            entries = {entry["corpus_id"]: entry for entry in audit["corpora"]}

            self.assertFalse(audit["sqlite_pipeline_used"])
            self.assertTrue(audit["active_rules_parity"]["exact_g1_g10_parity"])
            self.assertTrue(audit["active_rules_parity"]["hardcoded_default_preserved"])
            self.assertEqual(entries["active_g1_g10_v1"]["classification"], "active_runtime")
            self.assertEqual(entries["claude_web_deterministic_mapping_candidates"]["classification"], "deterministic_candidate")
            self.assertEqual(entries["claude_web_rust_shadow_bundle"]["classification"], "shadow_only")
            self.assertEqual(entries["reported_cofounder_457k_rules"]["inventory_status"], "not_present")
            self.assertEqual(audit["lineage"]["claude_web"]["missing_candidate_ids"], ["c3"])
            finding_ids = {finding["finding_id"] for finding in audit["serious_findings"]}
            self.assertIn("legacy_report_count_mismatch", finding_ids)
            self.assertIn("reported_457k_corpus_missing", finding_ids)

    def test_inventory_reports_duplicate_and_provenance_counts_and_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._fixture(Path(temp))
            summary = write_rules_corpus_audit(workdir)
            audit = json.loads((workdir / "reports" / "rules_corpus_inventory.json").read_text(encoding="utf-8"))
            entries = {entry["corpus_id"]: entry for entry in audit["corpora"]}
            legacy = entries["legacy_graph_rule_export"]

            self.assertEqual(legacy["record_count"], 2)
            self.assertEqual(legacy["program_coverage"]["program_count"], 1)
            self.assertEqual(legacy["provenance_coverage"]["source_url"]["present"], 2)
            self.assertEqual(legacy["provenance_coverage"]["source_hash"]["missing"], 2)
            self.assertEqual(legacy["duplicate_counts"]["normalized_content"]["duplicate_excess_records"], 1)
            self.assertTrue(summary["exact_g1_g10_parity"])
            self.assertTrue((workdir / "reports" / "rules_corpus_inventory.md").exists())


if __name__ == "__main__":
    unittest.main()
