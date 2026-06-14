from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from gov_rules_kg.ai import (
    AIOptions,
    AIProviderError,
    build_review_required_rule,
    evidence_matches_source,
    normalize_claude_rules,
    organize_atomic_rules,
    validate_ai_provider,
)
from gov_rules_kg.agent_discovery import PROGRAM_OFFICIAL_ENTRYPOINTS, build_deterministic_discovery_plan, build_official_source_pack, clean_search_result_url, extract_discovery_payload_from_content, extract_href_values, normalize_discovery_branches, source_allowed, write_official_source_pack
from gov_rules_kg.citations import citations_exactly_match, parse_citations
from gov_rules_kg.claude_web_research import RESEARCH_MODE, ClaudeWebResearchOptions, call_claude_web_search_batches, deterministic_web_research_plan, extract_web_research_payload, should_preserve_existing_report, write_claude_web_research
from gov_rules_kg.claude_web_review import review_claude_web_candidates, review_candidate
from gov_rules_kg.domain import classify_family_and_type, classify_government_hierarchy, infer_jurisdiction, valid_vertical
from gov_rules_kg.extract import extract_text
from gov_rules_kg.hierarchy_plan import PLAN_MODE, build_deterministic_hierarchy_plan, write_ai_hierarchy_plan
from gov_rules_kg.merge_gate import legal_citations_can_merge
from gov_rules_kg.reports import build_full_verified_hierarchy, build_programmatic_proof_report, build_rule_inventory_from_rules, build_verified_rules_by_hierarchy, clean_verified_rule, group_by_hierarchy, normalize_rule_record, prioritize_sample_rules, reclassify_verified_rules_for_export, verified_rules
from gov_rules_kg.config import load_source_manifest, make_config
from gov_rules_kg.scale import build_scale_playbook, write_ecfr_manifest


class LegalGradeFoundationTests(unittest.TestCase):
    def test_claude_selected_without_key_fails_loudly(self) -> None:
        previous_claude = os.environ.pop("CLAUDE_API_KEY", None)
        previous_anthropic = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(AIProviderError):
                validate_ai_provider(AIOptions(provider="claude", claude_model="claude-sonnet-4-6"))
        finally:
            if previous_claude:
                os.environ["CLAUDE_API_KEY"] = previous_claude
            if previous_anthropic:
                os.environ["ANTHROPIC_API_KEY"] = previous_anthropic

    def test_local_stub_requires_explicit_allowance(self) -> None:
        with self.assertRaises(AIProviderError):
            validate_ai_provider(AIOptions(provider="local", allow_local_stub=False))
        usage = validate_ai_provider(AIOptions(provider="local", allow_local_stub=True))
        self.assertEqual(usage.provider_used, "local_stub")
        self.assertTrue(usage.fallback_used)

    def test_cfr_parts_must_not_fuzzy_merge(self) -> None:
        self.assertFalse(legal_citations_can_merge("45 CFR Part 160", "45 CFR Part 164"))
        self.assertFalse(legal_citations_can_merge("42 CFR Part 2", "42 CFR Part 5"))
        self.assertFalse(legal_citations_can_merge("21 CFR Part 1306", "21 CFR Part 1316"))

    def test_state_code_sections_must_not_merge(self) -> None:
        self.assertFalse(legal_citations_can_merge("California WIC § 14000", "California WIC § 14100"))

    def test_exact_citation_match_requires_all_fields(self) -> None:
        left = parse_citations("42 CFR § 435.911(a)(1)")[0]
        right = parse_citations("42 CFR § 435.911(a)(1)")[0]
        different = parse_citations("42 CFR § 435.912(a)(1)")[0]
        self.assertTrue(citations_exactly_match(left, right))
        self.assertFalse(citations_exactly_match(left, different))

    def test_federal_rules_have_no_state_code(self) -> None:
        jurisdiction, state_code = infer_jurisdiction("https://www.ecfr.gov/api/versioner/v1/full/2026-06-10/title-42.xml", "Medicaid")
        self.assertEqual(jurisdiction, "federal")
        self.assertIsNone(state_code)

    def test_state_rules_have_state_code(self) -> None:
        jurisdiction, state_code = infer_jurisdiction("https://www.dhcs.ca.gov/formsandpubs/Pages/AllPlanLetters.aspx", "Medi-Cal")
        self.assertEqual(jurisdiction, "state")
        self.assertEqual(state_code, "CA")

    def test_texas_rules_do_not_become_california_space(self) -> None:
        jurisdiction, state_code = infer_jurisdiction("https://example.tx.gov/medicaid", "Texas Medicaid")
        self.assertEqual(jurisdiction, "state")
        self.assertEqual(state_code, "TX")

    def test_may_not_classifies_as_prohibition(self) -> None:
        family, rule_type, _ = classify_family_and_type("The provider may not bill the beneficiary for covered services.")
        self.assertEqual(rule_type, "prohibition")
        self.assertEqual(family, "claims")

    def test_must_submit_report_classifies_reporting_obligation(self) -> None:
        family, rule_type, _ = classify_family_and_type("The agency must submit a report to CMS within 30 days.")
        self.assertEqual(family, "reporting")
        self.assertEqual(rule_type, "obligation")

    def test_definition_with_shall_not_treated_as_prohibition(self) -> None:
        _, rule_type, _ = classify_family_and_type("The agency shall not treat this definition as creating eligibility.")
        self.assertEqual(rule_type, "prohibition")

    def test_government_hierarchy_classifies_medicaid_and_snap(self) -> None:
        medicaid = classify_government_hierarchy("The state Medicaid agency must determine eligibility.")
        snap = classify_government_hierarchy("SNAP households must report income changes.")
        self.assertEqual(medicaid["vertical"], "healthcare_benefits")
        self.assertEqual(medicaid["program"], "medicaid")
        self.assertEqual(snap["vertical"], "food_nutrition_benefits")
        self.assertEqual(snap["program"], "snap")
        self.assertEqual(valid_vertical("government_transaction_rules/cash_income_benefits"), "cash_income_benefits")

    def test_rules_group_into_broad_hierarchy(self) -> None:
        grouped = group_by_hierarchy(
            [
                {
                    "domain": "government_transaction_rules",
                    "vertical": "food_nutrition_benefits",
                    "program": "snap",
                    "jurisdiction_level": "federal",
                    "source_type": "regulation",
                    "rule_unit_type": "eligibility_rule",
                    "normalized_rule": "SNAP households must report income changes.",
                }
            ]
        )
        rules = grouped["government_transaction_rules"]["food_nutrition_benefits"]["snap"]["federal"]["regulation"]["eligibility_rule"]
        self.assertEqual(len(rules), 1)

    def test_agent_discovery_policy_allows_official_sources_only(self) -> None:
        self.assertTrue(source_allowed("https://www.cms.gov/medicaid/rules", official_only=True)[0])
        self.assertTrue(source_allowed("https://www.ssa.gov/OP_Home/rulings", official_only=True)[0])
        self.assertFalse(source_allowed("https://example.com/random-rules", official_only=True)[0])

    def test_agent_discovery_has_curated_official_entrypoints(self) -> None:
        self.assertIn("medicaid", PROGRAM_OFFICIAL_ENTRYPOINTS)
        self.assertIn("snap", PROGRAM_OFFICIAL_ENTRYPOINTS)
        self.assertTrue(any("cms.gov" in url or "medicaid.gov" in url for url in PROGRAM_OFFICIAL_ENTRYPOINTS["medicaid"]))

    def test_official_source_pack_covers_full_taxonomy_without_crawling(self) -> None:
        pack = build_official_source_pack()
        self.assertEqual(pack["taxonomy_programs_total"], 51)
        self.assertEqual(pack["programs_without_sources"], [])
        self.assertGreater(pack["source_count"], pack["taxonomy_programs_total"])
        self.assertEqual(pack["discovery_method"], "curated_official_entrypoints_no_recursive_crawl_no_search")
        self.assertTrue(all(source["official"] for source in pack["sources"]))
        programs = {source["program"] for source in pack["sources"]}
        self.assertIn("medicaid", programs)
        self.assertIn("snap", programs)
        self.assertIn("due_process", programs)

    def test_official_source_pack_writes_manifest_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            result = write_official_source_pack(workdir, Path("data/source_manifests/official_source_pack.json"), max_sources_per_program=1)
            sources = load_source_manifest(Path(result["manifest"]))
            commands = (workdir / "reports" / "official_source_pack_commands.md").read_text(encoding="utf-8")
        self.assertEqual(result["verdict"], "OFFICIAL_SOURCE_PACK_READY")
        self.assertEqual(result["taxonomy_programs_total"], 51)
        self.assertEqual(len(sources), 51)
        self.assertTrue(all(source.discovery_seed for source in sources))
        self.assertIn("--document-parser no-bs4", commands)

    def test_ai_hierarchy_plan_is_planning_only_and_covers_taxonomy(self) -> None:
        plan = build_deterministic_hierarchy_plan()
        self.assertEqual(plan["mode"], PLAN_MODE)
        self.assertEqual(plan["branch_count"], 51)
        self.assertTrue(plan["verification_contract"]["not_verified_in_plan"])
        self.assertIn("Do not mark AI-memory output as verified.", plan["verification_contract"]["forbidden"])
        programs = {branch["program"] for branch in plan["branches"]}
        self.assertIn("medicaid", programs)
        self.assertIn("snap", programs)
        self.assertIn("fraud_abuse", programs)

    def test_ai_hierarchy_plan_writes_reports_without_fetching(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = write_ai_hierarchy_plan(
                Path(tmpdir),
                AIOptions(provider="local", allow_local_stub=True),
            )
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")
        self.assertEqual(result["verdict"], "AI_HIERARCHY_PLAN_READY")
        self.assertEqual(result["mode"], PLAN_MODE)
        self.assertEqual(result["branch_count"], 51)
        self.assertIn("This plan does not create verified rules", markdown)

    def test_claude_web_research_stub_is_no_local_fetch_mode(self) -> None:
        report = deterministic_web_research_plan(
            ClaudeWebResearchOptions(
                ai_options=AIOptions(provider="local", allow_local_stub=True),
                max_branches=3,
                max_uses=2,
                max_candidates_per_branch=2,
                allowed_domains=["cms.gov"],
            )
        )
        self.assertEqual(report["mode"], RESEARCH_MODE)
        self.assertEqual(report["provider_used"], "local_stub")
        self.assertEqual(report["branch_count"], 3)
        self.assertEqual(report["allowed_domains"], ["cms.gov"])
        self.assertEqual(report["candidate_rules"], [])
        self.assertIn("No local fetching", report["claim"])

    def test_claude_web_research_writes_planning_report_without_local_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = write_claude_web_research(
                Path(tmpdir),
                ClaudeWebResearchOptions(
                    ai_options=AIOptions(provider="local", allow_local_stub=True),
                    max_branches=2,
                    max_uses=1,
                ),
            )
            markdown = Path(result["markdown"]).read_text(encoding="utf-8")
        self.assertEqual(result["verdict"], "CLAUDE_WEB_RESEARCH_READY")
        self.assertEqual(result["mode"], RESEARCH_MODE)
        self.assertEqual(result["provider_used"], "local_stub")
        self.assertIn("did not fetch URLs, parse HTML, crawl links, or use bs4", markdown)

    def test_claude_web_research_parses_json_text_after_web_search(self) -> None:
        payload = extract_web_research_payload(
            [
                {
                    "type": "text",
                    "text": '{"candidate_rules":[{"statement":"States must submit Medicaid state plan amendments.","source_url":"https://www.medicaid.gov/","program":"medicaid"}],"coverage_notes":["searched official sources"]}',
                }
            ]
        )
        self.assertEqual(payload["candidate_rules"][0]["program"], "medicaid")
        self.assertEqual(payload["coverage_notes"], ["searched official sources"])

    def test_claude_web_research_parses_fenced_json_text(self) -> None:
        payload = extract_web_research_payload(
            [
                {
                    "type": "text",
                    "text": '```json\n{"candidate_rules":[{"statement":"MAGI is used for Medicaid eligibility.","source_url":"https://www.medicaid.gov/medicaid/eligibility-policy","program":"medicaid"}],"coverage_notes":[]}\n```',
                }
            ]
        )
        self.assertEqual(payload["candidate_rules"][0]["source_url"], "https://www.medicaid.gov/medicaid/eligibility-policy")

    def test_claude_web_research_salvages_complete_rules_from_partial_json(self) -> None:
        payload = extract_web_research_payload(
            [
                {
                    "type": "text",
                    "text": '''```json
{
  "candidate_rules": [
    {"statement":"Rule one.","source_url":"https://www.medicaid.gov/","program":"medicaid"},
    {"statement":"Rule two.","source_url":"https://www.cms.gov/","program":"medicare"},
    {"statement":"Rule three.","source_url":"https://www.medicaid.gov/","program":"chip"
''',
                }
            ]
        )
        self.assertEqual(len(payload["candidate_rules"]), 2)
        self.assertIn("salvaged 2 complete", payload["coverage_notes"][0])

    def test_claude_web_research_batch_failures_return_partial_report(self) -> None:
        options = ClaudeWebResearchOptions(
            ai_options=AIOptions(provider="claude", claude_model="claude-sonnet-4-6"),
            batch_size=1,
        )
        branches = [
            {"program": "medicaid", "vertical": "healthcare_benefits"},
            {"program": "medicare", "vertical": "healthcare_benefits"},
        ]
        original = __import__("gov_rules_kg.claude_web_research", fromlist=["call_claude_web_search_batch"])

        def fake_batch(_options, batch, _allowed_domains, batch_index):
            if batch_index == 2:
                raise AIProviderError("timeout")
            return {
                "candidate_rules": [{"statement": "Rule", "source_url": "https://www.medicaid.gov/"}],
                "coverage_notes": ["ok"],
                "raw_usage": {"web_search_requests": 1},
            }

        previous = original.call_claude_web_search_batch
        original.call_claude_web_search_batch = fake_batch
        try:
            report = call_claude_web_search_batches(options, branches, ["medicaid.gov"], batch_size=1)
        finally:
            original.call_claude_web_search_batch = previous
        self.assertEqual(report["candidate_rule_count"], 1)
        self.assertEqual(len(report["failed_batches"]), 1)
        self.assertIn("timeout", report["failed_batches"][0]["error"])

    def test_claude_web_research_preserves_existing_report_after_empty_failed_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "claude_web_research.json"
            path.write_text(
                '{"candidate_rule_count": 3, "mode": "claude_server_web_search_no_local_fetch_no_local_parse", "provider_used": "claude_web_search"}',
                encoding="utf-8",
            )
            failed_report = {"candidate_rule_count": 0, "failed_batches": [{"batch_index": 1}]}
            self.assertTrue(should_preserve_existing_report(failed_report, path))

    def test_claude_web_review_marks_clean_candidate_promotion_ready(self) -> None:
        reviewed = review_candidate(
            {
                "domain": "government_transaction_rules",
                "vertical": "healthcare_benefits",
                "program": "medicaid",
                "jurisdiction_level": "federal",
                "source_type": "agency_guidance",
                "rule_unit_type": "eligibility_rule",
                "statement": "Medicaid financial eligibility for most children and adults is determined using MAGI methodology.",
                "source_url": "https://www.medicaid.gov/medicaid/eligibility-policy",
                "citation_text": "MAGI is the basis for determining Medicaid income eligibility for most children, pregnant women, parents, and adults.",
                "confidence_score": 0.96,
            },
            0.85,
        )
        self.assertEqual(reviewed["review_status"], "promotion_ready")
        self.assertEqual(reviewed["review_issues"], [])
        self.assertEqual(reviewed["promotion_status"], "candidate_only_not_verified")

    def test_claude_web_review_accepts_enrollment_rule_unit_type(self) -> None:
        reviewed = review_candidate(
            {
                "domain": "government_transaction_rules",
                "vertical": "healthcare_benefits",
                "program": "medicare",
                "jurisdiction_level": "federal",
                "source_type": "agency_guidance",
                "rule_unit_type": "enrollment_rule",
                "statement": "Individuals already receiving Social Security benefits may be automatically enrolled in Medicare Part A and Part B.",
                "source_url": "https://www.cms.gov/medicare/enrollment-renewal/original-part-a-b",
                "citation_text": "Individuals already receiving Social Security or RRB benefits are automatically enrolled in both premium-free Part A and Part B.",
                "confidence_score": 0.96,
            },
            0.85,
        )
        self.assertEqual(reviewed["review_status"], "promotion_ready")

    def test_claude_web_review_writes_review_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            reports_dir = workdir / "reports"
            reports_dir.mkdir()
            (reports_dir / "claude_web_research.json").write_text(
                '{"candidate_rules":[{"domain":"government_transaction_rules","vertical":"healthcare_benefits","program":"medicaid","jurisdiction_level":"federal","source_type":"agency_guidance","rule_unit_type":"eligibility_rule","statement":"Medicaid financial eligibility for most children and adults is determined using MAGI methodology.","source_url":"https://www.medicaid.gov/medicaid/eligibility-policy","citation_text":"MAGI is the basis for determining Medicaid income eligibility for most children, pregnant women, parents, and adults.","confidence_score":0.96}]}',
                encoding="utf-8",
            )
            result = review_claude_web_candidates(workdir)
        self.assertEqual(result["verdict"], "CLAUDE_WEB_REVIEW_READY")
        self.assertEqual(result["summary"]["promotion_ready_candidates"], 1)
        self.assertEqual(result["summary"]["human_review_required"], 0)

    def test_agent_discovery_plan_covers_multiple_hierarchy_branches(self) -> None:
        plan = build_deterministic_discovery_plan(max_branches=0, queries_per_branch=2)
        programs = {branch.program for branch in plan}
        self.assertIn("medicaid", programs)
        self.assertIn("snap", programs)
        self.assertIn("visas", programs)
        self.assertTrue(all(len(branch.queries) == 2 for branch in plan))

    def test_agent_discovery_accepts_human_taxonomy_labels(self) -> None:
        branches = normalize_discovery_branches(
            [
                {
                    "vertical": "Healthcare Benefits",
                    "program": "Medicaid",
                    "queries": ["Medicaid regulations official"],
                    "preferred_hosts": ["CMS.gov"],
                },
                {
                    "vertical": "Food / Nutrition Benefits",
                    "program": "SNAP",
                    "queries": ["SNAP rules official"],
                    "preferred_hosts": ["fns.usda.gov"],
                },
            ],
            queries_per_branch=1,
        )
        self.assertEqual(branches[0].vertical, "healthcare_benefits")
        self.assertEqual(branches[0].program, "medicaid")
        self.assertEqual(branches[1].vertical, "food_nutrition_benefits")
        self.assertEqual(branches[1].program, "snap")

    def test_duckduckgo_redirect_url_is_cleaned(self) -> None:
        cleaned = clean_search_result_url("/l/?uddg=https%3A%2F%2Fwww.cms.gov%2Fmedicaid")
        self.assertEqual(cleaned, "https://www.cms.gov/medicaid")

    def test_agent_search_extracts_links_without_bs4(self) -> None:
        links = extract_href_values('<a class="result__a" href="/l/?uddg=https%3A%2F%2Fwww.cms.gov%2Fmedicaid">CMS</a>')
        self.assertEqual(links, ["/l/?uddg=https%3A%2F%2Fwww.cms.gov%2Fmedicaid"])

    def test_agent_discovery_parses_claude_tool_payload(self) -> None:
        payload = extract_discovery_payload_from_content(
            [
                {
                    "type": "tool_use",
                    "name": "emit_discovery_plan",
                    "input": {
                        "branches": [
                            {
                                "vertical": "healthcare_benefits",
                                "program": "medicaid",
                                "queries": ["Medicaid rules official site:.gov"],
                                "preferred_hosts": ["cms.gov"],
                            }
                        ]
                    },
                }
            ]
        )
        self.assertEqual(payload["branches"][0]["program"], "medicaid")

    def test_claude_string_rule_is_accepted(self) -> None:
        rules = normalize_claude_rules(
            {"rules": ["The agency must submit a report to CMS within 30 days."]},
            "Reporting",
            "https://example.gov/rule",
            "claude-sonnet-4-6",
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["mode"], "claude")
        self.assertIn("reporting", rules[0]["rule_types"])

    def test_claude_empty_rules_become_review_required_rule(self) -> None:
        rules = build_review_required_rule(
            "Eligibility",
            "The agency must determine eligibility within 45 days unless the application is based on disability.",
            "https://example.gov/rule",
            "Claude returned no usable atomic rules for this section.",
            "claude_empty_review_required",
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["mode"], "claude_empty_review_required")
        self.assertTrue(rules[0]["human_review_required"])
        self.assertIn("must determine eligibility", rules[0]["statement"])

    def test_claude_evidence_must_match_provided_source_text(self) -> None:
        self.assertTrue(evidence_matches_source("The agency must determine eligibility.", "Section 1. The agency must determine eligibility."))
        rules = normalize_claude_rules(
            {
                "rules": [
                    {
                        "statement": "The agency must approve all applicants.",
                        "rule_types": ["eligibility"],
                        "confidence": 0.95,
                        "evidence": "The agency must approve all applicants.",
                    }
                ]
            },
            "Eligibility",
            "https://example.gov/rule",
            "claude-sonnet-4-6",
            "The agency must determine eligibility within 45 days.",
        )
        self.assertTrue(rules[0]["human_review_required"])
        self.assertLessEqual(rules[0]["confidence"], 0.65)

    def test_claude_cap_does_not_crash_when_local_stub_disallowed(self) -> None:
        previous_claude = os.environ.get("CLAUDE_API_KEY")
        os.environ["CLAUDE_API_KEY"] = "test-key"
        try:
            rules = organize_atomic_rules(
                "Eligibility",
                "The agency must determine eligibility within 45 days.",
                "https://example.gov/rule",
                AIOptions(
                    provider="claude",
                    claude_model="claude-sonnet-4-6",
                    claude_max_sections=1,
                    allow_local_stub=False,
                    fail_on_ai_fallback=True,
                ),
                section_index=1,
            )
        finally:
            if previous_claude is None:
                os.environ.pop("CLAUDE_API_KEY", None)
            else:
                os.environ["CLAUDE_API_KEY"] = previous_claude
        self.assertEqual(rules[0]["mode"], "claude_cap_review_required")
        self.assertTrue(rules[0]["human_review_required"])

    def test_legacy_atomic_rule_metadata_gets_safe_rule_id(self) -> None:
        normalized = normalize_rule_record(
            {
                "canonical_key": "atomic_rule:old",
                "row_text": "The agency must determine eligibility within 45 days.",
                "row_source_url": "https://example.gov/rule",
                "confidence": 0.6,
                "rule_types": "obligation",
            }
        )
        self.assertTrue(normalized["rule_id"].startswith("rule:legacy:"))
        self.assertEqual(normalized["source_url"], "https://example.gov/rule")
        self.assertTrue(normalized["human_review_required"])
        self.assertEqual(normalized["rule_type"], "obligation")

    def test_rule_inventory_separates_total_and_legacy_rules(self) -> None:
        inventory = build_rule_inventory_from_rules(
            [
                {"rule_id": "rule:legacy:1", "run_id": None},
                {"rule_id": "rule:new:1", "run_id": "run-20260613T000000Z"},
            ]
        )
        self.assertEqual(inventory["total_graph_atomic_rules"], 2)
        self.assertEqual(inventory["legacy_or_unversioned_atomic_rules"], 1)
        self.assertEqual(inventory["rules_excluded_from_current_scope"], 2)

    def test_programmatic_proof_report_counts_source_grounding(self) -> None:
        proof = build_programmatic_proof_report(
            [
                normalize_rule_record(
                    {
                        "rule_id": "rule:1",
                        "source_url": "https://example.gov/rule",
                        "exact_source_text": "The agency must determine eligibility.",
                        "normalized_citation": "42 CFR § 435.911",
                        "confidence_score": 0.9,
                        "human_review_required": False,
                        "extraction_method": "llm",
                    }
                )
            ],
            [{"canonical_url": "https://example.gov/rule"}],
            {"current_run_atomic_rules": 1, "new_atomic_rules_added": 1},
        )
        self.assertEqual(proof["summary"]["total_graph_atomic_rules"], 1)
        self.assertEqual(proof["summary"]["source_grounded_rules"], 1)
        self.assertEqual(proof["summary"]["citation_grounded_rules"], 1)
        self.assertEqual(proof["summary"]["machine_validated_candidate_rules"], 1)

    def test_programmatic_proof_samples_prioritize_current_run(self) -> None:
        sorted_rules = prioritize_sample_rules(
            [
                {"rule_id": "rule:legacy:1", "run_id": None, "confidence_score": 1.0},
                {"rule_id": "rule:new", "run_id": "run-current", "confidence_score": 0.7},
            ],
            "run-current",
        )
        self.assertEqual(sorted_rules[0]["rule_id"], "rule:new")

    def test_verified_rules_hierarchy_filters_review_required_rules(self) -> None:
        rules = [
            normalize_rule_record(
                {
                    "rule_id": "rule:verified",
                    "domain": "government_transaction_rules",
                    "vertical": "food_nutrition_benefits",
                    "program": "snap",
                    "jurisdiction_level": "federal",
                    "source_type": "regulation",
                    "rule_unit_type": "eligibility_rule",
                    "source_url": "https://example.gov/rule",
                    "exact_source_text": "SNAP households must report income changes.",
                    "normalized_citation": "7 CFR § 273.12",
                    "confidence_score": 0.9,
                    "human_review_required": False,
                    "verification_status": "machine_validated_candidate",
                    "normalized_rule": "SNAP households must report income changes.",
                }
            ),
            normalize_rule_record(
                {
                    "rule_id": "rule:review",
                    "source_url": "https://example.gov/rule",
                    "exact_source_text": "Needs review.",
                    "normalized_citation": "7 CFR § 273.12",
                    "confidence_score": 0.7,
                    "human_review_required": True,
                    "verification_status": "human_review_required",
                    "normalized_rule": "Needs review.",
                }
            ),
        ]
        self.assertEqual(len(verified_rules(rules)), 1)
        grouped = build_verified_rules_by_hierarchy(rules)
        verified = grouped["government_transaction_rules"]["food_nutrition_benefits"]["snap"]["federal"]["regulation"]["eligibility_rule"]
        self.assertEqual(verified[0]["rule_id"], "rule:verified")
        full = build_full_verified_hierarchy(rules)
        self.assertIn("medicaid", full["government_transaction_rules"]["healthcare_benefits"])
        self.assertEqual(
            full["government_transaction_rules"]["food_nutrition_benefits"]["snap"]["federal"]["regulation"]["eligibility_rule"][0]["rule_id"],
            "rule:verified",
        )
        self.assertEqual(
            full["government_transaction_rules"]["food_nutrition_benefits"]["wic"]["federal"]["regulation"]["eligibility_rule"],
            [],
        )
        clean = clean_verified_rule(verified[0])
        self.assertEqual(sorted(clean.keys()), ["citation", "confidence_score", "evidence", "path", "rule_id", "source_url", "statement", "verification_status"])

    def test_verified_export_reclassifies_unknown_source_and_admin_rule(self) -> None:
        rule = normalize_rule_record(
            {
                "rule_id": "rule:verified",
                "source_url": "https://www.ecfr.gov/api/versioner/v1/full/2026-06-10/title-42.xml",
                "exact_source_text": "The recipient is prohibited from redisclosing the record.",
                "normalized_citation": "42 CFR Part 2",
                "confidence_score": 0.95,
                "human_review_required": False,
                "verification_status": "machine_validated_candidate",
                "normalized_rule": "The recipient is prohibited from redisclosing the record.",
                "rule_type": "prohibition",
                "source_type": "unknown",
                "rule_unit_type": "administration_rule",
            }
        )
        self.assertEqual(rule["source_type"], "regulation")
        self.assertEqual(rule["rule_unit_type"], "enforcement_rule")
        exported = reclassify_verified_rules_for_export([rule])[0]
        self.assertEqual(exported["source_type"], "regulation")
        self.assertEqual(exported["rule_unit_type"], "enforcement_rule")
        clean = clean_verified_rule(exported)
        self.assertEqual(clean["path"]["source_type"], "regulation")

    def test_ecfr_manifest_round_trips_into_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ecfr.json"
            payload = write_ecfr_manifest(path, "2026-06-10")
            sources = load_source_manifest(path)
        self.assertEqual(payload["source_count"], 50)
        self.assertEqual(len(sources), 50)
        self.assertEqual(sources[0].jurisdiction_level, "federal")
        self.assertEqual(sources[0].source_type, "ecfr_xml")

    def test_manifest_only_skips_default_discovery_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            manifest = workdir / "ecfr.json"
            write_ecfr_manifest(manifest, "2026-06-10")
            config = make_config(workdir, source_manifest_path=manifest, source_manifest_only=True)
        discovery_names = {source.name for source in config.seeds if source.discovery_seed}
        self.assertIn("ecfr_title_1", discovery_names)
        self.assertNotIn("dhcs_apl", discovery_names)
        self.assertNotIn("ccr_title_22", discovery_names)

    def test_light_report_mode_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = make_config(
                Path(tmpdir),
                report_mode="light",
                polite_delay_seconds=0.05,
                phase0_mode="required",
                fetch_retries=4,
                fetch_retry_backoff_seconds=0.25,
                document_parser="no-bs4",
            )
        self.assertEqual(config.report_mode, "light")
        self.assertEqual(config.polite_delay_seconds, 0.05)
        self.assertEqual(config.phase0_mode, "required")
        self.assertEqual(config.fetch_retries, 4)
        self.assertEqual(config.fetch_retry_backoff_seconds, 0.25)
        self.assertEqual(config.document_parser, "no-bs4")

    def test_no_bs4_xml_parser_extracts_rule_sections(self) -> None:
        body = b"""<?xml version="1.0" encoding="UTF-8"?>
        <ROOT>
          <DIV8 TYPE="SECTION" N="435.911">
            <HEAD>Sec. 435.911 Timely eligibility determinations.</HEAD>
            <P>The Medicaid agency must determine eligibility within a reasonable period of time.</P>
          </DIV8>
        </ROOT>"""
        document = extract_text("https://www.ecfr.gov/current/title-42/part-435", "application/xml", body, parser_mode="no-bs4")
        self.assertIn("stdlib_xml_text", document.extractor_notes)
        self.assertEqual(len(document.rule_sections), 1)
        self.assertEqual(document.rule_sections[0].section_id, "435.911")
        self.assertEqual(document.rule_sections[0].source_kind, "xml_section_stdlib")

    def test_fetcher_retries_transient_http_status(self) -> None:
        try:
            from gov_rules_kg.fetcher import PoliteFetcher
        except ModuleNotFoundError as exc:
            if exc.name == "httpx":
                self.skipTest("httpx is not installed in this Python environment")
            raise

        class FakeResponse:
            def __init__(self, status_code: int, content: bytes) -> None:
                self.status_code = status_code
                self.content = content
                self.headers = {"content-type": "application/xml"}

        class FakeClient:
            def __init__(self) -> None:
                self.calls = 0

            def get(self, _url: str) -> FakeResponse:
                self.calls += 1
                if self.calls == 1:
                    return FakeResponse(503, b"temporarily unavailable")
                return FakeResponse(200, b"<root>ok</root>")

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as tmpdir:
            events: list[dict] = []
            config = make_config(
                Path(tmpdir),
                polite_delay_seconds=0,
                fetch_retries=2,
                fetch_retry_backoff_seconds=0,
            )
            fetcher = PoliteFetcher(config, events.append)
            fake_client = FakeClient()
            fetcher.client = fake_client  # type: ignore[assignment]
            result = fetcher.fetch("https://example.gov/rules.xml")

        self.assertEqual(result.status, "FETCHED")
        self.assertEqual(result.attempts, 2)
        self.assertEqual(fake_client.calls, 2)
        self.assertEqual(events[0]["event"], "fetch_retry_scheduled")
        self.assertEqual(events[0]["status_code"], 503)

    def test_scale_playbook_names_programmatic_advantage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            playbook = build_scale_playbook(Path(tmpdir), 600_000)
        self.assertEqual(playbook["target_atomic_rules"], 600_000)
        self.assertIn("federal_bulk_run", playbook["commands"])
        self.assertTrue(playbook["power_advantage_over_manual_collection"])


if __name__ == "__main__":
    unittest.main()
