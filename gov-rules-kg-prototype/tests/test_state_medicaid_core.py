from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from gov_rules_kg.state_medicaid_core import (
    build_postgres_supplemental_registry,
    canonical_sha256,
    validate_state_medicaid_preflight,
    validate_state_medicaid_registry,
)


WORKDIR = Path(__file__).resolve().parents[1]
REGISTRY_PATH = (
    WORKDIR / "data" / "source_manifests" / "state_medicaid_core_v1.json"
)
PREFLIGHT_PATH = WORKDIR / "reports" / "state_medicaid_core_preflight_v1.json"


class StateMedicaidCoreTests(unittest.TestCase):
    def registry(self) -> dict:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    def preflight(self) -> dict:
        return json.loads(PREFLIGHT_PATH.read_text(encoding="utf-8"))

    def test_registry_is_three_state_shadow_only_core(self) -> None:
        summary = validate_state_medicaid_registry(self.registry())
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["source_count"], 15)
        self.assertEqual(summary["state_counts"], {"NC": 5, "GA": 5, "CA": 5})
        self.assertFalse(summary["runtime_activation"])
        self.assertFalse(summary["proof_binding"])
        for state_code in ("NC", "GA", "CA"):
            with self.subTest(state_code=state_code):
                self.assertTrue(
                    all(
                        count > 0
                        for count in summary["rule_family_coverage"][state_code].values()
                    )
                )

    def test_registry_rejects_runtime_or_proof_activation(self) -> None:
        for field in ("runtime_activation", "proof_binding"):
            registry = self.registry()
            registry[field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must be false"):
                    validate_state_medicaid_registry(registry)

    def test_registry_rejects_state_host_mismatch(self) -> None:
        registry = self.registry()
        registry["sources"][0]["source_url"] = (
            "https://dch.georgia.gov/meetings-notices/public-notices"
        )
        with self.assertRaisesRegex(ValueError, "host is not approved for NC"):
            validate_state_medicaid_registry(registry)

    def test_registry_rejects_uncaptured_source_hash(self) -> None:
        registry = self.registry()
        registry["sources"][0]["source_hash"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "source_hash must be null until capture"):
            validate_state_medicaid_registry(registry)

    def test_registry_rejects_missing_state_rule_family(self) -> None:
        registry = self.registry()
        for source in registry["sources"]:
            if source["state_code"] == "CA":
                source["rule_families"] = [
                    family
                    for family in source["rule_families"]
                    if family != "timely_filing"
                ]
        with self.assertRaisesRegex(ValueError, "CA is missing rule-family coverage"):
            validate_state_medicaid_registry(registry)

    def test_canonical_hash_does_not_depend_on_object_key_order(self) -> None:
        registry = self.registry()
        reordered = {
            key: copy.deepcopy(registry[key])
            for key in reversed(list(registry.keys()))
        }
        self.assertEqual(canonical_sha256(registry), canonical_sha256(reordered))

    def test_preflight_report_matches_registry_and_remains_nonbinding(self) -> None:
        registry = self.registry()
        report = self.preflight()
        summary = validate_state_medicaid_preflight(report, registry)
        self.assertEqual(report["registry_id"], registry["registry_id"])
        self.assertEqual(report["registry_canonical_sha256"], canonical_sha256(registry))
        self.assertEqual(report["source_count"], len(registry["sources"]))
        self.assertEqual(report["http_200_count"], 15)
        self.assertEqual(report["capture_ready_count"], 10)
        self.assertEqual(report["special_adapter_required_count"], 5)
        self.assertFalse(report["source_bytes_captured"])
        self.assertFalse(report["legal_evidence_captured"])
        self.assertFalse(report["database_jobs_created"])
        self.assertFalse(report["runtime_activation"])
        self.assertFalse(report["proof_binding"])
        self.assertEqual(
            {source["source_id"] for source in report["sources"]},
            {source["source_id"] for source in registry["sources"]},
        )
        self.assertEqual(summary["status_counts"]["capture_ready"], 10)
        self.assertEqual(summary["status_counts"]["special_adapter_required"], 5)

    def test_california_shells_remain_adapter_blocked_and_not_evidence(self) -> None:
        registry = self.registry()
        preflight = self.preflight()
        supplemental = build_postgres_supplemental_registry(registry, preflight)
        california = [
            source
            for source in supplemental["sources"]
            if source["jurisdiction"]["state"] == "CA"
        ]
        self.assertEqual(len(california), 5)
        for source in california:
            with self.subTest(source_id=source["source_id"]):
                self.assertTrue(source["metadata"]["adapter_required"])
                self.assertFalse(source["metadata"]["captured_legal_evidence"])
                self.assertFalse(source["metadata"]["human_approved"])
                self.assertEqual(
                    source["metadata"]["legal_verification_status"],
                    "not_verified",
                )

    def test_preflight_rejects_california_shell_as_capture_ready(self) -> None:
        registry = self.registry()
        preflight = self.preflight()
        california = next(
            source
            for source in preflight["sources"]
            if source["source_id"].startswith("medicaid-us-ca-")
        )
        california["preflight_status"] = "capture_ready"
        with self.assertRaisesRegex(ValueError, "special_adapter_required for CA"):
            validate_state_medicaid_preflight(preflight, registry)

    def test_postgres_projection_preserves_all_source_ids_and_boundaries(self) -> None:
        registry = self.registry()
        supplemental = build_postgres_supplemental_registry(
            registry, self.preflight()
        )
        self.assertTrue(supplemental["supplemental"])
        self.assertFalse(supplemental["registry_activation"])
        self.assertFalse(supplemental["runtime_activation"])
        self.assertFalse(supplemental["proof_binding"])
        self.assertEqual(
            {source["source_id"] for source in supplemental["sources"]},
            {source["source_id"] for source in registry["sources"]},
        )
        self.assertTrue(
            all(source["program"] == "medicaid" for source in supplemental["sources"])
        )


if __name__ == "__main__":
    unittest.main()
