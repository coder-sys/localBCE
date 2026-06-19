import copy
import unittest
from pathlib import Path

from app.operational_readiness import (
    load_json,
    parse_env_file,
    validate_governance_config,
    validate_launch_blockers,
    validate_monitoring_events,
    validate_production_env_template,
    validate_production_env_values,
    validate_public_input_schema,
    validate_source_manifest,
    validate_verifier_pin_manifest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
OPS = REPO_ROOT / "ops"


class OperationalReadinessTests(unittest.TestCase):
    def test_production_env_template_has_required_fail_closed_keys(self):
        report = validate_production_env_template(OPS / "production.env.example")
        self.assertTrue(report.ok, report.errors)
        env = parse_env_file(OPS / "production.env.example")
        value_report = validate_production_env_values(env)
        self.assertFalse(value_report.ok)
        self.assertTrue(any("placeholder" in item for item in value_report.errors))

    def test_governance_config_validates_threshold_timelock_and_role_separation(self):
        payload = load_json(OPS / "governance_config.example.json")
        self.assertTrue(validate_governance_config(payload).ok)
        bad = copy.deepcopy(payload)
        bad["threshold"] = 1
        bad["minimum_timelock_seconds"] = 60
        bad["roles"]["auditor"] = bad["roles"]["admin"]
        report = validate_governance_config(bad)
        self.assertFalse(report.ok)
        self.assertIn("threshold must be at least 2", report.errors)
        self.assertTrue(any("timelock" in item for item in report.errors))
        self.assertTrue(any("roles must not overlap" in item for item in report.errors))

    def test_source_manifest_accepts_only_official_https_sources(self):
        payload = load_json(OPS / "oracle_source_manifest.example.json")
        self.assertTrue(validate_source_manifest(payload).ok)
        bad = copy.deepcopy(payload)
        bad["sources"][0]["url"] = "http://example.com/not-official"
        bad["sources"][0]["official"] = False
        report = validate_source_manifest(bad)
        self.assertFalse(report.ok)
        self.assertTrue(any("https" in item for item in report.errors))
        self.assertTrue(any("official" in item for item in report.errors))

    def test_native_stark_public_input_schema_is_exactly_ordered(self):
        payload = load_json(OPS / "native_stark_public_inputs_v1.json")
        self.assertTrue(validate_public_input_schema(payload).ok)
        bad = copy.deepcopy(payload)
        bad["fields"][0]["name"] = "batchId"
        report = validate_public_input_schema(bad)
        self.assertFalse(report.ok)
        self.assertTrue(any("nullifierRootBefore" in item for item in report.errors))

    def test_verifier_pin_manifest_hashes_sources_and_forbids_legacy_wrapper(self):
        payload = load_json(OPS / "verifier_artifact_pin.example.json")
        self.assertTrue(validate_verifier_pin_manifest(payload, repo_root=REPO_ROOT).ok)
        bad = copy.deepcopy(payload)
        bad["is_legacy_proof_wrapper"] = True
        bad["source_hashes"][0]["sha256"] = "00" * 32
        report = validate_verifier_pin_manifest(bad, repo_root=REPO_ROOT)
        self.assertFalse(report.ok)
        self.assertTrue(any("legacy proof" in item for item in report.errors))
        self.assertTrue(any("source hash mismatch" in item for item in report.errors))

    def test_monitoring_events_and_launch_blockers_are_machine_readable(self):
        self.assertTrue(validate_monitoring_events(load_json(OPS / "monitoring_events.json")).ok)
        blockers = load_json(OPS / "launch_blockers.json")
        self.assertTrue(validate_launch_blockers(blockers).ok)
        self.assertGreaterEqual(len([item for item in blockers["blockers"] if item["status"] == "open"]), 1)


if __name__ == "__main__":
    unittest.main()
