import tempfile
import unittest
from pathlib import Path

from app.operational_readiness import validate_verifier_pin_manifest
from app.production_readiness import (
    CANONICAL_FIELD_STRATEGY,
    CANONICAL_HASH_STRATEGY,
    CANONICAL_ONCHAIN_ANCHOR,
    CANONICAL_PROOF_LANE,
    assert_production_ready,
    production_readiness,
)


def canonical_prod_env() -> dict[str, str]:
    return {
        "BL_ENV": "production",
        "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
        "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
        "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
        "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
        "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
        "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
        "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
        "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
        "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
        "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256": "aggregator",
        "BL_VALUE_CONSERVATION_CIRCUIT_SHA256": "value-conservation",
        "BL_AGGREGATION_VALUE_CONSERVATION_ROOT": "value-root",
        "BL_RULE_CROSSWALK_HASH": "rule-crosswalk",
        "BL_LANE_DECISION_V2_SIGNED_SHA256": "lane-decision-v2",
        "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT": "ratifier-key-root",
        "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
        "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256": "verifier-artifact",
        "BL_ACCUMULATOR_ROOT": "root",
        "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT": "audit-key-root",
        "BL_NULLIFIER_NAMESPACE_ROOT": "nullifier-namespace",
        "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
        "BL_FEE_SCHEDULE_ROOT": "fee",
        "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
        "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
        "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
        "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
        "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
        "BL_DATA_AVAILABILITY_ROOT": "data-availability",
        "BL_DENIAL_ATTESTATION_ROOT": "denial-attestation",
        "BL_FORCED_INCLUSION_QUEUE_ROOT": "forced-inclusion",
        "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
        "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
        "BL_VERIFIER_TRUST_ROOT": "trust",
    }


class ProductionReadinessTests(unittest.TestCase):
    def test_non_production_mode_does_not_require_unbuilt_subsystems(self):
        report = production_readiness({"BL_ENV": "dev"})

        self.assertFalse(report.production_mode)
        self.assertTrue(report.ready)
        self.assertEqual(report.blockers, ())

    def test_production_mode_fails_closed_until_crypto_subsystems_exist(self):
        report = production_readiness({"BL_ENV": "production"})

        self.assertTrue(report.production_mode)
        self.assertFalse(report.ready)
        self.assertIn("BL_BINDING_CIRCUIT_AUDITED_SHA256 is required", report.blockers)
        self.assertIn("BL_BATCH_AGGREGATOR_CIRCUIT_SHA256 is required", report.blockers)
        self.assertIn("BL_VALUE_CONSERVATION_CIRCUIT_SHA256 is required", report.blockers)
        self.assertIn("BL_RULE_CROSSWALK_HASH is required", report.blockers)
        self.assertIn("BL_LANE_DECISION_V2_SIGNED_SHA256 is required", report.blockers)
        self.assertIn("BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT is required", report.blockers)
        self.assertIn("BL_NULLIFIER_NAMESPACE_ROOT is required", report.blockers)
        self.assertIn("BL_DENIAL_ATTESTATION_ROOT is required", report.blockers)
        self.assertIn("BL_FORCED_INCLUSION_QUEUE_ROOT is required", report.blockers)
        self.assertIn(f"BL_PROOF_LANE must be {CANONICAL_PROOF_LANE}", report.blockers)
        self.assertIn(f"BL_FIELD_STRATEGY must be {CANONICAL_FIELD_STRATEGY}", report.blockers)
        self.assertIn(f"BL_HASH_STRATEGY must be {CANONICAL_HASH_STRATEGY}", report.blockers)
        self.assertIn(f"BL_ONCHAIN_PROOF_ANCHOR must be {CANONICAL_ONCHAIN_ANCHOR}", report.blockers)

    def test_production_mode_rejects_test_double_escape_hatch(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
            "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256": "aggregator",
            "BL_VALUE_CONSERVATION_CIRCUIT_SHA256": "value-conservation",
            "BL_AGGREGATION_VALUE_CONSERVATION_ROOT": "value-root",
            "BL_RULE_CROSSWALK_HASH": "rule-crosswalk",
            "BL_LANE_DECISION_V2_SIGNED_SHA256": "lane-decision-v2",
            "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT": "ratifier-key-root",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256": "verifier-artifact",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT": "audit-key-root",
            "BL_NULLIFIER_NAMESPACE_ROOT": "nullifier-namespace",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_DENIAL_ATTESTATION_ROOT": "denial-attestation",
            "BL_FORCED_INCLUSION_QUEUE_ROOT": "forced-inclusion",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
            "BL_ALLOW_TEST_DOUBLES": "true",
        }

        with self.assertRaisesRegex(RuntimeError, "test doubles are forbidden"):
            assert_production_ready(env)

    def test_production_mode_rejects_forced_python_rules_engine(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
            "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256": "aggregator",
            "BL_VALUE_CONSERVATION_CIRCUIT_SHA256": "value-conservation",
            "BL_AGGREGATION_VALUE_CONSERVATION_ROOT": "value-root",
            "BL_RULE_CROSSWALK_HASH": "rule-crosswalk",
            "BL_LANE_DECISION_V2_SIGNED_SHA256": "lane-decision-v2",
            "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT": "ratifier-key-root",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256": "verifier-artifact",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT": "audit-key-root",
            "BL_NULLIFIER_NAMESPACE_ROOT": "nullifier-namespace",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_DENIAL_ATTESTATION_ROOT": "denial-attestation",
            "BL_FORCED_INCLUSION_QUEUE_ROOT": "forced-inclusion",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
            "BL_FORCE_PYTHON_RULES_ENGINE": "1",
        }

        with self.assertRaisesRegex(RuntimeError, "forced Python rules engine is forbidden"):
            assert_production_ready(env)

    def test_production_mode_rejects_legacy_proof_wrapper_anchor(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
            "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256": "aggregator",
            "BL_VALUE_CONSERVATION_CIRCUIT_SHA256": "value-conservation",
            "BL_AGGREGATION_VALUE_CONSERVATION_ROOT": "value-root",
            "BL_RULE_CROSSWALK_HASH": "rule-crosswalk",
            "BL_LANE_DECISION_V2_SIGNED_SHA256": "lane-decision-v2",
            "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT": "ratifier-key-root",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256": "verifier-artifact",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT": "audit-key-root",
            "BL_NULLIFIER_NAMESPACE_ROOT": "nullifier-namespace",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_DENIAL_ATTESTATION_ROOT": "denial-attestation",
            "BL_FORCED_INCLUSION_QUEUE_ROOT": "forced-inclusion",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
            "BL_ALLOW_LEGACY_PROOF_WRAPPER": "true",
            "BL_LEGACY_PROOF_WRAPPER_ADDRESS": "0xwrap",
        }

        with self.assertRaisesRegex(RuntimeError, "legacy proof wrapper"):
            assert_production_ready(env)

    def test_production_mode_rejects_physical_toy_circuit_sources(self):
        env = canonical_prod_env()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            toy = repo / "zk" / "claim.circom"
            toy.parent.mkdir(parents=True)
            toy.write_text("template Claim(){ signal output valid; valid <== 1; }", encoding="utf-8")

            report = production_readiness(env, repo_root=repo)

        self.assertFalse(report.ready)
        self.assertTrue(any("forbidden proof source present" in blocker for blocker in report.blockers))

    def test_production_mode_rejects_dev_only_winterfell_or_f128_markers(self):
        env = {**canonical_prod_env(), "BL_PROOF_ARTIFACT_NOTE": "Winterfell f128 local proof"}

        report = production_readiness(env)

        self.assertFalse(report.ready)
        self.assertTrue(any("unsupported dev proof lane" in blocker for blocker in report.blockers))

    def test_verifier_manifest_rejects_legacy_or_dev_only_sources(self):
        base_manifest = {
            "schema_version": "blind_ledger_native_stark_verifier_pin_v1",
            "proof_anchor": CANONICAL_ONCHAIN_ANCHOR,
            "artifact_hash": "0x" + "a" * 64,
            "is_legacy_proof_wrapper": False,
            "source_hashes": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            circom_manifest = {
                **base_manifest,
                "source_hashes": [{"path": "zk/claim.circom", "sha256": "b" * 64}],
            }
            winterfell_manifest = {
                **base_manifest,
                "source_hashes": [{"path": "blind-ledger-app-layer/zk-stark/src/lib.rs", "sha256": "b" * 64}],
            }

            circom_report = validate_verifier_pin_manifest(circom_manifest, repo_root=repo)
            winterfell_report = validate_verifier_pin_manifest(winterfell_manifest, repo_root=repo)

        self.assertFalse(circom_report.ok)
        self.assertTrue(any("forbidden legacy proof source" in error for error in circom_report.errors))
        self.assertFalse(winterfell_report.ok)
        self.assertTrue(any("dev-only proof source" in error for error in winterfell_report.errors))

    def test_production_mode_passes_only_with_explicit_canonical_artifacts(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
            "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256": "aggregator",
            "BL_VALUE_CONSERVATION_CIRCUIT_SHA256": "value-conservation",
            "BL_AGGREGATION_VALUE_CONSERVATION_ROOT": "value-root",
            "BL_RULE_CROSSWALK_HASH": "rule-crosswalk",
            "BL_LANE_DECISION_V2_SIGNED_SHA256": "lane-decision-v2",
            "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT": "ratifier-key-root",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256": "verifier-artifact",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT": "audit-key-root",
            "BL_NULLIFIER_NAMESPACE_ROOT": "nullifier-namespace",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_DENIAL_ATTESTATION_ROOT": "denial-attestation",
            "BL_FORCED_INCLUSION_QUEUE_ROOT": "forced-inclusion",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
        }

        assert_production_ready(env)
        self.assertTrue(production_readiness(env).ready)


if __name__ == "__main__":
    unittest.main()
