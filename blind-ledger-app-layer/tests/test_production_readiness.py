import unittest

from app.production_readiness import (
    CANONICAL_FIELD_STRATEGY,
    CANONICAL_PROOF_LANE,
    assert_production_ready,
    production_readiness,
)


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
        self.assertIn(f"BL_PROOF_LANE must be {CANONICAL_PROOF_LANE}", report.blockers)
        self.assertIn(f"BL_FIELD_STRATEGY must be {CANONICAL_FIELD_STRATEGY}", report.blockers)

    def test_production_mode_rejects_stub_escape_hatch(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
            "BL_ALLOW_STUBS": "true",
        }

        with self.assertRaisesRegex(RuntimeError, "stubs are forbidden"):
            assert_production_ready(env)

    def test_production_mode_passes_only_with_explicit_canonical_artifacts(self):
        env = {
            "BL_ENV": "production",
            "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
            "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
            "BL_BINDING_CIRCUIT_AUDITED_SHA256": "abc",
            "BL_BATCH_BINDING_VERIFIER_KEY_SHA256": "vk",
            "BL_RAW_837_DERIVATION_CIRCUIT_SHA256": "raw",
            "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256": "nullifier",
            "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256": "payment",
            "BL_NATIVE_STARK_VERIFIER_ADDRESS": "0x1234",
            "BL_ACCUMULATOR_ROOT": "root",
            "BL_EFFECTIVE_RULESET_TIMELINE_ROOT": "timeline",
            "BL_FEE_SCHEDULE_ROOT": "fee",
            "BL_ELIGIBILITY_ORACLE_ROOT": "eligibility",
            "BL_PROVIDER_STATUS_ORACLE_ROOT": "provider",
            "BL_PRIOR_AUTH_ORACLE_ROOT": "prior-auth",
            "BL_ORACLE_IN_CIRCUIT_KEY_ROOT": "oracle",
            "BL_SETTLEMENT_ADDRESS_BOOK_ROOT": "address-book",
            "BL_DATA_AVAILABILITY_ROOT": "data-availability",
            "BL_GOVERNANCE_MULTISIG_ADDRESS": "0xmultisig",
            "BL_GOVERNANCE_TIMELOCK_ADDRESS": "0xtimelock",
            "BL_VERIFIER_TRUST_ROOT": "trust",
        }

        assert_production_ready(env)
        self.assertTrue(production_readiness(env).ready)


if __name__ == "__main__":
    unittest.main()
