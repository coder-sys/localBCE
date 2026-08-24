import unittest
from app.batch.tar_required import load_default_tar_required_codes
from app.rules_engine_fallback import procedure_requires_prior_authorization


class TarRequiredRuleRegistryTests(unittest.TestCase):
    def test_default_policy_artifact_replaces_hardcoded_prior_auth_set(self) -> None:
        default_codes = load_default_tar_required_codes()
        self.assertEqual(default_codes, ("T1019", "S5102", "H2015"))
        self.assertTrue(procedure_requires_prior_authorization("T1019"))
        self.assertFalse(procedure_requires_prior_authorization("99213"))
if __name__ == "__main__":
    unittest.main()
