import unittest
from app.batch.tar_required import load_default_tar_required_codes


class TarRequiredRuleRegistryTests(unittest.TestCase):
    def test_default_policy_artifact_contains_registered_codes(self) -> None:
        default_codes = load_default_tar_required_codes()
        self.assertEqual(default_codes, ("T1019", "S5102", "H2015"))
if __name__ == "__main__":
    unittest.main()
