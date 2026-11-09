import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_rightrail_handoff",
    ROOT / "scripts" / "validate_rightrail_handoff.py",
)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


class ValidateRightRailHandoffTests(unittest.TestCase):
    def test_committed_outputs_and_runtime_boundaries(self):
        values = validator.validate_committed_outputs()
        self.assertEqual(values["crosswalk_summary"]["queue_record_count"], 1108)
        validator.validate_runtime_boundaries()
        validator.validate_formal_and_pq_files()

    def test_checkpoint_verification_rejects_tampering(self):
        value = {"answer": 42}
        value["checkpoint_sha256"] = validator.sha256_bytes(
            validator.canonical_json({"answer": 42})
        )
        validator.verify_checkpoint(value, label="test")
        value["answer"] = 43
        with self.assertRaises(validator.ValidationError):
            validator.verify_checkpoint(value, label="test")


if __name__ == "__main__":
    unittest.main()
