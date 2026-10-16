from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_rightrail_adopted_controls.py"
SPEC = importlib.util.spec_from_file_location("rightrail_adopted_controls", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class RightRailAdoptedControlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data_policy = validator.load_json(validator.DATA_POLICY_PATH)
        self.authority_policy = validator.load_json(validator.AUTHORITY_POLICY_PATH)

    def test_checked_in_controls_validate_and_are_deterministic(self) -> None:
        first_data = validator.validate_data_policy(self.data_policy)
        second_data = validator.validate_data_policy(copy.deepcopy(self.data_policy))
        first_authority = validator.validate_authority_policy(self.authority_policy)
        second_authority = validator.validate_authority_policy(
            copy.deepcopy(self.authority_policy)
        )

        self.assertEqual(first_data, second_data)
        self.assertEqual(first_authority, second_authority)

    def test_runtime_or_approval_claims_are_rejected(self) -> None:
        for field in ("runtime_enforced", "human_approved", "legal_verified"):
            mutated = copy.deepcopy(self.data_policy)
            mutated[field] = True
            with self.assertRaises(validator.ControlValidationError):
                validator.validate_data_policy(mutated)

    def test_sensitive_data_cannot_enter_external_ai(self) -> None:
        mutated = copy.deepcopy(self.data_policy)
        external_ai = next(
            item for item in mutated["destinations"] if item["id"] == "external_ai"
        )
        external_ai["allowed_classes"].append("phi")

        with self.assertRaisesRegex(
            validator.ControlValidationError, "cannot allow sensitive class phi"
        ):
            validator.validate_data_policy(mutated)

    def test_authority_record_cannot_omit_provenance(self) -> None:
        mutated = copy.deepcopy(self.authority_policy)
        mutated["required_authority_record_fields"].remove("source_reference")

        with self.assertRaisesRegex(
            validator.ControlValidationError, "authority-record fields are incomplete"
        ):
            validator.validate_authority_policy(mutated)

    def test_authority_requires_separate_roles(self) -> None:
        mutated = copy.deepcopy(self.authority_policy)
        mutated["required_roles_by_action"]["withholding"] = ["settlement_owner"]

        with self.assertRaisesRegex(
            validator.ControlValidationError,
            "withholding requires two distinct authority roles",
        ):
            validator.validate_authority_policy(mutated)

    def test_changed_retry_must_fail_closed(self) -> None:
        mutated = copy.deepcopy(self.authority_policy)
        mutated["retry_semantics"]["changed_retry"] = "accept"

        with self.assertRaisesRegex(
            validator.ControlValidationError, "retries must be idempotent"
        ):
            validator.validate_authority_policy(mutated)


if __name__ == "__main__":
    unittest.main()
