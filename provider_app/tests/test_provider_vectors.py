"""Manually expected synthetic cases across adapter and independent checker."""

from __future__ import annotations

import json
import unittest

from copy import deepcopy
from pathlib import Path

import jsonschema

from provider_app import preflight_bytes
from provider_app.checker import check_result

from tests.helpers import VECTORS, bundle_bytes, request_bytes


class SyntheticVectorTests(unittest.TestCase):
    def test_every_manual_vector_and_independent_reconstruction(self) -> None:
        self.assertEqual(26, len(VECTORS["cases"]))
        for case in VECTORS["cases"]:
            with self.subTest(vector=case["id"]):
                request = request_bytes(case)
                bundle = bundle_bytes(case)
                result_bytes = preflight_bytes(request, bundle)
                result = json.loads(result_bytes)
                self.assertEqual(case["outcome"], result["outcome"])
                self.assertEqual(case["issues"], result["bundleIssues"])
                self.assertEqual(case["ruleOutcomes"], [rule["outcome"] for rule in result["rules"]])
                self.assertEqual(case["missingFacts"], result["missingFacts"])
                self.assertEqual(VECTORS["ruleIds"], [rule["ruleId"] for rule in result["rules"]])
                binding = json.loads(bundle)
                expected_citations = [
                    f"{binding['bundleId']}/v{binding['version']}#{rule_id}/v1"
                    for rule_id in VECTORS["ruleIds"]
                ]
                self.assertEqual(expected_citations, [rule["citation"] for rule in result["rules"]])
                self.assertEqual((), check_result(request, bundle, result_bytes))

    def test_independent_checker_names_stable_result_difference(self) -> None:
        case = VECTORS["cases"][0]
        request = request_bytes(case)
        bundle = bundle_bytes(case)
        result = json.loads(preflight_bytes(request, bundle))
        result["outcome"] = "MISSING"
        changed = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
        first = check_result(request, bundle, changed)
        second = check_result(request, bundle, changed)
        self.assertEqual(first, second)
        self.assertIn("RESULT_VALUE:/outcome", first)

    def test_result_schema_rejects_duplicate_and_shuffled_rule_ids(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "check-result-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator_type = jsonschema.Draft202012Validator
        validator_type.check_schema(schema)
        validator = validator_type(schema)

        case = VECTORS["cases"][0]
        result = json.loads(preflight_bytes(request_bytes(case), bundle_bytes(case)))
        validator.validate(result)

        duplicate = deepcopy(result)
        duplicate["rules"][1]["ruleId"] = duplicate["rules"][0]["ruleId"]
        self.assertFalse(validator.is_valid(duplicate))

        shuffled = deepcopy(result)
        shuffled["rules"][0], shuffled["rules"][1] = shuffled["rules"][1], shuffled["rules"][0]
        self.assertFalse(validator.is_valid(shuffled))

    def test_unimplemented_lifecycle_areas_are_counted(self) -> None:
        self.assertEqual(3, len(VECTORS["notExercised"]))
        self.assertEqual(
            {"package-install-update", "recovery", "rollback"},
            {item["area"] for item in VECTORS["notExercised"]},
        )


if __name__ == "__main__":
    unittest.main()
