"""The plain-language fix list covers every code the 26 vectors produce and refuses the rest."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from provider_app import preflight_bytes
from provider_app.contracts import InputError
from provider_app.fix_list import REAL_USE_TEXT, TEXT, fix_list

from tests.helpers import VECTORS, bundle_bytes, canonical_bytes, request_bytes

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schemas" / "check-result-v1.schema.json").read_text(encoding="utf-8")
)
_RULE = _SCHEMA["$defs"]["ruleResult"]["properties"]
# Reason codes only a MISSING rule carries; the missing fact itself is what the text names.
_MISSING_ONLY = {"REQUIRED_FACT_MISSING", "SUPPORT_REFERENCE_MISSING", "SOURCE_EFFECTIVE_TIME_MISSING", "SOURCE_RECEIVED_TIME_MISSING"}


def _results() -> list[tuple[str, dict]]:
    return [
        (case["id"], json.loads(preflight_bytes(request_bytes(case), bundle_bytes(case))))
        for case in VECTORS["cases"]
    ]


class FixListTests(unittest.TestCase):
    def test_every_vector_code_has_text_and_the_table_is_exactly_the_closed_set(self) -> None:
        seen = set()
        for _, result in _results():
            for rule in result["rules"]:
                if rule["outcome"] == "MISSING":
                    seen.update(rule["missingFacts"])
                elif rule["outcome"] == "HUMAN_CHECK":
                    seen.update(rule["reasonCodes"])
        closed = set(_RULE["missingFacts"]["items"]["enum"]) | (set(_RULE["reasonCodes"]["items"]["enum"]) - _MISSING_ONLY)
        self.assertEqual(closed, set(TEXT))
        self.assertEqual(closed - {"RULE_SEMANTIC_UNSUPPORTED"}, seen)  # that one is unreachable from the vectors

    def test_every_vector_gives_one_fix_per_missing_or_review_code(self) -> None:
        for name, result in _results():
            with self.subTest(vector=name):
                lines = fix_list(canonical_bytes(result))
                if result["runMode"] == "REAL_USE":
                    self.assertEqual((("", "", "", REAL_USE_TEXT),), lines)
                elif result["bundleIssues"]:
                    self.assertEqual((("", "", "", TEXT["BUNDLE_BLOCKED"]),), lines)
                else:
                    expected = [
                        (r["ruleId"], r["citation"], r["missingFacts"][i] if r["outcome"] == "MISSING" else "")
                        for r in result["rules"] if r["outcome"] != "PASS"
                        for i in range(len(r["missingFacts"] if r["outcome"] == "MISSING" else r["reasonCodes"]))
                    ]
                    self.assertEqual(expected, [line[:3] for line in lines])
                    self.assertTrue(all(line[3] for line in lines))
                self.assertEqual(result["outcome"] == "PASS", lines == ())

    def test_unknown_code_raises_with_no_partial_output(self) -> None:
        cases = {"missing": ("support-reference-absent", "missingFacts", "nope"), "review": ("partial-source", "reasonCodes", "NOPE")}
        for label, (vector, key, code) in cases.items():
            case = next(c for c in VECTORS["cases"] if c["id"] == vector)
            result = json.loads(preflight_bytes(request_bytes(case), bundle_bytes(case)))
            rule = next(r for r in result["rules"] if r["outcome"] != "PASS")
            rule[key] = [*rule[key], code]
            with self.subTest(label), self.assertRaises(InputError) as caught:
                fix_list(canonical_bytes(result))
            self.assertEqual("RESULT_SHAPE", caught.exception.code)

    def _refused(self, vector: str, edit) -> None:
        case = next(c for c in VECTORS["cases"] if c["id"] == vector)
        result = json.loads(preflight_bytes(request_bytes(case), bundle_bytes(case)))
        edit(result, next(r for r in result["rules"] if r["outcome"] != "PASS"))
        with self.assertRaises(InputError) as caught:
            fix_list(canonical_bytes(result))
        self.assertEqual("RESULT_SHAPE", caught.exception.code)

    def test_codes_a_missing_rule_does_not_render_are_still_checked(self) -> None:
        self._refused("support-reference-absent", lambda _, rule: rule.update(reasonCodes=["NOPE"]))

    def test_codes_must_be_allowed_for_the_rule_outcome(self) -> None:
        for code in ("charge_cents", "BUNDLE_BLOCKED", "REQUIRED_FACT_MISSING"):
            with self.subTest(code):
                self._refused("partial-source", lambda _, rule: rule.update(reasonCodes=[code]))
        self._refused("support-reference-absent", lambda _, rule: rule.update(reasonCodes=["SERVICE_CATEGORY_REQUIRES_REVIEW"]))

    def test_a_non_pass_rule_with_no_codes_is_refused(self) -> None:
        self._refused("partial-source", lambda _, rule: rule.update(reasonCodes=[]))
        self._refused("support-reference-absent", lambda _, rule: rule.update(reasonCodes=[]))
        self._refused("support-reference-absent", lambda _, rule: rule.update(missingFacts=[]))

    def test_top_level_outcome_and_run_mode_are_checked(self) -> None:
        for key, bad in (("outcome", "NOPE"), ("runMode", "NOPE"), ("outcome", None)):
            with self.subTest(key, bad=bad):
                self._refused("partial-source", lambda result, _: result.update({key: bad}))

    def test_the_list_is_empty_exactly_when_the_outcome_is_pass(self) -> None:
        self._refused("partial-source", lambda result, _: result.update(outcome="PASS"))
        self._refused("partial-source", lambda result, rule: (rule.update(outcome="PASS", reasonCodes=[]), result.update(outcome="HUMAN_CHECK")))
        self._refused("real-use-blocked", lambda result, _: result.update(outcome="PASS"))

    def test_hostile_bytes_are_refused_typed_by_the_codec(self) -> None:
        for raw, code in (
            (b'{"a":1,"a":2}', "JSON_DUPLICATE_KEY"),
            (b'{"a":1.5}', "JSON_FLOAT_UNSUPPORTED"),
            (b"\xff", "JSON_INVALID"),
            (b"[]", "JSON_OBJECT_REQUIRED"),
            (b" " * 20_000, "RESULT_TOO_LARGE"),
            ("{}", "JSON_BYTES_REQUIRED"),
            (b"{}", "RESULT_SHAPE"),
        ):
            with self.subTest(code), self.assertRaises(InputError) as caught:
                fix_list(raw)
            self.assertEqual(code, caught.exception.code)

    def test_output_is_deterministic(self) -> None:
        for _, result in _results():
            self.assertEqual(fix_list(canonical_bytes(result)), fix_list(canonical_bytes(result)))


if __name__ == "__main__":
    unittest.main()
