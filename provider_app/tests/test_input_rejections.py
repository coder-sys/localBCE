"""Strict bounded parsing rejection vectors; not executed before lane handoff."""

from __future__ import annotations

import json
import unittest

from provider_app.codec import parse_bundle_bytes, parse_request_bytes
from provider_app.codec import bundle_content_digest
from provider_app.contracts import InputError, MAX_JSON_BYTES

from tests.helpers import bundle_mapping, canonical_bytes, request_bytes


class InputRejectionTests(unittest.TestCase):
    def assert_code(self, expected: str, operation) -> None:
        with self.assertRaises(InputError) as caught:
            operation()
        self.assertEqual(expected, caught.exception.code)

    def test_duplicate_json_key(self) -> None:
        raw = b'{"contract":"x","contract":"y"}'
        self.assert_code("JSON_DUPLICATE_KEY", lambda: parse_request_bytes(raw))

    def test_json_byte_limit(self) -> None:
        self.assert_code("REQUEST_TOO_LARGE", lambda: parse_request_bytes(b" " * (MAX_JSON_BYTES + 1)))

    def test_json_nesting_limit(self) -> None:
        raw = b'{"x":' + b"[" * 9 + b"0" + b"]" * 9 + b"}"
        self.assert_code("JSON_DEPTH_EXCEEDED", lambda: parse_request_bytes(raw))

    def test_json_numeric_tokens_fail_closed(self) -> None:
        request = json.loads(request_bytes())
        request["facts"]["chargeCents"] = 1.5
        self.assert_code("JSON_FLOAT_UNSUPPORTED", lambda: parse_request_bytes(canonical_bytes(request)))
        large_integer = b"9" * 5000
        self.assertLessEqual(len(large_integer), MAX_JSON_BYTES)
        self.assert_code("JSON_INVALID", lambda: parse_request_bytes(large_integer))

    def test_unknown_request_field_fails_closed(self) -> None:
        request = json.loads(request_bytes())
        request["facts"]["extra"] = "synthetic"
        self.assert_code("FACTS_SCHEMA", lambda: parse_request_bytes(canonical_bytes(request)))

    def test_invalid_calendar_date_is_rejected(self) -> None:
        request = json.loads(request_bytes())
        request["facts"]["serviceDate"] = "2026-02-30"
        self.assert_code("SERVICE_DATE_INVALID", lambda: parse_request_bytes(canonical_bytes(request)))

    def test_wrong_bundle_content_digest_is_rejected(self) -> None:
        bundle = bundle_mapping()
        wrong = "sha256:" + "0" * 64
        if wrong == bundle["contentDigest"]:
            wrong = "sha256:" + "1" * 64
        bundle["contentDigest"] = wrong
        self.assert_code("BUNDLE_DIGEST_MISMATCH", lambda: parse_bundle_bytes(canonical_bytes(bundle)))

    def test_bundle_withdrawal_cannot_precede_its_publication(self) -> None:
        bundle = bundle_mapping()
        bundle["withdrawnAt"] = bundle["publishedAt"]
        bundle["contentDigest"] = bundle_content_digest(bundle)
        self.assert_code("BUNDLE_WITHDRAWAL_INVALID", lambda: parse_bundle_bytes(canonical_bytes(bundle)))

    def test_duplicate_rule_id_is_rejected(self) -> None:
        bundle = bundle_mapping()
        bundle["rules"][1]["ruleId"] = bundle["rules"][0]["ruleId"]
        bundle["contentDigest"] = bundle_content_digest(bundle)
        self.assert_code("BUNDLE_RULE_DUPLICATE", lambda: parse_bundle_bytes(canonical_bytes(bundle)))


if __name__ == "__main__":
    unittest.main()
