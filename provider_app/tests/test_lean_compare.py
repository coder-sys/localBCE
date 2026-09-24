"""Pinned Lean differential checks over the hand-authored synthetic vectors."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from provider_app import preflight_bytes
from provider_app.checker import check_result
from provider_app.lean_compare import (
    LeanCompareError,
    _REPO_ROOT,
    _encode_input,
    _parse_output,
    _run_process,
    _utc_seconds,
    _verify_identity,
    _wait_bounded,
    compare_bytes,
)
from provider_app.codec import parse_bundle_bytes, parse_request_bytes

from tests.helpers import VECTORS, bundle_bytes, request_bytes


VECTOR_RESULT_FIELDS = frozenset(
    {"outcome", "issues", "ruleOutcomes", "missingFacts"}
)


class _HungProcess:
    def __init__(self) -> None:
        self.killed = False

    def poll(self) -> None:
        return None

    def kill(self) -> None:
        self.killed = True


def _tree_snapshot(root: Path) -> tuple[tuple[str, int, int, str], ...]:
    entries = []
    for path in root.rglob("*"):
        if path.is_file():
            stat = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(65_536), b""):
                    digest.update(block)
            entries.append(
                (
                    str(path.relative_to(root)),
                    stat.st_size,
                    stat.st_mtime_ns,
                    digest.hexdigest().upper(),
                )
            )
    return tuple(sorted(entries))


class LeanComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _verify_identity()

    def test_all_manual_vector_fields_match_python_and_independent_checker(self) -> None:
        self.assertEqual(26, len(VECTORS["cases"]))
        observed_fields: set[str] = set()
        compared_vector_values = 0
        for case in VECTORS["cases"]:
            with self.subTest(vector=case["id"]):
                request = request_bytes(case)
                bundle = bundle_bytes(case)
                python_bytes = preflight_bytes(request, bundle)
                projection = compare_bytes(request, bundle)
                self.assertEqual((), check_result(request, bundle, python_bytes))
                self.assertEqual(case["outcome"], projection.outcome)
                observed_fields.add("outcome")
                compared_vector_values += 1

                self.assertEqual(case["issues"], list(projection.bundle_issues))
                observed_fields.add("issues")
                compared_vector_values += 1

                self.assertEqual(
                    case["ruleOutcomes"],
                    [rule.outcome for rule in projection.rules],
                )
                self.assertEqual(
                    VECTORS["ruleIds"],
                    [rule.rule_id for rule in projection.rules],
                )
                result_bundle = parse_bundle_bytes(bundle)
                expected_citations = [
                    f"{result_bundle.bundle_id}/v{result_bundle.version}#{rule_id}/v1"
                    for rule_id in VECTORS["ruleIds"]
                ]
                self.assertEqual(
                    expected_citations,
                    [rule.citation for rule in projection.rules],
                )
                observed_fields.add("ruleOutcomes")
                compared_vector_values += 1

                self.assertEqual(case["missingFacts"], list(projection.missing_facts))
                observed_fields.add("missingFacts")
                compared_vector_values += 1

                # The adapter also rejects a nonempty independent-checker diff.

        self.assertEqual(VECTOR_RESULT_FIELDS, observed_fields)
        self.assertEqual(26 * len(VECTOR_RESULT_FIELDS), compared_vector_values)
        self.assertEqual(0, len(VECTOR_RESULT_FIELDS - observed_fields))

    def test_exact_retry_returns_identical_projection_without_mutation(self) -> None:
        case = VECTORS["cases"][0]
        request = request_bytes(case)
        bundle = bundle_bytes(case)
        original_inputs = (bytes(request), bytes(bundle))
        before = (
            _tree_snapshot(_REPO_ROOT / "provider_app"),
            _tree_snapshot(_REPO_ROOT / "lean" / "ProviderApp"),
        )

        first = compare_bytes(request, bundle)
        second = compare_bytes(request, bundle)

        after = (
            _tree_snapshot(_REPO_ROOT / "provider_app"),
            _tree_snapshot(_REPO_ROOT / "lean" / "ProviderApp"),
        )
        self.assertEqual(first, second)
        self.assertEqual(original_inputs, (request, bundle))
        self.assertEqual(before, after)

    def test_real_use_block_is_compared_without_forwarding_fact_tokens(self) -> None:
        case = next(item for item in VECTORS["cases"] if item["id"] == "real-use-blocked")
        request = request_bytes(case)
        bundle = bundle_bytes(case)
        payload = _encode_input(
            parse_request_bytes(request),
            parse_bundle_bytes(bundle),
        )
        self.assertEqual("R", payload.split("|")[1])
        self.assertEqual(["-"] * 7, payload.split("|")[5:12])
        self.assertEqual("HUMAN_CHECK", compare_bytes(request, bundle).outcome)

    def test_malformed_oversize_and_wrong_version_protocol_inputs_fail_closed(self) -> None:
        marker = "SYNTHETIC-PRIVATE-MARKER"
        cases = [
            (
                "short input",
                "RRPA-LEAN-COMPARE/v1|S|" + marker,
                "LEAN_PROTOCOL_MALFORMED",
            ),
            (
                "oversize ASCII input",
                "RRPA-LEAN-COMPARE/v1|" + ("A" * 2_100) + marker,
                "LEAN_PROTOCOL_INPUT_TOO_LARGE",
            ),
            (
                "oversize non-ASCII input",
                "RRPA-LEAN-COMPARE/v1|" + ("é" * 1_100) + marker,
                "LEAN_PROTOCOL_INPUT_TOO_LARGE",
            ),
            (
                "unsupported protocol version",
                "RRPA-LEAN-COMPARE/v2|" + marker,
                "LEAN_PROTOCOL_VERSION_UNSUPPORTED",
            ),
        ]
        vector = VECTORS["cases"][0]
        request = request_bytes(vector)
        bundle = bundle_bytes(vector)
        normalized = _encode_input(
            parse_request_bytes(request), parse_bundle_bytes(bundle)
        )

        def replace_field(index: int, value: str) -> str:
            fields = normalized.split("|")
            fields[index] = value
            return "|".join(fields)

        cases.extend(
            [
                ("unknown mode tag", replace_field(1, "X"), "LEAN_PROTOCOL_MALFORMED"),
                ("unknown scope tag", replace_field(2, "X"), "LEAN_PROTOCOL_MALFORMED"),
                (
                    "noncanonical integer",
                    replace_field(3, "01"),
                    "LEAN_PROTOCOL_MALFORMED",
                ),
                ("wrong rule count", replace_field(20, "4"), "LEAN_PROTOCOL_MALFORMED"),
                ("unknown rule tag", replace_field(21, "999"), "LEAN_PROTOCOL_MALFORMED"),
                (
                    "unknown semantic tag",
                    replace_field(23, "UNKNOWN"),
                    "LEAN_PROTOCOL_MALFORMED",
                ),
                ("extra field", normalized + "|EXTRA", "LEAN_PROTOCOL_MALFORMED"),
                (
                    "empty field",
                    normalized.replace("|", "||", 1),
                    "LEAN_PROTOCOL_MALFORMED",
                ),
                ("trailing separator", normalized + "|", "LEAN_PROTOCOL_MALFORMED"),
                (
                    "missing field",
                    "|".join(normalized.split("|")[:-1]),
                    "LEAN_PROTOCOL_MALFORMED",
                ),
            ]
        )

        real_use = next(
            item for item in VECTORS["cases"] if item["id"] == "real-use-blocked"
        )
        real_payload = _encode_input(
            parse_request_bytes(request_bytes(real_use)),
            parse_bundle_bytes(bundle_bytes(real_use)),
        )
        real_fields = real_payload.split("|")
        real_fields[5] = "1"
        cases.append(
            (
                "REAL_USE fact token",
                "|".join(real_fields),
                "LEAN_PROTOCOL_MALFORMED",
            )
        )

        for label, payload, expected_code in cases:
            with self.subTest(case=label):
                completed = _run_process(payload)
                self.assertNotEqual(0, completed.returncode)
                diagnostic = completed.stderr.replace(b"\r\n", b"\n")
                self.assertEqual(expected_code.encode("ascii") + b"\n", diagnostic)
                self.assertLessEqual(len(completed.stderr), 64)
                self.assertEqual(b"", completed.stdout)
                self.assertNotIn(marker.encode("ascii"), completed.stdout)
                self.assertNotIn(marker.encode("ascii"), completed.stderr)

    def test_output_protocol_rejects_version_tags_and_shape(self) -> None:
        vector = VECTORS["cases"][0]
        request = request_bytes(vector)
        bundle = bundle_bytes(vector)
        payload = _encode_input(
            parse_request_bytes(request), parse_bundle_bytes(bundle)
        )
        completed = _run_process(payload)
        self.assertEqual(0, completed.returncode)
        self.assertEqual(b"", completed.stderr)

        newline = b"\r\n" if completed.stdout.endswith(b"\r\n") else b"\n"
        fields = completed.stdout[: -len(newline)].split(b"|")
        self.assertEqual(b"RRPA-LEAN-RESULT/v1", fields[0])
        self.assertEqual(b"0", fields[2])
        self.assertEqual(b"5", fields[3])

        cases = []
        for label, index, value in (
            ("unsupported version", 0, b"RRPA-LEAN-RESULT/v2"),
            ("unknown outcome tag", 1, b"APPROVED"),
            ("noncanonical count", 2, b"00"),
            ("unknown rule tag", 4, b"SYN-PRE-999"),
        ):
            changed = list(fields)
            changed[index] = value
            cases.append((label, b"|".join(changed) + newline))
        cases.extend(
            [
                ("extra field", b"|".join(fields) + b"|EXTRA" + newline),
                ("missing field", b"|".join(fields[:-1]) + newline),
            ]
        )

        for label, malformed in cases:
            with self.subTest(case=label):
                with self.assertRaises(LeanCompareError) as raised:
                    _parse_output(malformed)
                self.assertEqual("LEAN_PROTOCOL_INVALID", str(raised.exception))

    def test_divergent_lean_projection_is_rejected_without_values(self) -> None:
        case = VECTORS["cases"][0]
        request = request_bytes(case)
        bundle = bundle_bytes(case)
        request_model = parse_request_bytes(request)
        bundle_model = parse_bundle_bytes(bundle)
        actual = _run_process(_encode_input(request_model, bundle_model))
        self.assertEqual(0, actual.returncode)
        fields = actual.stdout[:-1].split(b"|")
        self.assertEqual(b"PASS", fields[1])
        fields[1] = b"MISSING"
        divergent = replace(actual, stdout=b"|".join(fields) + b"\n")

        with patch("provider_app.lean_compare._run_process", return_value=divergent):
            with self.assertRaises(LeanCompareError) as raised:
                compare_bytes(request, bundle)
        self.assertEqual("LEAN_CHECKER_DISAGREEMENT", str(raised.exception))
        self.assertNotIn("SYNTHETIC-PRIVATE-MARKER", str(raised.exception))

    def test_expired_deadline_terminates_child_with_stable_timeout_code(self) -> None:
        child = _HungProcess()
        with self.assertRaises(LeanCompareError) as raised:
            _wait_bounded(child, time.monotonic() - 1.0, threading.Event())
        self.assertTrue(child.killed)
        self.assertEqual("LEAN_TIMEOUT", str(raised.exception))

    def test_non_utc_and_subsecond_times_fail_closed(self) -> None:
        values = (
            datetime(2026, 9, 20, 12, 0, tzinfo=timezone(timedelta(hours=1))),
            datetime(2026, 9, 20, 12, 0, 0, 1, tzinfo=timezone.utc),
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(LeanCompareError) as raised:
                    _utc_seconds(value)
                self.assertEqual("LEAN_INPUT_UNREPRESENTABLE", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
