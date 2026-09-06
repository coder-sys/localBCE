"""Targeted fail-closed tests for the native-v3 trust-boundary profile."""

from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from experiments.native_v3_phase0.native_v3_fixture import (
    ACCESS_READ,
    ACCESS_WRITE,
    AccessEvent,
    build_fixture,
)

from experiments.native_v3_trust_boundary.profile import (
    ProfileError,
    _validate_compiled_parameter_report,
    build_profile_bindings,
    build_security_ledger,
    DECISION_ACCESS_JOIN_BYTES,
    DecisionAccessJoin,
    parse_decision_access_join,
    profile_manifest,
    validate_security_ledger,
)


class TrustBoundaryProfileTests(unittest.TestCase):
    def test_manifest_is_explicit_and_nonactivating(self) -> None:
        manifest = profile_manifest()
        self.assertFalse(manifest["complete_bound_available"])
        self.assertFalse(manifest["production_usable"])
        self.assertIsNone(manifest["proof_suite_id"])
        grammar = manifest["grammar"]
        self.assertEqual(grammar["statement"]["length_bytes"], 992)
        self.assertEqual(grammar["vector_leaf"]["fields"][-1], ["salt", "bytes[32]", "hidden in statement; no production hiding claim"])
        self.assertEqual(grammar["vector_node"]["root"], "SHA3-512(vector-node-domain,canonical-node-bytes)")
        self.assertEqual(grammar["transcript"]["fields"][6], ["frame_count", "u16=3"])
        bindings = manifest["verifier_owned_public_bindings"]
        self.assertEqual(bindings["automatic_control_set"]["owner"], "verifier")
        self.assertEqual(bindings["decision_access_join"]["access_order"], ["read", "write"])
        self.assertEqual(bindings["decision_access_join"]["access_indices"], [0, 1])
        self.assertEqual(
            bindings["decision_access_join"]["access_value_binding"],
            [
                "access[0].value == operation.value_before",
                "access[1].value == operation.value_after",
            ],
        )
        self.assertFalse(bindings["completeness_or_nonmembership"]["absence_authorized"])
        self.assertEqual(bindings["chronology"]["sequence_after"], bindings["chronology"]["sequence_before"] + 1)

    def test_compiled_parameter_report_rejects_exactly_seven_categories(self) -> None:
        report_path = Path(
            "experiments/longfellow_v09_native_v3/evidence/"
            "implementation_parameter_attestation.json"
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        mutations = []

        missing = copy.deepcopy(report)
        missing.pop("proof_rate")
        mutations.append(("missing key", missing))

        extra = copy.deepcopy(report)
        extra["unexpected"] = False
        mutations.append(("extra key", extra))

        wrong_type = copy.deepcopy(report)
        wrong_type["proof_queries"] = "189"
        mutations.append(("wrong type", wrong_type))

        source_hash = copy.deepcopy(report)
        source_hash["sha3_patch_sha256"] = "0" * 64
        mutations.append(("changed source hash", source_hash))

        dimension = copy.deepcopy(report)
        dimension["circuit_terms"] += 1
        mutations.append(("changed circuit dimension", dimension))

        circuit_id = copy.deepcopy(report)
        circuit_id["circuit_id"] = "0" + circuit_id["circuit_id"][1:]
        mutations.append(("changed circuit ID", circuit_id))

        activation = copy.deepcopy(report)
        activation["activation"] = True
        mutations.append(("non-null/true activation field", activation))

        self.assertEqual(len(mutations), 7)
        for category, mutation in mutations:
            with self.subTest(category=category):
                with self.assertRaises(ProfileError):
                    _validate_compiled_parameter_report(mutation)

        attestation = build_security_ledger()["implementation_attestation"]
        self.assertEqual(attestation["status"], "IMPLEMENTATION_ATTESTED")
        self.assertEqual(attestation["report"]["proof_rate"], 4)
        self.assertFalse(attestation["production_usable"])
        self.assertFalse(attestation["activation"])
        self.assertIsNone(attestation["proof_suite_id"])
        self.assertTrue(
            all(
                value == "UNKNOWN"
                for key, value in attestation["dp24_mapping"].items()
                if key != "note"
            )
        )

    def test_symbolic_ledger_rejects_zero_or_complete_placeholders(self) -> None:
        ledger = build_security_ledger()
        self.assertFalse(ledger["complete_bound_available"])
        self.assertFalse(ledger["production_usable"])
        self.assertEqual(ledger["parameter_set"]["status"], "UNKNOWN_NOT_AUTHORITY_BOUND")
        self.assertEqual(ledger["dp24"]["status"], "UNKNOWN")
        self.assertFalse(ledger["dp24"]["exact_rational_arithmetic"]["used"])
        self.assertIsNone(ledger["dp24"]["bits_single_decimal"])
        self.assertIsNone(ledger["dp24"]["bits_union_decimal"])
        for field in ledger["parameter_set"]["fields"].values():
            self.assertIsNone(field["value"])
            self.assertEqual(field["status"], "UNKNOWN")
            self.assertEqual(field["candidate_value_status"], "HYPOTHETICAL_CANDIDATE_INPUT")
        self.assertTrue(all(term["bound"] is None for term in ledger["unresolved_terms"]))

        bad = copy.deepcopy(ledger)
        bad["unresolved_terms"][0]["bound"] = 0
        with self.assertRaises(ProfileError):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["complete_bound_available"] = True
        with self.assertRaises(ProfileError):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["parameter_set"]["fields"]["ell"]["status"] = "KNOWN"
        bad["parameter_set"]["fields"]["ell"]["value"] = 28
        with self.assertRaisesRegex(ProfileError, "ledger:parameter-provenance"):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["parameter_set"]["id"] = "0" * 128
        with self.assertRaisesRegex(ProfileError, "ledger:parameter-provenance"):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["parameter_set"]["fields"].pop("ell")
        with self.assertRaisesRegex(ProfileError, "ledger:parameter-provenance"):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["dp24"]["bits_single_decimal"] = "134.472"
        with self.assertRaisesRegex(ProfileError, "ledger:numeric-claim-with-unknown-parameters"):
            validate_security_ledger(bad)

        with patch(
            "experiments.native_v3_trust_boundary.profile.UPSTREAM_MANIFEST_SHA256",
            "0" * 64,
        ):
            with self.assertRaisesRegex(ProfileError, "ledger:provenance-source-mismatch"):
                build_security_ledger()

        with patch(
            "experiments.native_v3_trust_boundary.profile.UPSTREAM_MANIFEST_RELATIVE_PATH",
            "experiments/longfellow_v09_native_v3/missing-manifest.json",
        ):
            with self.assertRaisesRegex(ProfileError, "ledger:provenance-source-unavailable"):
                build_security_ledger()

    def test_decision_access_join_is_one_decision_and_read_then_write(self) -> None:
        fixture = build_fixture()
        join = DecisionAccessJoin(fixture.operation, fixture.accesses)
        encoded = join.canonical_bytes()
        self.assertEqual(len(encoded), DECISION_ACCESS_JOIN_BYTES)
        self.assertEqual(
            join.join_id.hex(),
            "d62d56dee1cc8b18869c128dbc178aa3ee993865bfe38216596b7f9b8788fb6b58fc8849b0db30c6b652e40dfa30bf8f8bea1b94f8a5e0f5b8421039ddc09245",
        )
        self.assertEqual(parse_decision_access_join(encoded), join)
        self.assertEqual(build_profile_bindings().decision_access_join_id, join.join_id)

        invalid_joins = (
            DecisionAccessJoin(fixture.operation, (fixture.accesses[1], fixture.accesses[0])),
            DecisionAccessJoin(
                fixture.operation,
                (AccessEvent(0, ACCESS_READ, fixture.operation.value_before),) * 2,
            ),
            DecisionAccessJoin(
                fixture.operation,
                (AccessEvent(0, ACCESS_WRITE, fixture.operation.value_after),) * 2,
            ),
            DecisionAccessJoin(fixture.operation, (fixture.accesses[0],)),
            DecisionAccessJoin(fixture.operation, fixture.accesses + (fixture.accesses[1],), access_count=3),
            DecisionAccessJoin(
                fixture.operation,
                (AccessEvent(1, ACCESS_READ, fixture.operation.value_before), fixture.accesses[1]),
            ),
            DecisionAccessJoin(
                fixture.operation,
                (AccessEvent(0, ACCESS_READ, b"x" * 64), fixture.accesses[1]),
            ),
            DecisionAccessJoin(
                fixture.operation,
                (fixture.accesses[0], AccessEvent(0, ACCESS_WRITE, b"y" * 64)),
            ),
            DecisionAccessJoin(fixture.operation, fixture.accesses, decision_count=0),
            DecisionAccessJoin(fixture.operation, fixture.accesses, access_count=1),
            DecisionAccessJoin(replace(fixture.operation, operation_index=1), fixture.accesses),
            DecisionAccessJoin(replace(fixture.operation, operation_count=2), fixture.accesses),
        )
        for invalid in invalid_joins:
            with self.assertRaises(ProfileError):
                invalid.canonical_bytes()

        rows_start = 4 + 480 + 4
        malformed = [encoded[:-1], encoded + b"\0"]
        bad = bytearray(encoded)
        bad[0:4] = (2).to_bytes(4, "big")
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 24] = ACCESS_WRITE
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 94 + 24] = ACCESS_READ
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 24] = 9
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 12] = 1
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 30] ^= 1
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[rows_start + 94 + 30] ^= 1
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[4 + 16:4 + 20] = (2).to_bytes(4, "big")
        malformed.append(bytes(bad))
        bad = bytearray(encoded)
        bad[4 + 480:4 + 484] = (1).to_bytes(4, "big")
        malformed.append(bytes(bad))
        self.assertEqual(len(malformed), 11)
        for mutation in malformed:
            with self.assertRaises(ProfileError):
                parse_decision_access_join(mutation)

    def test_producer_rejects_all_non_strict_time_orders(self) -> None:
        bindings = build_profile_bindings()
        times = [
            bindings.rule_effective_time,
            bindings.event_time,
            bindings.observation_time,
            bindings.decision_time,
        ]
        self.assertEqual(times, sorted(times))
        self.assertEqual(len(set(times)), 4)

        for left, right in ((0, 1), (1, 2), (2, 3), (0, 2), (1, 3), (0, 3)):
            swapped = times.copy()
            swapped[left], swapped[right] = swapped[right], swapped[left]
            with self.assertRaisesRegex(ProfileError, "bindings:chronology"):
                replace(
                    bindings,
                    rule_effective_time=swapped[0],
                    event_time=swapped[1],
                    observation_time=swapped[2],
                    decision_time=swapped[3],
                )

        for left, right in ((0, 1), (1, 2), (2, 3), (0, 2), (1, 3), (0, 3)):
            equal = times.copy()
            equal[right] = equal[left]
            with self.assertRaises(ProfileError):
                replace(
                    bindings,
                    rule_effective_time=equal[0],
                    event_time=equal[1],
                    observation_time=equal[2],
                    decision_time=equal[3],
                )

if __name__ == "__main__":
    unittest.main()
