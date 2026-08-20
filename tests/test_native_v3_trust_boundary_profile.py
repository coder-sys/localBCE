"""Targeted fail-closed tests for the native-v3 trust-boundary profile."""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.native_v3_phase0.native_v3_fixture import (
    ACCESS_READ,
    ACCESS_WRITE,
    AccessEvent,
    build_fixture,
)

from experiments.native_v3_trust_boundary.profile import (
    MAX_RETRIES,
    ProfileError,
    build_profile_bindings,
    build_security_ledger,
    DECISION_ACCESS_JOIN_BYTES,
    DecisionAccessJoin,
    parse_decision_access_join,
    profile_manifest,
    validate_security_ledger,
)
from experiments.native_v3_trust_boundary.session import (
    ChallengeMessage,
    CommitmentMessage,
    Opening,
    ProverSession,
    ProverState,
    ProfileStatement,
    Transcript,
    VerifierSession,
    build_verifier_bindings,
    create_session_artifacts,
    issue_session_challenge,
    recompute_decision_access_join_id,
    respond_to_challenge,
    verify_opening,
    verify_session_directory,
)


class CounterRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        return hashlib.sha3_512(self.counter.to_bytes(8, "big")).digest()[:length]


class TrustBoundaryProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="native-v3-tbp-", dir=Path("work"))
        self.directory = Path(self.temp.name)
        self.auth_key = bytes(range(32))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_flow(self):
        state = create_session_artifacts(self.directory, auth_key=self.auth_key, random_source=CounterRandom())
        challenge = issue_session_challenge(self.directory, random_source=CounterRandom())
        transcript = respond_to_challenge(self.directory, random_source=CounterRandom())
        return state, challenge, transcript

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

    def test_implementation_parameter_attestation_is_verified_and_non_theorem(self) -> None:
        ledger = build_security_ledger()
        attestation = ledger["implementation_attestation"]
        self.assertEqual(attestation["implementation_status"], "IMPLEMENTATION_ATTESTED")
        self.assertEqual(attestation["record_bytes"], 802)
        self.assertEqual(
            attestation["record_identity_sha3_512"],
            "5f5a45afd01cfa441f1c9671cce63495708fa7a9378c3305ce6a8f4f6e306ef8df64e3ff616e0e61f0f22462e351ca83b19d7b85b22a23b8d608d8d4f70377dd",
        )
        self.assertEqual(attestation["facts"]["proof_rate"], 4)
        self.assertEqual(attestation["facts"]["proof_queries"], 189)
        self.assertEqual(attestation["adversarial_matrix"], {
            "cases": 17,
            "proof_invocations": 0,
            "rejected": 17,
            "state_mutations": 0,
        })
        self.assertFalse(attestation["production_usable"])
        self.assertFalse(attestation["activation"])
        self.assertIsNone(attestation["proof_suite_id"])
        self.assertTrue(all(value == "UNKNOWN" for key, value in attestation["dp24_mapping"].items() if key != "note"))

        bad = copy.deepcopy(ledger)
        bad["implementation_attestation"]["facts"]["proof_rate"] = 5
        with self.assertRaisesRegex(ProfileError, "ledger:implementation-attestation"):
            validate_security_ledger(bad)

        with patch(
            "experiments.native_v3_trust_boundary.profile.IMPLEMENTATION_ATTESTATION_EVIDENCE_SHA256",
            "0" * 64,
        ):
            with self.assertRaisesRegex(ProfileError, "ledger:implementation-attestation-evidence-mismatch"):
                build_security_ledger()

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

    def test_independent_verifier_recomputes_join_and_rejects_raw_mutations(self) -> None:
        fixture = build_fixture()
        valid = DecisionAccessJoin(fixture.operation, fixture.accesses).canonical_bytes()
        expected = build_profile_bindings().decision_access_join_id
        self.assertEqual(recompute_decision_access_join_id(valid), expected)
        self.assertEqual(build_verifier_bindings().decision_access_join_id, expected)

        rows_start = 4 + 480 + 4
        mutations: list[bytes] = []
        for offset, value in (
            (0, 2),
            (4 + 16, 2),
            (4 + 480, 1),
            (rows_start + 12, 1),
            (rows_start + 20, 1),
            (rows_start + 24, ACCESS_WRITE),
            (rows_start + 94 + 24, ACCESS_READ),
            (rows_start + 24, 9),
        ):
            mutation = bytearray(valid)
            if offset in (0, 4 + 16, 4 + 480, rows_start + 12, rows_start + 20):
                mutation[offset:offset + 4] = value.to_bytes(4, "big")
            else:
                mutation[offset] = value
            mutations.append(bytes(mutation))
        mutation = bytearray(valid)
        mutation[rows_start + 30] ^= 1
        mutations.append(bytes(mutation))
        mutation = bytearray(valid)
        mutation[rows_start + 94 + 30] ^= 1
        mutations.append(bytes(mutation))
        mutation = bytearray(valid)
        mutation[4 + 280] ^= 1
        mutations.append(bytes(mutation))
        mutations.extend((valid[:-1], valid + b"\0"))
        self.assertEqual(len(mutations), 13)

        for mutation in mutations:
            with self.assertRaisesRegex(ProfileError, "verifier:join-"):
                recompute_decision_access_join_id(mutation)

        with patch(
            "experiments.native_v3_trust_boundary.profile.access_row_bytes",
            side_effect=AssertionError("producer validator called"),
        ):
            self.assertEqual(recompute_decision_access_join_id(valid), expected)

        with patch(
            "experiments.native_v3_trust_boundary.session.build_profile_bindings",
            return_value=replace(build_profile_bindings(), decision_access_join_id=b"\1" + b"\0" * 63),
        ):
            with self.assertRaisesRegex(ProfileError, "verifier:join-producer-disagreement"):
                build_verifier_bindings()

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
        self.assertEqual(len(ProfileStatement(b"\1" * 32, bindings).canonical_bytes()), 992)

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

    def test_live_flow_and_replay_marker(self) -> None:
        state, challenge, transcript = self.make_flow()
        result = verify_session_directory(self.directory)
        self.assertEqual(result.session_id, state.statement.session_id)
        self.assertEqual(result.challenge_digest, challenge.digest)
        self.assertEqual(result.transcript_digest, hashlib.sha3_512(
            b"BL/NATIVE-V3/TBP/TRANSCRIPT/v1\0"
            + transcript.session_id
            + transcript.statement
            + transcript.commitment
            + transcript.challenge
            + transcript.response
        ).digest())
        self.assertFalse(result.complete_bound_available)
        self.assertFalse(result.production_usable)
        with self.assertRaisesRegex(ProfileError, "registry:replay"):
            verify_session_directory(self.directory)

    def test_independent_parsers_reject_role_auth_truncation_and_reorder(self) -> None:
        state, _, _ = self.make_flow()
        statement_bytes = (self.directory / "statement.bin").read_bytes()
        commitment_bytes = (self.directory / "commitment.bin").read_bytes()
        challenge_bytes = (self.directory / "challenge.bin").read_bytes()
        transcript_bytes = (self.directory / "transcript.bin").read_bytes()

        bad_commitment = bytearray(commitment_bytes)
        bad_commitment[11] = 2
        with self.assertRaises(ProfileError):
            CommitmentMessage.parse(bytes(bad_commitment))

        bad_challenge = bytearray(challenge_bytes)
        bad_challenge[-1] ^= 1
        with self.assertRaises(ProfileError):
            ChallengeMessage.parse(bytes(bad_challenge), self.auth_key)

        with self.assertRaises(ProfileError):
            Transcript.parse(transcript_bytes[:-1])

        parsed = Transcript.parse(transcript_bytes)
        reordered = Transcript(
            parsed.session_id,
            parsed.statement,
            parsed.challenge,
            parsed.commitment,
            parsed.response,
        ).canonical_bytes()
        with self.assertRaises(ProfileError):
            Transcript.parse(reordered)

        bad_statement = bytearray(statement_bytes)
        source_root_offset = 112 + (3 * 64)
        bad_statement[source_root_offset] ^= 1
        with self.assertRaises(ProfileError):
            ProverState.parse(ProverState.parse((self.directory / "prover_state.bin").read_bytes()).canonical_bytes().replace(statement_bytes, bytes(bad_statement), 1))

        self.assertEqual(state.statement.session_id, parsed.session_id)

    def test_wrong_salt_and_opening_index_fail_closed(self) -> None:
        state, challenge, _ = self.make_flow()
        commitment = CommitmentMessage.parse((self.directory / "commitment.bin").read_bytes())
        response_bytes = (self.directory / "response.bin").read_bytes()
        response = ProverState.parse((self.directory / "prover_state.bin").read_bytes())
        self.assertEqual(response.statement.session_id, state.statement.session_id)
        opening = Opening.parse(response_bytes[-(len(response_bytes) - response_bytes.find(b"BLTBOP01")):])
        bad_salt = bytes((opening.salt[0] ^ 1,)) + opening.salt[1:]
        with self.assertRaises(ProfileError):
            verify_opening(Opening(opening.index, opening.value, bad_salt, opening.sibling_is_left, opening.sibling_hash), commitment, challenge)
        with self.assertRaises(ProfileError):
            verify_opening(Opening(1 - challenge.selected_index, opening.value, opening.salt, opening.sibling_is_left, opening.sibling_hash), commitment, challenge)

    def test_abort_retry_cap_and_challenge_replay(self) -> None:
        bindings = build_profile_bindings()
        registry = self.directory / "retry-registry"
        prover = ProverSession(bindings, random_source=CounterRandom(), registry_dir=registry)
        for _ in range(MAX_RETRIES):
            prover.commit()
            prover.abort()
        with self.assertRaisesRegex(ProfileError, "retry:cap"):
            prover.commit()

        state = ProverSession(bindings, random_source=CounterRandom(), registry_dir=self.directory / "challenge-registry").commit()
        statement = state.statement.canonical_bytes()
        commitment = state.commitment.canonical_bytes()
        verifier = VerifierSession(self.auth_key, random_source=CounterRandom(), registry_dir=self.directory / "challenge-registry")
        verifier.issue_challenge(commitment, statement)
        with self.assertRaisesRegex(ProfileError, "registry:replay"):
            VerifierSession(self.auth_key, random_source=CounterRandom(), registry_dir=self.directory / "challenge-registry").issue_challenge(commitment, statement)


if __name__ == "__main__":
    unittest.main()
