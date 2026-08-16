"""Targeted fail-closed tests for the native-v3 trust-boundary profile."""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest

from experiments.native_v3_trust_boundary.profile import (
    MAX_RETRIES,
    ProfileError,
    build_profile_bindings,
    build_security_ledger,
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
    create_session_artifacts,
    issue_session_challenge,
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
        self.assertFalse(bindings["completeness_or_nonmembership"]["absence_authorized"])
        self.assertEqual(bindings["chronology"]["sequence_after"], bindings["chronology"]["sequence_before"] + 1)

    def test_symbolic_ledger_rejects_zero_or_complete_placeholders(self) -> None:
        ledger = build_security_ledger()
        self.assertFalse(ledger["complete_bound_available"])
        self.assertFalse(ledger["production_usable"])
        self.assertEqual(ledger["dp24"]["bits_single_decimal"][:7], "134.472")
        self.assertEqual(ledger["dp24"]["bits_union_decimal"][:7], "128.664")
        self.assertTrue(all(term["bound"] is None for term in ledger["unresolved_terms"]))

        bad = copy.deepcopy(ledger)
        bad["unresolved_terms"][0]["bound"] = 0
        with self.assertRaises(ProfileError):
            validate_security_ledger(bad)

        bad = copy.deepcopy(ledger)
        bad["complete_bound_available"] = True
        with self.assertRaises(ProfileError):
            validate_security_ledger(bad)

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
