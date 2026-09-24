"""Fail-closed tests for the synthetic provider continuity wedge."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from parked.state_clearance.experiments.native_v3_phase0.native_v3_fixture import (
    DIRECTIVE_BLOCK,
    DIRECTIVE_CLEAR,
    DIRECTIVE_EXCEPTION_APPROVED,
    DIRECTIVE_HOLD,
    DIRECTIVE_HUMAN_REVIEW,
    ExceptionAuthorization,
    NO_EXCEPTION_SENTINEL,
    POLICY_RESULT_FAIL,
    TRUSTED_AUTHORIZER_ID,
)
from parked.state_clearance.experiments.native_v3_trust_boundary.profile import build_profile_bindings
from parked.state_clearance.experiments.native_v3_plaintext_continuity.continuity import (
    ACCESS_READ,
    ACCESS_WRITE,
    DEMO_CASES,
    DECISION_TIME,
    EXCEPTION_NONE_SENTINEL,
    FACT_ACTIVE,
    FACT_EXPIRED,
    FACT_TERMINATED,
    OBSERVATION_TIME,
    REASON_CONTROL_INTERVAL,
    ContinuityError,
    ContinuityRequest,
    ContinuityReceipt,
    ContinuityStore,
    CredentialEnrollmentFact,
    CredentialFactSet,
    DecisionAccessJoin,
    FeedCompleteness,
    RULE_ID,
    TrustBoundaryAdapter,
    automatic_control_set_id,
    build_demo_case,
    build_manifest,
    bundle_bytes,
    make_completeness,
    source_state_address,
    audit_state_address,
)
from parked.state_clearance.experiments.native_v3_plaintext_continuity.independent import (
    IndependentParseError,
    parse_bundle,
)


class PlaintextContinuityTests(unittest.TestCase):
    def apply_case(self, name: str):
        request, facts, completeness, exception = build_demo_case(name)
        store = ContinuityStore()
        receipt = store.apply(request, facts, completeness, exception)
        return request, facts, completeness, exception, store, receipt

    @staticmethod
    def split_bundle(raw: bytes) -> list[bytes]:
        if raw[:8] != b"BLCBND02":
            raise AssertionError("test fixture is not V2")
        offset = 12
        parts: list[bytes] = []
        for _ in range(7):
            length = int.from_bytes(raw[offset : offset + 4], "big")
            offset += 4
            parts.append(raw[offset : offset + length])
            offset += length
        if offset != len(raw):
            raise AssertionError("test bundle split trailing")
        return parts

    @staticmethod
    def join_bundle(parts: list[bytes]) -> bytes:
        return b"".join(
            (
                b"BLCBND02",
                (2).to_bytes(2, "big"),
                b"\0\0",
                *(len(part).to_bytes(4, "big") + part for part in parts),
            )
        )

    @staticmethod
    def digest(domain: bytes, *parts: bytes) -> bytes:
        hasher = hashlib.sha3_512()
        hasher.update(domain)
        for part in parts:
            hasher.update(part)
        return hasher.digest()

    @classmethod
    def rebind_receipt(cls, receipt_raw: bytes) -> bytes:
        body = bytearray(receipt_raw[:-64])
        decision_length_offset = 532
        decision_length = int.from_bytes(
            body[decision_length_offset : decision_length_offset + 4], "big"
        )
        access_count_offset = decision_length_offset + 4 + decision_length
        if int.from_bytes(body[access_count_offset : access_count_offset + 4], "big") != 2:
            raise AssertionError("test receipt access count")
        cursor = access_count_offset + 4
        access_raws: list[bytes] = []
        for _ in range(2):
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            access_raws.append(bytes(body[cursor : cursor + length]))
            cursor += length
        decision_raw = bytes(body[536 : 536 + decision_length])
        join_raw = b"".join(
            (
                b"BLCJON02",
                (2).to_bytes(2, "big"),
                b"\0\0",
                (1).to_bytes(4, "big"),
                (2).to_bytes(4, "big"),
                len(decision_raw).to_bytes(4, "big"),
                decision_raw,
                *(len(raw).to_bytes(4, "big") + raw for raw in access_raws),
            )
        )
        body[276:340] = cls.digest(b"BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2\0", join_raw)
        return bytes(body) + cls.digest(b"BL/NATIVE-V3/CONTINUITY/RECEIPT-ID/v2\0", bytes(body))

    @staticmethod
    def patch_access_field(access_raw: bytes, field_offset: int, value: bytes | int) -> bytes:
        mutated = bytearray(access_raw)
        if isinstance(value, int):
            mutated[field_offset] = value
        else:
            mutated[field_offset : field_offset + len(value)] = value
        return bytes(mutated)

    @classmethod
    def replace_access_rows(cls, raw: bytes, access_raws: tuple[bytes, bytes]) -> bytes:
        parts = cls.split_bundle(raw)
        body = bytearray(parts[0][:-64])
        decision_length = int.from_bytes(body[532:536], "big")
        cursor = 532 + 4 + decision_length + 4
        for index, access_raw in enumerate(access_raws):
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            if len(access_raw) != length:
                raise AssertionError(f"test access length {index}")
            body[cursor : cursor + length] = access_raw
            cursor += length
        parts[0] = cls.rebind_receipt(bytes(body) + b"\0" * 64)
        return cls.join_bundle(parts)

    @classmethod
    def replace_decision(cls, raw: bytes, decision_raw: bytes) -> bytes:
        parts = cls.split_bundle(raw)
        body = bytearray(parts[0][:-64])
        decision_length = int.from_bytes(body[532:536], "big")
        if len(decision_raw) != decision_length:
            raise AssertionError("test decision length")
        body[536 : 536 + decision_length] = decision_raw
        parts[0] = cls.rebind_receipt(bytes(body) + b"\0" * 64)
        return cls.join_bundle(parts)

    @classmethod
    def mutate_access(cls, raw: bytes, access_index: int, field_offset: int, value: int | None = None) -> bytes:
        parts = cls.split_bundle(raw)
        body = bytearray(parts[0][:-64])
        decision_length = int.from_bytes(body[532:536], "big")
        cursor = 532 + 4 + decision_length + 4
        for index in range(2):
            length = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            if index == access_index:
                target = cursor + field_offset
                body[target] = value if value is not None else body[target] ^ 1
            cursor += length
        parts[0] = cls.rebind_receipt(bytes(body) + b"\0" * 64)
        return cls.join_bundle(parts)

    def test_manifest_is_explicit_and_nonactivating(self) -> None:
        manifest = build_manifest()
        self.assertEqual(manifest["mode"], "DIRECT_STATE_OWNED")
        self.assertEqual(manifest["automatic_control_set_id"], automatic_control_set_id().hex())
        self.assertEqual(manifest["rule_order"], [RULE_ID.hex()])
        self.assertEqual(manifest["conflict_policy"], "priority-then-human-review")
        self.assertEqual(manifest["effective_interval"], [6_000, 9_000])
        self.assertFalse(manifest["proof_session_accepted"])
        self.assertIsNone(manifest["proof_suite_id"])
        self.assertFalse(manifest["production_usable"])
        self.assertFalse(manifest["activation"])

    def test_all_business_cases_and_independent_parser(self) -> None:
        expected = {
            "valid-continuity": (1, DIRECTIVE_CLEAR),
            "expired-credential": (4, DIRECTIVE_BLOCK),
            "terminated-credential": (4, DIRECTIVE_BLOCK),
            "missing-incomplete-feed": (3, DIRECTIVE_HUMAN_REVIEW),
            "authoritative-absence": (2, DIRECTIVE_HOLD),
            "conflicting-facts": (3, DIRECTIVE_HUMAN_REVIEW),
            "stale-rule-interval": (3, DIRECTIVE_HUMAN_REVIEW),
            "governed-exception": (POLICY_RESULT_FAIL, DIRECTIVE_EXCEPTION_APPROVED),
        }
        self.assertEqual(tuple(expected), DEMO_CASES)
        for name in DEMO_CASES:
            request, facts, completeness, _, _, receipt = self.apply_case(name)
            parsed = parse_bundle(bundle_bytes(receipt, facts, completeness))
            self.assertEqual((receipt.decision.policy_result, receipt.decision.effective_directive), expected[name])
            self.assertEqual(parsed["status"], "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_PASS")
            self.assertEqual(parsed["receipt_id"], receipt.receipt_id.hex())
            self.assertFalse(parsed["proof_session_accepted"])
            self.assertFalse(parsed["economic_mutation"])
            self.assertIsNone(parsed["proof_suite_id"])
            self.assertEqual(parsed["request_id"], request.request_id.hex())
            self.assertTrue(parsed["reason_id"])

    def test_producer_receipt_round_trip_all_demo_cases(self) -> None:
        for name in DEMO_CASES:
            request, facts, completeness, exception, _, receipt = self.apply_case(name)
            raw = receipt.canonical_bytes()
            parsed = ContinuityReceipt.parse(
                raw,
                before_state=receipt.before_state,
                after_state=receipt.after_state,
                request=request,
                exception_authorization=exception,
            )
            self.assertEqual(parsed.canonical_bytes(), raw)
            self.assertEqual(parsed.decision, receipt.decision)
            self.assertEqual(parsed.accesses, receipt.accesses)
            self.assertEqual(parsed.before_state, receipt.before_state)
            self.assertEqual(parsed.after_state, receipt.after_state)
            self.assertEqual(parsed.request, request)
            self.assertEqual(parsed.exception_authorization, exception)
            if exception is None:
                self.assertEqual(parsed.decision.exception_id, EXCEPTION_NONE_SENTINEL)
            else:
                self.assertEqual(parsed.decision.exception_id, exception.authorization_id)

    def test_completeness_fact_nonmembership_conflict_rejects(self) -> None:
        request, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        contradictory = replace(completeness, nonmembership_keys=(request.subject_key,))
        with self.assertRaisesRegex(ContinuityError, "completeness:fact-nonmembership-conflict"):
            ContinuityStore().apply(request, facts, contradictory)

        parts = self.split_bundle(bundle_bytes(receipt, facts, completeness))
        parts[3] = contradictory.canonical_bytes()
        with self.assertRaisesRegex(IndependentParseError, "completeness:fact-nonmembership-conflict"):
            parse_bundle(self.join_bundle(parts))

    def test_exact_join_chronology_and_roots(self) -> None:
        request, facts, completeness, _, store, receipt = self.apply_case("valid-continuity")
        self.assertEqual(store.state, receipt.after_state)
        self.assertEqual(receipt.before_state.sequence, 0)
        self.assertEqual(receipt.after_state.sequence, 1)
        self.assertEqual(receipt.decision.state_before_id, receipt.before_state.state_id)
        self.assertEqual(receipt.decision.state_after_id, receipt.after_state.state_id)
        self.assertEqual(receipt.decision.event_time, request.event_time)
        self.assertEqual(receipt.decision.observation_time, request.observation_time)
        self.assertEqual(receipt.decision.rule_effective_time, request.rule_effective_time)
        self.assertEqual(receipt.decision.decision_time, request.decision_time)
        self.assertEqual([row.mode for row in receipt.accesses], [ACCESS_READ, ACCESS_WRITE])
        self.assertEqual([row.access_index for row in receipt.accesses], [0, 1])
        self.assertEqual(receipt.accesses[0].access_time, request.observation_time)
        self.assertEqual(receipt.accesses[1].access_time, request.decision_time)
        self.assertEqual(receipt.accesses[0].value_before, facts.source_root)
        self.assertEqual(receipt.accesses[0].value_after, facts.source_root)
        self.assertNotEqual(receipt.accesses[1].value_before, receipt.accesses[1].value_after)
        self.assertEqual(receipt.join_id, receipt.join_id)
        self.assertEqual(receipt.decision.completeness_id, completeness.evidence_id)

    def test_producer_join_enforces_roles_times_values_and_transition(self) -> None:
        request, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        read, write = receipt.accesses
        replacement = b"\xA5" * 64

        invalid_joins = (
            (
                "swapped-roles",
                (
                    replace(read, mode=ACCESS_WRITE, value_after=replacement),
                    replace(write, mode=ACCESS_READ, value_after=write.value_before),
                ),
                "join:read",
            ),
            (
                "read-read",
                (read, replace(write, mode=ACCESS_READ, value_after=write.value_before)),
                "join:write",
            ),
            (
                "write-write",
                (replace(read, mode=ACCESS_WRITE, value_after=replacement), write),
                "join:read",
            ),
            ("unknown-role", (replace(read, mode=9), write), "access:mode"),
            ("wrong-access-order", (replace(read, access_index=1), replace(write, access_index=0)), "join:access-order"),
            ("wrong-access-count", (replace(read, access_count=3), write), "access:index-count"),
            ("wrong-decision-index", (replace(read, decision_index=1), write), "access:index-count"),
            ("wrong-decision-id", (replace(read, decision_id=replacement), write), "join:decision-binding"),
            ("read-at-decision", (replace(read, access_time=receipt.decision.decision_time), write), "join:read"),
            ("write-at-observation", (read, replace(write, access_time=receipt.decision.observation_time)), "join:write"),
            ("read-before-value", (replace(read, value_before=replacement, value_after=replacement), write), "join:read"),
            ("read-after-value", (replace(read, value_after=replacement), write), "access:read-mutates"),
            ("read-address", (replace(read, address=replacement), write), "join:read"),
            ("read-key", (replace(read, key=replacement), write), "join:read"),
            ("write-address", (read, replace(write, address=replacement)), "join:write"),
            ("write-key", (read, replace(write, key=replacement)), "join:write"),
            (
                "wrong-before-state-binding",
                (read, write),
                "join:state-binding",
            ),
            (
                "wrong-after-state-binding",
                (read, write),
                "join:state-binding",
            ),
        )
        invalid_states = {
            "wrong-before-state-binding": (
                replace(receipt.before_state, context_id=replacement),
                receipt.after_state,
            ),
            "wrong-after-state-binding": (
                receipt.before_state,
                replace(receipt.after_state, context_id=replacement),
            ),
        }
        for label, accesses, error in invalid_joins:
            before_state, after_state = invalid_states.get(
                label,
                (receipt.before_state, receipt.after_state),
            )
            with self.assertRaisesRegex(ContinuityError, error, msg=label):
                DecisionAccessJoin(receipt.decision, accesses, before_state, after_state).join_id

        bad_write = replace(write, value_before=replacement)
        bad_accesses = (read, bad_write)
        bad_join = DecisionAccessJoin(receipt.decision, bad_accesses, receipt.before_state, receipt.after_state)
        with self.assertRaisesRegex(ContinuityError, "join:write-state"):
            bad_join.join_id
        with self.assertRaisesRegex(ContinuityError, "join:write-state"):
            replace(receipt, accesses=bad_accesses).canonical_bytes()

        bad_after = replace(receipt.after_state, audit_head=replacement)
        bad_decision = replace(receipt.decision, state_after_id=bad_after.state_id)
        bad_write = replace(write, value_after=bad_after.audit_head)
        bad_accesses = (read, bad_write)
        bad_join = DecisionAccessJoin(bad_decision, bad_accesses, receipt.before_state, bad_after)
        with self.assertRaisesRegex(ContinuityError, "join:state-transition"):
            bad_join.join_id
        with self.assertRaisesRegex(ContinuityError, "join:state-transition"):
            replace(
                receipt,
                decision=bad_decision,
                accesses=bad_accesses,
                after_state=bad_after,
            ).canonical_bytes()

    def test_deterministic_rebuild_parse_and_replay_contract(self) -> None:
        request, facts, completeness, exception = build_demo_case("valid-continuity")
        first_store = ContinuityStore()
        first = first_store.apply(request, facts, completeness, exception)

        retry_request, retry_facts, retry_completeness, retry_exception = build_demo_case("valid-continuity")
        second = ContinuityStore().apply(
            retry_request,
            retry_facts,
            retry_completeness,
            retry_exception,
        )
        first_receipt_raw = first.canonical_bytes()
        second_receipt_raw = second.canonical_bytes()
        first_bundle_raw = bundle_bytes(first, facts, completeness)
        second_bundle_raw = bundle_bytes(second, retry_facts, retry_completeness)
        self.assertEqual(first_receipt_raw, second_receipt_raw)
        self.assertEqual(first_bundle_raw, second_bundle_raw)
        self.assertEqual(first.join_id, second.join_id)
        self.assertEqual(first.receipt_id, second.receipt_id)
        self.assertEqual(
            DecisionAccessJoin(first.decision, first.accesses, first.before_state, first.after_state).join_id,
            first.join_id,
        )

        parsed = ContinuityReceipt.parse(
            first_receipt_raw,
            before_state=first.before_state,
            after_state=first.after_state,
            request=request,
            exception_authorization=exception,
        )
        self.assertEqual(parsed.canonical_bytes(), first_receipt_raw)
        self.assertEqual(
            parse_bundle(first_bundle_raw)["status"],
            "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_PASS",
        )
        with self.assertRaisesRegex(ContinuityError, "replay:attempt"):
            first_store.apply(request, facts, completeness, exception)

    def test_plaintext_acceptance_is_not_proof_acceptance_or_clear(self) -> None:
        _, _, _, _, _, receipt = self.apply_case("valid-continuity")
        self.assertEqual(receipt.decision.effective_directive, DIRECTIVE_CLEAR)
        self.assertFalse(receipt.proof_session_accepted)
        self.assertIsNone(receipt.proof_suite_id)
        self.assertEqual(receipt.decision.proof_session_accepted, 0)
        self.assertEqual(receipt.decision.economic_mutation, 0)

    def test_authoritative_absence_is_hold_but_incomplete_is_review(self) -> None:
        _, incomplete_facts, _, _, _, incomplete = self.apply_case("missing-incomplete-feed")
        _, complete_facts, complete_evidence, _, _, absent = self.apply_case("authoritative-absence")
        self.assertEqual(incomplete_facts.facts, ())
        self.assertEqual(incomplete.decision.effective_directive, DIRECTIVE_HUMAN_REVIEW)
        self.assertFalse(complete_evidence.complete is False)
        self.assertEqual(complete_facts.facts, ())
        self.assertEqual(absent.decision.effective_directive, DIRECTIVE_HOLD)
        self.assertTrue(complete_evidence.nonmembership_keys)

    def test_decision_time_outside_control_interval_is_distinct_review(self) -> None:
        request, facts, completeness, _, _, _ = self.apply_case("valid-continuity")
        request = replace(request, decision_time=9_000)
        receipt = ContinuityStore().apply(request, facts, completeness)
        self.assertEqual(receipt.decision.effective_directive, DIRECTIVE_HUMAN_REVIEW)
        self.assertEqual(receipt.decision.reason_id, REASON_CONTROL_INTERVAL)
        parsed = parse_bundle(bundle_bytes(receipt, facts, completeness))
        self.assertEqual(parsed["effective_directive"], DIRECTIVE_HUMAN_REVIEW)

    def test_replay_wrong_before_and_caller_mode_selection_fail_closed(self) -> None:
        request, facts, completeness, exception, store, receipt = self.apply_case("valid-continuity")
        with self.assertRaisesRegex(ContinuityError, "replay:attempt"):
            store.apply(request, facts, completeness, exception)
        self.assertEqual(store.state, receipt.after_state)

        fresh_store = ContinuityStore()
        wrong_before = replace(request, expected_before_state_id=bytes([request.attempt_id[0] ^ 1]) + request.attempt_id[1:])
        with self.assertRaisesRegex(ContinuityError, "state:before-root"):
            fresh_store.apply(wrong_before, facts, completeness)
        self.assertEqual(fresh_store.state.sequence, 0)

        with self.assertRaisesRegex(ContinuityError, "caller-fields:forbidden"):
            ContinuityStore().apply(request, facts, completeness, caller_fields={"evidence_mode": "PRIVATE_ZK"})
        with self.assertRaisesRegex(ContinuityError, "caller-fields:forbidden"):
            ContinuityStore().apply(request, facts, completeness, caller_fields={"requested_directive": DIRECTIVE_CLEAR})

    def test_exception_is_governed_and_mutation_fails(self) -> None:
        request, facts, completeness, exception, _, receipt = self.apply_case("governed-exception")
        self.assertIsNotNone(exception)
        assert exception is not None
        self.assertEqual(receipt.decision.policy_result, POLICY_RESULT_FAIL)
        self.assertEqual(receipt.decision.effective_directive, DIRECTIVE_EXCEPTION_APPROVED)
        self.assertNotEqual(receipt.decision.exception_id, NO_EXCEPTION_SENTINEL)
        self.assertEqual(exception.signer_id, TRUSTED_AUTHORIZER_ID)

        wrong = ExceptionAuthorization.from_fields(
            signer_id=bytes([TRUSTED_AUTHORIZER_ID[0] ^ 1]) + TRUSTED_AUTHORIZER_ID[1:],
            subject_id=exception.subject_id,
            rule_id=exception.rule_id,
            reason_id=exception.reason_id,
            amount_scope=exception.amount_scope,
            effective_at=exception.effective_at,
            expires_at=exception.expires_at,
            policy_result=exception.policy_result,
        )
        with self.assertRaisesRegex(ContinuityError, "exception:scope-or-interval"):
            ContinuityStore().apply(request, facts, completeness, wrong)

    def test_canonical_corruption_duplicate_and_reorder_reject(self) -> None:
        _, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        fact_raw = bytearray(facts.facts[0].canonical_bytes())
        fact_raw[0] ^= 1
        with self.assertRaises(ContinuityError):
            CredentialEnrollmentFact.parse(bytes(fact_raw))
        complete_raw = bytearray(completeness.canonical_bytes())
        complete_raw[-1] ^= 1
        with self.assertRaises(ContinuityError):
            FeedCompleteness.parse(bytes(complete_raw))
        bundle = bundle_bytes(receipt, facts, completeness)
        with self.assertRaises(IndependentParseError):
            parse_bundle(bundle[:-1])
        reordered = replace(receipt, accesses=(receipt.accesses[1], receipt.accesses[0]))
        with self.assertRaises(ContinuityError):
            reordered.canonical_bytes()
        with self.assertRaises(ContinuityError):
            CredentialFactSet(facts.feed_id, (facts.facts[0], facts.facts[0])).canonical_bytes()

    def test_directive_economic_chronology_retry_and_root_mutations_reject(self) -> None:
        request, facts, completeness, _, store, receipt = self.apply_case("valid-continuity")
        with self.assertRaises(ContinuityError):
            replace(receipt.decision, effective_directive=DIRECTIVE_BLOCK).canonical_bytes()
        with self.assertRaises(ContinuityError):
            replace(receipt.decision, economic_mutation=1).canonical_bytes()
        with self.assertRaises(ContinuityError):
            replace(receipt, economic_mutation=True).canonical_bytes()
        with self.assertRaises(ContinuityError):
            replace(request, event_time=request.observation_time).canonical_bytes()
        with self.assertRaisesRegex(ContinuityError, "replay:attempt"):
            store.apply(replace(request, decision_time=request.decision_time + 1), facts, completeness)

        raw = bytearray(bundle_bytes(receipt, facts, completeness))
        raw[-1] ^= 1
        with self.assertRaises(IndependentParseError):
            parse_bundle(bytes(raw))
        fact_raw = bytearray(facts.facts[0].canonical_bytes())
        fact_raw[-1] ^= 1
        with self.assertRaises(ContinuityError):
            CredentialEnrollmentFact.parse(bytes(fact_raw))

    def test_v2_snapshot_temporal_and_caller_boundary_rejects(self) -> None:
        request = ContinuityRequest.synthetic(b"snapshot-mismatch")
        mismatched = CredentialEnrollmentFact.synthetic(FACT_ACTIVE, observed_at=OBSERVATION_TIME - 1)
        facts = CredentialFactSet(mismatched.feed_id, (mismatched,))
        completeness = make_completeness(request, facts, complete=True)
        with self.assertRaisesRegex(ContinuityError, "fact:observation-time"):
            ContinuityStore().apply(request, facts, completeness)

        with self.assertRaisesRegex(ContinuityError, "fact:terminated-temporal"):
            CredentialEnrollmentFact.synthetic(FACT_TERMINATED, terminated_at=DECISION_TIME + 1)
        with self.assertRaisesRegex(ContinuityError, "fact:expired-temporal"):
            CredentialEnrollmentFact.synthetic(FACT_EXPIRED, expires_at=DECISION_TIME)

        request, facts, completeness, _, _, _ = self.apply_case("valid-continuity")
        with self.assertRaisesRegex(ContinuityError, "caller-fields:forbidden"):
            ContinuityStore().apply(request, facts, completeness, caller_fields={"future_mode_alias": "PRIVATE_ZK"})
        with self.assertRaisesRegex(ContinuityError, "request:synthetic-provider"):
            ContinuityStore().apply(
                replace(request, provider_id=bytes([request.provider_id[0] ^ 1]) + request.provider_id[1:]),
                facts,
                completeness,
            )

    def test_v2_bundle_carries_request_exception_and_initial_state_binding(self) -> None:
        request, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        parts = self.split_bundle(bundle_bytes(receipt, facts, completeness))
        self.assertEqual(parts[1], request.canonical_bytes())
        self.assertEqual(parts[4], EXCEPTION_NONE_SENTINEL)

        request, facts, completeness, exception, _, receipt = self.apply_case("governed-exception")
        parts = self.split_bundle(bundle_bytes(receipt, facts, completeness))
        assert exception is not None
        self.assertEqual(parts[1], request.canonical_bytes())
        self.assertEqual(parts[4], exception.canonical_bytes())

        forged = self.split_bundle(bundle_bytes(receipt, facts, completeness))
        before = bytearray(forged[5])
        before[-1] ^= 1
        forged[5] = bytes(before)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(forged))

    def test_independent_request_time_identity_source_scope_control_and_before_mutations_reject(self) -> None:
        request, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        raw = bundle_bytes(receipt, facts, completeness)
        for offset in (284, 292, 300, 308, 204, 316):
            parts = self.split_bundle(raw)
            mutated = bytearray(parts[1])
            mutated[offset + 7] ^= 1
            parts[1] = bytes(mutated)
            with self.assertRaises(IndependentParseError):
                parse_bundle(self.join_bundle(parts))

        for offset in (12, 76, 140):
            parts = self.split_bundle(raw)
            mutated = bytearray(parts[1])
            mutated[offset] ^= 1
            parts[1] = bytes(mutated)
            with self.assertRaises(IndependentParseError):
                parse_bundle(self.join_bundle(parts))

        for part_index, offset in ((2, 12), (3, 140)):
            parts = self.split_bundle(raw)
            mutated = bytearray(parts[part_index])
            mutated[offset] ^= 1
            parts[part_index] = bytes(mutated)
            with self.assertRaises(IndependentParseError):
                parse_bundle(self.join_bundle(parts))

        parts = self.split_bundle(raw)
        mutated = bytearray(parts[3])
        mutated[204 + 7] ^= 1
        parts[3] = bytes(mutated)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts))

        parts = self.split_bundle(raw)
        receipt_body = bytearray(parts[0][:-64])
        receipt_body[212] ^= 1
        parts[0] = bytes(receipt_body) + parts[0][-64:]
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts))

    def test_independent_fact_subject_and_access_semantic_mutations_reject(self) -> None:
        request, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        raw = bundle_bytes(receipt, facts, completeness)
        parts = self.split_bundle(raw)
        fact_raw = bytearray(parts[2])
        fact_start = 12 + 64 + 4 + 4
        fact_raw[fact_start + 12] ^= 1
        parts[2] = bytes(fact_raw)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts))

        access_mutations = (
            (0, 96, None, "access:read"),   # address
            (0, 95, None, "access:read"),   # time
            (0, 160, None, "access:read"),  # key
            (0, 224, None, "access:read-mutates"),  # value before
            (0, 288, None, "access:read-mutates"),  # value after
            (0, 352, 9, "access:mode"),     # unknown access mode
            (1, 95, None, "access:write"),   # write at the wrong time
            (1, 224, None, "access:write"),  # write before value
            (1, 288, None, "access:write"),  # write after value
            (1, 352, ACCESS_READ, "access:read-mutates"),  # write/read role confusion
        )
        for access_index, field_offset, value, error in access_mutations:
            with self.assertRaisesRegex(IndependentParseError, error):
                parse_bundle(self.mutate_access(raw, access_index, field_offset, value))

        self.assertEqual(receipt.accesses[0].address, source_state_address(request.provider_id))
        self.assertEqual(receipt.accesses[1].address, audit_state_address(request.provider_id))

    def test_independent_rebound_join_mutations_reach_semantic_validators(self) -> None:
        _, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        raw = bundle_bytes(receipt, facts, completeness)
        read_raw, write_raw = tuple(row.canonical_bytes() for row in receipt.accesses)
        replacement = b"\xA5" * 64

        swapped_read = read_raw
        swapped_write = write_raw
        for field_offset, field_length in ((88, 8), (96, 64), (160, 64), (224, 64), (288, 64), (352, 1)):
            swapped_read = self.patch_access_field(
                swapped_read,
                field_offset,
                write_raw[field_offset : field_offset + field_length],
            )
            swapped_write = self.patch_access_field(
                swapped_write,
                field_offset,
                read_raw[field_offset : field_offset + field_length],
            )

        write_write = self.patch_access_field(read_raw, 352, bytes((ACCESS_WRITE,)))
        write_write = self.patch_access_field(write_write, 288, replacement)
        read_read = self.patch_access_field(write_raw, 352, bytes((ACCESS_READ,)))
        read_read = self.patch_access_field(read_read, 288, write_raw[224:288])
        wrong_access_index = self.patch_access_field(read_raw, 80, (1).to_bytes(4, "big"))
        wrong_access_count = self.patch_access_field(read_raw, 84, (3).to_bytes(4, "big"))
        wrong_decision_index = self.patch_access_field(read_raw, 76, (1).to_bytes(4, "big"))
        wrong_decision_id = self.patch_access_field(read_raw, 12, replacement)
        wrong_write_before = self.patch_access_field(write_raw, 224, replacement)
        wrong_write_after = self.patch_access_field(write_raw, 288, replacement)

        mutations = (
            ("coherent-access-row-swap", (swapped_read, swapped_write), "access:read"),
            ("write-write-role-confusion", (write_write, write_raw), "access:read"),
            ("read-read-role-confusion", (read_raw, read_read), "access:write"),
            ("wrong-access-index", (wrong_access_index, write_raw), "join:order-or-decision"),
            ("wrong-access-order", (write_raw, read_raw), "join:order-or-decision"),
            ("wrong-access-count", (wrong_access_count, write_raw), "access:shape"),
            ("wrong-decision-index", (wrong_decision_index, write_raw), "access:shape"),
            ("wrong-access-decision-id", (wrong_decision_id, write_raw), "join:order-or-decision"),
            ("wrong-write-before", (read_raw, wrong_write_before), "access:write"),
            ("wrong-write-after", (read_raw, wrong_write_after), "access:write"),
        )
        for label, access_raws, error in mutations:
            mutated = self.replace_access_rows(raw, access_raws)
            with self.assertRaisesRegex(IndependentParseError, error, msg=label):
                parse_bundle(mutated)

        decision_raw = bytearray(receipt.decision.canonical_bytes())
        decision_raw[12:16] = (1).to_bytes(4, "big")
        with self.assertRaisesRegex(IndependentParseError, "decision:shape-or-flags"):
            parse_bundle(self.replace_decision(raw, bytes(decision_raw)))

    def test_v2_framing_length_enum_and_domain_mutations_reject(self) -> None:
        _, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        raw = bundle_bytes(receipt, facts, completeness)
        wrong_magic = bytearray(raw)
        wrong_magic[:8] = b"BLCBND01"
        with self.assertRaises(IndependentParseError):
            parse_bundle(bytes(wrong_magic))
        wrong_version = bytearray(raw)
        wrong_version[8:10] = (1).to_bytes(2, "big")
        with self.assertRaises(IndependentParseError):
            parse_bundle(bytes(wrong_version))
        trailing = raw + b"\0"
        with self.assertRaises(IndependentParseError):
            parse_bundle(trailing)
        length_abuse = bytearray(raw)
        length_abuse[12:16] = (0xFFFFFFFF).to_bytes(4, "big")
        with self.assertRaises(IndependentParseError):
            parse_bundle(bytes(length_abuse))

        parts = self.split_bundle(raw)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts[:-1]))
        reordered = list(parts)
        reordered[1], reordered[2] = reordered[2], reordered[1]
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(reordered))
        duplicated = list(parts)
        duplicated[4] = duplicated[3]
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(duplicated))

        parts = self.split_bundle(raw)
        facts_raw = bytearray(parts[2])
        fact_start = 12 + 64 + 4 + 4
        facts_raw[fact_start + 12 + 64 * 4] = 9
        parts[2] = bytes(facts_raw)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts))

        parts = self.split_bundle(raw)
        body = bytearray(parts[0][:-64])
        decision_start = 536
        flags_offset = decision_start + 12 + 8 + 19 * 64
        body[flags_offset] = 9
        parts[0] = bytes(body) + parts[0][-64:]
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(parts))

    def test_governed_exception_missing_mutated_expired_wrong_scope_and_underlying_reject(self) -> None:
        request, facts, completeness, exception, _, receipt = self.apply_case("governed-exception")
        assert exception is not None
        raw = bundle_bytes(receipt, facts, completeness)

        missing = self.split_bundle(raw)
        missing[4] = EXCEPTION_NONE_SENTINEL
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(missing))

        mutated = self.split_bundle(raw)
        auth = bytearray(mutated[4])
        auth[-1] ^= 1
        mutated[4] = bytes(auth)
        with self.assertRaises(IndependentParseError):
            parse_bundle(self.join_bundle(mutated))

        expired = ExceptionAuthorization.from_fields(
            signer_id=exception.signer_id,
            subject_id=exception.subject_id,
            rule_id=exception.rule_id,
            reason_id=exception.reason_id,
            amount_scope=exception.amount_scope,
            effective_at=exception.effective_at,
            expires_at=request.decision_time,
            policy_result=exception.policy_result,
        )
        with self.assertRaisesRegex(ContinuityError, "exception:scope-or-interval"):
            ContinuityStore().apply(request, facts, completeness, expired)

        wrong_scope = ExceptionAuthorization.from_fields(
            signer_id=exception.signer_id,
            subject_id=exception.subject_id,
            rule_id=bytes([exception.rule_id[0] ^ 1]) + exception.rule_id[1:],
            reason_id=exception.reason_id,
            amount_scope=exception.amount_scope,
            effective_at=exception.effective_at,
            expires_at=exception.expires_at,
            policy_result=exception.policy_result,
        )
        with self.assertRaisesRegex(ContinuityError, "exception:scope-or-interval"):
            ContinuityStore().apply(request, facts, completeness, wrong_scope)

        valid_request, valid_facts, valid_completeness, _, _, _ = self.apply_case("valid-continuity")
        with self.assertRaisesRegex(ContinuityError, "exception:underlying-result"):
            ContinuityStore().apply(valid_request, valid_facts, valid_completeness, exception)

    def test_profile_adapter_only_binds_frozen_phase0_receipt(self) -> None:
        adapter = TrustBoundaryAdapter.create()
        bindings = build_profile_bindings()
        self.assertEqual(adapter.profile_id, bindings.profile_id)
        self.assertEqual(adapter.phase0_statement_digest, bindings.phase0_statement_digest)
        self.assertEqual(adapter.frozen_phase0_receipt_binding, bindings.frozen_receipt_binding)
        self.assertIsNone(adapter.proof_suite_id)
        self.assertEqual(len(adapter.bind_private_assertion(b"x" * 64)), 64)
        with self.assertRaisesRegex(ContinuityError, "adapter:verifier-owned-profile-mismatch"):
            ContinuityStore(
                replace(adapter, profile_id=bytes([adapter.profile_id[0] ^ 1]) + adapter.profile_id[1:])
            )

    def test_cli_kat_and_telemetry_are_nonactivating(self) -> None:
        root = Path(__file__).resolve().parents[3]  # repository root, for -m
        result = subprocess.run(
            [sys.executable, "-B", "-m", "parked.state_clearance.experiments.native_v3_plaintext_continuity.continuity", "kat"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "NATIVE_V3_PLAINTEXT_CONTINUITY_KAT_PASS")
        self.assertFalse(payload["proof_session_accepted"])
        self.assertIsNone(payload["proof_suite_id"])
        telemetry = __import__(
            "parked.state_clearance.experiments.native_v3_plaintext_continuity.continuity",
            fromlist=["measure_direct_slice"],
        ).measure_direct_slice()
        self.assertEqual(telemetry["cases"], len(DEMO_CASES))
        self.assertFalse(telemetry["proof_backend_selected"])
        self.assertFalse(telemetry["complete_proof_resource_gate_measured"])

    def test_independent_verifier_cross_process(self) -> None:
        root = Path(__file__).resolve().parents[3]  # repository root, for -m
        _, facts, completeness, _, _, receipt = self.apply_case("valid-continuity")
        raw = bundle_bytes(receipt, facts, completeness)
        valid = subprocess.run(
            [sys.executable, "-B", "-m", "parked.state_clearance.experiments.native_v3_plaintext_continuity.independent", "verify"],
            cwd=root,
            input=raw,
            capture_output=True,
            check=False,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr.decode())
        payload = json.loads(valid.stdout)
        self.assertEqual(payload["status"], "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_PASS")
        self.assertEqual(payload["receipt_id"], receipt.receipt_id.hex())
        invalid = subprocess.run(
            [sys.executable, "-B", "-m", "parked.state_clearance.experiments.native_v3_plaintext_continuity.independent", "verify"],
            cwd=root,
            input=raw[:-1],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(invalid.returncode, 0)
        rejected = json.loads(invalid.stdout)
        self.assertEqual(rejected["status"], "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_REJECT")


if __name__ == "__main__":
    unittest.main()
