import json
import os
import threading
import unittest
from copy import deepcopy
from dataclasses import replace
from hashlib import sha3_512
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    _claim_source_commitment_for_oracle,
    _submit_single_batch,
    submit_batches,
)
from app.batch.leaf import current_duplicate_pepper
from app.batch.poseidon import FIELD_MODULUS
from app.batch.verifier_receipt import (
    PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
    PRODUCTION_VERIFICATION_KIND,
    VERIFIER_RECEIPT_SCHEMA,
    LocalSyntheticVerifierAdapter,
    VerificationRequest,
    VerifiedBatchReceipt,
    VerifierAdapterDescriptor,
    VerifierReceiptIssuer,
)
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[2]
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def roles():
    book = RoleBook()
    book.grant(ADMIN, "admin@example.gov")
    book.grant(OPERATOR, "operator@example.gov")
    book.grant(AUDITOR, "auditor@example.gov")
    return book


def sample_payload(claim_id: str, amount: float = 125.0, flags=None, service_date: str | None = None, config=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    amount_text = f"{amount:.2f}"
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    payload["edi"] = (
        payload["edi"]
        .replace(f"CLM*{claim_id}*125.00", f"CLM*{claim_id}*{amount_text}")
        .replace("SV1*HC:99213*125.00", f"SV1*HC:99213*{amount_text}")
    )
    if service_date:
        payload["edi"] = payload["edi"].replace("DTP*472*D8*20260601", f"DTP*472*D8*{service_date}")
    if flags:
        payload["flags"].update(flags)
    active_config = config or BatchConfig(enforce_nullifier_proofs=False)
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        return payload
    ctx = build_shared_context(
        parsed,
        payload["flags"],
        strict_oracle=False,
        tar_required_procedure_codes=active_config.tar_required_procedure_codes,
    )
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=active_config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    tar_authorization_commitment = tar_authorization_commitment_for_context(
        ctx,
        active_config.tar_required_procedure_codes,
    )
    payload["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
        )
        for fact in DECISION_FACTS
    ]
    return payload


def privacy_v2_public_inputs_for_batch(batch) -> tuple[str, ...]:
    return (
        f"{2:064x}",
        f"{7001:064x}",
        f"{1:064x}",
        batch.duplicate_check_before,
        batch.duplicate_check_after,
        batch.claim_source_root,
        batch.oracle_facts_root,
        batch.policy_root,
        batch.ruleset_record,
        f"{9:064x}",
        f"{10:064x}",
        f"{11:064x}",
    )


def attach_synthetic_receipt(authority, adapter, batch):
    public_inputs = privacy_v2_public_inputs_for_batch(batch)
    placeholder = VerificationRequest.create(
        batch_id=batch.batch_id,
        verifier_key_id=batch.verifier_key_id,
        public_inputs=public_inputs,
        proof=b"placeholder",
    )
    proof = adapter.synthetic_proof(placeholder)
    return authority.verify_and_attach_receipt(
        batch,
        public_inputs_v2=public_inputs,
        proof=proof,
    )


def mutated_public_input(value: str, index: int) -> str:
    if index == 0:
        return f"{3:064x}"
    candidate = (int(value, 16) + 1) % FIELD_MODULUS
    if candidate == int(value, 16):
        candidate = (candidate + 1) % FIELD_MODULUS
    if index == 1 and candidate == 0:
        candidate = 1
    return f"{candidate:064x}"


class NoOpSelfDeclaredProductionAdapter:
    def __init__(self) -> None:
        self.verify_called = False
        self._descriptor = VerifierAdapterDescriptor(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            profile_id="MALICIOUS-NOOP-PRODUCTION",
            public_input_schema=PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
            verifier_artifact_digest_sha3_512=sha3_512(b"malicious-noop-adapter").hexdigest(),
            verification_kind=PRODUCTION_VERIFICATION_KIND,
        )

    @property
    def descriptor(self) -> VerifierAdapterDescriptor:
        return self._descriptor

    def verify(self, _request: VerificationRequest) -> None:
        self.verify_called = True


class Phase2FixedArchitectureAttackTests(unittest.TestCase):
    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_competing_prebuilt_batches_same_root_second_rejected_as_stale(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()

        batch_a, next_a, next_accumulators_a = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RACE-A", 201.0)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        batch_b, next_b, next_accumulators_b = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RACE-B", 202.0)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )

        authority.commit_batch(batch_a, next_a, next_accumulators_a)
        with self.assertRaisesRegex(ValueError, "stale nullifier root"):
            authority.commit_batch(batch_b, next_b, next_accumulators_b)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_concurrent_competing_commits_are_atomic_and_exactly_one_is_stale(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch_a, next_a, next_accumulators_a = _submit_single_batch(
            0,
            [sample_payload("BL-P2-CONCURRENT-RACE-A", 201.01)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        batch_b, next_b, next_accumulators_b = _submit_single_batch(
            0,
            [sample_payload("BL-P2-CONCURRENT-RACE-B", 201.02)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        barrier = threading.Barrier(3)
        result_lock = threading.Lock()
        results: list[tuple[str, str]] = []

        def commit(name, batch, next_tree, next_accumulators):
            barrier.wait()
            try:
                authority.commit_batch(batch, next_tree, next_accumulators)
            except Exception as exc:  # Captured verbatim for deterministic race assertions below.
                result = (name, f"{type(exc).__name__}:{exc}")
            else:
                result = (name, "committed")
            with result_lock:
                results.append(result)

        threads = (
            threading.Thread(target=commit, args=("a", batch_a, next_a, next_accumulators_a)),
            threading.Thread(target=commit, args=("b", batch_b, next_b, next_accumulators_b)),
        )
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "concurrent commit thread deadlocked")

        outcomes = sorted(outcome for _name, outcome in results)
        self.assertEqual(outcomes, ["ValueError:stale nullifier root", "committed"])
        self.assertEqual(len(authority.records), 1)
        self.assertIn(authority.nullifier_tree.root_hex, {next_a.root_hex, next_b.root_hex})

    def test_default_unverified_submission_leaves_all_authority_state_unchanged(self):
        authority = BatchAuthority()
        recorder = LocalBatchRecorder(authority=authority)
        before_tree, before_root, before_accumulators, before_accumulator_root = authority.snapshot()
        before_records = dict(authority.records)
        before_check_keys = set(authority.seen_duplicate_check_keys)
        before_identity_keys = set(authority.seen_duplicate_identity_keys)
        before_stable_identity_keys = set(authority.seen_stable_duplicate_identity_keys)

        batch = submit_batches(
            [sample_payload("BL-P2-UNVERIFIED-NO-COMMIT", 201.5)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        after_tree, after_root, after_accumulators, after_accumulator_root = authority.snapshot()
        self.assertFalse(batch.accepted_by_real_verifier)
        self.assertEqual(authority.records, before_records)
        self.assertEqual(authority.seen_duplicate_check_keys, before_check_keys)
        self.assertEqual(authority.seen_duplicate_identity_keys, before_identity_keys)
        self.assertEqual(authority.seen_stable_duplicate_identity_keys, before_stable_identity_keys)
        self.assertEqual(after_root, before_root)
        self.assertEqual(after_tree.root_hex, before_tree.root_hex)
        self.assertEqual(after_accumulators, before_accumulators)
        self.assertEqual(after_accumulator_root, before_accumulator_root)

    def test_direct_unverified_commit_rejects_before_any_state_mutation(self):
        authority = BatchAuthority()
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-DIRECT-UNVERIFIED", 201.75)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )

        with self.assertRaisesRegex(ValueError, "verifier-authenticated receipt required"):
            authority.commit_batch(batch, next_tree, next_accumulators)

        self.assertEqual(authority.records, {})
        self.assertEqual(authority.seen_duplicate_check_keys, set())
        self.assertEqual(authority.seen_duplicate_identity_keys, set())
        self.assertEqual(authority.seen_stable_duplicate_identity_keys, set())
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    def test_default_multichunk_submission_returns_only_first_unsettled_candidate(self):
        authority = BatchAuthority()
        recorder = LocalBatchRecorder(authority=authority)
        root_before = authority.nullifier_tree.root_hex
        batches = submit_batches(
            [
                sample_payload("BL-P2-UNSETTLED-CHUNK-A", 201.76, service_date="20260601"),
                sample_payload("BL-P2-UNSETTLED-CHUNK-B", 201.77, service_date="20260602"),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(max_claims=1, enforce_nullifier_proofs=False),
        )

        self.assertEqual(len(batches), 1)
        self.assertEqual([packet.claim_id for packet in batches[0].claim_packets], ["BL-P2-UNSETTLED-CHUNK-A"])
        self.assertEqual(batches[0].duplicate_check_before, root_before)
        self.assertNotEqual(batches[0].duplicate_check_after, root_before)
        self.assertEqual(authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_typed_local_receipt_is_authority_issued_and_has_no_boolean_fallback(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-p07-verifier-artifact",
        )
        authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-TYPED-RECEIPT", 201.78)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        authenticated = attach_synthetic_receipt(authority, adapter, batch)

        self.assertIsNotNone(authenticated.verifier_receipt)
        self.assertFalse(authenticated.accepted_by_real_verifier)
        self.assertEqual(len(authenticated.public_inputs), 12)
        self.assertEqual(tuple(authenticated.public_inputs), authenticated.verifier_receipt.public_inputs)
        with self.assertRaises(AttributeError):
            authenticated.accepted_by_real_verifier = True
        authority.commit_batch(authenticated, next_tree, next_accumulators)
        self.assertIn(authenticated.batch_id, authority.records)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_every_privacy_v2_field_and_in_place_batch_statement_mutation_is_rejected(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-p07-verifier-artifact",
        )
        authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-ALL-12-RECEIPT-FIELDS", 201.785)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        authenticated = attach_synthetic_receipt(authority, adapter, batch)
        self.assertEqual(tuple(authenticated.public_inputs), authenticated.verifier_receipt.public_inputs)

        for index in range(len(PUBLIC_INPUT_FIELD_NAMES_V2)):
            with self.subTest(surface="batch_public_inputs", index=index):
                mutated_values = list(authenticated.public_inputs)
                mutated_values[index] = mutated_public_input(mutated_values[index], index)
                mutated_batch = replace(authenticated, public_inputs=mutated_values)
                expected = (
                    "privacy_v2_protocol_version_mismatch"
                    if index == 0
                    else "verifier receipt public inputs mismatch"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    authority.commit_batch(mutated_batch, next_tree, next_accumulators)

            with self.subTest(surface="receipt_public_inputs", index=index):
                mutated_values = list(authenticated.verifier_receipt.public_inputs)
                mutated_values[index] = mutated_public_input(mutated_values[index], index)
                mutated_receipt = replace(
                    authenticated.verifier_receipt,
                    public_inputs=tuple(mutated_values),
                    settlement_domain=(
                        mutated_values[1]
                        if index == 1
                        else authenticated.verifier_receipt.settlement_domain
                    ),
                )
                mutated_batch = replace(
                    authenticated,
                    public_inputs=list(mutated_values),
                    verifier_receipt=mutated_receipt,
                )
                expected = (
                    "privacy_v2_protocol_version_mismatch"
                    if index == 0
                    else "verifier_receipt_authority_mismatch"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    authority.commit_batch(mutated_batch, next_tree, next_accumulators)

        in_place_mutated = deepcopy(authenticated)
        in_place_mutated.public_inputs[11] = mutated_public_input(in_place_mutated.public_inputs[11], 11)
        with self.assertRaisesRegex(ValueError, "verifier receipt public inputs mismatch"):
            authority.commit_batch(in_place_mutated, next_tree, next_accumulators)

        self.assertEqual(authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_authority_pinned_verifier_descriptor_rejects_profile_and_artifact_drift(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-p07-verifier-artifact",
        )
        authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-DESCRIPTOR-DRIFT", 201.786)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        authenticated = attach_synthetic_receipt(authority, adapter, batch)
        original_descriptor = adapter.descriptor

        mutations = (
            replace(original_descriptor, profile_id="MUTATED-SYNTHETIC-PROFILE"),
            replace(
                original_descriptor,
                verifier_artifact_digest_sha3_512=sha3_512(b"mutated-artifact").hexdigest(),
            ),
        )
        for mutated_descriptor in mutations:
            with self.subTest(mutated_descriptor=mutated_descriptor):
                adapter._descriptor = mutated_descriptor
                with self.assertRaisesRegex(RuntimeError, "verifier_adapter_descriptor_changed"):
                    authority.commit_batch(authenticated, next_tree, next_accumulators)
        adapter._descriptor = original_descriptor

        self.assertEqual(authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_self_declared_noop_production_adapter_cannot_issue_or_commit_receipt(self):
        adapter = NoOpSelfDeclaredProductionAdapter()
        with self.assertRaisesRegex(RuntimeError, "production_verifier_registration_unavailable"):
            VerifierReceiptIssuer(adapter)
        with self.assertRaisesRegex(RuntimeError, "production_verifier_registration_unavailable"):
            BatchAuthority(verifier_adapter=adapter)
        self.assertFalse(adapter.verify_called)

        authority = BatchAuthority()
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-NOOP-PRODUCTION-ADAPTER", 201.787)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        public_inputs = privacy_v2_public_inputs_for_batch(batch)
        forged_receipt = VerifiedBatchReceipt(
            receipt_schema=VERIFIER_RECEIPT_SCHEMA,
            public_input_schema=PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
            public_input_names=PUBLIC_INPUT_FIELD_NAMES_V2,
            public_inputs=public_inputs,
            settlement_domain=public_inputs[1],
            batch_id=batch.batch_id,
            verifier_key_id=batch.verifier_key_id,
            profile_id="MALICIOUS-NOOP-PRODUCTION",
            verifier_artifact_digest_sha3_512=adapter.descriptor.verifier_artifact_digest_sha3_512,
            proof_digest_sha3_512=sha3_512(b"fake-proof").hexdigest(),
            verification_kind=PRODUCTION_VERIFICATION_KIND,
            authority_tag_sha3_512="00" * 64,
        )
        forged_batch = replace(
            batch,
            public_inputs=list(public_inputs),
            verifier_receipt=forged_receipt,
        )
        self.assertFalse(forged_receipt.production_verified)
        self.assertFalse(forged_batch.accepted_by_real_verifier)
        with self.assertRaisesRegex(ValueError, "production_verifier_receipt_unavailable"):
            authority.commit_batch(forged_batch, next_tree, next_accumulators)
        self.assertEqual(authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_forged_or_cross_authority_receipt_cannot_commit(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-p07-verifier-artifact",
        )
        authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-FORGED-RECEIPT", 201.79)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        authenticated = attach_synthetic_receipt(authority, adapter, batch)
        forged_receipt = replace(
            authenticated.verifier_receipt,
            proof_digest_sha3_512="00" * 64,
        )
        forged_batch = replace(authenticated, verifier_receipt=forged_receipt)

        with self.assertRaisesRegex(ValueError, "verifier_receipt_authority_mismatch"):
            authority.commit_batch(forged_batch, next_tree, next_accumulators)

        second_authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        with self.assertRaisesRegex(ValueError, "verifier_receipt_authority_mismatch"):
            second_authority.commit_batch(authenticated, next_tree, next_accumulators)
        self.assertEqual(authority.records, {})
        self.assertEqual(second_authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(second_authority.nullifier_tree.root_hex, root_before)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_typed_receipt_cannot_authorize_empty_noop_transition(self):
        adapter = LocalSyntheticVerifierAdapter(
            verifier_key_id="NATIVE_STARK_SETTLEMENT_V1",
            artifact_bytes=b"synthetic-p07-verifier-artifact",
        )
        authority = BatchAuthority(
            allow_test_only_unverified_settlement=True,
            verifier_adapter=adapter,
        )
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, _next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-NOOP-RECEIPT", 201.80)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        no_op = replace(
            batch,
            attempt_nullifiers=[],
            duplicate_check_after=root_before,
        )
        authenticated_no_op = attach_synthetic_receipt(authority, adapter, no_op)

        with self.assertRaisesRegex(ValueError, "empty nullifier transition forbidden"):
            authority.commit_batch(authenticated_no_op, base_tree, next_accumulators)
        self.assertEqual(authority.records, {})
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_authoritative_state_exposure_and_post_commit_aliasing_are_blocked(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        recorder = LocalBatchRecorder(authority=authority)
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-STATE-OWNERSHIP", 201.81)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        expected_claim_count = batch.claim_count
        expected_attempts = list(batch.attempt_nullifiers)
        expected_payment_status = batch.payments[0].settlement["status"]
        authority.commit_batch(batch, next_tree, next_accumulators)
        committed_root = authority.nullifier_tree.root_hex
        committed_accumulators = dict(authority.accumulator_states)

        batch.claim_count = 999
        batch.attempt_nullifiers.append(1)
        batch.payments[0].settlement["status"] = "forged-after-commit"
        next_accumulators.clear()

        stored = authority.records[batch.batch_id]
        self.assertEqual(stored.claim_count, expected_claim_count)
        self.assertEqual(stored.attempt_nullifiers, expected_attempts)
        self.assertEqual(stored.payments[0].settlement["status"], expected_payment_status)
        self.assertEqual(dict(authority.accumulator_states), committed_accumulators)

        stored.claim_count = 888
        stored.attempt_nullifiers.clear()
        fresh = authority.records[batch.batch_id]
        self.assertEqual(fresh.claim_count, expected_claim_count)
        self.assertEqual(fresh.attempt_nullifiers, expected_attempts)

        exposed_tree = authority.nullifier_tree
        extra_nullifier = 1
        while exposed_tree.contains(extra_nullifier):
            extra_nullifier += 1
        exposed_tree.insert(extra_nullifier)
        recorder_tree = recorder.nullifier_tree
        recorder_tree.insert(extra_nullifier)
        self.assertEqual(authority.nullifier_tree.root_hex, committed_root)

        with self.assertRaises(TypeError):
            authority.records["forged"] = fresh
        with self.assertRaises(AttributeError):
            authority.seen_duplicate_check_keys.add("forged")
        with self.assertRaises(AttributeError):
            authority.approved_ruleset_records.add("forged")
        with self.assertRaises(TypeError):
            authority.accumulator_states["forged"] = next(iter(committed_accumulators.values()))
        with self.assertRaises(TypeError):
            authority.pepper_versions["forged"] = "forged"
        with self.assertRaises(AttributeError):
            authority.overlap_pepper_versions.add("forged")
        with self.assertRaises(AttributeError):
            authority.global_nullifier_pepper = "forged"

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_test_only_commit_rederives_ordered_tree_and_rejects_tampering_without_mutation(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [
                sample_payload("BL-P2-TAMPERED-AFTER-TREE-A", 201.85, service_date="20260601"),
                sample_payload("BL-P2-TAMPERED-AFTER-TREE-B", 201.95, service_date="20260602"),
            ],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )
        tampered_tree = next_tree.clone()
        extra_nullifier = 1
        while tampered_tree.contains(extra_nullifier):
            extra_nullifier += 1
        tampered_tree.insert(extra_nullifier)

        with self.assertRaisesRegex(ValueError, "next nullifier tree root mismatch"):
            authority.commit_batch(batch, tampered_tree, next_accumulators)
        with self.assertRaisesRegex(ValueError, "batch nullifier root after mismatch"):
            authority.commit_batch(
                replace(batch, duplicate_check_after=tampered_tree.root_hex),
                next_tree,
                next_accumulators,
            )
        with self.assertRaisesRegex(ValueError, "duplicate attempt nullifier within batch"):
            authority.commit_batch(
                replace(batch, attempt_nullifiers=[*batch.attempt_nullifiers, batch.attempt_nullifiers[0]]),
                next_tree,
                next_accumulators,
            )
        with self.assertRaisesRegex(ValueError, "next nullifier tree root mismatch"):
            authority.commit_batch(
                replace(batch, attempt_nullifiers=list(reversed(batch.attempt_nullifiers))),
                next_tree,
                next_accumulators,
            )

        self.assertEqual(authority.records, {})
        self.assertEqual(authority.seen_duplicate_check_keys, set())
        self.assertEqual(authority.seen_duplicate_identity_keys, set())
        self.assertEqual(authority.seen_stable_duplicate_identity_keys, set())
        self.assertEqual(authority.nullifier_tree.root_hex, root_before)
        self.assertEqual(authority.accumulator_states, accumulator_states)
        self.assertEqual(authority.accumulator_root, accumulator_root)

    def test_test_only_unverified_settlement_mode_is_rejected_in_production(self):
        with patch.dict(
            os.environ,
            {
                "BL_ENV": "production",
                "BL_DEV": "1",
                "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "test_only_unverified_settlement_forbidden"):
                BatchAuthority(allow_test_only_unverified_settlement=True)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_ruleset_revoked_after_build_is_rejected_at_commit(self):
        book = roles()
        authority = BatchAuthority(
            approved_ruleset_versions=["ruleset-v1"],
            allow_test_only_unverified_settlement=True,
        )
        config = BatchConfig(ruleset_version="ruleset-v1", enforce_nullifier_proofs=False)
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RULESET-REVOCATION", 203.0, config=config)],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
        )

        authority.set_ruleset_approved("ruleset-v1", False, actor="admin@example.gov", access=book)
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            authority.commit_batch(batch, next_tree, next_accumulators)

    def test_operator_cannot_approve_forged_ruleset(self):
        authority = BatchAuthority()
        with self.assertRaises(AccessDenied):
            authority.set_ruleset_approved("forged-ruleset", True, actor="operator@example.gov", access=roles())

    def test_unapproved_ruleset_blocked_before_batch_admission(self):
        authority = BatchAuthority(approved_ruleset_versions=["approved-v1"])
        forged_config = BatchConfig(ruleset_version="forged-v2", enforce_nullifier_proofs=False)
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            submit_batches(
                [sample_payload("BL-P2-FORGED-RULESET", 204.0, config=forged_config)],
                actor="operator@example.gov",
                access=roles(),
                config=forged_config,
                recorder=LocalBatchRecorder(authority=authority),
            )

    def test_default_batch_mode_requires_real_multi_claim_proof_for_many_approved_claims(self):
        config = BatchConfig(max_claims=10)
        batch = submit_batches(
            [
                sample_payload("BL-P2-BATCH-PROOF-1", 211.0, service_date="20260601", config=config),
                sample_payload("BL-P2-BATCH-PROOF-2", 212.0, service_date="20260602", config=config),
                sample_payload("BL-P2-BATCH-PROOF-3", 213.0, service_date="20260603", config=config),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=config,
        )[0]

        self.assertEqual(batch.claim_count, 3)
        self.assertEqual(len(batch.nullifier_proofs), 1)
        self.assertEqual(
            batch.nullifier_proofs[0]["mode"],
            "native_stark_database_transition_required",
        )
        self.assertFalse(batch.nullifier_proofs[0]["accepted"])
        self.assertEqual(batch.nullifier_proofs[0]["attempt_nullifier_count"], 3)
        self.assertFalse(batch.accepted_by_real_verifier)

    def test_mixed_quarantine_denial_and_approval_nets_payment_only_for_approved_claims(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        batch = submit_batches(
            [
                sample_payload("BL-P2-MIXED-APPROVED", 221.0, config=config),
                sample_payload("BL-P2-MIXED-DENIED", 222.0, {"eligibility_active": False}, service_date="20260602", config=config),
                {"edi": "", "flags": {}, "claim_id": "BL-P2-MIXED-BAD"},
                sample_payload("BL-P2-MIXED-DUP", 221.0, config=config),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=config,
        )[0]

        self.assertEqual([packet.decision for packet in batch.claim_packets], ["approved", "denied"])
        self.assertEqual(batch.quarantine_count, 2)
        self.assertEqual([item.reason for item in batch.quarantined], ["ingestion_failed", "duplicate_identity_key_already_recorded"])
        self.assertEqual(len(batch.payments), 1)
        self.assertEqual(batch.payments[0].approved_claim_count, 1)
        self.assertEqual(batch.payments[0].amount_cents, 12500)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_phase2_residual_duplicate_only_resubmission_not_recorded(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        recorder = LocalBatchRecorder(authority=authority)
        submit_batches(
            [sample_payload("BL-P2-EMPTY-FIRST", 231.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )
        duplicate_only = submit_batches(
            [sample_payload("BL-P2-EMPTY-DUP", 231.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(duplicate_only.claim_count, 0)
        self.assertEqual(duplicate_only.quarantine_count, 1)
        self.assertEqual(duplicate_only.quarantined[0].reason, "duplicate_identity_key_already_recorded")
        self.assertNotIn(duplicate_only.batch_id, recorder.records)

if __name__ == "__main__":
    unittest.main()
