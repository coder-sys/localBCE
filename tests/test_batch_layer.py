import copy
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import app.batch.batch_orchestrator as batch_orchestrator
from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    MAX_CLAIMS_PER_SUBMISSION,
    _claim_source_commitment_for_oracle,
    _enforce_payment_reconciliation,
    adjudicate_for_batch,
    ruleset_policy_record,
    submit_batches,
)
from app.batch.leaf import build_claim_leaf_set, combined_batch_commitment, duplicate_check_key, duplicate_identity_key, payment_leaf, payment_payee_record, stable_private_hash
from app.batch.leaf import current_duplicate_pepper
from app.batch.merkle import MerkleTree, PoseidonMerkleTree, verify_inclusion
from app.batch.proof_status import REAL_PROOF_REQUIRED_STATUS
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.provider_alias import provider_payment_alias
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[1]
RULESET = "rarc_mapping_v1_pending_domain_ratification"
RULESET_RECORD = ruleset_policy_record(RULESET)
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def sample_payload(claim_id="BL-CLAIM-0001", flags=None, edi_transform=None, *, duplicate_pepper=None, config=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    active_config = config or BatchConfig()
    try:
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
            duplicate_pepper=duplicate_pepper or current_duplicate_pepper(),
        )
    except ValueError:
        return payload
    payload["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment_for_context(ctx, active_config.tar_required_procedure_codes),
        )
        for fact in DECISION_FACTS
    ]
    return payload


def context_from_payload(payload):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], strict_oracle=False)


def two_line_transform(first: str = "99213", second: str = "T1019"):
    def transform(edi: str) -> str:
        def service_line(code: str, line_id: int) -> str:
            line = f"SV1*HC:{code}*125.00*UN*1***{line_id}"
            if code == "T1019":
                return f"{line}~REF*G1*PA-OK-123"
            return line

        line_a = service_line(first, 1)
        line_b = service_line(second, 2)
        return (
            edi.replace("*125.00***11:B:1", "*250.00***11:B:1")
            .replace("SV1*HC:99213*125.00*UN*1***1~REF*G1*PA-OK-123", f"{line_a}~{line_b}")
        )

    return transform


class BatchLeafAndMerkleTests(unittest.TestCase):
    def test_leaf_vectors_are_locked(self):
        payload = sample_payload()
        ctx = context_from_payload(payload)
        result, engine_mode = adjudicate_for_batch(ctx)
        leaf_set = build_claim_leaf_set(ctx, result, RULESET_RECORD, "original", engine_mode)
        provider_key = provider_payment_alias(ctx.provider.npi, ctx.provider.name)
        recipient_commitment = stable_private_hash(["CPN_MANAGED_PAYMENTS_PENDING", "recipient", provider_key])
        approved_result_commitment = stable_private_hash([leaf_set.result_leaf])
        reconciliation_commitment = stable_private_hash(
            {
                "provider_payment_key": provider_key,
                "approved_claim_count": 1,
                "expected_net_amount_cents": 12500,
                "approved_result_records": [leaf_set.result_leaf],
            }
        )
        settlement = stable_private_hash(
            ["test-batch-0001", provider_key, recipient_commitment, 12500, reconciliation_commitment, "CPN_MANAGED_PAYMENTS_PENDING", approved_result_commitment]
        )
        pay_leaf = payment_leaf(
            "test-batch-0001",
            provider_key,
            recipient_commitment,
            1,
            12500,
            reconciliation_commitment,
            "CPN_MANAGED_PAYMENTS_PENDING",
            settlement,
            approved_result_commitment,
        )

        # LOCKED_VECTOR_REBASELINE 2026-07-12:
        # - A amount-removed-from-duplicate-identity and B duplicate-identity-keyed-with-pepper
        #   changed duplicate_check_key, duplicate_nullifier, duplicate_leaf, and any leaf
        #   that includes duplicate_key.
        # - C new-stable-duplicate-identity is internal-only and intentionally absent from
        #   these external/audit vectors.
        # - D G8B_FEE_SCHEDULE_PRESENT was added to policy_spec_v1.yaml, changing
        #   RULESET_RECORD plus ruleset/gate downstream values.
        # - E the integer-only RISC Zero proof adjudicator was added to the governed
        #   Rust rules source, changing RULESET_RECORD and its downstream commitments.
        # - F authenticated fee-policy absence, verified prior-authorization handling,
        #   and caller-supplied governed fee schedules changed the governed Rust rules.
        # - G the final semantics-neutral Clippy fix pins rules-engine-rust/src/lib.rs at
        #   SHA-256 456388d8e06156efa7c644cb5f3a2662770161c29c3d7e6fd2597cf63dc02910.
        # - H R24 makes source money string-only, requires exact line-total equality,
        #   rejects malformed totals structurally, and pins rules-engine-rust/src/lib.rs
        #   at SHA-256 a0df54b220f4eef6b0cfb900013ecde882983dcaf1aa7ba77a7c3fba9edc920b.
        # - I R24 rejects policy key/value type coercion before engine selection and pins
        #   app/rules_engine_adapter.py at SHA-256
        #   cca3f7480ff5d3d86ab464d3e872be06f862816b1e0d0bac72b25c2e8dfe8ad8.
        # - J R33 applies the pinned Rust formatter without changing semantics and pins
        #   rules-engine-rust/src/lib.rs at SHA-256
        #   9c14dd0386b17c63e4772a529f73dcbf4e6d22d3ccae89e09689f9fc5ce6f251.
        # Merkle roots below changed only as downstream commitments to the rebaselined
        # claim_leaf/result_leaf values; the tree domains and layout are unchanged.
        # Unchanged controls: provider_key and recipient_commitment.
        self.assertEqual(RULESET_RECORD, "01cb26a95c5652c9d543ebfd12e39c2837c14a95a04753984a242648dbf81d47")
        self.assertEqual(provider_key, "provider_payment_key:83443c19ce8abae3e9d33b9df237c3dba571b4800d9ac0a7cd48d8cd7c7458c6")
        self.assertEqual(recipient_commitment, "cd28b4fe61c86a2017e2e154c525f1120adec8a9b8eb10b09c79a8f81f1da7c7")
        self.assertEqual(approved_result_commitment, "420e055bf6d2cc04a9f9b33f5491320b3a71aa7085ec56bfc013f1e60affbaf7")
        self.assertEqual(reconciliation_commitment, "0ccb760e81cbdf5550bf09f1c3c1a952bc33eaa151451d11936e32d320eb8f15")
        self.assertEqual(leaf_set.claim_leaf, "35c3ef8f11b26951d5e94742b57d76ce35b94be16187a76224cea6e6a91be7f2")
        self.assertEqual(leaf_set.result_leaf, "3963d7dbd83759eb106154953cb587ac336c58155a1933e480d2d856cb883187")
        self.assertEqual(leaf_set.duplicate_check_key, "0505fc3fe7108d90e3b1788afceaaa3ae5dca8e587bbd14bd02fc7e526e99202")
        self.assertEqual(
            leaf_set.duplicate_nullifier,
            2272139441130203997495185412459621129965807134058140640580579173785372561922,
        )
        self.assertEqual(leaf_set.duplicate_leaf, "a7e6a2aaf8d9d2b647a42b1f50b648f8e63645927d67250de902472d6e604944")
        self.assertEqual(pay_leaf, "c35346ef6adb9966cd524ea9df39f7161fa22a48bdf5bc092abeb864f0ea3e30")
        self.assertEqual(PoseidonMerkleTree([leaf_set.claim_leaf], 10, "claim").root, "008d9402a2a186f9c537e8d4ccffdb5bb430cfcd35ee814df6a4d1d65dc13c52")
        self.assertEqual(PoseidonMerkleTree([leaf_set.result_leaf], 10, "result").root, "006f22298951d7a8c786b14e19185f5289225c872a0a16c6a9828c378683f408")

    def test_merkle_round_trip_and_tamper_reject(self):
        leaves = [stable_private_hash(f"leaf-{idx}") for idx in range(5)]
        tree = MerkleTree(leaves, depth=10)
        proof = tree.prove(3)
        self.assertTrue(verify_inclusion(proof.leaf, proof.leaf_index, proof.siblings, proof.root))

        tampered_siblings = list(proof.siblings)
        tampered_siblings[0] = stable_private_hash("tampered")
        self.assertFalse(verify_inclusion(proof.leaf, proof.leaf_index, tampered_siblings, proof.root))

    def test_result_leaf_binds_gate_evidence_and_engine_mode(self):
        payload = sample_payload("BL-LEAF-GATE-EVIDENCE")
        ctx = context_from_payload(payload)
        result, engine_mode = adjudicate_for_batch(ctx)
        base = build_claim_leaf_set(ctx, result, RULESET_RECORD, "original", engine_mode).result_leaf

        changed_gate = copy.deepcopy(result)
        changed_gate.gates[0].reason = "tampered_gate_evidence"
        changed_gate_leaf = build_claim_leaf_set(ctx, changed_gate, RULESET_RECORD, "original", engine_mode).result_leaf

        alternate_engine_mode = "rust_binary" if engine_mode != "rust_binary" else "adapter_fallback"
        changed_engine_leaf = build_claim_leaf_set(ctx, result, RULESET_RECORD, "original", alternate_engine_mode).result_leaf

        self.assertNotEqual(base, changed_gate_leaf)
        self.assertNotEqual(base, changed_engine_leaf)

    def test_prod_like_rust_engine_failure_fails_closed_without_python_approval(self):
        payload = sample_payload("BL-RUST-FAIL-CLOSED")
        ctx = context_from_payload(payload)

        with patch.dict(os.environ, {"BL_ENV": "production"}, clear=False):
            os.environ.pop("BL_FORCE_PYTHON_RULES_ENGINE", None)
            os.environ.pop("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", None)
            with patch.object(batch_orchestrator, "RUST_BIN", Path(sys.executable)):
                with self.assertRaisesRegex(RuntimeError, "rules_engine_unavailable_fail_closed:batch_rust_binary_failed"):
                    adjudicate_for_batch(ctx, BatchConfig())

    def test_payment_leaf_binds_recipient_and_approved_result_set(self):
        provider_key = "provider_payment_key:" + ("11" * 32)
        recipient_commitment = stable_private_hash("recipient-a")
        approved_result_commitment = stable_private_hash(["result-a", "result-b"])
        reconciliation_commitment = stable_private_hash("reconciliation-a")
        settlement = stable_private_hash("settlement")
        base = payment_leaf("batch-a", provider_key, recipient_commitment, 2, 25000, reconciliation_commitment, "CPN_MANAGED_PAYMENTS_PENDING", settlement, approved_result_commitment)

        changed_recipient = payment_leaf(
            "batch-a",
            provider_key,
            stable_private_hash("recipient-b"),
            2,
            25000,
            reconciliation_commitment,
            "CPN_MANAGED_PAYMENTS_PENDING",
            settlement,
            approved_result_commitment,
        )
        changed_results = payment_leaf(
            "batch-a",
            provider_key,
            recipient_commitment,
            2,
            25000,
            reconciliation_commitment,
            "CPN_MANAGED_PAYMENTS_PENDING",
            settlement,
            stable_private_hash(["result-a"]),
        )
        changed_reconciliation = payment_leaf(
            "batch-a",
            provider_key,
            recipient_commitment,
            2,
            25000,
            stable_private_hash("reconciliation-b"),
            "CPN_MANAGED_PAYMENTS_PENDING",
            settlement,
            approved_result_commitment,
        )

        self.assertNotEqual(base, changed_recipient)
        self.assertNotEqual(base, changed_results)
        self.assertNotEqual(base, changed_reconciliation)

    def test_payment_reconciliation_rejects_tampered_net_amount(self):
        provider_key = "provider_payment_key:" + ("22" * 32)
        self.assertEqual(_enforce_payment_reconciliation(provider_key, [12500, 9900], 22400), 22400)
        with self.assertRaisesRegex(ValueError, "payment_reconciliation_mismatch"):
            _enforce_payment_reconciliation(provider_key, [12500, 9900], 999999)

    def test_reordered_service_lines_keep_same_duplicate_identity(self):
        original = context_from_payload(sample_payload("BL-LINE-ORDER-A", edi_transform=two_line_transform("99213", "T1019")))
        reordered = context_from_payload(sample_payload("BL-LINE-ORDER-B", edi_transform=two_line_transform("T1019", "99213")))

        self.assertEqual(duplicate_identity_key(original), duplicate_identity_key(reordered))
        self.assertEqual(duplicate_check_key(original), duplicate_check_key(reordered))


class BatchAccessTests(unittest.TestCase):
    def test_authorized_roles_succeed_and_unauthorized_fails(self):
        roles = RoleBook()
        roles.grant(ADMIN, "admin@example.gov")
        roles.grant(OPERATOR, "operator@example.gov")
        roles.grant(AUDITOR, "auditor@example.gov")

        roles.require_batch_submitter("admin@example.gov")
        roles.require_batch_submitter("operator@example.gov")
        roles.require_appeal_reader("auditor@example.gov")
        with self.assertRaises(AccessDenied):
            roles.require_batch_submitter("auditor@example.gov")
        with self.assertRaises(AccessDenied):
            roles.require_appeal_reader("visitor@example.gov")


class BatchOrchestratorTests(unittest.TestCase):
    def access(self):
        roles = RoleBook()
        roles.grant(OPERATOR, "operator@example.gov")
        return roles

    def admin_access(self):
        roles = self.access()
        roles.grant(ADMIN, "admin@example.gov")
        return roles

    def test_submission_request_has_a_finite_prototype_claim_cap(self):
        with self.assertRaisesRegex(ValueError, "claim_submission_count_exceeds_prototype_limit"):
            submit_batches(
                [{}] * (MAX_CLAIMS_PER_SUBMISSION + 1),
                actor="operator@example.gov",
                access=self.access(),
                recorder=LocalBatchRecorder(),
            )

    def test_deployed_enforcement_disable_switch_is_ignored(self):
        payload = sample_payload("BL-PROD-DISABLE-IGNORED")
        payload.pop("oracle_attestations", None)

        with patch.dict(
            os.environ,
            {
                "BL_ENV": "production",
                "BL_DEV": "1",
                "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
                "BL_DUPLICATE_CHECK_PEPPER": "BL_TEST_DUPLICATE_PEPPER",
                "BL_PROVIDER_ALIAS_KEY": "BL_TEST_PROVIDER_ALIAS_KEY",
            },
            clear=False,
        ), patch("app.batch.batch_orchestrator.assert_production_ready", lambda: None):
            batch = submit_batches(
                [payload],
                actor="operator@example.gov",
                access=self.access(),
                recorder=LocalBatchRecorder(),
                config=BatchConfig(strict_oracle_attestations=False, enforce_nullifier_proofs=False),
            )[0]

        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("oracle_attestation_required", ";".join(batch.quarantined[0].errors))

    def test_local_explicit_opt_in_can_disable_enforcement_for_dev_fixture(self):
        payload = sample_payload("BL-LOCAL-DISABLE-OPT-IN")
        payload.pop("oracle_attestations", None)

        with patch.dict(
            os.environ,
            {
                "BL_ENV": "test",
                "BL_DEV": "1",
                "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
                "BL_ALLOW_LOCAL_TEST_ORACLE_KEYS": "1",
                "BL_PROVIDER_ALIAS_KEY": "BL_TEST_PROVIDER_ALIAS_KEY",
            },
            clear=False,
        ):
            batch = submit_batches(
                [payload],
                actor="operator@example.gov",
                access=self.access(),
                recorder=LocalBatchRecorder(),
                config=BatchConfig(strict_oracle_attestations=False, enforce_nullifier_proofs=False),
            )[0]

        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_packets[0].decision, "approved")
        self.assertEqual(batch.payments[0].amount_cents, 12500)

    def test_happy_path_and_denial_in_same_batch(self):
        payloads = [
            sample_payload("BL-BATCH-APPROVED-1"),
            sample_payload("BL-BATCH-DENIED-G2", {"eligibility_active": False}),
        ]
        batches = submit_batches(payloads, actor="operator@example.gov", access=self.access(), recorder=LocalBatchRecorder())
        self.assertEqual(len(batches), 1)
        batch = batches[0]
        self.assertEqual(batch.claim_count, 2)
        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.proof_status, REAL_PROOF_REQUIRED_STATUS)
        self.assertFalse(batch.accepted_by_real_verifier)
        self.assertEqual(len(batch.payments), 1)
        self.assertEqual(batch.payments[0].amount_cents, 12500)
        self.assertEqual(batch.payments[0].settlement["status"], "not_submitted_real_verifier_rejected")
        self.assertEqual([packet.decision for packet in batch.claim_packets], ["approved", "denied"])
        for packet in batch.claim_packets:
            self.assertTrue(
                verify_inclusion(
                    packet.adjudication_record,
                    packet.adjudication_record_path.leaf_index,
                    packet.adjudication_record_path.siblings,
                    batch.adjudication_batch_record,
                    hash_domain=packet.adjudication_record_path.hash_domain,
                )
            )
            self.assertIn("ST*835", packet.remittance_835)

    def test_quarantine_path_settles_rest(self):
        payloads = [
            sample_payload("BL-BATCH-APPROVED-2"),
            {"edi": "", "flags": {}, "claim_id": "BAD-EMPTY"},
        ]
        batches = submit_batches(payloads, actor="operator@example.gov", access=self.access(), recorder=LocalBatchRecorder())
        batch = batches[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "ingestion_failed")
        self.assertEqual(len(batch.payments), 1)
        self.assertEqual(batch.payments[0].amount_cents, 12500)
        self.assertEqual(batch.payments[0].settlement["status"], "not_submitted_real_verifier_rejected")

    def test_approved_claim_with_malformed_npi_is_quarantined_not_settled(self):
        payload = sample_payload(
            "BL-BAD-NPI-APPROVED",
            edi_transform=lambda edi: edi.replace("NM1*82*1*ADAMS*ALICE****XX*1999999984", "NM1*82*1*ADAMS*ALICE****XX*1234567890"),
        )
        batches = submit_batches([payload], actor="operator@example.gov", access=self.access(), recorder=LocalBatchRecorder())
        batch = batches[0]
        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "dirty_claim_prefilter_rejected")
        self.assertIn("structural_invalid:invalid_npi_check_digit", batch.quarantined[0].errors[0])
        self.assertEqual(batch.claim_packets, [])
        self.assertEqual(batch.payments, [])

    def test_payment_root_uses_contract_payee_record_not_bare_payment_record(self):
        batch = submit_batches(
            [sample_payload("BL-PAYEE-ROOT")],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        payment = batch.payments[0]
        expected_payee_record = payment_payee_record(payment.recipient_address, payment.payment_record)
        self.assertEqual(payment.payee_record, expected_payee_record)
        self.assertNotEqual(payment.payee_record, payment.payment_record)

        tree = PoseidonMerkleTree([payment.payee_record], depth=10, hash_domain="payment")
        proof = tree.prove(0)
        self.assertEqual(batch.payment_batch_record, tree.root)
        self.assertTrue(verify_inclusion(payment.payee_record, proof.leaf_index, proof.siblings, batch.payment_batch_record, hash_domain=proof.hash_domain))
        self.assertFalse(verify_inclusion(payment.payment_record, proof.leaf_index, proof.siblings, batch.payment_batch_record, hash_domain=proof.hash_domain))

    def test_within_batch_duplicate_key_quarantined(self):
        duplicate_a = sample_payload("BL-DUP-IN-BATCH")
        duplicate_b = sample_payload("BL-DUP-IN-BATCH")
        parsed = parse_837(duplicate_b["edi"])
        ctx = build_shared_context(parsed, duplicate_b["flags"], strict_oracle=False)
        claim_source_commitment = _claim_source_commitment_for_oracle(
            ctx,
            config=BatchConfig(),
            frequency_type="original",
            duplicate_pepper=current_duplicate_pepper(),
        )
        duplicate_b["oracle_attestations"] = [
            make_test_attestation(
                fact,
                bool(duplicate_b["flags"][fact]),
                source_id=f"TEST-DUPLICATE-IDENTITY-{fact}",
                claim_id="BL-DUP-IN-BATCH",
                claim_source_commitment=claim_source_commitment,
            )
            for fact in DECISION_FACTS
        ]
        batches = submit_batches(
            [duplicate_a, duplicate_b],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
        )
        batch = batches[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "attempt_nullifier_replay")

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_reused_attestation_nullifier_across_chunks_quarantines_second_only(self):
        payload_a = sample_payload("BL-CROSS-CHUNK-REPLAY")
        payload_b = sample_payload("BL-CROSS-CHUNK-REPLAY")
        payload_b["oracle_attestations"] = payload_a["oracle_attestations"]

        batches = submit_batches(
            [payload_a, payload_b],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(allow_test_only_unverified_settlement=True),
            config=BatchConfig(max_claims=1),
        )

        self.assertEqual([batch.claim_count for batch in batches], [1, 0])
        self.assertEqual([batch.quarantine_count for batch in batches], [0, 1])
        self.assertEqual(batches[1].quarantined[0].reason, "oracle_attestation_replay")
        self.assertEqual(sum(payment.amount_cents for batch in batches for payment in batch.payments), 12500)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_distinct_attestation_nullifiers_across_chunks_all_proceed(self):
        payload_a = sample_payload("BL-CROSS-CHUNK-DISTINCT-A")
        payload_b = sample_payload(
            "BL-CROSS-CHUNK-DISTINCT-B",
            edi_transform=lambda edi: edi.replace("20260601", "20260602"),
        )

        batches = submit_batches(
            [payload_a, payload_b],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(allow_test_only_unverified_settlement=True),
            config=BatchConfig(max_claims=1),
        )

        self.assertEqual([batch.claim_count for batch in batches], [1, 1])
        self.assertEqual(sum(batch.quarantine_count for batch in batches), 0)
        self.assertEqual(sum(payment.amount_cents for batch in batches for payment in batch.payments), 25000)
        self.assertEqual(batches[1].duplicate_check_before, batches[0].duplicate_check_after)

    def test_replayed_attestation_leaves_no_accumulator_footprint_before_honest_claim(self):
        seed = sample_payload("BL-REPLAY-POISON-SEED")
        replay = sample_payload("BL-REPLAY-POISON-SEED")
        replay["oracle_attestations"] = seed["oracle_attestations"]
        honest = sample_payload(
            "BL-REPLAY-POISON-HONEST",
            edi_transform=lambda edi: edi.replace("20260601", "20260602"),
        )

        batch = submit_batches(
            [seed, replay, honest],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(annual_benefit_cap_cents=25_000),
        )[0]

        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "oracle_attestation_replay")
        self.assertEqual([packet.claim_id for packet in batch.claim_packets], ["BL-REPLAY-POISON-SEED", "BL-REPLAY-POISON-HONEST"])
        self.assertEqual([packet.decision for packet in batch.claim_packets], ["approved", "approved"])
        self.assertEqual(sum(payment.amount_cents for payment in batch.payments), 25000)

    def test_reordered_multiline_claim_is_quarantined_as_duplicate(self):
        batches = submit_batches(
            [
                sample_payload("BL-REORDER-A", edi_transform=two_line_transform("99213", "T1019")),
                sample_payload("BL-REORDER-B", edi_transform=two_line_transform("T1019", "99213")),
            ],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
        )
        batch = batches[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    def test_signed_suspended_provider_and_deceased_patient_do_not_approve(self):
        batch = submit_batches(
            [
                sample_payload("BL-SUSPENDED-PROVIDER", {"provider_not_suspended": False}),
                sample_payload("BL-DECEASED-PATIENT", {"not_deceased": False}),
            ],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual([packet.decision for packet in batch.claim_packets], ["denied", "denied"])
        self.assertEqual([packet.denial_reason for packet in batch.claim_packets], ["provider_suspended", "patient_deceased"])
        self.assertEqual(batch.payments, [])

    def test_overbilling_above_old_ceiling_pays_fee_schedule_amount_without_denial(self):
        def charge_above_old_ceiling(edi: str) -> str:
            return edi.replace("CLM*BL-FEE-REDUCTION*125.00", "CLM*BL-FEE-REDUCTION*600000.00").replace(
                "SV1*HC:99213*125.00", "SV1*HC:99213*600000.00"
            )

        batch = submit_batches(
            [sample_payload("BL-FEE-REDUCTION", edi_transform=charge_above_old_ceiling)],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual(batch.claim_packets[0].decision, "approved")
        self.assertEqual(batch.claim_packets[0].denial_reason, "")
        self.assertEqual(batch.claim_packets[0].total_charge_cents, 60_000_000)
        self.assertEqual(batch.claim_packets[0].payable_amount, 125.0)
        self.assertEqual(batch.payments[0].amount_cents, 12500)

    def test_accumulator_cap_rejects_many_individually_valid_claims(self):
        def charge_126(edi: str) -> str:
            return edi.replace("CLM*BL-CAP-2*125.00", "CLM*BL-CAP-2*126.00").replace("SV1*HC:99213*125.00", "SV1*HC:99213*126.00")

        batch = submit_batches(
            [sample_payload("BL-CAP-1"), sample_payload("BL-CAP-2", edi_transform=charge_126)],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(annual_benefit_cap_cents=20_000, enforce_nullifier_proofs=False),
        )[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("annual_benefit_cap_exceeded", batch.quarantined[0].errors[0])

    def test_combined_batch_commitment_binds_all_batch_roots(self):
        batch = submit_batches(
            [sample_payload("BL-BINDING-APP")],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        expected = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
            accumulator_root_before=batch.accumulator_root_before,
            accumulator_root_after=batch.accumulator_root_after,
        )
        self.assertEqual(batch.combined_batch_commitment, expected)
        swapped_batch_id = combined_batch_commitment(
            stable_private_hash("evil-batch-id"),
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_batch_id)
        swapped_payment = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            stable_private_hash("evil-payment-root"),
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_payment)
        swapped_claim_source = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=stable_private_hash("evil-claim-source-root"),
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_claim_source)
        wrong_count = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count + 1,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, wrong_count)
        swapped_denial_root = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=stable_private_hash("evil-denial-root"),
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_denial_root)
        swapped_data_availability = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=stable_private_hash("evil-data-availability-root"),
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_data_availability)
        swapped_forced_inclusion = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=stable_private_hash("evil-forced-inclusion-root"),
            value_conservation_commitment=batch.value_conservation_commitment,
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_forced_inclusion)
        swapped_value_conservation = combined_batch_commitment(
            batch.batch_id,
            batch.claim_batch_record,
            batch.adjudication_batch_record,
            batch.payment_batch_record,
            batch.duplicate_check_before,
            batch.duplicate_check_after,
            batch.batch_nullifier_commitment,
            batch.ruleset_record,
            batch.verifier_key_id,
            batch.claim_count,
            batch.payment_count,
            claim_source_root=batch.claim_source_root,
            oracle_facts_root=batch.oracle_facts_root,
            oracle_signer_root=batch.oracle_signer_root,
            policy_root=batch.policy_root,
            address_book_root=batch.address_book_root,
            data_availability_root=batch.data_availability_root,
            denial_attestation_root=batch.denial_attestation_root,
            forced_inclusion_root=batch.forced_inclusion_root,
            value_conservation_commitment=stable_private_hash("evil-value-conservation"),
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_value_conservation)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_pepper_rotation_checks_old_and_new_overlap_versions(self):
        access = self.admin_access()
        authority = BatchAuthority(
            duplicate_pepper="pepper-old",
            allow_test_only_unverified_settlement=True,
        )
        recorder = LocalBatchRecorder(authority=authority)
        submit_batches(
            [sample_payload("BL-PEPPER-OLD", duplicate_pepper="pepper-old")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )
        authority.rotate_duplicate_pepper(
            "pepper_v2",
            "pepper-new",
            actor="admin@example.gov",
            access=access,
        )
        duplicate_after_rotation = submit_batches(
            [sample_payload("BL-PEPPER-NEW-ID-SAME-CLAIM", duplicate_pepper="pepper-old")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        self.assertEqual(duplicate_after_rotation.claim_count, 0)
        self.assertEqual(duplicate_after_rotation.quarantine_count, 1)
        self.assertEqual(duplicate_after_rotation.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_duplicate_identity_survives_two_pepper_rotations(self):
        access = self.admin_access()
        authority = BatchAuthority(
            duplicate_pepper="pepper-old",
            allow_test_only_unverified_settlement=True,
        )
        recorder = LocalBatchRecorder(authority=authority)
        submit_batches(
            [sample_payload("BL-PEPPER-ROTATION-1", duplicate_pepper="pepper-old")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )
        authority.rotate_duplicate_pepper("pepper_v2", "pepper-new", actor="admin@example.gov", access=access)
        authority.rotate_duplicate_pepper("pepper_v3", "pepper-newer", actor="admin@example.gov", access=access)

        duplicate_after_two_rotations = submit_batches(
            [sample_payload("BL-PEPPER-ROTATION-2", duplicate_pepper="pepper-old")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(duplicate_after_two_rotations.claim_count, 0)
        self.assertEqual(duplicate_after_two_rotations.quarantine_count, 1)
        self.assertEqual(duplicate_after_two_rotations.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_stable_global_nullifier_survives_rotations_and_local_cache_loss(self):
        access = self.admin_access()
        authority = BatchAuthority(
            duplicate_pepper="alias-pepper-old",
            nullifier_epoch_mode="stable_global",
            global_nullifier_pepper="proof-nullifier-pepper-v1",
            allow_test_only_unverified_settlement=True,
        )
        recorder = LocalBatchRecorder(authority=authority)
        first = submit_batches(
            [sample_payload("BL-STABLE-EPOCH-1", duplicate_pepper="proof-nullifier-pepper-v1")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        first_nullifier = first.duplicate_nullifiers[0]

        authority.rotate_duplicate_pepper(
            "pepper_v2",
            "alias-pepper-new",
            actor="admin@example.gov",
            access=access,
        )
        authority.rotate_duplicate_pepper(
            "pepper_v3",
            "alias-pepper-newer",
            actor="admin@example.gov",
            access=access,
        )
        authority.test_only_reset_duplicate_caches()

        duplicate = submit_batches(
            [sample_payload("BL-STABLE-EPOCH-1", duplicate_pepper="proof-nullifier-pepper-v1")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(authority.global_nullifier_pepper, "proof-nullifier-pepper-v1")
        self.assertTrue(authority.nullifier_tree.contains(first_nullifier))
        self.assertEqual(first.nullifier_epoch_mode, "stable_global")
        self.assertEqual(first.nullifier_pepper_version, "stable_global_v1")
        self.assertEqual(duplicate.claim_count, 0)
        self.assertEqual(duplicate.quarantine_count, 1)
        self.assertEqual(duplicate.quarantined[0].reason, "attempt_nullifier_replay")

    def test_clm_total_must_match_service_line_sum(self):
        payload = sample_payload(
            "BL-CLM-SV1-MISMATCH",
            edi_transform=lambda edi: edi.replace("CLM*BL-CLM-SV1-MISMATCH*125.00", "CLM*BL-CLM-SV1-MISMATCH*50.00"),
        )
        parsed = parse_837(payload["edi"])
        self.assertTrue(parsed.accepted)
        with self.assertRaisesRegex(ValueError, "claim_total_mismatch"):
            build_shared_context(parsed, payload["flags"], strict_oracle=False)

    def test_equivalence_with_existing_per_claim_adjudication(self):
        def missing_npi(edi):
            return edi.replace("NM1*82*1*ADAMS*ALICE****XX*1999999984", "NM1*82*1*ADAMS*ALICE****XX*")

        payloads = [
            sample_payload("BL-EQ-APPROVED"),
            sample_payload("BL-EQ-G2", {"eligibility_active": False}),
            sample_payload("BL-EQ-G3", edi_transform=missing_npi),
            sample_payload("BL-EQ-G9", {"duplicate_claim": True}),
            sample_payload("BL-EQ-G10", {"program_integrity_hold": True}),
        ]
        expected = []
        for payload in payloads:
            ctx = context_from_payload(payload)
            result, _ = adjudicate_for_batch(ctx)
            expected.append((ctx.claim_id, result.approved, result.denial_reason, result.carc, result.rarc, result.payable_amount))

        batches = submit_batches(payloads, actor="operator@example.gov", access=self.access(), recorder=LocalBatchRecorder())
        observed = [
            (
                packet.claim_id,
                packet.decision == "approved",
                packet.denial_reason,
                packet.carc,
                packet.rarc,
                packet.payable_amount,
            )
            for packet in batches[0].claim_packets
        ]
        self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()

