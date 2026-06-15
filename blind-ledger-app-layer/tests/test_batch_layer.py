import copy
import json
import unittest
from pathlib import Path

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    _enforce_payment_reconciliation,
    adjudicate_for_batch,
    ruleset_policy_record,
    submit_batches,
)
from app.batch.leaf import build_claim_leaf_set, combined_batch_commitment, payment_leaf, payment_payee_record, stable_private_hash
from app.batch.merkle import MerkleTree, verify_inclusion
from app.batch.stubs import STUB_LABEL
from app.ingestion import parse_837
from app.provider_alias import provider_payment_alias
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]
RULESET = "rarc_mapping_v1_pending_domain_ratification"
RULESET_RECORD = ruleset_policy_record(RULESET)


def sample_payload(claim_id="BL-CLAIM-0001", flags=None, edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


def context_from_payload(payload):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], strict_oracle=False)


class BatchLeafAndMerkleTests(unittest.TestCase):
    def test_leaf_vectors_are_locked(self):
        payload = sample_payload()
        ctx = context_from_payload(payload)
        result, engine_mode = adjudicate_for_batch(ctx)
        leaf_set = build_claim_leaf_set(ctx, result, RULESET_RECORD, "original", engine_mode)
        provider_key = provider_payment_alias(ctx.provider.npi, ctx.provider.name)
        recipient_commitment = stable_private_hash(["CPN_MANAGED_PAYMENTS_STUB", "recipient", provider_key])
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
            ["test-batch-0001", provider_key, recipient_commitment, 12500, reconciliation_commitment, "CPN_MANAGED_PAYMENTS_STUB", approved_result_commitment]
        )
        pay_leaf = payment_leaf(
            "test-batch-0001",
            provider_key,
            recipient_commitment,
            1,
            12500,
            reconciliation_commitment,
            "CPN_MANAGED_PAYMENTS_STUB",
            settlement,
            approved_result_commitment,
        )

        self.assertEqual(RULESET_RECORD, "e2e16e825ba87e575db9e3af6047aad72cf0a2ed5e4e2dd014bd04175229f654")
        self.assertEqual(provider_key, "provider_payment_key:83443c19ce8abae3e9d33b9df237c3dba571b4800d9ac0a7cd48d8cd7c7458c6")
        self.assertEqual(recipient_commitment, "8abb904cb90cf7846cd9b7b18e9d7cd9770c6199b868e6b8f44bcf7be7e1bd2d")
        self.assertEqual(approved_result_commitment, "1b79d34967451e7f5d18310b1d590031ee15322afb71e3008f16fe293f7cd2f6")
        self.assertEqual(reconciliation_commitment, "58b3198dd77a66fb073cea8b9f4bdb974c76caa24ca0a937b96f53e76c31fa96")
        self.assertEqual(leaf_set.claim_leaf, "be0170d43042f1093d3e4e3a983f99d1639aab8711657ac3c222b286620488e7")
        self.assertEqual(leaf_set.result_leaf, "be58181f7648c75237cb03a1a75ea3a48e266aa49c468cbf3dd698d6fc2fc9c4")
        self.assertEqual(leaf_set.duplicate_check_key, "2ed1543ae5e3dd3672fe838e317b818fa8888e2ff28c791fc67a1da2596bc54a")
        self.assertEqual(
            leaf_set.duplicate_nullifier,
            21176243405949225942969571755015627710114287770437624131592815736281048532298,
        )
        self.assertEqual(leaf_set.duplicate_leaf, "0a6098b99b63d207738f81badd70bffcf596b1e6e223ed84107fdaf77a0370ce")
        self.assertEqual(pay_leaf, "6622bc20f31130afe8c5371fb7a0ed71974f7ae9ae3ab6f0e2ad2aa526b21793")
        self.assertEqual(MerkleTree([leaf_set.claim_leaf], 10).root, "84182e02f979ec2433fcd6c1dc4554c220ba58d883b9e859cc2c1f7a00e94996")
        self.assertEqual(MerkleTree([leaf_set.result_leaf], 10).root, "efa414f92879e39741e8c765e2db74b87024652b3f1812c538c7a7ce68fbfa6e")

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

        changed_engine_leaf = build_claim_leaf_set(ctx, result, RULESET_RECORD, "original", "adapter_fallback").result_leaf

        self.assertNotEqual(base, changed_gate_leaf)
        self.assertNotEqual(base, changed_engine_leaf)

    def test_payment_leaf_binds_recipient_and_approved_result_set(self):
        provider_key = "provider_payment_key:" + ("11" * 32)
        recipient_commitment = stable_private_hash("recipient-a")
        approved_result_commitment = stable_private_hash(["result-a", "result-b"])
        reconciliation_commitment = stable_private_hash("reconciliation-a")
        settlement = stable_private_hash("settlement")
        base = payment_leaf("batch-a", provider_key, recipient_commitment, 2, 25000, reconciliation_commitment, "CPN_MANAGED_PAYMENTS_STUB", settlement, approved_result_commitment)

        changed_recipient = payment_leaf(
            "batch-a",
            provider_key,
            stable_private_hash("recipient-b"),
            2,
            25000,
            reconciliation_commitment,
            "CPN_MANAGED_PAYMENTS_STUB",
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
            "CPN_MANAGED_PAYMENTS_STUB",
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
            "CPN_MANAGED_PAYMENTS_STUB",
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
        self.assertEqual(batch.proof_status, STUB_LABEL)
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

        tree = MerkleTree([payment.payee_record], depth=10)
        proof = tree.prove(0)
        self.assertEqual(batch.payment_batch_record, tree.root)
        self.assertTrue(verify_inclusion(payment.payee_record, proof.leaf_index, proof.siblings, batch.payment_batch_record))
        self.assertFalse(verify_inclusion(payment.payment_record, proof.leaf_index, proof.siblings, batch.payment_batch_record))

    def test_within_batch_duplicate_key_quarantined(self):
        batches = submit_batches(
            [sample_payload("BL-DUP-IN-BATCH"), sample_payload("BL-DUP-IN-BATCH")],
            actor="operator@example.gov",
            access=self.access(),
            recorder=LocalBatchRecorder(),
        )
        batch = batches[0]
        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "duplicate_identity_key_already_recorded")

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
        )
        self.assertNotEqual(batch.combined_batch_commitment, swapped_payment)
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
        )
        self.assertNotEqual(batch.combined_batch_commitment, wrong_count)

    def test_pepper_rotation_checks_old_and_new_overlap_versions(self):
        access = self.admin_access()
        authority = BatchAuthority(duplicate_pepper="pepper-old")
        recorder = LocalBatchRecorder(authority=authority)
        submit_batches(
            [sample_payload("BL-PEPPER-OLD")],
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
            [sample_payload("BL-PEPPER-NEW-ID-SAME-CLAIM")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        self.assertEqual(duplicate_after_rotation.claim_count, 0)
        self.assertEqual(duplicate_after_rotation.quarantine_count, 1)
        self.assertEqual(duplicate_after_rotation.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    def test_duplicate_identity_survives_two_pepper_rotations(self):
        access = self.admin_access()
        authority = BatchAuthority(duplicate_pepper="pepper-old")
        recorder = LocalBatchRecorder(authority=authority)
        submit_batches(
            [sample_payload("BL-PEPPER-ROTATION-1")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )
        authority.rotate_duplicate_pepper("pepper_v2", "pepper-new", actor="admin@example.gov", access=access)
        authority.rotate_duplicate_pepper("pepper_v3", "pepper-newer", actor="admin@example.gov", access=access)

        duplicate_after_two_rotations = submit_batches(
            [sample_payload("BL-PEPPER-ROTATION-2")],
            actor="operator@example.gov",
            access=access,
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(duplicate_after_two_rotations.claim_count, 0)
        self.assertEqual(duplicate_after_two_rotations.quarantine_count, 1)
        self.assertEqual(duplicate_after_two_rotations.quarantined[0].reason, "duplicate_identity_key_already_recorded")

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

        def excessive_charge(edi):
            return edi.replace("CLM*BL-EQ-G8*125.00", "CLM*BL-EQ-G8*6000.00").replace("SV1*HC:99213*125.00", "SV1*HC:99213*6000.00")

        payloads = [
            sample_payload("BL-EQ-APPROVED"),
            sample_payload("BL-EQ-G2", {"eligibility_active": False}),
            sample_payload("BL-EQ-G3", edi_transform=missing_npi),
            sample_payload("BL-EQ-G8", edi_transform=excessive_charge),
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
