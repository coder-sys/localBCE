import json
import unittest
from pathlib import Path

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    _submit_single_batch,
    submit_batches,
)


ROOT = Path(__file__).resolve().parents[2]


def roles():
    book = RoleBook()
    book.grant(ADMIN, "admin@example.gov")
    book.grant(OPERATOR, "operator@example.gov")
    book.grant(AUDITOR, "auditor@example.gov")
    return book


def sample_payload(claim_id: str, amount: float = 125.0, flags=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    amount_text = f"{amount:.2f}"
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    payload["edi"] = (
        payload["edi"]
        .replace(f"CLM*{claim_id}*125.00", f"CLM*{claim_id}*{amount_text}")
        .replace("SV1*HC:99213*125.00", f"SV1*HC:99213*{amount_text}")
    )
    if flags:
        payload["flags"].update(flags)
    return payload


class Phase2FixedArchitectureAttackTests(unittest.TestCase):
    def test_competing_prebuilt_batches_same_root_second_rejected_as_stale(self):
        authority = BatchAuthority()
        config = BatchConfig(enforce_nullifier_proofs=False)
        base_tree, root_before = authority.snapshot()

        batch_a, next_a = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RACE-A", 201.0)],
            config,
            root_before,
            base_tree,
        )
        batch_b, next_b = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RACE-B", 202.0)],
            config,
            root_before,
            base_tree,
        )

        authority.commit_batch(batch_a, next_a)
        with self.assertRaisesRegex(ValueError, "stale nullifier root"):
            authority.commit_batch(batch_b, next_b)

    def test_ruleset_revoked_after_build_is_rejected_at_commit(self):
        book = roles()
        authority = BatchAuthority(approved_ruleset_versions=["ruleset-v1"])
        config = BatchConfig(ruleset_version="ruleset-v1", enforce_nullifier_proofs=False)
        base_tree, root_before = authority.snapshot()
        batch, next_tree = _submit_single_batch(
            0,
            [sample_payload("BL-P2-RULESET-REVOCATION", 203.0)],
            config,
            root_before,
            base_tree,
        )

        authority.set_ruleset_approved("ruleset-v1", False, actor="admin@example.gov", access=book)
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            authority.commit_batch(batch, next_tree)

    def test_operator_cannot_approve_forged_ruleset(self):
        authority = BatchAuthority()
        with self.assertRaises(AccessDenied):
            authority.set_ruleset_approved("forged-ruleset", True, actor="operator@example.gov", access=roles())

    def test_unapproved_ruleset_blocked_before_batch_admission(self):
        authority = BatchAuthority(approved_ruleset_versions=["approved-v1"])
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            submit_batches(
                [sample_payload("BL-P2-FORGED-RULESET", 204.0)],
                actor="operator@example.gov",
                access=roles(),
                config=BatchConfig(ruleset_version="forged-v2", enforce_nullifier_proofs=False),
                recorder=LocalBatchRecorder(authority=authority),
            )

    def test_default_batch_mode_requires_real_multi_claim_proof_for_many_approved_claims(self):
        batch = submit_batches(
            [
                sample_payload("BL-P2-BATCH-PROOF-1", 211.0),
                sample_payload("BL-P2-BATCH-PROOF-2", 212.0),
                sample_payload("BL-P2-BATCH-PROOF-3", 213.0),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(max_claims=10),
        )[0]

        self.assertEqual(batch.claim_count, 3)
        self.assertEqual(len(batch.nullifier_proofs), 1)
        self.assertEqual(batch.nullifier_proofs[0]["mode"], "native_stark_settlement_required")
        self.assertFalse(batch.nullifier_proofs[0]["accepted"])
        self.assertEqual(batch.nullifier_proofs[0]["approved_nullifier_count"], 3)
        self.assertFalse(batch.accepted_by_real_verifier)

    def test_mixed_quarantine_denial_and_approval_nets_payment_only_for_approved_claims(self):
        batch = submit_batches(
            [
                sample_payload("BL-P2-MIXED-APPROVED", 221.0),
                sample_payload("BL-P2-MIXED-DENIED", 222.0, {"eligibility_active": False}),
                {"edi": "", "flags": {}, "claim_id": "BL-P2-MIXED-BAD"},
                sample_payload("BL-P2-MIXED-DUP", 221.0),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual([packet.decision for packet in batch.claim_packets], ["approved", "denied"])
        self.assertEqual(batch.quarantine_count, 2)
        self.assertEqual([item.reason for item in batch.quarantined], ["ingestion_failed", "duplicate_identity_key_already_recorded"])
        self.assertEqual(len(batch.payments), 1)
        self.assertEqual(batch.payments[0].approved_claim_count, 1)
        self.assertEqual(batch.payments[0].amount_cents, 22100)

    def test_phase2_residual_duplicate_only_resubmission_not_recorded(self):
        authority = BatchAuthority()
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

    def test_contract_sources_do_not_store_sample_claim_phi_or_plain_payment_amounts(self):
        registry_source = (ROOT / "contracts" / "src" / "batch" / "BatchClaimsRegistry.sol").read_text(encoding="utf-8")
        payment_source = (ROOT / "contracts" / "src" / "batch" / "BatchPaymentTrigger.sol").read_text(encoding="utf-8")
        combined = registry_source + "\n" + payment_source

        self.assertNotIn("BL-CLAIM-0001", combined)
        self.assertNotIn("MEM123456", combined)
        self.assertNotIn("1999999984", combined)
        self.assertNotIn("125.00", combined)
        self.assertNotIn("uint256 amount", payment_source)


if __name__ == "__main__":
    unittest.main()
