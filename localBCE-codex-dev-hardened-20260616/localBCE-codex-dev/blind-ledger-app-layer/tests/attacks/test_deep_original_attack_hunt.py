import json
import unittest
from pathlib import Path

from app.batch.access_control import ADMIN, OPERATOR, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    _submit_single_batch,
    submit_batches,
)
from app.batch.leaf import stable_private_hash


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-DEEP-0001"):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    return payload


def role_book(admin="admin@example.gov", operator="operator@example.gov"):
    roles = RoleBook()
    roles.grant(ADMIN, admin)
    roles.grant(OPERATOR, operator)
    return roles


class DeepOriginalAttackHuntTests(unittest.TestCase):
    def test_trust_boundary_non_mapping_flags_rejects_deterministically_blocked(self):
        """ASSUMPTION ATTACKED: batch builder rejects non-mapping flags before context build."""
        payload = sample_payload("BL-DEEP-FLAGS")
        payload["flags"] = "eligibility_active"

        batches = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )

        self.assertEqual(batches[0].claim_count, 0)
        self.assertEqual(batches[0].quarantined[0].reason, "adjudication_failed")
        self.assertIn("flags must be an object", batches[0].quarantined[0].errors[0])

    def test_temporal_ruleset_revoked_after_batch_build_is_blocked_clean(self):
        """ASSUMPTION ATTACKED: a batch built under an old ruleset can sneak in later."""
        config = BatchConfig(enforce_nullifier_proofs=False)
        authority = BatchAuthority()
        recorder = LocalBatchRecorder(authority)
        access = role_book()
        base_tree, root_before = authority.snapshot()
        batch, next_tree = _submit_single_batch(
            0,
            [sample_payload("BL-DEEP-RULESET-REVOKE")],
            config,
            root_before,
            base_tree,
            authority.active_pepper_epochs(),
        )

        authority.set_ruleset_approved(config.ruleset_version, False, actor="admin@example.gov", access=access)

        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            recorder.record(batch, next_tree)
        self.assertEqual(recorder.records, {})

    def test_operator_reality_blank_or_non_normalized_operator_account_rejected_blocked(self):
        """ASSUMPTION ATTACKED: operator identity cannot be an empty accidental value."""
        roles = RoleBook()
        with self.assertRaisesRegex(ValueError, "invalid account id"):
            roles.grant(OPERATOR, "")
        with self.assertRaisesRegex(ValueError, "invalid account id"):
            roles.grant(OPERATOR, " Operator@Example.Gov ")
        recorder = LocalBatchRecorder()

        with self.assertRaises(PermissionError):
            submit_batches(
                [sample_payload("BL-DEEP-BLANK-ACTOR")],
                actor="",
                access=roles,
                config=BatchConfig(enforce_nullifier_proofs=False),
                recorder=recorder,
            )

        self.assertEqual(recorder.records, {})

    def test_economic_quarantine_only_batch_is_not_recorded_blocked(self):
        """ASSUMPTION ATTACKED: recorded batches always contain at least one adjudicated claim."""
        recorder = LocalBatchRecorder()
        batches = submit_batches(
            [{"edi": "", "flags": {}}],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=recorder,
        )

        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0].claim_count, 0)
        self.assertEqual(batches[0].quarantine_count, 1)
        self.assertNotIn(batches[0].batch_id, recorder.records)
        self.assertEqual(recorder.records, {})

    def test_metadata_side_channel_batch_counts_and_quarantine_counts_are_exposed_succeeded(self):
        """ASSUMPTION ATTACKED: roots hide operational volume and exception patterns."""
        recorder = LocalBatchRecorder()
        batches = submit_batches(
            [sample_payload("BL-DEEP-SIDE-OK"), {"edi": "", "flags": {}}],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=recorder,
        )
        contract_source = (ROOT / "contracts" / "src" / "batch" / "BatchClaimsRegistry.sol").read_text(encoding="utf-8")

        self.assertEqual(batches[0].claim_count, 1)
        self.assertEqual(batches[0].quarantine_count, 1)
        self.assertIn("uint256 claimCount", contract_source)
        self.assertIn("uint256 claimCount,", contract_source)

    def test_own_category_semantic_dict_hash_is_insertion_order_stable_blocked(self):
        """ASSUMPTION ATTACKED: stable_private_hash is canonical for structured data."""
        left = {"claim": "A", "amount": 12500}
        right = {"amount": 12500, "claim": "A"}

        self.assertEqual(left, right)
        self.assertEqual(stable_private_hash(left), stable_private_hash(right))


if __name__ == "__main__":
    unittest.main()
