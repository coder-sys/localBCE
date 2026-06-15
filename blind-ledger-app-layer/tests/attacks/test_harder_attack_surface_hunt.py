import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchAuthority, BatchConfig, LocalBatchRecorder, ruleset_policy_record, submit_batches
from app.batch.leaf import combined_batch_commitment, digest_hex
from app.provider_alias import PROVIDER_ALIAS_KEY_ENV, provider_payment_alias


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-HARD-0001"):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    return payload


def role_book():
    roles = RoleBook()
    roles.grant(OPERATOR, "operator@example.gov")
    return roles


class HarderAttackSurfaceHuntTests(unittest.TestCase):
    def test_crypto_record_type_domain_separation_blocks_same_field_collision(self):
        """ASSUMPTION ATTACKED: two logical leaf types cannot reuse the same digest domain."""
        same_fields = ["same-claim", "same-provider", 12500, "same-root"]
        digests = {
            record_type: digest_hex(record_type, same_fields)
            for record_type in [
                "claim_leaf",
                "result_leaf",
                "payment_leaf",
                "duplicate_leaf",
                "combined_batch_commitment",
            ]
        }

        self.assertEqual(len(set(digests.values())), len(digests))

    def test_contract_public_inputs_bind_claim_count_blocked(self):
        """ASSUMPTION ATTACKED: on-chain verifier inputs bind every stored batch field."""
        source = (ROOT / "contracts" / "src" / "batch" / "BatchClaimsRegistry.sol").read_text(encoding="utf-8")
        inputs_body = source.split("function _batchInputsMatch", 1)[1].split("function _verifyRecord", 1)[0]
        combined_body = source.split("function computeCombinedBatchCommitment", 1)[1].split("function _batchInputsMatch", 1)[0]

        self.assertIn("uint256 claimCount", source)
        self.assertIn("require(submission.claimCount > 0", source)
        self.assertIn("batchInputs[8] == submission.verifierKeyId", inputs_body)
        self.assertIn("batchInputs[9] == bytes32(submission.claimCount)", inputs_body)
        self.assertIn("submission.batchId", combined_body)
        self.assertIn("submission.claimCount", combined_body)

        batch = submit_batches(
            [sample_payload("BL-HARD-COUNT-BIND")],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]
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

    def test_mixed_valid_batch_can_still_expose_large_quarantine_count_succeeded(self):
        """ASSUMPTION ATTACKED: batching roots hide operational exception volume."""
        recorder = LocalBatchRecorder()
        invalids = [{"edi": "", "flags": {}, "claim_id": f"BL-HARD-INVALID-{idx:02d}"} for idx in range(25)]
        batch = submit_batches(
            [sample_payload("BL-HARD-ONE-VALID"), *invalids],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=recorder,
        )[0]

        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 25)
        self.assertIn(batch.batch_id, recorder.records)

    def test_ruleset_record_is_content_addressed_blocked(self):
        """ASSUMPTION ATTACKED: approved ruleset root is a content hash of the mapped policy bundle."""
        version_label = "same-human-readable-ruleset-label"
        approved_content = "policy-content-v1"
        changed_content = "policy-content-v2"
        authority = BatchAuthority(approved_ruleset_versions=[])
        admin_roles = role_book()
        from app.batch.access_control import ADMIN

        admin_roles.grant(ADMIN, "admin@example.gov")
        authority.set_ruleset_approved(version_label, True, actor="admin@example.gov", access=admin_roles, policy_content=approved_content)
        batch = submit_batches(
            [sample_payload("BL-HARD-RULESET-LABEL")],
            actor="operator@example.gov",
            access=admin_roles,
            config=BatchConfig(ruleset_version=version_label, ruleset_policy_content=approved_content, enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(authority),
        )[0]

        self.assertEqual(batch.ruleset_record, ruleset_policy_record(version_label, approved_content))
        self.assertNotEqual(ruleset_policy_record(version_label, approved_content), ruleset_policy_record(version_label, changed_content))
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            submit_batches(
                [sample_payload("BL-HARD-RULESET-LABEL-CHANGED")],
                actor="operator@example.gov",
                access=admin_roles,
                config=BatchConfig(ruleset_version=version_label, ruleset_policy_content=changed_content, enforce_nullifier_proofs=False),
                recorder=LocalBatchRecorder(authority),
            )

    def test_sp1_public_values_bind_batch_context_commitment_blocked(self):
        """ASSUMPTION ATTACKED: single-claim SP1 public values bind the whole batch/on-chain context."""
        source = (ROOT / "zk-sp1" / "lib" / "src" / "lib.rs").read_text(encoding="utf-8")
        public_values = source.split("pub struct PublicValues", 1)[1].split("}", 1)[0]

        self.assertIn("raw_claim_identity_commitment", public_values)
        self.assertIn("batch_context_commitment", public_values)
        self.assertIn("decision", public_values)
        self.assertIn("failure_code", public_values)

    def test_provider_payment_alias_is_keyed_and_not_reproducible_without_key_blocked(self):
        """ASSUMPTION ATTACKED: provider alias cannot be brute-forced from a public NPI/name guess."""
        with patch.dict("os.environ", {PROVIDER_ALIAS_KEY_ENV: "secret-key-a"}):
            alias_a = provider_payment_alias("1999999984", "Alice Adams")
        with patch.dict("os.environ", {PROVIDER_ALIAS_KEY_ENV: "secret-key-b"}):
            alias_b = provider_payment_alias("1999999984", "Alice Adams")

        self.assertRegex(alias_a, r"^provider_payment_key:[0-9a-f]{64}$")
        self.assertRegex(alias_b, r"^provider_payment_key:[0-9a-f]{64}$")
        self.assertNotEqual(alias_a, alias_b)
        self.assertNotIn("1999999984", alias_a)


if __name__ == "__main__":
    unittest.main()
