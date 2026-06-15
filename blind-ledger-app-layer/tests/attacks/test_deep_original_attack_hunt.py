import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.orchestrator as orchestrator
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
    def test_spec_vs_code_payment_stub_receives_provider_payment_alias_blocked(self):
        """ASSUMPTION ATTACKED: payment rail sees only minimized payment identifiers."""
        captured = []

        class RecordingBridge:
            def trigger(self, claim_id, amount, recipient):
                captured.append({"claim_id": claim_id, "amount": amount, "recipient": recipient})
                return {"status": "recorded", "recipient": recipient}

        with tempfile.TemporaryDirectory() as td:
            input_path = Path(td) / "claim.json"
            out_dir = Path(td) / "out"
            input_path.write_text(json.dumps(sample_payload("BL-DEEP-PII-RAIL")), encoding="utf-8")

            with patch.object(orchestrator, "CircleBridgeStub", return_value=RecordingBridge()):
                result = orchestrator.run_pipeline(input_path, out_dir)

        self.assertTrue(result["accepted"])
        self.assertEqual(len(captured), 1)
        self.assertNotEqual(captured[0]["recipient"], "1999999984")
        self.assertRegex(captured[0]["recipient"], r"^provider_payment_key:[0-9a-f]{64}$")

    def test_trust_boundary_non_mapping_flags_rejects_deterministically_blocked(self):
        """ASSUMPTION ATTACKED: ingestion/orchestrator normalizes flags before context build."""
        payload = sample_payload("BL-DEEP-FLAGS")
        payload["flags"] = "eligibility_active"

        with tempfile.TemporaryDirectory() as td:
            input_path = Path(td) / "claim.json"
            input_path.write_text(json.dumps(payload), encoding="utf-8")
            result = orchestrator.run_pipeline(input_path, Path(td) / "out")

        self.assertFalse(result["accepted"])
        self.assertEqual(result["errors"], ["invalid_flags"])

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

    def test_partial_failure_stale_temp_registry_file_is_overwritten_clean(self):
        """ASSUMPTION ATTACKED: crash leftovers beside the registry can poison recovery."""
        from app.models import AdjudicationResult, GateResult, ProofBundle
        from app.registry import ClaimsRegistry

        result = AdjudicationResult(
            claim_id="BL-DEEP-TMP",
            approved=True,
            denial_reason="",
            gates=[GateResult("G1_MEMBER_ID_PRESENT", True, "")],
            carc="",
            rarc="",
            total_charge=125.0,
            payable_amount=125.0,
        )
        proof = ProofBundle("0xSTUBPROOFcc", ["0x01", "0x00"], "0x" + "ab" * 32, True)

        with tempfile.TemporaryDirectory() as td:
            registry_path = Path(td) / "claims_registry.json"
            registry_path.with_name("claims_registry.json.tmp").write_text("[{\"bad\": true}]", encoding="utf-8")
            ClaimsRegistry(registry_path).record(result, proof)
            rows = json.loads(registry_path.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["claim_id"], "BL-DEEP-TMP")
        self.assertIn("proof_hash", rows[0])

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
