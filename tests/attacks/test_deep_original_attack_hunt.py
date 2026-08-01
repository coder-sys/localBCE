import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import ADMIN, OPERATOR, RoleBook
from app.batch.batch_orchestrator import (
    BatchAuthority,
    BatchConfig,
    LocalBatchRecorder,
    _claim_source_commitment_for_oracle,
    _submit_single_batch,
    submit_batches,
)
from app.batch.leaf import current_duplicate_pepper, stable_private_hash
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
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


def sample_payload(claim_id="BL-DEEP-0001", config=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    active_config = config or BatchConfig()
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

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_temporal_ruleset_revoked_after_batch_build_is_blocked_clean(self):
        """ASSUMPTION ATTACKED: a batch built under an old ruleset can sneak in later."""
        config = BatchConfig(enforce_nullifier_proofs=False)
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        recorder = LocalBatchRecorder(authority)
        access = role_book()
        base_tree, root_before, accumulator_states, accumulator_root = authority.snapshot()
        batch, next_tree, next_accumulators = _submit_single_batch(
            0,
            [sample_payload("BL-DEEP-RULESET-REVOKE")],
            config,
            root_before,
            base_tree,
            accumulator_states,
            accumulator_root,
            authority.active_pepper_epochs(),
        )

        authority.set_ruleset_approved(config.ruleset_version, False, actor="admin@example.gov", access=access)

        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            recorder.record(batch, next_tree, next_accumulators)
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
        self.assertEqual(batches[0].claim_count, 1)
        self.assertEqual(batches[0].quarantine_count, 1)

    def test_own_category_semantic_dict_hash_is_insertion_order_stable_blocked(self):
        """ASSUMPTION ATTACKED: stable_private_hash is canonical for structured data."""
        left = {"claim": "A", "amount": 12500}
        right = {"amount": 12500, "claim": "A"}

        self.assertEqual(left, right)
        self.assertEqual(stable_private_hash(left), stable_private_hash(right))


if __name__ == "__main__":
    unittest.main()
