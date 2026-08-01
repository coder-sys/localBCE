import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchAuthority, BatchConfig, LocalBatchRecorder, _claim_source_commitment_for_oracle, ruleset_policy_record, submit_batches
from app.batch.leaf import combined_batch_commitment, current_duplicate_pepper, digest_hex
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.provider_alias import PROVIDER_ALIAS_KEY_ENV, provider_payment_alias
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


def sample_payload(claim_id="BL-HARD-0001", config=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
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
        self.assertFalse(batch.accepted_by_real_verifier)
        self.assertNotIn(batch.batch_id, recorder.records)
        self.assertEqual(recorder.records, {})

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
        approved_config = BatchConfig(ruleset_version=version_label, ruleset_policy_content=approved_content, enforce_nullifier_proofs=False)
        batch = submit_batches(
            [sample_payload("BL-HARD-RULESET-LABEL", config=approved_config)],
            actor="operator@example.gov",
            access=admin_roles,
            config=approved_config,
            recorder=LocalBatchRecorder(authority),
        )[0]

        self.assertEqual(batch.ruleset_record, ruleset_policy_record(version_label, approved_content))
        self.assertNotEqual(ruleset_policy_record(version_label, approved_content), ruleset_policy_record(version_label, changed_content))
        changed_config = BatchConfig(ruleset_version=version_label, ruleset_policy_content=changed_content, enforce_nullifier_proofs=False)
        with self.assertRaisesRegex(ValueError, "ruleset not approved"):
            submit_batches(
                [sample_payload("BL-HARD-RULESET-LABEL-CHANGED", config=changed_config)],
                actor="operator@example.gov",
                access=admin_roles,
                config=changed_config,
                recorder=LocalBatchRecorder(authority),
            )

    def test_native_stark_public_input_schema_binds_settlement_context_blocked(self):
        """ASSUMPTION ATTACKED: settlement public inputs bind every batch context root."""
        source = (ROOT.parent / "ops" / "native_stark_public_inputs_v1.json").read_text(encoding="utf-8")

        self.assertIn("nullifierRootBefore", source)
        self.assertIn("nullifierRootAfter", source)
        self.assertIn("dataAvailabilityRoot", source)
        self.assertIn("valueConservationCommitment", source)

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
