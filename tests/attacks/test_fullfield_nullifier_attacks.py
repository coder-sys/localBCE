import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchAuthority, BatchConfig, LocalBatchRecorder, _claim_source_commitment_for_oracle, submit_batches
from app.batch.leaf import current_duplicate_pepper
from app.batch.nullifier import MAX_NULLIFIER, DuplicateNullifierError, IndexedNullifierTree
from app.batch.poseidon import FIELD_MODULUS, domain_tag, poseidon_many
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


def sample_payload(claim_id: str, amount: float = 125.0, service_date: str | None = None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    amount_text = f"{amount:.2f}"
    payload["edi"] = (
        payload["edi"]
        .replace("BL-CLAIM-0001", claim_id)
        .replace(f"CLM*{claim_id}*125.00", f"CLM*{claim_id}*{amount_text}")
        .replace("SV1*HC:99213*125.00", f"SV1*HC:99213*{amount_text}")
    )
    if service_date:
        payload["edi"] = payload["edi"].replace("DTP*472*D8*20260601", f"DTP*472*D8*{service_date}")
    config = BatchConfig(enforce_nullifier_proofs=False)
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        return payload
    ctx = build_shared_context(
        parsed,
        payload["flags"],
        strict_oracle=False,
        tar_required_procedure_codes=config.tar_required_procedure_codes,
    )
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    tar_authorization_commitment = tar_authorization_commitment_for_context(
        ctx,
        config.tar_required_procedure_codes,
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


def roles():
    book = RoleBook()
    book.grant(OPERATOR, "operator@example.gov")
    return book


class FullFieldNullifierAttackTests(unittest.TestCase):
    def test_full_field_collision_attempt_has_no_collision_in_sample(self):
        values = poseidon_many([[domain_tag("nullifier"), 3, 0xB11D, idx, 0xA11CE] for idx in range(2000)])
        self.assertEqual(len(values), 2000)
        self.assertEqual(len(set(values)), 2000)
        self.assertTrue(all(0 < value < MAX_NULLIFIER for value in values))

    def test_field_wraparound_and_sentinel_values_rejected(self):
        tree = IndexedNullifierTree()
        for value in [-1, 0, MAX_NULLIFIER, FIELD_MODULUS, FIELD_MODULUS + 1]:
            with self.assertRaises(ValueError):
                tree.prove_nonmembership(value)

    def test_exact_duplicate_is_blocked_by_full_field_tree(self):
        value = poseidon_many([[domain_tag("nullifier"), 4, 0xD00D, 1, 2, 3]])[0]
        tree = IndexedNullifierTree()
        tree.insert(value)
        with self.assertRaises(DuplicateNullifierError):
            tree.prove_nonmembership(value)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_cross_worker_duplicate_blocked_by_authoritative_root(self):
        authority = BatchAuthority(allow_test_only_unverified_settlement=True)
        first = submit_batches(
            [sample_payload("BL-FF-RACE-A", 144.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        second = submit_batches(
            [sample_payload("BL-FF-RACE-B", 144.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(authority=authority),
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(first.claim_count, 1)
        self.assertEqual(second.claim_count, 0)
        self.assertEqual(second.quarantine_count, 1)
        self.assertEqual(second.quarantined[0].reason, "duplicate_identity_key_already_recorded")

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_shared_authoritative_root_blocks_cross_batch_duplicate(self):
        recorder = LocalBatchRecorder(allow_test_only_unverified_settlement=True)
        first = submit_batches(
            [sample_payload("BL-FF-SHARED-A", 145.0)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]
        second = submit_batches(
            [sample_payload("BL-FF-SHARED-B", 145.0), sample_payload("BL-FF-SHARED-C", 146.0, service_date="20260602")],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=BatchConfig(enforce_nullifier_proofs=False),
        )[0]

        self.assertEqual(first.claim_count, 1)
        self.assertEqual(second.claim_count, 1)
        self.assertEqual(second.quarantine_count, 1)
        self.assertEqual(second.quarantined[0].reason, "duplicate_identity_key_already_recorded")


if __name__ == "__main__":
    unittest.main()
