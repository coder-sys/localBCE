import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, _claim_source_commitment_for_oracle, submit_batches
from app.batch.leaf import current_duplicate_pepper
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)
APPROVING_FACTS = {
    "eligibility_active": True,
    "provider_enrolled": True,
    "provider_not_suspended": True,
    "not_deceased": True,
    "duplicate_claim": False,
    "program_integrity_hold": False,
}
DENIAL_REASON_BY_FACT = {
    "eligibility_active": "eligibility_inactive",
    "provider_enrolled": "provider_not_enrolled",
    "provider_not_suspended": "provider_suspended",
    "not_deceased": "patient_deceased",
    "duplicate_claim": "duplicate_claim",
    "program_integrity_hold": "program_integrity_hold",
}


def sample_payload(claim_id: str, flags: dict[str, bool] | None = None) -> dict[str, object]:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    payload["flags"] = dict(payload["flags"])
    if flags:
        payload["flags"].update(flags)
    return payload


def attestations_for_payload(payload: dict[str, object], claim_id: str, overrides: dict[str, bool] | None = None) -> list[object]:
    facts = dict(APPROVING_FACTS)
    facts.update(overrides or {})
    parsed = parse_837(str(payload["edi"]))
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=BatchConfig(),
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    return [
        make_test_attestation(
            fact,
            facts[fact],
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
        )
        for fact in DECISION_FACTS
    ]


def attestations_for(claim_id: str, overrides: dict[str, bool] | None = None) -> list[object]:
    return attestations_for_payload(sample_payload(claim_id), claim_id, overrides)


def roles() -> RoleBook:
    book = RoleBook()
    book.grant(OPERATOR, "operator@example.gov")
    return book


class AppLayerFactAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_env = {
            key: os.environ.get(key)
            for key in ("BL_DEV", "BL_ENV", "BL_ALLOW_DEV_ATTESTATIONS", "BL_ALLOW_LOCAL_TEST_ORACLE_KEYS", "BL_PROVIDER_ALIAS_KEY")
        }
        os.environ["BL_DEV"] = "1"
        os.environ["BL_ALLOW_LOCAL_TEST_ORACLE_KEYS"] = "1"
        os.environ["BL_PROVIDER_ALIAS_KEY"] = "BL_TEST_PROVIDER_ALIAS_KEY"
        os.environ.pop("BL_ENV", None)
        os.environ.pop("BL_ALLOW_DEV_ATTESTATIONS", None)

    def tearDown(self) -> None:
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _submit_one(self, payload: dict[str, object]):
        return submit_batches(
            [payload],
            actor="operator@example.gov",
            access=roles(),
            config=BatchConfig(strict_oracle_attestations=True, enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

    def _assert_attested_denial_wins(self, fact: str, attested_value: bool, submitter_value: bool) -> None:
        claim_id = f"BL-FACT-{fact.upper().replace('_', '-')}"
        payload = sample_payload(claim_id, {fact: submitter_value})
        payload["oracle_attestations"] = attestations_for(claim_id, {fact: attested_value})

        batch = self._submit_one(payload)

        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_count, 1)
        packet = batch.claim_packets[0]
        self.assertEqual(packet.decision, "denied")
        self.assertFalse(packet.payable_amount)
        self.assertEqual(packet.denial_reason, DENIAL_REASON_BY_FACT[fact])

    def test_signed_eligibility_false_beats_submitter_true(self):
        self._assert_attested_denial_wins("eligibility_active", False, True)

    def test_signed_provider_enrolled_false_beats_submitter_true(self):
        self._assert_attested_denial_wins("provider_enrolled", False, True)

    def test_signed_provider_not_suspended_false_beats_submitter_true(self):
        self._assert_attested_denial_wins("provider_not_suspended", False, True)

    def test_signed_not_deceased_false_beats_submitter_true(self):
        self._assert_attested_denial_wins("not_deceased", False, True)

    def test_signed_duplicate_true_beats_submitter_false(self):
        self._assert_attested_denial_wins("duplicate_claim", True, False)

    def test_signed_integrity_hold_true_beats_submitter_false(self):
        self._assert_attested_denial_wins("program_integrity_hold", True, False)

    def test_missing_duplicate_attestation_fails_closed(self):
        claim_id = "BL-MISS-DUP-ATT"
        payload = sample_payload(claim_id)
        attestations = [item for item in attestations_for(claim_id) if item.fact != "duplicate_claim"]
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
        claim_source_commitment = _claim_source_commitment_for_oracle(
            ctx,
            config=BatchConfig(),
            frequency_type="original",
            duplicate_pepper=current_duplicate_pepper(),
        )

        with self.assertRaisesRegex(ValueError, "oracle_attestation_required:duplicate_claim"):
            build_shared_context(
                parsed,
                payload["flags"],
                oracle_attestations=attestations,
                strict_oracle=True,
                claim_source_commitment=claim_source_commitment,
            )

    def test_strict_dev_fallback_requires_explicit_override(self):
        payload = sample_payload("BL-DEV-FALLBACK-WALLED")

        batch = self._submit_one(payload)

        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("oracle_attestation_required", ";".join(batch.quarantined[0].errors))

    def test_all_six_signed_approving_facts_approve_and_emit_payment(self):
        claim_id = "BL-ALL-SIX-SIGNED-APPROVE"
        payload = sample_payload(claim_id)
        payload["oracle_attestations"] = attestations_for(claim_id)

        batch = self._submit_one(payload)

        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_count, 1)
        packet = batch.claim_packets[0]
        self.assertEqual(packet.decision, "approved")
        self.assertEqual(packet.payable_amount, 125.0)
        self.assertEqual(batch.approved_amount_cents, 12500)

    def test_reused_attestation_nullifier_in_same_batch_quarantines_second_claim(self):
        claim_id = "BL-BATCH-REPLAY-REJECT"
        payload_a = sample_payload(claim_id, {"duplicate_claim": True})
        payload_a["oracle_attestations"] = attestations_for(claim_id, {"duplicate_claim": True})
        payload_b = sample_payload(claim_id, {"duplicate_claim": True})
        payload_b["oracle_attestations"] = payload_a["oracle_attestations"]

        batch = submit_batches(
            [payload_a, payload_b],
            actor="operator@example.gov",
            access=roles(),
            config=BatchConfig(strict_oracle_attestations=True, enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.claim_packets[0].decision, "denied")
        self.assertEqual(batch.quarantined[0].reason, "oracle_attestation_replay")

    def test_distinct_attestation_nullifiers_in_same_batch_all_proceed(self):
        payload_a = sample_payload("BL-BATCH-DISTINCT-A")
        payload_a["oracle_attestations"] = attestations_for("BL-BATCH-DISTINCT-A")
        payload_b = sample_payload("BL-BATCH-DISTINCT-B")
        payload_b["edi"] = payload_b["edi"].replace("20260601", "20260602")
        payload_b["oracle_attestations"] = attestations_for_payload(payload_b, "BL-BATCH-DISTINCT-B")

        batch = submit_batches(
            [payload_a, payload_b],
            actor="operator@example.gov",
            access=roles(),
            config=BatchConfig(strict_oracle_attestations=True, enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_count, 2)
        self.assertEqual([packet.decision for packet in batch.claim_packets], ["approved", "approved"])

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_reused_attestation_nullifier_across_batch_chunks_quarantines_second_and_pays_once(self):
        claim_id = "BL-BATCH-CHUNK-REPLAY"
        payload_a = sample_payload(claim_id)
        payload_a["oracle_attestations"] = attestations_for(claim_id)
        payload_b = sample_payload(claim_id)
        payload_b["oracle_attestations"] = payload_a["oracle_attestations"]

        batches = submit_batches(
            [payload_a, payload_b],
            actor="operator@example.gov",
            access=roles(),
            config=BatchConfig(strict_oracle_attestations=True, enforce_nullifier_proofs=False, max_claims=1),
            recorder=LocalBatchRecorder(allow_test_only_unverified_settlement=True),
        )

        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0].claim_count, 1)
        self.assertEqual(batches[0].quarantine_count, 0)
        self.assertEqual(batches[0].claim_packets[0].decision, "approved")
        self.assertEqual(batches[1].claim_count, 0)
        self.assertEqual(batches[1].quarantine_count, 1)
        self.assertEqual(batches[1].quarantined[0].reason, "oracle_attestation_replay")
        self.assertEqual(sum(batch.approved_amount_cents for batch in batches), 12500)


if __name__ == "__main__":
    unittest.main()
