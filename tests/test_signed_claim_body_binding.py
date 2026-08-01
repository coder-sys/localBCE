import copy
import json
import os
import unittest
from pathlib import Path

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, _claim_source_commitment_for_oracle, submit_batches
from app.batch.leaf import current_duplicate_pepper
from app.ingestion import parse_837
from app.oracle_attestation import LOCAL_TEST_ORACLE_KEYS_ENV, make_test_attestation
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


def role_book() -> RoleBook:
    roles = RoleBook()
    roles.grant(OPERATOR, "operator@example.gov")
    return roles


def signed_payload(claim_id: str) -> dict[str, object]:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig(enforce_nullifier_proofs=False)
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    payload["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
        ).to_dict()
        for fact in DECISION_FACTS
    ]
    return payload


class SignedClaimBodyBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["BL_DEV"] = "1"
        os.environ[LOCAL_TEST_ORACLE_KEYS_ENV] = "1"
        os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_TEST_PROVIDER_ALIAS_KEY")
        os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
        os.environ.pop("BL_ENV", None)

    def _tampered_submission(self, name: str, claim_id: str, transform) -> None:
        original = signed_payload(claim_id)
        tampered = copy.deepcopy(original)
        tampered["edi"] = transform(str(tampered["edi"]))

        batch = submit_batches(
            [tampered],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        errors = ";".join(batch.quarantined[0].errors if batch.quarantined else [])
        print(f"{name} => REJECT reason={batch.quarantined[0].reason if batch.quarantined else 'NONE'} errors={errors}")
        self.assertEqual(batch.claim_count, 0)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("oracle_attestation_invalid", errors)

    def test_member_id_swap_rejects(self):
        self._tampered_submission("member_id_swap", "BL-MEM-SWAP", lambda edi: edi.replace("MI*M123456789", "MI*M987654321"))

    def test_provider_npi_swap_rejects(self):
        self._tampered_submission("provider_npi_swap", "BL-PROV-SWAP", lambda edi: edi.replace("XX*1999999984", "XX*1999999992"))

    def test_service_date_backdate_rejects(self):
        self._tampered_submission("service_date_backdate", "BL-DATE-SWAP", lambda edi: edi.replace("DTP*472*D8*20260601", "DTP*472*D8*20260531"))

    def test_service_line_multiplication_rejects(self):
        self._tampered_submission(
            "service_line_multiplication",
            "BL-LINE-SWAP",
            lambda edi: edi.replace("CLM*BL-LINE-SWAP*125.00", "CLM*BL-LINE-SWAP*250.00").replace(
                "SV1*HC:99213*125.00*UN*1***1~REF",
                "SV1*HC:99213*125.00*UN*1***1~SV1*HC:99213*125.00*UN*1***2~REF",
            ),
        )

    def test_total_amount_change_rejects(self):
        self._tampered_submission(
            "total_amount_change",
            "BL-AMT-SWAP",
            lambda edi: edi.replace("CLM*BL-AMT-SWAP*125.00", "CLM*BL-AMT-SWAP*126.00").replace(
                "SV1*HC:99213*125.00",
                "SV1*HC:99213*126.00",
            ),
        )

    def test_honest_signed_body_approves_and_pays(self):
        batch = submit_batches(
            [signed_payload("BL-BODY-BIND-HONEST")],
            actor="operator@example.gov",
            access=role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        packet = batch.claim_packets[0] if batch.claim_packets else None
        print(
            "honest_path => APPROVE "
            f"decision={packet.decision if packet else 'NONE'} payable={packet.payable_amount if packet else 'NONE'}"
        )
        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_count, 1)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.decision, "approved")
        self.assertEqual(packet.payable_amount, 125.0)


if __name__ == "__main__":
    unittest.main()
