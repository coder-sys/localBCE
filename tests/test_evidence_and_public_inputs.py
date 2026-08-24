import json
import unittest
from pathlib import Path

from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.ingestion_boundary import PROTOTYPE_X12_BOUNDARY, Prototype837Ingestion
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from app.shared_context import build_shared_context


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT
def sample_payload(claim_id="BL-EVIDENCE-0001"):
    payload = json.loads((APP_ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    return payload


class EvidenceAndPublicInputTests(unittest.TestCase):
    def test_fact_resolver_builds_first_class_evidence_packet(self):
        payload = sample_payload()
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
        resolved = resolve_claim_facts(ctx, flags=payload["flags"])

        self.assertEqual(resolved.flags["eligibility_active"], True)
        self.assertEqual(resolved.flags["provider_enrolled"], True)
        self.assertEqual(resolved.flags["provider_not_suspended"], True)
        self.assertEqual(resolved.flags["not_deceased"], True)
        self.assertRegex(resolved.evidence_packet.evidence_root, r"^[0-9a-f]{64}$")
        fields = resolved.evidence_packet.to_dict()["items"][0].keys()
        for required in (
            "fact_name",
            "fact_value",
            "source_system",
            "source_record_id",
            "source_type",
            "fetched_at",
            "valid_from",
            "valid_until",
            "service_date_coverage",
            "hash",
            "attestation",
            "verification_status",
            "reason_if_missing",
        ):
            self.assertIn(required, fields)

    def test_adverse_document_fact_is_not_dropped_as_missing(self):
        payload = sample_payload("BL-EVIDENCE-HOLD")
        payload["flags"]["program_integrity_hold"] = True
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
        resolved = resolve_claim_facts(ctx, flags=payload["flags"])

        self.assertEqual(resolved.flags["program_integrity_hold"], True)
        self.assertNotIn("program_integrity_hold", resolved.evidence_packet.missing_reasons())

    def test_v2_manifest_matches_direct_state_boundary(self):
        manifest = json.loads(
            (REPO_ROOT / "ops" / "native_stark_public_inputs_v2.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            tuple(field["name"] for field in manifest["fields"]),
            PUBLIC_INPUT_FIELD_NAMES_V2,
        )
        self.assertIn("atomic database transition", manifest["statement"])

    def test_x12_ingestion_is_isolated_behind_prototype_boundary(self):
        ingestion = Prototype837Ingestion()
        parsed = ingestion.parse(sample_payload("BL-INGESTION-BOUNDARY")["edi"])

        self.assertTrue(parsed.accepted)
        self.assertEqual(ingestion.boundary_status, PROTOTYPE_X12_BOUNDARY)


if __name__ == "__main__":
    unittest.main()
