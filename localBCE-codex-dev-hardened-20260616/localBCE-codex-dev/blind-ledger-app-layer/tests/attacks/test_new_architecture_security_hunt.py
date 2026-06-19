import json
import unittest
from pathlib import Path

from app.batch.poseidon import FIELD_MODULUS
from app.ingestion import parse_837
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[2]
STARK_FIELD_MODULUS = 2**251 + 17 * 2**192 + 1


def sample_payload(claim_id="BL-NEW-ARCH-0001", flags=None, edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


class NewArchitectureSecurityHuntTests(unittest.TestCase):
    def test_app_batch_field_is_now_cairo_stark_field(self):
        self.assertEqual(FIELD_MODULUS, STARK_FIELD_MODULUS)

    def test_non_strict_mode_defaults_missing_required_facts_to_false(self):
        payload = sample_payload(
            "BL-NEW-ARCH-MISSING-FACTS",
            flags={
                "eligibility_active": None,
                "provider_enrolled": None,
            },
        )
        parsed = parse_837(payload["edi"])
        self.assertTrue(parsed.accepted, parsed.errors)

        ctx = build_shared_context(parsed, {}, strict_oracle=False)

        self.assertFalse(ctx.flags["eligibility_active"])
        self.assertFalse(ctx.flags["provider_enrolled"])
        self.assertFalse(ctx.flags["provider_not_suspended"])
        self.assertFalse(ctx.flags["not_deceased"])


if __name__ == "__main__":
    unittest.main()
