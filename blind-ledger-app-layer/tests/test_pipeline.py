import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.appeal_router import route_appeal
from app.generator_835 import generate_835
from app.ingestion import parse_837
from app.orchestrator import run_pipeline
from app.rules_engine_fallback import adjudicate
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def load_context(self, flags=None):
        payload = json.loads((ROOT / "sample_claim_input.json").read_text())
        if flags:
            payload["flags"].update(flags)
        parsed = parse_837(payload["edi"])
        self.assertTrue(parsed.accepted, parsed.errors)
        return build_shared_context(parsed, payload["flags"], strict_oracle=False)

    def test_ingestion_accepts_837(self):
        payload = json.loads((ROOT / "sample_claim_input.json").read_text())
        parsed = parse_837(payload["edi"])
        self.assertTrue(parsed.accepted)
        self.assertGreater(len(parsed.segments), 5)

    def test_rules_engine_approves_clean_claim(self):
        result = adjudicate(self.load_context())
        self.assertTrue(result.approved)
        self.assertEqual(result.denial_reason, "")

    def test_gate_g2_denies_inactive_eligibility(self):
        result = adjudicate(self.load_context({"eligibility_active": False}))
        self.assertFalse(result.approved)
        self.assertEqual(result.denial_reason, "eligibility_inactive")

    def test_835_denial_contains_reason_codes(self):
        ctx = self.load_context({"eligibility_active": False})
        result = adjudicate(ctx)
        edi = generate_835(ctx, result)
        self.assertIn("CAS*CO*27", edi)
        self.assertIn("LQ*HE*N30", edi)

    def test_appeal_router(self):
        ctx = self.load_context({"duplicate_claim": True})
        result = adjudicate(ctx)
        self.assertEqual(route_appeal(result), "program_integrity")

    def test_end_to_end_demo(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(
                os.environ,
                {
                    "BL_DEV": "1",
                    "BL_FORCE_PYTHON_RULES_ENGINE": "1",
                    "BL_PROVIDER_ALIAS_KEY": "BL_TEST_PROVIDER_ALIAS_KEY",
                },
                clear=False,
            ):
                result = run_pipeline(ROOT / "sample_claim_input.json", Path(td))
            self.assertTrue(result["accepted"])
            self.assertTrue(result["decision"]["approved"])
            self.assertTrue(Path(result["835_path"]).exists())


if __name__ == "__main__":
    unittest.main()
