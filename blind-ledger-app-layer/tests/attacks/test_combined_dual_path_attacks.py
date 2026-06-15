import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.orchestrator as orchestrator
from app.models import AdjudicationResult, ProofBundle
from app.registry import ClaimsRegistry
from app.rules_engine_fallback import adjudicate
from app.shared_context import build_shared_context
from app.ingestion import parse_837
from app.stubs import VerifierStub


ROOT = Path(__file__).resolve().parents[2]


def sample_payload(claim_id="BL-COMBINED-0001", flags=None, edi_transform=None):
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    return payload


def context_from_payload(payload):
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    return build_shared_context(parsed, payload["flags"], strict_oracle=False)


class CombinedDualPathAttackTests(unittest.TestCase):
    def test_registry_records_proof_path_and_artifact_hash_for_dual_path_audit(self):
        ctx = context_from_payload(sample_payload("BL-COMBINED-PATH"))
        result = adjudicate(ctx)
        grothish = ProofBundle(
            proof="0xSTUBPROOF" + "11" * 32,
            public_inputs=["0xgroth16-context", "0x01"],
            context_hash="0x" + "aa" * 32,
            stub=True,
            proof_system="LOCAL_STUB",
            verifier_key_id="LOCAL_STUB_V1",
        )
        sp1ish = ProofBundle(
            proof="0xSP1CORE" + "22" * 32,
            public_inputs=["0x" + "00" * 31 + "01", "0x" + "00" * 32],
            context_hash="0x" + "bb" * 32,
            stub=False,
            proof_system="SP1_CORE",
            verifier_key_id="SP1_CORE_V1",
        )

        with tempfile.TemporaryDirectory() as td:
            registry = ClaimsRegistry(Path(td) / "claims_registry.json")
            registry.record(result, grothish)
            registry.record(result, sp1ish)
            rows = json.loads((Path(td) / "claims_registry.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIn("proof_system", row)
            self.assertIn("proof_hash", row)
            self.assertIn("public_inputs", row)
            self.assertIn("verifier_key_id", row)
            self.assertRegex(row["proof_hash"], r"^0x[0-9a-f]{64}$")

    def test_stub_verifier_rejects_sp1_shaped_artifact_even_when_stub_flag_is_true(self):
        sp1_shaped = ProofBundle(
            proof="0xSTUBPROOF" + "sp1wrapped".encode().hex(),
            public_inputs=["0x" + "00" * 31 + "01", "0x" + "00" * 32],
            context_hash="0x" + "cc" * 32,
            stub=True,
            proof_system="SP1_CORE",
            verifier_key_id="SP1_CORE_V1",
        )

        self.assertFalse(VerifierStub().verify(sp1_shaped))

    def test_payment_side_effect_blocked_when_later_835_generation_fails(self):
        def unsafe_provider_name(edi):
            return edi.replace("NM1*82*1*ADAMS*ALICE", "NM1*82*1*ADAMS^BAD*ALICE")

        side_effects = []

        class RecordingBridge:
            def trigger(self, claim_id, amount, recipient):
                side_effects.append({"claim_id": claim_id, "amount": amount, "recipient": recipient})
                return {"status": "recorded"}

        payload = sample_payload("BL-COMBINED-PARTIAL-PAY", edi_transform=unsafe_provider_name)
        with tempfile.TemporaryDirectory() as td:
            input_path = Path(td) / "claim.json"
            out_dir = Path(td) / "out"
            input_path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(orchestrator, "CircleBridgeStub", return_value=RecordingBridge()):
                result = orchestrator.run_pipeline(input_path, out_dir)

            self.assertFalse(result["accepted"])
            self.assertEqual(result["errors"], ["noncanonical_provider_name"])
            self.assertEqual(len(side_effects), 0)
            self.assertFalse((out_dir / "claims_registry.json").exists())

    def test_corrupt_shared_registry_file_is_quarantined_and_future_record_succeeds(self):
        ctx = context_from_payload(sample_payload("BL-COMBINED-CORRUPT"))
        result = adjudicate(ctx)
        proof = ProofBundle("0xSTUBPROOFaa", ["0x01", "0x00"], "0x" + "dd" * 32, True)

        with tempfile.TemporaryDirectory() as td:
            registry_path = Path(td) / "claims_registry.json"
            registry_path.write_text("{not-json", encoding="utf-8")
            entry = ClaimsRegistry(registry_path).record(result, proof)
            rows = json.loads(registry_path.read_text(encoding="utf-8"))
            quarantined = list(Path(td).glob("claims_registry.json.corrupt_json.*.bak"))

            self.assertEqual(entry["claim_id"], result.claim_id)
            self.assertEqual(len(rows), 1)
            self.assertEqual(len(quarantined), 1)
            self.assertIn("proof_system", rows[0])
            self.assertIn("verifier_key_id", rows[0])
            self.assertIn("proof_hash", rows[0])
            self.assertIn("public_inputs", rows[0])

    def test_registry_rejects_missing_provenance_rows_by_quarantine(self):
        ctx = context_from_payload(sample_payload("BL-COMBINED-MISSING-PROV"))
        result = adjudicate(ctx)
        proof = ProofBundle("0xSTUBPROOFbb", ["0x01", "0x00"], "0x" + "ee" * 32, True)

        with tempfile.TemporaryDirectory() as td:
            registry_path = Path(td) / "claims_registry.json"
            registry_path.write_text(json.dumps([{"claim_id": "old", "approved": True}]), encoding="utf-8")
            ClaimsRegistry(registry_path).record(result, proof)
            rows = json.loads(registry_path.read_text(encoding="utf-8"))
            quarantined = list(Path(td).glob("claims_registry.json.missing_provenance.*.bak"))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["claim_id"], result.claim_id)
            self.assertEqual(len(quarantined), 1)

    def test_app_layer_has_no_live_sp1_path_selector_or_policy_gate(self):
        app_text = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "app").glob("*.py"))

        self.assertNotIn("SP1", app_text)
        self.assertNotIn("sp1", app_text)
        self.assertIn("proof_system", app_text)


if __name__ == "__main__":
    unittest.main()
