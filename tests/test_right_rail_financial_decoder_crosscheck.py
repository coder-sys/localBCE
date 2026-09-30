"""Python decoders of Lean results sit outside the correctness TCB (Art. V.3): every decoded value must re-encode to
the exact bytes Lean wrote.  Each mutation below is a decoder that silently drops, defaults, reorders or normalises
something; with the cross-check switched off it accepts the payload (the control), with it on it refuses."""

from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from app import right_rail_financial_engine as engine
from app import right_rail_financial_semantic_adapter as semantic
from tests.test_right_rail_financial_constitution_invariants import _duplicate_transition_result, _rejected_transition_result

LEAN_ACCEPTED = (Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "vectors" / "result.expected.bin").read_bytes()
REJECTED = _rejected_transition_result(4, 4)
DUPLICATE = _duplicate_transition_result(action_id="a1", claim_id="c1", evaluation_id="e1", expected_revision=3)
# the reject-reason option tag of REJECTED: after magic, version, status and the length-prefixed contract
REASON_TAG_AT = 11 + 2 + len(engine.CORRECTION_TRANSITION_OPERATION.encode())


class DecoderCrossCheckTests(unittest.TestCase):
    def test_every_lean_result_shape_encodes_back_to_its_bytes(self) -> None:
        for payload in (LEAN_ACCEPTED, REJECTED, DUPLICATE):
            decoded = engine.decode_correction_transition_result(payload)
            self.assertEqual(engine._encode_correction_transition_result(decoded), payload)

    def test_lenient_decoders_are_refused_by_the_cross_check(self) -> None:
        real_facts, real_action = engine._read_correction_dependency_facts, engine._read_correction_action

        def zero_owner_now(reader):
            facts = real_facts(reader)
            self.assertNotEqual(facts["owner_now_ms"], 0)  # else the mutant would be vacuous
            return {**facts, "owner_now_ms": 0}

        def reorder_observations(reader):
            facts = real_facts(reader)
            return {**facts, "query_observations": dict(reversed(list(facts["query_observations"].items())))}

        def default_digest(reader):
            return {**real_action(reader), "payload_digest": bytes(64)}

        def any_nonzero_tag_is_some(reader, tags, label):
            return None if reader.byte(f"{label}_tag") == 0 else tags[reader.byte(label)]

        bad_tag = REJECTED[:REASON_TAG_AT] + bytes([7]) + REJECTED[REASON_TAG_AT + 1:]
        for name, target, attribute, replacement, payload in (
            ("drops owner_now_ms", engine, "_read_correction_dependency_facts", zero_owner_now, LEAN_ACCEPTED),
            ("reorders the query observations", engine, "_read_correction_dependency_facts", reorder_observations, LEAN_ACCEPTED),
            ("defaults the action payload digest", engine, "_read_correction_action", default_digest, LEAN_ACCEPTED),
            ("ignores trailing bytes", semantic._WireReader, "finish", lambda self: None, LEAN_ACCEPTED + bytes(1)),
            ("reads any nonzero option tag as Some", engine, "_read_optional_correction_tag", any_nonzero_tag_is_some, bad_tag),
        ):
            with self.subTest(mutant=name), mock.patch.object(target, attribute, replacement):
                with mock.patch.object(engine, "_encode_correction_transition_result", lambda _result, payload=payload: payload):
                    engine.decode_correction_transition_result(payload)  # control: the decoder alone accepts it
                with self.assertRaises(engine.FinancialEngineResultError) as refused:
                    engine.decode_correction_transition_result(payload)
                self.assertEqual(str(refused.exception), "engine_correction_result_canonical")

    def test_lenient_evaluator_result_decoder_is_refused(self) -> None:
        wire = engine.decode_correction_transition_result(LEAN_ACCEPTED)["mutation"]["resulting_result_wire"]
        with mock.patch.object(semantic, "_bind_result_identity"), mock.patch.object(semantic._WireReader, "finish", lambda self: None):
            with mock.patch.object(semantic, "_encode_blfres02_result", lambda _result: wire + b"\x00"):
                semantic.decode_live_result(wire + b"\x00", {})  # control
            with self.assertRaises(semantic.SemanticAdapterCodecError) as refused:
                semantic.decode_live_result(wire + b"\x00", {})
            self.assertEqual(str(refused.exception), "result_canonical")

    def test_worker_frame_is_exact(self) -> None:
        worker = mock.Mock(exchange=mock.Mock(return_value=b"\x01\x00"), commit_bytes=mock.Mock(return_value=0))
        with mock.patch.object(engine, "_running_evaluator", return_value=worker):
            with self.assertRaises(engine.FinancialEngineResultError) as refused:
                engine._evaluate_wire(b"BLFIN02")
        self.assertEqual(str(refused.exception), "evaluator_response")  # a rejection status is exactly one byte


if __name__ == "__main__":
    unittest.main()
