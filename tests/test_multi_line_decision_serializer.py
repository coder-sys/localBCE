import json
import os
import unittest
from dataclasses import replace
from pathlib import Path

from app.batch.batch_orchestrator import BatchConfig, adjudicate_for_batch
from app.batch.nullifier import IndexedNullifierTree
from app.batch.stark_binding import (
    build_monolithic_batch_input_witness,
    build_multi_line_service_line_witness,
    claim_output_for_multi_line_witness,
    flatten_multi_line_decision_input_witness,
    validate_monolithic_batch_input_witness,
    validate_multi_line_claim_witness,
)
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]


def approved_claim_context():
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False)
    resolved = resolve_claim_facts(ctx, flags=payload["flags"], fee_schedule_cents=config.fee_schedule_cents)
    ctx = replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )
    result, engine_mode = adjudicate_for_batch(ctx)
    if not result.approved:
        raise AssertionError(result.denial_reason)
    return ctx, result, resolved.evidence_packet.evidence_root, config, engine_mode


def batch_claim_context(claim_id: str, service_date: str, flags_override=None):
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    edi = payload["edi"].replace("BL-CLAIM-0001", claim_id).replace("DTP*472*D8*20260601", f"DTP*472*D8*{service_date}")
    parsed = parse_837(edi)
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    flags = {**payload["flags"], **(flags_override or {})}
    ctx = build_shared_context(parsed, flags, strict_oracle=False)
    resolved = resolve_claim_facts(ctx, flags=flags, fee_schedule_cents=config.fee_schedule_cents)
    ctx = replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )
    result, engine_mode = adjudicate_for_batch(ctx)
    return ctx, result, resolved.evidence_packet.evidence_root, config, engine_mode


class MultiLineDecisionSerializerTests(unittest.TestCase):
    def test_serializer_emits_complete_multi_line_decision_input_and_roots_agree(self):
        ctx, result, evidence_root, config, engine_mode = approved_claim_context()
        _ = result, evidence_root, engine_mode
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        serialized = flatten_multi_line_decision_input_witness(bundle)

        self.assertTrue(validate_multi_line_claim_witness(bundle))
        self.assertEqual(
            serialized[-8:],
            [
                bundle.ruleset_root,
                bundle.ruleset_root,
                bundle.claim.claim_source_root,
                bundle.claim.claim_source_root,
                bundle.oracle_facts_root,
                bundle.oracle_facts_root,
                bundle.policy_root,
                bundle.policy_root,
            ],
        )
        self.assertEqual(len(bundle.claim.claim_source_path_elements), config.merkle_depth)
        self.assertEqual(len(bundle.fee_policy.fee_policy_path_elements), config.merkle_depth)
        self.assertEqual(len(bundle.service_lines[0].policy_path_elements), config.merkle_depth)
        self.assertEqual(len(bundle.nullifier.predecessor_path_elements), 32)
        self.assertGreater(len(serialized), 150)

    def test_serializer_validation_rejects_corrupted_claim_source_path(self):
        ctx, result, evidence_root, config, engine_mode = approved_claim_context()
        _ = result, evidence_root, engine_mode
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        corrupted_claim = replace(
            bundle.claim,
            claim_source_path_elements=(bundle.claim.claim_source_path_elements[0] + 1, *bundle.claim.claim_source_path_elements[1:]),
        )
        corrupted = replace(bundle, claim=corrupted_claim)

        with self.assertRaisesRegex(ValueError, "claim_source_membership_mismatch"):
            validate_multi_line_claim_witness(corrupted)

    def test_denied_claim_output_advances_attempt_nullifier_root(self):
        ctx, result, evidence_root, config, engine_mode = batch_claim_context(
            "BL-CLAIM-DENIED-SENTINEL",
            "20260601",
            {"duplicate_claim": True},
        )
        _ = result, evidence_root, engine_mode
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)

        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["payment_cents"], 0)
        self.assertEqual(output["nullifier_root_before"], bundle.nullifier.live_root_before)
        self.assertEqual(output["nullifier_root_after"], bundle.nullifier.root_after)
        self.assertNotEqual(output["nullifier_root_before"], output["nullifier_root_after"])

    def test_monolithic_batch_serializer_threads_approved_nullifier_roots(self):
        first = batch_claim_context("BL-CLAIM-BATCH-0001", "20260601")
        second = batch_claim_context("BL-CLAIM-BATCH-0002", "20260602")
        bundle = build_monolithic_batch_input_witness(
            [
                (first[0], first[1], first[2], first[4]),
                (second[0], second[1], second[2], second[4]),
            ],
            nullifier_tree=IndexedNullifierTree(),
            config=first[3],
        )

        self.assertTrue(validate_monolithic_batch_input_witness(bundle))
        self.assertEqual(bundle["metadata"]["approved_count"], 2)
        self.assertEqual(bundle["metadata"]["denied_count"], 0)
        self.assertEqual(bundle["witness"]["claims"][0].nullifier.root_after, bundle["witness"]["claims"][1].nullifier.live_root_before)
        self.assertEqual(bundle["witness"]["claim_source_root"], bundle["witness"]["claims"][0].claim.claim_source_root)
        self.assertEqual(bundle["witness"]["oracle_facts_root"], bundle["witness"]["claims"][1].oracle_facts_root)
        self.assertEqual(bundle["witness"]["policy_root"], bundle["witness"]["claims"][0].policy_root)

    def test_monolithic_batch_serializer_advances_nullifier_root_for_denied_claim(self):
        approved = batch_claim_context("BL-CLAIM-BATCH-0001", "20260601")
        denied = batch_claim_context("BL-CLAIM-BATCH-0002", "20260602", {"duplicate_claim": True})
        self.assertFalse(denied[1].approved)

        bundle = build_monolithic_batch_input_witness(
            [
                (approved[0], approved[1], approved[2], approved[4]),
                (denied[0], denied[1], denied[2], denied[4]),
            ],
            nullifier_tree=IndexedNullifierTree(),
            config=approved[3],
        )

        denied_witness = bundle["witness"]["claims"][1]
        self.assertTrue(validate_monolithic_batch_input_witness(bundle))
        self.assertEqual(bundle["metadata"]["approved_count"], 1)
        self.assertEqual(bundle["metadata"]["denied_count"], 1)
        self.assertEqual(
            denied_witness.nullifier.live_root_before,
            bundle["witness"]["claims"][0].nullifier.root_after,
        )
        self.assertEqual(denied_witness.nullifier.root_after, bundle["expected_output"]["batch_root_after"])
        self.assertEqual(len(bundle["witness"]["nullifier_transitions"]), 2)
        denied_output = claim_output_for_multi_line_witness(denied_witness)
        self.assertEqual(denied_output["nullifier_root_before"], denied_witness.nullifier.live_root_before)
        self.assertEqual(denied_output["nullifier_root_after"], denied_witness.nullifier.root_after)

    def test_monolithic_builder_starts_from_explicit_live_state_without_mutating_it(self):
        claim = batch_claim_context("BL-CLAIM-LIVE-ROOT-1", "20260603")
        live_tree = IndexedNullifierTree([123456789])
        live_root = live_tree.root

        bundle = build_monolithic_batch_input_witness(
            [(claim[0], claim[1], claim[2], claim[4])],
            nullifier_tree=live_tree,
            config=claim[3],
        )

        self.assertEqual(bundle["witness"]["batch_root_before"], live_root)
        self.assertEqual(live_tree.root, live_root)
        self.assertFalse(live_tree.contains(bundle["witness"]["claims"][0].claim.attempt_nullifier))
        self.assertNotEqual(bundle["witness"]["expected_batch_root_after"], live_root)


if __name__ == "__main__":
    unittest.main()
