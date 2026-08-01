import json
import os
import unittest
from dataclasses import replace
from itertools import count
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import ADMIN, OPERATOR, RoleBook
from app.batch.batch_orchestrator import (
    BatchConfig,
    DIRTY_CLAIM_PREFILTER_REASON,
    LocalBatchRecorder,
    _claim_source_commitment_for_oracle,
    _dirty_claim_prefilter,
    adjudicate_for_batch,
    submit_batches,
)
from app.batch.leaf import current_duplicate_pepper
from app.batch.stark_binding import build_multi_line_service_line_witness, claim_output_for_multi_line_witness
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[1]
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)
ATTESTATION_COUNTER = count(1)


def roles() -> RoleBook:
    book = RoleBook()
    book.grant(ADMIN, "admin@example.gov")
    book.grant(OPERATOR, "operator@example.gov")
    return book


def sample_payload(claim_id: str, flags=None, edi_transform=None, config: BatchConfig | None = None) -> dict[str, object]:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    if flags:
        payload["flags"].update(flags)
    if edi_transform:
        payload["edi"] = edi_transform(payload["edi"])
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        return payload
    active_config = config or BatchConfig()
    try:
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
    except ValueError:
        return payload
    fixture_id = next(ATTESTATION_COUNTER)
    payload["oracle_attestations"] = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"PREFILTER-{claim_id}-{fact}-{fixture_id}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
        )
        for fact in DECISION_FACTS
    ]
    return payload


def unique_service_date(day: int):
    return lambda edi: edi.replace("DTP*472*D8*20260601", f"DTP*472*D8*202606{day:02d}")


def resolved_context_for(payload: dict[str, object], config: BatchConfig):
    parsed = parse_837(str(payload["edi"]))
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    ctx = build_shared_context(
        parsed,
        dict(payload["flags"]),
        strict_oracle=False,
        tar_required_procedure_codes=config.tar_required_procedure_codes,
    )
    resolved = resolve_claim_facts(ctx, flags=ctx.flags, fee_schedule_cents=config.fee_schedule_cents)
    return replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )


class DirtyClaimPrefilterTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.setdefault("BL_DEV", "1")
        os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
        os.environ.setdefault("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", "1")
        os.environ.setdefault("BL_ALLOW_LOCAL_TEST_ORACLE_KEYS", "1")
        os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_TEST_PROVIDER_ALIAS_KEY")

    def test_g1_mixed_batch_quarantines_only_structural_claims_before_proof(self):
        config = BatchConfig(enforce_nullifier_proofs=True)

        def unknown_procedure(edi: str) -> str:
            return edi.replace("SV1*HC:99213", "SV1*HC:ZZ999")

        def zero_amount(edi: str) -> str:
            return edi.replace("DTP*472*D8*20260601", "DTP*472*D8*20260603").replace(
                "CLM*BL-PREFILTER-ZERO*125.00", "CLM*BL-PREFILTER-ZERO*0.00"
            ).replace(
                "SV1*HC:99213*125.00",
                "SV1*HC:99213*0.00",
            )

        def zero_units(edi: str) -> str:
            return edi.replace("DTP*472*D8*20260601", "DTP*472*D8*20260604").replace(
                "*UN*1***1", "*UN*0***1"
            )

        zero_amount_payload = sample_payload(
            "BL-PREFILTER-ZERO",
            edi_transform=zero_amount,
            config=config,
        )
        zero_units_payload = sample_payload(
            "BL-PREFILTER-ZERO-UNITS",
            edi_transform=zero_units,
            config=config,
        )

        batch = submit_batches(
            [
                sample_payload("BL-PREFILTER-APPROVED", edi_transform=unique_service_date(1), config=config),
                {"edi": "", "flags": {}, "claim_id": "BL-PREFILTER-MALFORMED"},
                sample_payload("BL-PREFILTER-UNKNOWN", edi_transform=unknown_procedure, config=config),
                zero_amount_payload,
                zero_units_payload,
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=config,
        )[0]

        self.assertEqual(batch.claim_count, 4)
        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(
            [(packet.claim_id, packet.decision, packet.denial_reason) for packet in batch.claim_packets],
            [
                ("BL-PREFILTER-APPROVED", "approved", ""),
                ("BL-PREFILTER-UNKNOWN", "denied", "fee_schedule_missing"),
                ("BL-PREFILTER-ZERO", "denied", "invalid_charge"),
                ("BL-PREFILTER-ZERO-UNITS", "denied", "invalid_charge"),
            ],
        )
        self.assertEqual([item.reason for item in batch.quarantined], ["ingestion_failed"])
        self.assertEqual(batch.payments[0].approved_claim_count, 1)
        self.assertEqual(batch.nullifier_proofs[0]["claim_count"], 4)
        self.assertEqual(batch.nullifier_proofs[0]["attempt_nullifier_count"], 4)

        for payload in (zero_amount_payload, zero_units_payload):
            parsed = parse_837(str(payload["edi"]))
            _ctx, errors = _dirty_claim_prefilter(parsed, payload["flags"], config)
            self.assertEqual(errors, [])
            proof_ctx = resolved_context_for(payload, config)
            output = claim_output_for_multi_line_witness(
                build_multi_line_service_line_witness(proof_ctx, config=config)
            )
            self.assertEqual(
                (output["decision"], output["failure_code"], output["payment_cents"]),
                (0, 10, 0),
            )

    def test_g2_prefilter_pass_does_not_approve_duplicate_claim(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        payload = sample_payload("BL-PREFILTER-DUPLICATE", {"duplicate_claim": True}, config=config)
        parsed = parse_837(str(payload["edi"]))

        _ctx, errors = _dirty_claim_prefilter(parsed, payload["flags"], config)
        self.assertEqual(errors, [])

        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=config,
        )[0]

        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_packets[0].decision, "denied")
        self.assertEqual(batch.claim_packets[0].denial_reason, "duplicate_claim")
        self.assertEqual(batch.payments, [])

    def test_g3_borderline_government_fact_passes_prefilter_then_denies_later(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        payload = sample_payload("BL-PREFILTER-INACTIVE", {"eligibility_active": False}, config=config)
        parsed = parse_837(str(payload["edi"]))

        _ctx, errors = _dirty_claim_prefilter(parsed, payload["flags"], config)
        self.assertEqual(errors, [])

        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=roles(),
            recorder=LocalBatchRecorder(),
            config=config,
        )[0]

        self.assertEqual(batch.claim_count, 1)
        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_packets[0].decision, "denied")
        self.assertEqual(batch.claim_packets[0].denial_reason, "eligibility_inactive")
        self.assertEqual(batch.payments, [])

    def test_g4_unknown_procedure_reaches_authenticated_private_denial(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        payload = sample_payload(
            "BL-PREFILTER-UNKNOWN-BYPASS",
            edi_transform=lambda edi: edi.replace("SV1*HC:99213", "SV1*HC:ZZ999"),
            config=config,
        )
        parsed = parse_837(str(payload["edi"]))

        ctx, errors = _dirty_claim_prefilter(parsed, payload["flags"], config)
        self.assertIsNotNone(ctx)
        self.assertEqual(errors, [])

        bypass_ctx = resolved_context_for(payload, config)
        result, _engine_mode = adjudicate_for_batch(bypass_ctx, config)
        self.assertFalse(result.approved)
        self.assertEqual(result.denial_reason, "fee_schedule_missing")
        bundle = build_multi_line_service_line_witness(bypass_ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)
        self.assertFalse(bundle.service_lines[0].policy_present)
        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["failure_code"], 11)
        self.assertEqual(output["payment_cents"], 0)

    def test_g5_unknown_procedure_private_denial_matches_proof_output(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        payload = sample_payload(
            "BL-PREFILTER-UNKNOWN-PROOF",
            edi_transform=lambda edi: edi.replace("SV1*HC:99213", "SV1*HC:ZZ999"),
            config=config,
        )
        bypass_ctx = resolved_context_for(payload, config)

        result, _engine_mode = adjudicate_for_batch(bypass_ctx, config)
        bundle = build_multi_line_service_line_witness(bypass_ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)

        self.assertFalse(result.approved)
        self.assertEqual(result.denial_reason, "fee_schedule_missing")
        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["failure_code"], 11)
        self.assertEqual(output["allowed_cents"], 0)
        self.assertEqual(output["payment_cents"], 0)

    @patch.dict(
        os.environ,
        {"BL_ENV": "test", "BL_DEV": "1", "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1"},
        clear=False,
    )
    def test_g6_denied_attempt_consumes_nullifier_and_exact_replay_is_quarantined(self):
        config = BatchConfig(enforce_nullifier_proofs=True)
        unknown = lambda edi: edi.replace("SV1*HC:99213", "SV1*HC:ZZ999")
        recorder = LocalBatchRecorder(allow_test_only_unverified_settlement=True)

        first = submit_batches(
            [sample_payload("BL-PREFILTER-DENIED-REPLAY", edi_transform=unknown, config=config)],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=config,
        )[0]
        second = submit_batches(
            [
                sample_payload("BL-PREFILTER-DENIED-REPLAY", edi_transform=unknown, config=config),
                sample_payload("BL-REPLAY-COVER", edi_transform=unique_service_date(2), config=config),
            ],
            actor="operator@example.gov",
            access=roles(),
            recorder=recorder,
            config=config,
        )[0]

        self.assertEqual(first.claim_count, 1)
        self.assertEqual(first.claim_packets[0].decision, "denied")
        self.assertEqual(first.claim_packets[0].denial_reason, "fee_schedule_missing")
        self.assertNotEqual(first.duplicate_check_before, first.duplicate_check_after)
        self.assertEqual(len(first.attempt_nullifiers), 1)
        self.assertTrue(recorder.nullifier_tree.contains(first.attempt_nullifiers[0]))

        self.assertEqual(second.duplicate_check_before, first.duplicate_check_after)
        self.assertEqual(second.claim_count, 1)
        self.assertEqual(second.quarantine_count, 1)
        self.assertEqual(second.quarantined[0].reason, "attempt_nullifier_replay")
        self.assertEqual(second.claim_packets[0].claim_id, "BL-REPLAY-COVER")
        self.assertNotEqual(second.duplicate_check_before, second.duplicate_check_after)

    def test_g4_prefilter_passed_denial_matches_direct_circuit_output(self):
        config = BatchConfig(enforce_nullifier_proofs=False)
        payload = sample_payload("BL-PREFILTER-DIRECT-DENY", {"duplicate_claim": True}, config=config)
        parsed = parse_837(str(payload["edi"]))

        bypass_ctx = resolved_context_for(payload, config)
        result, _engine_mode = adjudicate_for_batch(bypass_ctx, config)
        bundle = build_multi_line_service_line_witness(bypass_ctx, config=config)
        output = claim_output_for_multi_line_witness(bundle)
        _ctx, errors = _dirty_claim_prefilter(parsed, payload["flags"], config)

        self.assertEqual(errors, [])
        self.assertFalse(result.approved)
        self.assertEqual(output["decision"], 0)
        self.assertEqual(output["payment_cents"], 0)


if __name__ == "__main__":
    unittest.main()
