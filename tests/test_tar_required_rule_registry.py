from __future__ import annotations

import copy
import json
import os
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import (
    BatchConfig,
    LocalBatchRecorder,
    _claim_source_commitment_for_oracle,
    adjudicate_for_batch,
    policy_root_hex,
    ruleset_policy_record,
    submit_batches,
)
from app.batch.leaf import current_duplicate_pepper
from app.batch.stark_binding import build_multi_line_service_line_witness, validate_multi_line_claim_witness
from app.batch.tar_required import load_default_tar_required_codes
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.oracle_attestation import make_test_attestation
from app.rules_engine_fallback import DEFAULT_FEE_SCHEDULE_CENTS, procedure_requires_prior_authorization
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def _sample_payload(claim_id: str, procedure_code: str = "99213", include_prior_auth: bool = True) -> dict[str, object]:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    payload["edi"] = payload["edi"].replace("SV1*HC:99213*125.00", f"SV1*HC:{procedure_code}*125.00")
    if not include_prior_auth:
        payload["edi"] = payload["edi"].replace("~REF*G1*PA-OK-123", "")
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    ctx = build_shared_context(parsed, payload["flags"], strict_oracle=False, tar_required_procedure_codes=config.tar_required_procedure_codes)
    claim_source_commitment = _claim_source_commitment_for_oracle(
        ctx,
        config=config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    tar_authorization_commitment = tar_authorization_commitment_for_context(ctx, config.tar_required_procedure_codes)
    payload["claim_source_commitment"] = claim_source_commitment
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


def _role_book() -> RoleBook:
    roles = RoleBook()
    roles.grant(OPERATOR, "operator@example.gov")
    return roles


class TarRequiredRuleRegistryTests(unittest.TestCase):
    def test_default_policy_artifact_replaces_hardcoded_prior_auth_set(self) -> None:
        default_codes = load_default_tar_required_codes()
        self.assertEqual(default_codes, ("T1019", "S5102", "H2015"))
        self.assertTrue(procedure_requires_prior_authorization("T1019"))
        self.assertFalse(procedure_requires_prior_authorization("99213"))
        ruleset_record = ruleset_policy_record(BatchConfig().ruleset_version)
        fee_schedule = {**DEFAULT_FEE_SCHEDULE_CENTS, "S0512": 12500}
        default_root = policy_root_hex(
            BatchConfig(fee_schedule_cents=fee_schedule, tar_required_procedure_codes=default_codes),
            ruleset_record,
        )
        expanded_root = policy_root_hex(
            BatchConfig(fee_schedule_cents=fee_schedule, tar_required_procedure_codes=(*default_codes, "S0512")),
            ruleset_record,
        )
        self.assertNotEqual(default_root, expanded_root)

    def test_root_update_changes_g7_behavior_without_code_change(self) -> None:
        default_codes = load_default_tar_required_codes()
        config = BatchConfig(
            enforce_nullifier_proofs=False,
            fee_schedule_cents={"99213": 12500, "T1019": 12500, "S5102": 12500, "H2015": 12500, "S0512": 12500},
            tar_required_procedure_codes=(*default_codes, "S0512"),
        )
        batch = submit_batches(
            [_sample_payload("BL-TAR-ADD-S0512", "S0512", include_prior_auth=False)],
            actor="operator@example.gov",
            access=_role_book(),
            config=config,
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.claim_packets[0].decision, "denied")
        self.assertEqual(batch.claim_packets[0].denial_reason, "prior_authorization_required")
        self.assertEqual(batch.policy_root, policy_root_hex(config, ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)))

    def test_same_s0512_claim_flips_outcome_when_only_tar_table_changes(self) -> None:
        default_codes = load_default_tar_required_codes()
        fee_schedule = {"99213": 12500, "T1019": 12500, "S5102": 12500, "H2015": 12500, "S0512": 12500}
        claim = _sample_payload("BL-TAR-SAME-S0512", "S0512", include_prior_auth=False)
        config_without_s0512 = BatchConfig(
            enforce_nullifier_proofs=False,
            fee_schedule_cents=fee_schedule,
            tar_required_procedure_codes=default_codes,
        )
        config_with_s0512 = BatchConfig(
            enforce_nullifier_proofs=False,
            fee_schedule_cents=fee_schedule,
            tar_required_procedure_codes=(*default_codes, "S0512"),
        )

        with patch.dict(os.environ, {"BL_FORCE_PYTHON_RULES_ENGINE": "1"}, clear=False), patch.dict(
            DEFAULT_FEE_SCHEDULE_CENTS,
            {"S0512": 12500},
            clear=False,
        ):
            approved_batch = submit_batches(
                [copy.deepcopy(claim)],
                actor="operator@example.gov",
                access=_role_book(),
                config=config_without_s0512,
                recorder=LocalBatchRecorder(),
            )[0]
            denied_batch = submit_batches(
                [copy.deepcopy(claim)],
                actor="operator@example.gov",
                access=_role_book(),
                config=config_with_s0512,
                recorder=LocalBatchRecorder(),
            )[0]

        self.assertEqual(approved_batch.claim_packets[0].decision, "approved")
        self.assertEqual(denied_batch.claim_packets[0].decision, "denied")
        self.assertEqual(denied_batch.claim_packets[0].denial_reason, "prior_authorization_required")
        self.assertNotEqual(approved_batch.policy_root, denied_batch.policy_root)
        self.assertEqual(
            denied_batch.policy_root,
            policy_root_hex(
                config_with_s0512,
                ruleset_policy_record(config_with_s0512.ruleset_version, config_with_s0512.ruleset_policy_content),
            ),
        )

    def test_root_update_removing_code_makes_absent_pa_nonblocking_without_circuit_change(self) -> None:
        default_codes = load_default_tar_required_codes()
        reduced_codes = tuple(code for code in default_codes if code != "T1019")
        config = BatchConfig(
            enforce_nullifier_proofs=False,
            tar_required_procedure_codes=reduced_codes,
        )
        batch = submit_batches(
            [_sample_payload("BL-TAR-REMOVE-T1019", "T1019", include_prior_auth=False)],
            actor="operator@example.gov",
            access=_role_book(),
            config=config,
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.claim_packets[0].decision, "approved")
        self.assertEqual(batch.policy_root, policy_root_hex(config, ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)))

    def test_default_config_preserves_original_tar_code_adjudication_behavior(self) -> None:
        for procedure_code in ("T1019", "S5102", "H2015"):
            with self.subTest(procedure_code=procedure_code):
                batch = submit_batches(
                    [_sample_payload(f"BL-TAR-DEFAULT-{procedure_code}", procedure_code, include_prior_auth=False)],
                    actor="operator@example.gov",
                    access=_role_book(),
                    config=BatchConfig(),
                    recorder=LocalBatchRecorder(),
                )[0]
                self.assertEqual(batch.claim_packets[0].decision, "denied")
                self.assertEqual(batch.claim_packets[0].denial_reason, "prior_authorization_required")

        batch = submit_batches(
            [_sample_payload("BL-TAR-DEFAULT-99213", "99213", include_prior_auth=False)],
            actor="operator@example.gov",
            access=_role_book(),
            config=BatchConfig(),
            recorder=LocalBatchRecorder(),
        )[0]
        self.assertEqual(batch.claim_packets[0].decision, "approved")

    def test_fabricated_prior_auth_for_tar_required_service_is_quarantined(self) -> None:
        payload = _sample_payload("BL-TAR-FABRICATED-PA", "T1019", include_prior_auth=True)
        forged_attestations = [
            make_test_attestation(
                fact,
                bool(payload["flags"][fact]),
                source_id=f"UNSIGNED-TAR-{fact}",
                claim_id="BL-TAR-FABRICATED-PA",
                claim_source_commitment=payload["claim_source_commitment"],
                tar_authorization_commitment=0,
            )
            for fact in DECISION_FACTS
        ]
        payload["oracle_attestations"] = forged_attestations

        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=_role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("oracle_attestation_invalid", batch.quarantined[0].errors[0])

    def test_genuine_signed_prior_auth_for_tar_required_service_approves_and_pays(self) -> None:
        batch = submit_batches(
            [_sample_payload("BL-TAR-SIGNED-PA", "T1019", include_prior_auth=True)],
            actor="operator@example.gov",
            access=_role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.quarantine_count, 0)
        self.assertEqual(batch.claim_packets[0].decision, "approved")
        self.assertEqual(batch.claim_packets[0].payable_amount, 125.0)

    def test_prior_auth_swap_after_signing_is_quarantined(self) -> None:
        payload = _sample_payload("BL-TAR-SWAPPED-PA", "T1019", include_prior_auth=True)
        payload["edi"] = payload["edi"].replace("PA-OK-123", "PA-SWAPPED-999")

        batch = submit_batches(
            [payload],
            actor="operator@example.gov",
            access=_role_book(),
            config=BatchConfig(enforce_nullifier_proofs=False),
            recorder=LocalBatchRecorder(),
        )[0]

        self.assertEqual(batch.quarantine_count, 1)
        self.assertEqual(batch.quarantined[0].reason, "adjudication_failed")
        self.assertIn("oracle_attestation_invalid", batch.quarantined[0].errors[0])

    def test_forged_nonmembership_for_required_code_rejected_by_python_validator(self) -> None:
        os.environ.setdefault("BL_DEV", "1")
        os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
        payload = _sample_payload("BL-TAR-FORGED-NONMEMBER", "T1019", include_prior_auth=True)
        parsed = parse_837(payload["edi"])
        ctx = build_shared_context(
            parsed,
            payload["flags"],
            oracle_attestations=payload["oracle_attestations"],
            strict_oracle=True,
            claim_source_commitment=payload["claim_source_commitment"],
        )
        config = BatchConfig()
        resolved = resolve_claim_facts(ctx, flags=payload["flags"], fee_schedule_cents=config.fee_schedule_cents)
        ctx = replace(
            ctx,
            flags=resolved.flags,
            fact_verification={**ctx.fact_verification, **resolved.fact_verification},
        )
        result, _engine_mode = adjudicate_for_batch(ctx, config)
        self.assertTrue(result.approved)
        bundle = build_multi_line_service_line_witness(ctx, config=config)
        line = bundle.service_lines[0]
        policy_rows = list(bundle.policy_rows)
        policy_rows[line.policy_row_index] = replace(policy_rows[line.policy_row_index], requires_tar=False)
        forged_line = replace(line, tar_required=False, authorization_index=0)
        forged = replace(
            bundle,
            service_lines=(forged_line,),
            policy_rows=tuple(policy_rows),
            authorizations=(),
        )

        with self.assertRaisesRegex(ValueError, "multi_line_policy_dictionary_leaf_mismatch"):
            validate_multi_line_claim_witness(forged)


if __name__ == "__main__":
    unittest.main()
