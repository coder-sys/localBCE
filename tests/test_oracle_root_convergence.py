import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app.batch.access_control import OPERATOR, RoleBook
from app.batch.batch_orchestrator import (
    BatchConfig,
    LocalBatchRecorder,
    _claim_source_commitment_for_oracle,
    _dev_attestations_for_payload,
    adjudicate_for_batch,
    submit_batches,
)
from app.batch.leaf import current_duplicate_pepper
from app.batch.nullifier import IndexedNullifierTree
from app.batch.stark_binding import build_monolithic_batch_input_witness
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[1]


class OracleRootConvergenceTests(unittest.TestCase):
    def test_application_and_proof_roots_match_with_and_without_required_authorization(self):
        env = {
            "BL_ENV": "test",
            "BL_DEV": "1",
            "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE": "1",
            "BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK": "1",
            "BL_FORCE_PYTHON_RULES_ENGINE": "1",
            "BL_ALLOW_LOCAL_TEST_ORACLE_KEYS": "1",
            "BL_PROVIDER_ALIAS_KEY": "BL_TEST_PROVIDER_ALIAS_KEY",
            "BL_DUPLICATE_CHECK_PEPPER": "BL_TEST_DUPLICATE_PEPPER",
        }
        with patch.dict("os.environ", env, clear=False):
            for procedure_code in ("99213", "T1019"):
                with self.subTest(procedure_code=procedure_code):
                    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
                    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", f"BL-ROOT-{procedure_code}")
                    payload["edi"] = payload["edi"].replace("SV1*HC:99213", f"SV1*HC:{procedure_code}")
                    config = BatchConfig(strict_oracle_attestations=False, enforce_nullifier_proofs=False)
                    roles = RoleBook()
                    roles.grant(OPERATOR, "operator@example.gov")
                    batch = submit_batches(
                        [payload],
                        actor="operator@example.gov",
                        access=roles,
                        config=config,
                        recorder=LocalBatchRecorder(),
                    )[0]

                    parsed = parse_837(payload["edi"])
                    unsigned = build_shared_context(
                        parsed,
                        payload["flags"],
                        strict_oracle=False,
                        tar_required_procedure_codes=config.tar_required_procedure_codes,
                    )
                    source_root = _claim_source_commitment_for_oracle(
                        unsigned,
                        config=config,
                        frequency_type="original",
                        governed_pepper=current_duplicate_pepper(),
                    )
                    tar_commitment = tar_authorization_commitment_for_context(
                        unsigned,
                        config.tar_required_procedure_codes,
                    )
                    attestations = _dev_attestations_for_payload(
                        parsed,
                        payload["flags"],
                        strict_oracle=False,
                        claim_source_commitment=source_root,
                        tar_authorization_commitment=tar_commitment,
                    )
                    ctx = build_shared_context(
                        parsed,
                        payload["flags"],
                        oracle_attestations=attestations,
                        strict_oracle=False,
                        claim_source_commitment=source_root,
                        tar_required_procedure_codes=config.tar_required_procedure_codes,
                    )
                    resolved = resolve_claim_facts(ctx, flags=ctx.flags, fee_schedule_cents=config.fee_schedule_cents)
                    result, engine_mode = adjudicate_for_batch(ctx, config)
                    proof_bundle = build_monolithic_batch_input_witness(
                        [(ctx, result, resolved.evidence_packet.evidence_root, engine_mode)],
                        nullifier_tree=IndexedNullifierTree(),
                        config=config,
                        signer_root=batch.oracle_signer_root,
                    )

                    self.assertEqual(batch.claim_count, 1)
                    self.assertEqual(int(batch.oracle_facts_root, 16), proof_bundle["witness"]["oracle_facts_root"])


if __name__ == "__main__":
    unittest.main()
