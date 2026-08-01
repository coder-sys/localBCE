import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from app.batch.batch_orchestrator import BatchConfig
from app.batch.poseidon import domain_poseidon_hash
from app.batch.stark_binding import build_multi_line_service_line_witness, flatten_multi_line_decision_input_witness
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.shared_context import build_shared_context


ROOT = Path(__file__).resolve().parents[1]
CAIRO_DIR = ROOT / "zk-cairo-sharp"


def _bundle_with_flags(flags_override=None, *, claim_id="BL-CLAIM-FACTS-KAT"):
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    edi = payload["edi"].replace("BL-CLAIM-0001", claim_id)
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
    return build_multi_line_service_line_witness(ctx, config=config)


def _flag_words(bundle) -> list[int]:
    return [
        int(bool(bundle.member_active)),
        int(bool(bundle.provider_payable)),
        int(bool(bundle.provider_not_suspended)),
        int(bool(bundle.member_not_deceased)),
        int(bool(bundle.duplicate_claim_attested)),
        int(bool(bundle.integrity_hold_attested)),
    ]


def _normalized_for(bundle) -> int:
    return domain_poseidon_hash("normalized_facts", _flag_words(bundle))


def _claim_facts_leaf_for(bundle, normalized: int) -> int:
    return domain_poseidon_hash(
        "oracle",
        [
            0,
            int(bundle.claim.claim_id),
            int(bundle.claim.claim_source_leaf),
            int(bundle.claim_facts_signer),
            int(normalized),
            int(bundle.claim_facts_verification_commitment),
            int(bundle.claim_facts_evidence_commitment),
            *_flag_words(bundle),
        ],
    )


def _run_claim_main(bundle) -> subprocess.CompletedProcess[str]:
    values = flatten_multi_line_decision_input_witness(bundle)
    with tempfile.TemporaryDirectory() as tmp:
        args_file = Path(tmp) / "claim_main_args.json"
        args_file.write_text(json.dumps([hex(value) for value in values]), encoding="utf-8")
        return subprocess.run(
            [
                "scarb",
                "execute",
                "--executable-name",
                "claim_main",
                "--arguments-file",
                str(args_file),
                "--print-program-output",
            ],
            cwd=CAIRO_DIR,
            text=True,
            capture_output=True,
            check=False,
        )


def _print_raw(name: str, proc: subprocess.CompletedProcess[str]) -> None:
    print(f"=== scarb execute claim_main {name} ===")
    print(f"returncode: {proc.returncode}")
    if proc.stdout:
        print("--- stdout ---")
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.stderr:
        print("--- stderr ---")
        print(proc.stderr, end="" if proc.stderr.endswith("\n") else "\n")


class MultiLineClaimFactsBindingExecuteKATs(unittest.TestCase):
    def _assert_forged_flag_path_rejected(
        self,
        *,
        name: str,
        claim_id: str,
        ctx_flag: str,
        bundle_field: str,
        true_value: bool,
        favorable_value: bool,
    ) -> None:
        committed = _bundle_with_flags({ctx_flag: true_value}, claim_id=claim_id)
        forged_flags = replace(committed, **{bundle_field: favorable_value})
        forged_normalized = _normalized_for(forged_flags)
        forged_leaf = _claim_facts_leaf_for(forged_flags, forged_normalized)
        forged = replace(
            forged_flags,
            normalized_fact_commitment=forged_normalized,
            claim_facts_leaf=forged_leaf,
        )

        proc = _run_claim_main(forged)
        _print_raw(f"forged_{name}_path_rejected", proc)

        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("multi facts path", proc.stdout + proc.stderr)

    def test_valid_claim_facts_leaf_executes(self):
        bundle = _bundle_with_flags()

        proc = _run_claim_main(bundle)
        _print_raw("valid_claim_facts_leaf_executes", proc)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_forged_member_active_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="member_active",
            claim_id="BL-CF-0001",
            ctx_flag="eligibility_active",
            bundle_field="member_active",
            true_value=False,
            favorable_value=True,
        )

    def test_forged_provider_payable_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="provider_payable",
            claim_id="BL-CF-0002",
            ctx_flag="provider_enrolled",
            bundle_field="provider_payable",
            true_value=False,
            favorable_value=True,
        )

    def test_forged_provider_not_suspended_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="provider_not_suspended",
            claim_id="BL-CF-0003",
            ctx_flag="provider_not_suspended",
            bundle_field="provider_not_suspended",
            true_value=False,
            favorable_value=True,
        )

    def test_forged_member_not_deceased_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="member_not_deceased",
            claim_id="BL-CF-0004",
            ctx_flag="not_deceased",
            bundle_field="member_not_deceased",
            true_value=False,
            favorable_value=True,
        )

    def test_forged_duplicate_claim_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="duplicate_claim",
            claim_id="BL-CF-0005",
            ctx_flag="duplicate_claim",
            bundle_field="duplicate_claim_attested",
            true_value=True,
            favorable_value=False,
        )

    def test_forged_integrity_hold_recomputed_leaf_rejected_on_path(self):
        self._assert_forged_flag_path_rejected(
            name="integrity_hold",
            claim_id="BL-CF-0006",
            ctx_flag="program_integrity_hold",
            bundle_field="integrity_hold_attested",
            true_value=True,
            favorable_value=False,
        )

    def test_forged_normalized_without_leaf_update_rejected(self):
        committed = _bundle_with_flags({"eligibility_active": False}, claim_id="BL-CLAIM-FACTS-DENY-2")
        forged_flags = replace(committed, member_active=True)
        forged_normalized = _normalized_for(forged_flags)
        forged = replace(forged_flags, normalized_fact_commitment=forged_normalized)

        proc = _run_claim_main(forged)
        _print_raw("forged_normalized_without_leaf_update_rejected", proc)

        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("multi facts leaf", proc.stdout + proc.stderr)

    def test_valid_flags_wrong_normalized_is_not_serialized(self):
        bundle = _bundle_with_flags(claim_id="BL-CLAIM-FACTS-WRONG-NORM")
        forged = replace(bundle, normalized_fact_commitment=(int(bundle.normalized_fact_commitment) + 1))

        self.assertEqual(
            flatten_multi_line_decision_input_witness(bundle),
            flatten_multi_line_decision_input_witness(forged),
        )
        proc = _run_claim_main(forged)
        _print_raw("valid_flags_wrong_normalized_is_not_serialized", proc)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
