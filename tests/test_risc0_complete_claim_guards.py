from __future__ import annotations

from pathlib import Path
import re
import unittest

from app.batch.batch_orchestrator import BatchConfig, ruleset_policy_record
from app.batch.oracle_facts_root import canonical_oracle_signer_root
from tests.test_risc0_complete_claim_differential import _resolve_run_owned_target


ROOT = Path(__file__).resolve().parents[1]
RISC0 = ROOT / "experiments" / "risc0_privacy_v2"


class Risc0CompleteClaimGuardTests(unittest.TestCase):
    def test_frozen_candidate_uses_sibling_execution_target_without_dirtying_release_tree(self) -> None:
        execution_root = ROOT / "cache" / "synthetic-execution-root"
        candidate_root = execution_root / "release-tree" / "blind-ledger-app-layer"
        external_target = execution_root / "risc0-model-target"
        self.assertEqual(
            external_target.resolve(),
            _resolve_run_owned_target(str(external_target), candidate_root),
        )
        with self.assertRaisesRegex(AssertionError, "outside the frozen release tree"):
            _resolve_run_owned_target(str(candidate_root / "generated-target"), candidate_root)
        with self.assertRaisesRegex(AssertionError, "inside the run-owned execution root"):
            _resolve_run_owned_target(
                str(ROOT / "cache" / "different-execution-root" / "risc0-model-target"),
                candidate_root,
            )

    def test_guest_host_and_differential_preserve_exact_twelve_canonical_fields(self) -> None:
        model = (RISC0 / "model" / "src" / "lib.rs").read_text(encoding="utf-8")
        guest = (RISC0 / "methods" / "guest" / "src" / "main.rs").read_text(encoding="utf-8")
        host = (RISC0 / "host" / "src" / "main.rs").read_text(encoding="utf-8")
        differential = (ROOT / "tests" / "test_risc0_complete_claim_differential.py").read_text(
            encoding="utf-8"
        )
        cairo = (ROOT / "zk-cairo-sharp" / "src" / "lib.cairo").read_text(encoding="utf-8")
        scarb = (ROOT / "zk-cairo-sharp" / "Scarb.toml").read_text(encoding="utf-8")
        self.assertIn("pub const PUBLIC_FIELD_COUNT: usize = 12;", model)
        self.assertIn("env::commit(&execution.public_fields);", guest)
        self.assertIn("let output: [[u8; 32]; 12]", host)
        self.assertNotIn("execution.allowed_cents", guest)
        self.assertNotIn("execution.payment_cents", guest)
        batch_output_v2 = re.search(r"pub struct BatchOutputV2 \{(?P<body>.*?)\n\}", cairo, re.DOTALL)
        self.assertIsNotNone(batch_output_v2)
        production_fields = re.findall(r"pub (\w+): (\w+),", batch_output_v2.group("body"))
        self.assertEqual(
            [
                ("protocol_version", "felt252"),
                ("settlement_domain", "felt252"),
                ("batch_nonce", "felt252"),
                ("nullifier_root_before", "felt252"),
                ("nullifier_root_after", "felt252"),
                ("claim_source_root", "felt252"),
                ("oracle_facts_root", "felt252"),
                ("policy_root", "felt252"),
                ("ruleset_root", "felt252"),
                ("opaque_batch_commitment", "felt252"),
                ("value_conservation_commitment", "felt252"),
                ("settlement_commitment", "felt252"),
            ],
            production_fields,
        )
        self.assertIn("pub fn batch_main_v2(input: BatchClaimInputV2) -> BatchOutputV2", cairo)
        self.assertIn("canonical_batch_output_v2(batch_main_v2(input))", cairo)
        self.assertIn("canonical_multi_line_decision_output(\n        main(", cairo)
        self.assertIn('name = "batch_main_v2_canonical_transport"', scarb)
        self.assertIn('name = "claim_main_canonical_transport"', scarb)
        self.assertIn("expected_limbs = expected_count * 2", differential)
        self.assertIn("if not 0 <= limb < U128_LIMIT:", differential)
        self.assertIn("if not 0 <= value < FIELD_MODULUS:", differential)
        self.assertNotIn("% FIELD_MODULUS", differential)
        self.assertNotIn("+ FIELD_MODULUS", differential)
        self.assertIn('os.environ.get("BL_RISC0_MODEL_BINARY")', differential)
        self.assertIn('os.environ.get("BL_RISC0_MODEL_BINARY_SHA256")', differential)
        self.assertIn("if (binary_raw is None) != (expected_hash is None):", differential)
        self.assertIn('expected_binary = (target / "release" / "host").resolve()', differential)
        self.assertIn("if binary != expected_binary:", differential)
        self.assertIn("if not binary.is_file():", differential)
        self.assertIn('re.fullmatch(r"[0-9a-f]{64}", expected_hash)', differential)
        self.assertIn("digest = hashlib.sha256()", differential)
        self.assertIn("hmac.compare_digest(actual_hash, expected_hash)", differential)
        self.assertIn("hmac.compare_digest(post_execution_hash, expected_hash)", differential)
        self.assertIn('["wsl", "--exec", wsl_binary, "model"]', differential)
        self.assertIn(
            '"cargo run --release --quiet --offline --locked -p host -- model"',
            differential,
        )
        self.assertIn("if indices != list(range(12)):", differential)
        self.assertNotIn("shell=True", differential)

    def test_pinned_guest_ruleset_root_matches_current_governed_artifacts(self) -> None:
        model = (RISC0 / "model" / "src" / "lib.rs").read_text(encoding="utf-8")
        match = re.search(
            r'PINNED_RULESET_ROOT_DECIMAL: &str =\s*"(\d+)";',
            model,
        )
        self.assertIsNotNone(match)
        current = int(ruleset_policy_record(BatchConfig().ruleset_version), 16)
        self.assertEqual(current, int(match.group(1)))

    def test_pinned_guest_oracle_signer_descriptor_matches_canonical_application_root(self) -> None:
        model = (RISC0 / "model" / "src" / "lib.rs").read_text(encoding="utf-8")
        match = re.search(
            r'ORACLE_SIGNER_ROOT_HEX: &str =\s*"([0-9a-f]{64})";',
            model,
        )
        self.assertIsNotNone(match)
        self.assertEqual(canonical_oracle_signer_root(), match.group(1))

    def test_proof_adjudicator_has_no_float_or_ambient_io_behavior(self) -> None:
        source = (ROOT / "rules-engine-rust" / "src" / "lib.rs").read_text(encoding="utf-8")
        start = source.index("pub fn adjudicate_for_proof")
        end = source.index("\nfn gate(", start)
        proof_rule = source[start:end]
        for forbidden in (
            "f32",
            "f64",
            "std::fs",
            "std::net",
            "std::time",
            "std::env",
            "Command::",
            "serde_json",
            "default_tar_required_codes",
            "fee_allowed_cents",
        ):
            self.assertNotIn(forbidden, proof_rule)

    def test_wire_format_and_guest_fail_closed_before_execution(self) -> None:
        model = (RISC0 / "model" / "src" / "lib.rs").read_text(encoding="utf-8")
        guest = (RISC0 / "methods" / "guest" / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn('const WIRE_MAGIC: &[u8; 8] = b"BLPV2C03";', model)
        self.assertIn('copy_from_slice(b"BLPV2C02")', model)
        self.assertIn('"witness_wire_magic_mismatch"', model)
        self.assertIn("witness_wire_length_mismatch", model)
        self.assertIn("decode_witness(&wire).expect", guest)
        self.assertIn("execute_complete_claim(&witness).expect", guest)

    def test_non_development_local_prover_configuration_is_pinned(self) -> None:
        host_manifest = (RISC0 / "host" / "Cargo.toml").read_text(encoding="utf-8")
        runner = (RISC0 / "run_local.sh").read_text(encoding="utf-8")
        self.assertIn('risc0-zkvm = { version = "=3.0.5", features = ["disable-dev-mode"] }', host_manifest)
        self.assertIn("unset RISC0_DEV_MODE BONSAI_API_KEY BONSAI_API_URL", runner)
        operational_lines = [
            line.strip()
            for line in runner.splitlines()
            if line.strip() and not line.strip().startswith("unset ")
        ]
        self.assertFalse(any("BONSAI_API_KEY=" in line or "BONSAI_API_URL=" in line for line in operational_lines))
        self.assertFalse(any(re.search(r"\bbonsai\b", line, re.IGNORECASE) for line in operational_lines))


if __name__ == "__main__":
    unittest.main()
