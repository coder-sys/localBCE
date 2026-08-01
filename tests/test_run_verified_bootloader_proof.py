from __future__ import annotations

import inspect
import unittest
from unittest import mock

from tools import run_verified_bootloader_proof as runner


class VerifiedBootloaderProofTests(unittest.TestCase):
    def test_release_runner_does_not_self_verify_with_the_prover(self) -> None:
        self.assertNotIn('"--verify"', inspect.getsource(runner.main))

    def test_release_runner_does_not_accept_cli_selected_trust_tools(self) -> None:
        source = inspect.getsource(runner.main)
        self.assertNotIn('"--scarb-bin-wsl"', source)
        self.assertNotIn('"--prover-bin-wsl"', source)
        self.assertNotIn('"--bootloader-program-wsl"', source)

    def test_package_input_bypasses_synthetic_witness_generation(self) -> None:
        package = {
            "claim_count": 7,
            "witness": {
                "serialized_arguments_hex_json": ["0x1"],
                "expected_output_values": ["0x2"],
            },
        }
        with mock.patch.object(runner, "load_batch_package", return_value=package), mock.patch.object(
            runner.measure, "_build_batch_witness"
        ) as synthetic_builder:
            bundle, claim_count, loaded_package = runner._load_proving_input(
                None, runner.Path("package.json")
            )
        synthetic_builder.assert_not_called()
        self.assertEqual(7, claim_count)
        self.assertEqual(["0x1"], bundle["serialized_arguments_hex_json"])
        self.assertIs(package, loaded_package)

    def test_synthetic_input_is_rejected_in_production(self) -> None:
        with mock.patch.dict(runner.os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "disabled in production"):
                runner._load_proving_input(1, None)

    def test_plaintext_package_input_is_rejected_in_production(self) -> None:
        with mock.patch.dict(runner.os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "plaintext witness package proving"):
                runner._load_proving_input(None, runner.Path("package.json"))

    def test_default_blake_channel_does_not_override_upstream_defaults(self) -> None:
        self.assertIsNone(runner._prover_parameters("blake2s"))

    def test_poseidon_channel_preserves_the_upstream_96_bit_security_parameters(self) -> None:
        self.assertEqual(
            {
                "channel_hash": "poseidon252",
                "channel_salt": 0,
                "pcs_config": {
                    "pow_bits": 26,
                    "fri_config": {
                        "log_last_layer_degree_bound": 0,
                        "log_blowup_factor": 1,
                        "n_queries": 70,
                        "fold_step": 1,
                    },
                    "lifting_log_size": None,
                },
                "preprocessed_trace": "canonical_without_pedersen",
                "store_polynomials_coefficients": False,
                "include_all_preprocessed_columns": False,
                "opt_n_id_to_big_components": None,
            },
            runner._prover_parameters("poseidon252"),
        )

    def test_unknown_channel_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported prover channel"):
            runner._prover_parameters("unknown")

    def test_piped_package_builds_the_same_bundle_without_a_plaintext_file(self) -> None:
        package = {
            "claim_count": 3,
            "witness": {
                "serialized_arguments_hex_json": ["0x1", "0x2"],
                "expected_output_values": ["0x3"],
            },
        }
        with mock.patch.object(runner, "validate_batch_package", return_value=package):
            bundle, claim_count, loaded = runner._bundle_from_package(package)
        self.assertEqual(3, claim_count)
        self.assertEqual(["0x1", "0x2"], bundle["serialized_arguments_hex_json"])
        self.assertIs(package, loaded)

    def test_wsl_ram_staging_sends_payload_over_stdin(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(runner.subprocess, "run", return_value=completed) as run:
            runner._write_wsl_ram_file(
                "/dev/shm/blind-ledger-witness-test.json", b"[\"0x1\"]"
            )
        self.assertEqual(b"[\"0x1\"]", run.call_args.kwargs["input"])
        self.assertNotIn("0x1", " ".join(run.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
