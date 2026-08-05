#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import run_stark_sepolia_pilot as pilot


class StarkSepoliaPilotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.example_path = ROOT / "ops" / "stark_sepolia_pilot.example.json"
        self.example = json.loads(self.example_path.read_text(encoding="utf-8"))

    def write_config(self, directory: Path, value: dict) -> Path:
        path = directory / "pilot.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_example_configuration_is_valid_only_as_example(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        self.assertEqual(config.value["chain_id"], pilot.SEPOLIA_CHAIN_ID)
        self.assertEqual(config.governance_safe, self.example["emergency_safe"])

        with self.assertRaisesRegex(pilot.PilotError, "must not be an example"):
            pilot.PilotConfig.load(self.example_path)

    def test_configuration_rejects_secret_in_environment_name_field(self) -> None:
        value = copy.deepcopy(self.example)
        value["deployer_private_key_env"] = "0x" + "ab" * 32
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(Path(temporary), value)
            with self.assertRaisesRegex(pilot.PilotError, "environment variable"):
                pilot.PilotConfig.load(path, allow_example=True)

    def test_configuration_rejects_different_emergency_safe(self) -> None:
        value = copy.deepcopy(self.example)
        value["emergency_safe"] = "0x4444444444444444444444444444444444444444"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(Path(temporary), value)
            with self.assertRaisesRegex(pilot.PilotError, "must be the same Safe"):
                pilot.PilotConfig.load(path, allow_example=True)

    def test_live_configuration_rejects_test_only_signer(self) -> None:
        value = copy.deepcopy(self.example)
        value["environment"] = "sepolia_pilot"
        value["deployer_address"] = "0x4567890123456789012345678901234567890123"
        value["governance_safe"] = "0x1234567890123456789012345678901234567890"
        value["emergency_safe"] = value["governance_safe"]
        value["treasury"] = "0x2345678901234567890123456789012345678901"
        value["attestor"] = "0x3456789012345678901234567890123456789012"
        value["attestor_key_id"] = "sepolia-approved-key-v1"
        value["attestor_signer_program"] = "/usr/bin/python3"
        value["attestor_signer_args"] = [
            str((ROOT / "scripts" / "mock_mpc_attestation_signer.py").resolve())
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(Path(temporary), value)
            with self.assertRaisesRegex(pilot.PilotError, "mock signer is prohibited"):
                pilot.PilotConfig.load(path)

    def test_release_profile_rejects_early_stark_activation(self) -> None:
        gates = {name: False for name in pilot.RELEASE_GATES}
        profile = {
            "schema_version": pilot.RELEASE_SCHEMA,
            "chain_id": pilot.SEPOLIA_CHAIN_ID,
            "production_usable": True,
            "current_backend": "stark_attested",
            "candidate_backend": "stark_attested",
            "automatic_fallback": False,
            "rollback_mode": "manual_governed",
            "native_verifier_active": False,
            "activation_gates": gates,
        }
        with self.assertRaisesRegex(pilot.PilotError, "requires every gate"):
            pilot.validate_live_release_profile(profile)

        profile["activation_gates"] = {name: True for name in pilot.RELEASE_GATES}
        pilot.validate_live_release_profile(profile)

        del profile["activation_gates"]["pause_recovery_rehearsed"]
        with self.assertRaisesRegex(pilot.PilotError, "gates are incomplete"):
            pilot.validate_live_release_profile(profile)

    def test_deployment_pin_rejects_incomplete_source_commit(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        pin = json.loads(
            (ROOT / "ops" / "stark_v2_deployment_pin.example.json").read_text(encoding="utf-8")
        )
        with self.assertRaisesRegex(pilot.PilotError, "source_commit"):
            pilot.validate_deployment_pin(pin, config)

    def test_approved_canary_requires_denied_canary_first(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        state = {
            "completed_actions": {
                "authorize": {"evidence": {}},
                "signer-health": {"evidence": {}},
            }
        }
        with self.assertRaisesRegex(pilot.PilotError, "canary-denied"):
            pilot.run_canary(config, state, "approved")

    def test_generated_release_profile_stays_on_groth16(self) -> None:
        base = pilot.PilotConfig.load(self.example_path, allow_example=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "scripts" / "tests") as temporary:
            output = Path(temporary) / "release.json"
            config = replace(base, release_profile_path=output)
            completed = {
                name: {"evidence": {}}
                for name in (
                    "local-gates",
                    "deploy",
                    "authorize",
                    "signer-health",
                    "canary-approved",
                    "canary-denied",
                    "reconcile",
                    "pause",
                    "unpause",
                )
            }
            profile = pilot.release_profile(config, {"completed_actions": completed})
            self.assertEqual(profile["current_backend"], "groth16")
            self.assertFalse(profile["production_usable"])
            self.assertFalse(profile["activation_gates"]["legal_approval_recorded"])
            self.assertFalse(profile["activation_gates"]["independent_audits_complete"])

    def test_state_updates_are_atomic_and_idempotent_by_action_name(self) -> None:
        base = pilot.PilotConfig.load(self.example_path, allow_example=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "scripts" / "tests") as temporary:
            config = replace(base, artifact_directory=Path(temporary))
            state = {
                "schema_version": pilot.STATE_SCHEMA,
                "chain_id": pilot.SEPOLIA_CHAIN_ID,
                "completed_actions": {},
                "blocked_reasons": ["old failure"],
            }
            pilot.record_action(config, state, "preflight", {"status": "ready"})
            pilot.record_action(config, state, "preflight", {"status": "ready"})
            stored = pilot.load_json(config.state_path)
            self.assertEqual(list(stored["completed_actions"]), ["preflight"])
            self.assertEqual(stored["blocked_reasons"], [])

    def test_final_reconciliation_reuses_denied_evidence_and_reruns_only_approved(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scripts" / "tests") as temporary:
            directory = Path(temporary)
            denied_report = directory / "denied_report.json"
            approved_report = directory / "approved_report.json"
            for path in (denied_report, approved_report):
                path.write_text(
                    json.dumps({"status": "finalized_chain_and_local_state_reconciled"}),
                    encoding="utf-8",
                )
            state_directory = directory / "state"
            state_directory.mkdir()
            (state_directory / "nullifier_state.json").write_text(
                json.dumps({"root_bytes32": "0x" + "33" * 32}), encoding="utf-8"
            )
            denied = {
                "receipt": "denied-receipt.json",
                "journal": "denied-journal.json",
                "nullifier_root_before": "0x" + "11" * 32,
                "nullifier_root_after": "0x" + "11" * 32,
                "reconciliation": {
                    "report": str(denied_report.relative_to(ROOT)),
                    "idempotent": True,
                },
            }
            approved = {
                "receipt": "approved-receipt.json",
                "journal": "approved-journal.json",
                "nullifier_root_before": "0x" + "11" * 32,
                "nullifier_root_after": "0x" + "33" * 32,
                "reconciliation": {
                    "report": str(approved_report.relative_to(ROOT)),
                    "idempotent": True,
                },
            }
            state = {
                "completed_actions": {
                    "canary-denied": {"evidence": denied},
                    "canary-approved": {"evidence": approved},
                }
            }
            config = SimpleNamespace(
                rpc_url="https://example.invalid",
                state_directory=state_directory,
                artifact_directory=directory,
            )
            final = {"report": "approved-final.json", "idempotent": True}
            with (
                patch.object(
                    pilot,
                    "deployed_contracts",
                    return_value={"starkClaimsRegistryV2": "0x" + "44" * 20},
                ),
                patch.object(pilot, "reconcile_canary", return_value=final) as reconcile,
                patch.object(pilot, "cast", return_value="0x" + "33" * 32),
            ):
                summary = pilot.reconcile_canaries(config, state)

            self.assertEqual(summary["status"], "clean")
            self.assertTrue(summary["roots_match"])
            reconcile.assert_called_once()
            self.assertEqual(reconcile.call_args.kwargs["kind"], "approved-final")


if __name__ == "__main__":
    unittest.main()
