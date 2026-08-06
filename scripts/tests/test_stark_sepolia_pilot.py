#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import os
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

    def test_configuration_rejects_wrong_chain_and_live_placeholders(self) -> None:
        value = copy.deepcopy(self.example)
        value["chain_id"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(Path(temporary), value)
            with self.assertRaisesRegex(pilot.PilotError, "Sepolia chain ID"):
                pilot.PilotConfig.load(path, allow_example=True)

        value = copy.deepcopy(self.example)
        value["environment"] = "sepolia_pilot"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(Path(temporary), value)
            with self.assertRaisesRegex(pilot.PilotError, "placeholder address"):
                pilot.PilotConfig.load(path)

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

    def test_deployment_pin_rejects_policy_hash_mismatch(self) -> None:
        base = pilot.PilotConfig.load(self.example_path, allow_example=True)
        governance = "0x1234567890123456789012345678901234567890"
        treasury = "0x2345678901234567890123456789012345678901"
        attestor = "0x3456789012345678901234567890123456789012"
        config = replace(
            base,
            governance_safe=governance,
            treasury=treasury,
            attestor=attestor,
        )
        pin = json.loads(
            (ROOT / "ops" / "stark_v2_deployment_pin.example.json").read_text(encoding="utf-8")
        )
        pin.update(
            {
                "source_commit": "a" * 40,
                "governance_safe": governance,
                "emergency_safe": governance,
                "treasury": treasury,
                "attestor": attestor,
                "timelock": "0x4567890123456789012345678901234567890123",
                "verifier": "0x5678901234567890123456789012345678901234",
                "registry": "0x6789012345678901234567890123456789012345",
                "policy_manifest_hash": "0x" + "ff" * 32,
            }
        )
        with (
            patch.object(pilot, "git", return_value="a" * 40),
            self.assertRaisesRegex(pilot.PilotError, "policy hash"),
        ):
            pilot.validate_deployment_pin(pin, config)

    def test_preflight_rejects_missing_finalized_block_support(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        environment = {
            config.value["rpc_url_env"]: "https://rpc.example.invalid",
            config.value["deployer_private_key_env"]: "not-persisted",
            config.value["submitter_private_key_env"]: "not-persisted",
            config.value["verification_api_key_env"]: "not-persisted",
        }
        with (
            patch.dict(os.environ, environment, clear=False),
            patch.object(pilot.shutil, "which", return_value="/usr/bin/tool"),
            patch.object(pilot, "clean_pushed_source_commit", return_value="a" * 40),
            patch.object(pilot, "cast", return_value=str(pilot.SEPOLIA_CHAIN_ID)),
            patch.object(pilot, "command", return_value=SimpleNamespace(stdout="null")),
            self.assertRaisesRegex(pilot.PilotError, "finalized block tag"),
        ):
            pilot.preflight(config)

    def test_safe_action_ordering_is_fail_closed(self) -> None:
        empty = {"completed_actions": {}}
        with self.assertRaisesRegex(pilot.PilotError, "reconcile"):
            pilot.require_safe_action_prerequisites(empty, "pause", "execute")
        with self.assertRaisesRegex(pilot.PilotError, "prepare-authorize-schedule"):
            pilot.require_safe_action_prerequisites(empty, "authorize", "execute")

        state = {
            "completed_actions": {
                "reconcile": {"evidence": {}},
                "pause": {"evidence": {}},
                "prepare-unpause-schedule": {"evidence": {}},
                "prepare-unpause-execute": {"evidence": {}},
            }
        }
        pilot.require_safe_action_prerequisites(state, "pause", "execute")
        pilot.require_safe_action_prerequisites(state, "unpause", "execute")
        pilot.require_governance_verification_prerequisites(state, "unpause")

    def test_safe_bundle_is_deterministic_and_tamper_evident(self) -> None:
        base = pilot.PilotConfig.load(self.example_path, allow_example=True)
        deployment = {
            "timelock": "0x4567890123456789012345678901234567890123",
            "starkAttestationVerifierV2": "0x5678901234567890123456789012345678901234",
            "starkClaimsRegistryV2": "0x6789012345678901234567890123456789012345",
        }
        with tempfile.TemporaryDirectory(dir=ROOT / "scripts" / "tests") as temporary:
            config = replace(base, artifact_directory=Path(temporary))
            with (
                patch.object(pilot, "deployed_contracts", return_value=deployment),
                patch.object(pilot, "encode_calldata", return_value="0x1234"),
            ):
                first = pilot.safe_bundle(config, "authorize", "schedule")
                second = pilot.safe_bundle(config, "authorize", "schedule")
            self.assertEqual(first, second)
            bundle = pilot.validate_recorded_safe_bundle(config, first)
            self.assertTrue(bundle["human_approval_required"])
            self.assertFalse(bundle["automatic_submission"])
            self.assertEqual(bundle["timelock_operations"][0]["minimum_delay_seconds"], 259_200)

            path = ROOT / first["bundle"]
            bundle["automatic_submission"] = True
            pilot.write_json_atomic(path, bundle)
            with self.assertRaisesRegex(pilot.PilotError, "missing or changed"):
                pilot.validate_recorded_safe_bundle(config, first)

    def test_signer_health_report_binds_backend_key_and_attestor(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        report = {
            "schema_version": "stark-external-attestation-signer-health-v1",
            "status": "ok",
            "chain_id": pilot.SEPOLIA_CHAIN_ID,
            "request_id": "0x" + "ab" * 32,
            "signer_backend": "external_command",
            "key_id": config.signer_key_id,
            "attestor_address": config.attestor,
            "signature_validated": True,
            "low_s_validated": True,
            "recovery_validated": True,
        }
        pilot.validate_signer_health_report(config, report)
        for field, invalid in (
            ("signer_backend", "local_private_key"),
            ("key_id", "unapproved-key"),
            ("attestor_address", "0x4567890123456789012345678901234567890123"),
            ("low_s_validated", False),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(report)
                changed[field] = invalid
                with self.assertRaises(pilot.PilotError):
                    pilot.validate_signer_health_report(config, changed)

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

    def test_canary_outputs_enforce_controlled_attestation_boundary(self) -> None:
        config = pilot.PilotConfig.load(self.example_path, allow_example=True)
        deployment = {
            "starkAttestationVerifierV2": "0x5678901234567890123456789012345678901234",
            "starkClaimsRegistryV2": "0x6789012345678901234567890123456789012345",
        }
        before = "0x" + "11" * 32
        after = "0x" + "22" * 32
        receipt = {
            "schema_version": "stark-production-settlement-receipt-v2",
            "decision": 1,
            "finality_mode": "finalized",
            "finalized_on_chain": True,
            "groth16_executed": False,
            "proof_locally_verified": True,
            "attestation_locally_validated": True,
            "controlled_attestation_verification": True,
            "native_on_chain_stark_verification": False,
            "signer_backend": "external_command",
            "signer_key_id": config.signer_key_id,
            "policy_manifest_hash": config.policy_manifest_hash,
            "verifier_address": deployment["starkAttestationVerifierV2"],
            "registry_address": deployment["starkClaimsRegistryV2"],
            "nullifier_root_before": before,
            "nullifier_root_after": after,
        }
        pilot.validate_canary_outputs(
            config,
            deployment,
            kind="approved",
            receipt=receipt,
            adjudication={"status": "APPROVED", "tx_submitted": True},
            denied_evidence={"nullifier_root_after": before},
        )
        for field, invalid, message in (
            ("groth16_executed", True, "STARK-only"),
            ("native_on_chain_stark_verification", True, "trust boundary"),
            ("policy_manifest_hash", "0x" + "ff" * 32, "policy hash"),
            ("signer_backend", "local_private_key", "external signer"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(receipt)
                changed[field] = invalid
                with self.assertRaisesRegex(pilot.PilotError, message):
                    pilot.validate_canary_outputs(
                        config,
                        deployment,
                        kind="approved",
                        receipt=changed,
                        adjudication={"status": "APPROVED", "tx_submitted": True},
                        denied_evidence={"nullifier_root_after": before},
                    )

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

    def test_audit_package_is_trust_explicit_and_rejects_secret_material(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scripts" / "tests") as temporary:
            directory = Path(temporary)
            files = {
                name: directory / name
                for name in ("policy.json", "pin.json", "release.json", "deployment.json")
            }
            for path in files.values():
                path.write_text("{}\n", encoding="utf-8")
            local_report = directory / "local_gate_report.json"
            local_report.write_text("{}\n", encoding="utf-8")
            config = SimpleNamespace(
                policy_manifest_path=files["policy.json"],
                deployment_pin_path=files["pin.json"],
                release_profile_path=files["release.json"],
                deployment_path=files["deployment.json"],
                artifact_directory=directory,
                value={
                    "rpc_url_env": "PILOT_RPC_SECRET",
                    "deployer_private_key_env": "PILOT_DEPLOYER_SECRET",
                    "submitter_private_key_env": "PILOT_SUBMITTER_SECRET",
                    "verification_api_key_env": "PILOT_VERIFY_SECRET",
                },
            )
            completed = {
                name: {"evidence": {}}
                for name in (
                    "local-gates",
                    "deploy",
                    "authorize",
                    "signer-health",
                    "canary-denied",
                    "canary-approved",
                    "reconcile",
                    "pause",
                    "unpause",
                )
            }
            with patch.object(pilot, "git", return_value="a" * 40):
                result = pilot.audit_package(config, {"completed_actions": completed})
            manifest = pilot.load_json(ROOT / result["manifest"])
            self.assertFalse(manifest["trust_boundary"]["native_on_chain_winterfell"])
            self.assertFalse(manifest["trust_boundary"]["production_approved"])

            local_report.write_text("super-secret-value\n", encoding="utf-8")
            with (
                patch.dict(os.environ, {"PILOT_RPC_SECRET": "super-secret-value"}),
                patch.object(pilot, "git", return_value="a" * 40),
                self.assertRaisesRegex(pilot.PilotError, "secret material"),
            ):
                pilot.audit_package(config, {"completed_actions": completed})


if __name__ == "__main__":
    unittest.main()
