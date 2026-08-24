from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.proving_policy_fixtures import trusted_policy, valid_policy_value
from tools import proving_evidence_policy as evidence_policy
from tools import proving_job_runner
from tools import run_verified_bootloader_proof
from tools.proving_resource_policy import derive_policy, policy_file_bytes


class ProvingEvidencePolicyAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".test-proving-evidence-attacks-",
            dir=evidence_policy.ROOT.parent,
        )
        self.root = Path(self._temporary.name)
        self.policy_path = self.root / "policy.json"
        self.registry_path = self.root / "registry.json"
        self.now = datetime(2026, 7, 18, tzinfo=timezone.utc)
        self._legacy_environment = {
            name: os.environ.pop(name, None)
            for name in evidence_policy.LEGACY_TOOL_ENVIRONMENT
        }

    def tearDown(self) -> None:
        for name, value in self._legacy_environment.items():
            if value is not None:
                os.environ[name] = value
        self._temporary.cleanup()

    @staticmethod
    def _write_canonical(path: Path, value: object) -> bytes:
        raw = evidence_policy.canonical_json_bytes(value) + b"\n"
        path.write_bytes(raw)
        return raw

    def _activate(self, policy_raw: bytes, **registry_changes: object) -> None:
        registry: dict[str, object] = {
            "schema_version": evidence_policy.REGISTRY_SCHEMA,
            "activation_state": "ENABLED",
            "active_policy_sha3_512": evidence_policy.sha3_512_bytes(policy_raw),
            "production_usable": False,
        }
        registry.update(registry_changes)
        self._write_canonical(self.registry_path, registry)

    def _load(self) -> evidence_policy.ProvingEvidencePolicy:
        with mock.patch.object(evidence_policy, "REGISTRY_PATH", self.registry_path):
            return evidence_policy.load_approved_policy(self.policy_path, now=self.now)

    def test_disabled_registry_rejects_arbitrary_policy_and_digest(self) -> None:
        self._write_canonical(self.policy_path, valid_policy_value())
        with self.assertRaisesRegex(RuntimeError, "no independently provisioned"):
            evidence_policy.load_approved_policy(self.policy_path, now=self.now)

    def test_missing_policy_is_rejected(self) -> None:
        self._activate(b"missing-policy")
        with self.assertRaisesRegex(RuntimeError, "policy is missing"):
            self._load()

    def test_unapproved_or_altered_policy_digest_is_rejected(self) -> None:
        raw = self._write_canonical(self.policy_path, valid_policy_value())
        self._activate(raw)
        self._write_canonical(self.policy_path, {"altered": True})
        with self.assertRaisesRegex(RuntimeError, "altered or unapproved"):
            self._load()

    def test_duplicate_policy_keys_are_rejected(self) -> None:
        raw = b'{"schema_version":"first","schema_version":"second"}\n'
        self.policy_path.write_bytes(raw)
        self._activate(raw)
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON key"):
            self._load()

    def test_noncanonical_policy_is_rejected_as_ambiguous(self) -> None:
        raw = json.dumps(valid_policy_value(), indent=2).encode("utf-8") + b"\n"
        self.policy_path.write_bytes(raw)
        self._activate(raw)
        with self.assertRaisesRegex(RuntimeError, "not canonical JSON"):
            self._load()

    def test_registry_cannot_activate_multiple_or_extra_candidates(self) -> None:
        raw = self._write_canonical(self.policy_path, valid_policy_value())
        self._activate(raw, approved_policy_sha3_512=[evidence_policy.sha3_512_bytes(raw)])
        with self.assertRaisesRegex(RuntimeError, "registry keys are invalid"):
            self._load()

    def test_stale_policy_is_rejected(self) -> None:
        value = valid_policy_value()
        value["validity"]["not_after"] = "2026-07-18T00:00:00Z"  # type: ignore[index]
        raw = self._write_canonical(self.policy_path, value)
        self._activate(raw)
        with self.assertRaisesRegex(RuntimeError, "stale or not yet valid"):
            self._load()

    def test_revoked_or_scope_elevated_policy_is_rejected(self) -> None:
        revoked = valid_policy_value()
        revoked["validity"]["revoked"] = True  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "revoked"):
            evidence_policy._validate_policy_value(revoked, now=self.now)

        elevated = valid_policy_value()
        elevated["scope"]["production_usable"] = True  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "non-production"):
            evidence_policy._validate_policy_value(elevated, now=self.now)

    def test_prover_cannot_be_its_own_verifier(self) -> None:
        value = valid_policy_value()
        value["tools"]["verifier"] = deepcopy(value["tools"]["prover"])  # type: ignore[index]
        value["proof_system"]["verifier_artifact_id"] = "e" * 128  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "independently provisioned"):
            evidence_policy._validate_policy_value(value, now=self.now)

    def test_altered_parameters_or_artifact_identity_is_rejected(self) -> None:
        parameters = valid_policy_value()
        parameters["proof_system"]["parameters"]["security_level_bits"] = 1  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "parameters and parameter identity"):
            evidence_policy._validate_policy_value(parameters, now=self.now)

        artifact = valid_policy_value()
        artifact["build"]["artifact_id"] = "7" * 128  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "build artifact identity"):
            evidence_policy._validate_policy_value(artifact, now=self.now)

    def test_legacy_cli_environment_tool_override_is_rejected(self) -> None:
        raw = self._write_canonical(self.policy_path, valid_policy_value())
        self._activate(raw)
        with mock.patch.dict(os.environ, {"BL_SCARB_BIN_WSL": "/tmp/attacker-scarb"}):
            with self.assertRaisesRegex(RuntimeError, "tool overrides are forbidden"):
                self._load()

    def test_changed_tool_digest_is_rejected_by_attestation(self) -> None:
        policy = trusted_policy(self.policy_path)

        def local_hash(path: Path) -> str:
            return "b" * 128 if path.name == "Scarb.toml" else "c" * 128

        def wsl_hash(path: str, *, executable: bool) -> str:
            del executable
            if path.endswith("/prover"):
                return "9" * 128
            for name, record in policy.value["tools"].items():
                if record["wsl_path"] == path:
                    return record["sha3_512"]
            self.fail(f"unexpected WSL path: {path}")

        with mock.patch.object(
            evidence_policy, "source_manifest_sha3_512", return_value="a" * 128
        ), mock.patch.object(evidence_policy, "sha3_512_file", side_effect=local_hash), mock.patch.object(
            evidence_policy, "wsl_file_sha3_512", side_effect=wsl_hash
        ):
            with self.assertRaisesRegex(RuntimeError, "pinned prover digest"):
                evidence_policy.attest_policy(
                    policy, source_root=evidence_policy.ROOT / "zk-cairo-sharp"
                )

    def test_changed_source_digest_is_rejected_before_tool_execution(self) -> None:
        policy = trusted_policy(self.policy_path)
        with mock.patch.object(
            evidence_policy, "source_manifest_sha3_512", return_value="9" * 128
        ), mock.patch.object(evidence_policy, "wsl_file_sha3_512") as wsl_hash:
            with self.assertRaisesRegex(RuntimeError, "source manifest is altered"):
                evidence_policy.attest_policy(
                    policy, source_root=evidence_policy.ROOT / "zk-cairo-sharp"
                )
        wsl_hash.assert_not_called()

    def test_job_runner_does_not_launch_without_independent_policy(self) -> None:
        attempt = self.root / "attempt-no-policy"
        status_path = self.root / "status.json"
        resource_policy = derive_policy({"BL_PROVER_THREADS": "1"})
        (self.root / "resource_policy.json").write_bytes(policy_file_bytes(resource_policy))
        request = {
            "input_kind": "synthetic",
            "claim_count": 1,
            "resource_policy": resource_policy.as_json(),
            "resource_policy_sha256": resource_policy.digest,
        }
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            proving_job_runner, "run_contained_process"
        ) as launch:
            succeeded, transient, result = proving_job_runner._run_attempt(
                request,
                attempt,
                status_path,
                {},
                self.root / "queue",
            )
        self.assertFalse(succeeded)
        self.assertFalse(transient)
        self.assertEqual("trusted_evidence_policy", result["failure_class"])
        launch.assert_not_called()

    def test_child_manifest_cannot_replace_trusted_provenance(self) -> None:
        attempt = self.root / "attempt"
        attempt.mkdir()
        proof_path = attempt / "proof.json"
        proof_path.write_bytes(b"false-proof")
        policy = trusted_policy(self.policy_path)
        provenance = evidence_policy.trusted_manifest_bindings(policy)
        forged = deepcopy(provenance)
        forged["proof_suite_id"] = "8" * 128
        manifest = {
            "status": "independently_verified",
            "evidence_scope": evidence_policy.POLICY_PURPOSE,
            "evidence_policy": {
                "storage_key": "trusted-evidence-policy",
                "registry_sha3_512": policy.registry_sha3_512,
                "sha3_512": policy.sha3_512,
            },
            "trusted_provenance": forged,
            "semantic_output_match": True,
            "independent_verifier": True,
            "verification_interface": evidence_policy.VERIFIER_INTERFACE,
            "verification_success_marker": True,
            "production_verifier_claimed": False,
            "settlement_contract_verification_run": False,
            "protected_source_manifest_sha3_512_before": provenance[
                "source_manifest_sha3_512"
            ],
            "protected_source_manifest_sha3_512_after": provenance[
                "source_manifest_sha3_512"
            ],
            "proof": {
                "path": "proof.json",
                "bytes": proof_path.stat().st_size,
                "sha256": proving_job_runner._sha256_file(proof_path),
                "sha3_512": evidence_policy.sha3_512_file(proof_path),
            },
        }
        proving_job_runner._write_json_atomic(attempt / "run_manifest.json", manifest)
        with self.assertRaisesRegex(RuntimeError, "queue_manifest_provenance"):
            proving_job_runner._validate_success_manifest(attempt, policy)

    def test_release_runner_has_distinct_prove_and_verify_commands(self) -> None:
        source = inspect.getsource(run_verified_bootloader_proof.main)
        self.assertIn("prove_command =", source)
        self.assertIn("verify_command =", source)
        self.assertNotIn('"--verify"', source)
        self.assertNotIn('"--scarb-bin-wsl"', source)


if __name__ == "__main__":
    unittest.main()
