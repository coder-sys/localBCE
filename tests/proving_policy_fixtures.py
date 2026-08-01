from __future__ import annotations

from pathlib import Path

from tools import proving_evidence_policy as evidence_policy


def valid_policy_value() -> dict[str, object]:
    parameters: dict[str, object] = {
        "channel_hash": "sha3_512_candidate",
        "security_level_bits": 256,
    }
    parameters_digest = evidence_policy.sha3_512_bytes(
        evidence_policy.canonical_json_bytes(parameters)
    )
    return {
        "schema_version": evidence_policy.POLICY_SCHEMA,
        "status": evidence_policy.POLICY_STATUS,
        "validity": {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "revoked": False,
        },
        "scope": {
            "purpose": evidence_policy.POLICY_PURPOSE,
            "production_usable": False,
            "settlement_usable": False,
        },
        "source": {
            "root": "zk-cairo-sharp",
            "manifest_sha3_512": "a" * 128,
            "scarb_toml_sha3_512": "b" * 128,
            "scarb_lock_sha3_512": "c" * 128,
            "artifact_id": "a" * 128,
        },
        "tools": {
            "scarb": {"wsl_path": "/opt/blind-ledger/scarb", "sha3_512": "d" * 128},
            "prover": {"wsl_path": "/opt/blind-ledger/prover", "sha3_512": "e" * 128},
            "verifier": {"wsl_path": "/opt/blind-ledger/verifier", "sha3_512": "f" * 128},
            "bootloader_program": {
                "wsl_path": "/opt/blind-ledger/simple_bootloader.json",
                "sha3_512": "1" * 128,
            },
        },
        "proof_system": {
            "proof_suite_id": "2" * 128,
            "public_input_schema_id": "3" * 128,
            "parameter_set_id": parameters_digest,
            "parameters": parameters,
            "parameters_sha3_512": parameters_digest,
            "program_hash_function": "sha3_512_candidate",
            "prover_artifact_id": "e" * 128,
            "verifier_artifact_id": "f" * 128,
        },
        "build": {
            "mode": "SCARB_OFFLINE_PINNED_INPUTS",
            "profile": "dev",
            "executable_relative_path": "target/dev/batch_main.executable.json",
            "executable_sha3_512": "4" * 128,
            "artifact_id": "4" * 128,
        },
        "verification": {
            "interface": evidence_policy.VERIFIER_INTERFACE,
            "success_marker": "BL_INDEPENDENT_VERIFICATION_OK",
        },
    }


def trusted_policy(path: Path) -> evidence_policy.ProvingEvidencePolicy:
    return evidence_policy.ProvingEvidencePolicy(
        path=path.resolve(),
        sha3_512="5" * 128,
        registry_sha3_512="6" * 128,
        value=valid_policy_value(),
    )
