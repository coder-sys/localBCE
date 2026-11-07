#!/usr/bin/env python3
"""Generate a fail-closed governed STARK pilot chain/local reconciliation report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def cast(rpc: str, *args: str) -> str:
    result = subprocess.run(
        ["cast", *args, "--rpc-url", rpc], text=True, capture_output=True, timeout=30, check=False
    )
    if result.returncode:
        raise ValueError(f"cast {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def address(deployment: dict[str, Any], name: str) -> str:
    value = deployment.get(name)
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"deployment is missing {name}")
    return value


def integer(value: Any, label: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{label} is not an integer") from exc
    raise ValueError(f"{label} is not an integer")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--deployment-pin", type=Path, required=True)
    parser.add_argument("--release-profile", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        deployment, pin, profile, journal, receipt, state = map(
            load,
            (
                args.deployment,
                args.deployment_pin,
                args.release_profile,
                args.journal,
                args.receipt,
                args.state,
            ),
        )
        registry = address(deployment, "starkClaimsRegistryV2")
        verifier = address(deployment, "starkAttestationVerifierV2")
        timelock = address(deployment, "timelock")
        governance_safe = address(deployment, "governanceSafe")
        chain_id = int(cast(args.rpc_url, "chain-id"))
        chain_root = cast(args.rpc_url, "call", registry, "currentNullifierRoot()(bytes32)").lower()
        rejected_proofs = int(cast(args.rpc_url, "call", registry, "rejectedProofs()(uint256)"))
        registry_paused = cast(args.rpc_url, "call", registry, "paused()(bool)") == "true"
        verifier_paused = cast(args.rpc_url, "call", verifier, "paused()(bool)") == "true"
        chain_policy_hash = cast(args.rpc_url, "call", verifier, "policyManifestHash()(bytes32)").lower()
        chain_attestor = cast(args.rpc_url, "call", verifier, "attestor()(address)").lower()
        chain_treasury = cast(args.rpc_url, "call", registry, "treasury()(address)").lower()
        registry_authorized = cast(
            args.rpc_url,
            "call",
            verifier,
            "authorizedRegistries(address)(bool)",
            registry,
        ) == "true"
        timelock_delay = int(cast(args.rpc_url, "call", timelock, "getMinDelay()(uint256)"))
        safe_threshold = int(cast(args.rpc_url, "call", governance_safe, "getThreshold()(uint256)"))
        safe_owners_output = cast(args.rpc_url, "call", governance_safe, "getOwners()(address[])")
        safe_owners = sorted(set(re.findall(r"0x[0-9a-fA-F]{40}", safe_owners_output.lower())))
        finalized_block = json.loads(cast(args.rpc_url, "block", "finalized", "--json"))
        finalized_block_number = integer(finalized_block["number"], "finalized block number")
        finalized_block_hash = str(finalized_block["hash"]).lower()
        transaction_block_number = integer(
            journal.get("transaction_block_number"), "journal transaction block number"
        )
        transaction_finalized = transaction_block_number <= finalized_block_number
        local_root = str(state.get("root_bytes32", "")).lower()
        unfinalized = journal.get("status") not in {"finalized", "local_state_committed"}
        placeholder_pins = sorted(
            key for key, value in pin.items()
            if isinstance(value, str) and (value.startswith("REPLACE_") or value == "0x" + "00" * 32)
        )
        policy_matches = chain_policy_hash == str(receipt.get("policy_manifest_hash", "")).lower()
        root_matches = chain_root == local_root == str(receipt.get("nullifier_root_after", "")).lower()
        receipt_matches_journal = all(
            (
                str(receipt.get("transaction_hash", "")).lower()
                == str(journal.get("transaction_hash", "")).lower(),
                receipt.get("transaction_block_number") == journal.get("transaction_block_number"),
                str(receipt.get("transaction_block_hash", "")).lower()
                == str(journal.get("transaction_block_hash", "")).lower(),
                str(receipt.get("claim_hash", "")).lower()
                == str(journal.get("claim_hash", "")).lower(),
                str(receipt.get("batch_root", "")).lower()
                == str(journal.get("batch_root", "")).lower(),
            )
        )
        claim_output = cast(
            args.rpc_url,
            "call",
            registry,
            "claims(bytes32)(bool,bool,uint256,uint256,uint256,uint32,bytes32,bytes32,bytes32)",
            str(receipt.get("claim_hash", "")),
        )
        claim_recorded = claim_output.splitlines()[0].strip() == "true"
        batch_consumed = cast(
            args.rpc_url,
            "call",
            registry,
            "consumedBatchRoots(bytes32)(bool)",
            str(receipt.get("batch_root", "")),
        ) == "true"
        controlled_attestation = all(
            (
                receipt.get("proof_locally_verified") is True,
                receipt.get("attestation_locally_validated") is True,
                receipt.get("controlled_attestation_verification") is True,
                receipt.get("native_on_chain_stark_verification") is False,
                receipt.get("groth16_executed") is False,
                receipt.get("signer_backend") == "external_command",
                isinstance(receipt.get("signer_key_id"), str),
                bool(receipt.get("signer_key_id")),
            )
        )
        deployment_roles_match = all(
            (
                governance_safe.lower() == address(deployment, "emergencySafe").lower(),
                chain_treasury == str(pin.get("treasury", "")).lower(),
                chain_attestor == str(pin.get("attestor", "")).lower(),
                chain_policy_hash == str(pin.get("policy_manifest_hash", "")).lower(),
                chain_id == pin.get("chain_id"),
            )
        )
        gates = profile.get("activation_gates", {})
        release_ready = (
            profile.get("production_usable") is True
            and profile.get("current_backend") == "stark_attested"
            and isinstance(gates, dict)
            and bool(gates)
            and all(gates.values())
        )
        technical_clean = all(
            (
                chain_id == 11155111,
                root_matches,
                policy_matches,
                not unfinalized,
                transaction_finalized,
                receipt_matches_journal,
                claim_recorded,
                batch_consumed,
                controlled_attestation,
                deployment_roles_match,
                not registry_paused,
                not verifier_paused,
                not placeholder_pins,
                registry_authorized,
                timelock_delay == 259200,
                safe_threshold == 2,
                len(safe_owners) == 3,
            )
        )
        report = {
            "schema_version": "localbce-stark-pilot-reconciliation-report-v1",
            "status": "clean" if technical_clean else "blocked",
            "release_ready": release_ready,
            "chain_id": chain_id,
            "registry": registry,
            "verifier": verifier,
            "timelock": timelock,
            "governance_safe": governance_safe,
            "emergency_safe": address(deployment, "emergencySafe"),
            "treasury": chain_treasury,
            "safe_threshold": safe_threshold,
            "safe_owner_count": len(safe_owners),
            "safe_owners": safe_owners,
            "timelock_delay_seconds": timelock_delay,
            "registry_authorized": registry_authorized,
            "chain_nullifier_root": chain_root,
            "local_nullifier_root": local_root,
            "roots_match": root_matches,
            "unfinalized_transaction": unfinalized,
            "journal_status": journal.get("status"),
            "transaction_hash": journal.get("transaction_hash"),
            "transaction_block_number": transaction_block_number,
            "transaction_block_hash": journal.get("transaction_block_hash"),
            "finalized_block_number": finalized_block_number,
            "finalized_block_hash": finalized_block_hash,
            "transaction_finalized": transaction_finalized,
            "receipt_matches_journal": receipt_matches_journal,
            "claim_recorded_on_chain": claim_recorded,
            "batch_consumed_on_chain": batch_consumed,
            "rejected_proofs": rejected_proofs,
            "registry_paused": registry_paused,
            "verifier_paused": verifier_paused,
            "signer_key_id": receipt.get("signer_key_id"),
            "signer_backend": receipt.get("signer_backend"),
            "controlled_attestation_validated": controlled_attestation,
            "attestor": chain_attestor,
            "policy_manifest_hash": chain_policy_hash,
            "policy_matches_receipt": policy_matches,
            "deployment_pin_schema": pin.get("schema_version"),
            "deployment_pin_sha256": hashlib.sha256(args.deployment_pin.read_bytes()).hexdigest(),
            "deployment_transactions": pin.get("deployment_transactions", []),
            "deployment_roles_match": deployment_roles_match,
            "placeholder_deployment_pins": placeholder_pins,
            "release_profile_schema": profile.get("schema_version"),
            "current_backend": profile.get("current_backend"),
            "candidate_backend": profile.get("candidate_backend"),
            "activation_gates": gates,
            "open_activation_gates": sorted(name for name, value in gates.items() if value is not True),
            "automatic_fallback": profile.get("automatic_fallback"),
            "native_on_chain_winterfell": False,
            "controlled_attestation_limitation": (
                "Winterfell proves the constrained computation; this report does not establish the legal validity "
                "or source authenticity of claim and oracle inputs."
            ),
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "release_ready": report["release_ready"],
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
