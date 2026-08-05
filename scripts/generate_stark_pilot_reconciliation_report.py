#!/usr/bin/env python3
"""Generate a fail-closed governed STARK pilot chain/local reconciliation report."""

from __future__ import annotations

import argparse
import json
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--deployment-pin", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        deployment, pin, journal, receipt, state = map(
            load, (args.deployment, args.deployment_pin, args.journal, args.receipt, args.state)
        )
        registry = address(deployment, "starkClaimsRegistryV2")
        verifier = address(deployment, "starkAttestationVerifierV2")
        chain_id = int(cast(args.rpc_url, "chain-id"))
        chain_root = cast(args.rpc_url, "call", registry, "currentNullifierRoot()(bytes32)").lower()
        rejected_proofs = int(cast(args.rpc_url, "call", registry, "rejectedProofs()(uint256)"))
        registry_paused = cast(args.rpc_url, "call", registry, "paused()(bool)") == "true"
        verifier_paused = cast(args.rpc_url, "call", verifier, "paused()(bool)") == "true"
        chain_policy_hash = cast(args.rpc_url, "call", verifier, "policyManifestHash()(bytes32)").lower()
        chain_attestor = cast(args.rpc_url, "call", verifier, "attestor()(address)").lower()
        local_root = str(state.get("root_bytes32", "")).lower()
        unfinalized = journal.get("status") not in {"finalized", "local_state_committed"}
        placeholder_pins = sorted(
            key for key, value in pin.items()
            if isinstance(value, str) and (value.startswith("REPLACE_") or value == "0x" + "00" * 32)
        )
        policy_matches = chain_policy_hash == str(receipt.get("policy_manifest_hash", "")).lower()
        root_matches = chain_root == local_root == str(receipt.get("nullifier_root_after", "")).lower()
        report = {
            "schema_version": "localbce-stark-pilot-reconciliation-report-v1",
            "status": "ready" if all((chain_id == 11155111, root_matches, policy_matches, not unfinalized,
                                       not registry_paused, not verifier_paused, not placeholder_pins)) else "blocked",
            "chain_id": chain_id,
            "registry": registry,
            "verifier": verifier,
            "chain_nullifier_root": chain_root,
            "local_nullifier_root": local_root,
            "roots_match": root_matches,
            "unfinalized_transaction": unfinalized,
            "journal_status": journal.get("status"),
            "transaction_hash": journal.get("transaction_hash"),
            "rejected_proofs": rejected_proofs,
            "registry_paused": registry_paused,
            "verifier_paused": verifier_paused,
            "signer_key_id": receipt.get("signer_key_id"),
            "signer_backend": receipt.get("signer_backend"),
            "attestor": chain_attestor,
            "policy_manifest_hash": chain_policy_hash,
            "policy_matches_receipt": policy_matches,
            "deployment_pin_schema": pin.get("schema_version"),
            "placeholder_deployment_pins": placeholder_pins,
            "controlled_attestation_limitation": (
                "Winterfell proves the constrained computation; this report does not establish the legal validity "
                "or source authenticity of claim and oracle inputs."
            ),
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
