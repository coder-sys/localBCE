#!/usr/bin/env python3
"""Credential-gated, idempotent runner for the governed Sepolia STARK pilot.

The runner never accepts secrets in its JSON configuration. It advances only
explicit pilot actions, records public evidence atomically, and stops before
human Safe, legal, MPC, or audit gates that have not been satisfied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from validate_policy_manifest import ManifestError, validate as validate_policy_manifest


ROOT = Path(__file__).resolve().parents[1]
SEPOLIA_CHAIN_ID = 11_155_111
TIMELOCK_DELAY_SECONDS = 259_200
CONFIG_SCHEMA = "localbce-stark-sepolia-pilot-config-v1"
STATE_SCHEMA = "localbce-stark-sepolia-pilot-state-v1"
PIN_SCHEMA = "localbce-stark-v2-deployment-pin-v1"
RELEASE_SCHEMA = "localbce-stark-v2-release-profile-v1"
SAFE_BUNDLE_SCHEMA = "localbce-safe-transaction-bundle-v1"
ZERO_BYTES32 = "0x" + "00" * 32
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
BYTES32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
PLACEHOLDER_ADDRESSES = {f"0x{digit * 40}" for digit in "0123456789abcdef"}
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
RELEASE_GATES = (
    "local_v2_validation_passed",
    "safe_and_timelock_deployed",
    "external_mpc_key_approved",
    "policy_manifest_approved",
    "deployment_pins_complete",
    "approved_canary_finalized",
    "denied_canary_finalized",
    "reconciliation_report_clean",
    "pause_recovery_rehearsed",
    "legal_approval_recorded",
    "independent_audits_complete",
)


class PilotError(ValueError):
    pass


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def normalize_hex(value: str) -> str:
    return value.lower()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PilotError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PilotError(f"{path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PilotError(f"{path} must contain a JSON object")
    return value


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.replace(path)


def sha256_bytes(value: bytes, *, prefixed: bool = False) -> str:
    digest = hashlib.sha256(value).hexdigest()
    return f"0x{digest}" if prefixed else digest


def sha256_file(path: Path, *, prefixed: bool = False) -> str:
    return sha256_bytes(path.read_bytes(), prefixed=prefixed)


def canonical_hash(value: dict[str, Any], excluded: Iterable[str] = ()) -> str:
    payload = {key: item for key, item in value.items() if key not in set(excluded)}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return sha256_bytes(encoded, prefixed=True)


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PilotError(f"{field} must be a non-empty string")
    return value


def require_address(value: Any, field: str, *, live: bool = True) -> str:
    text = require_text(value, field)
    if not ADDRESS_RE.fullmatch(text):
        raise PilotError(f"{field} must be a 20-byte hex address")
    if live and text.lower() in PLACEHOLDER_ADDRESSES:
        raise PilotError(f"{field} must not be a placeholder address")
    return text.lower()


def require_bytes32(value: Any, field: str, *, nonzero: bool = True) -> str:
    text = require_text(value, field)
    if not BYTES32_RE.fullmatch(text):
        raise PilotError(f"{field} must be bytes32 hex")
    if nonzero and int(text, 16) == 0:
        raise PilotError(f"{field} must be nonzero")
    return text.lower()


def resolve_repo_path(value: Any, field: str) -> Path:
    text = require_text(value, field)
    path = Path(text)
    resolved = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise PilotError(f"{field} must stay within the repository") from exc
    return resolved


def command(
    arguments: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 300,
    label: str | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=merged,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        name = label or arguments[0]
        detail = (result.stderr or result.stdout).strip()
        raise PilotError(f"{name} failed with exit {result.returncode}: {detail}")
    return result


def cast(rpc_url: str, *arguments: str, timeout: int = 60) -> str:
    return command(
        ["cast", *arguments, "--rpc-url", rpc_url], timeout=timeout, label="cast"
    ).stdout.strip()


def git(*arguments: str) -> str:
    return command(["git", *arguments], label="git").stdout.strip()


def clean_pushed_source_commit() -> str:
    if git("status", "--porcelain"):
        raise PilotError("pilot actions require a clean Git worktree")
    head = git("rev-parse", "HEAD")
    origin = git("rev-parse", "origin/codex-dev")
    if head != origin:
        raise PilotError("pilot actions require HEAD to match origin/codex-dev")
    return head


@dataclass(frozen=True)
class PilotConfig:
    path: Path
    value: dict[str, Any]
    deployer_address: str
    governance_safe: str
    treasury: str
    attestor: str
    initial_nullifier_root: str
    policy_manifest_path: Path
    policy_manifest_hash: str
    signer_program: Path
    signer_args: list[str]
    signer_key_id: str
    signer_timeout_seconds: int
    artifact_directory: Path
    state_directory: Path
    deployment_pin_path: Path
    release_profile_path: Path
    approved_claim_path: Path
    denied_claim_path: Path

    @classmethod
    def load(cls, path: Path, *, allow_example: bool = False) -> "PilotConfig":
        value = load_json(path)
        required = {
            "schema_version",
            "environment",
            "production_usable",
            "chain_id",
            "rpc_url_env",
            "deployer_private_key_env",
            "submitter_private_key_env",
            "verification_api_key_env",
            "deployer_address",
            "governance_safe",
            "emergency_safe",
            "safe_threshold",
            "safe_owner_count",
            "treasury",
            "attestor",
            "attestor_key_id",
            "attestor_signer_program",
            "attestor_signer_args",
            "attestor_signer_timeout_seconds",
            "policy_manifest",
            "initial_nullifier_root",
            "transaction_value",
            "deployment_pin_output",
            "release_profile_output",
            "artifact_directory",
            "state_directory",
            "approved_claim_input",
            "denied_claim_input",
        }
        missing = required - set(value)
        unknown = set(value) - required
        if missing or unknown:
            raise PilotError(
                f"pilot config fields mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        if value["schema_version"] != CONFIG_SCHEMA:
            raise PilotError(f"schema_version must be {CONFIG_SCHEMA}")
        if value["production_usable"] is not False:
            raise PilotError("pilot configuration must keep production_usable=false")
        if value["chain_id"] != SEPOLIA_CHAIN_ID:
            raise PilotError("pilot configuration must pin Sepolia chain ID 11155111")
        environment = require_text(value["environment"], "environment")
        if not allow_example and "example" in environment.lower():
            raise PilotError("live pilot environment must not be an example")
        deployer_address = require_address(
            value["deployer_address"], "deployer_address", live=not allow_example
        )
        governance_safe = require_address(
            value["governance_safe"], "governance_safe", live=not allow_example
        )
        emergency_safe = require_address(
            value["emergency_safe"], "emergency_safe", live=not allow_example
        )
        if governance_safe != emergency_safe:
            raise PilotError("Sepolia pilot governance_safe and emergency_safe must be the same Safe")
        if value["safe_threshold"] != 2 or value["safe_owner_count"] != 3:
            raise PilotError("Sepolia pilot Safe must be configured as 2-of-3")
        treasury = require_address(value["treasury"], "treasury", live=not allow_example)
        attestor = require_address(value["attestor"], "attestor", live=not allow_example)
        if len({governance_safe, treasury, attestor}) != 3:
            raise PilotError("governance Safe, treasury, and attestor must be distinct")
        initial_root = require_bytes32(value["initial_nullifier_root"], "initial_nullifier_root")
        signer_program = Path(require_text(value["attestor_signer_program"], "attestor_signer_program"))
        if not signer_program.is_absolute():
            raise PilotError("attestor_signer_program must be an absolute path")
        signer_args = value["attestor_signer_args"]
        if not isinstance(signer_args, list) or not all(
            isinstance(item, str) and item for item in signer_args
        ):
            raise PilotError("attestor_signer_args must be a JSON array of non-empty strings")
        signer_key_id = require_text(value["attestor_key_id"], "attestor_key_id")
        if not allow_example and (
            "replace" in signer_key_id.lower()
            or "mock" in signer_key_id.lower()
            or "test-only" in signer_key_id.lower()
        ):
            raise PilotError("live pilot attestor_key_id must identify an approved external key")
        timeout = value["attestor_signer_timeout_seconds"]
        if not isinstance(timeout, int) or timeout < 1 or timeout > 120:
            raise PilotError("attestor_signer_timeout_seconds must be between 1 and 120")
        for field in (
            "rpc_url_env",
            "deployer_private_key_env",
            "submitter_private_key_env",
            "verification_api_key_env",
        ):
            environment_name = require_text(value[field], field)
            if not ENV_NAME_RE.fullmatch(environment_name):
                raise PilotError(
                    f"{field} must name an environment variable, not contain a credential"
                )
        require_text(value["transaction_value"], "transaction_value")
        if not allow_example:
            if not signer_program.is_file() or not os.access(signer_program, os.X_OK):
                raise PilotError("attestor_signer_program must be an executable file")
            mock_signer = (ROOT / "scripts" / "mock_mpc_attestation_signer.py").resolve()
            signer_paths = [signer_program.resolve()]
            signer_paths.extend(Path(item).resolve() for item in signer_args if item.startswith("/"))
            if mock_signer in signer_paths:
                raise PilotError("test-only mock signer is prohibited for the Sepolia pilot")
            if any(
                item == "--private-key" or re.fullmatch(r"0x[0-9a-fA-F]{64}", item)
                for item in signer_args
            ):
                raise PilotError("attestor_signer_args must not contain private-key material")

        policy_path = resolve_repo_path(value["policy_manifest"], "policy_manifest")
        policy = load_json(policy_path)
        try:
            validate_policy_manifest(policy)
        except ManifestError as exc:
            raise PilotError(f"policy manifest is invalid: {exc}") from exc
        if not allow_example and policy.get("status") != "pilot_approved":
            raise PilotError("live Sepolia policy manifest must have status pilot_approved")
        policy_hash = require_bytes32(policy.get("canonical_hash"), "policy canonical_hash")

        approved = resolve_repo_path(value["approved_claim_input"], "approved_claim_input")
        denied = resolve_repo_path(value["denied_claim_input"], "denied_claim_input")
        if not allow_example:
            for label, claim_path in (("approved", approved), ("denied", denied)):
                if not claim_path.is_file():
                    raise PilotError(f"{label} canary claim file does not exist: {claim_path}")

        return cls(
            path=path.resolve(),
            value=value,
            deployer_address=deployer_address,
            governance_safe=governance_safe,
            treasury=treasury,
            attestor=attestor,
            initial_nullifier_root=initial_root,
            policy_manifest_path=policy_path,
            policy_manifest_hash=policy_hash,
            signer_program=signer_program,
            signer_args=list(signer_args),
            signer_key_id=signer_key_id,
            signer_timeout_seconds=timeout,
            artifact_directory=resolve_repo_path(value["artifact_directory"], "artifact_directory"),
            state_directory=resolve_repo_path(value["state_directory"], "state_directory"),
            deployment_pin_path=resolve_repo_path(value["deployment_pin_output"], "deployment_pin_output"),
            release_profile_path=resolve_repo_path(value["release_profile_output"], "release_profile_output"),
            approved_claim_path=approved,
            denied_claim_path=denied,
        )

    def environment_value(self, field: str) -> str:
        name = self.value[field]
        result = os.environ.get(name)
        if not result:
            raise PilotError(f"required environment variable {name} is not set")
        return result

    @property
    def rpc_url(self) -> str:
        return self.environment_value("rpc_url_env")

    @property
    def deployment_path(self) -> Path:
        return ROOT / "blind-ledger" / "stark_v2_deployment.json"

    @property
    def state_path(self) -> Path:
        return self.artifact_directory / "pilot_state.json"


def new_state(config: PilotConfig) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA,
        "environment": config.value["environment"],
        "chain_id": SEPOLIA_CHAIN_ID,
        "source_commit": git("rev-parse", "HEAD"),
        "current_backend": "groth16",
        "candidate_backend": "stark_attested",
        "automatic_fallback": False,
        "native_verifier_active": False,
        "completed_actions": {},
        "blocked_reasons": [],
        "updated_at": now_utc(),
    }


def load_state(config: PilotConfig) -> dict[str, Any]:
    if not config.state_path.exists():
        return new_state(config)
    state = load_json(config.state_path)
    if state.get("schema_version") != STATE_SCHEMA:
        raise PilotError("pilot state schema_version is invalid")
    if state.get("chain_id") != SEPOLIA_CHAIN_ID:
        raise PilotError("pilot state chain_id is invalid")
    if state.get("automatic_fallback") is not False or state.get("native_verifier_active") is not False:
        raise PilotError("pilot state changed a protected trust boundary")
    if state.get("source_commit") != git("rev-parse", "HEAD"):
        raise PilotError("pilot state belongs to a different source commit")
    return state


def record_action(config: PilotConfig, state: dict[str, Any], action: str, evidence: Any) -> None:
    state.setdefault("completed_actions", {})[action] = {
        "completed_at": now_utc(),
        "evidence": evidence,
    }
    state["blocked_reasons"] = []
    state["updated_at"] = now_utc()
    write_json_atomic(config.state_path, state)


def record_block(config: PilotConfig, state: dict[str, Any], reason: str) -> None:
    reasons = state.setdefault("blocked_reasons", [])
    if reason not in reasons:
        reasons.append(reason)
    state["updated_at"] = now_utc()
    write_json_atomic(config.state_path, state)


def require_action(state: dict[str, Any], action: str) -> dict[str, Any]:
    value = state.get("completed_actions", {}).get(action)
    if not isinstance(value, dict):
        raise PilotError(f"required pilot action has not completed: {action}")
    return value


def require_safe_action_prerequisites(
    state: dict[str, Any], operation: str, phase: str
) -> None:
    if operation not in {"authorize", "pause", "unpause"}:
        raise PilotError("operation must be authorize, pause, or unpause")
    if phase not in {"schedule", "execute"}:
        raise PilotError("phase must be schedule or execute")
    if operation == "pause":
        if phase != "execute":
            raise PilotError("pause is immediate and supports execute phase only")
        require_action(state, "reconcile")
        return
    if operation == "unpause":
        require_action(state, "pause")
    if phase == "execute":
        require_action(state, f"prepare-{operation}-schedule")


def require_governance_verification_prerequisites(
    state: dict[str, Any], operation: str
) -> None:
    if operation == "pause":
        require_action(state, "reconcile")
    elif operation == "unpause":
        require_action(state, "pause")
    elif operation != "authorize":
        raise PilotError("operation must be authorize, pause, or unpause")
    require_action(state, f"prepare-{operation}-execute")


def validate_live_release_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != RELEASE_SCHEMA:
        raise PilotError(f"release profile schema_version must be {RELEASE_SCHEMA}")
    if profile.get("chain_id") != SEPOLIA_CHAIN_ID:
        raise PilotError("release profile must pin Sepolia")
    if profile.get("automatic_fallback") is not False:
        raise PilotError("release profile must prohibit automatic fallback")
    if profile.get("rollback_mode") != "manual_governed":
        raise PilotError("release profile must use manual governed rollback")
    if profile.get("native_verifier_active") is not False:
        raise PilotError("native verifier must remain inactive")
    gates = profile.get("activation_gates")
    if not isinstance(gates, dict) or set(gates) != set(RELEASE_GATES):
        raise PilotError("release profile activation gates are incomplete")
    if not all(isinstance(value, bool) for value in gates.values()):
        raise PilotError("release profile activation gates must be boolean")
    if profile.get("current_backend") == "stark_attested":
        if profile.get("production_usable") is not True or not all(gates.values()):
            raise PilotError("stark_attested activation requires every gate and production_usable=true")
    elif profile.get("current_backend") != "groth16":
        raise PilotError("current_backend must be groth16 or gated stark_attested")
    if profile.get("candidate_backend") != "stark_attested":
        raise PilotError("candidate_backend must be stark_attested")


def validate_deployment_pin(pin: dict[str, Any], config: PilotConfig) -> None:
    if pin.get("schema_version") != PIN_SCHEMA:
        raise PilotError(f"deployment pin schema_version must be {PIN_SCHEMA}")
    if pin.get("production_usable") is not False:
        raise PilotError("pilot deployment pin must retain production_usable=false")
    if pin.get("chain_id") != SEPOLIA_CHAIN_ID:
        raise PilotError("deployment pin must pin Sepolia")
    if pin.get("openzeppelin_contracts_version") != "v5.6.1":
        raise PilotError("deployment pin must pin OpenZeppelin v5.6.1")
    if not re.fullmatch(r"[0-9a-f]{40}", str(pin.get("source_commit", ""))):
        raise PilotError("deployment pin source_commit must be a full lowercase Git commit")
    if pin["source_commit"] != git("rev-parse", "HEAD"):
        raise PilotError("deployment pin source_commit does not match the current source")
    for field in ("governance_safe", "emergency_safe", "treasury", "attestor", "timelock", "verifier", "registry"):
        require_address(pin.get(field), f"deployment pin {field}")
    if normalize_hex(pin["governance_safe"]) != config.governance_safe:
        raise PilotError("deployment pin governance Safe does not match pilot config")
    if normalize_hex(pin["emergency_safe"]) != config.governance_safe:
        raise PilotError("deployment pin emergency Safe must match governance Safe")
    if normalize_hex(pin["treasury"]) != config.treasury or normalize_hex(pin["attestor"]) != config.attestor:
        raise PilotError("deployment pin treasury or attestor does not match pilot config")
    if len(
        {
            normalize_hex(pin["governance_safe"]),
            normalize_hex(pin["treasury"]),
            normalize_hex(pin["attestor"]),
            normalize_hex(pin["timelock"]),
            normalize_hex(pin["verifier"]),
            normalize_hex(pin["registry"]),
        }
    ) != 6:
        raise PilotError("deployment pin governance, treasury, signer, and contracts must be distinct")
    if normalize_hex(require_bytes32(pin.get("policy_manifest_hash"), "deployment pin policy hash")) != config.policy_manifest_hash:
        raise PilotError("deployment pin policy hash does not match the approved manifest")
    for field in (
        "cargo_lock_sha256",
        "proof_parameters_sha256",
        "verifier_runtime_bytecode_sha256",
        "registry_runtime_bytecode_sha256",
    ):
        value = require_text(pin.get(field), f"deployment pin {field}")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise PilotError(f"deployment pin {field} must be lowercase SHA-256")
    transactions = pin.get("deployment_transactions")
    if not isinstance(transactions, list) or len(transactions) != 3:
        raise PilotError("deployment pin must include exactly three deployment transactions")
    if not all(isinstance(item, str) and TX_RE.fullmatch(item) for item in transactions):
        raise PilotError("deployment transaction pins are invalid")
    if len(set(transactions)) != 3 or any(int(item, 16) == 0 for item in transactions):
        raise PilotError("deployment transaction pins must be unique and nonzero")
    for transaction_hash in transactions:
        transaction = json.loads(cast(config.rpc_url, "tx", transaction_hash, "--json"))
        if str(transaction.get("from", "")).lower() != config.deployer_address:
            raise PilotError("deployment transaction sender does not match configured deployer")
    pinned_parameters = pin.get("proof_parameters")
    if not isinstance(pinned_parameters, dict):
        raise PilotError("deployment pin must include proof_parameters")
    if pinned_parameters != proof_parameters():
        raise PilotError("deployment proof parameters do not match the production Winterfell build")
    if canonical_hash(pinned_parameters) != "0x" + pin["proof_parameters_sha256"]:
        raise PilotError("proof_parameters_sha256 does not match canonical proof parameters")
    if pin["cargo_lock_sha256"] != sha256_file(ROOT / "stark-engine" / "Cargo.lock"):
        raise PilotError("deployment Cargo.lock pin does not match the current lockfile")
    if pin.get("native_on_chain_winterfell") is not False:
        raise PilotError("deployment pin must keep native Winterfell verification inactive")
    if pin["verifier_runtime_bytecode_sha256"] != runtime_bytecode_sha(config.rpc_url, pin["verifier"]):
        raise PilotError("verifier runtime bytecode pin does not match Sepolia")
    if pin["registry_runtime_bytecode_sha256"] != runtime_bytecode_sha(config.rpc_url, pin["registry"]):
        raise PilotError("registry runtime bytecode pin does not match Sepolia")


def preflight(config: PilotConfig) -> dict[str, Any]:
    rpc_url = config.rpc_url
    config.environment_value("deployer_private_key_env")
    config.environment_value("submitter_private_key_env")
    config.environment_value("verification_api_key_env")
    for tool in ("cast", "forge", "cargo", "git", "python3"):
        if shutil.which(tool) is None:
            raise PilotError(f"required tool is not available: {tool}")
    head = clean_pushed_source_commit()
    if int(cast(rpc_url, "chain-id")) != SEPOLIA_CHAIN_ID:
        raise PilotError("RPC is not Sepolia chain ID 11155111")
    finalized = command(
        ["cast", "rpc", "eth_getBlockByNumber", "finalized", "false", "--rpc-url", rpc_url],
        label="finalized-block RPC check",
    ).stdout.strip()
    if not finalized or finalized == "null":
        raise PilotError("RPC does not expose the finalized block tag")
    balance = int(cast(rpc_url, "balance", config.deployer_address))
    if balance <= 0:
        raise PilotError("Sepolia deployer has no ETH")
    safe_code = cast(rpc_url, "code", config.governance_safe)
    if safe_code in {"0x", "0x0"}:
        raise PilotError("configured governance Safe has no Sepolia bytecode")
    threshold = int(cast(rpc_url, "call", config.governance_safe, "getThreshold()(uint256)"))
    owners_output = cast(rpc_url, "call", config.governance_safe, "getOwners()(address[])")
    owners = sorted(set(match.lower() for match in re.findall(r"0x[0-9a-fA-F]{40}", owners_output)))
    if threshold != 2 or len(owners) != 3:
        raise PilotError("configured Safe is not 2-of-3")
    report = {
        "schema_version": "localbce-stark-sepolia-preflight-v1",
        "status": "ready",
        "checked_at": now_utc(),
        "source_commit": head,
        "chain_id": SEPOLIA_CHAIN_ID,
        "finalized_rpc_supported": True,
        "deployer_address": config.deployer_address,
        "deployer_balance_wei": balance,
        "governance_safe": config.governance_safe,
        "emergency_safe": config.governance_safe,
        "safe_threshold": threshold,
        "safe_owner_count": len(owners),
        "safe_owners": owners,
        "treasury": config.treasury,
        "attestor": config.attestor,
        "attestor_key_id": config.signer_key_id,
        "policy_manifest_hash": config.policy_manifest_hash,
        "initial_nullifier_root": config.initial_nullifier_root,
        "secrets_persisted": False,
        "native_on_chain_winterfell": False,
    }
    output = config.artifact_directory / "preflight_report.json"
    write_json_atomic(output, report)
    return report


def local_gate_commands() -> list[tuple[str, list[str], Path]]:
    return [
        (
            "sepolia_pilot_unit_tests",
            ["python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"],
            ROOT,
        ),
        ("ops", ["python3", "scripts/validate_ops_scaffold.py"], ROOT),
        ("policy", ["python3", "scripts/validate_policy_manifest.py", "ops/policy_manifest.example.json"], ROOT),
        ("openzeppelin", ["python3", "scripts/validate_openzeppelin_pin.py"], ROOT),
        ("rules", ["bash", "scripts/validate_rules_pipeline.sh"], ROOT),
        ("rust_test", ["cargo", "test", "--jobs", "1"], ROOT / "rust-engine"),
        ("rust_check", ["cargo", "check", "--jobs", "1"], ROOT / "rust-engine"),
        ("stark_test", ["cargo", "test", "--all-features", "--jobs", "1"], ROOT / "stark-engine"),
        ("stark_check", ["cargo", "check", "--all-features", "--jobs", "1"], ROOT / "stark-engine"),
        ("foundry_test", ["forge", "test"], ROOT / "blind-ledger"),
        ("foundry_build", ["forge", "build"], ROOT / "blind-ledger"),
        ("foundry_gas", ["forge", "test", "--gas-report"], ROOT / "blind-ledger"),
        ("stark_bridge", ["bash", "scripts/validate_stark_bridge_chain.sh"], ROOT),
        ("stark_runtime", ["bash", "scripts/validate_stark_runtime_settlement.sh"], ROOT),
        ("governed_v2", ["bash", "scripts/validate_stark_v2_anvil.sh"], ROOT),
        ("secrets", ["python3", "scripts/scan_secrets.py"], ROOT),
        ("diff", ["git", "diff", "--check"], ROOT),
    ]


def run_local_gates(config: PilotConfig) -> dict[str, Any]:
    source_commit = clean_pushed_source_commit()
    log_directory = config.artifact_directory / "local-gates"
    log_directory.mkdir(parents=True, exist_ok=True)
    results = []
    build_env = {"CARGO_BUILD_JOBS": "1"}
    for name, arguments, cwd in local_gate_commands():
        started = time.monotonic()
        result = command(arguments, cwd=cwd, env=build_env, timeout=3_600, label=name)
        log = log_directory / f"{name}.log"
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        results.append(
            {
                "name": name,
                "status": "passed",
                "duration_seconds": round(time.monotonic() - started, 3),
                "log": str(log.relative_to(ROOT)),
                "log_sha256": sha256_file(log),
            }
        )
    report = {
        "schema_version": "localbce-stark-local-production-gates-v1",
        "status": "passed",
        "source_commit": source_commit,
        "completed_at": now_utc(),
        "results": results,
    }
    write_json_atomic(config.artifact_directory / "local_gate_report.json", report)
    return report


def proof_parameters() -> dict[str, Any]:
    source = ROOT / "stark-engine" / "src" / "production_air_winterfell.rs"
    return {
        "schema_version": "localbce-winterfell-proof-parameters-v1",
        "air": "production-g1-g10-v1",
        "trace_length": 1024,
        "base_field": "f64",
        "field_extension": "quadratic",
        "hash_function": "blake3_256",
        "random_coin": "blake3_256",
        "merkle_tree": "blake3_256",
        "acceptable_min_conjectured_security_bits": 80,
        "proof_options": {
            "num_queries": 32,
            "blowup_factor": 16,
            "grinding_factor": 0,
            "fri_folding_factor": 8,
            "fri_max_remainder_degree": 31,
            "constraint_batching": "linear",
            "deep_poly_batching": "linear",
        },
        "source_path": str(source.relative_to(ROOT)).replace("\\", "/"),
        "source_sha256": sha256_file(source),
    }


def deployed_contracts(config: PilotConfig) -> dict[str, Any]:
    deployment = load_json(config.deployment_path)
    if deployment.get("chainId") != SEPOLIA_CHAIN_ID:
        raise PilotError("deployment JSON is not for Sepolia")
    expected = {
        "governanceSafe": config.governance_safe,
        "emergencySafe": config.governance_safe,
        "treasury": config.treasury,
        "attestor": config.attestor,
        "policyManifestHash": config.policy_manifest_hash,
        "initialNullifierRoot": config.initial_nullifier_root,
    }
    for field, value in expected.items():
        actual = deployment.get(field)
        if not isinstance(actual, str) or actual.lower() != value.lower():
            raise PilotError(f"deployment {field} does not match pilot configuration")
    for field in ("timelock", "starkAttestationVerifierV2", "starkClaimsRegistryV2"):
        require_address(deployment.get(field), f"deployment {field}")
    return deployment


def broadcast_transactions() -> list[str]:
    path = ROOT / "blind-ledger" / "broadcast" / "DeployStarkGovernedV2.s.sol" / str(SEPOLIA_CHAIN_ID) / "run-latest.json"
    broadcast = load_json(path)
    transactions: list[str] = []
    for receipt in broadcast.get("receipts", []):
        if isinstance(receipt, dict):
            tx_hash = receipt.get("transactionHash")
            if isinstance(tx_hash, str) and TX_RE.fullmatch(tx_hash):
                transactions.append(tx_hash.lower())
    if len(transactions) < 3:
        raise PilotError("Foundry broadcast does not contain all governed V2 deployment transactions")
    return transactions


def runtime_bytecode_sha(rpc_url: str, address: str) -> str:
    code = cast(rpc_url, "code", address)
    if not code.startswith("0x") or len(code) <= 2:
        raise PilotError(f"contract has no runtime bytecode: {address}")
    try:
        return sha256_bytes(bytes.fromhex(code[2:]))
    except ValueError as exc:
        raise PilotError(f"contract returned invalid bytecode: {address}") from exc


def materialize_pin(config: PilotConfig, deployment: dict[str, Any]) -> dict[str, Any]:
    parameters = proof_parameters()
    pin = {
        "schema_version": PIN_SCHEMA,
        "environment": config.value["environment"],
        "production_usable": False,
        "chain_id": SEPOLIA_CHAIN_ID,
        "source_commit": git("rev-parse", "HEAD"),
        "openzeppelin_contracts_version": "v5.6.1",
        "cargo_lock_sha256": sha256_file(ROOT / "stark-engine" / "Cargo.lock"),
        "proof_parameters": parameters,
        "proof_parameters_sha256": canonical_hash(parameters)[2:],
        "deployment_transactions": broadcast_transactions(),
        "governance_safe": config.governance_safe,
        "emergency_safe": config.governance_safe,
        "treasury": config.treasury,
        "timelock": deployment["timelock"].lower(),
        "attestor": config.attestor,
        "verifier": deployment["starkAttestationVerifierV2"].lower(),
        "registry": deployment["starkClaimsRegistryV2"].lower(),
        "policy_manifest_hash": config.policy_manifest_hash,
        "verifier_runtime_bytecode_sha256": runtime_bytecode_sha(
            config.rpc_url, deployment["starkAttestationVerifierV2"]
        ),
        "registry_runtime_bytecode_sha256": runtime_bytecode_sha(
            config.rpc_url, deployment["starkClaimsRegistryV2"]
        ),
        "native_on_chain_winterfell": False,
    }
    validate_deployment_pin(pin, config)
    write_json_atomic(config.deployment_pin_path, pin)
    return pin


def release_profile(config: PilotConfig, state: dict[str, Any]) -> dict[str, Any]:
    completed = state.get("completed_actions", {})
    gates = {
        "local_v2_validation_passed": "local-gates" in completed,
        "safe_and_timelock_deployed": "deploy" in completed and "authorize" in completed,
        "external_mpc_key_approved": "signer-health" in completed,
        "policy_manifest_approved": load_json(config.policy_manifest_path).get("status") == "pilot_approved",
        "deployment_pins_complete": "deploy" in completed,
        "approved_canary_finalized": "canary-approved" in completed,
        "denied_canary_finalized": "canary-denied" in completed,
        "reconciliation_report_clean": "reconcile" in completed,
        "pause_recovery_rehearsed": "pause" in completed and "unpause" in completed,
        "legal_approval_recorded": False,
        "independent_audits_complete": False,
    }
    profile = {
        "schema_version": RELEASE_SCHEMA,
        "environment": config.value["environment"],
        "production_usable": False,
        "chain_id": SEPOLIA_CHAIN_ID,
        "current_backend": "groth16",
        "candidate_backend": "stark_attested",
        "automatic_fallback": False,
        "rollback_mode": "manual_governed",
        "native_verifier_active": False,
        "activation_gates": gates,
        "release_action": (
            "A human-approved release may switch current_backend only after every activation gate is true."
        ),
        "rollback_action": (
            "Pause, reconcile, then perform a human-approved manual rollback to groth16; never retry a failed STARK settlement through Groth16 automatically."
        ),
    }
    validate_live_release_profile(profile)
    write_json_atomic(config.release_profile_path, profile)
    return profile


def deploy(config: PilotConfig, state: dict[str, Any]) -> dict[str, Any]:
    require_action(state, "preflight")
    require_action(state, "local-gates")
    if config.deployment_path.exists():
        deployment = deployed_contracts(config)
        for field in ("timelock", "starkAttestationVerifierV2", "starkClaimsRegistryV2"):
            if cast(config.rpc_url, "code", deployment[field]) in {"0x", "0x0"}:
                raise PilotError(f"existing deployment has no code for {field}")
    else:
        deployment_env = {
            "STARK_DEPLOYER_PRIVATE_KEY": config.environment_value("deployer_private_key_env"),
            "STARK_GOVERNANCE_SAFE": config.governance_safe,
            "STARK_EMERGENCY_SAFE": config.governance_safe,
            "STARK_TREASURY": config.treasury,
            "STARK_ATTESTOR": config.attestor,
            "STARK_POLICY_MANIFEST_HASH": config.policy_manifest_hash,
            "STARK_INITIAL_NULLIFIER_ROOT": config.initial_nullifier_root,
            "ETHERSCAN_API_KEY": config.environment_value("verification_api_key_env"),
        }
        command(
            [
                "forge",
                "script",
                "script/DeployStarkGovernedV2.s.sol:DeployStarkGovernedV2",
                "--rpc-url",
                config.rpc_url,
                "--broadcast",
            ],
            cwd=ROOT / "blind-ledger",
            env=deployment_env,
            timeout=1_800,
            label="governed V2 Sepolia deployment",
        )
        deployment = deployed_contracts(config)
        command(
            [
                "forge",
                "script",
                "script/DeployStarkGovernedV2.s.sol:DeployStarkGovernedV2",
                "--rpc-url",
                config.rpc_url,
                "--resume",
                "--verify",
            ],
            cwd=ROOT / "blind-ledger",
            env=deployment_env,
            timeout=1_800,
            label="governed V2 source verification",
        )
    pin = materialize_pin(config, deployment)
    return {
        "deployment": str(config.deployment_path.relative_to(ROOT)),
        "deployment_pin": str(config.deployment_pin_path.relative_to(ROOT)),
        "timelock": deployment["timelock"],
        "verifier": deployment["starkAttestationVerifierV2"],
        "registry": deployment["starkClaimsRegistryV2"],
        "deployment_transactions": pin["deployment_transactions"],
        "source_verified": True,
    }


def encode_calldata(signature: str, *arguments: str) -> str:
    return command(["cast", "calldata", signature, *arguments], label="cast calldata").stdout.strip()


def operation_salt(config: PilotConfig, operation: str, target: str) -> str:
    preimage = f"localbce|{SEPOLIA_CHAIN_ID}|{config.value['environment']}|{operation}|{target}|{config.policy_manifest_hash}"
    return "0x" + hashlib.sha256(preimage.encode()).hexdigest()


def safe_bundle(config: PilotConfig, operation: str, phase: str) -> dict[str, Any]:
    deployment = deployed_contracts(config)
    verifier = deployment["starkAttestationVerifierV2"]
    registry = deployment["starkClaimsRegistryV2"]
    timelock = deployment["timelock"]
    inner: list[tuple[str, str, str]]
    if operation == "authorize":
        inner = [("authorize-registry", verifier, encode_calldata("setRegistryAuthorization(address,bool)", registry, "true"))]
    elif operation == "pause":
        if phase != "execute":
            raise PilotError("pause is immediate and supports execute phase only")
        inner = [
            ("pause-verifier", verifier, encode_calldata("pause()")),
            ("pause-registry", registry, encode_calldata("pause()")),
        ]
    elif operation == "unpause":
        inner = [
            ("unpause-verifier", verifier, encode_calldata("unpause()")),
            ("unpause-registry", registry, encode_calldata("unpause()")),
        ]
    else:
        raise PilotError("operation must be authorize, pause, or unpause")

    transactions = []
    operations = []
    for label, target, data in inner:
        salt = operation_salt(config, label, target)
        if operation == "pause":
            to, outer = target, data
        elif phase == "schedule":
            to = timelock
            outer = encode_calldata(
                "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
                target,
                "0",
                data,
                ZERO_BYTES32,
                salt,
                str(TIMELOCK_DELAY_SECONDS),
            )
        elif phase == "execute":
            to = timelock
            outer = encode_calldata(
                "execute(address,uint256,bytes,bytes32,bytes32)",
                target,
                "0",
                data,
                ZERO_BYTES32,
                salt,
            )
        else:
            raise PilotError("phase must be schedule or execute")
        transactions.append({"to": to, "value": "0", "data": outer, "operation": 0})
        operations.append(
            {
                "label": label,
                "target": target,
                "inner_calldata": data,
                "predecessor": ZERO_BYTES32,
                "salt": salt,
                "minimum_delay_seconds": 0 if operation == "pause" else TIMELOCK_DELAY_SECONDS,
                "execution_timing": (
                    "immediate_emergency_pause"
                    if operation == "pause"
                    else "schedule_block_timestamp_plus_259200_seconds"
                ),
            }
        )
    bundle = {
        "schema_version": SAFE_BUNDLE_SCHEMA,
        "chain_id": SEPOLIA_CHAIN_ID,
        "safe": config.governance_safe,
        "safe_threshold": 2,
        "safe_owner_count": 3,
        "operation_name": operation,
        "phase": phase,
        "transactions": transactions,
        "timelock_operations": operations,
        "human_approval_required": True,
        "automatic_submission": False,
    }
    output = config.artifact_directory / "safe-transactions" / f"{operation}-{phase}.json"
    write_json_atomic(output, bundle)
    evidence = {
        "bundle": str(output.relative_to(ROOT)),
        "bundle_sha256": sha256_file(output),
        "operation": operation,
        "phase": phase,
    }
    validate_recorded_safe_bundle(config, evidence)
    return evidence


def validate_recorded_safe_bundle(
    config: PilotConfig, evidence: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise PilotError("recorded Safe bundle evidence must be an object")
    operation = require_text(evidence.get("operation"), "Safe bundle operation")
    phase = require_text(evidence.get("phase"), "Safe bundle phase")
    bundle_path = resolve_repo_path(evidence.get("bundle"), "Safe bundle path")
    expected_directory = (config.artifact_directory / "safe-transactions").resolve()
    if bundle_path.parent != expected_directory:
        raise PilotError("recorded Safe bundle must stay in the pilot safe-transactions directory")
    if not bundle_path.is_file():
        raise PilotError(f"recorded Safe bundle is missing: {bundle_path}")
    expected_sha = require_text(evidence.get("bundle_sha256"), "Safe bundle SHA-256")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or sha256_file(bundle_path) != expected_sha:
        raise PilotError(f"recorded Safe bundle is missing or changed: {bundle_path}")
    bundle = load_json(bundle_path)
    if bundle.get("schema_version") != SAFE_BUNDLE_SCHEMA:
        raise PilotError("recorded Safe bundle schema_version is invalid")
    if bundle.get("chain_id") != SEPOLIA_CHAIN_ID:
        raise PilotError("recorded Safe bundle must pin Sepolia")
    if normalize_hex(str(bundle.get("safe", ""))) != config.governance_safe:
        raise PilotError("recorded Safe bundle targets the wrong governance Safe")
    if bundle.get("safe_threshold") != 2 or bundle.get("safe_owner_count") != 3:
        raise PilotError("recorded Safe bundle must retain the 2-of-3 approval boundary")
    if bundle.get("operation_name") != operation or bundle.get("phase") != phase:
        raise PilotError("recorded Safe bundle operation metadata does not match its evidence")
    if bundle.get("human_approval_required") is not True or bundle.get("automatic_submission") is not False:
        raise PilotError("recorded Safe bundle must require human approval and prohibit automatic submission")
    transactions = bundle.get("transactions")
    expected_transactions = 2 if operation in {"pause", "unpause"} else 1
    if not isinstance(transactions, list) or len(transactions) != expected_transactions:
        raise PilotError("recorded Safe bundle has an unexpected transaction count")
    for transaction in transactions:
        if not isinstance(transaction, dict):
            raise PilotError("recorded Safe bundle transaction must be an object")
        require_address(transaction.get("to"), "Safe transaction target")
        data = require_text(transaction.get("data"), "Safe transaction calldata")
        if not data.startswith("0x") or transaction.get("value") != "0" or transaction.get("operation") != 0:
            raise PilotError("recorded Safe transaction encoding is invalid")
    return bundle


def verify_governance(config: PilotConfig, operation: str) -> dict[str, Any]:
    deployment = deployed_contracts(config)
    verifier = deployment["starkAttestationVerifierV2"]
    registry = deployment["starkClaimsRegistryV2"]
    if operation == "authorize":
        authorized = cast(
            config.rpc_url,
            "call",
            verifier,
            "authorizedRegistries(address)(bool)",
            registry,
        ) == "true"
        if not authorized:
            raise PilotError("registry authorization is not active")
        return {"registry_authorized": True, "registry": registry, "verifier": verifier}
    verifier_paused = cast(config.rpc_url, "call", verifier, "paused()(bool)") == "true"
    registry_paused = cast(config.rpc_url, "call", registry, "paused()(bool)") == "true"
    expected = operation == "pause"
    if verifier_paused != expected or registry_paused != expected:
        raise PilotError(f"{operation} governance state is not active on both contracts")
    return {"verifier_paused": verifier_paused, "registry_paused": registry_paused}


def signer_environment(config: PilotConfig) -> dict[str, str]:
    return {
        "STARK_ATTESTOR_MODE": "external_command",
        "STARK_ATTESTOR_SIGNER_PROGRAM": str(config.signer_program),
        "STARK_ATTESTOR_SIGNER_ARGS_JSON": json.dumps(config.signer_args, separators=(",", ":")),
        "STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON": json.dumps([config.signer_key_id]),
        "STARK_ATTESTOR_ADDRESS": config.attestor,
        "STARK_ATTESTOR_SIGNER_TIMEOUT_SECONDS": str(config.signer_timeout_seconds),
        "STARK_POLICY_MANIFEST_HASH": config.policy_manifest_hash,
    }


def signer_health(config: PilotConfig) -> dict[str, Any]:
    deployment = deployed_contracts(config)
    result = command(
        [
            "cargo",
            "run",
            "--quiet",
            "--features",
            "production-air-winterfell",
            "--bin",
            "validate_external_attestation_signer",
            "--",
            str(SEPOLIA_CHAIN_ID),
            deployment["starkAttestationVerifierV2"],
            deployment["starkClaimsRegistryV2"],
            config.policy_manifest_hash,
        ],
        cwd=ROOT / "stark-engine",
        env=signer_environment(config),
        timeout=config.signer_timeout_seconds + 900,
        label="external attestation signer health check",
    )
    try:
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise PilotError("external signer health command did not return summary JSON") from exc
    validate_signer_health_report(config, report)
    output = config.artifact_directory / "external_signer_health.json"
    write_json_atomic(output, report)
    return report


def validate_signer_health_report(config: PilotConfig, report: dict[str, Any]) -> None:
    if report.get("schema_version") != "stark-external-attestation-signer-health-v1":
        raise PilotError("external signer health report schema_version is invalid")
    if report.get("status") != "ok" or report.get("chain_id") != SEPOLIA_CHAIN_ID:
        raise PilotError("external signer health report is not approved for Sepolia")
    if report.get("signer_backend") != "external_command":
        raise PilotError("external signer health report used an unapproved signer backend")
    if report.get("key_id") != config.signer_key_id:
        raise PilotError("external signer health report used an unapproved key ID")
    if normalize_hex(str(report.get("attestor_address", ""))) != config.attestor:
        raise PilotError("external signer health report used an unexpected attestor")
    require_bytes32(report.get("request_id"), "external signer health request_id")
    for field in ("signature_validated", "low_s_validated", "recovery_validated"):
        if report.get(field) is not True:
            raise PilotError(f"external signer health report did not prove {field}")


def runtime_config(config: PilotConfig, artifact_dir: Path, deployment: dict[str, Any]) -> dict[str, Any]:
    rules = load_json(ROOT / "rust-engine" / "rules_active_v1.json")
    return {
        "claims_registry_address": "0x" + "00" * 20,
        "private_key": "ENV_ONLY_STARK_SUBMITTER_PRIVATE_KEY",
        "rpc_url": config.rpc_url,
        "transaction_value": config.value["transaction_value"],
        "enable_stark_sidecar_artifacts": False,
        "proof_backend": "stark_attested",
        "stark_engine_binary": str(
            (ROOT / "stark-engine" / "target" / "debug" / "execute_production_stark_settlement").resolve()
        ),
        "stark_claims_registry_address": deployment["starkClaimsRegistryV2"],
        "stark_attestation_verifier_address": deployment["starkAttestationVerifierV2"],
        "stark_nullifier_state_path": str((config.state_directory / "nullifier_state.json").resolve()),
        "stark_artifacts_directory": str(artifact_dir.resolve()),
        "stark_chain_id": SEPOLIA_CHAIN_ID,
        "stark_attestor_mode": "external_command",
        "stark_attestor_signer_program": str(config.signer_program),
        "stark_attestor_signer_args": config.signer_args,
        "stark_attestor_allowed_key_ids": [config.signer_key_id],
        "stark_attestor_address": config.attestor,
        "stark_attestor_signer_timeout_seconds": config.signer_timeout_seconds,
        "stark_policy_manifest_hash": config.policy_manifest_hash,
        "stark_finality_mode": "finalized",
        "stark_finality_timeout_seconds": 900,
        "stark_finality_poll_seconds": 12,
        "stark_allow_test_mined_finality": False,
        "rules_backend": "versioned_g1_g10",
        "rules_file": str((ROOT / "rust-engine" / "rules_active_v1.json").resolve()),
        "rules_sha256": rules["rules_sha256"],
    }


def reconcile_canary(
    config: PilotConfig,
    deployment: dict[str, Any],
    *,
    kind: str,
    receipt_path: Path,
    journal_path: Path,
) -> dict[str, Any]:
    artifact_dir = receipt_path.parent
    transition_path = artifact_dir / "nullifier_transition.json"
    report_path = artifact_dir / "reconciliation_report.json"
    environment = {
        "STARK_CHAIN_ID": str(SEPOLIA_CHAIN_ID),
        "STARK_FINALITY_MODE": "finalized",
        "STARK_FINALITY_TIMEOUT_SECONDS": "900",
        "STARK_FINALITY_POLL_SECONDS": "12",
    }
    binary = ROOT / "stark-engine" / "target" / "debug" / "reconcile_production_stark_settlement"
    arguments = [
        str(binary),
        str(journal_path),
        str(transition_path),
        str(config.state_directory / "nullifier_state.json"),
        str(report_path),
        deployment["starkClaimsRegistryV2"],
        config.rpc_url,
    ]
    command(arguments, env=environment, timeout=1_200, label=f"{kind} canary reconciliation")
    first = load_json(report_path)
    command(arguments, env=environment, timeout=1_200, label=f"{kind} idempotent reconciliation")
    second = load_json(report_path)
    if first.get("status") != "finalized_chain_and_local_state_reconciled":
        raise PilotError(f"{kind} reconciliation is not clean")
    if second.get("status") != "finalized_chain_and_local_state_reconciled":
        raise PilotError(f"{kind} idempotent reconciliation is not clean")
    if second.get("local_state_committed_now") is True:
        raise PilotError(f"{kind} reconciliation was not idempotent")
    return {
        "report": str(report_path.relative_to(ROOT)),
        "transaction_hash": second.get("transaction_hash"),
        "chain_root": second.get("chain_root"),
        "retry_count": second.get("retry_count"),
        "idempotent": True,
    }


def validate_canary_outputs(
    config: PilotConfig,
    deployment: dict[str, Any],
    *,
    kind: str,
    receipt: dict[str, Any],
    adjudication: dict[str, Any],
    denied_evidence: dict[str, Any] | None,
) -> None:
    if kind not in {"approved", "denied"}:
        raise PilotError("canary kind must be approved or denied")
    expected_decision = 1 if kind == "approved" else 0
    if receipt.get("schema_version") != "stark-production-settlement-receipt-v2":
        raise PilotError("Sepolia canary did not produce a governed V2 receipt")
    if receipt.get("decision") != expected_decision or receipt.get("finality_mode") != "finalized":
        raise PilotError(f"{kind} canary decision or finality is invalid")
    if receipt.get("finalized_on_chain") is not True or receipt.get("groth16_executed") is True:
        raise PilotError(f"{kind} canary did not preserve the STARK-only finalized boundary")
    if (
        receipt.get("proof_locally_verified") is not True
        or receipt.get("attestation_locally_validated") is not True
        or receipt.get("controlled_attestation_verification") is not True
        or receipt.get("native_on_chain_stark_verification") is not False
    ):
        raise PilotError(f"{kind} canary did not preserve the controlled-attestation trust boundary")
    if receipt.get("signer_backend") != "external_command":
        raise PilotError(f"{kind} canary did not use the approved external signer")
    if receipt.get("signer_key_id") != config.signer_key_id:
        raise PilotError(f"{kind} canary used an unapproved signer key ID")
    if normalize_hex(str(receipt.get("policy_manifest_hash", ""))) != config.policy_manifest_hash:
        raise PilotError(f"{kind} canary policy hash does not match the approved manifest")
    if (
        normalize_hex(str(receipt.get("verifier_address", "")))
        != normalize_hex(deployment["starkAttestationVerifierV2"])
        or normalize_hex(str(receipt.get("registry_address", "")))
        != normalize_hex(deployment["starkClaimsRegistryV2"])
    ):
        raise PilotError(f"{kind} canary settled against unexpected contracts")
    root_before = receipt.get("nullifier_root_before")
    root_after = receipt.get("nullifier_root_after")
    if kind == "denied" and root_before != root_after:
        raise PilotError("denied canary advanced the nullifier root")
    if kind == "approved" and root_before == root_after:
        raise PilotError("approved canary did not advance the nullifier root")
    if kind == "approved":
        if not isinstance(denied_evidence, dict):
            raise PilotError("approved canary lacks denied-canary evidence")
        if root_before != denied_evidence.get("nullifier_root_after"):
            raise PilotError("approved canary did not start from the finalized denied-canary root")
    expected_status = "APPROVED" if kind == "approved" else "DENIED"
    if adjudication.get("status") != expected_status or adjudication.get("tx_submitted") is not True:
        raise PilotError(f"{kind} adjudication result is inconsistent with the finalized settlement")


def run_canary(config: PilotConfig, state: dict[str, Any], kind: str) -> dict[str, Any]:
    require_action(state, "authorize")
    require_action(state, "signer-health")
    if kind not in {"approved", "denied"}:
        raise PilotError("canary kind must be approved or denied")
    if kind == "approved":
        denied_evidence = require_action(state, "canary-denied")["evidence"]
    else:
        denied_evidence = None
    action = f"canary-{kind}"
    if action in state.get("completed_actions", {}):
        return state["completed_actions"][action]["evidence"]
    deployment = deployed_contracts(config)
    if cast(config.rpc_url, "call", deployment["starkAttestationVerifierV2"], "paused()(bool)") == "true":
        raise PilotError("STARK verifier is paused; canary submission is blocked")
    if cast(config.rpc_url, "call", deployment["starkClaimsRegistryV2"], "paused()(bool)") == "true":
        raise PilotError("STARK registry is paused; canary submission is blocked")
    if cast(
        config.rpc_url,
        "call",
        deployment["starkAttestationVerifierV2"],
        "authorizedRegistries(address)(bool)",
        deployment["starkClaimsRegistryV2"],
    ) != "true":
        raise PilotError("STARK registry authorization is not active")
    command(
        ["cargo", "build"],
        cwd=ROOT / "rust-engine",
        env={"CARGO_TARGET_DIR": str(ROOT / "rust-engine" / "target")},
        timeout=1_800,
        label="rust-engine build",
    )
    command(
        [
            "cargo",
            "build",
            "--features",
            "production-air-winterfell",
            "--bin",
            "execute_production_stark_settlement",
            "--bin",
            "reconcile_production_stark_settlement",
        ],
        cwd=ROOT / "stark-engine",
        env={"CARGO_TARGET_DIR": str(ROOT / "stark-engine" / "target")},
        timeout=1_800,
        label="stark-engine production build",
    )
    work = config.artifact_directory / "canaries" / kind / "work"
    artifacts = config.artifact_directory / "canaries" / kind / "artifacts"
    work.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    claim_path = config.approved_claim_path if kind == "approved" else config.denied_claim_path
    shutil.copy2(claim_path, work / "claim_input.json")
    write_json_atomic(work / "config.json", runtime_config(config, artifacts, deployment))
    environment = signer_environment(config)
    environment["STARK_SUBMITTER_PRIVATE_KEY"] = config.environment_value("submitter_private_key_env")
    result = command(
        [str((ROOT / "rust-engine" / "target" / "debug" / "rust-engine").resolve())],
        cwd=work,
        env=environment,
        timeout=1_800,
        label=f"{kind} Sepolia canary",
    )
    receipt = load_json(artifacts / "settlement_receipt.json")
    adjudication = load_json(work / "adjudication_result.json")
    validate_canary_outputs(
        config,
        deployment,
        kind=kind,
        receipt=receipt,
        adjudication=adjudication,
        denied_evidence=denied_evidence,
    )
    log = artifacts / "runtime_stdout.log"
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    reconciliation = reconcile_canary(
        config,
        deployment,
        kind=kind,
        receipt_path=artifacts / "settlement_receipt.json",
        journal_path=artifacts / "settlement_journal.json",
    )
    return {
        "kind": kind,
        "status": "finalized",
        "transaction_hash": receipt.get("transaction_hash"),
        "claim_hash": receipt.get("claim_hash"),
        "batch_root": receipt.get("batch_root"),
        "nullifier_root_before": receipt.get("nullifier_root_before"),
        "nullifier_root_after": receipt.get("nullifier_root_after"),
        "receipt": str((artifacts / "settlement_receipt.json").relative_to(ROOT)),
        "journal": str((artifacts / "settlement_journal.json").relative_to(ROOT)),
        "adjudication_result": str((work / "adjudication_result.json").relative_to(ROOT)),
        "runtime_log_sha256": sha256_file(log),
        "groth16_executed": False,
        "native_on_chain_winterfell": False,
        "controlled_attestation": True,
        "external_signer_validated": True,
        "reconciliation": reconciliation,
    }


def reconcile_canaries(config: PilotConfig, state: dict[str, Any]) -> dict[str, Any]:
    denied = require_action(state, "canary-denied")["evidence"]
    approved = require_action(state, "canary-approved")["evidence"]
    deployment = deployed_contracts(config)
    if denied.get("nullifier_root_before") != denied.get("nullifier_root_after"):
        raise PilotError("denied canary reconciliation evidence advances the root")
    if approved.get("nullifier_root_before") != denied.get("nullifier_root_after"):
        raise PilotError("approved canary does not follow the denied canary")
    reports = []
    for kind, evidence in (("denied", denied), ("approved", approved)):
        reconciliation = evidence.get("reconciliation")
        if not isinstance(reconciliation, dict) or reconciliation.get("idempotent") is not True:
            raise PilotError(f"{kind} canary lacks clean idempotent reconciliation evidence")
        report = load_json(ROOT / reconciliation["report"])
        if report.get("status") != "finalized_chain_and_local_state_reconciled":
            raise PilotError(f"{kind} reconciliation report is not clean")
        reports.append({"kind": kind, **reconciliation})

    approved_reconciliation = reconcile_canary(
        config,
        deployment,
        kind="approved-final",
        receipt_path=ROOT / approved["receipt"],
        journal_path=ROOT / approved["journal"],
    )
    chain_root = cast(
        config.rpc_url,
        "call",
        deployment["starkClaimsRegistryV2"],
        "currentNullifierRoot()(bytes32)",
    ).lower()
    local_state = load_json(config.state_directory / "nullifier_state.json")
    local_root = str(local_state.get("root_bytes32", "")).lower()
    expected_root = str(approved.get("nullifier_root_after", "")).lower()
    if chain_root != expected_root or local_root != expected_root:
        raise PilotError("final chain and local roots do not match the approved canary")
    summary = {
        "schema_version": "localbce-stark-sepolia-canary-reconciliation-v1",
        "status": "clean",
        "chain_id": SEPOLIA_CHAIN_ID,
        "reports": reports,
        "final_idempotent_reconciliation": approved_reconciliation,
        "chain_nullifier_root": chain_root,
        "local_nullifier_root": local_root,
        "roots_match": True,
    }
    write_json_atomic(config.artifact_directory / "canary_reconciliation_summary.json", summary)
    return summary


def audit_package(config: PilotConfig, state: dict[str, Any]) -> dict[str, Any]:
    for action in (
        "local-gates",
        "deploy",
        "authorize",
        "signer-health",
        "canary-denied",
        "canary-approved",
        "reconcile",
        "pause",
        "unpause",
    ):
        require_action(state, action)
    public_files = [
        config.policy_manifest_path,
        config.deployment_pin_path,
        config.release_profile_path,
        config.deployment_path,
        config.artifact_directory / "local_gate_report.json",
    ]
    optional = [
        config.artifact_directory / "preflight_report.json",
        config.artifact_directory / "external_signer_health.json",
        config.artifact_directory / "canary_reconciliation_summary.json",
    ]
    public_files.extend(path for path in optional if path.exists())
    public_files.extend(sorted((config.artifact_directory / "local-gates").glob("*.log")))
    public_files.extend(sorted((config.artifact_directory / "safe-transactions").glob("*.json")))
    for action in ("canary-denied", "canary-approved"):
        completed = state.get("completed_actions", {}).get(action, {})
        evidence = completed.get("evidence", {}) if isinstance(completed, dict) else {}
        for key in ("receipt", "journal"):
            value = evidence.get(key)
            if isinstance(value, str):
                public_files.append(ROOT / value)
        reconciliation = evidence.get("reconciliation")
        if isinstance(reconciliation, dict) and isinstance(reconciliation.get("report"), str):
            public_files.append(ROOT / reconciliation["report"])
    public_files = list(dict.fromkeys(public_files))
    missing = [str(path) for path in public_files if not path.exists()]
    if missing:
        raise PilotError(f"audit package inputs are missing: {missing}")
    package_dir = config.artifact_directory / "audit-package"
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir(parents=True)
    entries = []
    secret_values = [
        os.environ.get(config.value[field], "")
        for field in (
            "rpc_url_env",
            "deployer_private_key_env",
            "submitter_private_key_env",
            "verification_api_key_env",
        )
    ]
    for source in public_files:
        content = source.read_bytes()
        for secret in secret_values:
            if len(secret) >= 8 and secret.encode() in content:
                raise PilotError(f"audit package source contains configured secret material: {source}")
        archive_name = str(source.relative_to(ROOT)).replace("\\", "/").replace("/", "__")
        destination = package_dir / archive_name
        shutil.copy2(source, destination)
        entries.append(
            {
                "name": source.name,
                "source": str(source.relative_to(ROOT)),
                "sha256": sha256_file(destination),
                "size_bytes": destination.stat().st_size,
            }
        )
    trust = {
        "winterfell_proof_generated_and_verified_locally": True,
        "on_chain_verification": "governed_secp256k1_controlled_attestation",
        "native_on_chain_winterfell": False,
        "legal_or_source_authenticity_proved_by_winterfell": False,
        "automatic_stark_to_groth16_fallback": False,
        "production_approved": False,
    }
    manifest = {
        "schema_version": "localbce-stark-sepolia-audit-package-v1",
        "source_commit": git("rev-parse", "HEAD"),
        "created_at": now_utc(),
        "chain_id": SEPOLIA_CHAIN_ID,
        "entries": sorted(entries, key=lambda item: item["name"]),
        "trust_boundary": trust,
        "open_external_gates": [
            "legal_approval_recorded",
            "independent_cryptographic_audit",
            "independent_solidity_audit",
            "operational_recovery_approval",
        ],
    }
    manifest["manifest_sha256"] = canonical_hash(manifest)
    write_json_atomic(package_dir / "audit_manifest.json", manifest)
    archive = config.artifact_directory / "localbce-stark-sepolia-audit-package.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        for path in sorted(package_dir.iterdir()):
            handle.write(path, arcname=path.name)
    return {
        "package": str(archive.relative_to(ROOT)),
        "package_sha256": sha256_file(archive),
        "manifest": str((package_dir / "audit_manifest.json").relative_to(ROOT)),
        "production_approved": False,
    }


def status(config: PilotConfig, state: dict[str, Any]) -> dict[str, Any]:
    profile = release_profile(config, state)
    return {
        "schema_version": "localbce-stark-sepolia-pilot-status-v1",
        "environment": config.value["environment"],
        "chain_id": SEPOLIA_CHAIN_ID,
        "source_commit": state["source_commit"],
        "completed_actions": sorted(state.get("completed_actions", {})),
        "blocked_reasons": state.get("blocked_reasons", []),
        "activation_gates": profile["activation_gates"],
        "current_backend": profile["current_backend"],
        "candidate_backend": profile["candidate_backend"],
        "production_usable": profile["production_usable"],
        "native_on_chain_winterfell": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "action",
        choices=(
            "validate-config",
            "preflight",
            "local-gates",
            "deploy",
            "prepare-safe",
            "verify-governance",
            "signer-health",
            "canary-denied",
            "canary-approved",
            "reconcile",
            "audit",
            "status",
            "validate-artifacts",
        ),
    )
    parser.add_argument("--operation", choices=("authorize", "pause", "unpause"))
    parser.add_argument("--phase", choices=("schedule", "execute"), default="execute")
    parser.add_argument("--allow-example", action="store_true")
    args = parser.parse_args()
    try:
        config = PilotConfig.load(args.config, allow_example=args.allow_example)
        if args.action == "validate-config":
            print(json.dumps({"status": "ok", "schema_version": CONFIG_SCHEMA}))
            return 0
        state = load_state(config)
        if args.action == "preflight":
            evidence = preflight(config)
            record_action(config, state, "preflight", evidence)
        elif args.action == "local-gates":
            evidence = run_local_gates(config)
            record_action(config, state, "local-gates", evidence)
        elif args.action == "deploy":
            evidence = deploy(config, state)
            record_action(config, state, "deploy", evidence)
        elif args.action == "prepare-safe":
            if not args.operation:
                raise PilotError("prepare-safe requires --operation")
            require_safe_action_prerequisites(state, args.operation, args.phase)
            action_name = f"prepare-{args.operation}-{args.phase}"
            completed = state.get("completed_actions", {}).get(action_name)
            if isinstance(completed, dict):
                evidence = completed["evidence"]
                validate_recorded_safe_bundle(config, evidence)
            else:
                evidence = safe_bundle(config, args.operation, args.phase)
                record_action(config, state, action_name, evidence)
        elif args.action == "verify-governance":
            if not args.operation:
                raise PilotError("verify-governance requires --operation")
            require_governance_verification_prerequisites(state, args.operation)
            evidence = verify_governance(config, args.operation)
            record_action(config, state, args.operation, evidence)
        elif args.action == "signer-health":
            require_action(state, "deploy")
            evidence = signer_health(config)
            record_action(config, state, "signer-health", evidence)
        elif args.action in {"canary-denied", "canary-approved"}:
            kind = args.action.removeprefix("canary-")
            evidence = run_canary(config, state, kind)
            record_action(config, state, args.action, evidence)
        elif args.action == "reconcile":
            evidence = reconcile_canaries(config, state)
            record_action(config, state, "reconcile", evidence)
        elif args.action == "audit":
            release_profile(config, state)
            evidence = audit_package(config, state)
            record_action(config, state, "audit", evidence)
        elif args.action == "validate-artifacts":
            validate_deployment_pin(load_json(config.deployment_pin_path), config)
            validate_live_release_profile(load_json(config.release_profile_path))
            evidence = {"deployment_pin": "ok", "release_profile": "ok"}
        else:
            evidence = status(config, state)
        release_profile(config, state)
        print(json.dumps({"status": "ok", "action": args.action, "evidence": evidence}, sort_keys=True))
        return 0
    except (PilotError, OSError, subprocess.SubprocessError) as exc:
        try:
            if "config" in locals() and "state" in locals():
                record_block(config, state, str(exc))
        except Exception:
            pass
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
