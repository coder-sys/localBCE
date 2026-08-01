"""Strict trust policy for off-chain proof qualification evidence.

The source-controlled registry activates at most one externally provisioned
policy digest.  The policy then binds every source, tool, parameter, build, and
verifier identity with SHA3-512.  This module deliberately has no discovery or
fallback path: an absent activation is a hard stop.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config" / "proving_evidence_registry.json"
POLICY_PATH_ENV = "BL_PROVING_EVIDENCE_POLICY"
LEGACY_TOOL_ENVIRONMENT = (
    "BL_SCARB_BIN_WSL",
    "BL_STWO_RUN_AND_PROVE_BIN_WSL",
    "BL_STWO_SIMPLE_BOOTLOADER_WSL",
    "BL_STWO_VERIFIER_BIN_WSL",
)
REGISTRY_SCHEMA = "blind_ledger_proving_evidence_registry_v1"
POLICY_SCHEMA = "blind_ledger_proving_evidence_policy_v1"
POLICY_STATUS = "AUTHORIZED_FOR_CONTROLLED_QUALIFICATION"
POLICY_PURPOSE = "OFFCHAIN_PROOF_QUALIFICATION"
VERIFIER_INTERFACE = "BL_STWO_INDEPENDENT_VERIFIER_V1"
MAX_POLICY_BYTES = 1024 * 1024
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class ProvingEvidencePolicy:
    path: Path
    sha3_512: str
    registry_sha3_512: str
    value: dict[str, Any]


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha3_512_bytes(value: bytes) -> str:
    return hashlib.sha3_512(value).hexdigest()


def sha3_512_file(path: Path) -> str:
    digest = hashlib.sha3_512()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest_sha3_512(root: Path) -> str:
    digest = hashlib.sha3_512()
    ignored = {".git", "target", "__pycache__"}
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root)
        if any(part in ignored for part in relative.parts):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _read_strict_json(path: Path, *, maximum_bytes: int = MAX_POLICY_BYTES) -> tuple[dict[str, Any], bytes]:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise RuntimeError(f"trusted evidence document is missing: {path}") from exc
    if size < 3 or size > maximum_bytes:
        raise RuntimeError(f"trusted evidence document has an invalid size: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"trusted evidence document is not strict UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"trusted evidence document must be a JSON object: {path}")
    if raw != canonical_json_bytes(value) + b"\n":
        raise RuntimeError(f"trusted evidence document is not canonical JSON: {path}")
    return value, raw


def read_canonical_json_object(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    value, _ = _read_strict_json(path, maximum_bytes=maximum_bytes)
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RuntimeError(f"{label} keys are invalid; missing={missing}, extra={extra}")


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object")
    return value


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise RuntimeError(f"{label} must be a lowercase SHA3-512 digest")
    if value == "0" * 128:
        raise RuntimeError(f"{label} must not be the all-zero digest")
    return value


def _require_wsl_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{label} must be a non-empty WSL path")
    parsed = PurePosixPath(value)
    if not parsed.is_absolute() or parsed.as_posix() != value or any(part in {".", ".."} for part in parsed.parts):
        raise RuntimeError(f"{label} must be a normalized absolute WSL path")
    return value


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError(f"{label} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RuntimeError(f"{label} is not a valid ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RuntimeError(f"{label} must be UTC")
    return parsed


def _validate_tool(value: object, label: str) -> dict[str, Any]:
    tool = _require_object(value, label)
    _require_exact_keys(tool, {"sha3_512", "wsl_path"}, label)
    _require_wsl_path(tool["wsl_path"], f"{label}.wsl_path")
    _require_digest(tool["sha3_512"], f"{label}.sha3_512")
    return tool


def _validate_policy_value(value: dict[str, Any], *, now: datetime | None = None) -> None:
    _require_exact_keys(
        value,
        {"build", "proof_system", "schema_version", "scope", "source", "status", "tools", "validity", "verification"},
        "policy",
    )
    if value["schema_version"] != POLICY_SCHEMA or value["status"] != POLICY_STATUS:
        raise RuntimeError("trusted evidence policy schema or authorization status is not approved")

    scope = _require_object(value["scope"], "policy.scope")
    _require_exact_keys(scope, {"production_usable", "purpose", "settlement_usable"}, "policy.scope")
    if scope != {"production_usable": False, "purpose": POLICY_PURPOSE, "settlement_usable": False}:
        raise RuntimeError("trusted evidence policy may only authorize non-production off-chain qualification")

    validity = _require_object(value["validity"], "policy.validity")
    _require_exact_keys(validity, {"not_after", "not_before", "revoked"}, "policy.validity")
    if validity["revoked"] is not False:
        raise RuntimeError("trusted evidence policy is revoked")
    not_before = _parse_utc(validity["not_before"], "policy.validity.not_before")
    not_after = _parse_utc(validity["not_after"], "policy.validity.not_after")
    current = now or datetime.now(timezone.utc)
    if not_before >= not_after or current < not_before or current >= not_after:
        raise RuntimeError("trusted evidence policy is stale or not yet valid")

    source = _require_object(value["source"], "policy.source")
    _require_exact_keys(
        source,
        {"artifact_id", "manifest_sha3_512", "root", "scarb_lock_sha3_512", "scarb_toml_sha3_512"},
        "policy.source",
    )
    if source["root"] != "zk-cairo-sharp":
        raise RuntimeError("trusted evidence policy source root is not zk-cairo-sharp")
    source_digest = _require_digest(source["manifest_sha3_512"], "policy.source.manifest_sha3_512")
    _require_digest(source["scarb_toml_sha3_512"], "policy.source.scarb_toml_sha3_512")
    _require_digest(source["scarb_lock_sha3_512"], "policy.source.scarb_lock_sha3_512")
    if _require_digest(source["artifact_id"], "policy.source.artifact_id") != source_digest:
        raise RuntimeError("policy.source.artifact_id must equal the source manifest digest")

    tools = _require_object(value["tools"], "policy.tools")
    _require_exact_keys(tools, {"bootloader_program", "prover", "scarb", "verifier"}, "policy.tools")
    scarb = _validate_tool(tools["scarb"], "policy.tools.scarb")
    prover = _validate_tool(tools["prover"], "policy.tools.prover")
    verifier = _validate_tool(tools["verifier"], "policy.tools.verifier")
    _validate_tool(tools["bootloader_program"], "policy.tools.bootloader_program")
    if prover["wsl_path"] == verifier["wsl_path"] or prover["sha3_512"] == verifier["sha3_512"]:
        raise RuntimeError("prover and verifier must be independently provisioned artifacts")
    if scarb["wsl_path"] in {prover["wsl_path"], verifier["wsl_path"]}:
        raise RuntimeError("Scarb must not alias the prover or verifier executable")

    proof_system = _require_object(value["proof_system"], "policy.proof_system")
    _require_exact_keys(
        proof_system,
        {"parameter_set_id", "parameters", "parameters_sha3_512", "program_hash_function", "proof_suite_id", "prover_artifact_id", "public_input_schema_id", "verifier_artifact_id"},
        "policy.proof_system",
    )
    for key in ("parameter_set_id", "parameters_sha3_512", "proof_suite_id", "prover_artifact_id", "public_input_schema_id", "verifier_artifact_id"):
        _require_digest(proof_system[key], f"policy.proof_system.{key}")
    parameters_digest = sha3_512_bytes(canonical_json_bytes(proof_system["parameters"]))
    if proof_system["parameters_sha3_512"] != parameters_digest or proof_system["parameter_set_id"] != parameters_digest:
        raise RuntimeError("policy proof parameters and parameter identity do not match")
    if proof_system["prover_artifact_id"] != prover["sha3_512"]:
        raise RuntimeError("policy prover artifact identity does not match the pinned prover")
    if proof_system["verifier_artifact_id"] != verifier["sha3_512"]:
        raise RuntimeError("policy verifier artifact identity does not match the pinned verifier")
    if not isinstance(proof_system["program_hash_function"], str) or not proof_system["program_hash_function"]:
        raise RuntimeError("policy proof program hash function must be explicit")

    build = _require_object(value["build"], "policy.build")
    _require_exact_keys(build, {"artifact_id", "executable_relative_path", "executable_sha3_512", "mode", "profile"}, "policy.build")
    if build["mode"] != "SCARB_OFFLINE_PINNED_INPUTS" or build["profile"] != "dev":
        raise RuntimeError("policy build must use the supported offline pinned-input dev profile")
    if build["executable_relative_path"] != "target/dev/batch_main.executable.json":
        raise RuntimeError("policy build executable path is unsupported")
    executable_digest = _require_digest(build["executable_sha3_512"], "policy.build.executable_sha3_512")
    if _require_digest(build["artifact_id"], "policy.build.artifact_id") != executable_digest:
        raise RuntimeError("policy build artifact identity does not match the executable digest")

    verification = _require_object(value["verification"], "policy.verification")
    _require_exact_keys(verification, {"interface", "success_marker"}, "policy.verification")
    if verification["interface"] != VERIFIER_INTERFACE:
        raise RuntimeError("policy verifier interface is unsupported")
    marker = verification["success_marker"]
    if not isinstance(marker, str) or not marker or len(marker) > 256 or any(char in marker for char in "\r\n\0"):
        raise RuntimeError("policy verifier success marker is invalid")


def reject_legacy_tool_overrides(environment: Mapping[str, str] | None = None) -> None:
    active = os.environ if environment is None else environment
    present = [name for name in LEGACY_TOOL_ENVIRONMENT if name in active]
    if present:
        raise RuntimeError(f"legacy trust-critical tool overrides are forbidden: {present}")


def load_approved_policy(policy_path: Path, *, application_root: Path = ROOT, now: datetime | None = None) -> ProvingEvidencePolicy:
    reject_legacy_tool_overrides()
    registry, registry_raw = _read_strict_json(REGISTRY_PATH, maximum_bytes=16 * 1024)
    _require_exact_keys(
        registry,
        {"activation_state", "active_policy_sha3_512", "production_usable", "schema_version"},
        "registry",
    )
    if registry["schema_version"] != REGISTRY_SCHEMA or registry["production_usable"] is not False:
        raise RuntimeError("proving evidence registry schema or production scope is invalid")
    active_digest = registry["active_policy_sha3_512"]
    if registry["activation_state"] != "ENABLED" or active_digest is None:
        raise RuntimeError("no independently provisioned proving evidence policy is activated")
    active_digest = _require_digest(active_digest, "registry.active_policy_sha3_512")

    root = application_root.resolve()
    try:
        resolved_policy = policy_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"approved proving evidence policy is missing: {policy_path}") from exc
    try:
        resolved_policy.relative_to(root)
    except ValueError:
        pass
    else:
        raise RuntimeError("proving evidence policy must be provisioned outside the application source tree")
    if not resolved_policy.is_file():
        raise RuntimeError(f"approved proving evidence policy is not a file: {resolved_policy}")
    value, raw = _read_strict_json(resolved_policy)
    actual_digest = sha3_512_bytes(raw)
    if actual_digest != active_digest:
        raise RuntimeError("proving evidence policy digest is altered or unapproved")
    _validate_policy_value(value, now=now)
    return ProvingEvidencePolicy(
        path=resolved_policy,
        sha3_512=actual_digest,
        registry_sha3_512=sha3_512_bytes(registry_raw),
        value=value,
    )


def policy_path_from_environment(environment: Mapping[str, str] | None = None) -> Path:
    active = os.environ if environment is None else environment
    value = active.get(POLICY_PATH_ENV)
    if not value:
        raise RuntimeError(f"{POLICY_PATH_ENV} is required")
    if "\0" in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{POLICY_PATH_ENV} contains forbidden characters")
    return Path(value)


def wsl_file_sha3_512(path: str, *, executable: bool) -> str:
    flag = "-x" if executable else "-f"
    test = subprocess.run(["wsl", "test", flag, path], capture_output=True, check=False, timeout=30)
    if test.returncode != 0:
        raise RuntimeError(f"pinned WSL artifact is missing or has the wrong mode: {path}")
    digest = hashlib.sha3_512()
    with tempfile.TemporaryFile() as error_stream:
        process = subprocess.Popen(
            ["wsl", "cat", "--", path],
            stdout=subprocess.PIPE,
            stderr=error_stream,
            shell=False,
        )
        assert process.stdout is not None
        for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
            digest.update(chunk)
        process.stdout.close()
        returncode = process.wait(timeout=120)
        if returncode != 0:
            error_stream.seek(0)
            detail = error_stream.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(f"unable to hash pinned WSL artifact {path}: {detail}")
    return digest.hexdigest()


def attest_policy(policy: ProvingEvidencePolicy, *, source_root: Path) -> dict[str, Any]:
    source = policy.value["source"]
    expected_root = (ROOT / source["root"]).resolve()
    if source_root.resolve() != expected_root:
        raise RuntimeError("trusted evidence source root does not match the application source root")
    actual_source = source_manifest_sha3_512(expected_root)
    if actual_source != source["manifest_sha3_512"]:
        raise RuntimeError("protected source manifest is altered or unapproved")
    for name, relative, expected in (
        ("Scarb.toml", "Scarb.toml", source["scarb_toml_sha3_512"]),
        ("Scarb.lock", "Scarb.lock", source["scarb_lock_sha3_512"]),
    ):
        path = expected_root / relative
        if not path.is_file() or sha3_512_file(path) != expected:
            raise RuntimeError(f"{name} is missing, altered, or unapproved")

    actual_tools: dict[str, str] = {}
    for name in ("scarb", "prover", "verifier", "bootloader_program"):
        record = policy.value["tools"][name]
        digest = wsl_file_sha3_512(record["wsl_path"], executable=name != "bootloader_program")
        if digest != record["sha3_512"]:
            raise RuntimeError(f"pinned {name} digest is altered or unapproved")
        actual_tools[name] = digest
    return {
        "policy_sha3_512": policy.sha3_512,
        "protected_source_manifest_sha3_512": actual_source,
        "scarb_lock_sha3_512": source["scarb_lock_sha3_512"],
        "scarb_toml_sha3_512": source["scarb_toml_sha3_512"],
        "tool_sha3_512": actual_tools,
    }


def trusted_manifest_bindings(policy: ProvingEvidencePolicy) -> dict[str, Any]:
    source = policy.value["source"]
    proof_system = policy.value["proof_system"]
    build = policy.value["build"]
    tools = policy.value["tools"]
    return {
        "bootloader_program_sha3_512": tools["bootloader_program"]["sha3_512"],
        "build_artifact_id": build["artifact_id"],
        "build_executable_sha3_512": build["executable_sha3_512"],
        "parameter_set_id": proof_system["parameter_set_id"],
        "parameters_sha3_512": proof_system["parameters_sha3_512"],
        "program_hash_function": proof_system["program_hash_function"],
        "proof_suite_id": proof_system["proof_suite_id"],
        "prover_artifact_id": proof_system["prover_artifact_id"],
        "public_input_schema_id": proof_system["public_input_schema_id"],
        "scarb_lock_sha3_512": source["scarb_lock_sha3_512"],
        "scarb_sha3_512": tools["scarb"]["sha3_512"],
        "scarb_toml_sha3_512": source["scarb_toml_sha3_512"],
        "source_artifact_id": source["artifact_id"],
        "source_manifest_sha3_512": source["manifest_sha3_512"],
        "verifier_artifact_id": proof_system["verifier_artifact_id"],
    }
