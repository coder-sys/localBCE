from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from app.production_readiness import REQUIRED_NONEMPTY_ENV, REQUIRED_PRODUCTION_ENV, production_readiness


HEX32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
STATUS_VALUES = {"open", "closed", "accepted_risk"}
MIN_SIGNERS = 3
MIN_THRESHOLD = 2
MIN_TIMELOCK_SECONDS = 72 * 60 * 60

EXPECTED_PUBLIC_INPUTS = (
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimRoot",
    "resultRoot",
    "paymentRoot",
    "dataAvailabilityRoot",
    "encryptedClaimDataRoot",
    "valueConservationCommitment",
    "paymentAmountCents",
)
FORBIDDEN_PRODUCTION_SOURCE_MARKERS = (".circom", "groth", "groth16")
DEV_ONLY_PROOF_SOURCE_MARKERS = ("blind-ledger-app-layer/zk-stark/", "blind-ledger-app-layer\\zk-stark\\", "winterfell", "f128")


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    errors: tuple[str, ...]


def _report(errors: Iterable[str]) -> ValidationReport:
    values = tuple(errors)
    return ValidationReport(not values, values)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid env line: {raw_line}")
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def validate_production_env_template(path: Path) -> ValidationReport:
    try:
        env = parse_env_file(path)
    except Exception as exc:
        return _report([str(exc)])
    required = {"BL_ENV", *REQUIRED_PRODUCTION_ENV.keys(), *REQUIRED_NONEMPTY_ENV}
    errors = [f"missing env key: {key}" for key in sorted(required) if key not in env]
    for key, expected in REQUIRED_PRODUCTION_ENV.items():
        if env.get(key) != expected:
            errors.append(f"{key} must be {expected}")
    if env.get("BL_ENV") != "production":
        errors.append("BL_ENV must be production")
    for forbidden in ("BL_ALLOW_TEST_DOUBLES", "BL_FORCE_PYTHON_RULES_ENGINE", "BL_ALLOW_LEGACY_PROOF_WRAPPER"):
        if env.get(forbidden, "").lower() in {"1", "true", "yes"}:
            errors.append(f"{forbidden} must not be enabled")
    return _report(errors)


def validate_production_env_values(env: Mapping[str, str]) -> ValidationReport:
    readiness = production_readiness(env)
    errors = list(readiness.blockers)
    for key, value in env.items():
        upper = str(value).upper()
        if upper.startswith("REPLACE_") or upper in {"TODO", "TBD", "PLACEHOLDER"}:
            errors.append(f"{key} still contains a placeholder value")
    return _report(errors)


def _valid_address(value: Any) -> bool:
    return isinstance(value, str) and bool(ADDRESS_RE.fullmatch(value))


def _valid_hex32(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX32_RE.fullmatch(value))


def validate_governance_config(payload: Mapping[str, Any]) -> ValidationReport:
    errors: list[str] = []
    if payload.get("schema_version") != "blind_ledger_governance_config_v1":
        errors.append("governance schema_version mismatch")
    for key in ("governance_multisig", "governance_timelock"):
        if not _valid_address(payload.get(key)):
            errors.append(f"{key} must be a 20-byte hex address")
    signers = payload.get("signers")
    if not isinstance(signers, list) or len(signers) < MIN_SIGNERS:
        errors.append(f"signers must contain at least {MIN_SIGNERS} addresses")
        signers = []
    if len({str(item).lower() for item in signers}) != len(signers):
        errors.append("signers must be unique")
    for signer in signers:
        if not _valid_address(signer):
            errors.append(f"invalid signer address: {signer}")
    try:
        threshold = int(payload.get("threshold"))
    except (TypeError, ValueError):
        threshold = 0
        errors.append("threshold must be an integer")
    if threshold < MIN_THRESHOLD:
        errors.append(f"threshold must be at least {MIN_THRESHOLD}")
    if signers and threshold > len(signers):
        errors.append("threshold cannot exceed signer count")
    try:
        timelock = int(payload.get("minimum_timelock_seconds"))
    except (TypeError, ValueError):
        timelock = 0
        errors.append("minimum_timelock_seconds must be an integer")
    if timelock < MIN_TIMELOCK_SECONDS:
        errors.append(f"minimum_timelock_seconds must be at least {MIN_TIMELOCK_SECONDS}")
    roles = payload.get("roles", {})
    if not isinstance(roles, dict):
        errors.append("roles must be an object")
    else:
        admin_accounts = set(_role_accounts(roles, "admin"))
        operator_accounts = set(_role_accounts(roles, "operator"))
        auditor_accounts = set(_role_accounts(roles, "auditor"))
        if admin_accounts & auditor_accounts:
            errors.append("admin and auditor roles must not overlap")
        if operator_accounts & auditor_accounts:
            errors.append("operator and auditor roles must not overlap")
    return _report(errors)


def _role_accounts(roles: Mapping[str, Any], key: str) -> list[str]:
    raw = roles.get(key, [])
    if not isinstance(raw, list):
        return []
    return [str(item).lower() for item in raw]


def validate_source_manifest(payload: Mapping[str, Any]) -> ValidationReport:
    errors: list[str] = []
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        return _report(["source manifest must contain non-empty sources"])
    declared_count = payload.get("source_count")
    if declared_count is not None and int(declared_count) != len(sources):
        errors.append("source_count does not match sources length")
    seen_urls: set[str] = set()
    for idx, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"source {idx} must be an object")
            continue
        url = str(source.get("url") or "")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host:
            errors.append(f"source {idx} must use https URL")
        if url in seen_urls:
            errors.append(f"duplicate source URL: {url}")
        seen_urls.add(url)
        if source.get("official") is not True:
            errors.append(f"source {idx} must be marked official")
        if not (host.endswith(".gov") or host in {"healthcare.gov"}):
            errors.append(f"source {idx} host is not an allowed official host: {host}")
        snapshot = source.get("content_sha256")
        if snapshot is not None and not _valid_hex32(str(snapshot)):
            errors.append(f"source {idx} content_sha256 must be sha256 hex")
    return _report(errors)


def validate_public_input_schema(payload: Mapping[str, Any]) -> ValidationReport:
    errors: list[str] = []
    if payload.get("schema_version") != "blind_ledger_native_stark_public_inputs_v1":
        errors.append("public input schema_version mismatch")
    fields = payload.get("fields")
    if not isinstance(fields, list):
        return _report([*errors, "fields must be a list"])
    if len(fields) != len(EXPECTED_PUBLIC_INPUTS):
        errors.append("public input field count mismatch")
    for index, expected_name in enumerate(EXPECTED_PUBLIC_INPUTS):
        if index >= len(fields) or not isinstance(fields[index], dict):
            errors.append(f"missing public input field {index}: {expected_name}")
            continue
        field = fields[index]
        if field.get("index") != index:
            errors.append(f"field {expected_name} has wrong index")
        if field.get("name") != expected_name:
            errors.append(f"field {index} name must be {expected_name}")
        if field.get("solidity_type") != ("uint256_as_bytes32" if expected_name == "paymentAmountCents" else "bytes32"):
            errors.append(f"field {expected_name} has wrong solidity_type")
    return _report(errors)


def validate_verifier_pin_manifest(payload: Mapping[str, Any], *, repo_root: Path) -> ValidationReport:
    errors: list[str] = []
    if payload.get("schema_version") != "blind_ledger_native_stark_verifier_pin_v1":
        errors.append("verifier pin schema_version mismatch")
    if str(payload.get("proof_anchor") or "") != "NATIVE_STARK_DIRECT_ANCHOR":
        errors.append("proof_anchor must be NATIVE_STARK_DIRECT_ANCHOR")
    if payload.get("is_legacy_proof_wrapper") is not False:
        errors.append("legacy proof wrapper flag must be false")
    if not _valid_hex32(payload.get("artifact_hash")):
        errors.append("artifact_hash must be 32-byte hex")
    for item in payload.get("source_hashes", []):
        if not isinstance(item, dict):
            errors.append("source_hashes entries must be objects")
            continue
        rel = str(item.get("path") or "")
        if not rel or ".." in Path(rel).parts or Path(rel).is_absolute():
            errors.append(f"unsafe source hash path: {rel}")
            continue
        rel_lower = rel.lower()
        if any(marker in rel_lower for marker in FORBIDDEN_PRODUCTION_SOURCE_MARKERS):
            errors.append(f"forbidden legacy proof source in verifier manifest: {rel}")
            continue
        if any(marker in rel_lower for marker in DEV_ONLY_PROOF_SOURCE_MARKERS):
            errors.append(f"dev-only proof source cannot be a production verifier artifact: {rel}")
            continue
        observed_path = repo_root / rel
        if not observed_path.exists():
            errors.append(f"source hash path missing: {rel}")
            continue
        expected = str(item.get("sha256") or "").lower().removeprefix("0x")
        if not HEX32_RE.fullmatch(expected):
            errors.append(f"invalid source hash for {rel}")
            continue
        import hashlib

        observed = hashlib.sha256(observed_path.read_bytes()).hexdigest()
        if observed != expected:
            errors.append(f"source hash mismatch for {rel}")
    return _report(errors)


def validate_monitoring_events(payload: Mapping[str, Any]) -> ValidationReport:
    errors: list[str] = []
    if payload.get("schema_version") != "blind_ledger_monitoring_events_v1":
        errors.append("monitoring schema_version mismatch")
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        return _report([*errors, "events must be non-empty"])
    seen: set[tuple[str, str]] = set()
    for event in events:
        if not isinstance(event, dict):
            errors.append("event entries must be objects")
            continue
        source = str(event.get("source") or "")
        name = str(event.get("name") or "")
        if not source or not name:
            errors.append("event source and name are required")
        key = (source, name)
        if key in seen:
            errors.append(f"duplicate monitoring event: {source}:{name}")
        seen.add(key)
        if event.get("severity") not in {"info", "warning", "critical"}:
            errors.append(f"invalid severity for event {source}:{name}")
        fields = event.get("required_fields")
        if not isinstance(fields, list) or not fields:
            errors.append(f"event {source}:{name} must list required_fields")
    return _report(errors)


def validate_launch_blockers(payload: Mapping[str, Any]) -> ValidationReport:
    errors: list[str] = []
    if payload.get("schema_version") != "blind_ledger_launch_blockers_v1":
        errors.append("launch blockers schema_version mismatch")
    blockers = payload.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        return _report([*errors, "blockers must be non-empty"])
    ids: set[str] = set()
    for blocker in blockers:
        if not isinstance(blocker, dict):
            errors.append("blocker entries must be objects")
            continue
        blocker_id = str(blocker.get("id") or "")
        if not blocker_id:
            errors.append("blocker id is required")
        if blocker_id in ids:
            errors.append(f"duplicate blocker id: {blocker_id}")
        ids.add(blocker_id)
        if blocker.get("status") not in STATUS_VALUES:
            errors.append(f"invalid blocker status: {blocker_id}")
        if not blocker.get("owner"):
            errors.append(f"blocker owner is required: {blocker_id}")
        if not blocker.get("exit_criteria"):
            errors.append(f"blocker exit_criteria is required: {blocker_id}")
    return _report(errors)
