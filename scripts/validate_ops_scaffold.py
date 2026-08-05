#!/usr/bin/env python3
"""Validate inactive ops scaffolding files.

This script is intentionally lightweight and standard-library only. It validates
planning scaffolds under ops/ without importing runtime, app-layer, or hardened
bundle code.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPS_DIR = ROOT / "ops"

REQUIRED_JSON_FILES = [
    "launch_blockers.json",
    "monitoring_events.json",
    "governance_config.example.json",
    "oracle_source_manifest.example.json",
    "verifier_artifact_pin.example.json",
    "policy_manifest.example.json",
    "stark_v2_deployment_pin.example.json",
    "stark_v2_release_profile.example.json",
]

EXAMPLE_ADDRESSES = {
    f"0x{digit * 40}" for digit in ("1", "2", "3", "4", "5")
}

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ALLOWED_SEVERITIES = {"critical", "warning", "info"}


class ValidationError(ValueError):
    """Raised when ops scaffold validation fails."""


def load_json(path: Path) -> Any:
    if not path.exists():
        raise ValidationError(f"missing required file: {path.relative_to(ROOT)}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"{path.relative_to(ROOT)} is not valid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ValidationError(f"{path.relative_to(ROOT)} must contain a JSON object")

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise ValidationError(f"{path.relative_to(ROOT)} must have schema_version")

    return data


def require_nonempty_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label} must be a non-empty string")


def require_bool(value: Any, label: str) -> None:
    if not isinstance(value, bool):
        raise ValidationError(f"{label} must be a boolean")


def validate_launch_blockers(data: dict[str, Any]) -> None:
    blockers = data.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        raise ValidationError("launch_blockers.json must include at least one blocker")

    open_blockers = 0
    for index, blocker in enumerate(blockers):
        if not isinstance(blocker, dict):
            raise ValidationError(f"launch blocker {index} must be an object")
        require_nonempty_string(blocker.get("id"), f"launch blocker {index}.id")
        require_nonempty_string(blocker.get("title"), f"launch blocker {index}.title")
        require_nonempty_string(blocker.get("status"), f"launch blocker {index}.status")
        require_nonempty_string(blocker.get("owner"), f"launch blocker {index}.owner")
        require_nonempty_string(
            blocker.get("exit_criteria"), f"launch blocker {index}.exit_criteria"
        )
        if blocker["status"] == "open":
            open_blockers += 1

    if open_blockers == 0:
        raise ValidationError("launch_blockers.json must include at least one open blocker")


def validate_monitoring_events(data: dict[str, Any]) -> None:
    events = data.get("events")
    if not isinstance(events, list) or not events:
        raise ValidationError("monitoring_events.json must include at least one event")

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValidationError(f"monitoring event {index} must be an object")
        require_nonempty_string(event.get("source"), f"monitoring event {index}.source")
        require_nonempty_string(event.get("name"), f"monitoring event {index}.name")
        require_nonempty_string(event.get("severity"), f"monitoring event {index}.severity")
        if event["severity"] not in ALLOWED_SEVERITIES:
            raise ValidationError(
                f"monitoring event {index}.severity must be one of "
                f"{sorted(ALLOWED_SEVERITIES)}"
            )

        required_fields = event.get("required_fields")
        if not isinstance(required_fields, list) or not required_fields:
            raise ValidationError(
                f"monitoring event {index}.required_fields must be a non-empty list"
            )
        for field_index, field in enumerate(required_fields):
            require_nonempty_string(
                field, f"monitoring event {index}.required_fields[{field_index}]"
            )


def collect_addresses(value: Any, path: str = "") -> list[tuple[str, str]]:
    addresses: list[tuple[str, str]] = []

    if isinstance(value, str) and value.startswith("0x"):
        addresses.append((path, value))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            addresses.extend(collect_addresses(item, f"{path}[{index}]"))
    elif isinstance(value, dict):
        for key, item in value.items():
            next_path = f"{path}.{key}" if path else key
            addresses.extend(collect_addresses(item, next_path))

    return addresses


def validate_governance_config(data: dict[str, Any]) -> None:
    addresses = collect_addresses(data)
    if not addresses:
        raise ValidationError("governance_config.example.json must include example addresses")

    for path, address in addresses:
        if not ADDRESS_RE.match(address):
            raise ValidationError(f"governance address {path} is not a 20-byte hex address")
        if address.lower() not in EXAMPLE_ADDRESSES:
            raise ValidationError(
                f"governance address {path} must be an example/demo placeholder address"
            )


def validate_oracle_source_manifest(data: dict[str, Any]) -> None:
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValidationError("oracle_source_manifest.example.json must include sources")

    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ValidationError(f"oracle source {index} must be an object")
        require_nonempty_string(source.get("name"), f"oracle source {index}.name")
        require_nonempty_string(source.get("url"), f"oracle source {index}.url")
        require_bool(source.get("official"), f"oracle source {index}.official")
        require_bool(source.get("required"), f"oracle source {index}.required")

        if not source["url"].startswith("https://"):
            raise ValidationError(f"oracle source {index}.url must use https")
        if source["required"] and source["official"] is not True:
            raise ValidationError(
                f"required oracle source {index} must have official=true"
            )


def validate_verifier_artifact_pin(data: dict[str, Any]) -> None:
    if data.get("production_usable") is not False:
        raise ValidationError(
            "verifier_artifact_pin.example.json must have production_usable=false"
        )


def validate_stark_v2_deployment_pin(data: dict[str, Any]) -> None:
    if data.get("production_usable") is not False:
        raise ValidationError(
            "stark_v2_deployment_pin.example.json must have production_usable=false"
        )
    if data.get("chain_id") != 11155111:
        raise ValidationError("stark_v2_deployment_pin.example.json must pin Sepolia chain_id")
    if data.get("openzeppelin_contracts_version") != "v5.6.1":
        raise ValidationError("stark_v2_deployment_pin.example.json must pin OpenZeppelin v5.6.1")


def validate_stark_v2_release_profile(data: dict[str, Any]) -> None:
    if data.get("production_usable") is not False:
        raise ValidationError(
            "stark_v2_release_profile.example.json must have production_usable=false"
        )
    if data.get("chain_id") != 11155111:
        raise ValidationError("stark_v2_release_profile.example.json must pin Sepolia chain_id")
    if data.get("current_backend") != "groth16":
        raise ValidationError("inactive release profile must keep groth16 as current_backend")
    if data.get("candidate_backend") != "stark_attested":
        raise ValidationError("release profile candidate_backend must be stark_attested")
    if data.get("automatic_fallback") is not False:
        raise ValidationError("release profile must prohibit automatic fallback")
    if data.get("rollback_mode") != "manual_governed":
        raise ValidationError("release profile rollback_mode must be manual_governed")
    if data.get("native_verifier_active") is not False:
        raise ValidationError("inactive release profile must not activate native verification")

    gates = data.get("activation_gates")
    if not isinstance(gates, dict) or not gates:
        raise ValidationError("release profile must define activation_gates")
    for name, value in gates.items():
        require_bool(value, f"release profile activation_gates.{name}")
    if all(gates.values()):
        raise ValidationError("example release profile must retain at least one open gate")


def validate() -> list[str]:
    loaded: dict[str, dict[str, Any]] = {}
    ok_messages: list[str] = []

    for filename in REQUIRED_JSON_FILES:
        data = load_json(OPS_DIR / filename)
        loaded[filename] = data
        ok_messages.append(f"[OK] {filename} exists, parses, and has schema_version")

    validate_launch_blockers(loaded["launch_blockers.json"])
    ok_messages.append("[OK] launch_blockers.json has at least one open blocker")

    validate_monitoring_events(loaded["monitoring_events.json"])
    ok_messages.append("[OK] monitoring_events.json event fields are valid")

    validate_governance_config(loaded["governance_config.example.json"])
    ok_messages.append("[OK] governance_config.example.json uses example/demo addresses")

    validate_oracle_source_manifest(loaded["oracle_source_manifest.example.json"])
    ok_messages.append("[OK] oracle_source_manifest.example.json required sources are official https URLs")

    validate_verifier_artifact_pin(loaded["verifier_artifact_pin.example.json"])
    ok_messages.append("[OK] verifier_artifact_pin.example.json is marked non-production")

    validate_stark_v2_deployment_pin(loaded["stark_v2_deployment_pin.example.json"])
    ok_messages.append("[OK] stark_v2_deployment_pin.example.json pins Sepolia and remains inactive")

    validate_stark_v2_release_profile(loaded["stark_v2_release_profile.example.json"])
    ok_messages.append("[OK] stark_v2_release_profile.example.json is gated with manual rollback")

    return ok_messages


def main() -> int:
    try:
        messages = validate()
    except ValidationError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    for message in messages:
        print(message)
    print("[OK] ops scaffold validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
