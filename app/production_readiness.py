from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


PRODUCTION_ENV_VALUES = {"prod", "production"}
CANONICAL_PROOF_LANE = "CAIRO_STARK_NATIVE"
CANONICAL_FIELD_STRATEGY = "STARK_FIELD_END_TO_END"
CANONICAL_HASH_STRATEGY = "POSEIDON_STARK_FIELD_DOMAIN_SEPARATED"
CANONICAL_ONCHAIN_ANCHOR = "NATIVE_STARK_DIRECT_ANCHOR"

REQUIRED_PRODUCTION_ENV = {
    "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
    "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
    "BL_HASH_STRATEGY": CANONICAL_HASH_STRATEGY,
    "BL_ONCHAIN_PROOF_ANCHOR": CANONICAL_ONCHAIN_ANCHOR,
}

REQUIRED_NONEMPTY_ENV = (
    "BL_BINDING_CIRCUIT_AUDITED_SHA256",
    "BL_BATCH_BINDING_VERIFIER_KEY_SHA256",
    "BL_RAW_837_DERIVATION_CIRCUIT_SHA256",
    "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256",
    "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256",
    "BL_BATCH_AGGREGATOR_CIRCUIT_SHA256",
    "BL_VALUE_CONSERVATION_CIRCUIT_SHA256",
    "BL_AGGREGATION_VALUE_CONSERVATION_ROOT",
    "BL_RULE_CROSSWALK_HASH",
    "BL_LANE_DECISION_V2_SIGNED_SHA256",
    "BL_RULE_RATIFICATION_PUBLIC_KEYS_ROOT",
    "BL_NATIVE_STARK_VERIFIER_ADDRESS",
    "BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256",
    "BL_ACCUMULATOR_ROOT",
    "BL_AUDIT_DATA_ENCRYPTION_KEY_ROOT",
    "BL_NULLIFIER_NAMESPACE_ROOT",
    "BL_EFFECTIVE_RULESET_TIMELINE_ROOT",
    "BL_POLICY_ROOT",
    "BL_ELIGIBILITY_ORACLE_ROOT",
    "BL_PROVIDER_STATUS_ORACLE_ROOT",
    "BL_PRIOR_AUTH_ORACLE_ROOT",
    "BL_ORACLE_IN_CIRCUIT_KEY_ROOT",
    "BL_SETTLEMENT_ADDRESS_BOOK_ROOT",
    "BL_DATA_AVAILABILITY_ROOT",
    "BL_DENIAL_ATTESTATION_ROOT",
    "BL_FORCED_INCLUSION_QUEUE_ROOT",
    "BL_GOVERNANCE_MULTISIG_ADDRESS",
    "BL_GOVERNANCE_TIMELOCK_ADDRESS",
    "BL_VERIFIER_TRUST_ROOT",
)
REQUIRED_ADDRESS_ENV = {
    "BL_NATIVE_STARK_VERIFIER_ADDRESS",
    "BL_GOVERNANCE_MULTISIG_ADDRESS",
    "BL_GOVERNANCE_TIMELOCK_ADDRESS",
}
HEX32_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

LEGACY_PROOF_MARKERS = ("GRO" + "TH16", "PL" + "ONK", "BN" + "254", "CIR" + "COM")
UNSUPPORTED_PRODUCTION_PROOF_MARKERS = ("WINTERFELL", "F128", "ZK-STARK")
FORBIDDEN_PRODUCTION_SOURCE_MARKERS = (".CIRCOM", "GRO" + "TH", "GRO" + "TH16")


@dataclass(frozen=True)
class ProductionReadinessReport:
    production_mode: bool
    ready: bool
    blockers: tuple[str, ...]


def _is_production(env: Mapping[str, str]) -> bool:
    return env.get("BL_ENV", "").strip().lower() in PRODUCTION_ENV_VALUES


def _contains_legacy_proof_marker(value: str) -> bool:
    upper = value.upper()
    return any(marker in upper for marker in LEGACY_PROOF_MARKERS)


def _contains_unsupported_production_marker(value: str) -> bool:
    upper = value.upper()
    return any(marker in upper for marker in UNSUPPORTED_PRODUCTION_PROOF_MARKERS)


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _forbidden_production_sources(repo_root: Path) -> tuple[str, ...]:
    if not repo_root.exists():
        return ()
    found: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        upper = rel.upper()
        if any(marker in upper for marker in FORBIDDEN_PRODUCTION_SOURCE_MARKERS):
            found.append(rel)
    return tuple(sorted(found))


def _launch_blocker_errors(repo_root: Path) -> tuple[str, ...]:
    manifest_path = repo_root / "ops" / "launch_blockers.json"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return (f"launch blocker manifest is unavailable or invalid: {type(exc).__name__}",)
    if not isinstance(payload, dict) or payload.get("schema_version") != "blind_ledger_launch_blockers_v1":
        return ("launch blocker manifest schema_version mismatch",)
    blockers = payload.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        return ("launch blocker manifest must contain blockers",)
    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(blockers):
        if not isinstance(item, dict):
            errors.append(f"launch blocker entry {index} is invalid")
            continue
        blocker_id = str(item.get("id") or "").strip()
        status = str(item.get("status") or "").strip()
        if not blocker_id:
            errors.append(f"launch blocker entry {index} has no id")
            continue
        if blocker_id in seen_ids:
            errors.append(f"duplicate launch blocker id: {blocker_id}")
            continue
        seen_ids.add(blocker_id)
        if status != "closed":
            errors.append(f"launch blocker {blocker_id} is not closed")
    return tuple(errors)


def production_readiness(env: Mapping[str, str] | None = None, *, repo_root: Path | None = None) -> ProductionReadinessReport:
    env = os.environ if env is None else env
    production_mode = _is_production(env)
    blockers: list[str] = []
    if production_mode:
        for key, expected in REQUIRED_PRODUCTION_ENV.items():
            actual = env.get(key, "").strip()
            if actual != expected:
                blockers.append(f"{key} must be {expected}")
        for key in REQUIRED_NONEMPTY_ENV:
            actual = env.get(key, "").strip()
            if not actual:
                blockers.append(f"{key} is required")
            elif key in REQUIRED_ADDRESS_ENV and not ADDRESS_RE.fullmatch(actual):
                blockers.append(f"{key} must be a 20-byte hex address")
            elif key not in REQUIRED_ADDRESS_ENV and not HEX32_RE.fullmatch(actual):
                blockers.append(f"{key} must be a 32-byte hex value")
        if env.get("BL_ALLOW_TEST_DOUBLES", "").strip().lower() in {"1", "true", "yes"}:
            blockers.append("test doubles are forbidden in production")
        if env.get("BL_FORCE_PYTHON_RULES_ENGINE", "").strip().lower() in {"1", "true", "yes"}:
            blockers.append("forced Python rules engine is forbidden in production")
        if env.get("BL_ALLOW_LEGACY_PROOF_WRAPPER", "").strip().lower() in {"1", "true", "yes"}:
            blockers.append("legacy proof wrapper is forbidden in production")
        if env.get("BL_LEGACY_PROOF_WRAPPER_ADDRESS", "").strip():
            blockers.append("legacy proof wrapper address is forbidden in production")
        for key, value in env.items():
            if _contains_legacy_proof_marker(str(key)) or _contains_legacy_proof_marker(str(value)):
                blockers.append(f"legacy proof marker is forbidden in production: {key}")
            if _contains_unsupported_production_marker(str(key)) or _contains_unsupported_production_marker(str(value)):
                blockers.append(f"unsupported dev proof lane is forbidden in production: {key}")
        scan_root = _default_repo_root() if repo_root is None else repo_root
        blockers.extend(_launch_blocker_errors(scan_root))
        # The source walk is the expensive gate.  It cannot turn an existing
        # no-go into a go, so run it only after every cheaper fail-closed gate
        # has passed.  A candidate that could otherwise be ready still receives
        # the complete forbidden-source scan.
        if not blockers:
            for rel in _forbidden_production_sources(scan_root):
                blockers.append(f"forbidden proof source present in production build: {rel}")
    return ProductionReadinessReport(production_mode, not blockers, tuple(blockers))


def assert_production_ready(env: Mapping[str, str] | None = None, *, repo_root: Path | None = None) -> None:
    report = production_readiness(env, repo_root=repo_root)
    if report.production_mode and not report.ready:
        raise RuntimeError("production_not_ready:" + ";".join(report.blockers))


def blockers_text(blockers: Iterable[str]) -> str:
    return "\n".join(f"- {item}" for item in blockers)
