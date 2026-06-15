from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Mapping


PRODUCTION_ENV_VALUES = {"prod", "production"}
CANONICAL_PROOF_LANE = "CAIRO_STARK_NATIVE"
CANONICAL_FIELD_STRATEGY = "STARK_FIELD_END_TO_END"

REQUIRED_PRODUCTION_ENV = {
    "BL_PROOF_LANE": CANONICAL_PROOF_LANE,
    "BL_FIELD_STRATEGY": CANONICAL_FIELD_STRATEGY,
}

REQUIRED_NONEMPTY_ENV = (
    "BL_BINDING_CIRCUIT_AUDITED_SHA256",
    "BL_BATCH_BINDING_VERIFIER_KEY_SHA256",
    "BL_RAW_837_DERIVATION_CIRCUIT_SHA256",
    "BL_NULLIFIER_TRANSITION_CIRCUIT_SHA256",
    "BL_PAYMENT_RECONCILIATION_CIRCUIT_SHA256",
    "BL_NATIVE_STARK_VERIFIER_ADDRESS",
    "BL_ACCUMULATOR_ROOT",
    "BL_EFFECTIVE_RULESET_TIMELINE_ROOT",
    "BL_FEE_SCHEDULE_ROOT",
    "BL_ELIGIBILITY_ORACLE_ROOT",
    "BL_PROVIDER_STATUS_ORACLE_ROOT",
    "BL_PRIOR_AUTH_ORACLE_ROOT",
    "BL_ORACLE_IN_CIRCUIT_KEY_ROOT",
    "BL_SETTLEMENT_ADDRESS_BOOK_ROOT",
    "BL_DATA_AVAILABILITY_ROOT",
    "BL_GOVERNANCE_MULTISIG_ADDRESS",
    "BL_GOVERNANCE_TIMELOCK_ADDRESS",
    "BL_VERIFIER_TRUST_ROOT",
)


@dataclass(frozen=True)
class ProductionReadinessReport:
    production_mode: bool
    ready: bool
    blockers: tuple[str, ...]


def _is_production(env: Mapping[str, str]) -> bool:
    return env.get("BL_ENV", "").strip().lower() in PRODUCTION_ENV_VALUES


def production_readiness(env: Mapping[str, str] | None = None) -> ProductionReadinessReport:
    env = os.environ if env is None else env
    production_mode = _is_production(env)
    blockers: list[str] = []
    if production_mode:
        for key, expected in REQUIRED_PRODUCTION_ENV.items():
            actual = env.get(key, "").strip()
            if actual != expected:
                blockers.append(f"{key} must be {expected}")
        for key in REQUIRED_NONEMPTY_ENV:
            if not env.get(key, "").strip():
                blockers.append(f"{key} is required")
        if env.get("BL_ALLOW_STUBS", "").strip().lower() in {"1", "true", "yes"}:
            blockers.append("stubs are forbidden in production")
    return ProductionReadinessReport(production_mode, not blockers, tuple(blockers))


def assert_production_ready(env: Mapping[str, str] | None = None) -> None:
    report = production_readiness(env)
    if report.production_mode and not report.ready:
        raise RuntimeError("production_not_ready:" + ";".join(report.blockers))


def blockers_text(blockers: Iterable[str]) -> str:
    return "\n".join(f"- {item}" for item in blockers)
