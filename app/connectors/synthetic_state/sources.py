from __future__ import annotations

from dataclasses import dataclass, field

from app.rules_engine_fallback import DEFAULT_FEE_SCHEDULE_CENTS


@dataclass(frozen=True)
class SyntheticOfficialSources:
    eligibility: dict[str, bool] = field(default_factory=dict)
    provider_status: dict[str, bool] = field(default_factory=dict)
    prior_auth: dict[str, bool] = field(default_factory=dict)
    fee_schedule_cents: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_FEE_SCHEDULE_CENTS))
    claim_history: dict[str, bool] = field(default_factory=dict)
    documents: dict[str, bool] = field(default_factory=dict)


def build_synthetic_official_sources(
    flags: dict[str, object] | None = None,
    *,
    fee_schedule_cents: dict[str, int] | None = None,
) -> SyntheticOfficialSources:
    clean = dict(flags or {})
    return SyntheticOfficialSources(
        eligibility={
            "eligibility_active": bool(clean.get("eligibility_active", False)),
            "not_deceased": bool(clean.get("not_deceased", False)),
        },
        provider_status={
            "provider_enrolled": bool(clean.get("provider_enrolled", False)),
            "provider_not_suspended": bool(clean.get("provider_not_suspended", False)),
        },
        fee_schedule_cents=dict(fee_schedule_cents or DEFAULT_FEE_SCHEDULE_CENTS),
        claim_history={"duplicate_claim": bool(clean.get("duplicate_claim", False))},
        documents={"program_integrity_hold": bool(clean.get("program_integrity_hold", False))},
    )
