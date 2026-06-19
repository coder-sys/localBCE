from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json


@dataclass(frozen=True)
class BenefitAccumulator:
    member_id: str
    benefit_year: int
    annual_cap_cents: int
    paid_to_date_cents: int = 0
    deductible_remaining_cents: int = 0
    visit_limit: int | None = None
    visits_used: int = 0
    prior_authorization_required: bool = False
    prior_authorizations: tuple[str, ...] = ()

    def root(self) -> str:
        payload = {
            "member_id": self.member_id,
            "benefit_year": self.benefit_year,
            "annual_cap_cents": self.annual_cap_cents,
            "paid_to_date_cents": self.paid_to_date_cents,
            "deductible_remaining_cents": self.deductible_remaining_cents,
            "visit_limit": self.visit_limit,
            "visits_used": self.visits_used,
            "prior_authorization_required": self.prior_authorization_required,
            "prior_authorizations": list(self.prior_authorizations),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha256(encoded).hexdigest()


def apply_benefit_claim(
    accumulator: BenefitAccumulator,
    *,
    allowed_cents: int,
    visit_count: int = 1,
    prior_authorization: str | None = None,
    onchain_accumulator_root_before: str | None = None,
    onchain_accumulator_root_after: str | None = None,
) -> tuple[BenefitAccumulator, int]:
    if not onchain_accumulator_root_before or not onchain_accumulator_root_after:
        raise ValueError("accumulator_anchor_missing")
    if accumulator.root() != onchain_accumulator_root_before:
        raise ValueError("accumulator_root_before_not_onchain")
    if allowed_cents < 0:
        raise ValueError("allowed_amount_negative")
    if visit_count < 0:
        raise ValueError("visit_count_negative")
    if accumulator.prior_authorization_required and prior_authorization not in accumulator.prior_authorizations:
        raise ValueError("prior_authorization_missing_or_unrecognized")
    if accumulator.visit_limit is not None and accumulator.visits_used + visit_count > accumulator.visit_limit:
        raise ValueError("visit_limit_exceeded")

    patient_responsibility = min(accumulator.deductible_remaining_cents, allowed_cents)
    payable_cents = allowed_cents - patient_responsibility
    if accumulator.paid_to_date_cents + payable_cents > accumulator.annual_cap_cents:
        raise ValueError("annual_benefit_cap_exceeded")

    updated = replace(
        accumulator,
        paid_to_date_cents=accumulator.paid_to_date_cents + payable_cents,
        deductible_remaining_cents=accumulator.deductible_remaining_cents - patient_responsibility,
        visits_used=accumulator.visits_used + visit_count,
    )
    if updated.root() != onchain_accumulator_root_after:
        raise ValueError("accumulator_root_after_not_onchain")
    return updated, payable_cents
