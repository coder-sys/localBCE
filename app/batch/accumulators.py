from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json

from app.money import MAX_AMOUNT_CENTS


def _exact_nonnegative_int(label: str, value: object, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{label}_out_of_range")
    return value


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

    def __post_init__(self) -> None:
        if not isinstance(self.member_id, str) or not self.member_id:
            raise ValueError("member_id_invalid")
        _exact_nonnegative_int("benefit_year", self.benefit_year)
        if _exact_nonnegative_int("annual_cap_cents", self.annual_cap_cents, maximum=MAX_AMOUNT_CENTS) == 0:
            raise ValueError("annual_cap_cents_out_of_range")
        paid = _exact_nonnegative_int("paid_to_date_cents", self.paid_to_date_cents, maximum=MAX_AMOUNT_CENTS)
        _exact_nonnegative_int(
            "deductible_remaining_cents",
            self.deductible_remaining_cents,
            maximum=MAX_AMOUNT_CENTS,
        )
        if paid > self.annual_cap_cents:
            raise ValueError("paid_to_date_exceeds_annual_cap")
        visits = _exact_nonnegative_int("visits_used", self.visits_used)
        if self.visit_limit is not None:
            if type(self.visit_limit) is not int or self.visit_limit <= 0:
                raise ValueError("visit_limit_out_of_range")
            if visits > self.visit_limit:
                raise ValueError("visits_used_exceeds_limit")
        if type(self.prior_authorization_required) is not bool:
            raise ValueError("prior_authorization_required_not_bool")
        if not isinstance(self.prior_authorizations, tuple) or any(
            not isinstance(value, str) for value in self.prior_authorizations
        ):
            raise ValueError("prior_authorizations_invalid")

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


def preview_benefit_claim(
    accumulator: BenefitAccumulator,
    *,
    allowed_cents: int,
    visit_count: int = 1,
    prior_authorization: str | None = None,
) -> tuple[BenefitAccumulator, int]:
    _exact_nonnegative_int("allowed_cents", allowed_cents, maximum=MAX_AMOUNT_CENTS)
    _exact_nonnegative_int("visit_count", visit_count)
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
    return updated, payable_cents


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
    updated, payable_cents = preview_benefit_claim(
        accumulator,
        allowed_cents=allowed_cents,
        visit_count=visit_count,
        prior_authorization=prior_authorization,
    )
    if updated.root() != onchain_accumulator_root_after:
        raise ValueError("accumulator_root_after_not_onchain")
    return updated, payable_cents
