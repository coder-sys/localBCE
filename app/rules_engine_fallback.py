from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Tuple

from .batch.tar_required import is_tar_required
from .models import AdjudicationResult, GateResult, SharedContext
from .money import MAX_AMOUNT_CENTS, MAX_AMOUNT_CENTS_EXCLUSIVE
from .service_line_canonical import cents


DEFAULT_FEE_SCHEDULE_CENTS = {
    "99213": 12500,
    "T1019": 12500,
    "S5102": 12500,
    "H2015": 12500,
}
MAX_POLICY_CENTS = MAX_AMOUNT_CENTS_EXCLUSIVE
_CODE_MAPPING: dict[str, Tuple[str, str]] | None = None


def gate(name: str, passed: bool, reason: str) -> GateResult:
    return GateResult(name, passed, "" if passed else reason)


def procedure_requires_prior_authorization(procedure_code: str, tar_required_codes=None) -> bool:
    return is_tar_required(procedure_code, tar_required_codes)


def _governed_fee_amount(fee_schedule: dict[str, int], procedure_code: str) -> int | None:
    if procedure_code not in fee_schedule:
        return None
    amount = fee_schedule[procedure_code]
    if isinstance(amount, bool) or not isinstance(amount, int):
        return None
    return amount if 0 <= amount < MAX_POLICY_CENTS else None


def _context_money_cents(ctx: SharedContext) -> tuple[int, list[tuple[int, int]]]:
    total = cents(ctx.total_charge)
    lines = [(cents(line.charge_amount), cents(line.units)) for line in ctx.service_lines]
    line_total = sum(charge for charge, _units in lines)
    if line_total > MAX_AMOUNT_CENTS:
        raise ValueError("claim_total_out_of_range")
    if total != line_total:
        raise ValueError("claim_total_mismatch")
    return total, lines


def evaluate_gates(ctx: SharedContext, tar_required_codes=None, fee_schedule_cents: dict[str, int] | None = None) -> List[GateResult]:
    fee_schedule = DEFAULT_FEE_SCHEDULE_CENTS if fee_schedule_cents is None else fee_schedule_cents
    total_charge_cents, line_money = _context_money_cents(ctx)
    gates = [
        gate("G1_MEMBER_ID_PRESENT", bool(ctx.member_id), "member_id_missing"),
        gate("G2_ELIGIBILITY_ACTIVE", ctx.flags.get("eligibility_active", False), "eligibility_inactive"),
        gate("G2B_PATIENT_NOT_DECEASED", ctx.flags.get("not_deceased", False), "patient_deceased"),
        gate("G3_PROVIDER_NPI_PRESENT", bool(ctx.provider.npi), "provider_npi_missing"),
        gate("G4_PROVIDER_ENROLLED", ctx.flags.get("provider_enrolled", False), "provider_not_enrolled"),
        gate("G4B_PROVIDER_NOT_SUSPENDED", ctx.flags.get("provider_not_suspended", False), "provider_suspended"),
        gate("G5_SERVICE_LINES_PRESENT", bool(ctx.service_lines), "service_line_missing"),
        gate("G6_DIAGNOSIS_PRESENT", bool(ctx.diagnoses), "diagnosis_missing"),
    ]
    tar_authorization_verified = ctx.fact_verification.get("tar_authorization") == "VERIFIED"
    pa_ok = all(
        _governed_fee_amount(fee_schedule, line.procedure_code) is None
        or not procedure_requires_prior_authorization(line.procedure_code, tar_required_codes)
        or (bool(line.prior_authorization) and tar_authorization_verified)
        for line in ctx.service_lines
    )
    gates.append(gate("G7_PRIOR_AUTH_WHEN_REQUIRED", pa_ok, "prior_authorization_required"))
    charge_valid = (
        total_charge_cents > 0
        and all(charge > 0 and units > 0 for charge, units in line_money)
    )
    gates.append(gate("G8A_CHARGE_VALID", charge_valid, "invalid_charge"))
    missing_fee_codes = sorted(
        {
            line.procedure_code
            for line in ctx.service_lines
            if _governed_fee_amount(fee_schedule, line.procedure_code) is None
        }
    )
    gates.append(gate("G8B_FEE_SCHEDULE_PRESENT", not missing_fee_codes, "fee_schedule_missing"))
    gates.append(gate("G9_NOT_DUPLICATE", not ctx.flags.get("duplicate_claim", False), "duplicate_claim"))
    gates.append(gate("G10_NO_PROGRAM_INTEGRITY_HOLD", not ctx.flags.get("program_integrity_hold", False), "program_integrity_hold"))
    return gates


def allowed_amount_cents(ctx: SharedContext, fee_schedule_cents: dict[str, int] | None = None) -> int:
    fee_schedule = DEFAULT_FEE_SCHEDULE_CENTS if fee_schedule_cents is None else fee_schedule_cents
    _total_charge_cents, line_money = _context_money_cents(ctx)
    total = 0
    for line, (line_charge_cents, _units_cents) in zip(ctx.service_lines, line_money, strict=True):
        allowed_cents = _governed_fee_amount(fee_schedule, line.procedure_code)
        if allowed_cents is None:
            raise ValueError(f"fee_schedule_missing:{line.procedure_code}")
        total += min(line_charge_cents, allowed_cents)
        if total >= MAX_POLICY_CENTS:
            raise ValueError("allowed_amount_out_of_range")
    return total


def _load_code_mapping() -> dict[str, Tuple[str, str]]:
    global _CODE_MAPPING
    if _CODE_MAPPING is None:
        mapping_path = Path(__file__).resolve().parents[1] / "rarc_mapping.tsv"
        with mapping_path.open(encoding="utf-8", newline="") as handle:
            _CODE_MAPPING = {
                row["reason"]: (row["carc"], row["rarc"])
                for row in csv.DictReader(handle, delimiter="\t")
            }
    return _CODE_MAPPING


def denial_codes(reason: str) -> Tuple[str, str]:
    return _load_code_mapping().get(reason, ("16", "N130"))


def adjudicate(ctx: SharedContext, tar_required_codes=None, fee_schedule_cents: dict[str, int] | None = None) -> AdjudicationResult:
    gates = evaluate_gates(ctx, tar_required_codes, fee_schedule_cents)
    failed = next((gate for gate in gates if not gate.passed), None)
    approved = failed is None
    reason = "" if approved else failed.reason
    carc, rarc = ("", "") if approved else denial_codes(reason)
    return AdjudicationResult(
        claim_id=ctx.claim_id,
        approved=approved,
        denial_reason=reason,
        gates=gates,
        carc=carc,
        rarc=rarc,
        total_charge=ctx.total_charge,
        payable_amount=(allowed_amount_cents(ctx, fee_schedule_cents) / 100) if approved else 0.0,
    )
