from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Tuple

from .models import AdjudicationResult, GateResult, SharedContext


PA_REQUIRED_PROCEDURES = {"T1019", "S5102", "H2015"}
_CODE_MAPPING: dict[str, Tuple[str, str]] | None = None


def gate(name: str, passed: bool, reason: str) -> GateResult:
    return GateResult(name, passed, "" if passed else reason)


def evaluate_gates(ctx: SharedContext) -> List[GateResult]:
    gates = [
        gate("G1_MEMBER_ID_PRESENT", bool(ctx.member_id), "member_id_missing"),
        gate("G2_ELIGIBILITY_ACTIVE", ctx.flags.get("eligibility_active", False), "eligibility_inactive"),
        gate("G3_PROVIDER_NPI_PRESENT", bool(ctx.provider.npi), "provider_npi_missing"),
        gate("G4_PROVIDER_ENROLLED", ctx.flags.get("provider_enrolled", False), "provider_not_enrolled"),
        gate("G5_SERVICE_LINES_PRESENT", bool(ctx.service_lines), "service_line_missing"),
        gate("G6_DIAGNOSIS_PRESENT", bool(ctx.diagnoses), "diagnosis_missing"),
    ]
    pa_ok = all(line.procedure_code not in PA_REQUIRED_PROCEDURES or line.prior_authorization for line in ctx.service_lines)
    gates.append(gate("G7_PRIOR_AUTH_WHEN_REQUIRED", pa_ok, "prior_authorization_required"))
    charge_valid = ctx.total_charge > 0 and all(line.charge_amount > 0 for line in ctx.service_lines)
    charge_within_allowable = all(line.charge_amount <= 5000 for line in ctx.service_lines)
    gates.append(gate("G8A_CHARGE_VALID", charge_valid, "invalid_charge"))
    gates.append(gate("G8B_CHARGE_WITHIN_ALLOWABLE", charge_within_allowable, "excessive_charge"))
    gates.append(gate("G9_NOT_DUPLICATE", not ctx.flags.get("duplicate_claim", False), "duplicate_claim"))
    gates.append(gate("G10_NO_PROGRAM_INTEGRITY_HOLD", not ctx.flags.get("program_integrity_hold", False), "program_integrity_hold"))
    return gates


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


def adjudicate(ctx: SharedContext) -> AdjudicationResult:
    gates = evaluate_gates(ctx)
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
        payable_amount=ctx.total_charge if approved else 0.0,
    )
