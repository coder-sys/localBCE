from __future__ import annotations

from .models import AdjudicationResult


def route_appeal(result: AdjudicationResult) -> str:
    if result.approved:
        return "none"
    denial_reason = (result.denial_reason or "").strip().lower()
    if denial_reason in {"member_id_missing", "diagnosis_missing", "service_line_missing", "invalid_charge", "excessive_charge"}:
        return "cif_resubmission"
    if denial_reason in {"eligibility_inactive", "prior_authorization_required", "provider_not_enrolled"}:
        return "formal_appeal"
    if denial_reason in {"duplicate_claim", "program_integrity_hold"}:
        return "program_integrity"
    return "formal_appeal"
