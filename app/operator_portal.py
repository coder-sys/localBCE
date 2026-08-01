from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import threading
from binascii import Error as BinasciiError
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from fastapi import FastAPI, HTTPException
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, SubmittedBatch, submit_batches
from app.batch.proof_status import REAL_PROOF_REQUIRED_STATUS
from app.operational_readiness import load_json, validate_launch_blockers, validate_verifier_pin_manifest
from app.production_readiness import CANONICAL_ONCHAIN_ANCHOR, CANONICAL_PROOF_LANE, production_readiness
from app.service_line_canonical import cents


APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = APP_ROOT / "operator_portal"
PROVIDER_STATIC_ROOT = APP_ROOT / "provider_portal"
SHARED_STATIC_ROOT = APP_ROOT / "portal_shared"
PROVIDER_PACKET_STORAGE_ROOT = APP_ROOT / "cache" / "provider_packets"
SAMPLE_CLAIM_PATH = APP_ROOT / "sample_claim_input.json"
OPS_ROOT = APP_ROOT.parent / "ops"
PRODUCTION_ENVS = {"prod", "production"}
LOCAL_PORTAL_ENVS = {"dev", "development", "local", "test"}
PORTAL_ADMIN_TOKEN_ENV = "BL_ADMIN_OPERATOR_PORTAL_TOKEN"
PORTAL_OPERATOR_TOKEN_ENV = "BL_LOCAL_OPERATOR_PORTAL_TOKEN"
PORTAL_AUDITOR_TOKEN_ENV = "BL_AUDITOR_OPERATOR_PORTAL_TOKEN"
PROVIDER_PORTAL_TOKEN_ENV = "BL_PROVIDER_PORTAL_TOKEN"
PROVIDER_PORTAL_TENANTS_ENV = "BL_PROVIDER_PORTAL_TENANTS_JSON"
PORTAL_STATE_PATH_ENV = "BL_OPERATOR_PORTAL_STATE_PATH"
PROVIDER_PORTAL_PRINCIPAL = "provider@example.org"
PROVIDER_PORTAL_LOCAL_TOKEN = "local-provider-token"
PROVIDER_PORTAL_LOCAL_TENANTS: dict[str, dict[str, str]] = {
    "provider@example.org": {
        "token": PROVIDER_PORTAL_LOCAL_TOKEN,
        "name": "North Valley Home Health",
        "npi": "1999999984",
    },
    "east-bay@example.org": {
        "token": "local-east-bay-provider-token",
        "name": "East Bay Home Care",
        "npi": "1666666650",
    },
    "golden-state@example.org": {
        "token": "local-golden-state-provider-token",
        "name": "Golden State Therapy",
        "npi": "1555555542",
    },
    "capital-family@example.org": {
        "token": "local-capital-family-provider-token",
        "name": "Capital Family Services",
        "npi": "1333333326",
    },
}
PROVIDER_ATTACHMENT_MAX_BYTES = 5 * 1024 * 1024
PROVIDER_ATTACHMENT_MAX_BASE64_CHARS = ((PROVIDER_ATTACHMENT_MAX_BYTES + 2) // 3) * 4
PROVIDER_ATTACHMENT_MAX_COUNT = 8
PORTAL_EXCHANGE_STATE_PATH = APP_ROOT / "cache" / "operator_portal_exchange_state.json"
PORTAL_TOKEN_ENV_BY_PRINCIPAL = {
    "admin@example.gov": PORTAL_ADMIN_TOKEN_ENV,
    "operator@example.gov": PORTAL_OPERATOR_TOKEN_ENV,
    "auditor@example.gov": PORTAL_AUDITOR_TOKEN_ENV,
}
PORTAL_LOCAL_TOKEN_BY_PRINCIPAL = {
    "admin@example.gov": "local-admin-portal-token",
    "operator@example.gov": "local-operator-token",
    "auditor@example.gov": "local-auditor-portal-token",
}


REASON_GUIDE: dict[str, dict[str, Any]] = {
    "member_id_missing": {
        "category": "Missing member information",
        "summary": "The claim is missing the member identifier needed for eligibility and history matching.",
        "required_items": ["Member ID", "Corrected 837 claim"],
        "owner_queue": "Documents",
        "priority": "High",
        "next_actions": [
            {"id": "request_member_id", "label": "Request member ID", "detail": "Ask the submitter for a corrected claim with the member identifier."},
            {"id": "check_member_lookup", "label": "Check eligibility file", "detail": "Search eligibility records for a matching subscriber."},
            {"id": "prepare_resubmission", "label": "Prepare resubmission", "detail": "Hold for CIF or corrected-claim resubmission once the member ID is present."},
        ],
    },
    "diagnosis_missing": {
        "category": "Missing clinical information",
        "summary": "The claim has no usable diagnosis code.",
        "required_items": ["Diagnosis code", "Corrected service documentation"],
        "owner_queue": "Documents",
        "priority": "High",
        "next_actions": [
            {"id": "request_diagnosis", "label": "Request diagnosis", "detail": "Ask the provider for a corrected diagnosis field."},
            {"id": "prepare_resubmission", "label": "Prepare resubmission", "detail": "Queue for corrected-claim review when documentation arrives."},
        ],
    },
    "service_line_missing": {
        "category": "Missing service detail",
        "summary": "The claim does not include a complete service line.",
        "required_items": ["Procedure/service line", "Units", "Charge amount"],
        "owner_queue": "Documents",
        "priority": "High",
        "next_actions": [
            {"id": "request_service_line", "label": "Request service line", "detail": "Ask the provider to resubmit with procedure, units, and charge."},
            {"id": "prepare_resubmission", "label": "Prepare resubmission", "detail": "Move to resubmission review once the line is complete."},
        ],
    },
    "provider_npi_missing": {
        "category": "Missing provider information",
        "summary": "The rendering provider NPI is missing or invalid.",
        "required_items": ["Rendering provider NPI", "Provider record check"],
        "owner_queue": "Provider enrollment",
        "priority": "High",
        "next_actions": [
            {"id": "request_provider_npi", "label": "Request NPI", "detail": "Ask for corrected rendering provider information."},
            {"id": "verify_provider_record", "label": "Verify provider record", "detail": "Check provider enrollment records before resubmission."},
        ],
    },
    "eligibility_inactive": {
        "category": "Eligibility review",
        "summary": "Eligibility was not active for the service date.",
        "required_items": ["Eligibility record", "Coverage dates", "Service date confirmation"],
        "owner_queue": "Eligibility",
        "priority": "Medium",
        "next_actions": [
            {"id": "verify_eligibility", "label": "Verify eligibility", "detail": "Check eligibility source records for the service date."},
            {"id": "request_coverage_docs", "label": "Request coverage docs", "detail": "Ask for documentation if coverage should have been active."},
            {"id": "route_formal_appeal", "label": "Route appeal", "detail": "Send to formal appeal if the provider disputes eligibility."},
        ],
    },
    "provider_not_enrolled": {
        "category": "Provider enrollment review",
        "summary": "The provider was not confirmed as enrolled for payment.",
        "required_items": ["Provider enrollment record", "Effective date", "Provider NPI"],
        "owner_queue": "Provider enrollment",
        "priority": "Medium",
        "next_actions": [
            {"id": "verify_provider_enrollment", "label": "Verify enrollment", "detail": "Check provider enrollment and effective dates."},
            {"id": "request_provider_docs", "label": "Request provider docs", "detail": "Ask for enrollment documentation if records are incomplete."},
            {"id": "route_formal_appeal", "label": "Route appeal", "detail": "Route to formal appeal if enrollment is disputed."},
        ],
    },
    "provider_suspended": {
        "category": "Provider exclusion review",
        "summary": "The provider is attested as suspended or excluded and cannot be paid automatically.",
        "required_items": ["Provider suspension or exclusion record", "Effective date", "Reviewer sign-off"],
        "owner_queue": "Provider enrollment",
        "priority": "High",
        "next_actions": [
            {"id": "verify_provider_record", "label": "Verify provider record", "detail": "Confirm the suspension or exclusion record and dates."},
            {"id": "route_program_integrity", "label": "Route integrity", "detail": "Send to program integrity if payment was attempted for an excluded provider."},
            {"id": "hold_payment", "label": "Hold payment", "detail": "Keep payment closed until the provider status is cleared."},
        ],
    },
    "patient_deceased": {
        "category": "Eligibility review",
        "summary": "The patient is attested as deceased for the claim context and cannot be paid automatically.",
        "required_items": ["Death-master or eligibility record", "Service date confirmation", "Reviewer note"],
        "owner_queue": "Eligibility",
        "priority": "High",
        "next_actions": [
            {"id": "verify_eligibility", "label": "Verify eligibility", "detail": "Confirm the death-master and eligibility records for the service date."},
            {"id": "request_coverage_docs", "label": "Request coverage docs", "detail": "Ask for corrected coverage documentation if the record is wrong."},
            {"id": "hold_payment", "label": "Hold payment", "detail": "Keep payment closed until eligibility is corrected."},
        ],
    },
    "prior_authorization_required": {
        "category": "Missing authorization",
        "summary": "The service requires prior authorization and no usable authorization was found.",
        "required_items": ["Prior authorization number", "Authorization effective dates", "Procedure match"],
        "owner_queue": "Authorizations",
        "priority": "High",
        "next_actions": [
            {"id": "request_prior_auth", "label": "Request prior auth", "detail": "Ask for the authorization number and supporting document."},
            {"id": "verify_auth_match", "label": "Verify authorization", "detail": "Confirm the authorization covers the billed service and date."},
            {"id": "prepare_resubmission", "label": "Prepare resubmission", "detail": "Queue for resubmission once authorization is attached."},
        ],
    },
    "invalid_charge": {
        "category": "Rules coverage review",
        "summary": "The charge is missing or malformed, and the charge mapping still needs policy ratification.",
        "required_items": ["Corrected charge", "Policy reviewer sign-off"],
        "owner_queue": "Policy review",
        "priority": "Medium",
        "next_actions": [
            {"id": "request_corrected_charge", "label": "Request corrected charge", "detail": "Ask the provider for a corrected amount."},
            {"id": "assign_policy_review", "label": "Assign policy review", "detail": "Send to policy review before automated handling."},
        ],
    },
    "duplicate_claim": {
        "category": "Duplicate review",
        "summary": "The claim appears to duplicate a previously processed or in-process claim.",
        "required_items": ["Claim history", "Provider explanation if disputed"],
        "owner_queue": "Duplicate review",
        "priority": "Medium",
        "next_actions": [
            {"id": "compare_claim_history", "label": "Compare history", "detail": "Review matching claim history before release."},
            {"id": "route_program_integrity", "label": "Route integrity", "detail": "Send to program integrity if the duplicate pattern is suspicious."},
        ],
    },
    "program_integrity_hold": {
        "category": "Program integrity",
        "summary": "The claim is on a program integrity hold.",
        "required_items": ["Integrity review decision", "Reviewer note"],
        "owner_queue": "Program integrity",
        "priority": "High",
        "next_actions": [
            {"id": "route_program_integrity", "label": "Route integrity", "detail": "Send to program integrity review."},
            {"id": "hold_payment", "label": "Hold payment", "detail": "Keep payment closed until integrity review clears."},
        ],
    },
}

QUARANTINE_GUIDE: dict[str, dict[str, Any]] = {
    "ingestion_failed": {
        "category": "Unreadable claim file",
        "summary": "The claim file could not be parsed as a complete 837 transaction.",
        "required_items": ["Corrected 837 file", "Control segment check"],
        "owner_queue": "Documents",
        "priority": "High",
        "next_actions": [
            {"id": "request_corrected_837", "label": "Request corrected 837", "detail": "Ask the sender for a corrected electronic claim."},
            {"id": "check_submitter_file", "label": "Check file envelope", "detail": "Review ISA/GS/ST and trailer segment counts."},
        ],
    },
    "adjudication_failed": {
        "category": "Data validation review",
        "summary": "The claim passed initial parsing but failed validation before adjudication.",
        "required_items": ["Corrected claim data", "Operator review note"],
        "owner_queue": "Documents",
        "priority": "High",
        "next_actions": [
            {"id": "request_corrected_data", "label": "Request corrected data", "detail": "Ask the submitter to correct the invalid field."},
            {"id": "attach_review_note", "label": "Add review note", "detail": "Document the validation failure before return."},
        ],
    },
    "frequency_type_pending_domain_review": {
        "category": "Rules coverage review",
        "summary": "Replacement or void claim semantics need domain review before automated handling.",
        "required_items": ["Frequency type policy decision", "Domain reviewer sign-off"],
        "owner_queue": "Policy review",
        "priority": "Medium",
        "next_actions": [
            {"id": "assign_policy_review", "label": "Assign policy review", "detail": "Send to a domain reviewer for replacement/void policy."},
            {"id": "hold_payment", "label": "Hold payment", "detail": "Keep payment closed until the policy decision is recorded."},
        ],
    },
}

GATE_BY_REASON: dict[str, str] = {
    "member_id_missing": "G1_MEMBER_ID_PRESENT",
    "eligibility_inactive": "G2_ELIGIBILITY_ACTIVE",
    "patient_deceased": "G2B_PATIENT_NOT_DECEASED",
    "provider_npi_missing": "G3_PROVIDER_NPI_PRESENT",
    "provider_not_enrolled": "G4_PROVIDER_ENROLLED",
    "provider_suspended": "G4B_PROVIDER_NOT_SUSPENDED",
    "service_line_missing": "G5_SERVICE_LINES_PRESENT",
    "diagnosis_missing": "G6_DIAGNOSIS_PRESENT",
    "prior_authorization_required": "G7_PRIOR_AUTH_WHEN_REQUIRED",
    "invalid_charge": "G8A_CHARGE_VALID",
    "duplicate_claim": "G9_NOT_DUPLICATE",
    "program_integrity_hold": "G10_NO_PROGRAM_INTEGRITY_HOLD",
    "adjudication_failed": "canonicalization/adjudication_failed",
    "ingestion_failed": "837_ingestion",
    "dirty_claim_prefilter_rejected": "dirty_claim_prefilter",
}


class BatchSubmitRequest(BaseModel):
    actor: str = Field(default="operator@example.gov")
    claims: list[dict[str, Any]] = Field(default_factory=list)
    strict_oracle_attestations: bool = True
    enforce_nullifier_proofs: bool = True


class ReviewActionRequest(BaseModel):
    actor: str = Field(default="operator@example.gov")
    action_id: str
    note: str = ""


class OperatorAuditEventRequest(BaseModel):
    claim_id: str
    action: str
    status: str = ""
    payment_state: str = ""
    description: str = ""
    outcome: str = ""
    amount_cents: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderAuditEventRequest(BaseModel):
    request_id: str
    claim_id: str
    action: str
    status: str = ""
    description: str = ""
    outcome: str = ""


class ProviderPacketAttachmentRequest(BaseModel):
    filename: str
    content_base64: str = Field(max_length=PROVIDER_ATTACHMENT_MAX_BASE64_CHARS)
    mime_type: str = "application/octet-stream"
    size_bytes: int | None = None


class ProviderPacketSubmitRequest(BaseModel):
    request_id: str
    claim_id: str
    action: str = "submit_packet"
    pa_number: str
    effective_from: str
    effective_through: str
    correction_note: str = ""
    date_covers: bool
    procedure_match: bool
    signed_document: bool
    attachments: list[ProviderPacketAttachmentRequest] = Field(default_factory=list)


class ProviderMessageRequest(BaseModel):
    request_id: str
    claim_id: str
    message: str


class ProviderDecisionRequest(BaseModel):
    decision: str
    message: str = ""
    payment_state: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


OPERATOR_WORKFLOW_TRANSITIONS: dict[str, dict[str, str]] = {
    "release_blocked": {
        "prepare_request": "documentation_requested",
        "deny_claim": "denied",
        "route_clinical": "clinical_review",
        "override_review": "override_pending",
    },
    "documentation_requested": {
        "mark_docs_received": "docs_received",
        "send_reminder": "documentation_requested",
        "deny_claim": "denied",
        "reopen_review": "release_blocked",
    },
    "docs_received": {
        "verify_authorization": "ready_for_release",
        "send_reminder": "docs_received",
        "deny_claim": "denied",
        "reopen_review": "release_blocked",
    },
    "ready_for_release": {
        "reopen_review": "release_blocked",
        "route_clinical": "clinical_review",
    },
    "released": {"reopen_review": "release_blocked"},
    "denied": {"reopen_review": "release_blocked"},
    "clinical_review": {
        "reopen_review": "release_blocked",
        "deny_claim": "denied",
    },
    "override_pending": {
        "deny_claim": "denied",
        "reopen_review": "release_blocked",
    },
}
PAYMENT_STATE_BY_WORKFLOW = {
    "ready_for_release": "Ready",
    "denied": "Denied",
}
PROVIDER_WORKFLOW_BY_STATUS = {
    "needs_packet": "release_blocked",
    "needs_correction": "documentation_requested",
    "submitted": "docs_received",
    "accepted": "ready_for_release",
    "denied": "denied",
    "withdrawn": "denied",
    "released": "released",
}
SERVER_CLAIM_STATE_AUTHORITY = "operator_portal_server_v1"
UNTRUSTED_OPERATOR_METADATA_FIELDS = {
    "accepted_by_real_verifier",
    "amount_cents",
    "outcome",
    "payment_state",
    "proof_verified",
    "procedure_code",
    "provider",
    "provider_npi",
    "request_id",
    "service_date",
    "settlement_status",
    "settlement_verified",
    "status",
    "workflow_state",
}


def _replace_claim_id(claim: dict[str, Any], claim_id: str) -> dict[str, Any]:
    out = copy.deepcopy(claim)
    previous = str(out.get("claim_id") or "BL-CLAIM-0001")
    edi = str(out.get("edi", ""))
    out["claim_id"] = claim_id
    out["edi"] = edi.replace(previous, claim_id).replace("BL-CLAIM-0001", claim_id)
    return out


def _sample_claim(claim_id: str, *, flags: dict[str, bool] | None = None, edi_transform: Any | None = None) -> dict[str, Any]:
    claim = _replace_claim_id(load_json(SAMPLE_CLAIM_PATH), claim_id)
    claim.setdefault("flags", {})
    if flags:
        claim["flags"].update(flags)
    if edi_transform is not None:
        claim["edi"] = edi_transform(str(claim["edi"]))
    return claim


def _claim_charge_cents_from_edi(edi: str) -> int:
    match = re.search(r"(?:^|~)CLM\*[^*~]+\*([^*~]+)(?=\*|~|$)", str(edi or ""))
    if not match:
        return 0
    try:
        return cents(match.group(1))
    except ValueError:
        return 0


def _claim_id_from_edi(edi: str) -> str:
    match = re.search(r"(?:^|~)CLM\*([^*~]+)", str(edi or ""))
    return match.group(1) if match else ""


def build_synthetic_demo_claims() -> list[dict[str, Any]]:
    def missing_npi(edi: str) -> str:
        return edi.replace("NM1*82*1*ADAMS*ALICE****XX*1999999984", "NM1*82*1*ADAMS*ALICE****XX*")

    def malformed_approved(edi: str) -> str:
        return edi.replace("NM1*82*1*ADAMS*ALICE****XX*1999999984", "NM1*82*1*ADAMS*ALICE****XX*1234567890")

    return [
        _sample_claim("BL-DEMO-APPROVED"),
        _sample_claim("BL-DEMO-ELIGIBILITY", flags={"eligibility_active": False}),
        _sample_claim("BL-DEMO-MISSING-NPI", edi_transform=missing_npi),
        _sample_claim("BL-DEMO-DUPLICATE", flags={"duplicate_claim": True}),
        _sample_claim("BL-DEMO-INTEGRITY-HOLD", flags={"program_integrity_hold": True}),
        _sample_claim("BL-DEMO-MALFORMED-APPROVED", edi_transform=malformed_approved),
    ]


def _portal_roles() -> RoleBook:
    roles = RoleBook()
    roles.grant(ADMIN, "admin@example.gov")
    roles.grant(OPERATOR, "operator@example.gov")
    roles.grant(AUDITOR, "auditor@example.gov")
    return roles


def _is_production_env() -> bool:
    return os.environ.get("BL_ENV", "").strip().lower() in PRODUCTION_ENVS


def _local_portal_defaults_allowed() -> bool:
    return os.environ.get("BL_ENV", "").strip().lower() in LOCAL_PORTAL_ENVS


def _published_local_tokens() -> set[str]:
    return {
        *PORTAL_LOCAL_TOKEN_BY_PRINCIPAL.values(),
        *(tenant["token"] for tenant in PROVIDER_PORTAL_LOCAL_TENANTS.values()),
    }


def _reject_published_local_token_outside_local(token: str) -> None:
    if token and not _local_portal_defaults_allowed() and token in _published_local_tokens():
        raise HTTPException(status_code=500, detail="published local portal token is forbidden outside explicit local/test/dev mode")


def _configured_portal_tokens() -> dict[str, str]:
    tokens: dict[str, str] = {}
    for principal, env_name in PORTAL_TOKEN_ENV_BY_PRINCIPAL.items():
        token = os.environ.get(env_name, "").strip()
        if not token and _local_portal_defaults_allowed():
            token = PORTAL_LOCAL_TOKEN_BY_PRINCIPAL[principal]
        _reject_published_local_token_outside_local(token)
        if token:
            tokens[principal] = token
    if len(set(tokens.values())) != len(tokens):
        raise HTTPException(status_code=500, detail="operator portal token configuration must be per-principal and distinct")
    return tokens


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-bl-portal-token", "").strip()


def _authenticated_principal(request: Request, *, require_submitter: bool = False) -> str:
    supplied = _bearer_token(request)
    if not supplied:
        raise HTTPException(status_code=401, detail="operator portal authentication required")
    principal = ""
    operator_tokens, _provider_tokens = _validated_portal_token_maps()
    for candidate_principal, expected in operator_tokens.items():
        if hmac.compare_digest(supplied, expected):
            principal = candidate_principal
            break
    if not principal:
        raise HTTPException(status_code=403, detail="operator portal authentication failed")
    roles = _portal_roles()
    try:
        if require_submitter:
            roles.require_batch_submitter(principal)
        else:
            roles.require_appeal_reader(principal)
    except AccessDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return principal


def _configured_provider_tenants() -> dict[str, dict[str, str]]:
    configured = os.environ.get(PROVIDER_PORTAL_TENANTS_ENV, "").strip()
    if configured:
        try:
            raw_tenants = json.loads(configured)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail="provider portal tenant configuration is not valid JSON") from exc
        if not isinstance(raw_tenants, dict) or not raw_tenants:
            raise HTTPException(status_code=500, detail="provider portal tenant configuration must be a non-empty object")
        tenants: dict[str, dict[str, str]] = {}
        for principal, tenant in raw_tenants.items():
            if not isinstance(principal, str) or not isinstance(tenant, dict):
                raise HTTPException(status_code=500, detail="provider portal tenant configuration has an invalid entry")
            token = str(tenant.get("token") or "").strip()
            name = str(tenant.get("name") or "").strip()
            npi = str(tenant.get("npi") or "").strip()
            if not principal.strip() or not token or not name or not npi:
                raise HTTPException(status_code=500, detail="provider portal tenant configuration requires principal, token, name, and npi")
            _reject_published_local_token_outside_local(token)
            tenants[principal] = {"token": token, "name": name, "npi": npi}
        return tenants

    token = os.environ.get(PROVIDER_PORTAL_TOKEN_ENV, "").strip()
    if not _local_portal_defaults_allowed():
        if not token:
            raise HTTPException(status_code=500, detail="provider portal tenant configuration is not configured")
        _reject_published_local_token_outside_local(token)
        return {
            PROVIDER_PORTAL_PRINCIPAL: {
                "token": token,
                "name": "Configured provider",
                "npi": "configured-provider-npi",
            }
        }

    tenants = {principal: dict(tenant) for principal, tenant in PROVIDER_PORTAL_LOCAL_TENANTS.items()}
    if token:
        tenants[PROVIDER_PORTAL_PRINCIPAL]["token"] = token
    return tenants


def _configured_provider_tokens() -> dict[str, str]:
    return {principal: tenant["token"] for principal, tenant in _configured_provider_tenants().items()}


def _validated_portal_token_maps() -> tuple[dict[str, str], dict[str, str]]:
    operator_tokens = _configured_portal_tokens()
    provider_tokens = _configured_provider_tokens()
    assigned: dict[str, tuple[str, str]] = {}
    for surface, tokens in (("operator", operator_tokens), ("provider", provider_tokens)):
        for principal, token in tokens.items():
            previous = assigned.get(token)
            if previous is not None:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "portal token configuration must be globally unique across operator and provider principals:"
                        f"{previous[0]}:{previous[1]}:{surface}:{principal}"
                    ),
                )
            assigned[token] = (surface, principal)
    return operator_tokens, provider_tokens


def _provider_tenant(principal: str) -> dict[str, str]:
    tenant = _configured_provider_tenants().get(principal)
    if tenant is None:
        raise HTTPException(status_code=403, detail="provider portal tenant is not configured")
    return tenant


def _provider_tenant_can_access_request(tenant: dict[str, str], provider_request: dict[str, Any]) -> bool:
    return hmac.compare_digest(str(provider_request.get("provider_npi") or ""), tenant["npi"])


def _authenticated_provider(request: Request) -> str:
    supplied = _bearer_token(request)
    if not supplied:
        raise HTTPException(status_code=401, detail="provider portal authentication required")
    _operator_tokens, provider_tokens = _validated_portal_token_maps()
    for principal, expected in provider_tokens.items():
        if hmac.compare_digest(supplied, expected):
            return principal
    raise HTTPException(status_code=403, detail="provider portal authentication failed")


def _ensure_local_operator_defaults() -> None:
    if not _local_portal_defaults_allowed():
        return
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_OPERATOR_PORTAL_LOCAL_PROVIDER_ALIAS_KEY")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    for principal, env_name in PORTAL_TOKEN_ENV_BY_PRINCIPAL.items():
        os.environ.setdefault(env_name, PORTAL_LOCAL_TOKEN_BY_PRINCIPAL[principal])
    os.environ.setdefault(PROVIDER_PORTAL_TOKEN_ENV, PROVIDER_PORTAL_LOCAL_TOKEN)


def _readiness_payload() -> dict[str, Any]:
    report = production_readiness()
    launch_blockers = load_json(OPS_ROOT / "launch_blockers.json")
    launch_report = validate_launch_blockers(launch_blockers)
    verifier_pin = load_json(OPS_ROOT / "verifier_artifact_pin.example.json")
    verifier_report = validate_verifier_pin_manifest(verifier_pin, repo_root=APP_ROOT.parent)
    open_blockers = [
        {
            "id": str(item.get("id", "")),
            "title": str(item.get("title", "")),
            "owner": str(item.get("owner", "")),
            "status": str(item.get("status", "")),
        }
        for item in launch_blockers.get("blockers", [])
        if item.get("status") == "open"
    ]
    return {
        "portal_mode": "production" if report.production_mode else "local_operator_pilot",
        "production_ready": report.production_mode and report.ready,
        "production_blockers": list(report.blockers),
        "launch_manifest_ok": launch_report.ok,
        "verifier_pin_ok": verifier_report.ok,
        "open_launch_blockers": open_blockers,
        "proof_lane": CANONICAL_PROOF_LANE,
        "onchain_anchor": CANONICAL_ONCHAIN_ANCHOR,
        "proof_status": REAL_PROOF_REQUIRED_STATUS,
    }


def _default_provider_requests() -> list[dict[str, Any]]:
    base_required_items = [
        "Prior authorization number",
        "Authorization effective date window",
        "Procedure match",
        "Signed authorization document",
    ]
    return [
        {
            "request_id": "DOC-REQ-042",
            "claim_id": "BL-CLAIM-AUTH-042",
            "status": "needs_packet",
            "required_items": [
                "Prior authorization number",
                "Authorization effective date window",
                "Procedure code T1019 match",
                "Signed authorization document",
            ],
            "payment_state": "held_by_payer",
            "message": "Payment remains held pending provider packet.",
            "provider": "North Valley Home Health",
            "provider_npi": "1999999984",
            "procedure_code": "T1019",
            "service_date": "Jun 12, 2026",
            "amount_cents": 125000,
        },
        {
            "request_id": "DOC-REQ-144",
            "claim_id": "BL-CLAIM-AUTH-144",
            "status": "needs_packet",
            "required_items": [item.replace("Procedure match", "Procedure code T1019 match") for item in base_required_items],
            "payment_state": "held_by_payer",
            "message": "Payment remains held pending provider packet.",
            "provider": "East Bay Home Care",
            "provider_npi": "1666666650",
            "procedure_code": "T1019",
            "service_date": "Jun 9, 2026",
            "amount_cents": 70500,
        },
        {
            "request_id": "DOC-REQ-208",
            "claim_id": "BL-CLAIM-AUTH-208",
            "status": "needs_packet",
            "required_items": [item.replace("Procedure match", "Procedure code 97110 match") for item in base_required_items],
            "payment_state": "held_by_payer",
            "message": "Payment remains held pending provider packet.",
            "provider": "Golden State Therapy",
            "provider_npi": "1555555542",
            "procedure_code": "97110",
            "service_date": "Jun 7, 2026",
            "amount_cents": 61000,
        },
        {
            "request_id": "DOC-REQ-263",
            "claim_id": "BL-CLAIM-AUTH-263",
            "status": "needs_packet",
            "required_items": [item.replace("Procedure match", "Procedure code T1020 match") for item in base_required_items],
            "payment_state": "held_by_payer",
            "message": "Payment remains held pending provider packet.",
            "provider": "Capital Family Services",
            "provider_npi": "1333333326",
            "procedure_code": "T1020",
            "service_date": "Jun 4, 2026",
            "amount_cents": 89000,
        },
    ]


def _provider_workspace_payload(
    provider_audit_log: list[dict[str, Any]],
    provider_packets: list[dict[str, Any]] | None = None,
    provider_messages: list[dict[str, Any]] | None = None,
    provider_requests: list[dict[str, Any]] | None = None,
    principal: str | None = None,
) -> dict[str, Any]:
    requests = provider_requests or _default_provider_requests()
    tenant = _provider_tenant(principal) if principal else None
    visible_requests = [item for item in requests if tenant is None or _provider_tenant_can_access_request(tenant, item)]
    visible_request_ids = {str(item.get("request_id") or "") for item in visible_requests}
    visible_claim_ids = {str(item.get("claim_id") or "") for item in visible_requests}

    def is_visible(item: dict[str, Any]) -> bool:
        request_id = str(item.get("request_id") or item.get("metadata", {}).get("request_id") or "")
        claim_id = str(item.get("claim_id") or "")
        return not tenant or request_id in visible_request_ids or claim_id in visible_claim_ids

    return {
        "provider": {
            "name": tenant["name"] if tenant else "Provider workspace",
            "npi": tenant["npi"] if tenant else "",
            "principal": principal or "",
        },
        "requests": visible_requests,
        "packets": list(reversed([item for item in provider_packets or [] if is_visible(item)])),
        "messages": list(reversed([item for item in provider_messages or [] if is_visible(item)])),
        "audit_log": list(reversed([item for item in provider_audit_log if is_visible(item)])),
    }


def _safe_storage_component(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return (cleaned or fallback)[:96]


def _decode_provider_attachment(attachment: ProviderPacketAttachmentRequest) -> bytes:
    try:
        data = base64.b64decode(attachment.content_base64, validate=True)
    except (BinasciiError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid attachment encoding:{attachment.filename}") from exc
    if not data:
        raise HTTPException(status_code=400, detail=f"empty attachment:{attachment.filename}")
    if len(data) > PROVIDER_ATTACHMENT_MAX_BYTES:
        raise HTTPException(status_code=400, detail=f"attachment too large:{attachment.filename}")
    if attachment.size_bytes is not None and int(attachment.size_bytes) != len(data):
        raise HTTPException(status_code=400, detail=f"attachment size mismatch:{attachment.filename}")
    return data


def _prepare_provider_attachments(attachments: list[ProviderPacketAttachmentRequest]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for attachment in attachments:
        data = _decode_provider_attachment(attachment)
        base_filename = _safe_storage_component(Path(attachment.filename).name, "attachment.bin")
        filename = base_filename
        duplicate_index = 2
        while filename in used_names:
            stem = Path(base_filename).stem or "attachment"
            suffix = Path(base_filename).suffix
            filename = f"{stem}_{duplicate_index}{suffix}"
            duplicate_index += 1
        used_names.add(filename)
        prepared.append(
            {
                "filename": filename,
                "data": data,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mime_type": attachment.mime_type or "application/octet-stream",
            }
        )
    return prepared


def _packet_hash(packet_fields: list[str], attachment_hashes: list[str]) -> str:
    digest = hashlib.sha256()
    for value in packet_fields + attachment_hashes:
        digest.update(str(value).encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _next_numeric_id(records: list[dict[str, Any]], key: str, prefix: str) -> str:
    used = {str(record.get(key) or "") for record in records}
    highest = 0
    for value in used:
        if not value.startswith(prefix):
            continue
        suffix = value[len(prefix) :]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    candidate = highest + 1
    while f"{prefix}{candidate:06d}" in used:
        candidate += 1
    return f"{prefix}{candidate:06d}"


def _next_message_id(messages: list[dict[str, Any]], prefix: str) -> str:
    return _next_numeric_id(messages, "message_id", prefix)


def _portal_exchange_state_path() -> Path:
    configured = os.environ.get(PORTAL_STATE_PATH_ENV)
    return Path(configured).expanduser() if configured else PORTAL_EXCHANGE_STATE_PATH


def _load_portal_exchange_state() -> dict[str, Any]:
    path = _portal_exchange_state_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_portal_exchange_state(
    *,
    audit_log: list[dict[str, Any]],
    provider_audit_log: list[dict[str, Any]],
    provider_requests: list[dict[str, Any]],
    provider_packets: list[dict[str, Any]],
    provider_messages: list[dict[str, Any]],
    operator_claim_states: dict[str, dict[str, Any]] | None = None,
) -> None:
    path = _portal_exchange_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "saved_at": _now_iso(),
        "audit_log": audit_log,
        "provider_audit_log": provider_audit_log,
        "provider_requests": provider_requests,
        "provider_packets": provider_packets,
        "provider_messages": provider_messages,
        "operator_claim_states": operator_claim_states or {},
    }
    handle, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as tmp_file:
            json.dump(payload, tmp_file, indent=2, sort_keys=True)
            tmp_file.write("\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _fallback_review(reason: str) -> dict[str, Any]:
    return {
        "category": "Human review",
        "summary": f"The claim needs human review for `{reason or 'unknown'}`.",
        "required_items": ["Reviewer note", "Supporting documentation"],
        "owner_queue": "Manual review",
        "priority": "Medium",
        "next_actions": [
            {"id": "attach_review_note", "label": "Add review note", "detail": "Document what the reviewer found."},
            {"id": "prepare_resubmission", "label": "Prepare resubmission", "detail": "Route for corrected-claim handling if needed."},
        ],
    }


def _appeal_route_for_reason(reason: str) -> str:
    if reason in {"member_id_missing", "diagnosis_missing", "service_line_missing", "invalid_charge"}:
        return "cif_resubmission"
    if reason in {"eligibility_inactive", "patient_deceased", "prior_authorization_required", "provider_not_enrolled", "provider_suspended"}:
        return "formal_appeal"
    if reason in {"duplicate_claim", "program_integrity_hold"}:
        return "program_integrity"
    return "formal_appeal"


def _human_error_message(reason: str, errors: list[str]) -> str:
    joined = "; ".join(errors)
    if "flags must be an object" in joined:
        return "The supplemental flags were not sent as a valid object."
    if "oracle_attestation_required" in joined:
        return "Required eligibility/provider facts were not backed by attestations."
    if reason == "ingestion_failed":
        return "The 837 file is incomplete or malformed."
    if reason == "dirty_claim_prefilter_rejected":
        return "The claim was filtered before adjudication because required claim data is malformed, unsupported, or non-payable."
    return joined or "The input needs a reviewer before it can continue."


def _make_review_item(
    *,
    batch_id: str,
    claim_id: str,
    reason: str,
    source: str,
    actor: str,
    guide: dict[str, Any],
    explanation: str | None = None,
    carc: str = "",
    rarc: str = "",
    appeal_route: str = "",
) -> dict[str, Any]:
    item_id = f"review-{batch_id[:12]}-{claim_id}-{reason}".replace(" ", "-")
    return {
        "id": item_id,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "batch_id": batch_id,
        "claim_id": claim_id,
        "source": source,
        "status": "open",
        "priority": guide.get("priority", "Medium"),
        "owner_queue": guide.get("owner_queue", "Manual review"),
        "category": guide.get("category", "Human review"),
        "reason": reason,
        "summary": explanation or guide.get("summary", ""),
        "required_items": list(guide.get("required_items", [])),
        "next_actions": list(guide.get("next_actions", [])),
        "carc": carc,
        "rarc": rarc,
        "appeal_route": appeal_route,
        "assigned_to": "",
        "history": [
            {
                "at": _now_iso(),
                "actor": actor,
                "action": "created",
                "note": "Routed to human review",
            }
        ],
    }


def _add_audit_event(
    audit_log: list[dict[str, Any]],
    *,
    event_type: str,
    actor: str,
    description: str,
    batch_id: str = "",
    claim_id: str = "",
    outcome: str = "",
    amount_cents: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = {
        "id": _next_numeric_id(audit_log, "id", "audit-"),
        "created_at": _now_iso(),
        "event_type": event_type,
        "actor": actor,
        "batch_id": batch_id,
        "claim_id": claim_id,
        "description": description,
        "outcome": outcome,
        "amount_cents": amount_cents,
        "metadata": metadata or {},
    }
    audit_log.append(entry)
    return entry


def _add_batch_workflow_events(
    *,
    batch: SubmittedBatch,
    summary: dict[str, Any],
    actor: str,
    review_items: dict[str, dict[str, Any]],
    audit_log: list[dict[str, Any]],
) -> None:
    _add_audit_event(
        audit_log,
        event_type="batch_submitted",
        actor=actor,
        batch_id=batch.batch_id,
        description=f"Batch accepted into local review with {batch.claim_count} adjudicated claim(s).",
        outcome="recorded",
        metadata={
            "claim_count": batch.claim_count,
            "quarantine_count": batch.quarantine_count,
            "payment_count": batch.payment_count,
            "accepted_by_real_verifier": batch.accepted_by_real_verifier,
        },
    )
    for packet in batch.claim_packets:
        if packet.decision == "approved":
            _add_audit_event(
                audit_log,
                event_type="claim_approved",
                actor=actor,
                batch_id=batch.batch_id,
                claim_id=packet.claim_id,
                description="Claim passed automated rules and was included in the batch payment root.",
                outcome="approved_pending_verifier",
                amount_cents=cents(packet.payable_amount),
                metadata={"engine_mode": packet.engine_mode},
            )
            continue
        guide = REASON_GUIDE.get(packet.denial_reason, _fallback_review(packet.denial_reason))
        item = _make_review_item(
            batch_id=batch.batch_id,
            claim_id=packet.claim_id,
            reason=packet.denial_reason,
            source="denied_claim",
            actor=actor,
            guide=guide,
            carc=packet.carc,
            rarc=packet.rarc,
            appeal_route=_appeal_route_for_reason(packet.denial_reason),
        )
        review_items[item["id"]] = item
        _add_audit_event(
            audit_log,
            event_type="claim_routed_to_review",
            actor=actor,
            batch_id=batch.batch_id,
            claim_id=packet.claim_id,
            description=str(guide.get("summary", "Claim needs staff review.")),
            outcome="needs_review",
            metadata={
                "category": str(guide.get("category", "Human review")),
                "owner_queue": str(guide.get("owner_queue", "Manual review")),
                "reason": packet.denial_reason,
            },
        )
    for payment in batch.payments:
        _add_audit_event(
            audit_log,
            event_type="payment_record_prepared",
            actor=actor,
            batch_id=batch.batch_id,
            description="Provider payment record was prepared but settlement remains closed pending real verifier approval.",
            outcome=str(payment.settlement.get("status", "pending")),
            amount_cents=payment.amount_cents,
            metadata={
                "provider_payment_key": payment.provider_payment_key,
                "recipient_address": payment.recipient_address,
            },
        )
    for item in batch.quarantined:
        guide = QUARANTINE_GUIDE.get(item.reason, _fallback_review(item.reason))
        review = _make_review_item(
            batch_id=batch.batch_id,
            claim_id=item.claim_id,
            reason=item.reason,
            source="quarantined_input",
            actor=actor,
            guide=guide,
            explanation=_human_error_message(item.reason, item.errors),
        )
        review["input_index"] = item.input_index
        review["error_count"] = len(item.errors)
        review_items[review["id"]] = review
        _add_audit_event(
            audit_log,
            event_type="claim_routed_to_review",
            actor=actor,
            batch_id=batch.batch_id,
            claim_id=item.claim_id,
            description=str(review["summary"]),
            outcome="needs_review",
            metadata={
                "category": str(guide.get("category", "Human review")),
                "owner_queue": str(guide.get("owner_queue", "Manual review")),
                "reason": item.reason,
            },
        )
    summary["review_count"] = len([item for item in review_items.values() if item["batch_id"] == batch.batch_id and item["status"] == "open"])


def _status_after_action(action_id: str) -> str:
    if action_id.startswith("request_"):
        return "waiting_on_documents"
    if action_id in {"prepare_resubmission"}:
        return "ready_for_resubmission"
    if action_id in {"assign_policy_review", "route_program_integrity", "route_formal_appeal"}:
        return "assigned"
    if action_id in {"hold_payment"}:
        return "payment_hold"
    return "in_review"


def _input_charge_map(input_claims: list[dict[str, Any]] | None) -> dict[str, int]:
    charges: dict[str, int] = {}
    for index, claim in enumerate(input_claims or []):
        claim_id = str(claim.get("claim_id") or _claim_id_from_edi(str(claim.get("edi", ""))) or f"input_{index}")
        charges[claim_id] = _claim_charge_cents_from_edi(str(claim.get("edi", "")))
    return charges


def _batch_summary(batch: SubmittedBatch, input_claims: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    input_charges = _input_charge_map(input_claims)
    quarantined = []
    for item in batch.quarantined:
        quarantined.append(
            {
                "input_index": item.input_index,
                "claim_id": item.claim_id,
                "reason": item.reason,
                "error_count": len(item.errors),
                "billed_amount_cents": input_charges.get(item.claim_id, 0),
                "layer_gate": GATE_BY_REASON.get(item.reason, item.reason),
            }
        )
    return {
        "batch_id": batch.batch_id,
        "claim_count": batch.claim_count,
        "quarantine_count": batch.quarantine_count,
        "payment_count": batch.payment_count,
        "proof_status": batch.proof_status,
        "accepted_by_real_verifier": batch.accepted_by_real_verifier,
        "engine_modes": batch.engine_modes,
        "roots": {
            "claim_root": batch.claim_batch_record,
            "result_root": batch.adjudication_batch_record,
            "payment_root": batch.payment_batch_record,
            "nullifier_before": batch.duplicate_check_before,
            "nullifier_after": batch.duplicate_check_after,
            "claim_source_root": batch.claim_source_root,
            "oracle_facts_root": batch.oracle_facts_root,
            "oracle_signer_root": batch.oracle_signer_root,
            "policy_root": batch.policy_root,
            "address_book_root": batch.address_book_root,
            "ruleset_root": batch.ruleset_record,
            "combined_commitment": batch.combined_batch_commitment,
            "data_availability_root": batch.data_availability_root,
            "denial_attestation_root": batch.denial_attestation_root,
            "value_conservation_commitment": batch.value_conservation_commitment,
        },
        "claims": [
            {
                "claim_id": packet.claim_id,
                "decision": packet.decision,
                "denial_reason": packet.denial_reason,
                "carc": packet.carc,
                "rarc": packet.rarc,
                "billed_amount_cents": packet.total_charge_cents,
                "payable_amount_cents": cents(packet.payable_amount),
                "layer_gate": "all_gates_passed" if packet.decision == "approved" else GATE_BY_REASON.get(packet.denial_reason, packet.denial_reason),
                "payable_amount": packet.payable_amount,
                "engine_mode": packet.engine_mode,
            }
            for packet in batch.claim_packets
        ],
        "payments": [
            {
                "approved_claim_count": payment.approved_claim_count,
                "amount_cents": payment.amount_cents,
                "settlement_status": str(payment.settlement.get("status", "")),
            }
            for payment in batch.payments
        ],
        "quarantined": quarantined,
    }


def _dashboard_metrics(
    batches: list[dict[str, Any]],
    review_item_values: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> dict[str, Any]:
    approved = 0
    denied = 0
    quarantined = 0
    dollars_to_settle_cents = 0
    dollars_prevented_cents = 0
    denied_by_reason: dict[str, int] = {}
    caught_by_layer_gate: dict[str, int] = {}
    program_integrity_flags = 0
    for batch in batches:
        dollars_to_settle_cents += sum(int(payment.get("amount_cents", 0)) for payment in batch.get("payments", []))
        for claim in batch.get("claims", []):
            if claim.get("decision") == "approved":
                approved += 1
                continue
            denied += 1
            reason = str(claim.get("denial_reason") or "unknown")
            gate = str(claim.get("layer_gate") or GATE_BY_REASON.get(reason, reason))
            denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
            caught_by_layer_gate[gate] = caught_by_layer_gate.get(gate, 0) + 1
            dollars_prevented_cents += int(claim.get("billed_amount_cents", 0))
            if reason == "program_integrity_hold":
                program_integrity_flags += 1
        for item in batch.get("quarantined", []):
            quarantined += 1
            reason = str(item.get("reason") or "unknown")
            gate = str(item.get("layer_gate") or GATE_BY_REASON.get(reason, reason))
            caught_by_layer_gate[gate] = caught_by_layer_gate.get(gate, 0) + 1
            dollars_prevented_cents += int(item.get("billed_amount_cents", 0))
    open_reviews = [item for item in review_item_values if item.get("status") == "open"]
    appeal_queue: dict[str, int] = {}
    for item in open_reviews:
        route = str(item.get("appeal_route") or "manual_review")
        appeal_queue[route] = appeal_queue.get(route, 0) + 1
    return {
        "claims_processed": approved + denied + quarantined,
        "approved": approved,
        "denied": denied,
        "quarantined": quarantined,
        "review_open": len(open_reviews),
        "payment_records": sum(len(batch.get("payments", [])) for batch in batches),
        "denied_by_reason": denied_by_reason,
        "caught_by_layer_gate": caught_by_layer_gate,
        "dollars_to_settle_cents": dollars_to_settle_cents,
        "dollars_prevented_cents": dollars_prevented_cents,
        "appeal_queue": appeal_queue,
        "program_integrity_flags": program_integrity_flags,
        "sla": {
            "open_review_count": len(open_reviews),
            "oldest_open_created_at": min((str(item.get("created_at", "")) for item in open_reviews), default=""),
            "high_priority_open": len([item for item in open_reviews if item.get("priority") == "High"]),
        },
        "audit_event_count": len(audit_events),
    }


def assert_dashboard_metrics_match(
    metrics: Mapping[str, Any],
    batches: list[dict[str, Any]],
    review_item_values: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> bool:
    expected = _dashboard_metrics(batches, review_item_values, audit_events)
    if dict(metrics) != expected:
        raise ValueError("dashboard_metrics_divergence")
    return True


def run_synthetic_batch_demo(actor: str = "operator@example.gov") -> dict[str, Any]:
    _ensure_local_operator_defaults()
    claims = build_synthetic_demo_claims()
    recorder = LocalBatchRecorder()
    batch = submit_batches(
        claims,
        actor=actor,
        access=_portal_roles(),
        config=BatchConfig(strict_oracle_attestations=True, enforce_nullifier_proofs=True),
        recorder=recorder,
    )[0]
    summary = _batch_summary(batch, claims)
    review_items: dict[str, dict[str, Any]] = {}
    audit_log: list[dict[str, Any]] = []
    _add_batch_workflow_events(
        batch=batch,
        summary=summary,
        actor=actor,
        review_items=review_items,
        audit_log=audit_log,
    )
    readout = []
    packet_by_claim = {packet["claim_id"]: packet for packet in summary["claims"]}
    quarantine_by_claim = {item["claim_id"]: item for item in summary["quarantined"]}
    quarantine_by_index = {int(item["input_index"]): item for item in summary["quarantined"]}
    for index, claim in enumerate(claims):
        claim_id = str(claim.get("claim_id") or _claim_id_from_edi(str(claim.get("edi", ""))))
        if claim_id in packet_by_claim:
            packet = packet_by_claim[claim_id]
            readout.append(
                {
                    "claim_id": claim_id,
                    "decision": packet["decision"],
                    "denial_reason": packet["denial_reason"],
                    "carc": packet["carc"],
                    "rarc": packet["rarc"],
                    "payable_amount_cents": packet["payable_amount_cents"],
                    "layer_gate": packet["layer_gate"],
                }
            )
            continue
        quarantine = quarantine_by_claim.get(claim_id) or quarantine_by_index.get(index, {})
        readout.append(
            {
                "claim_id": claim_id,
                "decision": "quarantined",
                "denial_reason": quarantine.get("reason", "unknown"),
                "carc": "",
                "rarc": "",
                "payable_amount_cents": 0,
                "layer_gate": quarantine.get("layer_gate", "quarantine"),
            }
        )
    metrics = _dashboard_metrics([summary], list(review_items.values()), audit_log)
    assert_dashboard_metrics_match(metrics, [summary], list(review_items.values()), audit_log)
    return {
        "claims": claims,
        "claim_readout": readout,
        "batches": [summary],
        "review_items": sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"])),
        "audit_log": list(reversed(audit_log)),
        "dashboard_metrics": metrics,
        "public_inputs": batch.public_inputs,
        "real_vs_stubbed": {
            "real": [
                "837 parsing",
                "rules engine adjudication",
                "claim/result/payment/claim-source/oracle/fee/nullifier roots",
                "21-field public input construction",
                "835 generation",
                "appeal/review routing",
            ],
            "stubbed": ["native STARK proof generation and verifier acceptance"],
            "proof_status": batch.proof_status,
        },
    }


def create_app() -> FastAPI:
    app = FastAPI(title="Blind Ledger Medi-Cal Operator Portal", docs_url=None, redoc_url=None)
    state_lock = threading.RLock()
    batch_lock = threading.RLock()
    portal_state: dict[str, LocalBatchRecorder | None] = {"recorder": None}
    history: dict[str, dict[str, Any]] = {}
    review_items: dict[str, dict[str, Any]] = {}
    exchange_state = _load_portal_exchange_state()
    audit_log: list[dict[str, Any]] = list(exchange_state.get("audit_log") or [])
    provider_audit_log: list[dict[str, Any]] = list(exchange_state.get("provider_audit_log") or [])
    provider_requests: list[dict[str, Any]] = list(exchange_state.get("provider_requests") or _default_provider_requests())
    provider_packets: list[dict[str, Any]] = list(exchange_state.get("provider_packets") or [])
    provider_messages: list[dict[str, Any]] = list(exchange_state.get("provider_messages") or [])
    operator_claim_states: dict[str, dict[str, Any]] = dict(exchange_state.get("operator_claim_states") or {})

    def get_recorder() -> LocalBatchRecorder:
        with batch_lock:
            if portal_state["recorder"] is None:
                portal_state["recorder"] = LocalBatchRecorder()
            return portal_state["recorder"]

    def current_dashboard_metrics() -> dict[str, Any]:
        with state_lock:
            return _dashboard_metrics(list(history.values()), list(review_items.values()), audit_log)

    def persist_exchange_state() -> None:
        with state_lock:
            _save_portal_exchange_state(
                audit_log=audit_log,
                provider_audit_log=provider_audit_log,
                provider_requests=provider_requests,
                provider_packets=provider_packets,
                provider_messages=provider_messages,
                operator_claim_states=operator_claim_states,
            )

    def request_id_for_claim(claim_id: str, metadata: dict[str, Any]) -> str:
        return str(metadata.get("request_id") or f"DOC-REQ-{str(claim_id).split('-')[-1]}")

    def find_provider_request(request_id: str, claim_id: str = "") -> dict[str, Any] | None:
        with state_lock:
            provider_request = next((item for item in provider_requests if item.get("request_id") == request_id), None)
            if provider_request is None or (claim_id and provider_request.get("claim_id") != claim_id):
                return None
            return provider_request

    def provider_request_for_tenant(principal: str, request_id: str, claim_id: str) -> dict[str, Any]:
        with state_lock:
            provider_request = find_provider_request(request_id, claim_id)
            if provider_request is None:
                raise HTTPException(status_code=404, detail="provider request was not found")
            if not _provider_tenant_can_access_request(_provider_tenant(principal), provider_request):
                raise HTTPException(status_code=403, detail="provider request is outside the authenticated provider tenant")
            return provider_request

    def known_claim_ids() -> set[str]:
        with state_lock:
            claim_ids = {str(item.get("claim_id") or "") for item in provider_requests}
            claim_ids.update(str(item.get("claim_id") or "") for item in review_items.values())
            for batch in history.values():
                claim_ids.update(str(item.get("claim_id") or "") for item in batch.get("claims", []))
                claim_ids.update(str(item.get("claim_id") or "") for item in batch.get("quarantined", []))
            claim_ids.discard("")
            return claim_ids

    def canonical_claim_amount_cents(claim_id: str) -> int | None:
        with state_lock:
            provider_request = next((item for item in provider_requests if item.get("claim_id") == claim_id), None)
            if provider_request is not None and provider_request.get("amount_cents") is not None:
                return int(provider_request["amount_cents"])
            for batch in history.values():
                claim = next((item for item in batch.get("claims", []) if item.get("claim_id") == claim_id), None)
                if claim is not None:
                    key = "payable_amount_cents" if claim.get("decision") == "approved" else "billed_amount_cents"
                    return int(claim.get(key) or 0)
                quarantined = next((item for item in batch.get("quarantined", []) if item.get("claim_id") == claim_id), None)
                if quarantined is not None:
                    return int(quarantined.get("billed_amount_cents") or 0)
            review_item = next((item for item in review_items.values() if item.get("claim_id") == claim_id), None)
            if review_item is not None and review_item.get("billed_amount_cents") is not None:
                return int(review_item["billed_amount_cents"])
            return None

    def initial_operator_workflow(claim_id: str) -> str:
        provider_request = next((item for item in provider_requests if item.get("claim_id") == claim_id), None)
        if provider_request is not None:
            return PROVIDER_WORKFLOW_BY_STATUS.get(str(provider_request.get("status") or ""), "release_blocked")
        for batch in history.values():
            claim = next((item for item in batch.get("claims", []) if item.get("claim_id") == claim_id), None)
            if claim is not None:
                return "denied" if claim.get("decision") == "denied" else "release_blocked"
            if any(item.get("claim_id") == claim_id for item in batch.get("quarantined", [])):
                return "release_blocked"
        return "release_blocked"

    def current_operator_workflow(claim_id: str) -> str:
        with state_lock:
            if claim_id not in known_claim_ids():
                raise HTTPException(status_code=404, detail="claim was not found in authoritative portal records")
            previous = operator_claim_states.get(claim_id, {})
            previous_state = str(previous.get("workflow_state") or "")
            if previous.get("state_authority") == SERVER_CLAIM_STATE_AUTHORITY and previous_state in OPERATOR_WORKFLOW_TRANSITIONS:
                return previous_state
            return initial_operator_workflow(claim_id)

    def server_transition(claim_id: str, action: str) -> tuple[str, str]:
        current_state = current_operator_workflow(claim_id)
        if action == "release_payment":
            raise HTTPException(status_code=409, detail="verified_proof_and_settlement_required")
        provider_request = next((item for item in provider_requests if item.get("claim_id") == claim_id), None)
        if action in {"prepare_request", "send_reminder", "mark_docs_received", "verify_authorization"} and provider_request is None:
            raise HTTPException(status_code=409, detail="authoritative_provider_request_required")
        if action in {"mark_docs_received", "verify_authorization"} and not any(
            packet.get("claim_id") == claim_id for packet in provider_packets
        ):
            raise HTTPException(status_code=409, detail="provider_packet_required")
        next_state = OPERATOR_WORKFLOW_TRANSITIONS.get(current_state, {}).get(action)
        if next_state is None:
            raise HTTPException(status_code=409, detail=f"invalid_operator_transition:{action}:{current_state}")
        return current_state, next_state

    def authoritative_operator_metadata(claim_id: str, metadata: dict[str, Any], amount_cents: int | None) -> dict[str, Any]:
        sanitized = {key: value for key, value in metadata.items() if key not in UNTRUSTED_OPERATOR_METADATA_FIELDS}
        provider_request = next((item for item in provider_requests if item.get("claim_id") == claim_id), None)
        if provider_request is not None:
            for key in ("request_id", "provider", "provider_npi", "procedure_code", "service_date"):
                value = provider_request.get(key)
                if value not in (None, ""):
                    sanitized[key] = value
        if amount_cents is not None:
            sanitized["amount_cents"] = amount_cents
        return sanitized

    def update_operator_claim_state(
        request: OperatorAuditEventRequest,
        metadata: dict[str, Any],
        description: str,
        *,
        workflow_state: str,
        payment_state: str,
        amount_cents: int | None,
    ) -> None:
        operator_claim_states[request.claim_id] = {
            "claim_id": request.claim_id,
            "workflow_state": workflow_state,
            "payment_state": payment_state,
            "last_action": request.action,
            "description": description,
            "outcome": workflow_state,
            "amount_cents": amount_cents,
            "updated_at": _now_iso(),
            "metadata": metadata,
            "state_authority": SERVER_CLAIM_STATE_AUTHORITY,
        }

    def bridge_operator_provider_state(
        request: OperatorAuditEventRequest,
        *,
        actor: str,
        description: str,
        metadata: dict[str, Any],
        workflow_state: str,
        amount_cents: int | None,
    ) -> dict[str, Any] | None:
        action = request.action
        if action not in {
            "prepare_request",
            "send_reminder",
            "mark_docs_received",
            "verify_authorization",
            "deny_claim",
        }:
            return None

        existing = next((item for item in provider_requests if item.get("claim_id") == request.claim_id), None)
        if existing is None:
            return None
        request_id = str(existing.get("request_id") or request_id_for_claim(request.claim_id, {}))
        required_items = metadata.get("required_items") or []
        required_list = list(required_items) if isinstance(required_items, list) else [str(required_items)]
        provider_request = existing
        if amount_cents is not None:
            provider_request["amount_cents"] = amount_cents
        provider_request["updated_at"] = _now_iso()

        notify_provider = True
        event_type = "payer_provider_request_updated"
        outcome = "available_in_provider_workspace"
        message = str(metadata.get("message") or description)

        if action == "prepare_request":
            provider_request["status"] = "needs_packet"
            provider_request["payment_state"] = "held_by_payer"
            provider_request["required_items"] = required_list
            event_type = "payer_document_request_sent"
        elif action == "send_reminder":
            current_status = str(provider_request.get("status") or "needs_packet")
            if workflow_state == "docs_received" or current_status in {"submitted", "accepted", "released", "denied", "withdrawn", "needs_correction"}:
                provider_request["status"] = current_status if current_status != "needs_packet" else "submitted"
            else:
                provider_request["status"] = "needs_packet"
            provider_request["payment_state"] = provider_request.get("payment_state") or "held_by_payer"
            if required_list:
                provider_request["required_items"] = required_list
            event_type = "payer_followup_sent"
        elif action == "mark_docs_received":
            provider_request["status"] = "submitted"
            provider_request["payment_state"] = "held_by_payer"
            provider_request["required_items"] = []
            message = "Payer marked the packet received and is reviewing the authorization match."
            event_type = "payer_packet_marked_received"
            notify_provider = False
        elif action == "verify_authorization":
            provider_request["status"] = "accepted"
            provider_request["payment_state"] = "release_pending"
            provider_request["required_items"] = []
            message = str(metadata.get("message") or "Authorization accepted by payer. Payment release is pending payer batch.")
            event_type = "payer_authorization_accepted"
        elif action == "deny_claim":
            provider_request["status"] = "denied"
            provider_request["payment_state"] = "denied_by_payer"
            message = str(metadata.get("message") or "Claim denied by payer. See payer note for rationale.")
            event_type = "payer_claim_denied"
            outcome = "claim_denied"

        provider_request["message"] = message

        message_record = None
        if notify_provider:
            message_record = {
                "message_id": _next_message_id(provider_messages, "PAYER-MSG-"),
                "request_id": request_id,
                "claim_id": request.claim_id,
                "sent_at": _now_iso(),
                "actor": actor,
                "direction": "payer_to_provider",
                "message": message,
            }
            provider_messages.append(message_record)

        event_metadata = {
            "source": "operator_portal_claim_workstation",
            "request_id": request_id,
            "required_items": provider_request.get("required_items", []),
            "message": message,
            "status": provider_request.get("status"),
            "payment_state": provider_request.get("payment_state"),
        }
        if message_record is not None:
            event_metadata["message_id"] = message_record["message_id"]

        return _add_audit_event(
            provider_audit_log,
            event_type=event_type,
            actor=actor,
            claim_id=request.claim_id,
            description=message,
            outcome=outcome,
            metadata=event_metadata,
        )

    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
    app.mount("/provider-static", StaticFiles(directory=PROVIDER_STATIC_ROOT), name="provider_static")
    app.mount("/shared-static", StaticFiles(directory=SHARED_STATIC_ROOT), name="shared_static")

    @app.middleware("http")
    async def no_cache_operator_portal(request: Request, call_next):
        response = await call_next(request)
        if request.url.path in {"/", "/provider", "/provider/"} or request.url.path.startswith(("/static/", "/provider-static/", "/shared-static/")):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_ROOT / "index.html")

    @app.get("/provider", include_in_schema=False)
    @app.get("/provider/", include_in_schema=False)
    def provider_index() -> FileResponse:
        return FileResponse(PROVIDER_STATIC_ROOT / "index.html")

    @app.get("/api/readiness")
    def readiness() -> dict[str, Any]:
        return _readiness_payload()

    @app.get("/api/sample-claim")
    def sample_claim() -> dict[str, Any]:
        return load_json(SAMPLE_CLAIM_PATH)

    @app.get("/api/batches")
    def list_batches(request: Request) -> dict[str, Any]:
        _authenticated_principal(request)
        with state_lock:
            return {"batches": list(history.values()), "dashboard_metrics": current_dashboard_metrics()}

    @app.get("/api/review-items")
    def list_review_items(request: Request) -> dict[str, Any]:
        _authenticated_principal(request)
        with state_lock:
            ordered = sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"]))
            return {"items": ordered}

    @app.get("/api/audit-log")
    def list_audit_log(request: Request) -> dict[str, Any]:
        _authenticated_principal(request)
        with state_lock:
            return {"events": list(reversed(audit_log))}

    @app.post("/api/operator-events")
    def record_operator_event(request: OperatorAuditEventRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_principal(http_request, require_submitter=True)
        with state_lock:
            previous_state, workflow_state = server_transition(request.claim_id, request.action)
            amount_cents = canonical_claim_amount_cents(request.claim_id)
            payment_state = PAYMENT_STATE_BY_WORKFLOW.get(workflow_state, "Held")
            description = request.description.strip() or request.action.replace("_", " ")
            metadata = authoritative_operator_metadata(request.claim_id, dict(request.metadata or {}), amount_cents)
            metadata["previous_workflow_state"] = previous_state
            entry = _add_audit_event(
                audit_log,
                event_type="operator_portal_action",
                actor=actor,
                claim_id=request.claim_id,
                description=description,
                outcome=workflow_state,
                amount_cents=amount_cents,
                metadata={
                    **metadata,
                    "source": "operator_portal_claim_workstation",
                    "action": request.action,
                    "status": workflow_state,
                    "payment_state": payment_state,
                },
            )
            update_operator_claim_state(
                request,
                metadata,
                description,
                workflow_state=workflow_state,
                payment_state=payment_state,
                amount_cents=amount_cents,
            )
            provider_entry = bridge_operator_provider_state(
                request,
                actor=actor,
                description=description,
                metadata=metadata,
                workflow_state=workflow_state,
                amount_cents=amount_cents,
            )
            persist_exchange_state()
            return {
                "event": entry,
                "provider_event": provider_entry,
                "audit_log": list(reversed(audit_log)),
                "operator_claim_states": operator_claim_states,
                "provider_workspace": _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests),
                "dashboard_metrics": current_dashboard_metrics(),
            }

    @app.post("/api/provider-requests/{request_id}/decision")
    def record_provider_request_decision(request_id: str, request: ProviderDecisionRequest, http_request: Request) -> dict[str, Any]:
        _authenticated_principal(http_request, require_submitter=True)
        decision = request.decision.strip().lower()
        if decision not in {"accept", "return_correction", "deny", "release"}:
            raise HTTPException(status_code=400, detail="unsupported provider request decision")
        action_by_decision = {
            "accept": "verify_authorization",
            "return_correction": "send_reminder",
            "deny": "deny_claim",
        }
        status_by_decision = {
            "accept": "ready_for_release",
            "return_correction": "documentation_requested",
            "deny": "denied",
        }
        payment_by_decision = {
            "accept": "Ready",
            "return_correction": "Held",
            "deny": "Denied",
        }
        with state_lock:
            provider_request = find_provider_request(request_id)
            if provider_request is None:
                raise HTTPException(status_code=404, detail="provider request not found")
            if decision == "release":
                raise HTTPException(status_code=409, detail="verified_proof_and_settlement_required")
            claim_id = str(provider_request.get("claim_id") or "")
            server_transition(claim_id, action_by_decision[decision])
            metadata = dict(request.metadata or {})
            metadata.update(
                {
                    "request_id": request_id,
                    "message": request.message or metadata.get("message") or f"Payer decision recorded: {decision.replace('_', ' ')}",
                    "provider": provider_request.get("provider"),
                    "provider_npi": provider_request.get("provider_npi"),
                    "procedure_code": provider_request.get("procedure_code"),
                    "service_date": provider_request.get("service_date"),
                    "amount_cents": provider_request.get("amount_cents"),
                }
            )
            if decision == "return_correction":
                provider_request["status"] = "needs_correction"
                provider_request["payment_state"] = "held_by_payer"
            operator_request = OperatorAuditEventRequest(
                claim_id=claim_id,
                action=action_by_decision[decision],
                status=status_by_decision[decision],
                payment_state=payment_by_decision[decision],
                description=str(metadata["message"]),
                outcome=decision,
                amount_cents=provider_request.get("amount_cents"),
                metadata=metadata,
            )
            return record_operator_event(operator_request, http_request)

    @app.get("/api/provider-workspace")
    def provider_workspace(request: Request) -> dict[str, Any]:
        actor = _authenticated_provider(request)
        with state_lock:
            return _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests, actor)

    @app.post("/api/provider-events")
    def record_provider_event(request: ProviderAuditEventRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_provider(http_request)
        with state_lock:
            provider_request = provider_request_for_tenant(actor, request.request_id, request.claim_id)
            description = request.description.strip() or request.action.replace("_", " ")
            if request.action == "withdraw_claim":
                if provider_request.get("status") not in {"needs_packet", "needs_correction", "submitted"}:
                    raise HTTPException(status_code=409, detail="provider_request_is_closed")
                provider_request.update(
                    {
                        "status": "withdrawn",
                        "payment_state": "closed_by_provider",
                        "updated_at": _now_iso(),
                    }
                )
            authoritative_status = str(provider_request.get("status") or "")
            metadata = {
                "source": "provider_packet_desk",
                "request_id": request.request_id,
                "action": request.action,
                "status": authoritative_status,
                "provider_principal": actor,
            }
            entry = _add_audit_event(
                provider_audit_log,
                event_type="provider_portal_action",
                actor=actor,
                claim_id=request.claim_id,
                description=description,
                outcome=authoritative_status,
                metadata=metadata,
            )
            payer_entry = None
            if request.action == "withdraw_claim":
                payer_entry = _add_audit_event(
                    audit_log,
                    event_type="provider_claim_withdrawn",
                    actor=actor,
                    claim_id=request.claim_id,
                    description=description,
                    outcome="withdrawn",
                    metadata=metadata,
                )
            persist_exchange_state()
            return {
                "event": entry,
                "payer_event": payer_entry,
                "workspace": _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests, actor),
            }

    @app.post("/api/provider-packets")
    def receive_provider_packet(request: ProviderPacketSubmitRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_provider(http_request)
        if request.action not in {"submit_packet", "submit_correction"}:
            raise HTTPException(status_code=400, detail="unsupported provider packet action")
        if not request.pa_number.strip():
            raise HTTPException(status_code=400, detail="prior authorization number is required")
        if not request.effective_from or not request.effective_through:
            raise HTTPException(status_code=400, detail="authorization effective dates are required")
        if not (request.date_covers and request.procedure_match and request.signed_document):
            raise HTTPException(status_code=400, detail="packet verification checks are incomplete")
        if request.action == "submit_correction" and not request.correction_note.strip():
            raise HTTPException(status_code=400, detail="correction note is required")
        if not request.attachments:
            raise HTTPException(status_code=400, detail="at least one attachment is required")
        if len(request.attachments) > PROVIDER_ATTACHMENT_MAX_COUNT:
            raise HTTPException(status_code=400, detail="too many attachments")
        prepared_attachments = _prepare_provider_attachments(request.attachments)

        with state_lock:
            provider_request = provider_request_for_tenant(actor, request.request_id, request.claim_id)
            current_request_status = str(provider_request.get("status") or "")
            if current_request_status not in {"needs_packet", "needs_correction", "submitted"}:
                raise HTTPException(status_code=409, detail="provider_request_is_closed")
            if request.action == "submit_correction" and current_request_status != "needs_correction":
                raise HTTPException(status_code=409, detail="provider_correction_was_not_requested")
            packet_id = _next_numeric_id(provider_packets, "packet_id", "PROV-PACKET-")
            receipt_id = _next_numeric_id(provider_packets, "receipt_id", "DOC-REC-")
            safe_request = _safe_storage_component(request.request_id, "request")
            safe_packet = _safe_storage_component(packet_id, "packet")
            storage_parent = PROVIDER_PACKET_STORAGE_ROOT / safe_request
            storage_dir = storage_parent / safe_packet
            while storage_dir.exists():
                packet_number = int(packet_id.removeprefix("PROV-PACKET-")) + 1
                packet_id = f"PROV-PACKET-{packet_number:06d}"
                safe_packet = _safe_storage_component(packet_id, "packet")
                storage_dir = storage_parent / safe_packet

            original_provider_request = copy.deepcopy(provider_request)
            original_packet_count = len(provider_packets)
            original_provider_audit_count = len(provider_audit_log)
            original_payer_audit_count = len(audit_log)
            staging_dir: Path | None = None
            final_directory_created = False
            try:
                storage_parent.mkdir(parents=True, exist_ok=True)
                staging_dir = Path(tempfile.mkdtemp(prefix=f".{safe_packet}.", suffix=".staging", dir=storage_parent))
                stored_attachments: list[dict[str, Any]] = []
                for attachment in prepared_attachments:
                    destination = staging_dir / str(attachment["filename"])
                    destination.write_bytes(attachment["data"])
                    stored_attachments.append(
                        {
                            "filename": attachment["filename"],
                            "size_bytes": attachment["size_bytes"],
                            "sha256": attachment["sha256"],
                            "mime_type": attachment["mime_type"],
                            "storage_key": (Path(safe_request) / safe_packet / str(attachment["filename"])).as_posix(),
                        }
                    )
                staging_dir.replace(storage_dir)
                staging_dir = None
                final_directory_created = True

                packet_hash = _packet_hash(
                    [
                        request.request_id,
                        request.claim_id,
                        request.action,
                        request.pa_number,
                        request.effective_from,
                        request.effective_through,
                        request.correction_note,
                    ],
                    [str(attachment["sha256"]) for attachment in stored_attachments],
                )
                packet_record = {
                    "packet_id": packet_id,
                    "receipt_id": receipt_id,
                    "request_id": request.request_id,
                    "claim_id": request.claim_id,
                    "received_at": _now_iso(),
                    "actor": actor,
                    "provider_npi": provider_request["provider_npi"],
                    "action": request.action,
                    "pa_number": request.pa_number,
                    "effective_from": request.effective_from,
                    "effective_through": request.effective_through,
                    "correction_note": request.correction_note,
                    "packet_hash": packet_hash,
                    "attachments": stored_attachments,
                }
                provider_packets.append(packet_record)
                provider_request.update(
                    {
                        "status": "submitted",
                        "payment_state": "held_by_payer",
                        "packet_id": packet_id,
                        "receipt_id": receipt_id,
                        "updated_at": packet_record["received_at"],
                    }
                )
                provider_entry = _add_audit_event(
                    provider_audit_log,
                    event_type="provider_packet_submitted",
                    actor=actor,
                    claim_id=request.claim_id,
                    description=f"Provider packet {receipt_id} submitted to payer service.",
                    outcome="received_by_payer_service",
                    metadata={
                        "source": "provider_packet_desk",
                        "request_id": request.request_id,
                        "packet_id": packet_id,
                        "receipt_id": receipt_id,
                        "packet_hash": packet_hash,
                        "attachment_count": len(stored_attachments),
                        "attachments": stored_attachments,
                    },
                )
                payer_entry = _add_audit_event(
                    audit_log,
                    event_type="provider_packet_received",
                    actor=actor,
                    claim_id=request.claim_id,
                    description=f"Provider packet {receipt_id} was received by the payer service.",
                    outcome="available_for_operator_review",
                    metadata={
                        "source": "provider_packet_desk",
                        "request_id": request.request_id,
                        "packet_id": packet_id,
                        "receipt_id": receipt_id,
                        "packet_hash": packet_hash,
                        "attachment_count": len(stored_attachments),
                        "attachments": stored_attachments,
                    },
                )
                persist_exchange_state()
                return {
                    "packet": packet_record,
                    "event": provider_entry,
                    "payer_event": payer_entry,
                    "workspace": _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests, actor),
                }
            except BaseException:
                del provider_packets[original_packet_count:]
                del provider_audit_log[original_provider_audit_count:]
                del audit_log[original_payer_audit_count:]
                provider_request.clear()
                provider_request.update(original_provider_request)
                if final_directory_created:
                    shutil.rmtree(storage_dir, ignore_errors=True)
                raise
            finally:
                if staging_dir is not None:
                    shutil.rmtree(staging_dir, ignore_errors=True)
                try:
                    storage_parent.rmdir()
                except OSError:
                    pass

    @app.post("/api/provider-messages")
    def receive_provider_message(request: ProviderMessageRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_provider(http_request)
        message = request.message.strip()
        if not message:
            raise HTTPException(status_code=400, detail="message is required")
        with state_lock:
            provider_request_for_tenant(actor, request.request_id, request.claim_id)
            message_record = {
                "message_id": _next_message_id(provider_messages, "PROV-MSG-"),
                "request_id": request.request_id,
                "claim_id": request.claim_id,
                "sent_at": _now_iso(),
                "actor": actor,
                "provider_principal": actor,
                "message": message,
            }
            provider_messages.append(message_record)
            provider_entry = _add_audit_event(
                provider_audit_log,
                event_type="provider_message_sent",
                actor=actor,
                claim_id=request.claim_id,
                description="Provider message sent to payer service.",
                outcome="message_received_by_payer_service",
                metadata={
                    "source": "provider_packet_desk",
                    "request_id": request.request_id,
                    "message_id": message_record["message_id"],
                    "message": message,
                },
            )
            payer_entry = _add_audit_event(
                audit_log,
                event_type="provider_message_received",
                actor=actor,
                claim_id=request.claim_id,
                description="Provider message was received by the payer service.",
                outcome="available_for_operator_review",
                metadata={
                    "source": "provider_packet_desk",
                    "request_id": request.request_id,
                    "message_id": message_record["message_id"],
                    "message": message,
                },
            )
            persist_exchange_state()
            return {
                "message": message_record,
                "event": provider_entry,
                "payer_event": payer_entry,
                "workspace": _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests, actor),
            }

    @app.get("/api/provider-packets/{packet_id}/attachments/{filename}")
    def download_provider_packet_attachment(packet_id: str, filename: str, request: Request) -> FileResponse:
        _authenticated_principal(request)
        with state_lock:
            packet = next((item for item in provider_packets if item.get("packet_id") == packet_id), None)
            if packet is None:
                raise HTTPException(status_code=404, detail="provider packet not found")
            attachment = next((item for item in packet.get("attachments", []) if item.get("filename") == filename), None)
            if attachment is None:
                raise HTTPException(status_code=404, detail="provider attachment not found")
            storage_key = str(attachment.get("storage_key") or "")
            key_path = Path(storage_key)
            if key_path.parts[:2] == ("cache", "provider_packets"):
                storage_path = (APP_ROOT / key_path).resolve()
            else:
                storage_path = (PROVIDER_PACKET_STORAGE_ROOT / key_path).resolve()
            storage_root = PROVIDER_PACKET_STORAGE_ROOT.resolve()
            try:
                storage_path.relative_to(storage_root)
            except ValueError as exc:
                raise HTTPException(status_code=404, detail="provider attachment path is invalid") from exc
            if not storage_path.exists() or not storage_path.is_file():
                raise HTTPException(status_code=404, detail="provider attachment file not found")
            media_type = str(attachment.get("mime_type") or "application/octet-stream")
            download_name = str(attachment.get("filename") or filename)
        return FileResponse(storage_path, media_type=media_type, filename=download_name)

    @app.get("/api/workspace")
    def workspace(request: Request) -> dict[str, Any]:
        _authenticated_principal(request)
        with state_lock:
            return {
                "readiness": _readiness_payload(),
                "batches": list(history.values()),
                "review_items": sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"])),
                "audit_log": list(reversed(audit_log)),
                "operator_claim_states": operator_claim_states,
                "provider_workspace": _provider_workspace_payload(provider_audit_log, provider_packets, provider_messages, provider_requests),
                "dashboard_metrics": current_dashboard_metrics(),
            }

    @app.post("/api/batches")
    def create_batch(request: BatchSubmitRequest, http_request: Request) -> dict[str, Any]:
        _ensure_local_operator_defaults()
        actor = _authenticated_principal(http_request, require_submitter=True)
        if not request.claims:
            raise HTTPException(status_code=400, detail="at least one claim is required")
        config = BatchConfig(
            strict_oracle_attestations=request.strict_oracle_attestations,
            enforce_nullifier_proofs=request.enforce_nullifier_proofs,
        )
        with batch_lock:
            try:
                batches = submit_batches(
                    request.claims,
                    actor=actor,
                    access=_portal_roles(),
                    config=config,
                    recorder=get_recorder(),
                )
            except AccessDenied as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            except (RuntimeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            summaries = [_batch_summary(batch, request.claims) for batch in batches]
            with state_lock:
                for batch, summary in zip(batches, summaries):
                    _add_batch_workflow_events(
                        batch=batch,
                        summary=summary,
                        actor=actor,
                        review_items=review_items,
                        audit_log=audit_log,
                    )
                    history[str(summary["batch_id"])] = summary
                persist_exchange_state()
                return {
                    "batches": summaries,
                    "readiness": _readiness_payload(),
                    "review_items": sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"])),
                    "audit_log": list(reversed(audit_log)),
                    "dashboard_metrics": current_dashboard_metrics(),
                }

    @app.post("/api/demo-batch")
    def create_demo_batch(request: BatchSubmitRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_principal(http_request, require_submitter=True)
        if _is_production_env():
            raise HTTPException(status_code=403, detail="demo batch is disabled in production")
        _ensure_local_operator_defaults()
        with batch_lock:
            demo = run_synthetic_batch_demo(actor=actor)
            with state_lock:
                history.clear()
                review_items.clear()
                audit_log.clear()
                portal_state["recorder"] = LocalBatchRecorder()
                for summary in demo["batches"]:
                    history[str(summary["batch_id"])] = summary
                for item in demo["review_items"]:
                    review_items[str(item["id"])] = item
                audit_log.extend(reversed(demo["audit_log"]))
                persist_exchange_state()
                return {
                    **demo,
                    "readiness": _readiness_payload(),
                    "dashboard_metrics": current_dashboard_metrics(),
                }

    @app.post("/api/review-items/{item_id}/actions")
    def record_review_action(item_id: str, request: ReviewActionRequest, http_request: Request) -> dict[str, Any]:
        actor = _authenticated_principal(http_request, require_submitter=True)
        with state_lock:
            item = review_items.get(item_id)
            if item is None:
                raise HTTPException(status_code=404, detail="review item not found")
            action = next((candidate for candidate in item.get("next_actions", []) if candidate.get("id") == request.action_id), None)
            if action is None:
                raise HTTPException(status_code=400, detail="action is not available for this review item")
            item["status"] = _status_after_action(request.action_id)
            item["updated_at"] = _now_iso()
            item["assigned_to"] = actor
            item.setdefault("history", []).append(
                {
                    "at": _now_iso(),
                    "actor": actor,
                    "action": request.action_id,
                    "note": request.note or str(action.get("detail", "")),
                }
            )
            _add_audit_event(
                audit_log,
                event_type="review_action",
                actor=actor,
                batch_id=str(item.get("batch_id", "")),
                claim_id=str(item.get("claim_id", "")),
                description=str(action.get("label", request.action_id)),
                outcome=item["status"],
                metadata={"review_item_id": item_id, "note": request.note},
            )
            persist_exchange_state()
            return {"item": item, "audit_log": list(reversed(audit_log)), "dashboard_metrics": current_dashboard_metrics()}

    @app.post("/api/session/reset")
    def reset_session(request: Request) -> dict[str, Any]:
        _authenticated_principal(request, require_submitter=True)
        if _is_production_env():
            raise HTTPException(status_code=403, detail="session reset is disabled in production")
        _ensure_local_operator_defaults()
        with batch_lock:
            with state_lock:
                history.clear()
                review_items.clear()
                audit_log.clear()
                provider_audit_log.clear()
                provider_requests[:] = _default_provider_requests()
                provider_packets.clear()
                provider_messages.clear()
                operator_claim_states.clear()
                portal_state["recorder"] = LocalBatchRecorder()
                persist_exchange_state()
                return {"ok": True}

    return app


app = create_app()
