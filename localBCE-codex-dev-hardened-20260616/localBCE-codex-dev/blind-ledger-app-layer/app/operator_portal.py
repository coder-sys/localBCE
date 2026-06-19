from __future__ import annotations

import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.batch.access_control import ADMIN, AUDITOR, OPERATOR, AccessDenied, RoleBook
from app.batch.batch_orchestrator import BatchConfig, LocalBatchRecorder, SubmittedBatch, batch_to_plain_dict, submit_batches
from app.batch.proof_status import REAL_PROOF_REQUIRED_STATUS
from app.operational_readiness import load_json, validate_launch_blockers, validate_verifier_pin_manifest
from app.production_readiness import CANONICAL_ONCHAIN_ANCHOR, CANONICAL_PROOF_LANE, production_readiness


APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = APP_ROOT / "operator_portal"
SAMPLE_CLAIM_PATH = APP_ROOT / "sample_claim_input.json"
OPS_ROOT = APP_ROOT.parent / "ops"
PRODUCTION_ENVS = {"prod", "production"}


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
    "excessive_charge": {
        "category": "Rules coverage review",
        "summary": "The charge exceeds the current threshold and needs fee-schedule or policy review.",
        "required_items": ["Fee schedule reference", "Policy reviewer sign-off"],
        "owner_queue": "Policy review",
        "priority": "Medium",
        "next_actions": [
            {"id": "check_fee_schedule", "label": "Check fee schedule", "detail": "Compare the charge against the applicable fee schedule."},
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


class BatchSubmitRequest(BaseModel):
    actor: str = Field(default="operator@example.gov")
    claims: list[dict[str, Any]] = Field(default_factory=list)
    strict_oracle_attestations: bool = True
    enforce_nullifier_proofs: bool = True


class ReviewActionRequest(BaseModel):
    actor: str = Field(default="operator@example.gov")
    action_id: str
    note: str = ""


def _portal_roles() -> RoleBook:
    roles = RoleBook()
    roles.grant(ADMIN, "admin@example.gov")
    roles.grant(OPERATOR, "operator@example.gov")
    roles.grant(AUDITOR, "auditor@example.gov")
    return roles


def _is_production_env() -> bool:
    return os.environ.get("BL_ENV", "").strip().lower() in PRODUCTION_ENVS


def _ensure_local_operator_defaults() -> None:
    if _is_production_env():
        return
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_PROVIDER_ALIAS_KEY", "BL_OPERATOR_PORTAL_LOCAL_PROVIDER_ALIAS_KEY")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")


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
    if reason in {"member_id_missing", "diagnosis_missing", "service_line_missing", "invalid_charge", "excessive_charge"}:
        return "cif_resubmission"
    if reason in {"eligibility_inactive", "prior_authorization_required", "provider_not_enrolled"}:
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
        "id": f"audit-{len(audit_log) + 1:06d}",
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
                amount_cents=int(round(packet.payable_amount * 100)),
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
        review["raw_errors"] = item.errors
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


def _batch_summary(batch: SubmittedBatch) -> dict[str, Any]:
    plain = batch_to_plain_dict(batch)
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
            "fee_schedule_root": batch.fee_schedule_root,
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
                "payable_amount": packet.payable_amount,
                "engine_mode": packet.engine_mode,
                "remittance_835": packet.remittance_835,
            }
            for packet in batch.claim_packets
        ],
        "payments": [
            {
                "provider_payment_key": payment.provider_payment_key,
                "recipient_address": payment.recipient_address,
                "approved_claim_count": payment.approved_claim_count,
                "amount_cents": payment.amount_cents,
                "settlement": payment.settlement,
            }
            for payment in batch.payments
        ],
        "quarantined": [asdict(item) for item in batch.quarantined],
        "plain": plain,
    }


def create_app() -> FastAPI:
    app = FastAPI(title="Blind Ledger Medi-Cal Operator Portal", docs_url=None, redoc_url=None)
    portal_state: dict[str, LocalBatchRecorder | None] = {"recorder": None}
    history: dict[str, dict[str, Any]] = {}
    review_items: dict[str, dict[str, Any]] = {}
    audit_log: list[dict[str, Any]] = []

    def get_recorder() -> LocalBatchRecorder:
        if portal_state["recorder"] is None:
            portal_state["recorder"] = LocalBatchRecorder()
        return portal_state["recorder"]

    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")

    @app.middleware("http")
    async def no_cache_operator_portal(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_ROOT / "index.html")

    @app.get("/api/readiness")
    def readiness() -> dict[str, Any]:
        return _readiness_payload()

    @app.get("/api/sample-claim")
    def sample_claim() -> dict[str, Any]:
        return load_json(SAMPLE_CLAIM_PATH)

    @app.get("/api/batches")
    def list_batches() -> dict[str, Any]:
        return {"batches": list(history.values())}

    @app.get("/api/review-items")
    def list_review_items() -> dict[str, Any]:
        ordered = sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"]))
        return {"items": ordered}

    @app.get("/api/audit-log")
    def list_audit_log() -> dict[str, Any]:
        return {"events": list(reversed(audit_log))}

    @app.get("/api/workspace")
    def workspace() -> dict[str, Any]:
        return {
            "readiness": _readiness_payload(),
            "batches": list(history.values()),
            "review_items": sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"])),
            "audit_log": list(reversed(audit_log)),
        }

    @app.post("/api/batches")
    def create_batch(request: BatchSubmitRequest) -> dict[str, Any]:
        _ensure_local_operator_defaults()
        if not request.claims:
            raise HTTPException(status_code=400, detail="at least one claim is required")
        config = BatchConfig(
            strict_oracle_attestations=request.strict_oracle_attestations,
            enforce_nullifier_proofs=request.enforce_nullifier_proofs,
        )
        try:
            batches = submit_batches(
                request.claims,
                actor=request.actor,
                access=_portal_roles(),
                config=config,
                recorder=get_recorder(),
            )
        except AccessDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        summaries = [_batch_summary(batch) for batch in batches]
        for batch, summary in zip(batches, summaries):
            _add_batch_workflow_events(
                batch=batch,
                summary=summary,
                actor=request.actor,
                review_items=review_items,
                audit_log=audit_log,
            )
            history[str(summary["batch_id"])] = summary
        return {
            "batches": summaries,
            "readiness": _readiness_payload(),
            "review_items": sorted(review_items.values(), key=lambda item: (item["status"] != "open", item["created_at"])),
            "audit_log": list(reversed(audit_log)),
        }

    @app.post("/api/review-items/{item_id}/actions")
    def record_review_action(item_id: str, request: ReviewActionRequest) -> dict[str, Any]:
        item = review_items.get(item_id)
        if item is None:
            raise HTTPException(status_code=404, detail="review item not found")
        action = next((candidate for candidate in item.get("next_actions", []) if candidate.get("id") == request.action_id), None)
        if action is None:
            raise HTTPException(status_code=400, detail="action is not available for this review item")
        item["status"] = _status_after_action(request.action_id)
        item["updated_at"] = _now_iso()
        item["assigned_to"] = request.actor
        item.setdefault("history", []).append(
            {
                "at": _now_iso(),
                "actor": request.actor,
                "action": request.action_id,
                "note": request.note or str(action.get("detail", "")),
            }
        )
        _add_audit_event(
            audit_log,
            event_type="review_action",
            actor=request.actor,
            batch_id=str(item.get("batch_id", "")),
            claim_id=str(item.get("claim_id", "")),
            description=str(action.get("label", request.action_id)),
            outcome=item["status"],
            metadata={"review_item_id": item_id, "note": request.note},
        )
        return {"item": item, "audit_log": list(reversed(audit_log))}

    @app.post("/api/session/reset")
    def reset_session() -> dict[str, Any]:
        if _is_production_env():
            raise HTTPException(status_code=403, detail="session reset is disabled in production")
        _ensure_local_operator_defaults()
        history.clear()
        review_items.clear()
        audit_log.clear()
        portal_state["recorder"] = LocalBatchRecorder()
        return {"ok": True}

    return app


app = create_app()
