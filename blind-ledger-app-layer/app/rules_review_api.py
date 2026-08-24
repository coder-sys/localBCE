from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .rules_review_auth import RulesAuthError, RulesPrincipal, authenticate_rules_request


_ROOT = Path(__file__).resolve().parents[2]
_RULES_SRC = _ROOT / "gov-rules-kg-prototype" / "src"
if _RULES_SRC.is_dir() and str(_RULES_SRC) not in sys.path:
    sys.path.insert(0, str(_RULES_SRC))


def _review_error_status(exc: Exception) -> int:
    return 403 if isinstance(exc, RulesAuthError) else 409


try:
    from fastapi import APIRouter, Depends, Header, HTTPException, Request
    from pydantic import BaseModel, Field

    from gov_rules_kg.postgres_corpus import CorpusDatabaseError, PostgresCorpusStore
except Exception:  # pragma: no cover - optional app dependency gate
    APIRouter = None


if APIRouter:
    router = APIRouter(prefix="/rules", tags=["rules-review"])

    class DecisionBody(BaseModel):
        decision: str
        rationale: str = Field(min_length=1, max_length=4000)

    class ConflictDecisionBody(DecisionBody):
        selected_draft_id: str = Field(min_length=1, max_length=128)

    class QualityMeasurements(BaseModel):
        evidence_span_precise: bool
        typed_mapping_correct: bool
        program_classification_correct: bool
        deterministic_rerun_match: bool

    class QualityReviewBody(BaseModel):
        candidate_id: str = Field(min_length=1, max_length=128)
        draft_hash: str = Field(min_length=64, max_length=64)
        rationale: str = Field(min_length=1, max_length=4000)
        measurements: QualityMeasurements

    class SourceDecisionBody(BaseModel):
        decision: str
        rationale: str = Field(min_length=1, max_length=4000)

    def principal(
        request: Request,
        authorization: str | None = Header(default=None),
        x_local_reviewer_id: str | None = Header(default=None),
        x_local_reviewer_roles: str | None = Header(default=None),
    ) -> RulesPrincipal:
        try:
            return authenticate_rules_request(
                client_host=request.client.host if request.client else "",
                authorization=authorization,
                local_subject=x_local_reviewer_id,
                local_roles=x_local_reviewer_roles,
            )
        except RulesAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def store() -> PostgresCorpusStore:
        try:
            return PostgresCorpusStore()
        except CorpusDatabaseError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    def _one_role(user: RulesPrincipal) -> str:
        for role in ("policy_reviewer", "legal_verifier", "rules_admin"):
            if role in user.roles:
                return role
        raise HTTPException(status_code=403, detail="rules-review role is required")

    @router.get("/tasks")
    def tasks(
        limit: int = 100,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        return {"role": role, "tasks": corpus.list_review_tasks(role, limit=limit)}

    @router.post("/tasks/claim")
    def claim_task(
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        return {"task": corpus.claim_review_task(user.subject, role)}

    @router.get("/candidates/{candidate_id}")
    def candidate(
        candidate_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        _one_role(user)
        try:
            return corpus.candidate_review_detail(candidate_id)
        except CorpusDatabaseError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/tasks/{task_id}/renew")
    def renew_task_claim(
        task_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        try:
            return corpus.renew_review_task_claim(
                task_id,
                reviewer_id=user.subject,
                reviewer_role=role,
            )
        except (CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/tasks/{task_id}/release")
    def release_task_claim(
        task_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        try:
            return corpus.release_review_task_claim(
                task_id,
                reviewer_id=user.subject,
                reviewer_role=role,
            )
        except (CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    def _record(
        task_id: str,
        body: DecisionBody,
        required_role: str,
        user: RulesPrincipal,
        corpus: PostgresCorpusStore,
        selected_draft_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            user.require(required_role)
            decision_id = corpus.record_review_decision(
                task_id=task_id,
                reviewer_id=user.subject,
                reviewer_role=required_role,
                decision=body.decision,
                rationale=body.rationale,
                selected_draft_id=selected_draft_id,
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=_review_error_status(exc), detail=str(exc)) from exc
        return {"decision_id": decision_id, "runtime_activation": False, "proof_binding": False}

    @router.post("/tasks/{task_id}/policy-decision")
    def policy_decision(
        task_id: str,
        body: DecisionBody,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        return _record(task_id, body, "policy_reviewer", user, corpus)

    @router.post("/tasks/{task_id}/legal-decision")
    def legal_decision(
        task_id: str,
        body: DecisionBody,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        return _record(task_id, body, "legal_verifier", user, corpus)

    @router.post("/tasks/{task_id}/conflict-decision")
    def conflict_decision(
        task_id: str,
        body: ConflictDecisionBody,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        return _record(task_id, body, "rules_admin", user, corpus, body.selected_draft_id)

    @router.get("/quality")
    def quality(
        release_id: str | None = None,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        _one_role(user)
        quality_inputs = (
            corpus.quality_measurements(release_id=release_id)
            if release_id
            else corpus.quality_measurements()
        )
        return {
            "release_id": release_id,
            "metrics": corpus.rules_metrics(),
            "quality_inputs": quality_inputs,
        }

    @router.get("/sources/preflight")
    def source_preflight_summary(
        target_count: int = 5_100,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        try:
            user.require("rules_admin")
            return corpus.source_registry_preflight_summary(
                target_count=target_count
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(
                status_code=_review_error_status(exc), detail=str(exc)
            ) from exc

    @router.post("/sources/tasks/claim")
    def claim_source_task(
        program: str | None = None,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        try:
            user.require("rules_admin")
            task = corpus.claim_source_registry_candidate(
                reviewer_id=user.subject,
                program=program,
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(
                status_code=_review_error_status(exc), detail=str(exc)
            ) from exc
        return {"task": task}

    @router.get("/sources/candidates/{source_candidate_id}")
    def source_candidate(
        source_candidate_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        _one_role(user)
        try:
            return corpus.source_registry_candidate_detail(source_candidate_id)
        except CorpusDatabaseError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/sources/tasks/{source_candidate_id}/renew")
    def renew_source_task_claim(
        source_candidate_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        try:
            user.require("rules_admin")
            return corpus.renew_source_registry_candidate_claim(
                source_candidate_id,
                reviewer_id=user.subject,
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(
                status_code=_review_error_status(exc), detail=str(exc)
            ) from exc

    @router.post("/sources/tasks/{source_candidate_id}/release")
    def release_source_task_claim(
        source_candidate_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        try:
            user.require("rules_admin")
            return corpus.release_source_registry_candidate_claim(
                source_candidate_id,
                reviewer_id=user.subject,
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(
                status_code=_review_error_status(exc), detail=str(exc)
            ) from exc

    @router.post("/sources/tasks/{source_candidate_id}/decision")
    def submit_source_decision(
        source_candidate_id: str,
        body: SourceDecisionBody,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        try:
            user.require("rules_admin")
            return corpus.record_source_registry_candidate_decision(
                source_candidate_id=source_candidate_id,
                reviewer_id=user.subject,
                decision=body.decision,
                rationale=body.rationale,
            )
        except (RulesAuthError, CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(
                status_code=_review_error_status(exc), detail=str(exc)
            ) from exc

    @router.post("/quality/tasks/claim")
    def claim_quality_task(
        release_id: str | None = None,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        if role not in {"policy_reviewer", "legal_verifier"}:
            raise HTTPException(
                status_code=403,
                detail="quality review requires policy_reviewer or legal_verifier",
            )
        return {
            "task": corpus.claim_quality_sample(
                reviewer_id=user.subject,
                reviewer_role=role,
                release_id=release_id,
            )
        }

    @router.post("/quality/tasks/{sample_id}/review")
    def submit_quality_review(
        sample_id: str,
        body: QualityReviewBody,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        if role not in {"policy_reviewer", "legal_verifier"}:
            raise HTTPException(
                status_code=403,
                detail="quality review requires policy_reviewer or legal_verifier",
            )
        submission = {
            "schema_version": "localbce-rules-quality-review-v1",
            "sample_id": sample_id,
            "candidate_id": body.candidate_id,
            "draft_hash": body.draft_hash,
            "reviewer_id": user.subject,
            "reviewer_role": role,
            "measurements": (
                body.measurements.model_dump()
                if hasattr(body.measurements, "model_dump")
                else body.measurements.dict()
            ),
            "rationale": body.rationale,
            "runtime_activation": False,
            "proof_binding": False,
        }
        try:
            return corpus.record_quality_review(submission)
        except (CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/quality/tasks/{sample_id}/renew")
    def renew_quality_task_claim(
        sample_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        if role not in {"policy_reviewer", "legal_verifier"}:
            raise HTTPException(
                status_code=403,
                detail="quality review requires policy_reviewer or legal_verifier",
            )
        try:
            return corpus.renew_quality_sample_claim(
                sample_id,
                reviewer_id=user.subject,
                reviewer_role=role,
            )
        except (CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/quality/tasks/{sample_id}/release")
    def release_quality_task_claim(
        sample_id: str,
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        role = _one_role(user)
        if role not in {"policy_reviewer", "legal_verifier"}:
            raise HTTPException(
                status_code=403,
                detail="quality review requires policy_reviewer or legal_verifier",
            )
        try:
            return corpus.release_quality_sample_claim(
                sample_id,
                reviewer_id=user.subject,
                reviewer_role=role,
            )
        except (CorpusDatabaseError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
else:
    router = None
