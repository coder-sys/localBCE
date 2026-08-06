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
        user: RulesPrincipal = Depends(principal),
        corpus: PostgresCorpusStore = Depends(store),
    ) -> dict[str, Any]:
        _one_role(user)
        return {"metrics": corpus.rules_metrics(), "quality_inputs": corpus.quality_measurements()}
else:
    router = None
