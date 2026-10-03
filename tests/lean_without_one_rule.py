"""A writer whose Lean answers as if one rule were missing, so only the whole-store checker can still refuse the result.

Lean re-derives the shortfall, the due date and the pack dates, and the checker re-derives every evaluation from its
input, so a raw row edit cannot leave one defect alone.  Instead the writer is made to ask Lean a nearby request that
Lean accepts, and Lean's own accepted answer is turned into the bad decision.  The post-state is Lean's evaluation of
the rows the writer actually wrote, so every binding the owner checks still runs.  The owner's pre-commit check is
left alone: a test patches ``_verify_before_commit`` out for the writer that misses that too."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields
from typing import Any
from unittest.mock import patch

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner
from app import right_rail_financial_semantic_adapter as semantic

_OFFSET_EFFECTS = ["DETERMINATION_RECORDED", "CLAIM_AUTHORIZED", "CASE_UPSERTED", "ACTION_CREATED", "OUTBOX_CREATED", "PROJECTION_RECOMPUTED", "EVENT_APPENDED"]


def _as_offset(answer: dict[str, Any], keep_case: bool) -> None:
    """Lean's accepted correction answer, retargeted to authorize the offset (its claim amount) instead.
    An outstanding correction keeps the case as it is, as in a real offset answer."""
    mutation = answer["mutation"]
    deps, det, action = mutation["dependencies"], mutation["determination"], mutation["action"]
    case = mutation["case_delta"]["record"]
    answer["explanation"] = {**answer["explanation"], "transition": "OFFSET_AUTHORIZED", "code": "OFFSET_AUTHORIZED"}
    mutation["transition"] = mutation["event"]["kind"] = det["decision"] = "OFFSET_AUTHORIZED"
    mutation["ordered_effects"] = list(_OFFSET_EFFECTS)
    det["amount_cents"] = action["amount_cents"] = deps["claim_before"]["amount_cents"]
    action["kind"] = "OFFSET_AUTHORIZATION"
    action["payload_digest"] = owner._digest(owner._ACTION_DOMAIN, owner._canonical({
        "action_id": action["action_id"], "amount_cents": action["amount_cents"], "claim_id": deps["claim_before"]["claim_id"],
        "currency": action["currency"], "determination_id": action["determination_id"], "dispatch": "SYNTHETIC_RECORD_ONLY",
        "input_evaluation_id": deps["input_evaluation_id"], "input_evaluation_result_digest": owner._hex(deps["input_evaluation_result_digest"]),
        "kind": "OFFSET_AUTHORIZATION", "obligation_id": action["obligation_id"], "revision": action["revision"],
    }))
    if not keep_case:
        case["reason"], case["next_action_owner"], case["due_at_ms"] = "OFFSET_AUTHORIZED", "CASE_OWNER", deps["claim_before"]["deadline_at_ms"]


@contextmanager
def lean_without_one_rule(
    store: owner.FinancialOwner,
    *,
    exceeds_shortfall: bool = False,
    stale_owner_now: bool = False,
    lift_decision_to_ms: int | None = None,
) -> Iterator[None]:
    """``exceeds_shortfall``: Lean's accepted correction for the same request becomes the offset.  ``stale_owner_now``: Lean is
    asked with the owner clock at the decision time.  ``lift_decision_to_ms``: Lean is asked with the decision (and clock) no
    earlier than that time, which is when the pack is approved and in effect."""
    encode, run, correction, bind, apply = engine.encode_correction_transition_request, engine.run_offset_authorization_v1, engine.run_correction_transition_v1, semantic.bind_resulting_state, owner.FinancialOwner._apply_accepted_correction_transition
    commands: list[dict[str, Any]] = []

    def asked_encode(**kwargs: Any) -> bytes:
        command = kwargs["command"]
        commands.append(command)
        asked = dict(command)
        if stale_owner_now:
            asked["owner_now_ms"] = asked["decision_at_ms"]
        if lift_decision_to_ms is not None:
            asked["decision_at_ms"] = max(asked["decision_at_ms"], lift_decision_to_ms)
            asked["owner_now_ms"] = max(asked["owner_now_ms"], asked["decision_at_ms"])
        return encode(**{**kwargs, "command": asked})

    def answered(*, request: bytes) -> dict[str, Any]:
        command = commands[-1]
        answer = (correction if exceeds_shortfall else run)(request=request)
        mutation = answer["mutation"]
        now = max(command["decision_at_ms"], command["owner_now_ms"])
        deps, event = mutation["dependencies"], mutation["event"]
        deps["decision_at_ms"], deps["owner_now_ms"] = command["decision_at_ms"], command["owner_now_ms"]
        mutation["determination"]["decided_at_ms"] = command["decision_at_ms"]
        event["committed_at_ms"] = mutation["outbox"]["updated_at_ms"] = mutation["action"]["created_at_ms"] = mutation["case_delta"]["record"]["updated_at_ms"] = now
        return answer

    def applying(self: owner.FinancialOwner, connection: Any, **kwargs: Any) -> dict[str, Any]:
        if exceeds_shortfall:
            prior = connection.execute("SELECT reason FROM cases WHERE obligation_id=?", (kwargs["obligation"]["obligation_id"],)).fetchone()
            _as_offset(kwargs["transition_result"], prior is not None and prior["reason"] == "CORRECTION_REQUIRED")
        return apply(self, connection, **kwargs)

    def bound_to_lean(connection: Any, before: Any, *, authority_context: Any, evaluation_time_ms: int, mutation: dict[str, Any]) -> None:
        """The post-state is Lean's evaluation of the written rows (the case status they carry is part of that input)."""
        scope = {"scope": store._scope_value(), "owner_id": store.owner_id, "mode": store.mode}
        for _ in range(3):
            lean = engine.evaluate_live(connection, obligation_id=before.obligation_id, authority_context=authority_context, evaluation_time_ms=evaluation_time_ms, verification=scope)
            if connection.execute("UPDATE cases SET status=? WHERE obligation_id=? AND status<>?", (lean.case_status, before.obligation_id, lean.case_status)).rowcount == 0:
                break
        for field in fields(lean):
            object.__setattr__(mutation["resulting_result"], field.name, getattr(lean, field.name))
        mutation["resulting_result_wire"] = semantic._encode_blfres02_result(lean)
        mutation["case_delta"]["record"]["status"] = lean.case_status
        mutation["resulting_input_wire"] = semantic.live_evaluation_input(
            connection, obligation_id=before.obligation_id, authority_context=authority_context, evaluation_time_ms=evaluation_time_ms, verification=scope,
        )[0]
        bind(connection, before, authority_context=authority_context, evaluation_time_ms=evaluation_time_ms, mutation=mutation)

    with (
        patch.object(engine, "encode_correction_transition_request", asked_encode),
        patch.object(engine, "run_offset_authorization_v1", answered),
        patch.object(semantic, "bind_resulting_state", bound_to_lean),
        patch.object(owner.FinancialOwner, "_apply_accepted_correction_transition", applying),
    ):
        yield
