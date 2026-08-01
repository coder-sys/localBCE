from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from .models import AdjudicationResult, SharedContext
from .money import MAX_AMOUNT_CENTS_EXCLUSIVE, canonical_money_text
from .rules_engine_fallback import adjudicate as fallback_adjudicate


def canonical_rules_engine_context_payload(ctx: SharedContext) -> dict:
    payload = ctx.to_dict()
    payload["total_charge"] = canonical_money_text(ctx.total_charge)
    for encoded, line in zip(payload.get("service_lines", []), ctx.service_lines, strict=True):
        encoded["charge_amount"] = canonical_money_text(line.charge_amount)
        encoded["units"] = canonical_money_text(line.units)
    payload["tar_authorization_verified"] = (
        ctx.fact_verification.get("tar_authorization") == "VERIFIED"
    )
    return payload


def canonical_rules_engine_policy_payload(
    tar_required_codes=None,
    fee_schedule_cents=None,
) -> tuple[list[str] | None, dict[str, int] | None]:
    """Validate policy overrides without converting caller-supplied values."""

    encoded_tar_codes = None
    if tar_required_codes is not None:
        if isinstance(tar_required_codes, (str, bytes)):
            raise ValueError("tar_required_procedure_codes_invalid")
        encoded_tar_codes = list(tar_required_codes)
        if any(type(code) is not str for code in encoded_tar_codes):
            raise ValueError("tar_required_procedure_codes_invalid")

    encoded_fee_schedule = None
    if fee_schedule_cents is not None:
        if not isinstance(fee_schedule_cents, Mapping):
            raise ValueError("fee_schedule_cents_invalid")
        encoded_fee_schedule = {}
        for code, amount in fee_schedule_cents.items():
            if type(code) is not str:
                raise ValueError("policy_row_procedure_code_not_string")
            if type(amount) is not int:
                raise ValueError("policy_row_allowed_cents_not_integer")
            if not 0 <= amount < MAX_AMOUNT_CENTS_EXCLUSIVE:
                raise ValueError("policy_row_allowed_cents_out_of_range")
            encoded_fee_schedule[code] = amount
    return encoded_tar_codes, encoded_fee_schedule


def adjudicate(ctx: SharedContext, tar_required_codes=None, fee_schedule_cents=None) -> AdjudicationResult:
    tar_required_codes, fee_schedule_cents = canonical_rules_engine_policy_payload(
        tar_required_codes,
        fee_schedule_cents,
    )
    if os.environ.get("BL_FORCE_PYTHON_RULES_ENGINE") == "1":
        return fallback_adjudicate(ctx, tar_required_codes, fee_schedule_cents)
    cargo = shutil.which("cargo")
    crate = Path(__file__).resolve().parents[1] / "rules-engine-rust"
    if not cargo or not crate.exists():
        return fallback_adjudicate(ctx, tar_required_codes, fee_schedule_cents)
    try:
        context_payload = canonical_rules_engine_context_payload(ctx)
        request = context_payload
        if tar_required_codes is not None or fee_schedule_cents is not None:
            request = {
                "context": context_payload,
                "tar_required_procedure_codes": tar_required_codes,
                "fee_schedule_cents": fee_schedule_cents,
            }
        proc = subprocess.run(
            [cargo, "run", "--quiet", "--", json.dumps(request)],
            cwd=crate,
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        data = json.loads(proc.stdout)
        from .models import GateResult

        return AdjudicationResult(
            claim_id=data["claim_id"],
            approved=data["approved"],
            denial_reason=data.get("denial_reason", ""),
            gates=[GateResult(**gate) for gate in data.get("gates", [])],
            carc=data.get("carc", ""),
            rarc=data.get("rarc", ""),
            total_charge=float(data.get("total_charge", 0)),
            payable_amount=float(data.get("payable_amount", 0)),
        )
    except Exception:
        return fallback_adjudicate(ctx, tar_required_codes, fee_schedule_cents)
