from __future__ import annotations

from datetime import datetime, timezone
import math

from .models import AdjudicationResult, SharedContext


X12_FORBIDDEN_CHARS = {"*", "~", ":", "^", "\r", "\n"}


def _x12_text(value: object, field: str) -> str:
    text = "" if value is None else str(value)
    if any(char in text for char in X12_FORBIDDEN_CHARS) or any(ord(char) < 32 for char in text):
        raise ValueError(f"unsafe_835_field:{field}")
    return text


def _x12_amount(value: object, field: str) -> str:
    try:
        amount = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"malformed_835_amount:{field}") from exc
    if not math.isfinite(amount):
        raise ValueError(f"non_finite_835_amount:{field}")
    return f"{amount:.2f}"


def generate_835(ctx: SharedContext, result: AdjudicationResult) -> str:
    if ctx is None or result is None:
        raise ValueError("malformed_835_input")
    if not getattr(ctx, "claim_id", "") or not getattr(ctx, "provider", None):
        raise ValueError("malformed_835_input")
    if not hasattr(result, "approved") or not hasattr(result, "payable_amount"):
        raise ValueError("malformed_835_input")
    if getattr(result, "claim_id", None) != ctx.claim_id:
        raise ValueError("claim_id_mismatch_835")

    claim_id = _x12_text(ctx.claim_id, "claim_id")
    provider_name = _x12_text(ctx.provider.name or "PROVIDER", "provider_name")
    provider_npi = _x12_text(ctx.provider.npi, "provider_npi")
    denial_reason = _x12_text(result.denial_reason, "denial_reason")
    carc = _x12_text(result.carc, "carc")
    rarc = _x12_text(result.rarc, "rarc")

    now = datetime.now(timezone.utc).strftime("%Y%m%d")
    status = "1" if result.approved else "4"
    payment = _x12_amount(result.payable_amount, "payable_amount")
    total_charge = _x12_amount(ctx.total_charge, "total_charge")
    segments = [
        "ISA*00*          *00*          *ZZ*BLINDLEDGER    *ZZ*PROVIDER       *260612*1200*^*00501*000000001*0*T*:~",
        "GS*HP*BLINDLEDGER*PROVIDER*20260612*1200*1*X*005010X221A1~",
        "ST*835*0001~",
        f"BPR*I*{payment}*C*CHK************{now}~",
        f"TRN*1*{claim_id}*1512345678~",
        "N1*PR*MEDICAID PAYER~",
        f"N1*PE*{provider_name}*XX*{provider_npi}~",
        f"CLP*{claim_id}*{status}*{total_charge}*{payment}**MC*{claim_id}*11~",
    ]
    if result.approved:
        for line in ctx.service_lines:
            procedure_code = _x12_text(line.procedure_code, "procedure_code")
            line_charge = _x12_amount(line.charge_amount, "service_charge")
            units = float(line.units)
            if not math.isfinite(units):
                raise ValueError("non_finite_835_amount:service_units")
            segments.append(f"SVC*HC:{procedure_code}*{line_charge}*{line_charge}**{units:g}~")
    else:
        segments.append(f"CAS*CO*{carc}*{total_charge}~")
        if rarc:
            segments.append(f"LQ*HE*{rarc}~")
        segments.append(f"PLB*{provider_npi}*{now}*WO:{denial_reason}*0~")
    st_index = 2
    se_count = len(segments) - st_index + 1
    segments.extend([f"SE*{se_count}*0001~", "GE*1*1~", "IEA*1*000000001~"])
    return "\n".join(segments)
