from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Mapping
from typing import Dict, List, Optional
from datetime import datetime
from decimal import Decimal, InvalidOperation

from .ingestion import Parsed837, segment_map
from .models import Patient, Provider, ServiceLine, SharedContext
from .oracle_attestation import resolve_attested_flags

MAX_AMOUNT_CENTS = (2**32) - 1
CANONICAL_MEMBER_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
CANONICAL_PROCEDURE_RE = re.compile(r"^[A-Z0-9]{2,10}$")
CANONICAL_DIAGNOSIS_RE = re.compile(r"^[A-Z0-9.]{1,16}$")
CANONICAL_IDENTIFIER_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
CANONICAL_NAME_RE = re.compile(r"^[A-Z0-9][A-Z0-9 .'-]{0,99}$")


def _money(value: str) -> float:
    try:
        parsed_decimal = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid_money:{value}") from exc
    if not math.isfinite(float(parsed_decimal)):
        raise ValueError(f"invalid_money:{value}")
    if parsed_decimal != parsed_decimal.quantize(Decimal("0.01")):
        raise ValueError(f"noncanonical_money:{value}")
    cents = int(parsed_decimal * 100)
    if cents < 0:
        raise ValueError(f"amount_out_of_range:{value}")
    if cents > MAX_AMOUNT_CENTS:
        raise ValueError(f"amount_out_of_range:{value}")
    return float(parsed_decimal)


def _require_nfc(value: str, label: str) -> str:
    if value != unicodedata.normalize("NFC", value):
        raise ValueError(f"noncanonical_{label}")
    return value


def _canonical_member_id(value: str) -> str:
    if value == "":
        return value
    _require_nfc(value, "member_id")
    if value != value.strip() or value != value.upper() or not CANONICAL_MEMBER_RE.fullmatch(value):
        raise ValueError("noncanonical_member_id")
    if value.isdigit() and len(value) > 1 and value.startswith("0"):
        raise ValueError("noncanonical_member_id")
    return value


def _npi_check_digit_ok(value: str) -> bool:
    if not re.fullmatch(r"\d{10}", value):
        return False
    payload = "80840" + value[:9]
    total = 0
    reverse_digits = [int(ch) for ch in payload[::-1]]
    for idx, digit in enumerate(reverse_digits, start=1):
        if idx % 2 == 1:
            doubled = digit * 2
            total += doubled // 10 + doubled % 10
        else:
            total += digit
    expected = (10 - (total % 10)) % 10
    return expected == int(value[-1])


def _canonical_npi(value: str) -> str:
    if value == "":
        return value
    if value != value.strip() or not re.fullmatch(r"\d{10}", value):
        raise ValueError("noncanonical_npi")
    if not _npi_check_digit_ok(value):
        raise ValueError("invalid_npi_check_digit")
    return value


def _canonical_identifier(value: str, label: str) -> str:
    if value == "":
        return value
    _require_nfc(value, label)
    if value != value.strip() or value != value.upper() or not CANONICAL_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"noncanonical_{label}")
    return value


def _canonical_name(value: str, label: str) -> str:
    if value == "":
        return value
    _require_nfc(value, label)
    if value != value.strip() or value != value.upper() or not CANONICAL_NAME_RE.fullmatch(value):
        raise ValueError(f"noncanonical_{label}")
    return value


def _canonical_diagnosis(value: str) -> str:
    if value == "":
        raise ValueError("noncanonical_diagnosis")
    _require_nfc(value, "diagnosis")
    if value != value.strip() or value != value.upper() or not CANONICAL_DIAGNOSIS_RE.fullmatch(value):
        raise ValueError("noncanonical_diagnosis")
    return value


def _canonical_service_date(value: str) -> str:
    if value != value.strip() or not re.fullmatch(r"\d{8}", value):
        raise ValueError("noncanonical_service_date")
    try:
        datetime.strptime(value, "%Y%m%d")
    except ValueError as exc:
        raise ValueError("noncanonical_service_date") from exc
    return value


def _canonical_procedure_code(value: str) -> str:
    _require_nfc(value, "procedure_code")
    if value != value.strip() or value != value.upper() or not CANONICAL_PROCEDURE_RE.fullmatch(value):
        raise ValueError("noncanonical_procedure_code")
    return value


def _strict_bool(flags: Dict[str, object], key: str, default: bool) -> bool:
    if key not in flags:
        return default
    value = flags[key]
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        if value in {0, 0.0}:
            return False
        if value in {1, 1.0}:
            return True
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            return True
        if normalized in {"false", "0", "no", "n", ""}:
            return False
    raise ValueError(f"invalid_bool:{key}")


def _find_nm1(segments: List[List[str]], entity: str) -> Optional[List[str]]:
    for seg in segments:
        if len(seg) > 1 and seg[1] == entity:
            return seg
    return None


def build_shared_context(
    parsed: Parsed837,
    flags: Dict[str, bool] | None = None,
    *,
    oracle_attestations: List[object] | None = None,
    strict_oracle: bool = True,
) -> SharedContext:
    if not parsed.accepted:
        raise ValueError("cannot build context from rejected 837")
    by_tag = segment_map(parsed)
    clm = by_tag["CLM"][0]
    bht = by_tag.get("BHT", [["", "", "", clm[1] if len(clm) > 1 else "UNKNOWN"]])[0]
    claim_id = clm[1] if len(clm) > 1 else bht[3]
    if flags is not None and not isinstance(flags, Mapping):
        raise ValueError("flags must be an object")
    flags, fact_verification = resolve_attested_flags(
        dict(flags or {}),
        oracle_attestations,
        strict=strict_oracle,
        required_facts=("eligibility_active", "provider_enrolled", "provider_not_suspended", "not_deceased"),
        claim_id=claim_id,
    )
    payer = _find_nm1(by_tag.get("NM1", []), "PR") or []
    subscriber = _find_nm1(by_tag.get("NM1", []), "IL") or []
    provider = _find_nm1(by_tag.get("NM1", []), "82") or _find_nm1(by_tag.get("NM1", []), "41") or []
    payer_id = _canonical_identifier(payer[-1] if payer else "", "payer_id")
    member_id = _canonical_member_id(subscriber[-1] if subscriber else "")
    patient_name = _canonical_name(
        " ".join(part for part in [subscriber[3] if len(subscriber) > 3 else "", subscriber[4] if len(subscriber) > 4 else ""] if part),
        "patient_name",
    )
    provider_npi = _canonical_npi(provider[-1] if provider else "")
    provider_name = _canonical_name(
        " ".join(part for part in [provider[3] if len(provider) > 3 else "", provider[4] if len(provider) > 4 else ""] if part),
        "provider_name",
    )
    diagnoses = []
    for hi in by_tag.get("HI", []):
        for element in hi[1:]:
            parts = element.split(":")
            if len(parts) > 1:
                diagnoses.append(_canonical_diagnosis(parts[1]))
    service_date = ""
    for dtp in by_tag.get("DTP", []):
        if len(dtp) > 3 and dtp[1] == "472":
            service_date = dtp[3]
    if not service_date:
        raise ValueError("missing_service_date")
    service_date = _canonical_service_date(service_date)
    prior_auth = None
    for ref in by_tag.get("REF", []):
        if len(ref) > 2 and ref[1] in {"G1", "9F"}:
            prior_auth = ref[2]
    service_lines = []
    for idx, sv1 in enumerate(by_tag.get("SV1", []), start=1):
        proc = _canonical_procedure_code(sv1[1].split(":")[-1] if len(sv1) > 1 else "")
        charge = _money(sv1[2]) if len(sv1) > 2 else 0.0
        units = _money(sv1[4]) if len(sv1) > 4 else 1.0
        if units <= 0:
            raise ValueError("invalid_service_units")
        service_lines.append(ServiceLine(str(idx), proc, charge, units, prior_auth))
    service_total = round(sum(line.charge_amount for line in service_lines), 2)
    if len(clm) > 2:
        total = _money(clm[2])
        if service_lines and abs(total - service_total) > 0.01:
            raise ValueError("claim_total_mismatch")
    else:
        total = service_total
    return SharedContext(
        claim_id=claim_id,
        transaction_set="837",
        payer_id=payer_id,
        member_id=member_id,
        patient=Patient(name=patient_name, id=member_id),
        provider=Provider(npi=provider_npi, name=provider_name),
        service_date=service_date,
        diagnoses=diagnoses,
        service_lines=service_lines,
        total_charge=total,
        flags={
            "eligibility_active": _strict_bool(flags, "eligibility_active", False),
            "provider_enrolled": _strict_bool(flags, "provider_enrolled", False),
            "provider_not_suspended": _strict_bool(flags, "provider_not_suspended", False),
            "not_deceased": _strict_bool(flags, "not_deceased", False),
            "duplicate_claim": _strict_bool(flags, "duplicate_claim", False),
            "program_integrity_hold": _strict_bool(flags, "program_integrity_hold", False),
        },
        fact_verification=fact_verification,
    )
