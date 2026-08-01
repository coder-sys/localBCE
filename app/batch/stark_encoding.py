from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Iterable

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.canonical_order import canonical_diagnoses
from app.models import ServiceLine, SharedContext
from app.money import MAX_AMOUNT_CENTS_EXCLUSIVE, canonical_money_cents
from app.service_line_canonical import canonical_service_code_multiset, canonical_service_line_identities


MAX_CENTS = MAX_AMOUNT_CENTS_EXCLUSIVE
MAX_DATE_DAY = 2**32
MAX_NPI = 10**10
MAX_PACKED_BYTES = 31
NULLIFIER_PRF_SECRET_ENV = "BL_NULLIFIER_PRF_SECRET"
DEV_NULLIFIER_PRF_SECRET = "BL_LOCAL_DEV_NULLIFIER_PRF_SECRET_NOT_FOR_PRODUCTION"
PRODUCTION_ENV_VALUES = {"prod", "production"}


def _production_mode() -> bool:
    return os.environ.get("BL_ENV", "").strip().lower() in PRODUCTION_ENV_VALUES


def canonical_cents(amount: float | int | str | Decimal) -> int:
    try:
        return canonical_money_cents(amount)
    except ValueError as exc:
        if str(exc).startswith("amount_out_of_range:"):
            raise ValueError("amount_cents_out_of_range") from exc
        raise


def canonical_day_count(value: str | date | datetime) -> int:
    if isinstance(value, datetime):
        day = int(value.astimezone(timezone.utc).date().toordinal() - date(1970, 1, 1).toordinal())
    elif isinstance(value, date):
        day = int(value.toordinal() - date(1970, 1, 1).toordinal())
    else:
        raw = str(value).strip()
        if raw.isdigit() and len(raw) == 8:
            parsed = datetime.strptime(raw, "%Y%m%d").date()
        else:
            parsed = datetime.strptime(raw, "%Y-%m-%d").date()
        day = int(parsed.toordinal() - date(1970, 1, 1).toordinal())
    if day < 0 or day >= MAX_DATE_DAY:
        raise ValueError("date_day_out_of_range")
    return day


def canonical_npi(value: str | int) -> int:
    raw = str(value)
    if not re.fullmatch(r"[0-9]{10}", raw):
        raise ValueError("npi_must_be_10_decimal_digits")
    parsed = int(raw)
    if parsed <= 0 or parsed >= MAX_NPI:
        raise ValueError("npi_out_of_range")
    payload = "80840" + raw[:9]
    total = 0
    for index, character in enumerate(reversed(payload), start=1):
        digit = int(character)
        if index % 2 == 1:
            doubled = digit * 2
            total += doubled // 10 + doubled % 10
        else:
            total += digit
    if (10 - (total % 10)) % 10 != int(raw[-1]):
        raise ValueError("invalid_npi_check_digit")
    return parsed


def pack_felt_text(value: str, *, max_bytes: int = MAX_PACKED_BYTES) -> int:
    raw = value.encode("utf-8")
    if not raw or len(raw) > max_bytes:
        raise ValueError("packed_text_length_out_of_range")
    packed = len(raw)
    for byte in raw:
        packed = (packed << 8) | byte
    if packed >= FIELD_MODULUS:
        raise ValueError("packed_text_out_of_field")
    return packed


def packed_list_hash(domain: str, values: Iterable[str]) -> int:
    items = [str(value) for value in values]
    acc = domain_poseidon_hash(domain, [len(items)])
    for index, value in enumerate(items):
        acc = domain_poseidon_hash(domain, [len(items), index, acc, pack_felt_text(value)])
    return acc


def packed_service_lines_hash(domain: str, lines: Iterable[ServiceLine]) -> int:
    identities = canonical_service_line_identities(lines)
    acc = domain_poseidon_hash(domain, [len(identities)])
    for index, (procedure_code, charge_cents, units_cents, prior_authorization) in enumerate(identities):
        acc = domain_poseidon_hash(
            domain,
            [
                len(identities),
                index,
                acc,
                pack_felt_text(procedure_code),
                int(charge_cents),
                int(units_cents),
                0 if not prior_authorization else pack_felt_text(prior_authorization),
            ],
        )
    return acc


def _secret() -> bytes:
    configured = os.environ.get(NULLIFIER_PRF_SECRET_ENV)
    if configured:
        return configured.encode("utf-8")
    if _production_mode():
        raise RuntimeError(f"missing nullifier PRF secret: {NULLIFIER_PRF_SECRET_ENV}")
    if os.environ.get("BL_DEV") == "1":
        return DEV_NULLIFIER_PRF_SECRET.encode("utf-8")
    raise RuntimeError(f"missing nullifier PRF secret: {NULLIFIER_PRF_SECRET_ENV}")


def _prf_field(parts: list[int]) -> int:
    payload = "|".join(str(part) for part in parts).encode("utf-8")
    digest = hmac.new(_secret(), b"blind-ledger-nullifier-v1|" + payload, hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % FIELD_MODULUS


@dataclass(frozen=True)
class EncodedClaim:
    claim_id: int
    member_id: int
    provider_npi: int
    service_date: int
    procedure_codes_hash: int
    service_lines_commitment: int
    diagnosis_commitment: int
    total_charge_cents: int
    service_line_count: int
    diagnosis_count: int


def encode_claim(ctx: SharedContext) -> EncodedClaim:
    if not ctx.service_lines:
        raise ValueError("service_lines_missing")
    diagnoses = canonical_diagnoses(ctx.diagnoses)
    return EncodedClaim(
        claim_id=pack_felt_text(ctx.claim_id),
        member_id=0 if not ctx.member_id else pack_felt_text(ctx.member_id),
        provider_npi=0 if not ctx.provider.npi else canonical_npi(ctx.provider.npi),
        service_date=canonical_day_count(ctx.service_date),
        procedure_codes_hash=packed_list_hash("claim_source", canonical_service_code_multiset(ctx.service_lines)),
        service_lines_commitment=packed_service_lines_hash("claim_source", ctx.service_lines),
        diagnosis_commitment=packed_list_hash("claim_source", diagnoses),
        total_charge_cents=canonical_cents(ctx.total_charge),
        service_line_count=len(ctx.service_lines),
        diagnosis_count=len(diagnoses),
    )


def encode_service_line(line: ServiceLine) -> tuple[int, int, int, int]:
    return (
        pack_felt_text(line.line_id),
        pack_felt_text(line.procedure_code),
        canonical_cents(line.charge_amount),
        canonical_cents(line.units),
    )


def government_prf_nullifier(ctx: SharedContext, frequency_type: str = "original") -> int:
    encoded = encode_claim(ctx)
    prf = _prf_field(
        [
            encoded.member_id,
            encoded.provider_npi,
            encoded.service_date,
            encoded.procedure_codes_hash,
            encoded.total_charge_cents,
            pack_felt_text(frequency_type),
        ]
    )
    return domain_poseidon_hash(
        "nullifier",
        [
            prf,
            encoded.member_id,
            encoded.provider_npi,
            encoded.service_date,
            encoded.procedure_codes_hash,
            encoded.total_charge_cents,
            pack_felt_text(frequency_type),
        ],
    )
