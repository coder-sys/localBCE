from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from app.canonical_order import canonical_ascii_order_key, require_unique_service_line_ids
from app.models import ServiceLine
from app.money import canonical_money_cents


def cents(amount: float | int | str | Decimal) -> int:
    try:
        return canonical_money_cents(amount)
    except ValueError as exc:
        if str(exc).startswith("amount_out_of_range:"):
            raise ValueError("amount_cents_out_of_range") from exc
        raise


def service_line_identity(line: ServiceLine) -> tuple[str, int, int, str]:
    return (
        line.procedure_code,
        cents(line.charge_amount),
        cents(line.units),
        line.prior_authorization or "",
    )


def canonical_service_line_identities(lines: Iterable[ServiceLine]) -> list[tuple[str, int, int, str]]:
    materialized = tuple(lines)
    require_unique_service_line_ids(line.line_id for line in materialized)
    identities = [service_line_identity(line) for line in materialized]
    return sorted(
        identities,
        key=lambda identity: (
            canonical_ascii_order_key(
                identity[0],
                label="service_line_procedure_code",
                maximum_bytes=10,
            ),
            identity[1],
            identity[2],
            canonical_ascii_order_key(
                identity[3],
                label="service_line_prior_authorization",
                allow_empty=True,
            ),
        ),
    )


def canonical_service_code_multiset(lines: Iterable[ServiceLine]) -> list[str]:
    return [identity[0] for identity in canonical_service_line_identities(lines)]
