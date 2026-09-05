from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation


MAX_AMOUNT_CENTS = (1 << 32) - 1
MAX_AMOUNT_CENTS_EXCLUSIVE = 1 << 32

_CANONICAL_MONEY_TEXT = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$")


def _canonical_text_to_cents(raw: str) -> int:
    """Decode one already-canonical ASCII money string without rounding."""

    if not _CANONICAL_MONEY_TEXT.fullmatch(raw):
        raise ValueError(f"noncanonical_money:{raw}")
    try:
        parsed = Decimal(raw)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid_money:{raw}") from exc
    cents = int(parsed * 100)
    if cents < 0 or cents > MAX_AMOUNT_CENTS:
        raise ValueError(f"amount_out_of_range:{raw}")
    return cents


def canonical_source_money_cents(value: object) -> int:
    """Decode external money text; host numeric types are never coerced."""

    if type(value) is not str:
        raise ValueError("money_source_must_be_ascii_string")
    return _canonical_text_to_cents(value)


def canonical_money_cents(value: float | int | str | Decimal) -> int:
    """Decode a legacy in-memory model value after an explicit type check.

    External text must use ``canonical_source_money_cents`` and proof values
    must use their exact-integer validators.  This compatibility helper exists
    only because the prototype application dataclasses still store major-unit
    amounts instead of integer cents.
    """

    if isinstance(value, bool) or type(value) not in {float, int, str, Decimal}:
        raise ValueError("money_model_type_invalid")
    return _canonical_text_to_cents(str(value))
