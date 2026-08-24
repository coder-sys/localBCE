from __future__ import annotations

from decimal import Decimal

import pytest

from app.money import MAX_AMOUNT_CENTS, canonical_source_money_cents


def test_source_money_boundary_accepts_only_canonical_ascii_strings() -> None:
    assert canonical_source_money_cents("0") == 0
    assert canonical_source_money_cents("0.29") == 29
    assert canonical_source_money_cents("42949672.95") == MAX_AMOUNT_CENTS
    for invalid in (0, 0.0, True, Decimal("0"), b"0"):
        with pytest.raises(ValueError, match="money_source_must_be_ascii_string"):
            canonical_source_money_cents(invalid)
