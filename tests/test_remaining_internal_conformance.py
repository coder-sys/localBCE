from __future__ import annotations

from pathlib import Path

from tools.remaining_internal_conformance import (
    PACKAGE_IDS,
    PACKAGE_STATUS,
    STATUS,
    build_receipt,
)


def test_remaining_internal_packages_close_only_at_nonactivating_boundary() -> None:
    receipt = build_receipt(Path(__file__).resolve().parents[1])
    assert receipt["status"] == STATUS
    assert tuple(receipt["package_status"]) == PACKAGE_IDS
    assert set(receipt["package_status"].values()) == {PACKAGE_STATUS}
    assert receipt["package_count"] == 31
    assert receipt["profile_and_boundary"]["field_count"] == 12
    assert receipt["native_hiding"]["table_count"] == 16
    assert receipt["security_ledger_qualifies"] is True
    assert receipt["backend"]["rust_independent_verifier_present"] is True
    assert receipt["backend"]["production_native_stark_verifier"] is False
    assert receipt["proofSuiteId"] is None
    assert receipt["activationAllowed"] is False
    assert receipt["productionUsable"] is False
