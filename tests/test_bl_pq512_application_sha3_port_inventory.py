from __future__ import annotations

from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.application_sha3_port_inventory import (
    CALLSITE_DISPOSITIONS,
    PortDisposition,
    inventory_canonical_sha3_512,
    k128_inventory_summary,
    require_inventory_consistent,
    sha3_512_permutation_count,
)


ROOT = Path(__file__).resolve().parents[1]


def test_every_scoped_sha3_callsite_is_explicitly_classified() -> None:
    require_inventory_consistent(ROOT)
    assert len(CALLSITE_DISPOSITIONS) == 79
    assert {
        disposition: sum(
            observed is disposition for observed in CALLSITE_DISPOSITIONS.values()
        )
        for disposition in PortDisposition
    } == {
        PortDisposition.AIR_REQUIRED: 39,
        PortDisposition.PUBLIC_PRECOMPUTED: 5,
        PortDisposition.HOST_EVIDENCE_ONLY: 21,
        PortDisposition.WAVE1C_VERIFIER_STATE: 11,
        PortDisposition.SUPERSEDED_REFERENCE: 3,
    }


@pytest.mark.parametrize(
    ("length", "expected"),
    ((0, 1), (71, 1), (72, 2), (143, 2), (144, 3), (9733, 136)),
)
def test_sha3_padding_permutation_count_is_exact(length: int, expected: int) -> None:
    assert sha3_512_permutation_count(length) == expected


@pytest.mark.parametrize("invalid", (-1, True, 1.5, "72", None))
def test_sha3_padding_rejects_noncanonical_lengths(invalid: object) -> None:
    with pytest.raises(ValueError, match="preimage_length_invalid"):
        sha3_512_permutation_count(invalid)  # type: ignore[arg-type]


def test_historical_k128_envelope_reconciles_without_activation() -> None:
    summary = k128_inventory_summary()
    assert summary["staticInventoryCurrent"] is True
    assert summary["comprehensiveSourceScopeCurrent"] is True
    assert summary["governedSourceDirectories"] == [
        "app/batch",
        "experiments/fixed_shape_claim_air",
    ]
    assert summary["measurementCurrent"] is False
    assert summary["supersededByPackedSharedSchedule"] is True
    assert summary["reconciledAdditionMeasurementCurrent"] is True
    assert summary["reconciledAdditionCount"] == 5
    assert {
        (value["id"], value["phase"], value["preimageBytes"], value["invocations"])
        for value in summary["reconciledAdditionMeasurements"]
    } == {
        (
            "app/batch/pq_nullifier_derivation.py:derive_cover_nullifiers_v2#0",
            "ISOLATED_EXACT_HELPER",
            238,
            1,
        ),
        (
            "experiments/fixed_shape_claim_air/"
            "authenticated_payment_maps_reference.py:_dummy_key#0",
            "K128_PHYSICAL_TRACE_BUILD",
            169,
            512,
        ),
        (
            "experiments/fixed_shape_claim_air/"
            "authenticated_payment_maps_reference.py:member_benefit_key#0",
            "K128_PHYSICAL_TRACE_BUILD",
            139,
            1,
        ),
        (
            "experiments/fixed_shape_claim_air/"
            "authenticated_payment_maps_reference.py:provider_obligation_key#0",
            "K128_PHYSICAL_TRACE_BUILD",
            136,
            1,
        ),
        (
            "experiments/fixed_shape_claim_air/"
            "authenticated_payment_maps_reference.py:provider_payable_key#0",
            "K128_PHYSICAL_TRACE_BUILD",
            43,
            1,
        ),
    }
    assert summary["historicalOracleRecordsPerSlot"] == 51
    assert summary["physicalVerifierObservedInvocations"] == 404_482
    assert summary["airObservedInvocations"] == 401_274
    assert summary["airRequiredRestoredInvocations"] == 1
    assert summary["conservativeAirInvocations"] == 401_275
    assert summary["conservativeAirPermutations"] == 1_205_016
    assert summary["conservativeAirKeccakRoundRows"] == 28_920_384
    assert summary["publicPrecomputedInvocationsInObservedPhase"] == 3_078
    assert summary["hostEvidenceInvocationsInObservedPhase"] == 130
    assert summary["finalAirScheduleSelected"] is False
    assert summary["interactionPackingSelected"] is False
    assert summary["proofSuiteId"] is None
    assert summary["activationAllowed"] is False


def test_inventory_identity_is_stable() -> None:
    assert inventory_canonical_sha3_512() == (
        "618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2"
        "643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2"
    )
