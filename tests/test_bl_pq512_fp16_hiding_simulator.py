from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA = ROOT / "experiments" / "bl_pq512_crypto_core" / "cuda"
sys.path.insert(0, str(CUDA))
try:
    from fp16_zk_rs_hiding_simulator_kat import (
        GKR_BRIDGE_MASK_FIELDS,
        GKR_LAYER_TERMINAL_MASK_FIELDS,
        GKR_MASK_PADDED_COEFFICIENTS,
        GKR_PCS_QUERY_RANK,
        STATE_MASK_EXPECTATIONS,
        state_composed_mask_degrees,
    )
finally:
    sys.path.pop(0)


def test_state_composed_mask_rank_and_free_dimensions_are_exact() -> None:
    for capacity in (128, 512):
        layers = state_composed_mask_degrees(capacity)
        expected_layers, used, rank, conditioned_rank, free = (
            STATE_MASK_EXPECTATIONS[capacity]
        )
        calculated_rank = (
            len(layers)
            * (GKR_BRIDGE_MASK_FIELDS + GKR_LAYER_TERMINAL_MASK_FIELDS)
            + sum(1 + sum(degrees) for degrees in layers)
            + 1
        )
        assert len(layers) == expected_layers
        assert calculated_rank == rank
        assert rank + GKR_PCS_QUERY_RANK == conditioned_rank
        assert GKR_MASK_PADDED_COEFFICIENTS - conditioned_rank == free
        assert 0 < used <= GKR_MASK_PADDED_COEFFICIENTS
        assert free > 0


def test_state_composed_degree_schedule_rejects_other_capacities() -> None:
    try:
        state_composed_mask_degrees(256)
    except ValueError as error:
        assert str(error) == "state_mask_capacity"
    else:
        raise AssertionError("state_mask_capacity_accepted")
