from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA = ROOT / "experiments" / "bl_pq512_crypto_core" / "cuda"
sys.path.insert(0, str(CUDA))
try:
    from cuda_hash_bus_b16_gkr_worker import (
        BOUNDARY_HEADER_BYTES,
        GROUP_COUNT,
        LIVE_WIRES,
        PROFILE_STATE_TOTAL_PERMUTATIONS,
        read_boundary,
    )
finally:
    sys.path.pop(0)


def test_state_boundary_geometry_matches_descriptor_and_windows_byte_order(
    tmp_path: Path,
) -> None:
    assert PROFILE_STATE_TOTAL_PERMUTATIONS == {1: 114_232, 3: 413_370}
    file_bytes = BOUNDARY_HEADER_BYTES + 2 * LIVE_WIRES * GROUP_COUNT * 2
    path = tmp_path / "state-composed-zero-boundary.blhbb"
    header = (
        b"BLHBB102"
        + (2).to_bytes(2, "big")
        + bytes((1,))
        + bytes(64)
        + bytes(64)
        + bytes(64)
        + (1).to_bytes(2, "big")
        + (131_072).to_bytes(8, "big")
        + (1_600).to_bytes(2, "big")
    )
    assert len(header) == BOUNDARY_HEADER_BYTES
    with path.open("wb") as output:
        output.write(header)
        output.seek(file_bytes - 1)
        output.write(b"\x00")

    input_values, output_values, nonuniform_groups, packed_groups = read_boundary(
        path, 0
    )
    assert len(input_values) == LIVE_WIRES * packed_groups
    assert len(output_values) == LIVE_WIRES * packed_groups
    assert nonuniform_groups == (114_232 + 15) // 16
    assert packed_groups == 7_144
