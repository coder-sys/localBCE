from hashlib import sha3_512

from experiments.bl_pq512_crypto_foundation.gkr_semantic_bus import (
    GKR_INPUT_WIDTH,
    GKR_INSTANCES,
    INPUT_MAGIC,
    encode_gkr_initial_boundary,
    encode_gkr_output_boundary,
    iter_semantic_keccak_lanes,
)
from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
)
from experiments.fixed_shape_claim_air.sha3_512_boolean_executable_air import (
    Sha3BooleanCall,
    build_sha3_boolean_executable_air,
)


def _decode_wire_instance(encoded: bytes, wire: int, instance: int) -> int:
    words = GKR_INSTANCES // 64
    offset = 16 + 8 * (wire * words + instance // 64)
    word = int.from_bytes(encoded[offset : offset + 8], "big")
    return (word >> (instance % 64)) & 1


def test_semantic_bus_matches_sealed_boolean_trace_and_digest() -> None:
    calls = (
        Sha3Call("empty", b"", 73),
        Sha3Call("two_block", b"A" * 73, 73),
    )
    lanes = tuple(iter_semantic_keccak_lanes(calls))
    boolean = build_sha3_boolean_executable_air(
        tuple(Sha3BooleanCall(call.call_id, call.message, call.capacity) for call in calls)
    )
    absorb = boolean.traces["sha3_boolean_absorb"].columns
    rounds = boolean.traces["sha3_boolean_round"].columns

    assert len(lanes) == 4
    for lane in lanes:
        absorb_row = lane.ordinal
        assert lane.initial_state == bytes(
            sum(
                (
                    absorb[f"prior_{8 * byte + bit}"][absorb_row]
                    ^ (
                        absorb[f"block_bit_{8 * byte + bit}"][absorb_row]
                        if byte < 72
                        else 0
                    )
                )
                << bit
                for bit in range(8)
            )
            for byte in range(200)
        )
        final_row = lane.ordinal * 25 + 24
        assert lane.output_state == bytes(
            sum(rounds[f"state_{8 * byte + bit}"][final_row] << bit for bit in range(8))
            for byte in range(200)
        )
    assert tuple(lane.digest for lane in lanes if lane.actual_last) == tuple(
        sha3_512(call.message).digest() for call in calls
    )


def test_semantic_bus_boundary_is_strict_fixed_shape() -> None:
    lanes = tuple(
        iter_semantic_keccak_lanes((Sha3Call("message", b"abc", 3),))
    )
    encoded = encode_gkr_initial_boundary(lanes)
    assert encoded[:8] == INPUT_MAGIC
    assert int.from_bytes(encoded[10:12], "big") == 1
    assert int.from_bytes(encoded[12:14], "big") == GKR_INSTANCES
    assert int.from_bytes(encoded[14:16], "big") == GKR_INPUT_WIDTH
    for wire in range(1_600):
        expected = (lanes[0].initial_state[wire // 8] >> (wire % 8)) & 1
        assert _decode_wire_instance(encoded, wire, 0) == expected
        assert _decode_wire_instance(encoded, wire, 1) == 0
    for wire in range(1_600, GKR_INPUT_WIDTH):
        assert _decode_wire_instance(encoded, wire, 0) == 0

    output = encode_gkr_output_boundary(lanes)
    for wire in range(1_600):
        expected = (lanes[0].output_state[wire // 8] >> (wire % 8)) & 1
        assert _decode_wire_instance(output, wire, 0) == expected
    assert any(_decode_wire_instance(output, wire, 1) for wire in range(1_600))
    for wire in range(1_600, GKR_INPUT_WIDTH):
        assert _decode_wire_instance(output, wire, 0) == 0
        assert _decode_wire_instance(output, wire, 1) == 0
