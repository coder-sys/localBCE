from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    SHA3_BYTE_AIR_STATUS,
    Sha3ByteAirShape,
    block_absorb_lookup_rows,
    build_sha3_512_air_trace,
    padded_block_count,
    round_lookup_rows,
    verify_sha3_512_air_trace,
)


@pytest.mark.parametrize(
    ("message", "blocks"),
    (
        (b"", 1),
        (b"abc", 1),
        (bytes(range(71)), 1),
        (bytes(range(72)), 2),
        (bytes(range(143)), 2),
        (bytes(range(144)), 3),
    ),
)
def test_sha3_512_byte_air_matches_hashlib_and_exact_padding(
    message: bytes, blocks: int
) -> None:
    trace = build_sha3_512_air_trace(message)
    verify_sha3_512_air_trace(message, trace)
    assert len(trace.padded_blocks) == padded_block_count(len(message)) == blocks
    assert trace.digest == sha3_512(message).digest()
    assert trace.status == SHA3_BYTE_AIR_STATUS
    assert trace.proof_suite_id is None
    assert not trace.activation_allowed


def test_round_shape_and_lookup_inventory_are_exact() -> None:
    shape = Sha3ByteAirShape()
    assert shape.core_round_base_columns == 1_632
    assert shape.sponge_block_columns == 72
    assert shape.trace_base_columns == 1_704
    assert shape.core_round_lookup_messages == 1_024
    assert shape.absorb_xor_lookups == 72
    assert shape.first_round_lookup_messages == 1_096
    assert shape.round_xor_lookups == 608
    assert shape.round_and_not_lookups == 200
    assert shape.round_split_lookups == 216
    assert shape.direct_maximum_degree == 2
    assert shape.composed_maximum_degree == 3
    assert shape.proof_suite_id is None
    assert not shape.activation_allowed
    assert not shape.interaction_packing_selected
    assert shape.commitment_sha3_512.hex() == (
        "824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4ad"
        "ea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c"
    )

    trace = build_sha3_512_air_trace(b"abc")
    rows = round_lookup_rows(trace.rounds[0][0])
    assert len(rows) == 1_024
    assert sum(row[0] == "XOR8" for row in rows) == 608
    assert sum(row[0] == "AND_NOT8" for row in rows) == 200
    assert sum(row[0].startswith("SPLIT8_") for row in rows) == 216
    absorb_rows = block_absorb_lookup_rows(bytes(200), trace.padded_blocks[0])
    assert len(absorb_rows) == 72
    assert all(row[0] == "XOR8" for row in absorb_rows)


def test_fips_202_known_answer_vectors_are_exact() -> None:
    assert build_sha3_512_air_trace(b"").digest.hex() == (
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    )
    assert build_sha3_512_air_trace(b"abc").digest.hex() == (
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    )
