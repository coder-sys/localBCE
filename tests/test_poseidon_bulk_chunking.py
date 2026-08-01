from __future__ import annotations

import json
from unittest import mock

from app.batch import poseidon


def test_domain_poseidon_many_respects_helper_row_and_byte_limits_without_loss() -> None:
    largest = poseidon.FIELD_MODULUS - 1
    rows = tuple((largest, largest, largest, index) for index in range(4_096))
    observed_chunks: list[list[list[int]]] = []

    def fake_poseidon_many(chunk):
        materialized = [list(row) for row in chunk]
        observed_chunks.append(materialized)
        return [index for index in range(len(materialized))]

    with mock.patch.object(
        poseidon, "poseidon_many", side_effect=fake_poseidon_many
    ):
        result = poseidon.domain_poseidon_many("claim_source", rows)

    assert len(result) == len(rows)
    assert len(observed_chunks) > 1
    assert sum(len(chunk) for chunk in observed_chunks) == len(rows)
    for chunk in observed_chunks:
        assert len(chunk) <= poseidon.MAX_POSEIDON_ROWS
        normalized = [
            [poseidon._normalize_field(value) for value in row]
            for row in chunk
        ]
        encoded = json.dumps(normalized, separators=(",", ":")).encode("utf-8")
        assert len(encoded) <= poseidon.MAX_POSEIDON_INPUT_BYTES
