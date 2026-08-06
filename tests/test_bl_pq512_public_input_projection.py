from __future__ import annotations

from hashlib import sha3_512

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.native_public_input_projection import (
    LIMB_BITS,
    LIMBS_PER_FIELD,
    M31_MODULUS,
    PUBLIC_FIELD_COUNT,
    PUBLIC_INPUT_COUNT,
    PublicInputProjectionError,
    PublicInputProjectionV1,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(value: int) -> bytes:
    return value.to_bytes(32, "big")


def test_projection_is_lossless_and_fixed_shape() -> None:
    fields = tuple(
        _field((int.from_bytes(_wide(f"field-{index}"), "big") % FIELD_MODULUS))
        for index in range(PUBLIC_FIELD_COUNT)
    )
    outputs = b"".join(fields)
    projection = PublicInputProjectionV1(_wide("projection-schema"))
    values = projection.project(outputs)
    assert len(values) == PUBLIC_INPUT_COUNT
    assert all(0 <= value < M31_MODULUS for value in values)
    for index, field in enumerate(fields):
        recovered = sum(
            values[index * LIMBS_PER_FIELD + limb]
            << (limb * LIMB_BITS)
            for limb in range(LIMBS_PER_FIELD)
        )
        assert recovered == int.from_bytes(field, "big")
    encoded = projection.encode_file(outputs)
    assert encoded[:8] == b"BLPQPI01"
    assert int.from_bytes(encoded[10:14], "big") == PUBLIC_INPUT_COUNT
    assert len(encoded) == 14 + PUBLIC_INPUT_COUNT * 4


def test_projection_rejects_noncanonical_or_wrong_shape_fields() -> None:
    projection = PublicInputProjectionV1(_wide("projection-schema"))
    with pytest.raises(PublicInputProjectionError, match="public_field_0_not_canonical"):
        projection.project(_field(FIELD_MODULUS) + bytes(11 * 32))
    with pytest.raises(PublicInputProjectionError, match="public_outputs_shape_invalid"):
        projection.project(bytes(11 * 32))
