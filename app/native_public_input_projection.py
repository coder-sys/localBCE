"""Lossless public-boundary projection for the native M31 AIR.

The external Privacy V2 statement is twelve canonical 32-byte field values,
while the selected AIR consumes M31 values.  This module defines the narrow
wire-level projection between them: every public field is represented by nine
little-endian 30-bit limbs.  Nine limbs cover 270 bits, so the projection is
lossless for the canonical 251-bit statement field and never aliases a public
value.  The Rust verifier independently recomputes the same vector.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from app.batch.poseidon import FIELD_MODULUS


M31_MODULUS: Final[int] = (1 << 31) - 1
PUBLIC_FIELD_COUNT: Final[int] = 12
PUBLIC_FIELD_BYTES: Final[int] = 32
LIMBS_PER_FIELD: Final[int] = 9
LIMB_BITS: Final[int] = 30
LIMB_MASK: Final[int] = (1 << LIMB_BITS) - 1
PUBLIC_INPUT_COUNT: Final[int] = PUBLIC_FIELD_COUNT * LIMBS_PER_FIELD
PUBLIC_INPUT_MAGIC: Final[bytes] = b"BLPQPI01"
PUBLIC_INPUT_VERSION: Final[int] = 1
PROJECTION_DOMAIN: Final[bytes] = b"BL/PQ512/PUBLIC-INPUT-PROJECTION/V1\x00"


class PublicInputProjectionError(ValueError):
    """Fail-closed projection error."""


def _identity(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise PublicInputProjectionError(f"{label}_must_be_nonzero_512_bits")
    return value


def _public_outputs(value: object) -> bytes:
    if type(value) is not bytes or len(value) != PUBLIC_FIELD_COUNT * PUBLIC_FIELD_BYTES:
        raise PublicInputProjectionError("public_outputs_shape_invalid")
    for index in range(PUBLIC_FIELD_COUNT):
        field = value[index * PUBLIC_FIELD_BYTES : (index + 1) * PUBLIC_FIELD_BYTES]
        if int.from_bytes(field, "big") >= FIELD_MODULUS:
            raise PublicInputProjectionError(f"public_field_{index}_not_canonical")
    return value


@dataclass(frozen=True, slots=True)
class PublicInputProjectionV1:
    """Pinned schema identity for the lossless 12-field M31 projection."""

    schema_id: bytes

    def __post_init__(self) -> None:
        _identity("projection_schema_id", self.schema_id)

    @property
    def projection_id(self) -> bytes:
        return sha3_512(
            PROJECTION_DOMAIN
            + self.schema_id
            + PUBLIC_FIELD_COUNT.to_bytes(2, "big")
            + LIMBS_PER_FIELD.to_bytes(2, "big")
            + LIMB_BITS.to_bytes(2, "big")
        ).digest()

    def project(self, public_outputs: bytes) -> tuple[int, ...]:
        encoded = _public_outputs(public_outputs)
        values: list[int] = []
        for index in range(PUBLIC_FIELD_COUNT):
            field = int.from_bytes(
                encoded[index * PUBLIC_FIELD_BYTES : (index + 1) * PUBLIC_FIELD_BYTES],
                "big",
            )
            for limb_index in range(LIMBS_PER_FIELD):
                limb = (field >> (limb_index * LIMB_BITS)) & LIMB_MASK
                if limb >= M31_MODULUS:
                    raise PublicInputProjectionError("projected_limb_not_canonical")
                values.append(limb)
            reconstructed = sum(
                values[-LIMBS_PER_FIELD + limb_index] << (limb_index * LIMB_BITS)
                for limb_index in range(LIMBS_PER_FIELD)
            )
            if reconstructed != field:
                raise PublicInputProjectionError("projection_not_lossless")
        return tuple(values)

    def encode_file(self, public_outputs: bytes) -> bytes:
        values = self.project(public_outputs)
        return b"".join(
            (
                PUBLIC_INPUT_MAGIC,
                PUBLIC_INPUT_VERSION.to_bytes(2, "big"),
                len(values).to_bytes(4, "big"),
                b"".join(value.to_bytes(4, "big") for value in values),
            )
        )


__all__ = (
    "LIMBS_PER_FIELD",
    "LIMB_BITS",
    "M31_MODULUS",
    "PUBLIC_FIELD_COUNT",
    "PUBLIC_INPUT_COUNT",
    "PublicInputProjectionError",
    "PublicInputProjectionV1",
)
