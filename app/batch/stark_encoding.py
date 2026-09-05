"""Small current text-to-field helper retained for oracle commitment parsing."""

from __future__ import annotations

from app.batch.poseidon import FIELD_MODULUS


MAX_PACKED_BYTES = 31


def pack_felt_text(value: str, *, max_bytes: int = MAX_PACKED_BYTES) -> int:
    raw = value.encode("utf-8")
    if not raw or len(raw) > max_bytes:
        raise ValueError("packed_text_length_out_of_range")
    packed = len(raw)
    for byte in raw:
        packed = (packed << 8) | byte
    if packed >= FIELD_MODULUS:
        raise ValueError("packed_text_out_of_field")
    return packed


__all__ = ("MAX_PACKED_BYTES", "pack_felt_text")
