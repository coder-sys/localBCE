from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping


FIELD_MODULUS = 2**251 + 17 * 2**192 + 1
MULTIPART_ASCII_MAX_BYTES = 64
MULTIPART_ASCII_PARTS = 3
MULTIPART_ASCII_PART_PAYLOAD_BYTES = 30
MULTIPART_ASCII_CAPACITIES = (30, 30, 4)
_CANONICAL_TOKEN = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
_HEX_FELT = re.compile(r"^0x[0-9a-f]{64}$")


@dataclass(frozen=True)
class MultipartAscii64:
    byte_length: int
    parts: tuple[int, int, int]

    def as_json(self) -> dict[str, object]:
        return {
            "byte_length": self.byte_length,
            "parts": [f"0x{part:064x}" for part in self.parts],
        }


def _expected_part_lengths(byte_length: int) -> tuple[int, int, int]:
    remaining = byte_length
    lengths: list[int] = []
    for capacity in MULTIPART_ASCII_CAPACITIES:
        active = min(max(remaining, 0), capacity)
        lengths.append(active)
        remaining -= active
    return lengths[0], lengths[1], lengths[2]


def encode_multipart_ascii64(
    value: str,
    *,
    label: str,
    allow_empty: bool = False,
) -> MultipartAscii64:
    if not isinstance(value, str):
        raise TypeError(f"{label}_not_text")
    if not value:
        if not allow_empty:
            raise ValueError(f"{label}_empty")
    elif len(value) > MULTIPART_ASCII_MAX_BYTES:
        raise ValueError(f"{label}_too_long")
    elif _CANONICAL_TOKEN.fullmatch(value) is None:
        raise ValueError(f"{label}_not_canonical_ascii_token")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label}_not_ascii") from exc
    if len(raw) > MULTIPART_ASCII_MAX_BYTES:
        raise ValueError(f"{label}_too_long")

    parts: list[int] = []
    offset = 0
    for capacity in MULTIPART_ASCII_CAPACITIES:
        chunk = raw[offset : offset + capacity]
        offset += capacity
        payload = bytes((len(chunk),)) + chunk.ljust(MULTIPART_ASCII_PART_PAYLOAD_BYTES, b"\x00")
        part = int.from_bytes(payload, "big")
        if part >= FIELD_MODULUS:
            raise ValueError(f"{label}_part_out_of_field")
        parts.append(part)
    return MultipartAscii64(len(raw), (parts[0], parts[1], parts[2]))


def decode_multipart_ascii64(
    encoded: MultipartAscii64,
    *,
    label: str,
    allow_empty: bool = False,
) -> str:
    if isinstance(encoded.byte_length, bool) or not isinstance(encoded.byte_length, int):
        raise TypeError(f"{label}_byte_length_not_integer")
    if not 0 <= encoded.byte_length <= MULTIPART_ASCII_MAX_BYTES:
        raise ValueError(f"{label}_byte_length_out_of_range")
    if len(encoded.parts) != MULTIPART_ASCII_PARTS:
        raise ValueError(f"{label}_part_count")

    expected_lengths = _expected_part_lengths(encoded.byte_length)
    chunks: list[bytes] = []
    for index, (part, capacity, expected_length) in enumerate(
        zip(encoded.parts, MULTIPART_ASCII_CAPACITIES, expected_lengths, strict=True)
    ):
        if isinstance(part, bool) or not isinstance(part, int):
            raise TypeError(f"{label}_part_{index}_not_integer")
        if part < 0 or part >= FIELD_MODULUS:
            raise ValueError(f"{label}_part_{index}_out_of_field")
        try:
            payload = part.to_bytes(31, "big")
        except OverflowError as exc:
            raise ValueError(f"{label}_part_{index}_not_31_bytes") from exc
        chunk_length = payload[0]
        chunk_payload = payload[1:]
        if chunk_length != expected_length or chunk_length > capacity:
            raise ValueError(f"{label}_part_{index}_length_noncanonical")
        if any(chunk_payload[chunk_length:]):
            raise ValueError(f"{label}_part_{index}_padding_nonzero")
        chunks.append(chunk_payload[:chunk_length])

    raw = b"".join(chunks)
    if len(raw) != encoded.byte_length:
        raise ValueError(f"{label}_length_mismatch")
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}_not_ascii") from exc
    canonical = encode_multipart_ascii64(value, label=label, allow_empty=allow_empty)
    if canonical != encoded:
        raise ValueError(f"{label}_multipart_noncanonical")
    return value


def parse_multipart_ascii64_json(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
) -> MultipartAscii64:
    if not isinstance(value, Mapping) or set(value) != {"byte_length", "parts"}:
        raise ValueError(f"{label}_multipart_shape")
    byte_length = value["byte_length"]
    raw_parts = value["parts"]
    if isinstance(byte_length, bool) or not isinstance(byte_length, int):
        raise TypeError(f"{label}_byte_length_not_integer")
    if not isinstance(raw_parts, list) or len(raw_parts) != MULTIPART_ASCII_PARTS:
        raise ValueError(f"{label}_part_count")
    parts: list[int] = []
    for index, raw_part in enumerate(raw_parts):
        if not isinstance(raw_part, str) or _HEX_FELT.fullmatch(raw_part) is None:
            raise ValueError(f"{label}_part_{index}_hex_noncanonical")
        parts.append(int(raw_part[2:], 16))
    encoded = MultipartAscii64(byte_length, (parts[0], parts[1], parts[2]))
    decode_multipart_ascii64(encoded, label=label, allow_empty=allow_empty)
    return encoded


def multipart_ascii64_order_key(
    encoded: MultipartAscii64,
    *,
    label: str,
    allow_empty: bool = False,
) -> tuple[int, bytes]:
    value = decode_multipart_ascii64(encoded, label=label, allow_empty=allow_empty)
    raw = value.encode("ascii")
    return len(raw), raw


def require_unique_multipart_ascii64(
    values: list[MultipartAscii64] | tuple[MultipartAscii64, ...],
    *,
    label: str,
) -> None:
    seen: set[tuple[int, bytes]] = set()
    for index, value in enumerate(values):
        key = multipart_ascii64_order_key(
            value,
            label=f"{label}_{index}",
            allow_empty=False,
        )
        if key in seen:
            raise ValueError(f"{label}_duplicate")
        seen.add(key)
