"""Canonical ordering helpers for proof-bound synthetic claim records.

The current felt text encoding compares the explicit byte length before the
ASCII payload. These helpers make that ordering explicit before a record is
handed to Python, Rust, Cairo, or a proof reference. They do not define the
future BL-PQ512-v1 wire encoding; that remains a reviewed foundation item.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.multipart_ascii import encode_multipart_ascii64


MAX_FOUNDATION_TEXT_BYTES = 64
MAX_DIAGNOSIS_BYTES = 16


def canonical_ascii_order_key(
    value: str,
    *,
    label: str,
    maximum_bytes: int = MAX_FOUNDATION_TEXT_BYTES,
    allow_empty: bool = False,
) -> tuple[int, bytes]:
    if not isinstance(value, str):
        raise ValueError(f"{label}_not_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label}_not_ascii") from exc
    if (not allow_empty and not encoded) or len(encoded) > maximum_bytes:
        raise ValueError(f"{label}_length_out_of_range")
    return len(encoded), encoded


def canonical_diagnoses(values: Iterable[str]) -> tuple[str, ...]:
    keyed = [
        (
            canonical_ascii_order_key(
                value,
                label="diagnosis",
                maximum_bytes=MAX_DIAGNOSIS_BYTES,
            ),
            value,
        )
        for value in tuple(values)
    ]
    keyed.sort(key=lambda item: item[0])
    ordered = tuple(value for _key, value in keyed)
    if any(left == right for left, right in zip(ordered, ordered[1:])):
        raise ValueError("diagnoses_duplicate")
    return ordered


def require_unique_service_line_ids(values: Iterable[str]) -> None:
    seen: set[tuple[int, bytes]] = set()
    for value in values:
        encoded = encode_multipart_ascii64(value, label="service_line_id")
        raw = value.encode("ascii")
        key = (encoded.byte_length, raw)
        if key in seen:
            raise ValueError("service_line_id_duplicate")
        seen.add(key)
