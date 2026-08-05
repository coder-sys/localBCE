"""Fixed-width nonactivating sidecar and receipt grammar for H6 controls."""

from __future__ import annotations

from hashlib import sha3_512
from typing import Final


SIDECAR_MAGIC: Final[bytes] = b"BLH6SC01"
RECEIPT_MAGIC: Final[bytes] = b"BLH6RC01"
VERSION: Final[int] = 1
HEADER_BYTES: Final[int] = 16
IDENTITY_BYTES: Final[int] = 64
SIDECAR_FIELD_COUNT: Final[int] = 11
RECEIPT_FIELD_COUNT: Final[int] = 7
SIDECAR_BYTES: Final[int] = 744
RECEIPT_BYTES: Final[int] = 512
SIDECAR_RESERVED_BYTES: Final[int] = (
    SIDECAR_BYTES - HEADER_BYTES - IDENTITY_BYTES * SIDECAR_FIELD_COUNT
)
RECEIPT_RESERVED_BYTES: Final[int] = (
    RECEIPT_BYTES - HEADER_BYTES - IDENTITY_BYTES * RECEIPT_FIELD_COUNT
)
GRAMMAR_STATUS: Final[str] = "NONACTIVATING_FIXED_WIDTH_GRAMMAR_V1"


class H6ReceiptGrammarError(ValueError):
    """Fail-closed error for sidecar and receipt grammar violations."""


def _identity(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != IDENTITY_BYTES or not any(value):
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_invalid")
    return value


def _fields(values: object, count: int, label: str) -> tuple[bytes, ...]:
    if type(values) is not tuple or len(values) != count:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_count_invalid")
    return tuple(_identity(value, f"{label}_{index}") for index, value in enumerate(values))


def _encode(magic: bytes, total: int, values: object, count: int, reserved: int, label: str) -> bytes:
    fields = _fields(values, count, label)
    encoded = b"".join(
        (
            magic,
            VERSION.to_bytes(2, "big"),
            (0).to_bytes(2, "big"),
            total.to_bytes(4, "big"),
            b"".join(fields),
            bytes(reserved),
        )
    )
    if len(encoded) != total:
        raise AssertionError(f"h6_receipt_{label}_internal_length")
    return encoded


def _parse(encoded: object, magic: bytes, total: int, count: int, reserved: int, label: str) -> tuple[bytes, ...]:
    if type(encoded) is not bytes or len(encoded) != total:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_length_invalid")
    view = memoryview(encoded)
    if bytes(view[:8]) != magic:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_magic_invalid")
    if int.from_bytes(view[8:10], "big") != VERSION:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_version_invalid")
    if int.from_bytes(view[10:12], "big") != 0:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_flags_invalid")
    if int.from_bytes(view[12:16], "big") != total:
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_declared_length_invalid")
    fields_end = HEADER_BYTES + count * IDENTITY_BYTES
    if bytes(view[fields_end:]) != bytes(reserved):
        raise H6ReceiptGrammarError(f"h6_receipt_{label}_reserved_nonzero")
    fields = tuple(
        _identity(bytes(view[offset : offset + IDENTITY_BYTES]), f"{label}_{index}")
        for index, offset in enumerate(
            range(HEADER_BYTES, fields_end, IDENTITY_BYTES)
        )
    )
    return fields


def encode_sidecar(fields: tuple[bytes, ...]) -> bytes:
    return _encode(
        SIDECAR_MAGIC,
        SIDECAR_BYTES,
        fields,
        SIDECAR_FIELD_COUNT,
        SIDECAR_RESERVED_BYTES,
        "sidecar",
    )


def parse_sidecar(encoded: bytes) -> tuple[bytes, ...]:
    return _parse(
        encoded,
        SIDECAR_MAGIC,
        SIDECAR_BYTES,
        SIDECAR_FIELD_COUNT,
        SIDECAR_RESERVED_BYTES,
        "sidecar",
    )


def encode_receipt(fields: tuple[bytes, ...]) -> bytes:
    return _encode(
        RECEIPT_MAGIC,
        RECEIPT_BYTES,
        fields,
        RECEIPT_FIELD_COUNT,
        RECEIPT_RESERVED_BYTES,
        "receipt",
    )


def parse_receipt(encoded: bytes) -> tuple[bytes, ...]:
    return _parse(
        encoded,
        RECEIPT_MAGIC,
        RECEIPT_BYTES,
        RECEIPT_FIELD_COUNT,
        RECEIPT_RESERVED_BYTES,
        "receipt",
    )


def grammar_identity() -> bytes:
    return sha3_512(
        b"BL/PQ512/H6/RECEIPT-GRAMMAR/v1\x00"
        + SIDECAR_MAGIC
        + RECEIPT_MAGIC
        + VERSION.to_bytes(2, "big")
        + SIDECAR_BYTES.to_bytes(4, "big")
        + RECEIPT_BYTES.to_bytes(4, "big")
        + SIDECAR_FIELD_COUNT.to_bytes(2, "big")
        + RECEIPT_FIELD_COUNT.to_bytes(2, "big")
    ).digest()


__all__: tuple[str, ...] = (
    "GRAMMAR_STATUS",
    "H6ReceiptGrammarError",
    "IDENTITY_BYTES",
    "RECEIPT_BYTES",
    "RECEIPT_FIELD_COUNT",
    "SIDECAR_BYTES",
    "SIDECAR_FIELD_COUNT",
    "encode_receipt",
    "encode_sidecar",
    "grammar_identity",
    "parse_receipt",
    "parse_sidecar",
)
