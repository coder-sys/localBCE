from __future__ import annotations

import hashlib
import json
from typing import Iterable


TYPE_NONE = b"n"
TYPE_BOOL = b"b"
TYPE_INT = b"i"
TYPE_STR = b"s"
TYPE_BYTES = b"y"
TYPE_JSON = b"j"


def _reject_nested_float(value: object) -> None:
    if isinstance(value, float):
        raise ValueError("float_not_canonical")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_nested_float(key)
            _reject_nested_float(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nested_float(item)


def _as_tagged_bytes(value: object) -> bytes:
    if value is None:
        return TYPE_NONE
    if isinstance(value, bool):
        return TYPE_BOOL + (b"1" if value else b"0")
    if isinstance(value, int) and not isinstance(value, bool):
        return TYPE_INT + str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("float_not_canonical")
    if isinstance(value, bytes):
        return TYPE_BYTES + value
    if isinstance(value, (dict, list, tuple)):
        _reject_nested_float(value)
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return TYPE_JSON + payload.encode("utf-8")
    return TYPE_STR + str(value).encode("utf-8")


def len_prefix(value: object) -> bytes:
    raw = _as_tagged_bytes(value)
    return len(raw).to_bytes(4, "big") + raw


def canonical_record(record_type: str, fields: Iterable[object]) -> bytes:
    out = bytearray()
    out.extend(len_prefix("BL_CANONICAL_RECORD_V2"))
    out.extend(len_prefix(record_type))
    for field in fields:
        out.extend(len_prefix(field))
    return bytes(out)


def digest_hex(record_type: str, fields: Iterable[object]) -> str:
    return hashlib.sha256(canonical_record(record_type, fields)).hexdigest()


def digest_bytes(record_type: str, fields: Iterable[object]) -> bytes:
    return hashlib.sha256(canonical_record(record_type, fields)).digest()


def stable_private_hash(value: object) -> str:
    return digest_hex("stable_private_hash", [value])
