"""The one strict canonical-JSON encoder and decoder of the Financial modules; each caller keeps its own codes, caps and byte decoding."""

import json
from collections.abc import Callable


def encode(value: object) -> bytes:
    """Canonical ASCII bytes; json's own TypeError/ValueError/RecursionError escape (NaN and Infinity are ValueError)."""
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")


def decode(raw: bytes, encoding: str, duplicate_key: Callable[[str], object], constant: Callable[[str], object]) -> object:
    """Parse ``raw``; each callback must raise (a repeated key, or NaN/Infinity/-Infinity)."""
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                duplicate_key(key)
            result[key] = item
        return result

    return json.loads(raw.decode(encoding), object_pairs_hook=pairs, parse_constant=constant)
