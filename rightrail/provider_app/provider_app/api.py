"""Narrow in-memory byte adapter. It performs no storage or external I/O."""

from __future__ import annotations

import json

from .codec import parse_bundle_bytes, parse_request_bytes, result_to_mapping
from .contracts import InputError, MAX_RESULT_BYTES
from .evaluator import evaluate


def preflight_bytes(request_bytes: bytes, bundle_bytes: bytes) -> bytes:
    """Parse, evaluate, and return one canonical synthetic result document."""
    request = parse_request_bytes(request_bytes)
    bundle = parse_bundle_bytes(bundle_bytes)
    result = result_to_mapping(evaluate(request, bundle))
    encoded = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(encoded) > MAX_RESULT_BYTES:
        raise InputError("RESULT_TOO_LARGE")
    return encoded
