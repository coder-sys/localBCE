"""Deterministic fixture construction shared by source-only unittest suites."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from provider_app.codec import bundle_content_digest

VECTOR_PATH = Path(__file__).resolve().parents[1] / "vectors" / "synthetic-vectors-v1.json"
VECTORS = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _merge(target: dict[str, Any], changes: dict[str, Any]) -> None:
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def request_bytes(case: dict[str, Any] | None = None) -> bytes:
    request = copy.deepcopy(VECTORS["requestTemplate"])
    if case is not None:
        _merge(request, case.get("requestChanges", {}))
    return canonical_bytes(request)


def bundle_mapping(case: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle = copy.deepcopy(VECTORS["bundleTemplate"])
    if case is not None:
        for mutation in case.get("bundleChanges", []):
            node: Any = bundle
            for part in mutation["path"][:-1]:
                node = node[part]
            node[mutation["path"][-1]] = copy.deepcopy(mutation["value"])
    bundle["contentDigest"] = bundle_content_digest(bundle)
    return bundle


def bundle_bytes(case: dict[str, Any] | None = None) -> bytes:
    return canonical_bytes(bundle_mapping(case))
