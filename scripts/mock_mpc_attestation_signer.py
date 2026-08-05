#!/usr/bin/env python3
"""Disposable-Anvil external signer fixture. Never use with production keys."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def run_cast(*args: str) -> str:
    completed = subprocess.run(
        [os.environ.get("CAST_BIN", "cast"), *args],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if completed.returncode:
        fail(f"cast failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def require_hex(value: Any, size: int, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 2 + size * 2:
        fail(f"{field} must be {size}-byte hex")
    try:
        bytes.fromhex(value[2:])
    except ValueError:
        fail(f"{field} contains invalid hex")
    return value.lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-id", default="anvil-mock-attestor-v1")
    args = parser.parse_args()
    if os.environ.get("STARK_MOCK_SIGNER_ACKNOWLEDGE_TEST_ONLY") != "1":
        fail("STARK_MOCK_SIGNER_ACKNOWLEDGE_TEST_ONLY=1 is required")
    private_key = os.environ.get("STARK_MOCK_ATTESTOR_PRIVATE_KEY")
    if not private_key:
        fail("STARK_MOCK_ATTESTOR_PRIVATE_KEY is required")
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        fail(f"invalid request JSON: {exc}")
    if request.get("schema_version") != "stark-attestation-sign-request-v1":
        fail("unsupported request schema")
    require_hex(request.get("request_id"), 32, "request_id")
    digest = require_hex(request.get("digest"), 32, "digest")
    allowed_chain_ids = {
        int(value)
        for value in os.environ.get("STARK_MOCK_ALLOWED_CHAIN_IDS", "31337,11155111").split(",")
    }
    if request.get("chain_id") not in allowed_chain_ids:
        fail("request chain_id is not allowed")
    signature = require_hex(
        run_cast("wallet", "sign", "--no-hash", digest, "--private-key", private_key),
        65,
        "signature",
    )
    attestor = run_cast("wallet", "address", "--private-key", private_key).lower()
    print(json.dumps({
        "schema_version": "stark-attestation-sign-response-v1",
        "request_id": request["request_id"],
        "signer_backend": "mock_mpc_test_only",
        "key_id": args.key_id,
        "attestor_address": attestor,
        "signature_hex": signature,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
