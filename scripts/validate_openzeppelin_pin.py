#!/usr/bin/env python3
"""Validate the vendored OpenZeppelin v5.6.1 source aggregate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "blind-ledger" / "openzeppelin_contracts_pin.json"
SOURCE = ROOT / "blind-ledger" / "lib" / "openzeppelin-contracts"


def aggregate() -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
    if not files:
        raise ValueError("vendored OpenZeppelin source is empty")
    for path in files:
        relative = path.relative_to(SOURCE).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-hash", action="store_true")
    args = parser.parse_args()
    try:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        package = json.loads((SOURCE / "package.json").read_text(encoding="utf-8"))
        if pin.get("tag") != "v5.6.1" or pin.get("package_version") != "5.6.1":
            raise ValueError("pin must require OpenZeppelin v5.6.1")
        if package.get("version") != "5.6.1":
            raise ValueError("vendored package.json is not OpenZeppelin v5.6.1")
        actual = aggregate()
        if args.write_hash:
            pin["aggregate_sha256"] = actual
            PIN_PATH.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")
        if pin.get("aggregate_sha256") != actual:
            raise ValueError(f"OpenZeppelin aggregate mismatch: expected {actual}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "tag": "v5.6.1", "aggregate_sha256": actual}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
