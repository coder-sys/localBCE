"""Append the two verifier-owned state-root calls to a semantic snapshot."""

from __future__ import annotations

import argparse
from hashlib import sha3_512
import json
from pathlib import Path
import sys

from experiments.fixed_shape_claim_air.application_sha3_executable_air import Sha3Call
from experiments.fixed_shape_claim_air.hash_bus_snapshot import (
    encode_state_composed_hash_bus_snapshot,
)
from experiments.fixed_shape_claim_air.profile import get_profile


def _read_once(path: Path) -> bytes:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RuntimeError(f"input_invalid:{path}")
    return path.read_bytes()


def _parse_base(encoded: bytes):
    if len(encoded) < 211 or encoded[:8] != b"BLHBSN01" or int.from_bytes(encoded[8:10], "big") != 1:
        raise RuntimeError("base_snapshot_header")
    profile_tag = encoded[10]
    profile_id = {1: "K128_CALIBRATION", 3: "K512_CALIBRATION"}.get(profile_tag)
    if profile_id is None:
        raise RuntimeError("base_snapshot_profile")
    profile = get_profile(profile_id)
    program = encoded[11:75]
    expected_descriptor = encoded[75:139]
    expected_port = encoded[139:203]
    count = int.from_bytes(encoded[203:211], "big")
    calls = []
    cursor = 211
    for index in range(count):
        if cursor + 12 > len(encoded):
            raise RuntimeError(f"base_snapshot_truncated:{index}")
        capacity = int.from_bytes(encoded[cursor : cursor + 8], "big")
        length = int.from_bytes(encoded[cursor + 8 : cursor + 12], "big")
        cursor += 12
        end = cursor + length
        digest_end = end + 64
        if digest_end > len(encoded):
            raise RuntimeError(f"base_snapshot_message_truncated:{index}")
        message = encoded[cursor:end]
        digest = encoded[end:digest_end]
        if sha3_512(message).digest() != digest:
            raise RuntimeError(f"base_snapshot_digest:{index}")
        calls.append(Sha3Call(f"current_semantic_{index}", message, capacity))
        cursor = digest_end
    if cursor != len(encoded):
        raise RuntimeError("base_snapshot_trailing_bytes")
    return profile, program, expected_descriptor, expected_port, tuple(calls)


def _write_once(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"output_exists:{path}")
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_snapshot", type=Path)
    parser.add_argument("before_snapshot", type=Path)
    parser.add_argument("after_snapshot", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    base = _read_once(args.base_snapshot)
    before = _read_once(args.before_snapshot)
    after = _read_once(args.after_snapshot)
    profile, program, descriptor, port, calls = _parse_base(base)
    encoded = encode_state_composed_hash_bus_snapshot(profile, program, calls, before, after)
    if encoded[:8] != b"BLHBSN02":
        raise RuntimeError("state_snapshot_magic")
    if encoded[75:139] == descriptor or encoded[139:203] == port:
        raise RuntimeError("state_snapshot_commitment_not_distinct")
    _write_once(args.output, encoded)
    metadata = {
        "profile": profile.profile_id,
        "base_snapshot_bytes": len(base),
        "state_snapshot_bytes": len(encoded),
        "base_call_count": len(calls),
        "state_call_count": len(calls) + 2,
        "descriptor_commitment": encoded[75:139].hex(),
        "semantic_port_commitment": encoded[139:203].hex(),
    }
    metadata_path = args.output.with_suffix(args.output.suffix + ".json")
    _write_once(metadata_path, (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("ascii"))
    print("status=verified")
    print(f"profile={profile.profile_id}")
    print(f"base_call_count={len(calls)}")
    print(f"state_call_count={len(calls) + 2}")
    print(f"output_bytes={len(encoded)}")
    print(f"descriptor_commitment={encoded[75:139].hex()}")
    print(f"semantic_port_commitment={encoded[139:203].hex()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pragma: no cover - CLI boundary
        print(f"ERR:{error}", file=sys.stderr)
        raise SystemExit(2)
