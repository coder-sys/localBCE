"""Generate the synthetic canonical K128 SHA3/Keccak input-state batch.

This is a narrow research seam.  It consumes Blind Ledger's executable
capacity schedule, expands each fixed-width call into deterministic synthetic
bytes, and writes the 1,600-bit state immediately before every SHA3-512
Keccak-f[1600] permutation.  The output is raw 200-byte little-endian lane
states for the external Flock adapter; it is not a proof artifact and does not
change the production or activation boundary.
"""

from __future__ import annotations

import argparse
import json
from hashlib import sha3_512
from pathlib import Path
from typing import Iterable

from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    build_wave1a_global_sha3_schedule,
)

MASK64 = (1 << 64) - 1
RATE_BYTES = 72
STATE_BYTES = 200
ROUNDS = 24
SYNTHETIC_DOMAIN = b"BL/BINARY-FIELD/K128/SYNTHETIC-SHA3-INPUT/v1\x00"
ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
KAT_ZERO_LANES = (
    0xF1258F7940E1DDE7,
    0x84D5CCF933C0478A,
    0xD598261EA65AA9EE,
    0xBD1547306F80494D,
    0x8B284E056253D057,
    0xFF97A42D7F8E6FD4,
    0x90FEE5A0A44647C4,
    0x8C5BDA0CD6192E76,
    0xAD30A6F71B19059C,
    0x30935AB7D08FFC64,
    0xEB5AA93F2317D635,
    0xA9A6E6260D712103,
    0x81A57C16DBCF555F,
    0x43B831CD0347C826,
    0x01F22F1A11A5569F,
    0x05E5635A21D9AE61,
    0x64BEFEF28CC970F2,
    0x613670957BC46611,
    0xB87C5A554FD00ECB,
    0x8C3EE88A1CCF32C8,
    0x940C7922AE3A2614,
    0x1841F924A2C509E4,
    0x16F53526E70465C2,
    0x75F644E97F30A13B,
    0xEAF1FF7B5CECA249,
)


def _rotl(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def keccak_f(lanes: list[int]) -> None:
    if len(lanes) != 25:
        raise ValueError("keccak_state_lane_count_invalid")
    for round_constant in ROUND_CONSTANTS:
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(
                    lanes[x + 5 * y], RHO[x][y]
                )
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                ) & MASK64
        lanes[0] ^= round_constant


def _lanes_bytes(lanes: Iterable[int]) -> bytes:
    values = tuple(lanes)
    if len(values) != 25:
        raise ValueError("keccak_state_lane_count_invalid")
    return b"".join(value.to_bytes(8, "little") for value in values)


def _synthetic_message(component: str, label: str, call_index: int, length: int) -> bytes:
    seed = (
        SYNTHETIC_DOMAIN
        + component.encode("ascii")
        + b"\x00"
        + label.encode("ascii")
        + call_index.to_bytes(8, "big")
    )
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(sha3_512(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _padded_blocks(message: bytes) -> tuple[bytes, ...]:
    padded = bytearray(message)
    padded.append(0x06)
    padded.extend(b"\x00" * ((-len(padded)) % RATE_BYTES))
    padded[-1] ^= 0x80
    return tuple(
        bytes(padded[offset : offset + RATE_BYTES])
        for offset in range(0, len(padded), RATE_BYTES)
    )


def _permutation_inputs(message: bytes) -> tuple[tuple[bytes, bytes], ...]:
    lanes = [0] * 25
    rows: list[tuple[bytes, bytes]] = []
    for block in _padded_blocks(message):
        for index, value in enumerate(block):
            lanes[index // 8] ^= value << (8 * (index % 8))
        before = _lanes_bytes(lanes)
        keccak_f(lanes)
        rows.append((before, _lanes_bytes(lanes)))
    return tuple(rows)


def _run_kat() -> None:
    zero = [0] * 25
    keccak_f(zero)
    if tuple(zero) != KAT_ZERO_LANES:
        raise AssertionError("keccak_f_all_zero_known_answer_mismatch")


def generate(*, output: Path, start: int, count: int | None) -> dict[str, object]:
    profile = PROFILES["K128_CALIBRATION"]
    global_schedule = build_wave1a_global_sha3_schedule(profile)
    schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    if (
        global_schedule.total_calls != 46_858
        or schedule.total_calls != 46_858
        or schedule.total_permutations != 113_730
    ):
        raise AssertionError("k128_capacity_schedule_drift")
    end = schedule.total_permutations if count is None else start + count
    if start < 0 or end < start or end > schedule.total_permutations:
        raise ValueError("keccak_state_range_invalid")

    _run_kat()
    input_root = sha3_512()
    output_root = sha3_512()
    digest_root = sha3_512()
    selected = 0
    permutation_index = 0
    message_index = 0
    with output.open("wb") as destination:
        for run in schedule.runs:
            for local_index in range(run.count):
                message = _synthetic_message(
                    run.component, run.label, local_index, run.capacity
                )
                rows = _permutation_inputs(message)
                final_state = rows[-1][1]
                expected_digest = sha3_512(message).digest()
                if final_state[:64] != expected_digest:
                    raise AssertionError("synthetic_sha3_output_mismatch")
                if any(start <= permutation_index + offset < end for offset in range(len(rows))):
                    digest_root.update(expected_digest)
                for offset, (state_in, state_out) in enumerate(rows):
                    index = permutation_index + offset
                    if start <= index < end:
                        destination.write(state_in)
                        input_root.update(state_in)
                        output_root.update(state_out)
                        selected += 1
                permutation_index += len(rows)
                message_index += 1
                if permutation_index >= end:
                    break
            if permutation_index >= end:
                break

    if permutation_index < end or selected != end - start:
        raise AssertionError("keccak_state_selection_incomplete")
    metadata = {
        "status": "BL_BINARY_FIELD_K128_SYNTHETIC_INPUT_V1",
        "profile": profile.profile_id,
        "proofSuiteId": None,
        "production_usable": False,
        "activation": False,
        "synthetic_only": True,
        "source": "experiments/fixed_shape_claim_air/wave1a_global_sha3_capacity_schedule.py",
        "global_schedule_commitment_sha3_512": global_schedule.commitment_512.hex(),
        "capacity_schedule_commitment_sha3_512": schedule.commitment_512.hex(),
        "total_calls": schedule.total_calls,
        "total_permutations": schedule.total_permutations,
        "selected_start": start,
        "selected_permutations": selected,
        "state_bytes_per_permutation": STATE_BYTES,
        "input_state_root_sha3_512": input_root.hexdigest(),
        "output_state_root_sha3_512": output_root.hexdigest(),
        "message_digest_root_sha3_512": digest_root.hexdigest(),
        "message_count_processed": message_index,
    }
    print(json.dumps(metadata, sort_keys=True))
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int)
    args = parser.parse_args()
    generate(output=args.output, start=args.start, count=args.count)


if __name__ == "__main__":
    main()
