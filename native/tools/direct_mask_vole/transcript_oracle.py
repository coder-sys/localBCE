#!/usr/bin/env python3
"""Independent SHAKE transcript oracle for the direct-mask FS vectors."""

from __future__ import annotations

import hashlib
import pathlib
import re
import struct
import subprocess
import sys


PREFIX = b"BL/DMV/FAEST-256F/v3"
GENERATOR_VERSION = b"DMV-RO-WIDE-SEED-v3"
GENERATOR_WIDTH = 512


def h0_input(iv: bytes) -> bytes:
    encoded = bytearray(b"\xd7")
    encoded.extend(struct.pack("<I", len(GENERATOR_VERSION)))
    encoded.extend(GENERATOR_VERSION)
    encoded.extend(struct.pack("<H", GENERATOR_WIDTH))
    encoded.append(0)
    encoded.extend(struct.pack("<I", len(iv)))
    encoded.extend(iv)
    encoded.extend(struct.pack("<I", 0))
    return bytes(encoded)


def fill_pattern(length: int, seed: int) -> bytes:
    return bytes((seed + 29 * i + (i >> 3)) & 0xFF for i in range(length))


def transcript(domain: bytes, parts: list[bytes], output_length: int) -> bytes:
    encoded = bytearray(PREFIX)
    encoded.extend(domain)
    for part in parts:
        encoded.extend(struct.pack("<I", len(part)))
        encoded.extend(part)
    return hashlib.shake_256(encoded).digest(output_length)


def parse_line(output: str, prefix: str) -> str:
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise RuntimeError(f"missing {prefix} line")


def parse_hex_field(line: str, name: str) -> bytes:
    match = re.search(rf"(?:^| ){re.escape(name)}=([0-9a-f]+)(?= |$)", line)
    if match is None:
        raise RuntimeError(f"missing {name} in transcript output")
    return bytes.fromhex(match.group(1))


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[2]
    executable = repo / "build" / "direct_mask_vole" / "direct_mask_vole_probe.exe"
    if len(sys.argv) > 2:
        print("TRANSCRIPT_ORACLE status=FAIL reason=too_many_arguments")
        return 2
    if len(sys.argv) == 2:
        executable = pathlib.Path(sys.argv[1]).resolve()
    if not executable.exists():
        print(f"TRANSCRIPT_ORACLE status=FAIL reason=missing_executable path={executable}")
        return 2

    completed = subprocess.run([str(executable)], check=False, capture_output=True, text=True)
    sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        print(f"TRANSCRIPT_ORACLE status=FAIL reason=probe_exit_{completed.returncode}")
        return 1

    h0_line = parse_line(completed.stdout, "H0_KAT ")
    h0_iv = parse_hex_field(h0_line, "iv")
    h0_raw = parse_hex_field(h0_line, "raw")
    h0_nu = parse_hex_field(h0_line, "nu")
    expected_h0 = hashlib.shake_256(h0_input(h0_iv)).digest(230)
    h0_failures = []
    if h0_raw != expected_h0:
        h0_failures.append("h0_raw")
    if h0_nu != expected_h0[:228]:
        h0_failures.append("h0_leaf_uhash")
    if len(h0_iv) != 16 or len(h0_raw) != 230 or len(h0_nu) != 228:
        h0_failures.append("h0_lengths")
    if (h0_raw[227] & 0x80) != 0 or h0_raw[228] != 0 or (h0_raw[229] & 0x01) != 0:
        h0_failures.append("h0_filter")

    input_line = parse_line(completed.stdout, "TRANSCRIPT_C_INPUT ")
    input_values = {
        key: int(value)
        for key, value in re.findall(r"(?:^| )([a-z0-9_]+)=(\d+)(?= |$)", input_line)
    }
    required = {
        "statement",
        "uhash",
        "m1",
        "sigma1",
        "gamma1",
        "m2",
        "sigma2",
        "gamma2",
        "m3",
        "sigma3",
    }
    if set(input_values) != required:
        print("TRANSCRIPT_ORACLE status=FAIL reason=unexpected_input_fields")
        return 1

    statement = fill_pattern(input_values["statement"], 0x11)
    uhash = fill_pattern(input_values["uhash"], 0xA2)
    m1 = fill_pattern(input_values["m1"], 0x51)
    m2 = fill_pattern(input_values["m2"], 0x61)
    m3 = fill_pattern(input_values["m3"], 0x71)
    nonce1 = fill_pattern(input_values["sigma1"], 0x22)
    nonce2 = fill_pattern(input_values["sigma2"], 0x33)
    nonce3 = fill_pattern(input_values["sigma3"], 0x44)
    gamma1 = fill_pattern(input_values["gamma1"], 0x81)
    gamma2 = fill_pattern(input_values["gamma2"], 0x91)

    common = [statement, uhash, m1, nonce1]
    expected = {
        "fs1": transcript(b"FS1", common, 264),
        "fs2": transcript(b"FS2", common + [gamma1, m2, nonce2], 105),
        "fs3": transcript(
            b"FS3", common + [gamma1, m2, nonce2, gamma2, m3, nonce3], 33
        ),
    }
    kat_line = parse_line(completed.stdout, "TRANSCRIPT_C_KAT ")
    actual = {name: parse_hex_field(kat_line, name) for name in expected}
    failures = [name for name in expected if actual[name] != expected[name]]

    nonce1_changed = bytearray(nonce1)
    nonce1_changed[0] ^= 1
    nonce2_changed = bytearray(nonce2)
    nonce2_changed[0] ^= 1
    mutation_expected = {
        "nonce1_fs2": transcript(
            b"FS2", [statement, uhash, m1, bytes(nonce1_changed), gamma1, m2, nonce2], 105
        ),
        "nonce1_fs3": transcript(
            b"FS3",
            [
                statement,
                uhash,
                m1,
                bytes(nonce1_changed),
                gamma1,
                m2,
                nonce2,
                gamma2,
                m3,
                nonce3,
            ],
            33,
        ),
        "nonce2_fs3": transcript(
            b"FS3",
            [statement, uhash, m1, nonce1, gamma1, m2, bytes(nonce2_changed), gamma2, m3, nonce3],
            33,
        ),
    }
    mutation_line = parse_line(completed.stdout, "TRANSCRIPT_C_MUTATION ")
    mutation_actual = {
        name: parse_hex_field(mutation_line, name) for name in mutation_expected
    }
    failures.extend(name for name in mutation_expected if mutation_actual[name] != mutation_expected[name])
    failures.extend(h0_failures)

    cache_line = parse_line(completed.stdout, "TRANSCRIPT_CACHE_DERIVED ")
    cache_values = {
        key: int(value)
        for key, value in re.findall(r"(?:^| )([a-z0-9_]+)=(\d+)(?= |$)", cache_line)
    }
    cache_requirements = {
        "fs2_multi_nonce": 1,
        "fs3_multi_nonce": 1,
        "reinit_changed_input": 1,
        "cache_clear_zeroed": 1,
    }
    failures.extend(
        name
        for name, expected_value in cache_requirements.items()
        if cache_values.get(name) != expected_value
    )

    if failures:
        print(f"TRANSCRIPT_ORACLE status=FAIL mismatches={','.join(failures)}")
        return 1
    print(
        "TRANSCRIPT_ORACLE status=PASS "
        "kat=3 mutation_vectors=3 h0_vendor=1 cache_vectors=1 "
        "prefix=BL/DMV/FAEST-256F/v3 encoding=uint32le_length_delimited_parts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
