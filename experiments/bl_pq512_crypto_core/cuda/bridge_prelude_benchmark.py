"""Bounded diagnostic benchmark for the strict native bridge prelude.

This deliberately stops after ``gkr_ready_emitted``.  It does not produce a
proof, verifier receipt, qualification, or activation evidence.
"""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import threading
import time


FP16_BYTES = 64
MASK_COEFFICIENTS = 32_768
K128_ROUNDS = 6_791


def read_exact(stream, count, label):
    payload = stream.read(count)
    if len(payload) != count:
        raise SystemExit(f"{label}:short_read:{len(payload)}/{count}")
    return payload


def read_framed_fp16_vector(path, expected_label, expected_count):
    payload = path.read_bytes()
    if payload[:8] != b"BLH4FP01":
        raise SystemExit("mask_coefficients_magic")
    label_length = int.from_bytes(payload[8:10], "big")
    if payload[10:16] != b"\0" * 6:
        raise SystemExit("mask_coefficients_header")
    count = int.from_bytes(payload[16:24], "big")
    label = payload[24 : 24 + label_length].decode("ascii")
    values = payload[24 + label_length :]
    if label != expected_label or count != expected_count:
        raise SystemExit(f"mask_coefficients_shape:{label}:{count}")
    if len(values) != expected_count * FP16_BYTES:
        raise SystemExit("mask_coefficients_length")
    return values


def drain(stream):
    while stream.read(1 << 20):
        pass


def wait_for_phase(path, phase, timeout_seconds, process=None):
    deadline = time.monotonic() + timeout_seconds
    marker = f"phase={phase} "
    while time.monotonic() < deadline:
        if path.is_file() and marker in path.read_text(encoding="ascii"):
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"bridge_exit_before_{phase}:exit={process.returncode}")
        time.sleep(0.02)
    raise TimeoutError(phase)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--boundary", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--state-source", type=Path, required=True)
    parser.add_argument("--mask-commitment", type=Path, required=True)
    parser.add_argument("--mask-coefficients", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--schedule", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args()

    for path in (
        args.bridge,
        args.boundary,
        args.worker,
        args.state_source,
        args.mask_commitment,
        args.mask_coefficients,
        args.session,
        args.schedule,
    ):
        if not path.is_file():
            raise SystemExit(f"input_missing:{path}")
    if not args.telemetry.is_absolute() or args.telemetry.exists():
        raise SystemExit("telemetry_path")

    state_source = args.state_source.read_bytes()
    state_digest = hashlib.sha3_512(
        b"BL/PQ512/WAVE2/STATE-RELATION-SOURCE/v2\0"
        + len(state_source).to_bytes(8, "big")
        + state_source
    ).digest()
    commitment = args.mask_commitment.read_bytes()
    session = args.session.read_bytes()
    schedule = args.schedule.read_bytes()
    if any(len(value) != 64 for value in (commitment, session, schedule)):
        raise SystemExit("identity_length")
    coefficients = read_framed_fp16_vector(
        args.mask_coefficients,
        "h4_gkr_mask_coefficients",
        MASK_COEFFICIENTS,
    )

    command = [
        str(args.bridge),
        "--gkr-prelude-nonuniform-eager",
        str(args.boundary),
        "0",
        os.fspath(Path(os.sys.executable)),
        str(args.worker),
        str(args.state_source),
        state_digest.hex(),
    ]
    environment = os.environ.copy()
    environment["BL_CURRENT_STRICT_H4"] = "1"
    environment["BL_BRIDGE_PHASE_TELEMETRY_PATH"] = str(args.telemetry)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        bufsize=0,
    )
    stderr = bytearray()

    def drain_stderr():
        while True:
            block = process.stderr.read(1 << 16)
            if not block:
                return
            stderr.extend(block)

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()
    stdout_thread = None
    try:
        process.stdin.write(
            b"BLPCCN01"
            + session
            + (0).to_bytes(2, "big")
            + schedule
            + K128_ROUNDS.to_bytes(4, "big")
            + commitment
            + coefficients
        )
        process.stdin.flush()
        ready = read_exact(process.stdout, 16, "squarefree_ready")
        if ready[:8] != b"BLPCCB01":
            raise SystemExit(f"squarefree_ready_magic:{ready[:8]!r}")
        diagnostic_source_root = hashlib.sha3_512(
            b"BL/PQ512/DIAGNOSTIC/PRELUDE-SOURCE-ROOT/v1\0" + state_digest
        ).digest()
        process.stdin.write(b"BLPCCB02" + diagnostic_source_root)
        process.stdin.flush()
        witness_header = read_exact(process.stdout, 16, "squarefree_witness")
        if witness_header[:8] != b"BLPCCW01":
            raise SystemExit("squarefree_witness_magic")
        read_exact(process.stdout, FP16_BYTES, "squarefree_beta")
        read_exact(process.stdout, 2_048 * FP16_BYTES, "squarefree_coefficients")
        diagnostic_coefficient_root = hashlib.sha3_512(
            b"BL/PQ512/DIAGNOSTIC/PRELUDE-COEFFICIENT-ROOT/v1\0"
            + diagnostic_source_root
        ).digest()
        process.stdin.write(b"BLPCCC01" + diagnostic_coefficient_root)
        process.stdin.flush()
        stdout_thread = threading.Thread(target=drain, args=(process.stdout,), daemon=True)
        stdout_thread.start()
        wait_for_phase(args.telemetry, "gkr_ready_emitted", args.timeout, process)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        stderr_thread.join(timeout=2)
        if stderr:
            print(f"bridge_stderr={bytes(stderr)!r}", file=os.sys.stderr)
        raise
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        stderr_thread.join(timeout=2)
    elapsed = time.monotonic() - started
    print("diagnostic_only=true")
    print("proof_produced=false")
    print("proof_credit=false")
    print(f"state_relation_source_sha3_512={state_digest.hex()}")
    print(f"prelude_wall_seconds={elapsed:.6f}")
    print(args.telemetry.read_text(encoding="ascii"), end="")
    if stderr:
        raise SystemExit(f"bridge_stderr:{bytes(stderr)!r}")


if __name__ == "__main__":
    main()
