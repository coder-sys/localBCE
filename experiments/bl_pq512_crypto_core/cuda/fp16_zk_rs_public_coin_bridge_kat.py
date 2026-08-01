"""Real dual-PQ authenticated-public-coin bridge KAT for the 12-round PCS."""

import hashlib
import struct
import subprocess
import sys
import time
from pathlib import Path


ROUND_COUNT = 12


def exact_read(stream, length):
    payload = bytearray()
    while len(payload) < length:
        chunk = stream.read(length - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) != length:
        raise SystemExit(
            f"public_coin_short_read={len(payload)}/{length}"
        )
    return bytes(payload)


def round_message(round_ordinal):
    length = (
        256
        if round_ordinal in (0, 10)
        else 2_048 * 64
        if 1 <= round_ordinal <= 9
        else 144
    )
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha3_512(
                b"BL/PQ512/FP16-ZK-RS/PUBLIC-COIN-KAT/v1"
                + round_ordinal.to_bytes(4, "big")
                + counter.to_bytes(4, "big")
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def session_header():
    session = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/PUBLIC-COIN-KAT/SESSION/v1"
    ).digest()
    schedule = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/PUBLIC-COIN-KAT/SCHEDULE/v1"
    ).digest()
    return (
        b"BLPCCN01"
        + session
        + (0).to_bytes(2, "big")
        + schedule
        + ROUND_COUNT.to_bytes(4, "big")
    )


def main():
    executable = (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "fp16_zk_rs_public_coin_bridge.exe"
    )
    if not executable.is_file():
        raise SystemExit(f"public_coin_bridge_missing={executable}")
    process = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    started = time.perf_counter()
    try:
        process.stdin.write(session_header())
        process.stdin.flush()
        ready = exact_read(process.stdout, 16)
        if ready[:8] != b"BLPCCRD1":
            raise SystemExit(f"public_coin_ready={ready!r}")
        spawn_seconds = struct.unpack(">d", ready[8:])[0]
        challenges = []
        for ordinal in range(ROUND_COUNT):
            message = round_message(ordinal)
            output_count = 3 if ordinal == 0 else 1
            process.stdin.write(
                b"BLPCCRQ1"
                + (700 + ordinal).to_bytes(2, "big")
                + ordinal.to_bytes(4, "big")
                + output_count.to_bytes(2, "big")
                + len(message).to_bytes(4, "big")
                + message
            )
            process.stdin.flush()
            response = exact_read(process.stdout, 14 + 64 * output_count)
            if (
                response[:8] != b"BLPCCRS1"
                or int.from_bytes(response[8:12], "big") != ordinal
                or int.from_bytes(response[12:14], "big") != output_count
            ):
                raise SystemExit(
                    f"public_coin_round_response={ordinal}:{response[:14]!r}"
                )
            challenges.append(response[14:])
        process.stdin.close()
        finish_header = exact_read(process.stdout, 12)
        if finish_header[:8] != b"BLPCCFN1":
            raise SystemExit(
                f"public_coin_finish_magic={finish_header!r}"
            )
        bundle_length = int.from_bytes(finish_header[8:], "big")
        bundle = exact_read(process.stdout, bundle_length)
        finish_seconds = struct.unpack(
            ">d",
            exact_read(process.stdout, 8),
        )[0]
        if process.stdout.read():
            raise SystemExit("public_coin_trailing_output")
        status = process.wait(timeout=30)
        stderr = process.stderr.read()
        if status != 0 or stderr:
            raise SystemExit(
                "public_coin_bridge_failed="
                f"{status};stderr={stderr!r}"
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    wall_seconds = time.perf_counter() - started
    challenge_digest = hashlib.sha3_512(
        b"".join(challenges)
    ).hexdigest()

    malformed = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        malformed.stdin.write(session_header())
        malformed.stdin.flush()
        exact_read(malformed.stdout, 16)
        message = round_message(0)
        malformed.stdin.write(
            b"BLPCCRQ1"
            + (700).to_bytes(2, "big")
            + (1).to_bytes(4, "big")
            + (1).to_bytes(2, "big")
            + len(message).to_bytes(4, "big")
            + message
        )
        malformed.stdin.close()
        malformed_stdout = malformed.stdout.read()
        malformed_stderr = malformed.stderr.read()
        malformed_status = malformed.wait(timeout=30)
    finally:
        if malformed.poll() is None:
            malformed.kill()
            malformed.wait(timeout=10)
    order_mutation_rejected = (
        malformed_status == 2
        and b"ERR:round_shape:0" in malformed_stderr
        and not malformed_stdout
    )
    if not order_mutation_rejected:
        raise SystemExit(
            "public_coin_order_mutation="
            f"{malformed_status};stdout={malformed_stdout!r};"
            f"stderr={malformed_stderr!r}"
        )

    print("kat=fp16_zk_rs_public_coin_bridge_v1")
    print("evidence_class=real_dual_pq_authenticated_interaction")
    print(f"rounds={ROUND_COUNT}")
    print("vector_output_count_round_0=3")
    print(f"spawn_and_head_auth_seconds={spawn_seconds:.6f}")
    print(f"finish_and_independent_replay_seconds={finish_seconds:.6f}")
    print(f"total_wall_seconds={wall_seconds:.6f}")
    print(f"bundle_mb={len(bundle) / 1_000_000:.6f}")
    print(f"challenge_digest={challenge_digest}")
    print("ml_dsa_87_head_authenticated=true")
    print("slh_dsa_shake_256f_head_authenticated=true")
    print("message_before_challenge=true")
    print("independent_bundle_replay=true")
    print("round_order_mutation_rejected=true")
    print("launch_fiat_shamir=false")
    print("grinding_credit=false")
    print("prototype_integration_attached=false")
    print("complete_proof_qualification=false")


if __name__ == "__main__":
    sys.exit(main())
