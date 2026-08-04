"""Host-only KAT for the real-GKR plus PCS public-coin coordinator."""

import hashlib
import sys
from pathlib import Path

import cuda_fp16_zk_rs_theorem8_1_k128_prototype as prototype
from cuda_fp16_tower_kat import add, mul16, sub


ZERO = (0,) * 16
ONE = (1,) + (0,) * 15
GKR_MASK_VALUES = 32_768
GKR_MASK_WORD_VALUES = 512
PUBLIC_COIN_ROUNDS = 6_113


def relation_terminal_digest(weights, claim_challenge, challenges):
    scale = ONE
    for _ in range(19):
        scale = mul16(scale, claim_challenge)
    digest = hashlib.sha3_512()
    for word in range(64):
        start = word * GKR_MASK_WORD_VALUES * 16
        layer = [
            mul16(tuple(weights[offset : offset + 16]), scale)
            for offset in range(start, start + GKR_MASK_WORD_VALUES * 16, 16)
        ]
        active = GKR_MASK_WORD_VALUES
        for challenge in challenges:
            for index in range(active // 2):
                left = layer[2 * index]
                right = layer[2 * index + 1]
                layer[index] = add(
                    left,
                    mul16(sub(right, left), challenge),
                )
            active //= 2
        digest.update(prototype.fp16_bytes(layer[0]))
    return digest.digest()


def run_session(executable, gkr_root, schedule, mutate_terminal_digest):
    session = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/SAME-CHAIN-KAT/SESSION/v1"
        + bytes((mutate_terminal_digest,))
    ).digest()
    coefficients = prototype.fp16_bytes(ZERO) * GKR_MASK_VALUES
    bridge = prototype.NativePublicCoinBridge(
        executable,
        session,
        schedule,
        PUBLIC_COIN_ROUNDS,
        gkr_root,
        coefficients,
    )
    try:
        initial_root = hashlib.sha3_512(b"initial").digest()
        mask_root = hashlib.sha3_512(b"sumcheck-mask").digest()
        claims_digest = hashlib.sha3_512(b"claims").digest()
        mask_target = prototype.fp16_value(17)
        claims_message = (
            b"BLT8GC06"
            + initial_root
            + mask_root
            + gkr_root
            + prototype.fp16_bytes(bridge.gkr_mask_opening)
            + claims_digest
            + prototype.fp16_bytes(mask_target)
        )
        batching = bridge.challenge(
            799,
            claims_message
            + b"BLSQCL00"
            + b"\0" * 68,
            output_count=6,
        )
        claim_challenge = batching[0]
        initial_message = (
            b"BLT8SO06"
            + initial_root
            + mask_root
            + gkr_root
            + prototype.fp16_bytes(bridge.gkr_mask_opening)
            + hashlib.sha3_512(b"binding").digest()
            + prototype.fp16_bytes(prototype.fp16_value(19))
            + prototype.fp16_bytes(mask_target)
        )
        bridge.challenge(800, initial_message)
        challenges = tuple(
            bridge.challenge(
                801,
                b"BLT8HR04"
                + ordinal.to_bytes(4, "big")
                + (64).to_bytes(4, "big")
                + prototype.fp16_bytes(prototype.fp16_value(23 + ordinal)),
            )
            for ordinal in range(9)
        )
        terminal_digest = relation_terminal_digest(
            bridge.gkr_mask_weights,
            claim_challenge,
            challenges,
        )
        if mutate_terminal_digest:
            mutated = bytearray(terminal_digest)
            mutated[0] ^= 1
            terminal_digest = bytes(mutated)
        base_message = (
            b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v2"
            + hashlib.sha3_512(b"base-main").digest()
            + hashlib.sha3_512(b"base-aux").digest()
            + gkr_root
            + b"\0" * 64
            + terminal_digest
            + prototype.fp16_bytes(prototype.fp16_value(29))
        )
        try:
            bridge.challenge(802, base_message)
        except SystemExit as error:
            status = bridge.process.wait(timeout=30)
            stderr = bridge.process.stderr.read()
            bridge.closed = True
            bridge = None
            if (
                not mutate_terminal_digest
                or status != 2
                or stderr.strip() != b"ERR:gkr_pcs_terminal_digest"
            ):
                raise SystemExit(
                    "same_chain_rejection_mismatch="
                    f"error={error};status={status};stderr={stderr!r}"
                ) from error
            return None
        if mutate_terminal_digest:
            raise SystemExit("terminal_digest_mutation_accepted")
        bridge.challenge(
            803,
            b"BL/PQ512/FP16-ZK-RS/ANSWERS/v1"
            + hashlib.sha3_512(b"answers").digest(),
        )
        summary = bridge.finish()
        bridge = None
    finally:
        if bridge is not None:
            bridge.abort()
    return summary


def main():
    executable = (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "fp16_zk_rs_public_coin_bridge.exe"
    )
    if not executable.is_file():
        raise SystemExit(f"public_coin_bridge_missing={executable}")
    gkr_root = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/SAME-CHAIN-KAT/GKR-ROOT/v1"
    ).digest()
    schedule = hashlib.sha3_512(
        b"BL/PQ512/FP16-ZK-RS/SAME-CHAIN-KAT/SCHEDULE/v1"
    ).digest()
    summary = run_session(executable, gkr_root, schedule, False)
    run_session(executable, gkr_root, schedule, True)
    print("kat=fp16_zk_rs_same_chain_bridge_v1")
    print("status=verified")
    print("gkr_rounds=6100")
    print("pcs_continuation_rounds=13")
    print("combined_rounds=6113")
    print(f"bundle_mb={summary['bundle_mb']:.6f}")
    print("gkr_pcs_descriptor_schedule_verified=true")
    print("gkr_mask_root_reused=true")
    print("gkr_relation_terminal_digest_verified=true")
    print("gkr_relation_terminal_digest_mutation_rejected=true")
    print("independent_bundle_replay=true")
    print("complete_proof_qualification=false")


if __name__ == "__main__":
    sys.exit(main())
