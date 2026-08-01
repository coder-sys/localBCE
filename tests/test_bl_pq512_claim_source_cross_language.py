from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
import subprocess

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    NODE_MAGIC,
    ROOT_MAGIC,
    build_claim_source_commitments,
    claim_source_bundle_from_slot,
    encode_claim_source_bundle,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")
SCHEDULE_DOMAIN = b"BL/PQ512/WAVE1A/CLAIM-SOURCE-SHA3-SCHEDULE/v2\x00"


def _material():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    bundles = tuple(
        encode_claim_source_bundle(claim_source_bundle_from_slot(profile, slot))
        for slot in slots
    )
    commitments = build_claim_source_commitments(profile, slots)
    return profile, bundles, commitments


def _binary_input(profile, bundles, root: bytes) -> bytes:
    return b"".join(
        (
            b"BLCS1",
            b"\x01",
            profile.claim_slots.to_bytes(2, "big"),
            *bundles,
            root,
        )
    )


def _expected_commitment(profile, bundles, commitments) -> bytes:
    digest = sha3_512()
    digest.update(SCHEDULE_DOMAIN)
    digest.update(b"\x01")
    digest.update(profile.claim_slots.to_bytes(2, "big"))
    ordinal = 0

    def absorb(kind: int, message: bytes, output: bytes) -> None:
        nonlocal ordinal
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(bytes((kind,)))
        digest.update(len(message).to_bytes(2, "big"))
        digest.update(len(message).to_bytes(2, "big"))
        digest.update(message)
        digest.update(output)
        ordinal += 1

    for message, output in zip(
        bundles, commitments.leaf_digests, strict=True
    ):
        assert sha3_512(message).digest() == output
        absorb(1, message, output)
    for child_height, (children, parents) in enumerate(
        zip(commitments.levels[:-1], commitments.levels[1:], strict=True)
    ):
        for position, output in enumerate(parents):
            message = b"".join(
                (
                    NODE_MAGIC,
                    bytes((1, child_height)),
                    position.to_bytes(2, "big"),
                    children[2 * position],
                    children[2 * position + 1],
                )
            )
            assert sha3_512(message).digest() == output
            absorb(2, message, output)
    root_message = b"".join(
        (
            ROOT_MAGIC,
            bytes((1, profile.claim_source_tree_depth)),
            profile.claim_slots.to_bytes(2, "big"),
            commitments.levels[-1][0],
        )
    )
    assert sha3_512(root_message).digest() == commitments.root
    absorb(3, root_message, commitments.root)
    assert ordinal == 2 * profile.claim_slots
    digest.update(commitments.root)
    return digest.digest()


def test_k128_claim_source_stream_matches_python_exactly(tmp_path: Path) -> None:
    profile, bundles, commitments = _material()
    input_path = tmp_path / "claim-source-k128.bin"
    input_path.write_bytes(_binary_input(profile, bundles, commitments.root))
    completed = subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "run",
            "--quiet",
            "--locked",
            "--offline",
            "--target-dir",
            str(TARGET),
            "--bin",
            "claim_source_stream",
            "--",
            str(input_path),
        ),
        cwd=CRATE,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    observed = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )
    expected_commitment = _expected_commitment(profile, bundles, commitments)
    assert observed == {
        "slots": "128",
        "calls": "256",
        "permutations": "10368",
        "keccak_round_rows": "248832",
        "root": commitments.root.hex(),
        "commitment": expected_commitment.hex(),
    }
    assert commitments.root.hex() == (
        "5d875d9137c3e8aa659fe199298c7576a948d0ed9f37cdc2b0c2485ca53d7728"
        "d3f5b12865cbac7181f18906982f69896f2cc2c244f4df3f466dae50318a6dc2"
    )
    assert expected_commitment.hex() == (
        "6ed1d91f85b2a93b55582a124834c78f22e759f65efa514de4957e152469fd1e"
        "221b96212be550073bd1dc23657ea659dba92294f281ec9de10ad66ccddbc160"
    )
