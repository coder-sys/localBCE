from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
import subprocess

from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    EXECUTION_ROOT_MAGIC,
    build_policy_commitments,
)
from experiments.fixed_shape_claim_air.measurement import build_synthetic_measurement_slots
from experiments.fixed_shape_claim_air.profile import PROFILES


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")
SCHEDULE_DOMAIN = b"BL/PQ512/WAVE1A/POLICY-SHA3-SCHEDULE/v1\x00"


def _expected_commitment(profile, commitments) -> bytes:
    digest = sha3_512()
    digest.update(SCHEDULE_DOMAIN)
    digest.update(b"\x01")
    digest.update(profile.claim_slots.to_bytes(2, "big"))
    for ordinal, (message, output) in enumerate(
        zip(commitments.bundles, commitments.leaf_digests, strict=True)
    ):
        assert sha3_512(message).digest() == output
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(b"\x01")
        digest.update(len(message).to_bytes(2, "big") * 2)
        digest.update(message)
        digest.update(output)
    root_message = b"".join(
        (
            EXECUTION_ROOT_MAGIC,
            b"\x01",
            profile.claim_slots.to_bytes(2, "big"),
            *commitments.leaf_digests,
        )
    )
    assert sha3_512(root_message).digest() == commitments.execution_root
    digest.update(profile.claim_slots.to_bytes(4, "big"))
    digest.update(b"\x02")
    digest.update(len(root_message).to_bytes(2, "big") * 2)
    digest.update(root_message)
    digest.update(commitments.execution_root)
    digest.update(commitments.execution_root)
    return digest.digest()


def test_k128_policy_stream_matches_python_exactly(tmp_path: Path) -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    commitments = build_policy_commitments(profile, slots)
    input_path = tmp_path / "policy-k128.bin"
    input_path.write_bytes(
        b"".join(
            (
                b"BLPO1",
                b"\x01",
                profile.claim_slots.to_bytes(2, "big"),
                *commitments.bundles,
                commitments.execution_root,
            )
        )
    )
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
            "policy_stream",
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
    expected_commitment = _expected_commitment(profile, commitments)
    assert observed == {
        "slots": "128",
        "calls": "129",
        "permutations": "1778",
        "keccak_round_rows": "42672",
        "root": commitments.execution_root.hex(),
        "commitment": expected_commitment.hex(),
    }
