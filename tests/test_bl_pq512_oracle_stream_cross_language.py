from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
import subprocess

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    EXECUTION_ROOT_MAGIC,
    build_oracle_commitments,
    encode_oracle_bundle,
    oracle_bundle_from_slot,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")
SCHEDULE_DOMAIN = b"BL/PQ512/WAVE1A/ORACLE-SHA3-SCHEDULE/v1\x00"


def _material():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    oracle_bundles = tuple(oracle_bundle_from_slot(profile, slot) for slot in slots)
    bundles = tuple(encode_oracle_bundle(value) for value in oracle_bundles)
    commitments = build_oracle_commitments(profile, oracle_bundles)
    return profile, bundles, commitments


def _expected_commitment(profile, bundles, commitments) -> bytes:
    digest = sha3_512()
    digest.update(SCHEDULE_DOMAIN)
    digest.update(b"\x01")
    digest.update(profile.claim_slots.to_bytes(2, "big"))
    for ordinal, (message, output) in enumerate(
        zip(bundles, commitments.leaf_digests, strict=True)
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


def test_k128_oracle_stream_matches_python_exactly(tmp_path: Path) -> None:
    profile, bundles, commitments = _material()
    input_path = tmp_path / "oracle-k128.bin"
    input_path.write_bytes(
        b"".join(
            (
                b"BLOR1",
                b"\x01",
                profile.claim_slots.to_bytes(2, "big"),
                *bundles,
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
            "oracle_stream",
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
        "calls": "129",
        "permutations": "3954",
        "keccak_round_rows": "94896",
        "root": commitments.execution_root.hex(),
        "commitment": expected_commitment.hex(),
    }
    assert commitments.execution_root.hex() == (
        "64502aca9576c960ca69c767f6df3590ae5571d3a24ea38faebc0e8e7d4e8198"
        "ba35c274b91d24830c59f0b1809692288cdb3f45b1de7b9f6fcaa4192e86d5fa"
    )
    assert expected_commitment.hex() == (
        "109a0701e6c4758ea23053a183f34aae3d6761cd0192c6c2476581b23702607eb"
        "54cbba468b47db99a566e2d814c310d1e5802763cbc54769ea926c7ddb7fe49"
    )
