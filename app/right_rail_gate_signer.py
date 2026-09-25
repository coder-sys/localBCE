"""The one ML-DSA-87 signer for ``RR/GATE/CHECKPOINT/v1``.

Signing is AWS-LC's ML-DSA-87 (FIPS 204) through aws-lc-rs, built from
``rust/gate_mldsa87``.  The binary must hash to the SHA-256 pinned in
``rust/gate_mldsa87/rr_gate_mldsa87.sha256``; a pin mismatch, a missing
binary, a timeout, an OS error or output of the wrong size raises
``GateSignerError``.  There is no other implementation and no fallback.  This
key signs gate checkpoints only, so ML-DSA's context string stays empty.
Synthetic, activation=false.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
from typing import Final

from app.right_rail_gate_codec import ML_DSA_87_PUBLIC_KEY, ML_DSA_87_SIGNATURE

SEED: Final = 32
MAX_MESSAGE: Final = 64 * 1024
CRATE: Final = Path(__file__).resolve().parents[1] / "rust" / "gate_mldsa87"
BINARY: Final = CRATE / "target" / "release" / "rr_gate_mldsa87.exe"
PIN: Final = CRATE / "rr_gate_mldsa87.sha256"


class GateSignerError(RuntimeError):
    """The ML-DSA-87 binary is unpinned, missing, refused the input or failed."""


def run(mode: str, data: bytes, size: int) -> bytes:
    """Run one mode of the pinned binary; its output must be exactly ``size`` bytes."""
    try:
        if hashlib.sha256(BINARY.read_bytes()).hexdigest().encode() != PIN.read_bytes().strip():
            raise GateSignerError("mldsa87_binary_pin_mismatch")
        done = subprocess.run([str(BINARY), mode], input=data, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise GateSignerError(f"mldsa87_{mode}_failed") from error
    if done.returncode != 0 or len(done.stdout) != size:
        raise GateSignerError(f"mldsa87_{mode}_failed")
    return done.stdout


def _seed(value: object) -> bytes:
    if type(value) is not bytes or len(value) != SEED:
        raise GateSignerError("seed")
    return value


def public_key(seed: bytes) -> bytes:
    return run("public-key", _seed(seed), ML_DSA_87_PUBLIC_KEY)


def sign(seed: bytes, message: bytes) -> bytes:
    if type(message) is not bytes or len(message) > MAX_MESSAGE:
        raise GateSignerError("message")
    return run("sign", _seed(seed) + message, ML_DSA_87_SIGNATURE)
