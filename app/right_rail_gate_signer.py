"""The one ML-DSA-87 signer/verifier for ``RR/GATE/CHECKPOINT/v1``.

Signing and verification are AWS-LC's ML-DSA-87 (FIPS 204) through aws-lc-rs,
built from ``rust/gate_mldsa87``.  Keys, signatures and messages are opaque,
length-checked bytes.  There is no other implementation and no fallback: if
the binary is absent or fails, the call raises.  Synthetic, activation=false.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Final

from app.right_rail_gate_codec import ML_DSA_87_PUBLIC_KEY, ML_DSA_87_SIGNATURE

SEED: Final = 32
MAX_MESSAGE: Final = 64 * 1024
BINARY: Final = Path(__file__).resolve().parents[1] / "rust" / "gate_mldsa87" / "target" / "release" / "rr_gate_mldsa87.exe"


class GateSignerError(RuntimeError):
    """The ML-DSA-87 binary is missing, refused the input or failed."""


def _run(mode: str, data: bytes, size: int | None) -> bytes | bool:
    if not BINARY.is_file():
        raise GateSignerError("mldsa87_binary_missing")
    done = subprocess.run([str(BINARY), mode], input=data, capture_output=True, timeout=30, check=False)
    if mode == "verify" and done.returncode in (0, 1):
        return done.returncode == 0
    if done.returncode != 0 or len(done.stdout) != size:
        raise GateSignerError(f"mldsa87_{mode}_failed")
    return done.stdout


def _checked(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise GateSignerError(label)
    return value


def _message(value: object) -> bytes:
    if type(value) is not bytes or len(value) > MAX_MESSAGE:
        raise GateSignerError("message")
    return value


def public_key(seed: bytes) -> bytes:
    return _run("public-key", _checked(seed, SEED, "seed"), ML_DSA_87_PUBLIC_KEY)  # type: ignore[return-value]


def sign(seed: bytes, message: bytes) -> bytes:
    return _run("sign", _checked(seed, SEED, "seed") + _message(message), ML_DSA_87_SIGNATURE)  # type: ignore[return-value]


def verify(key: bytes, message: bytes, signature: bytes) -> bool:
    data = _checked(key, ML_DSA_87_PUBLIC_KEY, "public_key") + _checked(signature, ML_DSA_87_SIGNATURE, "signature")
    return _run("verify", data + _message(message), None)  # type: ignore[return-value]
