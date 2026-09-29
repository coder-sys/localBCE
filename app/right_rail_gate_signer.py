"""The one ML-DSA-87 signer for the gate: ``RR/GATE/CHECKPOINT/v1`` headers and ``KEY-CERT/v1`` bodies.

ML-DSA-87 (FIPS 204 algorithm) from a non-validated AWS-LC build (aws-lc-rs),
built from ``rust/gate_mldsa87``.  A key is a *handle*, today a key-file path;
the worker unseals the seed itself, so no seed or secret key reaches Python.
Signing is pure ML-DSA with an empty context and hedged; the epoch key signs
only checkpoint headers and the root key only KEY-CERT bodies, each of which
starts with its own domain.  Each pinned executable (this worker and the Lean
``gate_verify``) is copied into a private temporary directory, hashed against
its SHA-256 pin and run from the copy, so the file that runs is the file that
was checked.  A pin mismatch, a missing binary, a timeout, an OS error or
output of the wrong size raises ``GateSignerError``.  There is no other
implementation and no fallback.  Synthetic, activation=false.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Callable, Final, Sequence

from app.right_rail_gate_codec import ML_DSA_87_PUBLIC_KEY, ML_DSA_87_SIGNATURE, attach_signature

ROOT: Final = Path(__file__).resolve().parents[1]
CRATE: Final = ROOT / "rust" / "gate_mldsa87"
BINARY: Final = CRATE / "target" / "release" / "rr_gate_mldsa87.exe"
PIN: Final = CRATE / "rr_gate_mldsa87.sha256"
VERIFY: Final = ROOT / "artifacts" / "gate-verify" / "gate_verify.exe"
VERIFY_PIN: Final = VERIFY.with_suffix(".sha256")
ACCEPT: Final = b"GATE_VERIFY=ACCEPT\n"


class GateSignerError(RuntimeError):
    """A pinned executable is unpinned, missing, refused the input or failed."""


def _run(binary: Path, pin: Path, args: Sequence[str], data: bytes, size: int) -> bytes:
    """Run a private copy of a pinned executable; it must exit 0 with exactly ``size`` bytes of output."""
    name = binary.stem
    if type(data) is not bytes or any(type(arg) is not str for arg in args):
        raise GateSignerError(f"{name}_input")
    try:
        with tempfile.TemporaryDirectory() as private:
            copy = Path(private) / binary.name
            shutil.copyfile(binary, copy)
            if hashlib.sha256(copy.read_bytes()).hexdigest().encode() != pin.read_bytes().strip():
                raise GateSignerError(f"{name}_pin_mismatch")
            done = subprocess.run([str(copy), *args], input=data, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise GateSignerError(f"{name}_failed") from error
    if done.returncode != 0 or len(done.stdout) != size:
        raise GateSignerError(f"{name}_failed")
    return done.stdout


def keygen(handle: str) -> bytes:
    """Create the key ``handle`` (never overwriting one) and return its public key."""
    return _run(BINARY, PIN, ("keygen", handle), b"", ML_DSA_87_PUBLIC_KEY)


def public_key(handle: str) -> bytes:
    return _run(BINARY, PIN, ("public-key", handle), b"", ML_DSA_87_PUBLIC_KEY)


def sign(handle: str, message: bytes) -> bytes:
    return _run(BINARY, PIN, ("sign", handle), message, ML_DSA_87_SIGNATURE)


def checked(handle: str, root_pk: bytes, key_cert: bytes) -> Callable[[bytes], bytes]:
    """The ``sign`` callback of ``sign_batch``: sign the header through custody, then run the pinned Lean
    ``gate_verify`` on ``root_pk || u32 len || key_cert || signed checkpoint``.  The signature is returned
    only on ``GATE_VERIFY=ACCEPT`` (exit 0); any other answer raises, so a faulty signature never leaves."""

    def sign_header(header: bytes) -> bytes:
        signature = sign(handle, header)
        framed = root_pk + len(key_cert).to_bytes(4, "big") + key_cert + attach_signature(header, signature)
        if _run(VERIFY, VERIFY_PIN, (), framed, len(ACCEPT)) != ACCEPT:
            raise GateSignerError("gate_verify_refused")
        return signature

    return sign_header
