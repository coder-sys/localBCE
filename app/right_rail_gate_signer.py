"""The one ML-DSA-87 signer for the gate: ``RR/GATE/CHECKPOINT/v1`` headers and ``KEY-CERT/v1`` bodies.

ML-DSA-87 (FIPS 204 algorithm) from a non-validated AWS-LC build (aws-lc-rs),
built from ``rust/gate_mldsa87``.  A key is a *handle*, today a key-file path;
the worker unseals the seed itself, so no seed or secret key reaches Python.
Signing is pure ML-DSA with an empty context and hedged; the epoch key signs
only checkpoint headers and the root key only KEY-CERT bodies, each of which
starts with its own domain.  Each pinned executable (this worker and the Lean
``gate_verify``) is copied once per process into a private temporary directory,
held open so it cannot be written or deleted, and hashed; the hash is compared
with its SHA-256 pin before every run, so the file that runs is the file that
was checked.  A pin mismatch, a missing binary, a timeout, an OS error or
output of the wrong size raises ``GateSignerError``.  There is no other
implementation and no fallback.  Synthetic, activation=false.
"""

from __future__ import annotations

import atexit
import ctypes
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import Final, Sequence

from app.right_rail_gate_codec import ML_DSA_87_PUBLIC_KEY, ML_DSA_87_SIGNATURE, CheckedSigner, attach_signature

ROOT: Final = Path(__file__).resolve().parents[1]
CRATE: Final = ROOT / "rust" / "gate_mldsa87"
BINARY: Final = CRATE / "target" / "release" / "rr_gate_mldsa87.exe"
PIN: Final = CRATE / "rr_gate_mldsa87.sha256"
VERIFY: Final = ROOT / "artifacts" / "gate-verify" / "gate_verify.exe"
VERIFY_PIN: Final = VERIFY.with_suffix(".sha256")
ACCEPT: Final = b"GATE_VERIFY=ACCEPT\n"


class GateSignerError(RuntimeError):
    """A pinned executable is unpinned, missing, refused the input or failed."""


_COPIES: dict[Path, tuple[Path, bytes]] = {}
_PRIVATE: list[Path] = []
_LOCK = threading.Lock()
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.CreateFileW.restype = ctypes.c_void_p
_KERNEL32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
_KERNEL32.CloseHandle.argtypes = [ctypes.c_void_p]


def _private_copy(binary: Path) -> tuple[Path, bytes]:
    """The process-private copy of ``binary`` and its SHA-256, made once per process (a fresh executable costs
    about 0.4 s to copy and first start).  The copy is opened with sharing that denies write and delete until
    the process exits, then hashed, so the file that runs is the file that was hashed."""
    with _LOCK:
        held = _COPIES.get(binary)
        if held is None:
            if not _PRIVATE:
                _PRIVATE.append(Path(tempfile.mkdtemp()))
                atexit.register(shutil.rmtree, _PRIVATE[0], True)
            copy = _PRIVATE[0] / f"{len(_COPIES)}-{binary.name}"
            shutil.copyfile(binary, copy)
            handle = _KERNEL32.CreateFileW(str(copy), 0x80000000, 1, None, 3, 0, None)  # read; share read only; existing
            if handle in (None, ctypes.c_void_p(-1).value):
                raise OSError("gate_signer_hold")
            atexit.register(_KERNEL32.CloseHandle, handle)
            held = _COPIES[binary] = (copy, hashlib.sha256(copy.read_bytes()).hexdigest().encode())
        return held


def _run(binary: Path, pin: Path, args: Sequence[str], data: bytes, size: int) -> bytes:
    """Run the private copy of a pinned executable; it must exit 0 with exactly ``size`` bytes of output."""
    name = binary.stem
    if type(data) is not bytes or any(type(arg) is not str for arg in args):
        raise GateSignerError(f"{name}_input")
    try:
        copy, digest = _private_copy(binary)
        if digest != pin.read_bytes().strip():
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


def checked(handle: str, root_pk: bytes, key_cert: bytes) -> CheckedSigner:
    """The ``sign`` callback of ``sign_batch``: sign the header through custody, then run the pinned Lean
    ``gate_verify`` on ``root_pk || u32 len || key_cert || signed checkpoint``.  The signature is returned
    only on ``GATE_VERIFY=ACCEPT`` (exit 0); any other answer raises, so a faulty signature never leaves."""

    def sign_header(header: bytes) -> bytes:
        signature = sign(handle, header)
        framed = root_pk + len(key_cert).to_bytes(4, "big") + key_cert + attach_signature(header, signature)
        if _run(VERIFY, VERIFY_PIN, (), framed, len(ACCEPT)) != ACCEPT:
            raise GateSignerError("gate_verify_refused")
        return signature

    return CheckedSigner(sign_header)
