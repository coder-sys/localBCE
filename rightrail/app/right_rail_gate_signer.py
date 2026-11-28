"""The one ML-DSA-87 signer: the gate's ``RR/GATE/CHECKPOINT/v3`` headers, and the
financial owner's custody records and packs (``app/right_rail_financial_custody.py``), each under its own key.

ML-DSA-87 (FIPS 204 algorithm) from a non-validated AWS-LC build (aws-lc-rs),
built from ``rust/gate_mldsa87``.  A key is a *handle*, today a key-file path;
the worker unseals the seed itself, so no seed or secret key reaches Python.
Signing is pure ML-DSA with an empty context and hedged; the epoch key signs
checkpoint headers, the gate producer's row pledges and its stored decide frames, each message starting with its own domain
(the tenant's root and witness keys sign certificates and the verifier key its cosignatures; the state's custodian and the verifier
make those, not this module).  Each pinned executable (this worker and the Lean
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
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import Callable, Final, Sequence

from app import minimal_clearance_verifier_process as process
from app.right_rail_gate_codec import ML_DSA_87_PUBLIC_KEY, ML_DSA_87_SIGNATURE, attach_signature

ROOT: Final = Path(__file__).resolve().parents[1]
CRATE: Final = ROOT / "rust" / "gate_mldsa87"
BINARY: Final = CRATE / "target" / "release" / "rr_gate_mldsa87.exe"
PIN: Final = CRATE / "rr_gate_mldsa87.sha256"
VERIFY: Final = ROOT / "artifacts" / "gate-verify" / "gate_verify.exe"
VERIFY_PIN: Final = VERIFY.with_suffix(".sha256")
ACCEPT: Final = "GATE_VERIFY=ACCEPT"


class GateSignerError(RuntimeError):
    """A pinned executable is unpinned, missing, refused the input or failed."""


_COPIES: dict[Path, tuple[Path, bytes]] = {}
_PRIVATE: list[Path] = []
_LOCK = threading.Lock()
_SERVE = threading.Lock()  # serialises both resident workers; not _LOCK: _private_copy takes that one and it is not reentrant
_SERVER: list = [None, None]  # the resident signing worker and its workspace
_VSERVER: list = [None, None]  # the resident Lean gate_verify worker and its workspace: it keeps no state between requests
MAX_MESSAGE: Final = 65536
MAX_PATH: Final = 32767
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
            atexit.register(_close_server)  # registered last, so it runs first: the child stops before its copy is released and removed
            held = _COPIES[binary] = (copy, hashlib.sha256(copy.read_bytes()).hexdigest().encode())
        return held


def _exec(binary: Path, pin: Path, args: Sequence[str], data: bytes) -> subprocess.CompletedProcess[bytes]:
    """Run the private copy of a pinned executable."""
    name = binary.stem
    if type(data) is not bytes or any(type(arg) is not str for arg in args):
        raise GateSignerError(f"{name}_input")
    try:
        copy, digest = _private_copy(binary)
        if digest != pin.read_bytes().strip():
            raise GateSignerError(f"{name}_pin_mismatch")
        return subprocess.run([str(copy), *args], input=data, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise GateSignerError(f"{name}_failed") from error


def _run(binary: Path, pin: Path, args: Sequence[str], data: bytes, size: int) -> bytes:
    """A pinned executable must exit 0 with exactly ``size`` bytes of output."""
    done = _exec(binary, pin, args, data)
    if done.returncode != 0 or len(done.stdout) != size:
        raise GateSignerError(f"{binary.stem}_failed")
    return done.stdout


def keygen(handle: str) -> bytes:
    """Create the key ``handle`` (never overwriting one) and return its public key."""
    return _run(BINARY, PIN, ("keygen", handle), b"", ML_DSA_87_PUBLIC_KEY)


def public_key(handle: str) -> bytes:
    return _run(BINARY, PIN, ("public-key", handle), b"", ML_DSA_87_PUBLIC_KEY)


def _close_server(*slots: list) -> None:
    for slot in slots or (_SERVER, _VSERVER):
        worker, workspace = slot
        slot[0] = slot[1] = None
        try:
            if worker is not None:
                worker.close()
        finally:
            if workspace is not None:
                shutil.rmtree(workspace, True)


def _resident(slot: list, binary: Path, pin: Path, args: tuple[str, ...], request: bytes, cap: int, memory: int) -> bytes:
    """One framed exchange with the resident worker in ``slot``: pin checked per call; any failure closes it, no retry.
    A worker holding more than half its ``memory`` cap after an answer is closed, so the next call starts a fresh one: unless
    the exe reserves its allocator's address space at start (gate_verify does), the Windows Lean runtime's allocator never
    reuses or returns memory that a large request freed, and a worker that keeps no state between requests gives a fresh
    worker's answers."""
    name = binary.stem
    try:
        copy, digest = _private_copy(binary)
        if digest != pin.read_bytes().strip():
            _close_server(slot)
            raise GateSignerError(f"{name}_pin_mismatch")
    except OSError as error:
        raise GateSignerError(f"{name}_failed") from error
    try:
        if slot[0] is None or not slot[0].alive:
            _close_server(slot)
            slot[1] = Path(tempfile.mkdtemp(prefix="rr-sign-"))
            slot[0] = process.launch_contained_worker(
                copy, workspace=slot[1], job_memory_cap_bytes=memory, arguments=args,
                expected_executable_size_bytes=copy.stat().st_size, expected_executable_sha256=bytes.fromhex(digest.decode()))
        out = slot[0].exchange(request, response_cap_bytes=cap, timeout_seconds=30.0)
        if slot[0].commit_bytes() > memory // 2:
            _close_server(slot)
        return out
    except Exception as error:
        _close_server(slot)
        raise GateSignerError(f"{name}_failed") from error


def sign(handle: str, message: bytes) -> bytes:
    """Sign with the resident worker (one launch, then one framed exchange per call; the key is unsealed per call,
    never held). The pin is checked on every call; any failure closes the worker, with no retry."""
    name = BINARY.stem
    if type(handle) is not str or type(message) is not bytes or "\0" in handle:
        raise GateSignerError(f"{name}_input")
    try:
        path = os.path.abspath(handle).encode("utf-8")
        if len(message) > MAX_MESSAGE or len(path) > MAX_PATH:
            raise GateSignerError(f"{name}_failed")
        with _SERVE:
            out = _resident(_SERVER, BINARY, PIN, (), len(path).to_bytes(2, "big") + path + message, ML_DSA_87_SIGNATURE, 128 << 20)
            if len(out) != ML_DSA_87_SIGNATURE:
                _close_server(_SERVER)
                raise GateSignerError(f"{name}_failed")
            return out
    except (OSError, UnicodeError) as error:
        raise GateSignerError(f"{name}_failed") from error


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Pure ML-DSA-87 verification with the empty context that ``sign`` uses. FIPS 204 Algorithm 3 is
    ``Verify_internal(pk, 0x00 || 0x00 || message, sig)``, which the pinned worker's ``kat-verify`` mode runs."""
    if len(public_key) != ML_DSA_87_PUBLIC_KEY or len(signature) != ML_DSA_87_SIGNATURE:
        return False
    return _run(BINARY, PIN, ("kat-verify",), public_key + signature + b"\x00\x00" + message, 1) == b"\x01"


def framed(data: bytes) -> bytes:
    """``u32 length || data``, the ``gate_verify`` frame's field."""
    return len(data).to_bytes(4, "big") + data


def gate_verify(mode: int, frame: bytes) -> str:
    """The one answer line of the pinned Lean ``gate_verify serve`` (resident; each request decided from its own bytes) for
    ``mode`` and its frame (REJECT and HOLD are answers). A malformed frame or a dead, hung or garbled verifier raises."""
    with _SERVE:
        out = _resident(_VSERVER, VERIFY, VERIFY_PIN, ("serve",), bytes([mode]) + frame, 65536, 512 << 20)
        try:
            if out[0] not in (0, 1):
                raise ValueError
            return out[1:].decode("ascii").strip()
        except (ValueError, IndexError):
            _close_server(_VSERVER)
            raise GateSignerError("gate_verify_failed") from None


def custody(tpm: int | None, link: bytes, cert: bytes, signed: bytes) -> str:
    """Lean ``custodyOf`` for the shard's counter (None: defined but never written) and the store's newest sealed
    checkpoint ``signed`` (with its cosign record) with its epoch certificate ``cert`` (both empty when nothing is sealed).
    Lean reads the store's counter from ``signed`` itself, and its signature under the certificate, which counts only under
    the held authority ``link`` of the tenant, lets an unwritten counter under the shard's first checkpoint catch up:
    ``create``, ``ready`` or ``catch_up``, or a refusal reason (``no_store``, ``counter_reset``, ``store_rewound``,
    ``store_ahead``)."""
    frame = bytes([tpm is not None]) + (tpm or 0).to_bytes(8, "big") + framed(link) + framed(cert) + framed(signed)
    step = gate_verify(7, frame).removeprefix("GATE_VERIFY=CUSTODY ")
    if step not in ("create", "ready", "catch_up", "no_store", "counter_reset", "store_rewound", "store_ahead"):
        raise GateSignerError("gate_verify_failed")
    return step


def seal(handle: str, link: bytes, cert: bytes, last: bytes | None, header: bytes, tokens: Sequence[bytes], tpm: int,
         cosign: Callable[[bytes], bytes]) -> tuple[bytes, bytes]:
    """Sign ``header`` through custody, have the verifier cosign the signed checkpoint (``cosign``: the signed checkpoint, header
    and signature, to its cosign record), and release the signature and the record only if Lean ``publishOk`` accepts the
    cosigned checkpoint as the successor of ``last`` (None: the shard's first; else its signed bytes with its record) with
    exactly ``tokens``, taking the counter value ``tpm`` + 1 where ``tpm`` is the shard's counter before this checkpoint, under
    the held authority ``link``: a faulty, uncosigned or unpublishable signature never leaves."""
    signature = sign(handle, header)
    signed = attach_signature(header, signature)
    record = cosign(signed)
    if type(record) is not bytes:
        raise GateSignerError("gate_verify_refused")
    frame = (framed(link) + framed(cert) + framed(last or b"") + framed(signed + record)
             + len(tokens).to_bytes(2, "big") + b"".join(map(framed, tokens)) + tpm.to_bytes(8, "big"))
    if gate_verify(1, frame) != ACCEPT:
        raise GateSignerError("gate_verify_refused")
    return signature, record
