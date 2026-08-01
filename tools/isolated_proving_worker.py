"""Decrypt one witness inside an isolated worker and stream it to the prover."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid
from typing import Callable

from tools.encrypted_witness_envelope import (
    decrypt_batch_package,
    load_envelope,
    validate_envelope_authorization,
)
from tools.local_kms_simulator import LocalKmsClient
from tools.proving_submission import validate_package_submission, validate_batch_record
from tools import proving_evidence_policy as evidence_policy


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operations", ctypes.c_ulonglong),
        ("write_operations", ctypes.c_ulonglong),
        ("other_operations", ctypes.c_ulonglong),
        ("read_transfer", ctypes.c_ulonglong),
        ("write_transfer", ctypes.c_ulonglong),
        ("other_transfer", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time", ctypes.c_longlong),
        ("per_job_user_time", ctypes.c_longlong),
        ("limit_flags", ctypes.c_uint32),
        ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t),
        ("active_process_limit", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t),
        ("priority_class", ctypes.c_uint32),
        ("scheduling_class", ctypes.c_uint32),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimitInformation),
        ("io", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


def _start_contained_process(command: list[str]) -> tuple[subprocess.Popen[bytes], Callable[[], None]]:
    if os.name != "nt":
        process = subprocess.Popen(
            command,
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE,
            start_new_session=True,
        )

        def close_group() -> None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)

        return process, close_group

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    create_job.restype = ctypes.c_void_p
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    set_information.restype = ctypes.c_int
    assign_process = kernel32.AssignProcessToJobObject
    assign_process.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    assign_process.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    job = create_job(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "unable to create proving worker job object")
    information = _ExtendedLimitInformation()
    information.basic.limit_flags = 0x00002000
    if not set_information(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
        error = ctypes.get_last_error()
        close_handle(job)
        raise OSError(error, "unable to configure proving worker job object")
    try:
        process = subprocess.Popen(
            command,
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE,
        )
        if not assign_process(job, ctypes.c_void_p(int(process._handle))):
            error = ctypes.get_last_error()
            process.terminate()
            process.wait(timeout=10)
            raise OSError(error, "unable to contain isolated proof process")
    except Exception:
        close_handle(job)
        raise

    def close_job() -> None:
        close_handle(job)

    return process, close_job


def decrypt_authorized_package(
    envelope_path: Path,
    *,
    batch_record: dict[str, object],
    authenticated_principal: str,
    kms_client: LocalKmsClient,
) -> dict[str, object]:
    envelope = load_envelope(envelope_path.resolve())
    record = validate_batch_record(dict(batch_record))
    if envelope["agency_id"] != record["agency_id"]:
        raise RuntimeError("encrypted envelope agency does not match the batch record")
    if envelope["claim_count"] != record["claim_count"]:
        raise RuntimeError("encrypted envelope claim count does not match the batch record")
    validate_envelope_authorization(
        envelope,
        authenticated_principal=authenticated_principal,
    )
    request_id = f"unwrap-{uuid.uuid4().hex}"

    def unwrap(wrapped_key: bytes, key_id: str, context_sha256: str) -> bytes:
        return kms_client.unwrap_key(
            wrapped_key,
            key_id,
            agency_id=envelope["agency_id"],
            request_id=request_id,
            context_sha256=context_sha256,
        )

    package = decrypt_batch_package(envelope, unwrap_key=unwrap)
    try:
        validate_package_submission(
            record,
            package,
            authenticated_principal=authenticated_principal,
        )
    except Exception:
        package.clear()
        raise
    return package


def decrypt_authorize_and_reserve(
    envelope_path: Path,
    *,
    batch_record: dict[str, object],
    authenticated_principal: str,
    kms_client: LocalKmsClient,
    queue_root: Path,
    job_id: str,
) -> dict[str, object]:
    package = decrypt_authorized_package(
        envelope_path,
        batch_record=batch_record,
        authenticated_principal=authenticated_principal,
        kms_client=kms_client,
    )
    # Import lazily to avoid the submission/runner module cycle at process start.
    from tools.proving_job_runner import _prepare_queue_root, _reserve_package_once

    root = _prepare_queue_root(queue_root)
    try:
        _reserve_package_once(root, str(package["package_sha256"]), job_id)
    except Exception:
        package.clear()
        raise
    return package


def run_proof_with_pipe(
    package: dict[str, object],
    *,
    output_dir: Path,
    threads: int,
    policy_path: Path,
    ram_token: str | None = None,
) -> int:
    command = [
        sys.executable,
        "-m",
        "tools.run_verified_bootloader_proof",
        "--batch-package-stdin",
        "--output-dir",
        str(output_dir),
        "--threads",
        str(threads),
        "--evidence-policy",
        str(policy_path),
    ]
    if ram_token is not None:
        command.extend(["--ram-token", ram_token])
    payload = bytearray(
        json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    try:
        process, close_containment = _start_contained_process(command)
        try:
            process.communicate(input=payload)
            return int(process.returncode)
        finally:
            close_containment()
    finally:
        for index in range(len(payload)):
            payload[index] = 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolated encrypted-witness proving worker.")
    parser.add_argument("--encrypted-envelope", type=Path, required=True)
    parser.add_argument("--batch-record", type=Path, required=True)
    parser.add_argument("--authenticated-principal", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--queue-root", type=Path, required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--evidence-policy", type=Path, required=True)
    parser.add_argument("--ram-token", required=True)
    args = parser.parse_args()
    if args.threads < 1:
        raise RuntimeError("threads must be positive")
    policy = evidence_policy.load_approved_policy(args.evidence_policy)
    record = json.loads(args.batch_record.read_text(encoding="utf-8"))
    client = LocalKmsClient.from_environment()
    package = decrypt_authorize_and_reserve(
        args.encrypted_envelope,
        batch_record=record,
        authenticated_principal=args.authenticated_principal,
        kms_client=client,
        queue_root=args.queue_root,
        job_id=args.job_id,
    )
    try:
        result = run_proof_with_pipe(
            package,
            output_dir=args.output_dir,
            threads=args.threads,
            policy_path=policy.path,
            ram_token=args.ram_token,
        )
    finally:
        package.clear()
    if result != 0:
        raise RuntimeError(f"isolated proof process exited with code {result}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
