"""Decrypt one witness inside an isolated worker and stream it to the prover."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import uuid

from tools.encrypted_witness_envelope import (
    decrypt_batch_package,
    validate_envelope,
    validate_envelope_authorization,
)
from tools.local_kms_simulator import LocalKmsClient
from tools.proving_submission import _bounded_json, validate_package_submission, validate_batch_record
from tools import proving_evidence_policy as evidence_policy
from tools.proving_process_boundary import (
    ProvingProcessError,
    run_contained_process,
)
from tools.proving_resource_policy import (
    MAX_JOB_BYTES,
    read_policy_file,
)


ROOT = Path(__file__).resolve().parents[1]
_PUBLIC_CODE_PATTERN = re.compile(
    r"(?:batch|encrypted|evidence|proof|proving|queue|trusted)_[a-z0-9_]{1,95}\Z"
)


def _public_call(operation, fallback: str):
    code = fallback
    try:
        return operation()
    except Exception as exc:
        candidate = str(exc)
        if _PUBLIC_CODE_PATTERN.fullmatch(candidate):
            code = candidate
    raise RuntimeError(code)


def _bounded_json_payload(value: object, maximum_bytes: int) -> bytearray:
    payload = bytearray()
    encoder = json.JSONEncoder(
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    try:
        for text_chunk in encoder.iterencode(value):
            encoded = text_chunk.encode("utf-8")
            if len(payload) + len(encoded) > maximum_bytes:
                raise ProvingProcessError("proving_worker_input_cap")
            payload.extend(encoded)
    except ProvingProcessError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise ProvingProcessError("proving_worker_input_invalid") from None
    return payload


def decrypt_authorized_package(
    envelope_path: Path,
    *,
    batch_record: dict[str, object],
    authenticated_principal: str,
    kms_client: LocalKmsClient,
) -> dict[str, object]:
    def operation() -> dict[str, object]:
        envelope = validate_envelope(_bounded_json(envelope_path.resolve(), 2 * 1024 * 1024))
        record = validate_batch_record(dict(batch_record))
        if envelope["agency_id"] != record["agency_id"]:
            raise RuntimeError("queue_envelope_binding")
        if envelope["claim_count"] != record["claim_count"]:
            raise RuntimeError("queue_envelope_binding")
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

    return _public_call(operation, "encrypted_package_rejected")


def decrypt_authorize_and_reserve(
    envelope_path: Path,
    *,
    batch_record: dict[str, object],
    authenticated_principal: str,
    kms_client: LocalKmsClient,
    queue_root: Path,
    job_id: str,
) -> dict[str, object]:
    def operation() -> dict[str, object]:
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

    return _public_call(operation, "encrypted_package_rejected")


def run_proof_with_pipe(
    package: dict[str, object],
    *,
    output_dir: Path,
    resource_policy_path: Path,
    evidence_policy_path: Path,
    ram_token: str | None = None,
) -> int:
    resource_policy = read_policy_file(resource_policy_path)
    command = [
        sys.executable,
        "-m",
        "tools.run_verified_bootloader_proof",
        "--batch-package-stdin",
        "--output-dir",
        str(output_dir),
        "--resource-policy",
        str(resource_policy_path),
        "--evidence-policy",
        str(evidence_policy_path),
    ]
    if ram_token is not None:
        command.extend(["--ram-token", ram_token])
    payload = _bounded_json_payload(package, min(MAX_JOB_BYTES, 8 * 1024 * 1024))
    try:
        result = run_contained_process(
            command,
            cwd=ROOT,
            policy=resource_policy,
            input_bytes=bytes(payload),
            owned_root=output_dir.parent,
        )
        if result.output_overflow:
            raise ProvingProcessError("proving_worker_output_cap")
        return int(result.exit_code)
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
    parser.add_argument("--resource-policy", type=Path, required=True)
    parser.add_argument("--evidence-policy", type=Path, required=True)
    parser.add_argument("--ram-token", required=True)
    args = parser.parse_args()
    resource_policy = read_policy_file(args.resource_policy)
    evidence_policy.load_approved_policy(args.evidence_policy)
    try:
        record = _bounded_json(args.batch_record, 8 * 1024 * 1024)
    except RuntimeError:
        raise RuntimeError("proving_worker_batch_record") from None
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
            resource_policy_path=args.resource_policy,
            evidence_policy_path=args.evidence_policy,
            ram_token=args.ram_token,
        )
    finally:
        package.clear()
    if result != 0:
        raise RuntimeError("proving_worker_process")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        print("proving_worker_rejected", file=sys.stderr)
        raise SystemExit(1) from None
