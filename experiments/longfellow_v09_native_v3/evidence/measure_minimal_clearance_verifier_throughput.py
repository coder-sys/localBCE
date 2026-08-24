"""Run a bounded serial runtime exercise for synthetic evidence only.

The retained queue runtime owns admission, custody, verifier construction, and
processing.  This script is deliberately a single-owner sequential exercise;
it does not construct a verifier, inject a factory, or claim a throughput
qualification.  It never invokes a prover or mutates clearance/payment state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

if __package__ in (None, ""):
    _REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
    if str(_REPOSITORY_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPOSITORY_ROOT))

from app.minimal_clearance_verification_queue import ArtifactMetadata, QueueConfig
from app.minimal_clearance_verification_queue_independent import (
    read_verified_jobs,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime


SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFIER-SERIAL-RUNTIME/v1"
ARTIFACT_SHA256 = "69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E"
ARTIFACT_SHA3_512 = "A2D3DDBA8C6ECAABC70147793185318FA7910E8EBBA0675D614E95885DAC23331C3F2FE3689F30748B030C9A26D55D704DB244C5DC36136896F6B87F42045BE1"
VERIFIER_SHA256 = "E2BD096389E7D9CB3F8D83314747CA3D493DF6C30D86A57041F74B84F0023F3E"
ARTIFACT_BYTES = 411_672
CAP_BYTES = 5_000_000_000
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_JOBS = 256


class ThroughputError(RuntimeError):
    """Fixed-code script boundary error."""

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code.isidentifier() else "exercise_failed"
        super().__init__(self.code)
        self.__cause__ = None
        self.__context__ = None
        self.__suppress_context__ = True


def _fail(code: str) -> None:
    try:
        raise ThroughputError(code)
    except ThroughputError as fixed:
        fixed.__cause__ = None
        fixed.__context__ = None
        fixed.__suppress_context__ = True
        raise


def _bounded_digest(path: Path, expected_bytes: int | None = None) -> tuple[int, str, bool]:
    if not isinstance(path, Path):
        _fail("identity_type")
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or int(before.st_nlink) != 1 or path.is_symlink():
            _fail("identity_regular")
        descriptor = os.open(str(path), os.O_RDONLY | int(getattr(os, "O_BINARY", 0)))
        try:
            opened = os.fstat(descriptor)
            if (int(opened.st_dev), int(opened.st_ino), int(opened.st_nlink), int(opened.st_size)) != (
                int(before.st_dev), int(before.st_ino), int(before.st_nlink), int(before.st_size)
            ):
                _fail("identity_changed")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if expected_bytes is not None and total > expected_bytes:
                    _fail("identity_size")
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = os.lstat(path)
        if (int(after.st_dev), int(after.st_ino), int(after.st_nlink), int(after.st_size)) != (
            int(current.st_dev), int(current.st_ino), int(current.st_nlink), int(current.st_size)
        ):
            _fail("identity_changed")
        if expected_bytes is not None and total != expected_bytes:
            _fail("identity_size")
        readonly = not bool(int(current.st_mode) & stat.S_IWRITE)
        return total, digest.hexdigest().upper(), readonly
    except ThroughputError:
        raise
    except (OSError, ValueError):
        _fail("identity_read")


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("evidence_encoding")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        _fail("evidence_size")
    if b"\\" in encoded or b"MINIMAL_CLEARANCE_VERIFIER_" in encoded or b"MINIMAL_CLEARANCE_BUILD" in encoded:
        _fail("evidence_privacy")
    return encoded


def _write_evidence(path: Path, record: dict[str, Any]) -> bytes:
    encoded = _canonical_json(record)
    try:
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            _fail("evidence_target")
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0)), 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return encoded
    except ThroughputError:
        raise
    except (OSError, ValueError):
        _fail("evidence_write")


def run_serial(
    *,
    artifact: Path,
    verifier: Path,
    database: Path,
    workspace_parent: Path,
    restore_database: Path,
    evidence_output: Path,
    job_count: int = 4,
) -> dict[str, Any]:
    """Run one owner and a bounded sequential set of queue jobs."""

    if type(job_count) is not int or not 1 <= job_count <= MAX_JOBS:
        _fail("job_count")
    if any(path.exists() or path.is_symlink() for path in (database, restore_database, evidence_output)):
        _fail("fresh_target_required")
    if not isinstance(workspace_parent, Path) or not workspace_parent.is_dir() or workspace_parent.is_symlink():
        _fail("workspace_parent")
    artifact_size, artifact_hash, artifact_readonly = _bounded_digest(artifact, ARTIFACT_BYTES)
    verifier_size, verifier_hash, _ = _bounded_digest(verifier)
    if artifact_size != ARTIFACT_BYTES or artifact_hash != ARTIFACT_SHA256 or not artifact_readonly:
        _fail("retained_artifact_identity")
    if verifier_size <= 0 or verifier_hash != VERIFIER_SHA256:
        _fail("verifier_identity")

    metadata = ArtifactMetadata(
        artifact.name,
        ARTIFACT_BYTES,
        bytes.fromhex(ARTIFACT_SHA256),
        bytes.fromhex(ARTIFACT_SHA3_512),
    )
    config = QueueConfig(
        "minimal-clearance-serial-exercise-v3",
        1,
        bytes.fromhex(VERIFIER_SHA256),
        512 * 1024 * 1024,
    )
    job_ids = tuple(f"serial-job-{index}" for index in range(job_count))
    started = time.perf_counter()
    try:
        with MinimalClearanceVerificationRuntime(
            database=database,
            config=config,
            executable=verifier,
            source_root=artifact.parent,
            workspace_parent=workspace_parent,
        ) as runtime:
            for job_id in job_ids:
                runtime.admit(job_id=job_id, metadata=metadata)
            runtime_result = runtime.run(max_jobs=job_count)
            runtime.verify_integrity()
            exported = runtime.export_bytes()
    except ThroughputError:
        raise
    except BaseException:
        _fail("runtime_exercise")
    elapsed_ms = max(1, int(round((time.perf_counter() - started) * 1000)))
    if runtime_result.indeterminate or runtime_result.verified != job_count:
        _fail("serial_runtime_not_verified")

    try:
        producer_summary = verify_database(database, expected_config=config.as_json())
        export_summary = verify_export_bytes(exported, expected_config=config.as_json())
        restored_summary = restore_export_to_fresh_database(restore_database, exported)
        jobs = read_verified_jobs(database, job_ids, expected_config=config.as_json())
    except BaseException:
        _fail("independent_reconstruction")
    if producer_summary != export_summary or export_summary != restored_summary:
        _fail("reconstruction_parity")
    if len(jobs) != job_count or any(job.exit_code != 0 or job.timed_out or not job.cap_enforced for job in jobs):
        _fail("receipt_not_verified")
    _, artifact_hash_after, artifact_readonly_after = _bounded_digest(artifact, ARTIFACT_BYTES)
    _, verifier_hash_after, _ = _bounded_digest(verifier)
    if artifact_hash_after != ARTIFACT_SHA256 or not artifact_readonly_after or verifier_hash_after != VERIFIER_SHA256:
        _fail("source_identity_changed")

    output = {
        "schema": SCHEMA,
        "queue_schema": config.as_json()["schema_version"],
        "queue_id": config.queue_id,
        "verification_count": runtime_result.processed,
        "verified_count": runtime_result.verified,
        "rejected_count": runtime_result.rejected,
        "held_count": runtime_result.held,
        "retry_count": runtime_result.requeued,
        "serial_owner_runtime": True,
        "distinct_job_count": len(jobs),
        "distinct_lease_count": int(export_summary["claim_count"]),
        "distinct_worker_count": int(export_summary["distinct_worker_count"]),
        "distinct_verifier_count": 1,
        "artifact_bytes": ARTIFACT_BYTES,
        "artifact_sha256": ARTIFACT_SHA256,
        "artifact_sha3_512": ARTIFACT_SHA3_512,
        "artifact_readonly_before": artifact_readonly,
        "artifact_readonly_after": artifact_readonly_after,
        "verifier_sha256": VERIFIER_SHA256,
        "cap_bytes": CAP_BYTES,
        "cap_enforced": True,
        "active_process_limit": 1,
        "elapsed_ms": elapsed_ms,
        "claim_count": int(export_summary["claim_count"]),
        "completion_count": int(export_summary["completion_count"]),
        "queue_reconstruction_parity": True,
        "export_restore_parity": True,
        "runtime_recovered_leases": runtime_result.recovered_leases,
        "runtime_scavenged_workspaces": runtime_result.scavenged_workspaces,
        "state_store_mutation_count": 0,
        "clearance_authorization_count": 0,
        "payment_movement_count": 0,
        "prover_invocation_count": 0,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
        "experimental_software_only": True,
        "throughput_qualification": False,
    }
    _write_evidence(evidence_output, output)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--workspace-parent", type=Path, required=True)
    parser.add_argument("--restore-database", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--job-count", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        output = run_serial(**vars(args))
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        return 0
    except ThroughputError as error:
        sys.stderr.write(f"THROUGHPUT_FAILURE code={error.code}\n")
        return 1
    except BaseException:
        sys.stderr.write("THROUGHPUT_FAILURE code=exercise_failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
