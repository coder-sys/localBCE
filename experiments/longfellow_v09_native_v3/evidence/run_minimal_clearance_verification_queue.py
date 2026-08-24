"""Run one bounded, single-owner V3 queue exercise.

The exercise is synthetic/nonproduction evidence.  It never calls a prover or
the clearance state/payment owner, and it does not overwrite checked-in
historical evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import time
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from app.minimal_clearance_verification_queue import ArtifactMetadata, QueueConfig, VerificationQueueStore
from app.minimal_clearance_verification_queue_independent import (
    read_verified_jobs,
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime


ARTIFACT_BYTES = 411_672
ARTIFACT_SHA256 = "69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E"
ARTIFACT_SHA3_512 = "A2D3DDBA8C6ECAABC70147793185318FA7910E8EBBA0675D614E95885DAC23331C3F2FE3689F30748B030C9A26D55D704DB244C5DC36136896F6B87F42045BE1"
VERIFIER_SHA256 = "E2BD096389E7D9CB3F8D83314747CA3D493DF6C30D86A57041F74B84F0023F3E"
CAP_BYTES = 5_000_000_000


def _read_identity(path: Path) -> tuple[int, str, bool]:
    try:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("identity_source_not_regular")
        raw = path.read_bytes()
        readonly = not bool(path.stat().st_mode & stat.S_IWRITE)
    except RuntimeError:
        raise
    except (OSError, ValueError):
        raise RuntimeError("identity_source_not_regular") from None
    return len(raw), hashlib.sha256(raw).hexdigest().upper(), readonly


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run(*, artifact: Path, verifier: Path, database: Path, workspace: Path, restore_database: Path, evidence_output: Path) -> dict[str, Any]:
    if any(path.exists() or path.is_symlink() for path in (database, restore_database, evidence_output)):
        raise RuntimeError("fresh_target_required")
    if not workspace.is_dir() or workspace.is_symlink():
        raise RuntimeError("workspace_parent_required")
    artifact_size, artifact_hash, artifact_readonly = _read_identity(artifact)
    if artifact_size != ARTIFACT_BYTES or artifact_hash != ARTIFACT_SHA256 or not artifact_readonly:
        raise RuntimeError("retained_artifact_identity")
    _, verifier_hash, _ = _read_identity(verifier)
    if verifier_hash != VERIFIER_SHA256:
        raise RuntimeError("verifier_identity")

    artifact_ref = artifact.name
    metadata = ArtifactMetadata(artifact_ref, ARTIFACT_BYTES, bytes.fromhex(ARTIFACT_SHA256), bytes.fromhex(ARTIFACT_SHA3_512))
    config = QueueConfig("minimal-clearance-queue-exercise-v3", 4, bytes.fromhex(VERIFIER_SHA256), 512 * 1024 * 1024)
    store = VerificationQueueStore(path=database, config=config)
    job_ids = tuple(f"queue-job-{index}" for index in range(4))
    for job_id in job_ids:
        store.admit(job_id=job_id, metadata=metadata)
    started = time.perf_counter()
    with MinimalClearanceVerificationRuntime(
        database=database,
        config=config,
        executable=verifier,
        source_root=artifact.parent,
        workspace_parent=workspace,
    ) as runtime:
        runtime_result = runtime.run(max_jobs=4)
    wave_wall_ms = max(1, int(round((time.perf_counter() - started) * 1000)))
    if runtime_result.indeterminate or runtime_result.verified != 4:
        raise RuntimeError("queue_verification_not_verified")

    store.verify_integrity()
    exported = store.export_bytes()
    producer_summary = verify_database(database, expected_config=config.as_json())
    export_summary = verify_export_bytes(exported, expected_config=config.as_json())
    restored_summary = restore_export_to_fresh_database(restore_database, exported)
    if producer_summary != export_summary or export_summary != restored_summary:
        raise RuntimeError("independent_reconstruction_mismatch")
    jobs = read_verified_jobs(database, job_ids, expected_config=config.as_json())
    if len(jobs) != 4 or any(job.exit_code != 0 or job.timed_out or not job.cap_enforced for job in jobs):
        raise RuntimeError("queue_receipt_not_verified")
    artifact_size_after, artifact_hash_after, artifact_readonly_after = _read_identity(artifact)
    _, verifier_hash_after, _ = _read_identity(verifier)
    if artifact_size_after != ARTIFACT_BYTES or artifact_hash_after != ARTIFACT_SHA256 or artifact_readonly_after is not True or verifier_hash_after != VERIFIER_SHA256:
        raise RuntimeError("source_identity_changed")

    per_job = [
        {
            "job_id": job.job_id,
            "artifact_bytes": job.artifact_bytes,
            "peak_job_commit_bytes": job.peak_job_commit_bytes,
        }
        for job in jobs
    ]
    output = {
        "schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/INTEGRATION-EVIDENCE/v2",
        "queue_schema": config.as_json()["schema_version"],
        "queue_id": config.queue_id,
        "verification_count": runtime_result.processed,
        "verified_count": runtime_result.verified,
        "retry_count": runtime_result.requeued,
        "rejected_count": runtime_result.rejected,
        "held_count": runtime_result.held,
        "distinct_job_count": len(jobs),
        "distinct_lease_count": int(export_summary["claim_count"]),
        "distinct_worker_count": int(export_summary["distinct_worker_count"]),
        "distinct_verifier_instance_count": 1,
        "distinct_custody_snapshot_count": len(jobs),
        "verification_overlap": False,
        "single_owner_runtime": True,
        "artifact_bytes": ARTIFACT_BYTES,
        "artifact_sha256": ARTIFACT_SHA256,
        "artifact_sha3_512": ARTIFACT_SHA3_512,
        "artifact_readonly_before": artifact_readonly,
        "artifact_readonly_after": artifact_readonly_after,
        "verifier_sha256": VERIFIER_SHA256,
        "cap_bytes": CAP_BYTES,
        "cap_enforced": True,
        "active_process_limit": 1,
        "peak_job_commit_bytes": [job.peak_job_commit_bytes for job in jobs],
        "peak_job_commit_max_bytes": max(job.peak_job_commit_bytes for job in jobs),
        "timed_out": False,
        "exit_codes": [job.exit_code for job in jobs],
        "wave_wall_ms": wave_wall_ms,
        "per_job": per_job,
        "transition_claim_count": int(export_summary["claim_count"]),
        "transition_complete_verified_count": int(export_summary["completion_count"]),
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
        "payment_authority": False,
        "clearance_authority": False,
        "experimental_software_only": True,
        "full_claim_cost_measured": False,
        "proving_throughput_measured": False,
        "production_queue_db_multinode_soak_qualified": False,
    }
    encoded = _json_bytes(output)
    if b"\\" in encoded or _STDOUT_MARKER in encoded or _STDERR_MARKER in encoded:
        raise RuntimeError("evidence_privacy")
    evidence_output.parent.mkdir(parents=True, exist_ok=True)
    with evidence_output.open("xb") as handle:
        handle.write(encoded)
        handle.flush()
    return output


_STDOUT_MARKER = b"MINIMAL_CLEARANCE_VERIFIER_ACCEPT"
_STDERR_MARKER = b"MINIMAL_CLEARANCE_VERIFIER_STAGE"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--restore-database", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = run(**vars(args))
    except BaseException:
        print('{"error":"integration_exercise_failed"}')
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
