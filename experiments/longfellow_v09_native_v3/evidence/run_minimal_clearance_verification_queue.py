"""Run exactly one four-job queue integration exercise.

The command accepts paths, but the canonical JSON contains only synthetic
identities, bounded measurements, and queue state summaries.  It never calls
the prover or the clearance state store.
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

from app.minimal_clearance_verification_queue import (
    ArtifactMetadata,
    FilesystemArtifactCustody,
    QueueConfig,
    QueueWorker,
    VerificationQueueStore,
    run_bounded_workers,
)
from app.minimal_clearance_verification_queue_independent import (
    restore_export_to_fresh_database,
    verify_database,
    verify_export_bytes,
)
from app.minimal_clearance_proof_state import NativeMinimalClearanceVerifier


ARTIFACT_BYTES = 411_672
ARTIFACT_SHA256 = "69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E"
ARTIFACT_SHA3_512 = "A2D3DDBA8C6ECAABC70147793185318FA7910E8EBBA0675D614E95885DAC23331C3F2FE3689F30748B030C9A26D55D704DB244C5DC36136896F6B87F42045BE1"
VERIFIER_SHA256 = "E2BD096389E7D9CB3F8D83314747CA3D493DF6C30D86A57041F74B84F0023F3E"
CAP_BYTES = 5_000_000_000
ARTIFACT_REF = "retained-minimal-proof-v1"


class _TimedVerifier:
    def __init__(self, native: NativeMinimalClearanceVerifier) -> None:
        self.native = native
        self.started = 0.0
        self.ended = 0.0

    def identity_sha256(self) -> bytes:
        return self.native.identity_sha256()

    @property
    def last_containment_result(self):
        return self.native.last_containment_result

    def verify(self, artifact_path: Path):
        self.started = time.perf_counter()
        try:
            return self.native.verify(artifact_path)
        finally:
            self.ended = time.perf_counter()


class _Factory:
    def __init__(self, executable: Path) -> None:
        self.executable = executable
        self.instances: list[_TimedVerifier] = []

    def __call__(self) -> _TimedVerifier:
        verifier = _TimedVerifier(NativeMinimalClearanceVerifier(
            self.executable, executable_sha256=VERIFIER_SHA256, timeout_seconds=30.0 * 60.0,
        ))
        self.instances.append(verifier)
        return verifier


def _read_identity(path: Path) -> tuple[bytes, str, bool]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("identity_source_not_regular")
    raw = path.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest().upper(), not bool(path.stat().st_mode & stat.S_IWRITE)


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run(*, artifact: Path, verifier: Path, database: Path, workspace: Path, restore_database: Path, evidence_output: Path) -> dict[str, Any]:
    if any(path.exists() or path.is_symlink() for path in (database, restore_database, evidence_output)):
        raise RuntimeError("fresh_target_required")
    if not workspace.is_dir():
        raise RuntimeError("workspace_parent_required")
    artifact_raw, artifact_hash, artifact_readonly = _read_identity(artifact)
    if len(artifact_raw) != ARTIFACT_BYTES or artifact_hash != ARTIFACT_SHA256 or hashlib.sha3_512(artifact_raw).hexdigest().upper() != ARTIFACT_SHA3_512 or not artifact_readonly:
        raise RuntimeError("retained_artifact_identity")
    _, verifier_hash, _ = _read_identity(verifier)
    if verifier_hash != VERIFIER_SHA256:
        raise RuntimeError("verifier_identity")

    metadata = ArtifactMetadata(ARTIFACT_REF, ARTIFACT_BYTES, bytes.fromhex(ARTIFACT_SHA256), bytes.fromhex(ARTIFACT_SHA3_512))
    config = QueueConfig(
        queue_id="minimal-clearance-queue-exercise-v1", capacity=4, lease_seconds=300,
        verifier_sha256=bytes.fromhex(VERIFIER_SHA256), artifact_bytes_cap=512 * 1024 * 1024,
        retryable_codes=("custody_read", "custody_snapshot", "verifier_memory_cap", "verifier_process_unavailable", "verifier_timeout"),
    )
    custody = FilesystemArtifactCustody(resolver=lambda ref: artifact if ref == ARTIFACT_REF else Path("missing"), workspace_parent=workspace)
    factory = _Factory(verifier)
    store = VerificationQueueStore(path=database, config=config)
    for index in range(4):
        store.admit(job_id=f"queue-job-{index}", metadata=metadata)
    workers = tuple(
        QueueWorker(store=store, worker_id=f"queue-worker-{index}", custody=custody, verifier_factory=factory)
        for index in range(4)
    )
    wave_started = time.perf_counter()
    results = run_bounded_workers(workers)
    wave_wall_ms = max(1, int(round((time.perf_counter() - wave_started) * 1000)))
    if len(results) != 4 or any(result is None or result.status != "VERIFIED" for result in results):
        raise RuntimeError("queue_verification_not_verified")
    if len(factory.instances) != 4 or len({id(item.native) for item in factory.instances}) != 4:
        raise RuntimeError("verifier_instance_sharing")
    intervals = [(item.started, item.ended) for item in factory.instances]
    if not all(start > 0 and end >= start for start, end in intervals) or max(start for start, _ in intervals) >= min(end for _, end in intervals):
        raise RuntimeError("verifier_no_overlap")
    direct_containment = []
    for item in factory.instances:
        result = item.last_containment_result
        if result is None or result.exit_code != 0 or result.timed_out or result.cap_bytes != CAP_BYTES or result.cap_enforced is not True or result.active_process_limit != 1 or result.peak_job_commit_bytes > CAP_BYTES:
            raise RuntimeError("containment_not_qualified")
        direct_containment.append(result)
    store.verify_integrity()
    exported = store.export_bytes()
    producer_summary = verify_database(database, expected_config=config.as_json())
    export_summary = verify_export_bytes(exported, expected_config=config.as_json())
    restored_summary = restore_export_to_fresh_database(restore_database, exported)
    if producer_summary != export_summary or export_summary != restored_summary:
        raise RuntimeError("independent_reconstruction_mismatch")
    _, artifact_hash_after, artifact_readonly_after = _read_identity(artifact)
    _, verifier_hash_after, _ = _read_identity(verifier)
    if artifact_hash_after != ARTIFACT_SHA256 or artifact_readonly_after is not True or verifier_hash_after != VERIFIER_SHA256:
        raise RuntimeError("source_identity_changed")
    transition_value = json.loads(exported.decode("ascii"))
    claims = [item for item in transition_value["transitions"] if item["transition_kind"] == "CLAIM"]
    completes = [item for item in transition_value["transitions"] if item["transition_kind"] == "COMPLETE_VERIFIED"]
    workers_seen = {item["event_bytes"] for item in claims}
    receipts = []
    for result in results:
        receipt = json.loads(result.receipt_bytes.decode("ascii"))
        evidence = receipt["evidence"]
        receipts.append({
            "job_id": receipt["job_id"], "artifact_bytes": evidence["artifact_bytes"],
            "peak_job_commit_bytes": evidence["peak_job_commit_bytes"],
            "stdout_sha3_512": evidence["stdout_sha3_512"], "stderr_sha3_512": evidence["stderr_sha3_512"],
        })
    receipts.sort(key=lambda item: item["job_id"])
    output = {
        "schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE-VERIFICATION-QUEUE/INTEGRATION-EVIDENCE/v1",
        "queue_schema": config.as_json()["schema_version"], "queue_id": config.queue_id,
        "verification_count": 4, "verified_count": 4, "retry_count": 0, "rejected_count": 0, "held_count": 0,
        "distinct_job_count": len({item["job_id"] for item in receipts}), "distinct_lease_count": len(claims),
        "distinct_worker_count": len(workers_seen), "distinct_verifier_instance_count": len(factory.instances),
        "distinct_custody_snapshot_count": len(claims), "verification_overlap": True,
        "artifact_bytes": ARTIFACT_BYTES, "artifact_sha256": ARTIFACT_SHA256, "artifact_sha3_512": ARTIFACT_SHA3_512,
        "artifact_readonly_before": artifact_readonly, "artifact_readonly_after": artifact_readonly_after,
        "verifier_sha256": VERIFIER_SHA256, "cap_bytes": CAP_BYTES, "cap_enforced": True, "active_process_limit": 1,
        "peak_job_commit_bytes": [item["peak_job_commit_bytes"] for item in receipts],
        "peak_job_commit_max_bytes": max(item["peak_job_commit_bytes"] for item in receipts),
        "timed_out": False, "exit_codes": [item.exit_code for item in direct_containment],
        "wave_wall_ms": wave_wall_ms, "per_job": receipts,
        "per_verifier_wall_ms": [max(1, int(round((item.ended - item.started) * 1000))) for item in factory.instances],
        "transition_claim_count": len(claims), "transition_complete_verified_count": len(completes),
        "queue_reconstruction_parity": True, "export_restore_parity": True,
        "final_queue_head_root": producer_summary["head_root"], "final_status_counts": producer_summary["status_counts"],
        "state_store_mutation_count": 0, "clearance_authorization_count": 0, "payment_movement_count": 0,
        "prover_invocation_count": 0, "proof_suite_id": None, "production_usable": False,
        "activation": False, "payment_authority": False, "clearance_authority": False,
        "experimental_software_only": True,
        "full_claim_cost_measured": False, "proving_throughput_measured": False,
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
    output = run(**vars(args))
    print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
