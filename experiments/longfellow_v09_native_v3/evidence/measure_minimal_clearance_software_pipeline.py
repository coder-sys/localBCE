"""Measure the bounded synthetic software pipeline at its safe boundary.

This evidence runner deliberately stops at one independently verified queue
read.  The current composition store binds one state profile to one exact
statement shape; admitting 100 distinct synthetic statement states would
require a separate state-owner decision and is excluded here.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import os
import sys
import time
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

import tests.test_minimal_clearance_verification_queue as queue_fixtures
from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_proof_primitives import MinimalProofAcceptanceV1
from app.minimal_clearance_verification_queue import ArtifactMetadata
from app.minimal_clearance_verification_queue_independent import read_verified_jobs, verify_database


_COUNT = 100
_CAP_BYTES = 5_000_000_000
_ADMISSION_BYTES = 4_500_000_000
_SCHEMA = "BL/NATIVE-V3/MINIMAL-CLEARANCE/SOFTWARE-PIPELINE/v1"


class _SyntheticFactory:
    def __init__(self, acceptances: list[MinimalProofAcceptanceV1]) -> None:
        self._acceptances = list(acceptances)

    def __call__(self):
        if not self._acceptances:
            raise RuntimeError("synthetic_factory_exhausted")
        verifier = object.__new__(queue_fixtures.NativeMinimalClearanceVerifier)
        verifier._test_failure = None  # type: ignore[attr-defined]
        verifier._test_acceptance = self._acceptances.pop(0)  # type: ignore[attr-defined]
        return verifier


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("empty_latency")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1))
    return round(ordered[index], 3)


def _write_json_atomically(path: Path, value: dict[str, Any]) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise RuntimeError("evidence_temporary_exists")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def run(output_path: Path) -> dict[str, Any]:
    if not isinstance(output_path, Path) or output_path.suffix.lower() != ".json":
        raise ValueError("evidence_path")
    if output_path.exists():
        raise ValueError("evidence_exists")

    harness = queue_fixtures.VerificationQueueTests(methodName="runTest")
    harness.setUp()
    try:
        base_acceptance = queue_fixtures._accepted()
        base_bytes = queue_fixtures._RAW
        job_ids = tuple(f"synthetic-{index:03d}" for index in range(1, _COUNT + 1))
        artifacts: list[tuple[str, Path, ArtifactMetadata, MinimalProofAcceptanceV1]] = []
        for index, job_id in enumerate(job_ids, start=1):
            raw = base_bytes + b"BL-SYNTHETIC-PIPELINE-" + index.to_bytes(4, "big")
            ref = f"synthetic-ref-{index:03d}"
            source = harness.source_root / ref
            source.write_bytes(raw)
            source.chmod(0o400)
            metadata = ArtifactMetadata(ref, len(raw), hashlib.sha256(raw).digest(), hashlib.sha3_512(raw).digest())
            acceptance = replace(base_acceptance, artifact_sha256=metadata.artifact_sha256, artifact_digest=metadata.artifact_sha3_512, artifact_bytes=metadata.artifact_bytes)
            parse_acceptance_bytes(acceptance.canonical_bytes())
            artifacts.append((job_id, source, metadata, acceptance))

        store = harness._store(capacity=256, name="software-pipeline.sqlite")
        factory = _SyntheticFactory([item[3] for item in artifacts])
        operation_latencies: list[float] = []
        admission_started = time.perf_counter()
        verification_started = None
        verification_finished = None
        for job_id, _source, metadata, _acceptance in artifacts:
            store._admit(job_id=job_id, metadata=metadata)
            if verification_started is None:
                verification_started = time.perf_counter()
            operation_started = time.perf_counter()
            store._process_one(verifier=factory(), custody=harness._custody())
            operation_latencies.append((time.perf_counter() - operation_started) * 1000.0)
        verification_finished = time.perf_counter()
        promoted = store._promote_candidates()
        promotion_finished = time.perf_counter()
        promoted_count = sum(int(item["accepted_count"]) for item in promoted)
        if promoted_count != _COUNT:
            raise RuntimeError("synthetic_promotion_count")

        read_started = time.perf_counter()
        verified = read_verified_jobs(store.path, job_ids)
        read_finished = time.perf_counter()
        if len(verified) != _COUNT or tuple(job.job_id for job in verified) != job_ids:
            raise RuntimeError("synthetic_verified_order")
        independent_summary = verify_database(store.path)
        campaign_finished = time.perf_counter()
        total_ms = (campaign_finished - admission_started) * 1000.0
        evidence = {
            "schema": _SCHEMA,
            "campaign_boundary": "INDEPENDENTLY_VERIFIED_QUEUE_READ",
            "synthetic_only": True,
            "synthetic_job_count": _COUNT,
            "ordered_distinct_jobs": True,
            "admitted_count": _COUNT,
            "verified_count": _COUNT,
            "candidate_promoted_count": promoted_count,
            "independent_read_count": len(verified),
            "independent_reconciliation": True,
            "independent_status_counts": independent_summary["status_counts"],
            "independent_transition_count": independent_summary["transition_count"],
            "composition_batch_count": 0,
            "composition_applied_count": 0,
            "local_ack_count": 0,
            "official_receiver_measured": False,
            "native_proof_verification_measured": False,
            "cryptographic_proving_measured": False,
            "full_product_throughput": False,
            "excluded_stages": ["composition_state_transaction", "directive_outbox", "synthetic_receiver_ack"],
            "exclusion_reason": "current composition state profile is bound to one exact statement shape; widening that state owner is outside this batch seam",
            "total_wall_ms": round(total_ms, 3),
            "stage_wall_ms": {
                "admission_and_synthetic_verification": round((verification_finished - admission_started) * 1000.0, 3),
                "promotion": round((promotion_finished - verification_finished) * 1000.0, 3),
                "independent_read": round((read_finished - read_started) * 1000.0, 3),
                "independent_reconciliation": round((campaign_finished - read_finished) * 1000.0, 3),
            },
            "per_operation_latency_ms": {
                "count": len(operation_latencies),
                "p50": _percentile(operation_latencies, 0.50),
                "p95": _percentile(operation_latencies, 0.95),
                "p99": _percentile(operation_latencies, 0.99),
                "max": round(max(operation_latencies), 3),
            },
            "peak_queue_depth": _COUNT,
            "batch_sizes": [_COUNT],
            "retry_count": 0,
            "conflict_count": 0,
            "indeterminate_count": 0,
            "unconfirmed_count": 0,
            "state_counts": {"APPLIED": 0, "HELD": 0},
            "ack_counts": {"ACKNOWLEDGED": 0, "DELIVERY_UNCONFIRMED": 0},
            "resource_telemetry": {
                "native_process_count": 0,
                "complete_process_tree_peak_bytes": None,
                "admission_guard_bytes": _ADMISSION_BYTES,
                "cap_bytes": _CAP_BYTES,
                "cap_enforced": True,
                "resource_qualification": False,
                "pagefile_growth_evidence": "unavailable",
                "reason": "synthetic boundary created no native verifier process",
            },
            "payment_calls": 0,
            "payment_state_mutations": 0,
            "economic_mutation": False,
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
            "cleanup_complete": True,
        }
        _write_json_atomically(output_path, evidence)
        return evidence
    finally:
        harness.tearDown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-path", type=Path, required=True)
    args = parser.parse_args()
    evidence = run(args.evidence_path)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
