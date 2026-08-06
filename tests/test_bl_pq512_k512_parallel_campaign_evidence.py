from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.k512_parallel_campaign_evidence import (
    K512ParallelCampaignEvidenceError,
    validate_k512_parallel_campaign,
)


def _digest(index: int) -> str:
    return hashlib.sha3_512(f"parallel-test-{index}".encode()).hexdigest()


def _stdout(index: int, wall: float) -> str:
    values = {
        **{f"shard_{shard}_verified": "true" for shard in range(4)},
        **{f"shard_{shard}_proof_seconds": f"{40.0 + shard:.6f}" for shard in range(4)},
        **{f"shard_{shard}_coordinator_wall_seconds": f"{45.0 + shard:.6f}" for shard in range(4)},
        "status": "verified",
        "evidence_class": "k512_atomic_semantic_prototype",
        "atomic_parent_binding_sha3_512": _digest(index + 100),
        "atomic_statement_sha3_512": _digest(index + 200),
        "state_plane_binding_verified": "true",
        "state_plane_binding_digest_sha3_512": _digest(index + 300),
        "state_component_proof_suite_id": _digest(index + 400),
        "state_commitment_backend": "TRANSPARENT_SHAKE256_1024",
        "state_hash_bus_calls_verified": "true",
        "execution_manifest_sha3_512": _digest(900),
        "semantic_hash_bus_file_sha3_512": _digest(1000),
        "ordered_shards": "0,1,2,3",
        "complete_shard_proofs": "4",
        "shard_concurrency": "2",
        "sequential_single_gpu_execution": "false",
        "parallel_gpu_images": "2",
        "theorem_free_challenge_sharing": "false",
        "atomic_acceptance_boundary": "true",
        "all_shards_independently_verified": "true",
        "atomic_receipt_sha3_512": _digest(index + 500),
        "complete_process_wall_seconds": f"{wall:.6f}",
        "peak_host_mb": "600.000000",
        "peak_device_mb": "2000.000000",
        "scratch_mb": "0.000000",
        "latency_limit_seconds": "180",
        "complete_proof_latency_gate": "true",
        "proof_suite_id": "null",
        "complete_proof_qualification": "false",
    }
    return "".join(f"{key}={values[key]}\n" for key in values)


def _monitor(stdout: bytes, *, page_growth: int = 0) -> str:
    return (
        "external_exit_code=0\n"
        "external_wall_seconds=110.000000\n"
        "external_process_tree_peak_bytes=1000000000\n"
        "external_process_tree_peak_mb=1000.000000\n"
        "external_gpu_peak_mib=5000\n"
        "pagefile_before_mb=100\n"
        f"pagefile_after_mb={100 + page_growth}\n"
        f"pagefile_growth_mb={page_growth}\n"
        "post_launch_driver_event_count=0\n"
        f"stdout_bytes={len(stdout)}\n"
        f"stdout_sha256={hashlib.sha256(stdout).hexdigest()}\n"
        "stderr_bytes=0\n"
        f"stderr_sha256={hashlib.sha256(b'').hexdigest()}\n"
        "---stdout---\n"
        f"{stdout.decode()}"
        "---stderr---\n"
    )


def _build_campaign(root: Path) -> tuple[Path, Path]:
    results: list[dict[str, object]] = []
    measured_walls: list[float] = []
    for index in range(11):
        phase = "warmup" if index == 0 else "measured"
        wall = 100.0 if index == 0 else 101.0 + index / 10.0
        if phase == "measured":
            measured_walls.append(wall)
        state_dir = root / f"state-{index:02d}"
        state_dir.mkdir()
        state_path = state_dir / "state-binding.bin"
        state_path.write_bytes(f"state-{index}".encode())
        stdout_path = root / f"k512-{index:02d}-{phase}.stdout.txt"
        stderr_path = root / f"k512-{index:02d}-{phase}.stderr.txt"
        monitor_path = root / f"k512-{index:02d}-{phase}.monitor-host-output.txt"
        stdout = _stdout(index, wall).encode()
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(b"")
        monitor_path.write_text(_monitor(stdout), encoding="utf-8")
        results.append(
            {
                "ordinal": index,
                "phase": phase,
                "state": str(state_path),
                "state_verify_exit": 0,
                "monitor_exit": 0,
                "status": "verified",
                "complete_shard_proofs": "4",
                "wall": f"{wall:.6f}",
                "host": "600.000000",
                "device": "2000.000000",
                "scratch": "0.000000",
                "suite": "null",
                "qualification": "false",
                "external_tree": "1000.000000",
                "external_gpu": "5000",
                "page_growth": "0",
                "driver_events": "0",
                "stderr_bytes": "0",
                "stdout_path": str(stdout_path),
                "monitor_path": str(monitor_path),
            }
        )
    summary = {
        "campaign_id": "parallel-test-campaign",
        "run_count": 11,
        "warmup_count": 1,
        "measured_count": 10,
        "measured_wall_seconds": measured_walls,
        "p95_measured_wall_seconds": max(measured_walls),
        "mean_measured_wall_seconds": sum(measured_walls) / len(measured_walls),
        "max_reported_host_mb": 600,
        "max_reported_device_mb": 2000,
        "max_external_process_tree_mb": 1000,
        "max_external_gpu_mib": 5000,
        "max_pagefile_growth_mb": 0,
        "max_driver_events": 0,
        "max_stderr_bytes": 0,
    }
    results_path = root / "campaign-results.json"
    summary_path = root / "campaign-summary.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    return results_path, summary_path


def test_exact_two_lane_campaign_is_qualified_without_activation(tmp_path: Path) -> None:
    results_path, summary_path = _build_campaign(tmp_path)

    evidence = validate_k512_parallel_campaign(results_path, summary_path)

    assert evidence.campaign_id == "parallel-test-campaign"
    assert evidence.p95_seconds == 102.0
    assert evidence.proof_suite_id is None
    assert evidence.activation_allowed is False
    assert evidence.as_public_dict()["status"] == "QUALIFIED_K512_TWO_LANE_NONACTIVATING"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("pagefile", "k512_parallel_pagefile_growth"),
        ("concurrency", "k512_parallel_concurrency_invalid"),
        ("duplicate_state", "k512_parallel_reused_or_duplicate_identity"),
        ("summary", "k512_parallel_summary_statistics_disagreement"),
    ],
)
def test_parallel_evidence_rejects_trust_boundary_mutations(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    results_path, summary_path = _build_campaign(tmp_path)
    results = json.loads(results_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if mutation == "pagefile":
        monitor_path = Path(results[1]["monitor_path"])
        monitor_path.write_text(monitor_path.read_text(encoding="utf-8").replace("pagefile_growth_mb=0", "pagefile_growth_mb=1"), encoding="utf-8")
    elif mutation == "concurrency":
        stdout_path = Path(results[1]["stdout_path"])
        changed = stdout_path.read_text(encoding="utf-8").replace("shard_concurrency=2", "shard_concurrency=1")
        stdout_path.write_text(changed, encoding="utf-8")
        Path(results[1]["monitor_path"]).write_text(_monitor(changed.encode()), encoding="utf-8")
    elif mutation == "duplicate_state":
        results[1]["state"] = results[0]["state"]
        results_path.write_text(json.dumps(results), encoding="utf-8")
    else:
        summary["p95_measured_wall_seconds"] = 1
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(K512ParallelCampaignEvidenceError, match=expected):
        validate_k512_parallel_campaign(results_path, summary_path)
