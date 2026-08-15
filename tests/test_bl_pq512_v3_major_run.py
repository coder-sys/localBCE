from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation import v3_major_run


def test_governed_profiles_and_resource_limits_are_exact() -> None:
    assert v3_major_run.PROFILE_SPECS["K128_CALIBRATION"].code == 1
    assert v3_major_run.PROFILE_SPECS["K512_CALIBRATION"].code == 3
    assert v3_major_run.PROFILE_SPECS["K128_CALIBRATION"].shard_count == 1
    assert v3_major_run.PROFILE_SPECS["K512_CALIBRATION"].shard_count == 4
    assert v3_major_run.H4_AGGREGATE_BYTES == {
        "K128_CALIBRATION": 221_413_264,
        "K512_CALIBRATION": 825_393_040,
    }
    assert v3_major_run.PEAK_RESIDENT_BYTES == 5_000_000_000
    assert v3_major_run.SCRATCH_BYTES_EXCLUSIVE == 5_000_000_000
    assert v3_major_run.WORKER_RESPONSE_TIMEOUT_SECONDS == 21_600
    assert v3_major_run.TYPED_STATE_PROOF_PACKAGE_BYTES == 83_887_236


def test_current_inventory_does_not_invent_h4_or_parent_producers(tmp_path: Path) -> None:
    inventory = v3_major_run.current_entrypoints(tmp_path)
    assert inventory.h4_producer is None
    assert inventory.h4_assembler is None
    assert inventory.parent_producer is None
    assert inventory.semantic_producer.endswith(":prove_selected_air_v3_streaming")
    assert inventory.typed_state_producer.endswith(":prove_typed_state_air")
    assert v3_major_run.missing_seams(inventory) == [
        "orchestrator",
        "h4_producer",
        "parent_producer",
        "aggregate_accepting_verifier",
    ]


def test_preflight_reports_missing_current_v3_seams_without_launching(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        v3_major_run,
        "run_resource_preflight",
        lambda inputs, inventory: {
            "qualifies": "false",
            "scratch_gate_pass": "true",
            "activation_allowed": "false",
        },
    )
    inputs = v3_major_run.RunInputs(
        profile=v3_major_run.PROFILE_SPECS["K128_CALIBRATION"],
        evidence_dir=tmp_path / "evidence",
        scratch_dir=tmp_path / "scratch",
        shard_concurrency=1,
        semantic_program=None,
        raw_witness_bytes=None,
    )
    report = v3_major_run.preflight(inputs, root=tmp_path)
    assert report["status"] == "BLOCKED_MISSING_CURRENT_V3_SEAM"
    assert report["missing_seams"] == [
        "orchestrator",
        "h4_producer",
        "parent_producer",
        "aggregate_accepting_verifier",
    ]
    assert report["proof_suite_id"] is None
    assert report["production_usable"] is False
    assert report["activation_allowed"] is False


def test_k128_cannot_use_k512_shard_concurrency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    called = False

    def fail_if_called(inputs, inventory):
        nonlocal called
        called = True
        raise AssertionError("resource preflight must not run after shape rejection")

    monkeypatch.setattr(v3_major_run, "run_resource_preflight", fail_if_called)
    inputs = v3_major_run.RunInputs(
        profile=v3_major_run.PROFILE_SPECS["K128_CALIBRATION"],
        evidence_dir=tmp_path / "evidence",
        scratch_dir=tmp_path / "scratch",
        shard_concurrency=2,
        semantic_program=None,
        raw_witness_bytes=None,
    )
    with pytest.raises(v3_major_run.MajorRunError, match="shard_concurrency_invalid"):
        v3_major_run.preflight(inputs, root=tmp_path)
    assert called is False


def test_verifier_capability_probe_keeps_parser_and_acceptance_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = v3_major_run.EntrypointInventory(
        orchestrator=None,
        semantic_producer="semantic",
        h4_producer=None,
        h4_assembler=None,
        typed_state_producer="typed",
        parent_producer=None,
        verifier="v3-composite-verify",
        aggregate_accepting_verifier=None,
        resource_preflight="resource-preflight",
    )
    monkeypatch.setattr(
        v3_major_run.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            b"status=V3_GRAMMAR_PARSED_AGGREGATE_UNQUALIFIED\n"
            b"aggregate_verification=unavailable\n"
            b"production_usable=false\n"
            b"activation_allowed=false\n",
            b"",
        ),
    )
    assert v3_major_run.probe_verifier_capability(inventory) == {
        "status": "V3_GRAMMAR_PARSED_AGGREGATE_UNQUALIFIED",
        "aggregate_verification": "unavailable",
        "production_usable": "false",
        "activation_allowed": "false",
    }


def test_plan_only_is_nonactivating_and_does_not_need_inputs(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    exit_code = v3_major_run.main(
        [
            "--profile",
            "K128_CALIBRATION",
            "--evidence-dir",
            str(tmp_path / "evidence"),
            "--scratch-dir",
            str(tmp_path / "scratch"),
            "--plan-only",
            "--root",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PLAN_ONLY_NO_PROOF_STARTED"
    assert report["proof_run_started"] is False
    assert report["missing_seams"] == [
        "orchestrator",
        "h4_producer",
        "parent_producer",
        "aggregate_accepting_verifier",
    ]
    assert report["proof_suite_id"] is None
    assert report["production_usable"] is False
    assert report["activation_allowed"] is False
    evidence = {item["relative_path"]: item for item in report["evidence_plan"]}
    assert evidence["trusted-layout.bin"]["expected_magic"] == "BLV3LY01"
    assert evidence["h4-aggregate.bin"]["expected_magic"] == "BLH4AG02"
    assert evidence["h4-aggregate.bin"]["exact_bytes"] == 221_413_264
    assert evidence["typed-state-component.bin"]["exact_bytes"] == 83_887_236
    assert evidence["composite-envelope.bin"]["expected_magic"] == "BLPQENV3"
    assert "baseline_complete_v3_acceptance" in report["mutation_checks"]
    assert "proofSuiteId" in report["proof_identity_fields"]


def test_evidence_plan_resolves_profile_specific_h4_size() -> None:
    plan = v3_major_run.evidence_plan(
        v3_major_run.PROFILE_SPECS["K512_CALIBRATION"]
    )
    evidence = {item["relative_path"]: item for item in plan}
    assert evidence["h4-aggregate.bin"]["exact_bytes"] == 825_393_040
    assert evidence["h4-aggregate.bin"]["expected_magic"] == "BLH4AG02"
