"""Fail-closed execution contract for the next complete v3 proof runs.

This module is intentionally a run gate and evidence planner, not a proof verifier.  It makes the
missing executable seams explicit so a legacy H4 stdout assertion cannot be mistaken for a v3
acceptance.  Once producer and verifier artifacts exist, the same contract is the only place that
may launch a complete K128/K512 run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final


PEAK_RESIDENT_BYTES: Final[int] = 5_000_000_000
SCRATCH_BYTES_EXCLUSIVE: Final[int] = 5_000_000_000
WORKER_RESPONSE_TIMEOUT_SECONDS: Final[int] = 6 * 60 * 60
V3_ABSOLUTE_MAX_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
H4_SHARD_BYTES: Final[int] = 192 * 1024 * 1024
H4_AGGREGATE_BYTES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 221_413_264,
    "K512_CALIBRATION": 825_393_040,
}
TYPED_STATE_PROOF_PACKAGE_BYTES: Final[int] = 83_887_236
GPU_RESOURCE_GATE_NOTE: Final[str] = (
    "No independent numeric GPU hard cap is currently governed; retain tracked-device and "
    "total-residency telemetry and reject missing telemetry."
)
SYNTHETIC_COMMAND_TIMEOUT_SECONDS: Final[int] = 60
SYNTHETIC_INPUT_HEADER_BYTES: Final[int] = 20
SYNTHETIC_INPUT_RECORD_BYTES: Final[int] = 68
SYNTHETIC_BUNDLE_BYTES: Final[int] = 860
SYNTHETIC_STATUS: Final[str] = "ACCEPTED_SYNTHETIC_NONACTIVATING"
REAL_STATUS: Final[str] = "ACCEPTED_REAL_NONACTIVATING"
REAL_NATIVE_STATUS: Final[str] = "V3_NATIVE_AGGREGATE_ACCEPTED_NONACTIVATING"


@dataclass(frozen=True, slots=True)
class EvidenceFileSpec:
    """One raw file that must survive a complete proof attempt."""

    relative_path: str
    purpose: str
    expected_magic: str | None = None
    exact_bytes: int | None = None


EVIDENCE_FILE_SPECS: Final[tuple[EvidenceFileSpec, ...]] = (
    EvidenceFileSpec(
        "run-manifest.json",
        "profile, inputs, identities, commands, timestamps, and lifecycle flags",
    ),
    EvidenceFileSpec(
        "trusted-layout.bin",
        "governed v3 component lengths, program commitments, schedule commitments, and layout commitment",
        "BLV3LY01",
        820,
    ),
    EvidenceFileSpec(
        "semantic-component.bin",
        "semantic producer artifact; exact length comes from trusted-layout.bin",
    ),
    EvidenceFileSpec(
        "h4-aggregate.bin",
        "complete ordered H4-v2 aggregate; profile-specific exact aggregate length",
        "BLH4AG02",
    ),
    EvidenceFileSpec(
        "typed-state-component.bin",
        "typed-state v3 package, including its authenticated transcript and sidecar",
        "BLTSPK01",
        TYPED_STATE_PROOF_PACKAGE_BYTES,
    ),
    EvidenceFileSpec(
        "composite-transcript.bin",
        "parent 900/901/902 transcript and post-z completion evidence",
        "BLV3TR01",
    ),
    EvidenceFileSpec(
        "composite-envelope.bin",
        "outer v3 envelope assembled in semantic/H4/typed/parent order",
        "BLPQENV3",
    ),
    EvidenceFileSpec(
        "resource-preflight.stdout",
        "raw Rust resource model and scratch-gate output",
    ),
    EvidenceFileSpec(
        "resource-preflight.stderr",
        "raw resource-preflight diagnostics, including empty stderr",
    ),
    EvidenceFileSpec(
        "native-run.stdout",
        "raw combined producer/coordinator/accepting-verifier output",
    ),
    EvidenceFileSpec(
        "native-run.stderr",
        "raw combined producer/coordinator/accepting-verifier diagnostics",
    ),
    EvidenceFileSpec(
        "witness-artifact-hashes.sha3-512",
        "immutable identities for every raw witness input consumed by the native lane",
    ),
    EvidenceFileSpec(
        "mutation-results.jsonl",
        "baseline acceptance and every required forged/mutated rejection",
    ),
    EvidenceFileSpec(
        "host-resource-telemetry.jsonl",
        "RSS/process-tree peak, scratch, pagefile/swap, I/O, and timeout observations",
    ),
    EvidenceFileSpec(
        "device-resource-telemetry.jsonl",
        "tracked device state and sampled total residency; missing telemetry rejects credit",
    ),
    EvidenceFileSpec(
        "cleanup.json",
        "owned scratch paths, zeroization/cleanup result, and retained-path inventory",
    ),
    EvidenceFileSpec(
        "artifact-hashes.sha3-512",
        "SHA3-512 identities for every artifact and raw log",
    ),
)

PROOF_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "profile",
    "proofSuiteId",
    "candidate_descriptor_identity",
    "layout_commitment",
    "component_program_commitments",
    "component_schedule_commitments",
    "semantic_statement_and_source_state_bindings",
    "h4_native_root_inventory_and_bridge_bindings",
    "typed_state_before_after_and_transition_bindings",
    "parent_transcript_and_completion_bindings",
    "verifier_artifact_identity",
)

MUTATION_CHECKS: Final[tuple[str, ...]] = (
    "baseline_complete_v3_acceptance",
    "mutate_each_component_byte_and_require_native_rejection",
    "mutate_outer_header_descriptor_sidecar_public_field_length_and_padding",
    "mutate_transcript_order_seed_challenge_and_root_bindings",
    "replay_same_attempt_and_require_rejection",
    "stale_before_root_or_duplicate_nullifier_and_require_atomic_rejection",
)

# The file-backed native lane deliberately runs the two cheap mutations it can
# prove without fabricating application/database inputs.  Keep this separate
# from the broader qualification campaign so a real run cannot overclaim
# coverage it did not execute.
REAL_MUTATION_CHECKS: Final[tuple[str, ...]] = (
    "baseline_complete_v3_acceptance",
    "replay_same_attempt_and_require_rejection",
    "mutate_trusted_layout_and_require_native_rejection",
)


class MajorRunError(RuntimeError):
    """A preflight or execution contract failure with a stable report code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}{':' + detail if detail else ''}")


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    label: str
    code: int
    shard_count: int
    complete_p95_limit_seconds: float
    max_shard_concurrency: int


PROFILE_SPECS: Final[dict[str, ProfileSpec]] = {
    "K128_CALIBRATION": ProfileSpec("K128_CALIBRATION", 1, 1, 35.0, 1),
    "K512_CALIBRATION": ProfileSpec("K512_CALIBRATION", 3, 4, 180.0, 2),
}


@dataclass(frozen=True, slots=True)
class EntrypointInventory:
    orchestrator: str | None
    semantic_producer: str
    h4_producer: str | None
    h4_assembler: str | None
    typed_state_producer: str
    parent_producer: str | None
    verifier: str | None
    aggregate_accepting_verifier: str | None
    resource_preflight: str | None
    parent_chain_producer: str | None = None
    strict_h4_transcript_producer: str | None = None
    h4_pre_alpha_verifier: str | None = None
    h4_post_z_response_evidence_producer: str | None = None
    h4_pre_alpha_producer: str | None = None
    parent_transcript_producer: str | None = None
    real_authority_runner: str | None = None
    h4_replay_route: str | None = None
    parent_replay_route: str | None = None
    witness_acquisition_producer: str | None = None


@dataclass(frozen=True, slots=True)
class RunInputs:
    profile: ProfileSpec
    evidence_dir: Path
    scratch_dir: Path
    shard_concurrency: int
    semantic_program: Path | None
    raw_witness_bytes: int | None
    witness_dir: Path | None = None
    custody_dir: Path | None = None


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _release_executable(release: Path, name: str) -> Path | None:
    for candidate in (release / f"{name}.exe", release / name):
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _role_command(executable: Path, role: str) -> str:
    return (
        f'"{executable}" --role {role} --witness-dir <WITNESS_DIR> '
        "--evidence-dir <EVIDENCE_DIR> --scratch-dir <SCRATCH_DIR> "
        "--custody-dir <CUSTODY_DIR> --profile <PROFILE>"
    )


def current_entrypoints(root: Path | None = None) -> EntrypointInventory:
    """Return source-owned seams without confusing replay with production.

    The native runner accepts a complete, already-produced witness.  Its H4 and
    parent role labels are useful replay routes, but they do not acquire or
    generate missing witness bytes.  Keep those routes separate from the
    authority-bearing producer fields so a real run cannot start under a false
    producer claim.
    """

    root = repository_root() if root is None else root.resolve()
    rust_release = root / "experiments" / "bl_pq512_crypto_core" / "target" / "release"
    verifier = next(
        (
            path
            for path in (
                rust_release / "v3_composite_verify.exe",
                rust_release / "v3_composite_verify",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    resource_preflight = next(
        (
            path
            for path in (
                rust_release / "resource_preflight.exe",
                rust_release / "resource_preflight",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    h4_assembler = next(
        (
            path
            for path in (
                rust_release / "h4_aggregate_assemble.exe",
                rust_release / "h4_aggregate_assemble",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    parent_producer = next(
        (
            path
            for path in (
                rust_release / "composite_parent_produce.exe",
                rust_release / "composite_parent_produce",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    strict_h4_transcript_producer = next(
        (
            path
            for path in (
                rust_release / "strict_h4_transcript_produce.exe",
                rust_release / "strict_h4_transcript_produce",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    h4_pre_alpha_verifier = next(
        (
            path
            for path in (
                rust_release / "h4_pre_alpha_verify.exe",
                rust_release / "h4_pre_alpha_verify",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    h4_post_z_response_evidence_producer = next(
        (
            path
            for path in (
                rust_release / "h4_post_z_evidence_produce.exe",
                rust_release / "h4_post_z_evidence_produce",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    h4_pre_alpha_producer = next(
        (
            path
            for path in (
                rust_release / "h4_v2_produce.exe",
                rust_release / "h4_v2_produce",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    parent_transcript_producer = next(
        (
            path
            for path in (
                rust_release / "composite_parent_transcript_produce.exe",
                rust_release / "composite_parent_transcript_produce",
            )
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )
    parent_chain_executable = parent_producer
    real_authority_runner = _release_executable(rust_release, "v3_real_authority_run")
    if real_authority_runner is not None:
        orchestrator = _role_command(real_authority_runner, "orchestrator")
        h4_replay_route = _role_command(real_authority_runner, "h4-replay")
        parent_replay_route = _role_command(real_authority_runner, "parent-replay")
        # These are deliberately left absent.  The replay runner consumes a
        # complete witness; it is not a witness-to-proof producer.
        h4_producer = None
        parent_producer = None
        aggregate_accepting_verifier = _role_command(
            real_authority_runner,
            "outer-verifier",
        )
        verifier = str(real_authority_runner)
        witness_acquisition_producer = None
    else:
        orchestrator = None
        h4_producer = None
        parent_producer = None
        aggregate_accepting_verifier = None
        h4_replay_route = None
        parent_replay_route = None
        witness_acquisition_producer = None
    return EntrypointInventory(
        orchestrator=orchestrator,
        semantic_producer=(
            "experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator:"
            "prove_selected_air_v3_streaming"
        ),
        h4_producer=h4_producer,
        # This command only assembles independently produced artifacts.  It cannot replace the
        # missing H4 proof producer or native acceptance verifier.
        h4_assembler=None if h4_assembler is None else str(h4_assembler),
        typed_state_producer=(
            "experiments.bl_pq512_crypto_foundation.typed_state_air_proof:"
            "prove_typed_state_air"
        ),
        parent_producer=parent_producer,
        verifier=None if verifier is None else str(verifier),
        aggregate_accepting_verifier=aggregate_accepting_verifier,
        resource_preflight=None if resource_preflight is None else str(resource_preflight),
        parent_chain_producer=(
            None if parent_chain_executable is None else str(parent_chain_executable)
        ),
        strict_h4_transcript_producer=(
            None
            if strict_h4_transcript_producer is None
            else str(strict_h4_transcript_producer)
        ),
        h4_pre_alpha_verifier=(
            None if h4_pre_alpha_verifier is None else str(h4_pre_alpha_verifier)
        ),
        h4_post_z_response_evidence_producer=(
            None
            if h4_post_z_response_evidence_producer is None
            else str(h4_post_z_response_evidence_producer)
        ),
        h4_pre_alpha_producer=(
            None if h4_pre_alpha_producer is None else str(h4_pre_alpha_producer)
        ),
        parent_transcript_producer=(
            None
            if parent_transcript_producer is None
            else str(parent_transcript_producer)
        ),
        real_authority_runner=(
            None if real_authority_runner is None else str(real_authority_runner)
        ),
        h4_replay_route=h4_replay_route,
        parent_replay_route=parent_replay_route,
        witness_acquisition_producer=witness_acquisition_producer,
    )


def evidence_plan(profile: ProfileSpec) -> list[dict[str, object]]:
    """Return the exact retention contract without claiming any artifact exists."""

    result: list[dict[str, object]] = []
    for spec in EVIDENCE_FILE_SPECS:
        exact_bytes = spec.exact_bytes
        if spec.relative_path == "h4-aggregate.bin":
            exact_bytes = H4_AGGREGATE_BYTES[profile.label]
        result.append(
            {
                "relative_path": spec.relative_path,
                "purpose": spec.purpose,
                "expected_magic": spec.expected_magic,
                "exact_bytes": exact_bytes,
            }
        )
    return result


def _absolute_path(value: Path, name: str) -> Path:
    if not value.is_absolute():
        raise MajorRunError(f"{name}_must_be_absolute")
    return value.resolve()


def _existing_regular_file(value: Path, name: str) -> Path:
    value = _absolute_path(value, name)
    if value.is_symlink() or not value.is_file():
        raise MajorRunError(f"{name}_missing_or_not_regular", str(value))
    return value


def _bounded_directory(value: Path, name: str) -> Path:
    value = _absolute_path(value, name)
    if value.exists() and (value.is_symlink() or not value.is_dir()):
        raise MajorRunError(f"{name}_not_directory", str(value))
    return value


def _parse_key_value_lines(stdout: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.decode("ascii", errors="strict")
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key or key in values:
            raise MajorRunError("resource_preflight_output_invalid")
        values[key] = value
    return values


def run_resource_preflight(
    inputs: RunInputs,
    inventory: EntrypointInventory,
    *,
    raw_output_dir: Path | None = None,
) -> dict[str, str]:
    if inventory.resource_preflight is None:
        raise MajorRunError("resource_preflight_entrypoint_missing")
    if inputs.semantic_program is None or inputs.raw_witness_bytes is None:
        raise MajorRunError("resource_preflight_inputs_missing")
    program = _existing_regular_file(inputs.semantic_program, "semantic_program")
    if inputs.raw_witness_bytes <= 0:
        raise MajorRunError("raw_witness_bytes_invalid")
    command = [
        inventory.resource_preflight,
        str(program),
        str(inputs.raw_witness_bytes),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        raise MajorRunError("resource_preflight_timeout") from error
    if raw_output_dir is not None:
        _write_new_bytes(raw_output_dir / "resource-preflight.stdout", completed.stdout)
        _write_new_bytes(raw_output_dir / "resource-preflight.stderr", completed.stderr)
    if completed.returncode != 0:
        detail = completed.stderr.decode("ascii", errors="replace")[:512]
        raise MajorRunError("resource_preflight_failed", detail)
    values = _parse_key_value_lines(completed.stdout)
    if values.get("qualifies") != "false":
        raise MajorRunError("resource_preflight_qualification_state")
    if values.get("scratch_gate_pass") != "true":
        raise MajorRunError("scratch_gate_rejected")
    if values.get("activation_allowed") != "false":
        raise MajorRunError("resource_preflight_activation_state")
    return values


def probe_verifier_capability(inventory: EntrypointInventory) -> dict[str, str]:
    """Read the verifier's explicit capability mode without opening a proof."""

    if inventory.verifier is None:
        return {"status": "missing"}
    try:
        completed = subprocess.run(
            [inventory.verifier, "--capabilities"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as error:
        raise MajorRunError("verifier_capability_timeout") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("ascii", errors="replace")[:512]
        raise MajorRunError("verifier_capability_probe_failed", detail)
    values = _parse_key_value_lines(completed.stdout)
    if values.get("production_usable") != "false" or values.get("activation_allowed") != "false":
        raise MajorRunError("verifier_capability_activation_state")
    expected_aggregate_mode = (
        "available"
        if inventory.aggregate_accepting_verifier is not None
        else "unavailable"
    )
    if values.get("aggregate_verification") != expected_aggregate_mode:
        raise MajorRunError("verifier_capability_contract_invalid")
    return values


def missing_seams(inventory: EntrypointInventory) -> list[str]:
    """Return only authority-bearing seams; an assembler never counts as a producer."""

    return [
        name
        for name, value in (
            ("orchestrator", inventory.orchestrator),
            ("h4_producer", inventory.h4_producer),
            ("parent_producer", inventory.parent_producer),
            ("aggregate_accepting_verifier", inventory.aggregate_accepting_verifier),
        )
        if value is None
    ]


def preflight(inputs: RunInputs, *, root: Path | None = None) -> dict[str, object]:
    spec = inputs.profile
    if inputs.shard_concurrency < 1 or inputs.shard_concurrency > spec.max_shard_concurrency:
        raise MajorRunError("shard_concurrency_invalid")
    evidence_dir = _bounded_directory(inputs.evidence_dir, "evidence_dir")
    scratch_dir = _bounded_directory(inputs.scratch_dir, "scratch_dir")
    if evidence_dir == scratch_dir:
        raise MajorRunError("evidence_and_scratch_must_differ")
    inventory = current_entrypoints(root)
    resource = run_resource_preflight(inputs, inventory)
    verifier_capability = probe_verifier_capability(inventory)
    missing = missing_seams(inventory)
    status = "READY_TO_LAUNCH" if not missing else "BLOCKED_MISSING_CURRENT_V3_SEAM"
    return {
        "status": status,
        "profile": spec.label,
        "profile_code": spec.code,
        "shard_count": spec.shard_count,
        "shard_concurrency": inputs.shard_concurrency,
        "complete_p95_limit_seconds": spec.complete_p95_limit_seconds,
        "worker_response_timeout_seconds": WORKER_RESPONSE_TIMEOUT_SECONDS,
        "peak_resident_bytes_limit": PEAK_RESIDENT_BYTES,
        "scratch_bytes_limit_exclusive": SCRATCH_BYTES_EXCLUSIVE,
        "v3_envelope_absolute_max_bytes": V3_ABSOLUTE_MAX_BYTES,
        "h4_shard_bytes": H4_SHARD_BYTES,
        "h4_aggregate_bytes": H4_AGGREGATE_BYTES[spec.label],
        "gpu_resource_gate_note": GPU_RESOURCE_GATE_NOTE,
        "proof_identity_fields": PROOF_IDENTITY_FIELDS,
        "mutation_checks": MUTATION_CHECKS,
        "evidence_plan": evidence_plan(spec),
        "semantic_producer": inventory.semantic_producer,
        "orchestrator": inventory.orchestrator,
        "h4_producer": inventory.h4_producer,
        "h4_assembler": inventory.h4_assembler,
        "typed_state_producer": inventory.typed_state_producer,
        "parent_producer": inventory.parent_producer,
        "aggregate_verifier": inventory.verifier,
        "aggregate_accepting_verifier": inventory.aggregate_accepting_verifier,
        "resource_preflight": inventory.resource_preflight,
        "parent_chain_producer": inventory.parent_chain_producer,
        "strict_h4_transcript_producer": inventory.strict_h4_transcript_producer,
        "h4_pre_alpha_verifier": inventory.h4_pre_alpha_verifier,
        "h4_post_z_response_evidence_producer": inventory.h4_post_z_response_evidence_producer,
        "h4_pre_alpha_producer": inventory.h4_pre_alpha_producer,
        "parent_transcript_producer": inventory.parent_transcript_producer,
        "h4_replay_route": inventory.h4_replay_route,
        "parent_replay_route": inventory.parent_replay_route,
        "witness_acquisition_producer": inventory.witness_acquisition_producer,
        "verifier_capability": verifier_capability,
        "missing_seams": missing,
        "resource_preflight_output": resource,
        "proof_suite_id": None,
        "production_usable": False,
        "activation_allowed": False,
        "real_phi_or_payments": False,
    }


def _inventory_dict(inventory: EntrypointInventory) -> dict[str, str | None]:
    return {
        "orchestrator": inventory.orchestrator,
        "semantic_producer": inventory.semantic_producer,
        "h4_producer": inventory.h4_producer,
        "h4_assembler": inventory.h4_assembler,
        "typed_state_producer": inventory.typed_state_producer,
        "parent_producer": inventory.parent_producer,
        "parent_chain_producer": inventory.parent_chain_producer,
        "verifier": inventory.verifier,
        "aggregate_accepting_verifier": inventory.aggregate_accepting_verifier,
        "resource_preflight": inventory.resource_preflight,
        "strict_h4_transcript_producer": inventory.strict_h4_transcript_producer,
        "h4_pre_alpha_verifier": inventory.h4_pre_alpha_verifier,
        "h4_post_z_response_evidence_producer": inventory.h4_post_z_response_evidence_producer,
        "h4_pre_alpha_producer": inventory.h4_pre_alpha_producer,
        "parent_transcript_producer": inventory.parent_transcript_producer,
        "real_authority_runner": inventory.real_authority_runner,
        "h4_replay_route": inventory.h4_replay_route,
        "parent_replay_route": inventory.parent_replay_route,
        "witness_acquisition_producer": inventory.witness_acquisition_producer,
    }


def _synthetic_entrypoint(root: Path, name: str) -> Path:
    release = root.resolve() / "experiments" / "bl_pq512_crypto_core" / "target" / "release"
    for candidate in (release / f"{name}.exe", release / name):
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise MajorRunError("synthetic_entrypoint_missing", name)


def _write_new_text(path: Path, value: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
    except FileExistsError as error:
        raise MajorRunError("synthetic_evidence_overwrite_forbidden", str(path)) from error


def _write_new_bytes(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(value)
    except FileExistsError as error:
        raise MajorRunError("evidence_overwrite_forbidden", str(path)) from error


def _working_set_bytes(pid: int) -> int | None:
    """Return the sampled Windows working-set peak, or None if unavailable."""

    if os.name != "nt":
        return None
    try:
        import ctypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(0x0410, False, pid)
        if not handle:
            return None
        try:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(ProcessMemoryCounters)
            if not psapi.GetProcessMemoryInfo(
                handle,
                ctypes.byref(counters),
                ctypes.sizeof(counters),
            ):
                return None
            return int(counters.PeakWorkingSetSize)
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError, TypeError):
        return None


def _run_synthetic_child(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout_seconds: int = SYNTHETIC_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, object]:
    started = time.monotonic()
    peak_working_set: int | None = None
    timed_out = False
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        except OSError as error:
            stderr.write(f"launch_error={error!r}\n".encode("utf-8"))
            raise MajorRunError("synthetic_child_launch_failed", str(command[0])) from error
        while process.poll() is None:
            observed = _working_set_bytes(process.pid)
            if observed is not None:
                peak_working_set = max(peak_working_set or 0, observed)
            if time.monotonic() - started >= timeout_seconds:
                timed_out = True
                process.kill()
                break
            time.sleep(0.05)
        return_code = process.wait()
        observed = _working_set_bytes(process.pid)
        if observed is not None:
            peak_working_set = max(peak_working_set or 0, observed)
    wall_seconds = time.monotonic() - started
    if timed_out:
        raise MajorRunError(
            "synthetic_child_timeout",
            f"{command[0]} timeout_seconds={timeout_seconds}",
        )
    if return_code != 0:
        raise MajorRunError(
            "synthetic_child_failed",
            f"{command[0]} exit_code={return_code}",
        )
    return {
        "command": command,
        "exit_code": return_code,
        "wall_seconds": round(wall_seconds, 6),
        "timeout_seconds": timeout_seconds,
        "timed_out": False,
        "resource_class": "synthetic_cpu_only",
        "peak_working_set_bytes": peak_working_set,
        "working_set_observation": (
            "sampled_windows_peak_working_set"
            if peak_working_set is not None
            else "not_available"
        ),
    }


def _run_native_child(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout_seconds: int = WORKER_RESPONSE_TIMEOUT_SECONDS,
    expect_success: bool = True,
) -> dict[str, object]:
    """Run the one native transaction while retaining raw output and telemetry."""

    started = time.monotonic()
    peak_working_set: int | None = None
    timed_out = False
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        except OSError as error:
            stderr.write(f"launch_error={error!r}\n".encode("utf-8"))
            raise MajorRunError("native_child_launch_failed", str(command[0])) from error
        while process.poll() is None:
            observed = _working_set_bytes(process.pid)
            if observed is not None:
                peak_working_set = max(peak_working_set or 0, observed)
            if time.monotonic() - started >= timeout_seconds:
                timed_out = True
                process.kill()
                break
            time.sleep(0.05)
        return_code = process.wait()
        observed = _working_set_bytes(process.pid)
        if observed is not None:
            peak_working_set = max(peak_working_set or 0, observed)
    wall_seconds = time.monotonic() - started
    telemetry = {
        "command": command,
        "exit_code": return_code,
        "wall_seconds": round(wall_seconds, 6),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "resource_class": "native_cpu_verifier_over_raw_governed_witness",
        "peak_working_set_bytes": peak_working_set,
        "working_set_observation": (
            "sampled_windows_peak_working_set"
            if peak_working_set is not None
            else "not_available"
        ),
        "gpu_launched": False,
    }
    if timed_out:
        raise MajorRunError(
            "native_child_timeout",
            f"{command[0]} timeout_seconds={timeout_seconds}",
        )
    if expect_success and return_code != 0:
        raise MajorRunError(
            "native_child_failed",
            f"{command[0]} exit_code={return_code}",
        )
    if os.name == "nt" and peak_working_set is None:
        raise MajorRunError("host_resource_telemetry_missing")
    if peak_working_set is not None and peak_working_set > PEAK_RESIDENT_BYTES:
        raise MajorRunError(
            "host_peak_limit_exceeded",
            f"observed={peak_working_set} limit={PEAK_RESIDENT_BYTES}",
        )
    return telemetry


def _prepare_run_directory(value: Path, name: str) -> Path:
    path = _absolute_path(value, name)
    if path.exists():
        raise MajorRunError(f"{name}_must_not_exist", str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    return path


def _ensure_custody_directory(value: Path) -> Path:
    path = _absolute_path(value, "custody_dir")
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise MajorRunError("custody_dir_not_directory", str(path))
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    return path


def _witness_regular_bytes(witness_dir: Path) -> int:
    witness_dir = _absolute_path(witness_dir, "witness_dir")
    if witness_dir.is_symlink() or not witness_dir.is_dir():
        raise MajorRunError("witness_dir_missing_or_not_regular", str(witness_dir))
    total = 0
    for path in witness_dir.rglob("*"):
        if path.is_symlink():
            raise MajorRunError("witness_symlink_forbidden", str(path))
        if path.is_file():
            total += path.stat().st_size
            if total > V3_ABSOLUTE_MAX_BYTES * 64:
                raise MajorRunError("witness_bytes_exceed_preflight_bound")
    if total <= 0:
        raise MajorRunError("witness_bytes_invalid")
    return total


def _real_dependency(
    profile: ProfileSpec,
    preceding_evidence_dir: Path | None,
) -> dict[str, object]:
    if profile.label == "K128_CALIBRATION":
        if preceding_evidence_dir is not None:
            raise MajorRunError("k128_preceding_evidence_forbidden")
        return {"required": False, "profile": None, "receipt_identity": None}
    if preceding_evidence_dir is None:
        raise MajorRunError("k512_preceding_evidence_required")
    preceding = _absolute_path(preceding_evidence_dir, "preceding_evidence_dir")
    manifest_path = _existing_regular_file(
        preceding / "run-manifest.json",
        "preceding_run_manifest",
    )
    receipt_path = _existing_regular_file(
        preceding / "receipt-evidence.bin",
        "preceding_receipt_evidence",
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MajorRunError("preceding_manifest_invalid") from error
    if (
        manifest.get("status") != REAL_STATUS
        or manifest.get("profile") != "K128_CALIBRATION"
        or manifest.get("proofSuiteId") is not None
        or manifest.get("production_usable") is not False
        or manifest.get("activation_allowed") is not False
    ):
        raise MajorRunError("preceding_k128_not_accepted_real_nonactivating")
    return {
        "required": True,
        "profile": "K128_CALIBRATION",
        "receipt_identity": hashlib.sha3_512(receipt_path.read_bytes()).hexdigest(),
        "evidence_dir": str(preceding),
    }


def _parse_native_status(path: Path) -> dict[str, str]:
    values = _parse_key_value_lines(path.read_bytes())
    required = {
        "status",
        "proofSuiteId",
        "production_usable",
        "activation_allowed",
        "real_phi_or_payments",
    }
    if not required.issubset(values):
        raise MajorRunError("native_acceptance_output_incomplete")
    return values


def _hardlink_tree(source: Path, destination: Path) -> None:
    source = _absolute_path(source, "witness_dir")
    if source.is_symlink() or not source.is_dir():
        raise MajorRunError("witness_dir_missing_or_not_regular", str(source))
    if destination.exists():
        raise MajorRunError("mutation_witness_exists", str(destination))
    destination.mkdir(parents=True)
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise MajorRunError("witness_symlink_forbidden", str(item))
        if item.is_dir():
            target.mkdir()
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(item, target)
            except OSError:
                shutil.copy2(item, target)
        else:
            raise MajorRunError("witness_special_file_forbidden", str(item))


def _flip_one_byte(path: Path, offset: int, label: str) -> None:
    before = path.stat()
    with path.open("r+b") as stream:
        stream.seek(offset)
        value = stream.read(1)
        if len(value) != 1:
            raise MajorRunError(f"{label}_offset_invalid")
        stream.seek(offset)
        stream.write(bytes([value[0] ^ 1]))
        stream.flush()
        os.fsync(stream.fileno())
    after = path.stat()
    if before.st_size != after.st_size:
        raise MajorRunError(f"{label}_size_changed")


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    _write_new_text(
        path,
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
    )


def _prepare_synthetic_directory(value: Path, name: str) -> Path:
    path = _absolute_path(value, name)
    if path.exists():
        raise MajorRunError(f"{name}_must_not_exist", str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    return path


def _synthetic_dependency(
    profile: ProfileSpec,
    preceding_evidence_dir: Path | None,
) -> tuple[str, Path | None]:
    if profile.label == "K128_CALIBRATION":
        if preceding_evidence_dir is not None:
            raise MajorRunError("k128_preceding_evidence_forbidden")
        return "0" * 128, None
    if preceding_evidence_dir is None:
        raise MajorRunError("k512_preceding_evidence_required")
    preceding = _existing_regular_file(
        preceding_evidence_dir / "run-manifest.json",
        "preceding_run_manifest",
    )
    try:
        manifest = json.loads(preceding.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MajorRunError("preceding_run_manifest_invalid") from error
    if not isinstance(manifest, dict):
        raise MajorRunError("preceding_run_manifest_invalid")
    required = {
        "status": SYNTHETIC_STATUS,
        "evidence_class": "synthetic_nonactivating_integration",
        "profile": "K128_CALIBRATION",
        "proof_suite_id": None,
        "production_usable": False,
        "activation_allowed": False,
        "real_phi_or_payments": False,
    }
    if any(manifest.get(key) != value for key, value in required.items()):
        raise MajorRunError("preceding_k128_not_accepted_synthetic")
    proof_path = _existing_regular_file(
        preceding.parent / "synthetic-proof.bin",
        "preceding_synthetic_proof",
    )
    proof_identity = hashlib.sha3_512(proof_path.read_bytes()).hexdigest()
    if manifest.get("proof_artifact_sha3_512") != proof_identity:
        raise MajorRunError("preceding_k128_proof_identity_mismatch")
    return proof_identity, preceding.parent


def _parse_synthetic_stdout(path: Path) -> dict[str, str]:
    try:
        return _parse_key_value_lines(path.read_bytes())
    except (OSError, UnicodeError, MajorRunError) as error:
        if isinstance(error, MajorRunError):
            raise
        raise MajorRunError("synthetic_child_output_invalid", str(path)) from error


def _hash_synthetic_evidence(evidence_dir: Path) -> dict[str, str]:
    witness_hashes: dict[str, str] = {}
    for path in sorted(witness_dir.rglob("*")):
        if path.is_symlink():
            raise MajorRunError("witness_symlink_forbidden", str(path))
        if path.is_file():
            witness_hashes[str(path.relative_to(witness_dir))] = hashlib.sha3_512(
                path.read_bytes()
            ).hexdigest()
    _write_new_text(
        evidence / "witness-artifact-hashes.sha3-512",
        "".join(
            f"{name}={value}\n" for name, value in sorted(witness_hashes.items())
        ),
    )
    hashes: dict[str, str] = {}
    for path in sorted(evidence_dir.iterdir(), key=lambda item: item.name):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.name in {"artifact-hashes.sha3-512", "run-manifest.json"}
        ):
            continue
        hashes[path.name] = hashlib.sha3_512(path.read_bytes()).hexdigest()
    return hashes


def run_synthetic(
    profile: ProfileSpec,
    evidence_dir: Path,
    scratch_dir: Path,
    shard_concurrency: int,
    *,
    root: Path,
    preceding_evidence_dir: Path | None = None,
) -> dict[str, object]:
    """Run the explicit synthetic, nonactivating integration lane."""

    if shard_concurrency < 1 or shard_concurrency > profile.max_shard_concurrency:
        raise MajorRunError("shard_concurrency_invalid")
    evidence = _prepare_synthetic_directory(evidence_dir, "evidence_dir")
    scratch = _prepare_synthetic_directory(scratch_dir, "scratch_dir")
    dependency_hex, preceding = _synthetic_dependency(profile, preceding_evidence_dir)
    root = _absolute_path(root, "root")
    input_producer = _synthetic_entrypoint(root, "v3_synthetic_input_produce")
    proof_producer = _synthetic_entrypoint(root, "v3_synthetic_proof_produce")
    verifier = _synthetic_entrypoint(root, "v3_synthetic_aggregate_verify")
    resource_gate = _synthetic_entrypoint(root, "v3_synthetic_resource_preflight")
    input_path = evidence / "synthetic-input.bin"
    proof_path = evidence / "synthetic-proof.bin"
    telemetry: list[dict[str, object]] = []
    commands: dict[str, list[str]] = {}
    started_at = datetime.now(timezone.utc).isoformat()
    run_started = time.monotonic()

    input_command = [str(input_producer), profile.label, str(input_path)]
    commands["input_producer"] = input_command
    telemetry.append(
        _run_synthetic_child(
            input_command,
            evidence / "producer-input.stdout",
            evidence / "producer-input.stderr",
        )
    )
    input_output = _parse_synthetic_stdout(evidence / "producer-input.stdout")
    if input_output.get("status") != "SYNTHETIC_INPUT_PRODUCED":
        raise MajorRunError("synthetic_input_producer_status")
    if not input_path.is_file() or input_path.stat().st_size == 0:
        raise MajorRunError("synthetic_input_artifact_missing")

    resource_command = [str(resource_gate), profile.label, str(input_path)]
    commands["resource_preflight"] = resource_command
    telemetry.append(
        _run_synthetic_child(
            resource_command,
            evidence / "resource-preflight.stdout",
            evidence / "resource-preflight.stderr",
        )
    )
    resource_output = _parse_synthetic_stdout(evidence / "resource-preflight.stdout")
    if (
        resource_output.get("status") != "SYNTHETIC_RESOURCE_PREFLIGHT_PASS"
        or resource_output.get("qualifies") != "false"
        or resource_output.get("scratch_gate_pass") != "true"
        or resource_output.get("activation_allowed") != "false"
        or resource_output.get("production_usable") != "false"
    ):
        raise MajorRunError("synthetic_resource_gate_contract")

    proof_command = [
        str(proof_producer),
        profile.label,
        str(input_path),
        str(proof_path),
        dependency_hex,
    ]
    commands["proof_producer"] = proof_command
    telemetry.append(
        _run_synthetic_child(
            proof_command,
            evidence / "producer-proof.stdout",
            evidence / "producer-proof.stderr",
        )
    )
    proof_output = _parse_synthetic_stdout(evidence / "producer-proof.stdout")
    if proof_output.get("status") != "SYNTHETIC_PROOF_PRODUCED_UNQUALIFIED":
        raise MajorRunError("synthetic_proof_producer_status")
    if not proof_path.is_file() or proof_path.stat().st_size != SYNTHETIC_BUNDLE_BYTES:
        raise MajorRunError("synthetic_proof_artifact_shape")

    verifier_command = [
        str(verifier),
        profile.label,
        str(input_path),
        str(proof_path),
        dependency_hex,
        "--mutation-suite",
    ]
    commands["aggregate_verifier"] = verifier_command
    telemetry.append(
        _run_synthetic_child(
            verifier_command,
            evidence / "verifier.stdout",
            evidence / "verifier.stderr",
        )
    )
    verifier_output = _parse_synthetic_stdout(evidence / "verifier.stdout")
    proof_identity = hashlib.sha3_512(proof_path.read_bytes()).hexdigest()
    artifact_mutations = int(verifier_output.get("artifact_mutations", "-1"))
    input_mutations = int(verifier_output.get("input_mutations", "-1"))
    rejected_mutations = int(verifier_output.get("rejected_mutations", "-1"))
    if (
        verifier_output.get("status") != "SYNTHETIC_AGGREGATE_ACCEPTED_NONACTIVATING"
        or verifier_output.get("proof_identity_sha3_512") != proof_identity
        or verifier_output.get("mutation_suite") != "PASS"
        or rejected_mutations != artifact_mutations + input_mutations
        or verifier_output.get("proof_suite_id") != "null"
        or verifier_output.get("production_usable") != "false"
        or verifier_output.get("activation_allowed") != "false"
        or verifier_output.get("real_phi_or_payments") != "false"
    ):
        raise MajorRunError("synthetic_verifier_contract")
    _write_new_text(
        evidence / "mutation-results.jsonl",
        json.dumps(
            {
                "status": verifier_output["mutation_suite"],
                "artifact_mutations": artifact_mutations,
                "input_mutations": input_mutations,
                "rejected_mutations": rejected_mutations,
                "raw_verifier_stdout_sha3_512": hashlib.sha3_512(
                    (evidence / "verifier.stdout").read_bytes()
                ).hexdigest(),
            },
            sort_keys=True,
        )
        + "\n",
    )
    _write_new_text(
        evidence / "host-resource-telemetry.jsonl",
        "\n".join(json.dumps(item, sort_keys=True) for item in telemetry) + "\n",
    )
    _write_new_text(
        evidence / "device-resource-telemetry.jsonl",
        json.dumps(
            {
                "status": "NOT_APPLICABLE",
                "reason": "synthetic_lane_cpu_only_gpu_not_launched",
                "gpu_launched": False,
                "qualifies": False,
            },
            sort_keys=True,
        )
        + "\n",
    )
    scratch.rmdir()
    _write_new_text(
        evidence / "cleanup.json",
        json.dumps(
            {
                "status": "PASS",
                "scratch_dir": str(scratch),
                "owned_scratch_entries": [],
                "cleanup_scope": "synthetic_run_only",
                "scratch_removed": True,
            },
            sort_keys=True,
        )
        + "\n",
    )
    hashes = _hash_synthetic_evidence(evidence)
    _write_new_text(
        evidence / "artifact-hashes.sha3-512",
        "".join(f"{name}={value}\n" for name, value in sorted(hashes.items())),
    )
    manifest: dict[str, object] = {
        "status": SYNTHETIC_STATUS,
        "evidence_class": "synthetic_nonactivating_integration",
        "purpose": "native synthetic component integration; not complete governed H4/post-Z proof",
        "profile": profile.label,
        "profile_code": profile.code,
        "shard_count": profile.shard_count,
        "shard_concurrency": shard_concurrency,
        "input_kind": "synthetic_fixed_shape",
        "input_artifact": "synthetic-input.bin",
        "input_identity_sha3_512": hashlib.sha3_512(input_path.read_bytes()).hexdigest(),
        "proof_artifact": "synthetic-proof.bin",
        "proof_artifact_sha3_512": proof_identity,
        "aggregate_receipt": verifier_output["aggregate_receipt"],
        "work_receipt": verifier_output["work_receipt"],
        "dependency_commitment": verifier_output["dependency_commitment"],
        "preceding_evidence_dir": None if preceding is None else str(preceding),
        "orchestrator_entrypoint": str(Path(__file__).resolve()),
        "commands": commands,
        "resource": {
            "peak_host_bytes_limit": PEAK_RESIDENT_BYTES,
            "scratch_bytes_limit_exclusive": SCRATCH_BYTES_EXCLUSIVE,
            "child_timeout_seconds": SYNTHETIC_COMMAND_TIMEOUT_SECONDS,
            "gpu": "not_applicable",
            "resource_preflight": resource_output,
        },
        "mutation_suite": {
            "status": verifier_output["mutation_suite"],
            "artifact_mutations": artifact_mutations,
            "input_mutations": input_mutations,
            "rejected_mutations": rejected_mutations,
        },
        "proof_suite_id": None,
        "proofSuiteId": None,
        "production_usable": False,
        "activation_allowed": False,
        "real_phi_or_payments": False,
        "gpu_launched": False,
        "major_real_proof": False,
        "full_v3_governed_proof": False,
        "run_started_at": started_at,
        "run_duration_seconds": round(time.monotonic() - run_started, 6),
        "artifact_hash_scope": "all regular evidence files except this manifest and the hash listing",
    }
    _write_new_text(
        evidence / "run-manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    return manifest


def run_real(
    profile: ProfileSpec,
    evidence_dir: Path,
    scratch_dir: Path,
    shard_concurrency: int,
    *,
    root: Path,
    witness_dir: Path,
    custody_dir: Path,
    preceding_evidence_dir: Path | None = None,
) -> dict[str, object]:
    """Run the native governed lane over one complete raw witness.

    The witness is produced by the proof workers before this coordinator is
    invoked.  This function never fabricates missing component bytes: it
    performs resource preflight, invokes the one native transaction, retains
    its raw output, and requires the native accepting receipt plus two cheap
    fail-closed checks (durable same-attempt replay and a mutated trusted
    layout) before writing the run manifest.
    """

    if shard_concurrency < 1 or shard_concurrency > profile.max_shard_concurrency:
        raise MajorRunError("shard_concurrency_invalid")
    witness_dir = _absolute_path(witness_dir, "witness_dir")
    custody_dir = _ensure_custody_directory(custody_dir)
    dependency = _real_dependency(profile, preceding_evidence_dir)
    evidence = _prepare_run_directory(evidence_dir, "evidence_dir")
    scratch = _prepare_run_directory(scratch_dir, "scratch_dir")
    root = _absolute_path(root, "root")
    inventory = current_entrypoints(root)
    missing = missing_seams(inventory)
    if missing:
        raise MajorRunError("missing_current_v3_seams", ",".join(missing))
    if inventory.real_authority_runner is None:
        raise MajorRunError("real_authority_runner_missing")
    semantic_program = _existing_regular_file(
        witness_dir / "semantic-program.bin",
        "semantic_program",
    )
    raw_witness_bytes = _witness_regular_bytes(witness_dir)
    inputs = RunInputs(
        profile=profile,
        evidence_dir=evidence,
        scratch_dir=scratch,
        shard_concurrency=shard_concurrency,
        semantic_program=semantic_program,
        raw_witness_bytes=raw_witness_bytes,
        witness_dir=witness_dir,
        custody_dir=custody_dir,
    )
    started_at = datetime.now(timezone.utc).isoformat()
    run_started = time.monotonic()
    telemetry: list[dict[str, object]] = []
    mutation_results: list[dict[str, object]] = []
    cleanup_status = "NOT_STARTED"
    try:
        resource_output = run_resource_preflight(
            inputs,
            inventory,
            raw_output_dir=evidence,
        )
        verifier_capability = probe_verifier_capability(inventory)
        command = [
            str(inventory.real_authority_runner),
            "--role",
            "orchestrator",
            "--witness-dir",
            str(witness_dir),
            "--evidence-dir",
            str(evidence),
            "--scratch-dir",
            str(scratch),
            "--custody-dir",
            str(custody_dir),
            "--profile",
            profile.label,
        ]
        native_telemetry = _run_native_child(
            command,
            evidence / "native-run.stdout",
            evidence / "native-run.stderr",
        )
        telemetry.append(native_telemetry)
        native_output = _parse_native_status(evidence / "native-acceptance.txt")
        if (
            native_output.get("status") != REAL_NATIVE_STATUS
            or native_output.get("proofSuiteId") != "null"
            or native_output.get("production_usable") != "false"
            or native_output.get("activation_allowed") != "false"
            or native_output.get("real_phi_or_payments") != "false"
            or not (evidence / "receipt-evidence.bin").is_file()
        ):
            raise MajorRunError("native_acceptance_contract_invalid")
        mutation_results.append(
            {
                "check": "baseline_complete_v3_acceptance",
                "status": "PASS",
                "raw_status": native_output.get("status"),
                "proofSuiteId": native_output.get("proofSuiteId"),
                "production_usable": native_output.get("production_usable"),
                "activation_allowed": native_output.get("activation_allowed"),
            }
        )

        # A second process with the same governed key identity must fail before
        # replay. This is the durable attempt/replay check, not a forged pass.
        replay_evidence = evidence / "replay-check"
        replay_scratch = scratch / "replay-check"
        replay_evidence.mkdir()
        replay_scratch.mkdir()
        replay_command = command.copy()
        replay_command[replay_command.index("--evidence-dir") + 1] = str(replay_evidence)
        replay_command[replay_command.index("--scratch-dir") + 1] = str(replay_scratch)
        replay_telemetry = _run_native_child(
            replay_command,
            replay_evidence / "native-run.stdout",
            replay_evidence / "native-run.stderr",
            timeout_seconds=60,
            expect_success=False,
        )
        telemetry.append(replay_telemetry)
        replay_error = (replay_evidence / "native-run.stderr").read_text(
            encoding="utf-8",
            errors="replace",
        )
        replay_rejected = (
            replay_telemetry["exit_code"] != 0
            and "attempt_already_consumed" in replay_error
        )
        mutation_results.append(
            {
                "check": "same_attempt_replay",
                "status": "PASS" if replay_rejected else "FAIL",
                "terminal_error": "attempt_already_consumed",
                "raw_stderr": replay_error,
            }
        )
        if not replay_rejected:
            raise MajorRunError("same_attempt_replay_not_rejected")

        # Flip one trusted-layout byte in a hard-linked witness copy. The
        # native lane must reject the mutation before any component receipt is
        # minted; only the 820-byte layout is copied, so this check is cheap.
        mutation_witness = scratch / "mutation-witness"
        _hardlink_tree(witness_dir, mutation_witness)
        _flip_one_byte(mutation_witness / "trusted-layout.bin", 100, "mutation_layout")
        mutation_evidence = evidence / "mutation-layout-check"
        mutation_scratch = scratch / "mutation-layout-check"
        mutation_custody = scratch / "mutation-custody"
        mutation_evidence.mkdir()
        mutation_scratch.mkdir()
        mutation_custody.mkdir()
        mutation_command = command.copy()
        mutation_command[mutation_command.index("--witness-dir") + 1] = str(mutation_witness)
        mutation_command[mutation_command.index("--evidence-dir") + 1] = str(mutation_evidence)
        mutation_command[mutation_command.index("--scratch-dir") + 1] = str(mutation_scratch)
        mutation_command[mutation_command.index("--custody-dir") + 1] = str(mutation_custody)
        mutation_telemetry = _run_native_child(
            mutation_command,
            mutation_evidence / "native-run.stdout",
            mutation_evidence / "native-run.stderr",
            timeout_seconds=60,
            expect_success=False,
        )
        telemetry.append(mutation_telemetry)
        mutation_rejected = mutation_telemetry["exit_code"] != 0
        mutation_results.append(
            {
                "check": "trusted_layout_mutation",
                "status": "PASS" if mutation_rejected else "FAIL",
                "raw_stderr": (mutation_evidence / "native-run.stderr").read_text(
                    encoding="utf-8",
                    errors="replace",
                ),
            }
        )
        if not mutation_rejected:
            raise MajorRunError("trusted_layout_mutation_not_rejected")

        _write_jsonl(evidence / "mutation-results.jsonl", mutation_results)
        _write_jsonl(evidence / "host-resource-telemetry.jsonl", telemetry)
        _write_new_text(
            evidence / "device-resource-telemetry.jsonl",
            json.dumps(
                {
                    "status": "NOT_APPLICABLE",
                    "reason": "native_authority_replay_did_not_launch_gpu",
                    "gpu_launched": False,
                    "qualifies": False,
                },
                sort_keys=True,
            )
            + "\n",
        )
        cleanup_status = "PASS"
    finally:
        owned_entries = [str(path) for path in scratch.rglob("*")] if scratch.exists() else []
        if scratch.exists():
            shutil.rmtree(scratch)
        _write_new_text(
            evidence / "cleanup.json",
            json.dumps(
                {
                    "status": cleanup_status,
                    "scratch_dir": str(scratch),
                    "owned_scratch_entries_before_cleanup": owned_entries,
                    "scratch_removed": not scratch.exists(),
                    "custody_dir_retained": str(custody_dir),
                },
                sort_keys=True,
            )
            + "\n",
        )

    hashes: dict[str, str] = {}
    for path in sorted(evidence.rglob("*")):
        if (
            path.is_file()
            and not path.is_symlink()
            and path.name not in {"artifact-hashes.sha3-512", "run-manifest.json"}
        ):
            hashes[str(path.relative_to(evidence))] = hashlib.sha3_512(
                path.read_bytes()
            ).hexdigest()
    _write_new_text(
        evidence / "artifact-hashes.sha3-512",
        "".join(f"{name}={value}\n" for name, value in sorted(hashes.items())),
    )
    manifest: dict[str, object] = {
        "status": REAL_STATUS,
        "evidence_class": "real_governed_native_replay",
        "purpose": "complete raw-witness K128/K512 native replay and nonactivating acceptance",
        "profile": profile.label,
        "profile_code": profile.code,
        "shard_count": profile.shard_count,
        "shard_concurrency": shard_concurrency,
        "witness_dir": str(witness_dir),
        "witness_bytes": raw_witness_bytes,
        "witness_artifact_hashes": "witness-artifact-hashes.sha3-512",
        "preceding_dependency": dependency,
        "entrypoints": _inventory_dict(inventory),
        "commands": {
            "orchestrator": command,
            "h4_replay_route": inventory.h4_replay_route,
            "parent_replay_route": inventory.parent_replay_route,
            "h4_producer": inventory.h4_producer,
            "parent_producer": inventory.parent_producer,
            "outer_verifier_role": inventory.aggregate_accepting_verifier,
            "resource_preflight": inventory.resource_preflight,
        },
        "resource": {
            "peak_host_bytes_limit": PEAK_RESIDENT_BYTES,
            "scratch_bytes_limit_exclusive": SCRATCH_BYTES_EXCLUSIVE,
            "child_timeout_seconds": WORKER_RESPONSE_TIMEOUT_SECONDS,
            "resource_preflight": resource_output,
            "gpu_launched": False,
        },
        "verifier_capability": verifier_capability,
        "mutation_suite": {
            "status": "PASS",
            "checks": mutation_results,
            "required_checks": REAL_MUTATION_CHECKS,
            "scope": "durable_replay_and_trusted_layout_mutation",
        },
        "proof_suite_id": None,
        "proofSuiteId": None,
        "production_usable": False,
        "activation_allowed": False,
        "real_phi_or_payments": False,
        "gpu_launched": False,
        "major_real_proof": True,
        "full_v3_governed_proof": True,
        "run_started_at": started_at,
        "run_duration_seconds": round(time.monotonic() - run_started, 6),
        "artifact_hash_scope": "all regular evidence files except this manifest and the hash listing",
    }
    _write_new_text(evidence / "run-manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILE_SPECS), required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--shard-concurrency", type=int, default=1)
    parser.add_argument("--semantic-program", type=Path)
    parser.add_argument("--raw-witness-bytes", type=int)
    parser.add_argument("--root", type=Path, default=repository_root())
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="run the explicit synthetic nonactivating integration lane",
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="run the governed native lane over a complete raw witness",
    )
    parser.add_argument("--witness-dir", type=Path)
    parser.add_argument("--custody-dir", type=Path)
    parser.add_argument("--preceding-evidence-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    profile = PROFILE_SPECS[arguments.profile]
    inputs = RunInputs(
        profile=profile,
        evidence_dir=arguments.evidence_dir,
        scratch_dir=arguments.scratch_dir,
        shard_concurrency=arguments.shard_concurrency,
        semantic_program=arguments.semantic_program,
        raw_witness_bytes=arguments.raw_witness_bytes,
        witness_dir=arguments.witness_dir,
        custody_dir=arguments.custody_dir,
    )
    try:
        if arguments.synthetic and arguments.real:
            raise MajorRunError("synthetic_and_real_mutually_exclusive")
        if arguments.real:
            if arguments.witness_dir is None or arguments.custody_dir is None:
                raise MajorRunError("real_witness_and_custody_inputs_required")
            report = run_real(
                profile,
                arguments.evidence_dir,
                arguments.scratch_dir,
                arguments.shard_concurrency,
                root=arguments.root,
                witness_dir=arguments.witness_dir,
                custody_dir=arguments.custody_dir,
                preceding_evidence_dir=arguments.preceding_evidence_dir,
            )
        elif arguments.synthetic:
            report = run_synthetic(
                profile,
                arguments.evidence_dir,
                arguments.scratch_dir,
                arguments.shard_concurrency,
                root=arguments.root,
                preceding_evidence_dir=arguments.preceding_evidence_dir,
            )
        elif arguments.plan_only:
            inventory = current_entrypoints(arguments.root)
            report = {
                "status": "PLAN_ONLY_NO_PROOF_STARTED",
                "profile": profile.label,
                "entrypoints": _inventory_dict(inventory),
                "missing_seams": missing_seams(inventory),
                "proof_run_started": False,
                "gpu_resource_gate_note": GPU_RESOURCE_GATE_NOTE,
                "proof_identity_fields": PROOF_IDENTITY_FIELDS,
                "mutation_checks": MUTATION_CHECKS,
                "evidence_plan": evidence_plan(profile),
                "proof_suite_id": None,
                "production_usable": False,
                "activation_allowed": False,
            }
        else:
            report = preflight(inputs, root=arguments.root)
    except MajorRunError as error:
        print(json.dumps({"status": "BLOCKED", "code": error.code, "detail": error.detail}))
        return 3
    print(json.dumps(report, default=lambda value: value.__dict__, sort_keys=True))
    return 0 if report["status"] in {
        "READY_TO_LAUNCH",
        "PLAN_ONLY_NO_PROOF_STARTED",
        SYNTHETIC_STATUS,
        REAL_STATUS,
    } else 3


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "H4_AGGREGATE_BYTES",
    "H4_SHARD_BYTES",
    "EVIDENCE_FILE_SPECS",
    "GPU_RESOURCE_GATE_NOTE",
    "MajorRunError",
    "MUTATION_CHECKS",
    "REAL_MUTATION_CHECKS",
    "PEAK_RESIDENT_BYTES",
    "PROOF_IDENTITY_FIELDS",
    "PROFILE_SPECS",
    "RunInputs",
    "SCRATCH_BYTES_EXCLUSIVE",
    "SYNTHETIC_COMMAND_TIMEOUT_SECONDS",
    "SYNTHETIC_STATUS",
    "REAL_STATUS",
    "TYPED_STATE_PROOF_PACKAGE_BYTES",
    "WORKER_RESPONSE_TIMEOUT_SECONDS",
    "current_entrypoints",
    "evidence_plan",
    "missing_seams",
    "preflight",
    "probe_verifier_capability",
    "run_resource_preflight",
    "run_real",
    "run_synthetic",
)
