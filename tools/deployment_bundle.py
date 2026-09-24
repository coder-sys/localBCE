"""Assemble and independently validate the synthetic financial-correction bundle.

This is an offline source-and-evidence package for one candidate operation. It
does not select a profile or confer integration, release, or activation
authority. The package carries the exact source tree and dirty-file identities
for its known inputs, but all executable and external-control gates remain
explicit until independently attested.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "RR/DEPLOYMENT/SYNTHETIC-FINANCIAL-BUNDLE/v1"
EVIDENCE_SCHEMA = "RR/DEPLOYMENT/RUN-EVIDENCE/v1"
MANIFEST_NAME = "MANIFEST.json"
OPERATIONS_NAME = "OPERATIONS.md"
WORKSPACE_MAP_RELATIVE = "WORKSPACE_MAP.md"
WORKSPACE_MAP_MEMBER = "payload/workspace/WORKSPACE_MAP.md"
GUARD_SHA256 = "57f9ec8aefe1d0e281b3bb0d76f2f057c8295f99afdd04305dfc777703ed99fb"
PHYSICAL_RESERVE_BYTES = 3_221_225_472
PHYSICAL_FREE_FLOOR_BYTES = 2_190_433_321
PHYSICAL_RESERVE_TOLERANCE_PERCENT = 32

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_FILE_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_HASH_BYTES = 2 * 1024 * 1024 * 1024
MAX_EVIDENCE_LOG_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_DIRTY_FILES = 10_000
MAX_DIRTY_BYTES = 2 * 1024 * 1024 * 1024

PROJECT_ROOTS: Mapping[str, str] = {
    "financial": "rightrail-financial-workflow-20260913",
    "engine": "lean-engine-20260913",
    "queue": "lean-queue-20260913",
    "qualification": "rightrail-qualification-gate-v3-20260923",
}


class DeploymentBundleError(ValueError):
    """An input identity, bundle member, or evidence record is invalid."""


@dataclass(frozen=True)
class FileSpec:
    file_id: str
    repository: str
    path: str
    include: bool = True
    kind: str = "source"


@dataclass(frozen=True)
class ComponentSpec:
    component_id: str
    file_ids: tuple[str, ...]
    reason_if_unselected: str | None = None


FILE_SPECS: tuple[FileSpec, ...] = (
    FileSpec("engine.lean_toolchain", "engine", "semantic_kernel/lean/lean-toolchain", kind="toolchain"),
    FileSpec("engine.lakefile", "engine", "semantic_kernel/lean/lakefile.toml", kind="build-config"),
    FileSpec("engine.lake_manifest", "engine", "semantic_kernel/lean/lake-manifest.json", kind="dependency-lock"),
    FileSpec("engine.transition_root", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition.lean"),
    FileSpec("engine.transition_types", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Types.lean"),
    FileSpec("engine.transition", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Transition.lean"),
    FileSpec("engine.transition_theorems", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Theorems.lean"),
    FileSpec("engine.reuse", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Reuse.lean"),
    FileSpec("engine.codec", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Codec.lean"),
    FileSpec("engine.reuse_codec", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/ReuseCodec.lean"),
    FileSpec("engine.runtime", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Runtime.lean"),
    FileSpec("engine.wire_vectors", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/KAT.lean"),
    FileSpec("engine.cli", "engine", "semantic_kernel/lean/BlindLedger/Financial/CorrectionTransitionCli.lean"),
    FileSpec("engine.axiom_check_source", "engine", "semantic_kernel/lean/BlindLedger/Financial/AxiomCheck.lean"),
    FileSpec("engine.theorem_manifest", "engine", "semantic_kernel/lean/BlindLedger/Financial/Theorems/Manifest.lean"),
    FileSpec("engine.theorem_correspondence", "engine", "semantic_kernel/lean/BlindLedger/Financial/Theorems/Correspondence.lean"),
    FileSpec("engine.theorem_vectors", "engine", "semantic_kernel/lean/BlindLedger/Financial/Theorems/Vectors.lean"),
    FileSpec("engine.theorem_root", "engine", "semantic_kernel/lean/BlindLedger/Financial/Theorems.lean"),
    FileSpec("engine.financial_executable", "engine", "semantic_kernel/lean/BlindLedger/Financial/Executable.lean"),
    FileSpec("engine.financial_codec", "engine", "semantic_kernel/lean/BlindLedger/Financial/Codec.lean"),
    FileSpec("engine.codec_laws", "engine", "semantic_kernel/lean/BlindLedger/Financial/CodecLaws.lean"),
    FileSpec("engine.codec_laws_primitives", "engine", "semantic_kernel/lean/BlindLedger/Financial/CodecLaws/Primitives.lean"),
    FileSpec("engine.codec_laws_records", "engine", "semantic_kernel/lean/BlindLedger/Financial/CodecLaws/Records.lean"),
    FileSpec("engine.codec_laws_check", "engine", "semantic_kernel/lean/BlindLedger/Financial/CodecLawsCheck.lean"),
    FileSpec("engine.financial_evaluation", "engine", "semantic_kernel/lean/BlindLedger/Financial/Evaluation.lean"),
    FileSpec("engine.financial_specification", "engine", "semantic_kernel/lean/BlindLedger/Financial/Specification.lean"),
    FileSpec("engine.financial_types", "engine", "semantic_kernel/lean/BlindLedger/Financial/Types.lean"),
    FileSpec("engine.decision_types", "engine", "semantic_kernel/lean/BlindLedger/Financial/DecisionPackage/Types.lean"),
    FileSpec("engine.decision_projection", "engine", "semantic_kernel/lean/BlindLedger/Financial/DecisionPackage/Projection.lean"),
    FileSpec("engine.decision_codec", "engine", "semantic_kernel/lean/BlindLedger/Financial/DecisionPackage/Codec.lean"),
    FileSpec("engine.sha3", "engine", "semantic_kernel/lean/BlindLedger/Sha3.lean"),
    FileSpec("engine.executable", "engine", "semantic_kernel/lean/.lake/build/bin/blind_financial_correction.exe", include=False, kind="executable"),
    FileSpec("qualification.bundle_tool", "qualification", "tools/deployment_bundle.py", kind="bundle-tool-source"),
    FileSpec("qualification.acceptance_entrypoint", "qualification", "tools/project_acceptance.py", kind="acceptance-tool-source"),
    FileSpec("financial.owner", "financial", "app/right_rail_financial_owner.py"),
    FileSpec("financial.semantic_adapter", "financial", "app/right_rail_financial_semantic_adapter.py"),
    FileSpec("financial.engine_binding", "financial", "app/right_rail_financial_engine.py"),
    FileSpec("financial.independent_checker", "financial", "app/right_rail_financial_owner_independent.py"),
    FileSpec("financial.expected_answers", "financial", "tests/rightrail_financial_expected_cases.py", kind="expected-answers"),
    FileSpec("financial.verifier_process", "financial", "app/minimal_clearance_verifier_process.py", kind="process-boundary-source"),
    FileSpec("financial.verifier_resource_limits", "financial", "app/minimal_clearance_resource_limits.py", kind="resource-policy-source"),
    FileSpec("financial.mirror", "financial", "app/right_rail_financial_mirror.py"),
    FileSpec("financial.staff_server", "financial", "app/right_rail_financial_staff_server.py"),
    FileSpec("financial.staff_index", "financial", "app/staff_workspace/index.html", kind="staff-interface"),
    FileSpec("financial.staff_script", "financial", "app/staff_workspace/staff.js", kind="staff-interface"),
    FileSpec("financial.staff_style", "financial", "app/staff_workspace/staff.css", kind="staff-interface"),
    FileSpec("financial.source_receiver_contracts", "financial", "docs/SOURCE_RECEIVER_CONTRACTS.md", kind="interface-contract"),
    FileSpec("queue.lifecycle_adapter", "queue", "app/minimal_clearance_lifecycle_adapter.py"),
    FileSpec("queue.queue_independent", "queue", "app/minimal_clearance_verification_queue_independent.py"),
    FileSpec("queue.verifier_process", "queue", "app/minimal_clearance_verifier_process.py", kind="process-boundary-source"),
    FileSpec("queue.verifier_resource_limits", "queue", "app/minimal_clearance_resource_limits.py", kind="resource-policy-source"),
    FileSpec("queue.cargo_config", "queue", "semantic_kernel/rust/.cargo/config.toml", kind="build-config"),
    FileSpec("queue.lifecycle_build", "queue", "semantic_kernel/rust/build.rs", kind="build-config"),
    FileSpec("queue.lifecycle_rust", "queue", "semantic_kernel/rust/src/bin/lifecycle.rs"),
    FileSpec("queue.native_boundary", "queue", "semantic_kernel/rust/native_boundary.c", kind="native-link-source"),
    FileSpec("queue.cargo_manifest", "queue", "semantic_kernel/rust/Cargo.toml", kind="build-config"),
    FileSpec("queue.cargo_lock", "queue", "semantic_kernel/rust/Cargo.lock", kind="dependency-lock"),
    FileSpec("queue.post_link_attester", "queue", "semantic_kernel/rust/post_link_attest.py", kind="build-tool-source"),
    FileSpec("queue.lifecycle_lean", "queue", "semantic_kernel/lean/Admission/LifecycleKernel.lean"),
    FileSpec("queue.lifecycle_lean_root", "queue", "semantic_kernel/lean/Admission/Lifecycle.lean"),
    FileSpec("queue.lifecycle_model", "queue", "semantic_kernel/lean/Admission/Model.lean"),
    FileSpec("queue.lifecycle_lean_checker", "queue", "semantic_kernel/lean/Admission/Checker.lean"),
    FileSpec("queue.lifecycle_lean_library", "queue", "semantic_kernel/lean/Admission/Library.lean"),
    FileSpec("queue.lifecycle_lean_main", "queue", "semantic_kernel/lean/Admission/Main.lean"),
    FileSpec("queue.lean_sha3", "queue", "semantic_kernel/lean/BlindLedger/Sha3.lean"),
    FileSpec("queue.lean_toolchain", "queue", "semantic_kernel/lean/lean-toolchain", kind="toolchain"),
    FileSpec("queue.lakefile", "queue", "semantic_kernel/lean/lakefile.toml", kind="build-config"),
    FileSpec("queue.lake_manifest", "queue", "semantic_kernel/lean/lake-manifest.json", kind="dependency-lock"),
    FileSpec("queue.lifecycle_executable", "queue", "semantic_kernel/rust/target/x86_64-pc-windows-gnu/release/lifecycle.exe", include=False, kind="executable"),
)

COMPONENT_SPECS: tuple[ComponentSpec, ...] = (
    ComponentSpec("engine.build_inputs", ("engine.lean_toolchain", "engine.lakefile", "engine.lake_manifest")),
    ComponentSpec("engine.semantic_source", (
        "engine.cli", "engine.runtime", "engine.transition_root", "engine.transition_types", "engine.transition",
        "engine.reuse", "engine.codec", "engine.reuse_codec", "engine.financial_codec",
        "engine.financial_evaluation", "engine.financial_specification", "engine.financial_types",
        "engine.decision_types", "engine.decision_projection", "engine.decision_codec", "engine.sha3",
        "engine.wire_vectors", "engine.theorem_vectors",
    )),
    ComponentSpec("engine.theorem_manifest", (
        "engine.theorem_root", "engine.theorem_manifest", "engine.theorem_correspondence",
        "engine.theorem_vectors", "engine.transition_theorems", "engine.reuse", "engine.transition",
        "engine.transition_types", "engine.decision_types", "engine.decision_projection",
        "engine.financial_codec", "engine.financial_evaluation", "engine.financial_specification",
        "engine.financial_types", "engine.sha3",
    ), "The exact theorem source set is captured; no current-source compiler or theorem receipt is supplied."),
    ComponentSpec("engine.axiom_inventory", (
        "engine.axiom_check_source", "engine.financial_executable", "engine.codec_laws",
        "engine.codec_laws_primitives", "engine.codec_laws_records", "engine.codec_laws_check",
        "engine.theorem_root", "engine.theorem_manifest", "engine.theorem_correspondence",
        "engine.theorem_vectors", "engine.transition_theorems", "engine.reuse", "engine.transition",
        "engine.transition_types", "engine.decision_types", "engine.decision_projection",
        "engine.financial_codec", "engine.financial_evaluation", "engine.financial_specification",
        "engine.financial_types", "engine.sha3", "engine.lean_toolchain", "engine.lakefile",
        "engine.lake_manifest",
    ), "The exact axiom-check import sources are captured; no current-source admitted-axiom output is supplied."),
    ComponentSpec("engine.wire_contract", (
        "engine.transition_types", "engine.codec", "engine.reuse_codec", "engine.reuse",
        "engine.transition", "engine.financial_codec", "engine.financial_evaluation",
        "engine.financial_specification", "engine.financial_types", "engine.decision_types",
        "engine.decision_projection", "engine.decision_codec", "engine.sha3",
    )),
    ComponentSpec("engine.canonical_wire_vectors", (
        "engine.wire_vectors", "engine.theorem_vectors", "financial.expected_answers",
        "engine.transition_types", "engine.codec", "engine.reuse_codec", "engine.reuse",
        "engine.transition", "engine.financial_codec", "engine.financial_evaluation",
        "engine.financial_specification", "engine.financial_types", "engine.decision_types",
        "engine.decision_projection", "engine.decision_codec", "engine.sha3",
    ), "The canonical vector sources are captured; current-source guarded wire-vector evidence is missing."),
    ComponentSpec("engine.executable", (
        "engine.executable", "engine.lean_toolchain", "engine.lakefile", "engine.lake_manifest",
        "engine.cli", "engine.runtime", "engine.transition_types", "engine.transition", "engine.reuse",
        "engine.codec", "engine.reuse_codec", "engine.financial_codec", "engine.financial_evaluation",
        "engine.financial_specification", "engine.financial_types", "engine.decision_types",
        "engine.decision_projection", "engine.decision_codec", "engine.sha3",
    ), "The current executable is not bound to the captured source closure, toolchain, and dependency lock by a trusted build receipt."),
    ComponentSpec("state.owner", ("financial.owner",)),
    ComponentSpec("state.adapter_refinement", (
        "financial.semantic_adapter", "financial.engine_binding",
        "financial.verifier_process", "financial.verifier_resource_limits",
    ), "The financial owner still fails closed at correction_transition_unavailable for the current Engine transition."),
    ComponentSpec("state.independent_checker", ("financial.independent_checker",), "No current-source guarded integration receipt is supplied."),
    ComponentSpec("control_pack_config", (
        "financial.owner", "financial.semantic_adapter", "financial.independent_checker",
        "financial.expected_answers",
    ), "Exact synthetic Control Pack implementation and fixture sources are captured; no State-approved pack instance, identity, or issuer is selected."),
    ComponentSpec("schema_migration", ("financial.owner", "financial.semantic_adapter", "financial.independent_checker"), "Schema versions and migration checks are embedded in these source files; no separately accepted migration artifact or compatibility grant is supplied."),
    ComponentSpec("mirror", ("financial.mirror",)),
    ComponentSpec("report", ("financial.mirror", "financial.staff_server", "financial.staff_index", "financial.staff_script", "financial.staff_style")),
    ComponentSpec("support", ("financial.mirror", "financial.staff_server")),
    ComponentSpec("continuity_restore", ("financial.owner", "financial.semantic_adapter", "financial.independent_checker", "financial.mirror")),
    ComponentSpec("source_receiver_contracts", (
        "financial.source_receiver_contracts", "financial.owner", "financial.semantic_adapter",
        "financial.engine_binding", "financial.independent_checker", "financial.verifier_process",
        "financial.verifier_resource_limits",
    )),
    ComponentSpec("independent_expected_answers", ("financial.expected_answers",), "The fixture source is present; current-source guarded execution evidence is missing."),
    ComponentSpec("bundle_builder", ("qualification.bundle_tool", "qualification.acceptance_entrypoint"), "Local producer and validator identities cannot establish their own integrity or authorize release."),
    ComponentSpec("queue.lifecycle_source", (
        "queue.lifecycle_adapter", "queue.queue_independent", "queue.verifier_process",
        "queue.verifier_resource_limits", "queue.cargo_config", "queue.lifecycle_build",
        "queue.lifecycle_rust", "queue.native_boundary", "queue.cargo_manifest",
        "queue.cargo_lock", "queue.post_link_attester",
        "queue.lifecycle_lean", "queue.lifecycle_lean_root", "queue.lifecycle_model",
        "queue.lifecycle_lean_checker", "queue.lifecycle_lean_library", "queue.lifecycle_lean_main",
        "queue.lean_sha3", "queue.lean_toolchain", "queue.lakefile", "queue.lake_manifest",
    ), "Queue source-bound Lifecycle mode remains closed until current source-to-binary and final-link provenance are independently attested."),
    ComponentSpec("queue.lifecycle_executable", (
        "queue.lifecycle_executable", "queue.cargo_config", "queue.lifecycle_build",
        "queue.lifecycle_rust", "queue.native_boundary", "queue.cargo_manifest", "queue.cargo_lock",
        "queue.post_link_attester", "queue.lifecycle_lean", "queue.lifecycle_lean_root",
        "queue.lifecycle_model", "queue.lifecycle_lean_checker", "queue.lifecycle_lean_library",
        "queue.lifecycle_lean_main", "queue.lean_sha3", "queue.lean_toolchain",
        "queue.lakefile", "queue.lake_manifest",
    ), "The present executable is legacy-pinned and does not attest the current source manifest or final link inputs."),
)

CHECK_IDS = (
    "developer_smoke.bundle_tests",
    "engine.theorem_axiom_check",
    "engine.executable_provenance",
    "engine.canonical_wire_vectors",
    "state.atomic_adapter_integration",
    "state.independent_checker",
    "queue.lifecycle_provenance",
    "guarded.raw_exits",
)

EXTERNAL_GATES: tuple[dict[str, str], ...] = (
    {"id": "issuer", "status": "BLOCKED", "reason": "No independently configured issuer identity or signing authority is selected."},
    {"id": "revocation", "status": "BLOCKED", "reason": "No authenticated revocation snapshot or revocation procedure is supplied."},
    {"id": "source_to_binary_provenance", "status": "BLOCKED", "reason": "No trusted current-source build and final-link receipt binds the executable."},
    {"id": "custody", "status": "BLOCKED", "reason": "No State-approved custody boundary, keys, or recovery owner is selected."},
    {"id": "approved_profile", "status": "UNSELECTED", "reason": "No deployment profile or evidence mode is selected."},
    {"id": "receiver", "status": "UNSELECTED", "reason": "No official receiver or approved receiver test contract is selected."},
    {"id": "independent_audit", "status": "BLOCKED", "reason": "No conflict-separated independent audit receipt is supplied."},
    {"id": "release_control", "status": "BLOCKED", "reason": "Trusted runner, protected branch controls, and independent release authorization are not configured."},
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")

OPERATIONS_TEXT = """# Synthetic financial-correction bundle instructions

This package is a source-bound, nonactivating candidate for one synthetic
financial correction operation. It is not installable or authorized to make
payments. `proofSuiteId` remains null, `production_usable` is false, and
`activation` is false.

## Compatibility

- Preserve each component's exact contract and content digest from
  `MANIFEST.json`. The included financial contracts are source identities,
  not a declaration that an external profile accepts them.
- The captured financial owner source defines schema versions 5, 6, and 7,
  with schema 7 as its default. The narrow prior v5 owner acceptance does not
  qualify this current v7 source packet. No owner schema is selected here.
- The owner, adapter, and checker contain schema and Continuity migration
  handling. Their exact source identity is recorded, but no migration package,
  compatibility grant, or historical-data acceptance is selected.
- Queue/Profile 12 Lifecycle material remains source-only unless its current
  Lean output, Rust final link, executable, and adapter response are bound by
  independently attested evidence.
- Do not substitute a source hash for theorem, axiom, wire-vector, or
  executable evidence. A source change invalidates only components whose
  declared files or dependencies changed; the overall candidate still needs
  a newly assembled source snapshot before release review.
- When run evidence is supplied, pass one canonical UTC
  `--evidence-evaluated-at-utc` value. The archive preserves that exact
  evaluation time so freshness classification is reproducible. The value is
  a caller input, not an authenticated clock or issuer assertion.

## Withdrawal

No issuer, signing key, revocation source, State approval, or release control
is configured. The candidate therefore has no authority to be accepted as a
deployment. A later approved withdrawal must identify the exact artifact and
bundle identities, an authenticated issuer, an authenticated revocation
snapshot, effective time, affected dependents, and the permitted local action.
Never infer revocation from an absent file or a local status flag.

## Rollback

This candidate is not activated. For developer review, discard only the
isolated package copy and retain its manifest and raw evidence. No database,
owner state, dispatch route, or receiver action may be restored from this
source package. Any future deployed rollback requires a State-approved
forward recovery plan that preserves financial history, action identities,
pending receiver outcomes, and the one-writer boundary. Reinstalling an older
binary cannot rewind accepted state.

## Offline verification

Run `python -m tools.deployment_bundle --verify-bundle <bundle.zip>` to check
the archive bytes and fixed manifest policy. Add `--workspace-root <driver>`
to compare the captured source snapshot with the current local checkouts. This
command reports structural and source identity only; it cannot authorize a
profile, integration, release, or activation.
Assembly requires an existing output directory outside the Driver worktrees.
"""

_FILE_BY_ID = {spec.file_id: spec for spec in FILE_SPECS}
_COMPONENT_BY_ID = {spec.component_id: spec for spec in COMPONENT_SPECS}
if len(_FILE_BY_ID) != len(FILE_SPECS) or len(_COMPONENT_BY_ID) != len(COMPONENT_SPECS):
    raise RuntimeError("deployment bundle policy contains duplicate identities")


def _canonical_json(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DeploymentBundleError("bundle data is not canonical JSON") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentBundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise DeploymentBundleError(f"nonfinite JSON number: {value}")


def _parse_json(raw: bytes, *, limit: int) -> Any:
    if len(raw) > limit:
        raise DeploymentBundleError("JSON input exceeds the byte limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DeploymentBundleError("JSON input is malformed") from exc


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _normalise_relative(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise DeploymentBundleError("path must be a non-empty relative POSIX path")
    path = PurePosixPath(value)
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{index}" for index in range(1, 10)), *(f"LPT{index}" for index in range(1, 10))}
    if path.is_absolute() or any(
        part in {"", ".", ".."} or ":" in part or part.endswith((".", " "))
        or part.split(".", 1)[0].upper() in reserved
        for part in path.parts
    ):
        raise DeploymentBundleError(f"path is absolute or traverses: {value}")
    if path.as_posix() != value:
        raise DeploymentBundleError(f"path is not canonical POSIX syntax: {value}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise DeploymentBundleError("path is not valid UTF-8") from exc
    if len(encoded) > 4096:
        raise DeploymentBundleError("path exceeds the byte limit")
    return value


def _valid_git_status(value: object) -> bool:
    return type(value) is str and (
        value == "??"
        or len(value) == 2
        and value != "  "
        and all(char in " MTRADCU" for char in value)
    )


def _is_redirected_path(path: Path) -> bool:
    junction_check = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction_check) and junction_check())


def _safe_file(root: Path, relative: str, *, allow_missing: bool = True) -> Path | None:
    relative = _normalise_relative(relative)
    resolved_root = root.resolve(strict=True)
    candidate = root.joinpath(*relative.split("/"))
    cursor = resolved_root
    for part in relative.split("/"):
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                return None
            raise DeploymentBundleError(f"required source file is missing: {relative}")
        if stat.S_ISLNK(metadata.st_mode) or _is_redirected_path(cursor):
            raise DeploymentBundleError(f"source path contains a redirected path: {relative}")
        try:
            resolved_cursor = cursor.resolve(strict=True)
        except OSError as exc:
            raise DeploymentBundleError(f"source path cannot be resolved: {relative}") from exc
        if resolved_cursor != resolved_root and not resolved_cursor.is_relative_to(resolved_root):
            raise DeploymentBundleError(f"source path escaped its checkout: {relative}")
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise DeploymentBundleError(f"source is not a private regular file: {relative}")
    if candidate.resolve(strict=True).parent != candidate.parent.resolve(strict=True):
        raise DeploymentBundleError(f"source path escaped its directory: {relative}")
    return candidate


def _git(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", *args], cwd=root, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:300]
        raise DeploymentBundleError(f"git command failed ({args[0]}): {detail}")
    return completed.stdout


def _dirty_records(root: Path, status: bytes) -> list[dict[str, Any]]:
    if len(status) > MAX_STATUS_BYTES:
        raise DeploymentBundleError("Git status exceeds the byte limit")
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for item in status.split(b"\x00"):
        if not item:
            continue
        if len(item) < 4 or item[2:3] != b" ":
            raise DeploymentBundleError("Git status record has an unexpected format")
        try:
            code = item[:2].decode("ascii")
            relative = item[3:].decode("utf-8")
        except UnicodeError as exc:
            raise DeploymentBundleError("Git status path is not UTF-8") from exc
        if not _valid_git_status(code):
            raise DeploymentBundleError("Git status code is malformed")
        relative = _normalise_relative(relative)
        if len(records) >= MAX_DIRTY_FILES:
            raise DeploymentBundleError("Git dirty-path count exceeds the limit")
        record: dict[str, Any] = {"status": code, "path": relative, "size": None, "sha256": None}
        path = _safe_file(root, relative)
        if path is not None:
            size = path.stat().st_size
            total_bytes += size
            if total_bytes > MAX_DIRTY_BYTES:
                raise DeploymentBundleError("Git dirty-file bytes exceed the limit")
            record["size"] = size
            record["sha256"] = _hash_file(path, MAX_DIRTY_BYTES)
        records.append(record)
    return sorted(records, key=lambda row: (row["path"], row["status"]))


def _hash_file(path: Path, limit: int) -> str:
    digest = sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise DeploymentBundleError(f"file exceeds the read limit: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    if _is_redirected_path(path):
        raise DeploymentBundleError(f"{label} is redirected")
    data = bytearray()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise DeploymentBundleError(f"{label} is not a regular file")
        if before.st_size > limit:
            raise DeploymentBundleError(f"{label} exceeds the byte limit")
        while True:
            remaining = limit + 1 - len(data)
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise DeploymentBundleError(f"{label} exceeds the byte limit")
        after = os.fstat(handle.fileno())
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(data) != after.st_size
    ):
        raise DeploymentBundleError(f"{label} changed while reading")
    return bytes(data)


def _root_identity(root_id: str, root: Path) -> dict[str, Any]:
    if _is_redirected_path(root) or not root.is_dir() or not (root / ".git").exists():
        raise DeploymentBundleError(f"{root_id} is not a direct Git checkout")
    observed = Path(_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if observed != root.resolve():
        raise DeploymentBundleError(f"{root_id} Git root mismatch")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip().lower()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree):
        raise DeploymentBundleError(f"{root_id} Git identity is malformed")
    branch_raw = subprocess.run(
        ["git", "symbolic-ref", "--short", "-q", "HEAD"], cwd=root,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    branch = branch_raw.stdout.decode("utf-8").strip() if branch_raw.returncode == 0 else None
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
    dirty = _dirty_records(root, status)
    return {
        "id": root_id,
        "head": head,
        "tree": tree,
        "branch": branch,
        "status_sha256": _sha(status),
        "dirty_files": dirty,
        "dirty_count": len(dirty),
    }


def _read_source(
    root: Path, spec: FileSpec, root_identity: Mapping[str, Any]
) -> tuple[dict[str, Any], bytes | None]:
    path = _safe_file(root, spec.path)
    if path is None:
        return {
            "id": spec.file_id,
            "repository": spec.repository,
            "path": spec.path,
            "kind": spec.kind,
            "present": False,
            "included": False,
            "size": None,
            "sha256": None,
            "source_state": "MISSING",
            "archive_path": None,
        }, None
    size = path.stat().st_size
    limit = MAX_EXECUTABLE_HASH_BYTES if spec.kind == "executable" else MAX_PAYLOAD_FILE_BYTES
    if size > limit:
        raise DeploymentBundleError(f"source file exceeds its size limit: {spec.file_id}")
    if spec.include:
        data = _read_bounded(path, limit, f"source file {spec.file_id}")
        if len(data) != size:
            raise DeploymentBundleError(f"source changed while reading: {spec.file_id}")
        digest = _sha(data)
    else:
        data = None
        digest = _hash_file(path, limit)
        if path.stat().st_size != size:
            raise DeploymentBundleError(f"source changed while hashing: {spec.file_id}")
    archive_path = f"payload/{spec.repository}/{spec.path}" if spec.include else None
    source_state = _git_file_state(root, spec.path, root_identity)
    return {
        "id": spec.file_id,
        "repository": spec.repository,
        "path": spec.path,
        "kind": spec.kind,
        "present": True,
        "included": spec.include,
        "size": size,
        "sha256": digest,
        "source_state": source_state,
        "archive_path": archive_path,
    }, data


def _git_file_state(root: Path, relative: str, root_identity: Mapping[str, Any]) -> str:
    dirty = {
        row["path"]: row["status"]
        for row in root_identity["dirty_files"]
    }
    if relative in dirty:
        return f"WORKTREE_DIRTY:{dirty[relative]}"
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative], cwd=root,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if tracked.returncode == 0:
        return "COMMITTED_CLEAN"
    if tracked.returncode != 1:
        raise DeploymentBundleError(f"git could not classify selected source path: {relative}")
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", relative], cwd=root,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if ignored.returncode == 0:
        return "IGNORED"
    if ignored.returncode != 1:
        raise DeploymentBundleError(f"git could not classify ignored source path: {relative}")
    raise DeploymentBundleError(f"selected source is absent from Git status and index: {relative}")


def _component_digest(file_ids: Sequence[str], files: Mapping[str, Mapping[str, Any]]) -> str | None:
    rows = []
    for file_id in sorted(file_ids):
        record = files[file_id]
        if not record["present"]:
            return None
        rows.append({
            "id": file_id,
            "repository": record["repository"],
            "path": record["path"],
            "size": record["size"],
            "sha256": record["sha256"],
        })
    return _sha(_canonical_json(rows))


def _component_records(files: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for spec in sorted(COMPONENT_SPECS, key=lambda item: item.component_id):
        digest = _component_digest(spec.file_ids, files)
        missing = [file_id for file_id in spec.file_ids if not files[file_id]["present"]]
        if missing:
            status = "MISSING"
            reason = "Missing component files: " + ", ".join(missing)
        elif spec.reason_if_unselected:
            status = "UNSELECTED"
            reason = spec.reason_if_unselected
        else:
            status = "SOURCE_PRESENT_UNVERIFIED"
            reason = "Exact source bytes are captured; execution, approval, and authority are not inferred from their hashes."
        result.append({
            "id": spec.component_id,
            "file_ids": list(spec.file_ids),
            "artifact_sha256": digest,
            "status": status,
            "runtime_selected": False,
            "reason": reason,
        })
    return result


def _compatibility_record(components: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_id = {item["id"]: item for item in components}
    return {
        "source_contracts": [
            "RR/FINANCIAL/OWNER/v5",
            "RR/FINANCIAL/OWNER/v6",
            "RR/FINANCIAL/OWNER/v7",
            "RR/FINANCIAL/CONTINUITY/v5",
            "RR/FINANCIAL/CONTINUITY/v6",
            "RR/FINANCIAL/CONTINUITY/v7",
            "RR/FINANCIAL/EVALUATION-RECEIPT/v1",
            "RR/FINANCIAL/CORRECTION-FOLLOWUP/v1",
            "BLFCMD01/BLFCRES1",
        ],
        "owner_schema_versions": [5, 6, 7],
        "owner_default_schema_version": 7,
        "selected_owner_schema_version": None,
        "control_pack_component_sha256": by_id["control_pack_config"]["artifact_sha256"],
        "queue_contracts": ["schema-13", "profile-12"],
        "migration_component_sha256": by_id["schema_migration"]["artifact_sha256"],
        "migration_status": "SOURCE_IDENTITIES_ONLY_UNSELECTED",
        "status": "SOURCE_IDENTITIES_ONLY_UNSELECTED",
    }


def _source_identity(
    roots: Sequence[Mapping[str, Any]], files: Sequence[Mapping[str, Any]],
    producer: Mapping[str, Any], workspace_map: Mapping[str, Any],
) -> str:
    stable_files = [
        {key: row[key] for key in ("id", "repository", "path", "kind", "present", "included", "size", "sha256", "source_state", "archive_path")}
        for row in sorted(files, key=lambda item: item["id"])
    ]
    stable_roots = sorted(roots, key=lambda item: item["id"])
    return _sha(_canonical_json({
        "source_roots": stable_roots,
        "files": stable_files,
        "producer": dict(producer),
        "workspace_map": dict(workspace_map),
    }))


def _utc(value: object) -> datetime | None:
    if type(value) is not str:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _canonical_utc(value: object) -> datetime | None:
    parsed = _utc(value)
    if parsed is None:
        return None
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return parsed if value == canonical else None


def _classify_evidence(
    record: Mapping[str, Any] | None,
    expected_source_sha256: str,
    evaluated_at: datetime | None,
) -> tuple[str, str, list[dict[str, Any]]]:
    if record is None:
        return "MISSING", "No run evidence was supplied for this check.", []
    logs: list[dict[str, Any]] = []
    check_id = record.get("id") if type(record) is dict else None
    if type(check_id) is str and check_id in CHECK_IDS:
        for stream in ("command_stdout", "command_stderr", "guard_stdout", "guard_stderr"):
            raw = record.get(stream)
            if type(raw) is bytes and len(raw) <= MAX_EVIDENCE_LOG_BYTES:
                logs.append({
                    "member": f"evidence/{check_id}/{stream}.log",
                    "size": len(raw),
                    "sha256": _sha(raw),
                    "bytes": raw,
                })
    required = {
        "id", "status", "source_identity_sha256", "command", "runner_id",
        "issuer_id", "revocation_snapshot_sha256", "signature",
        "issued_at_utc", "expires_at_utc", "tests", "skipped",
        "child_exit_code", "outer_exit_code", "guard_sha256",
        "target_start_floor_bytes", "preflight_free_bytes",
        "physical_free_floor_bytes", "cleanup", "mutex", "command_stdout",
        "command_stderr", "guard_stdout", "guard_stderr",
    }
    if type(record) is not dict or set(record) != required:
        return "INVALID", "Evidence fields do not match the bounded run-evidence contract.", logs
    if evaluated_at is None:
        return "INVALID", "Evidence has no explicit canonical evaluation time.", logs
    if type(record["id"]) is not str or record["id"] not in CHECK_IDS:
        return "INVALID", "Evidence check id is not recognized by this bundle version.", logs
    if type(record["status"]) is not str:
        return "INVALID", "Evidence status is malformed.", logs
    raw_logs = tuple(record[name] for name in (
        "command_stdout", "command_stderr", "guard_stdout", "guard_stderr",
    ))
    if any(value is not None and type(value) is not bytes for value in raw_logs):
        return "INVALID", "A raw log is not a byte string or an explicit missing value.", logs
    if any(type(value) is bytes and len(value) > MAX_EVIDENCE_LOG_BYTES for value in raw_logs):
        return "INVALID", "A guarded raw log exceeds the evidence byte limit.", []
    logs_missing = any(type(value) is not bytes for value in raw_logs)
    if record["status"] in {"FAIL", "FAILED"}:
        reason = "The recorded run failed; one or more raw logs are missing." if logs_missing else "The recorded run failed."
        return "FAILED", reason, logs
    if record["status"] in {"SKIP", "SKIPPED"}:
        reason = "The recorded check was skipped; one or more raw logs are missing." if logs_missing else "The recorded check was skipped."
        return "SKIPPED", reason, logs
    if record["status"] != "PASS":
        return "INVALID", "Evidence status is not PASS, FAIL, or SKIPPED.", logs
    for field in ("source_identity_sha256", "runner_id", "issuer_id", "signature", "cleanup", "mutex"):
        if type(record[field]) is not str:
            return "INVALID", f"Evidence field {field} is malformed.", logs
    if type(record["command"]) is not list or not record["command"] or any(type(arg) is not str or not arg for arg in record["command"]):
        return "INVALID", "Evidence command must be a non-empty argument vector.", logs
    if record["revocation_snapshot_sha256"] is not None and (
        type(record["revocation_snapshot_sha256"]) is not str
        or not _HEX64.fullmatch(record["revocation_snapshot_sha256"])
    ):
        return "INVALID", "Revocation snapshot identity is malformed.", logs
    if record["source_identity_sha256"] != expected_source_sha256:
        return "STALE", "Evidence names a different source identity.", logs
    if type(record["tests"]) is not int or record["tests"] < 1:
        return "EMPTY", "The recorded run contains no executed tests.", logs
    if type(record["skipped"]) is not int or record["skipped"] < 0:
        return "INVALID", "Skipped-test count is malformed.", logs
    if record["skipped"]:
        return "SKIPPED", "The recorded run contains skipped tests.", logs
    if type(record["child_exit_code"]) is not int or type(record["outer_exit_code"]) is not int:
        return "INVALID", "Child or outer command exit code is malformed.", logs
    if record["child_exit_code"] != 0 or record["outer_exit_code"] != 0:
        return "FAILED", "A child or outer command exit was nonzero.", logs
    if record["guard_sha256"] != GUARD_SHA256:
        return "INVALID", "Evidence does not name the required v4 guard identity.", logs
    if type(record["physical_free_floor_bytes"]) is not int:
        return "INVALID", "Physical-free floor is malformed.", logs
    if record["physical_free_floor_bytes"] != PHYSICAL_FREE_FLOOR_BYTES:
        return "INVALID", "Evidence does not retain the current physical-free floor.", logs
    floor = record["target_start_floor_bytes"]
    free = record["preflight_free_bytes"]
    if type(floor) is not int or floor < PHYSICAL_FREE_FLOOR_BYTES or type(free) is not int:
        return "INVALID", "Target-specific preflight values are missing or malformed.", logs
    if free < floor:
        return "FAILED", "Fresh preflight was below the target-specific start floor.", logs
    if record["cleanup"] != "PASS" or record["mutex"] != "RELEASED":
        return "FAILED", "Guard cleanup or mutex release was not verified.", logs
    issued = _utc(record["issued_at_utc"])
    expires = _utc(record["expires_at_utc"])
    if issued is None or expires is None or expires <= issued:
        return "STALE", "Evidence timestamps are malformed.", logs
    if issued > evaluated_at or expires <= evaluated_at:
        return "STALE", "Evidence was not yet issued or had expired at its recorded evaluation time.", logs
    stdout = record["guard_stdout"]
    if logs_missing:
        return "EMPTY", "One or more guarded command or wrapper logs are missing.", logs
    if not stdout:
        return "EMPTY", "Guarded stdout is empty; raw preflight, exits, and cleanup are unavailable.", logs
    try:
        transcript = stdout.decode("utf-8")
    except UnicodeError:
        return "INVALID", "Guarded stdout is not UTF-8 and its exit transcript cannot be read.", logs
    preflight = re.findall(
        r"(?m)^PHYSICAL_PREFLIGHT free_bytes=(\d+) reserve_bytes=(\d+) reserve_floor_bytes=(\d+) target_start_floor_bytes=(\d+) effective_start_floor_bytes=(\d+) tolerance_percent=(\d+)$",
        transcript,
    )
    if len(preflight) != 1 or tuple(map(int, preflight[0])) != (
        free,
        PHYSICAL_RESERVE_BYTES,
        PHYSICAL_FREE_FLOOR_BYTES,
        floor,
        max(floor, PHYSICAL_FREE_FLOOR_BYTES),
        PHYSICAL_RESERVE_TOLERANCE_PERCENT,
    ):
        return "INVALID", "Raw v4 preflight line does not match the recorded free bytes and floors.", logs
    if "CHILD_EXIT_CHECK exit7=7 exit0=0" not in transcript:
        return "INVALID", "Raw v4 child-exit self-check is missing or failed.", logs
    guarded_children = re.findall(r"(?m)^CHILD_EXIT_STATUS label=([^\s]+) exit=(-?\d+)$", transcript)
    main_children = [
        (label, int(code)) for label, code in guarded_children
        if label not in {"child-exit-7", "child-exit-0"}
    ]
    if len(main_children) != 1 or main_children[0][1] != record["child_exit_code"]:
        return "INVALID", "Raw v4 child exit line does not match the recorded command exit.", logs
    main_label = main_children[0][0]
    if f"CLEANUP=PASS label={main_label} owned_process_tree=empty" not in transcript or "CLEANUP=FAIL" in transcript:
        return "FAILED", "Raw v4 cleanup result is missing or failed.", logs
    mutex_line = "MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907"
    if transcript.count(mutex_line) != 1 or "MUTEX=HELD_UNTIL_PROCESS_EXIT" in transcript:
        return "FAILED", "Raw v4 mutex release is missing or failed.", logs
    if "RUNNER_FAILURE " in transcript or b"RUNNER_FAILURE " in record["guard_stderr"]:
        return "FAILED", "Raw v4 runner reported a failure.", logs
    if record["runner_id"] == "" or record["issuer_id"] == "" or record["signature"] == "":
        return "UNVERIFIED", "Raw exits are bound, but runner issuer/signature verification is not configured.", logs
    if record["revocation_snapshot_sha256"] in {None, ""}:
        return "UNVERIFIED", "Raw exits are bound, but no authenticated revocation snapshot is supplied.", logs
    return "RECORDED_UNVERIFIED", "Record and raw log digests are internally consistent; no trusted verifier is configured.", logs


def _evidence_records(
    records: Iterable[Mapping[str, Any]],
    source_identity_sha256: str,
    evaluated_at: datetime | None,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if type(record) is not dict or type(record.get("id")) is not str:
            raise DeploymentBundleError("run-evidence record is malformed")
        for stream in ("command_stdout", "command_stderr", "guard_stdout", "guard_stderr"):
            raw = record.get(stream)
            if type(raw) is bytes and len(raw) > MAX_EVIDENCE_LOG_BYTES:
                raise DeploymentBundleError(f"run-evidence {stream} exceeds the byte limit and cannot be retained")
        if record["id"] in by_id:
            raise DeploymentBundleError(f"duplicate run-evidence record: {record['id']}")
        by_id[record["id"]] = record
    if set(by_id) - set(CHECK_IDS):
        raise DeploymentBundleError("run-evidence contains an unknown check id")
    output: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    total = 0
    for check_id in CHECK_IDS:
        record = by_id.get(check_id)
        status, reason, logs = _classify_evidence(record, source_identity_sha256, evaluated_at)
        if record is not None:
            for log in logs:
                total += log["size"]
                if total > MAX_EVIDENCE_TOTAL_BYTES:
                    raise DeploymentBundleError("run-evidence logs exceed the aggregate byte limit")
                payloads[log["member"]] = log.pop("bytes")
        output.append({
            "id": check_id,
            "status": status,
            "reason": reason,
            "record": _evidence_record_without_bytes(record) if record is not None else None,
            "raw_logs": [{key: value for key, value in log.items()} for log in logs],
        })
    return output, payloads


def _evidence_record_without_bytes(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in record.items()
        if key not in {"command_stdout", "command_stderr", "guard_stdout", "guard_stderr"}
    }


def load_evidence_file(path: Path, evidence_root: Path) -> list[dict[str, Any]]:
    if _is_redirected_path(path) or not path.is_file():
        raise DeploymentBundleError("evidence file is missing, redirected, or oversized")
    raw = _read_bounded(path, MAX_MANIFEST_BYTES, "evidence file")
    document = _parse_json(raw, limit=MAX_MANIFEST_BYTES)
    if type(document) is not dict or set(document) != {"schema", "records"} or document["schema"] != EVIDENCE_SCHEMA:
        raise DeploymentBundleError("evidence file has the wrong schema")
    if type(document["records"]) is not list or len(document["records"]) > len(CHECK_IDS):
        raise DeploymentBundleError("evidence record list is malformed or oversized")
    if _is_redirected_path(evidence_root) or not evidence_root.is_dir():
        raise DeploymentBundleError("evidence root is missing or redirected")
    root = evidence_root.resolve(strict=True)
    result = []
    for raw_record in document["records"]:
        if type(raw_record) is not dict:
            raise DeploymentBundleError("evidence record is not an object")
        streams = ("command_stdout", "command_stderr", "guard_stdout", "guard_stderr")
        expected = {"record", *(f"{stream}_path" for stream in streams)}
        if set(raw_record) != expected or type(raw_record["record"]) is not dict:
            raise DeploymentBundleError("evidence record wrapper has unexpected fields")
        value = dict(raw_record["record"])
        for stream in streams:
            relative = raw_record[f"{stream}_path"]
            if relative is None:
                value[stream] = None
                continue
            relative = _normalise_relative(relative)
            log_path = _safe_file(root, relative, allow_missing=False)
            assert log_path is not None
            value[stream] = _read_bounded(log_path, MAX_EVIDENCE_LOG_BYTES, "raw evidence log")
        result.append(value)
    return result


def _external_gate_records() -> list[dict[str, str]]:
    return [dict(item) for item in EXTERNAL_GATES]


def _phase_claims(evidence: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    evidence_by_id = {record["id"]: record for record in evidence}
    smoke = evidence_by_id["developer_smoke.bundle_tests"]["status"]
    if smoke == "MISSING":
        smoke_status = "NOT_RUN"
    elif smoke in {"FAILED", "SKIPPED", "STALE", "EMPTY", "INVALID"}:
        smoke_status = "BLOCKED"
    else:
        smoke_status = "UNVERIFIED"
    blocking_evidence = [
        {"id": item["id"], "status": item["status"]}
        for item in evidence if item["status"] != "VERIFIED"
    ]
    return {
        "developer_smoke": {
            "status": smoke_status,
            "evidence_status": smoke,
            "authority": "LOCAL_ADVISORY_ONLY",
        },
        "integration": {
            "status": "BLOCKED",
            "blocking_evidence": blocking_evidence,
            "authority": "TRUSTED_RUNNER_NOT_CONFIGURED",
        },
        "release": {
            "status": "BLOCKED",
            "blocking_gates": [item["id"] for item in EXTERNAL_GATES if item["status"] != "PASS"],
            "authority": "INDEPENDENT_RELEASE_CONTROL_NOT_CONFIGURED",
        },
        "activation": {
            "status": "UNSELECTED",
            "authority": "STATE_APPROVAL_AND_PROFILE_NOT_SELECTED",
        },
    }


def _producer_identity(qualification_root: Path) -> dict[str, Any]:
    tool_path = _safe_file(qualification_root, "tools/deployment_bundle.py", allow_missing=False)
    acceptance_path = _safe_file(qualification_root, "tools/project_acceptance.py", allow_missing=False)
    assert tool_path is not None and acceptance_path is not None
    return {
        "tool": {"path": "tools/deployment_bundle.py", "size": tool_path.stat().st_size, "sha256": _hash_file(tool_path, MAX_PAYLOAD_FILE_BYTES)},
        "entry_point": {"path": "tools/project_acceptance.py", "size": acceptance_path.stat().st_size, "sha256": _hash_file(acceptance_path, MAX_PAYLOAD_FILE_BYTES)},
        "assurance": "CANDIDATE_SOURCE_IDENTITY_ONLY",
    }


def _make_zip(manifest_bytes: bytes, payloads: Mapping[str, bytes]) -> bytes:
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise DeploymentBundleError("deployment manifest exceeds the byte limit")
    all_payloads = {OPERATIONS_NAME: OPERATIONS_TEXT.encode("utf-8"), **payloads}
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        members = [(MANIFEST_NAME, manifest_bytes)] + sorted(all_payloads.items())
        for name, data in members:
            _normalise_relative(name)
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.flag_bits = 0
            info.file_size = len(data)
            archive.writestr(info, data)
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        raise DeploymentBundleError("deployment archive exceeds the byte limit")
    return result


def build_candidate(
    workspace_root: Path,
    *,
    evidence_records: Iterable[Mapping[str, Any]] = (),
    evidence_evaluated_at_utc: str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Build the actual fixed-scope candidate package from current worktrees."""
    evidence_records = tuple(evidence_records)
    if evidence_records:
        evaluated_at = _canonical_utc(evidence_evaluated_at_utc)
        if evaluated_at is None:
            raise DeploymentBundleError(
                "run evidence requires an explicit canonical evidence_evaluated_at_utc"
            )
    else:
        if evidence_evaluated_at_utc is not None:
            raise DeploymentBundleError("evidence evaluation time was supplied without run evidence")
        evaluated_at = None
    if _is_redirected_path(workspace_root) or not workspace_root.is_dir():
        raise DeploymentBundleError("workspace root is missing or redirected")
    workspace = workspace_root.resolve(strict=True)
    work = workspace / "work"
    if _is_redirected_path(work) or not work.is_dir():
        raise DeploymentBundleError("workspace map or work directory is missing or redirected")
    workspace_map_path = _safe_file(workspace, WORKSPACE_MAP_RELATIVE, allow_missing=False)
    assert workspace_map_path is not None
    workspace_map_bytes = _read_bounded(
        workspace_map_path, MAX_PAYLOAD_FILE_BYTES, "workspace map"
    )
    workspace_map = {
        "path": WORKSPACE_MAP_RELATIVE,
        "size": len(workspace_map_bytes),
        "sha256": _sha(workspace_map_bytes),
        "archive_path": WORKSPACE_MAP_MEMBER,
    }
    roots: dict[str, Path] = {}
    for repository, directory in PROJECT_ROOTS.items():
        path = work / directory
        if path.resolve(strict=True).parent != work.resolve(strict=True):
            raise DeploymentBundleError(f"{repository} checkout escaped the workspace")
        roots[repository] = path
    root_records = [_root_identity(repository, roots[repository]) for repository in sorted(roots)]
    file_records: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {WORKSPACE_MAP_MEMBER: workspace_map_bytes}
    file_record_map: dict[str, dict[str, Any]] = {}
    for spec in FILE_SPECS:
        root_identity = next(row for row in root_records if row["id"] == spec.repository)
        record, data = _read_source(roots[spec.repository], spec, root_identity)
        if spec.include and data is None:
            raise DeploymentBundleError(f"required source file is missing: {spec.file_id}")
        file_records.append(record)
        file_record_map[spec.file_id] = record
        if data is not None and spec.include:
            assert record["archive_path"] is not None
            payloads[record["archive_path"]] = data
    producer = _producer_identity(roots["qualification"])
    source_identity_sha256 = _source_identity(root_records, file_records, producer, workspace_map)
    evidence, evidence_payloads = _evidence_records(evidence_records, source_identity_sha256, evaluated_at)
    payloads.update(evidence_payloads)
    components = _component_records(file_record_map)
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "bundle_version": 1,
        "purpose": "one synthetic financial correction operation",
        "classification": "SYNTHETIC_NONPHI_NONPAYMENT_NONACTIVATING",
        "source_identity_sha256": source_identity_sha256,
        "workspace_map": workspace_map,
        "source_roots": root_records,
        "files": sorted(file_records, key=lambda item: item["id"]),
        "components": components,
        "evidence": evidence,
        "evidence_evaluated_at_utc": evidence_evaluated_at_utc,
        "external_gates": _external_gate_records(),
        "phase_claims": _phase_claims(evidence),
        "compatibility": _compatibility_record(components),
        "operations_sha256": _sha(OPERATIONS_TEXT.encode("utf-8")),
        "producer": producer,
        "claims": {"proofSuiteId": None, "production_usable": False, "activation": False},
    }
    manifest_bytes = _canonical_json(manifest)
    archive_bytes = _make_zip(manifest_bytes, payloads)
    validation = validate_bundle_bytes(archive_bytes)
    if not validation["structural_valid"]:
        raise DeploymentBundleError("assembled bundle failed independent byte validation")
    # Recheck the exact checkout and file identities after packaging. This catches
    # edits racing the bundle read; it does not establish that a trusted runner ran.
    after_roots = [_root_identity(repository, roots[repository]) for repository in sorted(roots)]
    if _canonical_json(after_roots) != _canonical_json(root_records):
        raise DeploymentBundleError("source root changed during bundle assembly")
    for spec in FILE_SPECS:
        record = file_record_map[spec.file_id]
        root_identity = next(row for row in after_roots if row["id"] == spec.repository)
        current, _ = _read_source(roots[spec.repository], spec, root_identity)
        if _canonical_json(current) != _canonical_json(record):
            raise DeploymentBundleError(f"source file changed during bundle assembly: {spec.file_id}")
    final_roots = [_root_identity(repository, roots[repository]) for repository in sorted(roots)]
    if _canonical_json(final_roots) != _canonical_json(root_records):
        raise DeploymentBundleError("source root changed during bundle assembly")
    final_map = _safe_file(workspace, WORKSPACE_MAP_RELATIVE, allow_missing=False)
    assert final_map is not None
    if _read_bounded(final_map, MAX_PAYLOAD_FILE_BYTES, "workspace map") != workspace_map_bytes:
        raise DeploymentBundleError("workspace map changed during bundle assembly")
    report = {
        "schema": SCHEMA,
        "structural_status": "VALIDATED_FROM_ARCHIVE_BYTES",
        "archive_size": len(archive_bytes),
        "archive_sha256": _sha(archive_bytes),
        "manifest_sha256": _sha(manifest_bytes),
        "source_identity_sha256": source_identity_sha256,
        "status": "CANDIDATE_ASSEMBLED_RELEASE_BLOCKED",
        "component_count": len(components),
        "included_file_count": sum(1 for row in file_records if row["included"] and row["present"]),
        "missing_file_count": sum(1 for row in file_records if not row["present"]),
        "evidence_statuses": {item["id"]: item["status"] for item in evidence},
        "evidence_evaluated_at_utc": evidence_evaluated_at_utc,
        "phase_claims": manifest["phase_claims"],
        "external_gates": manifest["external_gates"],
        "release_status": "BLOCKED",
        "activation_status": "UNSELECTED",
        "validation": validation,
    }
    return archive_bytes, report


def _manifest_from_zip(archive_bytes: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    if type(archive_bytes) is not bytes or not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise DeploymentBundleError("bundle bytes are missing or exceed the archive limit")
    try:
        archive = zipfile.ZipFile(BytesIO(archive_bytes), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise DeploymentBundleError("bundle archive is malformed") from exc
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise DeploymentBundleError("bundle contains duplicate member paths")
        if not names or names[0] != MANIFEST_NAME:
            raise DeploymentBundleError("bundle manifest is not the first archive member")
        if archive.comment or names[1:] != sorted(names[1:]):
            raise DeploymentBundleError("bundle member order or archive comment is not canonical")
        payloads: dict[str, bytes] = {}
        for info in infos:
            _normalise_relative(info.filename)
            mode = info.external_attr >> 16
            if mode != (stat.S_IFREG | 0o644) or info.is_dir():
                raise DeploymentBundleError("bundle member is not a canonical regular file")
            if (
                info.compress_type != zipfile.ZIP_STORED or info.flag_bits != 0
                or info.date_time != (1980, 1, 1, 0, 0, 0)
                or info.create_system != 3 or info.extra or info.comment
            ):
                raise DeploymentBundleError("bundle member metadata is not canonical")
            if info.file_size > MAX_ARCHIVE_BYTES:
                raise DeploymentBundleError("bundle member exceeds the byte limit")
            try:
                payloads[info.filename] = archive.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
                raise DeploymentBundleError("bundle member bytes are malformed") from exc
        manifest_raw = payloads.pop(MANIFEST_NAME)
    manifest = _parse_json(manifest_raw, limit=MAX_MANIFEST_BYTES)
    if type(manifest) is not dict:
        raise DeploymentBundleError("bundle manifest is not an object")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    if manifest_raw != canonical:
        raise DeploymentBundleError("bundle manifest is not canonical JSON")
    return manifest, payloads


def _validate_manifest(manifest: Mapping[str, Any], payloads: Mapping[str, bytes]) -> dict[str, Any]:
    required_top = {
        "schema", "bundle_version", "purpose", "classification", "source_identity_sha256",
        "workspace_map", "evidence_evaluated_at_utc",
        "source_roots", "files", "components", "evidence", "external_gates",
        "phase_claims", "compatibility", "operations_sha256", "producer", "claims",
    }
    if set(manifest) != required_top or manifest.get("schema") != SCHEMA or type(manifest.get("bundle_version")) is not int or manifest["bundle_version"] != 1:
        raise DeploymentBundleError("bundle manifest has an unexpected schema or field set")
    if manifest["purpose"] != "one synthetic financial correction operation":
        raise DeploymentBundleError("bundle purpose changed")
    if manifest["classification"] != "SYNTHETIC_NONPHI_NONPAYMENT_NONACTIVATING":
        raise DeploymentBundleError("bundle classification is not the fixed synthetic boundary")
    if manifest["claims"] != {"proofSuiteId": None, "production_usable": False, "activation": False}:
        raise DeploymentBundleError("bundle claims attempt to exceed the fixed nonactivation boundary")
    if not _HEX64.fullmatch(str(manifest["source_identity_sha256"])):
        raise DeploymentBundleError("source identity digest is malformed")
    if (
        type(manifest["source_roots"]) is not list
        or any(type(row) is not dict for row in manifest["source_roots"])
        or [row.get("id") for row in manifest["source_roots"]] != sorted(PROJECT_ROOTS)
    ):
        raise DeploymentBundleError("source-root inventory is incomplete or unordered")
    if (
        type(manifest["files"]) is not list
        or any(type(row) is not dict for row in manifest["files"])
        or [row.get("id") for row in manifest["files"]] != sorted(_FILE_BY_ID)
    ):
        raise DeploymentBundleError("file identity inventory is incomplete or unordered")
    files = {row["id"]: row for row in manifest["files"]}
    expected_members = {OPERATIONS_NAME, WORKSPACE_MAP_MEMBER}
    workspace_map = manifest["workspace_map"]
    if (
        type(workspace_map) is not dict
        or set(workspace_map) != {"path", "size", "sha256", "archive_path"}
        or workspace_map["path"] != WORKSPACE_MAP_RELATIVE
        or workspace_map["archive_path"] != WORKSPACE_MAP_MEMBER
        or type(workspace_map["size"]) is not int
        or workspace_map["size"] < 0 or workspace_map["size"] > MAX_PAYLOAD_FILE_BYTES
        or type(workspace_map["sha256"]) is not str
        or not _HEX64.fullmatch(workspace_map["sha256"])
    ):
        raise DeploymentBundleError("workspace map identity is malformed")
    workspace_map_bytes = payloads.get(WORKSPACE_MAP_MEMBER)
    if (
        type(workspace_map_bytes) is not bytes
        or len(workspace_map_bytes) != workspace_map["size"]
        or _sha(workspace_map_bytes) != workspace_map["sha256"]
    ):
        raise DeploymentBundleError("workspace map payload does not match its identity")
    for spec in FILE_SPECS:
        row = files[spec.file_id]
        if set(row) != {"id", "repository", "path", "kind", "present", "included", "size", "sha256", "source_state", "archive_path"}:
            raise DeploymentBundleError(f"file identity fields are invalid: {spec.file_id}")
        if (
            (row["repository"], row["path"], row["kind"]) != (spec.repository, spec.path, spec.kind)
            or type(row["included"]) is not bool or row["included"] is not spec.include
        ):
            raise DeploymentBundleError(f"file identity is not the selected policy input: {spec.file_id}")
        if type(row["present"]) is not bool:
            raise DeploymentBundleError(f"file presence flag is malformed: {spec.file_id}")
        if row["present"]:
            if (
                type(row["size"]) is not int or row["size"] < 0
                or row["size"] > (MAX_EXECUTABLE_HASH_BYTES if spec.kind == "executable" else MAX_PAYLOAD_FILE_BYTES)
                or type(row["sha256"]) is not str or not _HEX64.fullmatch(row["sha256"])
                or type(row["source_state"]) is not str
            ):
                raise DeploymentBundleError(f"file digest or size is malformed: {spec.file_id}")
            source_state = row["source_state"]
            dirty_code = source_state.removeprefix("WORKTREE_DIRTY:")
            if not (
                source_state in {"COMMITTED_CLEAN", "IGNORED"}
                or source_state.startswith("WORKTREE_DIRTY:")
                and _valid_git_status(dirty_code)
            ):
                raise DeploymentBundleError(f"file Git state is malformed: {spec.file_id}")
            if spec.include:
                if not row["included"]:
                    raise DeploymentBundleError(f"required source file is not selected: {spec.file_id}")
                expected_member = f"payload/{spec.repository}/{spec.path}"
                if row["archive_path"] != expected_member or expected_member not in payloads:
                    raise DeploymentBundleError(f"source payload is missing: {spec.file_id}")
                data = payloads[expected_member]
                if len(data) != row["size"] or _sha(data) != row["sha256"]:
                    raise DeploymentBundleError(f"source payload digest mismatch: {spec.file_id}")
                expected_members.add(expected_member)
            elif row["archive_path"] is not None:
                raise DeploymentBundleError(f"unselected executable was packaged: {spec.file_id}")
        elif spec.include:
            raise DeploymentBundleError(f"required source file is missing: {spec.file_id}")
        elif row["size"] is not None or row["sha256"] is not None or row["archive_path"] is not None or row["source_state"] != "MISSING":
            raise DeploymentBundleError(f"missing file record contains a source identity: {spec.file_id}")
    operations = payloads.get(OPERATIONS_NAME)
    if operations != OPERATIONS_TEXT.encode("utf-8") or manifest["operations_sha256"] != _sha(OPERATIONS_TEXT.encode("utf-8")):
        raise DeploymentBundleError("compatibility, withdrawal, or rollback instructions changed")
    producer = manifest["producer"]
    if type(producer) is not dict or set(producer) != {"tool", "entry_point", "assurance"} or producer.get("assurance") != "CANDIDATE_SOURCE_IDENTITY_ONLY":
        raise DeploymentBundleError("bundle producer identity is malformed")
    for name, file_id, path in (
        ("tool", "qualification.bundle_tool", "tools/deployment_bundle.py"),
        ("entry_point", "qualification.acceptance_entrypoint", "tools/project_acceptance.py"),
    ):
        item = producer.get(name)
        if (
            type(item) is not dict or set(item) != {"path", "size", "sha256"}
            or item["path"] != path or type(item["size"]) is not int
            or item["size"] <= 0 or item["size"] > MAX_PAYLOAD_FILE_BYTES
            or type(item["sha256"]) is not str or not _HEX64.fullmatch(item["sha256"])
            or files[file_id]["size"] != item["size"] or files[file_id]["sha256"] != item["sha256"]
        ):
            raise DeploymentBundleError("bundle producer source identity is malformed")
    roots = manifest["source_roots"]
    for root in roots:
        if type(root) is not dict or set(root) != {"id", "head", "tree", "branch", "status_sha256", "dirty_files", "dirty_count"}:
            raise DeploymentBundleError("source-root identity record is malformed")
        if (
            type(root["id"]) is not str or root["id"] not in PROJECT_ROOTS
            or type(root["head"]) is not str or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", root["head"])
            or type(root["tree"]) is not str or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", root["tree"])
            or root["branch"] is not None and type(root["branch"]) is not str
            or type(root["status_sha256"]) is not str or not _HEX64.fullmatch(root["status_sha256"])
        ):
            raise DeploymentBundleError("source-root identity digest is malformed")
        if (
            type(root["dirty_files"]) is not list or type(root["dirty_count"]) is not int
            or root["dirty_count"] != len(root["dirty_files"])
        ):
            raise DeploymentBundleError("dirty-file identity list is malformed")
        if len(root["dirty_files"]) > MAX_DIRTY_FILES:
            raise DeploymentBundleError("Git dirty-path count exceeds the limit")
        seen_dirty: set[str] = set()
        dirty_bytes = 0
        for dirty in root["dirty_files"]:
            if type(dirty) is not dict or set(dirty) != {"status", "path", "size", "sha256"}:
                raise DeploymentBundleError("dirty-file identity record is malformed")
            path = _normalise_relative(dirty["path"])
            if path in seen_dirty:
                raise DeploymentBundleError("dirty-file identity is duplicated")
            seen_dirty.add(path)
            if not _valid_git_status(dirty["status"]):
                raise DeploymentBundleError("dirty-file Git status is malformed")
            if dirty["size"] is None:
                if dirty["sha256"] is not None:
                    raise DeploymentBundleError("missing dirty-file size has a digest")
            elif (
                type(dirty["size"]) is not int or dirty["size"] < 0
                or dirty["size"] > MAX_DIRTY_BYTES or type(dirty["sha256"]) is not str
                or not _HEX64.fullmatch(dirty["sha256"])
            ):
                raise DeploymentBundleError("dirty-file digest is malformed")
            else:
                dirty_bytes += dirty["size"]
                if dirty_bytes > MAX_DIRTY_BYTES:
                    raise DeploymentBundleError("Git dirty-file bytes exceed the limit")
        if root["dirty_files"] != sorted(root["dirty_files"], key=lambda row: (row["path"], row["status"])):
            raise DeploymentBundleError("dirty-file identities are not ordered")
    recomputed_source = _source_identity(roots, manifest["files"], producer, workspace_map)
    if recomputed_source != manifest["source_identity_sha256"]:
        raise DeploymentBundleError("source identity digest does not match the manifest inputs")
    components = manifest["components"]
    if (
        type(components) is not list or any(type(row) is not dict for row in components)
        or [row.get("id") for row in components] != sorted(_COMPONENT_BY_ID)
    ):
        raise DeploymentBundleError("component inventory is incomplete or unordered")
    file_map = {file_id: row for file_id, row in files.items()}
    if components != _component_records(file_map):
        raise DeploymentBundleError("component identities, statuses, or reasons do not match the fixed policy")
    evaluated_at_text = manifest["evidence_evaluated_at_utc"]
    if evaluated_at_text is None:
        evaluated_at = None
    else:
        evaluated_at = _canonical_utc(evaluated_at_text)
        if evaluated_at is None:
            raise DeploymentBundleError("evidence evaluation time is not canonical UTC")
    entries = manifest["evidence"]
    has_evidence_records = (
        type(entries) is list
        and any(type(entry) is dict and entry.get("record") is not None for entry in entries)
    )
    if has_evidence_records is not (evaluated_at is not None):
        raise DeploymentBundleError("evidence evaluation time does not match the supplied run records")
    evidence, evidence_payloads = _validate_evidence_manifest(
        entries, manifest["source_identity_sha256"], payloads, evaluated_at,
    )
    evidence_bytes = sum(len(data) for data in evidence_payloads.values())
    if evidence_bytes > MAX_EVIDENCE_TOTAL_BYTES:
        raise DeploymentBundleError("run-evidence logs exceed the aggregate byte limit")
    expected_members.update(evidence_payloads)
    if set(payloads) != expected_members:
        raise DeploymentBundleError("bundle contains unmanifested or missing payload members")
    if manifest["external_gates"] != _external_gate_records():
        raise DeploymentBundleError("external release controls were changed or self-authorized")
    expected_phases = _phase_claims(evidence)
    if manifest["phase_claims"] != expected_phases:
        raise DeploymentBundleError("phase claims do not match independently classified evidence")
    compatibility = manifest["compatibility"]
    if compatibility != _compatibility_record(components):
        raise DeploymentBundleError("compatibility selection or migration claim was changed")
    return {
        "structural_valid": True,
        "archive_sha256": _sha(b""),  # Filled by the caller with the whole archive identity.
        "source_identity_sha256": manifest["source_identity_sha256"],
        "component_statuses": {row["id"]: row["status"] for row in components},
        "evidence_statuses": {row["id"]: row["status"] for row in evidence},
        "phase_claims": expected_phases,
        "blocking_external_gates": [row["id"] for row in EXTERNAL_GATES if row["status"] != "PASS"],
    }


def _validate_evidence_manifest(
    entries: object,
    expected_source_sha256: str,
    payloads: Mapping[str, bytes],
    evaluated_at: datetime | None,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    if (
        type(entries) is not list or len(entries) != len(CHECK_IDS)
        or any(type(row) is not dict for row in entries)
        or [row.get("id") for row in entries] != list(CHECK_IDS)
    ):
        raise DeploymentBundleError("evidence inventory is incomplete")
    output = []
    log_payloads: dict[str, bytes] = {}
    for check_id, entry in zip(CHECK_IDS, entries):
        if set(entry) != {"id", "status", "reason", "record", "raw_logs"}:
            raise DeploymentBundleError(f"evidence fields are malformed: {check_id}")
        record = entry["record"]
        if record is None:
            status, reason, logs = _classify_evidence(None, expected_source_sha256, evaluated_at)
        else:
            if type(record) is not dict:
                raise DeploymentBundleError(f"evidence record is malformed: {check_id}")
            if evaluated_at is None:
                raise DeploymentBundleError(f"evidence evaluation time is missing: {check_id}")
            rebuilt = dict(record)
            log_records = entry["raw_logs"]
            if type(log_records) is not list or len(log_records) > 4:
                raise DeploymentBundleError(f"raw log inventory is malformed: {check_id}")
            found: dict[str, bytes] = {}
            for log in log_records:
                if type(log) is not dict or set(log) != {"member", "size", "sha256"}:
                    raise DeploymentBundleError(f"raw log identity is malformed: {check_id}")
                member = log["member"]
                if type(member) is not str or not member.startswith(f"evidence/{check_id}/") or not member.endswith(".log"):
                    raise DeploymentBundleError(f"raw log member is outside its evidence record: {check_id}")
                stream = member.rsplit("/", 1)[-1][:-4]
                if stream not in {"command_stdout", "command_stderr", "guard_stdout", "guard_stderr"} or stream in found:
                    raise DeploymentBundleError(f"raw log stream is unknown or duplicated: {check_id}")
                if member != f"evidence/{check_id}/{stream}.log":
                    raise DeploymentBundleError(f"raw log path is not canonical: {check_id}")
                data = payloads.get(member)
                if (
                    type(log["size"]) is not int or log["size"] < 0
                    or type(log["sha256"]) is not str or not _HEX64.fullmatch(log["sha256"])
                    or type(data) is not bytes or len(data) != log["size"]
                    or _sha(data) != log["sha256"]
                ):
                    raise DeploymentBundleError(f"raw log bytes do not match their identity: {check_id}")
                found[stream] = data
                log_payloads[member] = data
            for stream in ("command_stdout", "command_stderr", "guard_stdout", "guard_stderr"):
                rebuilt[stream] = found.get(stream)
            if rebuilt.get("id") != check_id:
                raise DeploymentBundleError(f"evidence record id mismatch: {check_id}")
            status, reason, logs = _classify_evidence(rebuilt, expected_source_sha256, evaluated_at)
        normalized_logs = [{key: value for key, value in log.items() if key != "bytes"} for log in logs]
        if entry["status"] != status or entry["reason"] != reason or entry["raw_logs"] != normalized_logs:
            raise DeploymentBundleError(f"evidence status or raw-log identity was self-asserted: {check_id}")
        output.append(entry)
    return output, log_payloads


def _validate_archive(archive_bytes: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest, payloads = _manifest_from_zip(archive_bytes)
    result = _validate_manifest(manifest, payloads)
    result["archive_sha256"] = _sha(archive_bytes)
    result["manifest_sha256"] = _sha(_canonical_json(manifest))
    return manifest, result


def validate_bundle_bytes(archive_bytes: bytes) -> dict[str, Any]:
    """Validate package bytes without trusting the producer's result object."""
    _, result = _validate_archive(archive_bytes)
    return result


def _validate_live_manifest(manifest: Mapping[str, Any], workspace_root: Path) -> dict[str, Any]:
    """Recheck selected file bytes while preserving artifact-level independence.

    A changed unrelated file alters the checkout snapshot and blocks use of the
    whole assembled candidate. It does not stale an artifact whose own bytes
    and declared dependencies remain unchanged.
    """
    if _is_redirected_path(workspace_root) or not workspace_root.is_dir():
        raise DeploymentBundleError("workspace root is missing or redirected")
    workspace = workspace_root.resolve(strict=True)
    roots = {repo: workspace / "work" / path for repo, path in PROJECT_ROOTS.items()}
    current_roots = [_root_identity(repository, roots[repository]) for repository in sorted(roots)]
    workspace_map_path = _safe_file(workspace, WORKSPACE_MAP_RELATIVE, allow_missing=False)
    assert workspace_map_path is not None
    current_map_bytes = _read_bounded(
        workspace_map_path, MAX_PAYLOAD_FILE_BYTES, "workspace map"
    )
    workspace_map_matches = (
        len(current_map_bytes) == manifest["workspace_map"]["size"]
        and _sha(current_map_bytes) == manifest["workspace_map"]["sha256"]
    )
    snapshot_matches = (
        _canonical_json(current_roots) == _canonical_json(manifest["source_roots"])
        and workspace_map_matches
    )
    source_snapshot_status = "CURRENT" if snapshot_matches else "CHANGED"
    file_rows = {row["id"]: row for row in manifest["files"]}
    artifact_statuses: dict[str, str] = {}
    for spec in COMPONENT_SPECS:
        changed = False
        missing = False
        for file_id in spec.file_ids:
            row = file_rows[file_id]
            file_spec = _FILE_BY_ID[file_id]
            current_root = next(row for row in current_roots if row["id"] == file_spec.repository)
            current, _ = _read_source(roots[file_spec.repository], file_spec, current_root)
            if current["present"] != row["present"] or current["sha256"] != row["sha256"]:
                changed = True
            if not current["present"]:
                missing = True
        if missing:
            artifact_statuses[spec.component_id] = "MISSING"
        elif changed:
            artifact_statuses[spec.component_id] = "STALE"
        elif spec.reason_if_unselected:
            artifact_statuses[spec.component_id] = "UNSELECTED"
        else:
            artifact_statuses[spec.component_id] = "USABLE_SOURCE_IDENTITY"
    ending_roots = [_root_identity(repository, roots[repository]) for repository in sorted(roots)]
    ending_map_path = _safe_file(workspace, WORKSPACE_MAP_RELATIVE, allow_missing=False)
    assert ending_map_path is not None
    ending_map_bytes = _read_bounded(
        ending_map_path, MAX_PAYLOAD_FILE_BYTES, "workspace map"
    )
    if (
        _canonical_json(ending_roots) != _canonical_json(current_roots)
        or ending_map_bytes != current_map_bytes
    ):
        snapshot_matches = False
        source_snapshot_status = "UNSTABLE_DURING_VALIDATION"
        artifact_statuses = {key: "UNSTABLE_SNAPSHOT" for key in artifact_statuses}
    return {
        "source_snapshot_matches": snapshot_matches,
        "source_snapshot_status": source_snapshot_status,
        "workspace_map_matches": workspace_map_matches,
        "component_statuses": artifact_statuses,
        "usable_components": sorted(key for key, value in artifact_statuses.items() if value == "USABLE_SOURCE_IDENTITY"),
        "release_status": "BLOCKED",
        "reason": "Current local hashes establish byte identity only; trusted execution, approval, custody, profile, receiver, audit, and release control remain open.",
    }


def validate_live_sources(archive_bytes: bytes, workspace_root: Path) -> dict[str, Any]:
    manifest, _ = _validate_archive(archive_bytes)
    return _validate_live_manifest(manifest, workspace_root)


def _write_new(path: Path, data: bytes) -> None:
    path = path.absolute()
    if path.exists() or _is_redirected_path(path):
        raise DeploymentBundleError("output already exists or is redirected")
    if not path.parent.is_dir():
        raise DeploymentBundleError("output directory must already exist")
    if any(
        _is_redirected_path(parent)
        for parent in (path.parent, *path.parent.parents)
    ):
        raise DeploymentBundleError("output path traverses a symbolic link")
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise DeploymentBundleError("output path traverses a redirected directory")
    except OSError as exc:
        raise DeploymentBundleError("output directory cannot be resolved") from exc
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp",
            dir=path.parent, delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
    except FileExistsError as exc:
        raise DeploymentBundleError("output already exists or is redirected") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _ensure_output_outside_worktrees(path: Path, workspace_root: Path) -> None:
    if _is_redirected_path(workspace_root):
        raise DeploymentBundleError("workspace root is redirected")
    workspace = workspace_root.resolve(strict=True)
    output = path.resolve(strict=False)
    work_root = (workspace / "work").resolve(strict=True)
    if output == work_root or output.is_relative_to(work_root):
        raise DeploymentBundleError("bundle output must be outside product worktrees")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="assemble a new candidate at this path")
    mode.add_argument("--verify-bundle", type=Path, help="validate an existing archive without modifying it")
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--evidence-evaluated-at-utc")
    args = parser.parse_args(argv)
    try:
        if args.verify_bundle is not None:
            if any(value is not None for value in (args.evidence, args.evidence_root, args.evidence_evaluated_at_utc)):
                raise DeploymentBundleError("evidence inputs are only valid while assembling a bundle")
            path = args.verify_bundle
            if _is_redirected_path(path) or not path.is_file():
                raise DeploymentBundleError("bundle input is missing, redirected, or oversized")
            archive = _read_bounded(path, MAX_ARCHIVE_BYTES, "bundle input")
            manifest, validation = _validate_archive(archive)
            result: dict[str, Any] = {
                "schema": SCHEMA,
                "status": "PASS_STRUCTURE_ONLY",
                "archive_validation": validation,
                "release_status": "BLOCKED",
            }
            if args.workspace_root is not None:
                live = _validate_live_manifest(manifest, args.workspace_root)
                result["live_source_validation"] = live
                if not live["source_snapshot_matches"]:
                    result["status"] = "BLOCKED_SOURCE_SNAPSHOT"
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0 if result["status"] == "PASS_STRUCTURE_ONLY" else 2
        if args.workspace_root is None:
            raise DeploymentBundleError("--workspace-root is required while assembling a bundle")
        if args.evidence is not None:
            if args.evidence_root is None:
                raise DeploymentBundleError("--evidence-root is required with --evidence")
            records = load_evidence_file(args.evidence, args.evidence_root)
        else:
            records = []
        _ensure_output_outside_worktrees(args.output, args.workspace_root)
        archive, report = build_candidate(
            args.workspace_root,
            evidence_records=records,
            evidence_evaluated_at_utc=args.evidence_evaluated_at_utc,
        )
        _write_new(args.output, archive)
        readback = _read_bounded(args.output, MAX_ARCHIVE_BYTES, "published bundle")
        validation = validate_bundle_bytes(readback)
        if validation["archive_sha256"] != report["archive_sha256"]:
            raise DeploymentBundleError("published candidate bytes differ from assembled bytes")
    except (DeploymentBundleError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "BLOCKED", "reason": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
