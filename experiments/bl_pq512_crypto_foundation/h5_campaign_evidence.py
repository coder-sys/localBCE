"""Fail-closed validation of the run-owned Wave 2 H5 campaign manifest.

The native coordinator and external PowerShell monitor are the evidence
producers.  This module only reads their raw files; it never turns a claimed
summary into qualification.  A missing file, parser disagreement, stale or
reused input, monitor failure, pagefile growth, stderr, driver event, or gate
violation rejects the complete campaign.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Final, Mapping


PROFILE_IDS: Final[tuple[str, ...]] = ("K128_CALIBRATION", "K512_CALIBRATION")
WARMUP_COUNT: Final[int] = 1
MEASURED_REPETITIONS: Final[int] = 10
FRESH_LAUNCH_COUNT: Final[int] = 22
LATENCY_LIMIT_SECONDS: Final[dict[str, float]] = {
    "K128_CALIBRATION": 35.0,
    "K512_CALIBRATION": 180.0,
}
MAX_RSS_BYTES: Final[int] = 5_000_000_000
MAX_SCRATCH_BYTES: Final[int] = 5_000_000_000
SCHEMA_VERSION: Final[str] = "blind_ledger_h5_campaign_evidence_v1"
_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_KEY_VALUE = re.compile(r"^[^=\r\n]+=[^\r\n]*$")


class H5CampaignEvidenceError(ValueError):
    """Raised when the raw campaign bundle is incomplete or contradictory."""


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_shape_invalid")
    return value


def _text(value: object, label: str, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_invalid")
    return value


def _hex(value: object, label: str, pattern: re.Pattern[str] = _HEX_128) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_digest_invalid")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_integer_invalid")
    return value


def _float(value: object, label: str, *, minimum: float = 0.0) -> float:
    if type(value) not in {int, float} or isinstance(value, bool):
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_number_invalid")
    result = float(value)
    if result < minimum:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_number_invalid")
    return result


def _boolean(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_invalid")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise H5CampaignEvidenceError("h5_campaign_manifest_not_canonicalizable") from exc


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise H5CampaignEvidenceError("h5_campaign_manifest_missing")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise H5CampaignEvidenceError("h5_campaign_manifest_read_failed") from exc
    if type(value) is not dict:
        raise H5CampaignEvidenceError("h5_campaign_manifest_object_required")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise H5CampaignEvidenceError("h5_campaign_duplicate_key")
        result[key] = value
    return result


def _artifact(path_value: object, label: str, *, maximum_bytes: int) -> tuple[Path, bytes]:
    path = Path(_text(path_value, f"{label}_path", 2048))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_file_invalid")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_read_failed") from exc
    if len(data) > maximum_bytes:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_too_large")
    return path, data


def _parse_key_values(data: bytes, label: str) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_not_utf8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or not _KEY_VALUE.fullmatch(line):
            raise H5CampaignEvidenceError(f"h5_campaign_{label}_line_invalid")
        key, value = line.split("=", 1)
        if key in values:
            raise H5CampaignEvidenceError(f"h5_campaign_{label}_duplicate_field:{key}")
        values[key] = value
    return values


def _parse_monitor(data: bytes, stdout: bytes, stderr: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise H5CampaignEvidenceError("h5_campaign_monitor_not_utf8") from exc
    marker_stdout = "---stdout---\n"
    marker_stderr = "\n---stderr---\n"
    if marker_stdout not in text or marker_stderr not in text:
        raise H5CampaignEvidenceError("h5_campaign_monitor_sections_missing")
    head, rest = text.split(marker_stdout, 1)
    embedded_stdout, embedded_stderr = rest.split(marker_stderr, 1)
    if embedded_stdout.splitlines() != stdout.decode("utf-8").splitlines():
        raise H5CampaignEvidenceError("h5_campaign_monitor_stdout_disagreement")
    if embedded_stderr.splitlines() != stderr.decode("utf-8").splitlines():
        raise H5CampaignEvidenceError("h5_campaign_monitor_stderr_disagreement")
    return _parse_key_values(head, "monitor")


def _require_fields(values: Mapping[str, str], fields: set[str], label: str) -> None:
    if set(values) != fields:
        missing = sorted(fields - set(values))
        extra = sorted(set(values) - fields)
        raise H5CampaignEvidenceError(f"h5_campaign_{label}_fields_invalid:missing={missing}:extra={extra}")


def _required_stdout_fields(profile_id: str) -> set[str]:
    shard_count = 1 if profile_id == "K128_CALIBRATION" else 4
    return {
        *(f"shard_{index}_{suffix}" for index in range(shard_count) for suffix in ("verified", "proof_seconds", "coordinator_wall_seconds")),
        "status",
        "evidence_class",
        "atomic_parent_binding_sha3_512",
        "atomic_statement_sha3_512",
        "state_plane_binding_verified",
        "state_plane_binding_digest_sha3_512",
        "state_component_proof_suite_id",
        "state_commitment_backend",
        "state_hash_bus_calls_verified",
        "execution_manifest_sha3_512",
        "semantic_hash_bus_file_sha3_512",
        "ordered_shards",
        "complete_shard_proofs",
        "sequential_single_gpu_execution",
        "parallel_gpu_images",
        "theorem_free_challenge_sharing",
        "atomic_acceptance_boundary",
        "all_shards_independently_verified",
        "atomic_receipt_sha3_512",
        "complete_process_wall_seconds",
        "peak_host_mb",
        "peak_device_mb",
        "scratch_mb",
        "latency_limit_seconds",
        "complete_proof_latency_gate",
        "proof_suite_id",
        "complete_proof_qualification",
    }


@dataclass(frozen=True, slots=True)
class H5RunEvidence:
    profile_id: str
    phase: str
    ordinal: int
    state_binding_sha3_512: str
    state_plane_binding_sha3_512: str
    parent_binding_sha3_512: str
    receipt_sha3_512: str
    stdout_sha256: str
    stderr_sha256: str
    complete_process_wall_seconds: float
    external_process_tree_peak_bytes: int
    scratch_bytes: int


@dataclass(frozen=True, slots=True)
class H5CampaignEvidence:
    campaign_id: str
    source_commit: str
    proof_suite_id: str
    execution_manifest_sha3_512: str
    campaign_digest_sha3_512: str
    runs: tuple[H5RunEvidence, ...]
    k128_p95_seconds: float
    k512_p95_seconds: float
    max_peak_rss_bytes: int
    max_scratch_bytes: int

    @property
    def measured_runs(self) -> tuple[H5RunEvidence, ...]:
        return tuple(run for run in self.runs if run.phase == "measured")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "source_commit": self.source_commit,
            "proof_suite_id": self.proof_suite_id,
            "execution_manifest_sha3_512": self.execution_manifest_sha3_512,
            "campaign_digest_sha3_512": self.campaign_digest_sha3_512,
            "run_count": len(self.runs),
            "warmup_count": sum(run.phase == "warmup" for run in self.runs),
            "measured_count": len(self.measured_runs),
            "k128_p95_seconds": self.k128_p95_seconds,
            "k512_p95_seconds": self.k512_p95_seconds,
            "max_peak_rss_bytes": self.max_peak_rss_bytes,
            "max_scratch_bytes": self.max_scratch_bytes,
        }


def _validate_run(raw: Mapping[str, Any], *, profile_id: str, expected_phase: str, expected_ordinal: int, manifest: Mapping[str, Any]) -> H5RunEvidence:
    required = {
        "profile_id", "phase", "ordinal", "state_binding_path", "state_binding_sha3_512",
        "state_verify_stdout_path", "state_verify_stderr_path", "state_verify_exit_code",
        "monitor_path", "stdout_path", "stderr_path", "monitor_exit_code",
    }
    item = _object(raw, required, f"run_{profile_id}_{expected_phase}_{expected_ordinal}")
    if item["profile_id"] != profile_id or item["phase"] != expected_phase or item["ordinal"] != expected_ordinal:
        raise H5CampaignEvidenceError("h5_campaign_run_order_invalid")
    state_path, state_bytes = _artifact(item["state_binding_path"], "state_binding", maximum_bytes=128 * 1024 * 1024)
    if state_path.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        raise H5CampaignEvidenceError("h5_campaign_state_binding_inside_checkout")
    state_hash = hashlib.sha3_512(state_bytes).hexdigest()
    if _hex(item["state_binding_sha3_512"], "state_binding") != state_hash:
        raise H5CampaignEvidenceError("h5_campaign_state_binding_digest_mismatch")
    verify_stdout_path, verify_stdout = _artifact(item["state_verify_stdout_path"], "state_verify_stdout", maximum_bytes=1 * 1024 * 1024)
    verify_stderr_path, verify_stderr = _artifact(item["state_verify_stderr_path"], "state_verify_stderr", maximum_bytes=1 * 1024 * 1024)
    del verify_stdout_path, verify_stderr_path
    if _int(item["state_verify_exit_code"], "state_verify_exit_code") != 0 or verify_stderr:
        raise H5CampaignEvidenceError("h5_campaign_state_verify_failed")
    state_values = _parse_key_values(verify_stdout, "state_verify")
    if state_values.get("state_plane_binding_verified") != "true" or state_values.get("state_profile") != profile_id:
        raise H5CampaignEvidenceError("h5_campaign_state_verify_identity_mismatch")
    if state_values.get("state_commitment_backend") != "TRANSPARENT_SHAKE256_1024":
        raise H5CampaignEvidenceError("h5_campaign_state_backend_invalid")

    monitor_path, monitor_bytes = _artifact(item["monitor_path"], "monitor", maximum_bytes=2 * 1024 * 1024)
    stdout_path, stdout_bytes = _artifact(item["stdout_path"], "stdout", maximum_bytes=32 * 1024 * 1024)
    stderr_path, stderr_bytes = _artifact(item["stderr_path"], "stderr", maximum_bytes=2 * 1024 * 1024)
    del monitor_path, stdout_path, stderr_path
    monitor = _parse_monitor(monitor_bytes, stdout_bytes, stderr_bytes)
    stdout = _parse_key_values(stdout_bytes, "stdout")
    _require_fields(stdout, _required_stdout_fields(profile_id), f"stdout_{profile_id}")
    if _int(item["monitor_exit_code"], "monitor_exit_code") != 0:
        raise H5CampaignEvidenceError("h5_campaign_monitor_exit_code_failed")
    if _int(monitor["external_exit_code"], "external_exit_code") != 0:
        raise H5CampaignEvidenceError("h5_campaign_external_exit_code_failed")
    if _int(monitor["stderr_bytes"], "stderr_bytes") != 0 or stderr_bytes:
        raise H5CampaignEvidenceError("h5_campaign_stderr_present")
    if _int(monitor["post_launch_driver_event_count"], "driver_event_count") != 0:
        raise H5CampaignEvidenceError("h5_campaign_driver_event_present")
    try:
        pagefile_growth = int(monitor["pagefile_growth_mb"])
    except ValueError as exc:
        raise H5CampaignEvidenceError("h5_campaign_pagefile_growth_invalid") from exc
    if pagefile_growth > 0:
        raise H5CampaignEvidenceError("h5_campaign_pagefile_growth")
    if _int(monitor["stdout_bytes"], "stdout_bytes") != len(stdout_bytes):
        raise H5CampaignEvidenceError("h5_campaign_stdout_length_mismatch")
    if _hex(hashlib.sha256(stdout_bytes).hexdigest(), "stdout_sha256", _HEX_64) != monitor["stdout_sha256"]:
        raise H5CampaignEvidenceError("h5_campaign_stdout_digest_mismatch")
    if _hex(hashlib.sha256(stderr_bytes).hexdigest(), "stderr_sha256", _HEX_64) != monitor["stderr_sha256"]:
        raise H5CampaignEvidenceError("h5_campaign_stderr_digest_mismatch")

    expected_limit = LATENCY_LIMIT_SECONDS[profile_id]
    if stdout["status"] != "verified" or stdout["state_commitment_backend"] != "TRANSPARENT_SHAKE256_1024":
        raise H5CampaignEvidenceError("h5_campaign_native_status_invalid")
    for key in ("state_plane_binding_verified", "state_hash_bus_calls_verified", "sequential_single_gpu_execution", "atomic_acceptance_boundary", "all_shards_independently_verified", "complete_proof_latency_gate", "complete_proof_qualification"):
        if stdout[key] != "true":
            raise H5CampaignEvidenceError(f"h5_campaign_native_{key}_invalid")
    if stdout["parallel_gpu_images"] != "0" or stdout["theorem_free_challenge_sharing"] != "false":
        raise H5CampaignEvidenceError("h5_campaign_gpu_or_challenge_boundary_invalid")
    if _float(stdout["latency_limit_seconds"], "latency_limit") != expected_limit:
        raise H5CampaignEvidenceError("h5_campaign_latency_limit_mismatch")
    wall = _float(stdout["complete_process_wall_seconds"], "complete_process_wall")
    if wall >= expected_limit:
        raise H5CampaignEvidenceError("h5_campaign_latency_not_below_limit")
    peak_rss = _float(monitor["external_process_tree_peak_bytes"], "peak_rss")
    scratch = _float(stdout["scratch_mb"], "scratch_mb") * 1_000_000.0
    if peak_rss > MAX_RSS_BYTES:
        raise H5CampaignEvidenceError("h5_campaign_peak_rss_limit")
    if scratch >= MAX_SCRATCH_BYTES:
        raise H5CampaignEvidenceError("h5_campaign_scratch_limit")
    for key in ("atomic_parent_binding_sha3_512", "state_plane_binding_digest_sha3_512", "atomic_receipt_sha3_512"):
        _hex(stdout[key], key)
    if stdout["proof_suite_id"] != manifest["proof_suite_id"] or stdout["execution_manifest_sha3_512"] != manifest["execution_manifest_sha3_512"]:
        raise H5CampaignEvidenceError("h5_campaign_manifest_identity_mismatch")
    return H5RunEvidence(
        profile_id=profile_id,
        phase=expected_phase,
        ordinal=expected_ordinal,
        state_binding_sha3_512=state_hash,
        state_plane_binding_sha3_512=stdout["state_plane_binding_digest_sha3_512"],
        parent_binding_sha3_512=stdout["atomic_parent_binding_sha3_512"],
        receipt_sha3_512=stdout["atomic_receipt_sha3_512"],
        stdout_sha256=monitor["stdout_sha256"],
        stderr_sha256=monitor["stderr_sha256"],
        complete_process_wall_seconds=wall,
        external_process_tree_peak_bytes=int(peak_rss),
        scratch_bytes=int(scratch),
    )


def validate_h5_campaign_manifest(path: Path) -> H5CampaignEvidence:
    """Validate the exact 22-launch campaign and return derived identities."""

    if not isinstance(path, Path):
        raise TypeError("h5_campaign_manifest_path_required")
    manifest = _read_json(path)
    required = {"schema_version", "campaign_id", "source_commit", "proof_suite_id", "execution_manifest_sha3_512", "brave_open_permitted", "runs"}
    _object(manifest, required, "manifest")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise H5CampaignEvidenceError("h5_campaign_schema_version_invalid")
    campaign_id = _text(manifest["campaign_id"], "campaign_id", 128)
    source_commit = _text(manifest["source_commit"], "source_commit", 40)
    if _COMMIT.fullmatch(source_commit) is None:
        raise H5CampaignEvidenceError("h5_campaign_source_commit_invalid")
    proof_suite_id = _hex(manifest["proof_suite_id"], "proof_suite_id")
    execution_manifest = _hex(manifest["execution_manifest_sha3_512"], "execution_manifest")
    _boolean(manifest["brave_open_permitted"], True, "brave_open_permitted")
    runs = manifest["runs"]
    if type(runs) is not list or len(runs) != FRESH_LAUNCH_COUNT:
        raise H5CampaignEvidenceError("h5_campaign_run_count_invalid")
    parsed: list[H5RunEvidence] = []
    for profile_index, profile_id in enumerate(PROFILE_IDS):
        profile_runs = runs[profile_index * 11 : (profile_index + 1) * 11]
        for ordinal, raw in enumerate(profile_runs):
            phase = "warmup" if ordinal == 0 else "measured"
            parsed.append(_validate_run(raw, profile_id=profile_id, expected_phase=phase, expected_ordinal=ordinal, manifest=manifest))
    identities = [(run.profile_id, run.state_binding_sha3_512, run.state_plane_binding_sha3_512, run.parent_binding_sha3_512, run.receipt_sha3_512, run.stdout_sha256) for run in parsed]
    if len(set(identities)) != len(identities) or len({item[1] for item in identities}) != len(identities):
        raise H5CampaignEvidenceError("h5_campaign_reused_or_duplicate_identity")
    measured = tuple(run for run in parsed if run.phase == "measured")
    k128 = tuple(run.complete_process_wall_seconds for run in measured if run.profile_id == PROFILE_IDS[0])
    k512 = tuple(run.complete_process_wall_seconds for run in measured if run.profile_id == PROFILE_IDS[1])
    if len(k128) != MEASURED_REPETITIONS or len(k512) != MEASURED_REPETITIONS:
        raise H5CampaignEvidenceError("h5_campaign_measured_count_invalid")
    digest = hashlib.sha3_512(_canonical_json(manifest)).hexdigest()
    return H5CampaignEvidence(
        campaign_id=campaign_id,
        source_commit=source_commit,
        proof_suite_id=proof_suite_id,
        execution_manifest_sha3_512=execution_manifest,
        campaign_digest_sha3_512=digest,
        runs=tuple(parsed),
        k128_p95_seconds=max(k128),
        k512_p95_seconds=max(k512),
        max_peak_rss_bytes=max(run.external_process_tree_peak_bytes for run in parsed),
        max_scratch_bytes=max(run.scratch_bytes for run in parsed),
    )


__all__ = (
    "FRESH_LAUNCH_COUNT",
    "H5CampaignEvidence",
    "H5CampaignEvidenceError",
    "H5RunEvidence",
    "LATENCY_LIMIT_SECONDS",
    "MAX_RSS_BYTES",
    "MAX_SCRATCH_BYTES",
    "MEASURED_REPETITIONS",
    "PROFILE_IDS",
    "SCHEMA_VERSION",
    "WARMUP_COUNT",
    "validate_h5_campaign_manifest",
)
