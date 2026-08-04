"""Small, digest-only evidence types for a qualified Wave 2 boundary.

The existing Gate 2E records intentionally remain blocked when these values
are absent.  This module does not promote a status by itself: every value is
recomputed from the raw run fields supplied by the caller, and all private
proof/witness bytes are represented only by digests.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from pathlib import Path
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    TRANSPARENT_SHAKE256_BACKEND_ID,
    backend_descriptor,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    SELECTED_PARAMETER_COMMITMENT,
)
from tools.privacy_artifact_scan import _decode_text, _text_categories, scan_artifacts


PROFILE_IDS: Final[tuple[str, ...]] = ("K128_CALIBRATION", "K512_CALIBRATION")
LATENCY_LIMIT_SECONDS: Final[dict[str, float]] = {
    "K128_CALIBRATION": 35.0,
    "K512_CALIBRATION": 180.0,
}
QUALIFIED_BACKEND_ID: Final[str] = TRANSPARENT_SHAKE256_BACKEND_ID
QUALIFIED_SUITE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE2/QUALIFIED-SHAKE256-SUITE/v1\x00"
)
LEAKAGE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/COMPLETE-LEAKAGE-SCAN/v1\x00"
H4_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/H4-ATOMIC-BINDING/v1\x00"


class QualifiedEvidenceError(ValueError):
    """Fail-closed error for malformed or contradictory qualification data."""


def _hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise QualifiedEvidenceError("qualified_evidence_hash_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def _text(value: object, label: str, maximum: int = 192) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_nul")
    return encoded


def _digest(value: object, label: str, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64 or (nonzero and not any(value)):
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_digest_invalid")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_boolean_required")
    return value


def _number(value: object, label: str, *, maximum: float = 5_000.0) -> float:
    if type(value) not in {int, float} or isinstance(value, bool):
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_number_invalid")
    result = float(value)
    if not 0.0 <= result < maximum:
        raise QualifiedEvidenceError(f"qualified_evidence_{label}_range_invalid")
    return result


def qualified_suite_id(component_suite_ids: Mapping[str, bytes]) -> bytes:
    """Derive one stable Wave 2 identity from both governed profile proofs."""

    if type(component_suite_ids) is not dict or tuple(sorted(component_suite_ids)) != PROFILE_IDS:
        raise QualifiedEvidenceError("qualified_suite_component_profile_set_invalid")
    descriptor = backend_descriptor(QUALIFIED_BACKEND_ID)
    encoded: list[bytes] = [
        descriptor.parameter_commitment_512,
        SELECTED_PARAMETER_COMMITMENT,
    ]
    for profile_id in PROFILE_IDS:
        encoded.extend((_text(profile_id, "profile_id"), _digest(component_suite_ids[profile_id], "component_suite")))
    return _hash(QUALIFIED_SUITE_DOMAIN, *encoded)


@dataclass(frozen=True, slots=True)
class LeakageScanEvidence:
    controlled_root: str
    controlled_root_findings: tuple[str, ...]
    raw_stream_findings: tuple[str, ...]
    stdout_digest_512: bytes
    stderr_digest_512: bytes
    telemetry_digest_512: bytes
    retained_artifact_count: int
    retained_artifact_bytes: int
    scan_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _text(self.controlled_root, "controlled_root", 512)
        if type(self.controlled_root_findings) is not tuple or self.controlled_root_findings:
            raise QualifiedEvidenceError("qualified_leakage_controlled_scan_not_empty")
        if type(self.raw_stream_findings) is not tuple or self.raw_stream_findings:
            raise QualifiedEvidenceError("qualified_leakage_raw_stream_scan_not_empty")
        for value, label in (
            (self.stdout_digest_512, "stdout"),
            (self.stderr_digest_512, "stderr"),
            (self.telemetry_digest_512, "telemetry"),
        ):
            _digest(value, label)
        if type(self.retained_artifact_count) is not int or self.retained_artifact_count != 0:
            raise QualifiedEvidenceError("qualified_leakage_retained_artifacts_present")
        if type(self.retained_artifact_bytes) is not int or self.retained_artifact_bytes != 0:
            raise QualifiedEvidenceError("qualified_leakage_retained_bytes_present")
        expected = _hash(
            LEAKAGE_DOMAIN,
            _text(self.controlled_root, "controlled_root"),
            self.stdout_digest_512,
            self.stderr_digest_512,
            self.telemetry_digest_512,
            self.retained_artifact_count.to_bytes(8, "big"),
            self.retained_artifact_bytes.to_bytes(8, "big"),
        )
        if self.scan_digest_512 not in (b"", expected):
            raise QualifiedEvidenceError("qualified_leakage_digest_mismatch")
        object.__setattr__(self, "scan_digest_512", expected)

    @classmethod
    def from_streams(
        cls,
        controlled_root: Path,
        *,
        stdout: bytes,
        stderr: bytes,
        telemetry: bytes,
        retained_artifact_count: int = 0,
        retained_artifact_bytes: int = 0,
    ) -> "LeakageScanEvidence":
        if not isinstance(controlled_root, Path) or not controlled_root.is_absolute() or not controlled_root.is_dir():
            raise QualifiedEvidenceError("qualified_leakage_controlled_root_invalid")
        findings = tuple(scan_artifacts(controlled_root))
        stream_findings: list[str] = []
        for label, value in (("stdout", stdout), ("stderr", stderr), ("telemetry", telemetry)):
            if type(value) is not bytes:
                raise QualifiedEvidenceError("qualified_leakage_stream_type_invalid")
            try:
                decoded = _decode_text(value)
            except UnicodeDecodeError:
                stream_findings.append(f"{label}:non_text_stream")
                continue
            stream_findings.extend(f"{label}:{category}" for category in _text_categories(decoded))
        return cls(
            str(controlled_root),
            findings,
            tuple(stream_findings),
            sha3_512(stdout).digest(),
            sha3_512(stderr).digest(),
            sha3_512(telemetry).digest(),
            retained_artifact_count,
            retained_artifact_bytes,
        )


@dataclass(frozen=True, slots=True)
class H4RunEvidence:
    profile_id: str
    run_id: str
    component_proof_suite_id_512: bytes
    qualified_proof_suite_id_512: bytes
    state_commitment_backend: str
    state_binding_digest_512: bytes
    parent_binding_512: bytes
    receipt_digest_512: bytes
    stdout_digest_512: bytes
    stderr_digest_512: bytes
    external_exit_code: int
    stderr_bytes: int
    post_launch_driver_event_count: int
    pagefile_growth_mb: float
    proof_seconds: float
    complete_process_wall_seconds: float
    peak_host_mb: float
    peak_device_mb: float
    scratch_mb: float
    state_plane_binding_verified: bool
    state_hash_bus_calls_verified: bool
    atomic_acceptance_boundary: bool
    all_shards_independently_verified: bool
    complete_fresh_proof_independently_verified: bool
    complete_proof_latency_gate: bool
    complete_proof_qualification: bool
    run_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _text(self.profile_id, "profile_id", 64)
        if self.profile_id not in PROFILE_IDS:
            raise QualifiedEvidenceError("qualified_h4_profile_invalid")
        _text(self.run_id, "run_id", 128)
        for value, label in (
            (self.component_proof_suite_id_512, "component_proof_suite"),
            (self.qualified_proof_suite_id_512, "qualified_proof_suite"),
            (self.state_binding_digest_512, "state_binding"),
            (self.parent_binding_512, "parent_binding"),
            (self.receipt_digest_512, "receipt"),
            (self.stdout_digest_512, "stdout"),
            (self.stderr_digest_512, "stderr"),
        ):
            _digest(value, label)
        if self.state_commitment_backend != QUALIFIED_BACKEND_ID:
            raise QualifiedEvidenceError("qualified_h4_state_commitment_backend_invalid")
        if type(self.external_exit_code) is not int:
            raise QualifiedEvidenceError("qualified_h4_exit_code_invalid")
        for value, label in (
            (self.stderr_bytes, "stderr_bytes"),
            (self.post_launch_driver_event_count, "driver_event_count"),
        ):
            if type(value) is not int or value < 0:
                raise QualifiedEvidenceError(f"qualified_h4_{label}_invalid")
        if self.external_exit_code != 0 or self.stderr_bytes != 0 or self.post_launch_driver_event_count != 0:
            raise QualifiedEvidenceError("qualified_h4_external_gate_failed")
        if type(self.pagefile_growth_mb) not in {int, float} or self.pagefile_growth_mb > 0:
            raise QualifiedEvidenceError("qualified_h4_pagefile_growth")
        for value, label in (
            (self.proof_seconds, "proof_seconds"),
            (self.complete_process_wall_seconds, "process_seconds"),
            (self.peak_host_mb, "host_peak"),
            (self.peak_device_mb, "device_peak"),
            (self.scratch_mb, "scratch"),
        ):
            _number(value, label)
        for value, label in (
            (self.proof_seconds, "proof_seconds"),
            (self.complete_process_wall_seconds, "process_seconds"),
            (self.peak_host_mb, "host_peak"),
            (self.peak_device_mb, "device_peak"),
        ):
            if float(value) <= 0.0:
                raise QualifiedEvidenceError(f"qualified_h4_{label}_must_be_positive")
        if self.complete_process_wall_seconds >= LATENCY_LIMIT_SECONDS[self.profile_id]:
            raise QualifiedEvidenceError("qualified_h4_latency_not_below_limit")
        for value, label in (
            (self.state_plane_binding_verified, "state_binding_verified"),
            (self.state_hash_bus_calls_verified, "hash_bus_verified"),
            (self.atomic_acceptance_boundary, "atomic_boundary"),
            (self.all_shards_independently_verified, "shards_verified"),
            (self.complete_fresh_proof_independently_verified, "fresh_proof_verified"),
            (self.complete_proof_latency_gate, "latency_gate"),
            (self.complete_proof_qualification, "proof_qualification"),
        ):
            if not _bool(value, label):
                raise QualifiedEvidenceError(f"qualified_h4_{label}_not_closed")
        expected = _hash(
            H4_DOMAIN,
            _text(self.profile_id, "profile_id"),
            _text(self.run_id, "run_id"),
            self.component_proof_suite_id_512,
            self.qualified_proof_suite_id_512,
            _text(self.state_commitment_backend, "state_commitment_backend"),
            self.state_binding_digest_512,
            self.parent_binding_512,
            self.receipt_digest_512,
            self.stdout_digest_512,
            self.stderr_digest_512,
            self.external_exit_code.to_bytes(4, "big", signed=True),
            self.stderr_bytes.to_bytes(8, "big"),
            self.post_launch_driver_event_count.to_bytes(8, "big"),
            repr(float(self.pagefile_growth_mb)).encode("ascii"),
            repr(float(self.proof_seconds)).encode("ascii"),
            repr(float(self.complete_process_wall_seconds)).encode("ascii"),
            repr(float(self.peak_host_mb)).encode("ascii"),
            repr(float(self.peak_device_mb)).encode("ascii"),
            repr(float(self.scratch_mb)).encode("ascii"),
            bytes(
                int(value)
                for value in (
                    self.state_plane_binding_verified,
                    self.state_hash_bus_calls_verified,
                    self.atomic_acceptance_boundary,
                    self.all_shards_independently_verified,
                    self.complete_fresh_proof_independently_verified,
                    self.complete_proof_latency_gate,
                    self.complete_proof_qualification,
                )
            ),
        )
        if self.run_digest_512 not in (b"", expected):
            raise QualifiedEvidenceError("qualified_h4_run_digest_mismatch")
        object.__setattr__(self, "run_digest_512", expected)


@dataclass(frozen=True, slots=True)
class H4AtomicBindingEvidence:
    backend_id: str
    qualified_proof_suite_id_512: bytes
    runs: tuple[H4RunEvidence, ...]
    evidence_digest_512: bytes = b""

    def __post_init__(self) -> None:
        if self.backend_id != QUALIFIED_BACKEND_ID:
            raise QualifiedEvidenceError("qualified_h4_backend_invalid")
        _digest(self.qualified_proof_suite_id_512, "qualified_proof_suite")
        if type(self.runs) is not tuple or not self.runs:
            raise QualifiedEvidenceError("qualified_h4_runs_required")
        if any(type(item) is not H4RunEvidence for item in self.runs):
            raise QualifiedEvidenceError("qualified_h4_run_type_invalid")
        if {item.profile_id for item in self.runs} != set(PROFILE_IDS):
            raise QualifiedEvidenceError("qualified_h4_profile_set_incomplete")
        if any(item.qualified_proof_suite_id_512 != self.qualified_proof_suite_id_512 for item in self.runs):
            raise QualifiedEvidenceError("qualified_h4_suite_mismatch")
        identities = {(item.profile_id, item.run_id) for item in self.runs}
        if len(identities) != len(self.runs):
            raise QualifiedEvidenceError("qualified_h4_run_identity_duplicate")
        expected = _hash(
            H4_DOMAIN,
            _text(self.backend_id, "backend_id"),
            self.qualified_proof_suite_id_512,
            b"".join(item.run_digest_512 for item in self.runs),
        )
        if self.evidence_digest_512 not in (b"", expected):
            raise QualifiedEvidenceError("qualified_h4_evidence_digest_mismatch")
        object.__setattr__(self, "evidence_digest_512", expected)


def qualified_admission_digest(
    *,
    h4: H4AtomicBindingEvidence,
    leakage: LeakageScanEvidence,
) -> bytes:
    if type(h4) is not H4AtomicBindingEvidence or type(leakage) is not LeakageScanEvidence:
        raise QualifiedEvidenceError("qualified_admission_evidence_type_invalid")
    return _hash(
        QUALIFIED_SUITE_DOMAIN,
        h4.qualified_proof_suite_id_512,
        h4.evidence_digest_512,
        leakage.scan_digest_512,
    )


__all__ = (
    "H4AtomicBindingEvidence",
    "H4RunEvidence",
    "LATENCY_LIMIT_SECONDS",
    "LeakageScanEvidence",
    "PROFILE_IDS",
    "QUALIFIED_BACKEND_ID",
    "QualifiedEvidenceError",
    "qualified_admission_digest",
    "qualified_suite_id",
)
