"""Fail-closed H5 qualification preflight.

This module freezes the H5 campaign contract without running a prover.  H5 is
authorized only after a sealed Gate 2E handoff, an admitted state/commitment
plane, and an atomic H4 parent binding.  The current repository has none of
those prerequisites, so the preflight emits a bounded blocked record instead
of treating the synthetic benchmark vector or the H4 one-run result as
qualification evidence.

The preflight independently replays the terminal Gate 2E context, validates
the reference hardware record, and checks the commit-bound canonical ``ops``
tree in this checkout.  It never creates or copies operational files,
launches CUDA, accepts cached proofs/witnesses, or assigns ``proofSuiteId``.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from pathlib import Path
from typing import Any, Final, Mapping

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.benchmark_evidence import (
    FAILURE_POLICY,
    PROTOCOL,
    BenchmarkEvidenceError,
    canonical_json_bytes,
    validate_reference_hardware_config,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_terminal_ledger import (
    TerminalLedger,
    TerminalLedgerContext,
    TerminalLedgerError,
    independently_verify_terminal_ledger,
)
from experiments.bl_pq512_crypto_foundation.ops_authority import (
    CANONICAL_OPS_ROOT,
    OPS_AUTHORITY_STATUS,
    verify_ops_authority,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_CANONICAL_OPS_ROOT: Final[Path] = CANONICAL_OPS_ROOT

STATUS: Final[str] = "H5_QUALIFICATION_PREFLIGHT_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PREFLIGHT_BLOCKED: Final[str] = "BLOCKED_H5_PREFLIGHT"
CAMPAIGN_NOT_STARTED: Final[str] = "NOT_STARTED_NO_COMPLETE_PROOF_CAMPAIGN"
EXTERNAL_MONITOR_NOT_CONFIGURED: Final[str] = "NOT_CONFIGURED_EXTERNAL_PROCESS_RESOURCE_MONITOR"
CANONICAL_OPS_VERIFIED: Final[str] = OPS_AUTHORITY_STATUS
CANONICAL_OPS_MISSING: Final[str] = "MISSING_TRACKED_OPS_AUTHORITY"
CANONICAL_OPS_MISMATCH: Final[str] = "TRACKED_OPS_AUTHORITY_MISMATCH"
REFERENCE_HARDWARE_READY: Final[str] = "READY"
REFERENCE_HARDWARE_NOT_READY: Final[str] = "NOT_READY"

PROFILE_IDS: Final[tuple[str, ...]] = ("K128_CALIBRATION", "K512_CALIBRATION")
WARMUP_COUNT: Final[int] = 1
MEASURED_REPETITIONS: Final[int] = 10
LAUNCHES_PER_PROFILE: Final[int] = WARMUP_COUNT + MEASURED_REPETITIONS
FRESH_LAUNCH_COUNT: Final[int] = len(PROFILE_IDS) * LAUNCHES_PER_PROFILE
PROTOCOL_ID_SHA3_512: Final[str] = sha3_512(
    canonical_json_bytes({"failure_policy": FAILURE_POLICY, "protocol": PROTOCOL})
).hexdigest()

_PREFLIGHT_DOMAIN = b"BL/PQ512/H5/QUALIFICATION-PREFLIGHT/v1\x00"
_DIGEST_LENGTH = 64


class H5PreflightError(ValueError):
    """Stable fail-closed error for malformed or contradictory preflight state."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 192) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise H5PreflightError(f"h5_preflight_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise H5PreflightError(f"h5_preflight_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise H5PreflightError(f"h5_preflight_{label}_nul")
    return encoded


def _digest(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != _DIGEST_LENGTH or not any(value):
        raise H5PreflightError(f"h5_preflight_{label}_digest_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise H5PreflightError("h5_preflight_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _encode_strings(values: tuple[str, ...], label: str) -> bytes:
    encoded: list[bytes] = []
    for value in values:
        item = _text(value, label)
        encoded.append(len(item).to_bytes(4, "big") + item)
    return b"".join(encoded)


def canonical_ops_identity_status(
    *,
    canonical_root: Path = DEFAULT_CANONICAL_OPS_ROOT,
) -> str:
    """Check the one commit-bound ops authority without fallback paths."""

    if not isinstance(canonical_root, Path):
        raise TypeError("h5_preflight_ops_path_must_be_path")
    if not canonical_root.exists():
        return CANONICAL_OPS_MISSING
    try:
        verify_ops_authority(canonical_root)
    except (OSError, ValueError):
        return CANONICAL_OPS_MISMATCH
    return CANONICAL_OPS_VERIFIED


@dataclass(frozen=True, slots=True)
class H5PreflightContext:
    """Private inputs used for independent preflight verification."""

    terminal_ledger: TerminalLedger
    terminal_context: TerminalLedgerContext
    hardware_config: Mapping[str, Any] | None = None
    canonical_ops_root: Path = DEFAULT_CANONICAL_OPS_ROOT

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.terminal_ledger) is not TerminalLedger:
            raise H5PreflightError("h5_preflight_terminal_ledger_type_invalid")
        if type(self.terminal_context) is not TerminalLedgerContext:
            raise H5PreflightError("h5_preflight_terminal_context_type_invalid")
        if self.hardware_config is not None and not isinstance(self.hardware_config, Mapping):
            raise H5PreflightError("h5_preflight_hardware_config_mapping_required")
        if not isinstance(self.canonical_ops_root, Path):
            raise H5PreflightError("h5_preflight_ops_path_must_be_path")


@dataclass(frozen=True, slots=True)
class H5Preflight:
    """Public blocked H5 campaign preflight record."""

    ledger_digest_512: bytes
    canonical_ops_status: str
    reference_hardware_status: str
    reference_hardware_ready: bool
    source_git_clean: bool
    protected_paths_clean: bool
    blockers: tuple[str, ...]
    status: str = PREFLIGHT_BLOCKED
    profile_ids: tuple[str, ...] = PROFILE_IDS
    warmup_count: int = WARMUP_COUNT
    measured_repetitions: int = MEASURED_REPETITIONS
    launches_per_profile: int = LAUNCHES_PER_PROFILE
    fresh_launch_count: int = FRESH_LAUNCH_COUNT
    campaign_status: str = CAMPAIGN_NOT_STARTED
    external_monitor_status: str = EXTERNAL_MONITOR_NOT_CONFIGURED
    proof_suite_id: None = None
    activation_allowed: bool = False
    preflight_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _digest(self.ledger_digest_512, "ledger")
        if self.status != PREFLIGHT_BLOCKED:
            raise H5PreflightError("h5_preflight_status_must_remain_blocked")
        if self.profile_ids != PROFILE_IDS:
            raise H5PreflightError("h5_preflight_profile_shape_invalid")
        if (
            type(self.warmup_count) is not int
            or self.warmup_count != WARMUP_COUNT
            or type(self.measured_repetitions) is not int
            or self.measured_repetitions != MEASURED_REPETITIONS
            or type(self.launches_per_profile) is not int
            or self.launches_per_profile != LAUNCHES_PER_PROFILE
            or type(self.fresh_launch_count) is not int
            or self.fresh_launch_count != FRESH_LAUNCH_COUNT
        ):
            raise H5PreflightError("h5_preflight_campaign_shape_invalid")
        if self.campaign_status != CAMPAIGN_NOT_STARTED:
            raise H5PreflightError("h5_preflight_campaign_status_invalid")
        if self.external_monitor_status != EXTERNAL_MONITOR_NOT_CONFIGURED:
            raise H5PreflightError("h5_preflight_external_monitor_status_invalid")
        if self.canonical_ops_status not in {
            CANONICAL_OPS_VERIFIED,
            CANONICAL_OPS_MISSING,
            CANONICAL_OPS_MISMATCH,
        }:
            raise H5PreflightError("h5_preflight_canonical_ops_status_invalid")
        if self.reference_hardware_status not in {
            REFERENCE_HARDWARE_READY,
            REFERENCE_HARDWARE_NOT_READY,
        }:
            raise H5PreflightError("h5_preflight_hardware_status_invalid")
        if type(self.reference_hardware_ready) is not bool:
            raise H5PreflightError("h5_preflight_hardware_ready_boolean_required")
        if self.reference_hardware_ready != (self.reference_hardware_status == REFERENCE_HARDWARE_READY):
            raise H5PreflightError("h5_preflight_hardware_status_mismatch")
        if type(self.source_git_clean) is not bool or type(self.protected_paths_clean) is not bool:
            raise H5PreflightError("h5_preflight_source_flags_boolean_required")
        if type(self.blockers) is not tuple or not self.blockers:
            raise H5PreflightError("h5_preflight_blockers_required")
        if len(self.blockers) != len(set(self.blockers)):
            raise H5PreflightError("h5_preflight_blockers_duplicate")
        for blocker in self.blockers:
            _text(blocker, "blocker", 96)
        if self.proof_suite_id is not None or self.activation_allowed is not False:
            raise H5PreflightError("h5_preflight_activation_boundary_invalid")
        expected = _hash(
            _PREFLIGHT_DOMAIN,
            _digest(self.ledger_digest_512, "ledger"),
            _text(self.status, "status"),
            _text(self.canonical_ops_status, "canonical_ops_status"),
            _text(self.reference_hardware_status, "hardware_status"),
            bytes((int(self.reference_hardware_ready), int(self.source_git_clean), int(self.protected_paths_clean))),
            _encode_strings(self.blockers, "blocker"),
            _encode_strings(self.profile_ids, "profile_id"),
            self.warmup_count.to_bytes(4, "big"),
            self.measured_repetitions.to_bytes(4, "big"),
            self.launches_per_profile.to_bytes(4, "big"),
            self.fresh_launch_count.to_bytes(4, "big"),
            _text(self.campaign_status, "campaign_status"),
            _text(self.external_monitor_status, "external_monitor_status"),
            bytes((int(self.activation_allowed),)),
            canonical_json_bytes({"failure_policy": FAILURE_POLICY, "protocol": PROTOCOL}),
        )
        if self.preflight_digest_512 not in (b"", expected):
            raise H5PreflightError("h5_preflight_digest_mismatch")
        object.__setattr__(self, "preflight_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        """Return only bounded status, shape, and digest data."""

        return {
            "status": STATUS,
            "preflight_status": self.status,
            "ledger_digest_sha3_512_hex": self.ledger_digest_512.hex(),
            "canonical_ops_status": self.canonical_ops_status,
            "reference_hardware_status": self.reference_hardware_status,
            "reference_hardware_ready": self.reference_hardware_ready,
            "source_git_clean": self.source_git_clean,
            "protected_paths_clean": self.protected_paths_clean,
            "profiles": self.profile_ids,
            "warmup_count_per_profile": self.warmup_count,
            "measured_repetitions_per_profile": self.measured_repetitions,
            "launches_per_profile": self.launches_per_profile,
            "fresh_launch_count": self.fresh_launch_count,
            "campaign_status": self.campaign_status,
            "external_monitor_status": self.external_monitor_status,
            "protocol_id_sha3_512": PROTOCOL_ID_SHA3_512,
            "cached_proofs_allowed": PROTOCOL["cached_proofs_allowed"],
            "cached_witnesses_allowed": PROTOCOL["cached_witnesses_allowed"],
            "automatic_retry_allowed": PROTOCOL["automatic_retry_allowed"],
            "failure_policy": dict(FAILURE_POLICY),
            "blockers": self.blockers,
            "proofSuiteId": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
            "preflight_digest_sha3_512_hex": self.preflight_digest_512.hex(),
        }


def _hardware_ready(value: Mapping[str, Any] | None) -> bool:
    try:
        hardware = validate_reference_hardware_config(value, require_ready=False)
    except (BenchmarkEvidenceError, OSError) as exc:
        raise H5PreflightError("h5_preflight_reference_hardware_invalid") from exc
    return hardware["benchmark_ready"] is True


def _append_unique(blockers: list[str], value: str) -> None:
    if value not in blockers:
        blockers.append(value)


def build_h5_preflight(context: H5PreflightContext) -> H5Preflight:
    """Replay prerequisites and construct a blocked, non-launching H5 record."""

    _synthetic()
    if type(context) is not H5PreflightContext:
        raise H5PreflightError("h5_preflight_context_type_invalid")
    try:
        independently_verify_terminal_ledger(
            context.terminal_ledger,
            context.terminal_context,
        )
    except (TerminalLedgerError, ValueError) as exc:
        raise H5PreflightError("h5_preflight_terminal_ledger_replay_failed") from exc

    ledger = context.terminal_ledger
    if ledger.proof_suite_id is not None or ledger.activation_allowed:
        raise H5PreflightError("h5_preflight_terminal_activation_boundary_invalid")
    canonical_status = canonical_ops_identity_status(
        canonical_root=context.canonical_ops_root,
    )
    context_ops_available = canonical_status == CANONICAL_OPS_VERIFIED
    if context_ops_available != context.terminal_context.canonical_ops_available:
        raise H5PreflightError("h5_preflight_terminal_ops_readback_mismatch")
    hardware_ready = _hardware_ready(context.hardware_config)
    blockers: list[str] = []
    if ledger.sealed is not True or ledger.status != "SEALED_GATE_2E_TERMINAL_LEDGER":
        _append_unique(blockers, "gate_2e_ledger_unsealed")
    if "no_backend_admitted" in ledger.blockers or ledger.h4_parent_bound is not True:
        _append_unique(blockers, "state_plane_unselected")
    if ledger.h4_parent_bound is not True or "h4_atomic_binding_deferred" in ledger.blockers:
        _append_unique(blockers, "h4_atomic_binding_deferred")
    if "complete_simulator_missing" in ledger.blockers:
        _append_unique(blockers, "complete_simulator_missing")
    if "complete_leakage_scan_missing" in ledger.blockers:
        _append_unique(blockers, "complete_leakage_scan_missing")
    if {"no_backend_admitted", "proof_suite_unselected"} & set(ledger.blockers):
        _append_unique(blockers, "strict_pq_security_ledger_open")
    if (
        "proof_suite_unselected" in ledger.blockers
        or context.terminal_context.selection.proof_suite_id is None
    ):
        _append_unique(blockers, "proof_suite_unselected")
    if canonical_status == CANONICAL_OPS_MISSING:
        _append_unique(blockers, "canonical_ops_missing")
    elif canonical_status == CANONICAL_OPS_MISMATCH:
        _append_unique(blockers, "canonical_ops_recursive_identity_mismatch")
    if not hardware_ready:
        _append_unique(blockers, "reference_hardware_not_ready")
    if context.terminal_context.git_clean is not True:
        _append_unique(blockers, "git_dirty")
    if context.terminal_context.protected_paths_clean is not True:
        _append_unique(blockers, "protected_path_changed")

    # These are always open in a preflight: no process was launched and no
    # run-owned external telemetry/proof artifact exists to validate.
    _append_unique(blockers, "h5_campaign_not_started")
    _append_unique(blockers, "h5_external_monitor_not_configured")
    _append_unique(blockers, "h5_source_readback_not_captured")
    _append_unique(blockers, "h5_no_qualified_evidence")

    return H5Preflight(
        ledger_digest_512=ledger.ledger_digest_512,
        canonical_ops_status=canonical_status,
        reference_hardware_status=(REFERENCE_HARDWARE_READY if hardware_ready else REFERENCE_HARDWARE_NOT_READY),
        reference_hardware_ready=hardware_ready,
        source_git_clean=context.terminal_context.git_clean,
        protected_paths_clean=context.terminal_context.protected_paths_clean,
        blockers=tuple(blockers),
    )


def independently_verify_h5_preflight(
    preflight: H5Preflight,
    context: H5PreflightContext,
) -> None:
    """Rebuild all public fields; never trust a supplied preflight digest."""

    _synthetic()
    if type(preflight) is not H5Preflight:
        raise H5PreflightError("h5_preflight_verifier_type_invalid")
    expected = build_h5_preflight(context)
    if preflight != expected:
        raise H5PreflightError("h5_preflight_verifier_replay_mismatch")


__all__: tuple[str, ...] = (
    "CAMPAIGN_NOT_STARTED",
    "CANONICAL_OPS_MISMATCH",
    "CANONICAL_OPS_MISSING",
    "CANONICAL_OPS_VERIFIED",
    "EXTERNAL_MONITOR_NOT_CONFIGURED",
    "FRESH_LAUNCH_COUNT",
    "H5Preflight",
    "H5PreflightContext",
    "H5PreflightError",
    "LAUNCHES_PER_PROFILE",
    "MEASURED_REPETITIONS",
    "PREFLIGHT_BLOCKED",
    "PROFILE_IDS",
    "PROTOCOL_ID_SHA3_512",
    "STATUS",
    "WARMUP_COUNT",
    "build_h5_preflight",
    "canonical_ops_identity_status",
    "independently_verify_h5_preflight",
)
