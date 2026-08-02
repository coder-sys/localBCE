"""Gate 2E-6/S6 and 2E-7/S7 reference bake-off and handoff.

The selector measures only the bounded synthetic S2/S3/S4 reference component
for every screened backend and both fixed profiles.  It never upgrades a
screened reference into a complete proof, and it never chooses by timing when
the cryptographic admission gate is closed.  With the current S3 evidence all
four candidates are rejected, so C0 is retained as a control and the handoff
remains explicitly unsealed.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from time import perf_counter_ns
from typing import Final, Mapping

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    AtomicComposition,
    build_atomic_composition,
    canonical_relation_payload,
    derive_composition_statement,
    independently_verify_composition,
)
from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    AUTHORITY_SUITE_IDS,
    CANDIDATE_IDS,
    AuthenticatedPublicCoinRound,
    PublicCoinAttestation,
    backend_descriptor,
    build_commitment,
    build_opening,
    derive_pre_challenge_digest,
    derive_public_coin_message_digest,
    screen_backend,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    PROFILE_CLAIM_SLOTS,
    build_scalar_control_batch,
    evaluate_candidate,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    is_exact_supported_adapter,
)


STATUS: Final[str] = "S6_S7_GATE_SELECTION_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
C0_CONTROL_ID: Final[str] = "C0_CONTROL"
RELATION_CANDIDATE_ID: Final[str] = "C1_SPARSE"
REFERENCE_BOUNDARY: Final[str] = "S2_S3_S4_REFERENCE_COMPONENT"
MEASUREMENT_LABEL: Final[str] = "MEASURED_REFERENCE_COMPONENT_NOT_COMPLETE_PROOF"
COMPLETE_BOUNDARY_STATUS: Final[str] = "NOT_RUN_NO_ELIGIBLE_FINALIST"
SELECTION_STATUS: Final[str] = "C0_CONTROL_RETAINED_NO_ELIGIBLE_PQ_FINALIST"
HANDOFF_STATUS: Final[str] = "UNSEALED_BLOCKED_SELECTION_HANDOFF"
PROFILE_IDS: Final[tuple[str, ...]] = tuple(PROFILE_CLAIM_SLOTS)
MIN_REPETITIONS: Final[int] = 2
MAX_REPETITIONS: Final[int] = 8

_MEASUREMENT_DOMAIN = b"BL/PQ512/S6/REFERENCE-MEASUREMENT/v1\x00"
_REJECTION_DOMAIN = b"BL/PQ512/S6/REJECTION/v1\x00"
_DECISION_DOMAIN = b"BL/PQ512/S7/DECISION/v1\x00"
_HANDOFF_DOMAIN = b"BL/PQ512/S7/HANDOFF/v1\x00"


class SelectionEvidenceError(ValueError):
    """Stable fail-closed error for S6/S7 evidence and selection."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 96) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise SelectionEvidenceError(f"s6_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SelectionEvidenceError(f"s6_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise SelectionEvidenceError(f"s6_{label}_nul")
    return encoded


def _bytes(value: object, label: str, length: int = 64, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise SelectionEvidenceError(f"s6_{label}_length_invalid")
    if nonzero and not any(value):
        raise SelectionEvidenceError(f"s6_{label}_zero")
    return value


def _u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise SelectionEvidenceError(f"s6_{label}_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise SelectionEvidenceError("s6_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _authority_material(material: Mapping[str, object]) -> dict[str, tuple[bytes, object, bytes, bytes]]:
    if type(material) is not dict or set(material) != set(AUTHORITY_SUITE_IDS):
        raise SelectionEvidenceError("s6_exact_dual_pq_authority_material_required")
    result: dict[str, tuple[bytes, object, bytes, bytes]] = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        value = material[suite_id]
        if type(value) is not tuple or len(value) != 4:
            raise SelectionEvidenceError("s6_authority_material_shape_invalid")
        authority_id, adapter, public_key, secret_key = value
        _bytes(authority_id, "authority_id", nonzero=True)
        if not is_exact_supported_adapter(adapter, suite_id):
            raise SelectionEvidenceError("s6_exact_dual_pq_adapter_required")
        if type(public_key) is not bytes or not public_key:
            raise SelectionEvidenceError("s6_authority_public_key_invalid")
        if type(secret_key) is not bytes or not secret_key:
            raise SelectionEvidenceError("s6_authority_secret_key_invalid")
        result[suite_id] = (authority_id, adapter, public_key, secret_key)
    return result


def _projection(profile_id: str, backend_id: str, repetition: int) -> tuple[bytes, ...]:
    return tuple(
        _hash(
            b"BL/PQ512/S6/PROJECTION/v1\x00",
            _text(profile_id, "profile_id"),
            _text(backend_id, "backend_id"),
            repetition.to_bytes(4, "big"),
            index.to_bytes(1, "big"),
        )[:32]
        for index in range(12)
    )


def _reference_case(
    backend_id: str,
    profile_id: str,
    repetition: int,
    authority_material: dict[str, tuple[bytes, object, bytes, bytes]],
) -> tuple[AtomicComposition, int, int, int]:
    start_ns = perf_counter_ns()
    batch = build_scalar_control_batch(profile_id)
    result = evaluate_candidate(RELATION_CANDIDATE_ID, batch)
    projection = _projection(profile_id, backend_id, repetition)
    statement = derive_composition_statement(
        batch,
        result,
        projection,
        epoch=7,
        sequence_before=22,
    )
    payload = canonical_relation_payload(result)
    mask = _hash(
        b"BL/PQ512/S6/MASK/v1\x00",
        _text(profile_id, "profile_id"),
        _text(backend_id, "backend_id"),
        repetition.to_bytes(4, "big"),
    )
    pre_challenge = derive_pre_challenge_digest(backend_id, statement, payload, mask)
    session_id = _hash(
        b"BL/PQ512/S6/SESSION/v1\x00",
        _text(profile_id, "profile_id"),
        _text(backend_id, "backend_id"),
        repetition.to_bytes(4, "big"),
    )
    message = derive_public_coin_message_digest(session_id, 0, pre_challenge)
    attestations: list[PublicCoinAttestation] = []
    adapters: dict[str, object] = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = authority_material[suite_id]
        attestations.append(
            PublicCoinAttestation(
                authority_id,
                suite_id,
                public_key,
                message,
                adapter.sign(secret_key=secret_key, message=message),
            )
        )
        adapters[suite_id] = adapter
    attestations.sort(key=lambda item: item.authority_id_512)
    coin_round = AuthenticatedPublicCoinRound(
        session_id,
        0,
        pre_challenge,
        tuple(attestations),
    )
    artifact = build_commitment(
        backend_id,
        statement,
        payload,
        mask,
        coin_round,
        adapters,
    )
    opening = build_opening(artifact, payload, mask, adapters)
    composition = build_atomic_composition(
        batch,
        result,
        projection,
        artifact,
        opening,
        adapters,
        epoch=7,
        sequence_before=22,
    )
    verify_start_ns = perf_counter_ns()
    independently_verify_composition(composition, batch, result, opening, adapters)
    verify_elapsed_ns = max(1, perf_counter_ns() - verify_start_ns)
    total_elapsed_ns = max(1, perf_counter_ns() - start_ns)
    return composition, total_elapsed_ns, verify_elapsed_ns, result.candidate_work_units


@dataclass(frozen=True, slots=True)
class CandidateMeasurement:
    backend_id: str
    profile_id: str
    repetition: int
    relation_candidate_id: str
    screening_accepted: bool
    rejection_reasons: tuple[str, ...]
    elapsed_ns: int
    verifier_elapsed_ns: int
    derived_work_units: int
    proof_bytes: int = 0
    independent_reference_verified: bool = True
    complete_boundary_verified: bool = False
    external_monitor_status: str = "NOT_RUN_NO_ELIGIBLE_FINALIST"
    measurement_label: str = MEASUREMENT_LABEL
    measurement_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _text(self.backend_id, "backend_id")
        try:
            backend = backend_descriptor(self.backend_id)
        except ValueError as exc:
            raise SelectionEvidenceError("s6_backend_unknown") from exc
        _text(self.profile_id, "profile_id")
        if self.profile_id not in PROFILE_IDS:
            raise SelectionEvidenceError("s6_profile_unknown")
        _u64(self.repetition, "repetition")
        if self.repetition >= MAX_REPETITIONS:
            raise SelectionEvidenceError("s6_repetition_too_large")
        _text(self.relation_candidate_id, "relation_candidate_id")
        if self.relation_candidate_id != RELATION_CANDIDATE_ID:
            raise SelectionEvidenceError("s6_relation_candidate_not_frozen")
        screening = screen_backend(self.backend_id)
        if self.screening_accepted != screening.accepted:
            raise SelectionEvidenceError("s6_screening_acceptance_not_recomputed")
        if self.rejection_reasons != screening.rejection_reasons:
            raise SelectionEvidenceError("s6_screening_reasons_not_recomputed")
        if type(self.rejection_reasons) is not tuple or any(
            type(reason) is not str or not reason for reason in self.rejection_reasons
        ):
            raise SelectionEvidenceError("s6_rejection_reasons_invalid")
        if self.screening_accepted:
            raise SelectionEvidenceError("s6_screened_candidate_must_not_be_admitted")
        if self.elapsed_ns <= 0 or self.verifier_elapsed_ns <= 0:
            raise SelectionEvidenceError("s6_observed_timing_invalid")
        if type(self.derived_work_units) is not int or self.derived_work_units <= 0:
            raise SelectionEvidenceError("s6_derived_work_invalid")
        if self.proof_bytes != 0:
            raise SelectionEvidenceError("s6_reference_proof_bytes_must_be_zero")
        if self.independent_reference_verified is not True:
            raise SelectionEvidenceError("s6_independent_reference_verification_required")
        if self.complete_boundary_verified is not False:
            raise SelectionEvidenceError("s6_complete_boundary_not_available")
        if self.external_monitor_status != COMPLETE_BOUNDARY_STATUS:
            raise SelectionEvidenceError("s6_external_monitor_status_invalid")
        if self.measurement_label != MEASUREMENT_LABEL:
            raise SelectionEvidenceError("s6_measurement_label_invalid")
        expected = _hash(
            _MEASUREMENT_DOMAIN,
            _text(backend.backend_id, "backend_id"),
            _text(self.profile_id, "profile_id"),
            self.repetition.to_bytes(8, "big"),
            _text(self.relation_candidate_id, "relation_candidate_id"),
            bytes((int(self.screening_accepted), int(self.independent_reference_verified))),
            b"".join(_text(reason, "rejection_reason") for reason in self.rejection_reasons),
            self.elapsed_ns.to_bytes(8, "big"),
            self.verifier_elapsed_ns.to_bytes(8, "big"),
            self.derived_work_units.to_bytes(8, "big"),
            self.proof_bytes.to_bytes(8, "big"),
            _text(self.external_monitor_status, "external_monitor_status"),
            _text(self.measurement_label, "measurement_label"),
        )
        if self.measurement_digest_512 not in (b"", expected):
            raise SelectionEvidenceError("s6_measurement_digest_mismatch")
        object.__setattr__(self, "measurement_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "boundary": REFERENCE_BOUNDARY,
            "backend_id": self.backend_id,
            "profile_id": self.profile_id,
            "repetition": self.repetition,
            "relation_candidate_id": self.relation_candidate_id,
            "screening_accepted": self.screening_accepted,
            "rejection_reasons": self.rejection_reasons,
            "elapsed_ns": self.elapsed_ns,
            "verifier_elapsed_ns": self.verifier_elapsed_ns,
            "derived_work_units": self.derived_work_units,
            "proof_bytes": self.proof_bytes,
            "independent_reference_verified": self.independent_reference_verified,
            "complete_boundary_verified": self.complete_boundary_verified,
            "external_monitor_status": self.external_monitor_status,
            "measurement_label": self.measurement_label,
            "measurement_digest_sha3_512_hex": self.measurement_digest_512.hex(),
        }


def measure_reference_candidate(
    backend_id: str,
    profile_id: str,
    authority_material: Mapping[str, object],
    *,
    repetitions: int = MIN_REPETITIONS,
) -> tuple[CandidateMeasurement, ...]:
    """Measure only the synthetic S2/S3/S4 component for one candidate/profile."""

    _synthetic()
    try:
        backend_descriptor(backend_id)
    except ValueError as exc:
        raise SelectionEvidenceError("s6_backend_unknown") from exc
    if profile_id not in PROFILE_IDS:
        raise SelectionEvidenceError("s6_profile_unknown")
    if type(repetitions) is not int or not MIN_REPETITIONS <= repetitions <= MAX_REPETITIONS:
        raise SelectionEvidenceError("s6_repetition_count_invalid")
    material = _authority_material(authority_material)
    screen = screen_backend(backend_id)
    measurements: list[CandidateMeasurement] = []
    for repetition in range(repetitions):
        _, elapsed_ns, verifier_elapsed_ns, work_units = _reference_case(
            backend_id,
            profile_id,
            repetition,
            material,
        )
        measurements.append(
            CandidateMeasurement(
                backend_id,
                profile_id,
                repetition,
                RELATION_CANDIDATE_ID,
                screen.accepted,
                screen.rejection_reasons,
                elapsed_ns,
                verifier_elapsed_ns,
                work_units,
            )
        )
    return tuple(measurements)


def measure_all_reference_components(
    authority_material: Mapping[str, object],
    *,
    repetitions: int = MIN_REPETITIONS,
) -> tuple[CandidateMeasurement, ...]:
    """Run the exact repeated component boundary for all five screened backends/profiles."""

    _synthetic()
    result: list[CandidateMeasurement] = []
    for profile_id in PROFILE_IDS:
        for backend_id in CANDIDATE_IDS:
            result.extend(
                measure_reference_candidate(
                    backend_id,
                    profile_id,
                    authority_material,
                    repetitions=repetitions,
                )
            )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class CandidateRejection:
    backend_id: str
    screening_reasons: tuple[str, ...]
    measurement_count: int
    complete_boundary_status: str = COMPLETE_BOUNDARY_STATUS
    rejection_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        try:
            backend_descriptor(self.backend_id)
        except ValueError as exc:
            raise SelectionEvidenceError("s7_backend_unknown") from exc
        if type(self.screening_reasons) is not tuple or not self.screening_reasons:
            raise SelectionEvidenceError("s7_rejection_reasons_empty")
        if self.measurement_count < 1:
            raise SelectionEvidenceError("s7_rejection_measurement_count_invalid")
        if self.complete_boundary_status != COMPLETE_BOUNDARY_STATUS:
            raise SelectionEvidenceError("s7_rejection_complete_status_invalid")
        expected = _hash(
            _REJECTION_DOMAIN,
            _text(self.backend_id, "backend_id"),
            b"".join(_text(reason, "rejection_reason") for reason in self.screening_reasons),
            self.measurement_count.to_bytes(8, "big"),
            _text(self.complete_boundary_status, "complete_boundary_status"),
        )
        if self.rejection_digest_512 not in (b"", expected):
            raise SelectionEvidenceError("s7_rejection_digest_mismatch")
        object.__setattr__(self, "rejection_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "backend_id": self.backend_id,
            "screening_reasons": self.screening_reasons,
            "measurement_count": self.measurement_count,
            "complete_boundary_status": self.complete_boundary_status,
            "rejection_digest_sha3_512_hex": self.rejection_digest_512.hex(),
        }


def _decision_digest(
    measurements: tuple[CandidateMeasurement, ...],
    rejections: tuple[CandidateRejection, ...],
    selection_status: str,
) -> bytes:
    return _hash(
        _DECISION_DOMAIN,
        _text(selection_status, "selection_status"),
        b"".join(item.measurement_digest_512 for item in measurements),
        b"".join(item.rejection_digest_512 for item in rejections),
        _text(C0_CONTROL_ID, "control_id"),
    )


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    measurements: tuple[CandidateMeasurement, ...]
    rejections: tuple[CandidateRejection, ...]
    selected_backend_id: None = None
    selected_relation_candidate_id: None = None
    fallback_control_id: str = C0_CONTROL_ID
    selection_status: str = SELECTION_STATUS
    warmup_status: str = COMPLETE_BOUNDARY_STATUS
    complete_boundary_status: str = COMPLETE_BOUNDARY_STATUS
    proof_suite_id: None = None
    activation_allowed: bool = False
    decision_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.measurements) is not tuple or not self.measurements:
            raise SelectionEvidenceError("s7_measurements_required")
        if any(type(item) is not CandidateMeasurement for item in self.measurements):
            raise SelectionEvidenceError("s7_measurement_type_invalid")
        if type(self.rejections) is not tuple or len(self.rejections) != len(CANDIDATE_IDS):
            raise SelectionEvidenceError("s7_rejection_count_invalid")
        if tuple(item.backend_id for item in self.rejections) != CANDIDATE_IDS:
            raise SelectionEvidenceError("s7_rejection_order_invalid")
        if any(type(item) is not CandidateRejection for item in self.rejections):
            raise SelectionEvidenceError("s7_rejection_type_invalid")
        if self.selected_backend_id is not None or self.selected_relation_candidate_id is not None:
            raise SelectionEvidenceError("s7_selection_must_remain_unset")
        if self.fallback_control_id != C0_CONTROL_ID:
            raise SelectionEvidenceError("s7_fallback_control_invalid")
        if self.selection_status != SELECTION_STATUS:
            raise SelectionEvidenceError("s7_selection_status_invalid")
        if self.warmup_status != COMPLETE_BOUNDARY_STATUS:
            raise SelectionEvidenceError("s7_warmup_status_invalid")
        if self.complete_boundary_status != COMPLETE_BOUNDARY_STATUS:
            raise SelectionEvidenceError("s7_complete_status_invalid")
        if self.proof_suite_id is not None or self.activation_allowed is not False:
            raise SelectionEvidenceError("s7_activation_fields_must_remain_closed")
        expected = _decision_digest(self.measurements, self.rejections, self.selection_status)
        if self.decision_digest_512 not in (b"", expected):
            raise SelectionEvidenceError("s7_decision_digest_mismatch")
        object.__setattr__(self, "decision_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "selection_status": self.selection_status,
            "selected_backend_id": self.selected_backend_id,
            "selected_relation_candidate_id": self.selected_relation_candidate_id,
            "fallback_control_id": self.fallback_control_id,
            "measurement_count": len(self.measurements),
            "rejections": tuple(item.as_public_dict() for item in self.rejections),
            "warmup_status": self.warmup_status,
            "complete_boundary_status": self.complete_boundary_status,
            "proofSuiteId": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
            "decision_digest_sha3_512_hex": self.decision_digest_512.hex(),
        }


def select_reference_candidates(
    measurements: tuple[CandidateMeasurement, ...],
) -> SelectionDecision:
    """Recompute screening and retain C0 without timing-based candidate selection."""

    _synthetic()
    if type(measurements) is not tuple or not measurements:
        raise SelectionEvidenceError("s7_measurements_required")
    if any(type(item) is not CandidateMeasurement for item in measurements):
        raise SelectionEvidenceError("s7_measurement_type_invalid")
    repetitions = {item.repetition for item in measurements}
    if len(repetitions) < MIN_REPETITIONS or repetitions != set(range(max(repetitions) + 1)):
        raise SelectionEvidenceError("s7_repetition_set_invalid")
    expected_count = len(CANDIDATE_IDS) * len(PROFILE_IDS) * len(repetitions)
    if len(measurements) != expected_count:
        raise SelectionEvidenceError("s7_measurement_count_invalid")
    identities = {
        (item.backend_id, item.profile_id, item.repetition) for item in measurements
    }
    expected_identities = {
        (backend_id, profile_id, repetition)
        for backend_id in CANDIDATE_IDS
        for profile_id in PROFILE_IDS
        for repetition in repetitions
    }
    if identities != expected_identities:
        raise SelectionEvidenceError("s7_measurement_identity_set_invalid")
    for item in measurements:
        screen = screen_backend(item.backend_id)
        if item.screening_accepted != screen.accepted or item.rejection_reasons != screen.rejection_reasons:
            raise SelectionEvidenceError("s7_screening_not_recomputed")
        if item.independent_reference_verified is not True:
            raise SelectionEvidenceError("s7_reference_verification_missing")
        if item.complete_boundary_verified is not False:
            raise SelectionEvidenceError("s7_complete_boundary_forged")
    ordered_measurements = tuple(
        sorted(measurements, key=lambda item: (CANDIDATE_IDS.index(item.backend_id), PROFILE_IDS.index(item.profile_id), item.repetition))
    )
    rejections = tuple(
        CandidateRejection(
            backend_id,
            screen_backend(backend_id).rejection_reasons
            + ("complete_boundary_not_authorized_for_rejected_candidate",),
            sum(item.backend_id == backend_id for item in ordered_measurements),
        )
        for backend_id in CANDIDATE_IDS
    )
    return SelectionDecision(ordered_measurements, rejections)


@dataclass(frozen=True, slots=True)
class SelectionHandoff:
    decision_digest_512: bytes
    commit_id: str
    tree_id: str
    git_clean: bool
    protected_paths_clean: bool
    canonical_ops_available: bool
    blockers: tuple[str, ...]
    status: str = HANDOFF_STATUS
    sealed: bool = False
    handoff_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _bytes(self.decision_digest_512, "handoff_decision_digest", nonzero=True)
        for value, label in ((self.commit_id, "commit_id"), (self.tree_id, "tree_id")):
            encoded = _text(value, label, 64)
            if len(encoded) not in {40, 64} or any(char not in b"0123456789abcdefABCDEF" for char in encoded):
                raise SelectionEvidenceError(f"s7_{label}_hex_invalid")
        if type(self.blockers) is not tuple or not self.blockers:
            raise SelectionEvidenceError("s7_handoff_blockers_required")
        if self.status != HANDOFF_STATUS or self.sealed is not False:
            raise SelectionEvidenceError("s7_handoff_must_remain_unsealed")
        expected = _hash(
            _HANDOFF_DOMAIN,
            self.decision_digest_512,
            _text(self.commit_id, "commit_id"),
            _text(self.tree_id, "tree_id"),
            bytes((int(self.git_clean), int(self.protected_paths_clean), int(self.canonical_ops_available))),
            b"".join(_text(blocker, "handoff_blocker") for blocker in self.blockers),
            _text(self.status, "handoff_status"),
        )
        if self.handoff_digest_512 not in (b"", expected):
            raise SelectionEvidenceError("s7_handoff_digest_mismatch")
        object.__setattr__(self, "handoff_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "sealed": self.sealed,
            "decision_digest_sha3_512_hex": self.decision_digest_512.hex(),
            "commit_id": self.commit_id,
            "tree_id": self.tree_id,
            "git_clean": self.git_clean,
            "protected_paths_clean": self.protected_paths_clean,
            "canonical_ops_available": self.canonical_ops_available,
            "blockers": self.blockers,
            "handoff_digest_sha3_512_hex": self.handoff_digest_512.hex(),
        }


def build_selection_handoff(
    decision: SelectionDecision,
    *,
    commit_id: str,
    tree_id: str,
    git_clean: bool,
    protected_paths_clean: bool,
    canonical_ops_available: bool,
) -> SelectionHandoff:
    _synthetic()
    if type(decision) is not SelectionDecision:
        raise SelectionEvidenceError("s7_decision_type_invalid")
    blockers = [
        "no_backend_admitted",
        "complete_boundary_not_authorized",
        "h4_atomic_binding_deferred",
    ]
    if not canonical_ops_available:
        blockers.append("canonical_ops_missing")
    if not git_clean:
        blockers.append("git_dirty")
    if not protected_paths_clean:
        blockers.append("protected_path_changed")
    return SelectionHandoff(
        decision.decision_digest_512,
        commit_id,
        tree_id,
        git_clean,
        protected_paths_clean,
        canonical_ops_available,
        tuple(blockers),
    )


__all__ = (
    "ACTIVATION_ALLOWED",
    "C0_CONTROL_ID",
    "COMPLETE_BOUNDARY_STATUS",
    "HANDOFF_STATUS",
    "MEASUREMENT_LABEL",
    "PROOF_SUITE_ID",
    "REFERENCE_BOUNDARY",
    "SELECTION_STATUS",
    "STATUS",
    "CandidateMeasurement",
    "CandidateRejection",
    "SelectionDecision",
    "SelectionEvidenceError",
    "SelectionHandoff",
    "build_selection_handoff",
    "measure_all_reference_components",
    "measure_reference_candidate",
    "select_reference_candidates",
)
