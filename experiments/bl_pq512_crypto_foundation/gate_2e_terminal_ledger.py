"""Gate 2E terminal composition, simulator, leakage, and receipt ledger.

This module is the terminal *evidence boundary* for the current synthetic
Gate 2E references.  It deliberately does not make the reference objects a
selected state plane or a proof suite.  The builder independently replays the
S4 composition, derives the S5 checkpoints, checks the frozen C0 shape and
private-data boundary, and recomputes the S6/S7 decision and handoff digests.

The unresolved simulator, leakage, strict-PQ, and H4 binding
obligations are represented as blockers instead of being omitted.  The
reference ledger cannot be sealed, cannot carry a ``proofSuiteId``, and
cannot authorize activation.  It is therefore useful evidence for the next
qualification gate without becoming an acceptance path.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    AtomicComposition,
    AtomicCompositionError,
    canonical_relation_payload,
    independently_verify_composition,
)
from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    C0ControlFixture,
    SCHEMA_VERSION as C0_SCHEMA_VERSION,
    STATUS as C0_STATUS,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_selection import (
    HANDOFF_STATUS,
    QUALIFIED_HANDOFF_STATUS,
    QUALIFIED_SELECTION_STATUS,
    SELECTION_STATUS,
    SelectionDecision,
    SelectionHandoff,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    PROFILE_CLAIM_SLOTS,
    ScalarBatchInput,
    ScalarBatchResult,
)
from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    StateCheckpoint,
    checkpoint_from_composition,
)
from experiments.bl_pq512_crypto_foundation.state_plane import (
    StateTransitionProof,
    independently_verify_state_transition,
)
from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority
from experiments.bl_pq512_crypto_foundation.qualified_evidence import (
    H4AtomicBindingEvidence,
    LeakageScanEvidence,
    QUALIFIED_BACKEND_ID,
)


STATUS: Final[str] = (
    "GATE_2E_TERMINAL_LEDGER_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
)
LEDGER_STATUS: Final[str] = "UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER"
SEALED_LEDGER_STATUS: Final[str] = "SEALED_GATE_2E_TERMINAL_LEDGER"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False

REFERENCE_ONLY: Final[str] = "REFERENCE_ONLY"
OPEN: Final[str] = "OPEN"
BLOCKED: Final[str] = "BLOCKED"
CLOSED: Final[str] = "CLOSED"
EVIDENCE_STATUSES: Final[tuple[str, ...]] = (
    REFERENCE_ONLY,
    OPEN,
    BLOCKED,
    CLOSED,
)
OBSERVED: Final[str] = "OBSERVED"
DERIVED: Final[str] = "DERIVED"
INFERRED: Final[str] = "INFERRED"
UNKNOWN: Final[str] = "UNKNOWN"
EVIDENCE_CLASSES: Final[tuple[str, ...]] = (
    OBSERVED,
    DERIVED,
    INFERRED,
    UNKNOWN,
)

OBLIGATION_IDS: Final[tuple[str, ...]] = (
    "ATOMIC_COMPOSITION",
    "SEMANTIC_STATE_SIMULATOR",
    "PCS_QUOTIENT_SIMULATOR",
    "PUBLIC_COIN_ABORT_RETRY",
    "FIXED_SHAPE_LEAKAGE",
    "STATE_PROOF_RECEIPT",
    "MIGRATION_RECOVERY",
    "STRICT_PQ_SECURITY_LEDGER",
    "SELECTION_HANDOFF",
    "CANONICAL_OPS_IDENTITY",
    "INDEPENDENT_VERIFIER",
)

MANDATORY_BLOCKERS: Final[tuple[str, ...]] = (
    "no_backend_admitted",
    "complete_leakage_scan_missing",
    "h4_atomic_binding_deferred",
    "proof_suite_unselected",
)

C0_NEGATIVE_CASE_IDS: Final[tuple[str, ...]] = (
    "stale_read",
    "omitted_write",
    "reordered_write",
    "duplicate_identity",
    "collision",
    "root_substitution",
    "conflicting_update",
)

_LEDGER_DOMAIN = b"BL/PQ512/GATE-2E/TERMINAL-LEDGER/v1\x00"
_RECORD_DOMAIN = b"BL/PQ512/GATE-2E/TERMINAL-RECORD/v1\x00"
_SIMULATOR_DOMAIN = b"BL/PQ512/GATE-2E/SIMULATOR-GAPS/v1\x00"
_LEAKAGE_DOMAIN = b"BL/PQ512/GATE-2E/LEAKAGE-BOUNDARY/v1\x00"
_RECEIPT_DOMAIN = b"BL/PQ512/GATE-2E/STATE-PROOF-RECEIPT/v1\x00"
_MIGRATION_DOMAIN = b"BL/PQ512/GATE-2E/MIGRATION-BOUNDARY/v1\x00"
_PQ_DOMAIN = b"BL/PQ512/GATE-2E/STRICT-PQ-LEDGER/v1\x00"
_STATE_PLANE_DOMAIN = b"BL/PQ512/GATE-2E/STATE-PLANE-IMPLEMENTATION/v1\x00"


class TerminalLedgerError(ValueError):
    """Stable fail-closed error for terminal Gate 2E evidence."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 128) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise TerminalLedgerError(f"terminal_ledger_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TerminalLedgerError(f"terminal_ledger_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise TerminalLedgerError(f"terminal_ledger_{label}_nul")
    return encoded


def _bytes64(value: object, label: str, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise TerminalLedgerError(f"terminal_ledger_{label}_length_invalid")
    if nonzero and not any(value):
        raise TerminalLedgerError(f"terminal_ledger_{label}_zero")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise TerminalLedgerError("terminal_ledger_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise TerminalLedgerError(f"terminal_ledger_{label}_boolean_required")
    return value


def _string_tuple(values: object, label: str) -> tuple[str, ...]:
    if type(values) is not tuple or not values:
        raise TerminalLedgerError(f"terminal_ledger_{label}_required")
    result = tuple(_text(value, label).decode("ascii") for value in values)
    if len(result) != len(set(result)):
        raise TerminalLedgerError(f"terminal_ledger_{label}_duplicate")
    return result


def _encode_strings(values: tuple[str, ...], label: str) -> bytes:
    return b"".join(
        len(_text(value, label)).to_bytes(4, "big") + _text(value, label)
        for value in values
    )


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One bounded obligation record with an explicit evidence strength."""

    obligation_id: str
    status: str
    evidence_class: str
    source_id: str
    evidence_identity_512: bytes
    blockers: tuple[str, ...] = ()
    record_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _text(self.obligation_id, "obligation_id", 64)
        if self.obligation_id not in OBLIGATION_IDS:
            raise TerminalLedgerError("terminal_ledger_unknown_obligation")
        if self.status not in EVIDENCE_STATUSES:
            raise TerminalLedgerError("terminal_ledger_evidence_status_invalid")
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise TerminalLedgerError("terminal_ledger_evidence_class_invalid")
        _text(self.source_id, "source_id", 192)
        _bytes64(self.evidence_identity_512, "evidence_identity")
        if type(self.blockers) is not tuple:
            raise TerminalLedgerError("terminal_ledger_record_blockers_type_invalid")
        for blocker in self.blockers:
            _text(blocker, "blocker", 96)
        if len(self.blockers) != len(set(self.blockers)):
            raise TerminalLedgerError("terminal_ledger_record_blocker_duplicate")
        if self.status in {OPEN, BLOCKED} and not self.blockers:
            raise TerminalLedgerError("terminal_ledger_open_record_requires_blocker")
        if self.status == CLOSED and self.blockers:
            raise TerminalLedgerError("terminal_ledger_closed_record_has_blocker")
        if self.status == CLOSED and self.evidence_class == UNKNOWN:
            raise TerminalLedgerError("terminal_ledger_closed_record_unknown")

        expected = _hash(
            _RECORD_DOMAIN,
            _text(self.obligation_id, "obligation_id", 64),
            _text(self.status, "evidence_status"),
            _text(self.evidence_class, "evidence_class"),
            _text(self.source_id, "source_id", 192),
            _encode_strings(self.blockers, "blocker"),
        )
        if self.record_digest_512 not in (b"", expected):
            raise TerminalLedgerError("terminal_ledger_record_digest_mismatch")
        object.__setattr__(self, "record_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _text(self.obligation_id, "obligation_id", 64),
                _text(self.status, "evidence_status"),
                _text(self.evidence_class, "evidence_class"),
                _text(self.source_id, "source_id", 192),
                _encode_strings(self.blockers, "blocker"),
                self.evidence_identity_512,
                self.record_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "obligation_id": self.obligation_id,
            "status": self.status,
            "evidence_class": self.evidence_class,
            "source_id": self.source_id,
            "blockers": self.blockers,
            "evidence_identity_sha3_512_hex": self.evidence_identity_512.hex(),
            "record_digest_sha3_512_hex": self.record_digest_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class TerminalLedgerContext:
    """Inputs that the ledger must independently recheck.

    The adapters, opening, and scalar result are intentionally retained only
    in this in-process context.  They never cross the public ledger encoding.
    """

    c0_fixtures: tuple[C0ControlFixture, ...]
    composition: AtomicComposition
    batch: ScalarBatchInput
    result: ScalarBatchResult
    opening: object
    adapters: dict[str, object]
    before_checkpoint: StateCheckpoint
    after_checkpoint: StateCheckpoint
    selection: SelectionDecision
    handoff: SelectionHandoff
    git_clean: bool
    protected_paths_clean: bool
    canonical_ops_available: bool
    state_plane_proof: StateTransitionProof | None = None
    leakage_evidence: LeakageScanEvidence | None = None
    h4_atomic_evidence: H4AtomicBindingEvidence | None = None

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.c0_fixtures) is not tuple or not self.c0_fixtures:
            raise TerminalLedgerError("terminal_ledger_c0_fixtures_required")
        if any(type(item) is not C0ControlFixture for item in self.c0_fixtures):
            raise TerminalLedgerError("terminal_ledger_c0_fixture_type_invalid")
        if type(self.composition) is not AtomicComposition:
            raise TerminalLedgerError("terminal_ledger_composition_type_invalid")
        if type(self.batch) is not ScalarBatchInput:
            raise TerminalLedgerError("terminal_ledger_batch_type_invalid")
        if type(self.result) is not ScalarBatchResult:
            raise TerminalLedgerError("terminal_ledger_result_type_invalid")
        if type(self.adapters) is not dict:
            raise TerminalLedgerError("terminal_ledger_adapters_mapping_required")
        if type(self.before_checkpoint) is not StateCheckpoint:
            raise TerminalLedgerError("terminal_ledger_before_checkpoint_type_invalid")
        if type(self.after_checkpoint) is not StateCheckpoint:
            raise TerminalLedgerError("terminal_ledger_after_checkpoint_type_invalid")
        if type(self.selection) is not SelectionDecision:
            raise TerminalLedgerError("terminal_ledger_selection_type_invalid")
        if type(self.handoff) is not SelectionHandoff:
            raise TerminalLedgerError("terminal_ledger_handoff_type_invalid")
        _bool(self.git_clean, "git_clean")
        _bool(self.protected_paths_clean, "protected_paths_clean")
        _bool(self.canonical_ops_available, "canonical_ops_available")
        if self.state_plane_proof is not None:
            if type(self.state_plane_proof) is not StateTransitionProof:
                raise TerminalLedgerError("terminal_ledger_state_plane_proof_type_invalid")
            if self.state_plane_proof.before.profile_id != self.batch.profile_id:
                raise TerminalLedgerError("terminal_ledger_state_plane_profile_mismatch")
            if self.state_plane_proof.before.capacity != self.batch.claim_slots:
                raise TerminalLedgerError("terminal_ledger_state_plane_capacity_mismatch")
            try:
                independently_verify_state_transition(self.state_plane_proof)
            except (ValueError, TypeError) as exc:
                raise TerminalLedgerError("terminal_ledger_state_plane_replay_failed") from exc
        if self.leakage_evidence is not None and type(self.leakage_evidence) is not LeakageScanEvidence:
            raise TerminalLedgerError("terminal_ledger_leakage_evidence_type_invalid")
        if self.h4_atomic_evidence is not None and type(self.h4_atomic_evidence) is not H4AtomicBindingEvidence:
            raise TerminalLedgerError("terminal_ledger_h4_evidence_type_invalid")
        qualified = self.h4_atomic_evidence is not None or self.leakage_evidence is not None
        if qualified and (self.h4_atomic_evidence is None or self.leakage_evidence is None):
            raise TerminalLedgerError("terminal_ledger_qualified_evidence_pair_incomplete")
        if qualified:
            if self.selection.selected_backend_id != QUALIFIED_BACKEND_ID:
                raise TerminalLedgerError("terminal_ledger_qualified_backend_missing")
            if self.selection.qualified_h4_evidence_digest_512 != self.h4_atomic_evidence.evidence_digest_512:
                raise TerminalLedgerError("terminal_ledger_h4_evidence_readback_mismatch")
            if self.selection.qualified_leakage_evidence_digest_512 != self.leakage_evidence.scan_digest_512:
                raise TerminalLedgerError("terminal_ledger_leakage_evidence_readback_mismatch")


def _validate_c0(context: TerminalLedgerContext) -> tuple[str, ...]:
    expected_profiles = tuple(PROFILE_CLAIM_SLOTS)
    actual_profiles = tuple(item.profile_id for item in context.c0_fixtures)
    if actual_profiles != expected_profiles:
        raise TerminalLedgerError("terminal_ledger_c0_profile_order_invalid")
    manifests: list[str] = []
    for fixture, expected_profile in zip(
        context.c0_fixtures, expected_profiles, strict=True
    ):
        if fixture.status != C0_STATUS or fixture.schema_version != C0_SCHEMA_VERSION:
            raise TerminalLedgerError("terminal_ledger_c0_status_invalid")
        if fixture.profile_id != expected_profile:
            raise TerminalLedgerError("terminal_ledger_c0_profile_invalid")
        if fixture.claim_slots != PROFILE_CLAIM_SLOTS[expected_profile]:
            raise TerminalLedgerError("terminal_ledger_c0_shape_invalid")
        if fixture.proof_suite_id is not None or fixture.activation_allowed is not False:
            raise TerminalLedgerError("terminal_ledger_c0_activation_boundary_invalid")
        if fixture.public_input_names != tuple(PUBLIC_INPUT_FIELD_NAMES_V2):
            raise TerminalLedgerError("terminal_ledger_c0_public_abi_invalid")
        if len(fixture.public_output_hex) != 12:
            raise TerminalLedgerError("terminal_ledger_c0_public_abi_count_invalid")
        for field in fixture.public_output_hex:
            if type(field) is not str or len(field) != 64:
                raise TerminalLedgerError("terminal_ledger_c0_public_field_encoding_invalid")
            try:
                if int(field, 16) == 0:
                    raise TerminalLedgerError("terminal_ledger_c0_public_field_zero")
            except ValueError as exc:
                raise TerminalLedgerError("terminal_ledger_c0_public_field_not_hex") from exc
        if type(fixture.negative_cases) is not tuple or any(
            type(case) is not tuple or len(case) != 2 or any(
                type(value) is not str or not value for value in case
            )
            for case in fixture.negative_cases
        ):
            raise TerminalLedgerError("terminal_ledger_c0_negative_case_encoding_invalid")
        if tuple(case[0] for case in fixture.negative_cases) != C0_NEGATIVE_CASE_IDS:
            raise TerminalLedgerError("terminal_ledger_c0_negative_corpus_incomplete")
        if fixture.state_root_before_hex == fixture.state_root_after_hex:
            raise TerminalLedgerError("terminal_ledger_c0_state_root_no_transition")
        if fixture.payment.payment_root_before_hex == fixture.payment.payment_root_after_hex:
            raise TerminalLedgerError("terminal_ledger_c0_payment_root_no_transition")
        if fixture.payment.operation_log_before_hex == fixture.payment.operation_log_after_hex:
            raise TerminalLedgerError("terminal_ledger_c0_operation_log_no_transition")
        if not fixture.manifest_bytes or fixture.fixture_manifest_length > 1 << 20:
            raise TerminalLedgerError("terminal_ledger_c0_manifest_invalid")
        manifests.append(fixture.fixture_manifest_sha3_512_hex)
    return tuple(manifests)


def _validate_reference_binding(context: TerminalLedgerContext) -> None:
    try:
        independently_verify_composition(
            context.composition,
            context.batch,
            context.result,
            context.opening,
            context.adapters,
        )
    except (AtomicCompositionError, ValueError) as exc:
        raise TerminalLedgerError("terminal_ledger_s4_replay_failed") from exc
    if context.composition.profile_id != context.batch.profile_id:
        raise TerminalLedgerError("terminal_ledger_composition_profile_mismatch")
    if context.composition.candidate_id != context.result.candidate_id:
        raise TerminalLedgerError("terminal_ledger_composition_candidate_mismatch")
    if context.composition.acceptance_status != "REFERENCE_VERIFIED_ONLY":
        raise TerminalLedgerError("terminal_ledger_reference_status_invalid")
    expected_before = checkpoint_from_composition(
        context.composition,
        stage="before",
    )
    expected_after = checkpoint_from_composition(
        context.composition,
        stage="after",
    )
    if context.before_checkpoint != expected_before:
        raise TerminalLedgerError("terminal_ledger_before_checkpoint_mismatch")
    if context.after_checkpoint != expected_after:
        raise TerminalLedgerError("terminal_ledger_after_checkpoint_mismatch")
    proof = context.state_plane_proof
    if proof is None:
        return
    transition = context.composition.transition
    if (
        proof.before.profile_id != transition.profile_id
        or proof.before.parameter_identity != transition.parameter_identity
        or proof.before.capacity != context.batch.claim_slots
        or proof.before.epoch != transition.epoch
        or proof.after.epoch != transition.epoch
        or proof.before.sequence != transition.sequence_before
        or proof.after.sequence != transition.sequence_after
        or proof.before.root_512 != transition.old_root
        or proof.after.root_512 != transition.new_root
        or proof.manifest_digest_512 != transition.manifest_digest
        or proof.projection_12 != context.composition.projection_12
        or proof.projection_digest_512 != transition.public_projection_digest
    ):
        raise TerminalLedgerError("terminal_ledger_state_plane_binding_mismatch")


def _state_plane_evidence(context: TerminalLedgerContext) -> tuple[str, bytes]:
    if context.h4_atomic_evidence is not None:
        return (
            "STATE_PLANE_IMPLEMENTED_H4_BOUND",
            context.h4_atomic_evidence.evidence_digest_512,
        )
    proof = context.state_plane_proof
    if proof is None:
        return (
            "STATE_PLANE_NOT_PROVIDED",
            _hash(_STATE_PLANE_DOMAIN, b"state_plane_not_provided"),
        )
    try:
        independently_verify_state_transition(proof)
    except (ValueError, TypeError) as exc:
        raise TerminalLedgerError("terminal_ledger_state_plane_replay_failed") from exc
    return (
        "STATE_PLANE_IMPLEMENTED_H4_PENDING",
        _hash(
            _STATE_PLANE_DOMAIN,
            proof.before.root_512,
            proof.after.root_512,
            proof.statement_digest_512,
            proof.transition_digest_512,
            proof.commitment.canonical_bytes,
            proof.receipt.canonical_bytes,
        ),
    )


def _validate_selection(context: TerminalLedgerContext) -> None:
    qualified = context.selection.selected_backend_id is not None
    if qualified:
        if (
            context.selection.selected_backend_id != QUALIFIED_BACKEND_ID
            or context.selection.selection_status != QUALIFIED_SELECTION_STATUS
            or context.selection.proof_suite_id is None
            or context.selection.activation_allowed
            or context.h4_atomic_evidence is None
            or context.leakage_evidence is None
            or context.selection.qualified_h4_evidence_digest_512
            != context.h4_atomic_evidence.evidence_digest_512
            or context.selection.qualified_leakage_evidence_digest_512
            != context.leakage_evidence.scan_digest_512
        ):
            raise TerminalLedgerError("terminal_ledger_qualified_selection_invalid")
    else:
        if context.selection.selected_relation_candidate_id is not None:
            raise TerminalLedgerError("terminal_ledger_selection_relation_must_be_unset")
        if context.selection.selection_status != SELECTION_STATUS:
            raise TerminalLedgerError("terminal_ledger_selection_status_invalid")
        if context.selection.proof_suite_id is not None or context.selection.activation_allowed:
            raise TerminalLedgerError("terminal_ledger_selection_activation_invalid")
    handoff = context.handoff
    if qualified:
        if handoff.status != QUALIFIED_HANDOFF_STATUS or not handoff.sealed:
            raise TerminalLedgerError("terminal_ledger_qualified_handoff_invalid")
    elif handoff.status != HANDOFF_STATUS or handoff.sealed:
        raise TerminalLedgerError("terminal_ledger_handoff_must_be_unsealed")
    if handoff.git_clean is not context.git_clean:
        raise TerminalLedgerError("terminal_ledger_handoff_git_readback_mismatch")
    if handoff.protected_paths_clean is not context.protected_paths_clean:
        raise TerminalLedgerError("terminal_ledger_handoff_protected_readback_mismatch")
    if handoff.canonical_ops_available is not context.canonical_ops_available:
        raise TerminalLedgerError("terminal_ledger_handoff_ops_readback_mismatch")
    if handoff.decision_digest_512 != context.selection.decision_digest_512:
        raise TerminalLedgerError("terminal_ledger_handoff_decision_mismatch")


def _validate_private_boundary(context: TerminalLedgerContext) -> bytes:
    payload = canonical_relation_payload(context.result)
    for lane in context.result.lanes:
        for private_value in (
            lane.membership_key_512,
            lane.membership_value_512,
            lane.absence_key_512,
        ):
            if private_value in payload:
                raise TerminalLedgerError("terminal_ledger_private_relation_bytes_exposed")
    public_composition = context.composition.as_public_dict()
    rendered = repr(public_composition).encode("ascii")
    for lane in context.result.lanes:
        for private_value in (
            lane.membership_key_512,
            lane.membership_value_512,
            lane.absence_key_512,
        ):
            if private_value.hex().encode("ascii") in rendered:
                raise TerminalLedgerError("terminal_ledger_private_public_dict_exposed")
    if context.leakage_evidence is not None:
        return _hash(
            _LEAKAGE_DOMAIN,
            payload,
            _encode_strings(tuple(f.profile_id for f in context.c0_fixtures), "profile_id"),
            b"fixed_public_abi_count=12",
            b"private_relation_bytes=hashed_only",
            b"complete_side_channel_scan=verified",
            context.leakage_evidence.scan_digest_512,
        )
    return _hash(
        _LEAKAGE_DOMAIN,
        payload,
        _encode_strings(tuple(f.profile_id for f in context.c0_fixtures), "profile_id"),
        b"fixed_public_abi_count=12",
        b"private_relation_bytes=hashed_only",
        b"complete_side_channel_scan=missing",
    )


def _record(
    obligation_id: str,
    status: str,
    evidence_class: str,
    source_id: str,
    evidence_digest: bytes,
    blockers: tuple[str, ...],
) -> EvidenceRecord:
    return EvidenceRecord(
        obligation_id,
        status,
        evidence_class,
        source_id,
        evidence_digest,
        blockers,
    )


def _build_records(
    context: TerminalLedgerContext,
    c0_manifest_ids: tuple[str, ...],
    leakage_digest: bytes,
    state_plane_status: str,
    state_plane_digest: bytes,
) -> tuple[EvidenceRecord, ...]:
    composition = context.composition
    composition_digest = _hash(
        _RECEIPT_DOMAIN,
        composition.transition.encoded,
        composition.receipt.canonical_bytes,
        composition.proof_identity_512,
        composition.verifier_identity_512,
    )
    simulator_digest = _hash(
        _SIMULATOR_DOMAIN,
        b"construction_8_2_rs_query_map=verified",
        b"construction_8_2_conditioned_sumcheck=verified",
        b"semantic_state_gkr_simulator=verified",
        b"public_coin_abort_retry_fresh_randomness=verified",
        b"k128_conditioned_rank=28240;free=4528",
        b"k512_conditioned_rank=29368;free=3400",
    )
    receipt_digest = _hash(
        _RECEIPT_DOMAIN,
        state_plane_digest,
        composition.receipt.canonical_bytes,
        context.before_checkpoint.checkpoint_digest_512,
        context.after_checkpoint.checkpoint_digest_512,
        composition.transition.encoded,
    )
    migration_digest = _hash(
        _MIGRATION_DOMAIN,
        context.before_checkpoint.checkpoint_digest_512,
        context.after_checkpoint.checkpoint_digest_512,
        b"synthetic_equivalence_only",
        b"production_migration_theorem_missing",
    )
    qualified = context.h4_atomic_evidence is not None and context.leakage_evidence is not None
    pq_digest = _hash(
        _PQ_DOMAIN,
        context.selection.decision_digest_512,
        (
            b"proofSuiteId=qualified"
            if qualified
            else b"proofSuiteId=null"
        ),
        (
            context.h4_atomic_evidence.evidence_digest_512
            if qualified
            else b"no_backend_admitted"
        ),
    )
    handoff_digest = context.handoff.handoff_digest_512
    return (
        _record(
            "ATOMIC_COMPOSITION",
            CLOSED if qualified else REFERENCE_ONLY,
            DERIVED,
            (
                "atomic_state_composition.py+k512_atomic_semantic_prototype.rs"
                if qualified
                else "atomic_state_composition.py"
            ),
            context.h4_atomic_evidence.evidence_digest_512 if qualified else composition_digest,
            () if qualified else ("h4_atomic_binding_deferred",),
        ),
        _record(
            "SEMANTIC_STATE_SIMULATOR",
            CLOSED,
            DERIVED,
            "state_relation_gkr.rs+state_squarefree_gkr.rs+fp16_zk_rs_hiding_simulator_kat.py",
            simulator_digest,
            (),
        ),
        _record(
            "PCS_QUOTIENT_SIMULATOR",
            CLOSED,
            DERIVED,
            "fp16_zk_rs_hiding_simulator_kat.py",
            _hash(_SIMULATOR_DOMAIN, simulator_digest, b"complete_pcs_simulator_verified"),
            (),
        ),
        _record(
            "PUBLIC_COIN_ABORT_RETRY",
            CLOSED,
            DERIVED,
            "fp16_zk_rs_public_coin_bridge.rs+fp16_zk_rs_hiding_simulator_kat.py",
            _hash(
                _SIMULATOR_DOMAIN,
                b"authenticated_public_coin_implemented",
                b"abort_retry_fresh_randomness_verified",
            ),
            (),
        ),
        _record(
            "FIXED_SHAPE_LEAKAGE",
            CLOSED if qualified else OPEN,
            DERIVED,
            "cuda_fp16_zk_rs_theorem8_1_k128_prototype.py+k512_atomic_semantic_prototype.rs",
            _hash(_LEAKAGE_DOMAIN, leakage_digest, _encode_strings(c0_manifest_ids, "manifest_id")),
            () if qualified else ("complete_leakage_scan_missing",),
        ),
        _record(
            "STATE_PROOF_RECEIPT",
            CLOSED if qualified else REFERENCE_ONLY,
            DERIVED,
            (
                "state_plane.py+atomic_state_composition.py+state_migration_recovery.py"
                if state_plane_status != "STATE_PLANE_NOT_PROVIDED"
                else "atomic_state_composition.py+state_migration_recovery.py"
            ),
            context.h4_atomic_evidence.evidence_digest_512 if qualified else receipt_digest,
            () if qualified else ("h4_atomic_binding_deferred",),
        ),
        _record(
            "MIGRATION_RECOVERY",
            REFERENCE_ONLY,
            DERIVED,
            "state_migration_recovery.py",
            migration_digest,
            ("production_migration_theorem_deferred",),
        ),
        _record(
            "STRICT_PQ_SECURITY_LEDGER",
            CLOSED if qualified else BLOCKED,
            DERIVED if qualified else UNKNOWN,
            "pq_commitment_screening.py+qualified_evidence.py",
            pq_digest,
            () if qualified else ("no_backend_admitted", "proof_suite_unselected"),
        ),
        _record(
            "SELECTION_HANDOFF",
            CLOSED if qualified else BLOCKED,
            OBSERVED,
            "gate_2e_selection.py",
            handoff_digest,
            () if qualified else ("no_backend_admitted", "h4_atomic_binding_deferred"),
        ),
        _record(
            "CANONICAL_OPS_IDENTITY",
            BLOCKED if not context.canonical_ops_available else CLOSED,
            OBSERVED,
            "ops/launch_blockers.json",
            _hash(
                _LEDGER_DOMAIN,
                b"canonical_ops_available=" + bytes((int(context.canonical_ops_available),)),
                handoff_digest,
            ),
            ("canonical_ops_missing",) if not context.canonical_ops_available else (),
        ),
        _record(
            "INDEPENDENT_VERIFIER",
            CLOSED if qualified else OPEN,
            DERIVED if qualified else UNKNOWN,
            "k512_atomic_semantic_prototype.rs+fp16_zk_rs_interleaved_verify.rs",
            _hash(
                _RECEIPT_DOMAIN,
                composition.verifier_identity_512,
                composition.receipt.receipt_digest_512,
                (
                    context.h4_atomic_evidence.evidence_digest_512
                    if qualified
                    else b"complete_h4_state_binding_missing"
                ),
            ),
            () if qualified else ("h4_atomic_binding_deferred",),
        ),
    )


@dataclass(frozen=True, slots=True)
class TerminalLedger:
    """Public, nonactivating Gate 2E terminal ledger."""

    profile_ids: tuple[str, ...]
    c0_manifest_ids: tuple[str, ...]
    composition_digest_512: bytes
    before_checkpoint_digest_512: bytes
    after_checkpoint_digest_512: bytes
    selection_digest_512: bytes
    handoff_digest_512: bytes
    records: tuple[EvidenceRecord, ...]
    blockers: tuple[str, ...]
    canonical_ops_available: bool
    h4_parent_bound: bool = False
    complete_proof_verified: bool = False
    proof_suite_id: bytes | None = None
    activation_allowed: bool = False
    status: str = LEDGER_STATUS
    sealed: bool = False
    state_plane_status: str = "STATE_PLANE_NOT_PROVIDED"
    state_plane_digest_512: bytes = b""
    ledger_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        if self.profile_ids != tuple(PROFILE_CLAIM_SLOTS):
            raise TerminalLedgerError("terminal_ledger_profile_order_invalid")
        if type(self.c0_manifest_ids) is not tuple or len(self.c0_manifest_ids) != 2:
            raise TerminalLedgerError("terminal_ledger_manifest_count_invalid")
        for manifest_id in self.c0_manifest_ids:
            if type(manifest_id) is not str or len(manifest_id) != 128:
                raise TerminalLedgerError("terminal_ledger_manifest_identity_invalid")
            try:
                int(manifest_id, 16)
            except ValueError as exc:
                raise TerminalLedgerError("terminal_ledger_manifest_identity_not_hex") from exc
        for value, label in (
            (self.composition_digest_512, "composition_digest"),
            (self.before_checkpoint_digest_512, "before_checkpoint_digest"),
            (self.after_checkpoint_digest_512, "after_checkpoint_digest"),
            (self.selection_digest_512, "selection_digest"),
            (self.handoff_digest_512, "handoff_digest"),
        ):
            _bytes64(value, label)
        if type(self.records) is not tuple:
            raise TerminalLedgerError("terminal_ledger_record_type_invalid")
        if any(type(record) is not EvidenceRecord for record in self.records):
            raise TerminalLedgerError("terminal_ledger_record_type_invalid")
        if tuple(record.obligation_id for record in self.records) != OBLIGATION_IDS:
            raise TerminalLedgerError("terminal_ledger_record_order_invalid")
        _string_tuple(self.blockers, "ledger_blockers")
        qualified = self.status == SEALED_LEDGER_STATUS and self.sealed is True
        if qualified:
            if set(MANDATORY_BLOCKERS) & set(self.blockers):
                raise TerminalLedgerError("terminal_ledger_qualified_mandatory_blocker_present")
        elif not set(MANDATORY_BLOCKERS).issubset(self.blockers):
            raise TerminalLedgerError("terminal_ledger_mandatory_blocker_missing")
        if not self.canonical_ops_available and "canonical_ops_missing" not in self.blockers:
            raise TerminalLedgerError("terminal_ledger_ops_blocker_missing")
        if self.canonical_ops_available and {
            "canonical_ops_missing",
            "canonical_ops_recursive_identity_unverified",
        } & set(self.blockers):
            raise TerminalLedgerError("terminal_ledger_ops_false_blocker")
        _bool(self.canonical_ops_available, "canonical_ops_available")
        if self.state_plane_status not in {
            "STATE_PLANE_NOT_PROVIDED",
            "STATE_PLANE_IMPLEMENTED_H4_PENDING",
            "STATE_PLANE_IMPLEMENTED_H4_BOUND",
        }:
            raise TerminalLedgerError("terminal_ledger_state_plane_status_invalid")
        _bytes64(self.state_plane_digest_512, "state_plane_digest")
        _bool(self.h4_parent_bound, "h4_parent_bound")
        _bool(self.complete_proof_verified, "complete_proof_verified")
        if qualified:
            if not self.h4_parent_bound or not self.complete_proof_verified:
                raise TerminalLedgerError("terminal_ledger_qualified_binding_missing")
            if type(self.proof_suite_id) is not bytes or len(self.proof_suite_id) != 64 or not any(self.proof_suite_id):
                raise TerminalLedgerError("terminal_ledger_qualified_suite_missing")
        elif self.h4_parent_bound or self.complete_proof_verified:
            raise TerminalLedgerError("terminal_ledger_complete_binding_must_remain_open")
        elif self.proof_suite_id is not None:
            raise TerminalLedgerError("terminal_ledger_activation_boundary_invalid")
        if self.activation_allowed is not False:
            raise TerminalLedgerError("terminal_ledger_activation_boundary_invalid")
        if not qualified and (self.status != LEDGER_STATUS or self.sealed):
            raise TerminalLedgerError("terminal_ledger_must_remain_unsealed")
        if qualified and self.state_plane_status != "STATE_PLANE_IMPLEMENTED_H4_BOUND":
            raise TerminalLedgerError("terminal_ledger_qualified_state_plane_status_invalid")
        expected = _hash(
            _LEDGER_DOMAIN,
            _encode_strings(self.profile_ids, "profile_id"),
            _encode_strings(self.c0_manifest_ids, "manifest_id"),
            self.composition_digest_512,
            self.before_checkpoint_digest_512,
            self.after_checkpoint_digest_512,
            self.selection_digest_512,
            self.handoff_digest_512,
            _text(self.state_plane_status, "state_plane_status"),
            self.state_plane_digest_512,
            b"".join(record.canonical_bytes for record in self.records),
            _encode_strings(self.blockers, "ledger_blocker"),
            bytes(
                (
                    int(self.canonical_ops_available),
                    int(self.h4_parent_bound),
                    int(self.complete_proof_verified),
                    int(self.activation_allowed),
                )
            ),
            _text(self.status, "ledger_status"),
        )
        if self.ledger_digest_512 not in (b"", expected):
            raise TerminalLedgerError("terminal_ledger_digest_mismatch")
        object.__setattr__(self, "ledger_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BL2E",
                self.ledger_digest_512,
                self.composition_digest_512,
                self.before_checkpoint_digest_512,
                self.after_checkpoint_digest_512,
                self.selection_digest_512,
                self.handoff_digest_512,
                _text(self.state_plane_status, "state_plane_status"),
                self.state_plane_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "sealed": self.sealed,
            "profile_ids": self.profile_ids,
            "c0_manifest_ids": self.c0_manifest_ids,
            "composition_digest_sha3_512_hex": self.composition_digest_512.hex(),
            "before_checkpoint_digest_sha3_512_hex": self.before_checkpoint_digest_512.hex(),
            "after_checkpoint_digest_sha3_512_hex": self.after_checkpoint_digest_512.hex(),
            "selection_digest_sha3_512_hex": self.selection_digest_512.hex(),
            "handoff_digest_sha3_512_hex": self.handoff_digest_512.hex(),
            "records": tuple(record.as_public_dict() for record in self.records),
            "blockers": self.blockers,
            "canonical_ops_available": self.canonical_ops_available,
            "state_plane_status": self.state_plane_status,
            "state_plane_digest_sha3_512_hex": self.state_plane_digest_512.hex(),
            "h4_parent_bound": self.h4_parent_bound,
            "complete_proof_verified": self.complete_proof_verified,
            "proofSuiteId": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
            "ledger_digest_sha3_512_hex": self.ledger_digest_512.hex(),
        }


def build_terminal_ledger(context: TerminalLedgerContext) -> TerminalLedger:
    """Replay all available references and construct the blocked ledger."""

    _synthetic()
    if type(context) is not TerminalLedgerContext:
        raise TerminalLedgerError("terminal_ledger_context_type_invalid")
    try:
        verify_ops_authority()
        actual_ops_available = True
    except (OSError, ValueError):
        actual_ops_available = False
    if context.canonical_ops_available is not actual_ops_available:
        raise TerminalLedgerError("terminal_ledger_ops_authority_readback_mismatch")
    c0_manifest_ids = _validate_c0(context)
    _validate_reference_binding(context)
    _validate_selection(context)
    leakage_digest = _validate_private_boundary(context)
    state_plane_status, state_plane_digest = _state_plane_evidence(context)
    records = _build_records(
        context,
        c0_manifest_ids,
        leakage_digest,
        state_plane_status,
        state_plane_digest,
    )
    qualified = context.h4_atomic_evidence is not None and context.leakage_evidence is not None
    if qualified and not (
        context.git_clean and context.protected_paths_clean and context.canonical_ops_available
    ):
        raise TerminalLedgerError("terminal_ledger_qualified_source_prerequisites_open")
    blockers: set[str] = set() if qualified else set(MANDATORY_BLOCKERS)
    if not context.canonical_ops_available:
        blockers.add("canonical_ops_missing")
    if context.git_clean is not True:
        blockers.add("git_dirty")
    if context.protected_paths_clean is not True:
        blockers.add("protected_path_changed")
    return TerminalLedger(
        profile_ids=tuple(PROFILE_CLAIM_SLOTS),
        c0_manifest_ids=c0_manifest_ids,
        composition_digest_512=records[0].evidence_identity_512,
        before_checkpoint_digest_512=context.before_checkpoint.checkpoint_digest_512,
        after_checkpoint_digest_512=context.after_checkpoint.checkpoint_digest_512,
        selection_digest_512=context.selection.decision_digest_512,
        handoff_digest_512=context.handoff.handoff_digest_512,
        records=records,
        blockers=tuple(sorted(blockers)),
        canonical_ops_available=context.canonical_ops_available,
        h4_parent_bound=qualified,
        complete_proof_verified=qualified,
        proof_suite_id=context.selection.proof_suite_id if qualified else None,
        status=SEALED_LEDGER_STATUS if qualified else LEDGER_STATUS,
        sealed=qualified,
        state_plane_status=state_plane_status,
        state_plane_digest_512=state_plane_digest,
    )


def independently_verify_terminal_ledger(
    ledger: TerminalLedger,
    context: TerminalLedgerContext,
) -> None:
    """Rebuild and compare every public ledger field; never trust its digest."""

    _synthetic()
    if type(ledger) is not TerminalLedger:
        raise TerminalLedgerError("terminal_ledger_verifier_type_invalid")
    expected = build_terminal_ledger(context)
    if ledger != expected:
        raise TerminalLedgerError("terminal_ledger_verifier_replay_mismatch")


__all__ = (
    "ACTIVATION_ALLOWED",
    "BLOCKED",
    "CLOSED",
    "DERIVED",
    "EVIDENCE_CLASSES",
    "EVIDENCE_STATUSES",
    "INFERRED",
    "LEDGER_STATUS",
    "OBLIGATION_IDS",
    "OBSERVED",
    "OPEN",
    "PROOF_SUITE_ID",
    "REFERENCE_ONLY",
    "SEALED_LEDGER_STATUS",
    "STATUS",
    "TerminalLedger",
    "TerminalLedgerContext",
    "TerminalLedgerError",
    "UNKNOWN",
    "build_terminal_ledger",
    "independently_verify_terminal_ledger",
)
