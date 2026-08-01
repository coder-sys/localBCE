"""Composed synthetic Wave 1A claim relation.

This module joins the authenticated claim-truth, uniform wide replay plus felt aliases,
exact aggregate and per-member/provider payment maps, ordered 12-field, and
wide commitment references.  It remains a host-side executable relation, not
an AIR or proof verifier.  A12 application
derivation uses one canonical preimage and one authoritative SHA3-512 value.
The one-felt compatibility key is the proved nonzero modular projection of that
wide value and has no replay or settlement authority.  S09 proof-system
primitives and final backend constraints remain unresolved.

Historical adapter-only Poseidon commitments remain isolated at the application
edge.  The SHA3-512 commitment binds raw 512-bit inputs and no wide value is
ever derived from a felt projection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
from typing import Final, Iterable, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    CoverReplayContextV2,
    DerivedNullifierV1,
    NullifierDerivationAuthorityV1,
    ReplayRegistryAuthorityBindingV1,
    REVISION_KIND_ORIGINAL,
    encode_attempt_preimage_v1,
    encode_cover_preimage_v2,
)
from app.batch.pq_suite_candidate import candidate_salt_use_tag
from app.batch.pq_strong_nullifier_reference import DuplicateStrongNullifierError
from app.batch.pq_tree_reference import require_synthetic_reference_enabled

from .authenticated_payment_reference import (
    AuthenticatedBatchPaymentTransition,
    AuthenticatedPaymentState,
    build_authenticated_payment_transition,
)
from .authenticated_replay_state_reference import (
    AuthenticatedReplayTransition,
    build_authenticated_replay_transitions,
)
from .authenticated_payment_maps_reference import (
    AuthenticatedPaymentMapBatchTransition,
    AuthenticatedPaymentMapState,
    build_authenticated_payment_map_transition,
)
from .claim_truth_reference import (
    ClaimTruthAuthentication,
    ClaimTruthReference,
    GovernedClaimTruthRoots,
    require_claim_truth_authentication,
)
from .payment import BatchEconomics, derive_batch_economics
from .profile import CalibrationProfile
from .semantics import ClaimSlot, SlotKind, StructuralError
from .stark252_projection_air import compatibility_felt_from_sha3_512


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_WAVE1A_COMPOSED_HOST_RELATION_"
    "A12_DERIVATION_BOUND_NOT_AIR_NOT_PRODUCTION"
)
PROTOCOL_VERSION: Final[int] = 2
PUBLIC_OUTPUT_NAMES: Final[tuple[str, ...]] = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)
_GOVERNANCE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/GOVERNANCE/REFERENCE/v1"
_STRONG_BATCH_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/STRONG-BATCH/REFERENCE/v1"
_STRONG_VALUE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/STRONG-VALUE/REFERENCE/v1"
_STRONG_SETTLEMENT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/STRONG-SETTLEMENT/REFERENCE/v1"
_U64_MAX: Final[int] = (1 << 64) - 1
_MAX_EXISTING_REFERENCE_NULLIFIERS: Final[int] = 4_096


def _felt(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value < FIELD_MODULUS:
        raise StructuralError(f"wave1a_relation_{label}_not_canonical_felt")
    if nonzero and value == 0:
        raise StructuralError(f"wave1a_relation_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise StructuralError(f"wave1a_relation_{label}_not_u64")
    if nonzero and value == 0:
        raise StructuralError(f"wave1a_relation_{label}_must_be_nonzero")
    return value


def _bytes64(label: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise StructuralError(f"wave1a_relation_{label}_must_be_64_bytes")
    if nonzero and not any(value):
        raise StructuralError(f"wave1a_relation_{label}_must_be_nonzero")
    return value


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise StructuralError("wave1a_relation_length_prefix_overflow")
    return len(value).to_bytes(2, "big") + value


def _profile_bytes(profile_id: str) -> bytes:
    if type(profile_id) is not str:
        raise StructuralError("wave1a_relation_profile_id_not_text")
    try:
        encoded = profile_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StructuralError("wave1a_relation_profile_id_not_ascii") from exc
    return _lp16(encoded)


@dataclass(frozen=True, slots=True)
class SlotNullifierInput:
    """Fixed-shape private cover-nonce lane; real slots use the zero sentinel."""

    slot_index: int
    private_cover_nonce_512: bytes = field(repr=False)

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if type(self.slot_index) is not int or not 0 <= self.slot_index <= 511:
            raise StructuralError("wave1a_relation_nullifier_slot_index_invalid")
        _bytes64("private_cover_nonce", self.private_cover_nonce_512, nonzero=False)


@dataclass(frozen=True, slots=True)
class Wave1AContext:
    epoch: int
    settlement_domain: int
    batch_nonce: int
    raw_master_salt_512: bytes = field(repr=False)
    strong_settlement_domain_id_512: bytes
    strong_batch_nonce_512: bytes
    replay_registry_authority_binding: ReplayRegistryAuthorityBindingV1
    nullifier_authority: NullifierDerivationAuthorityV1 = field(repr=False)
    payment_state_before: AuthenticatedPaymentState = field(repr=False)
    payment_map_state_before: AuthenticatedPaymentMapState = field(repr=False)

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _u64("epoch", self.epoch, nonzero=True)
        _felt("settlement_domain", self.settlement_domain, nonzero=True)
        _felt("batch_nonce", self.batch_nonce, nonzero=True)
        _bytes64("raw_master_salt", self.raw_master_salt_512)
        _bytes64(
            "strong_settlement_domain_id",
            self.strong_settlement_domain_id_512,
        )
        _bytes64("strong_batch_nonce", self.strong_batch_nonce_512)
        if self.settlement_domain != compatibility_felt_from_sha3_512(
            self.strong_settlement_domain_id_512
        ):
            raise StructuralError("wave1a_relation_settlement_domain_projection_mismatch")
        if self.batch_nonce != compatibility_felt_from_sha3_512(
            self.strong_batch_nonce_512
        ):
            raise StructuralError("wave1a_relation_batch_nonce_projection_mismatch")
        if not isinstance(self.nullifier_authority, NullifierDerivationAuthorityV1):
            raise StructuralError("wave1a_relation_nullifier_authority_required")
        if not isinstance(
            self.replay_registry_authority_binding,
            ReplayRegistryAuthorityBindingV1,
        ):
            raise StructuralError("wave1a_relation_registry_authority_binding_required")
        try:
            self.replay_registry_authority_binding.require_current_authority(
                self.nullifier_authority
            )
        except (TypeError, ValueError) as exc:
            raise StructuralError(str(exc)) from exc
        if not isinstance(self.payment_state_before, AuthenticatedPaymentState):
            raise StructuralError("wave1a_relation_payment_state_before_required")
        if self.payment_state_before.epoch != self.epoch:
            raise StructuralError("wave1a_relation_payment_epoch_mismatch")
        if not isinstance(
            self.payment_map_state_before, AuthenticatedPaymentMapState
        ):
            raise StructuralError("wave1a_relation_payment_map_state_before_required")
        if self.payment_map_state_before.epoch != self.epoch:
            raise StructuralError("wave1a_relation_payment_map_epoch_mismatch")
        if self.payment_map_state_before.sequence != self.payment_state_before.sequence:
            raise StructuralError("wave1a_relation_payment_state_sequence_mismatch")
        if not hmac.compare_digest(
            self.payment_map_state_before.strong_settlement_domain_id_512,
            self.strong_settlement_domain_id_512,
        ):
            raise StructuralError("wave1a_relation_payment_map_domain_mismatch")


@dataclass(frozen=True, slots=True)
class Wave1AReferenceRelation:
    status: str
    profile_id: str
    slots: tuple[ClaimSlot, ...] = field(repr=False)
    governed_roots: GovernedClaimTruthRoots
    authentication: ClaimTruthAuthentication = field(repr=False)
    nullifier_inputs: tuple[SlotNullifierInput, ...] = field(repr=False)
    replay_derivations: tuple[DerivedNullifierV1, ...] = field(repr=False)
    context: Wave1AContext = field(repr=False)
    existing_strong_nullifiers: tuple[bytes, ...] = field(repr=False)
    claim_truth: ClaimTruthReference = field(repr=False)
    economics: BatchEconomics = field(repr=False)
    strong_transitions: tuple[AuthenticatedReplayTransition, ...] = field(repr=False)
    payment_transition: AuthenticatedBatchPaymentTransition = field(repr=False)
    payment_map_transition: AuthenticatedPaymentMapBatchTransition = field(repr=False)
    public_outputs: tuple[int, ...]
    strong_governance_commitment_sha3_512: bytes
    strong_batch_commitment_sha3_512: bytes
    strong_value_conservation_commitment_sha3_512: bytes
    strong_settlement_commitment_sha3_512: bytes
    salt_use_tag_sha3_512: bytes = field(repr=False)
    nullifier_derivations_authenticated: bool = True
    cryptographic_paths_authenticated: bool = True
    physical_air_constrained: bool = False
    production_usable: bool = False

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != REFERENCE_STATUS:
            raise StructuralError("wave1a_relation_status_invalid")
        if len(self.public_outputs) != len(PUBLIC_OUTPUT_NAMES):
            raise StructuralError("wave1a_relation_public_output_count_mismatch")
        for value in self.public_outputs:
            _felt("public_output", value)
        if (
            not self.nullifier_derivations_authenticated
            or not self.cryptographic_paths_authenticated
            or self.physical_air_constrained
            or self.production_usable
        ):
            raise StructuralError("wave1a_relation_security_boundary_invalid")
        _bytes64(
            "strong_governance_commitment",
            self.strong_governance_commitment_sha3_512,
        )
        _bytes64("strong_batch_commitment", self.strong_batch_commitment_sha3_512)
        _bytes64(
            "strong_value_conservation_commitment",
            self.strong_value_conservation_commitment_sha3_512,
        )
        _bytes64("strong_settlement_commitment", self.strong_settlement_commitment_sha3_512)
        _bytes64("salt_use_tag", self.salt_use_tag_sha3_512)


def _bounded_tuple(
    values: Iterable[object],
    *,
    maximum: int,
    label: str,
) -> tuple[object, ...]:
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise StructuralError(f"wave1a_relation_{label}_not_iterable") from exc
    materialized: list[object] = []
    for value in iterator:
        if len(materialized) == maximum:
            raise StructuralError(f"wave1a_relation_{label}_capacity_exceeded")
        materialized.append(value)
    return tuple(materialized)


def _derive_replay_values(
    profile: CalibrationProfile,
    slots: tuple[ClaimSlot, ...],
    values: Sequence[SlotNullifierInput],
    context: Wave1AContext,
) -> tuple[tuple[SlotNullifierInput, ...], tuple[DerivedNullifierV1, ...]]:
    materialized = tuple(values)
    if len(materialized) != profile.claim_slots:
        raise StructuralError("wave1a_relation_nullifier_input_count_mismatch")
    derived: list[DerivedNullifierV1] = []
    for index, (slot, value) in enumerate(zip(slots, materialized, strict=True)):
        if not isinstance(value, SlotNullifierInput) or value.slot_index != index:
            raise StructuralError("wave1a_relation_nullifier_input_order_invalid")
        if slot.slot_index != index or slot.slot_kind not in (SlotKind.REAL, SlotKind.COVER):
            raise StructuralError("wave1a_relation_slot_alignment_invalid")
        if slot.slot_kind is SlotKind.REAL:
            if any(value.private_cover_nonce_512):
                raise StructuralError("wave1a_relation_real_cover_nonce_must_be_zero")
            try:
                preimage = encode_attempt_preimage_v1(
                    AttemptReplayIdentityV1(
                        slot.source_authority_id,
                        slot.claim_id,
                        slot.attempt_version,
                        REVISION_KIND_ORIGINAL,
                        slot.parent_attempt_version,
                    ),
                    context.nullifier_authority,
                )
                strong = sha3_512(preimage).digest()
                derived.append(
                    DerivedNullifierV1(
                        "ATTEMPT",
                        preimage,
                        compatibility_felt_from_sha3_512(strong),
                        strong,
                    )
                )
            except (TypeError, ValueError) as exc:
                raise StructuralError(f"wave1a_relation_attempt_derivation:{exc}") from exc
        else:
            if not any(value.private_cover_nonce_512):
                raise StructuralError("wave1a_relation_cover_nonce_must_be_nonzero")
            try:
                preimage = encode_cover_preimage_v2(
                    CoverReplayContextV2(
                        profile.profile_id,
                        context.strong_settlement_domain_id_512,
                        context.epoch,
                        context.strong_batch_nonce_512,
                        index,
                    ),
                    value.private_cover_nonce_512,
                )
                strong = sha3_512(preimage).digest()
                derived.append(
                    DerivedNullifierV1(
                        "COVER",
                        preimage,
                        compatibility_felt_from_sha3_512(strong),
                        strong,
                    )
                )
            except (TypeError, ValueError) as exc:
                raise StructuralError(f"wave1a_relation_cover_derivation:{exc}") from exc
    cover_nonces = tuple(
        value.private_cover_nonce_512
        for slot, value in zip(slots, materialized, strict=True)
        if slot.slot_kind is SlotKind.COVER
    )
    if len(set(cover_nonces)) != len(cover_nonces):
        raise StructuralError("wave1a_relation_cover_nonce_duplicate")
    for label, sequence in (
        ("legacy_nullifier", tuple(value.legacy_felt for value in derived)),
        ("strong_nullifier", tuple(value.strong_sha3_512 for value in derived)),
    ):
        if len(set(sequence)) != len(sequence):
            raise StructuralError(f"wave1a_relation_{label}_duplicate")
    return materialized, tuple(derived)


def _strong_transitions(
    existing: tuple[bytes, ...],
    additions: tuple[bytes, ...],
) -> tuple[AuthenticatedReplayTransition, ...]:
    try:
        return build_authenticated_replay_transitions(existing, additions)
    except DuplicateStrongNullifierError:
        raise
    except (TypeError, ValueError) as exc:
        raise StructuralError(f"wave1a_relation_{exc}") from exc


def _compatibility_outputs(
    context: Wave1AContext,
    governed: GovernedClaimTruthRoots,
    strong_transitions: tuple[AuthenticatedReplayTransition, ...],
    strong_batch: bytes,
    strong_value: bytes,
    strong_settlement: bytes,
) -> tuple[int, ...]:
    """Project wide authoritative values into the unchanged 12-field ABI."""

    wide_values = (
        strong_transitions[0].root_before,
        strong_transitions[-1].root_after,
        *governed.wide_roots,
        strong_batch,
        strong_value,
        strong_settlement,
    )
    aliases = tuple(compatibility_felt_from_sha3_512(value) for value in wide_values)
    return (
        PROTOCOL_VERSION,
        context.settlement_domain,
        context.batch_nonce,
        *aliases,
    )


def encode_strong_governance_preimage(
    profile: CalibrationProfile,
    context: Wave1AContext,
    governed: GovernedClaimTruthRoots,
) -> bytes:
    return (
        _GOVERNANCE_DOMAIN
        + _profile_bytes(profile.profile_id)
        + context.epoch.to_bytes(8, "big")
        + b"".join(governed.wide_roots)
        + context.replay_registry_authority_binding.authority_id_512
        + context.replay_registry_authority_binding.pepper_commitment_512
    )


def _strong_governance_commitment(
    profile: CalibrationProfile,
    context: Wave1AContext,
    governed: GovernedClaimTruthRoots,
) -> bytes:
    return sha3_512(
        encode_strong_governance_preimage(profile, context, governed)
    ).digest()


def encode_strong_batch_preimage(
    profile: CalibrationProfile,
    context: Wave1AContext,
    claim_truth: ClaimTruthReference,
    replay: tuple[DerivedNullifierV1, ...],
    governed: GovernedClaimTruthRoots,
    strong_transitions: tuple[AuthenticatedReplayTransition, ...],
    payment: AuthenticatedBatchPaymentTransition,
    payment_maps: AuthenticatedPaymentMapBatchTransition,
    governance_commitment: bytes,
    salt_use_tag: bytes,
) -> bytes:
    return (
        _STRONG_BATCH_DOMAIN
        + _profile_bytes(profile.profile_id)
        + PROTOCOL_VERSION.to_bytes(2, "big")
        + context.epoch.to_bytes(8, "big")
        + context.strong_settlement_domain_id_512
        + context.strong_batch_nonce_512
        + profile.claim_slots.to_bytes(2, "big")
        + b"".join(governed.wide_roots)
        + governance_commitment
        + strong_transitions[0].root_before
        + strong_transitions[-1].root_after
        + payment.root_before_sha3_512
        + payment.root_after_sha3_512
        + payment_maps.before.root()
        + payment_maps.after.root()
        + len(replay).to_bytes(2, "big")
        + b"".join(
            index.to_bytes(2, "big")
            + result.decision.to_bytes(1, "big")
            + result.failure_code.to_bytes(2, "big")
            + result.allowed_cents.to_bytes(4, "big")
            + result.payment_cents.to_bytes(4, "big")
            + sum(
                int(value) << bit
                for bit, value in enumerate(result.raw_gate_predicates)
            ).to_bytes(2, "big")
            + sum(
                int(value) << bit
                for bit, value in enumerate(result.effective_gate_predicates)
            ).to_bytes(2, "big")
            + nullifier.strong_sha3_512
            for index, (result, nullifier) in enumerate(
                zip(claim_truth.slot_results, replay, strict=True)
            )
        )
        + context.raw_master_salt_512
        + salt_use_tag
    )


def _strong_batch_commitment(
    profile: CalibrationProfile,
    context: Wave1AContext,
    claim_truth: ClaimTruthReference,
    replay: tuple[DerivedNullifierV1, ...],
    governed: GovernedClaimTruthRoots,
    strong_transitions: tuple[AuthenticatedReplayTransition, ...],
    payment: AuthenticatedBatchPaymentTransition,
    payment_maps: AuthenticatedPaymentMapBatchTransition,
    governance_commitment: bytes,
    salt_use_tag: bytes,
) -> bytes:
    return sha3_512(
        encode_strong_batch_preimage(
            profile,
            context,
            claim_truth,
            replay,
            governed,
            strong_transitions,
            payment,
            payment_maps,
            governance_commitment,
            salt_use_tag,
        )
    ).digest()


def encode_strong_value_preimage(
    context: Wave1AContext,
    economics: BatchEconomics,
    payment: AuthenticatedBatchPaymentTransition,
    payment_maps: AuthenticatedPaymentMapBatchTransition,
) -> bytes:
    gross = sum(value.gross_allowed_cents for value in economics.slots)
    responsibility = sum(value.patient_responsibility_cents for value in economics.slots)
    values = (
        gross,
        responsibility,
        economics.total_plan_payable_cents,
        economics.total_debits_cents,
        economics.total_credits_cents,
    )
    return (
        _STRONG_VALUE_DOMAIN
        + context.epoch.to_bytes(8, "big")
        + context.strong_batch_nonce_512
        + b"".join(value.to_bytes(8, "big") for value in values)
        + payment.root_before_sha3_512
        + payment.root_after_sha3_512
        + payment_maps.before.root()
        + payment_maps.after.root()
    )


def _strong_value_commitment(
    context: Wave1AContext,
    economics: BatchEconomics,
    payment: AuthenticatedBatchPaymentTransition,
    payment_maps: AuthenticatedPaymentMapBatchTransition,
) -> bytes:
    return sha3_512(
        encode_strong_value_preimage(context, economics, payment, payment_maps)
    ).digest()


def encode_strong_settlement_preimage(
    context: Wave1AContext,
    governed: GovernedClaimTruthRoots,
    strong_transitions: tuple[AuthenticatedReplayTransition, ...],
    governance: bytes,
    strong_batch: bytes,
    strong_value: bytes,
) -> bytes:
    return (
        _STRONG_SETTLEMENT_DOMAIN
        + PROTOCOL_VERSION.to_bytes(2, "big")
        + context.strong_settlement_domain_id_512
        + context.strong_batch_nonce_512
        + b"".join(governed.wide_roots)
        + strong_transitions[0].root_before
        + strong_transitions[-1].root_after
        + governance
        + strong_batch
        + strong_value
    )


def _strong_settlement_commitment(
    context: Wave1AContext,
    governed: GovernedClaimTruthRoots,
    strong_transitions: tuple[AuthenticatedReplayTransition, ...],
    governance: bytes,
    strong_batch: bytes,
    strong_value: bytes,
) -> bytes:
    return sha3_512(
        encode_strong_settlement_preimage(
            context,
            governed,
            strong_transitions,
            governance,
            strong_batch,
            strong_value,
        )
    ).digest()


def build_wave1a_reference_relation(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    governed_roots: GovernedClaimTruthRoots,
    authentication: ClaimTruthAuthentication,
    nullifier_inputs: Sequence[SlotNullifierInput],
    context: Wave1AContext,
    *,
    existing_legacy_nullifiers: Iterable[int] = (),
    existing_strong_nullifiers: Iterable[bytes] = (),
) -> Wave1AReferenceRelation:
    require_synthetic_reference_enabled()
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_relation_profile_required")
    materialized_slots = tuple(slots)
    if not isinstance(context, Wave1AContext):
        raise StructuralError("wave1a_relation_context_required")
    derivation_inputs, replay = _derive_replay_values(
        profile,
        materialized_slots,
        nullifier_inputs,
        context,
    )
    existing_legacy_raw = _bounded_tuple(
        existing_legacy_nullifiers,
        maximum=_MAX_EXISTING_REFERENCE_NULLIFIERS,
        label="existing_legacy_nullifiers",
    )
    existing_strong_raw = _bounded_tuple(
        existing_strong_nullifiers,
        maximum=_MAX_EXISTING_REFERENCE_NULLIFIERS,
        label="existing_strong_nullifiers",
    )
    if existing_legacy_raw:
        raise StructuralError("wave1a_relation_legacy_state_not_authoritative")
    if any(type(value) is not bytes or len(value) != 64 for value in existing_strong_raw):
        raise StructuralError("wave1a_relation_existing_strong_nullifier_type_invalid")
    existing_strong = tuple(existing_strong_raw)
    if len(set(existing_strong)) != len(existing_strong):
        raise StructuralError("wave1a_relation_existing_strong_nullifier_duplicate")

    claim_truth = require_claim_truth_authentication(
        profile,
        materialized_slots,
        governed_roots,
        authentication,
    )
    economics = derive_batch_economics(profile, materialized_slots)
    payment = build_authenticated_payment_transition(
        profile,
        economics.slots,
        context.payment_state_before,
    )
    payment_maps = build_authenticated_payment_map_transition(
        profile,
        materialized_slots,
        economics,
        context.payment_map_state_before,
    )
    salt_use_tag = candidate_salt_use_tag(context.raw_master_salt_512)
    if salt_use_tag in {value.strong_sha3_512 for value in replay}:
        raise StructuralError("wave1a_relation_salt_use_tag_collides_with_slot")
    strong = _strong_transitions(
        existing_strong,
        (
            *(value.strong_sha3_512 for value in replay),
            salt_use_tag,
        ),
    )
    governance = _strong_governance_commitment(profile, context, governed_roots)
    strong_batch = _strong_batch_commitment(
        profile,
        context,
        claim_truth,
        replay,
        governed_roots,
        strong,
        payment,
        payment_maps,
        governance,
        salt_use_tag,
    )
    strong_value = _strong_value_commitment(
        context,
        economics,
        payment,
        payment_maps,
    )
    strong_settlement = _strong_settlement_commitment(
        context,
        governed_roots,
        strong,
        governance,
        strong_batch,
        strong_value,
    )
    public_outputs = _compatibility_outputs(
        context,
        governed_roots,
        strong,
        strong_batch,
        strong_value,
        strong_settlement,
    )
    return Wave1AReferenceRelation(
        status=REFERENCE_STATUS,
        profile_id=profile.profile_id,
        slots=materialized_slots,
        governed_roots=governed_roots,
        authentication=authentication,
        nullifier_inputs=derivation_inputs,
        replay_derivations=replay,
        context=context,
        existing_strong_nullifiers=existing_strong,  # type: ignore[arg-type]
        claim_truth=claim_truth,
        economics=economics,
        strong_transitions=strong,
        payment_transition=payment,
        payment_map_transition=payment_maps,
        public_outputs=public_outputs,
        strong_governance_commitment_sha3_512=governance,
        strong_batch_commitment_sha3_512=strong_batch,
        strong_value_conservation_commitment_sha3_512=strong_value,
        strong_settlement_commitment_sha3_512=strong_settlement,
        salt_use_tag_sha3_512=salt_use_tag,
    )


def verify_wave1a_reference_relation(
    profile: CalibrationProfile,
    relation: Wave1AReferenceRelation,
) -> bool:
    if not isinstance(relation, Wave1AReferenceRelation):
        raise StructuralError("wave1a_relation_required")
    observed = build_wave1a_reference_relation(
        profile,
        relation.slots,
        relation.governed_roots,
        relation.authentication,
        relation.nullifier_inputs,
        relation.context,
        existing_strong_nullifiers=relation.existing_strong_nullifiers,
    )
    if observed != relation:
        raise StructuralError("wave1a_relation_recomputation_mismatch")
    return True
