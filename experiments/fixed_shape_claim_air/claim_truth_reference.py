"""Synthetic authenticated claim-truth reference for Wave 1A.

This module is a deterministic reference relation, not an AIR, proof system,
production state tree, or cryptographic parameter selection.  It converts the
already validated fixed-shape semantic batch into four independent canonical
record sets (claim source, oracle/authorization, policy, and ruleset), then
derives both the legacy compatibility root and the SHA3-512 root from the exact
same bytes.

``require_governed_claim_truth`` is the fail-closed boundary: adjudication data
is accepted only when recomputation matches separately supplied governed roots.
The proof suite remains unselected and this module is synthetic-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hmac
from typing import Final, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_tree_reference import (
    CanonicalField,
    DualTreeMembershipProof,
    DualTreeReference,
    SYNTHETIC_BYTES_MAGIC,
    derive_dual_tree_reference_with_membership_proofs,
    encode_canonical_record,
    require_synthetic_reference_enabled,
    verify_dual_tree_membership_proof,
)
from app.batch.pq_sparse_tree_reference import (
    SparseDualMembershipProof,
    SparseDualTreeReference,
    derive_sparse_dual_tree_reference_with_membership_proofs,
    verify_sparse_dual_membership_proof,
)

from .profile import (
    AUTHORIZATIONS_PER_CLAIM,
    DIAGNOSES_PER_CLAIM,
    POLICY_TREE_DEPTH,
    SERVICE_LINES_PER_CLAIM,
    CalibrationProfile,
)
from .semantics import (
    FAILURE_GATES,
    ClaimSlot,
    RevisionKind,
    SlotKind,
    SlotResult,
    evaluate_slot,
    validate_batch,
)


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_CLAIM_TRUTH_REFERENCE_V1_NOT_AIR_NOT_PRODUCTION"
)
REFERENCE_MAGIC: Final[bytes] = b"BL/PQ512/CLAIM-TRUTH/REFERENCE/v0"
ORACLE_REFERENCE_MAGIC: Final[bytes] = (
    b"BL/PQ512/CLAIM-TRUTH/ORACLE-RECORDS/v1"
)
SOURCE_PAYLOAD_DOMAIN: Final[bytes] = REFERENCE_MAGIC + b"\x00SOURCE\x00"
ORACLE_FACT_PAYLOAD_DOMAIN: Final[bytes] = (
    ORACLE_REFERENCE_MAGIC + b"\x00ORACLE-FACT\x00"
)
ORACLE_AUTHORIZATION_PAYLOAD_DOMAIN: Final[bytes] = (
    ORACLE_REFERENCE_MAGIC + b"\x00ORACLE-AUTHORIZATION\x00"
)
POLICY_PAYLOAD_DOMAIN: Final[bytes] = REFERENCE_MAGIC + b"\x00POLICY\x00"
RULESET_PAYLOAD_DOMAIN: Final[bytes] = REFERENCE_MAGIC + b"\x00RULESET\x00"

ROOT_NAMES: Final[tuple[str, ...]] = (
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
)

_REVISION_CODES: Final[dict[RevisionKind, int]] = {
    RevisionKind.COVER: 0,
    RevisionKind.ORIGINAL: 1,
    RevisionKind.CORRECTION: 2,
    RevisionKind.REPLACEMENT: 3,
    RevisionKind.VOID: 4,
}


def _u8(label: str, value: object) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise ValueError(f"claim_truth_{label}_not_u8")
    return value.to_bytes(1, "big")


def _u32(label: str, value: object) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"claim_truth_{label}_not_u32")
    return value.to_bytes(4, "big")


def _u64(label: str, value: object) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"claim_truth_{label}_not_u64")
    return value.to_bytes(8, "big")


def _flag(label: str, value: object) -> bytes:
    if type(value) is not bool:
        raise TypeError(f"claim_truth_{label}_not_boolean")
    return b"\x01" if value else b"\x00"


def _fixed_ascii(
    label: str,
    value: object,
    *,
    capacity: int,
) -> bytes:
    if type(value) is not str:
        raise TypeError(f"claim_truth_{label}_not_text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"claim_truth_{label}_not_ascii") from exc
    if len(raw) > capacity or capacity > 0xFF:
        raise ValueError(f"claim_truth_{label}_length_invalid")
    return bytes((len(raw),)) + raw.ljust(capacity, b"\x00")


def _payload(domain: bytes, body: bytes) -> bytes:
    return SYNTHETIC_BYTES_MAGIC + domain + body


def _source_payload(profile: CalibrationProfile, slot: ClaimSlot) -> bytes:
    out = bytearray()
    out.extend(_fixed_ascii("profile_id", profile.profile_id, capacity=32))
    out.extend(_u32("slot_index", slot.slot_index))
    out.extend(_flag("slot_is_real", slot.slot_kind is SlotKind.REAL))
    out.extend(
        _fixed_ascii(
            "source_authority_id", slot.source_authority_id, capacity=64
        )
    )
    out.extend(_u64("source_sequence", slot.source_sequence))
    out.extend(_fixed_ascii("claim_id", slot.claim_id, capacity=64))
    out.extend(_fixed_ascii("member_id", slot.member_id, capacity=64))
    out.extend(_fixed_ascii("provider_npi", slot.provider_npi, capacity=10))
    out.extend(_u32("attempt_version", slot.attempt_version))
    out.extend(_u8("revision_kind", _REVISION_CODES[slot.revision_kind]))
    out.extend(_u32("parent_attempt_version", slot.parent_attempt_version))
    out.extend(_u32("total_charge_cents", slot.total_charge_cents))
    out.extend(
        _u32(
            "patient_responsibility_cents",
            slot.patient_responsibility_cents,
        )
    )

    out.extend(_u8("diagnosis_count", len(slot.diagnoses)))
    for index in range(DIAGNOSES_PER_CLAIM):
        enabled = index < len(slot.diagnoses)
        out.extend(_flag("diagnosis_enabled", enabled))
        out.extend(
            _fixed_ascii(
                "diagnosis_code",
                slot.diagnoses[index] if enabled else "",
                capacity=16,
            )
        )

    out.extend(_u8("service_line_count", len(slot.service_lines)))
    for index in range(SERVICE_LINES_PER_CLAIM):
        enabled = index < len(slot.service_lines)
        out.extend(_flag("service_line_enabled", enabled))
        if enabled:
            line = slot.service_lines[index]
            out.extend(_u8("original_line_index", line.original_line_index))
            out.extend(_fixed_ascii("line_id", line.line_id, capacity=64))
            out.extend(
                _fixed_ascii(
                    "procedure_code", line.procedure_code, capacity=10
                )
            )
            out.extend(_u32("line_charge_cents", line.charge_cents))
            out.extend(_u32("line_units_cents", line.units_cents))
            out.extend(
                _fixed_ascii(
                    "prior_authorization",
                    line.prior_authorization,
                    capacity=64,
                )
            )
        else:
            out.extend(_u8("original_line_index", 0))
            out.extend(_fixed_ascii("line_id", "", capacity=64))
            out.extend(_fixed_ascii("procedure_code", "", capacity=10))
            out.extend(_u32("line_charge_cents", 0))
            out.extend(_u32("line_units_cents", 0))
            out.extend(_fixed_ascii("prior_authorization", "", capacity=64))
    return _payload(SOURCE_PAYLOAD_DOMAIN, bytes(out))


def _oracle_fact_payload(profile: CalibrationProfile, slot: ClaimSlot) -> bytes:
    out = bytearray()
    out.extend(_fixed_ascii("profile_id", profile.profile_id, capacity=32))
    out.extend(_u32("slot_index", slot.slot_index))
    out.extend(_flag("slot_is_real", slot.slot_kind is SlotKind.REAL))
    for label, value in (
        ("eligibility_active", slot.eligibility_active),
        ("provider_enrolled", slot.provider_enrolled),
        ("provider_not_suspended", slot.provider_not_suspended),
        ("not_deceased", slot.not_deceased),
        ("duplicate_claim", slot.duplicate_claim),
        ("program_integrity_hold", slot.program_integrity_hold),
    ):
        out.extend(_flag(label, value))
    return _payload(ORACLE_FACT_PAYLOAD_DOMAIN, bytes(out))


def _oracle_authorization_payload(
    profile: CalibrationProfile,
    slot: ClaimSlot,
    authorization_index: int,
) -> bytes:
    if not 0 <= authorization_index < AUTHORIZATIONS_PER_CLAIM:
        raise ValueError("claim_truth_authorization_index_out_of_range")
    enabled = authorization_index < len(slot.service_lines)
    out = bytearray()
    out.extend(_fixed_ascii("profile_id", profile.profile_id, capacity=32))
    out.extend(_u32("slot_index", slot.slot_index))
    out.extend(_flag("slot_is_real", slot.slot_kind is SlotKind.REAL))
    out.extend(_u8("authorization_index", authorization_index))
    out.extend(_flag("authorization_line_enabled", enabled))
    if enabled:
        line = slot.service_lines[authorization_index]
        out.extend(
            _flag(
                "authorization_required",
                line.requires_prior_authorization,
            )
        )
        out.extend(_flag("authorization_present", line.authorization_present))
        out.extend(
            _fixed_ascii(
                "authorization_token",
                line.prior_authorization,
                capacity=64,
            )
        )
    else:
        out.extend(_flag("authorization_required", False))
        out.extend(_flag("authorization_present", False))
        out.extend(_fixed_ascii("authorization_token", "", capacity=64))
    return _payload(ORACLE_AUTHORIZATION_PAYLOAD_DOMAIN, bytes(out))


def _policy_payload(profile: CalibrationProfile, slot: ClaimSlot) -> bytes:
    out = bytearray()
    out.extend(_fixed_ascii("profile_id", profile.profile_id, capacity=32))
    out.extend(_u32("slot_index", slot.slot_index))
    out.extend(_flag("slot_is_real", slot.slot_kind is SlotKind.REAL))
    for index in range(SERVICE_LINES_PER_CLAIM):
        enabled = index < len(slot.service_lines)
        out.extend(_flag("policy_line_enabled", enabled))
        if enabled:
            line = slot.service_lines[index]
            out.extend(_flag("policy_present", line.policy_present))
            out.extend(
                _fixed_ascii(
                    "policy_procedure_code",
                    line.procedure_code,
                    capacity=10,
                )
            )
            out.extend(_u32("policy_allowed_cents", line.allowed_cents))
            out.extend(
                _flag(
                    "policy_requires_authorization",
                    line.requires_prior_authorization,
                )
            )
        else:
            out.extend(_flag("policy_present", False))
            out.extend(
                _fixed_ascii("policy_procedure_code", "", capacity=10)
            )
            out.extend(_u32("policy_allowed_cents", 0))
            out.extend(_flag("policy_requires_authorization", False))
    return _payload(POLICY_PAYLOAD_DOMAIN, bytes(out))


def _ruleset_payload(profile: CalibrationProfile) -> bytes:
    out = bytearray()
    out.extend(_fixed_ascii("profile_id", profile.profile_id, capacity=32))
    out.extend(_u32("claim_slots", profile.claim_slots))
    out.extend(_u8("service_lines_per_claim", SERVICE_LINES_PER_CLAIM))
    out.extend(_u8("diagnoses_per_claim", DIAGNOSES_PER_CLAIM))
    out.extend(
        _u8("authorizations_per_claim", AUTHORIZATIONS_PER_CLAIM)
    )
    out.extend(_u8("claim_source_tree_depth", profile.claim_source_tree_depth))
    out.extend(_u8("oracle_tree_depth", profile.oracle_tree_depth))
    out.extend(_u8("policy_tree_depth", POLICY_TREE_DEPTH))
    out.extend(_u8("failure_gate_count", len(FAILURE_GATES)))
    for gate in FAILURE_GATES:
        out.extend(_u8("failure_gate_code", gate.code))
        out.extend(_fixed_ascii("failure_gate_id", gate.gate_id, capacity=40))
        out.extend(_fixed_ascii("failure_reason", gate.reason, capacity=40))
    return _payload(RULESET_PAYLOAD_DOMAIN, bytes(out))


def _slot_record(record_type: str, slot_index: int, payload: bytes) -> bytes:
    return encode_canonical_record(
        record_type,
        (
            CanonicalField.raw_bytes("payload", payload),
            CanonicalField.u32("slot_index", slot_index),
        ),
    )


def _oracle_records_for_slot(
    profile: CalibrationProfile,
    slot: ClaimSlot,
) -> tuple[bytes, ...]:
    records = [
        _slot_record(
            "synthetic_claim_truth_oracle_fact",
            slot.slot_index,
            _oracle_fact_payload(profile, slot),
        )
    ]
    records.extend(
        _slot_record(
            "synthetic_claim_truth_oracle_authorization",
            slot.slot_index,
            _oracle_authorization_payload(profile, slot, authorization_index),
        )
        for authorization_index in range(AUTHORIZATIONS_PER_CLAIM)
    )
    return tuple(records)


def _ruleset_record(profile: CalibrationProfile) -> bytes:
    return encode_canonical_record(
        "synthetic_claim_truth_ruleset",
        (CanonicalField.raw_bytes("payload", _ruleset_payload(profile)),),
    )


@lru_cache(maxsize=24)
def _cached_dense_material(
    records: tuple[bytes, ...], tree_kind: str, tree_height: int
) -> tuple[DualTreeReference, tuple[DualTreeMembershipProof, ...]]:
    return derive_dual_tree_reference_with_membership_proofs(
        records,
        tree_kind=tree_kind,
        tree_height=tree_height,
    )


@lru_cache(maxsize=24)
def _cached_sparse_material(
    keyed_records: tuple[tuple[int, bytes], ...],
    tree_kind: str,
    tree_depth: int,
) -> tuple[SparseDualTreeReference, tuple[SparseDualMembershipProof, ...]]:
    return derive_sparse_dual_tree_reference_with_membership_proofs(
        keyed_records,
        tree_kind=tree_kind,
        tree_depth=tree_depth,
    )


@dataclass(frozen=True, slots=True)
class GovernedClaimTruthRoots:
    """The separately provisioned roots a proof witness must match."""

    legacy_roots: tuple[int, int, int, int]
    wide_roots: tuple[bytes, bytes, bytes, bytes]

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if type(self.legacy_roots) is not tuple or len(self.legacy_roots) != 4:
            raise ValueError("claim_truth_legacy_root_count_invalid")
        if type(self.wide_roots) is not tuple or len(self.wide_roots) != 4:
            raise ValueError("claim_truth_wide_root_count_invalid")
        for value in self.legacy_roots:
            if type(value) is not int or not 0 <= value < FIELD_MODULUS:
                raise ValueError("claim_truth_legacy_root_not_canonical_felt")
        for value in self.wide_roots:
            if type(value) is not bytes or len(value) != 64:
                raise ValueError("claim_truth_wide_root_not_64_bytes")


@dataclass(frozen=True, slots=True)
class ClaimTruthSlotAuthentication:
    slot_index: int
    claim_source: DualTreeMembershipProof
    oracle: DualTreeMembershipProof
    oracle_authorizations: tuple[DualTreeMembershipProof, ...]
    policy: SparseDualMembershipProof

    def __post_init__(self) -> None:
        if type(self.slot_index) is not int or self.slot_index < 0:
            raise ValueError("claim_truth_authentication_slot_index_invalid")
        if not isinstance(self.claim_source, DualTreeMembershipProof):
            raise TypeError("claim_truth_source_membership_required")
        if not isinstance(self.oracle, DualTreeMembershipProof):
            raise TypeError("claim_truth_oracle_membership_required")
        if (
            type(self.oracle_authorizations) is not tuple
            or len(self.oracle_authorizations) != AUTHORIZATIONS_PER_CLAIM
            or any(
                not isinstance(value, DualTreeMembershipProof)
                for value in self.oracle_authorizations
            )
        ):
            raise TypeError(
                "claim_truth_oracle_authorization_memberships_required"
            )
        oracle_records = (
            self.oracle.canonical_record,
            *(value.canonical_record for value in self.oracle_authorizations),
        )
        if len(set(oracle_records)) != 1 + AUTHORIZATIONS_PER_CLAIM:
            raise ValueError("claim_truth_oracle_membership_record_duplicate")
        oracle_counts = {
            self.oracle.record_count,
            *(value.record_count for value in self.oracle_authorizations),
        }
        if len(oracle_counts) != 1:
            raise ValueError("claim_truth_oracle_membership_count_mismatch")
        if not isinstance(self.policy, SparseDualMembershipProof):
            raise TypeError("claim_truth_policy_membership_required")
        if self.policy.key != self.slot_index:
            raise ValueError("claim_truth_policy_membership_key_mismatch")


@dataclass(frozen=True, slots=True)
class ClaimTruthAuthentication:
    slots: tuple[ClaimTruthSlotAuthentication, ...]
    ruleset: DualTreeMembershipProof

    def __post_init__(self) -> None:
        if type(self.slots) is not tuple or any(
            not isinstance(value, ClaimTruthSlotAuthentication)
            for value in self.slots
        ):
            raise TypeError("claim_truth_slot_authentication_tuple_required")
        if tuple(value.slot_index for value in self.slots) != tuple(
            range(len(self.slots))
        ):
            raise ValueError("claim_truth_slot_authentication_order_invalid")
        if not isinstance(self.ruleset, DualTreeMembershipProof):
            raise TypeError("claim_truth_ruleset_membership_required")


@dataclass(frozen=True, slots=True)
class ClaimTruthReference:
    status: str
    profile_id: str
    slot_results: tuple[SlotResult, ...]
    claim_source_tree: DualTreeReference
    oracle_tree: DualTreeReference
    policy_tree: SparseDualTreeReference
    ruleset_tree: DualTreeReference
    authentication: ClaimTruthAuthentication

    def governed_roots(self) -> GovernedClaimTruthRoots:
        trees = (
            self.claim_source_tree,
            self.oracle_tree,
            self.policy_tree,
            self.ruleset_tree,
        )
        return GovernedClaimTruthRoots(
            tuple(tree.legacy_root_felt for tree in trees),  # type: ignore[arg-type]
            tuple(tree.wide_root_sha3_512 for tree in trees),  # type: ignore[arg-type]
        )


def build_claim_truth_reference(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> ClaimTruthReference:
    """Recompute all four fixed-shape truth roots from semantic witness data."""

    require_synthetic_reference_enabled()
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("claim_truth_profile_invalid")
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    results = tuple(evaluate_slot(slot) for slot in materialized)

    source_records = tuple(
        _slot_record(
            "synthetic_claim_truth_source",
            slot.slot_index,
            _source_payload(profile, slot),
        )
        for slot in materialized
    )
    oracle_record_sets = tuple(
        _oracle_records_for_slot(profile, slot) for slot in materialized
    )
    oracle_records = tuple(
        record for record_set in oracle_record_sets for record in record_set
    )
    policy_records = tuple(
        _slot_record(
            "synthetic_claim_truth_policy",
            slot.slot_index,
            _policy_payload(profile, slot),
        )
        for slot in materialized
    )

    claim_source_tree, claim_source_proofs = _cached_dense_material(
        source_records,
        "claim_truth_source",
        profile.claim_source_tree_depth,
    )
    oracle_tree, oracle_membership_proofs = _cached_dense_material(
        oracle_records,
        "claim_truth_oracle",
        profile.oracle_tree_depth,
    )
    policy_tree, policy_membership_proofs = _cached_sparse_material(
        tuple(
            (slot.slot_index, record)
            for slot, record in zip(
                materialized, policy_records, strict=True
            )
        ),
        "claim_truth_policy",
        POLICY_TREE_DEPTH,
    )
    ruleset_tree, ruleset_proofs = _cached_dense_material(
        (_ruleset_record(profile),),
        "claim_truth_ruleset",
        0,
    )
    source_proofs = {
        proof.canonical_record: proof
        for proof in claim_source_proofs
    }
    oracle_proofs = {
        proof.canonical_record: proof
        for proof in oracle_membership_proofs
    }
    policy_proofs = {
        proof.key: proof
        for proof in policy_membership_proofs
    }
    if len(ruleset_proofs) != 1:
        raise AssertionError("claim_truth_ruleset_membership_count_invalid")
    authentication = ClaimTruthAuthentication(
        tuple(
            ClaimTruthSlotAuthentication(
                slot_index=slot.slot_index,
                claim_source=source_proofs[source_record],
                oracle=oracle_proofs[oracle_record_set[0]],
                oracle_authorizations=tuple(
                    oracle_proofs[record] for record in oracle_record_set[1:]
                ),
                policy=policy_proofs[slot.slot_index],
            )
            for slot, source_record, oracle_record_set in zip(
                materialized,
                source_records,
                oracle_record_sets,
                strict=True,
            )
        ),
        ruleset_proofs[0],
    )

    return ClaimTruthReference(
        REFERENCE_STATUS,
        profile.profile_id,
        results,
        claim_source_tree,
        oracle_tree,
        policy_tree,
        ruleset_tree,
        authentication,
    )


def require_governed_claim_truth(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    governed: GovernedClaimTruthRoots,
) -> ClaimTruthReference:
    """Fail closed unless every legacy and wide root matches governed state."""

    if not isinstance(governed, GovernedClaimTruthRoots):
        raise TypeError("claim_truth_governed_roots_invalid")
    observed = build_claim_truth_reference(profile, slots)
    _require_governed_roots(observed, governed)
    return observed


def _require_governed_roots(
    observed: ClaimTruthReference,
    governed: GovernedClaimTruthRoots,
) -> None:
    actual = observed.governed_roots()
    for index, (left, right) in enumerate(
        zip(actual.legacy_roots, governed.legacy_roots, strict=True)
    ):
        if left != right:
            raise ValueError(
                f"claim_truth_governed_legacy_root_mismatch:{ROOT_NAMES[index]}"
            )
    for index, (left, right) in enumerate(
        zip(actual.wide_roots, governed.wide_roots, strict=True)
    ):
        if not hmac.compare_digest(left, right):
            raise ValueError(
                f"claim_truth_governed_wide_root_mismatch:{ROOT_NAMES[index]}"
            )


def require_claim_truth_authentication(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    governed: GovernedClaimTruthRoots,
    authentication: ClaimTruthAuthentication,
) -> ClaimTruthReference:
    """Rebuild and compare every exact path before accepting witness truth."""

    if not isinstance(authentication, ClaimTruthAuthentication):
        raise TypeError("claim_truth_authentication_invalid")
    observed = build_claim_truth_reference(profile, slots)
    _require_governed_roots(observed, governed)
    if len(authentication.slots) != profile.claim_slots:
        raise ValueError("claim_truth_authentication_slot_count_mismatch")
    if authentication != observed.authentication:
        for expected, supplied in zip(
            observed.authentication.slots,
            authentication.slots,
            strict=True,
        ):
            if expected != supplied:
                raise ValueError(
                    f"claim_truth_authentication_mismatch:slot={expected.slot_index}"
                )
        if authentication.ruleset != observed.authentication.ruleset:
            raise ValueError("claim_truth_authentication_mismatch:ruleset")
        raise ValueError("claim_truth_authentication_mismatch:unknown")

    roots = observed.governed_roots()
    selected = (
        authentication.slots[0],
        authentication.slots[len(authentication.slots) // 2],
        authentication.slots[-1],
    )
    # Recompute representative real/cover paths through the independent public
    # verifiers as a second implementation check; exact all-path comparison
    # above covers every slot without O(K * depth) scalar IPC overhead.
    for slot in selected:
        verify_dual_tree_membership_proof(
            slot.claim_source,
            expected_legacy_root_felt=roots.legacy_roots[0],
            expected_wide_root_sha3_512=roots.wide_roots[0],
        )
        verify_dual_tree_membership_proof(
            slot.oracle,
            expected_legacy_root_felt=roots.legacy_roots[1],
            expected_wide_root_sha3_512=roots.wide_roots[1],
        )
        for authorization in (
            slot.oracle_authorizations[0],
            slot.oracle_authorizations[-1],
        ):
            verify_dual_tree_membership_proof(
                authorization,
                expected_legacy_root_felt=roots.legacy_roots[1],
                expected_wide_root_sha3_512=roots.wide_roots[1],
            )
        verify_sparse_dual_membership_proof(
            slot.policy,
            expected_legacy_root_felt=roots.legacy_roots[2],
            expected_wide_root_sha3_512=roots.wide_roots[2],
        )
    verify_dual_tree_membership_proof(
        authentication.ruleset,
        expected_legacy_root_felt=roots.legacy_roots[3],
        expected_wide_root_sha3_512=roots.wide_roots[3],
    )
    return observed
