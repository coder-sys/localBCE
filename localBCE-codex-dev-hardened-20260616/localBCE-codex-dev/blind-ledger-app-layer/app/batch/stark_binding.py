from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Mapping, Sequence

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.nullifier import NonMembershipWitness, verify_nonmembership_witness
from app.batch.stark_encoding import EncodedClaim, canonical_cents, canonical_day_count, encode_claim, pack_felt_text
from app.models import SharedContext


REQUIRED_GOVERNED_ROOTS = (
    "claimSourceRoot",
    "oracleFactsRoot",
    "feeScheduleRoot",
    "addressBookRoot",
    "rulesetRoot",
)
ZERO_LEAF = 0


@dataclass(frozen=True)
class ServiceLineBinding:
    line_id: str
    procedure_code: str
    charge_cents: int
    allowed_cents: int
    fee_leaf: int
    fee_path_index: int
    fee_schedule_procedure_code: str = ""
    fee_effective_from: str = "1970-01-01"
    fee_effective_until: str = "9999-12-31"
    fee_allowed_cents: int | None = None
    fee_sorted_leaves: Sequence[int] = field(default_factory=tuple)


@dataclass(frozen=True)
class NullifierInsertWitness:
    root_before: int
    live_root: int
    inserted_nullifier: int
    non_membership: NonMembershipWitness


@dataclass(frozen=True)
class StarkClaimWitness:
    ctx: SharedContext
    governed_roots: Mapping[str, int]
    onchain_governed_roots: Mapping[str, int]
    claim_source_leaf: int
    normalized_fact_commitment: int
    service_lines: Sequence[ServiceLineBinding]
    total_charge_cents: int
    nullifier: NullifierInsertWitness
    claim_leaf_path_index: int
    approved: bool
    allowed_amount_cents: int
    claim_source_sorted_leaves: Sequence[int] = field(default_factory=tuple)


@dataclass(frozen=True)
class BatchSlot:
    claim_id: str
    inserted_nullifier: int
    approved: bool
    allowed_amount_cents: int
    payment_amount_cents: int
    padding: bool = False


@dataclass(frozen=True)
class AggregationWitness:
    slots: Sequence[BatchSlot]
    claimed_count: int
    running_balance_before: int
    running_balance_after: int
    onchain_running_balance_before: int | None = None
    onchain_running_balance_after: int | None = None


def _felt(value: int) -> int:
    value = int(value)
    if value < 0 or value >= FIELD_MODULUS:
        raise ValueError("felt_out_of_range")
    return value


def claim_source_leaf_for(encoded: EncodedClaim) -> int:
    return domain_poseidon_hash(
        "claim_source",
        [
            encoded.claim_id,
            encoded.member_id,
            encoded.provider_npi,
            encoded.service_date,
            encoded.procedure_codes_hash,
            encoded.total_charge_cents,
            encoded.service_line_count,
        ],
    )


def normalized_fact_commitment_for(ctx: SharedContext) -> int:
    flags = ctx.flags
    return domain_poseidon_hash(
        "normalized_facts",
        [
            int(bool(flags.get("eligibility_active"))),
            int(bool(flags.get("provider_enrolled"))),
            int(bool(flags.get("provider_not_suspended"))),
            int(bool(flags.get("not_deceased"))),
            int(any(line.prior_authorization for line in ctx.service_lines)),
            int(bool(flags.get("duplicate_claim"))),
            int(bool(flags.get("program_integrity_hold"))),
        ],
    )


def fee_leaf_for(line: ServiceLineBinding) -> int:
    fee_procedure = line.fee_schedule_procedure_code or line.procedure_code
    fee_allowed = line.allowed_cents if line.fee_allowed_cents is None else line.fee_allowed_cents
    return domain_poseidon_hash(
        "fee",
        [
            pack_felt_text(fee_procedure),
            _felt(fee_allowed),
            canonical_day_count(line.fee_effective_from),
            canonical_day_count(line.fee_effective_until),
        ],
    )


@lru_cache(maxsize=128)
def _sorted_leaf_index_map(sorted_leaves: tuple[int, ...], capacity: int) -> Mapping[int, int]:
    if len(sorted_leaves) > capacity:
        raise ValueError("sorted_leaf_order_exceeds_capacity")
    if sorted_leaves != tuple(sorted(sorted_leaves)):
        raise ValueError("sorted_leaf_order_not_sorted")
    if len(set(sorted_leaves)) != len(sorted_leaves):
        raise ValueError("sorted_leaf_order_contains_duplicate")
    return {value: index for index, value in enumerate(sorted_leaves)}


def expected_path_index(leaf: int, capacity: int, sorted_leaves: Sequence[int] | None = None) -> int:
    if capacity <= 0:
        raise ValueError("capacity_must_be_positive")
    if capacity > 2**32:
        raise ValueError("capacity_out_of_range")
    if sorted_leaves is None:
        raise ValueError("sorted_leaf_order_required")
    ordered = tuple(_felt(item) for item in sorted_leaves)
    leaf = _felt(leaf)
    try:
        return _sorted_leaf_index_map(ordered, capacity)[leaf]
    except ValueError as exc:
        raise exc
    except KeyError as exc:
        raise ValueError("leaf_missing_from_sorted_order") from exc


def verify_claim_binding(witness: StarkClaimWitness, *, tree_capacity: int) -> bool:
    for key in REQUIRED_GOVERNED_ROOTS:
        if key not in witness.governed_roots or key not in witness.onchain_governed_roots:
            raise ValueError(f"governed_root_missing:{key}")
        actual = _felt(int(witness.governed_roots[key]))
        expected = _felt(int(witness.onchain_governed_roots[key]))
        if actual != expected:
            raise ValueError(f"governed_root_mismatch:{key}")

    encoded = encode_claim(witness.ctx)
    if witness.claim_source_leaf != claim_source_leaf_for(encoded):
        raise ValueError("claim_source_leaf_mismatch")
    if witness.normalized_fact_commitment != normalized_fact_commitment_for(witness.ctx):
        raise ValueError("free_fact_commitment_mismatch")
    if witness.claim_leaf_path_index != expected_path_index(
        witness.claim_source_leaf,
        tree_capacity,
        witness.claim_source_sorted_leaves,
    ):
        raise ValueError("claim_path_index_not_bound_to_sorted_order")

    if len(witness.service_lines) != len(witness.ctx.service_lines):
        raise ValueError("service_line_count_mismatch")
    service_date = canonical_day_count(witness.ctx.service_date)
    line_total = 0
    allowed_total = 0
    for line, ctx_line in zip(witness.service_lines, witness.ctx.service_lines):
        if line.line_id != ctx_line.line_id:
            raise ValueError("service_line_id_mismatch")
        if line.procedure_code != ctx_line.procedure_code:
            raise ValueError("service_line_procedure_mismatch")
        if canonical_cents(ctx_line.charge_amount) != line.charge_cents:
            raise ValueError("service_line_charge_mismatch")
        fee_procedure = line.fee_schedule_procedure_code or line.procedure_code
        if fee_procedure != line.procedure_code:
            raise ValueError("fee_procedure_not_bound_to_claim")
        if line.fee_allowed_cents is not None and line.fee_allowed_cents != line.allowed_cents:
            raise ValueError("fee_allowed_not_bound_to_claim")
        if not (canonical_day_count(line.fee_effective_from) <= service_date <= canonical_day_count(line.fee_effective_until)):
            raise ValueError("fee_schedule_not_effective_for_service_date")
        if line.charge_cents < 0 or line.charge_cents >= 2**59:
            raise ValueError("line_charge_out_of_range")
        if line.allowed_cents < 0 or line.allowed_cents > line.charge_cents:
            raise ValueError("line_allowed_invalid")
        if line.fee_leaf != fee_leaf_for(line):
            raise ValueError("fee_leaf_mismatch")
        if line.fee_path_index != expected_path_index(line.fee_leaf, tree_capacity, line.fee_sorted_leaves):
            raise ValueError("fee_path_index_not_bound_to_sorted_order")
        line_total += line.charge_cents
        allowed_total += line.allowed_cents

    if witness.total_charge_cents != line_total:
        raise ValueError("multi_line_total_mismatch")
    if canonical_cents(witness.ctx.total_charge) != line_total:
        raise ValueError("claim_total_not_derived_from_lines")
    if witness.allowed_amount_cents != (allowed_total if witness.approved else 0):
        raise ValueError("allowed_amount_mismatch")

    nullifier = witness.nullifier
    if nullifier.root_before != nullifier.live_root:
        raise ValueError("stale_nullifier_root")
    _felt(nullifier.inserted_nullifier)
    if nullifier.non_membership.root != nullifier.live_root:
        raise ValueError("nullifier_witness_root_mismatch")
    if nullifier.non_membership.nullifier != nullifier.inserted_nullifier:
        raise ValueError("nullifier_witness_value_mismatch")
    verify_nonmembership_witness(nullifier.non_membership)
    return True


def verify_aggregation(witness: AggregationWitness) -> bool:
    if witness.onchain_running_balance_before is None or witness.onchain_running_balance_after is None:
        raise ValueError("running_balance_anchor_missing")
    if witness.running_balance_before != witness.onchain_running_balance_before:
        raise ValueError("running_balance_before_not_onchain")
    non_padding = [slot for slot in witness.slots if not slot.padding]
    if witness.claimed_count != len(non_padding):
        raise ValueError("claimed_count_mismatch")
    seen_nullifiers: set[int] = set()
    approved_total = 0
    payment_total = 0
    for slot in witness.slots:
        if slot.padding:
            if slot.inserted_nullifier != 0 or slot.allowed_amount_cents != 0 or slot.payment_amount_cents != 0 or slot.claim_id:
                raise ValueError("padding_not_inert")
            continue
        if slot.inserted_nullifier in seen_nullifiers:
            raise ValueError("duplicate_inserted_nullifier")
        seen_nullifiers.add(slot.inserted_nullifier)
        if slot.approved:
            approved_total += slot.allowed_amount_cents
        elif slot.payment_amount_cents != 0:
            raise ValueError("denied_claim_has_payment")
        payment_total += slot.payment_amount_cents
    if payment_total > approved_total:
        raise ValueError("batch_value_conservation_violation")
    if witness.running_balance_after != witness.running_balance_before + approved_total - payment_total:
        raise ValueError("running_balance_mismatch")
    if witness.running_balance_after != witness.onchain_running_balance_after:
        raise ValueError("running_balance_after_not_onchain")
    return True
