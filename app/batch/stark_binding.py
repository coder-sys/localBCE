from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence

from app.batch.attempt import (
    ATTEMPT_RECORD_SCHEMA,
    GovernedClaimAttempt,
    legacy_attempt_nullifier,
    legacy_attempt_record_commitment,
    synthetic_original_attempt,
)
from app.batch.claim_source_root import claim_source_leaf as canonical_claim_source_leaf
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.nullifier import DEPTH as NULLIFIER_DEPTH
from app.batch.nullifier import NonMembershipWitness, _indexed_leaf_hash, verify_nonmembership_witness
from app.batch.stark_encoding import canonical_cents, canonical_day_count, encode_claim, pack_felt_text
from app.batch.tar_required import is_tar_required
from app.models import SharedContext
from app.service_line_canonical import canonical_service_line_identities


REQUIRED_GOVERNED_ROOTS = (
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "addressBookRoot",
    "rulesetRoot",
)
ZERO_LEAF = 0
MAX_SERVICE_LINES_PER_CLAIM_WITNESS = 50
MULTI_LINE_CLAIM_WITNESS_SCHEMA = "BL_MULTI_LINE_CLAIM_WITNESS_V3"
_INDEX_MAP_CACHE_MAX = 32
_index_map_cache: dict[tuple[int, int, int], tuple[tuple[int, ...], Mapping[int, int]]] = {}


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
    attempt: GovernedClaimAttempt
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


@dataclass(frozen=True)
class MultiLineClaimSourceBinding:
    claim_source_root: int
    claim_source_leaf: int
    claim_id: int
    member_id: int
    provider_npi: int
    service_date_day: int
    service_lines_commitment: int
    diagnosis_commitment: int
    total_charge_cents: int
    source_authority_id: int
    payer_id: int
    attempt_version: int
    revision_kind: int
    parent_attempt_version: int
    attempt_nullifier: int
    attempt_record_commitment: int
    ruleset_root: int
    service_line_count: int
    diagnosis_count: int
    claim_source_leaf_index: int
    claim_source_path_elements: tuple[int, ...]
    claim_source_path_indices: tuple[int, ...]


@dataclass(frozen=True)
class AuthorizationLineWitness:
    auth_leaf: int
    auth_proof: Any
    auth_leaf_index: int
    auth_path_elements: tuple[int, ...]
    auth_path_indices: tuple[int, ...]
    claim_id: int
    line_index: int
    procedure_code: int
    service_date_day: int
    valid_from_day: int
    valid_until_day: int
    prior_authorization: str
    signed_tar_authorization_commitment: int
    authorization_present: bool
    signer_root: int
    fact_verification_commitment: int
    evidence_root: int


@dataclass(frozen=True)
class FeePolicyWitness:
    fee_policy_leaf: int
    fee_policy_leaf_index: int
    tree_depth: int
    real_row_count: int
    fee_policy_path_elements: tuple[int, ...]
    fee_policy_path_indices: tuple[int, ...]


@dataclass(frozen=True)
class FeeRowWitness:
    row_kind: int
    procedure_code: str
    procedure_code_felt: int
    allowed_cents: int
    fee_leaf: int
    fee_proof: Any
    requires_tar: bool
    policy_leaf_index: int
    next_procedure_code_felt: int
    next_policy_leaf_index: int
    policy_path_elements: tuple[int, ...]
    policy_path_indices: tuple[int, ...]


@dataclass(frozen=True)
class _InactiveAuthProof:
    root: str = "0" * 64
    leaf: str = "0" * 64
    leaf_index: int = 0
    siblings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceLineWitness:
    procedure_code: str
    procedure_code_felt: int
    line_charge_cents: int
    units_cents: int
    prior_authorization: str
    allowed_cents: int
    fee_leaf: int
    fee_proof: Any
    requires_tar: bool
    policy_leaf_index: int
    policy_path_elements: tuple[int, ...]
    policy_path_indices: tuple[int, ...]
    tar_required: bool
    policy_present: bool
    authorization: AuthorizationLineWitness
    policy_row_index: int = 0
    authorization_index: int = 0


@dataclass(frozen=True)
class MultiLineNullifierWitness:
    live_root_before: int
    onchain_root_before: int
    root_after: int
    onchain_root_after: int
    predecessor_leaf_hash: int
    updated_predecessor_leaf_hash: int
    inserted_leaf_hash: int
    inserted_nullifier_high: int
    inserted_nullifier_low: int
    predecessor_value_high: int
    predecessor_value_low: int
    successor_value_high: int
    successor_value_low: int
    predecessor_index: int
    successor_index: int
    inserted_index: int
    predecessor_path_elements: tuple[int, ...]
    predecessor_path_indices: tuple[int, ...]
    inserted_path_elements: tuple[int, ...]
    inserted_path_indices: tuple[int, ...]


@dataclass(frozen=True)
class MultiLineServiceLineWitnessBundle:
    claim: MultiLineClaimSourceBinding
    claim_id: int
    service_date_day: int
    oracle_facts_root: int
    normalized_fact_commitment: int
    claim_facts_leaf: int
    claim_facts_leaf_index: int
    claim_facts_path_elements: tuple[int, ...]
    claim_facts_path_indices: tuple[int, ...]
    claim_facts_signer: int
    claim_facts_verification_commitment: int
    claim_facts_evidence_commitment: int
    service_lines: tuple[ServiceLineWitness, ...]
    fee_policy: FeePolicyWitness
    policy_rows: tuple[FeeRowWitness, ...]
    authorizations: tuple[AuthorizationLineWitness, ...]
    policy_root: int
    fee_policy_leaf: int
    fee_policy_proof: Any
    fee_policy_leaf_index: int
    fee_policy_path_elements: tuple[int, ...]
    fee_policy_path_indices: tuple[int, ...]
    ruleset_root: int
    sum_line_charge_cents: int
    allowed_total_cents: int
    requires_any_tar: bool
    total_charge_cents: int
    nullifier: MultiLineNullifierWitness
    member_active: bool = True
    provider_payable: bool = True
    provider_not_suspended: bool = True
    member_not_deceased: bool = True
    duplicate_claim_attested: bool = False
    integrity_hold_attested: bool = False


def _felt(value: int) -> int:
    if type(value) is not int:
        raise ValueError("felt_not_integer")
    if value < 0 or value >= FIELD_MODULUS:
        raise ValueError("felt_out_of_range")
    return value


def claim_source_leaf_for(
    ctx: SharedContext,
    *,
    attempt: GovernedClaimAttempt,
    attempt_nullifier: int,
    ruleset_root: int = 0,
) -> int:
    return canonical_claim_source_leaf(
        ctx,
        attempt=attempt,
        attempt_nullifier=_felt(attempt_nullifier),
        ruleset_root=_felt(ruleset_root),
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
            1,
            pack_felt_text(fee_procedure),
            _felt(fee_allowed),
            canonical_day_count(line.fee_effective_from),
            canonical_day_count(line.fee_effective_until),
        ],
    )


def _sorted_leaf_index_map(sorted_leaves: tuple[int, ...], capacity: int) -> Mapping[int, int]:
    if len(sorted_leaves) > capacity:
        raise ValueError("sorted_leaf_order_exceeds_capacity")
    cache_key = (id(sorted_leaves), len(sorted_leaves), capacity)
    cached = _index_map_cache.get(cache_key)
    if cached is not None and cached[0] is sorted_leaves:
        return cached[1]

    index_map: dict[int, int] = {}
    previous: int | None = None
    for index, raw_value in enumerate(sorted_leaves):
        value = _felt(raw_value)
        if previous is not None:
            if value == previous:
                raise ValueError("sorted_leaf_order_contains_duplicate")
            if value < previous:
                raise ValueError("sorted_leaf_order_not_sorted")
        index_map[value] = index
        previous = value

    if len(_index_map_cache) >= _INDEX_MAP_CACHE_MAX:
        _index_map_cache.pop(next(iter(_index_map_cache)))
    _index_map_cache[cache_key] = (sorted_leaves, index_map)
    return index_map


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
        actual = _felt(witness.governed_roots[key])
        expected = _felt(witness.onchain_governed_roots[key])
        if actual != expected:
            raise ValueError(f"governed_root_mismatch:{key}")

    if _felt(witness.claim_source_leaf) != claim_source_leaf_for(
        witness.ctx,
        attempt=witness.attempt,
        attempt_nullifier=witness.nullifier.inserted_nullifier,
        ruleset_root=_felt(witness.governed_roots["rulesetRoot"]),
    ):
        raise ValueError("claim_source_leaf_mismatch")
    if _felt(witness.normalized_fact_commitment) != normalized_fact_commitment_for(witness.ctx):
        raise ValueError("free_fact_commitment_mismatch")
    if witness.claim_leaf_path_index != expected_path_index(
        witness.claim_source_leaf,
        tree_capacity,
        witness.claim_source_sorted_leaves,
    ):
        raise ValueError("claim_path_index_not_bound_to_sorted_order")

    if len(witness.service_lines) != len(witness.ctx.service_lines):
        raise ValueError("service_line_count_mismatch")
    total_charge_cents = _amount_cents(witness.total_charge_cents)
    allowed_amount_cents = _amount_cents(witness.allowed_amount_cents)
    approved = bool(_bool_bit(witness.approved))
    service_date = canonical_day_count(witness.ctx.service_date)
    line_total = 0
    allowed_total = 0
    for line, ctx_line in zip(witness.service_lines, witness.ctx.service_lines):
        charge_cents = _amount_cents(line.charge_cents)
        allowed_cents = _amount_cents(line.allowed_cents)
        if line.line_id != ctx_line.line_id:
            raise ValueError("service_line_id_mismatch")
        if line.procedure_code != ctx_line.procedure_code:
            raise ValueError("service_line_procedure_mismatch")
        if canonical_cents(ctx_line.charge_amount) != charge_cents:
            raise ValueError("service_line_charge_mismatch")
        fee_procedure = line.fee_schedule_procedure_code or line.procedure_code
        if fee_procedure != line.procedure_code:
            raise ValueError("fee_procedure_not_bound_to_claim")
        if line.fee_allowed_cents is not None:
            if _amount_cents(line.fee_allowed_cents) != allowed_cents:
                raise ValueError("fee_allowed_not_bound_to_claim")
        if not (canonical_day_count(line.fee_effective_from) <= service_date <= canonical_day_count(line.fee_effective_until)):
            raise ValueError("fee_schedule_not_effective_for_service_date")
        if allowed_cents > charge_cents:
            raise ValueError("line_allowed_invalid")
        if line.fee_leaf != fee_leaf_for(line):
            raise ValueError("fee_leaf_mismatch")
        if line.fee_path_index != expected_path_index(line.fee_leaf, tree_capacity, line.fee_sorted_leaves):
            raise ValueError("fee_path_index_not_bound_to_sorted_order")
        line_total += charge_cents
        allowed_total += allowed_cents

    if total_charge_cents != line_total:
        raise ValueError("multi_line_total_mismatch")
    if canonical_cents(witness.ctx.total_charge) != line_total:
        raise ValueError("claim_total_not_derived_from_lines")
    if allowed_amount_cents != (allowed_total if approved else 0):
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


def _u128(value: int) -> int:
    if type(value) is not int:
        raise ValueError("u128_not_integer")
    if value < 0 or value >= 2**128:
        raise ValueError("u128_out_of_range")
    return value


def _u32(value: int) -> int:
    if type(value) is not int:
        raise ValueError("u32_not_integer")
    if value < 0 or value >= 2**32:
        raise ValueError("u32_out_of_range")
    return value


def _amount_cents(value: int) -> int:
    if type(value) is not int or value < 0 or value >= 2**32:
        raise ValueError("amount_cents_out_of_range")
    return value


def _bool_bit(value: bool) -> int:
    if type(value) is not bool:
        raise ValueError("boolean_not_canonical")
    return int(value)


def _split_u256_words(value: int) -> tuple[int, int]:
    if type(value) is not int:
        raise ValueError("u256_not_integer")
    if value < 0 or value >= 2**256:
        raise ValueError("u256_out_of_range")
    return _u128(value >> 128), _u128(value & (2**128 - 1))


def _inserted_nullifier_from_transition(nullifier: MultiLineNullifierWitness) -> int:
    return (_u128(nullifier.inserted_nullifier_high) << 128) + _u128(nullifier.inserted_nullifier_low)


def _nullifier_transition_witness_from_nonmembership(witness: NonMembershipWitness) -> MultiLineNullifierWitness:
    inserted_high, inserted_low = _split_u256_words(witness.nullifier)
    predecessor_high, predecessor_low = _split_u256_words(witness.leafValue)
    successor_high, successor_low = _split_u256_words(witness.nextValue)
    return MultiLineNullifierWitness(
        live_root_before=witness.root,
        onchain_root_before=witness.root,
        root_after=witness.rootAfter,
        onchain_root_after=witness.rootAfter,
        predecessor_leaf_hash=_indexed_leaf_hash(witness.leafValue, witness.nextValue, witness.nextIndex, witness.leafIndex),
        updated_predecessor_leaf_hash=_indexed_leaf_hash(witness.leafValue, witness.nullifier, witness.insertedIndex, witness.leafIndex),
        inserted_leaf_hash=_indexed_leaf_hash(witness.nullifier, witness.nextValue, witness.nextIndex, witness.insertedIndex),
        inserted_nullifier_high=inserted_high,
        inserted_nullifier_low=inserted_low,
        predecessor_value_high=predecessor_high,
        predecessor_value_low=predecessor_low,
        successor_value_high=successor_high,
        successor_value_low=successor_low,
        predecessor_index=witness.leafIndex,
        successor_index=witness.nextIndex,
        inserted_index=witness.insertedIndex,
        predecessor_path_elements=tuple(witness.pathElements),
        predecessor_path_indices=tuple(witness.pathIndices),
        inserted_path_elements=tuple(witness.insertedPathElements),
        inserted_path_indices=tuple(witness.insertedPathIndices),
    )


def _path_indices(leaf_index: int, depth: int) -> list[int]:
    cursor = int(leaf_index)
    out: list[int] = []
    for _ in range(depth):
        out.append(cursor & 1)
        cursor //= 2
    return out


def _hex_to_felt(value: str | int) -> int:
    if isinstance(value, int):
        return _felt(value)
    clean = str(value).lower().removeprefix("0x")
    if len(clean) != 64:
        raise ValueError("expected_hex32")
    return _felt(int(clean, 16))


def _span(values: Sequence[int]) -> list[int]:
    return [_felt(value) for value in values]


def _serialize_span(values: Sequence[int]) -> list[int]:
    return [len(values), *[int(value) for value in values]]


def _path_elements_from_hex(siblings: Sequence[str]) -> list[int]:
    return [_hex_to_felt(value) for value in siblings]


def _assert_path_indices(leaf_index: int, indices: Sequence[int]) -> None:
    expected = _path_indices(leaf_index, len(indices))
    if [_u32(item) for item in indices] != expected:
        raise ValueError("merkle_path_indices_mismatch")


def _verify_field_inclusion(
    *,
    leaf: int,
    leaf_index: int,
    siblings: Sequence[int],
    indices: Sequence[int],
    root: int,
    domain: str,
    label: str,
) -> None:
    from app.batch.merkle import verify_inclusion

    _assert_path_indices(leaf_index, indices)
    if not verify_inclusion(
        f"{_felt(leaf):064x}",
        _u128(leaf_index),
        [f"{_felt(sibling):064x}" for sibling in siblings],
        f"{_felt(root):064x}",
        hash_domain=domain,
        leaf_is_hashed=True,
    ):
        raise ValueError(f"{label}_membership_mismatch")


def build_multi_line_service_line_witness(
    ctx: SharedContext,
    *,
    config: Any | None = None,
    nullifier_tree: Any | None = None,
    frequency_type: str = "original",
    duplicate_pepper: str | None = None,
    signer_root: str | None = None,
    evidence_root: str | None = None,
) -> MultiLineServiceLineWitnessBundle:
    from app.batch.batch_orchestrator import (
        BatchConfig,
        _validate_batch_config,
        fee_policy_leaf,
        fee_schedule_leaves,
        indexed_policy_row_leaf,
        POLICY_ROW_KIND_REAL,
        policy_tree_rows,
        ruleset_policy_record,
    )
    from app.batch.claim_source_root import (
        claim_source_leaf,
        claim_source_tree,
    )
    from app.batch.leaf import current_duplicate_pepper
    from app.batch.merkle import PoseidonFieldMerkleTree
    from app.batch.nullifier import IndexedNullifierTree
    from app.batch.oracle_facts_root import (
        canonical_oracle_claim_leaves,
        canonical_oracle_signer_root,
        oracle_claim_fact_commitment,
        oracle_claim_facts_leaf,
        oracle_evidence_commitment,
        oracle_fact_verification_commitment,
        oracle_facts_tree,
        oracle_line_authorization_leaf,
    )

    active_config = config or BatchConfig()
    _validate_batch_config(active_config)
    identities = canonical_service_line_identities(ctx.service_lines)
    line_count = len(identities)
    if line_count < 1 or line_count > MAX_SERVICE_LINES_PER_CLAIM_WITNESS:
        raise ValueError("multi_line_service_line_count_out_of_range")
    if any(
        not (
            2 <= len(procedure_code) <= 10
            and all("A" <= character <= "Z" or "0" <= character <= "9" for character in procedure_code)
        )
        for procedure_code, _charge, _units, _authorization in identities
    ):
        raise ValueError("multi_line_procedure_code_not_canonical")

    sum_line_charge_cents = sum(int(charge_cents) for _, charge_cents, _, _ in identities)
    total_charge_cents = canonical_cents(ctx.total_charge)
    if sum_line_charge_cents != total_charge_cents:
        raise ValueError("multi_line_total_charge_mismatch")

    ruleset_root_hex = ruleset_policy_record(active_config.ruleset_version, active_config.ruleset_policy_content)
    ruleset_root = _hex_to_felt(ruleset_root_hex)
    encoded_claim = encode_claim(ctx)
    claim_id_felt = encoded_claim.claim_id
    service_date_day = encoded_claim.service_date
    member_id_felt = encoded_claim.member_id
    provider_npi = encoded_claim.provider_npi
    service_lines_commitment = encoded_claim.service_lines_commitment
    diagnosis_commitment = encoded_claim.diagnosis_commitment
    if frequency_type != "original":
        raise ValueError("attempt_revision_pending_lifecycle_authority")
    attempt = synthetic_original_attempt(ctx, source_authority_id=active_config.claim_source_authority_id)
    governed_pepper = duplicate_pepper or current_duplicate_pepper()
    attempt_nullifier = legacy_attempt_nullifier(attempt, ctx, governed_pepper=governed_pepper)
    attempt_record_commitment = legacy_attempt_record_commitment(attempt, ctx)
    working_nullifier_tree = nullifier_tree or IndexedNullifierTree()
    nullifier_witness = working_nullifier_tree.prove_nonmembership(attempt_nullifier)
    nullifier_transition = _nullifier_transition_witness_from_nonmembership(nullifier_witness)
    source_leaf = claim_source_leaf(
        ctx,
        attempt=attempt,
        attempt_nullifier=attempt_nullifier,
        ruleset_root=ruleset_root_hex,
    )
    source_tree = claim_source_tree([source_leaf], active_config.merkle_depth)
    source_proof = source_tree.prove(source_tree.original_leaves.index(f"{source_leaf:064x}"))
    fee_leaves = fee_schedule_leaves(active_config, ruleset_root_hex)
    fee_tree = PoseidonFieldMerkleTree(fee_leaves, active_config.merkle_depth, "fee")
    fee_policy = fee_policy_leaf(
        ruleset_root_hex,
        tree_depth=active_config.merkle_depth,
        real_row_count=len(active_config.fee_schedule_cents),
    )
    fee_policy_proof = fee_tree.prove(0)
    if fee_tree.original_leaves[0] != f"{fee_policy:064x}":
        raise ValueError("fee_policy_leaf_not_first")
    fee_policy_witness = FeePolicyWitness(
        fee_policy_leaf=fee_policy,
        fee_policy_leaf_index=fee_policy_proof.leaf_index,
        tree_depth=active_config.merkle_depth,
        real_row_count=len(active_config.fee_schedule_cents),
        fee_policy_path_elements=tuple(_path_elements_from_hex(fee_policy_proof.siblings)),
        fee_policy_path_indices=tuple(_path_indices(fee_policy_proof.leaf_index, len(fee_policy_proof.siblings))),
    )
    governed_policy_rows = policy_tree_rows(active_config)
    governed_policy_keys = [row.procedure_code_felt for row in governed_policy_rows]

    def governed_row_witness(row: Any) -> FeeRowWitness:
        fee_leaf = indexed_policy_row_leaf(
            row_kind=row.row_kind,
            procedure_code_felt=row.procedure_code_felt,
            allowed_cents=row.allowed_cents,
            requires_tar=row.requires_tar,
            next_procedure_code_felt=row.next_procedure_code_felt,
            next_policy_leaf_index=row.next_policy_leaf_index,
            policy_leaf_index=row.policy_leaf_index,
        )
        proof = fee_tree.prove(row.policy_leaf_index)
        if proof.leaf != f"{fee_leaf:064x}":
            raise ValueError("policy_row_leaf_layout_mismatch")
        return FeeRowWitness(
            row_kind=row.row_kind,
            procedure_code=row.procedure_code,
            procedure_code_felt=row.procedure_code_felt,
            allowed_cents=row.allowed_cents,
            fee_leaf=fee_leaf,
            fee_proof=proof,
            requires_tar=row.requires_tar,
            policy_leaf_index=row.policy_leaf_index,
            next_procedure_code_felt=row.next_procedure_code_felt,
            next_policy_leaf_index=row.next_policy_leaf_index,
            policy_path_elements=tuple(_path_elements_from_hex(proof.siblings)),
            policy_path_indices=tuple(_path_indices(proof.leaf_index, len(proof.siblings))),
        )

    signer_root_text = signer_root or canonical_oracle_signer_root()
    evidence_root_text = evidence_root or str(
        ctx.fact_verification.get("evidence_root", "multi_line_oracle_evidence_root_v1")
    )
    signer_commitment = oracle_evidence_commitment(signer_root_text)
    evidence_commitment = oracle_evidence_commitment(evidence_root_text)
    fact_verification_commitment = oracle_fact_verification_commitment(ctx.fact_verification)
    tar_authorization_verified = ctx.fact_verification.get("tar_authorization") == "VERIFIED"
    normalized_fact_commitment = oracle_claim_fact_commitment(ctx)
    claim_facts_leaf = oracle_claim_facts_leaf(
        ctx,
        signer_root=signer_root_text,
        claim_source_commitment=source_leaf,
        normalized_fact_commitment=normalized_fact_commitment,
        evidence_root=evidence_root_text,
    )
    auth_rows: list[dict[str, int | str | bool]] = []
    for line_index, (procedure_code, _line_charge_cents, _units_cents, prior_authorization) in enumerate(identities):
        procedure_code_felt = pack_felt_text(procedure_code)
        authorization_present = bool(prior_authorization) and tar_authorization_verified
        signed_tar_authorization = _pack_optional_felt_text(prior_authorization) if authorization_present else 0
        auth_leaf = oracle_line_authorization_leaf(
            claim_id=claim_id_felt,
            line_index=line_index,
            procedure_code=procedure_code_felt,
            service_date_day=service_date_day,
            prior_authorization=prior_authorization,
            authorization_present=authorization_present,
            signed_tar_authorization_commitment=signed_tar_authorization,
            signer_root=signer_commitment,
            fact_verification_commitment=fact_verification_commitment,
            evidence_root=evidence_commitment,
            valid_from_day=service_date_day,
            valid_until_day=service_date_day,
        )
        auth_rows.append(
            {
                "leaf": auth_leaf,
                "claim_id": claim_id_felt,
                "line_index": line_index,
                "procedure_code": procedure_code_felt,
                "service_date_day": service_date_day,
                "valid_from_day": service_date_day,
                "valid_until_day": service_date_day,
                "prior_authorization": prior_authorization,
                "signed_tar_authorization_commitment": signed_tar_authorization,
                "authorization_present": authorization_present,
                "signer_root": signer_commitment,
                "fact_verification_commitment": fact_verification_commitment,
                "evidence_root": evidence_commitment,
            }
        )
    governed_tar_codes = tuple(
        code for code in active_config.tar_required_procedure_codes if code in active_config.fee_schedule_cents
    )
    canonical_oracle_leaves = canonical_oracle_claim_leaves(
        ctx,
        signer_root=signer_root_text,
        claim_source_commitment=source_leaf,
        evidence_root=evidence_root_text,
        tar_required_codes=governed_tar_codes,
    )
    if claim_facts_leaf != canonical_oracle_leaves[0]:
        raise ValueError("oracle_claim_leaf_schema_mismatch")
    expected_authorization_leaves = tuple(
        int(row["leaf"])
        for row, identity in zip(auth_rows, identities)
        if is_tar_required(identity[0], governed_tar_codes)
    )
    if expected_authorization_leaves != canonical_oracle_leaves[1:]:
        raise ValueError("oracle_authorization_leaf_schema_mismatch")
    oracle_tree = oracle_facts_tree(canonical_oracle_leaves, active_config.merkle_depth)
    claim_facts_proof = oracle_tree.prove(oracle_tree.original_leaves.index(f"{claim_facts_leaf:064x}"))

    service_line_witnesses: list[ServiceLineWitness] = []
    policy_rows: list[FeeRowWitness] = []
    policy_row_index_by_key: dict[int, int] = {}
    authorizations: list[AuthorizationLineWitness] = []
    allowed_total_cents = 0
    requires_any_tar = False
    for line_index, (procedure_code, line_charge_cents, units_cents, prior_authorization) in enumerate(identities):
        procedure_code_felt = pack_felt_text(procedure_code)
        governed_position = bisect_right(governed_policy_keys, procedure_code_felt) - 1
        if governed_position < 0 or governed_position >= len(governed_policy_rows):
            raise ValueError("policy_lookup_predecessor_missing")
        governed_row = governed_policy_rows[governed_position]
        policy_present = (
            governed_row.row_kind == POLICY_ROW_KIND_REAL
            and governed_row.procedure_code_felt == procedure_code_felt
        )
        if not policy_present and not (
            governed_row.procedure_code_felt
            < procedure_code_felt
            < governed_row.next_procedure_code_felt
        ):
            raise ValueError("policy_nonmembership_range_invalid")
        allowed_cents = governed_row.allowed_cents if policy_present else 0
        requires_tar = bool(governed_row.requires_tar) if policy_present else False
        policy_row = governed_row_witness(governed_row)
        fee_leaf = policy_row.fee_leaf
        fee_proof = policy_row.fee_proof
        policy_row_index = policy_row_index_by_key.get(policy_row.policy_leaf_index)
        if policy_row_index is None:
            policy_row_index = len(policy_rows)
            policy_row_index_by_key[policy_row.policy_leaf_index] = policy_row_index
            policy_rows.append(policy_row)
        auth_row = auth_rows[line_index]
        auth_leaf = int(auth_row["leaf"])
        if requires_tar:
            auth_proof = oracle_tree.prove(oracle_tree.original_leaves.index(f"{auth_leaf:064x}"))
            auth_leaf_index = auth_proof.leaf_index
            auth_path_elements = tuple(_path_elements_from_hex(auth_proof.siblings))
            auth_path_indices = tuple(_path_indices(auth_proof.leaf_index, len(auth_proof.siblings)))
        else:
            auth_proof = _InactiveAuthProof()
            auth_leaf_index = 0
            auth_path_elements = ()
            auth_path_indices = ()
        allowed_total_cents += min(int(line_charge_cents), allowed_cents)
        requires_any_tar = requires_any_tar or requires_tar
        authorization = AuthorizationLineWitness(
            auth_leaf=auth_leaf,
            auth_proof=auth_proof,
            auth_leaf_index=auth_leaf_index,
            auth_path_elements=auth_path_elements,
            auth_path_indices=auth_path_indices,
            claim_id=int(auth_row["claim_id"]),
            line_index=int(auth_row["line_index"]),
            procedure_code=int(auth_row["procedure_code"]),
            service_date_day=int(auth_row["service_date_day"]),
            valid_from_day=int(auth_row["valid_from_day"]),
            valid_until_day=int(auth_row["valid_until_day"]),
            prior_authorization=str(auth_row["prior_authorization"]),
            signed_tar_authorization_commitment=int(auth_row["signed_tar_authorization_commitment"]),
            authorization_present=bool(auth_row["authorization_present"]),
            signer_root=int(auth_row["signer_root"]),
            fact_verification_commitment=int(auth_row["fact_verification_commitment"]),
            evidence_root=int(auth_row["evidence_root"]),
        )
        if requires_tar:
            authorization_index = len(authorizations)
            authorizations.append(authorization)
        else:
            authorization_index = 0
        service_line_witnesses.append(
            ServiceLineWitness(
                procedure_code=procedure_code,
                procedure_code_felt=pack_felt_text(procedure_code),
                line_charge_cents=int(line_charge_cents),
                units_cents=int(units_cents),
                prior_authorization=prior_authorization,
                allowed_cents=allowed_cents,
                fee_leaf=fee_leaf,
                fee_proof=fee_proof,
                requires_tar=requires_tar,
                policy_leaf_index=fee_proof.leaf_index,
                policy_path_elements=tuple(_path_elements_from_hex(fee_proof.siblings)),
                policy_path_indices=tuple(_path_indices(fee_proof.leaf_index, len(fee_proof.siblings))),
                tar_required=requires_tar,
                policy_present=policy_present,
                authorization=authorization,
                policy_row_index=policy_row_index,
                authorization_index=authorization_index,
            )
        )

    return MultiLineServiceLineWitnessBundle(
        claim=MultiLineClaimSourceBinding(
            claim_source_root=_hex_to_felt(source_tree.root),
            claim_source_leaf=source_leaf,
            claim_id=claim_id_felt,
            member_id=member_id_felt,
            provider_npi=provider_npi,
            service_date_day=service_date_day,
            service_lines_commitment=service_lines_commitment,
            diagnosis_commitment=diagnosis_commitment,
            total_charge_cents=total_charge_cents,
            source_authority_id=pack_felt_text(attempt.source_authority_id),
            payer_id=pack_felt_text(ctx.payer_id),
            attempt_version=attempt.attempt_version,
            revision_kind=attempt.revision_kind,
            parent_attempt_version=attempt.parent_attempt_version,
            attempt_nullifier=attempt_nullifier,
            attempt_record_commitment=attempt_record_commitment,
            ruleset_root=ruleset_root,
            service_line_count=line_count,
            diagnosis_count=len(ctx.diagnoses),
            claim_source_leaf_index=source_proof.leaf_index,
            claim_source_path_elements=tuple(_path_elements_from_hex(source_proof.siblings)),
            claim_source_path_indices=tuple(_path_indices(source_proof.leaf_index, len(source_proof.siblings))),
        ),
        claim_id=claim_id_felt,
        service_date_day=service_date_day,
        oracle_facts_root=_hex_to_felt(oracle_tree.root),
        normalized_fact_commitment=normalized_fact_commitment,
        claim_facts_leaf=claim_facts_leaf,
        claim_facts_leaf_index=claim_facts_proof.leaf_index,
        claim_facts_path_elements=tuple(_path_elements_from_hex(claim_facts_proof.siblings)),
        claim_facts_path_indices=tuple(_path_indices(claim_facts_proof.leaf_index, len(claim_facts_proof.siblings))),
        claim_facts_signer=signer_commitment,
        claim_facts_verification_commitment=fact_verification_commitment,
        claim_facts_evidence_commitment=evidence_commitment,
        service_lines=tuple(service_line_witnesses),
        fee_policy=fee_policy_witness,
        policy_rows=tuple(policy_rows),
        authorizations=tuple(authorizations),
        policy_root=_hex_to_felt(fee_tree.root),
        fee_policy_leaf=fee_policy,
        fee_policy_proof=fee_policy_proof,
        fee_policy_leaf_index=fee_policy_proof.leaf_index,
        fee_policy_path_elements=tuple(_path_elements_from_hex(fee_policy_proof.siblings)),
        fee_policy_path_indices=tuple(_path_indices(fee_policy_proof.leaf_index, len(fee_policy_proof.siblings))),
        ruleset_root=ruleset_root,
        sum_line_charge_cents=sum_line_charge_cents,
        allowed_total_cents=allowed_total_cents,
        requires_any_tar=requires_any_tar,
        total_charge_cents=total_charge_cents,
        nullifier=nullifier_transition,
        member_active=bool(ctx.flags.get("eligibility_active")),
        provider_payable=bool(ctx.flags.get("provider_enrolled")),
        provider_not_suspended=bool(ctx.flags.get("provider_not_suspended")),
        member_not_deceased=bool(ctx.flags.get("not_deceased")),
        duplicate_claim_attested=bool(ctx.flags.get("duplicate_claim")),
        integrity_hold_attested=bool(ctx.flags.get("program_integrity_hold")),
    )


def _pack_optional_felt_text(value: str) -> int:
    return 0 if value == "" else pack_felt_text(value)


def _serialize_fee_policy_witness(policy: FeePolicyWitness) -> list[int]:
    values = [
        _felt(policy.fee_policy_leaf),
        _u128(policy.fee_policy_leaf_index),
        _u128(policy.tree_depth),
        _u128(policy.real_row_count),
    ]
    values.extend(_serialize_span(_span(policy.fee_policy_path_elements)))
    return values


def _serialize_fee_row_witness(row: FeeRowWitness) -> list[int]:
    values = [
        _u32(row.row_kind),
        _felt(row.procedure_code_felt),
        _u128(row.allowed_cents),
        _u32(int(bool(row.requires_tar))),
        _u128(row.policy_leaf_index),
        _felt(row.next_procedure_code_felt),
        _u128(row.next_policy_leaf_index),
    ]
    values.extend(_serialize_span(_span(row.policy_path_elements)))
    return values


def _serialize_authorization_witness(auth: AuthorizationLineWitness) -> list[int]:
    values = [
        _hex_to_felt(auth.auth_proof.root),
        _u128(auth.auth_leaf_index),
        _felt(auth.claim_id),
        _u128(auth.line_index),
        _felt(auth.procedure_code),
        _u128(auth.service_date_day),
        _u128(auth.valid_from_day),
        _u128(auth.valid_until_day),
        _pack_optional_felt_text(auth.prior_authorization),
        _felt(auth.signed_tar_authorization_commitment),
        _u32(int(bool(auth.authorization_present))),
        _felt(auth.signer_root),
        _felt(auth.fact_verification_commitment),
        _felt(auth.evidence_root),
    ]
    values.extend(_serialize_span(_span(auth.auth_path_elements)))
    return values


def _serialize_multi_line_nullifier_witness(nullifier: MultiLineNullifierWitness) -> list[int]:
    values = [
        _felt(nullifier.live_root_before),
        _felt(nullifier.onchain_root_before),
        _felt(nullifier.root_after),
        _felt(nullifier.onchain_root_after),
        _u128(nullifier.inserted_nullifier_high),
        _u128(nullifier.inserted_nullifier_low),
        _u128(nullifier.predecessor_value_high),
        _u128(nullifier.predecessor_value_low),
        _u128(nullifier.successor_value_high),
        _u128(nullifier.successor_value_low),
        _u128(nullifier.predecessor_index),
        _u128(nullifier.successor_index),
        _u128(nullifier.inserted_index),
    ]
    values.extend(_serialize_span(_span(nullifier.predecessor_path_elements)))
    values.extend(_serialize_span(_span(nullifier.inserted_path_elements)))
    return values


def _serialize_multi_line_claim_source_witness(claim: MultiLineClaimSourceBinding) -> list[int]:
    values = [
        _felt(claim.claim_source_leaf),
        _felt(claim.claim_id),
        _felt(claim.member_id),
        _felt(claim.provider_npi),
        _u128(claim.service_date_day),
        _felt(claim.service_lines_commitment),
        _felt(claim.diagnosis_commitment),
        _u128(claim.total_charge_cents),
        _felt(claim.source_authority_id),
        _felt(claim.payer_id),
        _u128(claim.attempt_version),
        _u32(claim.revision_kind),
        _u128(claim.parent_attempt_version),
        _felt(claim.attempt_nullifier),
        _u128(claim.service_line_count),
        _u128(claim.diagnosis_count),
        _u128(claim.claim_source_leaf_index),
    ]
    values.extend(_serialize_span(_span(claim.claim_source_path_elements)))
    return values


def flatten_multi_line_claim_witness(bundle: MultiLineServiceLineWitnessBundle) -> list[int]:
    return flatten_multi_line_decision_input_witness(bundle)


def _serialize_multi_line_claim_witness_only(bundle: MultiLineServiceLineWitnessBundle) -> list[int]:
    values = [
        _felt(bundle.claim_id),
        _u128(bundle.service_date_day),
        _u128(bundle.total_charge_cents),
    ]
    values.append(_u128(len(bundle.service_lines)))
    for line in bundle.service_lines:
        values.extend(
            [
                _felt(line.procedure_code_felt),
                _u128(line.line_charge_cents),
                _u128(line.units_cents),
                _pack_optional_felt_text(line.prior_authorization),
                _u128(line.allowed_cents),
                _u32(int(bool(line.tar_required))),
                _u32(int(bool(line.policy_present))),
                _u128(line.policy_row_index),
                _u128(line.authorization_index),
            ]
        )
    values.append(_u128(len(bundle.authorizations)))
    for authorization in bundle.authorizations:
        values.extend(_serialize_authorization_witness(authorization))
    return values


def flatten_multi_line_decision_input_witness(
    bundle: MultiLineServiceLineWitnessBundle,
    *,
    batch_id: int = 901,
    include_root_parameters: bool = True,
) -> list[int]:
    values = [
        _felt(batch_id),
    ]
    values.extend(_serialize_multi_line_claim_source_witness(bundle.claim))
    values.extend(
        [
            _felt(bundle.claim.claim_source_leaf),
            _felt(bundle.claim_facts_leaf),
            _u128(bundle.claim_facts_leaf_index),
        ]
    )
    values.extend(_serialize_span(_span(bundle.claim_facts_path_elements)))
    values.extend(
        [
            _felt(bundle.claim_facts_signer),
            _felt(bundle.claim_facts_verification_commitment),
            _felt(bundle.claim_facts_evidence_commitment),
        ]
    )
    values.extend(
        [
            _felt(bundle.claim.member_id),
            _felt(bundle.claim.provider_npi),
            _u128(bundle.claim.diagnosis_count),
            _u32(int(bool(bundle.member_active))),
            _u32(int(bool(bundle.provider_payable))),
            _u32(int(bool(bundle.provider_not_suspended))),
            _u32(int(bool(bundle.member_not_deceased))),
            _u32(int(bool(bundle.duplicate_claim_attested))),
            _u32(int(bool(bundle.integrity_hold_attested))),
        ]
    )
    values.extend(_serialize_multi_line_claim_witness_only(bundle))
    if include_root_parameters:
        values.extend(_serialize_fee_policy_witness(bundle.fee_policy))
        values.append(len(bundle.policy_rows))
        for row in bundle.policy_rows:
            values.extend(_serialize_fee_row_witness(row))
        values.extend(_serialize_multi_line_nullifier_witness(bundle.nullifier))
        values.extend(
            [
                _felt(bundle.ruleset_root),
                _felt(bundle.ruleset_root),
                _felt(bundle.claim.claim_source_root),
                _felt(bundle.claim.claim_source_root),
                _felt(bundle.oracle_facts_root),
                _felt(bundle.oracle_facts_root),
                _felt(bundle.policy_root),
                _felt(bundle.policy_root),
            ]
        )
    return values


def _assert_serialized_multi_line_matches(bundle: MultiLineServiceLineWitnessBundle, serialized_arguments: Sequence[int] | None) -> None:
    if serialized_arguments is None:
        return
    serialized = [int(item) for item in serialized_arguments]
    expected = flatten_multi_line_claim_witness(bundle)
    if serialized != expected:
        raise ValueError("multi_line_serialized_arguments_mismatch")


def _validate_authorization_line_witness(
    line: ServiceLineWitness,
    *,
    expected_line_index: int,
    claim_id: int,
    service_date_day: int,
    oracle_facts_root: int,
) -> None:
    from app.batch.oracle_facts_root import oracle_line_authorization_leaf

    auth = line.authorization
    if _felt(auth.claim_id) != _felt(claim_id):
        raise ValueError("multi_line_auth_claim_mismatch")
    if _u128(auth.line_index) != _u128(expected_line_index):
        raise ValueError("multi_line_auth_line_index_mismatch")
    if _felt(auth.procedure_code) != _felt(line.procedure_code_felt):
        raise ValueError("multi_line_auth_procedure_mismatch")
    if _u128(auth.service_date_day) != _u128(service_date_day):
        raise ValueError("multi_line_auth_service_date_mismatch")
    if not (_u128(auth.valid_from_day) <= _u128(service_date_day) <= _u128(auth.valid_until_day)):
        raise ValueError("multi_line_auth_service_date_window")
    if auth.prior_authorization != line.prior_authorization:
        raise ValueError("multi_line_auth_prior_authorization_mismatch")
    authorization_present = bool(auth.authorization_present)
    if authorization_present and not line.prior_authorization:
        raise ValueError("multi_line_auth_present_mismatch")
    expected_signed_authorization = _pack_optional_felt_text(line.prior_authorization) if authorization_present else 0
    if _felt(auth.signed_tar_authorization_commitment) != expected_signed_authorization:
        raise ValueError("multi_line_auth_signed_authorization_mismatch")
    expected_leaf = oracle_line_authorization_leaf(
        claim_id=_felt(claim_id),
        line_index=_u128(expected_line_index),
        procedure_code=_felt(line.procedure_code_felt),
        service_date_day=_u128(service_date_day),
        prior_authorization=line.prior_authorization,
        authorization_present=authorization_present,
        signed_tar_authorization_commitment=expected_signed_authorization,
        signer_root=_felt(auth.signer_root),
        fact_verification_commitment=_felt(auth.fact_verification_commitment),
        evidence_root=_felt(auth.evidence_root),
        valid_from_day=_u128(auth.valid_from_day),
        valid_until_day=_u128(auth.valid_until_day),
    )
    if not bool(line.tar_required):
        if _hex_to_felt(auth.auth_proof.root) != 0:
            raise ValueError("multi_line_auth_inactive_root_mismatch")
        if auth.auth_path_elements:
            raise ValueError("multi_line_auth_inactive_path_mismatch")
        if auth.auth_path_indices:
            raise ValueError("multi_line_auth_inactive_path_mismatch")
        return
    if _hex_to_felt(auth.auth_proof.root) != _felt(oracle_facts_root):
        raise ValueError("multi_line_auth_root_mismatch")
    if auth.auth_proof.leaf != f"{expected_leaf:064x}":
        raise ValueError("multi_line_auth_proof_leaf_mismatch")
    if _u128(auth.auth_proof.leaf_index) != _u128(auth.auth_leaf_index):
        raise ValueError("multi_line_auth_proof_index_mismatch")
    _verify_field_inclusion(
        leaf=expected_leaf,
        leaf_index=_u128(auth.auth_leaf_index),
        siblings=auth.auth_path_elements,
        indices=auth.auth_path_indices,
        root=_felt(oracle_facts_root),
        domain="oracle",
        label="multi_line_auth",
    )


def _multi_line_service_lines_commitment_from_witness(lines: Sequence[ServiceLineWitness]) -> int:
    acc = domain_poseidon_hash("claim_source", [len(lines)])
    for index, line in enumerate(lines):
        acc = domain_poseidon_hash(
            "claim_source",
            [
                len(lines),
                index,
                acc,
                _felt(line.procedure_code_felt),
                _u128(line.line_charge_cents),
                _u128(line.units_cents),
                _pack_optional_felt_text(line.prior_authorization),
            ],
        )
    return acc


def multi_line_payment_line_leaf(
    line: ServiceLineWitness,
    *,
    fee_row: FeeRowWitness | None = None,
    authorization: AuthorizationLineWitness | None = None,
) -> int:
    from app.batch.oracle_facts_root import oracle_line_authorization_leaf

    if fee_row is None:
        raise ValueError("multi_line_policy_row_required")
    else:
        if bool(line.policy_present):
            if _u32(fee_row.row_kind) != 1 or _felt(fee_row.procedure_code_felt) != _felt(line.procedure_code_felt):
                raise ValueError("multi_line_fee_dictionary_membership_mismatch")
            if _u128(fee_row.allowed_cents) != _u128(line.allowed_cents):
                raise ValueError("multi_line_fee_dictionary_allowed_mismatch")
            if bool(fee_row.requires_tar) != bool(line.tar_required):
                raise ValueError("multi_line_policy_dictionary_tar_mismatch")
        elif not (
            _felt(fee_row.procedure_code_felt)
            < _felt(line.procedure_code_felt)
            < _felt(fee_row.next_procedure_code_felt)
        ):
            raise ValueError("multi_line_fee_dictionary_nonmembership_mismatch")
        elif _u128(line.allowed_cents) != 0 or bool(line.tar_required):
            raise ValueError("multi_line_policy_absence_must_deny")
        expected_fee_leaf = _felt(fee_row.fee_leaf)
    if bool(line.tar_required):
        auth = authorization or line.authorization
        expected_auth_leaf = oracle_line_authorization_leaf(
            claim_id=_felt(auth.claim_id),
            line_index=_u128(auth.line_index),
            procedure_code=_felt(line.procedure_code_felt),
            service_date_day=_u128(auth.service_date_day),
            prior_authorization=line.prior_authorization,
            authorization_present=bool(auth.authorization_present),
            signed_tar_authorization_commitment=_felt(auth.signed_tar_authorization_commitment),
            signer_root=_felt(auth.signer_root),
            fact_verification_commitment=_felt(auth.fact_verification_commitment),
            evidence_root=_felt(auth.evidence_root),
            valid_from_day=_u128(auth.valid_from_day),
            valid_until_day=_u128(auth.valid_until_day),
        )
    else:
        expected_auth_leaf = 0
    return domain_poseidon_hash(
        "payment",
        [
            _felt(line.procedure_code_felt),
            _u128(line.line_charge_cents),
            _u128(line.units_cents),
            _pack_optional_felt_text(line.prior_authorization),
            _u128(line.allowed_cents),
            expected_fee_leaf,
            _u32(int(bool(line.tar_required))),
            _u32(int(bool(line.policy_present))),
            expected_auth_leaf,
        ],
    )


def multi_line_payment_lines_commitment(bundle: MultiLineServiceLineWitnessBundle) -> int:
    acc = domain_poseidon_hash("payment", [len(bundle.service_lines)])
    for index, line in enumerate(bundle.service_lines):
        fee_row = bundle.policy_rows[_u128(line.policy_row_index)]
        authorization = bundle.authorizations[_u128(line.authorization_index)] if bool(line.tar_required) else None
        acc = domain_poseidon_hash(
            "payment",
            [
                len(bundle.service_lines),
                index,
                acc,
                multi_line_payment_line_leaf(line, fee_row=fee_row, authorization=authorization),
            ],
        )
    return acc


def multi_line_claim_payment_commitment(
    bundle: MultiLineServiceLineWitnessBundle,
    *,
    batch_id: int = 901,
    inserted_nullifier: int | None = None,
) -> int:
    if inserted_nullifier is None:
        inserted_nullifier = _inserted_nullifier_from_transition(bundle.nullifier)
    normalized_fact_commitment = domain_poseidon_hash("normalized_facts", _claim_fact_values(bundle))
    return domain_poseidon_hash(
        "payment",
        [
            _felt(batch_id),
            _felt(bundle.claim.claim_source_leaf),
            normalized_fact_commitment,
            multi_line_payment_lines_commitment(bundle),
            _felt(inserted_nullifier),
            _felt(bundle.ruleset_root),
        ],
    )


def _validate_multi_line_claim_source_binding(bundle: MultiLineServiceLineWitnessBundle) -> None:
    claim = bundle.claim
    actual_order = [
        (line.procedure_code, _u128(line.line_charge_cents), _u128(line.units_cents), line.prior_authorization)
        for line in bundle.service_lines
    ]
    if actual_order != sorted(actual_order):
        raise ValueError("multi_line_service_lines_not_canonical")
    expected_service_lines = _multi_line_service_lines_commitment_from_witness(bundle.service_lines)
    if _felt(claim.service_lines_commitment) != expected_service_lines:
        raise ValueError("multi_line_claim_service_lines_mismatch")
    if _felt(claim.source_authority_id) == 0 or _felt(claim.payer_id) == 0:
        raise ValueError("multi_line_attempt_authority_missing")
    if (
        _u128(claim.attempt_version) != 1
        or _u32(claim.revision_kind) != 1
        or _u128(claim.parent_attempt_version) != 0
    ):
        raise ValueError("multi_line_attempt_lifecycle_invalid")
    attempt_identity_commitment = domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            _felt(claim.source_authority_id),
            _felt(claim.payer_id),
            _felt(claim.provider_npi),
            _felt(claim.claim_id),
            _u128(claim.attempt_version),
            _u32(claim.revision_kind),
            _u128(claim.parent_attempt_version),
        ],
    )
    attempt_snapshot_commitment = domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            _felt(claim.member_id),
            _u128(claim.service_date_day),
            expected_service_lines,
            _felt(claim.diagnosis_commitment),
            _u128(claim.diagnosis_count),
            _u128(claim.total_charge_cents),
            _u128(claim.service_line_count),
        ],
    )
    expected_attempt_record = domain_poseidon_hash(
        "claim_source",
        [ATTEMPT_RECORD_SCHEMA, attempt_identity_commitment, attempt_snapshot_commitment],
    )
    if _felt(claim.attempt_record_commitment) != expected_attempt_record:
        raise ValueError("multi_line_attempt_record_commitment_mismatch")
    expected_claim_leaf = domain_poseidon_hash(
        "claim_source",
        [
            2,
            _felt(claim.claim_id),
            _felt(claim.member_id),
            _felt(claim.provider_npi),
            _u128(claim.service_date_day),
            expected_service_lines,
            _felt(claim.diagnosis_commitment),
            _u128(claim.diagnosis_count),
            _u128(claim.total_charge_cents),
            _felt(claim.attempt_nullifier),
            expected_attempt_record,
            _felt(bundle.ruleset_root),
        ],
    )
    if _felt(claim.claim_source_leaf) != expected_claim_leaf:
        raise ValueError("multi_line_claim_source_leaf_mismatch")
    _verify_field_inclusion(
        leaf=expected_claim_leaf,
        leaf_index=_u128(claim.claim_source_leaf_index),
        siblings=claim.claim_source_path_elements,
        indices=claim.claim_source_path_indices,
        root=_felt(claim.claim_source_root),
        domain="claim_source",
        label="multi_line_claim_source",
    )
    if _felt(claim.claim_id) != _felt(bundle.claim_id):
        raise ValueError("multi_line_claim_id_link_mismatch")
    if _u128(claim.service_date_day) != _u128(bundle.service_date_day):
        raise ValueError("multi_line_claim_service_date_link_mismatch")
    if _u128(claim.total_charge_cents) != _u128(bundle.total_charge_cents):
        raise ValueError("multi_line_claim_total_charge_link_mismatch")
    if _u128(claim.service_line_count) != len(bundle.service_lines):
        raise ValueError("multi_line_claim_service_line_count_mismatch")


def _validate_multi_line_nullifier_witness(bundle: MultiLineServiceLineWitnessBundle) -> None:
    nullifier = bundle.nullifier
    inserted_nullifier = _inserted_nullifier_from_transition(nullifier)
    predecessor_value = (_u128(nullifier.predecessor_value_high) << 128) + _u128(nullifier.predecessor_value_low)
    successor_value = (_u128(nullifier.successor_value_high) << 128) + _u128(nullifier.successor_value_low)
    predecessor_index = _u128(nullifier.predecessor_index)
    successor_index = _u128(nullifier.successor_index)
    inserted_index = _u128(nullifier.inserted_index)
    if _felt(bundle.claim.attempt_nullifier) != _felt(inserted_nullifier):
        raise ValueError("multi_line_nullifier_claim_mismatch")
    verify_nonmembership_witness(
        NonMembershipWitness(
            root=_felt(nullifier.live_root_before),
            nullifier=inserted_nullifier,
            leafIndex=predecessor_index,
            leafValue=predecessor_value,
            nextValue=successor_value,
            nextIndex=successor_index,
            pathElements=[_felt(item) for item in nullifier.predecessor_path_elements],
            pathIndices=[_u32(item) for item in nullifier.predecessor_path_indices],
            rootAfter=_felt(nullifier.root_after),
            insertedIndex=inserted_index,
            insertedPathElements=[_felt(item) for item in nullifier.inserted_path_elements],
            insertedPathIndices=[_u32(item) for item in nullifier.inserted_path_indices],
        )
    )
    if _felt(nullifier.live_root_before) != _felt(nullifier.onchain_root_before):
        raise ValueError("multi_line_nullifier_root_before_onchain_mismatch")
    if _felt(nullifier.root_after) != _felt(nullifier.onchain_root_after):
        raise ValueError("multi_line_nullifier_root_after_onchain_mismatch")


def _claim_fact_values(bundle: MultiLineServiceLineWitnessBundle) -> list[int]:
    return [
        _u32(_bool_bit(bundle.member_active)),
        _u32(_bool_bit(bundle.provider_payable)),
        _u32(_bool_bit(bundle.provider_not_suspended)),
        _u32(_bool_bit(bundle.member_not_deceased)),
        _u32(_bool_bit(bundle.duplicate_claim_attested)),
        _u32(_bool_bit(bundle.integrity_hold_attested)),
    ]


def _validate_claim_facts_witness(bundle: MultiLineServiceLineWitnessBundle) -> None:
    flags = _claim_fact_values(bundle)
    normalized = domain_poseidon_hash("normalized_facts", flags)
    expected_leaf = domain_poseidon_hash(
        "oracle",
        [
            0,
            _felt(bundle.claim.claim_id),
            _felt(bundle.claim.claim_source_leaf),
            _felt(bundle.claim_facts_signer),
            normalized,
            _felt(bundle.claim_facts_verification_commitment),
            _felt(bundle.claim_facts_evidence_commitment),
            *flags,
        ],
    )
    if _felt(bundle.claim_facts_leaf) != expected_leaf:
        raise ValueError("multi_line_claim_facts_leaf_mismatch")
    _verify_field_inclusion(
        leaf=expected_leaf,
        leaf_index=_u128(bundle.claim_facts_leaf_index),
        siblings=bundle.claim_facts_path_elements,
        indices=bundle.claim_facts_path_indices,
        root=_felt(bundle.oracle_facts_root),
        domain="oracle",
        label="multi_line_claim_facts",
    )


def _validate_multi_line_money_shape(bundle: MultiLineServiceLineWitnessBundle) -> None:
    _amount_cents(bundle.claim.total_charge_cents)
    _amount_cents(bundle.total_charge_cents)
    for row in bundle.policy_rows:
        _amount_cents(row.allowed_cents)
        _bool_bit(row.requires_tar)
    for line in bundle.service_lines:
        _amount_cents(line.line_charge_cents)
        _amount_cents(line.units_cents)
        _amount_cents(line.allowed_cents)
        _bool_bit(line.tar_required)
        _bool_bit(line.policy_present)


def validate_multi_line_claim_witness(
    bundle: MultiLineServiceLineWitnessBundle,
    *,
    serialized_arguments: Sequence[int] | None = None,
) -> bool:
    line_count = len(bundle.service_lines)
    if line_count < 1 or line_count > MAX_SERVICE_LINES_PER_CLAIM_WITNESS:
        raise ValueError("multi_line_service_line_count_out_of_range")
    _validate_multi_line_money_shape(bundle)
    _assert_serialized_multi_line_matches(bundle, serialized_arguments)
    _validate_multi_line_claim_source_binding(bundle)
    _validate_multi_line_nullifier_witness(bundle)
    _validate_claim_facts_witness(bundle)

    from app.batch.batch_orchestrator import fee_policy_leaf, indexed_policy_row_leaf

    policy_tree_depth = _u128(bundle.fee_policy.tree_depth)
    policy_real_row_count = _u128(bundle.fee_policy.real_row_count)
    if policy_tree_depth != len(bundle.fee_policy.fee_policy_path_elements):
        raise ValueError("multi_line_fee_policy_depth_mismatch")
    if policy_tree_depth != len(bundle.fee_policy.fee_policy_path_indices):
        raise ValueError("multi_line_fee_policy_depth_mismatch")
    if policy_real_row_count + 3 > 2**policy_tree_depth:
        raise ValueError("multi_line_fee_policy_capacity_mismatch")
    expected_fee_policy_leaf = fee_policy_leaf(
        _felt(bundle.ruleset_root),
        tree_depth=_u128(bundle.fee_policy.tree_depth),
        real_row_count=_u128(bundle.fee_policy.real_row_count),
    )
    if _felt(bundle.fee_policy.fee_policy_leaf) != expected_fee_policy_leaf:
        raise ValueError("multi_line_fee_policy_leaf_mismatch")
    if _u128(bundle.fee_policy.fee_policy_leaf_index) != 0:
        raise ValueError("multi_line_fee_policy_index_mismatch")
    _verify_field_inclusion(
        leaf=expected_fee_policy_leaf,
        leaf_index=0,
        siblings=bundle.fee_policy.fee_policy_path_elements,
        indices=bundle.fee_policy.fee_policy_path_indices,
        root=_felt(bundle.policy_root),
        domain="fee",
        label="multi_line_fee_policy",
    )
    if not bundle.policy_rows:
        raise ValueError("multi_line_policy_dictionary_empty")
    if len(bundle.policy_rows) > policy_real_row_count + 2:
        raise ValueError("multi_line_policy_dictionary_count_mismatch")
    for row in bundle.policy_rows:
        row_kind = _u32(row.row_kind)
        row_leaf_index = _u128(row.policy_leaf_index)
        next_row_leaf_index = _u128(row.next_policy_leaf_index)
        if len(row.policy_path_elements) != policy_tree_depth or len(row.policy_path_indices) != policy_tree_depth:
            raise ValueError("multi_line_policy_row_depth_mismatch")
        if row_kind == 0 and row_leaf_index != 1:
            raise ValueError("multi_line_policy_lower_sentinel_index_mismatch")
        if row_kind == 1 and not (2 <= row_leaf_index <= policy_real_row_count + 1):
            raise ValueError("multi_line_policy_real_row_index_mismatch")
        if row_kind == 2 and row_leaf_index != policy_real_row_count + 2:
            raise ValueError("multi_line_policy_upper_sentinel_index_mismatch")
        if next_row_leaf_index > policy_real_row_count + 2:
            raise ValueError("multi_line_policy_successor_index_out_of_range")
        expected_fee_leaf = indexed_policy_row_leaf(
            row_kind=row_kind,
            procedure_code_felt=_felt(row.procedure_code_felt),
            allowed_cents=_u128(row.allowed_cents),
            requires_tar=bool(row.requires_tar),
            next_procedure_code_felt=_felt(row.next_procedure_code_felt),
            next_policy_leaf_index=_u128(row.next_policy_leaf_index),
            policy_leaf_index=_u128(row.policy_leaf_index),
        )
        if _felt(row.fee_leaf) != expected_fee_leaf:
            raise ValueError("multi_line_policy_dictionary_leaf_mismatch")
        if row.fee_proof.leaf != f"{expected_fee_leaf:064x}":
            raise ValueError("multi_line_policy_proof_leaf_mismatch")
        if _u128(row.fee_proof.leaf_index) != _u128(row.policy_leaf_index):
            raise ValueError("multi_line_policy_proof_index_mismatch")
        _verify_field_inclusion(
            leaf=expected_fee_leaf,
            leaf_index=_u128(row.policy_leaf_index),
            siblings=row.policy_path_elements,
            indices=row.policy_path_indices,
            root=_felt(bundle.policy_root),
            domain="fee",
            label="multi_line_policy_row",
        )

    actual_order = [
        (line.procedure_code, _u128(line.line_charge_cents), _u128(line.units_cents), line.prior_authorization)
        for line in bundle.service_lines
    ]
    if actual_order != sorted(actual_order):
        raise ValueError("multi_line_service_lines_not_canonical")

    sum_line_charge_cents = 0
    allowed_total_cents = 0
    requires_any_tar = False
    for line_index, line in enumerate(bundle.service_lines):
        if not (
            2 <= len(line.procedure_code) <= 10
            and all("A" <= character <= "Z" or "0" <= character <= "9" for character in line.procedure_code)
            and pack_felt_text(line.procedure_code) == _felt(line.procedure_code_felt)
        ):
            raise ValueError("multi_line_procedure_code_not_canonical")
        if _u128(line.policy_row_index) >= len(bundle.policy_rows):
            raise ValueError("multi_line_policy_dictionary_index_out_of_range")
        fee_row = bundle.policy_rows[_u128(line.policy_row_index)]
        policy_present = bool(line.policy_present)
        if policy_present:
            if _u32(fee_row.row_kind) != 1 or _felt(fee_row.procedure_code_felt) != _felt(line.procedure_code_felt):
                raise ValueError("multi_line_policy_membership_mismatch")
            if _u128(fee_row.allowed_cents) != _u128(line.allowed_cents):
                raise ValueError("multi_line_policy_dictionary_allowed_mismatch")
            if bool(fee_row.requires_tar) != bool(line.tar_required):
                raise ValueError("multi_line_policy_dictionary_flag_mismatch")
        else:
            if not (
                _felt(fee_row.procedure_code_felt)
                < _felt(line.procedure_code_felt)
                < _felt(fee_row.next_procedure_code_felt)
            ):
                raise ValueError("multi_line_policy_nonmembership_range_mismatch")
            if _u128(line.allowed_cents) != 0 or bool(line.tar_required):
                raise ValueError("multi_line_policy_absence_must_deny")
        if bool(line.tar_required):
            if _u128(line.authorization_index) >= len(bundle.authorizations):
                raise ValueError("multi_line_auth_index_out_of_range")
            _validate_authorization_line_witness(
                replace(line, authorization=bundle.authorizations[_u128(line.authorization_index)]),
                expected_line_index=line_index,
                claim_id=_felt(bundle.claim_id),
                service_date_day=_u128(bundle.service_date_day),
                oracle_facts_root=_felt(bundle.oracle_facts_root),
            )
        elif _u128(line.authorization_index) != 0:
            raise ValueError("multi_line_auth_inactive_index_mismatch")
        sum_line_charge_cents += _u128(line.line_charge_cents)
        allowed_total_cents += min(_u128(line.line_charge_cents), _u128(line.allowed_cents))
        requires_any_tar = requires_any_tar or bool(line.tar_required)

    if _u128(bundle.total_charge_cents) != sum_line_charge_cents:
        raise ValueError("multi_line_total_charge_mismatch")
    return True


def _computed_multi_line_math(bundle: MultiLineServiceLineWitnessBundle) -> dict[str, int | bool]:
    line_count = len(bundle.service_lines)
    sum_line_charge_cents = sum(_amount_cents(line.line_charge_cents) for line in bundle.service_lines)
    allowed_total_cents = sum(
        min(_amount_cents(line.line_charge_cents), _amount_cents(line.allowed_cents))
        for line in bundle.service_lines
    )
    requires_any_tar = any(bool(line.tar_required) for line in bundle.service_lines)
    all_required_authorized = all(
        (not bool(line.tar_required))
        or bool(bundle.authorizations[_u128(line.authorization_index)].authorization_present)
        for line in bundle.service_lines
    )
    all_fee_rows_present = all(bool(line.policy_present) for line in bundle.service_lines)
    return {
        "line_count": line_count,
        "sum_line_charge_cents": sum_line_charge_cents,
        "allowed_total_cents": allowed_total_cents,
        "requires_any_tar": requires_any_tar,
        "all_required_authorized": all_required_authorized,
        "all_fee_rows_present": all_fee_rows_present,
        "all_charges_and_units_positive": all(
            _amount_cents(line.line_charge_cents) > 0 and _amount_cents(line.units_cents) > 0
            for line in bundle.service_lines
        ),
    }


def _multi_line_decision_and_failure_code(bundle: MultiLineServiceLineWitnessBundle) -> tuple[int, int]:
    math = _computed_multi_line_math(bundle)
    if (
        _u128(bundle.total_charge_cents) != int(math["sum_line_charge_cents"])
        or int(math["allowed_total_cents"]) > int(math["sum_line_charge_cents"])
    ):
        raise ValueError("claim_total_mismatch")
    gates = [
        int(_felt(bundle.claim.member_id) != 0),
        int(bool(bundle.member_active)),
        int(bool(bundle.member_not_deceased)),
        int(_felt(bundle.claim.provider_npi) != 0),
        int(bool(bundle.provider_payable)),
        int(bool(bundle.provider_not_suspended)),
        int(int(math["line_count"]) != 0),
        int(_u128(bundle.claim.diagnosis_count) != 0),
        int(bool(math["all_required_authorized"])),
        int(
            _amount_cents(bundle.total_charge_cents) != 0
            and int(math["sum_line_charge_cents"]) != 0
            and bool(math["all_charges_and_units_positive"])
        ),
        int(bool(math["all_fee_rows_present"])),
        int(not bool(bundle.duplicate_claim_attested)),
        int(not bool(bundle.integrity_hold_attested)),
    ]
    decision = 1
    for gate in gates:
        decision *= gate
    failure_code = 0
    for index, gate in enumerate(gates, start=1):
        if gate == 0:
            failure_code = index
            break
    return decision, failure_code


def claim_output_for_multi_line_witness(
    bundle: MultiLineServiceLineWitnessBundle,
    *,
    batch_id: int = 901,
) -> dict[str, int]:
    validate_multi_line_claim_witness(bundle)
    decision, failure_code = _multi_line_decision_and_failure_code(bundle)
    commitment = multi_line_claim_payment_commitment(bundle, batch_id=batch_id)
    math = _computed_multi_line_math(bundle)
    allowed_cents = int(math["allowed_total_cents"])
    payment_cents = allowed_cents if decision == 1 else 0
    nullifier_root_before = _felt(bundle.nullifier.live_root_before)
    nullifier_root_after = _felt(bundle.nullifier.root_after)
    return {
        "commitment": commitment,
        "decision": decision,
        "failure_code": failure_code,
        "claim_source_root": _felt(bundle.claim.claim_source_root),
        "oracle_facts_root": _felt(bundle.oracle_facts_root),
        "policy_root": _felt(bundle.policy_root),
        "nullifier_root_before": nullifier_root_before,
        "nullifier_root_after": nullifier_root_after,
        "allowed_cents": allowed_cents,
        "payment_cents": payment_cents,
    }


def batch_output_leaf_for_claim_output(output: Mapping[str, int], claim_id: int) -> int:
    return domain_poseidon_hash(
        "batch",
        [
            _felt(claim_id),
            _u32(output["decision"]),
            _u32(output["failure_code"]),
            _u128(output["payment_cents"]),
            _felt(output["commitment"]),
        ],
    )


def flatten_batch_claim_input_witness(witness: Mapping[str, Any]) -> list[int]:
    batch_id = _felt(witness.get("batch_id", 901))
    values = [
        _felt(witness["batch_root_before"]),
        _felt(witness["expected_batch_root_after"]),
        _felt(witness["claim_source_root"]),
        _felt(witness["oracle_facts_root"]),
        _felt(witness["policy_root"]),
        _felt(witness["ruleset_root"]),
    ]
    values.extend(_serialize_fee_policy_witness(witness["fee_policy"]))
    policy_rows = list(witness["policy_rows"])
    values.append(len(policy_rows))
    for row in policy_rows:
        values.extend(_serialize_fee_row_witness(row))
    nullifier_transitions = list(witness["nullifier_transitions"])
    values.append(len(nullifier_transitions))
    for transition in nullifier_transitions:
        values.extend(_serialize_multi_line_nullifier_witness(transition))
    values.extend(
        [
        _felt(witness["expected_batch_commitment"]),
        _u128(witness["expected_total_allowed_cents"]),
        _u128(witness["expected_total_payment_cents"]),
        _u32(witness["expected_approved_count"]),
        _u32(witness["expected_denied_count"]),
        _u32(witness["expected_claim_count"]),
        ]
    )
    claims = list(witness["claims"])
    values.append(len(claims))
    for claim in claims:
        values.extend(
            flatten_multi_line_decision_input_witness(
                claim,
                batch_id=batch_id,
                include_root_parameters=False,
            )
        )
    return values


def _proofs_for_sorted_leaves(
    leaves: Sequence[int],
    depth: int,
    domain: str,
):
    from app.batch.merkle import PoseidonFieldMerkleTree

    tree = PoseidonFieldMerkleTree(sorted(leaves), depth, domain)
    indices_by_leaf: dict[str, list[int]] = {}
    for index, leaf in enumerate(tree.original_leaves):
        indices_by_leaf.setdefault(leaf, []).append(index)
    root = _hex_to_felt(tree.root)
    proofs = []
    for leaf in leaves:
        leaf_hex = f"{_felt(leaf):064x}"
        leaf_index = indices_by_leaf[leaf_hex].pop(0)
        proofs.append(tree.prove(leaf_index))
    return root, proofs


def _rewrite_multi_line_claim_source_tree(
    claims: Sequence[MultiLineServiceLineWitnessBundle],
    *,
    depth: int,
) -> tuple[list[MultiLineServiceLineWitnessBundle], int]:
    root, proofs = _proofs_for_sorted_leaves(
        [claim.claim.claim_source_leaf for claim in claims],
        depth,
        "claim_source",
    )
    rewritten: list[MultiLineServiceLineWitnessBundle] = []
    for claim, proof in zip(claims, proofs):
        rewritten_claim = replace(
            claim.claim,
            claim_source_root=root,
            claim_source_leaf_index=proof.leaf_index,
            claim_source_path_elements=tuple(_path_elements_from_hex(proof.siblings)),
            claim_source_path_indices=tuple(_path_indices(proof.leaf_index, len(proof.siblings))),
        )
        rewritten.append(replace(claim, claim=rewritten_claim))
    return rewritten, root


def _rewrite_multi_line_oracle_tree(
    claims: Sequence[MultiLineServiceLineWitnessBundle],
    *,
    depth: int,
) -> tuple[list[MultiLineServiceLineWitnessBundle], int]:
    leaves: list[int] = []
    claim_leaf_offsets: list[int] = []
    auth_positions: list[tuple[int, int]] = []
    auth_leaf_offsets: list[int] = []
    for claim_index, claim in enumerate(claims):
        leaves.append(claim.claim_facts_leaf)
        claim_leaf_offsets.append(len(leaves) - 1)
        for line_index, line in enumerate(claim.service_lines):
            if bool(line.tar_required):
                leaves.append(line.authorization.auth_leaf)
                auth_positions.append((claim_index, line_index))
                auth_leaf_offsets.append(len(leaves) - 1)
    root, proofs = _proofs_for_sorted_leaves(leaves, depth, "oracle")
    proof_by_claim_index: dict[int, Any] = {}
    for claim_index, proof_offset in enumerate(claim_leaf_offsets):
        proof_by_claim_index[claim_index] = proofs[proof_offset]
    proof_by_auth_position: dict[tuple[int, int], Any] = {}
    for position, proof_offset in zip(auth_positions, auth_leaf_offsets):
        proof_by_auth_position[position] = proofs[proof_offset]
    rewritten: list[MultiLineServiceLineWitnessBundle] = []
    for claim_index, claim in enumerate(claims):
        claim_proof = proof_by_claim_index[claim_index]
        service_lines: list[ServiceLineWitness] = []
        authorizations: list[AuthorizationLineWitness] = []
        for line_index, line in enumerate(claim.service_lines):
            if bool(line.tar_required):
                proof = proof_by_auth_position[(claim_index, line_index)]
                authorization = replace(
                    line.authorization,
                    auth_proof=proof,
                    auth_leaf_index=proof.leaf_index,
                    auth_path_elements=tuple(_path_elements_from_hex(proof.siblings)),
                    auth_path_indices=tuple(_path_indices(proof.leaf_index, len(proof.siblings))),
                )
                authorization_index = len(authorizations)
                authorizations.append(authorization)
            else:
                authorization = replace(
                    line.authorization,
                    auth_proof=_InactiveAuthProof(),
                    auth_leaf_index=0,
                    auth_path_elements=(),
                    auth_path_indices=(),
                )
                authorization_index = 0
            service_lines.append(replace(line, authorization=authorization, authorization_index=authorization_index))
        rewritten.append(
            replace(
                claim,
                oracle_facts_root=root,
                claim_facts_leaf_index=claim_proof.leaf_index,
                claim_facts_path_elements=tuple(_path_elements_from_hex(claim_proof.siblings)),
                claim_facts_path_indices=tuple(_path_indices(claim_proof.leaf_index, len(claim_proof.siblings))),
                service_lines=tuple(service_lines),
                authorizations=tuple(authorizations),
            )
        )
    return rewritten, root


def _rewrite_batch_policy_dictionaries(
    claims: Sequence[MultiLineServiceLineWitnessBundle],
) -> tuple[list[MultiLineServiceLineWitnessBundle], tuple[FeeRowWitness, ...]]:
    policy_rows: list[FeeRowWitness] = []
    policy_row_index_by_leaf_index: dict[int, int] = {}
    rewritten_claims: list[MultiLineServiceLineWitnessBundle] = []

    def authenticated_row_identity(row: FeeRowWitness) -> tuple[Any, ...]:
        return (
            _u32(row.row_kind),
            _felt(row.procedure_code_felt),
            _u128(row.allowed_cents),
            bool(row.requires_tar),
            _u128(row.policy_leaf_index),
            _felt(row.next_procedure_code_felt),
            _u128(row.next_policy_leaf_index),
            _felt(row.fee_leaf),
            tuple(_felt(item) for item in row.policy_path_elements),
            tuple(_u32(item) for item in row.policy_path_indices),
            str(row.fee_proof.root),
            str(row.fee_proof.leaf),
            _u128(row.fee_proof.leaf_index),
            tuple(str(item) for item in row.fee_proof.siblings),
        )

    for claim in claims:
        service_lines: list[ServiceLineWitness] = []
        for line in claim.service_lines:
            source_index = _u128(line.policy_row_index)
            if source_index >= len(claim.policy_rows):
                raise ValueError("batch_policy_dictionary_index_out_of_range")
            source_row = claim.policy_rows[source_index]
            physical_leaf_index = _u128(source_row.policy_leaf_index)
            policy_row_index = policy_row_index_by_leaf_index.get(physical_leaf_index)
            if policy_row_index is None:
                policy_row_index = len(policy_rows)
                policy_row_index_by_leaf_index[physical_leaf_index] = policy_row_index
                policy_rows.append(source_row)
            elif authenticated_row_identity(policy_rows[policy_row_index]) != authenticated_row_identity(source_row):
                raise ValueError("batch_policy_dictionary_leaf_conflict")

            service_lines.append(
                replace(
                    line,
                    policy_row_index=policy_row_index,
                )
            )
        rewritten_claims.append(
            replace(
                claim,
                service_lines=tuple(service_lines),
                policy_rows=tuple(policy_rows),
            )
        )

    global_policy_rows = tuple(policy_rows)
    rewritten_claims = [
        replace(claim, policy_rows=global_policy_rows)
        for claim in rewritten_claims
    ]
    return rewritten_claims, global_policy_rows


def build_monolithic_batch_input_witness(
    claim_items: Sequence[tuple[SharedContext, Any, str, str]],
    *,
    nullifier_tree: Any,
    config: Any | None = None,
    batch_id: str = "BL-MONOLITHIC-BATCH-1",
    signer_root: str | None = None,
) -> dict[str, Any]:
    from app.batch.batch_orchestrator import BatchConfig
    from app.batch.nullifier import IndexedNullifierTree
    from app.batch.oracle_facts_root import canonical_oracle_signer_root

    active_config = config or BatchConfig()
    if not claim_items:
        raise ValueError("monolithic_batch_requires_claims")
    if not isinstance(nullifier_tree, IndexedNullifierTree):
        raise ValueError("monolithic_live_nullifier_tree_required")
    working_nullifier_tree = nullifier_tree.clone()
    batch_root_before = working_nullifier_tree.root
    batch_id_felt = pack_felt_text(batch_id)
    claim_witnesses: list[MultiLineServiceLineWitnessBundle] = []
    approved_metadata: list[bool] = []
    active_signer_root = signer_root or canonical_oracle_signer_root()

    for ctx, result, evidence_root, engine_mode in claim_items:
        _ = engine_mode
        claim_witness = build_multi_line_service_line_witness(
            ctx,
            config=active_config,
            nullifier_tree=working_nullifier_tree,
            signer_root=active_signer_root,
            evidence_root=evidence_root,
        )
        decision, _failure_code = _multi_line_decision_and_failure_code(claim_witness)
        if bool(result.approved) != bool(decision):
            raise ValueError("batch_result_decision_mismatch")
        approved_metadata.append(bool(decision))
        working_nullifier_tree.insert(_inserted_nullifier_from_transition(claim_witness.nullifier))
        claim_witnesses.append(claim_witness)

    claim_witnesses, claim_source_root = _rewrite_multi_line_claim_source_tree(
        claim_witnesses,
        depth=active_config.merkle_depth,
    )
    claim_witnesses, oracle_facts_root = _rewrite_multi_line_oracle_tree(
        claim_witnesses,
        depth=active_config.merkle_depth,
    )
    claim_witnesses, batch_policy_rows = _rewrite_batch_policy_dictionaries(claim_witnesses)
    attempt_nullifier_transitions = tuple(witness.nullifier for witness in claim_witnesses)
    batch_commitment = 0
    total_allowed_cents = 0
    total_payment_cents = 0
    approved_count = 0
    denied_count = 0
    outputs: list[dict[str, int]] = []
    for witness, approved in zip(claim_witnesses, approved_metadata):
        output = claim_output_for_multi_line_witness(witness, batch_id=batch_id_felt)
        outputs.append(output)
        batch_commitment = domain_poseidon_hash(
            "batch",
            [
                batch_commitment,
                batch_output_leaf_for_claim_output(output, witness.claim.claim_id),
            ],
        )
        if approved:
            total_allowed_cents += output["allowed_cents"]
            total_payment_cents += output["payment_cents"]
            approved_count += 1
        else:
            denied_count += 1

    batch_witness = {
        "batch_id": batch_id_felt,
        "batch_root_before": batch_root_before,
        "expected_batch_root_after": working_nullifier_tree.root,
        "claim_source_root": claim_source_root,
        "oracle_facts_root": oracle_facts_root,
        "policy_root": _felt(claim_witnesses[0].policy_root),
        "ruleset_root": _felt(claim_witnesses[0].ruleset_root),
        "fee_policy": claim_witnesses[0].fee_policy,
        "policy_rows": batch_policy_rows,
        "nullifier_transitions": attempt_nullifier_transitions,
        "expected_batch_commitment": batch_commitment,
        "expected_total_allowed_cents": total_allowed_cents,
        "expected_total_payment_cents": total_payment_cents,
        "expected_approved_count": approved_count,
        "expected_denied_count": denied_count,
        "expected_claim_count": len(claim_witnesses),
        "claims": claim_witnesses,
    }
    bundle = {
        "entrypoint": "blind_ledger_cairo_adjudication::batch_main",
        "argument_format": "JSON sequence of 0x-prefixed strings for scarb execute --arguments-file; BatchClaimInput serializes header fields, claim count, then each MultiLineDecisionInput",
        "witness": batch_witness,
        "serialized_arguments": [str(value) for value in flatten_batch_claim_input_witness(batch_witness)],
        "serialized_arguments_comma": ",".join(str(value) for value in flatten_batch_claim_input_witness(batch_witness)),
        "serialized_arguments_hex_json": [hex(value) for value in flatten_batch_claim_input_witness(batch_witness)],
        "expected_output": {
            "batch_root_before": batch_root_before,
            "batch_root_after": working_nullifier_tree.root,
            "claim_source_root": batch_witness["claim_source_root"],
            "oracle_facts_root": batch_witness["oracle_facts_root"],
            "policy_root": batch_witness["policy_root"],
            "ruleset_root": batch_witness["ruleset_root"],
            "batch_commitment": batch_commitment,
            "total_allowed_cents": total_allowed_cents,
            "total_payment_cents": total_payment_cents,
            "approved_count": approved_count,
            "denied_count": denied_count,
            "claim_count": len(claim_witnesses),
        },
        "metadata": {
            "claim_count": len(claim_witnesses),
            "approved_count": approved_count,
            "denied_count": denied_count,
            "nullifier_rule": "every authenticated real claim inserts one governed attempt nullifier",
            "nullifier_depth": NULLIFIER_DEPTH,
        },
        "claim_outputs": outputs,
    }
    validate_monolithic_batch_input_witness(bundle)
    return bundle


def validate_monolithic_batch_input_witness(bundle: Mapping[str, Any]) -> bool:
    witness = bundle["witness"]
    claims = list(witness["claims"])
    if not claims:
        raise ValueError("batch_claims_empty")
    batch_id = _felt(witness.get("batch_id", 901))
    claim_source_root = _felt(witness["claim_source_root"])
    oracle_facts_root = _felt(witness["oracle_facts_root"])
    policy_root = _felt(witness["policy_root"])
    ruleset_root = _felt(witness["ruleset_root"])
    current_root = _felt(witness["batch_root_before"])
    batch_commitment = 0
    total_allowed_cents = 0
    total_payment_cents = 0
    approved_count = 0
    denied_count = 0
    transitions = list(witness["nullifier_transitions"])
    if len(transitions) != len(claims):
        raise ValueError("batch_attempt_transition_count_mismatch")
    for claim, transition in zip(claims, transitions):
        if transition != claim.nullifier:
            raise ValueError("batch_attempt_transition_claim_mismatch")
        if _felt(claim.claim.claim_source_root) != claim_source_root:
            raise ValueError("batch_claim_source_root_mismatch")
        if _felt(claim.oracle_facts_root) != oracle_facts_root:
            raise ValueError("batch_oracle_facts_root_mismatch")
        if _felt(claim.policy_root) != policy_root:
            raise ValueError("batch_policy_root_mismatch")
        if _felt(claim.ruleset_root) != ruleset_root:
            raise ValueError("batch_ruleset_root_mismatch")
        validate_multi_line_claim_witness(claim)
        output = claim_output_for_multi_line_witness(claim, batch_id=batch_id)
        if _felt(claim.nullifier.live_root_before) != current_root:
            raise ValueError("batch_nullifier_root_chain_mismatch")
        if _felt(output["nullifier_root_before"]) != current_root:
            raise ValueError("batch_attempt_output_root_before_mismatch")
        if _felt(output["nullifier_root_after"]) != _felt(claim.nullifier.root_after):
            raise ValueError("batch_attempt_output_root_after_mismatch")
        current_root = _felt(claim.nullifier.root_after)
        if output["decision"] == 1:
            total_allowed_cents += output["allowed_cents"]
            total_payment_cents += output["payment_cents"]
            approved_count += 1
        else:
            if output["payment_cents"] != 0:
                raise ValueError("denied_claim_has_payment")
            denied_count += 1
        batch_commitment = domain_poseidon_hash(
            "batch",
            [
                batch_commitment,
                batch_output_leaf_for_claim_output(output, claim.claim.claim_id),
            ],
        )
    if current_root != _felt(witness["expected_batch_root_after"]):
        raise ValueError("batch_expected_root_after_mismatch")
    if batch_commitment != _felt(witness["expected_batch_commitment"]):
        raise ValueError("batch_commitment_mismatch")
    if total_allowed_cents != _u128(witness["expected_total_allowed_cents"]):
        raise ValueError("batch_allowed_total_mismatch")
    if total_payment_cents != _u128(witness["expected_total_payment_cents"]):
        raise ValueError("batch_payment_total_mismatch")
    if approved_count != _u32(witness["expected_approved_count"]):
        raise ValueError("batch_approved_count_mismatch")
    if denied_count != _u32(witness["expected_denied_count"]):
        raise ValueError("batch_denied_count_mismatch")
    if len(claims) != _u32(witness["expected_claim_count"]):
        raise ValueError("batch_claim_count_mismatch")
    expected_serialized = [str(value) for value in flatten_batch_claim_input_witness(witness)]
    if list(bundle.get("serialized_arguments", [])) != expected_serialized:
        raise ValueError("batch_serialized_arguments_mismatch")
    return True


def verify_aggregation(witness: AggregationWitness) -> bool:
    if witness.onchain_running_balance_before is None or witness.onchain_running_balance_after is None:
        raise ValueError("running_balance_anchor_missing")
    running_before = _u128(witness.running_balance_before)
    running_after = _u128(witness.running_balance_after)
    onchain_before = _u128(witness.onchain_running_balance_before)
    onchain_after = _u128(witness.onchain_running_balance_after)
    if running_before != onchain_before:
        raise ValueError("running_balance_before_not_onchain")
    non_padding = [slot for slot in witness.slots if not slot.padding]
    if _u32(witness.claimed_count) != len(non_padding):
        raise ValueError("claimed_count_mismatch")
    seen_nullifiers: set[int] = set()
    approved_total = 0
    payment_total = 0
    for slot in witness.slots:
        if type(slot.padding) is not bool or type(slot.approved) is not bool:
            raise ValueError("batch_slot_boolean_invalid")
        allowed_cents = _amount_cents(slot.allowed_amount_cents)
        payment_cents = _amount_cents(slot.payment_amount_cents)
        if slot.padding:
            if slot.inserted_nullifier != 0 or allowed_cents != 0 or payment_cents != 0 or slot.claim_id:
                raise ValueError("padding_not_inert")
            continue
        _felt(slot.inserted_nullifier)
        if slot.inserted_nullifier in seen_nullifiers:
            raise ValueError("duplicate_inserted_nullifier")
        seen_nullifiers.add(slot.inserted_nullifier)
        if slot.approved:
            approved_total += allowed_cents
        elif payment_cents != 0:
            raise ValueError("denied_claim_has_payment")
        payment_total += payment_cents
    if payment_total > approved_total:
        raise ValueError("batch_value_conservation_violation")
    if running_after != running_before + approved_total - payment_total:
        raise ValueError("running_balance_mismatch")
    if running_after != onchain_after:
        raise ValueError("running_balance_after_not_onchain")
    return True
