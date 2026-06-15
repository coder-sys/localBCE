from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable, Mapping, Sequence

from app.batch.leaf import (
    build_claim_leaf_set,
    cents,
    combined_batch_commitment,
    payment_leaf,
    payment_payee_record,
    stable_private_hash,
)
from app.batch.merkle import MerkleTree
from app.models import AdjudicationResult, GateResult, SharedContext
from app.oracle_attestation import OracleAttestation, VERIFIED, _coerce_attestation, oracle_public_key_b64, verify_oracle_attestation
from app.provider_alias import provider_payment_alias
from app.rules_engine_fallback import PA_REQUIRED_PROCEDURES, denial_codes
from app.ingestion import parse_837
from app.shared_context import build_shared_context


BINDING_STATUS = (
    "EXECUTABLE PRODUCTION-BINDING CONSTRAINT HARNESS; not a compiled ZK circuit; "
    "soundness-checked by tests, PENDING CRYPTO AUDIT"
)
REQUIRED_ORACLE_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
)
EMPTY_ROOT = MerkleTree([], 10).root


@dataclass(frozen=True)
class FeeScheduleRow:
    procedure_code: str
    effective_from: str
    effective_until: str
    max_charge_cents: int
    source_id: str = "FEE_SCHEDULE_STUB_PENDING_POLICY"

    def leaf(self) -> str:
        return stable_private_hash(
            [
                "fee_schedule_row_v1",
                self.procedure_code,
                self.effective_from,
                self.effective_until,
                int(self.max_charge_cents),
                self.source_id,
            ]
        )


@dataclass(frozen=True)
class OracleRootBundle:
    eligibility_root: str
    provider_status_root: str
    prior_auth_root: str
    oracle_key_root: str
    all_oracle_facts_root: str
    fact_values: Mapping[str, bool]


@dataclass(frozen=True)
class ProductionBindingStatement:
    schema_version: str
    status: str
    batch_id: str
    claim_root: str
    result_root: str
    payment_root: str
    nullifier_root_before: str
    nullifier_root_after: str
    ruleset_root: str
    fee_schedule_root: str
    eligibility_root: str
    provider_status_root: str
    prior_auth_root: str
    oracle_key_root: str
    settlement_address_book_root: str
    verifier_key_id: str
    claim_count: int
    payment_count: int
    combined_batch_commitment: str


@dataclass(frozen=True)
class ProductionBindingWitness:
    raw_claim_digest: str
    claim_leaf: str
    result_leaf: str
    duplicate_nullifier: int
    payment_record: str
    payee_record: str
    recipient_address: str
    approved_result_commitment: str
    reconciliation_commitment: str
    oracle_fact_leaves: tuple[str, ...]
    fee_schedule_leaves: tuple[str, ...]


@dataclass(frozen=True)
class ProductionBindingBundle:
    statement: ProductionBindingStatement
    witness: ProductionBindingWitness
    ctx: SharedContext
    result: AdjudicationResult
    attestations: tuple[OracleAttestation, ...]
    fee_rows: tuple[FeeScheduleRow, ...]
    engine_mode: str


def oracle_fact_leaf(attestation: OracleAttestation) -> str:
    return stable_private_hash(["oracle_fact_leaf_v1", attestation.to_dict()])


def _root(leaves: Iterable[str]) -> str:
    return MerkleTree(sorted(leaves), 10).root


def _service_date(ctx: SharedContext):
    return datetime.strptime(ctx.service_date, "%Y%m%d").date()


def _oracle_group(fact: str) -> str:
    if fact == "eligibility_active":
        return "eligibility"
    if fact in {"provider_enrolled", "provider_not_suspended", "not_deceased"}:
        return "provider_status"
    if fact == "prior_authorization_valid":
        return "prior_auth"
    return "other"


def build_oracle_roots(attestations: Iterable[OracleAttestation | Mapping[str, object]], *, claim_id: str, service_date: str) -> OracleRootBundle:
    service_day = datetime.strptime(service_date, "%Y%m%d").date()
    coerced = tuple(_coerce_attestation(item) for item in attestations)
    leaves_by_group: dict[str, list[str]] = {"eligibility": [], "provider_status": [], "prior_auth": [], "other": []}
    fact_values: dict[str, bool] = {}
    for item in coerced:
        if not verify_oracle_attestation(item, claim_id=claim_id, now=service_day):
            raise ValueError(f"oracle_attestation_invalid:{item.fact or 'missing_fact'}")
        fact_values[item.fact] = item.value
        leaves_by_group.setdefault(_oracle_group(item.fact), []).append(oracle_fact_leaf(item))

    all_leaves = [leaf for group in leaves_by_group.values() for leaf in group]
    return OracleRootBundle(
        eligibility_root=_root(leaves_by_group["eligibility"]),
        provider_status_root=_root(leaves_by_group["provider_status"]),
        prior_auth_root=_root(leaves_by_group["prior_auth"]),
        oracle_key_root=stable_private_hash(["oracle_key_root_v1", oracle_public_key_b64()]),
        all_oracle_facts_root=_root(all_leaves),
        fact_values=fact_values,
    )


def fee_schedule_root(rows: Iterable[FeeScheduleRow]) -> str:
    return _root(row.leaf() for row in rows)


def _row_effective(row: FeeScheduleRow, service_date: str) -> bool:
    return row.effective_from <= service_date <= row.effective_until


def _fee_row_for(line_code: str, service_date: str, rows: Sequence[FeeScheduleRow]) -> FeeScheduleRow:
    matches = [row for row in rows if row.procedure_code == line_code and _row_effective(row, service_date)]
    if not matches:
        raise ValueError(f"fee_schedule_missing:{line_code}")
    if len(matches) > 1:
        raise ValueError(f"fee_schedule_ambiguous:{line_code}")
    return matches[0]


def _expected_gates_from_bound_facts(ctx: SharedContext, rows: Sequence[FeeScheduleRow], oracle_roots: OracleRootBundle) -> list[GateResult]:
    for fact in REQUIRED_ORACLE_FACTS:
        if ctx.fact_verification.get(fact) != VERIFIED:
            raise ValueError(f"oracle_fact_unverified:{fact}")
        if fact not in oracle_roots.fact_values:
            raise ValueError(f"oracle_fact_missing:{fact}")
        if bool(ctx.flags.get(fact, False)) != bool(oracle_roots.fact_values[fact]):
            raise ValueError(f"oracle_fact_mismatch:{fact}")

    prior_auth_needed = any(line.procedure_code in PA_REQUIRED_PROCEDURES for line in ctx.service_lines)
    if prior_auth_needed and oracle_roots.fact_values.get("prior_authorization_valid") is not True:
        raise ValueError("oracle_fact_missing:prior_authorization_valid")

    fee_rows = [_fee_row_for(line.procedure_code, ctx.service_date, rows) for line in ctx.service_lines]
    charge_valid = ctx.total_charge > 0 and all(line.charge_amount > 0 for line in ctx.service_lines)
    charge_within_allowable = all(cents(line.charge_amount) <= row.max_charge_cents for line, row in zip(ctx.service_lines, fee_rows))

    return [
        GateResult("G1_MEMBER_ID_PRESENT", bool(ctx.member_id), "" if ctx.member_id else "member_id_missing"),
        GateResult("G2_ELIGIBILITY_ACTIVE", bool(ctx.flags.get("eligibility_active", False)), "" if ctx.flags.get("eligibility_active", False) else "eligibility_inactive"),
        GateResult("G3_PROVIDER_NPI_PRESENT", bool(ctx.provider.npi), "" if ctx.provider.npi else "provider_npi_missing"),
        GateResult("G4_PROVIDER_ENROLLED", bool(ctx.flags.get("provider_enrolled", False)), "" if ctx.flags.get("provider_enrolled", False) else "provider_not_enrolled"),
        GateResult("G5_SERVICE_LINES_PRESENT", bool(ctx.service_lines), "" if ctx.service_lines else "service_line_missing"),
        GateResult("G6_DIAGNOSIS_PRESENT", bool(ctx.diagnoses), "" if ctx.diagnoses else "diagnosis_missing"),
        GateResult("G7_PRIOR_AUTH_WHEN_REQUIRED", not prior_auth_needed or oracle_roots.fact_values.get("prior_authorization_valid") is True, "" if not prior_auth_needed or oracle_roots.fact_values.get("prior_authorization_valid") is True else "prior_authorization_required"),
        GateResult("G8A_CHARGE_VALID", charge_valid, "" if charge_valid else "invalid_charge"),
        GateResult("G8B_CHARGE_WITHIN_ALLOWABLE", charge_within_allowable, "" if charge_within_allowable else "excessive_charge"),
        GateResult("G9_NOT_DUPLICATE", not ctx.flags.get("duplicate_claim", False), "" if not ctx.flags.get("duplicate_claim", False) else "duplicate_claim"),
        GateResult("G10_NO_PROGRAM_INTEGRITY_HOLD", not ctx.flags.get("program_integrity_hold", False), "" if not ctx.flags.get("program_integrity_hold", False) else "program_integrity_hold"),
    ]


def _assert_result_matches_bound_facts(ctx: SharedContext, result: AdjudicationResult, rows: Sequence[FeeScheduleRow], oracle_roots: OracleRootBundle) -> None:
    if result.claim_id != ctx.claim_id:
        raise ValueError("result_claim_id_mismatch")
    expected_gates = _expected_gates_from_bound_facts(ctx, rows, oracle_roots)
    if [asdict(gate) for gate in result.gates] != [asdict(gate) for gate in expected_gates]:
        raise ValueError("gate_vector_mismatch")
    first_failed = next((gate for gate in expected_gates if not gate.passed), None)
    expected_approved = first_failed is None
    expected_reason = "" if expected_approved else first_failed.reason
    expected_carc, expected_rarc = ("", "") if expected_approved else denial_codes(expected_reason)
    expected_payable = ctx.total_charge if expected_approved else 0.0
    if result.approved != expected_approved:
        raise ValueError("decision_mismatch")
    if result.denial_reason != expected_reason:
        raise ValueError("denial_reason_mismatch")
    if (result.carc, result.rarc) != (expected_carc, expected_rarc):
        raise ValueError("remittance_code_mismatch")
    if cents(result.payable_amount) != cents(expected_payable):
        raise ValueError("payable_amount_mismatch")


def _assert_service_total_bound(ctx: SharedContext) -> None:
    total = sum(cents(line.charge_amount) for line in ctx.service_lines)
    if total != cents(ctx.total_charge):
        raise ValueError("claim_total_mismatch")


def _assert_raw_claim_derives_context(raw_edi: str, ctx: SharedContext, attestations: Sequence[OracleAttestation]) -> None:
    parsed = parse_837(raw_edi)
    if not parsed.accepted:
        raise ValueError("raw_claim_rejected")
    derived = build_shared_context(parsed, {}, oracle_attestations=list(attestations), strict_oracle=True)
    expected = derived.to_dict()
    observed = ctx.to_dict()
    expected.pop("fact_verification", None)
    observed.pop("fact_verification", None)
    if expected != observed:
        raise ValueError("raw_claim_derivation_mismatch")


def _settlement_address_book_root(provider_key: str, recipient_address: str) -> str:
    return _root([stable_private_hash(["settlement_address_v1", provider_key, recipient_address.lower()])])


def build_production_binding(
    ctx: SharedContext,
    result: AdjudicationResult,
    attestations: Iterable[OracleAttestation | Mapping[str, object]],
    fee_rows: Iterable[FeeScheduleRow],
    *,
    raw_edi: str,
    batch_id: str,
    ruleset_root: str,
    nullifier_root_before: str,
    nullifier_root_after: str,
    recipient_address: str,
    verifier_key_id: str = "CAIRO_STARK_NATIVE_BINDING_V0",
    engine_mode: str = "rust_or_python_equivalent",
) -> ProductionBindingBundle:
    rows = tuple(fee_rows)
    oracle_items = tuple(_coerce_attestation(item) for item in attestations)
    oracle_roots = build_oracle_roots(oracle_items, claim_id=ctx.claim_id, service_date=ctx.service_date)
    _assert_raw_claim_derives_context(raw_edi, ctx, oracle_items)
    _assert_service_total_bound(ctx)
    _assert_result_matches_bound_facts(ctx, result, rows, oracle_roots)

    leaf_set = build_claim_leaf_set(ctx, result, ruleset_root, "original", engine_mode)
    claim_root = MerkleTree([leaf_set.claim_leaf], 10).root
    result_root = MerkleTree([leaf_set.result_leaf], 10).root
    provider_key = provider_payment_alias(ctx.provider.npi, ctx.provider.name)
    fee_root = fee_schedule_root(rows)
    address_book_root = _settlement_address_book_root(provider_key, recipient_address)

    payment_record = ""
    payee_record = ""
    approved_result_commitment = ""
    reconciliation_commitment = ""
    payment_root = EMPTY_ROOT
    payment_count = 0
    if result.approved:
        approved_result_commitment = stable_private_hash([leaf_set.result_leaf])
        reconciliation_commitment = stable_private_hash(
            {
                "provider_payment_key": provider_key,
                "approved_claim_count": 1,
                "expected_net_amount_cents": cents(result.payable_amount),
                "approved_result_records": [leaf_set.result_leaf],
            }
        )
        recipient_commitment = stable_private_hash(["PRODUCTION_SETTLEMENT", "recipient", provider_key, recipient_address.lower()])
        settlement_instruction = stable_private_hash(
            [
                batch_id,
                provider_key,
                recipient_commitment,
                cents(result.payable_amount),
                reconciliation_commitment,
                "PRODUCTION_SETTLEMENT",
                approved_result_commitment,
            ]
        )
        payment_record = payment_leaf(
            batch_id,
            provider_key,
            recipient_commitment,
            1,
            cents(result.payable_amount),
            reconciliation_commitment,
            "PRODUCTION_SETTLEMENT",
            settlement_instruction,
            approved_result_commitment,
        )
        payee_record = payment_payee_record(recipient_address, payment_record)
        payment_root = MerkleTree([payee_record], 10).root
        payment_count = 1
        if nullifier_root_after == nullifier_root_before:
            raise ValueError("approved_payment_requires_nullifier_advance")

    statement = ProductionBindingStatement(
        schema_version="production_binding_v0",
        status=BINDING_STATUS,
        batch_id=batch_id,
        claim_root=claim_root,
        result_root=result_root,
        payment_root=payment_root,
        nullifier_root_before=nullifier_root_before,
        nullifier_root_after=nullifier_root_after,
        ruleset_root=ruleset_root,
        fee_schedule_root=fee_root,
        eligibility_root=oracle_roots.eligibility_root,
        provider_status_root=oracle_roots.provider_status_root,
        prior_auth_root=oracle_roots.prior_auth_root,
        oracle_key_root=oracle_roots.oracle_key_root,
        settlement_address_book_root=address_book_root,
        verifier_key_id=verifier_key_id,
        claim_count=1,
        payment_count=payment_count,
        combined_batch_commitment="",
    )
    combined = combined_batch_commitment(
        batch_id,
        claim_root,
        result_root,
        payment_root,
        nullifier_root_before,
        nullifier_root_after,
        f"{leaf_set.duplicate_nullifier:064x}",
        ruleset_root,
        verifier_key_id,
        1,
        payment_count,
    )
    statement = ProductionBindingStatement(**{**asdict(statement), "combined_batch_commitment": combined})
    witness = ProductionBindingWitness(
        raw_claim_digest=stable_private_hash(["raw_837_v1", raw_edi]),
        claim_leaf=leaf_set.claim_leaf,
        result_leaf=leaf_set.result_leaf,
        duplicate_nullifier=leaf_set.duplicate_nullifier,
        payment_record=payment_record,
        payee_record=payee_record,
        recipient_address=recipient_address.lower(),
        approved_result_commitment=approved_result_commitment,
        reconciliation_commitment=reconciliation_commitment,
        oracle_fact_leaves=tuple(sorted(oracle_fact_leaf(item) for item in oracle_items)),
        fee_schedule_leaves=tuple(sorted(row.leaf() for row in rows)),
    )
    return ProductionBindingBundle(statement, witness, ctx, result, oracle_items, rows, engine_mode)


def verify_production_binding(bundle: ProductionBindingBundle, *, raw_edi: str) -> bool:
    expected = build_production_binding(
        bundle.ctx,
        bundle.result,
        bundle.attestations,
        bundle.fee_rows,
        raw_edi=raw_edi,
        batch_id=bundle.statement.batch_id,
        ruleset_root=bundle.statement.ruleset_root,
        nullifier_root_before=bundle.statement.nullifier_root_before,
        nullifier_root_after=bundle.statement.nullifier_root_after,
        recipient_address=bundle.witness.recipient_address,
        verifier_key_id=bundle.statement.verifier_key_id,
        engine_mode=bundle.engine_mode,
    )
    if asdict(bundle.statement) != asdict(expected.statement):
        raise ValueError("public_statement_mismatch")
    if asdict(bundle.witness) != asdict(expected.witness):
        raise ValueError("witness_mismatch")
    return True
