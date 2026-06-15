from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from app.batch.access_control import ADMIN, AccessDenied, RoleBook
from app.batch.leaf import (
    batch_nullifier_commitment,
    build_claim_leaf_set,
    combined_batch_commitment,
    current_duplicate_pepper,
    duplicate_check_key,
    duplicate_identity_key,
    duplicate_check_nullifier,
    payment_leaf,
    payment_payee_record,
    stable_private_hash,
)
from app.batch.merkle import InclusionProof, MerkleTree
from app.batch.nullifier import DuplicateNullifierError, IndexedNullifierTree, NullifierProofRunner
from app.batch.stubs import CPNAdapterStub, STUB_LABEL
from app.generator_835 import generate_835
from app.ingestion import parse_837
from app.models import AdjudicationResult, GateResult, SharedContext
from app.oracle_attestation import make_test_attestation
from app.production_readiness import assert_production_ready
from app.provider_alias import provider_payment_alias
from app.rules_engine_adapter import adjudicate as adapter_adjudicate
from app.shared_context import MAX_AMOUNT_CENTS, build_shared_context


ROOT = Path(__file__).resolve().parents[2]
RUST_BIN = ROOT / "rules-engine-rust" / "target" / "debug" / "rules-engine.exe"
POLICY_ARTIFACTS = (
    "rarc_mapping.tsv",
    "rules-engine-rust/src/lib.rs",
    "rules-engine-rust/src/main.rs",
    "app/rules_engine_fallback.py",
    "app/rules_engine_adapter.py",
)


@dataclass(frozen=True)
class BatchConfig:
    max_claims: int = 1024
    max_window_seconds: int = 3600
    merkle_depth: int = 10
    ruleset_version: str = "rarc_mapping_v1_pending_domain_ratification"
    ruleset_policy_content: str | None = None
    verifier_key_id: str = "RISC_ZERO_WRAPPED_STUB_V1"
    payment_rail: str = "CPN_MANAGED_PAYMENTS_STUB"
    provider_settlement_addresses: Dict[str, str] = field(default_factory=dict)
    enforce_nullifier_proofs: bool = True
    nullifier_proof_mode: str = "batch"
    strict_oracle_attestations: bool = True


@dataclass
class QuarantineItem:
    input_index: int
    claim_id: str
    reason: str
    errors: List[str] = field(default_factory=list)


@dataclass
class ClaimAuditPacket:
    claim_id: str
    batch_id: str
    claim_index: int
    decision: str
    denial_reason: str
    carc: str
    rarc: str
    payable_amount: float
    engine_mode: str
    claim_record: str
    adjudication_record: str
    claim_record_path: InclusionProof
    adjudication_record_path: InclusionProof
    remittance_835: str


@dataclass
class ProviderPayment:
    provider_payment_key: str
    recipient_address: str
    recipient_commitment: str
    approved_claim_count: int
    amount_cents: int
    reconciliation_commitment: str
    approved_result_commitment: str
    payment_record: str
    payee_record: str
    settlement: Dict[str, object]


@dataclass(frozen=True)
class PepperEpoch:
    version: str
    pepper: str


@dataclass
class SubmittedBatch:
    batch_id: str
    claim_count: int
    quarantine_count: int
    claim_batch_record: str
    adjudication_batch_record: str
    duplicate_check_before: str
    duplicate_check_after: str
    batch_nullifier_commitment: str
    combined_batch_commitment: str
    payment_batch_record: str
    payment_count: int
    ruleset_record: str
    verifier_key_id: str
    proof_status: str
    accepted_by_real_verifier: bool
    engine_modes: Dict[str, int]
    duplicate_check_keys: List[str]
    duplicate_identity_keys: List[str]
    duplicate_nullifiers: List[int]
    nullifier_proofs: List[Dict[str, object]]
    claim_packets: List[ClaimAuditPacket]
    payments: List[ProviderPayment]
    quarantined: List[QuarantineItem]


@dataclass
class PreparedClaim:
    ctx: SharedContext
    result: AdjudicationResult
    claim_record: str
    adjudication_record: str
    duplicate_record: str
    duplicate_check_key: str
    duplicate_identity_key: str
    duplicate_nullifier: int
    engine_mode: str


def _result_from_rust(data: Dict[str, object]) -> AdjudicationResult:
    return AdjudicationResult(
        claim_id=str(data["claim_id"]),
        approved=bool(data["approved"]),
        denial_reason=str(data.get("denial_reason", "")),
        gates=[GateResult(**gate) for gate in data.get("gates", [])],
        carc=str(data.get("carc", "")),
        rarc=str(data.get("rarc", "")),
        total_charge=float(data.get("total_charge", 0)),
        payable_amount=float(data.get("payable_amount", 0)),
    )


def adjudicate_for_batch(ctx: SharedContext) -> Tuple[AdjudicationResult, str]:
    """Use the existing Rust binary when present; otherwise fall back honestly."""
    if RUST_BIN.exists():
        proc = subprocess.run(
            [str(RUST_BIN), json.dumps(ctx.to_dict())],
            cwd=RUST_BIN.parent.parent,
            text=True,
            capture_output=True,
            check=True,
        )
        return _result_from_rust(json.loads(proc.stdout)), "rust_binary"
    return adapter_adjudicate(ctx), "adapter_fallback"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ruleset_policy_record(ruleset_version: str, policy_content: str | None = None) -> str:
    if policy_content is None:
        policy_bundle = {
            "ruleset_version": ruleset_version,
            "artifacts": {artifact: _file_sha256(ROOT / artifact) for artifact in POLICY_ARTIFACTS},
        }
    else:
        policy_bundle = {
            "ruleset_version": ruleset_version,
            "inline_policy_content": policy_content,
        }
    return stable_private_hash(policy_bundle)


class BatchAuthority:
    """Authoritative app-side mirror for root/ruleset admission.

    The batch contract remains the chain source of truth. This object mirrors the
    same atomic transition locally so two builders cannot both commit batches
    against the same root before submission.
    """

    def __init__(
        self,
        approved_ruleset_versions: Iterable[str] | None = None,
        *,
        pepper_version: str = "pepper_v1",
        duplicate_pepper: str | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self.records: Dict[str, SubmittedBatch] = {}
        self.seen_duplicate_check_keys: set[str] = set()
        self.seen_duplicate_identity_keys: set[str] = set()
        self.nullifier_tree = IndexedNullifierTree()
        versions = [BatchConfig().ruleset_version] if approved_ruleset_versions is None else list(approved_ruleset_versions)
        self.approved_ruleset_records: set[str] = {ruleset_policy_record(version) for version in versions}
        self.current_pepper_version = pepper_version
        self.pepper_versions: Dict[str, str] = {pepper_version: duplicate_pepper or current_duplicate_pepper()}
        self.overlap_pepper_versions: set[str] = set()
        self.pepper_rotation_log: List[Dict[str, object]] = []

    def set_ruleset_approved(
        self,
        ruleset_version: str,
        approved: bool,
        *,
        actor: str,
        access: RoleBook,
        policy_content: str | None = None,
    ) -> None:
        if not access.has(ADMIN, actor):
            raise AccessDenied("account lacks ruleset admin role")
        record = ruleset_policy_record(ruleset_version, policy_content)
        if approved:
            self.approved_ruleset_records.add(record)
        else:
            self.approved_ruleset_records.discard(record)

    def require_ruleset_approved(self, ruleset_record: str) -> None:
        if ruleset_record not in self.approved_ruleset_records:
            raise ValueError("ruleset not approved")

    def active_pepper_epochs(self) -> List[PepperEpoch]:
        versions = [self.current_pepper_version, *sorted(self.overlap_pepper_versions)]
        seen: set[str] = set()
        out: List[PepperEpoch] = []
        for version in versions:
            if version in seen:
                continue
            seen.add(version)
            out.append(PepperEpoch(version, self.pepper_versions[version]))
        return out

    def rotate_duplicate_pepper(
        self,
        new_version: str,
        new_pepper: str,
        *,
        actor: str,
        access: RoleBook,
        overlap_versions: Iterable[str] | None = None,
    ) -> None:
        if not access.has(ADMIN, actor):
            raise AccessDenied("account lacks pepper rotation admin role")
        if not new_version or new_version in self.pepper_versions:
            raise ValueError("pepper version must be new and non-empty")
        previous = self.current_pepper_version
        requested_overlap = set(overlap_versions or [])
        requested_overlap.add(previous)
        missing = requested_overlap.difference(self.pepper_versions)
        if missing:
            raise ValueError(f"unknown overlap pepper versions: {sorted(missing)}")
        self.pepper_versions[new_version] = new_pepper
        self.current_pepper_version = new_version
        self.overlap_pepper_versions = requested_overlap
        self.pepper_rotation_log.append(
            {
                "from": previous,
                "to": new_version,
                "overlap_versions": sorted(requested_overlap),
                "actor": actor,
            }
        )

    def snapshot(self) -> Tuple[IndexedNullifierTree, str]:
        with self._lock:
            tree = self.nullifier_tree.clone()
            return tree, tree.root_hex

    def commit_batch(self, batch: SubmittedBatch, next_tree: IndexedNullifierTree) -> None:
        with self._lock:
            self.require_ruleset_approved(batch.ruleset_record)
            current_root = self.nullifier_tree.root_hex
            if batch.duplicate_check_before != current_root:
                raise ValueError("stale nullifier root")
            self._record_locked(batch, next_tree)

    def _record_locked(self, batch: SubmittedBatch, next_tree: IndexedNullifierTree) -> None:
        if batch.batch_id in self.records:
            raise ValueError("batch already submitted")
        repeated = self.seen_duplicate_check_keys.intersection(batch.duplicate_check_keys)
        if repeated:
            raise ValueError("duplicate check key already recorded")
        repeated_identity = self.seen_duplicate_identity_keys.intersection(batch.duplicate_identity_keys)
        if repeated_identity:
            raise ValueError("duplicate identity key already recorded")
        repeated_nullifiers = [value for value in batch.duplicate_nullifiers if self.nullifier_tree.contains(value)]
        if repeated_nullifiers:
            raise ValueError("nullifier already recorded")
        self.records[batch.batch_id] = batch
        self.seen_duplicate_check_keys.update(batch.duplicate_check_keys)
        self.seen_duplicate_identity_keys.update(batch.duplicate_identity_keys)
        self.nullifier_tree = next_tree


class LocalBatchRecorder:
    """Local recorder for tests/demo only; the real recorder is the batch contract."""

    def __init__(self, authority: BatchAuthority | None = None, approved_ruleset_versions: Iterable[str] | None = None) -> None:
        self.authority = authority or BatchAuthority(approved_ruleset_versions)

    @property
    def records(self) -> Dict[str, SubmittedBatch]:
        return self.authority.records

    @property
    def seen_duplicate_check_keys(self) -> set[str]:
        return self.authority.seen_duplicate_check_keys

    @property
    def seen_duplicate_identity_keys(self) -> set[str]:
        return self.authority.seen_duplicate_identity_keys

    @property
    def nullifier_tree(self) -> IndexedNullifierTree:
        return self.authority.nullifier_tree

    def record(self, batch: SubmittedBatch, next_tree: IndexedNullifierTree | None = None) -> None:
        tree = next_tree or self.authority.nullifier_tree.clone()
        if next_tree is None:
            for value in batch.duplicate_nullifiers:
                tree.insert(value)
        self.authority.commit_batch(batch, tree)


def _chunks(items: List[Dict[str, object]], size: int) -> Iterable[Tuple[int, List[Dict[str, object]]]]:
    for start in range(0, len(items), size):
        yield start, items[start : start + size]


def _quarantine_record(item: QuarantineItem) -> str:
    return stable_private_hash(asdict(item))


def _batch_id(start_index: int, claim_records: List[str], adjudication_records: List[str], quarantine_records: List[str]) -> str:
    return stable_private_hash(
        {
            "start_index": start_index,
            "claim_records": claim_records,
            "adjudication_records": adjudication_records,
            "quarantine_records": quarantine_records,
        }
    )


def _empty_tree_record(depth: int) -> str:
    return MerkleTree([], depth).root


def _provider_key(ctx: SharedContext) -> str:
    return provider_payment_alias(ctx.provider.npi, ctx.provider.name)


def _validate_evm_address(address: str) -> str:
    clean = address[2:] if address.startswith("0x") else address
    if len(clean) != 40:
        raise ValueError("expected 20-byte EVM address")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ValueError("expected hex EVM address") from exc
    return "0x" + clean.lower()


def _stub_recipient_address(provider_key: str) -> str:
    return "0x" + stable_private_hash(["stub_settlement_recipient", provider_key])[-40:]


def _recipient_address(provider_key: str, config: BatchConfig) -> str:
    address = config.provider_settlement_addresses.get(provider_key)
    if address:
        return _validate_evm_address(address)
    if config.payment_rail.endswith("_STUB"):
        return _stub_recipient_address(provider_key)
    raise ValueError(f"missing settlement recipient address:{provider_key}")


def _payment_reconciliation_commitment(provider_key: str, approved_count: int, expected_cents: int, result_records: List[str]) -> str:
    return stable_private_hash(
        {
            "provider_payment_key": provider_key,
            "approved_claim_count": approved_count,
            "expected_net_amount_cents": expected_cents,
            "approved_result_records": result_records,
        }
    )


def _enforce_payment_reconciliation(provider_key: str, approved_amounts_cents: List[int], proposed_amount_cents: int) -> int:
    if proposed_amount_cents < 0 or proposed_amount_cents > MAX_AMOUNT_CENTS:
        raise ValueError(f"payment_amount_out_of_range:{provider_key}:{proposed_amount_cents}")
    for amount in approved_amounts_cents:
        if amount < 0 or amount > MAX_AMOUNT_CENTS:
            raise ValueError(f"approved_amount_out_of_range:{provider_key}:{amount}")
    expected = sum(approved_amounts_cents)
    if expected > MAX_AMOUNT_CENTS:
        raise ValueError(f"payment_amount_out_of_range:{provider_key}:{expected}")
    if proposed_amount_cents != expected:
        raise ValueError(f"payment_reconciliation_mismatch:{provider_key}:{proposed_amount_cents}!={expected}")
    return expected


def _validate_batch_config(config: BatchConfig) -> None:
    if config.max_claims <= 0:
        raise ValueError("max_claims must be positive")
    if config.merkle_depth <= 0:
        raise ValueError("merkle_depth must be positive")
    if config.max_claims > 2**config.merkle_depth:
        raise ValueError("max_claims exceeds merkle capacity")


def _claim_id_from_parsed(parsed) -> str:
    for segment in parsed.segments:
        if segment and segment[0] == "CLM" and len(segment) > 1:
            return str(segment[1])
    return "UNKNOWN"


def _dev_attestations_for_payload(parsed, flags: Dict[str, object]) -> List[object]:
    if os.environ.get("BL_DEV") != "1" or os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        return []
    claim_id = _claim_id_from_parsed(parsed)
    facts = {
        "eligibility_active": flags.get("eligibility_active", False),
        "provider_enrolled": flags.get("provider_enrolled", False),
        "provider_not_suspended": flags.get("provider_not_suspended", False),
        "not_deceased": flags.get("not_deceased", False),
    }
    return [
        make_test_attestation(fact, bool(value), source_id=f"DEV-{fact.upper()}", claim_id=claim_id)
        for fact, value in facts.items()
    ]


def _missing_real_batch_proof_status(claim_count: int, approved_nullifier_count: int) -> Dict[str, object]:
    return {
        "mode": "multi_claim_batch_circuit_required",
        "accepted": False,
        "claim_count": claim_count,
        "approved_nullifier_count": approved_nullifier_count,
        "reason": "no real multi-claim batch proof supplied by live prover; fail closed",
        "circuit": "zk/batch_multiclaim/batch_nullifier_nonmembership.circom",
        "label": "PENDING CRYPTO AUDIT",
    }


def submit_batches(
    payloads: List[Dict[str, object]],
    *,
    actor: str,
    access: RoleBook,
    config: BatchConfig | None = None,
    recorder: LocalBatchRecorder | None = None,
) -> List[SubmittedBatch]:
    assert_production_ready()
    config = config or BatchConfig()
    _validate_batch_config(config)
    access.require_batch_submitter(actor)
    recorder = recorder or LocalBatchRecorder()
    ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
    recorder.authority.require_ruleset_approved(ruleset_record)
    submitted: List[SubmittedBatch] = []

    for start_index, chunk in _chunks(payloads, config.max_claims):
        base_tree, duplicate_record_before = recorder.authority.snapshot()
        pepper_epochs = recorder.authority.active_pepper_epochs()
        submitted_batch, next_tree = _submit_single_batch(
            start_index,
            chunk,
            config,
            duplicate_record_before,
            base_tree,
            pepper_epochs,
            recorder.authority.seen_duplicate_identity_keys,
        )
        if submitted_batch.claim_count > 0:
            recorder.record(submitted_batch, next_tree)
        submitted.append(submitted_batch)
    return submitted


def _submit_single_batch(
    start_index: int,
    payloads: List[Dict[str, object]],
    config: BatchConfig,
    duplicate_check_before: str,
    base_nullifier_tree: IndexedNullifierTree,
    pepper_epochs: Iterable[PepperEpoch] | None = None,
    seen_duplicate_identity_keys: Iterable[str] | None = None,
) -> Tuple[SubmittedBatch, IndexedNullifierTree]:
    parsed_claims: List[PreparedClaim] = []
    quarantined: List[QuarantineItem] = []
    engine_modes: Dict[str, int] = {}
    working_nullifier_tree = base_nullifier_tree.clone()
    nullifier_proofs: List[Dict[str, object]] = []
    proof_mode = "none" if not config.enforce_nullifier_proofs else config.nullifier_proof_mode
    if proof_mode not in {"none", "batch", "per_claim"}:
        raise ValueError("invalid nullifier proof mode")
    proof_runner = NullifierProofRunner() if proof_mode in {"batch", "per_claim"} else None
    batch_witnesses = []
    active_peppers = list(pepper_epochs or [PepperEpoch("env", current_duplicate_pepper())])
    current_pepper = active_peppers[0]
    working_identity_keys = set(seen_duplicate_identity_keys or [])

    for offset, payload in enumerate(payloads):
        input_index = start_index + offset
        parsed = parse_837(str(payload.get("edi", "")))
        if not parsed.accepted:
            quarantined.append(QuarantineItem(input_index, str(payload.get("claim_id", f"input_{input_index}")), "ingestion_failed", parsed.errors))
            continue
        try:
            ctx = build_shared_context(
                parsed,
                payload.get("flags", {}),
                oracle_attestations=payload.get("oracle_attestations") or _dev_attestations_for_payload(parsed, payload.get("flags", {})),
                strict_oracle=config.strict_oracle_attestations,
            )
            result, engine_mode = adjudicate_for_batch(ctx)
            engine_modes[engine_mode] = engine_modes.get(engine_mode, 0) + 1
            frequency_type = str(payload.get("frequency_type", "original")).lower()
            if frequency_type != "original":
                quarantined.append(
                    QuarantineItem(
                        input_index,
                        ctx.claim_id,
                        "frequency_type_pending_domain_review",
                        ["replacement_void_duplicate_semantics_require_domain_review"],
                    )
                )
                continue
            if result.approved:
                identity_key = duplicate_identity_key(ctx, frequency_type)
                if identity_key in working_identity_keys:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "duplicate_identity_key_already_recorded", [identity_key]))
                    continue
                candidates = [
                    (
                        epoch,
                        duplicate_check_key(ctx, frequency_type, epoch.pepper),
                        duplicate_check_nullifier(ctx, frequency_type, epoch.pepper),
                    )
                    for epoch in active_peppers
                ]
                duplicate_hits = [f"{epoch.version}:{nullifier}" for epoch, _, nullifier in candidates if working_nullifier_tree.contains(nullifier)]
                if duplicate_hits:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "nullifier_nonmembership_duplicate", duplicate_hits))
                    continue
                duplicate_nullifier = candidates[0][2]
                try:
                    witness = working_nullifier_tree.prove_nonmembership(duplicate_nullifier)
                    if proof_runner is not None and proof_mode == "per_claim":
                        proof = proof_runner.prove_and_verify(witness, f"{ctx.claim_id}-{duplicate_nullifier}")
                        if not proof.accepted:
                            quarantined.append(QuarantineItem(input_index, ctx.claim_id, "nullifier_nonmembership_proof_rejected", []))
                            continue
                        nullifier_proofs.append(asdict(proof))
                    elif proof_mode == "batch":
                        batch_witnesses.append((ctx.claim_id, witness))
                    working_nullifier_tree.insert(duplicate_nullifier)
                    working_identity_keys.add(identity_key)
                except DuplicateNullifierError as exc:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "nullifier_nonmembership_duplicate", [str(exc)]))
                    continue
                except Exception as exc:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "nullifier_nonmembership_proof_failed", [str(exc)]))
                    continue
            ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
            identity_key = duplicate_identity_key(ctx, frequency_type)
            leaf_set = build_claim_leaf_set(ctx, result, ruleset_record, frequency_type, engine_mode, current_pepper.pepper)
            parsed_claims.append(
                PreparedClaim(
                    ctx=ctx,
                    result=result,
                    claim_record=leaf_set.claim_leaf,
                    adjudication_record=leaf_set.result_leaf,
                    duplicate_record=leaf_set.duplicate_leaf,
                    duplicate_check_key=leaf_set.duplicate_check_key,
                    duplicate_identity_key=identity_key if result.approved else "",
                    duplicate_nullifier=leaf_set.duplicate_nullifier,
                    engine_mode=engine_mode,
                )
            )
        except Exception as exc:
            claim_id = parsed.segments[0][1] if parsed.segments and len(parsed.segments[0]) > 1 else f"input_{input_index}"
            quarantined.append(QuarantineItem(input_index, claim_id, "adjudication_failed", [str(exc)]))

    claim_records = [item.claim_record for item in parsed_claims]
    adjudication_records = [item.adjudication_record for item in parsed_claims]
    duplicate_records = [item.duplicate_record for item in parsed_claims]
    claim_tree = MerkleTree(claim_records, config.merkle_depth)
    adjudication_tree = MerkleTree(adjudication_records, config.merkle_depth)
    duplicate_tree = MerkleTree(duplicate_records, config.merkle_depth)
    duplicate_check_after = working_nullifier_tree.root_hex
    quarantine_records = [_quarantine_record(item) for item in quarantined]
    batch_id = _batch_id(start_index, claim_records, adjudication_records, quarantine_records)

    if proof_runner is not None and proof_mode == "batch" and batch_witnesses:
        nullifier_proofs.append(_missing_real_batch_proof_status(len(parsed_claims), len(batch_witnesses)))

    provider_totals: Dict[str, Tuple[int, List[int], List[str]]] = {}
    for item in parsed_claims:
        if not item.result.approved:
            continue
        provider_key = _provider_key(item.ctx)
        count, amounts, result_records = provider_totals.get(provider_key, (0, [], []))
        provider_totals[provider_key] = (
            count + 1,
            [*amounts, int(round(item.result.payable_amount * 100))],
            [*result_records, item.adjudication_record],
        )

    cpn = CPNAdapterStub()
    payments: List[ProviderPayment] = []
    for provider_key, (approved_count, amounts_cents, result_records) in sorted(provider_totals.items()):
        amount_cents = _enforce_payment_reconciliation(provider_key, amounts_cents, sum(amounts_cents))
        recipient_address = _recipient_address(provider_key, config)
        recipient_commitment = stable_private_hash([config.payment_rail, "recipient", provider_key])
        approved_result_commitment = stable_private_hash(result_records)
        reconciliation_commitment = _payment_reconciliation_commitment(provider_key, approved_count, amount_cents, result_records)
        settlement_instruction = stable_private_hash(
            [
                batch_id,
                provider_key,
                recipient_commitment,
                amount_cents,
                reconciliation_commitment,
                config.payment_rail,
                approved_result_commitment,
            ]
        )
        record = payment_leaf(
            batch_id,
            provider_key,
            recipient_commitment,
            approved_count,
            amount_cents,
            reconciliation_commitment,
            config.payment_rail,
            settlement_instruction,
            approved_result_commitment,
        )
        payee_record = payment_payee_record(recipient_address, record)
        settlement = {"status": "not_submitted_real_verifier_rejected", "reason": STUB_LABEL}
        payments.append(
            ProviderPayment(
                provider_key,
                recipient_address,
                recipient_commitment,
                approved_count,
                amount_cents,
                reconciliation_commitment,
                approved_result_commitment,
                record,
                payee_record,
                settlement,
            )
        )
    payment_tree = MerkleTree([payment.payee_record for payment in payments], config.merkle_depth)
    claim_count = len(parsed_claims)
    ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
    batch_nullifier_record = batch_nullifier_commitment([item.duplicate_nullifier for item in parsed_claims if item.result.approved])
    combined_record = combined_batch_commitment(
        batch_id,
        claim_tree.root,
        adjudication_tree.root,
        payment_tree.root,
        duplicate_check_before,
        duplicate_check_after,
        batch_nullifier_record,
        ruleset_record,
        config.verifier_key_id,
        claim_count,
        len(payments),
    )

    public_inputs = [
        claim_tree.root,
        adjudication_tree.root,
        payment_tree.root,
        duplicate_check_before,
        duplicate_check_after,
        batch_nullifier_record,
        ruleset_record,
        combined_record,
        config.verifier_key_id,
        str(claim_count),
        str(len(payments)),
    ]
    accepted = False
    proof_status = STUB_LABEL
    if accepted:
        payments = [
            ProviderPayment(
                payment.provider_payment_key,
                payment.recipient_address,
                payment.recipient_commitment,
                payment.approved_claim_count,
                payment.amount_cents,
                payment.reconciliation_commitment,
                payment.approved_result_commitment,
                payment.payment_record,
                payment.payee_record,
                cpn.submit_provider_payment(batch_id, payment.provider_payment_key, payment.amount_cents),
            )
            for payment in payments
        ]

    packets: List[ClaimAuditPacket] = []
    for index, item in enumerate(parsed_claims):
        packets.append(
            ClaimAuditPacket(
                claim_id=item.ctx.claim_id,
                batch_id=batch_id,
                claim_index=index,
                decision="approved" if item.result.approved else "denied",
                denial_reason=item.result.denial_reason,
                carc=item.result.carc,
                rarc=item.result.rarc,
                payable_amount=item.result.payable_amount,
                engine_mode=item.engine_mode,
                claim_record=item.claim_record,
                adjudication_record=item.adjudication_record,
                claim_record_path=claim_tree.prove(index),
                adjudication_record_path=adjudication_tree.prove(index),
                remittance_835=generate_835(item.ctx, item.result),
            )
        )

    batch = SubmittedBatch(
        batch_id=batch_id,
        claim_count=claim_count,
        quarantine_count=len(quarantined),
        claim_batch_record=claim_tree.root,
        adjudication_batch_record=adjudication_tree.root,
        duplicate_check_before=duplicate_check_before,
        duplicate_check_after=duplicate_check_after,
        batch_nullifier_commitment=batch_nullifier_record,
        combined_batch_commitment=combined_record,
        payment_batch_record=payment_tree.root,
        payment_count=len(payments),
        ruleset_record=ruleset_record,
        verifier_key_id=config.verifier_key_id,
        proof_status=proof_status,
        accepted_by_real_verifier=accepted,
        engine_modes=engine_modes,
        duplicate_check_keys=[item.duplicate_check_key for item in parsed_claims if item.result.approved],
        duplicate_identity_keys=[item.duplicate_identity_key for item in parsed_claims if item.result.approved],
        duplicate_nullifiers=[item.duplicate_nullifier for item in parsed_claims if item.result.approved],
        nullifier_proofs=nullifier_proofs,
        claim_packets=packets,
        payments=payments,
        quarantined=quarantined,
    )
    return batch, working_nullifier_tree


def batch_to_plain_dict(batch: SubmittedBatch) -> Dict[str, object]:
    out = asdict(batch)
    out["proof_status"] = STUB_LABEL
    return out
