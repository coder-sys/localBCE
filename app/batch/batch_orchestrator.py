from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import warnings
from copy import deepcopy
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Iterable, List, Tuple

from app.batch.accumulators import BenefitAccumulator, apply_benefit_claim, preview_benefit_claim
from app.batch.access_control import ADMIN, AccessDenied, RoleBook
from app.batch.attempt import (
    SYNTHETIC_SOURCE_AUTHORITY_ID,
    GovernedClaimAttempt,
    legacy_attempt_nullifier,
    synthetic_original_attempt,
)
from app.batch.claim_source_root import claim_source_leaf_hex, claim_source_root_hex
from app.batch.encrypted_da import (
    encrypt_claim_data_for_stark,
    encrypted_claim_data_root as encrypted_payload_root,
    serialize_encrypted_claim_data,
)
from app.batch.oracle_facts_root import (
    canonical_oracle_claim_leaves,
    canonical_oracle_signer_root,
    oracle_facts_root_hex,
)
from app.batch.leaf import (
    batch_nullifier_commitment,
    build_claim_leaf_set,
    combined_batch_commitment,
    current_duplicate_pepper,
    duplicate_identity_key,
    payment_leaf,
    payment_payee_record,
    stable_duplicate_identity_key,
    stable_private_hash,
)
from app.batch.merkle import InclusionProof, MerkleTree, PoseidonMerkleTree
from app.batch.nullifier import DuplicateNullifierError, IndexedNullifierTree
from app.batch.proof_status import REAL_PROOF_REQUIRED_STATUS
from app.batch.ruleset_root import ruleset_policy_digest_hex
from app.batch.stark_binding import normalized_fact_commitment_for
from app.batch.stark_encoding import canonical_day_count, pack_felt_text
from app.batch.poseidon import domain_poseidon_hash
from app.batch.tar_required import is_tar_required, load_default_tar_required_codes
from app.batch.verifier_receipt import (
    PRODUCTION_VERIFICATION_KIND,
    SYNTHETIC_TEST_VERIFICATION_KIND,
    VerificationRequest,
    VerifiedBatchReceipt,
    VerifierAdapter,
    VerifierReceiptIssuer,
    canonical_public_inputs_v2,
)
from app.fact_resolver import resolve_claim_facts
from app.generator_835 import generate_835
from app.ingestion import parse_837
from app.models import AdjudicationResult, GateResult, SharedContext
from app.money import MAX_AMOUNT_CENTS_EXCLUSIVE
from app.oracle_attestation import make_test_attestation
from app.production_readiness import assert_production_ready
from app.provider_alias import provider_payment_alias
from app.public_inputs import build_native_stark_public_inputs
from app.rules_engine_adapter import (
    adjudicate as adapter_adjudicate,
    canonical_rules_engine_context_payload,
    canonical_rules_engine_policy_payload,
)
from app.rules_engine_fallback import DEFAULT_FEE_SCHEDULE_CENTS, allowed_amount_cents
from app.service_line_canonical import cents
from app.shared_context import MAX_AMOUNT_CENTS, build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[2]
RUST_BIN = ROOT / "rules-engine-rust" / "target" / "debug" / "rules-engine.exe"
LOCAL_RULES_ENGINE_FALLBACK_ENV = "BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK"
LOCAL_ENFORCEMENT_DISABLE_ENV = "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE"
_LOCAL_RULES_ENGINE_ENVS = {"", "local", "test", "unit", "ci"}
_LOCAL_ENFORCEMENT_DISABLE_ENVS = {"", "local", "test", "unit", "ci"}
_TEST_ONLY_UNVERIFIED_SETTLEMENT_ENVS = {"local", "test"}
DIRTY_CLAIM_PREFILTER_REASON = "dirty_claim_prefilter_rejected"
FEE_POLICY_SCHEMA_TAG = 2
FEE_SOURCE_UNBOUND = 0
POLICY_ROW_SCHEMA_TAG = 2
POLICY_ROW_KIND_LOWER_SENTINEL = 0
POLICY_ROW_KIND_REAL = 1
POLICY_ROW_KIND_UPPER_SENTINEL = 2
POLICY_LOWER_SENTINEL_KEY = 0
POLICY_UPPER_SENTINEL_KEY = (1 << 128) - 1
POLICY_MAX_CENTS = MAX_AMOUNT_CENTS_EXCLUSIVE
MAX_CLAIMS_PER_SUBMISSION = 1024
POLICY_ARTIFACTS = (
    # The first element is the immutable v1 commitment label, not a path.
    # Retaining it prevents a packaging-layout migration from changing every
    # existing ruleset identity; bytes resolve only from the second element.
    ("../ops/policy_spec_v1.yaml", "ops/policy_spec_v1.yaml"),
    ("rarc_mapping.tsv", "rarc_mapping.tsv"),
    ("rules-engine-rust/src/lib.rs", "rules-engine-rust/src/lib.rs"),
    ("rules-engine-rust/src/main.rs", "rules-engine-rust/src/main.rs"),
    ("app/rules_engine_fallback.py", "app/rules_engine_fallback.py"),
    ("app/rules_engine_adapter.py", "app/rules_engine_adapter.py"),
)


def _local_rules_engine_fallback_allowed() -> bool:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    return environment in _LOCAL_RULES_ENGINE_ENVS and os.environ.get(LOCAL_RULES_ENGINE_FALLBACK_ENV) == "1"


def _local_enforcement_disable_allowed() -> bool:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    return (
        environment in _LOCAL_ENFORCEMENT_DISABLE_ENVS
        and os.environ.get("BL_DEV") == "1"
        and os.environ.get(LOCAL_ENFORCEMENT_DISABLE_ENV) == "1"
    )


def _test_only_unverified_settlement_allowed() -> bool:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    return (
        environment in _TEST_ONLY_UNVERIFIED_SETTLEMENT_ENVS
        and os.environ.get("BL_DEV") == "1"
        and os.environ.get(LOCAL_ENFORCEMENT_DISABLE_ENV) == "1"
    )


def _require_test_only_unverified_settlement() -> None:
    if not _test_only_unverified_settlement_allowed():
        raise RuntimeError(
            "test_only_unverified_settlement_forbidden:requires_local_test_env_and_explicit_dev_flags"
        )


def _require_local_rules_engine_fallback(reason: str, exc: Exception | None = None) -> None:
    if _local_rules_engine_fallback_allowed():
        warnings.warn(
            f"LOCAL DEV ONLY RULES ENGINE FALLBACK ACTIVE: {reason}",
            RuntimeWarning,
            stacklevel=3,
        )
        return
    if exc is None:
        raise RuntimeError(f"rules_engine_unavailable_fail_closed:{reason}")
    raise RuntimeError(f"rules_engine_unavailable_fail_closed:{reason}") from exc


@dataclass(frozen=True)
class BatchConfig:
    max_claims: int = 1024
    max_window_seconds: int = 3600
    merkle_depth: int = 10
    ruleset_version: str = "rarc_mapping_v1_pending_domain_ratification"
    ruleset_policy_content: str | None = None
    verifier_key_id: str = "NATIVE_STARK_SETTLEMENT_V1"
    payment_rail: str = "CPN_MANAGED_PAYMENTS_PENDING"
    provider_settlement_addresses: Dict[str, str] = field(default_factory=dict)
    fee_schedule_cents: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_FEE_SCHEDULE_CENTS))
    tar_required_procedure_codes: Tuple[str, ...] = field(default_factory=load_default_tar_required_codes)
    annual_benefit_cap_cents: int = MAX_AMOUNT_CENTS
    deductible_cents: int = 0
    visit_limit: int | None = None
    enforce_nullifier_proofs: bool = True
    nullifier_proof_mode: str = "native_stark"
    strict_oracle_attestations: bool = True
    encrypted_claim_data_mode: str = "legacy_commitment"
    audit_data_key_id: str = "audit-key-local-dev"
    audit_data_key_epoch: str = "local-dev-epoch-1"
    claim_source_authority_id: str = SYNTHETIC_SOURCE_AUTHORITY_ID


@dataclass(frozen=True)
class PolicyTreeRow:
    row_kind: int
    procedure_code: str
    procedure_code_felt: int
    allowed_cents: int
    requires_tar: bool
    policy_leaf_index: int
    next_procedure_code_felt: int
    next_policy_leaf_index: int


def _canonical_governed_procedure_code(value: object) -> bool:
    return (
        isinstance(value, str)
        and 2 <= len(value) <= 10
        and all("A" <= character <= "Z" or "0" <= character <= "9" for character in value)
    )


def _validated_tar_required_codes(config: BatchConfig) -> tuple[str, ...]:
    codes = tuple(config.tar_required_procedure_codes)
    if not codes:
        raise ValueError("tar_required_procedure_codes invalid")
    if any(not _canonical_governed_procedure_code(code) for code in codes):
        raise ValueError("tar_required_procedure_codes invalid")
    if len(set(codes)) != len(codes):
        raise ValueError("tar_required_procedure_codes duplicate")
    return codes


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
    total_charge_cents: int
    payable_amount: float
    engine_mode: str
    claim_record: str
    adjudication_record: str
    claim_record_path: InclusionProof
    adjudication_record_path: InclusionProof
    remittance_835: str
    evidence_root: str = ""
    evidence_packet: Dict[str, object] = field(default_factory=dict)


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
    claim_source_root: str
    oracle_facts_root: str
    oracle_signer_root: str
    policy_root: str
    address_book_root: str
    data_availability_root: str
    encrypted_claim_data_root: str
    denial_attestation_root: str
    forced_inclusion_root: str
    value_conservation_commitment: str
    accumulator_root_before: str
    accumulator_root_after: str
    approved_amount_cents: int
    payment_amount_cents: int
    public_inputs: List[str]
    verifier_key_id: str
    proof_status: str
    engine_modes: Dict[str, int]
    duplicate_check_keys: List[str]
    duplicate_identity_keys: List[str]
    attempt_nullifiers: List[int]
    nullifier_proofs: List[Dict[str, object]]
    claim_packets: List[ClaimAuditPacket]
    payments: List[ProviderPayment]
    quarantined: List[QuarantineItem]
    stable_duplicate_identity_keys: List[str] = field(default_factory=list, repr=False)
    encrypted_claim_payload: bytes = field(default=b"", repr=False)
    nullifier_epoch_mode: str = "legacy_rotating"
    nullifier_pepper_version: str = ""
    verifier_receipt: VerifiedBatchReceipt | None = field(default=None, repr=False)

    @property
    def accepted_by_real_verifier(self) -> bool:
        # No production verifier is registered in this repository. Keep this
        # compatibility view fail-closed even for a caller-constructed receipt.
        return False

    @property
    def duplicate_nullifiers(self) -> List[int]:
        """Deprecated compatibility alias for pre-attempt-nullifier test callers."""

        return self.attempt_nullifiers


@dataclass
class PreparedClaim:
    ctx: SharedContext
    result: AdjudicationResult
    claim_record: str
    claim_source_leaf: str
    oracle_facts_leaves: Tuple[str, ...]
    adjudication_record: str
    duplicate_record: str
    duplicate_check_key: str
    duplicate_identity_key: str
    stable_duplicate_identity_key: str
    duplicate_nullifier: int
    attempt: GovernedClaimAttempt
    attempt_nullifier: int
    raw_claim_digest: str
    engine_mode: str
    evidence_root: str
    evidence_packet: Dict[str, object]
    raw_edi: str
    source_flags: Dict[str, object]


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


def adjudicate_for_batch(ctx: SharedContext, config: BatchConfig | None = None) -> Tuple[AdjudicationResult, str]:
    """Use the existing Rust binary, failing closed unless local fallback is explicit."""
    if config is not None:
        _validate_batch_config(config)
    tar_required_codes = config.tar_required_procedure_codes if config is not None else None
    fee_schedule_cents = config.fee_schedule_cents if config is not None else None
    tar_required_codes, fee_schedule_cents = canonical_rules_engine_policy_payload(
        tar_required_codes,
        fee_schedule_cents,
    )
    if os.environ.get("BL_FORCE_PYTHON_RULES_ENGINE") == "1":
        _require_local_rules_engine_fallback("forced_python_rules_engine")
        return adapter_adjudicate(ctx, tar_required_codes, fee_schedule_cents), "adapter_fallback"
    if RUST_BIN.exists():
        context_payload = canonical_rules_engine_context_payload(ctx)
        request = context_payload
        if tar_required_codes is not None or fee_schedule_cents is not None:
            request = {
                "context": context_payload,
                "tar_required_procedure_codes": tar_required_codes,
                "fee_schedule_cents": fee_schedule_cents,
            }
        try:
            proc = subprocess.run(
                [str(RUST_BIN), json.dumps(request)],
                cwd=RUST_BIN.parent.parent,
                text=True,
                capture_output=True,
                check=True,
            )
            return _result_from_rust(json.loads(proc.stdout)), "rust_binary"
        except Exception as exc:
            _require_local_rules_engine_fallback("batch_rust_binary_failed", exc)
            return adapter_adjudicate(ctx, tar_required_codes, fee_schedule_cents), "adapter_fallback"
    _require_local_rules_engine_fallback("batch_rust_binary_missing")
    return adapter_adjudicate(ctx, tar_required_codes, fee_schedule_cents), "adapter_fallback"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ruleset_policy_record(ruleset_version: str, policy_content: str | None = None) -> str:
    if policy_content is None:
        return ruleset_policy_digest_hex(
            ruleset_version,
            artifacts={
                label: _file_sha256(ROOT / path)
                for label, path in POLICY_ARTIFACTS
            },
        )
    return ruleset_policy_digest_hex(ruleset_version, policy_content=policy_content)


def _benefit_year(ctx: SharedContext) -> int:
    return int(str(ctx.service_date)[:4])


def _accumulator_key(ctx: SharedContext) -> str:
    return f"{ctx.member_id}:{_benefit_year(ctx)}"


def _accumulator_root(states: Mapping[str, BenefitAccumulator]) -> str:
    return stable_private_hash(
        {
            "schema": "benefit_accumulator_root_v1",
            "members": [[key, states[key].root()] for key in sorted(states)],
        }
    )


def _initial_accumulator(ctx: SharedContext, config: BatchConfig) -> BenefitAccumulator:
    return BenefitAccumulator(
        member_id=ctx.member_id,
        benefit_year=_benefit_year(ctx),
        annual_cap_cents=config.annual_benefit_cap_cents,
        deductible_remaining_cents=config.deductible_cents,
        visit_limit=config.visit_limit,
    )


def _first_prior_authorization(ctx: SharedContext) -> str | None:
    for line in ctx.service_lines:
        if line.prior_authorization:
            return line.prior_authorization
    return None


def _legacy_policy_row_leaf_v1(
    procedure_code: str,
    allowed_cents: int,
    requires_tar: bool,
    effective_from: str = "1970-01-01",
    effective_until: str = "9999-12-31",
) -> int:
    return domain_poseidon_hash(
        "fee",
        [
            1,
            pack_felt_text(procedure_code),
            int(allowed_cents),
            int(bool(requires_tar)),
            canonical_day_count(effective_from),
            canonical_day_count(effective_until),
        ],
    )


def indexed_policy_row_leaf(
    *,
    row_kind: int,
    procedure_code_felt: int,
    allowed_cents: int,
    requires_tar: bool,
    next_procedure_code_felt: int,
    next_policy_leaf_index: int,
    policy_leaf_index: int,
) -> int:
    row_kind = int(row_kind)
    procedure_code_felt = int(procedure_code_felt)
    allowed_cents = int(allowed_cents)
    next_procedure_code_felt = int(next_procedure_code_felt)
    next_policy_leaf_index = int(next_policy_leaf_index)
    policy_leaf_index = int(policy_leaf_index)
    if row_kind not in {
        POLICY_ROW_KIND_LOWER_SENTINEL,
        POLICY_ROW_KIND_REAL,
        POLICY_ROW_KIND_UPPER_SENTINEL,
    }:
        raise ValueError("policy_row_kind_invalid")
    if policy_leaf_index < 1 or next_policy_leaf_index < 1:
        raise ValueError("policy_row_index_invalid")
    if allowed_cents < 0 or allowed_cents >= POLICY_MAX_CENTS:
        raise ValueError("policy_row_allowed_cents_out_of_range")
    if row_kind == POLICY_ROW_KIND_LOWER_SENTINEL:
        if procedure_code_felt != POLICY_LOWER_SENTINEL_KEY or allowed_cents != 0 or requires_tar:
            raise ValueError("policy_lower_sentinel_invalid")
    elif row_kind == POLICY_ROW_KIND_UPPER_SENTINEL:
        if (
            procedure_code_felt != POLICY_UPPER_SENTINEL_KEY
            or next_procedure_code_felt != POLICY_UPPER_SENTINEL_KEY
            or next_policy_leaf_index != policy_leaf_index
            or allowed_cents != 0
            or requires_tar
        ):
            raise ValueError("policy_upper_sentinel_invalid")
    elif procedure_code_felt <= POLICY_LOWER_SENTINEL_KEY or procedure_code_felt >= POLICY_UPPER_SENTINEL_KEY:
        raise ValueError("policy_row_procedure_key_out_of_range")
    if row_kind != POLICY_ROW_KIND_UPPER_SENTINEL:
        if not procedure_code_felt < next_procedure_code_felt:
            raise ValueError("policy_row_successor_order_invalid")
        if next_policy_leaf_index != policy_leaf_index + 1:
            raise ValueError("policy_row_successor_index_invalid")
    return domain_poseidon_hash(
        "fee",
        [
            POLICY_ROW_SCHEMA_TAG,
            row_kind,
            procedure_code_felt,
            allowed_cents,
            int(bool(requires_tar)),
            next_procedure_code_felt,
            next_policy_leaf_index,
            policy_leaf_index,
            canonical_day_count("1970-01-01"),
            canonical_day_count("9999-12-31"),
        ],
    )


def policy_tree_rows(config: BatchConfig) -> List[PolicyTreeRow]:
    tar_required_codes = _validated_tar_required_codes(config)
    real_rows: List[tuple[int, str, int, bool]] = []
    seen_keys: set[int] = set()
    for procedure_code, amount in config.fee_schedule_cents.items():
        if not _canonical_governed_procedure_code(procedure_code):
            raise ValueError("policy_row_procedure_code_not_canonical")
        key = pack_felt_text(procedure_code)
        if key in seen_keys:
            raise ValueError("policy_row_procedure_key_duplicate")
        seen_keys.add(key)
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("policy_row_allowed_cents_not_integer")
        allowed_cents = amount
        if allowed_cents < 0 or allowed_cents >= POLICY_MAX_CENTS:
            raise ValueError("policy_row_allowed_cents_out_of_range")
        real_rows.append(
            (
                key,
                procedure_code,
                allowed_cents,
                is_tar_required(procedure_code, tar_required_codes),
            )
        )
    real_rows.sort(key=lambda row: row[0])
    raw_rows: List[tuple[int, str, int, int, bool]] = [
        (POLICY_ROW_KIND_LOWER_SENTINEL, "", POLICY_LOWER_SENTINEL_KEY, 0, False),
        *(
            (POLICY_ROW_KIND_REAL, procedure_code, key, allowed_cents, requires_tar)
            for key, procedure_code, allowed_cents, requires_tar in real_rows
        ),
        (POLICY_ROW_KIND_UPPER_SENTINEL, "", POLICY_UPPER_SENTINEL_KEY, 0, False),
    ]
    rows: List[PolicyTreeRow] = []
    for offset, (row_kind, procedure_code, key, allowed_cents, requires_tar) in enumerate(raw_rows):
        policy_leaf_index = offset + 1
        if offset + 1 < len(raw_rows):
            next_key = raw_rows[offset + 1][2]
            next_index = policy_leaf_index + 1
        else:
            next_key = POLICY_UPPER_SENTINEL_KEY
            next_index = policy_leaf_index
        rows.append(
            PolicyTreeRow(
                row_kind=row_kind,
                procedure_code=procedure_code,
                procedure_code_felt=key,
                allowed_cents=allowed_cents,
                requires_tar=requires_tar,
                policy_leaf_index=policy_leaf_index,
                next_procedure_code_felt=next_key,
                next_policy_leaf_index=next_index,
            )
        )
    return rows


def fee_row_leaf(
    procedure_code: str,
    allowed_cents: int,
    effective_from: str = "1970-01-01",
    effective_until: str = "9999-12-31",
) -> int:
    return _legacy_policy_row_leaf_v1(procedure_code, allowed_cents, False, effective_from, effective_until)


def fee_policy_leaf(
    ruleset_root: str | int,
    fee_source_commitment: int = FEE_SOURCE_UNBOUND,
    *,
    tree_depth: int,
    real_row_count: int,
) -> int:
    # Per-procedure fee values are placeholders until an authoritative fee-schedule artifact is bound.
    return domain_poseidon_hash(
        "fee",
        [
            FEE_POLICY_SCHEMA_TAG,
            int(fee_source_commitment),
            int(str(ruleset_root), 16) if isinstance(ruleset_root, str) else int(ruleset_root),
            int(tree_depth),
            int(real_row_count),
        ],
    )


def fee_schedule_leaves(config: BatchConfig, ruleset_root: str | int) -> List[int]:
    leaves = [
        fee_policy_leaf(
            ruleset_root,
            tree_depth=config.merkle_depth,
            real_row_count=len(config.fee_schedule_cents),
        )
    ]
    leaves.extend(
        indexed_policy_row_leaf(
            row_kind=row.row_kind,
            procedure_code_felt=row.procedure_code_felt,
            allowed_cents=row.allowed_cents,
            requires_tar=row.requires_tar,
            next_procedure_code_felt=row.next_procedure_code_felt,
            next_policy_leaf_index=row.next_policy_leaf_index,
            policy_leaf_index=row.policy_leaf_index,
        )
        for row in policy_tree_rows(config)
    )
    return leaves


def policy_root_hex(config: BatchConfig, ruleset_root: str | int) -> str:
    from app.batch.merkle import PoseidonFieldMerkleTree

    return PoseidonFieldMerkleTree(fee_schedule_leaves(config, ruleset_root), config.merkle_depth, "fee").root


def _apply_allowed_amount_and_accumulator(
    ctx: SharedContext,
    result: AdjudicationResult,
    config: BatchConfig,
    working_accumulators: Mapping[str, BenefitAccumulator],
) -> tuple[AdjudicationResult, str | None, BenefitAccumulator | None]:
    if not result.approved:
        return result, None, None
    allowed_cents = allowed_amount_cents(ctx, config.fee_schedule_cents)
    key = _accumulator_key(ctx)
    current = working_accumulators.get(key, _initial_accumulator(ctx, config))
    expected_next, _ = preview_benefit_claim(
        current,
        allowed_cents=allowed_cents,
        visit_count=len(ctx.service_lines),
        prior_authorization=_first_prior_authorization(ctx),
    )
    updated, payable_cents = apply_benefit_claim(
        current,
        allowed_cents=allowed_cents,
        visit_count=len(ctx.service_lines),
        prior_authorization=_first_prior_authorization(ctx),
        onchain_accumulator_root_before=current.root(),
        onchain_accumulator_root_after=expected_next.root(),
    )
    return replace(result, payable_amount=payable_cents / 100), key, updated


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
        nullifier_epoch_mode: str = "stable_global",
        global_nullifier_pepper: str | None = None,
        allow_test_only_unverified_settlement: bool = False,
        verifier_adapter: VerifierAdapter | None = None,
    ) -> None:
        if allow_test_only_unverified_settlement:
            _require_test_only_unverified_settlement()
        if nullifier_epoch_mode != "stable_global":
            raise ValueError("legacy rotating nullifiers forbidden by attempt-nullifier schema")
        resolved_duplicate_pepper = duplicate_pepper or current_duplicate_pepper()
        resolved_global_nullifier_pepper = global_nullifier_pepper or resolved_duplicate_pepper
        if not resolved_global_nullifier_pepper:
            raise ValueError("global_nullifier_pepper required")
        self._lock = threading.RLock()
        self._records: Dict[str, SubmittedBatch] = {}
        self._seen_duplicate_check_keys: set[str] = set()
        self._seen_duplicate_identity_keys: set[str] = set()
        self._seen_stable_duplicate_identity_keys: set[str] = set()
        self._nullifier_tree = IndexedNullifierTree()
        self._accumulator_states: Dict[str, BenefitAccumulator] = {}
        self._accumulator_root = _accumulator_root(self._accumulator_states)
        versions = [BatchConfig().ruleset_version] if approved_ruleset_versions is None else list(approved_ruleset_versions)
        self._approved_ruleset_records: set[str] = {ruleset_policy_record(version) for version in versions}
        self._current_pepper_version = pepper_version
        self._pepper_versions: Dict[str, str] = {pepper_version: resolved_duplicate_pepper}
        self._nullifier_epoch_mode = nullifier_epoch_mode
        self._global_nullifier_pepper = resolved_global_nullifier_pepper
        self._allow_test_only_unverified_settlement = bool(allow_test_only_unverified_settlement)
        self._overlap_pepper_versions: set[str] = set()
        self._pepper_rotation_log: List[Dict[str, object]] = []
        self._verifier_receipts = VerifierReceiptIssuer(verifier_adapter)
        descriptor = self._verifier_receipts.adapter_descriptor
        if (
            descriptor is not None
            and descriptor.verification_kind == SYNTHETIC_TEST_VERIFICATION_KIND
            and not self._allow_test_only_unverified_settlement
        ):
            raise ValueError("synthetic verifier adapter requires test-only settlement mode")

    @property
    def records(self) -> Mapping[str, SubmittedBatch]:
        with self._lock:
            return MappingProxyType({batch_id: deepcopy(batch) for batch_id, batch in self._records.items()})

    @property
    def seen_duplicate_check_keys(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._seen_duplicate_check_keys)

    @property
    def seen_duplicate_identity_keys(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._seen_duplicate_identity_keys)

    @property
    def seen_stable_duplicate_identity_keys(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._seen_stable_duplicate_identity_keys)

    @property
    def nullifier_tree(self) -> IndexedNullifierTree:
        with self._lock:
            return self._nullifier_tree.clone()

    @property
    def accumulator_states(self) -> Mapping[str, BenefitAccumulator]:
        with self._lock:
            return MappingProxyType(dict(self._accumulator_states))

    @property
    def accumulator_root(self) -> str:
        with self._lock:
            return self._accumulator_root

    @property
    def approved_ruleset_records(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._approved_ruleset_records)

    @property
    def current_pepper_version(self) -> str:
        with self._lock:
            return self._current_pepper_version

    @property
    def pepper_versions(self) -> Mapping[str, str]:
        with self._lock:
            return MappingProxyType(dict(self._pepper_versions))

    @property
    def nullifier_epoch_mode(self) -> str:
        with self._lock:
            return self._nullifier_epoch_mode

    @property
    def global_nullifier_pepper(self) -> str:
        with self._lock:
            return self._global_nullifier_pepper

    @property
    def overlap_pepper_versions(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._overlap_pepper_versions)

    @property
    def pepper_rotation_log(self) -> tuple[Dict[str, object], ...]:
        with self._lock:
            return tuple(deepcopy(self._pepper_rotation_log))

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
        with self._lock:
            if approved:
                self._approved_ruleset_records.add(record)
            else:
                self._approved_ruleset_records.discard(record)

    def require_ruleset_approved(self, ruleset_record: str) -> None:
        with self._lock:
            if ruleset_record not in self._approved_ruleset_records:
                raise ValueError("ruleset not approved")

    def active_pepper_epochs(self) -> List[PepperEpoch]:
        with self._lock:
            current_version = self._current_pepper_version
            overlap_versions = tuple(sorted(self._overlap_pepper_versions))
            pepper_versions = dict(self._pepper_versions)
        versions = [current_version, *overlap_versions]
        seen: set[str] = set()
        out: List[PepperEpoch] = []
        for version in versions:
            if version in seen:
                continue
            seen.add(version)
            out.append(PepperEpoch(version, pepper_versions[version]))
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
        requested_overlap = set(overlap_versions or [])
        with self._lock:
            if not new_version or new_version in self._pepper_versions:
                raise ValueError("pepper version must be new and non-empty")
            previous = self._current_pepper_version
            requested_overlap.add(previous)
            missing = requested_overlap.difference(self._pepper_versions)
            if missing:
                raise ValueError(f"unknown overlap pepper versions: {sorted(missing)}")
            self._pepper_versions[new_version] = new_pepper
            self._current_pepper_version = new_version
            self._overlap_pepper_versions = requested_overlap
            self._pepper_rotation_log.append(
                {
                    "from": previous,
                    "to": new_version,
                    "overlap_versions": sorted(requested_overlap),
                    "actor": actor,
                }
            )

    def snapshot(self) -> Tuple[IndexedNullifierTree, str, Dict[str, BenefitAccumulator], str]:
        with self._lock:
            tree = self._nullifier_tree.clone()
            return tree, tree.root_hex, dict(self._accumulator_states), self._accumulator_root

    @property
    def test_only_unverified_settlement_enabled(self) -> bool:
        if not self._allow_test_only_unverified_settlement:
            return False
        _require_test_only_unverified_settlement()
        return True

    def test_only_reset_duplicate_caches(self) -> None:
        if not self.test_only_unverified_settlement_enabled:
            raise RuntimeError("test-only duplicate-cache reset forbidden")
        with self._lock:
            self._seen_duplicate_check_keys.clear()
            self._seen_duplicate_identity_keys.clear()
            self._seen_stable_duplicate_identity_keys.clear()

    def verify_and_attach_receipt(
        self,
        batch: SubmittedBatch,
        *,
        public_inputs_v2: Iterable[str],
        proof: bytes | bytearray | memoryview,
    ) -> SubmittedBatch:
        if batch.verifier_receipt is not None:
            raise ValueError("batch already has verifier receipt")
        request = VerificationRequest.create(
            batch_id=batch.batch_id,
            verifier_key_id=batch.verifier_key_id,
            public_inputs=tuple(public_inputs_v2),
            proof=proof,
        )
        receipt = self._verifier_receipts.issue(request)
        authenticated_batch = replace(
            batch,
            public_inputs=list(receipt.public_inputs),
            verifier_receipt=receipt,
        )
        self._validate_verifier_receipt_bindings(authenticated_batch, receipt)
        return authenticated_batch

    def _validate_verifier_receipt_bindings(
        self,
        batch: SubmittedBatch,
        receipt: VerifiedBatchReceipt,
    ) -> None:
        self._verifier_receipts.validate(receipt)
        if receipt.verification_kind == PRODUCTION_VERIFICATION_KIND:
            raise ValueError("production verifier settlement unavailable: incomplete Privacy V2 transition binding")
        descriptor = self._verifier_receipts.adapter_descriptor
        if descriptor is None:
            raise ValueError("verifier receipt adapter unavailable")
        descriptor_bindings = (
            (receipt.verifier_key_id, descriptor.verifier_key_id, "key"),
            (receipt.profile_id, descriptor.profile_id, "profile"),
            (receipt.public_input_schema, descriptor.public_input_schema, "schema"),
            (
                receipt.verifier_artifact_digest_sha3_512,
                descriptor.verifier_artifact_digest_sha3_512,
                "artifact",
            ),
            (receipt.verification_kind, descriptor.verification_kind, "kind"),
        )
        for supplied, expected, name in descriptor_bindings:
            if supplied != expected:
                raise ValueError(f"verifier receipt configured {name} mismatch")
        if receipt.batch_id != batch.batch_id:
            raise ValueError("verifier receipt batch identity mismatch")
        if receipt.verifier_key_id != batch.verifier_key_id:
            raise ValueError("verifier receipt key mismatch")
        batch_public_inputs = canonical_public_inputs_v2(batch.public_inputs)
        if batch_public_inputs != receipt.public_inputs:
            raise ValueError("verifier receipt public inputs mismatch")
        expected_fields = {
            3: batch.duplicate_check_before,
            4: batch.duplicate_check_after,
            5: batch.claim_source_root,
            6: batch.oracle_facts_root,
            7: batch.policy_root,
            8: batch.ruleset_record,
        }
        for index, expected in expected_fields.items():
            if receipt.public_inputs[index] != expected:
                raise ValueError(f"verifier receipt batch field mismatch:{index}")

    def commit_batch(
        self,
        batch: SubmittedBatch,
        next_tree: IndexedNullifierTree,
        next_accumulator_states: Mapping[str, BenefitAccumulator] | None = None,
    ) -> None:
        with self._lock:
            batch = deepcopy(batch)
            test_only_unverified_settlement = self.test_only_unverified_settlement_enabled
            if batch.verifier_receipt is None:
                if not test_only_unverified_settlement:
                    raise ValueError("verifier-authenticated receipt required")
            else:
                self._validate_verifier_receipt_bindings(batch, batch.verifier_receipt)
                if (
                    batch.verifier_receipt.verification_kind == SYNTHETIC_TEST_VERIFICATION_KIND
                    and not test_only_unverified_settlement
                ):
                    raise ValueError("synthetic verifier receipt forbidden outside test-only settlement mode")
            self.require_ruleset_approved(batch.ruleset_record)
            current_root = self._nullifier_tree.root_hex
            if batch.duplicate_check_before != current_root:
                raise ValueError("stale nullifier root")
            if batch.accumulator_root_before != self._accumulator_root:
                raise ValueError("stale accumulator root")
            attempt_nullifiers = list(batch.attempt_nullifiers)
            if any(isinstance(value, bool) or not isinstance(value, int) for value in attempt_nullifiers):
                raise ValueError("attempt nullifiers must be canonical integers")
            if not attempt_nullifiers:
                raise ValueError("empty nullifier transition forbidden")
            if len(attempt_nullifiers) != len(set(attempt_nullifiers)):
                raise ValueError("duplicate attempt nullifier within batch")
            expected_next_tree = self._nullifier_tree.clone()
            for value in attempt_nullifiers:
                expected_next_tree.insert(value)
            expected_next_root = expected_next_tree.root_hex
            if expected_next_root == current_root:
                raise ValueError("no-op nullifier transition forbidden")
            if not isinstance(next_tree, IndexedNullifierTree) or next_tree.root_hex != expected_next_root:
                raise ValueError("next nullifier tree root mismatch")
            if batch.duplicate_check_after != expected_next_root:
                raise ValueError("batch nullifier root after mismatch")
            next_states = dict(self._accumulator_states if next_accumulator_states is None else next_accumulator_states)
            if _accumulator_root(next_states) != batch.accumulator_root_after:
                raise ValueError("accumulator root after mismatch")
            self._record_locked(batch, expected_next_tree, next_states)

    def _record_locked(
        self,
        batch: SubmittedBatch,
        next_tree: IndexedNullifierTree,
        next_accumulator_states: Dict[str, BenefitAccumulator],
    ) -> None:
        if batch.batch_id in self._records:
            raise ValueError("batch already submitted")
        repeated = self._seen_duplicate_check_keys.intersection(batch.duplicate_check_keys)
        if repeated:
            raise ValueError("duplicate check key already recorded")
        repeated_identity = self._seen_duplicate_identity_keys.intersection(batch.duplicate_identity_keys)
        if repeated_identity:
            raise ValueError("duplicate identity key already recorded")
        repeated_stable_identity = self._seen_stable_duplicate_identity_keys.intersection(batch.stable_duplicate_identity_keys)
        if repeated_stable_identity:
            raise ValueError("stable duplicate identity already recorded")
        repeated_nullifiers = [value for value in batch.attempt_nullifiers if self._nullifier_tree.contains(value)]
        if repeated_nullifiers:
            raise ValueError("nullifier already recorded")
        self._records[batch.batch_id] = deepcopy(batch)
        self._seen_duplicate_check_keys.update(batch.duplicate_check_keys)
        self._seen_duplicate_identity_keys.update(batch.duplicate_identity_keys)
        self._seen_stable_duplicate_identity_keys.update(batch.stable_duplicate_identity_keys)
        self._nullifier_tree = next_tree.clone()
        self._accumulator_states = dict(next_accumulator_states)
        self._accumulator_root = _accumulator_root(self._accumulator_states)


class LocalBatchRecorder:
    """Local recorder for tests and review runs; the batch contract is final authority."""

    def __init__(
        self,
        authority: BatchAuthority | None = None,
        approved_ruleset_versions: Iterable[str] | None = None,
        *,
        allow_test_only_unverified_settlement: bool = False,
    ) -> None:
        if authority is not None:
            if allow_test_only_unverified_settlement and not authority.test_only_unverified_settlement_enabled:
                raise ValueError("test-only unverified settlement must be enabled on the supplied authority")
            self.authority = authority
        else:
            self.authority = BatchAuthority(
                approved_ruleset_versions,
                allow_test_only_unverified_settlement=allow_test_only_unverified_settlement,
            )

    @property
    def records(self) -> Mapping[str, SubmittedBatch]:
        return self.authority.records

    @property
    def seen_duplicate_check_keys(self) -> frozenset[str]:
        return self.authority.seen_duplicate_check_keys

    @property
    def seen_duplicate_identity_keys(self) -> frozenset[str]:
        return self.authority.seen_duplicate_identity_keys

    @property
    def seen_stable_duplicate_identity_keys(self) -> frozenset[str]:
        return self.authority.seen_stable_duplicate_identity_keys

    @property
    def nullifier_tree(self) -> IndexedNullifierTree:
        return self.authority.nullifier_tree

    def record(
        self,
        batch: SubmittedBatch,
        next_tree: IndexedNullifierTree | None = None,
        next_accumulator_states: Mapping[str, BenefitAccumulator] | None = None,
    ) -> None:
        tree = next_tree or self.authority.nullifier_tree.clone()
        if next_tree is None:
            for value in batch.attempt_nullifiers:
                tree.insert(value)
        self.authority.commit_batch(batch, tree, next_accumulator_states)


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


def _root_bundle_record(label: str, values: Iterable[object]) -> str:
    return stable_private_hash([label, sorted(str(value) for value in values)])


def _root_records(label: str, values: Iterable[object]) -> str:
    return MerkleTree([stable_private_hash([label, value]) for value in values], 10).root


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


def _pending_recipient_address(provider_key: str) -> str:
    return "0x" + stable_private_hash(["pending_settlement_recipient", provider_key])[-40:]


def _recipient_address(provider_key: str, config: BatchConfig) -> str:
    address = config.provider_settlement_addresses.get(provider_key)
    if address:
        return _validate_evm_address(address)
    if config.payment_rail.endswith("_PENDING"):
        return _pending_recipient_address(provider_key)
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
    if type(proposed_amount_cents) is not int or proposed_amount_cents < 0 or proposed_amount_cents >= 2**128:
        raise ValueError(f"payment_amount_out_of_range:{provider_key}:{proposed_amount_cents}")
    for amount in approved_amounts_cents:
        if type(amount) is not int or amount < 0 or amount > MAX_AMOUNT_CENTS:
            raise ValueError(f"approved_amount_out_of_range:{provider_key}:{amount}")
    expected = sum(approved_amounts_cents)
    if expected >= 2**128:
        raise ValueError(f"payment_amount_out_of_range:{provider_key}:{expected}")
    if proposed_amount_cents != expected:
        raise ValueError(f"payment_reconciliation_mismatch:{provider_key}:{proposed_amount_cents}!={expected}")
    return expected


def _batch_value_conservation_commitment(parsed_claims: List[PreparedClaim], payments: List[ProviderPayment]) -> str:
    approved_total = sum(cents(item.result.payable_amount) for item in parsed_claims if item.result.approved)
    payment_total = sum(payment.amount_cents for payment in payments)
    if approved_total != payment_total:
        raise ValueError(f"batch_value_conservation_mismatch:{payment_total}!={approved_total}")
    return stable_private_hash(
        {
            "schema": "batch_value_conservation_v1",
            "approved_payable_cents": approved_total,
            "payment_net_cents": payment_total,
            "approved_claim_count": sum(1 for item in parsed_claims if item.result.approved),
            "payment_count": len(payments),
        }
    )


def _validate_batch_config(config: BatchConfig) -> None:
    for label, value in (
        ("max_claims", config.max_claims),
        ("max_window_seconds", config.max_window_seconds),
        ("merkle_depth", config.merkle_depth),
    ):
        if type(value) is not int:
            raise ValueError(f"{label} must be an integer")
    if config.max_claims <= 0:
        raise ValueError("max_claims must be positive")
    if config.max_window_seconds <= 0:
        raise ValueError("max_window_seconds must be positive")
    if config.merkle_depth <= 0:
        raise ValueError("merkle_depth must be positive")
    if config.max_claims > 2**config.merkle_depth:
        raise ValueError("max_claims exceeds merkle capacity")
    if type(config.annual_benefit_cap_cents) is not int or not (0 < config.annual_benefit_cap_cents <= MAX_AMOUNT_CENTS):
        raise ValueError("annual_benefit_cap_cents must be positive")
    if type(config.deductible_cents) is not int or not (0 <= config.deductible_cents <= MAX_AMOUNT_CENTS):
        raise ValueError("deductible_cents must be non-negative")
    if config.visit_limit is not None and (type(config.visit_limit) is not int or config.visit_limit <= 0):
        raise ValueError("visit_limit must be positive")
    try:
        pack_felt_text(config.claim_source_authority_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("claim_source_authority_id invalid") from exc
    policy_rows = policy_tree_rows(config)
    if 1 + len(policy_rows) > 2**config.merkle_depth:
        raise ValueError("fee_schedule exceeds merkle capacity")
    if config.encrypted_claim_data_mode not in {"legacy_commitment", "aes_gcm"}:
        raise ValueError("encrypted_claim_data_mode invalid")
    if config.encrypted_claim_data_mode == "aes_gcm":
        if not config.audit_data_key_id:
            raise ValueError("audit_data_key_id required")
        if not config.audit_data_key_epoch:
            raise ValueError("audit_data_key_epoch required")


def _effective_batch_config(config: BatchConfig) -> BatchConfig:
    if config.strict_oracle_attestations and config.enforce_nullifier_proofs:
        return config
    if _local_enforcement_disable_allowed():
        return config
    return replace(config, strict_oracle_attestations=True, enforce_nullifier_proofs=True)


def _claim_id_from_parsed(parsed) -> str:
    for segment in parsed.segments:
        if segment and segment[0] == "CLM" and len(segment) > 1:
            return str(segment[1])
    return "UNKNOWN"


def _oracle_attestation_nullifiers(attestations: Iterable[object] | None) -> List[str]:
    nullifiers: List[str] = []
    for item in attestations or []:
        if isinstance(item, Mapping):
            nullifier = item.get("nullifier", "")
        else:
            nullifier = getattr(item, "nullifier", "")
        if nullifier:
            nullifiers.append(str(nullifier))
    return nullifiers


def _dev_attestations_for_payload(
    parsed,
    flags: Dict[str, object],
    *,
    strict_oracle: bool,
    claim_source_commitment: int | str,
    tar_authorization_commitment: int | str,
) -> List[object]:
    if os.environ.get("BL_DEV") != "1" or os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        return []
    if strict_oracle and os.environ.get("BL_ALLOW_DEV_ATTESTATIONS") != "1":
        return []
    claim_id = _claim_id_from_parsed(parsed)
    facts = {
        "eligibility_active": flags.get("eligibility_active", False),
        "provider_enrolled": flags.get("provider_enrolled", False),
        "provider_not_suspended": flags.get("provider_not_suspended", False),
        "not_deceased": flags.get("not_deceased", False),
        "duplicate_claim": flags.get("duplicate_claim", False),
        "program_integrity_hold": flags.get("program_integrity_hold", False),
    }
    return [
        make_test_attestation(
            fact,
            bool(value),
            source_id=f"DEV-{fact.upper()}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
        )
        for fact, value in facts.items()
    ]


def _claim_source_commitment_for_oracle(
    ctx: SharedContext,
    *,
    config: BatchConfig,
    frequency_type: str,
    governed_pepper: str | None = None,
    duplicate_pepper: str | None = None,
) -> str:
    if governed_pepper is None:
        governed_pepper = duplicate_pepper
    elif duplicate_pepper is not None and duplicate_pepper != governed_pepper:
        raise ValueError("attempt_governed_pepper_conflict")
    if not governed_pepper:
        raise ValueError("attempt_governed_pepper_empty")
    ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
    if frequency_type != "original":
        raise ValueError("attempt_revision_pending_lifecycle_authority")
    attempt = synthetic_original_attempt(ctx, source_authority_id=config.claim_source_authority_id)
    attempt_nullifier = legacy_attempt_nullifier(attempt, ctx, governed_pepper=governed_pepper)
    try:
        return claim_source_leaf_hex(
            ctx,
            attempt=attempt,
            attempt_nullifier=attempt_nullifier,
            ruleset_root=ruleset_record,
        )
    except ValueError:
        if not ctx.member_id or not ctx.provider.npi or not ctx.service_lines:
            return f"{0:064x}"
        raise


def _missing_real_batch_proof_status(claim_count: int, attempt_nullifier_count: int) -> Dict[str, object]:
    return {
        "mode": "native_stark_settlement_required",
        "accepted": False,
        "claim_count": claim_count,
        "attempt_nullifier_count": attempt_nullifier_count,
        "reason": "no audited native STARK proof supplied by live prover; settlement remains closed",
        "settlement_contract": "contracts/src/stark/StarkBatchSettlement.sol",
        "label": "NATIVE STARK PROVER PENDING AUDIT",
    }


def _dirty_claim_prefilter(
    parsed,
    flags: Mapping[str, object],
    config: BatchConfig,
) -> Tuple[SharedContext | None, List[str]]:
    if not parsed.accepted:
        return None, [f"malformed_837:{error}" for error in parsed.errors]
    try:
        ctx = build_shared_context(
            parsed,
            dict(flags),
            strict_oracle=False,
            tar_required_procedure_codes=config.tar_required_procedure_codes,
        )
        canonical_day_count(ctx.service_date)
    except Exception as exc:
        return None, [f"structural_invalid:{exc}"]

    return ctx, []


def submit_batches(
    payloads: List[Dict[str, object]],
    *,
    actor: str,
    access: RoleBook,
    config: BatchConfig | None = None,
    recorder: LocalBatchRecorder | None = None,
) -> List[SubmittedBatch]:
    assert_production_ready()
    config = _effective_batch_config(config or BatchConfig())
    _validate_batch_config(config)
    access.require_batch_submitter(actor)
    if len(payloads) > MAX_CLAIMS_PER_SUBMISSION:
        raise ValueError("claim_submission_count_exceeds_prototype_limit")
    recorder = recorder or LocalBatchRecorder()
    ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
    recorder.authority.require_ruleset_approved(ruleset_record)
    submitted: List[SubmittedBatch] = []
    oracle_replay_cache: set[str] = set()

    for start_index, chunk in _chunks(payloads, config.max_claims):
        base_tree, duplicate_record_before, accumulator_states_before, accumulator_root_before = recorder.authority.snapshot()
        pepper_epochs = recorder.authority.active_pepper_epochs()
        submitted_batch, next_tree, next_accumulator_states = _submit_single_batch(
            start_index,
            chunk,
            config,
            duplicate_record_before,
            base_tree,
            accumulator_states_before,
            accumulator_root_before,
            pepper_epochs,
            recorder.authority.seen_duplicate_identity_keys,
            recorder.authority.seen_stable_duplicate_identity_keys,
            oracle_replay_cache,
            nullifier_epoch_mode=recorder.authority.nullifier_epoch_mode,
            global_nullifier_pepper=recorder.authority.global_nullifier_pepper,
        )
        if submitted_batch.claim_count > 0:
            if (
                submitted_batch.verifier_receipt is not None
                or recorder.authority.test_only_unverified_settlement_enabled
            ):
                recorder.record(submitted_batch, next_tree, next_accumulator_states)
            else:
                submitted.append(submitted_batch)
                break
        submitted.append(submitted_batch)
    return submitted


def _submit_single_batch(
    start_index: int,
    payloads: List[Dict[str, object]],
    config: BatchConfig,
    duplicate_check_before: str,
    base_nullifier_tree: IndexedNullifierTree,
    accumulator_states_before: Mapping[str, BenefitAccumulator] | None = None,
    accumulator_root_before: str | None = None,
    pepper_epochs: Iterable[PepperEpoch] | None = None,
    seen_duplicate_identity_keys: Iterable[str] | None = None,
    seen_stable_duplicate_identity_keys: Iterable[str] | None = None,
    oracle_replay_cache: set[str] | None = None,
    *,
    nullifier_epoch_mode: str = "stable_global",
    global_nullifier_pepper: str | None = None,
) -> Tuple[SubmittedBatch, IndexedNullifierTree, Dict[str, BenefitAccumulator]]:
    parsed_claims: List[PreparedClaim] = []
    quarantined: List[QuarantineItem] = []
    engine_modes: Dict[str, int] = {}
    working_nullifier_tree = base_nullifier_tree.clone()
    working_accumulators: Dict[str, BenefitAccumulator] = dict(accumulator_states_before or {})
    accumulator_root_before = accumulator_root_before or _accumulator_root(working_accumulators)
    nullifier_proofs: List[Dict[str, object]] = []
    proof_mode = "none" if not config.enforce_nullifier_proofs else config.nullifier_proof_mode
    if proof_mode not in {"none", "native_stark"}:
        raise ValueError("invalid nullifier proof mode")
    batch_witnesses = []
    active_peppers = list(pepper_epochs or [PepperEpoch("env", current_duplicate_pepper())])
    current_pepper = active_peppers[0]
    if nullifier_epoch_mode != "stable_global":
        raise ValueError("legacy rotating nullifiers forbidden by attempt-nullifier schema")
    if not global_nullifier_pepper:
        global_nullifier_pepper = current_pepper.pepper
    nullifier_peppers = [PepperEpoch("stable_global_v1", global_nullifier_pepper)]
    current_nullifier_pepper = nullifier_peppers[0]
    working_identity_keys = set(seen_duplicate_identity_keys or [])
    working_stable_identity_keys = set(seen_stable_duplicate_identity_keys or [])
    oracle_replay_cache = oracle_replay_cache if oracle_replay_cache is not None else set()

    for offset, payload in enumerate(payloads):
        input_index = start_index + offset
        parsed = parse_837(str(payload.get("edi", "")))
        if not parsed.accepted:
            quarantined.append(QuarantineItem(input_index, str(payload.get("claim_id", f"input_{input_index}")), "ingestion_failed", parsed.errors))
            continue
        try:
            flags_payload = payload.get("flags", {})
            if flags_payload is not None and not isinstance(flags_payload, Mapping):
                raise ValueError("flags must be an object")
            flags = dict(flags_payload or {})
            frequency_type = str(payload.get("frequency_type", "original")).lower()
            if frequency_type != "original":
                quarantined.append(
                    QuarantineItem(
                        input_index,
                        _claim_id_from_parsed(parsed),
                        "frequency_type_pending_domain_review",
                        ["replacement_void_duplicate_semantics_require_domain_review"],
                    )
                )
                continue
            unsigned_ctx, prefilter_errors = _dirty_claim_prefilter(parsed, flags, config)
            if prefilter_errors or unsigned_ctx is None:
                quarantined.append(
                    QuarantineItem(
                        input_index,
                        _claim_id_from_parsed(parsed),
                        DIRTY_CLAIM_PREFILTER_REASON,
                        prefilter_errors,
                    )
                )
                continue
            expected_claim_source_commitment = _claim_source_commitment_for_oracle(
                unsigned_ctx,
                config=config,
                frequency_type=frequency_type,
                duplicate_pepper=current_nullifier_pepper.pepper,
            )
            expected_tar_authorization_commitment = tar_authorization_commitment_for_context(
                unsigned_ctx,
                config.tar_required_procedure_codes,
            )
            oracle_attestations = payload.get("oracle_attestations") or _dev_attestations_for_payload(
                parsed,
                flags,
                strict_oracle=config.strict_oracle_attestations,
                claim_source_commitment=expected_claim_source_commitment,
                tar_authorization_commitment=expected_tar_authorization_commitment,
            )
            oracle_attestation_nullifiers = _oracle_attestation_nullifiers(oracle_attestations)
            replayed_oracle_nullifiers = [
                nullifier for nullifier in oracle_attestation_nullifiers if nullifier in oracle_replay_cache
            ]
            if replayed_oracle_nullifiers:
                quarantined.append(QuarantineItem(input_index, _claim_id_from_parsed(parsed), "oracle_attestation_replay", replayed_oracle_nullifiers))
                continue
            ctx = build_shared_context(
                parsed,
                flags,
                oracle_attestations=oracle_attestations,
                strict_oracle=config.strict_oracle_attestations,
                claim_source_commitment=expected_claim_source_commitment,
                tar_required_procedure_codes=config.tar_required_procedure_codes,
                oracle_replay_cache=oracle_replay_cache,
            )
            resolved_facts = resolve_claim_facts(ctx, flags=ctx.flags, fee_schedule_cents=config.fee_schedule_cents)
            result, engine_mode = adjudicate_for_batch(ctx, config)
            raw_claim_digest = stable_private_hash(["raw_837_v1", str(payload.get("edi", ""))])
            engine_modes[engine_mode] = engine_modes.get(engine_mode, 0) + 1
            attempt = synthetic_original_attempt(
                ctx,
                source_authority_id=config.claim_source_authority_id,
            )
            attempt_nullifier = legacy_attempt_nullifier(
                attempt,
                ctx,
                governed_pepper=current_nullifier_pepper.pepper,
            )
            if working_nullifier_tree.contains(attempt_nullifier):
                quarantined.append(
                    QuarantineItem(
                        input_index,
                        ctx.claim_id,
                        "attempt_nullifier_replay",
                        [f"{current_nullifier_pepper.version}:{attempt_nullifier:064x}"],
                    )
                )
                continue
            pending_accumulator_key = None
            pending_accumulator_state = None
            if result.approved:
                result, pending_accumulator_key, pending_accumulator_state = _apply_allowed_amount_and_accumulator(
                    ctx,
                    result,
                    config,
                    working_accumulators,
                )
                stable_identity_key = stable_duplicate_identity_key(ctx, frequency_type)
                if stable_identity_key in working_stable_identity_keys:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "duplicate_identity_key_already_recorded", []))
                    continue
                identity_key = duplicate_identity_key(ctx, frequency_type, current_pepper.pepper)
                if identity_key in working_identity_keys:
                    quarantined.append(QuarantineItem(input_index, ctx.claim_id, "duplicate_identity_key_already_recorded", [identity_key]))
                    continue
            try:
                witness = working_nullifier_tree.prove_nonmembership(attempt_nullifier)
                if proof_mode == "native_stark":
                    batch_witnesses.append((ctx.claim_id, witness))
                working_nullifier_tree.insert(attempt_nullifier)
                if result.approved:
                    working_stable_identity_keys.add(stable_identity_key)
                    working_identity_keys.add(identity_key)
                    if pending_accumulator_key and pending_accumulator_state:
                        working_accumulators[pending_accumulator_key] = pending_accumulator_state
            except DuplicateNullifierError as exc:
                quarantined.append(QuarantineItem(input_index, ctx.claim_id, "attempt_nullifier_replay", [str(exc)]))
                continue
            except Exception as exc:
                quarantined.append(QuarantineItem(input_index, ctx.claim_id, "attempt_nullifier_witness_failed", [str(exc)]))
                continue
            ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
            identity_key = duplicate_identity_key(ctx, frequency_type, current_pepper.pepper)
            stable_identity_key = stable_duplicate_identity_key(ctx, frequency_type)
            leaf_set = build_claim_leaf_set(
                ctx,
                result,
                ruleset_record,
                frequency_type,
                engine_mode,
                current_nullifier_pepper.pepper,
            )
            claim_source_leaf_record = claim_source_leaf_hex(
                ctx,
                attempt=attempt,
                attempt_nullifier=attempt_nullifier,
                ruleset_root=ruleset_record,
            )
            oracle_signer_record = canonical_oracle_signer_root()
            oracle_leaf_records = tuple(
                f"{leaf:064x}"
                for leaf in canonical_oracle_claim_leaves(
                    ctx,
                    signer_root=oracle_signer_record,
                    claim_source_commitment=expected_claim_source_commitment,
                    evidence_root=resolved_facts.evidence_packet.evidence_root,
                    tar_required_codes=tuple(
                        code
                        for code in config.tar_required_procedure_codes
                        if code in config.fee_schedule_cents
                    ),
                )
            )
            parsed_claims.append(
                PreparedClaim(
                    ctx=ctx,
                    result=result,
                    claim_record=leaf_set.claim_leaf,
                    claim_source_leaf=claim_source_leaf_record,
                    oracle_facts_leaves=oracle_leaf_records,
                    adjudication_record=leaf_set.result_leaf,
                    duplicate_record=leaf_set.duplicate_leaf,
                    duplicate_check_key=leaf_set.duplicate_check_key,
                    duplicate_identity_key=identity_key if result.approved else "",
                    stable_duplicate_identity_key=stable_identity_key if result.approved else "",
                    duplicate_nullifier=leaf_set.duplicate_nullifier,
                    attempt=attempt,
                    attempt_nullifier=attempt_nullifier,
                    raw_claim_digest=raw_claim_digest,
                    engine_mode=engine_mode,
                    evidence_root=resolved_facts.evidence_packet.evidence_root,
                    evidence_packet=resolved_facts.evidence_packet.to_dict(),
                    raw_edi=str(payload.get("edi", "")),
                    source_flags=dict(flags),
                )
            )
        except Exception as exc:
            claim_id = parsed.segments[0][1] if parsed.segments and len(parsed.segments[0]) > 1 else f"input_{input_index}"
            quarantined.append(QuarantineItem(input_index, claim_id, "adjudication_failed", [str(exc)]))

    claim_records = [item.claim_record for item in parsed_claims]
    claim_source_leaves = [int(item.claim_source_leaf, 16) for item in parsed_claims]
    adjudication_records = [item.adjudication_record for item in parsed_claims]
    duplicate_records = [item.duplicate_record for item in parsed_claims]
    claim_tree = PoseidonMerkleTree(claim_records, config.merkle_depth, "claim")
    adjudication_tree = PoseidonMerkleTree(adjudication_records, config.merkle_depth, "result")
    duplicate_tree = MerkleTree(duplicate_records, config.merkle_depth)
    duplicate_check_after = working_nullifier_tree.root_hex
    accumulator_root_after = _accumulator_root(working_accumulators)
    quarantine_records = [_quarantine_record(item) for item in quarantined]
    batch_id = _batch_id(start_index, claim_records, adjudication_records, quarantine_records)

    if proof_mode == "native_stark" and batch_witnesses:
        nullifier_proofs.append(_missing_real_batch_proof_status(len(parsed_claims), len(batch_witnesses)))

    provider_totals: Dict[str, Tuple[int, List[int], List[str]]] = {}
    for item in parsed_claims:
        if not item.result.approved:
            continue
        provider_key = _provider_key(item.ctx)
        count, amounts, result_records = provider_totals.get(provider_key, (0, [], []))
        provider_totals[provider_key] = (
            count + 1,
            [*amounts, cents(item.result.payable_amount)],
            [*result_records, item.adjudication_record],
        )

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
        settlement = {"status": "not_submitted_real_verifier_rejected", "reason": REAL_PROOF_REQUIRED_STATUS}
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
    payment_tree = PoseidonMerkleTree([payment.payee_record for payment in payments], config.merkle_depth, "payment")
    claim_count = len(parsed_claims)
    ruleset_record = ruleset_policy_record(config.ruleset_version, config.ruleset_policy_content)
    attempt_nullifiers = sorted(item.attempt_nullifier for item in parsed_claims)
    batch_nullifier_record = batch_nullifier_commitment(attempt_nullifiers)
    claim_source_root = claim_source_root_hex(claim_source_leaves, config.merkle_depth)
    oracle_fact_records = [
        int(leaf, 16)
        for item in parsed_claims
        for leaf in item.oracle_facts_leaves
    ]
    oracle_facts_root = oracle_facts_root_hex(oracle_fact_records, config.merkle_depth)
    oracle_signer_root = canonical_oracle_signer_root()
    policy_root = policy_root_hex(config, ruleset_record)
    address_book_root = _root_bundle_record(
        "address_book_root_v1",
        [f"{payment.provider_payment_key}:{payment.recipient_address.lower()}" for payment in payments],
    )
    data_availability_root = _root_records(
        "data_availability_leaf_v1",
        [
            {
                "claim_id": item.ctx.claim_id,
                "raw_claim_digest": item.raw_claim_digest,
                "claim_record": item.claim_record,
                "adjudication_record": item.adjudication_record,
                "evidence_root": item.evidence_root,
            }
            for item in parsed_claims
        ],
    )
    encrypted_claim_payload = b""
    if config.encrypted_claim_data_mode == "aes_gcm":
        audit_payload = {
            "schema_version": "blind_ledger_batch_audit_payload_v1",
            "batch_id": batch_id,
            "data_availability_root": data_availability_root,
            "claims": [
                {
                    "claim_id": item.ctx.claim_id,
                    "raw_edi": item.raw_edi,
                    "source_flags": item.source_flags,
                    "raw_claim_digest": item.raw_claim_digest,
                    "claim_record": item.claim_record,
                    "adjudication_record": item.adjudication_record,
                    "evidence_root": item.evidence_root,
                    "evidence_packet": item.evidence_packet,
                }
                for item in parsed_claims
            ],
        }
        encrypted_bundle = encrypt_claim_data_for_stark(
            audit_payload,
            aad=f"blind-ledger-batch-audit-v1:{batch_id}:{data_availability_root}",
            key_id=config.audit_data_key_id,
            key_epoch=config.audit_data_key_epoch,
        )
        encrypted_claim_payload = serialize_encrypted_claim_data(encrypted_bundle)
        encrypted_claim_data_root = encrypted_payload_root(encrypted_bundle)
    else:
        encrypted_claim_data_root = _root_records(
            "encrypted_claim_data_root_v1",
            [
                {
                    "claim_id": item.ctx.claim_id,
                    "raw_claim_digest": item.raw_claim_digest,
                    "evidence_root": item.evidence_root,
                    "claim_record": item.claim_record,
                }
                for item in parsed_claims
            ],
        )
    denial_attestation_root = _root_records(
        "denial_attestation_leaf_v1",
        [
            {
                "claim_id": item.ctx.claim_id,
                "denial_reason": item.result.denial_reason,
                "carc": item.result.carc,
                "rarc": item.result.rarc,
                "adjudication_record": item.adjudication_record,
            }
            for item in parsed_claims
            if not item.result.approved
        ],
    )
    forced_inclusion_root = _root_records(
        "forced_inclusion_leaf_v1",
        [
            {
                "input_index": start_index + offset,
                "claim_id": str(payload.get("claim_id") or f"input_{start_index + offset}"),
                "raw_claim_digest": stable_private_hash(["raw_837_v1", str(payload.get("edi", ""))]),
            }
            for offset, payload in enumerate(payloads)
        ],
    )
    value_conservation_commitment = _batch_value_conservation_commitment(parsed_claims, payments)
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
        claim_source_root=claim_source_root,
        oracle_facts_root=oracle_facts_root,
        oracle_signer_root=oracle_signer_root,
        policy_root=policy_root,
        address_book_root=address_book_root,
        data_availability_root=data_availability_root,
        encrypted_claim_data_root=encrypted_claim_data_root if encrypted_claim_payload else "",
        denial_attestation_root=denial_attestation_root,
        forced_inclusion_root=forced_inclusion_root,
        value_conservation_commitment=value_conservation_commitment,
        accumulator_root_before=accumulator_root_before,
        accumulator_root_after=accumulator_root_after,
    )

    approved_amount_cents = sum(cents(item.result.payable_amount) for item in parsed_claims if item.result.approved)
    payment_amount_cents = sum(payment.amount_cents for payment in payments)
    proof_status = REAL_PROOF_REQUIRED_STATUS

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
                total_charge_cents=cents(item.result.total_charge),
                payable_amount=item.result.payable_amount,
                engine_mode=item.engine_mode,
                claim_record=item.claim_record,
                adjudication_record=item.adjudication_record,
                claim_record_path=claim_tree.prove(index),
                adjudication_record_path=adjudication_tree.prove(index),
                remittance_835=generate_835(item.ctx, item.result),
                evidence_root=item.evidence_root,
                evidence_packet=item.evidence_packet,
            )
        )

    batch_fields = {
        "batch_id": batch_id,
        "claim_count": claim_count,
        "quarantine_count": len(quarantined),
        "claim_batch_record": claim_tree.root,
        "adjudication_batch_record": adjudication_tree.root,
        "duplicate_check_before": duplicate_check_before,
        "duplicate_check_after": duplicate_check_after,
        "batch_nullifier_commitment": batch_nullifier_record,
        "combined_batch_commitment": combined_record,
        "payment_batch_record": payment_tree.root,
        "payment_count": len(payments),
        "ruleset_record": ruleset_record,
        "claim_source_root": claim_source_root,
        "oracle_facts_root": oracle_facts_root,
        "oracle_signer_root": oracle_signer_root,
        "policy_root": policy_root,
        "address_book_root": address_book_root,
        "data_availability_root": data_availability_root,
        "encrypted_claim_data_root": encrypted_claim_data_root,
        "denial_attestation_root": denial_attestation_root,
        "forced_inclusion_root": forced_inclusion_root,
        "value_conservation_commitment": value_conservation_commitment,
        "accumulator_root_before": accumulator_root_before,
        "accumulator_root_after": accumulator_root_after,
        "approved_amount_cents": approved_amount_cents,
        "payment_amount_cents": payment_amount_cents,
    }
    public_inputs = build_native_stark_public_inputs(batch_fields)

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
        claim_source_root=claim_source_root,
        oracle_facts_root=oracle_facts_root,
        oracle_signer_root=oracle_signer_root,
        policy_root=policy_root,
        address_book_root=address_book_root,
        data_availability_root=data_availability_root,
        encrypted_claim_data_root=encrypted_claim_data_root,
        denial_attestation_root=denial_attestation_root,
        forced_inclusion_root=forced_inclusion_root,
        value_conservation_commitment=value_conservation_commitment,
        accumulator_root_before=accumulator_root_before,
        accumulator_root_after=accumulator_root_after,
        approved_amount_cents=approved_amount_cents,
        payment_amount_cents=payment_amount_cents,
        public_inputs=public_inputs,
        verifier_key_id=config.verifier_key_id,
        proof_status=proof_status,
        engine_modes=engine_modes,
        duplicate_check_keys=[item.duplicate_check_key for item in parsed_claims if item.result.approved],
        duplicate_identity_keys=[item.duplicate_identity_key for item in parsed_claims if item.result.approved],
        stable_duplicate_identity_keys=[item.stable_duplicate_identity_key for item in parsed_claims if item.result.approved],
        attempt_nullifiers=[item.attempt_nullifier for item in parsed_claims],
        nullifier_proofs=nullifier_proofs,
        claim_packets=packets,
        payments=payments,
        quarantined=quarantined,
        encrypted_claim_payload=encrypted_claim_payload,
        nullifier_epoch_mode=nullifier_epoch_mode,
        nullifier_pepper_version=current_nullifier_pepper.version,
    )
    return batch, working_nullifier_tree, working_accumulators


def batch_to_plain_dict(batch: SubmittedBatch) -> Dict[str, object]:
    return {
        "batch_id": batch.batch_id,
        "claim_count": batch.claim_count,
        "quarantine_count": batch.quarantine_count,
        "payment_count": batch.payment_count,
        "proof_status": REAL_PROOF_REQUIRED_STATUS,
        "accepted_by_real_verifier": batch.accepted_by_real_verifier,
        "encrypted_claim_payload": {
            "present": bool(batch.encrypted_claim_payload),
            "bytes": len(batch.encrypted_claim_payload),
        },
        "nullifier_epoch": {
            "mode": batch.nullifier_epoch_mode,
            "pepper_version": batch.nullifier_pepper_version,
        },
        "engine_modes": dict(batch.engine_modes),
        "roots": {
            "claim_root": batch.claim_batch_record,
            "result_root": batch.adjudication_batch_record,
            "payment_root": batch.payment_batch_record,
            "nullifier_before": batch.duplicate_check_before,
            "nullifier_after": batch.duplicate_check_after,
            "batch_nullifier_commitment": batch.batch_nullifier_commitment,
            "combined_commitment": batch.combined_batch_commitment,
            "claim_source_root": batch.claim_source_root,
            "oracle_facts_root": batch.oracle_facts_root,
            "oracle_signer_root": batch.oracle_signer_root,
            "policy_root": batch.policy_root,
            "ruleset_root": batch.ruleset_record,
            "data_availability_root": batch.data_availability_root,
            "encrypted_claim_data_root": batch.encrypted_claim_data_root,
            "denial_attestation_root": batch.denial_attestation_root,
            "forced_inclusion_root": batch.forced_inclusion_root,
            "value_conservation_commitment": batch.value_conservation_commitment,
            "accumulator_root_before": batch.accumulator_root_before,
            "accumulator_root_after": batch.accumulator_root_after,
        },
        "amounts": {
            "approved_amount_cents": batch.approved_amount_cents,
            "payment_amount_cents": batch.payment_amount_cents,
        },
        "claims": [
            {
                "claim_index": packet.claim_index,
                "decision": packet.decision,
                "denial_reason": packet.denial_reason,
                "carc": packet.carc,
                "rarc": packet.rarc,
                "total_charge_cents": packet.total_charge_cents,
                "payable_amount_cents": cents(packet.payable_amount),
                "engine_mode": packet.engine_mode,
            }
            for packet in batch.claim_packets
        ],
        "payments": [
            {
                "approved_claim_count": payment.approved_claim_count,
                "amount_cents": payment.amount_cents,
                "settlement_status": str(payment.settlement.get("status", "")),
            }
            for payment in batch.payments
        ],
        "quarantined": [
            {
                "input_index": item.input_index,
                "reason": item.reason,
                "error_count": len(item.errors),
            }
            for item in batch.quarantined
        ],
    }
