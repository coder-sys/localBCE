"""Depth-64 authenticated economic state for the Wave 1A relation.

Every map retains complete 512-bit keys and fixed-width 512-bit values.  A
sequential depth-64 position is only an authenticated allocator index.  Each
slot performs one benefit upsert, one obligation upsert, two ledger upserts,
and one operation-log append.  Approval, denial, and cover therefore have the
same logical state schedule.  Non-economic slots update four authenticated
domain-separated zero-valued dummy leaves rather than skipping work or
permanently allocating throwaway records.

This is an executable, fail-closed semantic reference.  It is not a proof
system, production state store, durable commit protocol, or permission to
settle money.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
from typing import Final, Mapping, Sequence

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    encode_authorization_token,
)

from .ordered_map_reference import (
    ORDERED_MAP_DEPTH,
    ZERO_512,
    OrderedMapBuilder,
    OrderedMapSnapshot,
    OrderedMapUpsertWitness,
    require_ordered_map_upsert,
)
from .ordered_map_batch_reference import (
    OrderedMapBatchWitness,
    build_ordered_map_batch_witness,
)
from .payment import BatchEconomics, SlotEconomics
from .profile import CalibrationProfile
from .semantics import ClaimSlot, SlotKind, StructuralError


PAYMENT_MAP_STATUS: Final[str] = (
    "SYNTHETIC_WAVE1A_AUTHENTICATED_PAYMENT_MAPS_ORDERED_DEPTH64_V4_NONACTIVATING"
)
# Compatibility export.  The authoritative structure is no longer a sparse
# key-positioned map; consumers must observe the value 64.
SPARSE_MAP_DEPTH: Final[int] = ORDERED_MAP_DEPTH
_U64_MAX: Final[int] = (1 << 64) - 1
_KEY_BYTES: Final[int] = 64

_KEY_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/KEY/v1"
_RANK_KEY_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/RANK-KEY/v2"
_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/STATE/v4"
_LOG_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/OPLOG/v2"
_OPERATION_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/OPERATION/v3"
_ASSET_REGISTRY_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-ASSET-REGISTRY/v1"
_BENEFIT_SCOPE_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/BENEFIT-SCOPE/v1"

BENEFIT_MAP_DOMAIN: Final[bytes] = b"\x11"
OBLIGATION_MAP_DOMAIN: Final[bytes] = b"\x12"
LEDGER_MAP_DOMAIN: Final[bytes] = b"\x13"

_BENEFIT_VALUE_TAG: Final[bytes] = b"BLBEN003"
_OBLIGATION_VALUE_TAG: Final[bytes] = b"BLOBG003"
_BALANCE_VALUE_TAG: Final[bytes] = b"BLBAL003"

_PAYER_RESERVE_PREIMAGE: Final[bytes] = _RANK_KEY_DOMAIN + b"\x03"
_PAYER_RESERVE_KEY: Final[bytes] = sha3_512(_PAYER_RESERVE_PREIMAGE).digest()
_ASSET_REGISTRY_ROOT: Final[bytes] = sha3_512(
    _ASSET_REGISTRY_DOMAIN
    + b"USD-CENTS"
    + b"PAYER-RESERVE"
    + b"PROVIDER-PAYABLE"
).digest()


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < 0 or value > _U64_MAX:
        raise StructuralError(f"wave1a_payment_map_{label}_out_of_range")
    if nonzero and value == 0:
        raise StructuralError(f"wave1a_payment_map_{label}_must_be_nonzero")
    return value


def _bytes64(label: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != _KEY_BYTES:
        raise StructuralError(f"wave1a_payment_map_{label}_must_be_64_bytes")
    if nonzero and not any(value):
        raise StructuralError(f"wave1a_payment_map_{label}_must_be_nonzero")
    return value


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise StructuralError("wave1a_payment_map_length_prefix_overflow")
    return len(value).to_bytes(2, "big") + value


def _ascii(label: str, value: object) -> bytes:
    if type(value) is not str:
        raise StructuralError(f"wave1a_payment_map_{label}_must_be_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StructuralError(f"wave1a_payment_map_{label}_must_be_ascii") from exc
    if not encoded or len(encoded) > 64:
        raise StructuralError(f"wave1a_payment_map_{label}_length_invalid")
    return encoded


def _pack_value(tag: bytes, payload: bytes) -> bytes:
    if type(tag) is not bytes or len(tag) != 8:
        raise StructuralError("wave1a_payment_map_value_tag_invalid")
    if type(payload) is not bytes or len(payload) > 54:
        raise StructuralError("wave1a_payment_map_value_payload_invalid")
    return tag + len(payload).to_bytes(2, "big") + payload + bytes(54 - len(payload))


def _unpack_value(tag: bytes, value: bytes, *, size: int) -> bytes:
    _bytes64("fixed_value", value, nonzero=False)
    if value[:8] != tag or int.from_bytes(value[8:10], "big") != size:
        raise StructuralError("wave1a_payment_map_value_header_invalid")
    payload = value[10 : 10 + size]
    if any(value[10 + size :]):
        raise StructuralError("wave1a_payment_map_value_padding_nonzero")
    return payload


@dataclass(frozen=True, slots=True)
class BenefitScopeV1:
    """One payer/plan/benefit-period namespace for member accumulators."""

    payer_authority_id: str
    plan_id: str
    benefit_period_start_day: int
    benefit_period_end_day: int

    def __post_init__(self) -> None:
        _ascii("benefit_scope_payer_authority_id", self.payer_authority_id)
        _ascii("benefit_scope_plan_id", self.plan_id)
        start = _u64("benefit_scope_start_day", self.benefit_period_start_day)
        end = _u64("benefit_scope_end_day", self.benefit_period_end_day)
        if end < start:
            raise StructuralError("wave1a_payment_map_benefit_scope_period_invalid")

    def commitment_512(self) -> bytes:
        return sha3_512(
            _BENEFIT_SCOPE_DOMAIN
            + _lp16(_ascii("benefit_scope_payer_authority_id", self.payer_authority_id))
            + _lp16(_ascii("benefit_scope_plan_id", self.plan_id))
            + self.benefit_period_start_day.to_bytes(8, "big")
            + self.benefit_period_end_day.to_bytes(8, "big")
            + _ASSET_REGISTRY_ROOT
        ).digest()


def payment_map_key_preimage(kind: bytes, *parts: bytes) -> bytes:
    if type(kind) is not bytes or not kind:
        raise StructuralError("wave1a_payment_map_key_kind_invalid")
    if any(type(part) is not bytes for part in parts):
        raise StructuralError("wave1a_payment_map_key_part_invalid")
    return (
        _KEY_DOMAIN
        + _lp16(kind)
        + len(parts).to_bytes(2, "big")
        + b"".join(_lp16(part) for part in parts)
    )


def _map_key(kind: bytes, *parts: bytes) -> bytes:
    return sha3_512(payment_map_key_preimage(kind, *parts)).digest()


def member_benefit_key_preimage(
    member_id: str, *, benefit_scope: BenefitScopeV1
) -> bytes:
    if type(benefit_scope) is not BenefitScopeV1:
        raise StructuralError("wave1a_payment_map_benefit_scope_required")
    return b"".join(
        (
            _RANK_KEY_DOMAIN,
            b"\x01",
            benefit_scope.commitment_512(),
            encode_authorization_token(member_id),
        )
    )


def member_benefit_key(member_id: str, *, benefit_scope: BenefitScopeV1) -> bytes:
    return sha3_512(
        member_benefit_key_preimage(member_id, benefit_scope=benefit_scope)
    ).digest()


def provider_payable_key_preimage(provider_npi: str) -> bytes:
    provider = _ascii("provider_npi", provider_npi)
    if len(provider) != 10:
        raise StructuralError("wave1a_payment_map_provider_npi_length_invalid")
    return _RANK_KEY_DOMAIN + b"\x04" + provider


def provider_payable_key(provider_npi: str) -> bytes:
    return sha3_512(provider_payable_key_preimage(provider_npi)).digest()


def payer_reserve_key_preimage() -> bytes:
    return _PAYER_RESERVE_PREIMAGE


def payer_reserve_key() -> bytes:
    return _PAYER_RESERVE_KEY


def provider_obligation_key_preimage(slot: ClaimSlot) -> bytes:
    if not isinstance(slot, ClaimSlot) or slot.slot_kind is not SlotKind.REAL:
        raise StructuralError("wave1a_payment_map_real_claim_required")
    revision_code = {
        "ORIGINAL": 1,
        "CORRECTION": 2,
        "REPLACEMENT": 3,
        "VOID": 4,
    }.get(slot.revision_kind.value)
    if revision_code is None:
        raise StructuralError("wave1a_payment_map_revision_kind_invalid")
    provider = _ascii("provider_npi", slot.provider_npi)
    if len(provider) != 10:
        raise StructuralError("wave1a_payment_map_provider_npi_length_invalid")
    return b"".join(
        (
            _RANK_KEY_DOMAIN,
            b"\x02",
            encode_authorization_token(slot.source_authority_id),
            encode_authorization_token(slot.claim_id),
            slot.attempt_version.to_bytes(4, "big"),
            bytes((revision_code,)),
            slot.parent_attempt_version.to_bytes(4, "big"),
            provider,
        )
    )


def provider_obligation_key(slot: ClaimSlot) -> bytes:
    return sha3_512(provider_obligation_key_preimage(slot)).digest()


def payment_dummy_key_preimage(
    lane: bytes,
    strong_settlement_domain_id_512: bytes,
    epoch: int,
    benefit_scope_commitment_512: bytes,
) -> bytes:
    lane_code = {
        b"BENEFIT": 0x11,
        b"OBLIGATION": 0x12,
        b"RESERVE": 0x13,
        b"PAYABLE": 0x14,
    }.get(lane)
    if lane_code is None:
        raise StructuralError("wave1a_payment_map_dummy_lane_invalid")
    return b"".join(
        (
            _RANK_KEY_DOMAIN,
            bytes((lane_code,)),
            _bytes64("dummy_settlement_domain", strong_settlement_domain_id_512),
            _u64("dummy_epoch", epoch, nonzero=True).to_bytes(8, "big"),
            _bytes64("dummy_benefit_scope", benefit_scope_commitment_512),
        )
    )


def _dummy_key(
    lane: bytes,
    strong_settlement_domain_id_512: bytes,
    epoch: int,
    benefit_scope_commitment_512: bytes,
) -> bytes:
    return sha3_512(
        payment_dummy_key_preimage(
            lane,
            strong_settlement_domain_id_512,
            epoch,
            benefit_scope_commitment_512,
        )
    ).digest()


@dataclass(frozen=True, slots=True, order=True)
class AuthenticatedMapEntry:
    """Logical import/export entry; ordered snapshots use fixed 64-byte values."""

    key_512: bytes
    value: bytes

    def __post_init__(self) -> None:
        _bytes64("entry_key", self.key_512)
        if type(self.value) is not bytes or not 1 <= len(self.value) <= 64:
            raise StructuralError("wave1a_payment_map_entry_value_length_invalid")


@dataclass(frozen=True, slots=True)
class BenefitAccumulatorRecord:
    allowed_cents: int
    patient_responsibility_cents: int
    visits: int
    authorization_uses: int

    def __post_init__(self) -> None:
        for label, value in (
            ("benefit_allowed", self.allowed_cents),
            ("benefit_patient_responsibility", self.patient_responsibility_cents),
            ("benefit_visits", self.visits),
            ("benefit_authorization_uses", self.authorization_uses),
        ):
            _u64(label, value)

    def encode(self) -> bytes:
        return b"".join(
            value.to_bytes(8, "big")
            for value in (
                self.allowed_cents,
                self.patient_responsibility_cents,
                self.visits,
                self.authorization_uses,
            )
        )

    @classmethod
    def decode(cls, value: bytes | None) -> "BenefitAccumulatorRecord":
        if value is None:
            return cls(0, 0, 0, 0)
        if type(value) is not bytes or len(value) != 32:
            raise StructuralError("wave1a_payment_map_benefit_record_invalid")
        return cls(*(int.from_bytes(value[i : i + 8], "big") for i in range(0, 32, 8)))


def _benefit_fixed(record: BenefitAccumulatorRecord) -> bytes:
    return _pack_value(_BENEFIT_VALUE_TAG, record.encode())


def _benefit_logical(value: bytes) -> bytes:
    return _unpack_value(_BENEFIT_VALUE_TAG, value, size=32)


def _obligation_fixed(plan_payable_cents: int) -> bytes:
    payload = _u64("obligation_payable", plan_payable_cents).to_bytes(8, "big") + b"OPEN" + bytes(4)
    return _pack_value(_OBLIGATION_VALUE_TAG, payload)


def _obligation_import(payload: bytes) -> bytes:
    if type(payload) is not bytes or len(payload) != 16 or payload[8:] != b"OPEN" + bytes(4):
        raise StructuralError("wave1a_payment_map_obligation_status_invalid")
    return _pack_value(_OBLIGATION_VALUE_TAG, payload)


def _obligation_logical(value: bytes) -> bytes:
    payload = _unpack_value(_OBLIGATION_VALUE_TAG, value, size=16)
    if payload[8:] != b"OPEN" + bytes(4):
        raise StructuralError("wave1a_payment_map_obligation_status_invalid")
    return payload


def _balance_fixed(value: int) -> bytes:
    return _pack_value(_BALANCE_VALUE_TAG, _u64("balance", value).to_bytes(8, "big"))


def _balance_logical(value: bytes) -> bytes:
    return _unpack_value(_BALANCE_VALUE_TAG, value, size=8)


def _balance(value: bytes | None, *, required: bool = False) -> int:
    if value is None:
        if required:
            raise StructuralError("wave1a_payment_map_required_balance_missing")
        return 0
    return int.from_bytes(_balance_logical(value), "big")


def _snapshot_entries(
    snapshot: OrderedMapSnapshot,
    decoder,
) -> tuple[AuthenticatedMapEntry, ...]:
    values: list[AuthenticatedMapEntry] = []
    for leaf in snapshot.leaves:
        if leaf.index in {0, 1} or leaf.value_512 == ZERO_512:
            continue
        values.append(AuthenticatedMapEntry(leaf.key_512, decoder(leaf.value_512)))
    return tuple(sorted(values))


def _snapshot_value(snapshot: OrderedMapSnapshot, key_512: bytes) -> bytes | None:
    return next(
        (leaf.value_512 for leaf in snapshot.leaves if leaf.key_512 == key_512),
        None,
    )


def _ordered_builder(
    map_domain: bytes,
    *,
    entries: tuple[tuple[bytes, bytes], ...] = (),
    snapshot: OrderedMapSnapshot | None = None,
) -> OrderedMapBuilder:
    try:
        return OrderedMapBuilder(map_domain, entries, snapshot=snapshot)
    except (TypeError, ValueError) as exc:
        raise StructuralError(f"wave1a_payment_map_ordered_map:{exc}") from exc


def _prove(
    builder: OrderedMapBuilder,
    key: bytes,
    value: bytes,
) -> OrderedMapUpsertWitness:
    try:
        return builder.prove_upsert(key, value)
    except (TypeError, ValueError) as exc:
        raise StructuralError(f"wave1a_payment_map_ordered_map:{exc}") from exc


def _apply(builder: OrderedMapBuilder, witness: OrderedMapUpsertWitness) -> None:
    try:
        builder.apply(witness)
    except (TypeError, ValueError) as exc:
        raise StructuralError(f"wave1a_payment_map_ordered_map:{exc}") from exc


@dataclass(frozen=True, slots=True)
class AuthenticatedPaymentMapState:
    epoch: int
    sequence: int
    next_slot_index: int
    strong_settlement_domain_id_512: bytes
    asset_registry_root_512: bytes
    benefit_scope: BenefitScopeV1
    benefit_snapshot: OrderedMapSnapshot = field(repr=False)
    obligation_snapshot: OrderedMapSnapshot = field(repr=False)
    ledger_snapshot: OrderedMapSnapshot = field(repr=False)
    operation_log_root_512: bytes
    status: str = PAYMENT_MAP_STATUS

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        _u64("state_epoch", self.epoch, nonzero=True)
        _u64("state_sequence", self.sequence)
        if type(self.next_slot_index) is not int or not 0 <= self.next_slot_index <= 511:
            raise StructuralError("wave1a_payment_map_next_slot_index_invalid")
        _bytes64("strong_settlement_domain", self.strong_settlement_domain_id_512)
        if not hmac.compare_digest(
            _bytes64("asset_registry_root", self.asset_registry_root_512),
            _ASSET_REGISTRY_ROOT,
        ):
            raise StructuralError("wave1a_payment_map_asset_registry_root_invalid")
        if type(self.benefit_scope) is not BenefitScopeV1:
            raise StructuralError("wave1a_payment_map_benefit_scope_required")
        for label, domain, snapshot in (
            ("benefit", BENEFIT_MAP_DOMAIN, self.benefit_snapshot),
            ("obligation", OBLIGATION_MAP_DOMAIN, self.obligation_snapshot),
            ("ledger", LEDGER_MAP_DOMAIN, self.ledger_snapshot),
        ):
            if not isinstance(snapshot, OrderedMapSnapshot) or snapshot.map_domain != domain:
                raise StructuralError(f"wave1a_payment_map_{label}_snapshot_invalid")
            try:
                snapshot.__post_init__()
            except (TypeError, ValueError) as exc:
                raise StructuralError(f"wave1a_payment_map_{label}_snapshot:{exc}") from exc
        scope = self.benefit_scope.commitment_512()
        for lane, snapshot in (
            (b"BENEFIT", self.benefit_snapshot),
            (b"OBLIGATION", self.obligation_snapshot),
            (b"RESERVE", self.ledger_snapshot),
            (b"PAYABLE", self.ledger_snapshot),
        ):
            key = _dummy_key(
                lane,
                self.strong_settlement_domain_id_512,
                self.epoch,
                scope,
            )
            if _snapshot_value(snapshot, key) != ZERO_512:
                raise StructuralError("wave1a_payment_map_dummy_leaf_invalid")
        _bytes64("operation_log_root", self.operation_log_root_512)
        if self.status != PAYMENT_MAP_STATUS:
            raise StructuralError("wave1a_payment_map_state_status_invalid")

    @property
    def benefit_root_512(self) -> bytes:
        return self.benefit_snapshot.root

    @property
    def obligation_root_512(self) -> bytes:
        return self.obligation_snapshot.root

    @property
    def private_asset_ledger_root_512(self) -> bytes:
        return self.ledger_snapshot.root

    @property
    def benefit_entries(self) -> tuple[AuthenticatedMapEntry, ...]:
        return _snapshot_entries(self.benefit_snapshot, _benefit_logical)

    @property
    def obligation_entries(self) -> tuple[AuthenticatedMapEntry, ...]:
        return _snapshot_entries(self.obligation_snapshot, _obligation_logical)

    @property
    def ledger_entries(self) -> tuple[AuthenticatedMapEntry, ...]:
        return _snapshot_entries(self.ledger_snapshot, _balance_logical)

    def root(self) -> bytes:
        return sha3_512(
            _STATE_DOMAIN
            + self.epoch.to_bytes(8, "big")
            + self.sequence.to_bytes(8, "big")
            + self.next_slot_index.to_bytes(2, "big")
            + self.strong_settlement_domain_id_512
            + self.asset_registry_root_512
            + self.benefit_scope.commitment_512()
            + self.benefit_root_512
            + self.obligation_root_512
            + self.private_asset_ledger_root_512
            + self.operation_log_root_512
        ).digest()


def build_payment_map_state(
    *,
    epoch: int,
    sequence: int,
    strong_settlement_domain_id_512: bytes,
    benefit_scope: BenefitScopeV1,
    payer_reserve_cents: int,
    operation_log_root_512: bytes,
    benefit_entries: tuple[AuthenticatedMapEntry, ...] = (),
    obligation_entries: tuple[AuthenticatedMapEntry, ...] = (),
    provider_payable_balances: Mapping[str, int] | None = None,
) -> AuthenticatedPaymentMapState:
    _u64("initial_epoch", epoch, nonzero=True)
    _u64("initial_payer_reserve", payer_reserve_cents)
    strong_domain = _bytes64(
        "strong_settlement_domain",
        strong_settlement_domain_id_512,
    )
    if provider_payable_balances is None:
        provider_payable_balances = {}
    if not isinstance(provider_payable_balances, Mapping):
        raise StructuralError("wave1a_payment_map_provider_balances_not_mapping")
    if type(benefit_scope) is not BenefitScopeV1:
        raise StructuralError("wave1a_payment_map_benefit_scope_required")
    if type(benefit_entries) is not tuple or type(obligation_entries) is not tuple:
        raise StructuralError("wave1a_payment_map_initial_entries_not_tuple")

    scope_commitment = benefit_scope.commitment_512()
    benefit_dummy = _dummy_key(
        b"BENEFIT",
        strong_domain,
        epoch,
        scope_commitment,
    )
    obligation_dummy = _dummy_key(
        b"OBLIGATION",
        strong_domain,
        epoch,
        scope_commitment,
    )
    reserve_dummy = _dummy_key(
        b"RESERVE",
        strong_domain,
        epoch,
        scope_commitment,
    )
    payable_dummy = _dummy_key(
        b"PAYABLE",
        strong_domain,
        epoch,
        scope_commitment,
    )

    benefit_fixed = tuple(
        sorted(
            (
                *(
                    (
                        entry.key_512,
                        _benefit_fixed(BenefitAccumulatorRecord.decode(entry.value)),
                    )
                    for entry in benefit_entries
                ),
                (benefit_dummy, ZERO_512),
            )
        )
    )
    obligation_fixed = tuple(
        sorted(
            (
                *((entry.key_512, _obligation_import(entry.value)) for entry in obligation_entries),
                (obligation_dummy, ZERO_512),
            )
        )
    )
    ledger_fixed = [
        (_PAYER_RESERVE_KEY, _balance_fixed(payer_reserve_cents)),
        (reserve_dummy, ZERO_512),
        (payable_dummy, ZERO_512),
    ]
    for provider, balance in sorted(provider_payable_balances.items()):
        ledger_fixed.append((provider_payable_key(provider), _balance_fixed(balance)))

    benefit = _ordered_builder(BENEFIT_MAP_DOMAIN, entries=benefit_fixed)
    obligation = _ordered_builder(OBLIGATION_MAP_DOMAIN, entries=obligation_fixed)
    ledger = _ordered_builder(LEDGER_MAP_DOMAIN, entries=tuple(sorted(ledger_fixed)))
    return AuthenticatedPaymentMapState(
        epoch=epoch,
        sequence=sequence,
        next_slot_index=0,
        strong_settlement_domain_id_512=strong_domain,
        asset_registry_root_512=_ASSET_REGISTRY_ROOT,
        benefit_scope=benefit_scope,
        benefit_snapshot=benefit.snapshot(),
        obligation_snapshot=obligation.snapshot(),
        ledger_snapshot=ledger.snapshot(),
        operation_log_root_512=_bytes64("operation_log_root", operation_log_root_512),
    )


@dataclass(frozen=True, slots=True)
class PaymentMapSlotTransition:
    slot_index: int
    witness_class: str
    benefit_upsert: OrderedMapUpsertWitness = field(repr=False)
    obligation_upsert: OrderedMapUpsertWitness = field(repr=False)
    reserve_upsert: OrderedMapUpsertWitness = field(repr=False)
    payable_upsert: OrderedMapUpsertWitness = field(repr=False)
    operation_log_root_before_512: bytes
    operation_log_root_after_512: bytes

    def __post_init__(self) -> None:
        if type(self.slot_index) is not int or not 0 <= self.slot_index <= 511:
            raise StructuralError("wave1a_payment_map_transition_slot_invalid")
        if self.witness_class not in {"approval", "denial", "cover"}:
            raise StructuralError("wave1a_payment_map_witness_class_invalid")
        expected_domains = (
            BENEFIT_MAP_DOMAIN,
            OBLIGATION_MAP_DOMAIN,
            LEDGER_MAP_DOMAIN,
            LEDGER_MAP_DOMAIN,
        )
        for witness, domain in zip(self.upserts, expected_domains, strict=True):
            try:
                require_ordered_map_upsert(witness)
            except (TypeError, ValueError) as exc:
                raise StructuralError(f"wave1a_payment_map_upsert:{exc}") from exc
            if witness.map_domain != domain:
                raise StructuralError("wave1a_payment_map_upsert_domain_invalid")
        if self.reserve_upsert.root_after != self.payable_upsert.root_before:
            raise StructuralError("wave1a_payment_map_ledger_upsert_chain_invalid")
        if self.witness_class == "approval":
            if self.obligation_upsert.mode != "insert" or self.reserve_upsert.mode != "update":
                raise StructuralError("wave1a_payment_map_approval_shape_invalid")
        elif any(
            witness.mode != "update"
            or witness.value_before_512 != ZERO_512
            or witness.value_after_512 != ZERO_512
            for witness in self.upserts
        ):
            raise StructuralError("wave1a_payment_map_non_economic_shape_invalid")
        _bytes64("operation_log_root_before", self.operation_log_root_before_512)
        _bytes64("operation_log_root_after", self.operation_log_root_after_512)
        if hmac.compare_digest(
            self.operation_log_root_before_512, self.operation_log_root_after_512
        ):
            raise StructuralError("wave1a_payment_map_operation_log_unchanged")

    @property
    def upserts(self) -> tuple[OrderedMapUpsertWitness, ...]:
        return (
            self.benefit_upsert,
            self.obligation_upsert,
            self.reserve_upsert,
            self.payable_upsert,
        )

    @property
    def benefit_key_512(self) -> bytes:
        return self.benefit_upsert.key_512

    @property
    def obligation_key_512(self) -> bytes:
        return self.obligation_upsert.key_512

    @property
    def reserve_key_512(self) -> bytes:
        return self.reserve_upsert.key_512

    @property
    def payable_key_512(self) -> bytes:
        return self.payable_upsert.key_512

    @property
    def benefit_root_before_512(self) -> bytes:
        return self.benefit_upsert.root_before

    @property
    def benefit_root_after_512(self) -> bytes:
        return self.benefit_upsert.root_after

    @property
    def obligation_root_before_512(self) -> bytes:
        return self.obligation_upsert.root_before

    @property
    def obligation_root_after_512(self) -> bytes:
        return self.obligation_upsert.root_after

    @property
    def ledger_root_before_512(self) -> bytes:
        return self.reserve_upsert.root_before

    @property
    def ledger_root_after_512(self) -> bytes:
        return self.payable_upsert.root_after


@dataclass(frozen=True, slots=True)
class AuthenticatedPaymentMapBatchTransition:
    profile_id: str
    before: AuthenticatedPaymentMapState
    after: AuthenticatedPaymentMapState
    transitions: tuple[PaymentMapSlotTransition, ...]
    benefit_batch_witness: OrderedMapBatchWitness = field(repr=False)
    obligation_batch_witness: OrderedMapBatchWitness = field(repr=False)
    ledger_batch_witness: OrderedMapBatchWitness = field(repr=False)
    total_plan_payable_cents: int
    total_debits_cents: int
    total_credits_cents: int
    status: str = PAYMENT_MAP_STATUS

    def __post_init__(self) -> None:
        if self.status != PAYMENT_MAP_STATUS:
            raise StructuralError("wave1a_payment_map_batch_status_invalid")
        if not isinstance(self.before, AuthenticatedPaymentMapState) or not isinstance(
            self.after, AuthenticatedPaymentMapState
        ):
            raise StructuralError("wave1a_payment_map_batch_state_invalid")
        if type(self.transitions) is not tuple or not self.transitions:
            raise StructuralError("wave1a_payment_map_batch_transitions_required")
        if tuple(value.slot_index for value in self.transitions) != tuple(range(len(self.transitions))):
            raise StructuralError("wave1a_payment_map_batch_order_invalid")
        expected_batches = (
            (
                self.benefit_batch_witness,
                self.before.benefit_snapshot,
                self.after.benefit_snapshot,
                tuple(value.benefit_upsert.operation() for value in self.transitions),
            ),
            (
                self.obligation_batch_witness,
                self.before.obligation_snapshot,
                self.after.obligation_snapshot,
                tuple(value.obligation_upsert.operation() for value in self.transitions),
            ),
            (
                self.ledger_batch_witness,
                self.before.ledger_snapshot,
                self.after.ledger_snapshot,
                tuple(
                    operation
                    for value in self.transitions
                    for operation in (
                        value.reserve_upsert.operation(),
                        value.payable_upsert.operation(),
                    )
                ),
            ),
        )
        for witness, before_snapshot, after_snapshot, operations in expected_batches:
            if (
                not isinstance(witness, OrderedMapBatchWitness)
                or witness.root_before != before_snapshot.root
                or witness.root_after != after_snapshot.root
                or witness.operations != operations
            ):
                raise StructuralError("wave1a_payment_map_batch_multiproof_invalid")
        for label, value in (
            ("total_plan_payable", self.total_plan_payable_cents),
            ("total_debits", self.total_debits_cents),
            ("total_credits", self.total_credits_cents),
        ):
            _u64(label, value)
        if not self.total_plan_payable_cents == self.total_debits_cents == self.total_credits_cents:
            raise StructuralError("wave1a_payment_map_batch_conservation_mismatch")
        if self.after.sequence != self.before.sequence + 1:
            raise StructuralError("wave1a_payment_map_batch_sequence_invalid")
        if self.before.next_slot_index != 0 or self.after.next_slot_index != 0:
            raise StructuralError("wave1a_payment_map_batch_cursor_invalid")
        if (
            self.after.epoch != self.before.epoch
            or self.after.strong_settlement_domain_id_512 != self.before.strong_settlement_domain_id_512
            or self.after.asset_registry_root_512 != self.before.asset_registry_root_512
            or self.after.benefit_scope != self.before.benefit_scope
        ):
            raise StructuralError("wave1a_payment_map_batch_authority_drift")
        first = self.transitions[0]
        last = self.transitions[-1]
        if (
            first.benefit_root_before_512 != self.before.benefit_root_512
            or first.obligation_root_before_512 != self.before.obligation_root_512
            or first.ledger_root_before_512 != self.before.private_asset_ledger_root_512
            or first.operation_log_root_before_512 != self.before.operation_log_root_512
            or last.benefit_root_after_512 != self.after.benefit_root_512
            or last.obligation_root_after_512 != self.after.obligation_root_512
            or last.ledger_root_after_512 != self.after.private_asset_ledger_root_512
            or last.operation_log_root_after_512 != self.after.operation_log_root_512
        ):
            raise StructuralError("wave1a_payment_map_batch_endpoint_root_mismatch")
        for left, right in zip(self.transitions, self.transitions[1:], strict=False):
            if (
                left.benefit_root_after_512 != right.benefit_root_before_512
                or left.obligation_root_after_512 != right.obligation_root_before_512
                or left.ledger_root_after_512 != right.ledger_root_before_512
                or left.operation_log_root_after_512 != right.operation_log_root_before_512
            ):
                raise StructuralError("wave1a_payment_map_batch_root_chain_mismatch")
        if hmac.compare_digest(self.before.root(), self.after.root()):
            raise StructuralError("wave1a_payment_map_composite_root_unchanged")

    @property
    def inner_node_hash_count(self) -> int:
        return sum(
            value.inner_node_hash_count
            for value in (
                self.benefit_batch_witness,
                self.obligation_batch_witness,
                self.ledger_batch_witness,
            )
        )


def _checked_add(label: str, left: int, right: int) -> int:
    return _u64(label, left + right)


def _operation_commitment(
    slot: ClaimSlot,
    economics: SlotEconomics,
    upserts: tuple[OrderedMapUpsertWitness, ...],
) -> bytes:
    witness_class = "approval" if economics.decision else (
        "denial" if slot.slot_kind is SlotKind.REAL else "cover"
    )
    return sha3_512(
        payment_operation_preimage(
            slot.slot_index,
            witness_class,
            economics,
            upserts,
        )
    ).digest()


def payment_operation_preimage(
    slot_index: int,
    witness_class: str,
    economics: SlotEconomics,
    upserts: tuple[OrderedMapUpsertWitness, ...],
) -> bytes:
    """Canonical log operation bytes without redundant intermediate roots."""

    if type(slot_index) is not int or not 0 <= slot_index <= 511:
        raise StructuralError("wave1a_payment_map_operation_slot_invalid")
    if witness_class not in {"approval", "denial", "cover"}:
        raise StructuralError("wave1a_payment_map_operation_class_invalid")
    if not isinstance(economics, SlotEconomics) or economics.slot_index != slot_index:
        raise StructuralError("wave1a_payment_map_operation_economics_invalid")
    if type(upserts) is not tuple or len(upserts) != 4:
        raise StructuralError("wave1a_payment_map_operation_upserts_invalid")
    for upsert in upserts:
        try:
            require_ordered_map_upsert(upsert)
        except (TypeError, ValueError) as exc:
            raise StructuralError(f"wave1a_payment_map_operation_upsert:{exc}") from exc
    class_byte = {"approval": b"A", "denial": b"D", "cover": b"C"}[
        witness_class
    ]
    return (
        _OPERATION_DOMAIN
        + slot_index.to_bytes(2, "big")
        + class_byte
        + economics.gross_allowed_cents.to_bytes(4, "big")
        + economics.patient_responsibility_cents.to_bytes(4, "big")
        + economics.plan_payable_cents.to_bytes(4, "big")
        + b"".join(witness.key_512 for witness in upserts)
        + b"".join(
            witness.value_before_512 + witness.value_after_512
            for witness in upserts
        )
    )


def payment_operation_log_preimage(
    root_before_512: bytes,
    sequence: int,
    slot_index: int,
    operation_commitment_512: bytes,
) -> bytes:
    _bytes64("operation_log_root_before", root_before_512)
    _u64("operation_log_sequence", sequence)
    if type(slot_index) is not int or not 0 <= slot_index <= 511:
        raise StructuralError("wave1a_payment_map_operation_slot_invalid")
    _bytes64("operation_commitment", operation_commitment_512)
    return (
        _LOG_DOMAIN
        + root_before_512
        + sequence.to_bytes(8, "big")
        + slot_index.to_bytes(2, "big")
        + operation_commitment_512
    )


def build_authenticated_payment_map_transition(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    economics: BatchEconomics,
    before: AuthenticatedPaymentMapState,
) -> AuthenticatedPaymentMapBatchTransition:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_payment_map_profile_required")
    materialized_slots = tuple(slots)
    if len(materialized_slots) != profile.claim_slots:
        raise StructuralError("wave1a_payment_map_slot_count_mismatch")
    if not isinstance(economics, BatchEconomics) or economics.profile_id != profile.profile_id:
        raise StructuralError("wave1a_payment_map_economics_mismatch")
    if not isinstance(before, AuthenticatedPaymentMapState):
        raise StructuralError("wave1a_payment_map_before_state_required")
    if before.next_slot_index != 0:
        raise StructuralError("wave1a_payment_map_batch_must_start_at_zero")

    benefit = _ordered_builder(BENEFIT_MAP_DOMAIN, snapshot=before.benefit_snapshot)
    obligation = _ordered_builder(OBLIGATION_MAP_DOMAIN, snapshot=before.obligation_snapshot)
    ledger = _ordered_builder(LEDGER_MAP_DOMAIN, snapshot=before.ledger_snapshot)
    log_root = before.operation_log_root_512
    transitions: list[PaymentMapSlotTransition] = []

    for position, (slot, operation) in enumerate(
        zip(materialized_slots, economics.slots, strict=True)
    ):
        if slot.slot_index != position or operation.slot_index != position:
            raise StructuralError("wave1a_payment_map_slot_order_invalid")
        approval = operation.decision == 1
        witness_class = "approval" if approval else (
            "denial" if slot.slot_kind is SlotKind.REAL else "cover"
        )
        if approval:
            benefit_key = member_benefit_key(slot.member_id, benefit_scope=before.benefit_scope)
            obligation_key = provider_obligation_key(slot)
            reserve_key = _PAYER_RESERVE_KEY
            payable_key = provider_payable_key(slot.provider_npi)
            if obligation.get(obligation_key) is not None:
                raise StructuralError("wave1a_payment_map_duplicate_obligation")
            if reserve_key == payable_key:
                raise StructuralError("wave1a_payment_map_ledger_key_collision")
            record_fixed = benefit.get(benefit_key)
            record = BenefitAccumulatorRecord.decode(
                None if record_fixed is None else _benefit_logical(record_fixed)
            )
            authorization_uses = sum(
                int(line.requires_prior_authorization and line.authorization_present)
                for line in slot.service_lines
            )
            benefit_value = _benefit_fixed(
                BenefitAccumulatorRecord(
                    _checked_add("benefit_allowed", record.allowed_cents, operation.gross_allowed_cents),
                    _checked_add(
                        "benefit_patient_responsibility",
                        record.patient_responsibility_cents,
                        operation.patient_responsibility_cents,
                    ),
                    _checked_add("benefit_visits", record.visits, 1),
                    _checked_add(
                        "benefit_authorization_uses",
                        record.authorization_uses,
                        authorization_uses,
                    ),
                )
            )
            obligation_value = _obligation_fixed(operation.plan_payable_cents)
            reserve = _balance(ledger.get(reserve_key), required=True)
            if reserve < operation.payer_reserve_debit_cents:
                raise StructuralError("wave1a_payment_map_reserve_underflow")
            payable = _balance(ledger.get(payable_key))
            reserve_value = _balance_fixed(reserve - operation.payer_reserve_debit_cents)
            payable_value = _balance_fixed(
                _checked_add("provider_payable", payable, operation.provider_payable_credit_cents)
            )
        else:
            scope = before.benefit_scope.commitment_512()
            benefit_key = _dummy_key(
                b"BENEFIT",
                before.strong_settlement_domain_id_512,
                before.epoch,
                scope,
            )
            obligation_key = _dummy_key(
                b"OBLIGATION",
                before.strong_settlement_domain_id_512,
                before.epoch,
                scope,
            )
            reserve_key = _dummy_key(
                b"RESERVE",
                before.strong_settlement_domain_id_512,
                before.epoch,
                scope,
            )
            payable_key = _dummy_key(
                b"PAYABLE",
                before.strong_settlement_domain_id_512,
                before.epoch,
                scope,
            )
            if reserve_key == payable_key:
                raise StructuralError("wave1a_payment_map_dummy_ledger_key_collision")
            benefit_value = obligation_value = reserve_value = payable_value = ZERO_512

        benefit_upsert = _prove(benefit, benefit_key, benefit_value)
        obligation_upsert = _prove(obligation, obligation_key, obligation_value)
        reserve_upsert = _prove(ledger, reserve_key, reserve_value)
        if not approval and any(
            witness.mode != "update"
            for witness in (benefit_upsert, obligation_upsert, reserve_upsert)
        ):
            raise StructuralError("wave1a_payment_map_dummy_leaf_missing")
        if approval and (
            obligation_upsert.mode != "insert" or reserve_upsert.mode != "update"
        ):
            raise StructuralError("wave1a_payment_map_approval_state_shape_invalid")
        _apply(benefit, benefit_upsert)
        _apply(obligation, obligation_upsert)
        _apply(ledger, reserve_upsert)
        payable_upsert = _prove(ledger, payable_key, payable_value)
        if not approval and payable_upsert.mode != "update":
            raise StructuralError("wave1a_payment_map_dummy_leaf_missing")
        _apply(ledger, payable_upsert)

        upserts = (benefit_upsert, obligation_upsert, reserve_upsert, payable_upsert)
        operation_commitment = _operation_commitment(slot, operation, upserts)
        next_log = sha3_512(
            payment_operation_log_preimage(
                log_root,
                before.sequence,
                position,
                operation_commitment,
            )
        ).digest()
        transitions.append(
            PaymentMapSlotTransition(
                position,
                witness_class,
                *upserts,
                log_root,
                next_log,
            )
        )
        log_root = next_log

    after = AuthenticatedPaymentMapState(
        epoch=before.epoch,
        sequence=before.sequence + 1,
        next_slot_index=0,
        strong_settlement_domain_id_512=before.strong_settlement_domain_id_512,
        asset_registry_root_512=before.asset_registry_root_512,
        benefit_scope=before.benefit_scope,
        benefit_snapshot=benefit.snapshot(),
        obligation_snapshot=obligation.snapshot(),
        ledger_snapshot=ledger.snapshot(),
        operation_log_root_512=log_root,
    )
    benefit_batch = build_ordered_map_batch_witness(
        before.benefit_snapshot,
        after.benefit_snapshot,
        tuple(value.benefit_upsert for value in transitions),
    )
    obligation_batch = build_ordered_map_batch_witness(
        before.obligation_snapshot,
        after.obligation_snapshot,
        tuple(value.obligation_upsert for value in transitions),
    )
    ledger_batch = build_ordered_map_batch_witness(
        before.ledger_snapshot,
        after.ledger_snapshot,
        tuple(
            upsert
            for value in transitions
            for upsert in (value.reserve_upsert, value.payable_upsert)
        ),
    )
    return AuthenticatedPaymentMapBatchTransition(
        profile.profile_id,
        before,
        after,
        tuple(transitions),
        benefit_batch,
        obligation_batch,
        ledger_batch,
        economics.total_plan_payable_cents,
        economics.total_debits_cents,
        economics.total_credits_cents,
    )


def verify_authenticated_payment_map_transition(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    economics: BatchEconomics,
    transition: AuthenticatedPaymentMapBatchTransition,
) -> bool:
    if not isinstance(transition, AuthenticatedPaymentMapBatchTransition):
        raise StructuralError("wave1a_payment_map_transition_required")
    observed = build_authenticated_payment_map_transition(
        profile, slots, economics, transition.before
    )
    if observed != transition:
        raise StructuralError("wave1a_payment_map_recomputation_mismatch")
    return True


__all__ = [
    "AuthenticatedMapEntry",
    "AuthenticatedPaymentMapBatchTransition",
    "AuthenticatedPaymentMapState",
    "BENEFIT_MAP_DOMAIN",
    "BenefitAccumulatorRecord",
    "BenefitScopeV1",
    "LEDGER_MAP_DOMAIN",
    "OBLIGATION_MAP_DOMAIN",
    "PAYMENT_MAP_STATUS",
    "PaymentMapSlotTransition",
    "SPARSE_MAP_DEPTH",
    "build_authenticated_payment_map_transition",
    "build_payment_map_state",
    "member_benefit_key",
    "member_benefit_key_preimage",
    "payer_reserve_key_preimage",
    "payer_reserve_key",
    "payment_dummy_key_preimage",
    "payment_map_key_preimage",
    "provider_obligation_key",
    "provider_obligation_key_preimage",
    "provider_payable_key",
    "provider_payable_key_preimage",
    "payment_operation_log_preimage",
    "payment_operation_preimage",
    "verify_authenticated_payment_map_transition",
]
