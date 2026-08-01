"""Synthetic structural payment-state framing; not authenticated map updates."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import os
from typing import Final, Sequence

from .payment import SlotEconomics
from .semantics import StructuralError


REFERENCE_STATUS: Final[str] = (
    "SYNTHETIC_R25_PAYMENT_STATE_FRAMING_NO_AUTHENTICATED_MAP_TRANSITION"
)
SYNTHETIC_PAYMENT_STATE_ENABLE_ENV: Final[str] = (
    "BL_ALLOW_SYNTHETIC_R25_PAYMENT_STATE_REFERENCE"
)
PAYMENT_STATE_VERSION: Final[int] = 1
PAYMENT_STATE_MAGIC: Final[bytes] = b"BLPQPSR0"
PAYMENT_STATE_ENCODED_LENGTH: Final[int] = 350
_PAYMENT_STATE_ROOT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PAYMENT-STATE/ROOT/REFERENCE/v0"
)
_OPERATION_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PAYMENT-OPERATION/REFERENCE/v0"
)
_OPERATION_LOG_DOMAIN: Final[bytes] = (
    b"BL/PQ512/PAYMENT-OPLOG-APPEND/REFERENCE/v0"
)
_UINT64_MAX: Final[int] = (1 << 64) - 1
_SYNTHETIC_ENVS: Final[frozenset[str]] = frozenset(
    {"local", "test", "unit", "ci"}
)


def require_synthetic_payment_state_enabled() -> None:
    if (
        os.environ.get("BL_ENV") not in _SYNTHETIC_ENVS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_PAYMENT_STATE_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "synthetic_r25_payment_state_forbidden:"
            "requires_local_test_env_and_explicit_dev_flags"
        )


def _exact_uint(label: str, value: object, maximum: int, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise StructuralError(f"r25_payment_state_{label}_out_of_range")
    if nonzero and value == 0:
        raise StructuralError(f"r25_payment_state_{label}_must_be_nonzero")
    return value


def _root(label: str, value: object) -> bytes:
    if type(value) is not bytes:
        raise StructuralError(f"r25_payment_state_{label}_must_be_bytes")
    if len(value) != 64:
        raise StructuralError(f"r25_payment_state_{label}_length_invalid")
    if not any(value):
        raise StructuralError(f"r25_payment_state_{label}_must_be_nonzero")
    return value


@dataclass(frozen=True, slots=True)
class StrongPaymentStateV1Reference:
    version: int
    epoch: int
    sequence: int
    asset_registry_root_512: bytes
    benefit_accumulator_root_512: bytes
    obligation_root_512: bytes
    private_asset_ledger_root_512: bytes
    operation_log_root_512: bytes
    reference_status: str = REFERENCE_STATUS

    def __post_init__(self) -> None:
        require_synthetic_payment_state_enabled()
        if self.reference_status != REFERENCE_STATUS:
            raise StructuralError("r25_payment_state_reference_status_invalid")
        if type(self.version) is not int or self.version != PAYMENT_STATE_VERSION:
            raise StructuralError("r25_payment_state_version_invalid")
        _exact_uint("epoch", self.epoch, _UINT64_MAX, nonzero=True)
        _exact_uint("sequence", self.sequence, _UINT64_MAX)
        for label, value in (
            ("asset_registry_root", self.asset_registry_root_512),
            ("benefit_accumulator_root", self.benefit_accumulator_root_512),
            ("obligation_root", self.obligation_root_512),
            ("private_asset_ledger_root", self.private_asset_ledger_root_512),
            ("operation_log_root", self.operation_log_root_512),
        ):
            _root(label, value)


@dataclass(frozen=True, slots=True)
class PaymentStateRootPairReference:
    root_before_512: bytes
    root_after_512: bytes

    def __post_init__(self) -> None:
        require_synthetic_payment_state_enabled()
        before = _root("composite_root_before", self.root_before_512)
        after = _root("composite_root_after", self.root_after_512)
        if before == after:
            raise StructuralError("r25_payment_state_composite_root_unchanged")


def encode_reference_payment_state(state: StrongPaymentStateV1Reference) -> bytes:
    require_synthetic_payment_state_enabled()
    if not isinstance(state, StrongPaymentStateV1Reference):
        raise StructuralError("r25_payment_state_type_invalid")
    encoded = b"".join(
        (
            PAYMENT_STATE_MAGIC,
            PAYMENT_STATE_ENCODED_LENGTH.to_bytes(4, "big"),
            state.version.to_bytes(2, "big"),
            state.epoch.to_bytes(8, "big"),
            state.sequence.to_bytes(8, "big"),
            state.asset_registry_root_512,
            state.benefit_accumulator_root_512,
            state.obligation_root_512,
            state.private_asset_ledger_root_512,
            state.operation_log_root_512,
        )
    )
    if len(encoded) != PAYMENT_STATE_ENCODED_LENGTH:
        raise AssertionError("r25_payment_state_internal_length_mismatch")
    return encoded


def decode_reference_payment_state(encoded: bytes) -> StrongPaymentStateV1Reference:
    require_synthetic_payment_state_enabled()
    if type(encoded) is not bytes:
        raise StructuralError("r25_payment_state_encoding_must_be_bytes")
    if len(encoded) != PAYMENT_STATE_ENCODED_LENGTH:
        raise StructuralError("r25_payment_state_encoding_length_mismatch")
    if encoded[:8] != PAYMENT_STATE_MAGIC:
        raise StructuralError("r25_payment_state_magic_mismatch")
    if int.from_bytes(encoded[8:12], "big") != PAYMENT_STATE_ENCODED_LENGTH:
        raise StructuralError("r25_payment_state_declared_length_mismatch")
    cursor = 12

    def take(length: int) -> bytes:
        nonlocal cursor
        value = encoded[cursor : cursor + length]
        cursor += length
        return value

    state = StrongPaymentStateV1Reference(
        version=int.from_bytes(take(2), "big"),
        epoch=int.from_bytes(take(8), "big"),
        sequence=int.from_bytes(take(8), "big"),
        asset_registry_root_512=take(64),
        benefit_accumulator_root_512=take(64),
        obligation_root_512=take(64),
        private_asset_ledger_root_512=take(64),
        operation_log_root_512=take(64),
    )
    if cursor != len(encoded) or encode_reference_payment_state(state) != encoded:
        raise StructuralError("r25_payment_state_reencoding_mismatch")
    return state


def reference_payment_state_root(state: StrongPaymentStateV1Reference) -> bytes:
    encoded = encode_reference_payment_state(state)
    preimage = b"".join(
        (
            len(_PAYMENT_STATE_ROOT_DOMAIN).to_bytes(2, "big"),
            _PAYMENT_STATE_ROOT_DOMAIN,
            len(encoded).to_bytes(4, "big"),
            encoded,
        )
    )
    return sha3_512(preimage).digest()


def reference_slot_operation_commitment(economics: SlotEconomics) -> bytes:
    require_synthetic_payment_state_enabled()
    if not isinstance(economics, SlotEconomics):
        raise StructuralError("r25_payment_operation_type_invalid")
    kind = b"R" if economics.slot_kind.value == "REAL" else b"C"
    payload = b"".join(
        (
            _OPERATION_DOMAIN,
            economics.slot_index.to_bytes(2, "big"),
            kind,
            economics.decision.to_bytes(1, "big"),
            economics.gross_allowed_cents.to_bytes(4, "big"),
            economics.patient_responsibility_cents.to_bytes(4, "big"),
            economics.plan_payable_cents.to_bytes(4, "big"),
            economics.payer_reserve_debit_cents.to_bytes(4, "big"),
            economics.provider_payable_credit_cents.to_bytes(4, "big"),
        )
    )
    return sha3_512(payload).digest()


def append_reference_operation_log(
    previous_root_512: bytes,
    economics: Sequence[SlotEconomics],
    *,
    expected_count: int,
) -> bytes:
    require_synthetic_payment_state_enabled()
    accumulator = _root("operation_log_root_before", previous_root_512)
    _exact_uint("operation_count", expected_count, 512, nonzero=True)
    if type(economics) is not tuple or len(economics) != expected_count:
        raise StructuralError("r25_payment_operation_count_mismatch")
    for expected_position, operation in enumerate(economics):
        if not isinstance(operation, SlotEconomics):
            raise StructuralError("r25_payment_operation_type_invalid")
        if operation.slot_index != expected_position:
            raise StructuralError("r25_payment_operation_order_invalid")
        commitment = reference_slot_operation_commitment(operation)
        accumulator = sha3_512(
            _OPERATION_LOG_DOMAIN
            + accumulator
            + expected_position.to_bytes(2, "big")
            + commitment
        ).digest()
    if accumulator == previous_root_512:
        raise AssertionError("r25_payment_operation_log_unchanged")
    return accumulator


def build_reference_payment_root_pair(
    before: StrongPaymentStateV1Reference,
    after: StrongPaymentStateV1Reference,
) -> PaymentStateRootPairReference:
    require_synthetic_payment_state_enabled()
    if not isinstance(before, StrongPaymentStateV1Reference) or not isinstance(
        after, StrongPaymentStateV1Reference
    ):
        raise StructuralError("r25_payment_state_pair_type_invalid")
    if before.epoch != after.epoch:
        raise StructuralError("r25_payment_state_epoch_mismatch")
    if before.sequence == _UINT64_MAX or after.sequence != before.sequence + 1:
        raise StructuralError("r25_payment_state_sequence_transition_invalid")
    if before.operation_log_root_512 == after.operation_log_root_512:
        raise StructuralError("r25_payment_state_operation_log_unchanged")
    return PaymentStateRootPairReference(
        reference_payment_state_root(before),
        reference_payment_state_root(after),
    )
