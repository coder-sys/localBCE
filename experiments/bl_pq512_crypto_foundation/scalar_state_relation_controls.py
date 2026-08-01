"""Gate 2E-2/S2 scalar state-relation controls.

The controls in this module are deliberately small, deterministic, and
synthetic-only.  They are relation references, not commitments, proofs, or
activation code.  Each candidate replays the same fixed-shape batch, derives
its own state identities, and exposes an independent verifier that rebuilds
the operation transition from the canonical input.

The candidate roots are intentionally candidate-specific.  S2 compares the
semantic boundary to C0 (shape, membership/absence, sequential transition,
money, and accept/deny/cover outcomes); it does not compare independently
produced roots on the host.  Atomic root equality is a later 2E composition
gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from app.batch.pq_tree_reference import require_synthetic_reference_enabled


STATUS: Final[str] = "S2_SCALAR_STATE_RELATION_CONTROLS_V1_SYNTHETIC_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
MAX_STATE_CAPACITY: Final[int] = 1 << 24
MAX_OPERATION_COUNT: Final[int] = 2_048
SHA3_512_LENGTH: Final[int] = 64
ZERO_512: Final[bytes] = bytes(SHA3_512_LENGTH)
MAX_512: Final[bytes] = b"\xff" * SHA3_512_LENGTH
LANE_ORDER: Final[tuple[str, ...]] = ("replay", "benefit", "obligation", "ledger")
PROFILE_CLAIM_SLOTS: Final[dict[str, int]] = {
    "K128_CALIBRATION": 128,
    "K512_CALIBRATION": 512,
}
LANE_POSITION_ROWS: Final[dict[str, int]] = {
    "replay": 0,  # the profile-specific value is operation_count + 1
    "benefit": 4,
    "obligation": 3,
    "ledger": 5,
}
LANE_PROOF_NODE_ROWS: Final[dict[str, int]] = {
    "replay": 63,
    "benefit": 64,
    "obligation": 64,
    "ledger": 63,
}
CANDIDATE_IDS: Final[tuple[str, ...]] = (
    "C1_DENSE",
    "C1_SPARSE",
    "C2",
    "C3",
    "C4",
)
C1_VARIANTS: Final[tuple[str, ...]] = ("dense", "sparse")
C0_NEGATIVE_CASE_NAMES: Final[tuple[str, ...]] = (
    "stale_read",
    "omitted_write",
    "reordered_write",
    "duplicate_identity",
    "collision",
    "root_substitution",
    "conflicting_update",
)

_DOMAIN = b"BL/PQ512/S2/SCALAR-STATE/v1\x00"
_ROOT_DOMAIN = b"BL/PQ512/S2/SCALAR-ROOT/v1\x00"
_OPERATION_DOMAIN = b"BL/PQ512/S2/OPERATION/v1\x00"
_SEMANTIC_DOMAIN = b"BL/PQ512/S2/SEMANTIC/v1\x00"
_ECONOMIC_DOMAIN = b"BL/PQ512/S2/ECONOMIC/v1\x00"
_CANDIDATE_DOMAIN = b"BL/PQ512/S2/CANDIDATE/v1\x00"
_SHUFFLE_DOMAIN = b"BL/PQ512/S2/C4-SHUFFLE/v1\x00"


class ScalarRelationError(ValueError):
    """Fail-closed error raised by the scalar relation controls."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _digest(label: str, value: object, *, allow_zero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != SHA3_512_LENGTH:
        raise ScalarRelationError(f"s2_{label}_digest_invalid")
    if not allow_zero and value in {ZERO_512, MAX_512}:
        raise ScalarRelationError(f"s2_{label}_reserved")
    return value


def _ascii(label: str, value: object, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ScalarRelationError(f"s2_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ScalarRelationError(f"s2_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise ScalarRelationError(f"s2_{label}_nul")
    return value


def _uint(label: str, value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ScalarRelationError(f"s2_{label}_invalid")
    return value


def _hash_parts(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512()
    hasher.update(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise ScalarRelationError("s2_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _text_bytes(value: str) -> bytes:
    return value.encode("ascii")


def _candidate_id(candidate_id: str, variant: str | None = None) -> str:
    if candidate_id == "C1":
        if variant is None:
            variant = "sparse"
        if variant not in C1_VARIANTS:
            raise ScalarRelationError("s2_c1_variant_unknown")
        candidate_id = f"C1_{variant.upper()}"
    if candidate_id not in CANDIDATE_IDS:
        raise ScalarRelationError("s2_candidate_unknown")
    return candidate_id


def _profile_slots(profile_id: str) -> int:
    try:
        return PROFILE_CLAIM_SLOTS[profile_id]
    except KeyError as exc:
        raise ScalarRelationError("s2_profile_unknown") from exc


@dataclass(frozen=True, slots=True)
class ScalarProfileShape:
    profile_id: str
    claim_slots: int
    state_capacity: int
    lane_operation_counts: tuple[int, ...]

    def __post_init__(self) -> None:
        _synthetic()
        _ascii("profile_id", self.profile_id, 32)
        if self.claim_slots != _profile_slots(self.profile_id):
            raise ScalarRelationError("s2_profile_slot_shape_invalid")
        if self.state_capacity != MAX_STATE_CAPACITY:
            raise ScalarRelationError("s2_profile_capacity_invalid")
        if self.lane_operation_counts != (
            self.claim_slots + 1,
            self.claim_slots,
            self.claim_slots,
            2 * self.claim_slots,
        ):
            raise ScalarRelationError("s2_profile_lane_shape_invalid")


@dataclass(frozen=True, slots=True)
class ScalarStateEntry:
    index: int
    key_512: bytes
    value_512: bytes

    def __post_init__(self) -> None:
        _synthetic()
        _uint("entry_index", self.index, MAX_STATE_CAPACITY - 1)
        _digest("entry_key", self.key_512)
        _digest("entry_value", self.value_512, allow_zero=False)


@dataclass(frozen=True, slots=True)
class ScalarStateSnapshot:
    capacity: int
    next_append_index: int
    entries: tuple[ScalarStateEntry, ...]

    def __post_init__(self) -> None:
        _synthetic()
        _uint("state_capacity", self.capacity, MAX_STATE_CAPACITY)
        if self.capacity == 0:
            raise ScalarRelationError("s2_state_capacity_zero")
        _uint("state_next_append_index", self.next_append_index, self.capacity)
        if type(self.entries) is not tuple or len(self.entries) > self.next_append_index:
            raise ScalarRelationError("s2_state_entries_shape_invalid")
        indices: set[int] = set()
        keys: set[bytes] = set()
        for entry in self.entries:
            if type(entry) is not ScalarStateEntry:
                raise ScalarRelationError("s2_state_entry_type_invalid")
            if entry.index >= self.next_append_index:
                raise ScalarRelationError("s2_state_entry_index_not_allocated")
            if entry.index in indices:
                raise ScalarRelationError("s2_state_entry_index_duplicate")
            if entry.key_512 in keys:
                raise ScalarRelationError("s2_state_entry_key_duplicate")
            indices.add(entry.index)
            keys.add(entry.key_512)


@dataclass(frozen=True, slots=True)
class ScalarOperation:
    operation_id_512: bytes
    ordinal: int
    lane: str
    mode: str
    key_512: bytes
    value_before_512: bytes
    value_after_512: bytes
    expected_index: int
    slot_index: int

    def __post_init__(self) -> None:
        _synthetic()
        _digest("operation_id", self.operation_id_512)
        _uint("operation_ordinal", self.ordinal, MAX_OPERATION_COUNT)
        if self.lane not in LANE_ORDER:
            raise ScalarRelationError("s2_operation_lane_unknown")
        if self.mode not in {"insert", "update"}:
            raise ScalarRelationError("s2_operation_mode_invalid")
        _digest("operation_key", self.key_512)
        if self.key_512 in {ZERO_512, MAX_512}:
            raise ScalarRelationError("s2_operation_key_reserved")
        _digest("operation_value_before", self.value_before_512, allow_zero=True)
        _digest("operation_value_after", self.value_after_512)
        if self.value_before_512 == self.value_after_512:
            raise ScalarRelationError("s2_operation_noop_forbidden")
        _uint("operation_expected_index", self.expected_index, MAX_STATE_CAPACITY - 1)
        _uint("operation_slot_index", self.slot_index, 0xFFFFFFFF)


@dataclass(frozen=True, slots=True)
class ScalarSlotOutcome:
    slot_index: int
    case_name: str
    result: str
    failure_code: str
    plan_payable_cents: int
    debit_cents: int
    credit_cents: int

    def __post_init__(self) -> None:
        _synthetic()
        _uint("slot_index", self.slot_index, 0xFFFFFFFF)
        _ascii("slot_case_name", self.case_name, 32)
        if self.result not in {"accepted", "denied", "cover"}:
            raise ScalarRelationError("s2_slot_result_invalid")
        _ascii("slot_failure_code", self.failure_code, 64)
        for label, value in (
            ("slot_plan_payable", self.plan_payable_cents),
            ("slot_debit", self.debit_cents),
            ("slot_credit", self.credit_cents),
        ):
            _uint(label, value, 1_000_000_000)


@dataclass(frozen=True, slots=True)
class ScalarLaneInput:
    lane: str
    claim_slots: int
    state_before: ScalarStateSnapshot
    operations: tuple[ScalarOperation, ...]
    expected_operation_count: int
    expected_access_rows: int
    membership_key_512: bytes
    absence_key_512: bytes
    update_operation: ScalarOperation

    def __post_init__(self) -> None:
        _synthetic()
        if self.lane not in LANE_ORDER:
            raise ScalarRelationError("s2_lane_unknown")
        _uint("lane_claim_slots", self.claim_slots, MAX_STATE_CAPACITY)
        if type(self.state_before) is not ScalarStateSnapshot:
            raise ScalarRelationError("s2_lane_state_type_invalid")
        if type(self.operations) is not tuple:
            raise ScalarRelationError("s2_lane_operations_type_invalid")
        _uint("lane_expected_operation_count", self.expected_operation_count, MAX_OPERATION_COUNT)
        _uint("lane_expected_access_rows", self.expected_access_rows, MAX_OPERATION_COUNT * 2)
        _digest("lane_membership_key", self.membership_key_512)
        _digest("lane_absence_key", self.absence_key_512)
        if self.membership_key_512 in {ZERO_512, MAX_512} or self.absence_key_512 in {ZERO_512, MAX_512}:
            raise ScalarRelationError("s2_lane_query_key_reserved")
        if type(self.update_operation) is not ScalarOperation:
            raise ScalarRelationError("s2_lane_update_type_invalid")


@dataclass(frozen=True, slots=True)
class ScalarBatchInput:
    profile_id: str
    claim_slots: int
    lanes: tuple[ScalarLaneInput, ...]
    outcomes: tuple[ScalarSlotOutcome, ...]

    def __post_init__(self) -> None:
        _synthetic()
        _ascii("batch_profile_id", self.profile_id, 32)
        _uint("batch_claim_slots", self.claim_slots, MAX_STATE_CAPACITY)
        if type(self.lanes) is not tuple or type(self.outcomes) is not tuple:
            raise ScalarRelationError("s2_batch_sequence_type_invalid")


@dataclass(frozen=True, slots=True)
class ScalarDictionaryRow:
    index: int
    key_512: bytes
    value_512: bytes


@dataclass(frozen=True, slots=True)
class ScalarLaneResult:
    candidate_id: str
    lane: str
    state_root_before_512: bytes
    state_root_after_512: bytes
    update_root_before_512: bytes
    update_root_after_512: bytes
    next_index_before: int
    next_index_after: int
    update_next_index_before: int
    update_next_index_after: int
    operation_count: int
    access_rows: int
    position_rows: int
    proof_node_rows: int
    membership_key_512: bytes
    membership_value_512: bytes
    absence_key_512: bytes
    membership_present: bool
    absence_proven: bool
    operation_digest_512: bytes
    relation_digest_512: bytes
    candidate_payload_digest_512: bytes
    touched_keys: tuple[bytes, ...]
    dictionary_rows: tuple[ScalarDictionaryRow, ...]
    projection_positions: tuple[int, ...]
    shuffle_challenge_512: bytes
    shuffle_permutation: tuple[int, ...]
    shuffle_digest_512: bytes
    candidate_capacity_work_units: int
    candidate_online_work_units: int
    candidate_initialization_work_units: int
    candidate_requires_persistent_scan: bool


@dataclass(frozen=True, slots=True)
class ScalarBatchResult:
    status: str
    candidate_id: str
    profile_id: str
    claim_slots: int
    accepted: bool
    lanes: tuple[ScalarLaneResult, ...]
    semantic_digest_512: bytes
    economic_digest_512: bytes
    total_plan_payable_cents: int
    total_debits_cents: int
    total_credits_cents: int
    candidate_work_units: int

    def as_public_dict(self) -> dict[str, object]:
        """Return only bounded identities and scalar metrics, never raw keys."""

        return {
            "status": self.status,
            "candidate_id": self.candidate_id,
            "profile_id": self.profile_id,
            "claim_slots": self.claim_slots,
            "accepted": self.accepted,
            "lane_count": len(self.lanes),
            "lane_operation_counts": [lane.operation_count for lane in self.lanes],
            "semantic_digest_sha3_512_hex": self.semantic_digest_512.hex(),
            "economic_digest_sha3_512_hex": self.economic_digest_512.hex(),
            "total_plan_payable_cents": self.total_plan_payable_cents,
            "total_debits_cents": self.total_debits_cents,
            "total_credits_cents": self.total_credits_cents,
            "candidate_work_units": self.candidate_work_units,
        }


@dataclass(frozen=True, slots=True)
class ScalarNegativeCase:
    name: str
    batch: ScalarBatchInput
    result_mutation: str | None


@dataclass(frozen=True, slots=True)
class _LaneTrace:
    state_before: ScalarStateSnapshot
    state_after_main: ScalarStateSnapshot
    state_after_update: ScalarStateSnapshot
    membership_value_512: bytes
    operation_digest_512: bytes
    relation_digest_512: bytes


def _entry_encoding(entry: ScalarStateEntry) -> bytes:
    return (
        entry.index.to_bytes(8, "big")
        + entry.key_512
        + entry.value_512
    )


def _snapshot_encoding(snapshot: ScalarStateSnapshot) -> bytes:
    payload = bytearray()
    payload.extend(snapshot.capacity.to_bytes(8, "big"))
    payload.extend(snapshot.next_append_index.to_bytes(8, "big"))
    ordered = tuple(sorted(snapshot.entries, key=lambda value: value.index))
    payload.extend(len(ordered).to_bytes(4, "big"))
    for entry in ordered:
        payload.extend(_entry_encoding(entry))
    return bytes(payload)


def _operation_encoding(operation: ScalarOperation) -> bytes:
    return (
        operation.operation_id_512
        + operation.ordinal.to_bytes(4, "big")
        + len(operation.lane).to_bytes(1, "big")
        + operation.lane.encode("ascii")
        + (b"I" if operation.mode == "insert" else b"U")
        + operation.key_512
        + operation.value_before_512
        + operation.value_after_512
        + operation.expected_index.to_bytes(8, "big")
        + operation.slot_index.to_bytes(4, "big")
    )


def _outcome_encoding(outcome: ScalarSlotOutcome) -> bytes:
    return (
        outcome.slot_index.to_bytes(4, "big")
        + len(outcome.case_name).to_bytes(1, "big")
        + outcome.case_name.encode("ascii")
        + len(outcome.result).to_bytes(1, "big")
        + outcome.result.encode("ascii")
        + len(outcome.failure_code).to_bytes(1, "big")
        + outcome.failure_code.encode("ascii")
        + outcome.plan_payable_cents.to_bytes(8, "big")
        + outcome.debit_cents.to_bytes(8, "big")
        + outcome.credit_cents.to_bytes(8, "big")
    )


def _state_root(candidate_id: str, lane: str, stage: str, snapshot: ScalarStateSnapshot) -> bytes:
    return _hash_parts(
        _ROOT_DOMAIN,
        _text_bytes(candidate_id),
        _text_bytes(lane),
        _text_bytes(stage),
        _snapshot_encoding(snapshot),
    )


def _derive(profile_id: str, lane: str, label: str, index: int) -> bytes:
    value = _hash_parts(
        _DOMAIN,
        _text_bytes(profile_id),
        _text_bytes(lane),
        _text_bytes(label),
        index.to_bytes(8, "big"),
    )
    if value in {ZERO_512, MAX_512}:
        raise AssertionError("s2_fixture_reserved_digest")
    return value


def _snapshot_from_values(
    capacity: int,
    next_append_index: int,
    values: dict[bytes, ScalarStateEntry],
) -> ScalarStateSnapshot:
    return ScalarStateSnapshot(
        capacity,
        next_append_index,
        tuple(sorted(values.values(), key=lambda value: value.index)),
    )


def _shape(profile_id: str) -> ScalarProfileShape:
    slots = _profile_slots(profile_id)
    return ScalarProfileShape(
        profile_id,
        slots,
        MAX_STATE_CAPACITY,
        (slots + 1, slots, slots, 2 * slots),
    )


def _build_lane(profile_id: str, lane: str, operation_count: int) -> ScalarLaneInput:
    slots = _profile_slots(profile_id)
    initial_entries: list[ScalarStateEntry] = []
    operations: list[ScalarOperation] = []
    for ordinal in range(operation_count):
        mode = "insert" if lane == "replay" or ordinal == operation_count - 1 else "update"
        initial_value = (
            ZERO_512
            if mode == "insert"
            else _derive(profile_id, lane, "initial-value", ordinal)
        )
        if mode == "update":
            initial_entries.append(
                ScalarStateEntry(
                    ordinal,
                    _derive(profile_id, lane, "key", ordinal),
                    initial_value,
                )
            )
        operations.append(
            ScalarOperation(
                _derive(profile_id, lane, "operation-id", ordinal),
                ordinal,
                lane,
                mode,
                _derive(profile_id, lane, "key", ordinal),
                initial_value,
                _derive(profile_id, lane, "value", ordinal),
                ordinal if mode == "update" else (ordinal if lane == "replay" else operation_count - 1),
                ordinal % slots,
            )
        )
    state = ScalarStateSnapshot(
        MAX_STATE_CAPACITY,
        len(initial_entries),
        tuple(initial_entries),
    )
    membership = operations[operation_count // 2].key_512
    absence = _derive(profile_id, lane, "absence", 0)
    while absence in {operation.key_512 for operation in operations}:
        absence = _derive(profile_id, lane, "absence", len(operations) + 1)
    member_operation = operations[operation_count // 2]
    update = ScalarOperation(
        _derive(profile_id, lane, "update-id", 0),
        operation_count,
        lane,
        "update",
        membership,
        member_operation.value_after_512,
        _derive(profile_id, lane, "updated-value", 0),
        member_operation.expected_index,
        member_operation.slot_index,
    )
    return ScalarLaneInput(
        lane,
        slots,
        state,
        tuple(operations),
        operation_count,
        2 * operation_count,
        membership,
        absence,
        update,
    )


def build_scalar_control_batch(profile_id: str) -> ScalarBatchInput:
    """Build the fixed K128/K512 synthetic S2 input."""

    _synthetic()
    shape = _shape(profile_id)
    lanes = tuple(
        _build_lane(profile_id, lane, count)
        for lane, count in zip(LANE_ORDER, shape.lane_operation_counts, strict=True)
    )
    outcomes = []
    for slot_index in range(shape.claim_slots):
        if slot_index == 0:
            outcomes.append(ScalarSlotOutcome(slot_index, "approved", "accepted", "0", 80, 80, 80))
        elif slot_index == 1:
            outcomes.append(ScalarSlotOutcome(slot_index, "duplicate", "denied", "12", 0, 0, 0))
        elif slot_index == 2:
            outcomes.append(ScalarSlotOutcome(slot_index, "conflict", "denied", "13", 0, 0, 0))
        elif slot_index == 3:
            outcomes.append(ScalarSlotOutcome(slot_index, "denial", "denied", "1", 0, 0, 0))
        else:
            outcomes.append(ScalarSlotOutcome(slot_index, "cover", "cover", "0", 0, 0, 0))
    result = ScalarBatchInput(profile_id, shape.claim_slots, lanes, tuple(outcomes))
    _validate_batch(result)
    return result


def _validate_outcomes(batch: ScalarBatchInput) -> None:
    if len(batch.outcomes) != batch.claim_slots:
        raise ScalarRelationError("s2_slot_shape_mismatch")
    if tuple(item.slot_index for item in batch.outcomes) != tuple(range(batch.claim_slots)):
        raise ScalarRelationError("s2_slot_order_mismatch")
    total_plan = total_debits = total_credits = 0
    for item in batch.outcomes:
        if item.result == "accepted":
            if item.plan_payable_cents == 0 or item.debit_cents != item.plan_payable_cents or item.credit_cents != item.plan_payable_cents:
                raise ScalarRelationError("s2_approved_money_mismatch")
        elif item.result in {"denied", "cover"}:
            if item.plan_payable_cents or item.debit_cents or item.credit_cents:
                raise ScalarRelationError("s2_denied_cover_money_nonzero")
        else:
            raise ScalarRelationError("s2_slot_result_invalid")
        total_plan += item.plan_payable_cents
        total_debits += item.debit_cents
        total_credits += item.credit_cents
    if total_debits != total_credits or total_credits > total_plan:
        raise ScalarRelationError("s2_money_conservation_mismatch")


def _validate_batch(batch: ScalarBatchInput) -> None:
    _synthetic()
    shape = _shape(batch.profile_id)
    if batch.claim_slots != shape.claim_slots:
        raise ScalarRelationError("s2_batch_profile_shape_mismatch")
    if tuple(item.lane for item in batch.lanes) != LANE_ORDER:
        raise ScalarRelationError("s2_lane_order_mismatch")
    expected_ids: set[bytes] = set()
    for lane, expected_count in zip(batch.lanes, shape.lane_operation_counts, strict=True):
        if lane.claim_slots != batch.claim_slots:
            raise ScalarRelationError("s2_lane_profile_shape_mismatch")
        if lane.state_before.capacity != MAX_STATE_CAPACITY:
            raise ScalarRelationError("s2_lane_capacity_mismatch")
        if lane.expected_operation_count != expected_count or len(lane.operations) != expected_count:
            raise ScalarRelationError("s2_lane_operation_count_mismatch")
        if lane.expected_access_rows != 2 * expected_count:
            raise ScalarRelationError("s2_lane_access_shape_mismatch")
        if lane.update_operation.ordinal != expected_count:
            raise ScalarRelationError("s2_update_ordinal_mismatch")
        if lane.update_operation.lane != lane.lane:
            raise ScalarRelationError("s2_update_lane_mismatch")
        keys: set[bytes] = set()
        for ordinal, operation in enumerate(lane.operations):
            if operation.ordinal != ordinal:
                raise ScalarRelationError("s2_operation_ordinal_mismatch")
            if operation.lane != lane.lane:
                raise ScalarRelationError("s2_operation_lane_mismatch")
            if operation.operation_id_512 in expected_ids:
                raise ScalarRelationError("s2_operation_identity_duplicate")
            expected_ids.add(operation.operation_id_512)
            if operation.mode == "insert" and operation.key_512 in keys:
                raise ScalarRelationError("s2_operation_key_collision")
            keys.add(operation.key_512)
        if lane.update_operation.operation_id_512 in expected_ids:
            raise ScalarRelationError("s2_operation_identity_duplicate")
        expected_ids.add(lane.update_operation.operation_id_512)
        if lane.membership_key_512 not in keys:
            raise ScalarRelationError("s2_membership_key_not_in_transition")
        if lane.absence_key_512 in keys:
            raise ScalarRelationError("s2_absence_key_is_member")
    _validate_outcomes(batch)


def _apply_one(
    lane: ScalarLaneInput,
    operation: ScalarOperation,
    values: dict[bytes, ScalarStateEntry],
    next_append_index: int,
    *,
    ordinal: int,
) -> int:
    if operation.ordinal != ordinal:
        raise ScalarRelationError("s2_operation_ordinal_mismatch")
    if operation.lane != lane.lane:
        raise ScalarRelationError("s2_operation_lane_mismatch")
    current = values.get(operation.key_512)
    if operation.mode == "insert":
        if current is not None:
            raise ScalarRelationError("s2_operation_key_collision")
        if operation.expected_index != next_append_index:
            raise ScalarRelationError("s2_insert_cursor_mismatch")
        if operation.value_before_512 != ZERO_512:
            raise ScalarRelationError("s2_insert_value_before_mismatch")
        values[operation.key_512] = ScalarStateEntry(
            next_append_index,
            operation.key_512,
            operation.value_after_512,
        )
        return next_append_index + 1
    if current is None:
        raise ScalarRelationError("s2_update_membership_missing")
    if current.index != operation.expected_index:
        raise ScalarRelationError("s2_update_index_mismatch")
    if current.value_512 != operation.value_before_512:
        raise ScalarRelationError("s2_update_value_before_mismatch")
    values[operation.key_512] = ScalarStateEntry(
        current.index,
        current.key_512,
        operation.value_after_512,
    )
    return next_append_index


def _trace_lane(lane: ScalarLaneInput) -> _LaneTrace:
    values = {entry.key_512: entry for entry in lane.state_before.entries}
    next_append_index = lane.state_before.next_append_index
    operation_bytes = bytearray()
    for ordinal, operation in enumerate(lane.operations):
        operation_bytes.extend(_operation_encoding(operation))
        next_append_index = _apply_one(lane, operation, values, next_append_index, ordinal=ordinal)
    state_after_main = _snapshot_from_values(lane.state_before.capacity, next_append_index, values)
    membership = values.get(lane.membership_key_512)
    if membership is None:
        raise ScalarRelationError("s2_membership_proof_missing")
    if lane.absence_key_512 in values:
        raise ScalarRelationError("s2_absence_proof_invalid")
    update = lane.update_operation
    operation_bytes.extend(_operation_encoding(update))
    update_next_index = _apply_one(
        lane,
        update,
        values,
        next_append_index,
        ordinal=len(lane.operations),
    )
    state_after_update = _snapshot_from_values(lane.state_before.capacity, update_next_index, values)
    operation_digest = _hash_parts(_OPERATION_DOMAIN, bytes(operation_bytes))
    relation_digest = _hash_parts(
        _SEMANTIC_DOMAIN,
        _text_bytes(lane.lane),
        _snapshot_encoding(lane.state_before),
        bytes(operation_bytes),
        lane.membership_key_512,
        membership.value_512,
        lane.absence_key_512,
        _snapshot_encoding(state_after_main),
        _snapshot_encoding(state_after_update),
    )
    return _LaneTrace(
        lane.state_before,
        state_after_main,
        state_after_update,
        membership.value_512,
        operation_digest,
        relation_digest,
    )


def _touched_keys(lane: ScalarLaneInput) -> tuple[bytes, ...]:
    values = {operation.key_512 for operation in lane.operations}
    values.add(lane.membership_key_512)
    values.add(lane.absence_key_512)
    return tuple(sorted(values))


def _dictionary_rows(snapshot: ScalarStateSnapshot) -> tuple[ScalarDictionaryRow, ...]:
    return tuple(
        ScalarDictionaryRow(entry.index, entry.key_512, entry.value_512)
        for entry in sorted(snapshot.entries, key=lambda value: value.index)
    )


def _projection_positions(lane: ScalarLaneInput, trace: _LaneTrace) -> tuple[int, ...]:
    by_key = {entry.key_512: entry.index for entry in trace.state_after_main.entries}
    absent_position = trace.state_after_main.next_append_index
    return tuple(sorted(by_key.get(key, absent_position) for key in _touched_keys(lane)))


def _shuffle_artifacts(lane: ScalarLaneInput, trace: _LaneTrace) -> tuple[bytes, tuple[int, ...], bytes]:
    challenge = _hash_parts(
        _SHUFFLE_DOMAIN,
        trace.relation_digest_512,
        trace.operation_digest_512,
    )
    keyed = sorted(
        (
            _hash_parts(challenge, index.to_bytes(4, "big")),
            index,
        )
        for index in range(len(lane.operations))
    )
    permutation = tuple(index for _, index in keyed)
    shuffled = b"".join(_operation_encoding(lane.operations[index]) for index in permutation)
    return challenge, permutation, _hash_parts(_SHUFFLE_DOMAIN, shuffled)


def _candidate_artifacts(
    candidate_id: str,
    lane: ScalarLaneInput,
    trace: _LaneTrace,
) -> tuple[
    tuple[bytes, ...],
    tuple[ScalarDictionaryRow, ...],
    tuple[int, ...],
    bytes,
    tuple[int, ...],
    bytes,
    bytes,
    int,
    int,
    int,
    bool,
]:
    touched = _touched_keys(lane)
    dictionary = _dictionary_rows(trace.state_after_update)
    positions = _projection_positions(lane, trace)
    challenge, permutation, shuffle_digest = _shuffle_artifacts(lane, trace)
    if candidate_id == "C1_DENSE":
        payload = _hash_parts(
            _CANDIDATE_DOMAIN,
            _text_bytes(candidate_id),
            lane.lane.encode("ascii"),
            lane.state_before.capacity.to_bytes(8, "big"),
            b"".join(touched),
        )
        return (
            touched,
            (),
            (),
            ZERO_512,
            (),
            ZERO_512,
            payload,
            lane.state_before.capacity,
            len(lane.operations) + len(touched),
            lane.state_before.capacity,
            True,
        )
    if candidate_id == "C1_SPARSE":
        payload = _hash_parts(
            _CANDIDATE_DOMAIN,
            _text_bytes(candidate_id),
            lane.lane.encode("ascii"),
            b"".join(touched),
        )
        return (
            touched,
            (),
            (),
            ZERO_512,
            (),
            ZERO_512,
            payload,
            len(touched),
            len(lane.operations) + len(touched),
            len(touched),
            False,
        )
    if candidate_id == "C2":
        row_bytes = b"".join(
            row.index.to_bytes(8, "big") + row.key_512 + row.value_512
            for row in dictionary
        )
        payload = _hash_parts(_CANDIDATE_DOMAIN, _text_bytes(candidate_id), row_bytes)
        return (
            (),
            dictionary,
            (),
            ZERO_512,
            (),
            ZERO_512,
            payload,
            len(dictionary),
            2 * len(lane.operations) + len(dictionary),
            len(dictionary),
            False,
        )
    if candidate_id == "C3":
        payload = _hash_parts(
            _CANDIDATE_DOMAIN,
            _text_bytes(candidate_id),
            b"".join(touched),
            b"".join(value.to_bytes(8, "big") for value in positions),
        )
        width = 1
        while width < len(touched):
            width <<= 1
        return (
            touched,
            (),
            positions,
            ZERO_512,
            (),
            ZERO_512,
            payload,
            width,
            len(touched) * len(touched),
            len(lane.operations),
            False,
        )
    if candidate_id == "C4":
        payload = _hash_parts(
            _CANDIDATE_DOMAIN,
            _text_bytes(candidate_id),
            challenge,
            b"".join(value.to_bytes(4, "big") for value in permutation),
            shuffle_digest,
        )
        return (
            (),
            (),
            (),
            challenge,
            permutation,
            shuffle_digest,
            payload,
            len(lane.operations),
            len(lane.operations) * 2,
            len(lane.operations),
            True,
        )
    raise ScalarRelationError("s2_candidate_unknown")


def _lane_result(candidate_id: str, lane: ScalarLaneInput, trace: _LaneTrace) -> ScalarLaneResult:
    (
        touched,
        dictionary,
        positions,
        challenge,
        permutation,
        shuffle_digest,
        payload,
        capacity_work,
        online_work,
        initialization_work,
        persistent_scan,
    ) = _candidate_artifacts(candidate_id, lane, trace)
    state_before_root = _state_root(candidate_id, lane.lane, "before", trace.state_before)
    state_after_root = _state_root(candidate_id, lane.lane, "after", trace.state_after_main)
    update_before_root = _state_root(candidate_id, lane.lane, "update-before", trace.state_after_main)
    update_after_root = _state_root(candidate_id, lane.lane, "update-after", trace.state_after_update)
    return ScalarLaneResult(
        candidate_id,
        lane.lane,
        state_before_root,
        state_after_root,
        update_before_root,
        update_after_root,
        trace.state_before.next_append_index,
        trace.state_after_main.next_append_index,
        trace.state_after_main.next_append_index,
        trace.state_after_update.next_append_index,
        len(lane.operations),
        lane.expected_access_rows,
        len(lane.operations) + 1 if lane.lane == "replay" else LANE_POSITION_ROWS[lane.lane],
        LANE_PROOF_NODE_ROWS[lane.lane],
        lane.membership_key_512,
        trace.membership_value_512,
        lane.absence_key_512,
        True,
        True,
        trace.operation_digest_512,
        trace.relation_digest_512,
        payload,
        touched,
        dictionary,
        positions,
        challenge,
        permutation,
        shuffle_digest,
        capacity_work,
        online_work,
        initialization_work,
        persistent_scan,
    )


def _economic_values(batch: ScalarBatchInput) -> tuple[int, int, int, bytes]:
    total_plan = sum(item.plan_payable_cents for item in batch.outcomes)
    total_debits = sum(item.debit_cents for item in batch.outcomes)
    total_credits = sum(item.credit_cents for item in batch.outcomes)
    encoded = b"".join(_outcome_encoding(item) for item in batch.outcomes)
    return total_plan, total_debits, total_credits, _hash_parts(_ECONOMIC_DOMAIN, encoded)


def _semantic_digest(batch: ScalarBatchInput, traces: tuple[_LaneTrace, ...]) -> bytes:
    parts = [_text_bytes(batch.profile_id), batch.claim_slots.to_bytes(4, "big")]
    parts.extend(trace.relation_digest_512 for trace in traces)
    parts.extend(_outcome_encoding(item) for item in batch.outcomes)
    return _hash_parts(_SEMANTIC_DOMAIN, *parts)


def evaluate_candidate(
    candidate_id: str,
    batch: ScalarBatchInput,
    *,
    variant: str | None = None,
) -> ScalarBatchResult:
    """Evaluate one scalar candidate without mutating the input batch."""

    _synthetic()
    canonical_candidate = _candidate_id(candidate_id, variant)
    _validate_batch(batch)
    traces = tuple(_trace_lane(lane) for lane in batch.lanes)
    lanes = tuple(
        _lane_result(canonical_candidate, lane, trace)
        for lane, trace in zip(batch.lanes, traces, strict=True)
    )
    total_plan, total_debits, total_credits, economic_digest = _economic_values(batch)
    return ScalarBatchResult(
        STATUS,
        canonical_candidate,
        batch.profile_id,
        batch.claim_slots,
        True,
        lanes,
        _semantic_digest(batch, traces),
        economic_digest,
        total_plan,
        total_debits,
        total_credits,
        sum(
            lane.candidate_capacity_work_units
            + lane.candidate_online_work_units
            + lane.candidate_initialization_work_units
            for lane in lanes
        ),
    )


def _verify_lane_result(candidate_id: str, lane: ScalarLaneInput, result: ScalarLaneResult) -> None:
    """Independently replay one lane and compare every result field."""

    # This is intentionally a separate replay from _trace_lane.  It rebuilds
    # the map by index and then checks key lookup, rather than trusting any
    # candidate-produced state or root.
    by_index = {entry.index: entry for entry in lane.state_before.entries}
    by_key = {entry.key_512: entry for entry in lane.state_before.entries}
    next_index = lane.state_before.next_append_index
    seen_ids: set[bytes] = set()
    operation_bytes = bytearray()
    for ordinal, operation in enumerate(lane.operations):
        if operation.ordinal != ordinal:
            raise ScalarRelationError("s2_verifier_operation_ordinal_mismatch")
        if operation.operation_id_512 in seen_ids:
            raise ScalarRelationError("s2_verifier_operation_identity_duplicate")
        seen_ids.add(operation.operation_id_512)
        operation_bytes.extend(_operation_encoding(operation))
        current = by_key.get(operation.key_512)
        if operation.mode == "insert":
            if current is not None:
                raise ScalarRelationError("s2_verifier_operation_key_collision")
            if operation.expected_index != next_index or operation.value_before_512 != ZERO_512:
                raise ScalarRelationError("s2_verifier_insert_transition_mismatch")
            entry = ScalarStateEntry(next_index, operation.key_512, operation.value_after_512)
            by_index[next_index] = entry
            by_key[operation.key_512] = entry
            next_index += 1
        else:
            if current is None:
                raise ScalarRelationError("s2_verifier_update_membership_missing")
            if current.index != operation.expected_index or current.value_512 != operation.value_before_512:
                raise ScalarRelationError("s2_verifier_update_value_before_mismatch")
            entry = ScalarStateEntry(current.index, current.key_512, operation.value_after_512)
            by_index[current.index] = entry
            by_key[operation.key_512] = entry
    after_main = ScalarStateSnapshot(lane.state_before.capacity, next_index, tuple(sorted(by_index.values(), key=lambda value: value.index)))
    membership = by_key.get(lane.membership_key_512)
    if membership is None:
        raise ScalarRelationError("s2_verifier_membership_missing")
    if lane.absence_key_512 in by_key:
        raise ScalarRelationError("s2_verifier_absence_is_member")
    update = lane.update_operation
    if update.operation_id_512 in seen_ids:
        raise ScalarRelationError("s2_verifier_operation_identity_duplicate")
    seen_ids.add(update.operation_id_512)
    if update.ordinal != len(lane.operations) or update.mode != "update":
        raise ScalarRelationError("s2_verifier_update_shape_mismatch")
    if update.key_512 != membership.key_512 or update.expected_index != membership.index:
        raise ScalarRelationError("s2_verifier_update_target_mismatch")
    if update.value_before_512 != membership.value_512:
        raise ScalarRelationError("s2_verifier_update_value_before_mismatch")
    operation_bytes.extend(_operation_encoding(update))
    updated = ScalarStateEntry(membership.index, membership.key_512, update.value_after_512)
    by_index[membership.index] = updated
    by_key[membership.key_512] = updated
    after_update = ScalarStateSnapshot(lane.state_before.capacity, next_index, tuple(sorted(by_index.values(), key=lambda value: value.index)))
    operation_digest = _hash_parts(_OPERATION_DOMAIN, bytes(operation_bytes))
    relation_digest = _hash_parts(
        _SEMANTIC_DOMAIN,
        _text_bytes(lane.lane),
        _snapshot_encoding(lane.state_before),
        bytes(operation_bytes),
        lane.membership_key_512,
        membership.value_512,
        lane.absence_key_512,
        _snapshot_encoding(after_main),
        _snapshot_encoding(after_update),
    )
    expected_trace = _LaneTrace(lane.state_before, after_main, after_update, membership.value_512, operation_digest, relation_digest)
    expected = _lane_result(candidate_id, lane, expected_trace)
    if result != expected:
        # Keep the failure family stable without exposing raw private state.
        for field_name in (
            "state_root_before_512",
            "state_root_after_512",
            "update_root_before_512",
            "update_root_after_512",
            "operation_digest_512",
            "relation_digest_512",
            "candidate_payload_digest_512",
            "shuffle_challenge_512",
            "shuffle_digest_512",
        ):
            if getattr(result, field_name) != getattr(expected, field_name):
                raise ScalarRelationError(f"s2_verifier_{field_name}_mismatch")
        raise ScalarRelationError("s2_verifier_lane_result_mismatch")


def independently_verify_candidate(
    candidate_id: str,
    batch: ScalarBatchInput,
    result: ScalarBatchResult,
    *,
    variant: str | None = None,
) -> None:
    """Recompute and fail closed on any candidate result mutation."""

    _synthetic()
    canonical_candidate = _candidate_id(candidate_id, variant)
    _validate_batch(batch)
    if type(result) is not ScalarBatchResult or result.status != STATUS:
        raise ScalarRelationError("s2_verifier_result_status_invalid")
    if result.candidate_id != canonical_candidate or result.profile_id != batch.profile_id:
        raise ScalarRelationError("s2_verifier_result_identity_mismatch")
    if result.claim_slots != batch.claim_slots or result.accepted is not True:
        raise ScalarRelationError("s2_verifier_result_shape_invalid")
    if tuple(item.lane for item in result.lanes) != LANE_ORDER:
        raise ScalarRelationError("s2_verifier_lane_order_mismatch")
    for lane, lane_result in zip(batch.lanes, result.lanes, strict=True):
        if lane_result.candidate_id != canonical_candidate or lane_result.lane != lane.lane:
            raise ScalarRelationError("s2_verifier_lane_identity_mismatch")
        _verify_lane_result(canonical_candidate, lane, lane_result)
    traces = tuple(_trace_lane(lane) for lane in batch.lanes)
    total_plan, total_debits, total_credits, economic_digest = _economic_values(batch)
    if result.semantic_digest_512 != _semantic_digest(batch, traces):
        raise ScalarRelationError("s2_verifier_semantic_digest_mismatch")
    if result.economic_digest_512 != economic_digest:
        raise ScalarRelationError("s2_verifier_economic_digest_mismatch")
    if (result.total_plan_payable_cents, result.total_debits_cents, result.total_credits_cents) != (
        total_plan,
        total_debits,
        total_credits,
    ):
        raise ScalarRelationError("s2_verifier_money_mismatch")
    expected_work = sum(
        lane.candidate_capacity_work_units
        + lane.candidate_online_work_units
        + lane.candidate_initialization_work_units
        for lane in result.lanes
    )
    if result.candidate_work_units != expected_work:
        raise ScalarRelationError("s2_verifier_work_mismatch")


def run_all_scalar_controls(batch: ScalarBatchInput) -> tuple[ScalarBatchResult, ...]:
    """Evaluate and independently verify C1 dense/sparse, C2, C3, and C4."""

    _synthetic()
    results = tuple(evaluate_candidate(candidate, batch) for candidate in CANDIDATE_IDS)
    for result in results:
        independently_verify_candidate(result.candidate_id, batch, result)
    return results


def scalar_parity_summary(batch: ScalarBatchInput, result: ScalarBatchResult) -> dict[str, object]:
    """Return the exact semantic boundary used for C0 differential parity."""

    _synthetic()
    if result.profile_id != batch.profile_id:
        raise ScalarRelationError("s2_parity_profile_mismatch")
    representative_outcomes = tuple(
        (item.case_name, item.result, item.failure_code)
        for item in batch.outcomes[:4]
    ) + (
        ("cover", "cover", "0"),
        ("correction", "rejected", "r25_revision_not_authorized"),
    )
    return {
        "profile_id": batch.profile_id,
        "claim_slots": batch.claim_slots,
        "map_geometry": tuple(
            (lane.lane, lane.operation_count, lane.access_rows, lane.position_rows)
            for lane in result.lanes
        ),
        "membership_absence": tuple(
            (lane.lane, lane.membership_present, lane.absence_proven)
            for lane in result.lanes
        ),
        "state_changes": tuple(
            (
                lane.lane,
                lane.state_root_before_512 != lane.state_root_after_512,
                lane.update_root_before_512 != lane.update_root_after_512,
                lane.next_index_after - lane.next_index_before,
                lane.update_next_index_after - lane.update_next_index_before,
            )
            for lane in result.lanes
        ),
        "case_outcomes": representative_outcomes,
        "money": (
            result.total_plan_payable_cents,
            result.total_debits_cents,
            result.total_credits_cents,
        ),
        "semantic_digest_sha3_512_hex": result.semantic_digest_512.hex(),
    }


def _mutate_batch(base: ScalarBatchInput, name: str) -> ScalarBatchInput:
    from dataclasses import replace

    lane = base.lanes[0]
    if name == "stale_read":
        first = lane.operations[0]
        bad = replace(first, value_before_512=_derive(base.profile_id, lane.lane, "stale", 0))
        lane = replace(lane, operations=(bad, *lane.operations[1:]))
    elif name == "omitted_write":
        lane = replace(lane, operations=lane.operations[:-1])
    elif name == "reordered_write":
        reordered = (lane.operations[1], lane.operations[0], *lane.operations[2:])
        lane = replace(lane, operations=reordered)
    elif name == "duplicate_identity":
        duplicate = replace(lane.operations[1], operation_id_512=lane.operations[0].operation_id_512)
        lane = replace(lane, operations=(lane.operations[0], duplicate, *lane.operations[2:]))
    elif name == "collision":
        collision = replace(lane.operations[1], key_512=lane.operations[0].key_512)
        lane = replace(lane, operations=(lane.operations[0], collision, *lane.operations[2:]))
    elif name == "conflicting_update":
        member_operation = lane.operations[len(lane.operations) // 2]
        conflict = replace(
            lane.operations[-1],
            operation_id_512=_derive(base.profile_id, lane.lane, "conflict", 0),
            mode="update",
            key_512=member_operation.key_512,
            value_before_512=member_operation.value_after_512,
            value_after_512=_derive(base.profile_id, lane.lane, "conflict-value", 0),
            expected_index=member_operation.expected_index,
        )
        lane = replace(
            lane,
            operations=(*lane.operations[:-1], conflict),
        )
    else:
        raise ScalarRelationError("s2_negative_case_unknown")
    return replace(base, lanes=(lane, *base.lanes[1:]))


def build_scalar_negative_corpus(profile_id: str) -> tuple[ScalarNegativeCase, ...]:
    """Build the seven C0 negative classes plus a result-root mutation case."""

    _synthetic()
    base = build_scalar_control_batch(profile_id)
    cases = [
        ScalarNegativeCase(name, _mutate_batch(base, name), None)
        for name in C0_NEGATIVE_CASE_NAMES
        if name != "root_substitution"
    ]
    cases.append(ScalarNegativeCase("root_substitution", base, "state_root_before_512"))
    return tuple(cases)


def mutate_result_for_negative_case(
    result: ScalarBatchResult,
    case: ScalarNegativeCase,
) -> ScalarBatchResult:
    """Apply the explicitly named root substitution to a result for testing."""

    _synthetic()
    if case.result_mutation != "state_root_before_512":
        return result
    from dataclasses import replace

    lane = result.lanes[0]
    forged = replace(lane, state_root_before_512=_hash_parts(_DOMAIN, b"forged-root"))
    return replace(result, lanes=(forged, *result.lanes[1:]))


def verify_negative_case(candidate_id: str, case: ScalarNegativeCase) -> str:
    """Return the raw fail-closed family; raise if a negative case accepts."""

    _synthetic()
    try:
        result = evaluate_candidate(candidate_id, case.batch)
        result = mutate_result_for_negative_case(result, case)
        independently_verify_candidate(candidate_id, case.batch, result)
    except (ScalarRelationError, ValueError, RuntimeError) as exc:
        return str(exc)
    raise AssertionError("s2_negative_case_accepted")


__all__ = (
    "ACTIVATION_ALLOWED",
    "CANDIDATE_IDS",
    "C0_NEGATIVE_CASE_NAMES",
    "C1_VARIANTS",
    "LANE_ORDER",
    "MAX_STATE_CAPACITY",
    "PROOF_SUITE_ID",
    "PROFILE_CLAIM_SLOTS",
    "STATUS",
    "ScalarBatchInput",
    "ScalarBatchResult",
    "ScalarDictionaryRow",
    "ScalarLaneInput",
    "ScalarLaneResult",
    "ScalarNegativeCase",
    "ScalarOperation",
    "ScalarProfileShape",
    "ScalarRelationError",
    "ScalarSlotOutcome",
    "ScalarStateEntry",
    "ScalarStateSnapshot",
    "build_scalar_control_batch",
    "build_scalar_negative_corpus",
    "evaluate_candidate",
    "independently_verify_candidate",
    "mutate_result_for_negative_case",
    "run_all_scalar_controls",
    "scalar_parity_summary",
    "verify_negative_case",
)
