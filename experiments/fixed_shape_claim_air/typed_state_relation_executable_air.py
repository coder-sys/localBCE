"""Proof-native typed C0 state relation.

The generic state relation is useful for the fixed-capacity H4 lane, but it is
not the semantic authority for ordered state.  This component composes the
existing ordered-map AIR and claim/payment AIR instead of duplicating either
relation.  It adds only the cross-component links that were missing at the
Wave 2 seam: replay/payment roots and cursors, fixed slot order, and checked
money totals.

Hash preimages and SHA3 digests remain on the existing shared H4 hash bus.  No
host-computed root or amount is accepted as a substitute for the component
AIRs; the summary tables are linked back to their exact executable traces.
The component is synthetic C0 evidence and never selects a suite or enables
activation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    C0TypedStateWitness,
    build_c0_typed_state_witness,
)
from experiments.fixed_shape_claim_air.air_composition import (
    Sha3ComposedComponent,
    compose_sha3_interface_components,
)
from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_interface_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    M31,
    PublicInputBinding,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
    evaluate_program,
)
from experiments.fixed_shape_claim_air.claim_payment_maps_executable_air import (
    ClaimPaymentMapsAirInstance,
    build_claim_payment_maps_executable_air,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_executable_air import (
    OrderedMapBatchAirInstance,
    build_ordered_map_batch_sha3_executable_air,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-PQ512-C0-TYPED-STATE-AIR-v1"
LANE_ORDER: Final[tuple[str, ...]] = ("replay", "benefit", "obligation", "ledger")
MONEY_TABLE: Final[str] = "typed_state_money"
SUMMARY_TABLE: Final[str] = "typed_state_lane_summary"
_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/TYPED-STATE-AIR/v1\x00"


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _summary_table(
    replay: OrderedMapBatchAirInstance,
    payment: ClaimPaymentMapsAirInstance,
) -> tuple[AirTable, TraceTable, LookupArgument, tuple[PublicInputBinding, ...], tuple[int, ...]]:
    replay_columns = replay.traces["ordered_map_state"].columns
    payment_columns = payment.traces["payment_map_lane_state"].columns
    columns: dict[str, list[int]] = {
        "lane": [],
        "map_domain": [],
        "cursor_before": [],
        "cursor_after": [],
    }
    for prefix in (
        "inner_root_before",
        "inner_root_after",
        "root_before",
        "root_after",
    ):
        for index in range(64):
            columns[f"{prefix}_{index}"] = []

    def add_row(lane: int, source: Mapping[str, tuple[int, ...]], row: int) -> None:
        _append(columns, "lane", lane)
        for name in ("map_domain", "cursor_before", "cursor_after"):
            _append(columns, name, source[name][row])
        for prefix in (
            "inner_root_before",
            "inner_root_after",
            "root_before",
            "root_after",
        ):
            for index in range(64):
                _append(columns, f"{prefix}_{index}", source[f"{prefix}_{index}"][row])

    add_row(0, replay_columns, 0)
    for lane in range(3):
        add_row(lane + 1, payment_columns, lane)

    frozen = freeze_columns(columns)
    trace = TraceTable(SUMMARY_TABLE, frozen)
    summary_values = (
        cell("lane"),
        cell("map_domain"),
        cell("cursor_before"),
        cell("cursor_after"),
        *(
            cell(f"{prefix}_{index}")
            for prefix in (
                "inner_root_before",
                "inner_root_after",
                "root_before",
                "root_after",
            )
            for index in range(64)
        ),
    )
    replay_values = (
        const(0),
        cell("map_domain"),
        cell("cursor_before"),
        cell("cursor_after"),
        *(
            cell(f"{prefix}_{index}")
            for prefix in (
                "inner_root_before",
                "inner_root_after",
                "root_before",
                "root_after",
            )
            for index in range(64)
        ),
    )
    payment_values = (
        cell("lane") + 1,
        cell("map_domain"),
        cell("cursor_before"),
        cell("cursor_after"),
        *(
            cell(f"{prefix}_{index}")
            for prefix in (
                "inner_root_before",
                "inner_root_after",
                "root_before",
                "root_after",
            )
            for index in range(64)
        ),
    )
    links = LookupArgument(
        "typed_state_lane_root_cursor_links",
        (LookupSide(SUMMARY_TABLE, const(1), summary_values, 0, 4),),
        (
            LookupSide("ordered_map_state", const(1), replay_values, 0, 1),
            LookupSide("payment_map_lane_state", const(1), payment_values, 0, 3),
        ),
    )
    fixed = MappingProxyType({"lane": tuple(range(4))})
    table = AirTable(SUMMARY_TABLE, tuple(frozen), 4, (), fixed)
    public_bindings: list[PublicInputBinding] = []
    public_values: list[int] = []
    for row, lane in enumerate(LANE_ORDER):
        for phase in ("root_before", "root_after"):
            for index in range(64):
                column = f"{phase}_{index}"
                public_bindings.append(
                    PublicInputBinding(f"typed_state_{lane}_{phase}_{index}", SUMMARY_TABLE, column, row)
                )
                public_values.append(frozen[column][row])
        for label in ("cursor_before", "cursor_after"):
            column = label
            public_bindings.append(
                PublicInputBinding(f"typed_state_{lane}_{label}", SUMMARY_TABLE, column, row)
            )
            public_values.append(frozen[column][row])
    return table, trace, links, tuple(public_bindings), tuple(public_values)


def _money_table(
    payment: ClaimPaymentMapsAirInstance,
) -> tuple[
    AirTable,
    TraceTable,
    AirTable,
    TraceTable,
    LookupArgument,
    LookupArgument,
    tuple[PublicInputBinding, ...],
    tuple[int, ...],
]:
    source = payment.traces["claim_payment_map_slot"].columns
    rows = len(source["slot_index"])
    columns: dict[str, list[int]] = {
        "slot_index": [],
        "approval": [],
        "allowed_limb_0": [],
        "allowed_limb_1": [],
        "payment_limb_0": [],
        "payment_limb_1": [],
        **{f"allowed_byte_{index}": [] for index in range(4)},
        **{f"payment_byte_{index}": [] for index in range(4)},
        **{f"difference_byte_{index}": [] for index in range(4)},
        **{f"difference_borrow_{index}": [] for index in range(4)},
        "allowed_value": [],
        "payment_value": [],
        "debit_value": [],
        "credit_value": [],
        "running_allowed": [],
        "running_payment": [],
        "running_debit": [],
        "running_credit": [],
    }
    for row in range(rows):
        allowed = source["allowed_limb_0"][row] + (1 << 16) * source["allowed_limb_1"][row]
        payment_value = source["payment_limb_0"][row] + (1 << 16) * source["payment_limb_1"][row]
        if allowed >= M31 or payment_value >= M31:
            raise StructuralError("typed_state_air_money_m31_range")
        if not source["approval"][row] and payment_value:
            raise StructuralError("typed_state_air_nonapproval_payment_nonzero")
        allowed_bytes = allowed.to_bytes(4, "big")
        payment_bytes = payment_value.to_bytes(4, "big")
        difference_bytes = [0] * 4
        difference_borrows = [0] * 4
        incoming = 0
        for index in range(3, -1, -1):
            raw = allowed_bytes[index] - payment_bytes[index] - incoming
            borrow = int(raw < 0)
            difference_borrows[index] = borrow
            difference_bytes[index] = raw + 256 * borrow
            incoming = borrow
        if incoming:
            raise StructuralError("typed_state_air_payment_exceeds_allowed")
        _append(columns, "slot_index", source["slot_index"][row])
        _append(columns, "approval", source["approval"][row])
        for name in ("allowed_limb_0", "allowed_limb_1", "payment_limb_0", "payment_limb_1"):
            _append(columns, name, source[name][row])
        for index in range(4):
            _append(columns, f"allowed_byte_{index}", allowed_bytes[index])
            _append(columns, f"payment_byte_{index}", payment_bytes[index])
            _append(columns, f"difference_byte_{index}", difference_bytes[index])
            _append(columns, f"difference_borrow_{index}", difference_borrows[index])
        _append(columns, "allowed_value", allowed)
        _append(columns, "payment_value", payment_value)
        _append(columns, "debit_value", payment_value)
        _append(columns, "credit_value", payment_value)
        previous = row and columns["running_allowed"][-1] or 0
        previous_payment = row and columns["running_payment"][-1] or 0
        previous_debit = row and columns["running_debit"][-1] or 0
        previous_credit = row and columns["running_credit"][-1] or 0
        _append(columns, "running_allowed", previous + allowed)
        _append(columns, "running_payment", previous_payment + payment_value)
        _append(columns, "running_debit", previous_debit + payment_value)
        _append(columns, "running_credit", previous_credit + payment_value)

    frozen = freeze_columns(columns)
    identities: list[Identity] = [
        Identity("approval_boolean", boolean(cell("approval")), 0, rows),
        Identity("allowed_value_encoding", cell("allowed_value") - cell("allowed_limb_0") - (1 << 16) * cell("allowed_limb_1"), 0, rows),
        Identity("payment_value_encoding", cell("payment_value") - cell("payment_limb_0") - (1 << 16) * cell("payment_limb_1"), 0, rows),
        Identity("allowed_high_limb_bytes", cell("allowed_limb_1") - 256 * cell("allowed_byte_0") - cell("allowed_byte_1"), 0, rows),
        Identity("allowed_low_limb_bytes", cell("allowed_limb_0") - 256 * cell("allowed_byte_2") - cell("allowed_byte_3"), 0, rows),
        Identity("payment_high_limb_bytes", cell("payment_limb_1") - 256 * cell("payment_byte_0") - cell("payment_byte_1"), 0, rows),
        Identity("payment_low_limb_bytes", cell("payment_limb_0") - 256 * cell("payment_byte_2") - cell("payment_byte_3"), 0, rows),
        Identity("debit_payment_binding", cell("debit_value") - cell("payment_value"), 0, rows),
        Identity("credit_payment_binding", cell("credit_value") - cell("payment_value"), 0, rows),
        Identity("nonapproval_payment_zero", (1 - cell("approval")) * cell("payment_value"), 0, rows),
        Identity("debit_credit_conservation", cell("debit_value") - cell("credit_value"), 0, rows),
    ]
    for index in range(4):
        incoming = 0 if index == 3 else cell(f"difference_borrow_{index + 1}")
        identities.extend(
            (
                Identity(
                    f"difference_borrow_{index}_boolean",
                    boolean(cell(f"difference_borrow_{index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"difference_subtraction_{index}",
                    cell(f"allowed_byte_{index}")
                    - cell(f"payment_byte_{index}")
                    - incoming
                    + 256 * cell(f"difference_borrow_{index}")
                    - cell(f"difference_byte_{index}"),
                    0,
                    rows,
                ),
            )
        )
    identities.append(
        Identity("difference_no_underflow", cell("difference_borrow_0"), 0, rows)
    )
    if rows > 1:
        for field, amount in (
            ("running_allowed", "allowed_value"),
            ("running_payment", "payment_value"),
            ("running_debit", "debit_value"),
            ("running_credit", "credit_value"),
        ):
            identities.append(
                Identity(
                    f"{field}_transition",
                    cell(field, 1) - cell(field) - cell(amount, 1),
                    0,
                    rows - 1,
                    "transition",
                )
            )
    identities.extend(
        (
            Identity("running_allowed_initial", cell("running_allowed") - cell("allowed_value"), 0, 1, "boundary"),
            Identity("running_payment_initial", cell("running_payment") - cell("payment_value"), 0, 1, "boundary"),
            Identity("running_debit_initial", cell("running_debit") - cell("debit_value"), 0, 1, "boundary"),
            Identity("running_credit_initial", cell("running_credit") - cell("credit_value"), 0, 1, "boundary"),
            Identity("total_debit_credit", cell("running_debit") - cell("running_credit"), rows - 1, rows, "boundary"),
            Identity("total_payment_value", cell("running_payment") - cell("running_debit"), rows - 1, rows, "boundary"),
        )
    )
    trace = TraceTable(MONEY_TABLE, frozen)
    table = AirTable(
        MONEY_TABLE,
        tuple(frozen),
        rows,
        tuple(identities),
        MappingProxyType({"slot_index": tuple(range(rows))}),
    )
    byte_names = tuple(
        f"{prefix}_{index}"
        for prefix in ("allowed_byte", "payment_byte", "difference_byte")
        for index in range(4)
    )
    multiplicity = Counter(value for name in byte_names for value in frozen[name])
    byte_values = tuple(range(256))
    byte_columns = freeze_columns(
        {
            "value": byte_values,
            "multiplicity": tuple(multiplicity[value] for value in byte_values),
        }
    )
    byte_trace = TraceTable("typed_state_money_byte", byte_columns)
    byte_table = AirTable(
        byte_trace.name,
        tuple(byte_columns),
        256,
        (),
        MappingProxyType({"value": byte_values}),
    )
    link = LookupArgument(
        "typed_state_money_slot_links",
        (
            LookupSide(
                MONEY_TABLE,
                const(1),
                (
                    cell("slot_index"),
                    cell("approval"),
                    cell("allowed_limb_0"),
                    cell("allowed_limb_1"),
                    cell("payment_limb_0"),
                    cell("payment_limb_1"),
                ),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                (
                    cell("slot_index"),
                    cell("approval"),
                    cell("allowed_limb_0"),
                    cell("allowed_limb_1"),
                    cell("payment_limb_0"),
                    cell("payment_limb_1"),
                ),
                0,
                rows,
            ),
        ),
    )
    byte_link = LookupArgument(
        "typed_state_money_byte_range",
        tuple(
            LookupSide(MONEY_TABLE, const(1), (cell(name),), 0, rows)
            for name in byte_names
        ),
        (
            LookupSide(
                byte_table.name,
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    bindings = tuple(
        PublicInputBinding(f"typed_state_money_{name}", MONEY_TABLE, name, rows - 1)
        for name in ("running_allowed", "running_payment", "running_debit", "running_credit")
    )
    values = tuple(frozen[name][rows - 1] for name in ("running_allowed", "running_payment", "running_debit", "running_credit"))
    return table, trace, byte_table, byte_trace, link, byte_link, bindings, values


@dataclass(frozen=True, slots=True)
class TypedStateRelationAirInstance:
    """Merged executable relation for one exact C0 profile."""

    program: AirProgram
    traces: Mapping[str, TraceTable]
    state_witness: C0TypedStateWitness
    replay: OrderedMapBatchAirInstance
    payment: ClaimPaymentMapsAirInstance
    public_values: tuple[int, ...]
    hash_calls: tuple[object, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.program, AirProgram):
            raise StructuralError("typed_state_air_program_invalid")
        if set(self.traces) != {table.name for table in self.program.tables}:
            raise StructuralError("typed_state_air_trace_set_invalid")
        if type(self.state_witness) is not C0TypedStateWitness:
            raise StructuralError("typed_state_air_witness_invalid")
        if type(self.public_values) is not tuple or any(
            type(value) is not int or not 0 <= value < M31 for value in self.public_values
        ):
            raise StructuralError("typed_state_air_public_values_invalid")

    @property
    def relation_digest_512(self) -> bytes:
        return sha3_512(
            _DOMAIN
            + self.program.commitment()
            + b"".join(value.to_bytes(4, "big") for value in self.public_values)
        ).digest()


def build_typed_state_relation_air(
    state_witness: C0TypedStateWitness,
) -> TypedStateRelationAirInstance:
    if type(state_witness) is not C0TypedStateWitness:
        raise StructuralError("typed_state_air_witness_required")
    replay_schedule = build_ordered_map_batch_schedule(len(state_witness.replay_batch.operations))
    replay = build_ordered_map_batch_sha3_executable_air(
        state_witness.replay_batch,
        replay_schedule,
        interface_only=True,
    )
    replay_calls = tuple(
        Sha3Call(
            f"map_hash_{call.ordinal}",
            call.message,
            len(call.message),
        )
        for call in replay.hash_calls
    )
    payment = build_claim_payment_maps_executable_air(
        state_witness.slots,
        state_witness.payment_transition,
        compose_operation_log_sha3=True,
        compose_key_sha3=True,
        compose_map_sha3=True,
        interface_only=True,
        call_index_offset=len(replay_calls),
    )
    summary_table, summary_trace, summary_link, summary_public, summary_values = _summary_table(
        replay, payment
    )
    (
        money_table,
        money_trace,
        money_byte_table,
        money_byte_trace,
        money_link,
        money_byte_link,
        money_public,
        money_values,
    ) = _money_table(payment)
    replay_component = Sha3ComposedComponent(
        replay.program,
        replay.traces,
        build_application_sha3_interface_air(replay_calls),
        0,
    )
    payment_component = Sha3ComposedComponent(
        payment.program,
        payment.traces,
        payment.application_sha3,
        len(replay_calls),
    )
    merged = compose_sha3_interface_components(
        PROGRAM_ID,
        (replay_component, payment_component),
        extra_tables=(summary_table, money_table, money_byte_table),
        extra_traces={
            summary_trace.name: summary_trace,
            money_trace.name: money_trace,
            money_byte_trace.name: money_byte_trace,
        },
        extra_lookups=(summary_link, money_link, money_byte_link),
        extra_public_inputs=(*summary_public, *money_public),
    )
    public_values = (*summary_values, *money_values)
    instance = TypedStateRelationAirInstance(
        merged.program,
        merged.traces,
        state_witness,
        replay,
        payment,
        public_values,
        replay_calls + tuple(payment.application_sha3.calls)
        if payment.application_sha3 is not None
        else replay_calls,
    )
    return instance


def verify_typed_state_relation_air(instance: TypedStateRelationAirInstance) -> None:
    if type(instance) is not TypedStateRelationAirInstance:
        raise StructuralError("typed_state_air_instance_required")
    evaluate_program(instance.program, instance.traces, instance.public_values)


def build_c0_typed_state_relation_air(profile) -> TypedStateRelationAirInstance:
    return build_typed_state_relation_air(build_c0_typed_state_witness(profile))


__all__ = (
    "LANE_ORDER",
    "MONEY_TABLE",
    "PROGRAM_ID",
    "SUMMARY_TABLE",
    "TypedStateRelationAirInstance",
    "build_c0_typed_state_relation_air",
    "build_typed_state_relation_air",
    "verify_typed_state_relation_air",
)
