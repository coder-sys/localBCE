"""Proof-native typed C0 state relation.

The generic state relation is useful for the fixed-capacity H4 lane, but it is
not the semantic authority for ordered state.  This component composes the
existing ordered-map AIR and claim/payment AIR instead of duplicating either
    relation.  It adds only the cross-component links that were missing at the
    Wave 2 seam: replay/payment roots and cursors, fixed slot order, and checked
    money totals.  Exact totals remain private witness columns; only canonical
    state identities and roots cross the public boundary.

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
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    _ASSET_REGISTRY_ROOT,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_executable_air import (
    OrderedMapBatchAirInstance,
    build_ordered_map_batch_sha3_executable_air,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-PQ512-C0-TYPED-STATE-AIR-v3"
LANE_ORDER: Final[tuple[str, ...]] = ("replay", "benefit", "obligation", "ledger")
MONEY_TABLE: Final[str] = "typed_state_money"
SUMMARY_TABLE: Final[str] = "typed_state_lane_summary"
AUTHORITY_TABLE: Final[str] = "typed_state_authority"
LOG_MESSAGE_TABLE: Final[str] = "typed_state_log_message_batch"
_SOURCE_BUNDLE_TABLE: Final[str] = "claim_source_bundle_byte"
_PACKED_SOURCE_BUNDLE_TABLE: Final[str] = "claim_source_bundle_word"
_SOURCE_BUNDLE_LANES: Final[int] = 8
_LOG_MESSAGE_LANES: Final[int] = 64
_SOURCE_BUNDLE_MASKS: Final[tuple[str, ...]] = (
    "is_token_byte",
    "is_scalar_byte",
    "is_diagnosis_byte",
    "is_service_non_token_byte",
)
_REMOVED_SHA3_TABLES: Final[frozenset[str]] = frozenset(
    {"sha3_message_batch", "sha3_digest_byte_batch"}
)
_REMOVED_MAP_PORT_TABLES: Final[frozenset[str]] = frozenset(
    {
        "ordered_map_hash_port",
        "benefit__ordered_map_hash_port",
        "obligation__ordered_map_hash_port",
        "ledger__ordered_map_hash_port",
    }
)
_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/TYPED-STATE-AIR/v1\x00"
_C0_STATE_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/C0/STATE-ROOT/v1\x00"
_STATE_ROOT_ENTRY_WIDTH: Final[int] = 137
_STATE_ROOT_CAPACITY_BASE: Final[int] = 512


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
    # The arithmetic remains proof-native, but exact amounts are private
    # witness values and must not become authenticated public inputs.
    return table, trace, byte_table, byte_trace, link, byte_link, (), ()


def _authority_columns(
    state_witness: C0TypedStateWitness,
    replay: OrderedMapBatchAirInstance,
    payment: ClaimPaymentMapsAirInstance,
) -> tuple[
    AirTable,
    TraceTable,
    tuple[LookupArgument, ...],
    tuple[PublicInputBinding, ...],
    tuple[int, ...],
    tuple[Sha3Call, ...],
]:
    """Expose only state identities and bind them to the typed traces.

    The payment root itself is consumed as a native SHA3 interface call.  Its
    inputs are still carried as typed columns so the native H4 verifier can
    recompute the exact state root from this execution, rather than trusting a
    host-side root supplied beside the proof.
    """

    payment_states = (state_witness.payment_before, state_witness.payment_after)
    replay_roots = (
        state_witness.replay_batch.root_before,
        state_witness.replay_batch.root_after,
    )
    state_roots = tuple(
        sha3_512(_C0_STATE_ROOT_DOMAIN + state.root() + replay_root).digest()
        for state, replay_root in zip(payment_states, replay_roots, strict=True)
    )
    columns: dict[str, list[int]] = {
        "phase": [0, 1],
        "epoch": [],
        "sequence": [],
        "next_slot_index": [],
        **{f"epoch_byte_{index}": [] for index in range(8)},
        **{f"sequence_byte_{index}": [] for index in range(8)},
        **{f"settlement_{index}": [] for index in range(64)},
        **{f"asset_registry_{index}": [] for index in range(64)},
        **{f"scope_{index}": [] for index in range(64)},
        **{f"benefit_root_{index}": [] for index in range(64)},
        **{f"obligation_root_{index}": [] for index in range(64)},
        **{f"ledger_root_{index}": [] for index in range(64)},
        **{f"operation_log_root_{index}": [] for index in range(64)},
        **{f"payment_root_{index}": [] for index in range(64)},
        **{f"replay_root_{index}": [] for index in range(64)},
        **{f"state_root_{index}": [] for index in range(64)},
    }

    def append_bytes(prefix: str, value: bytes) -> None:
        if type(value) is not bytes or len(value) != 64:
            raise StructuralError(f"typed_state_authority_{prefix}_width_invalid")
        for index, byte in enumerate(value):
            _append(columns, f"{prefix}_{index}", byte)

    for phase, (state, replay_root, state_root) in enumerate(
        zip(payment_states, replay_roots, state_roots, strict=True)
    ):
        if phase == 0:
            operation_log_root = state.operation_log_root_512
        else:
            operation_log_root = state.operation_log_root_512
        epoch_bytes = state.epoch.to_bytes(8, "big")
        sequence_bytes = state.sequence.to_bytes(8, "big")
        _append(columns, "epoch", state.epoch)
        _append(columns, "sequence", state.sequence)
        _append(columns, "next_slot_index", state.next_slot_index)
        for index, byte in enumerate(epoch_bytes):
            _append(columns, f"epoch_byte_{index}", byte)
        for index, byte in enumerate(sequence_bytes):
            _append(columns, f"sequence_byte_{index}", byte)
        append_bytes("settlement", state.strong_settlement_domain_id_512)
        append_bytes("asset_registry", state.asset_registry_root_512)
        append_bytes("scope", state.benefit_scope.commitment_512())
        append_bytes("benefit_root", state.benefit_root_512)
        append_bytes("obligation_root", state.obligation_root_512)
        append_bytes("ledger_root", state.private_asset_ledger_root_512)
        append_bytes("operation_log_root", operation_log_root)
        payment_root = state.root()
        append_bytes("payment_root", payment_root)
        append_bytes("replay_root", replay_root)
        append_bytes("state_root", state_root)

    frozen = freeze_columns(columns)
    identities: list[Identity] = []
    identities.extend(
        (
            Identity(
                "epoch_byte_encoding",
                cell("epoch")
                - sum(
                    (256 ** (7 - index)) * cell(f"epoch_byte_{index}")
                    for index in range(8)
                ),
                0,
                2,
            ),
            Identity(
                "sequence_byte_encoding",
                cell("sequence")
                - sum(
                    (256 ** (7 - index)) * cell(f"sequence_byte_{index}")
                    for index in range(8)
                ),
                0,
                2,
            ),
        )
    )
    identities.extend(
        (
            Identity("authority_epoch_stable", cell("epoch", 1) - cell("epoch"), 0, 1, "transition"),
            Identity(
                "authority_sequence_increment",
                cell("sequence", 1) - cell("sequence") - 1,
                0,
                1,
                "transition",
            ),
            Identity(
                "authority_next_slot_stable",
                cell("next_slot_index", 1) - cell("next_slot_index"),
                0,
                1,
                "transition",
            ),
        )
    )
    for prefix in ("settlement", "asset_registry", "scope"):
        for index in range(64):
            identities.append(
                Identity(
                    f"authority_{prefix}_stable_{index}",
                    cell(f"{prefix}_{index}", 1) - cell(f"{prefix}_{index}"),
                    0,
                    1,
                    "transition",
                )
            )
    table = AirTable(
        AUTHORITY_TABLE,
        tuple(frozen),
        2,
        tuple(identities),
        MappingProxyType(
            {
                "phase": (0, 1),
                "next_slot_index": (0, 0),
                **{
                    f"asset_registry_{index}": (_ASSET_REGISTRY_ROOT[index],) * 2
                    for index in range(64)
                },
            }
        ),
    )
    trace = TraceTable(AUTHORITY_TABLE, frozen)
    public_bindings: list[PublicInputBinding] = []
    public_values: list[int] = []
    for phase in range(2):
        for name in ("epoch", "sequence", "next_slot_index"):
            public_bindings.append(
                PublicInputBinding(
                    f"typed_state_authority_{phase}_{name}",
                    AUTHORITY_TABLE,
                    name,
                    phase,
                )
            )
            public_values.append(frozen[name][phase])
        for prefix in (
            "settlement",
            "asset_registry",
            "scope",
            "benefit_root",
            "obligation_root",
            "ledger_root",
            "operation_log_root",
            "payment_root",
            "replay_root",
            "state_root",
        ):
            for index in range(64):
                column = f"{prefix}_{index}"
                public_bindings.append(
                    PublicInputBinding(
                        f"typed_state_authority_{phase}_{prefix}_{index}",
                        AUTHORITY_TABLE,
                        column,
                        phase,
                    )
                )
                public_values.append(frozen[column][phase])

    lookup_values = lambda prefix: tuple(cell(f"{prefix}_{index}") for index in range(64))
    summary_links: list[LookupArgument] = []
    summary_rows = {"replay": 0, "benefit": 1, "obligation": 2, "ledger": 3}
    authority_prefixes = {
        "replay": "replay_root",
        "benefit": "benefit_root",
        "obligation": "obligation_root",
        "ledger": "ledger_root",
    }
    for lane, summary_row in summary_rows.items():
        prefix = authority_prefixes[lane]
        summary_links.append(
            LookupArgument(
                f"typed_state_authority_{lane}_roots",
                tuple(
                    LookupSide(AUTHORITY_TABLE, const(1), lookup_values(prefix), phase, phase + 1)
                    for phase in range(2)
                ),
                tuple(
                    LookupSide(
                        SUMMARY_TABLE,
                        const(1),
                        tuple(
                            cell(f"root_{'before' if phase == 0 else 'after'}_{index}")
                            for index in range(64)
                        ),
                        summary_row,
                        summary_row + 1,
                    )
                    for phase in range(2)
                ),
            )
        )
    metadata_lookup = LookupArgument(
        "typed_state_authority_payment_metadata",
        tuple(
            LookupSide(
                AUTHORITY_TABLE,
                const(1),
                (
                    *(cell(f"settlement_{index}") for index in range(64)),
                    *(cell(f"scope_{index}") for index in range(64)),
                    *(cell(f"epoch_byte_{index}") for index in range(8)),
                ),
                phase,
                phase + 1,
            )
            for phase in range(2)
        ),
        (
            LookupSide(
                "claim_payment_key_material",
                const(1),
                (
                    *(cell(f"settlement_byte_{index}") for index in range(64)),
                    *(cell(f"scope_byte_{index}") for index in range(64)),
                    *(cell(f"epoch_byte_{index}") for index in range(8)),
                ),
                0,
                2,
            ),
        ),
    )
    sequence_lookup = LookupArgument(
        "typed_state_authority_sequence",
        (
            LookupSide(
                AUTHORITY_TABLE,
                const(1),
                tuple(cell(f"sequence_byte_{index}") for index in range(8)),
                0,
                1,
            ),
        ),
        (
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                tuple(cell(f"sequence_byte_{index}") for index in range(8)),
                0,
                1,
            ),
        ),
    )
    rows = len(payment.traces["claim_payment_map_slot"].columns["slot_index"])
    operation_log_lookup = LookupArgument(
        "typed_state_authority_operation_log",
        (
            LookupSide(
                AUTHORITY_TABLE,
                const(1),
                tuple(cell(f"operation_log_root_{index}") for index in range(64)),
                0,
                1,
            ),
            LookupSide(
                AUTHORITY_TABLE,
                const(1),
                tuple(cell(f"operation_log_root_{index}") for index in range(64)),
                1,
                2,
            ),
        ),
        (
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                tuple(cell(f"operation_log_before_{index}") for index in range(64)),
                0,
                1,
            ),
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                tuple(cell(f"operation_log_after_{index}") for index in range(64)),
                rows - 1,
                rows,
            ),
        ),
    )
    root_calls = tuple(
        Sha3Call(
            f"c0_state_root_{'before' if phase == 0 else 'after'}",
            _C0_STATE_ROOT_DOMAIN + payment_states[phase].root() + replay_roots[phase],
            _STATE_ROOT_CAPACITY_BASE + state_witness.profile.claim_slots * _STATE_ROOT_ENTRY_WIDTH,
        )
        for phase in range(2)
    )
    return (
        table,
        trace,
        (*summary_links, metadata_lookup, sequence_lookup, operation_log_lookup),
        tuple(public_bindings),
        tuple(public_values),
        root_calls,
    )


def _root_component(
    authority_table: AirTable,
    authority_trace: TraceTable,
    authority_public: tuple[PublicInputBinding, ...],
    root_calls: tuple[Sha3Call, ...],
    call_index_offset: int,
) -> Sha3ComposedComponent:
    interface = build_application_sha3_interface_air(root_calls)
    message_rows = interface.traces["sha3_message_batch"].rows
    message_length = len(root_calls[0].message)

    def root_message_value(phase: int, position: int) -> Expr:
        domain_length = len(_C0_STATE_ROOT_DOMAIN)
        if position < domain_length:
            return const(_C0_STATE_ROOT_DOMAIN[position])
        if position < domain_length + 64:
            return cell(f"payment_root_{position - domain_length}")
        if position < domain_length + 128:
            return cell(f"replay_root_{position - domain_length - 64}")
        raise StructuralError("typed_state_root_message_position_invalid")

    message_sources: list[LookupSide] = []
    for phase in range(2):
        for position in range(message_length):
            message_sources.append(
                LookupSide(
                    AUTHORITY_TABLE,
                    const(1),
                    (
                        const(call_index_offset + phase),
                        const(position),
                        root_message_value(phase, position),
                    ),
                    phase,
                    phase + 1,
                )
            )
    message_binding = LookupArgument(
        "typed_state_root_sha3_messages",
        tuple(message_sources),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                message_rows,
            ),
        ),
    )
    digest_binding = LookupArgument(
        "typed_state_root_sha3_digests",
        tuple(
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (
                    const(call_index_offset + phase),
                    *(cell(f"value_{index}") for index in range(64)),
                ),
                phase,
                phase + 1,
            )
            for phase in range(2)
        ),
        tuple(
            LookupSide(
                AUTHORITY_TABLE,
                const(1),
                (
                    *(const(call_index_offset + phase) for _ in (0,)),
                    *(cell(f"state_root_{index}") for index in range(64)),
                ),
                phase,
                phase + 1,
            )
            for phase in range(2)
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (authority_table, *interface.program.tables),
        (
            *interface.program.lookups,
            message_binding,
            digest_binding,
        ),
        authority_public,
    )
    traces = MappingProxyType(
        {
            authority_trace.name: authority_trace,
            **dict(interface.traces),
        }
    )
    return Sha3ComposedComponent(program, traces, interface, call_index_offset)


def _compact_log_message_port(
    payment: ClaimPaymentMapsAirInstance,
    call_index_offset: int,
    slot_count: int,
) -> tuple[AirTable, TraceTable]:
    """Keep only the log-call message rows needed by the native H4 seam.

    Map and key messages already live in proof-native semantic port tables.
    Payment operation/log messages are the only calls whose complete
    preimages are assembled across the claim-payment tables and the prior
    operation digest.  Retaining this small interface preserves that exact
    AIR lookup while removing the global per-byte SHA3 message table.
    """

    if (
        not isinstance(payment, ClaimPaymentMapsAirInstance)
        or payment.application_sha3 is None
        or type(call_index_offset) is not int
        or call_index_offset < 0
        or type(slot_count) is not int
        or slot_count <= 0
    ):
        raise StructuralError("typed_state_log_message_port_input_invalid")
    calls = payment.application_sha3.calls
    log_call_count = 2 * slot_count
    if len(calls) < log_call_count:
        raise StructuralError("typed_state_log_message_port_call_count_invalid")
    log_calls = calls[-log_call_count:]
    source_table = next(
        table
        for table in payment.application_sha3.program.tables
        if table.name == "sha3_message_batch"
    )
    source_trace = payment.application_sha3.traces[source_table.name]
    packed_columns: dict[str, list[int]] = {
        "call_index": [],
        "position_base": [],
        **{f"live_{lane}": [] for lane in range(_LOG_MESSAGE_LANES)},
        **{f"value_{lane}": [] for lane in range(_LOG_MESSAGE_LANES)},
    }
    for call_ordinal, log_call in enumerate(log_calls):
        call_rows = payment.application_sha3.call_rows[log_call.call_id]
        padded_rows = call_rows.message_stop - call_rows.message_start
        message_rows = len(log_call.message)
        if message_rows <= 0 or message_rows > padded_rows:
            raise StructuralError("typed_state_log_message_port_length_invalid")
        for position in range(padded_rows):
            source_row = call_rows.message_start + position
            expected_live = int(position < message_rows)
            if (
                source_trace.columns["live"][source_row] != expected_live
                or source_trace.columns["value"][source_row]
                != (log_call.message[position] if expected_live else 0)
            ):
                raise StructuralError("typed_state_log_message_port_source_invalid")
        local_call_index = source_trace.columns["call_index"][call_rows.message_start]
        segments = (
            ((0, message_rows),)
            if call_ordinal < slot_count
            else ((0, message_rows - 64), (message_rows - 64, message_rows))
        )
        if any(start < 0 or start >= stop or stop > message_rows for start, stop in segments):
            raise StructuralError("typed_state_log_message_port_segment_invalid")
        for segment_start, segment_stop in segments:
            for position_base in range(segment_start, segment_stop, _LOG_MESSAGE_LANES):
                _append(packed_columns, "call_index", local_call_index + call_index_offset)
                _append(packed_columns, "position_base", position_base)
                for lane in range(_LOG_MESSAGE_LANES):
                    position = position_base + lane
                    live = int(position < segment_stop)
                    _append(packed_columns, f"live_{lane}", live)
                    _append(
                        packed_columns,
                        f"value_{lane}",
                        source_trace.columns["value"][call_rows.message_start + position]
                        if live
                        else 0,
                    )
    row_count = len(packed_columns["call_index"])
    if row_count == 0:
        raise StructuralError("typed_state_log_message_port_empty")
    fixed = {
        "call_index": tuple(packed_columns["call_index"]),
        "position_base": tuple(packed_columns["position_base"]),
        **{
            f"live_{lane}": tuple(packed_columns[f"live_{lane}"])
            for lane in range(_LOG_MESSAGE_LANES)
        },
    }
    return (
        AirTable(
            LOG_MESSAGE_TABLE,
            tuple(packed_columns),
            row_count,
            (),
            fixed,
        ),
        TraceTable(LOG_MESSAGE_TABLE, freeze_columns(packed_columns)),
    )


def _packed_bundle_value_side(
    mask: str | None,
    lane: int,
    row_count: int,
    weight,
) -> LookupSide:
    if type(lane) is not int or not 0 <= lane < _SOURCE_BUNDLE_LANES:
        raise StructuralError("typed_state_bundle_lane_invalid")
    selector = const(1) if mask is None else cell(f"{mask}_{lane}")
    return LookupSide(
        _PACKED_SOURCE_BUNDLE_TABLE,
        selector,
        (
            cell("slot_index"),
            cell("byte_index_base") + lane,
            cell(f"value_{lane}"),
        ),
        0,
        row_count,
        weight,
    )


def _packed_bundle_byte_value_sides(
    lane_mask: str | None,
    row_count: int,
    weight,
) -> tuple[LookupSide, ...]:
    return tuple(
        LookupSide(
            _PACKED_SOURCE_BUNDLE_TABLE,
            const(1) if lane_mask is None else cell(f"{lane_mask}_{lane}"),
            (cell(f"value_{lane}"),),
            0,
            row_count,
            weight,
        )
        for lane in range(_SOURCE_BUNDLE_LANES)
    )


def _pack_source_bundle_table(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
) -> tuple[AirProgram, Mapping[str, TraceTable]]:
    """Pack the duplicate claim bundle byte transport without changing lookups.

    Every packed lookup retains the original absolute byte index and value,
    with the lane carried as a separate key.  This is a representation change
    only: the fixed header, selector masks, byte range, and all source-field
    multiset obligations remain exact.
    """

    if _SOURCE_BUNDLE_TABLE not in traces:
        return program, traces
    source_table = next(
        table for table in program.tables if table.name == _SOURCE_BUNDLE_TABLE
    )
    source_trace = traces[_SOURCE_BUNDLE_TABLE]
    if source_table.rows % _SOURCE_BUNDLE_LANES:
        raise StructuralError("typed_state_bundle_row_alignment_invalid")
    source_columns = source_trace.columns
    bundle_rows = source_table.rows
    packed_rows = bundle_rows // _SOURCE_BUNDLE_LANES
    slot_values = tuple(source_columns["slot_index"])
    slot_count = len(set(slot_values))
    if slot_count == 0 or bundle_rows % slot_count:
        raise StructuralError("typed_state_bundle_slot_geometry_invalid")
    bytes_per_slot = bundle_rows // slot_count
    if source_columns["byte_index"] != tuple(
        index
        for _ in range(slot_count)
        for index in range(bytes_per_slot)
    ):
        raise StructuralError("typed_state_bundle_byte_index_invalid")
    if any(
        len(source_columns[name]) != bundle_rows for name in source_table.columns
    ):
        raise StructuralError("typed_state_bundle_trace_shape_invalid")

    packed_columns: dict[str, tuple[int, ...]] = {
        "slot_index": tuple(
            source_columns["slot_index"][row * _SOURCE_BUNDLE_LANES]
            for row in range(packed_rows)
        ),
        "word_index": tuple(
            row % bytes_per_slot
            for row in range(packed_rows)
        ),
        "byte_index_base": tuple(
            source_columns["byte_index"][row * _SOURCE_BUNDLE_LANES]
            for row in range(packed_rows)
        ),
    }
    for mask in _SOURCE_BUNDLE_MASKS:
        for lane in range(_SOURCE_BUNDLE_LANES):
            packed_columns[f"{mask}_{lane}"] = tuple(
                source_columns[mask][row * _SOURCE_BUNDLE_LANES + lane]
                for row in range(packed_rows)
            )
    for prefix in ("fixed_value_active", "fixed_value"):
        for lane in range(_SOURCE_BUNDLE_LANES):
            packed_columns[f"{prefix}_{lane}"] = tuple(
                source_columns[prefix][row * _SOURCE_BUNDLE_LANES + lane]
                for row in range(packed_rows)
            )
    for lane in range(_SOURCE_BUNDLE_LANES):
        packed_columns[f"value_{lane}"] = tuple(
            source_columns["value"][row * _SOURCE_BUNDLE_LANES + lane]
            for row in range(packed_rows)
        )
    packed_column_names = tuple(packed_columns)
    packed_fixed = {
        name: values
        for name, values in packed_columns.items()
        if not name.startswith("value_")
    }
    packed_table = AirTable(
        _PACKED_SOURCE_BUNDLE_TABLE,
        packed_column_names,
        packed_rows,
        tuple(
            Identity(
                f"fixed_header_value_{lane}",
                cell(f"fixed_value_active_{lane}")
                * (cell(f"value_{lane}") - cell(f"fixed_value_{lane}")),
                0,
                packed_rows,
            )
            for lane in range(_SOURCE_BUNDLE_LANES)
        ),
        MappingProxyType(packed_fixed),
    )
    packed_trace = TraceTable(
        _PACKED_SOURCE_BUNDLE_TABLE,
        freeze_columns(packed_columns),
    )

    def replace_lookup(lookup: LookupArgument) -> LookupArgument:
        if lookup.name in {
            "claim_source_token_bytes_match_bundle",
            "claim_source_scalar_bytes_match_bundle",
            "claim_source_diagnosis_bytes_match_bundle",
            "claim_source_service_bytes_match_bundle",
        }:
            if len(lookup.destinations) != 1 or lookup.destinations[0].table != _SOURCE_BUNDLE_TABLE:
                raise StructuralError("typed_state_bundle_lookup_shape_invalid")
            old = lookup.destinations[0]
            mask = {
                "claim_source_token_bytes_match_bundle": "is_token_byte",
                "claim_source_scalar_bytes_match_bundle": "is_scalar_byte",
                "claim_source_diagnosis_bytes_match_bundle": "is_diagnosis_byte",
                "claim_source_service_bytes_match_bundle": "is_service_non_token_byte",
            }[lookup.name]
            return LookupArgument(
                lookup.name,
                lookup.sources,
                tuple(
                    _packed_bundle_value_side(
                        mask, lane, packed_rows, old.weight
                    )
                    for lane in range(_SOURCE_BUNDLE_LANES)
                ),
            )
        if lookup.name == "claim_source_values_are_bytes":
            old_sources = tuple(
                side for side in lookup.sources if side.table == _SOURCE_BUNDLE_TABLE
            )
            if len(old_sources) != 1:
                raise StructuralError("typed_state_bundle_lookup_shape_invalid")
            old = old_sources[0]
            sources = tuple(
                side for side in lookup.sources if side.table != _SOURCE_BUNDLE_TABLE
            )
            return LookupArgument(
                lookup.name,
                (*sources, *_packed_bundle_byte_value_sides(None, packed_rows, old.weight)),
                lookup.destinations,
            )
        if lookup.name == "claim_source_hash_leaf_messages":
            old_sources = tuple(
                side for side in lookup.sources if side.table == _SOURCE_BUNDLE_TABLE
            )
            if len(old_sources) != 1:
                raise StructuralError("typed_state_bundle_lookup_shape_invalid")
            old = old_sources[0]
            source_values = (
                cell("slot_index") + old.values[0].right.value
                if old.values[0].kind == "add"
                and old.values[0].right is not None
                and old.values[0].right.kind == "const"
                and type(old.values[0].right.value) is int
                else None
            )
            if source_values is None:
                raise StructuralError("typed_state_bundle_leaf_offset_invalid")
            packed_sources = tuple(
                LookupSide(
                    _PACKED_SOURCE_BUNDLE_TABLE,
                    const(1),
                    (
                        source_values,
                        cell("byte_index_base") + lane,
                        cell(f"value_{lane}"),
                    ),
                    0,
                    packed_rows,
                    old.weight,
                )
                for lane in range(_SOURCE_BUNDLE_LANES)
            )
            return LookupArgument(
                lookup.name,
                packed_sources,
                tuple(side for side in lookup.destinations if side.table != _SOURCE_BUNDLE_TABLE),
            )
        if any(
            side.table == _SOURCE_BUNDLE_TABLE
            for side in (*lookup.sources, *lookup.destinations)
        ):
            raise StructuralError(f"typed_state_bundle_lookup_unhandled:{lookup.name}")
        return lookup

    tables = tuple(
        packed_table if table.name == _SOURCE_BUNDLE_TABLE else table
        for table in program.tables
    )
    compact_lookups = tuple(replace_lookup(lookup) for lookup in program.lookups)
    if any(
        binding.table == _SOURCE_BUNDLE_TABLE for binding in program.public_inputs
    ):
        raise StructuralError("typed_state_bundle_public_input_invalid")
    compact_traces = MappingProxyType(
        {
            _PACKED_SOURCE_BUNDLE_TABLE: packed_trace,
            **{
                name: trace
                for name, trace in traces.items()
                if name != _SOURCE_BUNDLE_TABLE
            },
        }
    )
    return (
        AirProgram(program.program_id, tables, compact_lookups, program.public_inputs),
        compact_traces,
    )


def _retarget_log_message_lookup(
    lookup: LookupArgument,
    message_rows: int,
) -> LookupArgument:
    if lookup.name != "claim_payment_log_sha3_messages":
        return lookup
    if len(lookup.destinations) != 1:
        raise StructuralError("typed_state_log_message_lookup_shape_invalid")
    destination = lookup.destinations[0]
    if destination.table != "sha3_message_batch":
        raise StructuralError("typed_state_log_message_lookup_table_invalid")
    grouped_sources: list[LookupSide] = []
    run: list[LookupSide] = []
    previous_position: int | None = None

    def flush_run() -> None:
        nonlocal run
        for start in range(0, len(run), _LOG_MESSAGE_LANES):
            block = run[start : start + _LOG_MESSAGE_LANES]
            values = []
            for lane in range(_LOG_MESSAGE_LANES):
                if lane < len(block):
                    values.extend((const(1), *block[lane].values))
                else:
                    values.extend((const(0), const(0), const(0), const(0)))
            first = block[0]
            grouped_sources.append(
                LookupSide(
                    first.table,
                    const(1),
                    tuple(values),
                    first.row_start,
                    first.row_stop,
                    first.weight,
                )
            )
        run = []

    for side in lookup.sources:
        if (
            side.selector != const(1)
            or len(side.values) != 3
            or side.values[1].kind != "const"
        ):
            raise StructuralError("typed_state_log_message_lookup_source_invalid")
        position = side.values[1].value
        if type(position) is not int or position < 0:
            raise StructuralError("typed_state_log_message_lookup_position_invalid")
        if run:
            first = run[0]
            contiguous = (
                side.table == first.table
                and side.selector == first.selector
                and side.weight == first.weight
                and side.row_start == first.row_start
                and side.row_stop == first.row_stop
                and previous_position is not None
                and position == previous_position + 1
            )
            if not contiguous:
                flush_run()
        run.append(side)
        previous_position = position
    if run:
        flush_run()

    destination_values = []
    for lane in range(_LOG_MESSAGE_LANES):
        live = cell(f"live_{lane}")
        destination_values.extend(
            (
                live,
                live * cell("call_index"),
                live * (cell("position_base") + lane),
                cell(f"value_{lane}"),
            )
        )
    return LookupArgument(
        lookup.name,
        tuple(grouped_sources),
        (
            LookupSide(
                LOG_MESSAGE_TABLE,
                const(1),
                tuple(destination_values),
                0,
                message_rows,
                destination.weight,
            ),
        ),
    )


def _compact_sha3_interface(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    log_message_rows: int,
) -> tuple[AirProgram, Mapping[str, TraceTable]]:
    removed_tables = _REMOVED_SHA3_TABLES | _REMOVED_MAP_PORT_TABLES
    tables = tuple(table for table in program.tables if table.name not in removed_tables)
    table_names = {table.name for table in tables}
    compact_lookups: list[LookupArgument] = []
    for lookup in program.lookups:
        lookup = _retarget_log_message_lookup(lookup, log_message_rows)
        sides = (*lookup.sources, *lookup.destinations)
        if any(side.table not in table_names for side in sides):
            continue
        compact_lookups.append(lookup)
    compact_traces = MappingProxyType(
        {name: trace for name, trace in traces.items() if name in table_names}
    )
    if set(compact_traces) != table_names:
        raise StructuralError("typed_state_compact_trace_set_invalid")
    return (
        AirProgram(
            program.program_id,
            tables,
            tuple(compact_lookups),
            program.public_inputs,
        ),
        compact_traces,
    )


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
    (
        authority_table,
        authority_trace,
        authority_lookups,
        authority_public,
        authority_values,
        root_calls,
    ) = _authority_columns(state_witness, replay, payment)
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
    root_component = _root_component(
        authority_table,
        authority_trace,
        authority_public,
        root_calls,
        len(replay_calls) + len(payment.application_sha3.calls),
    )
    log_message_table, log_message_trace = _compact_log_message_port(
        payment,
        len(replay_calls),
        len(state_witness.slots),
    )
    merged = compose_sha3_interface_components(
        PROGRAM_ID,
        (replay_component, payment_component, root_component),
        extra_tables=(summary_table, money_table, money_byte_table, log_message_table),
        extra_traces={
            summary_trace.name: summary_trace,
            money_trace.name: money_trace,
            money_byte_trace.name: money_byte_trace,
            log_message_trace.name: log_message_trace,
        },
        extra_lookups=(
            summary_link,
            money_link,
            money_byte_link,
            *authority_lookups,
        ),
        extra_public_inputs=(*summary_public, *money_public),
    )
    packed_program, packed_traces = _pack_source_bundle_table(
        merged.program,
        merged.traces,
    )
    compact_program, compact_traces = _compact_sha3_interface(
        packed_program,
        packed_traces,
        log_message_table.rows,
    )
    public_values = (*authority_values, *summary_values, *money_values)
    instance = TypedStateRelationAirInstance(
        compact_program,
        compact_traces,
        state_witness,
        replay,
        payment,
        public_values,
        replay_calls + tuple(payment.application_sha3.calls) + root_calls
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
    "AUTHORITY_TABLE",
    "TypedStateRelationAirInstance",
    "build_c0_typed_state_relation_air",
    "build_typed_state_relation_air",
    "verify_typed_state_relation_air",
)
