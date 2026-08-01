"""One-engine executable SHA3 AIR for authoritative Wave 1A commitments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    BATCH_DOMAIN,
    GOVERNANCE_DOMAIN,
    PROTOCOL_VERSION,
    SETTLEMENT_DOMAIN,
    VALUE_DOMAIN,
    MasterCommitmentInputsV2,
    MasterCommitmentsV2,
    batch_preimage,
    build_master_commitments_v2,
    governance_preimage,
    settlement_preimage,
    value_preimage,
)

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
)
from .executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-MASTER-COMMITMENTS-SHA3-AIR-v2"
OUTPUT_NAMES: Final[tuple[str, ...]] = (
    "governance",
    "batch",
    "value_conservation",
    "settlement",
)
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


@dataclass(frozen=True, slots=True)
class MasterCommitmentsAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    inputs: MasterCommitmentInputsV2
    commitments: MasterCommitmentsV2
    field_ids: Mapping[str, int]
    call_index_offset: int
    master_hashes_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        tables = {table.name for table in self.program.tables}
        lookups = {lookup.name for lookup in self.program.lookups}
        if (not self.master_hashes_constrained and not self.hash_ports_constrained) or not {
            "master_commitment_material_byte",
            "master_commitment_material_message_byte",
            "master_commitment_chain_message_byte",
            "master_commitment_constant_message_byte",
            "master_commitment_output_byte",
            "master_commitment_slot",
            "master_commitment_economic_totals",
        }.issubset(tables) or not {
            "master_commitment_material_reuse",
            "master_commitment_digest_chain",
            "master_commitment_sha3_messages",
            "master_commitment_sha3_digests",
            "master_commitment_slot_encoding",
            "master_commitment_economic_encoding",
            "master_commitment_economic_slot_totals",
        }.issubset(lookups):
            raise StructuralError("master_commitment_air_false_completion_claim")
        if self.sha3_interface_only != self.hash_ports_constrained or (
            self.sha3_interface_only and self.master_hashes_constrained
        ):
            raise StructuralError("master_commitment_air_false_completion_claim")


def _build_layout(
    value: MasterCommitmentInputsV2,
    commitments: MasterCommitmentsV2,
    call_index_offset: int,
) -> tuple[
    tuple[bytes, ...],
    dict[str, bytes],
    list[tuple[int, int, int, int, int]],
    list[tuple[int, int, int]],
    list[tuple[int, int, int, int, int]],
]:
    fields: dict[str, bytes] = {}
    material_occurrences: list[tuple[int, int, int, int, int]] = []
    constants: list[tuple[int, int, int]] = []
    chains: list[tuple[int, int, int, int, int]] = []
    field_ids: dict[str, int] = {}
    messages: list[bytes] = []

    def register(name: str, raw: bytes) -> int:
        previous = fields.get(name)
        if previous is not None and previous != raw:
            raise StructuralError(f"master_commitment_field_conflict:{name}")
        if previous is None:
            field_ids[name] = len(field_ids)
            fields[name] = raw
        return field_ids[name]

    def call(parts: tuple[tuple[str, str | int, bytes], ...]) -> None:
        call_index = call_index_offset + len(messages)
        message = bytearray()
        for kind, label, raw in parts:
            position = len(message)
            message.extend(raw)
            if kind == "constant":
                constants.extend(
                    (call_index, position + index, byte)
                    for index, byte in enumerate(raw)
                )
            elif kind == "field":
                field_id = register(str(label), raw)
                material_occurrences.extend(
                    (call_index, position + index, field_id, index, byte)
                    for index, byte in enumerate(raw)
                )
            elif kind == "chain":
                output_id = int(label)
                chains.extend(
                    (call_index, position + index, output_id, index, byte)
                    for index, byte in enumerate(raw)
                )
            else:
                raise StructuralError("master_commitment_layout_kind_invalid")
        messages.append(bytes(message))

    truth_parts = tuple(
        ("field", f"claim_truth_root_{index}", root)
        for index, root in enumerate(value.claim_truth_roots_512)
    )
    payment_before_parts = tuple(
        ("field", f"payment_lane_before_{index}", root)
        for index, root in enumerate(value.payment_lane_roots_before_512)
    )
    payment_after_parts = tuple(
        ("field", f"payment_lane_after_{index}", root)
        for index, root in enumerate(value.payment_lane_roots_after_512)
    )
    slot_parts = tuple(
        ("field", f"slot_{index}", slot.encode())
        for index, slot in enumerate(value.slots)
    )
    epoch = value.epoch.to_bytes(8, "big")
    profile = bytes((_PROFILE_CODES[value.profile_id],))
    protocol = PROTOCOL_VERSION.to_bytes(2, "big")
    slot_count = len(value.slots).to_bytes(2, "big")

    call(
        (
            ("constant", "governance_domain", GOVERNANCE_DOMAIN),
            ("constant", "profile", profile),
            ("field", "epoch", epoch),
            *truth_parts,
            ("field", "claim_truth_authority_digest", value.claim_truth_authority_digest_512),
            ("field", "nullifier_authority_id", value.nullifier_authority_id_512),
            ("field", "pepper_commitment", value.pepper_commitment_512),
        )
    )
    call(
        (
            ("constant", "batch_domain", BATCH_DOMAIN),
            ("constant", "profile", profile),
            ("constant", "protocol", protocol),
            ("field", "epoch", epoch),
            ("field", "settlement_domain", value.strong_settlement_domain_id_512),
            ("field", "batch_nonce", value.strong_batch_nonce_512),
            ("constant", "slot_count", slot_count),
            ("chain", 0, commitments.governance_512),
            ("field", "replay_before", value.replay_root_before_512),
            ("field", "replay_after", value.replay_root_after_512),
            *payment_before_parts,
            *payment_after_parts,
            ("field", "operation_log_before", value.operation_log_root_before_512),
            ("field", "operation_log_after", value.operation_log_root_after_512),
            *slot_parts,
            ("field", "salt_use_tag", value.salt_use_tag_512),
        )
    )
    call(
        (
            ("constant", "value_domain", VALUE_DOMAIN),
            ("field", "epoch", epoch),
            ("field", "batch_nonce", value.strong_batch_nonce_512),
            ("field", "economic_totals", value.economic_totals.encode()),
            *payment_before_parts,
            *payment_after_parts,
            ("field", "operation_log_before", value.operation_log_root_before_512),
            ("field", "operation_log_after", value.operation_log_root_after_512),
        )
    )
    call(
        (
            ("constant", "settlement_domain_prefix", SETTLEMENT_DOMAIN),
            ("constant", "protocol", protocol),
            ("field", "settlement_domain", value.strong_settlement_domain_id_512),
            ("field", "batch_nonce", value.strong_batch_nonce_512),
            ("chain", 0, commitments.governance_512),
            ("chain", 1, commitments.batch_512),
            ("chain", 2, commitments.value_conservation_512),
            ("field", "replay_before", value.replay_root_before_512),
            ("field", "replay_after", value.replay_root_after_512),
            *payment_before_parts,
            *payment_after_parts,
            ("field", "operation_log_before", value.operation_log_root_before_512),
            ("field", "operation_log_after", value.operation_log_root_after_512),
        )
    )
    expected = (
        governance_preimage(value),
        batch_preimage(value, commitments.governance_512),
        value_preimage(value),
        settlement_preimage(
            value,
            commitments.governance_512,
            commitments.batch_512,
            commitments.value_conservation_512,
        ),
    )
    if tuple(messages) != expected:
        raise StructuralError("master_commitment_layout_preimage_mismatch")
    return tuple(messages), fields, material_occurrences, constants, chains


def _slot_semantic_table(
    value: MasterCommitmentInputsV2,
    field_ids: Mapping[str, int],
    material_table: AirTable,
    material_trace: TraceTable,
) -> tuple[AirTable, TraceTable, LookupArgument]:
    columns: dict[str, list[int]] = {
        "slot_index": [],
        **{f"encoded_{index}": [] for index in range(81)},
        **{f"raw_gate_{index}": [] for index in range(13)},
        **{f"effective_gate_{index}": [] for index in range(13)},
    }
    running = {"gross": 0, "payment": 0}
    for slot in value.slots:
        columns["slot_index"].append(slot.slot_index)
        encoded = slot.encode()
        for index, byte in enumerate(encoded):
            columns[f"encoded_{index}"].append(byte)
        for index in range(13):
            columns[f"raw_gate_{index}"].append((slot.raw_gate_bits >> index) & 1)
            columns[f"effective_gate_{index}"].append(
                (slot.effective_gate_bits >> index) & 1
            )
        for label, delta in (
            ("gross", slot.allowed_cents),
            ("payment", slot.payment_cents),
        ):
            before = running[label]
            after = before + delta
            carry = 0
            for limb in range(4):
                before_limb = (before >> (16 * limb)) & 0xFFFF
                after_limb = (after >> (16 * limb)) & 0xFFFF
                delta_limb = (delta >> (16 * limb)) & 0xFFFF
                total = before_limb + delta_limb + carry
                next_carry = total >> 16
                columns.setdefault(f"{label}_before_{limb}", []).append(before_limb)
                columns.setdefault(f"{label}_after_{limb}", []).append(after_limb)
                columns.setdefault(f"{label}_carry_{limb}", []).append(next_carry)
                carry = next_carry
            running[label] = after
    rows = len(value.slots)
    identities: list[Identity] = [
        Identity(
            "slot_index_encoding",
            cell("slot_index") - 256 * cell("encoded_0") - cell("encoded_1"),
            0,
            rows,
        ),
        Identity("slot_decision_boolean", boolean(cell("encoded_2")), 0, rows),
        Identity(
            "slot_raw_gate_mask",
            256 * cell("encoded_13")
            + cell("encoded_14")
            - sum(
                (cell(f"raw_gate_{index}") * (1 << index) for index in range(13)),
                const(0),
            ),
            0,
            rows,
        ),
        Identity(
            "slot_effective_gate_mask",
            256 * cell("encoded_15")
            + cell("encoded_16")
            - sum(
                (
                    cell(f"effective_gate_{index}") * (1 << index)
                    for index in range(13)
                ),
                const(0),
            ),
            0,
            rows,
        ),
    ]
    for family in ("raw", "effective"):
        identities.extend(
            Identity(
                f"slot_{family}_gate_boolean_{index}",
                boolean(cell(f"{family}_gate_{index}")),
                0,
                rows,
            )
            for index in range(13)
        )
    for label, byte_start in (("gross", 5), ("payment", 9)):
        for limb in range(4):
            delta = (
                256 * cell(f"encoded_{byte_start + 2}")
                + cell(f"encoded_{byte_start + 3}")
                if limb == 0
                else 256 * cell(f"encoded_{byte_start}")
                + cell(f"encoded_{byte_start + 1}")
                if limb == 1
                else const(0)
            )
            previous_carry = const(0) if limb == 0 else cell(f"{label}_carry_{limb - 1}")
            identities.extend(
                (
                    Identity(
                        f"slot_{label}_accumulate_{limb}",
                        cell(f"{label}_before_{limb}")
                        + delta
                        + previous_carry
                        - cell(f"{label}_after_{limb}")
                        - 65536 * cell(f"{label}_carry_{limb}"),
                        0,
                        rows,
                    ),
                    Identity(
                        f"slot_{label}_carry_boolean_{limb}",
                        boolean(cell(f"{label}_carry_{limb}")),
                        0,
                        rows,
                    ),
                    Identity(
                        f"slot_{label}_initial_{limb}",
                        cell(f"{label}_before_{limb}"),
                        0,
                        1,
                        "boundary",
                    ),
                )
            )
            if rows > 1:
                identities.append(
                    Identity(
                        f"slot_{label}_chain_{limb}",
                        cell(f"{label}_after_{limb}")
                        - cell(f"{label}_before_{limb}", 1),
                        0,
                        rows - 1,
                        "transition",
                    )
                )
        identities.append(
            Identity(
                f"slot_{label}_terminal_no_overflow",
                cell(f"{label}_carry_3"),
                0,
                rows,
            )
        )
    frozen = freeze_columns(columns)
    trace = TraceTable("master_commitment_slot", frozen)
    table = AirTable(
        trace.name,
        tuple(frozen),
        rows,
        tuple(identities),
        MappingProxyType({"slot_index": tuple(range(rows))}),
    )
    slot_field_base = field_ids["slot_0"]
    material_start = next(
        index
        for index, observed in enumerate(material_trace.columns["field_id"])
        if observed == slot_field_base
    )
    slot_encoding = LookupArgument(
        "master_commitment_slot_encoding",
        tuple(
            LookupSide(
                table.name,
                const(1),
                (
                    cell("slot_index") + slot_field_base,
                    const(byte_index),
                    cell(f"encoded_{byte_index}"),
                ),
                0,
                rows,
            )
            for byte_index in range(81)
        ),
        (
            LookupSide(
                material_table.name,
                const(1),
                (cell("field_id"), cell("byte_index"), cell("value")),
                material_start,
                material_start + rows * 81,
            ),
        ),
    )
    return table, trace, slot_encoding


def _economic_semantic_table(
    value: MasterCommitmentInputsV2,
    field_ids: Mapping[str, int],
    material_table: AirTable,
    material_trace: TraceTable,
    slot_table: AirTable,
    slot_trace: TraceTable,
) -> tuple[AirTable, TraceTable, tuple[LookupArgument, LookupArgument]]:
    encoded = value.economic_totals.encode()
    gross = value.economic_totals.gross_allowed_cents
    responsibility = value.economic_totals.patient_responsibility_cents
    plan = value.economic_totals.plan_payable_cents
    carries: list[int] = []
    carry = 0
    for limb in range(4):
        total = (
            (responsibility >> (16 * limb)) & 0xFFFF
        ) + ((plan >> (16 * limb)) & 0xFFFF) + carry
        carries.append(total >> 16)
        carry = total >> 16
    columns = freeze_columns(
        {
            "row": (0,),
            **{f"encoded_{index}": (byte,) for index, byte in enumerate(encoded)},
            **{f"gross_carry_{index}": (carry,) for index, carry in enumerate(carries)},
        }
    )

    def limb(metric: int, index: int):
        start = metric * 8 + 6 - 2 * index
        return 256 * cell(f"encoded_{start}") + cell(f"encoded_{start + 1}")

    identities: list[Identity] = []
    for index in range(4):
        previous = const(0) if index == 0 else cell(f"gross_carry_{index - 1}")
        identities.extend(
            (
                Identity(
                    f"economic_gross_conservation_{index}",
                    limb(1, index)
                    + limb(2, index)
                    + previous
                    - limb(0, index)
                    - 65536 * cell(f"gross_carry_{index}"),
                    0,
                    1,
                ),
                Identity(
                    f"economic_gross_carry_boolean_{index}",
                    boolean(cell(f"gross_carry_{index}")),
                    0,
                    1,
                ),
                Identity(
                    f"economic_debit_conservation_{index}",
                    limb(2, index) - limb(3, index),
                    0,
                    1,
                ),
                Identity(
                    f"economic_credit_conservation_{index}",
                    limb(2, index) - limb(4, index),
                    0,
                    1,
                ),
            )
        )
    identities.append(
        Identity("economic_gross_terminal_no_overflow", cell("gross_carry_3"), 0, 1)
    )
    trace = TraceTable("master_commitment_economic_totals", columns)
    table = AirTable(trace.name, tuple(columns), 1, tuple(identities), MappingProxyType({"row": (0,)}))
    field_id = field_ids["economic_totals"]
    material_start = next(
        index
        for index, observed in enumerate(material_trace.columns["field_id"])
        if observed == field_id
    )
    encoding = LookupArgument(
        "master_commitment_economic_encoding",
        tuple(
            LookupSide(
                table.name,
                const(1),
                (const(field_id), const(index), cell(f"encoded_{index}")),
                0,
                1,
            )
            for index in range(40)
        ),
        (
            LookupSide(
                material_table.name,
                const(1),
                (cell("field_id"), cell("byte_index"), cell("value")),
                material_start,
                material_start + 40,
            ),
        ),
    )
    totals = LookupArgument(
        "master_commitment_economic_slot_totals",
        (
            LookupSide(
                slot_table.name,
                const(1),
                (
                    *(cell(f"gross_after_{index}") for index in range(4)),
                    *(cell(f"payment_after_{index}") for index in range(4)),
                ),
                slot_trace.rows - 1,
                slot_trace.rows,
            ),
        ),
        (
            LookupSide(
                table.name,
                const(1),
                (
                    *(limb(0, index) for index in range(4)),
                    *(limb(2, index) for index in range(4)),
                ),
                0,
                1,
            ),
        ),
    )
    return table, trace, (encoding, totals)


def build_master_commitments_executable_air(
    value: MasterCommitmentInputsV2,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> MasterCommitmentsAirInstance:
    if not isinstance(value, MasterCommitmentInputsV2):
        raise StructuralError("master_commitment_air_inputs_required")
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("master_commitment_air_call_offset_invalid")
    commitments = build_master_commitments_v2(value)
    messages, fields, material_occurrences, constant_rows, chain_rows = _build_layout(
        value, commitments, call_index_offset
    )
    calls = tuple(
        Sha3Call(f"master_{name}", message, len(message))
        for name, message in zip(OUTPUT_NAMES, messages, strict=True)
    )
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    field_ids = {name: index for index, name in enumerate(fields)}
    occurrence_bytes = Counter(row[2] for row in material_occurrences)
    occurrence_counts = {
        field_id: occurrence_bytes[field_id] // len(fields[name])
        for name, field_id in field_ids.items()
    }
    material_rows = tuple(
        (field_ids[name], index, byte, occurrence_counts[field_ids[name]])
        for name, raw in fields.items()
        for index, byte in enumerate(raw)
    )
    material_columns = freeze_columns(
        {
            "field_id": tuple(row[0] for row in material_rows),
            "byte_index": tuple(row[1] for row in material_rows),
            "value": tuple(row[2] for row in material_rows),
            "occurrence_count": tuple(row[3] for row in material_rows),
        }
    )
    material_trace = TraceTable("master_commitment_material_byte", material_columns)
    material_table = AirTable(
        material_trace.name,
        tuple(material_columns),
        material_trace.rows,
        (),
        MappingProxyType(
            {
                name: material_columns[name]
                for name in ("field_id", "byte_index", "occurrence_count")
            }
        ),
    )

    def byte_table(
        name: str,
        rows: list[tuple[int, ...]],
        columns: tuple[str, ...],
        *,
        fixed_value: bool = False,
    ) -> tuple[AirTable, TraceTable]:
        frozen = freeze_columns(
            {column: tuple(row[index] for row in rows) for index, column in enumerate(columns)}
        )
        trace = TraceTable(name, frozen)
        fixed_names = columns if fixed_value else columns[:-1]
        table = AirTable(
            name,
            columns,
            trace.rows,
            (),
            MappingProxyType({column: frozen[column] for column in fixed_names}),
        )
        return table, trace

    material_message_table, material_message_trace = byte_table(
        "master_commitment_material_message_byte",
        material_occurrences,
        ("call_index", "position", "field_id", "byte_index", "value"),
    )
    constant_table, constant_trace = byte_table(
        "master_commitment_constant_message_byte",
        constant_rows,
        ("call_index", "position", "value"),
        fixed_value=True,
    )
    chain_table, chain_trace = byte_table(
        "master_commitment_chain_message_byte",
        chain_rows,
        ("call_index", "position", "output_id", "byte_index", "value"),
    )
    output_values = (
        commitments.governance_512,
        commitments.batch_512,
        commitments.value_conservation_512,
        commitments.settlement_512,
    )
    chain_counts = tuple(sum(row[2] == output_id for row in chain_rows) // 64 for output_id in range(4))
    output_rows = [
        (output_id, index, byte, chain_counts[output_id])
        for output_id, raw in enumerate(output_values)
        for index, byte in enumerate(raw)
    ]
    output_columns = freeze_columns(
        {
            "output_id": tuple(row[0] for row in output_rows),
            "byte_index": tuple(row[1] for row in output_rows),
            "value": tuple(row[2] for row in output_rows),
            "chain_count": tuple(row[3] for row in output_rows),
        }
    )
    output_trace = TraceTable("master_commitment_output_byte", output_columns)
    output_table = AirTable(
        output_trace.name,
        tuple(output_columns),
        output_trace.rows,
        (),
        MappingProxyType(
            {
                name: output_columns[name]
                for name in ("output_id", "byte_index", "chain_count")
            }
        ),
    )
    slot_table, slot_trace, slot_encoding = _slot_semantic_table(
        value,
        field_ids,
        material_table,
        material_trace,
    )
    economic_table, economic_trace, economic_lookups = _economic_semantic_table(
        value,
        field_ids,
        material_table,
        material_trace,
        slot_table,
        slot_trace,
    )
    material_reuse = LookupArgument(
        "master_commitment_material_reuse",
        (
            LookupSide(
                material_table.name,
                const(1),
                (cell("field_id"), cell("byte_index"), cell("value")),
                0,
                material_trace.rows,
                cell("occurrence_count"),
            ),
        ),
        (
            LookupSide(
                material_message_table.name,
                const(1),
                (cell("field_id"), cell("byte_index"), cell("value")),
                0,
                material_message_trace.rows,
            ),
        ),
    )
    digest_chain = LookupArgument(
        "master_commitment_digest_chain",
        (
            LookupSide(
                output_table.name,
                const(1),
                (cell("output_id"), cell("byte_index"), cell("value")),
                0,
                output_trace.rows,
                cell("chain_count"),
            ),
        ),
        (
            LookupSide(
                chain_table.name,
                const(1),
                (cell("output_id"), cell("byte_index"), cell("value")),
                0,
                chain_trace.rows,
            ),
        ),
    )
    sha_messages = LookupArgument(
        "master_commitment_sha3_messages",
        (
            LookupSide(
                material_message_table.name,
                const(1),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                material_message_trace.rows,
            ),
            LookupSide(
                constant_table.name,
                const(1),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                constant_trace.rows,
            ),
            LookupSide(
                chain_table.name,
                const(1),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                chain_trace.rows,
            ),
        ),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                sha3.traces["sha3_message_batch"].rows,
            ),
        ),
    )
    sha_digests = LookupArgument(
        "master_commitment_sha3_digests",
        (
            LookupSide(
                "sha3_digest_byte_batch",
                const(1),
                (
                    cell("call_index"),
                    cell("byte_index"),
                    cell("value"),
                ),
                0,
                sha3.traces["sha3_digest_byte_batch"].rows,
            ),
        ),
        (
            LookupSide(
                output_table.name,
                const(1),
                (cell("output_id") + call_index_offset, cell("byte_index"), cell("value")),
                0,
                output_trace.rows,
            ),
        ),
    )
    local_tables = (
        material_table,
        material_message_table,
        constant_table,
        chain_table,
        output_table,
        slot_table,
        economic_table,
    )
    local_traces = {
        material_trace.name: material_trace,
        material_message_trace.name: material_message_trace,
        constant_trace.name: constant_trace,
        chain_trace.name: chain_trace,
        output_trace.name: output_trace,
        slot_trace.name: slot_trace,
        economic_trace.name: economic_trace,
    }
    program = AirProgram(
        PROGRAM_ID,
        (*local_tables, *sha3.program.tables),
        (
            *sha3.program.lookups,
            material_reuse,
            digest_chain,
            sha_messages,
            sha_digests,
            slot_encoding,
            *economic_lookups,
        ),
    )
    return MasterCommitmentsAirInstance(
        program,
        MappingProxyType({**local_traces, **dict(sha3.traces)}),
        sha3,
        value,
        commitments,
        MappingProxyType(field_ids),
        call_index_offset,
        master_hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = (
    "MasterCommitmentsAirInstance",
    "OUTPUT_NAMES",
    "build_master_commitments_executable_air",
)
