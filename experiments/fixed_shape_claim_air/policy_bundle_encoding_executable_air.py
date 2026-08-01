"""Executable fixed-shape encoding constraints for packed claim policy bundles."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    BUNDLE_MAGIC,
    LINE_BASE,
    LINE_BYTES,
    POLICY_BUNDLE_BYTES,
    PolicyCommitments,
    build_policy_commitments,
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
from .profile import SERVICE_LINES_PER_CLAIM, CalibrationProfile
from .semantics import ClaimSlot


PROGRAM_ID: Final[str] = "BL-WAVE1A-PACKED-POLICY-ENCODING-AIR-v1"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


@dataclass(frozen=True, slots=True)
class PolicyBundleEncodingAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    commitments: PolicyCommitments
    policy_payload_constrained: bool = True
    policy_hashes_constrained: bool = False
    policy_signer_epoch_constrained: bool = False


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def build_policy_bundle_encoding_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> PolicyBundleEncodingAirInstance:
    materialized = tuple(slots)
    commitments = build_policy_commitments(profile, materialized)
    bundles = commitments.bundles
    rows = profile.claim_slots * SERVICE_LINES_PER_CLAIM

    line: dict[str, list[int]] = {}
    for slot, bundle in zip(materialized, bundles, strict=True):
        for index in range(SERVICE_LINES_PER_CLAIM):
            base = LINE_BASE + index * LINE_BYTES
            enabled = bundle[base]
            length = bundle[base + 2]
            _append(line, "slot_index", slot.slot_index)
            _append(line, "line_index", index)
            _append(line, "has_next", int(index + 1 < SERVICE_LINES_PER_CLAIM))
            _append(line, "enabled", enabled)
            _append(line, "present", bundle[base + 1])
            _append(line, "procedure_length", length)
            for char_index in range(10):
                _append(line, f"procedure_char_{char_index}", bundle[base + 3 + char_index])
                _append(line, f"procedure_active_{char_index}", int(char_index < length))
            for byte_index in range(4):
                _append(line, f"allowed_byte_{byte_index}", bundle[base + 13 + byte_index])
            _append(line, "requires_authorization", bundle[base + 17])

    frozen_line = freeze_columns({name: tuple(values) for name, values in line.items()})
    identities: list[Identity] = []
    for name in ("enabled", "present", "requires_authorization"):
        identities.append(Identity(f"{name}_boolean", boolean(cell(name)), 0, rows))
    identities.extend(
        (
            Identity(
                "procedure_length",
                cell("procedure_length")
                - sum(
                    (cell(f"procedure_active_{index}") for index in range(10)),
                    const(0),
                ),
                0,
                rows,
            ),
            Identity(
                "enabled_procedure_minimum_0",
                cell("procedure_active_0") - cell("enabled"),
                0,
                rows,
            ),
            Identity(
                "enabled_procedure_minimum_1",
                cell("procedure_active_1") - cell("enabled"),
                0,
                rows,
            ),
            Identity(
                "disabled_present_zero",
                (1 - cell("enabled")) * cell("present"),
                0,
                rows,
            ),
            Identity(
                "disabled_requires_authorization_zero",
                (1 - cell("enabled")) * cell("requires_authorization"),
                0,
                rows,
            ),
        )
    )
    for index in range(10):
        identities.extend(
            (
                Identity(
                    f"procedure_active_{index}_boolean",
                    boolean(cell(f"procedure_active_{index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"procedure_padding_{index}_zero",
                    (1 - cell(f"procedure_active_{index}"))
                    * cell(f"procedure_char_{index}"),
                    0,
                    rows,
                ),
            )
        )
        if index:
            identities.append(
                Identity(
                    f"procedure_active_prefix_{index}",
                    cell(f"procedure_active_{index}")
                    * (1 - cell(f"procedure_active_{index - 1}")),
                    0,
                    rows,
                )
            )
    for name in (
        *(f"allowed_byte_{index}" for index in range(4)),
        *(f"procedure_char_{index}" for index in range(10)),
    ):
        identities.append(
            Identity(f"disabled_{name}_zero", (1 - cell("enabled")) * cell(name), 0, rows)
        )
    for slot_index in range(profile.claim_slots):
        start = slot_index * SERVICE_LINES_PER_CLAIM
        identities.append(
            Identity(
                f"enabled_prefix_{slot_index}",
                cell("enabled", 1) * (1 - cell("enabled")),
                start,
                start + SERVICE_LINES_PER_CLAIM - 1,
                "transition",
            )
        )
    line_trace = TraceTable("policy_line", frozen_line)
    line_table = AirTable(
        "policy_line",
        tuple(frozen_line),
        rows,
        tuple(identities),
        MappingProxyType(
            {name: frozen_line[name] for name in ("slot_index", "line_index", "has_next")}
        ),
    )

    slot_columns = freeze_columns(
        {
            "slot_index": tuple(slot.slot_index for slot in materialized),
            **{
                f"slot_byte_{byte_index}": tuple(
                    bundle[9 + byte_index] for bundle in bundles
                )
                for byte_index in range(4)
            },
            "real": tuple(bundle[13] for bundle in bundles),
        }
    )
    slot_trace = TraceTable("policy_slot", slot_columns)
    slot_table = AirTable(
        "policy_slot",
        tuple(slot_columns),
        profile.claim_slots,
        (
            Identity("real_boolean", boolean(cell("real")), 0, profile.claim_slots),
            Identity(
                "slot_index_bytes",
                cell("slot_index")
                - (1 << 24) * cell("slot_byte_0")
                - (1 << 16) * cell("slot_byte_1")
                - (1 << 8) * cell("slot_byte_2")
                - cell("slot_byte_3"),
                0,
                profile.claim_slots,
            ),
        ),
        MappingProxyType({"slot_index": slot_columns["slot_index"]}),
    )

    fixed_positions = set(range(len(BUNDLE_MAGIC))) | {8}
    bundle_columns = freeze_columns(
        {
            "slot_index": tuple(
                slot.slot_index for slot in materialized for _ in range(POLICY_BUNDLE_BYTES)
            ),
            "byte_index": tuple(
                index for _ in materialized for index in range(POLICY_BUNDLE_BYTES)
            ),
            "fixed_active": tuple(
                int(index in fixed_positions)
                for _ in materialized
                for index in range(POLICY_BUNDLE_BYTES)
            ),
            "fixed_value": tuple(
                BUNDLE_MAGIC[index]
                if index < len(BUNDLE_MAGIC)
                else _PROFILE_CODES[profile.profile_id]
                if index == 8
                else 0
                for _ in materialized
                for index in range(POLICY_BUNDLE_BYTES)
            ),
            "is_line_byte": tuple(
                int(index >= LINE_BASE)
                for _ in materialized
                for index in range(POLICY_BUNDLE_BYTES)
            ),
            "is_slot_byte": tuple(
                int(9 <= index < LINE_BASE)
                for _ in materialized
                for index in range(POLICY_BUNDLE_BYTES)
            ),
            "value": tuple(value for bundle in bundles for value in bundle),
        }
    )
    bundle_rows = profile.claim_slots * POLICY_BUNDLE_BYTES
    bundle_trace = TraceTable("policy_bundle_byte", bundle_columns)
    bundle_table = AirTable(
        "policy_bundle_byte",
        tuple(bundle_columns),
        bundle_rows,
        (
            Identity(
                "fixed_header_value",
                cell("fixed_active") * (cell("value") - cell("fixed_value")),
                0,
                bundle_rows,
            ),
        ),
        MappingProxyType(
            {
                name: bundle_columns[name]
                for name in (
                    "slot_index",
                    "byte_index",
                    "fixed_active",
                    "fixed_value",
                    "is_line_byte",
                    "is_slot_byte",
                )
            }
        ),
    )

    counts = Counter(bundle_columns["value"])
    byte_trace = TraceTable(
        "policy_byte_range",
        freeze_columns(
            {
                "value": tuple(range(256)),
                "multiplicity": tuple(counts[value] for value in range(256)),
            }
        ),
    )
    byte_table = AirTable(
        "policy_byte_range",
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": tuple(range(256))}),
    )
    line_values = (
        cell("enabled"),
        cell("present"),
        cell("procedure_length"),
        *(cell(f"procedure_char_{index}") for index in range(10)),
        *(cell(f"allowed_byte_{index}") for index in range(4)),
        cell("requires_authorization"),
    )
    line_bundle_link = LookupArgument(
        "policy_line_values_match_bundle",
        tuple(
            LookupSide(
                "policy_line",
                const(1),
                (
                    cell("slot_index"),
                    LINE_BASE + LINE_BYTES * cell("line_index") + offset,
                    value,
                ),
                0,
                rows,
            )
            for offset, value in enumerate(line_values)
        ),
        (
            LookupSide(
                "policy_bundle_byte",
                cell("is_line_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    slot_bundle_link = LookupArgument(
        "policy_slot_values_match_bundle",
        tuple(
            LookupSide(
                "policy_slot",
                const(1),
                (cell("slot_index"), const(9 + offset), value),
                0,
                profile.claim_slots,
            )
            for offset, value in enumerate(
                (
                    *(cell(f"slot_byte_{index}") for index in range(4)),
                    cell("real"),
                )
            )
        ),
        (
            LookupSide(
                "policy_bundle_byte",
                cell("is_slot_byte"),
                (cell("slot_index"), cell("byte_index"), cell("value")),
                0,
                bundle_rows,
            ),
        ),
    )
    byte_range = LookupArgument(
        "policy_bundle_values_are_bytes",
        (
            LookupSide(
                "policy_bundle_byte", const(1), (cell("value"),), 0, bundle_rows
            ),
        ),
        (
            LookupSide(
                "policy_byte_range",
                const(1),
                (cell("value"),),
                0,
                256,
                cell("multiplicity"),
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (line_table, slot_table, bundle_table, byte_table),
        (line_bundle_link, slot_bundle_link, byte_range),
    )
    traces = MappingProxyType(
        {
            "policy_line": line_trace,
            "policy_slot": slot_trace,
            "policy_bundle_byte": bundle_trace,
            "policy_byte_range": byte_trace,
        }
    )
    return PolicyBundleEncodingAirInstance(program, traces, commitments)


__all__ = ["PolicyBundleEncodingAirInstance", "build_policy_bundle_encoding_executable_air"]
