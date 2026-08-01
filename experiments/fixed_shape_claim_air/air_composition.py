"""Fail-closed composition helpers for modular executable AIR components."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    INTERFACE_PROGRAM_ID,
    build_application_sha3_interface_program,
    combine_application_sha3_executable_air,
    combine_application_sha3_interface_air,
)
from .executable_air import (
    AirProgram,
    AirTable,
    FixedColumnRuns,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError
from .sha3_512_boolean_executable_air import (
    Sha3BooleanAirInstance,
    Sha3BooleanCall,
    build_sha3_boolean_executable_air,
    build_sha3_boolean_sponge_program,
)


@dataclass(frozen=True, slots=True)
class Sha3ComposedComponent:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    call_index_offset: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.program, AirProgram)
            or not isinstance(self.sha3, ApplicationSha3AirInstance)
            or type(self.call_index_offset) is not int
            or self.call_index_offset < 0
        ):
            raise StructuralError("air_composition_component_invalid")
        if not {table.name for table in self.sha3.program.tables}.issubset(
            table.name for table in self.program.tables
        ):
            raise StructuralError("air_composition_sha3_tables_missing")


@dataclass(frozen=True, slots=True)
class ComposedAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    component_count: int


@dataclass(frozen=True, slots=True)
class BooleanComposedAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    boolean_sha3: Sha3BooleanAirInstance
    component_count: int


@dataclass(frozen=True, slots=True)
class AirFragment:
    program: AirProgram
    traces: Mapping[str, TraceTable]


@dataclass(frozen=True, slots=True)
class MergedAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    fragment_count: int


@dataclass(frozen=True, slots=True)
class Sha3ProgramFragment:
    """Verifier-only application fragment with compact local SHA3 interfaces."""

    program: AirProgram
    capacities: tuple[int, ...]
    call_index_offset: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.program, AirProgram)
            or not self.capacities
            or any(type(value) is not int or value < 0 for value in self.capacities)
            or type(self.call_index_offset) is not int
            or self.call_index_offset < 0
        ):
            raise StructuralError("air_program_fragment_invalid")


def _same_table(left: AirTable, right: AirTable) -> bool:
    return left.canonical() == right.canonical()


def _same_trace(left: TraceTable, right: TraceTable) -> bool:
    return left.name == right.name and left.columns == right.columns


def _shift_external_lookup(
    lookup: LookupArgument,
    *,
    call_offset: int,
    round_offset: int,
    message_offset: int,
) -> LookupArgument:
    row_offsets = {
        "sha3_round_batch": round_offset,
        "sha3_message_batch": message_offset,
        "sha3_digest_batch": call_offset,
        "sha3_digest_byte_batch": call_offset * 64,
    }

    def shift(side: LookupSide) -> LookupSide:
        offset = row_offsets.get(side.table, 0)
        return LookupSide(
            side.table,
            side.selector,
            side.values,
            side.row_start + offset,
            side.row_stop + offset,
            side.weight,
        )

    return LookupArgument(
        lookup.name,
        tuple(shift(side) for side in lookup.sources),
        tuple(shift(side) for side in lookup.destinations),
    )


def compose_sha3_air_components(
    program_id: str,
    components: Sequence[Sha3ComposedComponent],
    *,
    extra_tables: Sequence[AirTable] = (),
    extra_traces: Mapping[str, TraceTable] | None = None,
    extra_lookups: Sequence[LookupArgument] = (),
    extra_public_inputs: Sequence[PublicInputBinding] = (),
) -> ComposedAirInstance:
    materialized = tuple(components)
    if type(program_id) is not str or not program_id or not materialized:
        raise StructuralError("air_composition_inputs_invalid")
    expected_offset = 0
    round_offset = 0
    message_offset = 0
    tables: dict[str, AirTable] = {}
    traces: dict[str, TraceTable] = {}
    lookups: dict[str, LookupArgument] = {}
    public_inputs: dict[str, PublicInputBinding] = {}
    sha_batches: list[ApplicationSha3AirInstance] = []

    for component in materialized:
        if component.call_index_offset != expected_offset:
            raise StructuralError("air_composition_call_offsets_not_contiguous")
        sha_table_names = {table.name for table in component.sha3.program.tables}
        sha_lookup_names = {lookup.name for lookup in component.sha3.program.lookups}
        for table in component.program.tables:
            if table.name in sha_table_names:
                continue
            trace = component.traces[table.name]
            previous_table = tables.get(table.name)
            previous_trace = traces.get(table.name)
            if previous_table is None:
                tables[table.name] = table
                traces[table.name] = trace
            elif not _same_table(previous_table, table) or previous_trace is None or not _same_trace(previous_trace, trace):
                raise StructuralError(f"air_composition_table_conflict:{table.name}")
        for lookup in component.program.lookups:
            if lookup.name in sha_lookup_names:
                continue
            shifted = _shift_external_lookup(
                lookup,
                call_offset=expected_offset,
                round_offset=round_offset,
                message_offset=message_offset,
            )
            previous = lookups.get(lookup.name)
            if previous is None:
                lookups[lookup.name] = shifted
            elif previous.canonical() != shifted.canonical():
                raise StructuralError(f"air_composition_lookup_conflict:{lookup.name}")
        for binding in component.program.public_inputs:
            previous = public_inputs.get(binding.name)
            if previous is None:
                public_inputs[binding.name] = binding
            elif previous != binding:
                raise StructuralError(f"air_composition_public_conflict:{binding.name}")
        sha_batches.append(component.sha3)
        expected_offset += len(component.sha3.digests)
        round_offset += component.sha3.traces["sha3_round_batch"].rows
        message_offset += component.sha3.traces["sha3_message_batch"].rows

    for table in extra_tables:
        if table.name in tables:
            raise StructuralError(f"air_composition_extra_table_conflict:{table.name}")
        tables[table.name] = table
    for name, trace in ({} if extra_traces is None else dict(extra_traces)).items():
        if name in traces or name not in tables:
            raise StructuralError(f"air_composition_extra_trace_conflict:{name}")
        traces[name] = trace
    if set(tables) != set(traces):
        raise StructuralError("air_composition_trace_set_incomplete")
    for lookup in extra_lookups:
        if lookup.name in lookups:
            raise StructuralError(f"air_composition_extra_lookup_conflict:{lookup.name}")
        lookups[lookup.name] = lookup
    for binding in extra_public_inputs:
        if binding.name in public_inputs:
            raise StructuralError(f"air_composition_extra_public_conflict:{binding.name}")
        public_inputs[binding.name] = binding

    sha3 = combine_application_sha3_executable_air(tuple(sha_batches))
    for table in sha3.program.tables:
        tables[table.name] = table
        traces[table.name] = sha3.traces[table.name]
    program = AirProgram(
        program_id,
        tuple(tables.values()),
        (*sha3.program.lookups, *lookups.values()),
        tuple(public_inputs.values()),
    )
    return ComposedAirInstance(
        program,
        MappingProxyType(traces),
        sha3,
        len(materialized),
    )


def compose_sha3_interface_components(
    program_id: str,
    components: Sequence[Sha3ComposedComponent],
    *,
    extra_tables: Sequence[AirTable] = (),
    extra_traces: Mapping[str, TraceTable] | None = None,
    extra_lookups: Sequence[LookupArgument] = (),
    extra_public_inputs: Sequence[PublicInputBinding] = (),
) -> ComposedAirInstance:
    """Compose compact application SHA ports before adding the Boolean engine."""

    materialized = tuple(components)
    if type(program_id) is not str or not program_id or not materialized:
        raise StructuralError("air_composition_inputs_invalid")
    if any(
        component.sha3.program.program_id != INTERFACE_PROGRAM_ID
        for component in materialized
    ):
        raise StructuralError("air_composition_interface_component_required")
    expected_offset = 0
    message_offset = 0
    tables: dict[str, AirTable] = {}
    traces: dict[str, TraceTable] = {}
    lookups: dict[str, LookupArgument] = {}
    public_inputs: dict[str, PublicInputBinding] = {}
    sha_batches: list[ApplicationSha3AirInstance] = []

    for component in materialized:
        if component.call_index_offset != expected_offset:
            raise StructuralError("air_composition_call_offsets_not_contiguous")
        sha_table_names = {table.name for table in component.sha3.program.tables}
        sha_lookup_names = {lookup.name for lookup in component.sha3.program.lookups}
        for table in component.program.tables:
            if table.name in sha_table_names:
                continue
            trace = component.traces[table.name]
            previous_table = tables.get(table.name)
            previous_trace = traces.get(table.name)
            if previous_table is None:
                tables[table.name] = table
                traces[table.name] = trace
            elif (
                not _same_table(previous_table, table)
                or previous_trace is None
                or not _same_trace(previous_trace, trace)
            ):
                raise StructuralError(f"air_composition_table_conflict:{table.name}")
        for lookup in component.program.lookups:
            if lookup.name in sha_lookup_names:
                continue
            shifted = _shift_external_lookup(
                lookup,
                call_offset=expected_offset,
                round_offset=0,
                message_offset=message_offset,
            )
            previous = lookups.get(lookup.name)
            if previous is None:
                lookups[lookup.name] = shifted
            elif previous.canonical() != shifted.canonical():
                raise StructuralError(f"air_composition_lookup_conflict:{lookup.name}")
        for binding in component.program.public_inputs:
            previous = public_inputs.get(binding.name)
            if previous is None:
                public_inputs[binding.name] = binding
            elif previous != binding:
                raise StructuralError(f"air_composition_public_conflict:{binding.name}")
        sha_batches.append(component.sha3)
        expected_offset += len(component.sha3.digests)
        message_offset += component.sha3.traces["sha3_message_batch"].rows

    for table in extra_tables:
        if table.name in tables:
            raise StructuralError(f"air_composition_extra_table_conflict:{table.name}")
        tables[table.name] = table
    for name, trace in ({} if extra_traces is None else dict(extra_traces)).items():
        if name in traces or name not in tables:
            raise StructuralError(f"air_composition_extra_trace_conflict:{name}")
        traces[name] = trace
    if set(tables) != set(traces):
        raise StructuralError("air_composition_trace_set_incomplete")
    for lookup in extra_lookups:
        if lookup.name in lookups:
            raise StructuralError(f"air_composition_extra_lookup_conflict:{lookup.name}")
        lookups[lookup.name] = lookup
    for binding in extra_public_inputs:
        if binding.name in public_inputs:
            raise StructuralError(f"air_composition_extra_public_conflict:{binding.name}")
        public_inputs[binding.name] = binding

    sha3 = combine_application_sha3_interface_air(tuple(sha_batches))
    for table in sha3.program.tables:
        tables[table.name] = table
        traces[table.name] = sha3.traces[table.name]
    return ComposedAirInstance(
        AirProgram(
            program_id,
            tuple(tables.values()),
            (*sha3.program.lookups, *lookups.values()),
            tuple(public_inputs.values()),
        ),
        MappingProxyType(traces),
        sha3,
        len(materialized),
    )


def _fixed_runs(values: Sequence[int]) -> FixedColumnRuns:
    runs: list[tuple[int, int]] = []
    for value in values:
        if runs and runs[-1][0] == value:
            runs[-1] = (value, runs[-1][1] + 1)
        else:
            runs.append((value, 1))
    return FixedColumnRuns(tuple(runs))


def _compact_sha3_message_interface(
    sha3: ApplicationSha3AirInstance,
) -> tuple[AirTable, TraceTable]:
    source_table = next(
        table for table in sha3.program.tables if table.name == "sha3_message_batch"
    )
    source = sha3.traces[source_table.name]
    columns = (
        "call_index",
        "position",
        "call_start",
        "same_call_next",
        "live",
        "value",
    )
    frozen = freeze_columns({name: source.columns[name] for name in columns})
    identities = (
        Identity(
            "live_boolean",
            cell("live") * (cell("live") - 1),
            0,
            source.rows,
            "local",
        ),
        Identity(
            "position_starts_at_zero",
            cell("call_start") * cell("position"),
            0,
            source.rows,
            "local",
        ),
        Identity(
            "position_increments",
            cell("same_call_next")
            * (cell("position", 1) - cell("position") - 1),
            0,
            source.rows - 1,
            "transition",
        ),
        Identity(
            "live_prefix",
            cell("same_call_next") * cell("live", 1) * (1 - cell("live")),
            0,
            source.rows - 1,
            "transition",
        ),
    )
    fixed = {
        name: _fixed_runs(source_table.fixed_columns[name])
        for name in ("call_index", "call_start", "same_call_next")
    }
    return (
        AirTable(source_table.name, columns, source.rows, identities, fixed),
        TraceTable(source_table.name, frozen),
    )


def _boolean_sha3_bridges(
    sha3: ApplicationSha3AirInstance,
    boolean_sha3: Sha3BooleanAirInstance,
) -> tuple[LookupArgument, ...]:
    message_rows = sha3.traces["sha3_message_batch"].rows
    absorb_rows = boolean_sha3.traces["sha3_boolean_absorb"].rows
    digest_rows = sha3.traces["sha3_digest_batch"].rows
    boolean_digest_rows = boolean_sha3.traces["sha3_boolean_digest"].rows
    message_bridge = LookupArgument(
        "application_sha3_message_to_boolean_sha3",
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                message_rows,
            ),
        ),
        tuple(
            LookupSide(
                "sha3_boolean_absorb",
                cell(f"message_live_{byte_index}"),
                (
                    cell("call_index"),
                    72 * cell("block_index") + const(byte_index),
                    cell(f"block_byte_{byte_index}"),
                ),
                0,
                absorb_rows,
            )
            for byte_index in range(72)
        ),
    )
    digest_bridge = LookupArgument(
        "application_sha3_digest_to_boolean_sha3",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (cell("call_index"),)
                + tuple(cell(f"value_{index}") for index in range(64)),
                0,
                digest_rows,
            ),
        ),
        (
            LookupSide(
                "sha3_boolean_digest",
                const(1),
                (cell("call_index"),)
                + tuple(cell(f"digest_byte_{index}") for index in range(64)),
                0,
                boolean_digest_rows,
            ),
        ),
    )
    normalization = next(
        lookup
        for lookup in sha3.program.lookups
        if lookup.name == "application_sha3_digest_byte_normalization"
    )
    return message_bridge, digest_bridge, normalization


def build_boolean_application_sha3_program(
    capacities: Sequence[int],
    *,
    program_id: str = "BL-WAVE1A-GLOBAL-BOOLEAN-SHA3-AIR-v1",
) -> AirProgram:
    """Build the complete global SHA verifier program without a private witness."""

    materialized = tuple(capacities)
    interface = build_application_sha3_interface_program(materialized)
    boolean = build_sha3_boolean_sponge_program(materialized)
    message_rows = interface.tables[0].rows
    digest_rows = interface.tables[1].rows
    absorb_rows = boolean.tables[1].rows
    boolean_digest_rows = boolean.tables[2].rows
    message_bridge = LookupArgument(
        "application_sha3_message_to_boolean_sha3",
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                message_rows,
            ),
        ),
        tuple(
            LookupSide(
                "sha3_boolean_absorb",
                cell(f"message_live_{byte_index}"),
                (
                    cell("call_index"),
                    72 * cell("block_index") + const(byte_index),
                    cell(f"block_byte_{byte_index}"),
                ),
                0,
                absorb_rows,
            )
            for byte_index in range(72)
        ),
    )
    digest_bridge = LookupArgument(
        "application_sha3_digest_to_boolean_sha3",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (cell("call_index"),)
                + tuple(cell(f"value_{index}") for index in range(64)),
                0,
                digest_rows,
            ),
        ),
        (
            LookupSide(
                "sha3_boolean_digest",
                const(1),
                (cell("call_index"),)
                + tuple(cell(f"digest_byte_{index}") for index in range(64)),
                0,
                boolean_digest_rows,
            ),
        ),
    )
    return AirProgram(
        program_id,
        (*interface.tables, *boolean.tables),
        (
            *boolean.lookups,
            message_bridge,
            digest_bridge,
            *interface.lookups,
        ),
    )


def compose_boolean_sha3_program_fragments(
    program_id: str,
    fragments: Sequence[Sha3ProgramFragment],
    *,
    extra_tables: Sequence[AirTable] = (),
    extra_lookups: Sequence[LookupArgument] = (),
    extra_public_inputs: Sequence[PublicInputBinding] = (),
) -> AirProgram:
    """Assemble the complete verifier IR without materializing private traces."""

    materialized = tuple(fragments)
    if type(program_id) is not str or not program_id or not materialized:
        raise StructuralError("air_program_composition_inputs_invalid")
    tables: dict[str, AirTable] = {}
    lookups: dict[str, LookupArgument] = {}
    public_inputs: dict[str, PublicInputBinding] = {}
    capacities: list[int] = []
    expected_call_offset = 0
    message_offset = 0
    interface_table_names = {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }
    interface_lookup_name = "application_sha3_digest_byte_normalization"

    for fragment in materialized:
        if fragment.call_index_offset != expected_call_offset:
            raise StructuralError("air_program_composition_call_offsets_not_contiguous")
        interface = build_application_sha3_interface_program(fragment.capacities)
        observed_interface = tuple(
            table for table in fragment.program.tables if table.name in interface_table_names
        )
        if tuple(table.canonical() for table in observed_interface) != tuple(
            table.canonical() for table in interface.tables
        ):
            raise StructuralError("air_program_composition_interface_mismatch")
        for table in fragment.program.tables:
            if table.name in interface_table_names:
                continue
            previous = tables.get(table.name)
            if previous is None:
                tables[table.name] = table
            elif not _same_table(previous, table):
                raise StructuralError(f"air_program_composition_table_conflict:{table.name}")
        for lookup in fragment.program.lookups:
            if lookup.name == interface_lookup_name:
                continue
            shifted = _shift_external_lookup(
                lookup,
                call_offset=expected_call_offset,
                round_offset=0,
                message_offset=message_offset,
            )
            previous = lookups.get(lookup.name)
            if previous is None:
                lookups[lookup.name] = shifted
            elif previous.canonical() != shifted.canonical():
                raise StructuralError(f"air_program_composition_lookup_conflict:{lookup.name}")
        for binding in fragment.program.public_inputs:
            previous = public_inputs.get(binding.name)
            if previous is None:
                public_inputs[binding.name] = binding
            elif previous != binding:
                raise StructuralError(f"air_program_composition_public_conflict:{binding.name}")
        capacities.extend(fragment.capacities)
        expected_call_offset += len(fragment.capacities)
        message_offset += interface.tables[0].rows

    for table in extra_tables:
        previous = tables.get(table.name)
        if previous is not None and not _same_table(previous, table):
            raise StructuralError(f"air_program_composition_extra_table_conflict:{table.name}")
        if previous is None:
            tables[table.name] = table
    for lookup in extra_lookups:
        previous = lookups.get(lookup.name)
        if previous is not None and previous.canonical() != lookup.canonical():
            raise StructuralError(f"air_program_composition_extra_lookup_conflict:{lookup.name}")
        if previous is None:
            lookups[lookup.name] = lookup
    for binding in extra_public_inputs:
        previous = public_inputs.get(binding.name)
        if previous is not None and previous != binding:
            raise StructuralError(f"air_program_composition_extra_public_conflict:{binding.name}")
        if previous is None:
            public_inputs[binding.name] = binding

    sha3 = build_boolean_application_sha3_program(tuple(capacities))
    return AirProgram(
        program_id,
        (*tables.values(), *sha3.tables),
        (*sha3.lookups, *lookups.values()),
        tuple(public_inputs.values()),
    )


def compose_sha3_interface_program_fragments(
    program_id: str,
    fragments: Sequence[Sha3ProgramFragment],
    *,
    extra_tables: Sequence[AirTable] = (),
    extra_lookups: Sequence[LookupArgument] = (),
    extra_public_inputs: Sequence[PublicInputBinding] = (),
) -> AirProgram:
    """Assemble verifier IR with the canonical external SHA3 bus only."""

    materialized = tuple(fragments)
    if type(program_id) is not str or not program_id or not materialized:
        raise StructuralError("air_program_composition_inputs_invalid")
    tables: dict[str, AirTable] = {}
    lookups: dict[str, LookupArgument] = {}
    public_inputs: dict[str, PublicInputBinding] = {}
    capacities: list[int] = []
    expected_call_offset = 0
    message_offset = 0
    interface_table_names = {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }
    interface_lookup_name = "application_sha3_digest_byte_normalization"

    for fragment in materialized:
        if fragment.call_index_offset != expected_call_offset:
            raise StructuralError(
                "air_program_composition_call_offsets_not_contiguous"
            )
        interface = build_application_sha3_interface_program(fragment.capacities)
        observed_interface = tuple(
            table
            for table in fragment.program.tables
            if table.name in interface_table_names
        )
        if tuple(table.canonical() for table in observed_interface) != tuple(
            table.canonical() for table in interface.tables
        ):
            raise StructuralError("air_program_composition_interface_mismatch")
        for table in fragment.program.tables:
            if table.name in interface_table_names:
                continue
            previous = tables.get(table.name)
            if previous is None:
                tables[table.name] = table
            elif not _same_table(previous, table):
                raise StructuralError(
                    f"air_program_composition_table_conflict:{table.name}"
                )
        for lookup in fragment.program.lookups:
            if lookup.name == interface_lookup_name:
                continue
            shifted = _shift_external_lookup(
                lookup,
                call_offset=expected_call_offset,
                round_offset=0,
                message_offset=message_offset,
            )
            previous = lookups.get(lookup.name)
            if previous is None:
                lookups[lookup.name] = shifted
            elif previous.canonical() != shifted.canonical():
                raise StructuralError(
                    f"air_program_composition_lookup_conflict:{lookup.name}"
                )
        for binding in fragment.program.public_inputs:
            previous = public_inputs.get(binding.name)
            if previous is None:
                public_inputs[binding.name] = binding
            elif previous != binding:
                raise StructuralError(
                    f"air_program_composition_public_conflict:{binding.name}"
                )
        capacities.extend(fragment.capacities)
        expected_call_offset += len(fragment.capacities)
        message_offset += interface.tables[0].rows

    for table in extra_tables:
        previous = tables.get(table.name)
        if previous is not None and not _same_table(previous, table):
            raise StructuralError(
                f"air_program_composition_extra_table_conflict:{table.name}"
            )
        if previous is None:
            tables[table.name] = table
    for lookup in extra_lookups:
        previous = lookups.get(lookup.name)
        if previous is not None and previous.canonical() != lookup.canonical():
            raise StructuralError(
                f"air_program_composition_extra_lookup_conflict:{lookup.name}"
            )
        if previous is None:
            lookups[lookup.name] = lookup
    for binding in extra_public_inputs:
        previous = public_inputs.get(binding.name)
        if previous is not None and previous != binding:
            raise StructuralError(
                f"air_program_composition_extra_public_conflict:{binding.name}"
            )
        if previous is None:
            public_inputs[binding.name] = binding

    sha3 = build_application_sha3_interface_program(tuple(capacities))
    return AirProgram(
        program_id,
        (*tables.values(), *sha3.tables),
        (*sha3.lookups, *lookups.values()),
        tuple(public_inputs.values()),
    )


def compose_boolean_sha3_air_components(
    program_id: str,
    components: Sequence[Sha3ComposedComponent],
) -> BooleanComposedAirInstance:
    """Compose application fragments around the direct Boolean SHA3 engine.

    The legacy byte/truth-table Keccak implementation is retained only as a
    build-time witness adapter.  Its round, truth, range, and padded-message
    machinery is absent from the returned proving program.  A six-column
    message interface preserves existing application lookups and is bound
    bijectively to live Boolean-sponge bytes; digest interfaces are bound to
    the Boolean digest table.
    """

    materialized = tuple(components)
    interface_only = all(
        component.sha3.program.program_id == INTERFACE_PROGRAM_ID
        for component in materialized
    )
    if not interface_only and any(
        component.sha3.program.program_id == INTERFACE_PROGRAM_ID
        for component in materialized
    ):
        raise StructuralError("air_composition_mixed_sha3_backends")
    legacy = (
        compose_sha3_interface_components(program_id, materialized)
        if interface_only
        else compose_sha3_air_components(program_id, materialized)
    )
    calls = tuple(
        Sha3BooleanCall(call.call_id, call.message, call.capacity)
        for call in legacy.sha3.calls
    )
    boolean_sha3 = build_sha3_boolean_executable_air(calls)
    if dict(boolean_sha3.digests) != dict(legacy.sha3.digests):
        raise StructuralError("air_composition_boolean_sha3_digest_mismatch")

    legacy_sha_tables = {table.name for table in legacy.sha3.program.tables}
    legacy_sha_lookups = {lookup.name for lookup in legacy.sha3.program.lookups}
    tables = [
        table for table in legacy.program.tables if table.name not in legacy_sha_tables
    ]
    traces = {
        table.name: legacy.traces[table.name]
        for table in tables
    }
    if interface_only:
        message_table = next(
            table
            for table in legacy.sha3.program.tables
            if table.name == "sha3_message_batch"
        )
        message_trace = legacy.sha3.traces[message_table.name]
    else:
        message_table, message_trace = _compact_sha3_message_interface(legacy.sha3)
    tables.append(message_table)
    traces[message_table.name] = message_trace
    for name in ("sha3_digest_batch", "sha3_digest_byte_batch"):
        table = next(table for table in legacy.sha3.program.tables if table.name == name)
        tables.append(table)
        traces[name] = legacy.sha3.traces[name]
    tables.extend(boolean_sha3.program.tables)
    traces.update(boolean_sha3.traces)

    external_lookups = tuple(
        lookup for lookup in legacy.program.lookups if lookup.name not in legacy_sha_lookups
    )
    program = AirProgram(
        program_id,
        tuple(tables),
        (
            *boolean_sha3.program.lookups,
            *_boolean_sha3_bridges(legacy.sha3, boolean_sha3),
            *external_lookups,
        ),
        legacy.program.public_inputs,
    )
    return BooleanComposedAirInstance(
        program,
        MappingProxyType(traces),
        legacy.sha3,
        boolean_sha3,
        legacy.component_count,
    )


def merge_air_fragments(
    program_id: str,
    fragments: Sequence[AirFragment],
    *,
    extra_tables: Sequence[AirTable] = (),
    extra_traces: Mapping[str, TraceTable] | None = None,
    extra_lookups: Sequence[LookupArgument] = (),
    extra_public_inputs: Sequence[PublicInputBinding] = (),
) -> MergedAirInstance:
    materialized = tuple(fragments)
    if type(program_id) is not str or not program_id or not materialized:
        raise StructuralError("air_fragment_merge_inputs_invalid")
    tables: dict[str, AirTable] = {}
    traces: dict[str, TraceTable] = {}
    lookups: dict[str, LookupArgument] = {}
    public_inputs: dict[str, PublicInputBinding] = {}
    for fragment in materialized:
        if not isinstance(fragment, AirFragment) or set(fragment.traces) != {
            table.name for table in fragment.program.tables
        }:
            raise StructuralError("air_fragment_invalid")
        for table in fragment.program.tables:
            trace = fragment.traces[table.name]
            previous = tables.get(table.name)
            if previous is None:
                tables[table.name] = table
                traces[table.name] = trace
            elif not _same_table(previous, table) or not _same_trace(
                traces[table.name], trace
            ):
                raise StructuralError(f"air_fragment_table_conflict:{table.name}")
        for lookup in fragment.program.lookups:
            previous = lookups.get(lookup.name)
            if previous is None:
                lookups[lookup.name] = lookup
            elif previous.canonical() != lookup.canonical():
                raise StructuralError(f"air_fragment_lookup_conflict:{lookup.name}")
        for binding in fragment.program.public_inputs:
            previous = public_inputs.get(binding.name)
            if previous is None:
                public_inputs[binding.name] = binding
            elif previous != binding:
                raise StructuralError(f"air_fragment_public_conflict:{binding.name}")
    for table in extra_tables:
        if table.name in tables:
            raise StructuralError(f"air_fragment_extra_table_conflict:{table.name}")
        tables[table.name] = table
    for name, trace in ({} if extra_traces is None else dict(extra_traces)).items():
        if name in traces or name not in tables:
            raise StructuralError(f"air_fragment_extra_trace_conflict:{name}")
        traces[name] = trace
    if set(tables) != set(traces):
        raise StructuralError("air_fragment_trace_set_incomplete")
    for lookup in extra_lookups:
        if lookup.name in lookups:
            raise StructuralError(f"air_fragment_extra_lookup_conflict:{lookup.name}")
        lookups[lookup.name] = lookup
    for binding in extra_public_inputs:
        if binding.name in public_inputs:
            raise StructuralError(f"air_fragment_extra_public_conflict:{binding.name}")
        public_inputs[binding.name] = binding
    program = AirProgram(
        program_id,
        tuple(tables.values()),
        tuple(lookups.values()),
        tuple(public_inputs.values()),
    )
    return MergedAirInstance(
        program, MappingProxyType(traces), len(materialized)
    )


__all__ = (
    "BooleanComposedAirInstance",
    "ComposedAirInstance",
    "AirFragment",
    "MergedAirInstance",
    "Sha3ComposedComponent",
    "Sha3ProgramFragment",
    "compose_boolean_sha3_air_components",
    "compose_boolean_sha3_program_fragments",
    "compose_sha3_air_components",
    "compose_sha3_interface_components",
    "compose_sha3_interface_program_fragments",
    "merge_air_fragments",
    "build_boolean_application_sha3_program",
)
