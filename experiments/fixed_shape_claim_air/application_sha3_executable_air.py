"""Batch exact SHA3-512 calls into one compact physical AIR schedule.

Every call still has its complete message, padding, Keccak round, and digest
witness.  The program does not duplicate identical table schemas and identity
ASTs per call.  A fixed call index is present on every private table and on all
cross-table lookup messages, so batching cannot exchange messages, states, or
digests between calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import re
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .executable_air import (
    AirProgram,
    AirTable,
    FixedColumnPeriodic,
    FixedColumnRuns,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError
from .sha3_512_executable_air import (
    Sha3ExecutableAirInstance,
    _build_sha3_512_trace_only,
    build_sha3_512_executable_air,
)
from experiments.bl_pq512_crypto_foundation.sha3_512_air_reference import (
    RATE_BYTES,
    padded_block_count,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-APPLICATION-SHA3-BATCH-AIR-v4"
INTERFACE_PROGRAM_ID: Final[str] = "BL-WAVE1A-APPLICATION-SHA3-INTERFACE-AIR-v1"
_CALL_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PRIVATE_TABLES: Final[tuple[str, ...]] = (
    "sha3_round",
    "sha3_message",
    "sha3_digest",
)
_SHARED_TABLES: Final[tuple[str, ...]] = (
    "sha3_truth",
    "sha3_byte_range",
)
_BATCH_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "sha3_round": "sha3_round_batch",
        "sha3_message": "sha3_message_batch",
        "sha3_digest": "sha3_digest_batch",
        "sha3_truth": "sha3_truth_shared",
        "sha3_byte_range": "sha3_byte_range_shared",
    }
)


@dataclass(frozen=True, slots=True)
class Sha3Call:
    call_id: str
    message: bytes
    capacity: int

    def __post_init__(self) -> None:
        if type(self.call_id) is not str or _CALL_ID.fullmatch(self.call_id) is None:
            raise StructuralError("application_sha3_call_id_invalid")
        if type(self.message) is not bytes:
            raise StructuralError("application_sha3_message_invalid")
        if (
            type(self.capacity) is not int
            or self.capacity < 0
            or len(self.message) > self.capacity
        ):
            raise StructuralError("application_sha3_capacity_invalid")


@dataclass(frozen=True, slots=True)
class Sha3CallRows:
    call_index: int
    round_start: int
    round_stop: int
    message_start: int
    message_stop: int
    digest_row: int


@dataclass(frozen=True, slots=True)
class ApplicationSha3AirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    digests: Mapping[str, bytes]
    call_rows: Mapping[str, Sha3CallRows]
    calls: tuple[Sha3Call, ...]


def _coalesced_runs(values: Sequence[int]) -> FixedColumnRuns:
    runs: list[tuple[int, int]] = []
    for value in values:
        if runs and runs[-1][0] == value:
            runs[-1] = (value, runs[-1][1] + 1)
        else:
            runs.append((value, 1))
    return FixedColumnRuns(tuple(runs))


def build_application_sha3_interface_program(
    capacities: Sequence[int],
) -> AirProgram:
    materialized = tuple(capacities)
    if not materialized or any(type(value) is not int or value < 0 for value in materialized):
        raise StructuralError("application_sha3_capacities_invalid")
    call_rows = tuple(padded_block_count(value) * RATE_BYTES for value in materialized)
    message_rows = sum(call_rows)
    message_table = AirTable(
        "sha3_message_batch",
        (
            "call_index",
            "position",
            "call_start",
            "same_call_next",
            "live",
            "value",
        ),
        message_rows,
        (
            Identity(
                "live_boolean",
                cell("live") * (cell("live") - 1),
                0,
                message_rows,
                "local",
            ),
            Identity(
                "inactive_value_zero",
                (1 - cell("live")) * cell("value"),
                0,
                message_rows,
                "local",
            ),
            Identity(
                "position_starts_at_zero",
                cell("call_start") * cell("position"),
                0,
                message_rows,
                "local",
            ),
            Identity(
                "position_increments",
                cell("same_call_next")
                * (cell("position", 1) - cell("position") - 1),
                0,
                message_rows - 1,
                "transition",
            ),
            Identity(
                "live_prefix",
                cell("same_call_next") * cell("live", 1) * (1 - cell("live")),
                0,
                message_rows - 1,
                "transition",
            ),
        ),
        {
            "call_index": FixedColumnRuns(
                tuple((call_index, rows) for call_index, rows in enumerate(call_rows))
            ),
            "call_start": FixedColumnRuns(
                tuple(
                    run
                    for rows in call_rows
                    for run in ((1, 1), (0, rows - 1))
                    if run[1]
                )
            ),
            "same_call_next": FixedColumnRuns(
                tuple(
                    run
                    for rows in call_rows
                    for run in ((1, rows - 1), (0, 1))
                    if run[1]
                )
            ),
        },
    )
    call_count = len(materialized)
    digest_table = AirTable(
        "sha3_digest_batch",
        ("call_index",) + tuple(f"value_{index}" for index in range(64)),
        call_count,
        (),
        {"call_index": FixedColumnRuns(tuple((index, 1) for index in range(call_count)))},
    )
    digest_byte_rows = call_count * 64
    digest_byte_table = AirTable(
        "sha3_digest_byte_batch",
        ("call_index", "byte_index", "value"),
        digest_byte_rows,
        (),
        {
            "call_index": FixedColumnRuns(tuple((index, 64) for index in range(call_count))),
            "byte_index": FixedColumnPeriodic(tuple(range(64)), digest_byte_rows),
        },
    )
    normalization = LookupArgument(
        "application_sha3_digest_byte_normalization",
        tuple(
            LookupSide(
                digest_table.name,
                const(1),
                (cell("call_index"), const(index), cell(f"value_{index}")),
                0,
                call_count,
            )
            for index in range(64)
        ),
        (
            LookupSide(
                digest_byte_table.name,
                const(1),
                (cell("call_index"), cell("byte_index"), cell("value")),
                0,
                digest_byte_rows,
            ),
        ),
    )
    return AirProgram(
        INTERFACE_PROGRAM_ID,
        (message_table, digest_table, digest_byte_table),
        (normalization,),
    )


def build_application_sha3_interface_air(
    calls: Sequence[Sha3Call],
) -> ApplicationSha3AirInstance:
    """Build only the modular message/digest ports for the global Boolean engine."""

    materialized = tuple(calls)
    if not materialized:
        raise StructuralError("application_sha3_calls_required")
    if len({call.call_id for call in materialized}) != len(materialized):
        raise StructuralError("application_sha3_call_id_duplicate")

    message_columns: dict[str, list[int]] = {
        name: []
        for name in (
            "call_index",
            "position",
            "call_start",
            "same_call_next",
            "live",
            "value",
        )
    }
    ranges: dict[str, Sha3CallRows] = {}
    message_cursor = 0
    digests: dict[str, bytes] = {}
    for call_index, call in enumerate(materialized):
        rows = padded_block_count(call.capacity) * RATE_BYTES
        start = message_cursor
        for position in range(rows):
            message_columns["call_index"].append(call_index)
            message_columns["position"].append(position)
            message_columns["call_start"].append(int(position == 0))
            message_columns["same_call_next"].append(int(position + 1 < rows))
            live = int(position < len(call.message))
            message_columns["live"].append(live)
            message_columns["value"].append(call.message[position] if live else 0)
        message_cursor += rows
        ranges[call.call_id] = Sha3CallRows(
            call_index,
            0,
            0,
            start,
            message_cursor,
            call_index,
        )
        digests[call.call_id] = sha3_512(call.message).digest()

    message_frozen = freeze_columns(message_columns)
    template = build_application_sha3_interface_program(
        tuple(call.capacity for call in materialized)
    )
    message_table = template.tables[0]
    message_trace = TraceTable(message_table.name, message_frozen)

    digest_columns = {
        "call_index": tuple(range(len(materialized))),
        **{
            f"value_{index}": tuple(digests[call.call_id][index] for call in materialized)
            for index in range(64)
        },
    }
    digest_frozen = freeze_columns(digest_columns)
    digest_table = AirTable(
        "sha3_digest_batch",
        tuple(digest_columns),
        len(materialized),
        (),
        {"call_index": _coalesced_runs(digest_columns["call_index"])},
    )
    digest_trace = TraceTable(digest_table.name, digest_frozen)

    digest_byte_columns = {
        "call_index": tuple(
            call_index for call_index in range(len(materialized)) for _ in range(64)
        ),
        "byte_index": tuple(index for _ in materialized for index in range(64)),
        "value": tuple(
            value for call in materialized for value in digests[call.call_id]
        ),
    }
    digest_byte_frozen = freeze_columns(digest_byte_columns)
    digest_byte_table = AirTable(
        "sha3_digest_byte_batch",
        tuple(digest_byte_columns),
        len(materialized) * 64,
        (),
        {
            "call_index": _coalesced_runs(digest_byte_columns["call_index"]),
            "byte_index": FixedColumnPeriodic(
                tuple(range(64)), len(materialized) * 64
            ),
        },
    )
    digest_byte_trace = TraceTable(digest_byte_table.name, digest_byte_frozen)
    normalization = template.lookups[0]
    return ApplicationSha3AirInstance(
        AirProgram(
            INTERFACE_PROGRAM_ID,
            (message_table, digest_table, digest_byte_table),
            (normalization,),
        ),
        MappingProxyType(
            {
                message_trace.name: message_trace,
                digest_trace.name: digest_trace,
                digest_byte_trace.name: digest_byte_trace,
            }
        ),
        MappingProxyType(digests),
        MappingProxyType(ranges),
        materialized,
    )


def _table(instance: Sha3ExecutableAirInstance, name: str) -> AirTable:
    return next(value for value in instance.program.tables if value.name == name)


def _same_schema(left: AirTable, right: AirTable) -> bool:
    return (
        left.columns == right.columns
        and tuple(left.fixed_columns) == tuple(right.fixed_columns)
        and tuple(
            (value.name, value.expression.canonical(), value.family)
            for value in left.identities
        )
        == tuple(
            (value.name, value.expression.canonical(), value.family)
            for value in right.identities
        )
    )


def _batch_identity(identity: Identity, rows: int) -> Identity:
    if identity.family == "boundary":
        return Identity(
            identity.name,
            cell("call_start") * identity.expression,
            0,
            rows,
            "local",
        )
    expression = identity.expression
    if identity.name == "live_prefix":
        expression = cell("live", 1) * (cell("same_call_next") - cell("live"))
    elif identity.name == "active_block_transition":
        expression = cell("block_end") * (
            cell("active", 1)
            - cell("active_after")
            - (1 - cell("same_call_next"))
        )
    return Identity(
        identity.name,
        expression,
        0,
        rows - 1 if identity.family == "transition" else rows,
        identity.family,
    )


def _batch_private_table(
    name: str,
    instances: Sequence[Sha3ExecutableAirInstance],
) -> tuple[AirTable, TraceTable]:
    templates = tuple(_table(instance, name) for instance in instances)
    template = templates[0]
    if any(not _same_schema(template, value) for value in templates[1:]):
        raise StructuralError("application_sha3_private_table_schema_mismatch")

    columns = {
        column: tuple(
            value
            for instance in instances
            for value in instance.traces[name].columns[column]
        )
        for column in template.columns
    }
    rows = sum(value.rows for value in templates)
    call_index = tuple(
        index
        for index, value in enumerate(templates)
        for _ in range(value.rows)
    )
    call_start = tuple(
        int(row == 0)
        for value in templates
        for row in range(value.rows)
    )
    same_call_next = tuple(
        int(row + 1 < value.rows)
        for value in templates
        for row in range(value.rows)
    )
    columns["call_index"] = call_index
    columns["call_start"] = call_start
    columns["same_call_next"] = same_call_next

    fixed = {
        column: tuple(
            value
            for table in templates
            for value in table.fixed_columns[column]
        )
        for column in template.fixed_columns
    }
    fixed["call_index"] = call_index
    fixed["call_start"] = call_start
    fixed["same_call_next"] = same_call_next

    identities = tuple(_batch_identity(value, rows) for value in template.identities)
    if name == "sha3_round":
        identities += (
            Identity(
                "round_call_index_within_rounds",
                cell("has_next_round")
                * (cell("call_index", 1) - cell("call_index")),
                0,
                rows - 1,
                "transition",
            ),
            Identity(
                "round_call_index_between_blocks",
                cell("has_next_block")
                * (cell("call_index", 1) - cell("call_index")),
                0,
                rows - 1,
                "transition",
            ),
        )
    elif name == "sha3_message":
        identities += (
            Identity(
                "message_call_index_transition",
                cell("has_next") * (cell("call_index", 1) - cell("call_index")),
                0,
                rows - 1,
                "transition",
            ),
        )

    frozen = freeze_columns(columns)
    batch_name = _BATCH_NAMES[name]
    return (
        AirTable(
            batch_name,
            tuple(frozen),
            rows,
            identities,
            MappingProxyType(fixed),
        ),
        TraceTable(batch_name, frozen),
    )


def _shared_table(
    name: str,
    instances: Sequence[Sha3ExecutableAirInstance],
) -> tuple[AirTable, TraceTable]:
    templates = tuple(_table(instance, name) for instance in instances)
    template = templates[0]
    if any(
        value.columns != template.columns
        or value.rows != template.rows
        or value.identities != template.identities
        or value.fixed_columns != template.fixed_columns
        for value in templates[1:]
    ):
        raise StructuralError("application_sha3_shared_table_schema_mismatch")
    base = instances[0].traces[name]
    # Fixed-shape batches commonly repeat the same cover/dummy message hundreds
    # of times.  Reuse its immutable trace and scale its multiplicities instead
    # of rescanning the 133k-row Keccak truth table once per duplicate call.
    grouped: dict[int, tuple[Sha3ExecutableAirInstance, int]] = {}
    for instance in instances:
        key = id(instance)
        previous = grouped.get(key)
        grouped[key] = (instance, 1 if previous is None else previous[1] + 1)
    multiplicity = tuple(
        sum(
            count * instance.traces[name].columns["multiplicity"][row]
            for instance, count in grouped.values()
        )
        for row in range(template.rows)
    )
    frozen = freeze_columns(
        {
            **{
                column: base.columns[column]
                for column in template.columns
                if column != "multiplicity"
            },
            "multiplicity": multiplicity,
        }
    )
    batch_name = _BATCH_NAMES[name]
    return (
        AirTable(
            batch_name,
            template.columns,
            template.rows,
            template.identities,
            template.fixed_columns,
        ),
        TraceTable(batch_name, frozen),
    )


def _batch_side(
    side: LookupSide,
    table_rows: Mapping[str, int],
    *,
    isolate_call: bool,
) -> LookupSide:
    return LookupSide(
        _BATCH_NAMES[side.table],
        side.selector,
        ((cell("call_index"), *side.values) if isolate_call else side.values),
        0,
        table_rows[side.table],
        side.weight,
    )


def _batch_lookups(
    instances: Sequence[Sha3ExecutableAirInstance],
    table_rows: Mapping[str, int],
) -> tuple[LookupArgument, ...]:
    template = instances[0]
    lookups: list[LookupArgument] = []
    for lookup in template.program.lookups:
        tables = {side.table for side in lookup.sources + lookup.destinations}
        isolate_call = not tables.intersection(_SHARED_TABLES)
        lookups.append(
            LookupArgument(
                f"application_{lookup.name}",
                tuple(
                    _batch_side(side, table_rows, isolate_call=isolate_call)
                    for side in lookup.sources
                ),
                tuple(
                    _batch_side(side, table_rows, isolate_call=isolate_call)
                    for side in lookup.destinations
                ),
            )
        )
    return tuple(lookups)


def build_application_sha3_executable_air(
    calls: Sequence[Sha3Call],
) -> ApplicationSha3AirInstance:
    materialized = tuple(calls)
    if not materialized:
        raise StructuralError("application_sha3_calls_required")
    call_ids = tuple(call.call_id for call in materialized)
    if len(set(call_ids)) != len(call_ids):
        raise StructuralError("application_sha3_call_id_duplicate")

    templates: dict[int, Sha3ExecutableAirInstance] = {}
    trace_cache: dict[tuple[int, bytes], Sha3ExecutableAirInstance] = {}
    built: list[Sha3ExecutableAirInstance] = []
    for call in materialized:
        cached = trace_cache.get((call.capacity, call.message))
        if cached is not None:
            built.append(cached)
            continue
        template = templates.get(call.capacity)
        if template is None:
            template = build_sha3_512_executable_air(
                call.message,
                capacity=call.capacity,
            )
            templates[call.capacity] = template
            built.append(template)
            trace_cache[(call.capacity, call.message)] = template
        else:
            instance = _build_sha3_512_trace_only(
                call.message,
                capacity=call.capacity,
                template=template,
            )
            trace_cache[(call.capacity, call.message)] = instance
            built.append(instance)
    instances = tuple(built)
    tables: list[AirTable] = []
    traces: dict[str, TraceTable] = {}
    for name in _PRIVATE_TABLES:
        table, trace = _batch_private_table(name, instances)
        tables.append(table)
        traces[trace.name] = trace
    for name in _SHARED_TABLES:
        table, trace = _shared_table(name, instances)
        tables.append(table)
        traces[trace.name] = trace

    digest_byte_columns = freeze_columns(
        {
            "call_index": tuple(
                call_index
                for call_index in range(len(instances))
                for _ in range(64)
            ),
            "byte_index": tuple(
                byte_index for _ in instances for byte_index in range(64)
            ),
            "value": tuple(value for instance in instances for value in instance.digest),
        }
    )
    digest_byte_rows = len(instances) * 64
    digest_byte_trace = TraceTable("sha3_digest_byte_batch", digest_byte_columns)
    digest_byte_table = AirTable(
        "sha3_digest_byte_batch",
        tuple(digest_byte_columns),
        digest_byte_rows,
        (),
        MappingProxyType(
            {
                name: digest_byte_columns[name]
                for name in ("call_index", "byte_index")
            }
        ),
    )
    tables.append(digest_byte_table)
    traces[digest_byte_trace.name] = digest_byte_trace
    digest_byte_link = LookupArgument(
        "application_sha3_digest_byte_normalization",
        tuple(
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (cell("call_index"), const(byte_index), cell(f"value_{byte_index}")),
                0,
                len(instances),
            )
            for byte_index in range(64)
        ),
        (
            LookupSide(
                "sha3_digest_byte_batch",
                const(1),
                (cell("call_index"), cell("byte_index"), cell("value")),
                0,
                digest_byte_rows,
            ),
        ),
    )

    table_rows = {
        name: sum(_table(instance, name).rows for instance in instances)
        if name in _PRIVATE_TABLES
        else _table(instances[0], name).rows
        for name in (*_PRIVATE_TABLES, *_SHARED_TABLES)
    }
    round_cursor = message_cursor = 0
    ranges: dict[str, Sha3CallRows] = {}
    for index, (call, instance) in enumerate(zip(materialized, instances, strict=True)):
        round_rows = _table(instance, "sha3_round").rows
        message_rows = _table(instance, "sha3_message").rows
        ranges[call.call_id] = Sha3CallRows(
            call_index=index,
            round_start=round_cursor,
            round_stop=round_cursor + round_rows,
            message_start=message_cursor,
            message_stop=message_cursor + message_rows,
            digest_row=index,
        )
        round_cursor += round_rows
        message_cursor += message_rows

    return ApplicationSha3AirInstance(
        AirProgram(
            PROGRAM_ID,
            tuple(tables),
            (*_batch_lookups(instances, table_rows), digest_byte_link),
        ),
        MappingProxyType(traces),
        MappingProxyType(
            {call.call_id: instance.digest for call, instance in zip(materialized, instances, strict=True)}
        ),
        MappingProxyType(ranges),
        materialized,
    )


def combine_application_sha3_executable_air(
    batches: Sequence[ApplicationSha3AirInstance],
) -> ApplicationSha3AirInstance:
    """Combine already-built batches into one physical Keccak table set.

    This is an exact structural concatenation: private call indices and row
    ranges are shifted, shared truth/range multiplicities are summed, and one
    copy of each AIR schema/lookup remains.  No digest or witness is recomputed.
    """

    materialized = tuple(batches)
    if not materialized:
        raise StructuralError("application_sha3_batches_required")
    if len(materialized) == 1:
        return materialized[0]
    expected_tables = tuple(table.name for table in materialized[0].program.tables)
    expected_lookups = tuple(lookup.name for lookup in materialized[0].program.lookups)
    for batch in materialized[1:]:
        if tuple(table.name for table in batch.program.tables) != expected_tables:
            raise StructuralError("application_sha3_batch_table_schema_mismatch")
        if tuple(lookup.name for lookup in batch.program.lookups) != expected_lookups:
            raise StructuralError("application_sha3_batch_lookup_schema_mismatch")

    call_counts = tuple(len(batch.digests) for batch in materialized)
    call_offsets: list[int] = []
    running_calls = 0
    for count in call_counts:
        call_offsets.append(running_calls)
        running_calls += count
    shared = {"sha3_truth_shared", "sha3_byte_range_shared"}
    tables: list[AirTable] = []
    traces: dict[str, TraceTable] = {}

    for name in expected_tables:
        batch_tables = tuple(
            next(table for table in batch.program.tables if table.name == name)
            for batch in materialized
        )
        template = batch_tables[0]
        if any(
            table.columns != template.columns
            or tuple((identity.name, identity.expression, identity.family) for identity in table.identities)
            != tuple((identity.name, identity.expression, identity.family) for identity in template.identities)
            or tuple(table.fixed_columns) != tuple(template.fixed_columns)
            for table in batch_tables[1:]
        ):
            raise StructuralError("application_sha3_batch_table_schema_mismatch")
        if name in shared:
            rows = template.rows
            if any(table.rows != rows for table in batch_tables[1:]):
                raise StructuralError("application_sha3_batch_shared_rows_mismatch")
            base = materialized[0].traces[name]
            columns = {
                column: (
                    tuple(
                        sum(batch.traces[name].columns[column][row] for batch in materialized)
                        for row in range(rows)
                    )
                    if column == "multiplicity"
                    else base.columns[column]
                )
                for column in template.columns
            }
            fixed = template.fixed_columns
            identities = template.identities
        else:
            rows = sum(table.rows for table in batch_tables)
            columns = {}
            for column in template.columns:
                values: list[int] = []
                for batch, offset in zip(materialized, call_offsets, strict=True):
                    source_values = batch.traces[name].columns[column]
                    values.extend(
                        value + offset if column == "call_index" else value
                        for value in source_values
                    )
                columns[column] = tuple(values)
            fixed = MappingProxyType(
                {
                    column: tuple(
                        value + offset if column == "call_index" else value
                        for table, offset in zip(batch_tables, call_offsets, strict=True)
                        for value in table.fixed_columns[column]
                    )
                    for column in template.fixed_columns
                }
            )
            identities = tuple(
                Identity(
                    identity.name,
                    identity.expression,
                    0,
                    rows - 1 if identity.family == "transition" else rows,
                    identity.family,
                )
                for identity in template.identities
            )
        frozen = freeze_columns(columns)
        table = AirTable(name, template.columns, rows, identities, fixed)
        tables.append(table)
        traces[name] = TraceTable(name, frozen)

    table_rows = {table.name: table.rows for table in tables}
    lookups = tuple(
        LookupArgument(
            lookup.name,
            tuple(
                LookupSide(
                    side.table,
                    side.selector,
                    side.values,
                    0,
                    table_rows[side.table],
                    side.weight,
                )
                for side in lookup.sources
            ),
            tuple(
                LookupSide(
                    side.table,
                    side.selector,
                    side.values,
                    0,
                    table_rows[side.table],
                    side.weight,
                )
                for side in lookup.destinations
            ),
        )
        for lookup in materialized[0].program.lookups
    )

    digests: dict[str, bytes] = {}
    ranges: dict[str, Sha3CallRows] = {}
    round_offset = message_offset = 0
    for batch, call_offset in zip(materialized, call_offsets, strict=True):
        for call_id, digest in batch.digests.items():
            if call_id in digests:
                raise StructuralError("application_sha3_call_id_duplicate")
            digests[call_id] = digest
            value = batch.call_rows[call_id]
            ranges[call_id] = Sha3CallRows(
                value.call_index + call_offset,
                value.round_start + round_offset,
                value.round_stop + round_offset,
                value.message_start + message_offset,
                value.message_stop + message_offset,
                value.digest_row + call_offset,
            )
        round_offset += batch.traces["sha3_round_batch"].rows
        message_offset += batch.traces["sha3_message_batch"].rows
    return ApplicationSha3AirInstance(
        AirProgram(PROGRAM_ID, tuple(tables), lookups),
        MappingProxyType(traces),
        MappingProxyType(digests),
        MappingProxyType(ranges),
        tuple(call for batch in materialized for call in batch.calls),
    )


def combine_application_sha3_interface_air(
    batches: Sequence[ApplicationSha3AirInstance],
) -> ApplicationSha3AirInstance:
    """Combine compact SHA3 interfaces without reintroducing legacy Keccak tables."""

    materialized = tuple(batches)
    if not materialized:
        raise StructuralError("application_sha3_batches_required")
    if any(batch.program.program_id != INTERFACE_PROGRAM_ID for batch in materialized):
        raise StructuralError("application_sha3_interface_batch_required")
    if len(materialized) == 1:
        return materialized[0]
    return build_application_sha3_interface_air(
        tuple(call for batch in materialized for call in batch.calls)
    )


__all__ = [
    "ApplicationSha3AirInstance",
    "Sha3Call",
    "Sha3CallRows",
    "build_application_sha3_executable_air",
    "build_application_sha3_interface_air",
    "build_application_sha3_interface_program",
    "combine_application_sha3_executable_air",
    "combine_application_sha3_interface_air",
]
