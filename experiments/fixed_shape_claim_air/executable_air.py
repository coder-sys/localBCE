"""Small executable AIR kernel for the Wave 1A constraint implementation.

This module deliberately contains no prover.  It provides the missing boundary
that the historical R33 inventory did not: explicit field cells, expression
trees with derived degrees, row/boundary/transition identities, typed lookup
multisets, canonical program serialization, and a second serialized evaluator.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha3_512
import json
import re
from types import MappingProxyType
from typing import Final, Iterable, Iterator, Mapping, Sequence

from .semantics import StructuralError


M31: Final[int] = (1 << 31) - 1
PROGRAM_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/EXECUTABLE-AIR-PROGRAM/v1\x00"
TRACE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/EXECUTABLE-AIR-TRACE/v1\x00"
MAX_SERIALIZED_PROGRAM_BYTES: Final[int] = 256 * 1024 * 1024
_AIR_NAMESPACE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")


def _field(value: int) -> int:
    if type(value) is not int:
        raise StructuralError("air_field_value_must_be_int")
    return value % M31


@dataclass(frozen=True, slots=True)
class Expr:
    """Canonical field-expression AST.

    Kinds are ``const``, ``cell``, ``add``, ``sub``, and ``mul``.  Cell shifts
    are limited to the current or next row so transition access stays explicit.
    """

    kind: str
    value: int | str | None = None
    shift: int = 0
    left: "Expr | None" = None
    right: "Expr | None" = None

    def __post_init__(self) -> None:
        if self.kind == "const":
            if type(self.value) is not int or self.shift or self.left is not None or self.right is not None:
                raise StructuralError("air_const_expression_invalid")
        elif self.kind == "cell":
            if type(self.value) is not str or not self.value or self.shift not in {0, 1}:
                raise StructuralError("air_cell_expression_invalid")
            if self.left is not None or self.right is not None:
                raise StructuralError("air_cell_expression_children_forbidden")
        elif self.kind in {"add", "sub", "mul"}:
            if self.value is not None or self.shift or not isinstance(self.left, Expr) or not isinstance(self.right, Expr):
                raise StructuralError("air_binary_expression_invalid")
        else:
            raise StructuralError("air_expression_kind_invalid")

    @property
    def degree(self) -> int:
        if self.kind == "const":
            return 0
        if self.kind == "cell":
            return 1
        assert self.left is not None and self.right is not None
        if self.kind == "mul":
            return self.left.degree + self.right.degree
        return max(self.left.degree, self.right.degree)

    def evaluate(self, columns: Mapping[str, Sequence[int]], row: int) -> int:
        if self.kind == "const":
            assert type(self.value) is int
            return self.value % M31
        if self.kind == "cell":
            assert type(self.value) is str
            try:
                return columns[self.value][row + self.shift] % M31
            except (KeyError, IndexError) as exc:
                raise StructuralError("air_expression_cell_out_of_bounds") from exc
        assert self.left is not None and self.right is not None
        lhs = self.left.evaluate(columns, row)
        rhs = self.right.evaluate(columns, row)
        if self.kind == "add":
            return (lhs + rhs) % M31
        if self.kind == "sub":
            return (lhs - rhs) % M31
        return (lhs * rhs) % M31

    def canonical(self) -> object:
        if self.kind == "const":
            return ["const", int(self.value) % M31]
        if self.kind == "cell":
            return ["cell", self.value, self.shift]
        assert self.left is not None and self.right is not None
        return [self.kind, self.left.canonical(), self.right.canonical()]

    def __add__(self, other: int | "Expr") -> "Expr":
        return Expr("add", left=self, right=as_expr(other))

    def __radd__(self, other: int | "Expr") -> "Expr":
        return as_expr(other) + self

    def __sub__(self, other: int | "Expr") -> "Expr":
        return Expr("sub", left=self, right=as_expr(other))

    def __rsub__(self, other: int | "Expr") -> "Expr":
        return as_expr(other) - self

    def __mul__(self, other: int | "Expr") -> "Expr":
        return Expr("mul", left=self, right=as_expr(other))

    def __rmul__(self, other: int | "Expr") -> "Expr":
        return as_expr(other) * self


def const(value: int) -> Expr:
    return Expr("const", value=value)


def cell(name: str, shift: int = 0) -> Expr:
    return Expr("cell", value=name, shift=shift)


def as_expr(value: int | Expr) -> Expr:
    return value if isinstance(value, Expr) else const(value)


def boolean(value: Expr) -> Expr:
    return value * (value - 1)


@dataclass(frozen=True, slots=True)
class Identity:
    name: str
    expression: Expr
    row_start: int
    row_stop: int
    family: str = "local"

    def __post_init__(self) -> None:
        if not self.name or self.family not in {"local", "transition", "boundary"}:
            raise StructuralError("air_identity_metadata_invalid")
        if type(self.row_start) is not int or type(self.row_stop) is not int:
            raise StructuralError("air_identity_row_range_invalid")
        if not 0 <= self.row_start < self.row_stop:
            raise StructuralError("air_identity_row_range_invalid")
        if self.family != "transition" and _has_next(self.expression):
            raise StructuralError("air_next_cell_outside_transition")

    def canonical(self) -> object:
        return {
            "family": self.family,
            "name": self.name,
            "rows": [self.row_start, self.row_stop],
            "expression": self.expression.canonical(),
            "degree": self.expression.degree,
        }


def _has_next(expression: Expr) -> bool:
    if expression.kind == "cell":
        return expression.shift == 1
    if expression.left is None:
        return False
    assert expression.right is not None
    return _has_next(expression.left) or _has_next(expression.right)


@dataclass(frozen=True, slots=True)
class LookupSide:
    table: str
    selector: Expr
    values: tuple[Expr, ...]
    row_start: int
    row_stop: int
    weight: Expr = const(1)

    def __post_init__(self) -> None:
        if not self.table or not self.values:
            raise StructuralError("air_lookup_side_invalid")
        if self.selector.degree > 1 or _has_next(self.selector):
            raise StructuralError("air_lookup_selector_invalid")
        if self.weight.degree > 1 or _has_next(self.weight):
            raise StructuralError("air_lookup_weight_invalid")
        if not 0 <= self.row_start < self.row_stop:
            raise StructuralError("air_lookup_row_range_invalid")

    def canonical(self) -> object:
        return {
            "table": self.table,
            "selector": self.selector.canonical(),
            "values": [value.canonical() for value in self.values],
            "weight": self.weight.canonical(),
            "rows": [self.row_start, self.row_stop],
        }


@dataclass(frozen=True, slots=True)
class LookupArgument:
    name: str
    sources: tuple[LookupSide, ...]
    destinations: tuple[LookupSide, ...]

    def __post_init__(self) -> None:
        if not self.name or not self.sources or not self.destinations:
            raise StructuralError("air_lookup_argument_invalid")
        widths = {len(side.values) for side in self.sources + self.destinations}
        if len(widths) != 1:
            raise StructuralError("air_lookup_width_mismatch")

    def canonical(self) -> object:
        return {
            "name": self.name,
            "sources": [value.canonical() for value in self.sources],
            "destinations": [value.canonical() for value in self.destinations],
        }


@dataclass(frozen=True, slots=True)
class PublicInputBinding:
    """One ordered public M31 cell bound to an exact trace location."""

    name: str
    table: str
    column: str
    row: int

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or type(self.table) is not str
            or not self.table
            or type(self.column) is not str
            or not self.column
            or type(self.row) is not int
            or self.row < 0
        ):
            raise StructuralError("air_public_input_binding_invalid")

    def canonical(self) -> object:
        return {
            "name": self.name,
            "table": self.table,
            "column": self.column,
            "row": self.row,
        }


@dataclass(frozen=True, slots=True)
class TraceTable:
    name: str
    columns: Mapping[str, tuple[int, ...]]

    def __post_init__(self) -> None:
        if not self.name or not self.columns:
            raise StructuralError("air_trace_table_invalid")
        materialized = dict(self.columns)
        if any(type(name) is not str or not name for name in materialized):
            raise StructuralError("air_trace_column_name_invalid")
        lengths = {len(values) for values in materialized.values()}
        if len(lengths) != 1 or not lengths or next(iter(lengths)) == 0:
            raise StructuralError("air_trace_column_length_mismatch")
        for values in materialized.values():
            if type(values) is not tuple or any(type(value) is not int or not 0 <= value < M31 for value in values):
                raise StructuralError("air_trace_field_value_invalid")
        object.__setattr__(self, "columns", MappingProxyType(materialized))

    @property
    def rows(self) -> int:
        return len(next(iter(self.columns.values())))

    def canonical_trace(self) -> object:
        return {"name": self.name, "columns": {name: list(self.columns[name]) for name in sorted(self.columns)}}


@dataclass(frozen=True, slots=True)
class FixedColumnRuns(Sequence[int]):
    """Canonical run-length encoding for a verifier-derived fixed column."""

    runs: tuple[tuple[int, int], ...]
    _row_count: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.runs) is not tuple or not self.runs:
            raise StructuralError("air_fixed_column_runs_invalid")
        row_count = 0
        previous: int | None = None
        for run in self.runs:
            if (
                type(run) is not tuple
                or len(run) != 2
                or type(run[0]) is not int
                or not 0 <= run[0] < M31
                or type(run[1]) is not int
                or run[1] <= 0
                or run[0] == previous
            ):
                raise StructuralError("air_fixed_column_runs_invalid")
            row_count += run[1]
            if row_count > 0xFFFF_FFFF:
                raise StructuralError("air_fixed_column_runs_invalid")
            previous = run[0]
        object.__setattr__(self, "_row_count", row_count)

    def __len__(self) -> int:
        return self._row_count

    def __iter__(self) -> Iterator[int]:
        for value, count in self.runs:
            for _ in range(count):
                yield value

    def __getitem__(self, index: int | slice) -> int | tuple[int, ...]:
        if isinstance(index, slice):
            return tuple(self)[index]
        if type(index) is not int:
            raise TypeError("fixed_column_index_must_be_int_or_slice")
        if index < 0:
            index += self._row_count
        if not 0 <= index < self._row_count:
            raise IndexError("fixed_column_index_out_of_range")
        offset = index
        for value, count in self.runs:
            if offset < count:
                return value
            offset -= count
        raise IndexError("fixed_column_index_out_of_range")

    def canonical(self) -> object:
        return {"encoding": "rle", "runs": [list(run) for run in self.runs]}


@dataclass(frozen=True, slots=True)
class FixedColumnPeriodic(Sequence[int]):
    """Canonical repetition of one exact fixed-column period."""

    pattern: tuple[int, ...]
    row_count: int

    def __post_init__(self) -> None:
        if (
            type(self.pattern) is not tuple
            or not self.pattern
            or any(type(value) is not int or not 0 <= value < M31 for value in self.pattern)
            or type(self.row_count) is not int
            or self.row_count <= 0
            or self.row_count > 0xFFFF_FFFF
            or self.row_count % len(self.pattern) != 0
        ):
            raise StructuralError("air_fixed_column_periodic_invalid")

    def __len__(self) -> int:
        return self.row_count

    def __iter__(self) -> Iterator[int]:
        for index in range(self.row_count):
            yield self.pattern[index % len(self.pattern)]

    def __getitem__(self, index: int | slice) -> int | tuple[int, ...]:
        if isinstance(index, slice):
            return tuple(self)[index]
        if type(index) is not int:
            raise TypeError("fixed_column_index_must_be_int_or_slice")
        if index < 0:
            index += self.row_count
        if not 0 <= index < self.row_count:
            raise IndexError("fixed_column_index_out_of_range")
        return self.pattern[index % len(self.pattern)]

    def canonical(self) -> object:
        return {
            "encoding": "periodic",
            "pattern": list(self.pattern),
            "rows": self.row_count,
        }


FixedColumnValues = tuple[int, ...] | FixedColumnRuns | FixedColumnPeriodic


def _canonical_fixed_column(values: FixedColumnValues) -> object:
    if type(values) is tuple:
        return list(values)
    return values.canonical()


def _fixed_column_matches(values: Sequence[int], observed: Sequence[int]) -> bool:
    return len(values) == len(observed) and all(
        expected == actual for expected, actual in zip(values, observed, strict=True)
    )


@dataclass(frozen=True, slots=True)
class AirTable:
    name: str
    columns: tuple[str, ...]
    rows: int
    identities: tuple[Identity, ...]
    fixed_columns: Mapping[str, FixedColumnValues] | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.columns or len(set(self.columns)) != len(self.columns):
            raise StructuralError("air_table_schema_invalid")
        if type(self.rows) is not int or self.rows <= 0:
            raise StructuralError("air_table_rows_invalid")
        fixed = {} if self.fixed_columns is None else dict(self.fixed_columns)
        if not set(fixed).issubset(self.columns):
            raise StructuralError("air_fixed_column_unknown")
        for values in fixed.values():
            if not isinstance(values, (tuple, FixedColumnRuns, FixedColumnPeriodic)) or len(values) != self.rows:
                raise StructuralError("air_fixed_column_length_invalid")
            if type(values) is tuple and any(type(value) is not int or not 0 <= value < M31 for value in values):
                raise StructuralError("air_fixed_column_value_invalid")
        object.__setattr__(self, "fixed_columns", MappingProxyType(fixed))
        for identity in self.identities:
            if identity.row_stop > self.rows:
                raise StructuralError("air_identity_exceeds_table")
            if identity.family == "transition" and identity.row_stop >= self.rows:
                raise StructuralError("air_transition_exceeds_table")
            referenced = _referenced_columns(identity.expression)
            if not referenced.issubset(self.columns):
                raise StructuralError("air_identity_unknown_column")

    @property
    def maximum_degree(self) -> int:
        return max((value.expression.degree for value in self.identities), default=0)

    def canonical(self) -> object:
        return {
            "name": self.name,
            "columns": list(self.columns),
            "rows": self.rows,
            "fixed_columns": {
                name: _canonical_fixed_column(fixed[name]) for name in sorted(fixed)
            } if (fixed := self.fixed_columns) else {},
            "identities": [value.canonical() for value in self.identities],
        }


def _referenced_columns(expression: Expr) -> set[str]:
    if expression.kind == "cell":
        assert type(expression.value) is str
        return {expression.value}
    if expression.left is None:
        return set()
    assert expression.right is not None
    return _referenced_columns(expression.left) | _referenced_columns(expression.right)


@dataclass(frozen=True, slots=True)
class AirProgram:
    program_id: str
    tables: tuple[AirTable, ...]
    lookups: tuple[LookupArgument, ...] = ()
    public_inputs: tuple[PublicInputBinding, ...] = ()

    def __post_init__(self) -> None:
        if not self.program_id or not self.tables:
            raise StructuralError("air_program_invalid")
        names = tuple(value.name for value in self.tables)
        if len(set(names)) != len(names):
            raise StructuralError("air_program_duplicate_table")
        lookup_names = tuple(value.name for value in self.lookups)
        if len(set(lookup_names)) != len(lookup_names):
            raise StructuralError("air_program_duplicate_lookup")
        known = {table.name: table for table in self.tables}
        for lookup in self.lookups:
            for side in lookup.sources + lookup.destinations:
                if side.table not in known:
                    raise StructuralError("air_lookup_unknown_table")
                table = known[side.table]
                if side.row_stop > table.rows:
                    raise StructuralError("air_lookup_exceeds_table")
                expressions = (side.selector, side.weight, *side.values)
                references: set[str] = set()
                for expression in expressions:
                    references.update(_referenced_columns(expression))
                if not references.issubset(table.columns):
                    raise StructuralError("air_lookup_unknown_column")
        public_names = tuple(value.name for value in self.public_inputs)
        if len(set(public_names)) != len(public_names):
            raise StructuralError("air_public_input_duplicate")
        for binding in self.public_inputs:
            if not isinstance(binding, PublicInputBinding) or binding.table not in known:
                raise StructuralError("air_public_input_binding_invalid")
            table = known[binding.table]
            if binding.column not in table.columns or binding.row >= table.rows:
                raise StructuralError("air_public_input_binding_invalid")

    @property
    def maximum_degree(self) -> int:
        return max(value.maximum_degree for value in self.tables)

    def canonical_object(self) -> object:
        return {
            "field": "M31",
            "program_id": self.program_id,
            "tables": [value.canonical() for value in self.tables],
            "lookups": [value.canonical() for value in self.lookups],
            "public_inputs": [value.canonical() for value in self.public_inputs],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical_object(), sort_keys=True, separators=(",", ":")).encode("ascii")

    def commitment(self) -> bytes:
        return sha3_512(PROGRAM_DOMAIN + self.canonical_bytes()).digest()


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    program_commitment: bytes
    trace_commitment: bytes
    identities_evaluated: int
    lookup_messages_evaluated: int
    maximum_degree: int


@dataclass(frozen=True, slots=True)
class NamespacedAirProgram:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    table_names: Mapping[str, str]


def namespace_air_program(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    namespace: str,
) -> NamespacedAirProgram:
    """Rename an AIR's table/lookup/public namespaces without cloning logic."""

    if not isinstance(program, AirProgram):
        raise TypeError("air_program_required")
    if type(namespace) is not str or _AIR_NAMESPACE.fullmatch(namespace) is None:
        raise StructuralError("air_namespace_invalid")
    expected_names = tuple(table.name for table in program.tables)
    if set(traces) != set(expected_names):
        raise StructuralError("air_trace_table_set_mismatch")
    table_names = {
        name: f"{namespace}__{name}"
        for name in expected_names
    }
    tables = tuple(
        AirTable(
            table_names[table.name],
            table.columns,
            table.rows,
            table.identities,
            table.fixed_columns,
        )
        for table in program.tables
    )

    def side(value: LookupSide) -> LookupSide:
        return LookupSide(
            table_names[value.table],
            value.selector,
            value.values,
            value.row_start,
            value.row_stop,
            value.weight,
        )

    lookups = tuple(
        LookupArgument(
            f"{namespace}__{lookup.name}",
            tuple(side(value) for value in lookup.sources),
            tuple(side(value) for value in lookup.destinations),
        )
        for lookup in program.lookups
    )
    public_inputs = tuple(
        PublicInputBinding(
            f"{namespace}__{binding.name}",
            table_names[binding.table],
            binding.column,
            binding.row,
        )
        for binding in program.public_inputs
    )
    namespaced_traces = MappingProxyType(
        {
            table_names[name]: TraceTable(
                table_names[name],
                trace.columns,
            )
            for name, trace in traces.items()
        }
    )
    return NamespacedAirProgram(
        AirProgram(
            f"{program.program_id}/{namespace}",
            tables,
            lookups,
            public_inputs,
        ),
        namespaced_traces,
        MappingProxyType(table_names),
    )


def _trace_commitment(traces: Mapping[str, TraceTable]) -> bytes:
    payload = [traces[name].canonical_trace() for name in sorted(traces)]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return sha3_512(TRACE_DOMAIN + encoded).digest()


def _bind_public_inputs(
    bindings: Sequence[PublicInputBinding],
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None,
) -> None:
    supplied = () if public_inputs is None else tuple(public_inputs)
    if len(supplied) != len(bindings):
        raise StructuralError("air_public_input_count_mismatch")
    for binding, value in zip(bindings, supplied, strict=True):
        if type(value) is not int or not 0 <= value < M31:
            raise StructuralError(f"air_public_input_not_canonical:{binding.name}")
        if traces[binding.table].columns[binding.column][binding.row] != value:
            raise StructuralError(f"air_public_input_mismatch:{binding.name}")


def evaluate_program(
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None = None,
) -> EvaluationReport:
    """Evaluate the typed AST directly and reject the first nonzero identity."""

    expected = {table.name for table in program.tables}
    if set(traces) != expected:
        raise StructuralError("air_trace_table_set_mismatch")
    _bind_public_inputs(program.public_inputs, traces, public_inputs)
    identity_count = 0
    for table in program.tables:
        trace = traces[table.name]
        if trace.name != table.name or trace.rows != table.rows or set(trace.columns) != set(table.columns):
            raise StructuralError("air_trace_schema_mismatch")
        assert table.fixed_columns is not None
        for name, values in table.fixed_columns.items():
            if not _fixed_column_matches(values, trace.columns[name]):
                raise StructuralError(f"air_fixed_column_mismatch:{table.name}:{name}")
        for identity in table.identities:
            for row in range(identity.row_start, identity.row_stop):
                identity_count += 1
                if identity.expression.evaluate(trace.columns, row) != 0:
                    raise StructuralError(f"air_identity_failed:{table.name}:{identity.name}:{row}")
    lookup_count = 0
    for lookup in program.lookups:
        source: Counter[tuple[int, ...]] = Counter()
        destination: Counter[tuple[int, ...]] = Counter()
        source_capacity = sum(side.row_stop - side.row_start for side in lookup.sources)
        destination_capacity = sum(
            side.row_stop - side.row_start for side in lookup.destinations
        )
        for sides, counter, opposing_capacity in (
            (lookup.sources, source, destination_capacity),
            (lookup.destinations, destination, source_capacity),
        ):
            for side in sides:
                columns = traces[side.table].columns
                for row in range(side.row_start, side.row_stop):
                    selector = side.selector.evaluate(columns, row)
                    if selector not in {0, 1}:
                        raise StructuralError(f"air_lookup_selector_nonboolean:{lookup.name}:{side.table}:{row}")
                    if selector:
                        weight = side.weight.evaluate(columns, row)
                        if weight > opposing_capacity:
                            raise StructuralError(
                                f"air_lookup_weight_out_of_range:{lookup.name}:{side.table}:{row}"
                            )
                        counter[tuple(value.evaluate(columns, row) for value in side.values)] += weight
                        lookup_count += weight
        if source != destination:
            raise StructuralError(f"air_lookup_multiset_mismatch:{lookup.name}")
    return EvaluationReport(
        program.commitment(),
        _trace_commitment(traces),
        identity_count,
        lookup_count,
        program.maximum_degree,
    )


def _serialized_eval(
    node: object,
    columns: Mapping[str, tuple[int, ...]],
    row: int,
    depth: int = 0,
) -> int:
    """Independent interpreter for canonical AST arrays."""

    if depth > 64:
        raise StructuralError("air_serialized_expression_too_deep")
    if type(node) is not list or not node:
        raise StructuralError("air_serialized_expression_invalid")
    kind = node[0]
    if kind == "const" and len(node) == 2 and type(node[1]) is int:
        return node[1] % M31
    if kind == "cell" and len(node) == 3 and type(node[1]) is str and node[2] in {0, 1}:
        try:
            return columns[node[1]][row + node[2]] % M31
        except (KeyError, IndexError) as exc:
            raise StructuralError("air_serialized_cell_out_of_bounds") from exc
    if kind in {"add", "sub", "mul"} and len(node) == 3:
        lhs = _serialized_eval(node[1], columns, row, depth + 1)
        rhs = _serialized_eval(node[2], columns, row, depth + 1)
        if kind == "add":
            return (lhs + rhs) % M31
        if kind == "sub":
            return (lhs - rhs) % M31
        return (lhs * rhs) % M31
    raise StructuralError("air_serialized_expression_invalid")


def _serialized_expression_metadata(
    node: object,
    depth: int = 0,
) -> tuple[int, set[str], bool]:
    """Derive degree, referenced columns, and next-row use from serialized AST."""

    if depth > 64:
        raise StructuralError("air_serialized_expression_too_deep")
    if type(node) is not list or not node:
        raise StructuralError("air_serialized_expression_invalid")
    kind = node[0]
    if kind == "const" and len(node) == 2 and type(node[1]) is int:
        return 0, set(), False
    if (
        kind == "cell"
        and len(node) == 3
        and type(node[1]) is str
        and node[1]
        and type(node[2]) is int
        and node[2] in {0, 1}
    ):
        return 1, {node[1]}, node[2] == 1
    if kind in {"add", "sub", "mul"} and len(node) == 3:
        left_degree, left_columns, left_next = _serialized_expression_metadata(
            node[1], depth + 1
        )
        right_degree, right_columns, right_next = _serialized_expression_metadata(
            node[2], depth + 1
        )
        degree = (
            left_degree + right_degree
            if kind == "mul"
            else max(left_degree, right_degree)
        )
        return degree, left_columns | right_columns, left_next or right_next
    raise StructuralError("air_serialized_expression_invalid")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StructuralError(f"air_serialized_duplicate_key:{key}")
        result[key] = value
    return result


def _require_exact_keys(
    value: Mapping[str, object], expected: set[str], error: str
) -> None:
    if set(value) != expected:
        raise StructuralError(error)


def _serialized_rows(value: object, limit: int) -> tuple[int, int]:
    if (
        type(value) is not list
        or len(value) != 2
        or any(type(item) is not int for item in value)
    ):
        raise StructuralError("air_serialized_row_range_invalid")
    start, stop = value
    if not 0 <= start < stop <= limit:
        raise StructuralError("air_serialized_row_range_invalid")
    return start, stop


def _serialized_fixed_column_matches(
    encoded: object,
    observed: Sequence[int] | None,
    rows: int,
) -> bool:
    if observed is None or len(observed) != rows:
        return False
    if type(encoded) is list:
        return (
            len(encoded) == rows
            and all(type(value) is int and 0 <= value < M31 for value in encoded)
            and all(
                expected == actual
                for expected, actual in zip(encoded, observed, strict=True)
            )
        )
    if type(encoded) is not dict or type(encoded.get("encoding")) is not str:
        return False
    if encoded["encoding"] == "rle":
        if set(encoded) != {"encoding", "runs"} or type(encoded.get("runs")) is not list:
            return False
        offset = 0
        previous: int | None = None
        for run in encoded["runs"]:
            if (
                type(run) is not list
                or len(run) != 2
                or type(run[0]) is not int
                or not 0 <= run[0] < M31
                or type(run[1]) is not int
                or run[1] <= 0
                or run[0] == previous
                or offset + run[1] > rows
            ):
                return False
            if any(observed[index] != run[0] for index in range(offset, offset + run[1])):
                return False
            offset += run[1]
            previous = run[0]
        return offset == rows
    if encoded["encoding"] == "periodic":
        if set(encoded) != {"encoding", "pattern", "rows"}:
            return False
        pattern = encoded.get("pattern")
        return (
            type(pattern) is list
            and bool(pattern)
            and all(type(value) is int and 0 <= value < M31 for value in pattern)
            and type(encoded.get("rows")) is int
            and encoded["rows"] == rows
            and rows % len(pattern) == 0
            and all(observed[index] == pattern[index % len(pattern)] for index in range(rows))
        )
    return False


def evaluate_serialized(
    program_bytes: bytes,
    traces: Mapping[str, TraceTable],
    public_inputs: Sequence[int] | None = None,
) -> EvaluationReport:
    """Evaluate canonical bytes without using ``Expr.evaluate`` or typed identities."""

    if type(program_bytes) is not bytes or not 0 < len(program_bytes) <= MAX_SERIALIZED_PROGRAM_BYTES:
        raise StructuralError("air_serialized_program_invalid")
    try:
        document = json.loads(
            program_bytes.decode("ascii"),
            object_pairs_hook=_strict_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                StructuralError("air_serialized_program_invalid")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StructuralError("air_serialized_program_invalid") from exc
    if type(document) is not dict or document.get("field") != "M31":
        raise StructuralError("air_serialized_program_invalid")
    _require_exact_keys(
        document,
        {"field", "program_id", "tables", "lookups", "public_inputs"},
        "air_serialized_program_invalid",
    )
    if json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") != program_bytes:
        raise StructuralError("air_serialized_program_not_canonical")
    if type(document.get("program_id")) is not str or not document["program_id"]:
        raise StructuralError("air_serialized_program_invalid")
    tables = document.get("tables")
    lookups = document.get("lookups")
    public_bindings = document.get("public_inputs")
    if (
        type(tables) is not list
        or type(lookups) is not list
        or type(public_bindings) is not list
        or not tables
    ):
        raise StructuralError("air_serialized_program_invalid")
    if any(type(value) is not dict for value in tables):
        raise StructuralError("air_serialized_table_invalid")
    table_names = [value.get("name") for value in tables]
    if (
        any(type(name) is not str or not name for name in table_names)
        or len(set(table_names)) != len(table_names)
    ):
        raise StructuralError("air_serialized_table_invalid")
    expected_names = set(table_names)
    if set(traces) != expected_names:
        raise StructuralError("air_trace_table_set_mismatch")
    table_schemas: dict[str, tuple[int, set[str]]] = {}
    identity_count = 0
    maximum_degree = 0
    for table in tables:
        _require_exact_keys(
            table,
            {"name", "columns", "rows", "fixed_columns", "identities"},
            "air_serialized_table_invalid",
        )
        name, rows, columns, identities, fixed = table.get("name"), table.get("rows"), table.get("columns"), table.get("identities"), table.get("fixed_columns")
        if (
            type(name) is not str
            or type(rows) is not int
            or rows <= 0
            or type(columns) is not list
            or not columns
            or any(type(column) is not str or not column for column in columns)
            or len(set(columns)) != len(columns)
            or type(identities) is not list
            or type(fixed) is not dict
        ):
            raise StructuralError("air_serialized_table_invalid")
        column_set = set(columns)
        table_schemas[name] = (rows, column_set)
        trace = traces[name]
        if trace.name != name or trace.rows != rows or set(trace.columns) != column_set:
            raise StructuralError("air_trace_schema_mismatch")
        for fixed_name, fixed_values in fixed.items():
            if (
                fixed_name not in column_set
                or not _serialized_fixed_column_matches(
                    fixed_values,
                    trace.columns.get(fixed_name),
                    rows,
                )
            ):
                raise StructuralError(f"air_fixed_column_mismatch:{name}:{fixed_name}")
        for identity in identities:
            if (
                type(identity) is not dict
                or type(identity.get("name")) is not str
                or not identity["name"]
                or identity.get("family") not in {"local", "transition", "boundary"}
            ):
                raise StructuralError("air_serialized_identity_invalid")
            _require_exact_keys(
                identity,
                {"family", "name", "rows", "expression", "degree"},
                "air_serialized_identity_invalid",
            )
            start, stop = _serialized_rows(identity.get("rows"), rows)
            degree, references, has_next = _serialized_expression_metadata(
                identity.get("expression")
            )
            if (
                type(identity.get("degree")) is not int
                or identity["degree"] != degree
                or not references.issubset(column_set)
                or (identity["family"] != "transition" and has_next)
                or (identity["family"] == "transition" and stop >= rows)
            ):
                raise StructuralError("air_serialized_identity_invalid")
            maximum_degree = max(maximum_degree, degree)
            for row in range(start, stop):
                identity_count += 1
                if _serialized_eval(identity.get("expression"), trace.columns, row) != 0:
                    raise StructuralError(f"air_identity_failed:{name}:{identity.get('name')}:{row}")
    parsed_bindings: list[PublicInputBinding] = []
    for binding in public_bindings:
        if type(binding) is not dict:
            raise StructuralError("air_serialized_public_input_invalid")
        _require_exact_keys(
            binding,
            {"name", "table", "column", "row"},
            "air_serialized_public_input_invalid",
        )
        try:
            parsed = PublicInputBinding(
                binding["name"], binding["table"], binding["column"], binding["row"]
            )
        except (KeyError, TypeError, StructuralError) as exc:
            raise StructuralError("air_serialized_public_input_invalid") from exc
        if parsed.table not in table_schemas:
            raise StructuralError("air_serialized_public_input_invalid")
        rows, columns = table_schemas[parsed.table]
        if parsed.column not in columns or parsed.row >= rows:
            raise StructuralError("air_serialized_public_input_invalid")
        parsed_bindings.append(parsed)
    if len({binding.name for binding in parsed_bindings}) != len(parsed_bindings):
        raise StructuralError("air_serialized_public_input_invalid")
    _bind_public_inputs(parsed_bindings, traces, public_inputs)
    lookup_count = 0
    for lookup in lookups:
        if (
            type(lookup) is not dict
            or type(lookup.get("name")) is not str
            or not lookup["name"]
            or type(lookup.get("sources")) is not list
            or not lookup["sources"]
            or type(lookup.get("destinations")) is not list
            or not lookup["destinations"]
        ):
            raise StructuralError("air_serialized_lookup_invalid")
        _require_exact_keys(
            lookup,
            {"name", "sources", "destinations"},
            "air_serialized_lookup_invalid",
        )
        counters: list[Counter[tuple[int, ...]]] = []
        sides_by_key = (lookup["sources"], lookup["destinations"])
        capacities = tuple(
            sum(_serialized_rows(side.get("rows"), table_schemas[side.get("table")][0])[1]
                - _serialized_rows(side.get("rows"), table_schemas[side.get("table")][0])[0]
                for side in sides)
            if all(
                type(side) is dict and side.get("table") in table_schemas
                for side in sides
            )
            else -1
            for sides in sides_by_key
        )
        widths: set[int] = set()
        for side_index, key in enumerate(("sources", "destinations")):
            counter: Counter[tuple[int, ...]] = Counter()
            sides = lookup.get(key)
            if type(sides) is not list or not sides or capacities[side_index] < 0:
                raise StructuralError("air_serialized_lookup_invalid")
            for side in sides:
                if type(side) is not dict or side.get("table") not in table_schemas:
                    raise StructuralError("air_serialized_lookup_invalid")
                _require_exact_keys(
                    side,
                    {"table", "selector", "values", "weight", "rows"},
                    "air_serialized_lookup_invalid",
                )
                table_name = side["table"]
                table_rows, table_columns = table_schemas[table_name]
                values = side.get("values")
                if type(values) is not list or not values:
                    raise StructuralError("air_serialized_lookup_invalid")
                widths.add(len(values))
                start, stop = _serialized_rows(side.get("rows"), table_rows)
                selector_degree, selector_columns, selector_next = _serialized_expression_metadata(
                    side.get("selector")
                )
                weight_node = side.get("weight", ["const", 1])
                weight_degree, weight_columns, weight_next = _serialized_expression_metadata(
                    weight_node
                )
                value_columns: set[str] = set()
                for value in values:
                    _, references, _ = _serialized_expression_metadata(value)
                    value_columns.update(references)
                if (
                    selector_degree > 1
                    or selector_next
                    or weight_degree > 1
                    or weight_next
                    or not (selector_columns | weight_columns | value_columns).issubset(
                        table_columns
                    )
                ):
                    raise StructuralError("air_serialized_lookup_invalid")
                trace = traces[table_name]
                for row in range(start, stop):
                    selector = _serialized_eval(side["selector"], trace.columns, row)
                    if selector not in {0, 1}:
                        raise StructuralError("air_lookup_selector_nonboolean")
                    if selector:
                        weight = _serialized_eval(weight_node, trace.columns, row)
                        if weight > capacities[1 - side_index]:
                            raise StructuralError(
                                f"air_lookup_weight_out_of_range:{lookup['name']}:{table_name}:{row}"
                            )
                        counter[tuple(_serialized_eval(value, trace.columns, row) for value in values)] += weight
                        lookup_count += weight
            counters.append(counter)
        if len(widths) != 1:
            raise StructuralError("air_serialized_lookup_invalid")
        if counters[0] != counters[1]:
            raise StructuralError(f"air_lookup_multiset_mismatch:{lookup.get('name')}")
    digest = sha3_512(PROGRAM_DOMAIN + program_bytes).digest()
    return EvaluationReport(digest, _trace_commitment(traces), identity_count, lookup_count, maximum_degree)


def freeze_columns(columns: Mapping[str, Iterable[int]]) -> Mapping[str, tuple[int, ...]]:
    return MappingProxyType({name: tuple(_field(value) for value in values) for name, values in columns.items()})


__all__ = [
    "M31",
    "AirProgram",
    "AirTable",
    "EvaluationReport",
    "Expr",
    "FixedColumnPeriodic",
    "FixedColumnRuns",
    "FixedColumnValues",
    "Identity",
    "LookupArgument",
    "LookupSide",
    "NamespacedAirProgram",
    "PublicInputBinding",
    "TraceTable",
    "boolean",
    "cell",
    "const",
    "evaluate_program",
    "evaluate_serialized",
    "freeze_columns",
    "namespace_air_program",
]
