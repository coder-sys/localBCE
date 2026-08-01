from __future__ import annotations

from hashlib import sha3_512
from functools import lru_cache
from types import MappingProxyType, SimpleNamespace

import pytest

from experiments.fixed_shape_claim_air.air_composition import (
    AirFragment,
    Sha3ComposedComponent,
    Sha3ProgramFragment,
    compose_boolean_sha3_air_components,
    compose_boolean_sha3_program_fragments,
    compose_sha3_air_components,
    compose_sha3_interface_components,
    compose_sha3_interface_program_fragments,
    merge_air_fragments,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    TraceTable,
    StructuralError,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.packed_execution_commitment_executable_air import (
    _build,
)


def _component(kind: str, magic: bytes, offset: int, *, interface_only: bool = False):
    bundles = (
        f"{kind}-bundle-zero".encode(),
        f"{kind}-bundle-one".encode(),
    )
    leaves = tuple(sha3_512(value).digest() for value in bundles)
    prefix = magic + b"\x01" + len(bundles).to_bytes(2, "big")
    execution = sha3_512(prefix + b"".join(leaves)).digest()
    columns = freeze_columns(
        {
            "slot_index": tuple(
                slot for slot, bundle in enumerate(bundles) for _ in bundle
            ),
            "byte_index": tuple(
                index for bundle in bundles for index in range(len(bundle))
            ),
            "value": tuple(value for bundle in bundles for value in bundle),
        }
    )
    trace = TraceTable(f"{kind}_bundle_byte", columns)
    table = AirTable(trace.name, tuple(columns), trace.rows, ())
    encoding = SimpleNamespace(
        program=AirProgram(f"{kind}-mini-encoding", (table,)),
        traces=MappingProxyType({trace.name: trace}),
    )
    profile = SimpleNamespace(profile_id="K128_CALIBRATION", claim_slots=2)
    return _build(
        profile,
        kind,
        encoding,
        bundle_table=trace.name,
        bundles=bundles,
        leaves=leaves,
        execution_root=execution,
        audit_root=sha3_512(f"{kind}-audit".encode()).digest(),
        magic=magic,
        call_index_offset=offset,
        interface_only=interface_only,
    )


def test_modular_hash_components_collapse_to_one_sha3_engine() -> None:
    policy = _component("policy", b"BLPQPXR2", 0)
    oracle = _component("oracle", b"BLPQOXR2", 3)
    composed = compose_sha3_air_components(
        "BL-WAVE1A-MINI-GLOBAL-SHA3-COMPOSITION-v1",
        (
            Sha3ComposedComponent(
                policy.program, policy.traces, policy.sha3, 0
            ),
            Sha3ComposedComponent(
                oracle.program, oracle.traces, oracle.sha3, 3
            ),
        ),
    )

    report = evaluate_program(composed.program, composed.traces)
    assert composed.component_count == 2
    assert composed.traces["sha3_digest_batch"].rows == 6
    assert tuple(table.name for table in composed.program.tables).count(
        "sha3_truth_shared"
    ) == 1
    assert report.maximum_degree == 2


def test_compact_interfaces_compose_without_legacy_keccak_tables() -> None:
    policy = _component("policy", b"BLPQPXR2", 0, interface_only=True)
    oracle = _component("oracle", b"BLPQOXR2", 3, interface_only=True)
    composed = compose_sha3_interface_components(
        "BL-WAVE1A-MINI-GLOBAL-SHA3-INTERFACE-v1",
        (
            Sha3ComposedComponent(policy.program, policy.traces, policy.sha3, 0),
            Sha3ComposedComponent(oracle.program, oracle.traces, oracle.sha3, 3),
        ),
    )

    report = evaluate_program(composed.program, composed.traces)
    names = {table.name for table in composed.program.tables}
    assert composed.traces["sha3_digest_batch"].rows == 6
    assert "sha3_message_batch" in names
    assert {"sha3_round_batch", "sha3_truth_shared"}.isdisjoint(names)
    assert report.maximum_degree == 3


@lru_cache(maxsize=1)
def _interface_boolean_composed():
    policy = _component("policy", b"BLPQPXR2", 0, interface_only=True)
    oracle = _component("oracle", b"BLPQOXR2", 3, interface_only=True)
    return compose_boolean_sha3_air_components(
        "BL-WAVE1A-MINI-GLOBAL-BOOLEAN-SHA3-INTERFACE-v1",
        (
            Sha3ComposedComponent(policy.program, policy.traces, policy.sha3, 0),
            Sha3ComposedComponent(oracle.program, oracle.traces, oracle.sha3, 3),
        ),
    )


def test_compact_interfaces_bind_directly_to_boolean_sha3() -> None:
    composed = _interface_boolean_composed()
    report = evaluate_program(composed.program, composed.traces)
    names = {table.name for table in composed.program.tables}
    assert {"sha3_round_batch", "sha3_truth_shared"}.isdisjoint(names)
    assert {
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    }.issubset(names)
    assert dict(composed.boolean_sha3.digests) == dict(composed.sha3.digests)
    assert report.maximum_degree == 11


def test_program_only_boolean_composition_matches_witness_backed_program() -> None:
    policy = _component("policy", b"BLPQPXR2", 0, interface_only=True)
    oracle = _component("oracle", b"BLPQOXR2", 3, interface_only=True)
    program = compose_boolean_sha3_program_fragments(
        "BL-WAVE1A-MINI-GLOBAL-BOOLEAN-SHA3-INTERFACE-v1",
        (
            Sha3ProgramFragment(
                policy.program,
                tuple(call.capacity for call in policy.sha3.calls),
                0,
            ),
            Sha3ProgramFragment(
                oracle.program,
                tuple(call.capacity for call in oracle.sha3.calls),
                3,
            ),
        ),
    )
    witnessed = _interface_boolean_composed().program
    assert program.canonical_bytes() == witnessed.canonical_bytes()
    assert program.commitment() == witnessed.commitment()


def test_program_only_external_bus_composition_matches_witness_backed_program() -> None:
    policy = _component("policy", b"BLPQPXR2", 0, interface_only=True)
    oracle = _component("oracle", b"BLPQOXR2", 3, interface_only=True)
    components = (
        Sha3ComposedComponent(policy.program, policy.traces, policy.sha3, 0),
        Sha3ComposedComponent(oracle.program, oracle.traces, oracle.sha3, 3),
    )
    fragments = tuple(
        Sha3ProgramFragment(
            component.program,
            tuple(call.capacity for call in component.sha3.calls),
            component.call_index_offset,
        )
        for component in components
    )
    program = compose_sha3_interface_program_fragments(
        "BL-WAVE1A-MINI-GLOBAL-SHA3-BUS-v1",
        fragments,
    )
    witnessed = compose_sha3_interface_components(
        "BL-WAVE1A-MINI-GLOBAL-SHA3-BUS-v1",
        components,
    ).program
    names = {table.name for table in program.tables}

    assert program.canonical_bytes() == witnessed.canonical_bytes()
    assert program.commitment() == witnessed.commitment()
    assert {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }.issubset(names)
    assert {
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    }.isdisjoint(names)


def test_identical_shared_fragments_are_deduplicated_exactly() -> None:
    columns = freeze_columns({"value": (7,)})
    trace = TraceTable("shared", columns)
    table = AirTable("shared", ("value",), 1, ())
    fragment = AirFragment(
        AirProgram("fragment", (table,)), MappingProxyType({"shared": trace})
    )
    merged = merge_air_fragments("merged", (fragment, fragment))
    assert len(merged.program.tables) == 1
    assert merged.fragment_count == 2
    evaluate_program(merged.program, merged.traces)


@lru_cache(maxsize=1)
def _boolean_composed():
    policy = _component("policy", b"BLPQPXR2", 0)
    oracle = _component("oracle", b"BLPQOXR2", 3)
    return compose_boolean_sha3_air_components(
        "BL-WAVE1A-MINI-GLOBAL-BOOLEAN-SHA3-COMPOSITION-v1",
        (
            Sha3ComposedComponent(policy.program, policy.traces, policy.sha3, 0),
            Sha3ComposedComponent(oracle.program, oracle.traces, oracle.sha3, 3),
        ),
    )


def test_modular_components_use_one_direct_boolean_sha3_engine() -> None:
    composed = _boolean_composed()
    report = evaluate_program(composed.program, composed.traces)
    names = {table.name for table in composed.program.tables}

    assert {"sha3_round_batch", "sha3_truth_shared", "sha3_byte_range_shared"}.isdisjoint(names)
    assert {
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    }.issubset(names)
    assert next(
        table for table in composed.program.tables if table.name == "sha3_message_batch"
    ).columns == (
        "call_index",
        "position",
        "call_start",
        "same_call_next",
        "live",
        "value",
    )
    assert dict(composed.boolean_sha3.digests) == dict(composed.sha3.digests)
    assert report.maximum_degree == 11


def test_boolean_sha3_message_bridge_and_round_binding_fail_closed() -> None:
    composed = _boolean_composed()
    interface = composed.traces["sha3_message_batch"]
    interface_columns = {
        name: list(values) for name, values in interface.columns.items()
    }
    row = next(index for index, live in enumerate(interface_columns["live"]) if live)
    call_index = interface_columns["call_index"][row]
    position = interface_columns["position"][row]
    interface_columns["value"][row] ^= 1

    absorb = composed.traces["sha3_boolean_absorb"]
    absorb_columns = {name: list(values) for name, values in absorb.columns.items()}
    absorb_row = next(
        index
        for index, observed_call in enumerate(absorb_columns["call_index"])
        if observed_call == call_index
        and 72 * absorb_columns["block_index"][index] <= position
        < 72 * (absorb_columns["block_index"][index] + 1)
    )
    byte_index = position % 72
    absorb_columns[f"block_byte_{byte_index}"][absorb_row] ^= 1
    absorb_columns[f"block_bit_{8 * byte_index}"][absorb_row] ^= 1

    bad = dict(composed.traces)
    bad[interface.name] = TraceTable(interface.name, freeze_columns(interface_columns))
    bad[absorb.name] = TraceTable(absorb.name, freeze_columns(absorb_columns))
    with pytest.raises(StructuralError, match="sha3_boolean_absorb_to_round"):
        evaluate_program(composed.program, bad)
