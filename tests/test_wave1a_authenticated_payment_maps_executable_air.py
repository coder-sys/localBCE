from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.authenticated_payment_maps_executable_air import (
    AuthenticatedPaymentMapsAirInstance,
)
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    build_authenticated_payment_map_transition,
)
from experiments.fixed_shape_claim_air.claim_payment_maps_executable_air import (
    ClaimPaymentMapsAirInstance,
    build_claim_payment_maps_executable_air,
    build_claim_payment_maps_sha3_interface_program,
)
from experiments.fixed_shape_claim_air.executable_air import (
    M31,
    AirProgram,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from tests.test_wave1a_authenticated_payment_maps_reference import FLAGS, _slots, _state


@lru_cache(maxsize=1)
def claim_payment_maps_air_instance() -> ClaimPaymentMapsAirInstance:
    profile = get_profile("K128_CALIBRATION")
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        return build_claim_payment_maps_executable_air(slots, transition)


def payment_maps_air_instance() -> AuthenticatedPaymentMapsAirInstance:
    return claim_payment_maps_air_instance().payment_maps


@lru_cache(maxsize=1)
def fully_hashed_claim_payment_maps_air_instance() -> ClaimPaymentMapsAirInstance:
    profile = get_profile("K128_CALIBRATION")
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        return build_claim_payment_maps_executable_air(
            slots,
            transition,
            compose_operation_log_sha3=True,
            compose_key_sha3=True,
        )


@lru_cache(maxsize=1)
def interface_hashed_claim_payment_maps_air_instance() -> ClaimPaymentMapsAirInstance:
    profile = get_profile("K128_CALIBRATION")
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        payment_runs = tuple(
            run
            for run in build_wave1a_global_sha3_capacity_schedule(profile).runs
            if run.component == "payment"
        )
        map_call_count = sum(run.count for run in payment_runs[:-3])
        return build_claim_payment_maps_executable_air(
            slots,
            transition,
            compose_operation_log_sha3=True,
            compose_key_sha3=True,
            interface_only=True,
            sha3_call_prefix=map_call_count,
        )


def test_k128_payment_maps_air_has_one_shared_byte_table() -> None:
    instance = payment_maps_air_instance()

    assert len(instance.program.tables) == 23
    assert len(instance.program.lookups) == 29
    assert set(instance.traces) == {table.name for table in instance.program.tables}
    assert sum(name.endswith("__ordered_map_byte") for name in instance.traces) == 0
    assert "payment_maps_byte_shared" in instance.traces
    assert instance.program.maximum_degree == 3
    assert instance.program.commitment().hex() == (
        "6d7841a9028259c9fb645677f713bdee390c8b3ff389c2d1f0a15b64bc265f4a"
        "00ba9c3a4b5312730fadf397e46012482019ea5b19e8c199eff6a0d3055c4932"
    )
    assert instance.hashes_constrained is False
    assert instance.payment_semantics_constrained is False


def test_k128_claim_payment_maps_air_evaluates() -> None:
    instance = claim_payment_maps_air_instance()
    report = evaluate_program(instance.program, instance.traces)

    assert len(instance.program.tables) == 32
    assert len(instance.program.lookups) == 44
    assert report.identities_evaluated == 30_178_149
    assert report.lookup_messages_evaluated == 41_308_372
    assert report.maximum_degree == 3
    assert report.program_commitment.hex() == (
        "aa8df56ab409259ba70636c83402cdc3566f6d9219f2050da18f0482c01ef86d"
        "ea1901041f68807ccc95ed2c926d536c5100a6a97e12850678e9536125115d08"
    )
    assert report.trace_commitment.hex() == (
        "38aff0c74a1cd66cd7c48fd71b22b760cb02ed706229715a4a17112735e53d8fe"
        "b3dae5c2dc97964c150d58760adfce4db57be27630aced86ae112ad87c2419f"
    )
    assert instance.authorization_uses_constrained is True
    assert instance.key_derivations_constrained is False
    assert instance.operation_log_constrained is False


def test_k128_claim_payment_maps_one_sha3_engine_fully_evaluates() -> None:
    instance = fully_hashed_claim_payment_maps_air_instance()
    report = evaluate_program(instance.program, instance.traces)

    assert len(instance.program.tables) == 52
    assert len(instance.program.lookups) == 80
    assert instance.traces["sha3_digest_batch"].rows == 768
    assert instance.traces["sha3_message_batch"].rows == 248_832
    assert report.identities_evaluated == 112_616_159
    assert report.lookup_messages_evaluated == 220_927_478
    assert report.maximum_degree == 3
    assert report.program_commitment.hex() == (
        "8b97aba8b5998d63f71f3dc596229168fe3bb9f5d4149fc3ec0a72bfd6848849"
        "f8b9feac8288c8bd0c0544590f13b512e036d76ba76fbe2ead702ff9f4ec3b83"
    )
    assert report.trace_commitment.hex() == (
        "1422c09b2e9f9a106e4345d98966f7dc7d0ef57ab56cf1beb96feecab0c6f2ca"
        "1c79b95b3f96eece223a13049320fe88ffd643f1cfc558352338fd0741190b95"
    )
    assert instance.key_derivations_constrained is True
    assert instance.authorization_uses_constrained is True
    assert instance.operation_log_constrained is True


def test_k128_payment_sha3_interfaces_compose_without_legacy_tables() -> None:
    instance = interface_hashed_claim_payment_maps_air_instance()
    assert instance.application_sha3 is not None
    sha_names = {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }
    assert {table.name for table in instance.application_sha3.program.tables} == sha_names
    assert instance.application_sha3.traces["sha3_digest_batch"].rows == 768
    assert instance.application_sha3.traces["sha3_message_batch"].rows == 248_832
    payment_runs = tuple(
        run
        for run in build_wave1a_global_sha3_capacity_schedule(
            get_profile("K128_CALIBRATION")
        ).runs
        if run.component == "payment"
    )
    expected_application_capacities = tuple(
        run.capacity
        for run in payment_runs[-3:]
        for _ in range(run.count)
    )
    assert tuple(
        call.capacity for call in instance.application_sha3.calls
    ) == expected_application_capacities
    program, capacities = build_claim_payment_maps_sha3_interface_program(instance)
    expected_capacities = tuple(
        run.capacity for run in payment_runs for _ in range(run.count)
    )
    assert capacities == expected_capacities
    assert next(
        table for table in program.tables if table.name == "sha3_message_batch"
    ).rows == sum((capacity // 72 + 1) * 72 for capacity in capacities)
    assert {"sha3_round_batch", "sha3_truth_shared"}.isdisjoint(
        table.name for table in program.tables
    )


def _mutate(trace: TraceTable, column: str, row: int) -> TraceTable:
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = (columns[column][row] + 1) % M31
    return TraceTable(trace.name, freeze_columns(columns))


def test_payment_carry_mutation_fails_in_reduced_bridge_program() -> None:
    instance = claim_payment_maps_air_instance()
    table = next(
        table for table in instance.program.tables if table.name == "claim_payment_map_slot"
    )
    trace = instance.traces[table.name]
    reduced = AirProgram("payment-bridge-local-test", (table,))
    bad = _mutate(trace, "reserve_carry_0", 0)
    with pytest.raises(StructuralError, match="air_identity_failed"):
        evaluate_program(reduced, {table.name: bad})


def test_payment_key_mutation_fails_authenticated_operation_link() -> None:
    instance = claim_payment_maps_air_instance()
    table_names = {"claim_payment_map_slot", "benefit__ordered_map_operation"}
    tables = tuple(table for table in instance.program.tables if table.name in table_names)
    lookup = next(
        lookup
        for lookup in instance.program.lookups
        if lookup.name == "claim_payment_benefit_operation"
    )
    reduced = AirProgram("payment-bridge-link-test", tables, (lookup,))
    traces = {name: instance.traces[name] for name in table_names}
    traces["claim_payment_map_slot"] = _mutate(
        traces["claim_payment_map_slot"], "benefit_key_0", 0
    )
    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:claim_payment_benefit_operation",
    ):
        evaluate_program(reduced, traces)


@pytest.mark.parametrize(
    "field",
    ("hashes_constrained", "payment_semantics_constrained"),
)
def test_payment_maps_air_rejects_false_boundary_claim(field: str) -> None:
    instance = payment_maps_air_instance()
    with pytest.raises(StructuralError, match="payment_maps_air_false_completion_claim"):
        replace(instance, **{field: True})
