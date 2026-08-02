from __future__ import annotations

from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    encode_air_execution,
)
from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.state_plane_executable_air import (
    PROGRAM_ID,
    build_state_plane_air,
    compose_state_plane_air,
)
from tests.test_wave1a_executable_air import _fixture
from tests.test_wave1a_air_binary_ir_cross_language import (
    _build_binary,
    _report,
    _run,
)
from tests.test_bl_pq512_state_plane import _proof


def test_state_plane_air_constrains_slots_sha3_roots_and_public_order() -> None:
    proof = _proof()
    instance = build_state_plane_air(proof)
    direct = evaluate_program(instance.program, instance.traces, instance.public_values)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(), instance.traces, instance.public_values
    )
    assert instance.program.program_id == PROGRAM_ID
    assert direct == serialized
    assert direct.identities_evaluated > proof.before.capacity
    assert direct.lookup_messages_evaluated >= len(instance.call_messages)
    assert instance.public_values == tuple(
        value
        for root in (proof.before.root_512, proof.after.root_512)
        for value in root
    )
    assert encode_air_execution(
        instance.program, instance.traces, instance.public_values
    )


def test_state_plane_air_composes_into_one_ordered_execution() -> None:
    base_program, base_traces = _fixture()
    program, traces, public_values = compose_state_plane_air(
        base_program, base_traces, (), _proof()
    )
    report = evaluate_program(program, traces, public_values)
    assert report.identities_evaluated > 0
    assert program.program_id.endswith("/WITH-STATE")
    assert any(
        binding.name.startswith("state_plane__state_root_")
        for binding in program.public_inputs
    )


def test_rust_independent_evaluator_accepts_composed_state_air() -> None:
    base_program, base_traces = _fixture()
    program, traces, public_values = compose_state_plane_air(
        base_program, base_traces, (), _proof()
    )
    expected = evaluate_program(program, traces, public_values)
    result = _run(
        _build_binary("air_ir_evaluate"),
        encode_air_execution(program, traces, public_values),
    )
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    assert _report(result.stdout) == {
        "source_program_commitment": expected.program_commitment.hex(),
        "binary_commitment": air_binary_commitment(
            encode_air_execution(program, traces, public_values)
        ).hex(),
        "identities_evaluated": str(expected.identities_evaluated),
        "lookup_messages_evaluated": str(expected.lookup_messages_evaluated),
        "maximum_degree": str(expected.maximum_degree),
    }
