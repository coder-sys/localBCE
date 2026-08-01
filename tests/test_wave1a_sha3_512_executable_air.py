from __future__ import annotations

from hashlib import sha3_512

from experiments.fixed_shape_claim_air.executable_air import evaluate_program, evaluate_serialized
from experiments.fixed_shape_claim_air.sha3_512_executable_air import (
    build_sha3_512_executable_air,
    sha3_512_trace_rows_commitment,
)


def test_sha3_512_executable_air_matches_fips_abc_kat() -> None:
    instance = build_sha3_512_executable_air(b"abc")
    assert instance.digest == sha3_512(b"abc").digest()
    assert instance.program.tables[0].rows == 24
    assert len(instance.program.tables[0].columns) == 1_935
    assert len(instance.program.tables[0].identities) == 720

    direct = evaluate_program(instance.program, instance.traces)
    serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
    assert direct == serialized
    assert direct.maximum_degree == 2
    assert direct.identities_evaluated == 16_952
    assert direct.lookup_messages_evaluated == 49_302


def test_sha3_512_executable_air_constrains_multiblock_absorption() -> None:
    message = bytes(range(80))
    instance = build_sha3_512_executable_air(message)
    assert instance.digest == sha3_512(message).digest()
    assert instance.program.tables[0].rows == 48
    report = evaluate_program(instance.program, instance.traces)
    assert report.maximum_degree == 2


def test_fixed_capacity_sha3_program_hides_message_length() -> None:
    short = build_sha3_512_executable_air(b"abc", capacity=143)
    long = build_sha3_512_executable_air(bytes(range(80)), capacity=143)
    assert short.program.commitment() == long.program.commitment()
    assert short.program.tables[0].rows == long.program.tables[0].rows == 48
    assert short.traces["sha3_message"].rows == long.traces["sha3_message"].rows == 144
    assert short.digest == sha3_512(b"abc").digest()
    assert long.digest == sha3_512(bytes(range(80))).digest()
    for instance in (short, long):
        direct = evaluate_program(instance.program, instance.traces)
        serialized = evaluate_serialized(instance.program.canonical_bytes(), instance.traces)
        assert direct == serialized
        assert direct.maximum_degree == 2


def test_sha3_streaming_trace_commitment_matches_rust_kat() -> None:
    assert sha3_512_trace_rows_commitment(b"abc", capacity=71).hex() == (
        "227da2c01e98a51402e53ceef7feb77015e2ba714b7fb465400a6af69b601ff4"
        "f2f1a4c0a7de504063bb38ce99e7d1b05ae43f44e66afe410909c699921114d8"
    )
