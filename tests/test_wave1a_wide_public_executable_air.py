from __future__ import annotations

from hashlib import sha3_512

from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.stark252_projection_air import (
    compatibility_felt_from_sha3_512,
)
from experiments.fixed_shape_claim_air.wide_public_executable_air import (
    PUBLIC_FIELD_NAMES,
    build_wide_public_executable_air,
    build_wide_public_executable_air_v2,
)


def _wide_values() -> tuple[bytes, ...]:
    return tuple(sha3_512(f"BL-WIDE-PUBLIC-{index}".encode()).digest() for index in range(9))


def test_wide_public_air_binds_order_canonical_felts_and_wide_projections() -> None:
    wide = _wide_values()
    instance = build_wide_public_executable_air(2, 7001, 9001, wide)
    assert len(PUBLIC_FIELD_NAMES) == 12
    assert instance.public_outputs[:3] == (2, 7001, 9001)
    assert instance.public_outputs[3:] == tuple(
        compatibility_felt_from_sha3_512(value) for value in wide
    )
    assert len(instance.public_input_bytes) == 12 * 32
    direct = evaluate_program(
        instance.program, instance.traces, instance.public_input_bytes
    )
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(),
        instance.traces,
        instance.public_input_bytes,
    )
    assert direct == serialized
    assert direct.maximum_degree == 2


def test_v2_domain_and_nonce_are_only_compatibility_projections() -> None:
    wide = _wide_values()
    strong_domain = sha3_512(b"BL-STRONG-SETTLEMENT-DOMAIN").digest()
    strong_nonce = sha3_512(b"BL-STRONG-BATCH-NONCE").digest()
    instance = build_wide_public_executable_air_v2(
        2, strong_domain, strong_nonce, wide
    )
    assert instance.public_outputs == (
        2,
        compatibility_felt_from_sha3_512(strong_domain),
        compatibility_felt_from_sha3_512(strong_nonce),
        *(compatibility_felt_from_sha3_512(value) for value in wide),
    )
    assert instance.wide_values == (strong_domain, strong_nonce, *wide)
    report = evaluate_program(
        instance.program, instance.traces, instance.public_input_bytes
    )
    assert report.maximum_degree == 2
