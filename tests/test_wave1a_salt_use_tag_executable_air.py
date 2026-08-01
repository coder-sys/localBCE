from __future__ import annotations

from hashlib import sha3_512

from app.batch.pq_suite_candidate import candidate_salt_use_tag
from experiments.fixed_shape_claim_air.executable_air import evaluate_program
from experiments.fixed_shape_claim_air.salt_use_tag_executable_air import (
    build_salt_use_tag_executable_air,
)


def test_salt_use_tag_is_exact_hidden_sha3_call() -> None:
    raw = sha3_512(b"BL-WAVE1A-RAW-MASTER-SALT").digest()
    instance = build_salt_use_tag_executable_air(raw)
    assert instance.tag_512 == candidate_salt_use_tag(raw)
    assert instance.tag_constrained is True
    assert not hasattr(instance, "raw_master_salt_512")
    report = evaluate_program(instance.program, instance.traces)
    assert report.maximum_degree == 2
