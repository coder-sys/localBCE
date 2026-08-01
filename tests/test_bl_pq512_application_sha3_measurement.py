from __future__ import annotations

from pathlib import Path

from app.batch.pq_nullifier_derivation import pepper_commitment_sha3_512
from experiments.bl_pq512_crypto_foundation.application_sha3_measurement import (
    ApplicationSha3Measurement,
    RECONCILED_ADDITION_WIDTHS,
    measure_reconciled_additions,
)


ROOT = Path(__file__).resolve().parents[1]


def test_measurement_resolves_exact_scoped_callsite_and_restores_module() -> None:
    pepper = bytes(range(64))
    with ApplicationSha3Measurement(ROOT) as measurement:
        digest = pepper_commitment_sha3_512(pepper)
        observations = measurement.observations()
    assert len(digest) == 64
    assert len(observations) == 1
    assert observations[0].callsite.stable_id == (
        "app/batch/pq_nullifier_derivation.py:pepper_commitment_sha3_512#0"
    )
    assert observations[0].preimage_bytes == 76
    assert observations[0].invocations == 1
    assert len(pepper_commitment_sha3_512(pepper)) == 64


def test_h0_additions_are_dynamically_measured_not_guessed() -> None:
    observations = measure_reconciled_additions(ROOT)
    assert {
        value.callsite.stable_id: value.preimage_bytes for value in observations
    } == RECONCILED_ADDITION_WIDTHS
    assert all(value.invocations == 1 for value in observations)
