from __future__ import annotations

import os
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.measurement import (
    MEASUREMENT_STATUS,
    SHAPES,
    measure_model,
)
from experiments.fixed_shape_claim_air.profile import get_profile


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_R25_PAYMENT_STATE_REFERENCE": "1",
}


@pytest.mark.parametrize("shape", SHAPES)
def test_k128_model_measurement_is_honest_and_percentages_reconcile(shape: str) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        measurement = measure_model(get_profile("K128_CALIBRATION"), shape)
    assert measurement.status == MEASUREMENT_STATUS
    assert measurement.proofs_generated == 0
    assert measurement.proof_suite_id is None
    assert measurement.activation_allowed is False
    assert measurement.physical_air_rows is None
    assert measurement.physical_air_columns is None
    assert measurement.total_seconds > 0
    assert measurement.python_tracemalloc_peak_bytes > 0
    assert sum(measurement.phase_percent.values()) == pytest.approx(100.0)
    assert sum(measurement.phase_seconds.values()) == pytest.approx(
        measurement.total_seconds
    )
