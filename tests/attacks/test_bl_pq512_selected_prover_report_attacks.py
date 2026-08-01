from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    SelectedProofByteAttribution,
    SelectedProofResult,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


ATTRIBUTION = SelectedProofByteAttribution(
    header_bytes=10,
    initial_index_bytes=8,
    mask_opening_bytes=1,
    main_opening_bytes=1,
    interaction_opening_bytes=1,
    composition_opening_bytes=1,
    next_main_opening_bytes=1,
    next_interaction_opening_bytes=1,
    fri_layer_count_bytes=1,
    fri_opened_value_bytes=128,
    fri_log_size_bytes=1,
    fri_merkle_metadata_bytes=34,
    fri_path_digest_bytes=64,
    query_count=1,
    fri_layer_count=1,
    fri_opened_value_count=2,
    fri_path_digest_count=1,
)


def _report(**changes: int) -> str:
    values = {
        "grammar_version": 2,
        "proof_bytes": ATTRIBUTION.total_bytes,
        "attribution_total": ATTRIBUTION.total_bytes,
        "query_count": 1,
        "trace_masks": 1,
        "quotient_masks": 1,
        "folds": 1,
        "main_ms": 1,
        "interaction_ms": 1,
        "composition_ms": 1,
        "deep_ms": 1,
        "fri_start_ms": 1,
        "fold_compute_ms": 1,
        "openings_ms": 1,
        "verify_ms": 1,
        "worker_wall_ms": 2,
    }
    values.update(changes)
    return "OK " + " ".join(f"{name}={value}" for name, value in values.items())


def _result(attribution: SelectedProofByteAttribution, report: str) -> SelectedProofResult:
    return SelectedProofResult(  # type: ignore[arg-type]
        object(), object(), attribution.total_bytes, attribution, report
    )


def test_exact_attribution_and_worker_report_are_accepted() -> None:
    assert _result(ATTRIBUTION, _report()).proof_bytes == ATTRIBUTION.total_bytes


@pytest.mark.parametrize(
    "report",
    (
        _report(proof_bytes=999),
        _report(grammar_version=1),
        _report(attribution_total=999),
        _report(query_count=0),
        _report(folds=2),
        _report(main_ms=3),
        _report() + " extra=1",
        _report().replace(" proof_bytes=", " proof_bytes=1 proof_bytes="),
    ),
)
def test_forged_or_noncanonical_worker_report_is_rejected(report: str) -> None:
    with pytest.raises(StructuralError, match="worker_report"):
        _result(ATTRIBUTION, report)


def test_byte_partition_mismatch_is_rejected() -> None:
    forged = replace(ATTRIBUTION, fri_path_digest_bytes=65)
    with pytest.raises(StructuralError, match="worker_report"):
        SelectedProofResult(  # type: ignore[arg-type]
            object(), object(), ATTRIBUTION.total_bytes, forged, _report()
        )


@pytest.mark.parametrize(
    "fields",
    (
        ("header_bytes=1",),
        tuple(f"{name}=0" for name in ("header_bytes", "header_bytes")),
        tuple(),
    ),
)
def test_incomplete_or_duplicate_attribution_fields_are_rejected(
    fields: tuple[str, ...],
) -> None:
    with pytest.raises(StructuralError, match="report_field"):
        SelectedProofByteAttribution.from_worker_fields(fields)
