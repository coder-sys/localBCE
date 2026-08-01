from __future__ import annotations

import os
from dataclasses import replace
from fractions import Fraction

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    InterfaceTableDimensions,
    InterfaceTheoremEnvelope,
    UniqueDecodingCandidate,
    build_candidate_sweep,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def _envelope() -> InterfaceTheoremEnvelope:
    program = build_wave1a_physical_air_program(PROFILES["K512_CALIBRATION"])
    return InterfaceTheoremEnvelope(
        profile_id=program.profile_id,
        tables=tuple(
            InterfaceTableDimensions(
                table.name,
                table.padded_rows,
                table.trace_columns,
                table.constraint_count,
                table.maximum_degree,
                table.lookup_message_width,
            )
            for table in program.tables
        ),
        commitment_group_count=program.commitment_count,
    )


def test_boundary_equality_cannot_be_relabelled_unique_decoding() -> None:
    candidate = build_candidate_sweep(_envelope(), (2,))[0]
    with pytest.raises(ValueError, match="outside_unique_decoding_regime"):
        replace(candidate, theta=candidate.relative_distance / 2)


def test_final_expansion_and_activation_flags_cannot_be_forged() -> None:
    envelope = _envelope()
    with pytest.raises(ValueError, match="cannot_claim_final_expansion"):
        replace(envelope, final_expansion_substituted=True)
    with pytest.raises(ValueError, match="cannot_activate"):
        replace(envelope, activation_allowed=True)


def test_candidate_cannot_be_forged_as_selected_or_final() -> None:
    candidate = build_candidate_sweep(_envelope(), (1,))[0]
    with pytest.raises(ValueError, match="cannot_be_selected"):
        replace(candidate, selected=True)
    with pytest.raises(ValueError, match="cannot_be_selected"):
        replace(candidate, final_expansion_substituted=True)


def test_out_of_regime_candidate_is_detectable() -> None:
    candidate = build_candidate_sweep(_envelope(), (1,))[0]
    with pytest.raises(ValueError, match="outside_unique_decoding_regime"):
        UniqueDecodingCandidate(
            log_blowup=candidate.log_blowup,
            theta=Fraction(1, 2),
            query_count=candidate.query_count,
            evaluation_domain_size=candidate.evaluation_domain_size,
            terminal_domain_size=candidate.terminal_domain_size,
            interface_error_terms=candidate.interface_error_terms,
        )
