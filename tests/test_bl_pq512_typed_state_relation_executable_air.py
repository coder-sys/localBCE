from __future__ import annotations

from dataclasses import replace
import os
from functools import lru_cache
from unittest import mock

import pytest

from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.executable_air import TraceTable
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.typed_state_relation_executable_air import (
    MONEY_TABLE,
    PROGRAM_ID,
    SUMMARY_TABLE,
    build_c0_typed_state_relation_air,
    verify_typed_state_relation_air,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@lru_cache(maxsize=1)
def _k128_instance():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        return build_c0_typed_state_relation_air(get_profile("K128_CALIBRATION"))


def _mutated_trace(instance, table_name: str, column: str, row: int):
    columns = dict(instance.traces[table_name].columns)
    values = list(columns[column])
    values[row] = (values[row] + 1) % (1 << 31)
    columns[column] = tuple(values)
    traces = dict(instance.traces)
    traces[table_name] = TraceTable(table_name, columns)
    return replace(instance, traces=traces)


def test_typed_state_air_replays_c0_maps_money_and_h4_hash_ports() -> None:
    instance = _k128_instance()
    verify_typed_state_relation_air(instance)

    assert instance.program.program_id == PROGRAM_ID
    assert SUMMARY_TABLE in instance.traces
    assert MONEY_TABLE in instance.traces
    assert "typed_state_lane_root_cursor_links" in {
        lookup.name for lookup in instance.program.lookups
    }
    assert "typed_state_money_byte_range" in {
        lookup.name for lookup in instance.program.lookups
    }
    assert instance.payment.key_derivation_ports_constrained is True
    assert instance.payment.operation_log_ports_constrained is True
    assert instance.payment.payment_map_hash_ports_constrained is True
    assert instance.public_values[-4:] == (100, 80, 80, 80)
    assert len(instance.hash_calls) == 46_208


def test_typed_state_air_binds_replay_roots_and_cursors() -> None:
    with pytest.raises(StructuralError, match="lookup|multiset"):
        verify_typed_state_relation_air(
            _mutated_trace(_k128_instance(), "ordered_map_state", "root_after_0", 0)
        )


def test_typed_state_air_rejects_money_mutation() -> None:
    with pytest.raises(StructuralError, match="identity|lookup|multiset"):
        verify_typed_state_relation_air(
            _mutated_trace(_k128_instance(), MONEY_TABLE, "payment_value", 0)
        )


def test_typed_state_air_rejects_replay_hash_port_mutation() -> None:
    with pytest.raises(StructuralError, match="lookup|multiset"):
        verify_typed_state_relation_air(
            _mutated_trace(_k128_instance(), "ordered_map_hash_port", "message_0", 0)
        )
