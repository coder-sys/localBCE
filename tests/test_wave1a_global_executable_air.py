from __future__ import annotations

from functools import lru_cache
from types import SimpleNamespace

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    M31,
    StructuralError,
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.master_public_composition import (
    build_master_public_composition,
)
from experiments.fixed_shape_claim_air.wave1a_global_executable_air import (
    _global_links,
)
from tests.test_bl_pq512_master_commitments_v2 import _inputs


def _trace(name: str, columns) -> TraceTable:
    return TraceTable(name, freeze_columns(columns))


def _wide_columns(prefix: str, rows: tuple[bytes, ...]):
    return {
        f"{prefix}{byte}": tuple(value[byte] for value in rows)
        for byte in range(64)
    }


@lru_cache(maxsize=1)
def _boundary_fixture():
    master_public = build_master_public_composition(_inputs())
    value = master_public.master.inputs
    slot = master_public.traces["master_commitment_slot"]
    rows = len(value.slots)
    is_attempt = (1, 1, *(0 for _ in range(rows - 2)))

    traces = {
        "claim_source_hash_root": _trace(
            "claim_source_hash_root",
            _wide_columns("value_", (value.claim_truth_roots_512[0],)),
        ),
        "oracle_execution_root": _trace(
            "oracle_execution_root",
            {
                **_wide_columns("execution_", (value.claim_truth_roots_512[1],)),
                **_wide_columns("audit_", (value.claim_truth_roots_512[2],)),
            },
        ),
        "policy_execution_root": _trace(
            "policy_execution_root",
            {
                **_wide_columns("execution_", (value.claim_truth_roots_512[3],)),
                **_wide_columns("audit_", (value.claim_truth_roots_512[4],)),
            },
        ),
        "ruleset_commitment": _trace(
            "ruleset_commitment",
            _wide_columns("root_", (value.claim_truth_roots_512[5],)),
        ),
        "claim_truth_authority_material": _trace(
            "claim_truth_authority_material",
            _wide_columns("digest_", (value.claim_truth_authority_digest_512,)),
        ),
        "a12_authority": _trace(
            "a12_authority",
            {
                **_wide_columns("authority_id_", (value.nullifier_authority_id_512,)),
                **_wide_columns("commitment_", (value.pepper_commitment_512,)),
            },
        ),
        "a12_request": _trace(
            "a12_request",
            {
                "is_attempt": is_attempt,
                **{
                    f"cover_domain_{byte}": tuple(
                        0 if attempt else value.strong_settlement_domain_id_512[byte]
                        for attempt in is_attempt
                    )
                    for byte in range(64)
                },
                **{
                    f"cover_batch_{byte}": tuple(
                        0 if attempt else value.strong_batch_nonce_512[byte]
                        for attempt in is_attempt
                    )
                    for byte in range(64)
                },
                **{
                    f"cover_epoch_{byte}": tuple(
                        0 if attempt else value.epoch.to_bytes(8, "big")[byte]
                        for attempt in is_attempt
                    )
                    for byte in range(8)
                },
            },
        ),
        "claim_payment_key_material": _trace(
            "claim_payment_key_material",
            {
                **_wide_columns(
                    "settlement_byte_",
                    tuple(value.strong_settlement_domain_id_512 for _ in range(rows)),
                ),
                **{
                    f"epoch_byte_{byte}": tuple(
                        value.epoch.to_bytes(8, "big")[byte] for _ in range(rows)
                    )
                    for byte in range(8)
                },
            },
        ),
        "claim_result": _trace(
            "claim_result",
            {
                "slot_index": tuple(range(rows)),
                "decision": slot.columns["encoded_2"],
                "failure_code": tuple(
                    256 * slot.columns["encoded_3"][row]
                    + slot.columns["encoded_4"][row]
                    for row in range(rows)
                ),
                "allowed_limb_0": tuple(
                    256 * slot.columns["encoded_7"][row]
                    + slot.columns["encoded_8"][row]
                    for row in range(rows)
                ),
                "allowed_limb_1": tuple(
                    256 * slot.columns["encoded_5"][row]
                    + slot.columns["encoded_6"][row]
                    for row in range(rows)
                ),
                "payment_limb_0": tuple(
                    256 * slot.columns["encoded_11"][row]
                    + slot.columns["encoded_12"][row]
                    for row in range(rows)
                ),
                "payment_limb_1": tuple(
                    256 * slot.columns["encoded_9"][row]
                    + slot.columns["encoded_10"][row]
                    for row in range(rows)
                ),
                **{
                    f"raw_gate_{bit}": slot.columns[f"raw_gate_{bit}"]
                    for bit in range(13)
                },
                **{
                    f"effective_gate_{bit}": slot.columns[f"effective_gate_{bit}"]
                    for bit in range(13)
                },
            },
        ),
        "a12_output": _trace(
            "a12_output",
            {
                "request_index": tuple(range(rows)),
                **{
                    f"strong_{byte}": slot.columns[f"encoded_{17 + byte}"]
                    for byte in range(64)
                },
            },
        ),
        "salt_use_tag_material": _trace(
            "salt_use_tag_material",
            _wide_columns("tag_", (value.salt_use_tag_512,)),
        ),
        "replay_map__ordered_map_state": _trace(
            "replay_map__ordered_map_state",
            {
                **_wide_columns("root_before_", (value.replay_root_before_512,)),
                **_wide_columns("root_after_", (value.replay_root_after_512,)),
            },
        ),
        "payment_map_lane_state": _trace(
            "payment_map_lane_state",
            {
                **_wide_columns("root_before_", value.payment_lane_roots_before_512),
                **_wide_columns("root_after_", value.payment_lane_roots_after_512),
            },
        ),
        "claim_payment_map_slot": _trace(
            "claim_payment_map_slot",
            {
                **_wide_columns(
                    "operation_log_before_",
                    tuple(value.operation_log_root_before_512 for _ in range(rows)),
                ),
                **_wide_columns(
                    "operation_log_after_",
                    tuple(value.operation_log_root_after_512 for _ in range(rows)),
                ),
            },
        ),
    }
    a12 = SimpleNamespace(
        traces={"a12_request": traces["a12_request"]},
        operation_ids=tuple(f"slot-{index}" for index in range(rows)),
    )
    payment = SimpleNamespace(
        traces={"claim_payment_key_material": traces["claim_payment_key_material"]}
    )
    salt = SimpleNamespace()
    replay = SimpleNamespace()
    links = _global_links(
        SimpleNamespace(), a12, salt, replay, payment, master_public
    )
    all_traces = {**dict(master_public.traces), **traces}
    table_names = {
        side.table
        for lookup in links
        for side in (*lookup.sources, *lookup.destinations)
    }
    tables = tuple(
        AirTable(name, tuple(all_traces[name].columns), all_traces[name].rows, ())
        for name in sorted(table_names)
    )
    selected_traces = {name: all_traces[name] for name in table_names}
    return (
        AirProgram("BL-WAVE1A-GLOBAL-BOUNDARY-GATE-v1", tables, links),
        selected_traces,
        master_public.master.field_ids,
    )


def test_k128_every_global_master_boundary_matches_exactly() -> None:
    program, traces, _ = _boundary_fixture()
    report = evaluate_program(program, traces)
    assert len(program.lookups) == 12
    assert report.maximum_degree <= 1
    assert report.lookup_messages_evaluated == 55_776


def test_master_replay_root_tampering_fails_at_named_boundary() -> None:
    program, traces, field_ids = _boundary_fixture()
    material = traces["master_commitment_material_byte"]
    columns = {name: list(values) for name, values in material.columns.items()}
    replay_field_id = field_ids["replay_before"]
    row = next(
        index
        for index, field_id in enumerate(columns["field_id"])
        if field_id == replay_field_id
    )
    columns["value"][row] = (columns["value"][row] + 1) % M31
    bad = dict(traces)
    bad[material.name] = TraceTable(material.name, freeze_columns(columns))
    with pytest.raises(StructuralError, match="wave1a_master_replay_root_links"):
        evaluate_program(program, bad)
