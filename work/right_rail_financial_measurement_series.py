"""Bounded synthetic measurement series for the existing RightRail financial owner.

This is a task-local runner, not a second owner or a benchmark framework.  It exercises the
existing owner APIs with fresh SQLite databases, keeps each sample's database for readback, and
prints canonical JSON lines for guarded evidence.  Parent/child resource totals come from the
existing guarded wrapper; this process does not invent native or queue measurements.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import statistics
import sys
import threading
import time
from typing import Any, Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import app.right_rail_financial_owner as owner_module
from app.right_rail_financial_owner import (
    ControlPack,
    FinancialOwner,
    FinancialOwnerConfig,
    PopulationItem,
    SyntheticTrustedAuthority,
)


SERIES_SCHEMA = "RR/FINANCIAL/MEASUREMENT-SERIES/v1"
MEASUREMENT_CHUNK_SIZE = 5
MAX_MEASUREMENT_SIZES = 3
MAX_MEASUREMENT_SAMPLES = 5
MAX_MEASUREMENT_ITEMS = 100
DEFAULT_SIZES = (5, 10, 20)
DEFAULT_SAMPLES = 3
MEASUREMENT_DUE_AT_MS = 4_102_444_800_000  # 2100-01-01T00:00:00Z
MEASUREMENT_PACK_END_MS = 4_102_531_200_000
LOCK_PROBE_HOLD_MS = 8


class _MeasuredFinancialOwner(FinancialOwner):
    """Harness-only owner subclass that observes the existing owner write lock."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._actual_lock_records: list[dict[str, float]] = []
        self._actual_lock_acquisition_failures = 0
        super().__init__(*args, **kwargs)

    @contextmanager
    def _write(self):
        wait_started_ns = time.perf_counter_ns()
        acquired_ns: int | None = None
        try:
            with super()._write() as connection:
                acquired_ns = time.perf_counter_ns()
                yield connection
        except BaseException:
            if acquired_ns is None:
                self._actual_lock_acquisition_failures += 1
            raise
        finally:
            if acquired_ns is not None:
                released_ns = time.perf_counter_ns()
                self._actual_lock_records.append(
                    {
                        "wait_to_acquire_ms": ((acquired_ns - wait_started_ns) / 1_000_000),
                        "transaction_held_ms": ((released_ns - acquired_ns) / 1_000_000),
                    }
                )


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _elapsed_ms(start_ns: int, end_ns: int | None = None) -> float:
    return round(((end_ns or time.perf_counter_ns()) - start_ns) / 1_000_000, 3)


def _parse_sizes(value: str) -> tuple[int, ...]:
    try:
        sizes = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError:
        raise ValueError("measurement_sizes") from None
    if not sizes or len(sizes) > MAX_MEASUREMENT_SIZES:
        raise ValueError("measurement_size_count")
    if any(size < 1 or size > MAX_MEASUREMENT_ITEMS for size in sizes):
        raise ValueError("measurement_size_limit")
    if tuple(sorted(set(sizes))) != sizes:
        raise ValueError("measurement_sizes_not_strictly_increasing")
    return sizes


def _parse_samples(value: str) -> int:
    try:
        samples = int(value)
    except ValueError:
        raise ValueError("measurement_sample_count") from None
    if not 1 <= samples <= MAX_MEASUREMENT_SAMPLES:
        raise ValueError("measurement_sample_limit")
    return samples


def _storage_bytes(path: Path) -> int:
    total = path.stat().st_size if path.is_file() else 0
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.is_file():
            total += sidecar.stat().st_size
    return total


def _source_hashes() -> dict[str, str]:
    paths = {
        "owner": REPOSITORY_ROOT / "app" / "right_rail_financial_owner.py",
        "independent_checker": REPOSITORY_ROOT / "app" / "right_rail_financial_owner_independent.py",
    }
    return {
        name: hashlib.sha256(path.read_bytes()).hexdigest().upper()
        for name, path in paths.items()
    }


def _pack(*, state_id: str, deployment_id: str, program_id: str, period_id: str, pack_id: str) -> ControlPack:
    return ControlPack(
        pack_id=pack_id,
        state_id=state_id,
        deployment_id=deployment_id,
        program_id=program_id,
        period_id=period_id,
        version=1,
        source_refs=("measurement:synthetic:control-pack",),
        effective_start_ms=1,
        effective_end_ms=MEASUREMENT_PACK_END_MS,
        recorded_at_ms=1,
        approved_at_ms=2,
        calculation_rule_id="calculation:per-recipient:v1",
        adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=(
            "program-total=100000000",
            "H-owed=10000000",
            "other-total=90000000",
            "timeliness-separate",
        ),
    )


def _items(population_id: str, size: int) -> tuple[PopulationItem, ...]:
    return tuple(
        PopulationItem(
            population_id=population_id,
            item_id=f"measurement-item-{index:04d}",
            display_label=f"Synthetic measurement item {index:04d}",
            owed_cents=1_000_000,
            due_at_ms=MEASUREMENT_DUE_AT_MS,
        )
        for index in range(size)
    )


def _metric_summary(values: Iterable[float]) -> dict[str, float | int]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("empty_measurement_values")
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "sample_count": len(ordered),
        "min_ms": round(ordered[0], 3),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "max_ms": round(ordered[-1], 3),
    }


def _actual_lock_summary(owners: Iterable[_MeasuredFinancialOwner]) -> dict[str, Any]:
    records: list[dict[str, float]] = []
    acquisition_failures = 0
    for measured_owner in owners:
        records.extend(measured_owner._actual_lock_records)
        acquisition_failures += measured_owner._actual_lock_acquisition_failures
    if not records:
        raise RuntimeError("actual_lock_measurement_empty")
    return {
        "transaction_count": len(records),
        "successful_acquisitions": len(records),
        "acquisition_failures": acquisition_failures,
        "wait_to_acquire_ms": _metric_summary(record["wait_to_acquire_ms"] for record in records),
        "transaction_held_ms": _metric_summary(record["transaction_held_ms"] for record in records),
    }


def _rate(count: int, elapsed_ms: float) -> float:
    if elapsed_ms <= 0:
        raise ValueError("nonpositive_elapsed")
    return round(count / (elapsed_ms / 1_000), 3)


def _lock_probe(database: Path) -> dict[str, Any]:
    """Measure one real SQLite BEGIN IMMEDIATE wait against one held transaction."""

    holder = sqlite3.connect(str(database), timeout=5.0, isolation_level=None)
    holder.execute("PRAGMA busy_timeout=5000")
    waiter_started = threading.Event()
    waiter_result: dict[str, Any] = {}
    waiter_errors: list[BaseException] = []
    holder_started_ns = time.perf_counter_ns()
    try:
        holder.execute("BEGIN IMMEDIATE")
        holder_started_ns = time.perf_counter_ns()

        def waiter() -> None:
            connection = sqlite3.connect(str(database), timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA busy_timeout=5000")
            try:
                waiter_started.set()
                wait_started_ns = time.perf_counter_ns()
                connection.execute("BEGIN IMMEDIATE")
                acquired_ns = time.perf_counter_ns()
                row = connection.execute("SELECT COUNT(*) FROM financial_events").fetchone()
                connection.execute("ROLLBACK")
                waiter_result.update(
                    {
                        "wait_to_acquire_ms": _elapsed_ms(wait_started_ns, acquired_ns),
                        "event_count_seen": int(row[0]),
                        "acquired": True,
                    }
                )
            except BaseException as error:
                waiter_errors.append(error)
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()

        thread = threading.Thread(target=waiter, name="financial-lock-probe-waiter")
        thread.start()
        if not waiter_started.wait(timeout=5.0):
            raise RuntimeError("lock_probe_waiter_start")
        time.sleep(LOCK_PROBE_HOLD_MS / 1_000)
        holder.execute("SELECT COUNT(*) FROM financial_events").fetchone()
        holder.execute("ROLLBACK")
        holder_finished_ns = time.perf_counter_ns()
        thread.join(timeout=5.0)
        if thread.is_alive():
            raise RuntimeError("lock_probe_waiter_join")
        if waiter_errors:
            raise RuntimeError("lock_probe_waiter_failed") from waiter_errors[0]
        if waiter_result.get("acquired") is not True:
            raise RuntimeError("lock_probe_not_acquired")
        return {
            "transaction_held_ms": _elapsed_ms(holder_started_ns, holder_finished_ns),
            "wait_to_acquire_ms": float(waiter_result["wait_to_acquire_ms"]),
            "holder_statements": 1,
            "waiter_attempts": 1,
            "successful_acquisitions": 1,
            "contention_requested": True,
            "hold_target_ms": LOCK_PROBE_HOLD_MS,
            "event_count_seen": int(waiter_result["event_count_seen"]),
        }
    finally:
        if holder.in_transaction:
            holder.execute("ROLLBACK")
        holder.close()


def _assert_v5_evaluation_receipt(
    receipt: dict[str, Any],
    *,
    item: PopulationItem,
    config: FinancialOwnerConfig,
    pack: ControlPack,
    authority: SyntheticTrustedAuthority,
) -> None:
    if not isinstance(receipt, dict):
        raise RuntimeError("evaluation_receipt_type")
    required = {
        "contract_version",
        "scope",
        "evaluation_id",
        "obligation_id",
        "revision",
        "control_pack",
        "evidence_bindings",
        "authority",
        "evidence_ids",
        "evaluated_at_ms",
        "input_snapshot_digest",
        "result_digest",
        "evaluation_result_digest",
    }
    if not required <= set(receipt):
        raise RuntimeError("evaluation_receipt_shape")
    if receipt["contract_version"] != owner_module._EVALUATION_RECEIPT_CONTRACT:
        raise RuntimeError("evaluation_receipt_contract")
    if type(receipt["evaluation_id"]) is not str or type(receipt["obligation_id"]) is not str:
        raise RuntimeError("evaluation_receipt_identity")
    if type(receipt["revision"]) is not int or receipt["revision"] < 0:
        raise RuntimeError("evaluation_receipt_revision")
    if type(receipt["evaluated_at_ms"]) is not int or receipt["evaluated_at_ms"] < 0:
        raise RuntimeError("evaluation_receipt_time")
    expected_scope = {
        "state_id": config.state_id,
        "deployment_id": config.deployment_id,
        "program_id": config.program_id,
        "period_id": config.period_id,
        "currency": config.currency,
    }
    if receipt["scope"] != expected_scope:
        raise RuntimeError("evaluation_receipt_scope")
    control_pack = receipt["control_pack"]
    if control_pack != {
        "pack_id": pack.pack_id,
        "version": pack.version,
        "digest": pack.digest.hex().upper(),
    }:
        raise RuntimeError("evaluation_receipt_control_pack")
    receipt_authority = receipt["authority"]
    if receipt_authority != {
        "authority_id": authority.authority_id,
        "epoch": authority.epoch,
        "digest": authority.digest.hex().upper(),
    }:
        raise RuntimeError("evaluation_receipt_authority")
    evidence_ids = receipt["evidence_ids"]
    bindings = receipt["evidence_bindings"]
    if not isinstance(evidence_ids, list) or not isinstance(bindings, list):
        raise RuntimeError("evaluation_receipt_evidence_shape")
    if evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
        raise RuntimeError("evaluation_receipt_evidence_order")
    if [binding.get("evidence_id") for binding in bindings] != evidence_ids:
        raise RuntimeError("evaluation_receipt_evidence_binding")
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"evidence_id", "record_digest"}:
            raise RuntimeError("evaluation_receipt_evidence_binding")
        if type(binding["evidence_id"]) is not str or type(binding["record_digest"]) is not str:
            raise RuntimeError("evaluation_receipt_evidence_binding")
    if receipt["evaluation_result_digest"] != receipt["result_digest"]:
        raise RuntimeError("evaluation_receipt_result_digest")
    input_snapshot_digest = receipt["input_snapshot_digest"]
    if (
        type(input_snapshot_digest) is not str
        or len(input_snapshot_digest) != 128
        or any(character not in "0123456789ABCDEFabcdef" for character in input_snapshot_digest)
    ):
        raise RuntimeError("evaluation_receipt_input_snapshot_digest")
    if "raw_evidence" in receipt or "signatures" in receipt:
        raise RuntimeError("evaluation_receipt_raw_payload")
    if not item.item_id or receipt["obligation_id"] == "":
        raise RuntimeError("evaluation_receipt_item")


def _evaluate_with_v5_reference(
    owner: FinancialOwner,
    *,
    item: PopulationItem,
    config: FinancialOwnerConfig,
    pack: ControlPack,
    authority: SyntheticTrustedAuthority,
) -> dict[str, Any]:
    original = owner.current_evaluation_receipt(item.item_id)
    _assert_v5_evaluation_receipt(original, item=item, config=config, pack=pack, authority=authority)
    if owner.current_evaluation_receipt(item.item_id) != original:
        raise RuntimeError("evaluation_receipt_read_retry_changed")
    evaluated = owner.evaluate_obligation(item.item_id, expected_revision=int(original["revision"]))
    returned = evaluated.get("evaluation_receipt")
    if not isinstance(returned, dict):
        raise RuntimeError("evaluation_receipt_missing_from_evaluate")
    _assert_v5_evaluation_receipt(returned, item=item, config=config, pack=pack, authority=authority)
    if returned["evaluation_id"] != evaluated.get("current_evaluation_id"):
        raise RuntimeError("evaluation_receipt_projection_binding")
    if int(returned["revision"]) != int(original["revision"]) + 1:
        raise RuntimeError("evaluation_receipt_pre_revision")
    if owner.current_evaluation_receipt(item.item_id) != returned:
        raise RuntimeError("evaluation_receipt_current_binding")
    return {
        "item_id": item.item_id,
        "original_evaluation_id": original["evaluation_id"],
        "original_pre_revision": int(original["revision"]),
        "original_evaluation_result_digest": original["evaluation_result_digest"],
        "original_input_snapshot_digest": original["input_snapshot_digest"],
        "returned_evaluation_id": returned["evaluation_id"],
        "returned_revision": int(returned["revision"]),
        "returned_evaluation_result_digest": returned["evaluation_result_digest"],
        "returned_input_snapshot_digest": returned["input_snapshot_digest"],
        "read_retry_identity_stable": True,
    }


def _limits() -> dict[str, Any]:
    return {
        "source": "app/right_rail_financial_owner.py",
        "owner_schema": owner_module._SCHEMA,
        "continuity_schema": owner_module._CONTINUITY_SCHEMA,
        "evaluation_receipt_contract": owner_module._EVALUATION_RECEIPT_CONTRACT,
        "source_hashes": _source_hashes(),
        "max_cents": owner_module._MAX_CENTS,
        "max_rows": owner_module._MAX_ROWS,
        "max_continuity_package_bytes": owner_module._MAX_PACKAGE_BYTES,
        "population_chunk_size_min": 1,
        "population_chunk_size_max": 1_000,
        "obligation_page_max": 100,
        "detail_page_max": 200,
        "history_page_max": 200,
        "page_offset_max": owner_module._MAX_ROWS,
        "sqlite_timeout_ms": 5_000,
        "sqlite_busy_timeout_ms": 5_000,
        "lock_probe_hold_ms": LOCK_PROBE_HOLD_MS,
        "measurement_caps": {
            "max_sizes": MAX_MEASUREMENT_SIZES,
            "max_samples_per_size": MAX_MEASUREMENT_SAMPLES,
            "max_items_per_sample": MAX_MEASUREMENT_ITEMS,
            "chunk_size": MEASUREMENT_CHUNK_SIZE,
        },
    }


def _sample(root: Path, *, size: int, sample: int) -> dict[str, Any]:
    sample_root = root / f"size-{size:04d}" / f"sample-{sample:02d}"
    sample_root.mkdir(parents=True, exist_ok=False)
    database = sample_root / "owner.sqlite"
    state_id = "measurement-state"
    deployment_id = "measurement-deployment"
    program_id = "measurement-program"
    period_id = f"measurement-period-{size:04d}"
    population_id = f"measurement-population-{size:04d}-{sample:02d}"
    config = FinancialOwnerConfig(
        state_id=state_id,
        deployment_id=deployment_id,
        program_id=program_id,
        period_id=period_id,
        currency="USD",
    )
    authority = SyntheticTrustedAuthority()
    total_start = time.perf_counter_ns()
    owner = _MeasuredFinancialOwner(path=database, config=config, trusted_authority=authority)
    pack = _pack(
        state_id=state_id,
        deployment_id=deployment_id,
        program_id=program_id,
        period_id=period_id,
        pack_id=f"measurement-pack-{size:04d}-{sample:02d}",
    )
    owner.publish_control_pack(pack)
    items = _items(population_id, size)

    build_start = time.perf_counter_ns()
    owner.stage_population(
        population_id=population_id,
        pack_id=pack.pack_id,
        cutoff_ms=pack.effective_start_ms,
        inclusion_rules=("included:synthetic-measurement",),
        expected_count=size,
        items=items,
        chunk_size=MEASUREMENT_CHUNK_SIZE,
    )
    owner.validate_population(population_id)
    owner.publish_population(population_id)
    build_ms = _elapsed_ms(build_start)
    storage_after_build = _storage_bytes(database)

    update_start = time.perf_counter_ns()
    statuses: list[str] = []
    for index, item in enumerate(items):
        result = owner.record_support_evidence(
            item_id=item.item_id,
            evidence_id=f"measurement-evidence-{size:04d}-{sample:02d}-{index:04d}",
            common_origin_id=f"measurement-origin-{size:04d}-{sample:02d}-{index:04d}",
            source_id="synthetic-measurement-source",
            source_version="measurement-v1",
            local_ref=f"measurement:record:{size}:{sample}:{index}",
            applicable_at_ms=3,
            event_at_ms=3,
            received_at_ms=4,
        )
        statuses.append(str(result["status"]))
    update_ms = _elapsed_ms(update_start)
    if statuses != ["RECORDED"] * size:
        raise RuntimeError("measurement_update_status")
    storage_after_updates = _storage_bytes(database)

    evaluation_start = time.perf_counter_ns()
    evaluation_references = [
        _evaluate_with_v5_reference(
            owner,
            item=item,
            config=config,
            pack=pack,
            authority=authority,
        )
        for item in items
    ]
    evaluation_ms = _elapsed_ms(evaluation_start)
    final_receipts = {
        item.item_id: owner.current_evaluation_receipt(item.item_id)
        for item in items
    }
    for item in items:
        _assert_v5_evaluation_receipt(final_receipts[item.item_id], item=item, config=config, pack=pack, authority=authority)
        reference = next(value for value in evaluation_references if value["item_id"] == item.item_id)
        if final_receipts[item.item_id]["evaluation_id"] != reference["returned_evaluation_id"]:
            raise RuntimeError("evaluation_receipt_final_identity")

    lock_timing = _lock_probe(database)

    continuity_start = time.perf_counter_ns()
    package = owner.export_continuity()
    package_result = FinancialOwner.validate_continuity_package(package)
    continuity_ms = _elapsed_ms(continuity_start)

    verify_start = time.perf_counter_ns()
    verify_result = owner.verify_integrity()
    verify_ms = _elapsed_ms(verify_start)

    source_bytes_before_restore = database.read_bytes()
    test_database = sample_root / "test-continuation.sqlite"
    test_restore_start = time.perf_counter_ns()
    test_owner = _MeasuredFinancialOwner.restore_continuity(
        package_bytes=package,
        recovered_path=test_database,
        trusted_authority=authority,
        restore_mode="TEST",
    )
    test_owner.verify_integrity()
    test_restore_receipt_matches = sum(
        test_owner.current_evaluation_receipt(item.item_id) == final_receipts[item.item_id]
        for item in items
    )
    if test_restore_receipt_matches != size:
        raise RuntimeError("test_restore_evaluation_reference_changed")
    test_restore_ms = _elapsed_ms(test_restore_start)
    test_owner.close()
    test_restart_start = time.perf_counter_ns()
    reopened_test = _MeasuredFinancialOwner(
        path=test_database,
        config=config,
        trusted_authority=authority,
        mode="TEST",
        owner_id=owner_module._TEST_OWNER_ID,
    )
    test_restart_summary = reopened_test.summary()
    reopened_test.verify_integrity()
    test_restart_receipt_matches = sum(
        reopened_test.current_evaluation_receipt(item.item_id) == final_receipts[item.item_id]
        for item in items
    )
    if test_restart_receipt_matches != size:
        raise RuntimeError("test_restart_evaluation_reference_changed")
    test_restart_ms = _elapsed_ms(test_restart_start)
    reopened_test.close()
    source_bytes_unchanged = database.read_bytes() == source_bytes_before_restore
    if not source_bytes_unchanged:
        raise RuntimeError("test_restore_source_changed")

    owner.close()
    restart_start = time.perf_counter_ns()
    reopened = _MeasuredFinancialOwner(path=database, config=config, trusted_authority=authority)
    restart_summary = reopened.summary()
    reopened.verify_integrity()
    owner_restart_receipt_matches = sum(
        reopened.current_evaluation_receipt(item.item_id) == final_receipts[item.item_id]
        for item in items
    )
    if owner_restart_receipt_matches != size:
        raise RuntimeError("owner_restart_evaluation_reference_changed")
    restart_ms = _elapsed_ms(restart_start)
    reopened.close()

    final_storage_bytes = _storage_bytes(database)
    total_ms = _elapsed_ms(total_start)
    table_counts = {str(table): len(rows) for table, rows in package_result["tables"].items()}
    actual_lock = _actual_lock_summary((owner, test_owner))
    return {
        "schema": SERIES_SCHEMA,
        "size": size,
        "sample": sample,
        "warmup": False,
        "database": str(database),
        "population_items": size,
        "support_records": len(statuses),
        "history_event_count": table_counts.get("financial_events", 0),
        "continuity_table_count": len(table_counts),
        "continuity_package_bytes": len(package),
        "continuity_package_table_counts": table_counts,
        "latency_ms": {
            "population_build": build_ms,
            "financial_updates": update_ms,
            "financial_evaluations": evaluation_ms,
            "continuity_export_validate": continuity_ms,
            "independent_verify": verify_ms,
            "test_restore_verify": test_restore_ms,
            "test_restart_reopen_verify": test_restart_ms,
            "restart_reopen_verify": restart_ms,
            "total": total_ms,
        },
        "lock_timing_ms": {
            "wait_to_acquire": actual_lock["wait_to_acquire_ms"],
            "transaction_held": actual_lock["transaction_held_ms"],
        },
        "lock_workload": {
            "owner_transactions": len(owner._actual_lock_records),
            "test_continuation_transactions": len(test_owner._actual_lock_records),
            "transaction_count": actual_lock["transaction_count"],
            "successful_acquisitions": actual_lock["successful_acquisitions"],
            "acquisition_failures": actual_lock["acquisition_failures"],
            "workload": "FinancialOwner._write actual operations",
        },
        "synthetic_lock_probe": {
            "transaction_held_ms": lock_timing["transaction_held_ms"],
            "wait_to_acquire_ms": lock_timing["wait_to_acquire_ms"],
            "holder_statements": lock_timing["holder_statements"],
            "waiter_attempts": lock_timing["waiter_attempts"],
            "successful_acquisitions": lock_timing["successful_acquisitions"],
            "contention_requested": lock_timing["contention_requested"],
            "hold_target_ms": lock_timing["hold_target_ms"],
            "event_count_seen": lock_timing["event_count_seen"],
        },
        "test_restore": {
            "mode": "TEST",
            "owner_id": owner_module._TEST_OWNER_ID,
            "status": "VERIFIED",
            "restart_status": "VERIFIED",
            "obligation_count": test_restart_summary["obligation_count"],
            "sequence": test_restart_summary["sequence"],
            "dispatch_enabled": test_restart_summary["dispatch_enabled"],
            "egress_enabled": test_restart_summary["egress_enabled"],
            "source_bytes_unchanged": source_bytes_unchanged,
            "evaluation_reference_matches": test_restore_receipt_matches,
            "restart_evaluation_reference_matches": test_restart_receipt_matches,
            "database": str(test_database),
        },
        "evaluation_reference": {
            "contract_version": owner_module._EVALUATION_RECEIPT_CONTRACT,
            "owner_schema": owner_module._SCHEMA,
            "item_count": size,
            "producer_call_count": len(evaluation_references),
            "original_pre_revision_min": min(value["original_pre_revision"] for value in evaluation_references),
            "original_pre_revision_max": max(value["original_pre_revision"] for value in evaluation_references),
            "returned_revision_min": min(value["returned_revision"] for value in evaluation_references),
            "returned_revision_max": max(value["returned_revision"] for value in evaluation_references),
            "read_retry_identity_stable_count": sum(value["read_retry_identity_stable"] for value in evaluation_references),
            "test_restore_reference_match_count": test_restore_receipt_matches,
            "test_restart_reference_match_count": test_restart_receipt_matches,
            "owner_restart_reference_match_count": owner_restart_receipt_matches,
            "reference_samples": [evaluation_references[0], evaluation_references[-1]],
        },
        "rates_per_second": {
            "population_items": _rate(size, build_ms),
            "financial_updates": _rate(len(statuses), update_ms),
            "financial_evaluations": _rate(len(evaluation_references), evaluation_ms),
        },
        "storage_bytes": {
            "after_build": storage_after_build,
            "after_updates": storage_after_updates,
            "final": final_storage_bytes,
            "growth": final_storage_bytes,
        },
        "restart": {
            "status": "VERIFIED",
            "obligation_count": restart_summary["obligation_count"],
            "sequence": restart_summary["sequence"],
            "dispatch_enabled": restart_summary["dispatch_enabled"],
            "egress_enabled": restart_summary["egress_enabled"],
        },
        "integrity": {
            "status": "VERIFIED",
            "schema": verify_result.get("schema"),
        },
        "native_batch_metrics": {"status": "PENDING_NATIVE_REGRESSION", "batches_per_second": None},
        "queue_wait_age_metrics": {"status": "NOT_APPLICABLE_TO_FINANCIAL_OWNER_SLICE", "wait_ms": None, "age_ms": None},
        "resource_measurement": {"status": "OUTER_GUARD_REQUIRED", "parent_child_memory": None},
    }


def _aggregate(size: int, samples: list[dict[str, Any]]) -> dict[str, Any]:
    latency_fields = (
        "population_build",
        "financial_updates",
        "financial_evaluations",
        "continuity_export_validate",
        "independent_verify",
        "test_restore_verify",
        "test_restart_reopen_verify",
        "restart_reopen_verify",
        "total",
    )
    return {
        "schema": SERIES_SCHEMA,
        "owner_schema": owner_module._SCHEMA,
        "continuity_schema": owner_module._CONTINUITY_SCHEMA,
        "evaluation_receipt_contract": owner_module._EVALUATION_RECEIPT_CONTRACT,
        "size": size,
        "sample_count": len(samples),
        "population_items": size,
        "latency_ms": {field: _metric_summary(sample["latency_ms"][field] for sample in samples) for field in latency_fields},
        "lock_timing_ms": {
            "aggregation": "median_of_per_sample_medians",
            "sample_count": len(samples),
            "wait_to_acquire": _metric_summary(sample["lock_timing_ms"]["wait_to_acquire"]["median_ms"] for sample in samples),
            "transaction_held": _metric_summary(sample["lock_timing_ms"]["transaction_held"]["median_ms"] for sample in samples),
        },
        "lock_workload": {
            "aggregation": "sum_of_per_sample_counts",
            "sample_count": len(samples),
            "owner_transactions": sum(sample["lock_workload"]["owner_transactions"] for sample in samples),
            "test_continuation_transactions": sum(sample["lock_workload"]["test_continuation_transactions"] for sample in samples),
            "transaction_count": sum(sample["lock_workload"]["transaction_count"] for sample in samples),
            "successful_acquisitions": sum(sample["lock_workload"]["successful_acquisitions"] for sample in samples),
            "acquisition_failures": sum(sample["lock_workload"]["acquisition_failures"] for sample in samples),
            "all_source_bytes_unchanged": all(sample["test_restore"]["source_bytes_unchanged"] for sample in samples),
        },
        "evaluation_reference": {
            "aggregation": "sum_of_per_sample_counts_and_all_identity_checks",
            "sample_count": len(samples),
            "producer_call_count": sum(sample["evaluation_reference"]["producer_call_count"] for sample in samples),
            "original_pre_revision_min": min(sample["evaluation_reference"]["original_pre_revision_min"] for sample in samples),
            "original_pre_revision_max": max(sample["evaluation_reference"]["original_pre_revision_max"] for sample in samples),
            "returned_revision_min": min(sample["evaluation_reference"]["returned_revision_min"] for sample in samples),
            "returned_revision_max": max(sample["evaluation_reference"]["returned_revision_max"] for sample in samples),
            "read_retry_identity_stable_count": sum(sample["evaluation_reference"]["read_retry_identity_stable_count"] for sample in samples),
            "test_restore_reference_match_count": sum(sample["evaluation_reference"]["test_restore_reference_match_count"] for sample in samples),
            "test_restart_reference_match_count": sum(sample["evaluation_reference"]["test_restart_reference_match_count"] for sample in samples),
            "owner_restart_reference_match_count": sum(sample["evaluation_reference"]["owner_restart_reference_match_count"] for sample in samples),
            "all_reference_checks_passed": all(
                sample["evaluation_reference"]["read_retry_identity_stable_count"] == size
                and sample["evaluation_reference"]["test_restore_reference_match_count"] == size
                and sample["evaluation_reference"]["test_restart_reference_match_count"] == size
                and sample["evaluation_reference"]["owner_restart_reference_match_count"] == size
                for sample in samples
            ),
        },
        "synthetic_lock_probe": {
            "sample_count": len(samples),
            "wait_to_acquire": _metric_summary(sample["synthetic_lock_probe"]["wait_to_acquire_ms"] for sample in samples),
            "transaction_held": _metric_summary(sample["synthetic_lock_probe"]["transaction_held_ms"] for sample in samples),
            "successful_acquisitions": sum(sample["synthetic_lock_probe"]["successful_acquisitions"] for sample in samples),
        },
        "test_restore": {
            "mode": "TEST",
            "restart_verified_count": sum(sample["test_restore"]["restart_status"] == "VERIFIED" for sample in samples),
            "source_bytes_unchanged_count": sum(sample["test_restore"]["source_bytes_unchanged"] for sample in samples),
        },
        "storage_bytes": {
            "min_final": min(sample["storage_bytes"]["final"] for sample in samples),
            "max_final": max(sample["storage_bytes"]["final"] for sample in samples),
            "min_growth": min(sample["storage_bytes"]["growth"] for sample in samples),
            "max_growth": max(sample["storage_bytes"]["growth"] for sample in samples),
        },
        "restart_verified_count": sum(sample["restart"]["status"] == "VERIFIED" for sample in samples),
        "native_batch_metrics": {"status": "PENDING_NATIVE_REGRESSION", "batches_per_second": None},
        "queue_wait_age_metrics": {"status": "NOT_APPLICABLE_TO_FINANCIAL_OWNER_SLICE", "wait_ms": None, "age_ms": None},
        "resource_measurement": {"status": "OUTER_GUARD_REQUIRED", "parent_child_memory": None},
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--sizes", default=','.join(str(value) for value in DEFAULT_SIZES))
    parser.add_argument("--samples", default=str(DEFAULT_SAMPLES))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        sizes = _parse_sizes(args.sizes)
        samples_per_size = _parse_samples(args.samples)
        root = args.output_root
        if not isinstance(root, Path) or root.is_symlink() or root.exists() or not root.parent.is_dir():
            raise ValueError("measurement_output_root")
        root.mkdir()
        print(_json({"schema": SERIES_SCHEMA, "type": "limits", "limits": _limits()}))
        print(_json({"schema": SERIES_SCHEMA, "type": "plan", "owner_schema": owner_module._SCHEMA, "continuity_schema": owner_module._CONTINUITY_SCHEMA, "evaluation_receipt_contract": owner_module._EVALUATION_RECEIPT_CONTRACT, "source_hashes": _source_hashes(), "sizes": sizes, "warmups_per_size": 1, "samples_per_size": samples_per_size, "native": "PENDING", "queue": "NOT_APPLICABLE", "test_restore_mode": "TEST", "actual_lock_workload": "FinancialOwner._write actual operations", "synthetic_lock_probe_diagnostic": {"hold_target_ms": LOCK_PROBE_HOLD_MS, "waiter_attempts_per_sample": 1, "holder_statements_per_sample": 1}}))
        for size in sizes:
            # Warmup is retained but not included in the measured sample distribution.
            warmup = _sample(root, size=size, sample=0)
            warmup["warmup"] = True
            print(_json({"schema": SERIES_SCHEMA, "type": "warmup", "result": warmup}))
            measured = []
            for sample in range(1, samples_per_size + 1):
                result = _sample(root, size=size, sample=sample)
                measured.append(result)
                print(_json({"schema": SERIES_SCHEMA, "type": "sample", "result": result}))
            print(_json({"schema": SERIES_SCHEMA, "type": "summary", "result": _aggregate(size, measured)}))
        print(_json({"schema": SERIES_SCHEMA, "type": "complete", "status": "PASS", "owner_schema": owner_module._SCHEMA, "continuity_schema": owner_module._CONTINUITY_SCHEMA, "evaluation_receipt_contract": owner_module._EVALUATION_RECEIPT_CONTRACT, "source_hashes": _source_hashes(), "sizes": sizes, "samples_per_size": samples_per_size, "output_root": str(root)}))
        return 0
    except Exception as error:
        print(_json({"schema": SERIES_SCHEMA, "type": "failure", "error": error.__class__.__name__, "code": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
