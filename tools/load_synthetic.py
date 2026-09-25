"""Synthetic load/throughput harness for the RightRail financial owner.

Answers one audit question: "a single-writer SQLite owner in Python has no
measured decisions-per-second" (CONSTITUTION Art. IX.3, XI.11, XI.12 --
measure before claiming performance; label evidence by class). This script
drives ``FinancialOwner``'s real public command methods -- no private
methods, no direct SQL, no mocking the owner, no second writer -- against a
fresh temporary SQLite store, and reports measured throughput and latency.

Every number this script prints is labelled "measured, local laptop,
synthetic". Standing claims: synthetic, non-PHI, nonpayment,
proofSuiteId=null, production_usable=false, activation=false.

Usage:
    python tools/load_synthetic.py --n 1000 --seed 1 --out result.json [--history DIR]

With ``--history DIR`` the run also exports the history as segments to DIR,
restores it by replay into a fresh store, checks it, and shows that one
flipped byte in a segment is refused (docs/CORE_REDESIGN.md "History segments").
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.right_rail_financial_owner import (  # noqa: E402
    ControlPack,
    FinancialOwner,
    FinancialOwnerConfig,
    PopulationItem,
    PopulationManifest,
    ProgramFundingReceipt,
    SyntheticTrustedAuthority,
    _checker_authority,
)
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_history_export  # noqa: E402

# Explicit bounds (CONSTITUTION III.5 / IX.3: every input has a bound).
_MAX_N = 100_000
_MAX_WALL_SECONDS = 600.0

_STATE_ID = "state:harness"
_DEPLOYMENT_ID = "deployment:harness"
_PROGRAM_ID = "program:harness"
_PERIOD_ID = "period:harness-load"
_PACK_ID = "pack:harness-v1"
_MANIFEST_ID = "manifest:harness-v1"
_POPULATION_ID = "population:harness-v1"
_FUNDING_RECEIPT_ID = "funding:harness-v1"

# Steady-state command mix: predominantly the commands that decide/settle an
# already-published obligation, since that is the closest proxy to "inline
# payment gate decisions/sec". This mix never reaches the Lean correction
# path (reject_offset_and_authorize_correction / drain_correction_followups)
# so it launches no Lean subprocess; see the report for why.
_MIX = (("payment", 0.5), ("support", 0.3), ("evaluate", 0.2))

_LABEL = "measured, local laptop, synthetic"


def _digest64(label: str) -> bytes:
    return hashlib.sha3_512(label.encode("utf-8")).digest()


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    if low == high:
        return sorted_values[low]
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (rank - low)


def _peak_rss_bytes() -> tuple[float | None, str]:
    """Best-effort peak RSS. No new third-party dependency is added for this:
    ``resource`` is POSIX-only (unavailable on Windows) and psutil is not an
    existing dependency of this repo (requirements.txt has none;
    requirements-dev.txt pins only pytest and its own deps)."""
    try:
        import resource  # type: ignore  # POSIX only

        return float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), "resource.getrusage (KB, POSIX only)"
    except ImportError:
        return None, "not available (resource module is POSIX-only; psutil is not an installed dependency of this repo)"


def _build_cohort(rng: random.Random, cohort_size: int) -> tuple[PopulationItem, ...]:
    items = []
    for i in range(cohort_size):
        owed_cents = rng.randint(500, 250_000)
        items.append(
            PopulationItem(
                population_id=_POPULATION_ID,
                item_id=f"item:{i:06d}",
                display_label=f"synthetic-obligation-{i:06d}",
                owed_cents=owed_cents,
                due_at_ms=2_000 + i,
            )
        )
    return tuple(items)


def _setup(owner: FinancialOwner, rng: random.Random, cohort_size: int, authority: SyntheticTrustedAuthority) -> tuple[tuple[PopulationItem, ...], dict[str, float]]:
    """Publish one control pack, manifest and population -- once per cohort,
    not per command -- plus one program funding receipt. Every object here is
    harness-owned synthetic data built directly from ``ControlPack`` /
    ``PopulationManifest`` / ``PopulationItem`` / ``ProgramFundingReceipt``,
    not the protected acceptance-test fixture."""

    latencies: dict[str, float] = {}
    items = _build_cohort(rng, cohort_size)

    pack = ControlPack(
        pack_id=_PACK_ID,
        state_id=_STATE_ID,
        deployment_id=_DEPLOYMENT_ID,
        program_id=_PROGRAM_ID,
        period_id=_PERIOD_ID,
        version=1,
        source_refs=("harness:source:v1",),
        effective_start_ms=1_000,
        effective_end_ms=4_102_444_800_000,
        recorded_at_ms=500,
        approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1",
        adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=(
            "program-total=100000000",
            "H-owed=10000000",
            "other-total=90000000",
            "timeliness-separate",
        ),
    )
    t0 = time.perf_counter()
    owner.publish_control_pack(pack)
    latencies["publish_control_pack"] = time.perf_counter() - t0

    manifest = PopulationManifest(
        manifest_id=_MANIFEST_ID,
        manifest_version=1,
        state_id=_STATE_ID,
        deployment_id=_DEPLOYMENT_ID,
        program_id=_PROGRAM_ID,
        period_id=_PERIOD_ID,
        pack_id=_PACK_ID,
        cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",),
        source_owner_id="source-owner:harness",
        authority_id=authority.authority_id,
        authority_epoch=authority.epoch,
        authority_digest=authority.digest,
        approved_by="synthetic-official",
        approval_ref="approval:harness-v1",
        source_id="source:harness-v1",
        source_version="v1",
        source_digest=_digest64("harness-population-source-v1"),
        member_ids=tuple(sorted(item.item_id for item in items)),
    )
    t0 = time.perf_counter()
    owner.register_population_manifest(manifest)
    latencies["register_population_manifest"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    owner.stage_population(
        population_id=_POPULATION_ID,
        manifest_id=_MANIFEST_ID,
        pack_id=_PACK_ID,
        cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",),
        expected_count=len(items),
        items=items,
        chunk_size=min(len(items), 250),
    )
    latencies["stage_population"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    owner.validate_population(_POPULATION_ID)
    latencies["validate_population"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    owner.publish_population(_POPULATION_ID)
    latencies["publish_population"] = time.perf_counter() - t0

    receipt = ProgramFundingReceipt(
        receipt_id=_FUNDING_RECEIPT_ID,
        state_id=_STATE_ID,
        deployment_id=_DEPLOYMENT_ID,
        program_id=_PROGRAM_ID,
        period_id=_PERIOD_ID,
        source_record_ref="funding-source:harness-v1",
        amount_cents=sum(item.owed_cents for item in items),
        event_at_ms=1_000,
    )
    t0 = time.perf_counter()
    owner.record_program_funding_receipt(receipt)
    latencies["record_program_funding_receipt"] = time.perf_counter() - t0

    return items, latencies


def _history_round_trip(owner: FinancialOwner, authority: SyntheticTrustedAuthority, directory: Path) -> dict:
    timings = {}
    t0 = time.perf_counter()
    manifest = json.loads(owner.export_history(directory))
    timings["export_seconds"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    FinancialOwner.restore_continuity(history=directory, recovered_path=directory.with_name(f"{directory.name}-restored.sqlite3"), trusted_authority=authority)
    timings["restore_seconds"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    verify_history_export(directory, expected_authority=_checker_authority(authority))
    timings["check_seconds"] = time.perf_counter() - t0
    tampered = directory.with_name(f"{directory.name}-tampered")
    shutil.copytree(directory, tampered)
    segment = tampered / f"segment-{manifest['segment_count'] // 2:08d}.json"
    data = bytearray(segment.read_bytes())
    data[len(data) // 2] ^= 1
    segment.write_bytes(bytes(data))
    try:
        verify_history_export(tampered, expected_authority=_checker_authority(authority))
        refusal = None
    except IndependentFinancialError as error:
        refusal = str(error)
    sizes = [path.stat().st_size for path in directory.glob("segment-*.json")]
    return {**timings, "segment_count": manifest["segment_count"], "sequence": manifest["meta"]["sequence"], "largest_segment_bytes": max(sizes, default=0), "export_bytes": sum(sizes), "tamper_refusal": refusal}


def run(n: int, seed: int, history: Path | None = None) -> dict:
    if n <= 0:
        raise SystemExit(f"aborting: --n must be positive, got {n}")
    if n > _MAX_N:
        raise SystemExit(f"aborting: n={n} exceeds the hard max of {_MAX_N} commands; not running")

    rng = random.Random(seed)
    cohort_size = max(1, min(1000, math.ceil(n / 20)))

    with tempfile.TemporaryDirectory(prefix="rr-load-synthetic-") as tmp_dir:
        db_path = Path(tmp_dir) / "rightrail-load.sqlite3"
        authority = SyntheticTrustedAuthority()
        config = FinancialOwnerConfig(
            state_id=_STATE_ID,
            deployment_id=_DEPLOYMENT_ID,
            program_id=_PROGRAM_ID,
            period_id=_PERIOD_ID,
        )
        owner = FinancialOwner(path=db_path, config=config, trusted_authority=authority)

        run_start = time.perf_counter()
        items, setup_latencies = _setup(owner, rng, cohort_size, authority)
        setup_wall = time.perf_counter() - run_start
        setup_commands = len(setup_latencies)

        by_kind: dict[str, list[float]] = {"payment": [], "support": [], "evaluate": []}
        kinds = [k for k, _w in _MIX]
        weights = [w for _k, w in _MIX]
        aborted = False
        abort_reason = None
        completed = 0

        steady_start = time.perf_counter()
        for i in range(n):
            if time.perf_counter() - run_start > _MAX_WALL_SECONDS:
                aborted = True
                abort_reason = f"wall_clock_bound_exceeded ({_MAX_WALL_SECONDS:.0f}s) after {completed} of {n} steady-state commands"
                break
            item = items[i % cohort_size]
            kind = rng.choices(kinds, weights=weights, k=1)[0]
            t0 = time.perf_counter()
            if kind == "payment":
                owner.record_payment_evidence(
                    item_id=item.item_id,
                    payment_id=f"payment:{seed}:{i:07d}",
                    common_origin_id=f"origin:{seed}:{i:07d}",
                    amount_cents=rng.randint(100, 10_000),
                    evidence_id=f"evidence:payment:{seed}:{i:07d}",
                    event_at_ms=1_000 + i,
                )
            elif kind == "support":
                owner.record_support_evidence(
                    item_id=item.item_id,
                    evidence_id=f"evidence:support:{seed}:{i:07d}",
                    common_origin_id=f"origin:support:{seed}:{i:07d}",
                )
            else:
                owner.evaluate_obligation(item.item_id)
            dt = time.perf_counter() - t0
            by_kind[kind].append(dt)
            completed += 1
        steady_wall = time.perf_counter() - steady_start
        history_result = None if history is None else _history_round_trip(owner, authority, history)

        store_size_bytes = os.path.getsize(db_path)
        for suffix in ("-wal", "-shm", "-journal"):
            side_file = Path(str(db_path) + suffix)
            if side_file.exists():
                store_size_bytes += side_file.stat().st_size

    all_latencies_ms = sorted(dt * 1000.0 for values in by_kind.values() for dt in values)
    total_wall = setup_wall + steady_wall
    peak_rss, peak_rss_note = _peak_rss_bytes()

    result = {
        "evidence_class": _LABEL,
        "n_requested": n,
        "n_completed": completed,
        "seed": seed,
        "cohort_size": cohort_size,
        "aborted_early": aborted,
        "abort_reason": abort_reason,
        "setup": {
            "commands": setup_commands,
            "wall_seconds": setup_wall,
            "latency_ms_by_command": {k: v * 1000.0 for k, v in setup_latencies.items()},
        },
        "steady_state": {
            "commands": completed,
            "wall_seconds": steady_wall,
            "commands_per_sec": (completed / steady_wall) if steady_wall > 0 else 0.0,
            "command_mix_counts": {k: len(v) for k, v in by_kind.items()},
            "latency_ms": {
                "p50": _percentile(all_latencies_ms, 50),
                "p95": _percentile(all_latencies_ms, 95),
                "p99": _percentile(all_latencies_ms, 99),
                "mean_by_kind": {
                    k: (sum(v) / len(v) * 1000.0) if v else None for k, v in by_kind.items()
                },
            },
        },
        "overall": {
            "commands": setup_commands + completed,
            "wall_seconds": total_wall,
            "commands_per_sec": ((setup_commands + completed) / total_wall) if total_wall > 0 else 0.0,
        },
        "store_size_bytes": store_size_bytes,
        "history": history_result,
        "peak_rss": {"value": peak_rss, "note": peak_rss_note},
        "lean_engine_launch": {
            "count": 0,
            "total_seconds": 0.0,
            "percent_of_wall_clock": 0.0,
            "note": (
                "This command mix (setup + record_payment_evidence / "
                "record_support_evidence / evaluate_obligation) never calls "
                "reject_offset_and_authorize_correction or the correction-followup "
                "path, which are the only FinancialOwner commands that launch the "
                "pinned Lean correction engine subprocess. No Lean engine launch "
                "was exercised or measured by this run."
            ),
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=1000, help="number of steady-state commands to run (default 1000, hard max %d)" % _MAX_N)
    parser.add_argument("--seed", type=int, default=1, help="integer seed for deterministic synthetic data (default 1)")
    parser.add_argument("--out", type=str, default=None, help="path to write the JSON result (default: print to stdout)")
    parser.add_argument("--history", type=Path, default=None, help="export, restore by replay and check the history in this new directory")
    args = parser.parse_args()

    result = run(args.n, args.seed, args.history)

    payload = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
    else:
        print(payload)

    steady = result["steady_state"]
    overall = result["overall"]
    print(f"[{_LABEL}] n_completed={result['n_completed']} aborted_early={result['aborted_early']}", file=sys.stderr)
    print(f"[{_LABEL}] steady-state: {steady['commands_per_sec']:.1f} commands/sec over {steady['commands']} commands", file=sys.stderr)
    print(f"[{_LABEL}] latency ms: p50={steady['latency_ms']['p50']:.3f} p95={steady['latency_ms']['p95']:.3f} p99={steady['latency_ms']['p99']:.3f}", file=sys.stderr)
    print(f"[{_LABEL}] overall (setup+steady): {overall['commands_per_sec']:.1f} commands/sec over {overall['commands']} commands", file=sys.stderr)
    print(f"[{_LABEL}] store size on disk: {result['store_size_bytes']} bytes", file=sys.stderr)
    print(f"[{_LABEL}] peak RSS: {result['peak_rss']['value']} ({result['peak_rss']['note']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
