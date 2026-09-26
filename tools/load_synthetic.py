"""Synthetic load harness for the RightRail financial owner (CONSTITUTION IX.3, XI.11, XI.12).

Drives FinancialOwner's public commands against a fresh temporary store and
reports throughput and latency, labelled "measured, local laptop, synthetic".
The mix never calls the Lean correction path, so no Lean process is launched.
With --history DIR it also exports, restores by replay and checks the history,
and shows one flipped segment byte is refused. Standing claims: synthetic,
non-PHI, nonpayment, proofSuiteId=null, production_usable=false, activation=false.

    python tools/load_synthetic.py --n 1000 --seed 1 --out result.json [--history DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.right_rail_financial_owner import (  # noqa: E402
    ControlPack,
    FinancialIntegrityError,
    FinancialOwner,
    FinancialOwnerConfig,
    PopulationItem,
    PopulationManifest,
    ProgramFundingReceipt,
    SyntheticTrustedAuthority,
    _checker_authority,
)
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_history_export  # noqa: E402

_MAX_N = 100_000  # every input has a bound (III.5)
_MAX_WALL_SECONDS = 600.0
_LABEL = "measured, local laptop, synthetic"
_MIX = {"payment": 0.5, "support": 0.3, "evaluate": 0.2}
_SCOPE = {"state_id": "state:harness", "deployment_id": "deployment:harness", "program_id": "program:harness", "period_id": "period:harness-load"}
_POPULATION_ID = "population:harness-v1"


def _timed(latencies: dict[str, float], name: str, call) -> None:
    start = time.perf_counter()
    call()
    latencies[name] = time.perf_counter() - start


def _setup(owner: FinancialOwner, rng: random.Random, size: int, authority: SyntheticTrustedAuthority) -> tuple[list[PopulationItem], dict[str, float]]:
    """One pack, manifest, population and funding receipt; harness-owned data, not the protected fixture."""
    items = [PopulationItem(population_id=_POPULATION_ID, item_id=f"item:{i:06d}", display_label=f"synthetic-obligation-{i:06d}", owed_cents=rng.randint(500, 250_000), due_at_ms=2_000 + i) for i in range(size)]
    pack = ControlPack(
        pack_id="pack:harness-v1", version=1, source_refs=("harness:source:v1",), effective_start_ms=1_000, effective_end_ms=4_102_444_800_000,
        recorded_at_ms=500, approved_at_ms=500, calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"), **_SCOPE,
    )
    manifest = PopulationManifest(
        manifest_id="manifest:harness-v1", manifest_version=1, pack_id=pack.pack_id, cutoff_ms=1_000, inclusion_rules=("included:synthetic",),
        source_owner_id="source-owner:harness", authority_id=authority.authority_id, authority_epoch=authority.epoch, authority_digest=authority.digest,
        approved_by="synthetic-official", approval_ref="approval:harness-v1", source_id="source:harness-v1", source_version="v1",
        source_digest=hashlib.sha3_512(b"harness-population-source-v1").digest(), member_ids=tuple(item.item_id for item in items), **_SCOPE,
    )
    receipt = ProgramFundingReceipt(receipt_id="funding:harness-v1", source_record_ref="funding-source:harness-v1", amount_cents=sum(item.owed_cents for item in items), event_at_ms=1_000, **_SCOPE)
    latencies: dict[str, float] = {}
    _timed(latencies, "publish_control_pack", lambda: owner.publish_control_pack(pack))
    _timed(latencies, "register_population_manifest", lambda: owner.register_population_manifest(manifest))
    _timed(latencies, "stage_population", lambda: owner.stage_population(
        population_id=_POPULATION_ID, manifest_id=manifest.manifest_id, pack_id=pack.pack_id, cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",), expected_count=size, items=tuple(items), chunk_size=min(size, 250)))
    _timed(latencies, "validate_population", lambda: owner.validate_population(_POPULATION_ID))
    _timed(latencies, "publish_population", lambda: owner.publish_population(_POPULATION_ID))
    _timed(latencies, "record_program_funding_receipt", lambda: owner.record_program_funding_receipt(receipt))
    return items, latencies


def _history_round_trip(owner: FinancialOwner, authority: SyntheticTrustedAuthority, directory: Path) -> dict:
    timings: dict[str, float] = {}
    checker = _checker_authority(authority)
    _timed(timings, "export_seconds", lambda: owner.export_history(directory))
    _timed(timings, "restore_seconds", lambda: FinancialOwner.restore_continuity(history=directory, recovered_path=directory.with_name(f"{directory.name}-restored.sqlite3"), trusted_authority=authority))
    _timed(timings, "check_seconds", lambda: verify_history_export(directory, expected_authority=checker))
    manifest = json.loads((directory / "manifest.json").read_bytes())
    tampered = directory.with_name(f"{directory.name}-tampered")
    shutil.copytree(directory, tampered)
    segment = tampered / f"segment-{manifest['segment_count'] // 2:08d}.json"
    data = bytearray(segment.read_bytes())
    data[len(data) // 2] ^= 1
    segment.write_bytes(bytes(data))
    try:
        verify_history_export(tampered, expected_authority=checker)
        refusal = None
    except IndependentFinancialError as error:
        refusal = str(error)
    sizes = [path.stat().st_size for path in directory.glob("segment-*.json")]
    return {**timings, "segment_count": manifest["segment_count"], "sequence": manifest["meta"]["sequence"], "largest_segment_bytes": max(sizes, default=0), "export_bytes": sum(sizes), "tamper_refusal": refusal}


def _peak_rss() -> dict:
    try:  # no new dependency: resource is POSIX-only and psutil is not installed
        import resource
    except ImportError:
        return {"value": None, "note": "not available (resource is POSIX-only)"}
    return {"value": float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), "note": "resource.getrusage (KB, POSIX only)"}


def run(n: int, seed: int, history: Path | None = None) -> dict:
    if not 0 < n <= _MAX_N:
        raise SystemExit(f"aborting: --n must be in 1..{_MAX_N}, got {n}")
    rng = random.Random(seed)
    size = max(1, min(1000, -(-n // 20)))
    authority = SyntheticTrustedAuthority()
    latencies: dict[str, list[float]] = {kind: [] for kind in _MIX}
    abort_reason = None
    with tempfile.TemporaryDirectory(prefix="rr-load-synthetic-") as tmp_dir:
        db_path = Path(tmp_dir) / "rightrail-load.sqlite3"
        owner = FinancialOwner(path=db_path, config=FinancialOwnerConfig(**_SCOPE), trusted_authority=authority)
        run_start = time.perf_counter()
        items, setup = _setup(owner, rng, size, authority)
        steady_start = time.perf_counter()
        for i in range(n):
            if time.perf_counter() - run_start > _MAX_WALL_SECONDS:
                abort_reason = f"wall_clock_bound_exceeded ({_MAX_WALL_SECONDS:.0f}s) after {i} of {n} steady-state commands"
                break
            item_id = items[i % size].item_id
            kind = rng.choices(list(_MIX), weights=list(_MIX.values()))[0]
            start = time.perf_counter()
            try:
                if kind == "payment":
                    owner.record_payment_evidence(item_id=item_id, payment_id=f"payment:{seed}:{i:07d}", common_origin_id=f"origin:{seed}:{i:07d}", amount_cents=rng.randint(100, 10_000), evidence_id=f"evidence:payment:{seed}:{i:07d}", event_at_ms=1_000 + i)
                elif kind == "support":
                    owner.record_support_evidence(item_id=item_id, evidence_id=f"evidence:support:{seed}:{i:07d}", common_origin_id=f"origin:support:{seed}:{i:07d}")
                else:
                    owner.evaluate_obligation(item_id)
            except FinancialIntegrityError as error:  # the owner's ceiling (Lean's maxRows events) is a measured result
                if str(error) != "history_capacity":
                    raise
                abort_reason = f"refused after {i} of {n} steady-state commands: {error}"
                break
            latencies[kind].append(time.perf_counter() - start)
        steady_wall = time.perf_counter() - steady_start
        history_result = None if history is None else _history_round_trip(owner, authority, history)
        store_size_bytes = sum(path.stat().st_size for path in Path(tmp_dir).glob("rightrail-load.sqlite3*"))
    completed = sum(map(len, latencies.values()))
    ordered = sorted(1000.0 * value for values in latencies.values() for value in values)
    percentile = {f"p{pct}": ordered[round(pct / 100 * (len(ordered) - 1))] if ordered else 0.0 for pct in (50, 95, 99)}
    total_wall = steady_start - run_start + steady_wall
    return {
        "evidence_class": _LABEL, "n_requested": n, "n_completed": completed, "seed": seed, "cohort_size": size,
        "aborted_early": abort_reason is not None, "abort_reason": abort_reason,
        "setup": {"commands": len(setup), "wall_seconds": steady_start - run_start, "latency_ms_by_command": {k: v * 1000.0 for k, v in setup.items()}},
        "steady_state": {
            "commands": completed, "wall_seconds": steady_wall, "commands_per_sec": completed / steady_wall if steady_wall > 0 else 0.0,
            "command_mix_counts": {k: len(v) for k, v in latencies.items()},
            "latency_ms": {**percentile, "mean_by_kind": {k: sum(v) / len(v) * 1000.0 if v else None for k, v in latencies.items()}},
        },
        "overall": {"commands": len(setup) + completed, "wall_seconds": total_wall, "commands_per_sec": (len(setup) + completed) / total_wall if total_wall > 0 else 0.0},
        "store_size_bytes": store_size_bytes,
        "history": history_result,
        "peak_rss": _peak_rss(),
        "lean_engine_launch": {"count": 0, "note": "this mix never reaches the correction path, the only one that launches Lean"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=1000, help=f"steady-state commands (hard max {_MAX_N})")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, default=None, help="write the JSON result here instead of stdout")
    parser.add_argument("--history", type=Path, default=None, help="export, restore by replay and check the history in this new directory")
    args = parser.parse_args()
    result = run(args.n, args.seed, args.history)
    payload = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    steady = result["steady_state"]
    print(f"[{_LABEL}] {steady['commands_per_sec']:.1f} commands/sec over {steady['commands']} commands; p50={steady['latency_ms']['p50']:.3f} ms p99={steady['latency_ms']['p99']:.3f} ms; store {result['store_size_bytes']} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
