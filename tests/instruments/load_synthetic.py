"""Synthetic load harness: measured decisions/sec of ``FinancialOwner`` (Art. IX.3, XI.11, XI.12).

Drives the owner's public commands only (no private methods, direct SQL, mocks or second
writer) against a fresh temporary store. The mix (payment/support evidence, evaluation) never
reaches the Lean correction path, so no Lean process is launched or measured. The owner's
history ceiling (``history_capacity``) ends a run and is reported; any other refusal is raised.
With --history DIR the run also exports, restores by replay and checks its history, and shows
one flipped segment byte is refused. Standing claims: synthetic, non-PHI, nonpayment,
proofSuiteId=null, production_usable=false, activation=false.

Usage: python tests/instruments/load_synthetic.py --n 600 --seed 1 --batch 100 [--history DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.right_rail_financial_owner import (  # noqa: E402
    ControlPack, FinancialIntegrityError, FinancialOwner, FinancialOwnerConfig, PopulationItem, PopulationManifest,
    ProgramFundingReceipt, SyntheticTrustedAuthority, _checker_authority,
)
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_history_export  # noqa: E402

_MAX_N = 100_000  # every input has a bound (III.5); the owner's 10,000-event ceiling stops a run cleanly
_SCOPE = {"state_id": "state:harness", "deployment_id": "deployment:harness", "program_id": "program:harness", "period_id": "period:harness-load"}
_PACK_ID, _MANIFEST_ID, _POPULATION_ID = "pack:harness-v1", "manifest:harness-v1", "population:harness-v1"
_MIX = {"record_payment_evidence": 0.5, "record_support_evidence": 0.3, "evaluate_obligation": 0.2}
_LABEL = "measured, local laptop, synthetic"


def _build_cohort(rng: random.Random, size: int) -> tuple[PopulationItem, ...]:
    return tuple(PopulationItem(population_id=_POPULATION_ID, item_id=f"item:{i:06d}", display_label=f"synthetic-obligation-{i:06d}", owed_cents=rng.randint(500, 250_000), due_at_ms=2_000 + i) for i in range(size))


def _setup(owner: FinancialOwner, rng: random.Random, size: int, authority: SyntheticTrustedAuthority) -> tuple[PopulationItem, ...]:
    """One published pack, manifest, population and funding receipt, all harness-owned synthetic data."""
    items = _build_cohort(rng, size)
    owner.publish_control_pack(ControlPack(
        pack_id=_PACK_ID, **_SCOPE, version=1, source_refs=("harness:source:v1",), effective_start_ms=1_000,
        effective_end_ms=4_102_444_800_000, recorded_at_ms=500, approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"),
    ))
    owner.register_population_manifest(PopulationManifest(
        manifest_id=_MANIFEST_ID, manifest_version=1, **_SCOPE, pack_id=_PACK_ID, cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",), source_owner_id="source-owner:harness", authority_id=authority.authority_id,
        authority_epoch=authority.epoch, authority_digest=authority.digest, approved_by="synthetic-official",
        approval_ref="approval:harness-v1", source_id="source:harness-v1", source_version="v1",
        source_digest=hashlib.sha3_512(b"harness-population-source-v1").digest(), member_ids=tuple(sorted(item.item_id for item in items)),
    ))
    owner.stage_population(population_id=_POPULATION_ID, manifest_id=_MANIFEST_ID, pack_id=_PACK_ID, cutoff_ms=1_000, inclusion_rules=("included:synthetic",), expected_count=size, items=items, chunk_size=min(size, 250))
    owner.validate_population(_POPULATION_ID)
    owner.publish_population(_POPULATION_ID)
    owner.record_program_funding_receipt(ProgramFundingReceipt(receipt_id="funding:harness-v1", **_SCOPE, source_record_ref="funding-source:harness-v1", amount_cents=sum(item.owed_cents for item in items), event_at_ms=1_000))
    return items


def _command(rng: random.Random, item: PopulationItem, seed: int, i: int) -> tuple[str, dict]:
    """The i-th steady-state command as (owner method, arguments)."""
    method = rng.choices(list(_MIX), weights=list(_MIX.values()))[0]
    if method == "record_payment_evidence":
        return method, {"item_id": item.item_id, "payment_id": f"payment:{seed}:{i:07d}", "common_origin_id": f"origin:{seed}:{i:07d}", "amount_cents": rng.randint(100, 10_000), "evidence_id": f"evidence:payment:{seed}:{i:07d}", "event_at_ms": 1_000 + i}
    if method == "record_support_evidence":
        return method, {"item_id": item.item_id, "evidence_id": f"evidence:support:{seed}:{i:07d}", "common_origin_id": f"origin:support:{seed}:{i:07d}"}
    return method, {"item_id": item.item_id}


def _history_round_trip(owner: FinancialOwner, authority: SyntheticTrustedAuthority, directory: Path) -> dict:
    """Export, restore by replay and check the history; then one flipped byte in a segment must be refused."""
    checker, seconds = _checker_authority(authority), {}
    for name, call in (("export", lambda: owner.export_history(directory)),
                       ("restore", lambda: FinancialOwner.restore_continuity(history=directory, recovered_path=directory.with_name(f"{directory.name}-restored.sqlite3"), trusted_authority=authority)),
                       ("check", lambda: verify_history_export(directory, expected_authority=checker))):
        start = time.perf_counter()
        call()
        seconds[f"{name}_seconds"] = time.perf_counter() - start
    manifest = json.loads((directory / "manifest.json").read_bytes())
    tampered = shutil.copytree(directory, directory.with_name(f"{directory.name}-tampered"))
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
    return {**seconds, "segment_count": manifest["segment_count"], "sequence": manifest["meta"]["sequence"], "largest_segment_bytes": max(sizes, default=0), "export_bytes": sum(sizes), "tamper_refusal": refusal}


def _percentile(ordered: list[float], pct: int) -> float:
    return ordered[min(len(ordered) - 1, math.ceil(len(ordered) * pct / 100) - 1)] if ordered else 0.0


def run(n: int, seed: int, batch: int = 0, history: Path | None = None, cohort: int = 0) -> dict:
    """``batch`` 0 runs each command alone; K>0 sends K commands per ``run_batch`` (one commit each)."""
    cohort = cohort or max(1, min(1000, math.ceil(n / 20)))
    if not (0 < n <= _MAX_N and 0 <= batch <= 1_000 and 0 < cohort <= 1_000):
        raise SystemExit(f"aborting: need 0 < n <= {_MAX_N}, 0 <= batch <= 1000 and 0 < cohort <= 1000, got n={n} batch={batch} cohort={cohort}")
    rng = random.Random(seed)
    authority = SyntheticTrustedAuthority()
    with tempfile.TemporaryDirectory(prefix="rr-load-synthetic-") as tmp, FinancialOwner(path=Path(tmp) / "load.sqlite3", config=FinancialOwnerConfig(**_SCOPE), trusted_authority=authority) as owner:
        items = _setup(owner, rng, cohort, authority)
        commands = [_command(rng, items[i % cohort], seed, i) for i in range(n)]
        latencies: list[float] = []  # each command's latency is its own commit (alone) or its batch's
        stopped_by, step, start = None, max(batch, 1), time.perf_counter()
        for first in range(0, n, step):
            chunk, t0 = commands[first:first + step], time.perf_counter()
            try:
                owner.run_batch(chunk) if batch else getattr(owner, chunk[0][0])(**chunk[0][1])
            except FinancialIntegrityError as error:  # the owner's ceiling (Lean's maxRows) is a measured result
                if str(error) != "history_capacity":
                    raise
                stopped_by = f"history_capacity after {len(latencies)} commands"
                break
            latencies += [time.perf_counter() - t0] * len(chunk)
        wall = time.perf_counter() - start
        store_bytes = sum(path.stat().st_size for path in Path(tmp).glob("load.sqlite3*"))
        history_result = None if history is None else _history_round_trip(owner, authority, history)
    ordered = sorted(dt * 1000.0 for dt in latencies)
    return {
        "evidence_class": _LABEL, "n_requested": n, "n_completed": len(latencies), "seed": seed, "cohort_size": cohort, "batch": batch,
        "stopped_by": stopped_by, "commands_per_sec": len(latencies) / wall if wall > 0 else 0.0,
        "latency_ms": {"p50": _percentile(ordered, 50), "p99": _percentile(ordered, 99)}, "store_size_bytes": store_bytes, "history": history_result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=600, help=f"steady-state commands (hard max {_MAX_N})")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--batch", type=int, default=0, help="commands per run_batch commit (0: each alone)")
    parser.add_argument("--history", type=Path, default=None, help="export, restore by replay and check the history in this new directory")
    parser.add_argument("--cohort", type=int, default=0, help="obligations sharing the commands (default: n/20, at most 1000)")
    args = parser.parse_args()
    print(json.dumps(run(args.n, args.seed, args.batch, args.history, args.cohort), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
