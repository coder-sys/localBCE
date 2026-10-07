"""CFI-HIST H0 (rrb/state/cfi-history-design-20261007.md section 6): what does a cash file cost as earlier history grows?

Report only, no product change.  One synthetic store is seeded to each history size in turn; every (file size, route) pair then
runs on a fresh copy of it, twice: unmetered for wall time (a progress handler or tracemalloc would distort it), and metered
with the test_history_growth meter for sql_ops and peak_kib.  Routes: direct (run_batch) and plan (plan on a copy, then commit).
begin and finish are timed by wrapping CashFileCheck; on the plan route each runs twice (copy, then live) and is summed.
The product caps a file at 500 rows, so a 5,000-line file is ten 500-row files: the row reports the first (history = earlier)
and files_wall_s the whole run.  *_x columns are the growth ratio against the smallest history: flat is good, linear is burden.
Each unmetered pass runs `samples` times (default 5), each on a fresh copy; every *_s column is the median of the first file's samples,
with *_s_min and *_s_max beside it. counts_s is begin's _counts step (a COUNT(*) of every table) and load_s begin's whole obligations and
cases load (_table, cash_file_independent.py:382); both are inside begin_s.
Synthetic, non-PHI, nonpayment; proofSuiteId=null, production_usable=false, activation=false.
"""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import statistics
import sys
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import right_rail_financial_cash_file as cash  # noqa: E402
from app import right_rail_financial_cash_file_independent as check  # noqa: E402
from app import right_rail_financial_engine as engine  # noqa: E402
from app import right_rail_financial_owner as owner  # noqa: E402
from tests import test_history_growth as growth  # noqa: E402  (the meter: _hooks, _measure, _work)
from tests import test_right_rail_financial_cash_file as cash_tests  # noqa: E402

ROUTES = {"direct": lambda store, prepared: store.run_batch(prepared[0], cash_file_context=prepared[1]),
          "plan": lambda store, prepared: cash.apply_cash_file(store, *prepared)}
RATIOS = {"begin_s": "begin_x", "finish_s": "finish_x", "counts_s": "counts_x", "load_s": "load_x", "sql_ops": "ops_x", "peak_kib": "peak_x"}
STEPS = ("begin_s", "finish_s", "counts_s", "load_s")


def _timed(acc, phase):
    real = getattr(check.CashFileCheck, phase)

    def wrapper(self, *args, **kwargs):
        start, ops, acc["inside"] = time.perf_counter(), growth._work["sql_ops"], phase == "begin"
        try:
            return real(self, *args, **kwargs)
        finally:
            acc["inside"] = False
            acc[phase + "_s"] += time.perf_counter() - start
            acc[phase + "_ops"] += growth._work["sql_ops"] - ops
    return patch.object(check.CashFileCheck, phase, wrapper)


def _step(acc, name, key, only=None):
    """Wall time into acc[key] of check.<name> (only for the tables in `only`) while begin runs."""
    real = getattr(check, name)

    def wrapper(connection, *args, **kwargs):
        start = time.perf_counter()
        try:
            return real(connection, *args, **kwargs)
        finally:
            if acc["inside"] and (only is None or args[0] in only):
                acc[key] += time.perf_counter() - start
    return patch.object(check, name, wrapper)


def _file(route, store, prepared, metered):
    acc = {"begin_s": 0.0, "finish_s": 0.0, "counts_s": 0.0, "load_s": 0.0, "begin_ops": 0, "finish_ops": 0, "inside": False}
    with ExitStack() as stack:
        for phase in ("begin", "finish"):
            stack.enter_context(_timed(acc, phase))
        stack.enter_context(_step(acc, "_counts", "counts_s"))
        stack.enter_context(_step(acc, "_table", "load_s", ("obligations", "cases")))
        with engine._evaluator_lock:
            engine._running_evaluator()  # warm: no file pays a worker launch
        run, start = (lambda: ROUTES[route](store, prepared)), time.perf_counter()
        try:
            if metered:
                acc["sql_ops"], _, _, acc["peak_kib"], refused = growth._measure(run)
                acc["refused"] = "owner_refused" if refused else None
            else:
                run()
        except (check.CashFileError, owner.FinancialError) as error:
            acc["refused"] = str(error)
        acc["wall_s"] = time.perf_counter() - start
    return acc


def _config(fx, seeded, fresh, size, lines, route, cap, samples):
    row = {"earlier": size, "lines": lines, "route": route, "files": -(-lines // cap), "samples": samples}
    timed = []
    for metered in (False, True):
        for sample in range(1 if metered else samples):  # only the first unmetered pass runs every file; the others, the first file
            with ExitStack() as hooks:
                if metered:  # on before the owner opens: a progress handler reaches only connections made under it
                    for target, new in growth._hooks():
                        hooks.enter_context(patch(target, new))
                store = hooks.enter_context(fx.fixture._make_owner(path=fx.fixture._copy(None, seeded), clock=seeded.clock))
                fx.store, done = store, []
                for number in range(1 if metered or sample else row["files"]):
                    fx.source = {**fx.source, "capture_id": f"bench-{int(metered)}-{sample}-{number}"}
                    done.append(_file(route, store, fx._prepare(fx._file_of(fresh, min(cap, lines - number * cap), prefix=f"bench-{int(metered)}-{sample}-{number}")), metered))
                    if done[-1].get("refused"):
                        break
                fx.store = seeded
            if metered:  # counters only; its wall time carries the meter's own cost
                row.update({k: v for k, v in done[0].items() if k in ("sql_ops", "begin_ops", "finish_ops", "peak_kib")})
            else:
                timed.append(done)
    for key in STEPS:
        values = [done[0][key] for done in timed]
        row.update({key: statistics.median(values), key + "_min": min(values), key + "_max": max(values)})
    row.update({"refused": next((done[0]["refused"] for done in timed if done[0].get("refused")), None), "files_wall_s": sum(d["wall_s"] for d in timed[0])})
    return row


def _ratios(rows):
    for row in rows:
        first = next(r for r in rows if (r["lines"], r["route"]) == (row["lines"], row["route"]))
        for key, name in RATIOS.items():
            row[name] = row[key] / first[key] if first.get(key) else 1.0
    return rows


def run(earlier=(256, 2_560, 9_500), lines=(500, 5_000), routes=("direct", "plan"), seed_items=100, fresh_items=100, cap=check.MAX_ROWS, out=None, samples=5):
    fx = cash_tests.ReceiverCashFileTests()
    fx.setUp()
    try:
        ids = fx._wide_store(seed_items + fresh_items)
        seeded, have, rows = fx.store, 0, []
        for size in sorted(earlier):
            while have < size:  # earlier payments, as test_history_growth seeds them
                count = min(check.MAX_ROWS, size - have)
                seeded.run_batch(cash._propose(cash_tests.canonical(fx._file_of(ids[:seed_items], count, prefix=f"seed-{have}")), fx.baseline))
                have += count
            fx.baseline = fx._manifest()
            for count in lines:
                for route in routes:
                    rows.append(_config(fx, seeded, ids[-fresh_items:], size, count, route, cap, samples))
                    print(f"CFI_H0 {rows[-1]}", flush=True)
                    out and Path(out).write_text(json.dumps({"sqlite": growth.sqlite3.sqlite_version, "rows": _ratios(rows)}, indent=1), encoding="utf-8")  # a crash keeps what ran
    finally:
        fx.doCleanups()
    return _ratios(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--earlier", default="256,2560,9500")
    parser.add_argument("--lines", default="500,5000")
    parser.add_argument("--routes", default="direct,plan")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(tuple(map(int, args.earlier.split(","))), tuple(map(int, args.lines.split(","))), tuple(args.routes.split(",")), out=args.out, samples=args.samples)
