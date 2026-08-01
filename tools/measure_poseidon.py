#!/usr/bin/env python
from __future__ import annotations

import argparse
import os
from time import perf_counter

from app.batch import poseidon


def _measure(rows: list[list[int]], iterations: int, *, oneshot: bool) -> tuple[float, list[int]]:
    if oneshot:
        os.environ["BLIND_LEDGER_POSEIDON_ONESHOT"] = "1"
    else:
        os.environ.pop("BLIND_LEDGER_POSEIDON_ONESHOT", None)
    poseidon._close_worker()
    start = perf_counter()
    result: list[int] = []
    for _ in range(iterations):
        result = poseidon.poseidon_many(rows)
    elapsed = perf_counter() - start
    poseidon._close_worker()
    return elapsed, result


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare persistent and one-shot Poseidon helper plumbing.")
    parser.add_argument("--rows", type=int, default=256, help="Rows per request (default: 256)")
    parser.add_argument("--iterations", type=int, default=20, help="Repeated requests per mode (default: 20)")
    args = parser.parse_args()
    if args.rows < 1 or args.rows > poseidon.MAX_POSEIDON_ROWS:
        raise SystemExit(f"rows must be between 1 and {poseidon.MAX_POSEIDON_ROWS}")
    if args.iterations < 1:
        raise SystemExit("iterations must be at least 1")

    rows = [
        [poseidon.domain_tag("claim_source"), 3, index + 1, index + 2, index + 3]
        for index in range(args.rows)
    ]
    persistent_seconds, persistent_output = _measure(rows, args.iterations, oneshot=False)
    oneshot_seconds, oneshot_output = _measure(rows, args.iterations, oneshot=True)
    outputs_identical = persistent_output == oneshot_output
    print(f"rows_per_request={args.rows}")
    print(f"iterations={args.iterations}")
    print(f"outputs_identical={str(outputs_identical).lower()}")
    print(f"persistent_seconds={persistent_seconds:.6f}")
    print(f"oneshot_seconds={oneshot_seconds:.6f}")
    print(f"persistent_speedup={oneshot_seconds / persistent_seconds:.2f}")
    if not outputs_identical:
        raise SystemExit("persistent and one-shot Poseidon outputs differ")


if __name__ == "__main__":
    main()
