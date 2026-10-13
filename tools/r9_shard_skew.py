"""OWC S11 / B0: how skewed is the per-item line count, and what does the hash route make of it at each K? Judge only (no shards, nothing written); synthetic.
Per corpus: lines per item, the biggest item's share, and for each K the lines per shard under route = sha3(PAYER, item)[:8] mod K with imbalance = busiest / mean.
With --results RESULTS.json (a r9_shard_bench output) the measured per-shard busy seconds of each K are set next to the lines, to tell line skew from per-line cost."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import r9_bench as rb  # noqa: E402
from tools import r9_shard_bench as sb  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k", type=int, nargs="+", default=[1, 8, 12])
    ap.add_argument("--corpus", nargs="+", default=["FL", "DE"])
    ap.add_argument("--lines", type=int, default=5000)
    ap.add_argument("--files", type=int, default=24)
    ap.add_argument("--results", type=Path)
    a = ap.parse_args()
    sb.SCRATCH.mkdir(parents=True, exist_ok=True)
    template = sb.SCRATCH / "template.sqlite3"
    if not template.exists():
        rb.make_owner_db(template)
    runs = json.loads(a.results.read_text(encoding="utf-8"))["runs"] if a.results else []
    seeds = {"FL": 20261006, "DE": 20261007}
    for name in a.corpus:
        files = sb.corpus(seeds[name], a.lines, a.files)
        tbl = sb.tables(template, 1)
        per_item: dict[str, int] = {}
        for i, (record, _) in enumerate(files):
            for parts in sb.prepare(tbl, i, record.rows, i + 1).blobs.values():
                for part in sb.pickle.loads(parts):
                    item = tbl.obl[part[7]]
                    per_item[item] = per_item.get(item, 0) + 1
        total, counts = sum(per_item.values()), sorted(per_item.values(), reverse=True)
        print(f"{name}: {total} shard lines over {len(per_item)} items; biggest item {counts[0]} ({counts[0] / total:.1%}), top3 {sum(counts[:3]) / total:.1%}, median {counts[len(counts) // 2]}, smallest {counts[-1]}")
        for k in a.k:
            lines = [0] * k
            for item, n in per_item.items():
                lines[int.from_bytes(rb.sha("RR/SHARD/v1", sb.PAYER, item)[:8], "big") % k] += n
            print(f"  K={k}: lines/shard {lines} imbalance by lines {max(lines) / (total / k):.3f}")
            rows = [r for r in runs if r.get("corpus") == name and r["K"] == k and "shard_busy_s" in r]
            if rows:
                busy = [sum(r["shard_busy_s"][s] for r in rows) / len(rows) for s in range(k)]
                us = [b / n * 1e6 if n else 0.0 for b, n in zip(busy, lines)]
                print(f"       measured busy s/shard (mean of {len(rows)} runs) {[round(b, 2) for b in busy]}; us/line per shard {[round(u) for u in us]}; busy imbalance {max(busy) / (sum(busy) / k):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
