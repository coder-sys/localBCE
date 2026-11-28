#!/usr/bin/env python3
"""Build localBCE's G2 (program eligibility) rule as RightRail rule-set v2 records.

Reads rules/rightrail_packs/g2_elig_v2.source.json and encodes two records with RightRail's own codec
(rightrail/app/right_rail_ruleset_codec.py):

- elig_only: the three eligibility rules and the eligibility source alone, for the case table.
- full: RightRail's pack 1 (thirteen fact rules, four ages) plus the three eligibility rules, because a shard runs
  under exactly one rule set.

Prints each record's rule count, cost, body length and digest (SHA3-512 of the body, signatures excluded).  `--check`
compares them with rules/rightrail_packs/g2_elig_v2.expected.json and exits 1 on a difference.  Nothing is written.

Synthetic, not legally verified, nonpayment.  The records carry placeholder bytes where signatures go: they are not
signed and no gate admits them.  Design: docs/integration/G2_RULESET_V2_DESIGN.md.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rules" / "rightrail_packs" / "g2_elig_v2.source.json"
EXPECTED = ROOT / "rules" / "rightrail_packs" / "g2_elig_v2.expected.json"
ELIG = 7
ELIG_REASONS = {26: "PROGRAM_NOT_ELIGIBLE", 27: "PROGRAM_NOT_ELIGIBLE_UNVERIFIED", 28: "STALE_ELIGIBILITY"}
KEY_LEN, SIG_LEN = 64, 4627


def load_module(name: str, relative: str):
    """A RightRail module loaded by path, so its package names never meet localBCE's own."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


codec = load_module("rr_ruleset_codec", "rightrail/app/right_rail_ruleset_codec.py")


def expr(node) -> tuple:
    """A condition written as nested JSON lists, as the codec's tuples."""
    if not isinstance(node, list) or not node or not isinstance(node[0], str):
        raise ValueError(f"not a condition: {node!r}")
    op, args = node[0], node[1:]
    if op in ("and", "or"):
        return (op, [expr(x) for x in args])
    if op == "not":
        if len(args) != 1:
            raise ValueError(f"not takes one condition: {node!r}")
        return ("not", expr(args[0]))
    arity = {"date_ok": 0, "flow": 1, "present": 1, "fresh": 1, "overlap": 1, "elig": 2, "hit": 3}
    if op not in arity or len(args) != arity[op] or not all(isinstance(a, int) for a in args):
        raise ValueError(f"not a condition: {node!r}")
    return (op, *args)


def _placeholder(n: int, seed: int) -> bytes:
    return bytes((seed + i) & 255 for i in range(n))


def load_source(path: Path = SOURCE) -> dict:
    return json.loads(path.read_text("utf-8"))


def records(source: dict) -> dict:
    """The two records as the codec's dicts."""
    for flag in ("synthetic", "not_legally_verified", "nonpayment"):
        if source.get(flag) is not True:
            raise ValueError(f"the source must say {flag}: true")
    rules = [(r["bit"], 0, expr(r["when"])) for r in source["rules"]]
    for r in source["rules"]:
        if ELIG_REASONS.get(r["bit"]) != r["reason"]:
            raise ValueError(f"rule {r['bit']} is not {r['reason']!r}")
    h, cite = source["header"], source["cite"]
    aids = sorted(((code, 1) for code in source["aids_eligible"]), key=lambda a: a[0].encode())
    base = {
        "format": 2,
        "state": hashlib.sha3_512(h["state_label"].encode()).digest(),
        "tenant": h["tenant"], "version": h["version"], "prev": bytes(64),
        "not_before": h["not_before"], "not_after": h["not_after"], "eff_from": h["eff_from"], "eff_to": h["eff_to"],
        "ends": [],
        "cites": [(cite["kind"], cite["ref"], cite["date"], hashlib.sha3_512(cite["text"].encode()).digest())],
        "aids": aids,
        # placeholders, not signatures: the digest covers the body only
        "sigs": [(_placeholder(KEY_LEN, 1), _placeholder(SIG_LEN, 1)), (_placeholder(KEY_LEN, 2), _placeholder(SIG_LEN, 2))],
    }
    age = (ELIG, source["elig_max_age_days"])
    pack = source["base_pack"]
    pack_rules = [(r["bit"], 0, expr(r["when"])) for r in pack["rules"]]
    return {
        "elig_only": dict(base, ages=[age], rules=rules),
        "full": dict(base, ages=[tuple(a) for a in pack["ages"]] + [age], rules=sorted(pack_rules + rules)),
    }


def summary(record: dict) -> dict:
    """What is pinned about a record.  `encode` decodes its own bytes again, so a record it returns is canonical."""
    data = codec.encode(record)
    if codec.decode(data) != record:
        raise ValueError("the record does not decode to itself")
    return {
        "rules": len(record["rules"]),
        "ages": len(record["ages"]),
        "cost": sum(codec.cost(e) for _, _, e in record["rules"]),
        "body_bytes": len(data) - 1 - len(record["sigs"]) * (KEY_LEN + SIG_LEN),
        "unbacked": codec.unbacked(record),
        "digest": codec.digest(data).hex(),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the pinned expected file")
    args = ap.parse_args(argv)
    got = {name: summary(rec) for name, rec in records(load_source()).items()}
    for name, s in got.items():
        print(f"{name}: rules={s['rules']} ages={s['ages']} cost={s['cost']} body_bytes={s['body_bytes']} "
              f"unbacked={s['unbacked']}\n  digest={s['digest']}")
    if args.check:
        want = json.loads(EXPECTED.read_text("utf-8"))["records"]
        if got != want:
            print("MISMATCH with " + EXPECTED.relative_to(ROOT).as_posix(), file=sys.stderr)
            return 1
        print("OK: matches " + EXPECTED.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())
