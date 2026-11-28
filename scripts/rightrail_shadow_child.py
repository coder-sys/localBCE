#!/usr/bin/env python3
"""The RightRail side of a shadow run (scripts/rightrail_shadow.py), in its own process.  Local only.

**Test keys. It decides nothing and binds no one.**  It reads one job (JSON) on standard input, decides the job's
requests with RightRail's pinned decision engine against the job's feeds, and prints RightRail's answers (JSON).  The
caller records them beside localBCE's decisions; nothing here changes a claim's status.

How it runs RightRail, as rightrail/tests/test_right_rail_gate_ffs.py `FileToDecisionTests` does:
- the pinned engine `gate_engine.exe` only.  Its SHA-256 must equal the `pin gate_engine` line of RightRail's
  PROVENANCE.txt, or the run stops.  No other engine and no substituted pin.
- RightRail's own test fixtures for the key set, the grant, the deployment slots, the tenant authority and one store per
  shard.  The stores live in a scratch directory outside both repositories and are removed at the end.
- requests built directly with RightRail's line encoder.  Its normal claim intake is bypassed.

Keys.  The key set and the grant are signed with RightRail's fixed test-only keys, derived in memory by the signer's
`kat-keygen` mode.  **The shard stores also need an epoch key file: RightRail's fixture (`fx.custody`) makes one per
store group with the signer's `keygen` mode, a random seed sealed with DPAPI and written into the scratch directory,
removed with it.**  That is a seed file made by `keygen`, so the job must say `allow_scratch_keygen: true`; without it
this script stops before any key is made.

It writes nothing under rightrail/ or parked/, and no bytecode (run it with `python -B`).
Synthetic, not legally verified, nonpayment.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RIGHTRAIL = ROOT / "rightrail"
SCRATCH: list = []  # each scratch directory this process made


def run(job: dict) -> dict:
    if job.get("allow_scratch_keygen") is not True:
        raise RuntimeError("the shard stores need an epoch key file made by `keygen` in the scratch directory, "
                           "and the job does not allow it")
    os.chdir(RIGHTRAIL)
    sys.path.insert(0, str(RIGHTRAIL))
    from app import right_rail_gate_signer as signer
    signer.BINARY = Path(job["signer"])  # before the fixtures are imported: they sign at import; pin-checked per call
    from app import right_rail_deployment_slots as slots
    from app import right_rail_fact_codec as fact_codec
    from app import right_rail_fact_registry as reg
    from app import right_rail_gate_codec as gate
    from app import right_rail_gate_decide as decider
    from app import right_rail_gate_ffs as ffs
    from app.right_rail_reader_elig_independent import verify_elig
    from tests import _gate_authority as au
    from tests import _gate_shards as g
    from tests import test_right_rail_deployment_slots as ts
    from tests import test_right_rail_gate_formats as fx

    engine = g.ENGINE
    engine_sha = hashlib.sha256(engine.read_bytes()).hexdigest()
    if engine_sha != decider.committed_pin().hex():
        raise RuntimeError("gate_engine.exe is not the pinned program")
    if job["today"] != au.TODAY:
        raise RuntimeError(f"the job's batch date must be the test key set's day, {au.TODAY}")
    pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
    out = {"today": job["today"], "steps": [],
           "engine": {"name": engine.name, "sha256": engine_sha, "is_the_pinned_program": True}}

    # The scratch directory holds the stores and the epoch key files.  It is removed whether the run ends well or not;
    # the key files are never copied, logged or printed.  If it cannot be removed, its path is reported.
    top = tempfile.mkdtemp(prefix="rr-shadow-")
    SCRATCH.append(top)
    try:
        groups: dict = {}  # store group -> (host, shards, flats)
        try:
            for n, step in enumerate(job["steps"]):
                name = step["store"] if step["store"] == "main" else f"separate-{n}"
                if name not in groups:
                    tmp = Path(top) / name
                    tmp.mkdir()
                    cluster = g.Cluster(str(tmp), fx.custody(str(tmp)), shards=fx.SHARDS)  # `keygen`: one sealed key file here
                    shards = {k: cluster.producer(k) for k in range(fx.SHARDS)}
                    floor = tmp / "tenant.floor"
                    decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
                    host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), engine)
                    groups[name] = (host, shards, {k: tmp / f"idx{k}" for k in shards})
                host, shards, flats = groups[name]
                feeds = tuple(decider.feed(kind, step["feeds"][kind]["as_of"], [tuple(r) for r in step["feeds"][kind]["rows"]])
                              for kind in decider.FEED_WIDTHS)
                requests = []
                for r in step["requests"]:
                    key = bytes.fromhex(r["member_key"])
                    lines = tuple(gate.encode_line("FFS_CLAIM", ln["line_id"], key, r["payee"], ln["rendering"], ln["date"],
                                                   ln["procedure"], ln["units"], ln["cents"]) for ln in r["lines"])
                    requests.append(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", r["payment_id"], r["payment_id"], key,
                                                       r["payee"], r["cents"], fx.PERIOD, lines, (bytes.fromhex(r["evidence"]),)))
                rows, _, sealed = ffs.decide_claims(requests, (job["today"], feeds), host, shards, flats, g.GRANT, g.KEYS,
                                                    fx.PROGRAM, fx.NOW)
                out["steps"].append({
                    "name": step["name"], "store": name,
                    "rows": [[p, at, outcome, list(why)] for p, at, outcome, why in rows],
                    "feed_digests": {kind: hashlib.sha3_512(desc).hexdigest()
                                     for kind, (desc, _) in zip(decider.FEED_WIDTHS, feeds)},
                    "checkpoint_digests": [hashlib.sha3_512(signed).hexdigest() for signed, _, _ in sealed],
                })
        finally:
            for host, shards, _ in groups.values():
                try:
                    host[1].close()
                finally:
                    for store in shards.values():
                        store.close()

        # The eligibility extract: read by RightRail's independent verifier.  No decision uses it.
        ex = job.get("extract")
        if ex:
            golden = json.loads((RIGHTRAIL / "tests" / "elig_vectors" / "golden.json").read_text("utf-8"))
            entry = dict(golden["entry"], scope=ex["scope"])
            entry["kinds"] = reg.mask_of(entry["ids"])
            entry["scope"], entry["name"] = reg.ident(21, entry["scope"]), reg.ident(31, entry["name"])
            data, facts = bytes.fromhex(ex["hex"]), []
            import io
            scratch = Path(top) / "extract"
            scratch.mkdir()
            receipt = fact_codec.decode_receipt(verify_elig(io.BytesIO(data), golden["secret"].encode(), entry, facts.append,
                                                            scratch=str(scratch), **golden["transport"]))
            out["extract"] = {"accepted": True, "fact_rows": len(facts), "file_sha3_512": hashlib.sha3_512(data).hexdigest(),
                              "receipt_file_matches": receipt["file"] == hashlib.sha3_512(data).digest(),
                              "used_by_a_decision": False}
    finally:
        shutil.rmtree(top, ignore_errors=True)
    out["scratch_dir"] = top
    out["stores_removed"] = not Path(top).exists()
    return out


def main() -> int:
    try:
        print(json.dumps(run(json.loads(sys.stdin.read()))))
        return 0
    except Exception:  # noqa: BLE001  the caller reports it; nothing was decided
        print(traceback.format_exc()[-3000:], file=sys.stderr)
        for top in SCRATCH:
            kept = Path(top).exists()
            print(f"SCRATCH {'KEPT' if kept else 'removed'}: {top}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
