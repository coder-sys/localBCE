#!/usr/bin/env python3
"""Shadow run: record RightRail's answer beside localBCE's.  It decides nothing.

Design: docs/integration/SHADOW_RUN_DESIGN.md.  Synthetic, not legally verified, nonpayment.

**This is a test-key run. It decides nothing and binds no one.**  The Rust engine decides each claim exactly as it does
today.  RightRail's answer, made under test keys, a test grant and hand-written synthetic feeds, is written to a
separate record for comparison only.  Nothing reads that record to change a status.  Every record and the summary say
so in words (`STATEMENT`).

What a run does: for each scenario of scripts/tests/fixtures/shadow/scenarios.json it runs the Rust engine (the
decision), runs the adapter (`rightrail_claim_adapter.request_of`), sends the claims that can be sent to RightRail's
pinned decision engine through scripts/rightrail_shadow_child.py, maps the answer with `result_of`, names the
difference, and appends one record per claim and one summary under state/shadow/.

Limits to read every record with:
- The request is built directly with RightRail's line encoder.  **RightRail's normal claim intake (its 837 reader and
  `requests_of`) is bypassed, so a run says nothing about that path.**
- Only the pinned engine is used.  It decides by the gate's fixed rules and runs no rule set, so no eligibility (G2)
  decision can appear.
- On a matched scenario the claim's flags and the feed rows are written to say the same thing: **agreement there is by
  construction**.  The scenarios marked `differ` state in advance where the two sides are expected to part.
- The rendering party is the billing NPI, an assumption for tests only.
- No raw member id is written to any record: a member appears only as its keyed form.
- Keys: the key set and grant use RightRail's test-only keys, derived in memory.  RightRail's store fixture also makes
  one epoch key file per store group with the signer's `keygen` mode, sealed and written into the scratch directory and
  removed with it.  The run refuses to start unless SHADOW_ALLOW_SCRATCH_KEYGEN=1 says the owner allowed that.

The run itself is local only: Windows, RightRail's built executables, the signer, and SHADOW_RUN=1, under the memory
guard (scripts/rr_guarded_interim.ps1).  Everything else in this module is pure and is tested in CI.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_elig_extract  # noqa: E402
import g_rule_parity as gp  # noqa: E402
import rightrail_claim_adapter as ad  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scripts" / "tests" / "fixtures" / "shadow" / "scenarios.json"
ROSTER = ROOT / "scripts" / "tests" / "fixtures" / "elig_extract" / "roster_v1.json"
CHILD = ROOT / "scripts" / "rightrail_shadow_child.py"
OUT_DIR = ROOT / "state" / "shadow"
RIGHTRAIL = ROOT / "rightrail"
ENGINE = RIGHTRAIL / "lean" / ".lake" / "build" / "bin" / "gate_engine.exe"
SIGNER_REL = Path("rust") / "gate_mldsa87" / "target" / "release" / "rr_gate_mldsa87.exe"
STATEMENT = ("Test-key run. It decides nothing and binds no one. The decision is the Rust engine's; RightRail's answer "
             "was made under test keys and synthetic feeds and is recorded for comparison only.")
MARKERS = {"synthetic": True, "not_legally_verified": True, "nonpayment": True, "decides_nothing": True, "test_keys": True}
KINDS = ("matched", "differ", "not_sent")
FEEDS = ("dmf", "pdeath", "excl", "span")
FEED_FLAGS = ("eligibility_active", "eligibility_period_from", "eligibility_period_thru", "provider_enrolled",
              "recipient_not_deceased")
CATEGORY_NOTES = dict(gp.CATEGORY_NOTES, **{
    "rightrail_answered_local_approves": "RightRail answers an exact repeat of a paid line without paying it; localBCE approves.",
    "rightrail_answered_local_denies": "RightRail answers an exact repeat of a paid line without paying it; localBCE denies.",
    "not_sent_local_approves": "The adapter set the claim aside, so RightRail was not asked; localBCE approves.",
    "not_sent_local_denies": "The adapter set the claim aside, so RightRail was not asked; localBCE denies.",
    "no_rightrail_answer": "The claim was sent and no usable answer came back.",
})
AGREEMENT = gp.AGREEMENT


class ScenarioError(ValueError):
    pass


# ---- the scenario set

def day(iso: str) -> int:
    """A `YYYY-MM-DD` calendar day as yyyymmdd."""
    d = datetime.date.fromisoformat(iso)
    return d.year * 10000 + d.month * 100 + d.day


def load_scenarios(path: Path = SCENARIOS) -> dict:
    """The scenario set, checked for shape, with each feed set resolved (`like`) and each claim built from the base."""
    doc = json.loads(Path(path).read_text("utf-8"))
    if doc.get("synthetic") is not True:
        raise ScenarioError("the scenario set must say synthetic: true")
    feeds = {}
    for name, f in doc["feeds"].items():
        whole = dict(doc["feeds"][f["like"]]) if "like" in f else {}
        whole.update({k: v for k, v in f.items() if k != "like"})
        if set(whole) != set(FEEDS):
            raise ScenarioError(f"feed set {name} must have exactly {FEEDS}")
        feeds[name] = whole
    names = [s["name"] for s in doc["scenarios"]]
    if len(names) != len(set(names)):
        raise ScenarioError("scenario names repeat")
    stepped = [n for step in doc["steps"] for n in step["scenarios"]]
    if sorted(stepped) != sorted(names):
        raise ScenarioError("every scenario must be in exactly one step")
    for step in doc["steps"]:
        if step["feeds"] not in feeds or step["store"] not in ("main", "separate"):
            raise ScenarioError(f"step {step['name']} names an unknown feed set or store")
    for s in doc["scenarios"]:
        if s["kind"] not in KINDS or s["expect"]["category"] not in CATEGORY_NOTES:
            raise ScenarioError(f"scenario {s['name']} has an unknown kind or category")
        if (s["kind"] == "not_sent") != ("set_aside" in s["expect"]["rightrail"]):
            raise ScenarioError(f"scenario {s['name']}: not_sent and a set-aside go together")
        if s["kind"] == "matched" and (s.get("disagrees_on") or not s["expect"]["category"] in AGREEMENT):
            raise ScenarioError(f"scenario {s['name']}: a matched scenario agrees")
        s["claim"] = dict(copy.deepcopy(doc["base_claim"]), **copy.deepcopy(s["claim"]))
    doc["feeds"] = feeds
    return doc


def flags_from_feeds(claim: dict, feeds: dict) -> dict:
    """What the feed rows say about the claim, as localBCE flags (the parity harness's derivation, from the scenario's
    own feed rows): death, provider standing and enrollment."""
    service = ad.service_day(claim["date_of_service_from"])
    member, npi = claim["member_id"], claim["provider_npi"]
    dead = any(r["member_id"] == member and day(r["date"]) < service for r in feeds["dmf"]["rows"])
    provider_dead = any(r["npi"] == npi and day(r["date"]) < service for r in feeds["pdeath"]["rows"])
    excluded = any(r["npi"] == npi and day(r["from"]) <= service <= day(r["to"]) for r in feeds["excl"]["rows"])
    spans = [r for r in feeds["span"]["rows"] if r["member_id"] == member]
    covering = [r for r in spans if day(r["from"]) <= service <= day(r["to"])]
    period = (covering or spans or [None])[0]

    def count(iso: str) -> int:
        return (datetime.date.fromisoformat(iso) - datetime.date(1970, 1, 1)).days

    return {
        "eligibility_active": 1 if spans else 0,
        "eligibility_period_from": count(period["from"]) if period else 0,
        "eligibility_period_thru": count(period["to"]) if period else 0,
        "provider_enrolled": 0 if (excluded or provider_dead) else 1,
        "recipient_not_deceased": 0 if dead else 1,
    }


def ident(b: bytes) -> int:
    """RightRail's identifier number: 0x01, then the bytes, big-endian (rightrail/app/right_rail_gate_ffs.py `ident`)."""
    return int.from_bytes(b"\x01" + b, "big")


def keyed_feeds(feeds: dict, secret: bytes) -> dict:
    """A feed set as the rows RightRail's `decider.feed` takes: numbers only, members by their keyed form."""
    def member(m: str) -> int:
        return ident(ad.member_key(secret, m))

    def npi(n: str) -> int:
        return ident(n.encode())

    rows = {
        "dmf": [[member(r["member_id"]), day(r["date"])] for r in feeds["dmf"]["rows"]],
        "pdeath": [[npi(r["npi"]), day(r["date"])] for r in feeds["pdeath"]["rows"]],
        "excl": [[npi(r["npi"]), day(r["from"]), day(r["to"])] for r in feeds["excl"]["rows"]],
        "span": [[member(r["member_id"]), ident(r["plan"].encode()), day(r["from"]), day(r["to"])] for r in feeds["span"]["rows"]],
    }
    return {k: {"as_of": day(feeds[k]["as_of"]), "rows": rows[k]} for k in FEEDS}


# ---- comparison and records

def classify(local_status: str, local_reason, rightrail: dict | None) -> str:
    """The category of one claim.  `rightrail` is the adapter's result (`result_of`), or None when a sent claim got no
    usable answer."""
    if local_status not in ("APPROVED", "DENIED"):
        raise ValueError("localBCE's status must be APPROVED or DENIED")
    denies = "denies" if local_status == "DENIED" else "approves"
    if rightrail is None:
        return "no_rightrail_answer"
    outcome = rightrail["rightrail_outcome"]
    if outcome == "SET_ASIDE":
        return "not_sent_local_" + denies
    if outcome == "ANSWERED":
        return "rightrail_answered_local_" + denies
    return gp.classify(gp.Expect(outcome, tuple(rightrail["rightrail_reasons"])), local_status, local_reason)


def record(run_id: str, scenario: dict, secret: bytes, local: tuple, sent, rightrail: dict | None, context: dict) -> dict:
    """One claim's record.  `local` is the Rust engine's (status, reason); `sent` the adapter's `Request` or `SetAside`;
    `rightrail` the adapter's result, or None for no usable answer.  No raw member id is written."""
    claim = scenario["claim"]
    category = classify(local[0], local[1], rightrail)
    want = scenario["expect"]
    got_rr = (None if rightrail is None else {"set_aside": rightrail["rightrail_set_aside_cause"]}
              if rightrail["rightrail_outcome"] == "SET_ASIDE" else
              {"outcome": rightrail["rightrail_outcome"], "reasons": rightrail["rightrail_reasons"]})
    is_request = isinstance(sent, ad.Request)
    return {
        "schema": "localbce.rightrail_shadow_record.v1",
        "statement": STATEMENT,
        **MARKERS,
        "run_id": run_id,
        "scenario": scenario["name"],
        "kind": scenario["kind"],
        "claim_id": claim["claim_id"],
        "claim_hash": ad.claim_hash(claim["claim_id"], claim["claim_amount"]),
        "member_key": ad.member_key(secret, claim["member_id"]).hex(),
        "localbce": {"status": local[0], "reason": local[1], "is_the_decision": True},
        "adapter": {
            "sent": is_request,
            "payment_id": sent.payment_id if is_request else None,
            "lines": len(sent.lines) if is_request else 0,
            "cents": sent.cents,
            "service_date": sent.lines[0].date if is_request else None,
            "set_aside_cause": None if is_request else sent.cause,
            "assumptions": list(sent.assumptions) if is_request else [],
            "intake_bypassed": True,
        },
        "rightrail": None if rightrail is None else {
            "recorded_only": True,
            "outcome": rightrail["rightrail_outcome"],
            "reasons": rightrail["rightrail_reasons"],
            "final": rightrail["rightrail_final"],
            "lines": rightrail["rightrail_lines"],
            "mapped_status": rightrail["status"],
            "mapped_reason": rightrail["reason"],
        },
        "category": category,
        "agreement_is_by_construction": scenario["kind"] == "matched",
        "expected": {"local": want["local"], "rightrail": want["rightrail"], "category": want["category"]},
        "as_expected": [local[0], local[1]] == want["local"] and got_rr == want["rightrail"] and category == want["category"],
        "context": context,
    }


def summary(run_id: str, records: list, context: dict, started: str, ended: str, extract: dict | None) -> dict:
    counts: dict = {}
    for r in records:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    return {
        "schema": "localbce.rightrail_shadow_summary.v1",
        "statement": STATEMENT,
        **MARKERS,
        "run_id": run_id,
        "started": started,
        "ended": ended,
        "claims": len(records),
        "sent": sum(r["adapter"]["sent"] for r in records),
        "set_aside": sum(not r["adapter"]["sent"] for r in records),
        "no_rightrail_answer": counts.get("no_rightrail_answer", 0),
        "by_category": dict(sorted(counts.items())),
        "matched_scenarios": sum(r["kind"] == "matched" for r in records),
        "matched_note": "Agreement on a matched scenario is by construction: its flags and feed rows were written to say the same thing.",
        "as_expected": sum(r["as_expected"] for r in records),
        "not_as_expected": [r["scenario"] for r in records if not r["as_expected"]],
        "intake_note": "Requests were built directly with RightRail's line encoder; its normal claim intake was bypassed, so this run says nothing about that path.",
        "eligibility_extract": extract,
        "context": context,
    }


def _write_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def write_out(out_dir: Path, records: list, summ: dict) -> tuple[Path, Path]:
    """Append the records to `rightrail_shadow.jsonl` and replace `summary.json`, under `out_dir`.  Refuses a place
    under rightrail/ or parked/."""
    out_dir = Path(out_dir).resolve()
    for base in ((ROOT / "rightrail").resolve(), (ROOT / "parked").resolve()):
        if out_dir == base or base in out_dir.parents:
            raise ValueError("refused: output path")
    text = json.dumps([records, summ], sort_keys=True)
    if any(raw and raw in text for raw in _RAW_MEMBER_IDS):
        raise ValueError("refused: a raw member id is in the records")
    out_dir.mkdir(parents=True, exist_ok=True)
    log, summary_path = out_dir / "rightrail_shadow.jsonl", out_dir / "summary.json"
    lines = b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in records)
    _write_atomic(log, (log.read_bytes() if log.exists() else b"") + lines)
    _write_atomic(summary_path, (json.dumps(summ, indent=2, sort_keys=True) + "\n").encode())
    return log, summary_path


_RAW_MEMBER_IDS: set = set()  # filled by `job_of` and `build_records`; used only to refuse a leak into the records


# ---- the run (local only)

def signer_path() -> Path | None:
    named = os.environ.get("RR_GATE_SIGNER")
    for p in ([Path(named)] if named else []) + [RIGHTRAIL / SIGNER_REL, ROOT.parent / "rightrail" / SIGNER_REL]:
        if p.is_file():
            return p
    return None


def cannot_run() -> str | None:
    """Why the run cannot start here, or None."""
    if os.environ.get("SHADOW_RUN") != "1":
        return "local only: set SHADOW_RUN=1 and run under the memory guard (scripts/rr_guarded_interim.ps1)"
    if os.name != "nt":
        return "RightRail's host runs the Windows executables"
    missing = [str(p) for p in (ENGINE,) if not p.is_file()] + ([] if signer_path() else ["the signer rr_gate_mldsa87.exe"])
    if missing:
        return "absent: " + "; ".join(missing)
    if os.environ.get("SHADOW_ALLOW_SCRATCH_KEYGEN") != "1":
        return ("not allowed: RightRail's store fixture makes an epoch key file with the signer's `keygen` mode in the "
                "scratch directory; set SHADOW_ALLOW_SCRATCH_KEYGEN=1 only with the owner's approval")
    return None


def job_of(doc: dict) -> tuple[dict, dict]:
    """(the child's job, each scenario's `Request` or `SetAside`).  The job holds no raw member id."""
    secret = doc["secret"].encode()
    by_name = {s["name"]: s for s in doc["scenarios"]}
    sent, steps = {}, []
    for step in doc["steps"]:
        requests = []
        for name in step["scenarios"]:
            claim = by_name[name]["claim"]
            _RAW_MEMBER_IDS.add(claim["member_id"])
            got = sent[name] = ad.request_of(claim, secret)
            if isinstance(got, ad.Request):
                evidence = hashlib.sha3_512(json.dumps(claim, sort_keys=True).encode()).hexdigest()
                requests.append({"scenario": name, "payment_id": got.payment_id, "member_key": got.member_key,
                                 "payee": got.payee, "cents": got.cents, "evidence": evidence,
                                 "lines": [{"line_id": ln.line_id, "rendering": ln.rendering, "date": ln.date,
                                            "procedure": ln.procedure, "units": ln.units, "cents": ln.cents} for ln in got.lines]})
        steps.append({"name": step["name"], "store": step["store"], "feeds_name": step["feeds"],
                      "feeds": keyed_feeds(doc["feeds"][step["feeds"]], secret), "requests": requests})
    extract, report = build_elig_extract.build(json.loads(ROSTER.read_text("utf-8")), 1)
    return ({"today": day(doc["today"]), "steps": steps,
             "extract": {"hex": extract.hex(), "scope": "LOCALBCE-SYN-STATE", "file_sha3_512": report["file_sha3_512"]}}, sent)


def local_decisions(doc: dict, engine: str) -> dict:
    """The Rust engine's (status, reason) for every scenario: the decision.  Its result files are scratch copies."""
    out = {}
    with tempfile.TemporaryDirectory(prefix="shadow_local_") as work:
        for s in doc["scenarios"]:
            out[s["name"]] = gp.run_engine(engine, s["claim"], work)
    return out


def build_records(doc: dict, run_id: str, local: dict, sent: dict, answer: dict) -> list:
    """The records of a run from the Rust engine's answers, the adapter's requests and the child's `answer`."""
    secret = doc["secret"].encode()
    _RAW_MEMBER_IDS.update(s["claim"]["member_id"] for s in doc["scenarios"])
    rows_by_payment: dict = {}
    for step in answer["steps"]:
        for pid, at, outcome, reasons in step["rows"]:
            rows_by_payment.setdefault(pid, []).append((pid, at, outcome, tuple(reasons)))
    step_of = {n: step for step in doc["steps"] for n in step["scenarios"]}
    answered = {step["name"]: step for step in answer["steps"]}
    records = []
    for s in doc["scenarios"]:
        got, name = sent[s["name"]], s["name"]
        if isinstance(got, ad.SetAside):
            rightrail = ad.result_of(s["claim"], got)
        else:
            try:
                rightrail = ad.result_of(s["claim"], (got, rows_by_payment.get(got.payment_id, [])))
            except ad.NoDecision:
                rightrail = None
        step = answered.get(step_of[name]["name"], {})
        context = {"engine": answer["engine"], "rule_set": "none", "keys": "test keys", "batch_date": answer["today"],
                   "step": step_of[name]["name"], "feeds": step_of[name]["feeds"], "feed_digests": step.get("feed_digests"),
                   "checkpoint_digests": step.get("checkpoint_digests"), "scenario_set_sha3_512": answer["scenario_set_sha3_512"]}
        records.append(record(run_id, s, secret, local[name], got, rightrail, context))
    return records


def run(out_dir: Path = OUT_DIR, engine: str | None = None) -> dict:
    """One shadow run.  Returns the summary."""
    why = cannot_run()
    if why:
        raise RuntimeError(why)
    engine = engine or str(ROOT / "rust-engine" / "target" / "debug" / "rust-engine.exe")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    run_id = "shadow-" + started.replace(":", "").replace("-", "")
    doc = load_scenarios()
    local = local_decisions(doc, engine)
    job, sent = job_of(doc)
    job["signer"] = str(signer_path())
    job["allow_scratch_keygen"] = os.environ.get("SHADOW_ALLOW_SCRATCH_KEYGEN") == "1"
    done = subprocess.run([sys.executable, "-B", str(CHILD)], input=json.dumps(job).encode(), capture_output=True,
                          timeout=3600, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if done.returncode != 0:
        raise RuntimeError(f"the RightRail side failed (exit {done.returncode}): {done.stderr.decode(errors='replace')[-2000:]}")
    answer = json.loads(done.stdout)
    answer["scenario_set_sha3_512"] = hashlib.sha3_512(SCENARIOS.read_bytes()).hexdigest()
    records = build_records(doc, run_id, local, sent, answer)
    ended = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    context = {"engine": answer["engine"], "rule_set": "none", "keys": "test keys", "batch_date": answer["today"],
               "scenario_set_sha3_512": answer["scenario_set_sha3_512"], "stores_removed": answer["stores_removed"],
               "scratch_dir": answer.get("scratch_dir")}
    summ = summary(run_id, records, context, started, ended, answer.get("extract"))
    write_out(out_dir, records, summ)
    return summ


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--engine", help="the built rust-engine binary")
    args = ap.parse_args(argv)
    why = cannot_run()
    if why:
        print("not run: " + why, file=sys.stderr)
        return 3
    summ = run(args.out_dir, args.engine)
    print(STATEMENT)
    print(json.dumps({k: summ[k] for k in ("run_id", "claims", "sent", "set_aside", "by_category", "as_expected", "not_as_expected")},
                     sort_keys=True))
    return 0 if not summ["not_as_expected"] else 1


if __name__ == "__main__":
    sys.exit(main())
