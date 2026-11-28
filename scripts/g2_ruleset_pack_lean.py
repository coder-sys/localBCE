#!/usr/bin/env python3
"""Put the G2 rule-set pack's records to RightRail's Lean tool `ruleset_admit`, with test keys.  Local only.

Prints one JSON object with the Lean tool's raw answer lines:

- `eval`: for the eligibility-only and the full record as built (not signed), every case of
  rules/rightrail_packs/g2_elig_v2.expected.json as an EVAL question (the gate's own `dataFires`).
- `admit`: admission of copies of both records signed with test keys, and of copies that must be refused.

**A test-key admission checks mechanics only. It is not a real signed rule set.**  The keys are RightRail's fixed
test-only keys, derived in this process from public constants (`RR/GATE/TEST-ONLY-SEED/v1`) by the signer's
known-answer mode `kat-keygen`, which reads a seed and writes nothing.  No key or seed file is made, `keygen` is never
run, and the keys are gone when the process ends.  The admitted copies carry the test fixture's state, tenant and
signing window in place of the source's, so their digests are not the pinned ones.  Nobody with authority over a rule
set has signed anything.

Needs two executables that CI does not have: `rightrail/lean/.lake/build/bin/ruleset_admit.exe` (from `lake build`)
and the pinned signer `rr_gate_mldsa87.exe` (in this checkout, in a RightRail clone beside it, or at RR_GATE_SIGNER).
Exits 3 and names what is absent.  Run it with `python -B` so no bytecode is written; it writes no file itself.
Synthetic, not legally verified, nonpayment.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_g2_ruleset_pack as gp  # noqa: E402

RIGHTRAIL = gp.ROOT / "rightrail"
ADMIT_EXE = RIGHTRAIL / "lean" / ".lake" / "build" / "bin" / "ruleset_admit.exe"
SIGNER_REL = Path("rust") / "gate_mldsa87" / "target" / "release" / "rr_gate_mldsa87.exe"
FLOW = 2


def signer_path() -> Path | None:
    """The signer executable: named by RR_GATE_SIGNER, in this checkout, or in a RightRail clone beside it."""
    named = os.environ.get("RR_GATE_SIGNER")
    for p in ([Path(named)] if named else []) + [RIGHTRAIL / SIGNER_REL, gp.ROOT.parent / "rightrail" / SIGNER_REL]:
        if p.is_file():
            return p
    return None


def absent() -> list:
    """What this check needs and does not find, by name."""
    out = [] if ADMIT_EXE.is_file() else [f"ruleset_admit.exe (Lean build) at {ADMIT_EXE}"]
    return out if signer_path() else out + ["the signer rr_gate_mldsa87.exe"]


def block(code: bytes) -> bytes:
    return bytes([len(code)]) + code + bytes(20 - len(code))


def to_read(r: dict) -> dict:
    aids = [bytes.fromhex(a["hex"]) if isinstance(a, dict) else block(a.encode()) for a in r["aids"]]
    return {"ans": r["ans"], "status": r["status"], "asof": r["asof"], "aids": aids}


def run() -> dict:
    os.chdir(RIGHTRAIL)
    sys.path.insert(0, str(RIGHTRAIL))
    from app import right_rail_gate_signer as signer
    # Set before the fixtures are imported: they sign at import.  The wrapper checks the executable against the pin
    # in this checkout's rightrail/ on every call.
    signer.BINARY = signer_path()
    from tests import _gate_authority as au
    from tests import test_right_rail_gate_formats as fx
    from tests import test_ruleset_admission as ra
    from tests import test_ruleset_v1_codec as rs
    from tests import test_ruleset_v2 as v2

    records = gp.records(gp.load_source())
    cases = json.loads(gp.EXPECTED.read_text("utf-8"))["cases"]
    names = ["elig_only", "full"]

    # EVAL: the records exactly as built.  They are not signed, so each is refused admission and still evaluated.
    questions = [(i, c["service"], FLOW, to_read(c["read"]), c["batch"]) for i in range(len(names)) for c in cases]
    lines = v2.lean([gp.codec.encode(records[n]) for n in names], questions)
    out = {"eval": {"records": names, "cases": [c["name"] for c in cases], "flow": FLOW,
                    "admission": lines[:len(names)], "answers": lines[len(names):]}}

    # Admission: copies under the test fixture's state, tenant and window, signed by its two test policy keys.
    admit = {}
    for n in names:
        d = dict(records[n], state=au.STATE, tenant=fx.TENANT, not_before=ra.NB, not_after=ra.NA)
        d.pop("sigs")
        body = v2.body(d)
        if body != gp.codec.encode(dict(d, sigs=records[n]["sigs"]))[:len(body)]:
            raise AssertionError("the test encoder and the codec disagree on the body")
        benefit = dict(d, rules=sorted([(24, 0, ("present", 7))] + d["rules"]))
        got = {
            "digest": hashlib.sha3_512(body).hexdigest(),
            "signed": v2.lean([v2.signed_v2(d)]),
            "signed_under_v1_tag": v2.lean([v2.signed_v2(d, tag=rs.SIGTAG)]),
            "one_signer": v2.lean([body + rs.sigs({"sigs": [(au.key_id("p1"), fx.det_sign(
                "authority-p1", hashlib.sha3_512(v2.SIGTAG2 + body).digest()))]})]),
            "benefit_level_rule": v2.lean([v2.signed_v2(benefit)]),
        }
        admit[n] = got
    out["admit"] = admit
    return out


def main() -> int:
    missing = absent()
    if missing:
        print("absent: " + "; ".join(missing), file=sys.stderr)
        return 3
    print(json.dumps(run()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
