"""G-rule parity harness (RIGHTRAIL_BASE_PLAN.md Phase 2, test-only).

Runs localBCE's `denial_reason()` (through the built `rust-engine` binary) and
RightRail's Lean gate rules (their expected results, as recorded in
`tests/fixtures/rightrail_rules_v1.vectors`, a frozen copy of the retired
`rightrail/tests/gate_rules/rules_v1.vectors` at trunk fc89f9e5, provenance in
`tests/fixtures/rightrail_rules_v1.vectors.source.json`, checked by the Lean runner before G2)
on the same synthetic lines, and reports every difference for G1/G3/G5/G7/G9.

This is a comparison tool, not a decider.  It writes nothing into `rightrail/`
and nothing it prints is a determination (CONST I.3, V.1).

The two engines take different inputs.  Lean reads pinned snapshots (death
lists, exclusions, enrollment spans, the released and unresolved sets); localBCE
reads per-claim flags.  This harness derives the flags from the same snapshot
rows (`derive_claim`), so a difference means the rules disagree on the same
facts, or the Lean rule reads something localBCE has no input for (staleness,
the unresolved set, member-months).  The derivation is this harness's
assumption and is listed in the report.

Usage:
  python3 scripts/g_rule_parity.py --engine PATH [--vectors PATH] [--json OUT] [--markdown OUT]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Frozen copy (plan decision 13): RightRail retired Gate rules v1 at G2 and deleted the file; G2 stays an always-passing
# gate here (PASSING_FLAGS), so the v1 lines, which carry no eligibility, are still the comparison set.
DEFAULT_VECTORS = os.path.join(ROOT, "tests", "fixtures", "rightrail_rules_v1.vectors")

# localBCE denial reason -> the RightRail reasons the plan maps it onto (§3).
G_TO_LEAN = {
    "G1_IDENTITY_VERIFICATION_FAILED": {"MEMBER_NOT_ENROLLED"},
    "G3_MONTH_OF_SERVICE_FAILED": {"MEMBER_NOT_ENROLLED"},
    "G5_PROVIDER_NOT_ENROLLED": {"PROVIDER_EXCLUDED", "PROVIDER_DECEASED"},
    "G7_DUPLICATE_CLAIM": {"FFS_DUPLICATE_LINE"},
    "G9_RECIPIENT_DECEASED": {"MEMBER_DECEASED"},
    # G2's aid code test, as the rule-set v2 pack writes it (reason bit 26; G2_RULESET_V2_DESIGN.md).  Compared
    # only on the pack's own cases (G2_PACK_CASES): the v1 lines carry no eligibility.
    "G2_PROGRAM_ELIGIBILITY_FAILED": {"PROGRAM_NOT_ELIGIBLE"},
}
MAPPED_LEAN = set().union(*G_TO_LEAN.values())

# The G2 pack's case table: each case's eligibility read and the reasons the pack fires on it.  Those reasons are
# pinned there and checked against RightRail's Python reference in CI and its Lean model locally
# (scripts/tests/test_g2_ruleset_pack*.py); no gate runs the pack.
G2_PACK_CASES = os.path.join(ROOT, "rules", "rightrail_packs", "g2_elig_v2.expected.json")
G2_SET, V1_SET = "g2_pack", "rules_v1"
G2_REASONS = {26: "PROGRAM_NOT_ELIGIBLE", 27: "PROGRAM_NOT_ELIGIBLE_UNVERIFIED", 28: "STALE_ELIGIBILITY"}
G2_OUTCOMES = {"allow": "ALLOW", "hold": "HOLD", "review": "HUMAN_REVIEW"}
G2_NOT_COMPARED = "G2_BENEFIT_LEVEL_MISSING"  # the eligibility fact has no benefit level; the pack cannot test it
LOCAL_AID_CODES = (13, 23, 53, 103, 104)  # denial_reason()'s list; test_g2_ruleset_pack.py pins the pack's to it

G2_ASSUMPTIONS = [
    "G2 pack cases: the RightRail side is the pack's pinned expected reasons for the case's eligibility read "
    "(26 PROGRAM_NOT_ELIGIBLE holds; 27 PROGRAM_NOT_ELIGIBLE_UNVERIFIED and 28 STALE_ELIGIBILITY send the line to a "
    "person), not the result of a running gate.",
    "G2 aid_code = the first cited aid code that is on localBCE's list; else the first cited code that is a "
    "number; else 0 (no cited code, or only malformed ones), which is not on the list.",
    "G1 eligibility_active = 1 when the read's answer is present with status eligible or presumptive; 0 for "
    "not eligible, pending, or an absent, unknown or conflicting answer.  Presumptive and pending follow the "
    "pack's own unverified policy choices.",
    "The read's as-of, the batch date and whether the service date is a calendar date are not localBCE inputs: "
    "localBCE has no freshness test.  The eligibility period is set to cover every date, so G3 passes.",
    "G2_BENEFIT_LEVEL_MISSING is not compared: benefit_level_exists is set to 1, and the pack's four "
    "benefit-level cases are listed as blocked, not run.",
]

# Flags for gates the harness does not compare (G2 on the v1 lines, G4, G6, G8, G10): always passing.
PASSING_FLAGS = {
    "aid_code": 13,
    "benefit_level_exists": 1,
    "soc_amount": 0,
    "soc_met": 1,
    "provider_type_valid": 1,
    "billing_code_valid": 1,
    "units_valid": 1,
    "disability_determination_valid": 1,
    "physician_certification_valid": 1,
}

ASSUMPTIONS = [
    "G9 recipient_not_deceased = 0 when a DMF row for the member is dated strictly before the service date "
    "(the snapshot's rows, whether or not Lean finds the snapshot usable).",
    "G1 eligibility_active = 0 when the member has no enrollment span at all; otherwise 1.",
    "G3 eligibility period = the span covering the service date (for CAP_820, with the paying plan); with no "
    "covering span, the member's first span, so G3 fires.",
    "G5 provider_enrolled = 0 when the payee or rendering party is on the exclusion rows on the service date, "
    "or on the provider death rows dated before it.",
    "G7 is_duplicate = 1 when the line's exact key (flow kind, member, payee, date, procedure, units, cents) is "
    "on a released-set row, on an earlier ALLOW line of the same case, or on an earlier line of the same batch "
    "in Lean's canonical order.  The unresolved set and near keys are not localBCE inputs.",
    "An earlier commit releases a line only when every line of its payment is ALLOW and the payment is not "
    "being decided again (`redo`); a re-decided payment's own released line is not its own duplicate.",
    "The gate's own checkpoint of the released and unresolved sets (used when a set read does not chain) is not "
    "modelled: localBCE has no checkpoint, so only the rows of the set read count.",
    "On the v1 lines the G2, G4, G6, G8 and G10 flags are set to passing values: those lines carry no "
    "eligibility, and no RightRail rule exists for G4, G6, G8 or G10 yet.",
    "A dropped snapshot, or one whose rows do not hash to its declared pin, contributes no rows: Lean treats "
    "both as missing (Run.lean `snapshot`).",
    "A line the vector gives no expected result is not compared, and is not counted as released for later "
    "commits (its Lean result is unknown here).",
    "Dates are given to the Rust engine as yyyymmdd numbers, not in its stated encoding (integer days since "
    "1970-01-01, rust-engine/rules.json).  The engine only compares a claim's dates with each other (G3), and "
    "yyyymmdd numbers sort as day counts do, so no result depends on it: checked on 2026-11-28, all 288 lines with a "
    "calendar service date give the same status and reason in both encodings.  The 20 lines whose service date is "
    "not a calendar date (13 v1 lines, 7 G2 pack cases) have no day count; they can be shown to the engine only "
    "in this encoding, and a converter would set such a claim aside instead.",
]


@dataclass(frozen=True)
class Line:
    id: int
    pay: int
    flow: str
    member: int
    payee: int
    rendering: int
    date: int
    proc: int
    units: int
    cents: int

    def exact_key(self):
        kind = 3 if self.flow == "CAP_820" else 1
        return (kind, self.member, self.payee, self.date, self.proc, self.units, self.cents)

    def enc(self):
        tag = {"FFS_CYCLE": 1, "FFS_CLAIM": 2, "CAP_820": 3}[self.flow]
        return (tag, self.member, self.payee, self.rendering, self.date, self.proc, self.units, self.cents,
                self.id, self.pay)


@dataclass
class Expect:
    outcome: str
    reasons: tuple


@dataclass
class Case:
    name: str
    batches: list = field(default_factory=list)  # list of list[(Line, Expect, facts, case_allowed)]
    redo: list = field(default_factory=list)  # per batch: the payments it decides again


class VectorError(ValueError):
    pass


# Pins (Spec.lean `pinInput`, Run.lean `St.pin`): SHA3-512 over DOMAIN, NUL, the u32 kind, date and count,
# then each row's fixed-width big-endian fields, rows in ascending byte order.  A value too wide fails the pin.
ID_W, PAY_W = 129, 261
PIN_KINDS = {
    "dmf": ("RR/GATE/SNAPSHOT/v1", 1, lambda r: [(ID_W, r[0]), (4, r[1])]),
    "pdeath": ("RR/GATE/SNAPSHOT/v1", 2, lambda r: [(ID_W, r[0]), (4, r[1])]),
    "excl": ("RR/GATE/SNAPSHOT/v1", 3, lambda r: [(ID_W, r[0]), (4, r[1]), (4, r[2])]),
    "span": ("RR/GATE/SNAPSHOT/v1", 4, lambda r: [(ID_W, r[0]), (ID_W, r[1]), (4, r[2]), (4, r[3])]),
    "released": ("RR/GATE/RELEASED/v1", 5, None),
    "unresolved": ("RR/GATE/UNRESOLVED/v1", 6, None),
}
FLOW_TAG = {"FFS_CYCLE": 1, "FFS_CLAIM": 2, "CAP_820": 3}


def _line_fields(l):
    return [(ID_W, l.id), (PAY_W, l.pay), (1, FLOW_TAG[l.flow]), (ID_W, l.member), (ID_W, l.payee),
            (ID_W, l.rendering), (4, l.date), (ID_W, l.proc), (4, l.units), (8, l.cents)]


def _be(fields):
    out = b""
    for width, value in fields:
        if value >= 256 ** width:
            return None
        out += value.to_bytes(width, "big")
    return out


def snapshot_pin(kind, as_of, count, rows):
    """The hex pin Lean computes for a declared snapshot, or None when a value does not fit."""
    domain, k, fields = PIN_KINDS[kind]
    fields = fields or _line_fields
    head = _be([(4, k), (4, as_of), (4, count)])
    body = [_be(fields(r)) for r in rows]
    if head is None or any(b is None for b in body):
        return None
    return hashlib.sha3_512(domain.encode("utf-8") + b"\x00" + head + b"".join(sorted(body))).hexdigest()


def released_by(batch, redo):
    """Exact keys a committed batch adds to the released set, per the vectors' expected outcomes: the lines
    of payments whose every line is ALLOW, except a re-decided payment's (released already)."""
    by_pay = {}
    for ln, ex, _, _ in batch:
        by_pay.setdefault(ln.pay, []).append((ln, ex))
    out = []
    for pay, items in by_pay.items():
        if pay in redo:
            continue
        if all(ex is not None and ex.outcome == "ALLOW" for _, ex in items):
            out += [ln for ln, _ in items]
    return out


def parse_line_fields(fs):
    if len(fs) != 9:
        raise VectorError(f"line needs 9 fields, got {fs}")
    ident = fs[0].split(":")
    lid = int(ident[0])
    pay = int(ident[1]) if len(ident) > 1 else lid
    if fs[1] not in ("FFS_CYCLE", "FFS_CLAIM", "CAP_820"):
        raise VectorError(f"unknown flow {fs[1]}")
    nums = [int(x) for x in fs[2:]]
    return Line(lid, pay, fs[1], *nums)


def parse_vectors(text):
    """Replay the vector directives that rules_v1 uses and capture, per line, the rows Lean read."""
    rows = {k: [] for k in ("dmf", "pdeath", "excl", "span", "released", "unresolved")}
    present = {k: False for k in rows}
    cases = []
    case = None
    batch = []
    redo = []  # payments the next commit decides again
    case_allowed = []  # exact keys released by earlier commits of this case

    decl = {}  # kind -> (asOf, count, declared pin)

    def snapshot_facts():
        def live(k):
            # Lean treats a snapshot whose pin does not match its rows as missing (Run.lean `snapshot`).
            if not present[k] or k not in decl:
                return []
            as_of, count, declared = decl[k]
            return list(rows[k]) if snapshot_pin(k, as_of, count, rows[k]) == declared else []
        return {
            "dmf": live("dmf"),
            "pdeath": live("pdeath"),
            "excl": live("excl"),
            "span": live("span"),
            "released": live("released"),
        }

    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        fs = s.split()
        k = fs[0]
        if k == "today":
            continue
        elif k == "case":
            case = Case(fs[1])
            cases.append(case)
            batch, case_allowed, redo = [], [], []
        elif k == "snap":
            if len(fs) != 5:
                raise VectorError(f"line {n}: snap needs KIND ASOF COUNT PIN")
            rows[fs[1]] = []
            present[fs[1]] = True
            decl[fs[1]] = (int(fs[2]), int(fs[3]), fs[4])
            if fs[1] == "released":
                case_allowed = []
        elif k == "drop":
            present[fs[1]] = False
        elif k in ("dmf", "pdeath"):
            rows[k].append((int(fs[1]), int(fs[2])))
        elif k == "excl":
            rows[k].append((int(fs[1]), int(fs[2]), int(fs[3])))
        elif k == "span":
            rows[k].append((int(fs[1]), int(fs[2]), int(fs[3]), int(fs[4])))
        elif k in ("released", "unresolved"):
            rows[k].append(parse_line_fields(fs[1:]))
        elif k == "line":
            if case is None:
                raise VectorError(f"line {n}: line before any case")
            line = parse_line_fields(fs[1:10])
            e = fs[10:]
            if len(e) == 0:
                # The vector records no Lean result for this line (the runner checks all lines of a commit or
                # none; rules_v1 uses this only for a `commit UNANCHORED` batch, which Lean refuses).
                expect = None
            elif len(e) in (2, 3):
                expect = Expect(e[0], () if e[1] == "-" else tuple(e[1].split(",")))
            else:
                raise VectorError(f"line {n}: malformed expectation {e}")
            batch.append((line, expect, snapshot_facts(), list(case_allowed)))
        elif k == "commit":
            case.batches.append(batch)
            case.redo.append(set(redo))
            case_allowed += released_by(batch, redo)
            batch, redo = [], []
        elif k == "redo":
            redo.append(int(fs[1]))
        elif k in ("pay", "anchor", "end", "report"):
            continue  # payment-level and checkpoint directives: not line rules
        else:
            raise VectorError(f"line {n}: unsupported directive {k}")
    if batch:
        raise VectorError("vector file ends with an uncommitted batch")
    return cases


def is_own(line, released_lines, redo):
    """Lean `own`: a line of a payment decided again that the released set already holds."""
    return line.pay in redo and line in released_lines


def derive_claim(line, facts, earlier_keys, redo=frozenset()):
    """ClaimInput flags for one line, from the rows Lean read (see ASSUMPTIONS).  `facts["released"]` holds
    the released set's lines (snapshot rows plus this case's earlier releases)."""
    date = line.date
    dead = any(m == line.member and d < date for m, d in facts["dmf"])
    spans = [s for s in facts["span"] if s[0] == line.member]
    covering = [s for s in spans if s[2] <= date <= s[3] and (line.flow != "CAP_820" or s[1] == line.payee)]
    if covering:
        period = (covering[0][2], covering[0][3])
    elif spans:
        period = (spans[0][2], spans[0][3])
        if period[0] <= date <= period[1]:  # a span with another plan covers the date (CAP_820)
            period = (0, 0)
    else:
        period = (0, 0)
    parties = {line.payee, line.rendering}
    excluded = any(i in parties and a <= date <= b for i, a, b in facts["excl"])
    provider_dead = any(i in parties and d < date for i, d in facts["pdeath"])
    # A re-decided payment's own released lines are not duplicates of themselves (Lean `seen0`, `own`).
    released_keys = {r.exact_key() for r in facts["released"] if not (r.pay in redo and r == line)}
    dup = line.exact_key() in released_keys or line.exact_key() in earlier_keys
    claim = {
        "claim_id": f"RRV-{line.id}",
        "claim_amount": line.cents,
        "member_id": f"SYN-{line.member}",
        "provider_npi": f"SYN-{line.payee}",
        "eligibility_active": 1 if spans else 0,
        "date_of_service_from": date,
        "eligibility_period_from": period[0],
        "eligibility_period_thru": period[1],
        "provider_enrolled": 0 if (excluded or provider_dead) else 1,
        "is_duplicate": 1 if dup else 0,
        "recipient_not_deceased": 0 if dead else 1,
    }
    claim.update(PASSING_FLAGS)
    return claim


def load_g2_cases(path=G2_PACK_CASES):
    """(cases, blocked) of the G2 pack's case table."""
    with open(path, encoding="utf-8") as f:
        table = json.load(f)
    return table["cases"], table["blocked"]


def g2_expect(case):
    """What the pack decides for the case, as an `Expect`."""
    return Expect(G2_OUTCOMES[case["outcome"]], tuple(G2_REASONS[b] for b in case["expect"]))


def derive_g2_claim(case, index):
    """ClaimInput flags for one G2 pack case, from its eligibility read (see G2_ASSUMPTIONS)."""
    read = case["read"]
    codes = [int(a) for a in read["aids"] if isinstance(a, str) and a.isascii() and a.isdigit()]
    listed = [c for c in codes if c in LOCAL_AID_CODES]
    claim = {
        "claim_id": f"G2P-{index}",
        "claim_amount": 100,
        "member_id": "SYN-G2",
        "provider_npi": "SYN-G2",
        "eligibility_active": 1 if read["ans"] == 0 and read["status"] in (1, 4) else 0,
        "date_of_service_from": case["service"],
        "eligibility_period_from": 0,
        "eligibility_period_thru": 99999999,
        "provider_enrolled": 1,
        "is_duplicate": 0,
        "recipient_not_deceased": 1,
    }
    claim.update(PASSING_FLAGS)
    claim["aid_code"] = (listed or codes or [0])[0]
    return claim


def compare_g2(cases, engine):
    records = []
    with tempfile.TemporaryDirectory(prefix="g_rule_parity_") as work:
        for index, case in enumerate(cases, 1):
            expect = g2_expect(case)
            claim = derive_g2_claim(case, index)
            status, reason = run_engine(engine, claim, work)
            records.append({
                "set": G2_SET,
                "case": case["name"],
                "batch": 0,
                "line_id": index,
                "flow": "-",
                "lean_outcome": expect.outcome,
                "lean_reasons": list(expect.reasons),
                "localbce_status": status,
                "localbce_reason": reason,
                "category": classify(expect, status, reason),
                "derived_flags": {k: claim[k] for k in ("eligibility_active", "aid_code", "benefit_level_exists")},
            })
    return records


def run_engine(engine, claim, workdir):
    claim_path = os.path.join(workdir, "claim_input.json")
    config_path = os.path.join(workdir, "config.json")
    result_path = os.path.join(workdir, "adjudication_result.json")
    with open(claim_path, "w", encoding="utf-8") as f:
        json.dump(claim, f)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({"proof_execution_enabled": False, "proof_backend": "none", "rules_backend": "hardcoded_g1_g10"}, f)
    if os.path.exists(result_path):
        os.remove(result_path)
    env = dict(os.environ, LOCALBCE_CONFIG_PATH=config_path, LOCALBCE_CLAIM_INPUT_PATH=claim_path)
    run = subprocess.run([engine], cwd=workdir, env=env, capture_output=True, text=True, timeout=60)
    if run.returncode != 0:
        raise RuntimeError(f"rust-engine failed on {claim['claim_id']}: {run.stderr.strip()}")
    with open(result_path, encoding="utf-8") as f:
        result = json.load(f)
    if result.get("tx_submitted") is not False or result.get("tx_hash") is not None:
        raise RuntimeError(f"rust-engine reported a chain submission for {claim['claim_id']}")
    return result["status"], result["reason"]


def classify(expect, status, reason):
    if expect is None:
        return "no_lean_expectation"
    lean = set(expect.reasons)
    if expect.outcome == "ALLOW":
        return "agree_allow" if status == "APPROVED" else "local_denies_lean_allows"
    if expect.outcome == "HUMAN_REVIEW":
        if status == "DENIED":
            return "lean_review_local_denies"
        return "lean_review_local_approves"
    # HOLD
    if status == "DENIED":
        return "agree_hold" if G_TO_LEAN.get(reason, set()) & lean else "hold_reason_differs"
    if lean & MAPPED_LEAN:
        return "lean_holds_on_mapped_rule_local_approves"
    return "lean_holds_on_unmapped_rule_local_approves"


# Which categories are differences, and what each one means for review.
CATEGORY_NOTES = {
    "no_lean_expectation": "The vector records no Lean result for the line (in rules_v1, only a `commit "
                           "UNANCHORED` batch, which Lean refuses at its checkpoint), so there is nothing to "
                           "compare; localBCE has no checkpoint and decides the line anyway.",
    "agree_allow": "Both pass the line.",
    "agree_hold": "Both stop the line, for a mapped reason.",
    "hold_reason_differs": "Both stop the line, but localBCE's first failing gate does not map to any Lean reason given.",
    "local_denies_lean_allows": "localBCE denies a line Lean allows: a mapped rule disagrees on the same facts.",
    "lean_holds_on_mapped_rule_local_approves": "Lean holds on a mapped rule (R1/R3/R4/R5) and localBCE approves.",
    "lean_holds_on_unmapped_rule_local_approves": "Lean holds only on a rule localBCE has no input for "
                                                  "(ALREADY_DECIDED, DUPLICATE_OF_UNRESOLVED, CAP member-month).",
    "lean_review_local_approves": "Lean sends the line to a person (stale or unverified data, near duplicate, bad "
                                  "date); localBCE has no review outcome and approves.",
    "lean_review_local_denies": "Lean sends the line to a person; localBCE denies it outright.",
}
AGREEMENT = {"agree_allow", "agree_hold"}


def compare(cases, engine):
    records = []
    with tempfile.TemporaryDirectory(prefix="g_rule_parity_") as work:
        for case in cases:
            for bi, batch in enumerate(case.batches):
                redo = case.redo[bi]

                def released_lines(item):
                    return item[2]["released"] + item[3]

                # Lean `order`: a re-decision's own lines first, then the rest, each canonical.
                ordered = sorted(batch, key=lambda item: (not is_own(item[0], released_lines(item), redo),
                                                          item[0].enc()))
                earlier_in_batch = []
                for item in ordered:
                    line, expect, facts, _ = item
                    facts = dict(facts, released=released_lines(item))
                    claim = derive_claim(line, facts, set(earlier_in_batch), redo)
                    status, reason = run_engine(engine, claim, work)
                    earlier_in_batch.append(line.exact_key())
                    records.append({
                        "set": V1_SET,
                        "case": case.name,
                        "batch": bi,
                        "line_id": line.id,
                        "flow": line.flow,
                        "lean_outcome": expect.outcome if expect else None,
                        "lean_reasons": list(expect.reasons) if expect else [],
                        "localbce_status": status,
                        "localbce_reason": reason,
                        "category": classify(expect, status, reason),
                        "derived_flags": {k: claim[k] for k in (
                            "eligibility_active", "eligibility_period_from", "eligibility_period_thru",
                            "provider_enrolled", "is_duplicate", "recipient_not_deceased")},
                    })
    return records


def _counts(records):
    counts = {}
    for r in records:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    return {
        "lines": len(records),
        "agreements": sum(v for k, v in counts.items() if k in AGREEMENT),
        "differences": sum(v for k, v in counts.items() if k not in AGREEMENT and k != "no_lean_expectation"),
        "not_compared": counts.get("no_lean_expectation", 0),
        "by_category": dict(sorted(counts.items())),
    }


def summarize(records, vectors_path, g2_blocked=None):
    """The report.  The top-level counts cover every record; `sets` gives them per comparison set.  `g2_blocked`
    (the pack's benefit-level cases) is given when the G2 pack cases were compared."""
    sets = {}
    for r in records:
        sets.setdefault(r.get("set", V1_SET), []).append(r)
    g2 = g2_blocked is not None
    report = {
        "schema": "localbce.g_rule_parity_report.v2",
        "authoritative": False,
        "vectors": os.path.relpath(vectors_path, ROOT).replace(os.sep, "/"),
        "compared_rules": {"localbce": sorted(G_TO_LEAN), "rightrail": sorted(MAPPED_LEAN)},
        "assumptions": ASSUMPTIONS + (G2_ASSUMPTIONS if g2 else []),
        "sets": {name: _counts(rs) for name, rs in sets.items()},
        "records": records,
    }
    report.update(_counts(records))
    if g2:
        report["g2_pack"] = {
            "cases": os.path.relpath(G2_PACK_CASES, ROOT).replace(os.sep, "/"),
            "not_compared_rule": G2_NOT_COMPARED,
            "blocked_cases": g2_blocked,
        }
    return report


def markdown(report):
    out = [
        "# G-rule parity report (generated, test-only)",
        "",
        "Generated by `scripts/g_rule_parity.py`. Not authoritative: Lean decides inside RightRail, and this report",
        "only lists where localBCE's `denial_reason()` would disagree on the same synthetic facts.",
        f"Vectors: `{report['vectors']}`. Lines compared: {report['lines']}. Agreements: {report['agreements']}. "
        f"Differences: {report['differences']}. Not compared (no Lean result recorded): {report['not_compared']}.",
        "",
        "## Assumptions (how localBCE flags are derived from Lean's rows)",
        "",
    ]
    out += [f"- {a}" for a in report["assumptions"]]
    out += ["", "## Counts by comparison set", "",
            "| Set | Lines | Agreements | Differences | Not compared |", "|---|---|---|---|---|"]
    for name, s in report["sets"].items():
        out.append(f"| `{name}` | {s['lines']} | {s['agreements']} | {s['differences']} | {s['not_compared']} |")
    out.append(f"| all | {report['lines']} | {report['agreements']} | {report['differences']} | {report['not_compared']} |")
    out += ["", "## Counts", "", "| Category | Lines | Meaning |", "|---|---|---|"]
    for cat, n in report["by_category"].items():
        out.append(f"| `{cat}` | {n} | {CATEGORY_NOTES[cat]} |")
    if "g2_pack" in report:
        g2 = report["g2_pack"]
        s = report["sets"].get(G2_SET, {"by_category": {}})
        out += ["", "## G2 pack cases", "",
                f"Cases: `{g2['cases']}`. RightRail side: the pack's pinned expected reasons, not a running gate "
                "(no gate runs a rule-set v2 pack yet). Synthetic, not legally verified.",
                f"`{g2['not_compared_rule']}` is not compared: the eligibility fact has no benefit level. "
                f"Blocked cases, not run: {', '.join(b['from_bbd0e947'] for b in g2['blocked_cases'])}.",
                "", "| Category | Cases |", "|---|---|"]
        out += [f"| `{cat}` | {n} |" for cat, n in s["by_category"].items()]
    out += ["", "## Differences", "", "| Set | Case | Line | Flow | Lean | localBCE | Category |", "|---|---|---|---|---|---|---|"]
    for r in report["records"]:
        if r["category"] in AGREEMENT:
            continue
        lean = (r["lean_outcome"] or "no result recorded") +(" " + ",".join(r["lean_reasons"]) if r["lean_reasons"] else "")
        local = r["localbce_status"] + (" " + r["localbce_reason"] if r["localbce_reason"] else "")
        out.append(f"| {r.get('set', V1_SET)} | {r['case']} | {r['line_id']} | {r['flow']} | {lean} | {local} | `{r['category']}` |")
    out.append("")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--engine", required=True, help="path to the built rust-engine binary")
    p.add_argument("--vectors", default=DEFAULT_VECTORS)
    p.add_argument("--json", dest="json_out")
    p.add_argument("--markdown", dest="md_out")
    p.add_argument("--no-g2-pack", action="store_true", help="compare the v1 lines only, not the G2 pack's cases")
    a = p.parse_args(argv)
    with open(a.vectors, encoding="utf-8") as f:
        cases = parse_vectors(f.read())
    records, blocked = compare(cases, a.engine), None
    if not a.no_g2_pack:
        g2_cases, blocked = load_g2_cases()
        records += compare_g2(g2_cases, a.engine)
    report = summarize(records, a.vectors, blocked)
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
    if a.md_out:
        with open(a.md_out, "w", encoding="utf-8", newline="\n") as f:
            f.write(markdown(report))
    print(json.dumps({k: report[k] for k in ("lines", "agreements", "differences", "not_compared", "by_category", "sets")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
