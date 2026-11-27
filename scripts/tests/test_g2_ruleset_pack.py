"""localBCE's G2 (program eligibility) rule as a RightRail rule-set v2 pack (scripts/build_g2_ruleset_pack.py).

Checks the pack's logic with Python only: the two records encode, round-trip and keep their pinned digests; every case
in rules/rightrail_packs/g2_elig_v2.expected.json fires its expected reasons on RightRail's reference evaluator
(rightrail/conformance/ruleset_v2_ref.py); and every one-node change to the pack (a mutant) is caught by a named case.

Not checked here: Lean's own evaluation and a signed admission (both need executables CI does not build), and the
pack running in a gate (no gate runs a version 2 record until the engine carries the eligibility read).
Design: docs/integration/G2_RULESET_V2_DESIGN.md.  Synthetic, not legally verified, nonpayment.
"""

import contextlib
import copy
import io
import itertools
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import build_g2_ruleset_pack as gp  # noqa: E402

ROOT = gp.ROOT
ref = gp.load_module("rr_ruleset_v2_ref", "rightrail/conformance/ruleset_v2_ref.py")
EXPECTED = json.loads(gp.EXPECTED.read_text("utf-8"))
CASES = {c["name"]: c for c in EXPECTED["cases"]}
PNE, PNE_UNV, STALE, STALE_ENROLLMENT = 26, 27, 28, 19
FRESH, PRESENT, DATE_OK = ("fresh", 7), ("present", 7), ("date_ok",)


def block(code: bytes) -> bytes:
    """A 21-byte identifier block as a fact row stores an aid code: a length byte, the code, zeros."""
    return bytes([len(code)]) + code + bytes(20 - len(code))


def to_read(r: dict) -> dict:
    aids = [bytes.fromhex(a["hex"]) if isinstance(a, dict) else block(a.encode()) for a in r["aids"]]
    return {"ans": r["ans"], "status": r["status"], "asof": r["asof"], "aids": aids}


def bits(mask: int) -> list:
    return [i for i in range(64) if mask >> i & 1]


def decided(record: dict, case: dict, flow: int = 2) -> list:
    """The reasons fired besides STALE_ENROLLMENT, which the reference's empty context always fires."""
    got = bits(ref.fired(record, to_read(case["read"]), case["service"], flow, case["batch"]))
    return [b for b in got if b != STALE_ENROLLMENT]


def outcome(fired: list) -> str:
    return "hold" if any(b not in ref.REVIEW for b in fired) else "review" if fired else "allow"


class Records(unittest.TestCase):
    def setUp(self):
        self.source = gp.load_source()
        self.records = gp.records(self.source)

    def test_source_is_marked(self):
        for flag in ("synthetic", "not_legally_verified", "nonpayment"):
            self.assertIs(self.source[flag], True, flag)
            with self.assertRaises(ValueError, msg=flag):
                gp.records(dict(self.source, **{flag: False}))
        self.assertIn("benefit level", self.source["partial"])

    def test_records_round_trip_and_match_the_pins(self):
        for name, record in self.records.items():
            data = gp.codec.encode(record)
            self.assertEqual(gp.codec.decode(data), record, name)
            self.assertEqual(gp.codec.encode(gp.codec.decode(data)), data, name)
            self.assertEqual(gp.summary(record), EXPECTED["records"][name], name)
        self.assertEqual(gp.summary(self.records["elig_only"])["cost"], 20)
        self.assertEqual(gp.summary(self.records["full"])["cost"], 102)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gp.main(["--check"]), 0)

    def test_only_the_three_backed_eligibility_reasons(self):
        self.assertEqual([b for b, _, _ in self.records["elig_only"]["rules"]], [PNE, PNE_UNV, STALE])
        for record in self.records.values():
            self.assertEqual(gp.codec.unbacked(record), [])
            self.assertTrue(ref.admissible(record))

    def test_a_benefit_level_rule_would_be_refused(self):
        """The open gap: reasons 24 and 25 have no data source, so a record naming one is not admissible."""
        for bit in (24, 25):
            record = dict(self.records["elig_only"])
            record["rules"] = [(bit, 0, PRESENT)] + record["rules"]
            gp.codec.encode(record)  # well formed: the refusal is admission's
            self.assertEqual(gp.codec.unbacked(record), [bit])
            self.assertFalse(ref.admissible(record))

    def test_aid_table_is_the_rust_engines_list(self):
        text = (ROOT / "rust-engine" / "src" / "main.rs").read_text("utf-8")
        found = re.search(r"if !matches!\(claim\.aid_code, ([0-9 |]+)\) \{\s*return Some\(\"G2_PROGRAM_ELIGIBILITY_FAILED\"\)", text)
        self.assertIsNotNone(found, "denial_reason()'s aid code test not found")
        rust = sorted(c.strip() for c in found.group(1).split("|"))
        self.assertEqual(sorted(self.source["aids_eligible"]), rust)
        self.assertEqual(self.records["elig_only"]["aids"], sorted(((c, 1) for c in rust), key=lambda a: a[0].encode()))

    def test_base_pack_is_trunks_pack_1(self):
        rs = gp.load_module("rr_test_ruleset_v1_codec", "rightrail/tests/test_ruleset_v1_codec.py")
        pack = self.source["base_pack"]
        self.assertEqual([tuple(a) for a in pack["ages"]], rs.PACK1["ages"])
        self.assertEqual([(r["bit"], 0, gp.expr(r["when"])) for r in pack["rules"]], rs.PACK1["rules"])
        full = self.records["full"]
        self.assertEqual(full["ages"], rs.PACK1["ages"] + [(7, self.source["elig_max_age_days"])])
        self.assertEqual(full["rules"], rs.PACK1["rules"] + self.records["elig_only"]["rules"])

    def test_bad_conditions_are_refused(self):
        for bad in (["fresh"], ["not", ["date_ok"], ["date_ok"]], ["elig", 2], ["nope", 1], "date_ok", [], ["elig", "2", 2]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gp.expr(bad)


class Cases(unittest.TestCase):
    def setUp(self):
        self.records = gp.records(gp.load_source())

    def test_names_are_unique(self):
        self.assertEqual(len(CASES), len(EXPECTED["cases"]))

    def test_each_case_fires_its_reasons(self):
        for name, case in CASES.items():
            fired = decided(self.records["elig_only"], case)
            self.assertEqual(fired, case["expect"], name)
            self.assertEqual(outcome(fired), case["outcome"], name)

    def test_the_full_record_adds_pack_1_and_changes_nothing(self):
        """Under the full record a line gets the eligibility reasons the eligibility-only record gives it, plus what
        pack 1 alone fires, on every flow."""
        pack1 = {k: v for k, v in self.records["full"].items() if k not in ("format", "aids")}
        pack1["ages"], pack1["rules"] = pack1["ages"][:-1], [r for r in pack1["rules"] if r[0] < 24]
        gp.codec.encode(pack1)
        for name, case in CASES.items():
            read = to_read(case["read"])
            for flow in range(1, 8):
                alone = ref.fired(pack1, read, case["service"], flow, case["batch"])
                want = alone | sum(1 << b for b in case["expect"])
                self.assertEqual(ref.fired(self.records["full"], read, case["service"], flow, case["batch"]), want,
                                 (name, flow))
                self.assertEqual(decided(self.records["elig_only"], case, flow), case["expect"], (name, flow))

    def test_what_carries_over_from_bbd0e947(self):
        carried = {c["from_bbd0e947"]: c["name"] for c in EXPECTED["cases"] if "from_bbd0e947" in c}
        self.assertEqual(sorted(carried), ["c7", "c8", "cNE", "cNEu", "cOk", "none"])
        blocked = {b["from_bbd0e947"]: b["blocked"] for b in EXPECTED["blocked"]}
        self.assertEqual(blocked, dict.fromkeys(("cBL", "cPair", "cLvl2", "cBLu"), "benefit level"))
        self.assertEqual(sorted(x["from_bbd0e947"] for x in EXPECTED["not_the_packs"]), ["cRev", "cStart", "cStop"])

    def test_the_forced_differences_are_as_recorded(self):
        """Design section 3: the four places the pack cannot match localBCE's G2 or the owner's rule."""
        self.assertEqual(CASES["absent"]["outcome"], "review")                 # 1: no fact is a review, not a hold
        self.assertEqual(CASES["age_8_days"]["expect"], [PNE_UNV, STALE])      # 2: a stale read gives 27 and 28
        self.assertEqual(len(EXPECTED["blocked"]), 4)                          # 3: benefit level is not tested
        for name in ("malformed_char", "malformed_empty", "malformed_length"):  # 4: a malformed aid code holds
            self.assertEqual(CASES[name]["expect"], [PNE], name)
            self.assertEqual(ref.aid_class({}, to_read(CASES[name]["read"])["aids"][0]), 3, name)
        self.assertEqual(ref.aid_class({}, block(b"999")), 3)                  # the same class as an unlisted code


def rule(record: dict, bit: int) -> tuple:
    return next(e for b, _, e in record["rules"] if b == bit)


def with_rule(record: dict, bit: int, cond) -> dict:
    """`record` with rule `bit` replaced by `cond`, or removed when `cond` is None."""
    rules = [(b, c, cond if b == bit else e) for b, c, e in record["rules"] if not (b == bit and cond is None)]
    return dict(record, rules=rules)


def swap(cond: tuple, old: tuple, new) -> tuple:
    """`cond` with each node equal to `old` replaced by `new`, or dropped from its AND or OR when `new` is None."""
    if cond == old:
        return new
    if cond[0] in ("and", "or"):
        return (cond[0], [y for y in (swap(x, old, new) for x in cond[1]) if y is not None])
    if cond[0] == "not":
        return ("not", swap(cond[1], old, new))
    return cond


def change(bit: int, old: tuple, new):
    return lambda r: with_rule(r, bit, swap(rule(r, bit), old, new))


def aids(f):
    return lambda r: dict(r, aids=sorted(f(list(r["aids"])), key=lambda a: a[0].encode()))


NOT_LISTED = ("not", ("elig", 3, 1))
# (name, change to the eligibility-only record, the case that must catch it)
MUTANTS = [
    ("pne_without_date_ok", change(PNE, DATE_OK, None), "bad_service_date"),
    ("pne_status_eligible_holds", change(PNE, ("elig", 2, 2), ("elig", 2, 1)), "eligible_13"),
    ("pne_ignores_status", lambda r: with_rule(r, PNE, ("and", [FRESH, DATE_OK, NOT_LISTED])), "status_not_eligible"),
    ("pne_ignores_aid_code", lambda r: with_rule(r, PNE, ("and", [FRESH, DATE_OK, ("elig", 2, 2)])), "unlisted_999"),
    ("pne_listed_code_holds", change(PNE, NOT_LISTED, ("elig", 3, 1)), "eligible_13"),
    ("pne_rule_removed", lambda r: with_rule(r, PNE, None), "unlisted_999"),
    ("aid_999_added", aids(lambda t: t + [("999", 1)]), "unlisted_999"),
    ("age_6", lambda r: dict(r, ages=[(7, 6)]), "age_7_days"),
    ("age_8", lambda r: dict(r, ages=[(7, 8)]), "age_8_days"),
    ("unv_rule_removed", lambda r: with_rule(r, PNE_UNV, None), "status_pending"),
    ("unv_without_pending", change(PNE_UNV, ("elig", 2, 4), None), "status_pending"),
    ("unv_presumptive_reviewed", change(PNE_UNV, ("elig", 2, 4), ("elig", 2, 12)), "status_presumptive"),
    ("unv_unknown_only", change(PNE_UNV, ("elig", 1, 12), ("elig", 1, 4)), "bad_service_date_conflict_with_as_of"),
    ("unv_conflict_only", change(PNE_UNV, ("elig", 1, 12), ("elig", 1, 8)), "bad_service_date_unknown_with_as_of"),
    ("unv_without_no_as_of", change(PNE_UNV, ("not", PRESENT), None), "bad_service_date_absent"),
    ("stale_rule_removed", lambda r: with_rule(r, STALE, None), "age_8_days"),
    ("stale_asks_fresh", change(STALE, PRESENT, FRESH), "age_8_days"),
    ("stale_without_as_of", lambda r: with_rule(r, STALE, ("not", FRESH)), "absent"),
]
for _code in ("103", "104", "13", "23", "53"):
    MUTANTS.append((f"aid_{_code}_removed", aids(lambda t, c=_code: [a for a in t if a[0] != c]), f"eligible_{_code}"))
    MUTANTS.append((f"aid_{_code}_listed_not_eligible",
                    aids(lambda t, c=_code: [(a[0], 2 if a[0] == c else a[1]) for a in t]), f"eligible_{_code}"))

# Changes no case can catch, because the gate's fixed guard already does what the node says: a PROGRAM_NOT_ELIGIBLE
# rule fires only on a fresh read whatever it asks (RULESET_V2.md section 5), so FRESH 7 in rule 26 is there for the
# reader, not for the result.
EQUIVALENT = [
    ("pne_without_fresh", change(PNE, FRESH, None)),
]


def grid():
    """Reads and dates around every edge the pack looks at: (read, service date, batch date)."""
    tables = ([], [block(b"999")], [block(b"13"), block(b"999")], [block(b"a/b")],
              *([block(c)] for c in (b"103", b"104", b"13", b"23", b"53")))
    for ans, status, asof, table, service, batch in itertools.product(
            range(4), range(1, 5), (None, 20270301, 20270302, 20270303, 20270308, 20270312, 20270316), tables,
            (20270310, 20270230), (20270315, 20270230)):
        yield {"ans": ans, "status": status, "asof": asof, "aids": table}, service, batch


class Mutants(unittest.TestCase):
    def setUp(self):
        self.record = gp.records(gp.load_source())["elig_only"]

    def test_names_are_unique_and_changes_are_real(self):
        names = [m[0] for m in MUTANTS + EQUIVALENT]
        self.assertEqual(len(names), len(set(names)))
        for name, f, *_ in MUTANTS + EQUIVALENT:
            mutant = f(copy.deepcopy(self.record))
            self.assertNotEqual(mutant, self.record, name)
            gp.codec.encode(mutant)  # still a well-formed record: the mutant is a pack someone could sign

    def test_every_mutant_is_caught_by_its_case(self):
        for name, f, killer in MUTANTS:
            mutant = f(copy.deepcopy(self.record))
            self.assertNotEqual(decided(mutant, CASES[killer]), CASES[killer]["expect"], (name, killer))

    def test_equivalent_mutants_change_no_result(self):
        for name, f in EQUIVALENT:
            mutant = f(copy.deepcopy(self.record))
            for case in CASES.values():
                self.assertEqual(decided(mutant, case), case["expect"], (name, case["name"]))
            n = 0
            for read, service, batch in grid():
                self.assertEqual(ref.fired(mutant, read, service, 2, batch),
                                 ref.fired(self.record, read, service, 2, batch), (name, read, service, batch))
                n += 1
            self.assertEqual(n, 4 * 4 * 7 * 9 * 2 * 2)

    def test_the_grid_is_not_blind(self):
        """The grid that calls a mutant equivalent tells every other mutant from the pack."""
        points = list(grid())
        for name, f, _ in MUTANTS:
            mutant = f(copy.deepcopy(self.record))
            self.assertTrue(any(ref.fired(mutant, r, s, 2, b) != ref.fired(self.record, r, s, 2, b)
                                for r, s, b in points), name)


if __name__ == "__main__":
    unittest.main()
