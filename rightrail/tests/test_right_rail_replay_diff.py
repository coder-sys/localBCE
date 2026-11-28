"""Replay difference report: the readers' line control number, identical sides give an empty report, one seeded difference per cause,
one-sided lines, claim-level fallback, set-aside units counted, byte-stable output, the file tool, and the real decide path end to end."""

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app import right_rail_gate_codec as codec
from app import right_rail_gate_ffs as ffs
from app import right_rail_reader_leie as leie
from app import right_rail_replay_diff as rd
from app import right_rail_x12_835 as r835
from app import right_rail_x12_837 as r837
from tests import _class_cases as cc
from tests import _messy_file as mf
from tests import _class_harness as ch
from tests import test_reader_leie as tl
from tests import test_right_rail_gate_formats as fx
from tests import test_x12_837 as t837
from tests.test_x12 import file_of
from tests.test_x12_835 import head
from tools import replay_diff as tool

INCUMBENT, GATE = "incumbent", "gate"
CAUSES = {row["code"]: row for row in json.loads((Path(rd.__file__).with_name("cause_actions.json")).read_text("utf-8"))}


def cents(n):
    return f"{n // 100}.{n % 100:02d}"


def remittance(*claims):
    return r835.read_835(remittance_bytes(*claims))


def remittance_bytes(*claims, payee="1999999984"):
    """claims: (id, [(line control or None, paid cents, billed cents, CAS segment or None)]); a claim with no lines is paid nothing."""
    body, paid = [], 0
    for cid, lines in claims:
        got, billed = sum(x[1] for x in lines), sum(x[2] for x in lines)
        paid += got
        body.append(f"CLP*{cid}*1*{cents(billed)}*{cents(got)}*0.00*MC*PCN-{cid}*11*1")
        for ctl, p, c, cas in lines:
            body += [f"SVC*HC:99213*{cents(c)}*{cents(p)}**1", "DTM*472*20260115"] + ([cas] if cas else []) + ([f"REF*6R*{ctl}"] if ctl else [])
    return file_of([head(cents(paid), payee=payee) + body], kind="835")


def with_control(segs, *controls):
    """A claim's segments with REF*6R after each line's DTP*472, one control number per line (None: leave it out; a tuple: send each)."""
    out, n = [], 0
    for seg in segs:
        out.append(seg)
        if seg.startswith("DTP*472"):
            for ctl in (controls[n] if isinstance(controls[n], tuple) else (controls[n],)):
                if ctl:
                    out.append(f"REF*6R*{ctl}")
            n += 1
    return out


def claims_837(*claims, npi="1999999984"):
    return r837.read_837(file_of([t837.head(npi) + [s for c in claims for s in c]], kind="837"))


def row(claim, control, outcome, cents_, *reasons):
    return {"claim": claim, "control": control, "outcome": outcome, "reasons": list(reasons), "cents": cents_}


def same():
    return (remittance(("K1", [("A1", 8000, 8000, None), ("A2", 12000, 12000, None)]), ("K2", [("B1", 0, 5000, "CAS*CO*45*50.00")])),
            [row("K1", "A1", "ALLOW", 8000), row("K1", "A2", "ALLOW", 12000), row("K2", "B1", "HOLD", 5000, "FFS_DUPLICATE_LINE")])


class ReaderControlTests(unittest.TestCase):
    def test_835_service_line_control(self):
        got = remittance(("K1", [("A1", 100, 100, None), (None, 200, 200, None)]))
        self.assertEqual([s.line_control for s in got.services], ["A1", ""])
        twice = r835.read_835(file_of([head("1.00") + ["CLP*K1*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*A1", "REF*6R*A2"]], kind="835"))
        self.assertEqual([s.line_control for s in twice.services], [""])
        self.assertEqual([(q.unit, q.cause) for q in twice.quarantines], [("segment", "repeated_segment")])

    def test_837_line_control(self):
        got = claims_837(with_control(cc.claim_of("K1", 3), "A1", None, ("B1", "B2")))
        self.assertEqual([r.line_control for r in got.rows], ["A1", "", ""])
        self.assertEqual((got.quarantines, len(got.rows)), ((), 3))


class ReplayDiffTests(unittest.TestCase):
    def report(self, rows, remit=None):
        return rd.diff_report(rd.from_835(INCUMBENT, [remit or same()[0]]), rd.from_gate(GATE, rows))

    def test_identical_replay_is_an_empty_report(self):
        got = self.report(same()[1])
        self.assertEqual((got["compared"], got["differing"], got["cents_at_stake"]), (3, 0, 0))
        self.assertEqual((got["differences"], got["by_cause"], got["by_system"], got["claim_level"], got["set_aside"]), ([], [], [], [], []))

    def test_a_held_line_the_incumbent_paid_is_named_in_staff_words(self):
        rows = same()[1]
        rows[0] = row("K1", "A1", "HOLD", 8000, "STALE_ENROLLMENT", "MEMBER_NOT_ENROLLED")
        got = self.report(rows)
        (d,) = got["differences"]
        self.assertEqual((d["key"], d["cause"], d["causes"], d["system"], d["cents"], d["paid"]),
                         ("K1#A1", "MEMBER_NOT_ENROLLED", ["MEMBER_NOT_ENROLLED", "STALE_ENROLLMENT"], GATE, 8000, {INCUMBENT: 8000, GATE: 0}))
        (g,) = got["by_cause"]
        self.assertEqual((g["cause"], g["system"], g["count"], g["cents"]), ("MEMBER_NOT_ENROLLED", GATE, 1, 8000))
        self.assertEqual((g["meaning"], g["action"]), (CAUSES["MEMBER_NOT_ENROLLED"]["meaning"], CAUSES["MEMBER_NOT_ENROLLED"]["action"]))
        self.assertEqual(got["by_system"], [{"system": GATE, "count": 1, "cents": 8000}])

    def test_every_cause_in_the_staff_table_can_be_seeded(self):
        for code, entry in CAUSES.items():
            with self.subTest(code=code):
                got = rd.diff_report(rd.from_gate(INCUMBENT, [row("K", "1", "ALLOW", 700)]), rd.from_gate(GATE, [row("K", "1", "HUMAN_REVIEW", 700, code)]))
                (g,) = got["by_cause"]
                self.assertEqual((g["cause"], g["system"], g["count"], g["cents"], g["meaning"], g["action"]), (code, GATE, 1, 700, entry["meaning"], entry["action"]))

    def test_a_denial_the_gate_would_pay_is_named_by_the_remittance_code(self):
        rows = same()[1]
        rows[2] = row("K2", "B1", "ALLOW", 5000)
        (d,) = self.report(rows)["differences"]
        self.assertEqual((d["key"], d["cause"], d["system"], d["cents"]), ("K2#B1", "CARC_45", INCUMBENT, 5000))

    def test_the_patient_share_is_not_a_denial(self):
        side = rd.from_835(INCUMBENT, [remittance(("P1", [("A1", 0, 1000, "CAS*PR*1*10.00")]))])
        self.assertEqual(side.claims["P1"][0].causes, ())
        got = rd.diff_report(side, rd.from_gate(GATE, [row("P1", "A1", "ALLOW", 1000)]))
        self.assertEqual(got["differences"][0]["cause"], "NOT_PAID_NO_REASON")

    def test_a_line_both_pay_agrees_whatever_each_paid(self):
        rows = same()[1]
        rows[1] = row("K1", "A2", "ALLOW", 11000)
        got = self.report(rows)
        self.assertEqual((got["compared"], got["differing"], got["differences"]), (3, 0, []))
        remit = remittance(("K5", [("A1", 7500, 10000, "CAS*CO*45*25.00")]))  # charge 100.00, paid 75.00 after the contractual adjustment
        got = self.report([row("K5", "A1", "ALLOW", 10000)], remit)
        self.assertEqual((got["compared"], got["differing"], got["differences"], got["by_cause"]), (1, 0, [], []))

    def test_a_claim_on_one_side_only(self):
        rows = same()[1][:2] + [row("K9", "Z1", "ALLOW", 300)]
        got = self.report(rows)
        self.assertEqual([(d["key"], d["cause"], d["system"], d["cents"]) for d in got["differences"]],
                         [("K2#B1", "MISSING_ON_ONE_SIDE", GATE, 5000), ("K9#Z1", "MISSING_ON_ONE_SIDE", INCUMBENT, 300)])
        self.assertEqual(got["cents_at_stake"], 5300)

    def test_different_control_numbers_for_one_claim_are_compared_as_one_key_when_both_sides_are_uniform(self):
        rows = same()[1]
        rows[0:2] = [row("K1", "A1", "HOLD", 8000, "SCOPE"), row("K1", "A9", "HOLD", 12000, "SCOPE")]
        got = self.report(rows)
        self.assertEqual([(d["key"], d["cause"], d["system"], d["cents"]) for d in got["differences"]], [("K1#claim", "SCOPE", GATE, 20000)])
        self.assertEqual(got["claim_level"], [{"system": GATE, "claims": 1}, {"system": INCUMBENT, "claims": 1}])

    def test_a_claim_with_a_missing_line_or_a_partly_paid_side_is_set_aside_at_claim_level(self):
        both = [{"system": GATE, "cause": "claim:partly_paid_at_claim_level", "count": 1}, {"system": INCUMBENT, "cause": "claim:partly_paid_at_claim_level", "count": 1}]
        rows = same()[1]
        rows[1:2] = []  # the gate has no A2 for K1: its line count differs
        got = self.report(rows)
        self.assertEqual((got["compared"], got["differing"], got["claim_level"], got["set_aside"]), (1, 0, [], both))
        rows = same()[1] + [row("K1", "A3", "ALLOW", 50)]
        self.assertEqual((self.report(rows)["compared"], self.report(rows)["set_aside"]), (1, both))
        remit = remittance(("K1", [(None, 1000, 1000, None), (None, 0, 1000, "CAS*CO*45*10.00")]))  # one line paid, one not: a sum hides the held line
        got = self.report([row("K1", "", "ALLOW", 1000), row("K1", "", "HOLD", 1000, "SCOPE")], remit)
        self.assertEqual((got["compared"], got["differing"], got["set_aside"]), (0, 0, both))

    def test_counts_and_cents_group_by_cause_and_system(self):
        rows = [row("K1", "A1", "HOLD", 8000, "FFS_DUPLICATE_LINE"), row("K1", "A2", "HOLD", 12000, "FFS_DUPLICATE_LINE"), row("K2", "B1", "ALLOW", 5000)]
        got = self.report(rows)
        self.assertEqual([(g["cause"], g["system"], g["count"], g["cents"]) for g in got["by_cause"]],
                         [("CARC_45", INCUMBENT, 1, 5000), ("FFS_DUPLICATE_LINE", GATE, 2, 20000)])
        self.assertEqual(got["by_system"], [{"system": GATE, "count": 2, "cents": 20000}, {"system": INCUMBENT, "count": 1, "cents": 5000}])

    def test_a_claim_without_control_numbers_is_compared_as_one_key(self):
        remit = remittance(("K3", [(None, 1000, 1000, None), (None, 1000, 1000, None)]), ("K4", [("A1", 500, 500, None), ("A2", 500, 500, None)]))
        rows = [row("K3", "X1", "HOLD", 1000, "SCOPE"), row("K3", "X2", "HOLD", 1000, "FFS_NEAR_DUPLICATE"), row("K4", "A1", "ALLOW", 500), row("K4", "A2", "ALLOW", 500)]
        got = self.report(rows, remit)
        (d,) = got["differences"]
        self.assertEqual((d["key"], d["cause"], d["causes"], d["system"], d["cents"], d["paid"]),
                         ("K3#claim", "FFS_NEAR_DUPLICATE", ["FFS_NEAR_DUPLICATE", "SCOPE"], GATE, 2000, {INCUMBENT: 2000, GATE: 0}))
        self.assertEqual((got["compared"], got["claim_level"]), (3, [{"system": INCUMBENT, "claims": 1}]))

    def test_coarse_comparison_agrees_on_equal_sums_and_counts_each_system_that_lacked_numbers(self):
        remit = remittance(("K3", [(None, 600, 600, None), (None, 400, 400, None)]))
        got = self.report([row("K3", "", "ALLOW", 600), row("K3", "", "ALLOW", 400)], remit)
        self.assertEqual((got["differing"], got["compared"], got["claim_level"]), (0, 1, [{"system": GATE, "claims": 1}, {"system": INCUMBENT, "claims": 1}]))
        self.assertEqual(got["set_aside"], [])

    def test_a_control_number_that_is_the_word_claim_is_not_used_as_a_line_key(self):
        remit = remittance(("K3", [("claim", 100, 100, None)]))
        got = self.report([row("K3", "claim", "HOLD", 100, "SCOPE")], remit)
        self.assertEqual(([d["key"] for d in got["differences"]], got["claim_level"]), (["K3#claim"], [{"system": GATE, "claims": 1}, {"system": INCUMBENT, "claims": 1}]))

    def test_a_claim_on_one_side_with_no_numbers_is_one_missing_key(self):
        got = self.report(same()[1] + [row("K7", "", "ALLOW", 90), row("K7", "", "ALLOW", 10)])
        (d,) = got["differences"]
        self.assertEqual((d["key"], d["cause"], d["system"], d["cents"]), ("K7#claim", "MISSING_ON_ONE_SIDE", INCUMBENT, 100))
        self.assertEqual(got["claim_level"], [{"system": GATE, "claims": 1}])

    def test_a_repeated_control_number_sets_the_claim_aside_on_both_sides(self):
        rows = same()[1][:2] + [row("K2", "B1", "ALLOW", 2000), row("K2", "B1", "ALLOW", 3000)]
        got = self.report(rows)
        self.assertEqual((got["compared"], got["differing"]), (2, 0))
        self.assertEqual(got["set_aside"], [{"system": GATE, "cause": "loop:duplicate_line_control", "count": 2}])

    def test_malformed_gate_rows_are_set_aside_and_counted(self):
        rows = same()[1] + [row("Q1", "A", "ALLOW", 0), row("Q2", "A", "MAYBE", 1), row("Q3", "A", "ALLOW", -1), row("Q4", "A", "HOLD", 1, "made_up"), "junk"]
        got = self.report(rows)
        self.assertEqual(got["differing"], 0)
        self.assertEqual(got["set_aside"], [{"system": GATE, "cause": "row:allow_zero_cents", "count": 1}, {"system": GATE, "cause": "row:bad_row", "count": 3},
                                            {"system": GATE, "cause": "row:unknown_reason", "count": 1}])

    def test_an_unreadable_835_is_incomplete_and_never_makes_a_claim_missing(self):
        refused = r835.read_835(b"not an x12 file")
        broken = r835.read_835(file_of([head() + ["CLP*K9*1*1.00*8O.00*0.00*MC*P*11*1"]], kind="835"))
        self.assertEqual(refused.refused, "isa_unframed")
        extra = [row("K9", "Z1", "ALLOW", 300)]
        for name, reads, cause in (("refused", [refused], "file:isa_unframed"), ("bad_clp", [same()[0], broken], "loop:bad_clp")):
            with self.subTest(name):
                side = rd.from_835(INCUMBENT, reads)
                self.assertTrue(side.incomplete)
                got = rd.diff_report(side, rd.from_gate(GATE, same()[1] + extra if name == "bad_clp" else same()[1]))
                self.assertEqual([d["cause"] for d in got["differences"]], [])
                counts = {(r["system"], r["cause"]): r["count"] for r in got["set_aside"]}
                self.assertEqual(counts[INCUMBENT, cause], 1)
                self.assertEqual(counts[INCUMBENT, "claim:not_known_missing_from_incomplete_input"], 1 if name == "bad_clp" else 2)
        whole = rd.from_835(INCUMBENT, [same()[0]])
        self.assertFalse(whole.incomplete)
        self.assertEqual([d["key"] for d in rd.diff_report(whole, rd.from_gate(GATE, same()[1] + extra))["differences"]], ["K9#Z1"])

    def test_a_quarantined_set_or_group_makes_a_side_incomplete_but_a_bad_service_line_does_not(self):
        for fault, want in (({"unit": "set"}, True), ({"unit": "group"}, True), ({"unit": "interchange"}, True), ({"unit": "file"}, True), ({"unit": "loop", "cause": "bad_svc"}, False)):
            read = SimpleNamespace(refused="", quarantines=[SimpleNamespace(unit=fault["unit"], cause=fault.get("cause", "x"))], services=[], claims=[], duplicates=[], findings=[])
            self.assertEqual(rd.from_835(INCUMBENT, [read]).incomplete, want, fault)

    def test_an_id_repeated_in_one_file_is_set_aside_whole(self):
        one = ("D1", [("A1", 100, 100, None)])
        read = remittance(one, one, ("K2", [("B1", 0, 5000, "CAS*CO*45*50.00")]))
        self.assertEqual([d[0] for d in read.duplicates], ["D1"])
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((list(side.claims), side.excluded, side.aside), (["K2"], frozenset({"D1"}), {"loop:duplicate_claim_id": 4}))

    def test_an_id_repeated_across_files_counts_the_first_copy_too(self):
        one = ("D1", [("A1", 100, 100, None)])
        side = rd.from_835(INCUMBENT, [remittance(one, ("K2", [("B1", 5, 5, None)])), remittance(one)])
        self.assertEqual((sorted(side.claims), side.excluded, side.aside), (["K2"], frozenset({"D1"}), {"loop:duplicate_claim_id": 4}))

    def test_a_claim_whose_835_total_does_not_add_up_is_set_aside_whole(self):
        read = r835.read_835(file_of([head("3.00") + ["CLP*M1*1*2.00*2.00*0.00*MC*P*11*1", "SVC*HC:99213*2.00*1.00**1", "REF*6R*A1",
                                                       "CLP*M2*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*B1"]], kind="835"))
        self.assertEqual([q.cause for q in read.findings], ["total_mismatch"])
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((sorted(side.claims), side.excluded, side.aside), (["M2"], frozenset({"M1"}), {"loop:total_mismatch": 2}))
        got = rd.diff_report(side, rd.from_gate(GATE, [row("M1", "A1", "HOLD", 200, "SCOPE"), row("M2", "B1", "ALLOW", 100)]))
        self.assertEqual((got["compared"], got["differing"], got["set_aside"]), (1, 0, [{"system": INCUMBENT, "cause": "loop:total_mismatch", "count": 2}]))

    def test_a_quarantined_segment_inside_a_claim_sets_that_claim_aside_only(self):
        read = r835.read_835(file_of([head("2.00") + ["CLP*Q1*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*A1", "REF*6R*A2",
                                                       "CLP*Q2*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*B1"]], kind="835"))
        self.assertEqual([(q.unit, q.cause) for q in read.quarantines], [("segment", "repeated_segment")])
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((sorted(side.claims), side.excluded, side.aside), (["Q2"], frozenset({"Q1"}), {"segment:repeated_segment": 1, "loop:segment_quarantined": 2}))
        self.assertFalse(side.incomplete)

    def test_several_quarantined_segments_between_claims_set_aside_only_the_claims_they_sit_in(self):
        clp = lambda cid, ctl, *extra: [f"CLP*{cid}*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", f"REF*6R*{ctl}", *extra]  # noqa: E731
        read = r835.read_835(file_of([head("4.00") + clp("R1", "A1", "REF*6R*A2", "REF*6R*A3") + clp("R2", "B1") + clp("R3", "C1", "REF*6R*C2") + clp("R4", "D1")]
                                     , kind="835"))
        self.assertEqual(len(read.quarantines), 3)
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((sorted(side.claims), side.excluded), (["R2", "R4"], frozenset({"R1", "R3"})))
        self.assertEqual(side.aside["loop:segment_quarantined"], 4)

    def test_a_payee_that_differs_from_the_billing_provider_is_set_aside_on_both_sides(self):
        gate = rd.from_gate(GATE, [row("K1", "A1", "HOLD", 100, "SCOPE"), row("K2", "B1", "HOLD", 100, "SCOPE")])._replace(npi={"K1": "1999999984", "K2": "1999999984"})
        pay = lambda payee: r835.read_835(file_of([head("2.00", payee=payee) + ["CLP*K1*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*A1",  # noqa: E731
                                                                                  "CLP*K2*1*1.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*B1"]], kind="835"))
        got = rd.diff_report(rd.from_835(INCUMBENT, [pay("1999999992")]), gate)
        self.assertEqual((got["compared"], got["differing"]), (0, 0))
        self.assertEqual(got["set_aside"], [{"system": GATE, "cause": "claim:payee_differs", "count": 2}, {"system": INCUMBENT, "cause": "claim:payee_differs", "count": 2}])
        got = rd.diff_report(rd.from_835(INCUMBENT, [pay("1999999984")]), gate)  # the same provider: compared
        self.assertEqual((got["compared"], got["differing"], got["set_aside"]), (2, 2, []))
        got = rd.diff_report(rd.from_835(INCUMBENT, [pay("")]), gate)  # no payee NPI sent: keyed by claim id alone
        self.assertEqual((got["compared"], got["differing"], got["set_aside"]), (2, 2, []))

    def test_a_reversal_is_set_aside_not_compared(self):
        read = remittance(("N1", [("A1", -1000, 1000, None)]))
        self.assertEqual(len(read.services), 1)
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((side.claims, side.aside), ({}, {"line:negative_cents": 1}))

    def test_a_claim_that_lost_a_service_line_is_set_aside_not_shifted(self):
        data = file_of([head("1.00") + ["CLP*L1*1*2.00*1.00*0.00*MC*P*11*1", "SVC*HC:99213*1.00*1.00**1", "REF*6R*A1", "SVC*HC:99214*1.00*x**1", "REF*6R*A2"]], kind="835")
        read = r835.read_835(data)
        self.assertIn("bad_svc", [q.cause for q in read.quarantines])
        side = rd.from_835(INCUMBENT, [read])
        self.assertEqual((side.claims, side.excluded, side.aside["loop:service_line_lost"]), ({}, frozenset({"L1"}), 2))

    def test_two_systems_that_both_decline_for_different_reasons_agree(self):
        rows = same()[1]
        rows[2] = row("K2", "B1", "HUMAN_REVIEW", 5000, "SCOPE")
        got = self.report(rows)
        self.assertEqual((got["differing"], got["differences"], got["by_cause"]), (0, [], []))

    def test_output_is_byte_stable(self):
        rows = same()[1]
        rows[0] = row("K1", "A1", "HOLD", 8000, "FFS_DUPLICATE_LINE")
        first = rd.render(self.report(rows))
        self.assertEqual(first, rd.render(self.report(list(reversed(rows)))))
        self.assertTrue(first.endswith(b"}\n") and first.isascii())
        self.assertEqual(first, json.dumps(json.loads(first), sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def test_the_two_systems_must_differ(self):
        with self.assertRaises(ValueError):
            rd.diff_report(rd.from_gate("x", []), rd.from_gate("x", []))


class DecisionAdapterTests(unittest.TestCase):
    NPI = "1999999984"

    def setUp(self):
        self.reads = [claims_837(with_control(cc.claim_of("P1", 2), "A1", "A2"), with_control(cc.claim_of("P2", 2), "B1", "B2"))]
        self.pid = {c: ffs.canonical_id("C", self.NPI, c) for c in ("P1", "P2")}
        self.sent = [SimpleNamespace(payment_id=self.pid[c], lines=(b"", b"")) for c in ("P1", "P2")]
        self.rows = [(self.pid["P1"], 0, "ALLOW", ()), (self.pid["P1"], 1, "HOLD", ("STALE_DMF",)),
                     (self.pid["P2"], 0, "ANSWERED", ("FFS_DUPLICATE_LINE",)), (self.pid["P2"], 1, "ALLOW", ())]

    def side(self, sent=None, rows=None, left=()):
        return rd.from_decision(GATE, self.reads, self.sent if sent is None else sent, self.rows if rows is None else rows, left)

    def test_rows_map_to_claim_and_line_control_number_with_the_837_cents(self):
        side = self.side()
        self.assertEqual(side.claims["P1"], (rd.Line("A1", 1000, 1000, ()), rd.Line("A2", 0, 1000, ("STALE_DMF",))))
        self.assertEqual(side.claims["P2"], (rd.Line("B1", 0, 1000, ("FFS_DUPLICATE_LINE",)), rd.Line("B2", 1000, 1000, ())))
        self.assertEqual((side.excluded, side.aside), (frozenset(), {}))

    def test_what_does_not_map_is_set_aside_and_counted(self):
        cases = [
            ("claim:line_count_mismatch", dict(sent=[SimpleNamespace(payment_id=self.pid["P1"], lines=(b"",)), self.sent[1]]), 1, "P1"),
            ("claim:line_without_one_outcome", dict(rows=self.rows[1:]), 2, "P1"),
            ("claim:line_without_one_outcome", dict(rows=self.rows + [self.rows[0]]), 2, "P1"),
            ("row:unknown_payment", dict(rows=self.rows + [("nope", 0, "ALLOW", ())]), 1, None),
            ("row:unknown_reason", dict(rows=[(self.pid["P1"], 0, "HOLD", ("invented",))] + self.rows[1:]), 1, "P1"),
            ("claim:set_aside_before_decide", dict(left=[ffs.SetAside("P2", "partial", 2000, 0)]), 1, "P2"),
        ]
        for cause, args, count, claim in cases:
            with self.subTest(cause=cause, claim=claim):
                side = self.side(**args)
                self.assertEqual(side.aside[cause], count)
                self.assertEqual(side.excluded, frozenset({claim} if claim else ()))
                self.assertNotIn(claim, side.claims)

    def test_the_left_argument_is_required(self):
        with self.assertRaises(TypeError):
            rd.from_decision(GATE, self.reads, self.sent, self.rows)

    def test_a_claim_id_under_two_payment_ids_is_set_aside_whole(self):
        other = claims_837(with_control(cc.claim_of("P1", 2), "C1", "C2"), npi="1999999992")
        pid = ffs.canonical_id("C", "1999999992", "P1")
        sent = self.sent + [SimpleNamespace(payment_id=pid, lines=(b"", b""))]
        rows = self.rows + [(pid, 0, "ALLOW", ()), (pid, 1, "ALLOW", ())]
        side = rd.from_decision(GATE, self.reads + [other], sent, rows, ())
        self.assertEqual((sorted(side.claims), side.excluded, side.aside), (["P2"], frozenset({"P1"}), {"claim:id_under_several_payments": 2}))

    def test_an_unreadable_837_makes_the_gate_side_incomplete_so_paid_claims_are_not_missing(self):
        empty_id = SimpleNamespace(rows=(), claims=[SimpleNamespace(id="")], refused="", quarantines=())
        for name, extra in (("refused", r837.read_837(b"not an x12 file")), ("empty id", empty_id),
                            ("file quarantine", SimpleNamespace(rows=(), claims=[], refused="", quarantines=[SimpleNamespace(unit="group", cause="x")]))):
            with self.subTest(name):
                side = rd.from_decision(GATE, self.reads + [extra], self.sent, self.rows, ())
                self.assertTrue(side.incomplete)
                got = rd.diff_report(rd.from_gate(INCUMBENT, [row("Z9", "A1", "ALLOW", 500)]), side)
                self.assertEqual([d for d in got["differences"] if d["key"].startswith("Z9")], [])
                self.assertIn({"system": GATE, "cause": "claim:not_known_missing_from_incomplete_input", "count": 1}, got["set_aside"])
        self.assertFalse(self.side().incomplete)

    def test_a_retry_is_decided_with_its_claim(self):
        side = self.side(left=[ffs.SetAside("P2", "retry", 2000, 0)])
        self.assertEqual((side.excluded, sorted(side.claims)), (frozenset(), ["P1", "P2"]))


class EndToEndTests(ch.Harness):
    """The real decide path (the pinned rules engine on a signed store) against a remittance that paid every line."""

    def test_the_gate_holds_an_excluded_provider_the_incumbent_paid_and_one_claim_falls_back_to_claim_level(self):
        free, listed, plain = cc.Parts(1), cc.Parts(2), cc.Parts(3)
        listed.leie = [cc.tl.row(npi=listed.npi)]
        for p, controls in ((free, ("A1", "A2")), (listed, ("B1", "B2")), (plain, (None, None))):
            p.claim = with_control(cc.claim_of(p.cid, 2), *controls)
        cases = [ch.read_case(p) for p in (free, listed, plain)]
        with self.session() as run:
            decided = [run(c["sent"], c["feed"])[0] for c in cases]
        sides = [rd.from_decision(GATE, c["reads"], c["sent"], rows, c["aside"]) for c, rows in zip(cases, decided)]
        claims = {k: v for side in sides for k, v in side.claims.items()}
        self.assertEqual((sorted(claims), [s.aside for s in sides]), ([free.cid, listed.cid, plain.cid], [{}, {}, {}]))
        remit = remittance((free.cid, [("A1", 1000, 1000, None), ("A2", 1000, 1000, None)]), (listed.cid, [("B1", 1000, 1000, None), ("B2", 1000, 1000, None)]),
                           (plain.cid, [("X1", 1000, 1000, None), ("X2", 1000, 1000, None)]))
        report = rd.diff_report(rd.from_835(INCUMBENT, [remit]), rd.Side(GATE, claims, frozenset(), {}))
        self.assertEqual([(d["key"], d["cause"], d["system"], d["cents"]) for d in report["differences"]],
                         [(f"{listed.cid}#B1", "PROVIDER_EXCLUDED", GATE, 1000), (f"{listed.cid}#B2", "PROVIDER_EXCLUDED", GATE, 1000)])
        self.assertEqual((report["compared"], report["claim_level"], report["set_aside"]), (5, [{"system": GATE, "claims": 1}], []))
        self.assertEqual(report["by_cause"][0]["meaning"], CAUSES["PROVIDER_EXCLUDED"]["meaning"])


class FileToolTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("E3_SCRATCH")
        if scratch:
            os.makedirs(scratch, exist_ok=True)
        self.dir = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.dir.cleanup)
        tmp = self.tmp = Path(self.dir.name)
        (tmp / "in835").mkdir()
        (tmp / "in835" / "a.835").write_bytes(file_of([head("20.00") + ["CLP*P1*1*20.00*20.00*0.00*MC*P*11*1", "SVC*HC:99213*10.00*10.00**1", "REF*6R*A1",
                                                                          "SVC*HC:99213*10.00*10.00**1", "REF*6R*A2"]], kind="835"))
        (tmp / "claims.837").write_bytes(file_of([t837.head() + with_control(cc.claim_of("P1", 2), "A1", "A2")], kind="837"))
        (tmp / "work").mkdir()
        self.stores = []

    def decide(self, reads, store):
        self.stores.append(store)
        (store / "sealed.bin").write_bytes(b"signed")  # what a real decide seals goes under its store
        pid = ffs.canonical_id("C", "1999999984", "P1")
        return [SimpleNamespace(payment_id=pid, lines=(b"", b""))], [], [(pid, 0, "ALLOW", ()), (pid, 1, "HOLD", ("STALE_DMF",))]

    def argv(self, out, *more):
        return [str(self.tmp / "claims.837"), "--835", str(self.tmp / "in835"), "--out", str(out), *more]

    def tree(self):
        return sorted(str(p.relative_to(self.tmp)).replace("\\", "/") for p in self.tmp.rglob("*"))

    def test_a_run_writes_only_the_report_and_removes_its_fresh_store(self):
        before = self.tree()
        out = self.tmp / "work" / "report.json"
        report = tool.report_files([self.tmp / "in835"], [self.tmp / "claims.837"], self.decide, out, scratch=self.tmp / "work")
        self.assertEqual(self.tree(), sorted(before + ["work/report.json"]))
        self.assertEqual(out.read_bytes(), rd.render(report))
        (d,) = report["differences"]
        self.assertEqual((d["key"], d["cause"], d["system"], d["cents"]), ("P1#A2", "STALE_DMF", GATE, 1000))
        (store,) = self.stores
        self.assertEqual(store.parent, self.tmp / "work")
        self.assertFalse(store.exists())

    def test_the_store_is_removed_when_decide_fails_and_the_message_is_plain(self):
        def failing(reads, store):
            (store / "x").write_bytes(b"1")
            raise tool.decider.GateDecideError("rules_refused")
        before = self.tree()
        out = self.tmp / "work" / "report.json"
        self.assertEqual(tool.main(self.argv(out), failing, scratch=self.tmp / "work"), 1)
        self.assertEqual(self.tree(), before)

    def test_without_a_decide_that_takes_a_fresh_store_it_refuses(self):
        before = self.tree()
        self.assertEqual(tool.main(self.argv(self.tmp / "work" / "r.json"), None), 1)
        self.assertEqual(self.tree(), before)

    def test_the_output_path_is_checked_before_anything_is_read_or_written(self):
        for bad in (self.tmp / "claims.837", self.tmp / "in835" / "report.json"):
            self.assertEqual(tool.main(self.argv(bad), self.decide, scratch=self.tmp / "work"), 1)
        self.assertEqual((self.stores, self.tree().count("in835/report.json")), ([], 0))
        out = self.tmp / "work" / "report.json"
        out.write_bytes(b"old")
        self.assertEqual(tool.main(self.argv(out), self.decide, scratch=self.tmp / "work"), 1)
        self.assertEqual(out.read_bytes(), b"old")
        self.assertEqual(tool.main(self.argv(out, "--overwrite"), self.decide, scratch=self.tmp / "work"), 0)
        first = out.read_bytes()
        self.assertNotEqual(first, b"old")
        self.assertEqual(tool.main(self.argv(out, "--overwrite"), self.decide, scratch=self.tmp / "work"), 0)
        self.assertEqual(out.read_bytes(), first)
        self.assertEqual([p for p in self.tree() if p.endswith(".part")], [])


    def test_argv_errors_exit_nonzero_before_anything_is_read(self):
        for bad in ([], [str(self.tmp / "claims.837")], ["--835", str(self.tmp / "in835")], ["x", "--835"], ["x", "--835", "y", "--nope"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
                tool.main(bad, self.decide)
            self.assertEqual(stop.exception.code, 2)
        self.assertEqual(self.stores, [])

    def test_a_folder_that_yields_nothing_or_holds_a_non_file_is_named_and_counted(self):
        empty, only_dirs, mixed = self.tmp / "empty", self.tmp / "only_dirs", self.tmp / "in835"
        empty.mkdir()
        (only_dirs / "2026-01").mkdir(parents=True)
        (mixed / "sub").mkdir()
        for folder, named in ((empty, [empty]), (only_dirs, [only_dirs / "2026-01", only_dirs]), (mixed, [mixed / "sub"])):
            seen = []
            self.assertEqual(tool._files(folder, seen), sorted(p for p in folder.iterdir() if p.is_file()))
            self.assertEqual(seen, [str(p) for p in named])
        out, err = self.tmp / "work" / "r.json", io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main([str(self.tmp / "claims.837"), "--835", str(only_dirs), "--out", str(out)], self.decide, scratch=self.tmp / "work")
        self.assertEqual(code, 3)
        self.assertIn(f"replay_diff: could not read {only_dirs}; set aside", err.getvalue().splitlines())
        self.assertTrue(out.is_file())

    def test_the_output_folder_is_checked_first_and_a_file_that_appears_during_the_run_is_kept(self):
        self.assertEqual(tool.main(self.argv(self.tmp / "nodir" / "r.json"), self.decide, scratch=self.tmp / "work"), 1)
        self.assertEqual(self.stores, [])
        out = self.tmp / "work" / "r.json"

        def appearing(reads, store):
            out.write_bytes(b"theirs")
            return self.decide(reads, store)
        self.assertEqual(tool.main(self.argv(out), appearing, scratch=self.tmp / "work"), 1)
        self.assertEqual(out.read_bytes(), b"theirs")
        self.assertEqual(tool.main(self.argv(out, "--overwrite"), appearing, scratch=self.tmp / "work"), 0)
        self.assertNotEqual(out.read_bytes(), b"theirs")
        self.assertEqual([p for p in self.tree() if p.endswith(".part")], [])

    def test_a_missing_or_unreadable_file_is_set_aside_and_counted_not_dropped(self):
        gone = self.tmp / "gone.837"
        out, err = self.tmp / "work" / "report.json", io.StringIO()
        (self.tmp / "in835" / "z.835").write_bytes(remittance_bytes(("Z9", [("A1", 1000, 1000, None)])))  # a claim the gate side cannot be known to lack
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main([str(self.tmp / "claims.837"), str(gone), "--835", str(self.tmp / "in835"), str(self.tmp / "nope.835"),
                              "--out", str(out)], self.decide, scratch=self.tmp / "work")
        self.assertEqual(code, 3)
        self.assertEqual(sorted(err.getvalue().splitlines()), sorted(f"replay_diff: could not read {p}; set aside" for p in (gone, self.tmp / "nope.835")))
        report = json.loads(out.read_bytes())
        self.assertEqual(report["contract"], rd.CONTRACT)
        self.assertEqual([(r["system"], r["cause"], r["count"]) for r in report["set_aside"]],
                         [(GATE, "claim:not_known_missing_from_incomplete_input", 1), (INCUMBENT, "file:no_interchange", 1)])
        self.assertEqual(self.tree().count("work/report.json"), 1)

    def test_the_same_input_gives_the_same_bytes_and_stdout_takes_the_report_without_out(self):
        a, b = self.tmp / "work" / "a.json", self.tmp / "work" / "b.json"
        for out in (a, b):
            tool.main(self.argv(out), self.decide, scratch=self.tmp / "work")
        self.assertEqual(a.read_bytes(), b.read_bytes())
        shown = io.BytesIO()
        with mock.patch.object(tool.sys, "stdout", SimpleNamespace(buffer=shown)), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main([str(self.tmp / "claims.837"), "--835", str(self.tmp / "in835")], self.decide, scratch=self.tmp / "work"), 0)
        self.assertEqual(shown.getvalue(), a.read_bytes())


class GateDecideEndToEndTests(ch.Harness):
    """The file tool on files, with the real decide path (``gate_decide`` over the pinned engine on a signed store)."""

    def test_files_in_report_out_with_the_real_gate(self):
        listed = cc.Parts(2)
        listed.leie = [cc.tl.row(npi=listed.npi)]
        listed.claim = with_control(cc.claim_of(listed.cid, 2), "B1", "B2")
        case = ch.read_case(listed)
        with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH") or None) as name:
            tmp = Path(name)
            (tmp / "work").mkdir()
            (tmp / "claims.837").write_bytes(listed.file837())
            (tmp / "p.835").write_bytes(remittance_bytes((listed.cid, [("B1", 1000, 1000, None), ("B2", 1000, 1000, None)]), payee=listed.npi))
            @contextlib.contextmanager
            def session(store):  # the signed store and everything it seals live in the folder the tool handed over
                self.assertEqual((store.parent, list(store.iterdir())), (tmp / "work", []))
                with mock.patch.object(tempfile, "tempdir", str(store)), self.session() as run:
                    yield run
            decide = tool.gate_decide(session, ch.fx.TENANT, ch.fx.PROGRAM, ch.fx.PERIOD, ch.SECRET,
                                     leie.read_leie(listed.leie_bytes(), source="synthetic", as_of=cc.AS_OF, kind=listed.leie_kind), case["feed"])
            outs = []
            for n in (1, 2):
                outs.append(tmp / f"r{n}.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(tool.main([str(tmp / "claims.837"), "--835", str(tmp / "p.835"), "--out", str(outs[-1])], decide, scratch=tmp / "work"), 0)
            self.assertEqual(list((tmp / "work").iterdir()), [])
            self.assertEqual(outs[0].read_bytes(), outs[1].read_bytes())
            report = json.loads(outs[0].read_bytes())
        self.assertEqual([(d["key"], d["cause"], d["system"]) for d in report["differences"]],
                        [(f"{listed.cid}#B1", "PROVIDER_EXCLUDED", GATE), (f"{listed.cid}#B2", "PROVIDER_EXCLUDED", GATE)])


class GuardTests(unittest.TestCase):
    SECRET = b"synthetic tenant secret, 32 b.."
    NO_ONE = leie.read_leie((tl.HEAD + tl.row(npi=tl.make_npi(1))).encode(), source="synthetic", as_of="2027-03-10")

    def requests(self, *reads):
        return ffs.requests_of(list(reads), fx.TENANT, fx.PROGRAM, fx.PERIOD, self.SECRET, self.NO_ONE)

    def read(self, claim, *controls):
        return r837.read_837(file_of([t837.head() + with_control(claim, *controls)], kind="837"))

    def test_copies_that_differ_only_in_the_line_control_number_are_a_retry(self):
        claim = [s.replace("UN*1.5", "UN*1") for s in t837.claim("C1", 2)]
        sent, aside = self.requests(self.read(claim, "A1", "A2"), self.read(claim, "B1", "B2"))
        self.assertEqual(([r.payment_id for r in sent], [a.cause for a in aside]), ([ffs.canonical_id("C", "1999999984", "C1")], ["retry"]))

    def test_copies_that_differ_in_anything_else_are_still_a_conflict(self):
        one = [s.replace("UN*1.5", "UN*1") for s in t837.claim("C1", 2)]
        other = [s.replace("UN*1.5", "UN*1") for s in t837.claim("C1", 2, charge="11.00", total="22.00")]
        sent, aside = self.requests(self.read(one, "A1", "A2"), self.read(other, "A1", "A2"))
        self.assertEqual((sent, [a.cause for a in aside]), ((), ["payment_id_conflict", "payment_id_conflict"]))

    def test_the_payment_id_request_and_encoded_lines_do_not_depend_on_the_line_control_number(self):
        claim = [s.replace("UN*1.5", "UN*1") for s in t837.claim("C1", 2)]
        (with6r,), _ = self.requests(self.read(claim, "A1", "A2"))
        (plain,), _ = self.requests(self.read(claim, None, None))
        self.assertEqual((with6r.payment_id, with6r.lines), (plain.payment_id, plain.lines))
        blank = lambda r: dataclasses.replace(r, evidence_refs=())  # noqa: E731  the file's own hash is the one thing that differs
        self.assertEqual(codec.encode_decide_request(blank(with6r)), codec.encode_decide_request(blank(plain)))


class Reader835ControlGuardTests(unittest.TestCase):
    def read(self, *segments):
        data = file_of([head("1.00") + ["CLP*K1*1*1.00*1.00*0.00*MC*P*11*1", *segments]], kind="835")
        return data, r835.read_835(data)

    def test_a_third_control_number_is_quarantined_too_and_the_line_has_none(self):
        _, got = self.read("SVC*HC:99213*1.00*1.00**1", "REF*6R*A1", "REF*6R*A2", "REF*6R*A3")
        self.assertEqual([s.line_control for s in got.services], [""])
        self.assertEqual([(q.unit, q.cause, q.detail) for q in got.quarantines], [("segment", "repeated_segment", "REF*6R")] * 2)

    def test_the_reference_offset_keeps_the_order_of_the_segments(self):
        for order in (("DTM*472*20260115", "REF*6R*A1", "CAS*CO*45*0.50"), ("REF*6R*A1", "DTM*472*20260115", "CAS*CO*45*0.50"),
                      ("CAS*CO*45*0.50", "DTM*472*20260115", "REF*6R*A1")):
            with self.subTest(order=order):
                data, got = self.read("SVC*HC:99213*1.00*1.00**1", *order)
                (svc,) = got.services
                self.assertEqual([data[o:o + 3] for o in svc.offsets], [b"SVC", *(seg[:3].encode() for seg in order)])
                self.assertEqual((svc.line_control, svc.service_date, svc.adjustments), ("A1", "2026-01-15", (("CO", "45", 50, ""),)))
                self.assertEqual(list(svc.offsets), sorted(svc.offsets))


MAP = json.dumps({"systems": {"old": {"kind": "vendor", "owner": "Old Claims Co"}, "new": {"kind": "vendor", "owner": "New Claims Co"},
                              "shadow": {"kind": "vendor", "owner": "Parallel Run Co"}, GATE: {"kind": "gate", "owner": "Gate"},
                              "state_eligibility_office": {"kind": "state_office", "owner": "State Eligibility Office"}},
                  "steps": {"CARC_31": "state_eligibility_office", "MEMBER_NOT_ENROLLED": "state_eligibility_office", "CARC_96": "@side", "SCOPE": "@side",
                            "PRICE_DIFFERS": "@side", "MISSING_ON_ONE_SIDE": "@side", "NOT_PAID_NO_REASON": "@side"}}).encode()
PIN = hashlib.sha3_512(MAP).hexdigest()


def pays(system, claim, *lines):
    """A side that prices: ``lines`` are (control, outcome, cents, reasons...)."""
    return rd.from_gate(system, [row(claim, c, outcome, n, *why) for c, outcome, n, *why in lines], prices=True)


def mapped(*sides):
    return rd.diff_report(*sides, system_map=rd.load_map(MAP, PIN))


class SystemSidesTests(unittest.TestCase):
    def test_a_pricing_difference_between_two_systems_that_both_pay_is_a_difference_named_by_both(self):
        a, b = pays("old", "K1", ("A1", "ALLOW", 7000)), pays("new", "K1", ("A1", "ALLOW", 8000))
        got = rd.diff_report(a, b)
        (d,) = got["differences"]
        self.assertEqual((d["cause"], d["system"], d["cents"], d["paid"]), ("PRICE_DIFFERS", "new+old", 1000, {"new": 8000, "old": 7000}))
        self.assertEqual(rd.render(got), rd.render(rd.diff_report(b, a)))
        self.assertIn("not a payable amount", got["cents_meaning"])

    def test_a_third_system_decides_which_of_two_prices_is_off_and_the_gate_never_votes(self):
        sides = [pays("old", "K1", ("A1", "ALLOW", 7000)), pays("new", "K1", ("A1", "ALLOW", 8000)), pays("shadow", "K1", ("A1", "ALLOW", 8000)),
                 rd.from_gate(GATE, [row("K1", "A1", "ALLOW", 10000)])]
        (d,) = rd.diff_report(*sides)["differences"]
        self.assertEqual((d["system"], d["cents"]), ("old", 1000))
        self.assertEqual(rd.diff_report(*sides[1:])["differences"], [])  # the gate pays the billed charge: not a price

    def test_hand_computed_cents_with_three_sides(self):
        def cents_of(*amounts):
            names = ("old", "new", "shadow")
            sides = [pays(n, "K", ("A", "ALLOW", a)) if a else rd.from_gate(n, [], True) for n, a in zip(names, amounts)]
            return [(d["cause"], d["system"], d["cents"]) for d in rd.diff_report(*sides)["differences"]]
        self.assertEqual(cents_of(7000, 8000, 8000), [("PRICE_DIFFERS", "old", 1000)])
        self.assertEqual(cents_of(5000, 7000, 9000), [("PRICE_DIFFERS", "new+old+shadow", 4000)])
        self.assertEqual(cents_of(7000, 8000, 0), [("MISSING_ON_ONE_SIDE", "shadow", 8000)])  # the price spread there is only in "paid"
        self.assertEqual(cents_of(0, 8000, 8000), [("MISSING_ON_ONE_SIDE", "old", 8000)])

    def test_the_map_names_the_system_at_fault_and_its_owner(self):
        sides = [pays("old", "K1", ("A1", "ALLOW", 8000), ("A2", "ALLOW", 8000)),
                 rd.from_gate("new", [row("K1", "A1", "HOLD", 8000, "MEMBER_NOT_ENROLLED"), row("K1", "A2", "HOLD", 8000, "SCOPE")], True)]
        got = mapped(*sides)
        self.assertEqual([(d["key"], d["system"], d["fault"], d["owner"]) for d in got["differences"]],
                         [("K1#A1", "new", "state_eligibility_office", "State Eligibility Office"), ("K1#A2", "new", "new", "New Claims Co")])
        self.assertEqual(got["by_fault"], [{"fault": "new", "count": 1, "cents": 8000}, {"fault": "state_eligibility_office", "count": 1, "cents": 8000}])
        self.assertEqual(got["map"], PIN)

    def test_a_cause_the_map_has_no_step_for_is_unmapped_never_guessed(self):
        got = mapped(pays("old", "K1", ("A1", "ALLOW", 8000)), pays("new", "K1", ("A1", "HOLD", 8000, "STALE_DMF")))
        (d,) = got["differences"]
        self.assertEqual((d["system"], d["fault"], d["owner"]), ("new", "UNMAPPED:STALE_DMF", ""))
        self.assertEqual(got["by_fault"], [{"fault": "UNMAPPED:STALE_DMF", "count": 1, "cents": 8000}])

    def test_each_side_that_stopped_is_blamed_for_its_own_cause(self):
        got = mapped(pays("old", "K1", ("A1", "HOLD", 8000, "SCOPE")), pays("new", "K1", ("A1", "HOLD", 8000, "MEMBER_NOT_ENROLLED")), pays("shadow", "K1", ("A1", "ALLOW", 8000)))
        (d,) = got["differences"]
        self.assertEqual((d["system"], d["fault"], d["owner"], d["cents"]), ("new+old", "old+state_eligibility_office", "Old Claims Co+State Eligibility Office", 8000))
        self.assertEqual(d["causes"], ["MEMBER_NOT_ENROLLED", "SCOPE"])

    def test_a_map_must_be_pinned_whole_and_name_every_side(self):
        with self.assertRaises(ValueError):
            rd.load_map(MAP, "0" * 128)
        self.assertEqual(rd.load_map(MAP, PIN)["digest"], PIN)
        for bad in (b"[", b"{}", b"[" * 100000, MAP.replace(b'"CARC_31": "state_eligibility_office"', b'"CARC_31": "nobody"'),
                    MAP.replace(b'"vendor"', b'"friend"', 1), MAP.replace(b'"old"', b'"o+ld"', 1), MAP.replace(b'"new": {', b'"old": {', 1)):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                rd.load_map(bad, hashlib.sha3_512(bad).hexdigest())
        with self.assertRaises(ValueError):
            mapped(pays("old", "K", ("A", "ALLOW", 1)), pays("other", "K", ("A", "ALLOW", 1)))
        with self.assertRaises(ValueError):
            rd.diff_report(pays("old", "K", ("A", "ALLOW", 1)))

    def test_a_gate_system_is_exactly_a_side_that_does_not_price(self):
        with self.assertRaises(ValueError):
            mapped(pays(GATE, "K", ("A", "ALLOW", 1)), pays("old", "K", ("A", "ALLOW", 1)))  # named gate, but it prices
        with self.assertRaises(ValueError):
            mapped(rd.from_gate("old", [row("K", "A", "ALLOW", 1)]), pays("new", "K", ("A", "ALLOW", 1)))  # a vendor that does not price
        self.assertEqual(mapped(rd.from_gate(GATE, [row("K", "A", "ALLOW", 1)]), pays("old", "K", ("A", "ALLOW", 1)))["differences"], [])

    def test_a_hash_in_a_claim_id_or_control_number_cannot_make_two_keys_alike(self):
        got = rd.diff_report(rd.from_gate("a", [row("A#1", "B", "ALLOW", 1), row("A", "1#B", "ALLOW", 1)]), rd.from_gate("b", []))
        self.assertEqual(sorted(d["key"] for d in got["differences"]), ["A#1%23B", "A%231#B"])

    def test_absurd_cents_are_set_aside_not_compared(self):
        got = rd.diff_report(rd.from_gate("a", [row("K", "A", "ALLOW", 10 ** 11)]), rd.from_gate("b", []))
        self.assertEqual((got["differences"], got["set_aside"]), ([], [{"system": "a", "cause": "row:bad_row", "count": 1}]))
        side = rd.from_835("a", [remittance(("Z", [("A1", 2000, 1000, None)]))])
        self.assertEqual((side.claims, side.aside), ({}, {"line:cents_implausible": 1}))

    def test_random_sides_match_an_independent_count_and_do_not_depend_on_their_order(self):
        rng = random.Random(7)
        for _ in range(40):
            sides, truth = [], {}
            for name in ("a", "b", "c", "d"):
                priced, rows = rng.random() < 0.7, []
                for k in range(4):
                    if rng.random() < 0.9:
                        outcome, billed = rng.choice(("ALLOW", "ALLOW", "HOLD")), rng.choice((100, 200, 300))
                        rows += [row(f"K{k}", f"L{n}", outcome, billed, *(["SCOPE"] * (outcome == "HOLD"))) for n in range(2)]
                        truth.setdefault(k, {})[name] = (priced, billed if outcome == "ALLOW" else 0, billed)
                sides.append(rd.from_gate(name, rows, priced))
            want = 0
            for k, seen in truth.items():  # each claim has two lines that the sides decide alike
                paid = [p for _, p, _ in seen.values()]
                if len(seen) < 4:
                    per = max(paid) or max(b for _, _, b in seen.values())
                elif any(paid) and not all(paid):
                    per = max(paid)
                elif all(paid):
                    prices = {p for pr, p, _ in seen.values() if pr}
                    per = max(prices) - min(prices) if len(prices) > 1 else 0
                else:
                    per = 0
                want += 2 * per
            got = rd.diff_report(*sides)
            self.assertEqual(got["cents_at_stake"], want)
            for key in ("by_cause", "by_system"):
                self.assertEqual(sum(g["cents"] for g in got[key]), want, key)
            for order in (sides[::-1], sides[2:] + sides[:2]):
                self.assertEqual(rd.render(rd.diff_report(*order)), rd.render(got))


class PlantedSystemDefectTests(unittest.TestCase):
    """The messy file's three parallel runs (tests/_messy_file.py ``systems_835``): every planted defect, tagged with the system at fault, is found, and nothing else."""

    @classmethod
    def setUpClass(cls):
        w, _, _ = mf.build()
        cls.files, cls.planted = mf.systems_835(w)

    def report(self, names=("old", "new", "shadow"), system_map=True):
        sides = [rd.from_835(n, [r835.read_835(self.files[n])]) for n in names]
        return rd.diff_report(*sides, system_map=rd.load_map(MAP, PIN) if system_map else None)

    def test_every_planted_defect_is_recovered_with_its_system_and_its_exact_cents_and_no_other_name(self):
        got = self.report()
        self.assertEqual({d["key"]: (d["fault"], d["cents"]) for d in got["differences"]}, self.planted)
        self.assertEqual({d["fault"] for d in got["differences"]}, {"old", "new", "state_eligibility_office"})
        self.assertEqual({d["system"] for d in got["differences"]}, {"old", "new"})
        self.assertEqual(got["set_aside"], [])

    def test_cents_add_up_from_the_planted_inputs_and_the_sides_can_be_swapped(self):
        got = self.report()
        want = {}
        for fault, cents in self.planted.values():
            n, m = want.get(fault, (0, 0))
            want[fault] = (n + 1, m + cents)
        self.assertEqual(got["cents_at_stake"], sum(m for _, m in want.values()))
        self.assertEqual(got["by_fault"], [{"fault": f, "count": n, "cents": m} for f, (n, m) in sorted(want.items())])
        for names in (("shadow", "new", "old"), ("new", "old", "shadow")):
            self.assertEqual(rd.render(self.report(names)), rd.render(got))

    def test_without_the_map_the_report_names_the_sides_only(self):
        got = self.report(system_map=False)
        self.assertEqual({d["fault"] for d in got["differences"]}, {"old", "new"})
        self.assertEqual({d["owner"] for d in got["differences"]}, {""})

    def test_old_against_new_alone_still_finds_every_difference_and_names_both_when_it_cannot_tell(self):
        got = self.report(("old", "new"))
        self.assertEqual({d["key"] for d in got["differences"]}, set(self.planted))
        self.assertEqual({d["system"] for d in got["differences"] if d["cause"] == "PRICE_DIFFERS"}, {"new+old"})


class OldAgainstNewFilesTests(unittest.TestCase):
    def test_the_tool_reports_old_against_new_remittances_with_a_pinned_map(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH") or None) as name:
            tmp = Path(name)
            for side, paid in (("old", 7000), ("new", 8000), ("shadow", 8000)):
                (tmp / side).mkdir()
                (tmp / side / "a.835").write_bytes(remittance_bytes(("P1", [("A1", paid, 10000, "CAS*CO*45*1.00")])))
            (tmp / "map.json").write_bytes(MAP)
            sides = ["--side", "old", str(tmp / "old"), "--side", "new", str(tmp / "new"), "--side", "shadow", str(tmp / "shadow")]
            outs = []
            for n in (1, 2):
                outs.append(tmp / f"r{n}.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(tool.main([*sides, "--map", str(tmp / "map.json"), "--map-pin", PIN, "--out", str(outs[-1])]), 0)
            self.assertEqual(outs[0].read_bytes(), outs[1].read_bytes())
            (d,) = json.loads(outs[0].read_bytes())["differences"]
            self.assertEqual((d["key"], d["system"], d["fault"], d["owner"], d["cents"]), ("P1#A1", "old", "old", "Old Claims Co", 1000))
            for bad in (["--side", "old", str(tmp / "old"), "--side", "old", str(tmp / "new")], ["--side", "old"], ["--835", str(tmp / "old")],
                        ["--835", str(tmp / "old"), "--side", "new", str(tmp / "new"), "--map-pin", PIN],
                        ["--835", str(tmp / "old"), "--side", "new", str(tmp / "new"), "--map", str(tmp / "map.json")],  # a map with no pin
                        ["--835", str(tmp / "old"), "--side", "new", str(tmp / "new"), "--deployment", str(tmp), "--keyset-pin", "0" * 128]):  # nothing for it to decide
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
                    tool.main(bad)
                self.assertEqual(stop.exception.code, 2)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tool.main(["--835", str(tmp / "old"), "--side", "new", str(tmp / "new"), "--map", str(tmp / "map.json"), "--map-pin", "0" * 128]), 1)

    def test_every_835_side_gives_the_gate_its_as_of_day_and_a_damaged_one_refuses_it(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH") or None) as name:
            tmp = Path(name)
            (tmp / "old.835").write_bytes(remittance_bytes(("P1", [("A1", 100, 100, None)])))
            (tmp / "new.835").write_bytes(remittance_bytes(("P1", [("A1", 100, 100, None)])))
            (tmp / "claims.837").write_bytes(file_of([t837.head() + with_control(cc.claim_of("P1", 1), "A1")], kind="837"))
            (tmp / "folder").mkdir()
            (tmp / "folder" / "sub").mkdir()
            seen = []

            def decide(reads, store, paid):
                seen.append(len(paid))
                return [], [], []
            decide.wants_835 = True
            self.assertEqual(tool.main([str(tmp / "claims.837"), "--835", str(tmp / "old.835"), "--side", "new", str(tmp / "new.835"), "--out", str(tmp / "r.json")], decide), 0)
            self.assertEqual(seen, [2])  # the 835 of the --side as well
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tool.main([str(tmp / "claims.837"), "--835", str(tmp / "old.835"), "--side", "new", str(tmp / "folder"), "--out", str(tmp / "r2.json"),
                                            "--overwrite"], decide), 1)  # a --side folder that is not all readable files
            self.assertEqual(seen, [2])


if __name__ == "__main__":
    unittest.main()
