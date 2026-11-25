"""Class test: a finding or set-aside any reader records about a member, provider, claim or line never lets its payment be ALLOW.

The kinds come from the source (tests/_class_kinds.py), so a kind added later is covered by name: the generator test fails until
tests/_class_cases.py can trigger it.  Each case is synthetic input read by the real readers, turned into requests and feeds
by right_rail_gate_ffs, and decided by the pinned engine on one signed store.  A payment that is never sent (the claim was set
aside) is not ALLOW either; what is never allowed is an ALLOW row for the subject's payment."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests import _class_cases as cc
from app import right_rail_gate_ffs as ffs
from app import right_rail_reader_leie as leie
from app import right_rail_x12_837 as r837
from tests import _class_kinds as ck
from tests import test_right_rail_gate_formats as fx
from tests._class_harness import SECRET, Harness, read_case

APP = Path(__file__).resolve().parents[1] / "app"


class ReaderFindingTests(Harness):
    def test_a_case_with_no_fault_is_paid_and_one_with_a_clean_exclusion_row_is_held(self) -> None:
        """The harness can say ALLOW: without it, an assertion of never ALLOW would pass for any input."""
        free, listed = cc.Parts(1), cc.Parts(2)
        listed.leie = [cc.tl.row(npi=listed.npi)]
        cases = [read_case(free), read_case(listed)]
        rows = self.decide(cases)
        self.assertEqual([(r[0] == cases[0]["pid"], r[2], r[3]) for r in rows[0]], [(True, "ALLOW", ())])
        self.assertEqual([(r[2], r[3]) for r in rows[1]], [("HOLD", ("PROVIDER_EXCLUDED",))])

    def test_a_fault_in_a_file_of_many_claims_holds_only_the_claims_it_can_belong_to(self) -> None:
        """Three oracles for each fault: no ALLOW for a claim it may belong to; every claim sent or set aside once (a file that cannot be
        read is one item); every claim in a unit the fault does not touch is sent and ALLOW.  The file without the fault pays every claim."""
        faults = cc.multi_faults()
        parts = [cc.multi(399)] + [f.make(400 + i) for i, f in enumerate(faults)]
        cases = [read_case(p) for p in parts]
        for fault, p, case, rows in zip([None, *faults], parts, cases, self.decide(cases)):
            with self.subTest(fault=fault.name if fault else "none"):
                pid = {t: ffs.canonical_id("C", p.bill, p.cids[t]) for t in cc.TAGS}
                sent, allowed = {r.payment_id for r in case["sent"]}, {r[0] for r in rows if r[2] == "ALLOW"}
                if fault and fault.refused:
                    self.assertEqual((sent, [a.id for a in case["aside"]]), (set(), ["file 0"]))
                    continue
                for tag in cc.TAGS:
                    self.assertEqual((pid[tag] in sent) + sum(a.id == p.cids[tag] for a in case["aside"]), 1, f"{tag} must be sent or set aside, once")
                for r in case["sent"]:  # never a claim under another claim's member
                    tag = next(t for t in cc.TAGS if pid[t] == r.payment_id)
                    self.assertEqual(r.member_key, ffs.member_key(SECRET, p.members[tag]), f"{tag} sent under another member")
                for tag in fault.hurt if fault else ():
                    self.assertNotIn(pid[tag], allowed, f"{tag} may be hurt by {fault.name}")
                    for a in case["aside"]:
                        if a.id == p.cids[tag] and a.cause == "quarantined":
                            self.assertTrue(a.reader, f"{tag} is held with no cause from the reader")
                for tag in set(cc.TAGS) - (fault.touched if fault else set()):
                    self.assertIn(pid[tag], allowed, f"{tag} is in a unit {fault.name if fault else 'nothing'} does not touch")

    def test_a_blank_line_in_the_exclusion_list_is_skipped_but_a_spoiled_number_holds_only_its_provider(self) -> None:
        blank, other, mine = cc.Parts(1), cc.Parts(2), cc.Parts(3)
        blank.leie_raw = (cc.tl.HEAD + cc.tl.row(npi=cc.tl.make_npi(1)) + "   \n" + cc.tl.row(npi=cc.tl.make_npi(5), last="OTHER")).encode()
        other.leie = [cc.tl.row(last="OTHER", npi=other.npi + ".0")]  # a spoiled number under another name than the claim's provider
        mine.leie = [cc.tl.row(last="", bus="SYNTHETIC CLINIC", npi=mine.npi + ".0")]
        cases = [read_case(p) for p in (blank, other, mine)]
        self.assertEqual([a.cause for a in cases[1]["left"]], ["exclusion_npi_unreadable"])
        self.assertEqual(cases[0]["left"], ())
        rows = self.decide(cases)
        self.assertEqual([[(r[2], r[3]) for r in rs] for rs in rows], [[("ALLOW", ())], [("ALLOW", ())], []])
        self.assertEqual([(a.cause, a.reader.split(" ")[:2]) for a in cases[2]["aside"]], [("exclusion_npi_unreadable", ["exclusion", "row"])])  # the hold names the row

    def test_a_clean_copy_of_a_claim_set_aside_is_decided_and_a_copy_of_one_sent_is_a_retry(self) -> None:
        hurt = cc.envelope("repeated_element", "837")
        late, early = cc.Parts(1), cc.Parts(2)
        late.earlier = [hurt(1)]  # the hurt copy first, never sent; the clean one after
        early.f837, early.earlier = hurt(2).f837, [cc.Parts(2)]  # the clean copy first; the hurt one after
        cases = [read_case(late), read_case(early)]
        self.assertEqual([[(a.cause, a.reader) for a in c["aside"]] for c in cases], [[("quarantined", "repeated_element")], [("retry", "")]])
        rows = self.decide(cases)
        self.assertEqual([[(r[0] == c["pid"], r[2]) for r in rs] for c, rs in zip(cases, rows)], [[(True, "ALLOW")]] * 2)

    # Real faults this test finds (left failing; the failing subtests are named by kind, subject and where):
    #   A. an 837 envelope fault inside a claim (a segment or set fault) is dropped by requests_of, which ignores the reader's quarantines,
    #      so the claim is still paid;
    #   B. a quarantined LEIE row (not a clean exclusion) is ignored by feeds, so an excluded provider whose row is set aside is paid;
    #   C. excluded_after_as_of: an exclusion dated after the as-of day does not hold the claim;
    #   D. isa_unframed (file_wide): an unframed file after the last good interchange does not make every line reviewed.
    def never_allowed(self, wanted: str) -> None:
        variants = [v for v in cc.variants() if v.where == wanted]
        cases = [read_case(v.make(100 + i)) for i, v in enumerate(variants)]
        for v, case, rows in zip(variants, cases, self.decide(cases)):
            with self.subTest(kind=f"{v.module.removeprefix('right_rail_')}:{v.kind}", subject=v.subject, where=v.where):
                if v.mode != "trigger_only":
                    allowed = [r for r in rows if r[0] == case["pid"] and r[2] == "ALLOW"]
                    self.assertLessEqual(len(allowed), 1 if v.mode == "allow_once" else 0, f"ALLOW for the payment of a {v.subject} with a {v.kind} record: {rows}")

    def test_a_finding_on_a_row_that_does_not_exclude_the_provider_holds_nothing(self) -> None:
        """Rows that are live exclusions hold the claim whatever else is wrong with them; this is the same row reinstated before the claim's
        day, so it is not an exclusion, and the claim is paid."""
        kinds = ("duplicate_row", "npi_two_names", "waiver_after_as_of", "waiver_without_state", "unknown_exclusion_type")
        cases = [read_case(cc.leie_case(k, lifted=True)(100 + i)) for i, k in enumerate(kinds)]
        for k, case, rows in zip(kinds, cases, self.decide(cases)):
            with self.subTest(kind=k):
                self.assertIn(k, case["seen"]["right_rail_reader_leie"], "the reader did not record the kind")
                self.assertEqual({(r[2], r[3]) for r in rows if r[0] == case["pid"]}, {("ALLOW", ())})

    def test_every_case_is_paid_with_its_fault_removed(self) -> None:
        """Never ALLOW would pass for a case whose scaffolding is itself held: each variant, built with its fault left out, must be ALLOW."""
        variants = cc.variants()
        cases = [read_case((v.clean or cc.Parts)(100 + i)) for i, v in enumerate(variants)]
        for v, case, rows in zip(variants, cases, self.decide(cases)):
            with self.subTest(kind=f"{v.module.removeprefix('right_rail_')}:{v.kind}", subject=v.subject, where=v.where):
                lines = [(r[2], r[3]) for r in rows if r[0] == case["pid"]]  # one row per line
                self.assertEqual(set(lines), {("ALLOW", ())}, "held with no fault")

    def test_no_finding_or_set_aside_on_a_member_provider_claim_or_line_is_ever_allowed(self) -> None:
        self.never_allowed("in_subject")

    def test_no_finding_elsewhere_in_the_file_of_a_claim_or_member_lets_it_be_allowed(self) -> None:
        """A fault after the last good interchange hides nothing the subject sent, but the 834 reader already treats it as a lost
        cancellation or death (every line is reviewed); the 837 path must not be looser."""
        self.never_allowed("file_wide")


class GeneratorTests(unittest.TestCase):
    def test_every_kind_a_reader_can_record_has_an_input_that_triggers_it(self) -> None:
        """A kind found in the source with no variant, or a variant that does not make its reader record that kind, fails here; add or
        fix the input in tests/_class_cases.py."""
        found, variants = ck.all_kinds(), cc.variants()
        self.assertEqual(sorted(found - {(v.module, v.kind) for v in variants}), [], "a kind no generator covers")
        self.assertEqual(sorted({(v.module, v.kind) for v in variants} - found), [], "a generator for a kind the source no longer records")
        for i, v in enumerate(variants):
            with self.subTest(kind=f"{v.module}:{v.kind}", subject=v.subject):
                if v.triggers:
                    self.assertIn(v.kind, read_case(v.make(100 + i))["seen"][v.module], "the input did not make the reader record the kind")

    def test_no_claim_is_lost_whatever_unit_of_the_envelope_is_not_opened(self) -> None:
        """For every kind of fault the envelope can record in an 837 file (the list the generator test keeps whole), the claim is sent, set
        aside under its id, or its unit is one item that names the reader's cause: never nothing."""
        for kind in cc.ENVELOPE:
            if cc.ONLY.get(kind, "837") != "837":
                continue
            with self.subTest(kind=kind):
                p = cc.envelope(kind, "837")(1)
                read = r837.read_837(p.file837())
                listed = leie.read_leie((cc.tl.HEAD + cc.tl.row(npi=cc.tl.make_npi(1))).encode(), source="synthetic", as_of=cc.AS_OF)
                sent, aside = ffs.requests_of([read], fx.TENANT, fx.PROGRAM, fx.PERIOD, SECRET, listed)
                mine = [a for a in aside if a.id == p.cid]
                units = [a for a in aside if a.id.split()[0] in ("file", "set", "group", "interchange", "segment")]
                self.assertTrue(sent or mine or units, "the claim vanished")
                self.assertEqual(len(units), len({a.id for a in units}), "one item per unit")
                causes = {q.cause for q in read.quarantines} | {read.refused}
                self.assertTrue(all(a.cause == "quarantined" and a.reader in causes for a in units), [(a.id, a.reader) for a in units])

    def test_every_set_aside_cause_is_a_string_the_walker_can_read(self) -> None:
        self.assertEqual(ck.non_literal("right_rail_gate_ffs"), [], "a cause the kind list cannot see, so no class test covers it")

    def test_the_readers_on_the_claim_path_are_the_ones_the_kind_list_covers(self) -> None:
        """A reader module the claim path starts to use must be listed in ON_CLAIM_PATH, or its kinds are not covered."""
        readers = {p.stem for p in APP.glob("right_rail_x12_8*.py")} | {p.stem for p in APP.glob("right_rail_reader_*.py")} - {"right_rail_reader_lines"}
        self.assertEqual(sorted(readers - set(ck.ON_CLAIM_PATH) - set(ck.NOT_ON_CLAIM_PATH)), [], "a reader no list names")
        for path in APP.glob("*.py"):
            tree = ast.parse(path.read_text("utf-8"))
            imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "app" for a in n.names} | \
                       {n.module.split(".")[-1] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("app.")}
            if not path.stem.startswith(("right_rail_x12", "right_rail_reader_")):
                self.assertEqual(sorted(imported & set(ck.NOT_ON_CLAIM_PATH)), [], f"{path.name} reads a reader the class test treats as off the claim path")


if __name__ == "__main__":
    unittest.main()
