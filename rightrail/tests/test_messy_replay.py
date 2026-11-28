"""A deliberately messy state hand-over (tests/_messy_file.py, fixed seed) through the whole replay path.

Tests that pass pin what holds today: nothing is lost, the answer is the same every time, and the blast radius of each known fault.
Tests marked expected failure state what should hold and name the finding (MR-n) that stops it; each one starts passing when its finding is fixed,
and then the marker must go.  Findings, with the code that causes them:
  MR-2  one envelope count that is off (SE) holds every claim in its set, clean ones included          (app/right_rail_x12.py:445)
  MR-6  units of 99999 on a line are accepted                                                           (app/right_rail_gate_ffs.py:206)
  MR-7  one service sent under two claim ids is held on one of the two for only 6 of 8 pairs            (app/right_rail_gate_ffs.py)
  MR-8  a repeated roster loop, padded fields and a stray byte in one set hold claims that were tolerable (app/right_rail_gate_ffs.py:289)
  MR-9  each of 200 exclusion-list rows without an NPI is its own set-aside item                         (app/right_rail_gate_ffs.py:306)
"""

import unittest

from tests import _messy_file as mf
from tests import _messy_run as run

DIGEST = "869b2a9703243418491ba8d2068a77d6a5e451f4b03c01c7bea17d5057bafc5e"
STAFF_BOUND = 150  # a few thousand records should not ask staff for more items than this
STAFF_TODAY = 470  # what the run gives today (464 before the roster loops with no member id were sent as later changes for members on the roster, each now holding its member; 431 without the roster loop with no member id and the short exclusion row, 445 without the replacements and voids that do not read whole or name their claim another way, 457 before the roster loops with no member id whose name was changed, swapped or spaced, 463 before the exclusion row that is not UTF-8); the pinned test keeps it from growing
CLEAN_HELD_TODAY = 149  # clean claims held today (all of them MR-2 or a neighbour of a damaged segment)


def go(skip=(), cut=False):
    w, files, notes = mf.build(skip=skip, cut=cut)
    w.files = files
    return w, files, notes, run.replay(files, w)


class Messy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w, files, notes, replayed = go()
        cls.w, cls.a = w, run.analyse(w, files, notes, replayed)
        cls.out = run.headline(cls.a, w)

    def missed(self, *kinds):
        return {k: self.a["kinds"][k]["missed"] for k in kinds if self.a["kinds"][k]["missed"]}

    def test_every_claim_is_accounted_for(self):
        self.assertEqual(self.a["lost"], [])
        self.assertEqual(self.a["code"], 0)
        self.assertEqual(self.out["accepted"] + self.out["set_aside_or_held"], self.out["distinct_claims"])

    def test_output_is_deterministic(self):
        self.assertEqual(run.digest(self.a, self.w), DIGEST)
        again, _, _ = mf.build()
        self.assertEqual(again.manifest, self.w.manifest)

    def test_blast_radius_is_pinned(self):
        self.assertLessEqual(self.out["clean_claims_held"], CLEAN_HELD_TODAY)
        self.assertLessEqual(self.out["staff_items"], STAFF_TODAY)

    def test_most_of_the_file_is_accepted(self):
        self.assertGreater(self.out["accepted"] * 100, self.out["distinct_claims"] * 80)

    @unittest.expectedFailure
    def test_no_clean_claim_is_held_MR2(self):
        self.assertEqual(self.a["clean_held"], [])

    def test_voided_and_replaced_originals_are_not_paid(self):
        self.assertEqual(self.missed("void_before_original", "void_after_original", "replacement_before_original", "replacement_after_original",
                                     *mf.NAMING_KINDS), {})

    @unittest.expectedFailure
    def test_absurd_units_are_held_MR6(self):
        self.assertEqual(self.missed("units_absurd"), {})

    @unittest.expectedFailure
    def test_same_service_under_two_ids_is_held_MR7(self):
        self.assertEqual(self.missed("same_service_new_claim_id"), {})

    def test_every_other_defect_is_caught_or_accepted(self):
        known = {"units_absurd", "same_service_new_claim_id"}
        self.assertEqual({k: v for k, v in self.missed(*self.a["kinds"]).items() if k not in known}, {})

    @unittest.expectedFailure
    def test_tolerated_defects_are_not_held_MR8(self):
        self.assertEqual([k for k in self.a["allow_held"] if self.a["claim_of"][k].defect], [])

    @unittest.expectedFailure
    def test_staff_items_are_within_bound_MR9(self):
        self.assertLessEqual(self.out["staff_items"], STAFF_BOUND)

    def test_each_staff_cause_has_wording(self):
        self.assertEqual(sorted({c for (c, _) in self.a["items"] if c not in run.ACTIONS and not c.startswith("feed:")}), [])


class Nobody(unittest.TestCase):
    def test_a_roster_loop_with_no_member_id_that_matches_no_member_blanks_the_member_feeds(self):
        from app import right_rail_gate_ffs as ffs, right_rail_reader_leie as leie, right_rail_x12_834 as r834
        from tests import test_reader_leie as tl
        absent = {}
        for nobody in (False, True):  # with it, the messy roster's members whose names do not read must not keep the feeds live
            roster = r834.read_834(mf.build(nobody=nobody)[1]["834"])
            self.assertTrue(any(r.name_raw_hex for r in roster.rows))
            (_, sent), _ = ffs.feeds(int(mf.ROSTER_DAY), roster, leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2027-03-15"), ("2027-03-15", []), b"s")
            absent[nobody] = sent[3] == (bytes(77), b"")
        self.assertEqual(absent, {False: False, True: True})


class Cut(unittest.TestCase):
    """The same file cut off in its last line: only the set it ends in is set aside."""

    def test_truncated_last_line_holds_only_its_set(self):
        w, files, notes, replayed = go(cut=True)
        a = run.analyse(w, files, notes, replayed)
        out = run.headline(a, w)
        self.assertEqual((a["lost"], a["kinds"]["truncated_last_line"]["missed"]), ([], []))
        self.assertIn("iea_missing", {cause for cause, _ in a["items"]})  # staff are told a replacement or void may have been cut off
        self.assertGreater(out["accepted"] * 100, out["distinct_claims"] * 80)


if __name__ == "__main__":
    unittest.main()
