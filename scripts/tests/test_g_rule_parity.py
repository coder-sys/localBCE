"""Tests for the Phase 2 G-rule parity harness (scripts/g_rule_parity.py)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import g_rule_parity as gp  # noqa: E402

ROOT = gp.ROOT


def pinned(text):
    """Replace each `snap KIND ASOF COUNT PIN` placeholder pin with the pin of the rows that follow it."""
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        fs = raw.split()
        if fs[:1] != ["snap"]:
            continue
        kind = fs[1]
        rows = []
        for r in lines[i + 1:]:
            rf = r.split()
            if rf[:1] != [kind]:
                break
            rows.append(gp.parse_line_fields(rf[1:]) if kind in ("released", "unresolved")
                        else tuple(int(x) for x in rf[1:]))
        lines[i] = " ".join(fs[:4] + [gp.snapshot_pin(kind, int(fs[2]), int(fs[3]), rows)])
    return "\n".join(lines) + "\n"


SYNTHETIC = """
today 20270315
snap released 20270315 0 x
snap unresolved 20270315 0 x
snap dmf 20270301 1 x
dmf 9001 20270110
snap pdeath 20270301 1 x
pdeath 7701 20270120
snap excl 20270310 1 x
excl 504 20260101 99991231
snap span 20270314 3 x
span 1001 501 20260101 20271231
span 9001 501 20260101 20271231
span 1003 501 20260101 20270131
case mixed
line 1 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
line 2 FFS_CLAIM 9001 7001 7001 20270305 99213 1 12500 HOLD MEMBER_DECEASED
line 3 FFS_CLAIM 1003 7001 7001 20270305 99213 1 12500 HOLD MEMBER_NOT_ENROLLED
line 4 FFS_CLAIM 1001 504 7001 20270306 99213 1 12500 HOLD PROVIDER_EXCLUDED
line 5 FFS_CLAIM 1001 7001 7701 20270307 99213 1 12500 HOLD PROVIDER_DECEASED
commit
line 6 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HOLD FFS_DUPLICATE_LINE
line 7 FFS_CLAIM 1002 7001 7001 20270305 99213 1 12500 HOLD MEMBER_NOT_ENROLLED
commit
"""


def find_engine():
    env = os.environ.get("LOCALBCE_RUST_ENGINE")
    candidates = [env] if env else []
    target = os.environ.get("CARGO_TARGET_DIR")
    for base in filter(None, [target, os.path.join(ROOT, "rust-engine", "target")]):
        for profile in ("debug", "release"):
            for name in ("rust-engine", "rust-engine.exe"):
                candidates.append(os.path.join(base, profile, name))
    return next((c for c in candidates if c and os.path.isfile(c)), None)


class ParseVectors(unittest.TestCase):
    def test_rules_v1_every_line_parsed_with_expectation(self):
        with open(gp.DEFAULT_VECTORS, encoding="utf-8") as f:
            text = f.read()
        cases = gp.parse_vectors(text)
        parsed = sum(len(b) for c in cases for b in c.batches)
        declared = sum(1 for raw in text.splitlines() if raw.startswith("line "))
        self.assertEqual(parsed, declared)
        self.assertGreater(parsed, 200)

    def test_unknown_directive_is_refused(self):
        with self.assertRaises(gp.VectorError):
            gp.parse_vectors("case x\nbogus 1\n")

    def test_uncommitted_batch_is_refused(self):
        with self.assertRaises(gp.VectorError):
            gp.parse_vectors("case x\nline 1 FFS_CLAIM 1 2 2 20270101 1 1 1 ALLOW -\n")

    def test_dropped_snapshot_contributes_no_rows(self):
        cases = gp.parse_vectors(pinned(
            "snap dmf 20270301 1 x\ndmf 5 20270101\ncase c\n"
            "line 1 FFS_CLAIM 5 2 2 20270201 1 1 1 HOLD MEMBER_DECEASED\ncommit\ndrop dmf\n"
            "line 2 FFS_CLAIM 5 2 2 20270201 1 1 1 HUMAN_REVIEW STALE_DMF\ncommit\n"))
        self.assertEqual(cases[0].batches[0][0][2]["dmf"], [(5, 20270101)])
        self.assertEqual(cases[0].batches[1][0][2]["dmf"], [])

    def test_snapshot_failing_its_pin_contributes_no_rows(self):
        """Lean treats a snapshot whose rows do not hash to its declared pin as missing (review 2026-11-07)."""
        good = pinned("snap dmf 20270301 1 x\ndmf 5 20270101\n")
        bad = good.replace("dmf 5 20270101", "dmf 6 20270101")
        for text, rows in ((good, [(5, 20270101)]), (bad, []), ("snap dmf 20270301 1 00\ndmf 5 20270101\n", [])):
            cases = gp.parse_vectors(text + "case c\nline 1 FFS_CLAIM 5 2 2 20270201 1 1 1 ALLOW -\ncommit\n")
            self.assertEqual(cases[0].batches[0][0][2]["dmf"], rows)

    def test_pins_reproduce_rules_v1_except_its_wrong_pin_cases(self):
        """The harness's pin is Lean's: every declared pin in rules_v1 matches except the deliberately wrong ones."""
        with open(gp.DEFAULT_VECTORS, encoding="utf-8") as f:
            lines = f.read().splitlines()
        case, matched, wrong_cases = None, 0, set()
        for i, raw in enumerate(lines):
            fs = raw.split()
            if fs[:1] == ["case"]:
                case = fs[1]
            if fs[:1] != ["snap"]:
                continue
            rows = []
            for r in lines[i + 1:]:
                rf = r.split()
                if rf[:1] != [fs[1]]:
                    break
                rows.append(gp.parse_line_fields(rf[1:]) if fs[1] in ("released", "unresolved")
                            else tuple(int(x) for x in rf[1:]))
            if gp.snapshot_pin(fs[1], int(fs[2]), int(fs[3]), rows) == fs[4]:
                matched += 1
            else:
                wrong_cases.add(case)
        self.assertGreater(matched, 100)
        self.assertTrue(wrong_cases)
        self.assertTrue(all(c.endswith(("_wrong_pin", "_bad_pin")) for c in wrong_cases), wrong_cases)


class DeriveClaim(unittest.TestCase):
    def setUp(self):
        self.case = gp.parse_vectors(pinned(SYNTHETIC))[0]

    def flags(self, batch, index, earlier=()):
        line, _, facts, allowed = self.case.batches[batch][index]
        return gp.derive_claim(line, dict(facts, released=facts["released"] + allowed), set(earlier))

    def test_clean_line_passes_every_flag(self):
        c = self.flags(0, 0)
        self.assertEqual((c["eligibility_active"], c["provider_enrolled"], c["is_duplicate"],
                          c["recipient_not_deceased"]), (1, 1, 0, 1))
        self.assertTrue(c["eligibility_period_from"] <= c["date_of_service_from"] <= c["eligibility_period_thru"])

    def test_deceased_member(self):
        self.assertEqual(self.flags(0, 1)["recipient_not_deceased"], 0)

    def test_span_ended_before_service_fails_month_of_service(self):
        c = self.flags(0, 2)
        self.assertEqual(c["eligibility_active"], 1)
        self.assertFalse(c["eligibility_period_from"] <= c["date_of_service_from"] <= c["eligibility_period_thru"])

    def test_no_span_fails_identity(self):
        self.assertEqual(self.flags(1, 1)["eligibility_active"], 0)

    def test_excluded_or_dead_provider(self):
        self.assertEqual(self.flags(0, 3)["provider_enrolled"], 0)
        self.assertEqual(self.flags(0, 4)["provider_enrolled"], 0)

    def test_earlier_allow_in_case_is_a_duplicate(self):
        self.assertEqual(self.flags(1, 0)["is_duplicate"], 1)

    def test_cap_line_for_another_plan_fails_month_of_service(self):
        cases = gp.parse_vectors(pinned("snap span 20270314 1 x\nspan 1001 501 20260101 20271231\ncase c\n"
                                 "line 1 CAP_820 1001 502 502 20270301 0 1 45000 HOLD MEMBER_NOT_ENROLLED\ncommit\n"))
        line, _, facts, _ = cases[0].batches[0][0]
        c = gp.derive_claim(line, facts, set())
        self.assertFalse(c["eligibility_period_from"] <= c["date_of_service_from"] <= c["eligibility_period_thru"])

    def test_uncompared_gates_always_pass(self):
        c = self.flags(0, 0)
        for k, v in gp.PASSING_FLAGS.items():
            self.assertEqual(c[k], v)


class ReleasedBy(unittest.TestCase):
    def test_only_fully_allowed_payments_release(self):
        cases = gp.parse_vectors(
            "case c\n"
            "line 1:900 FFS_CLAIM 1 2 2 20270101 1 1 1 ALLOW -\n"
            "line 2:900 FFS_CLAIM 1 2 2 20270102 1 1 1 HOLD MEMBER_DECEASED\n"
            "line 3 FFS_CLAIM 1 2 2 20270103 1 1 1 ALLOW -\n"
            "commit\n"
            "line 4 FFS_CLAIM 1 2 2 20270101 1 1 1 ALLOW -\n"
            "commit\n")
        _, _, _, allowed = cases[0].batches[1][0]
        self.assertEqual([ln.id for ln in allowed], [3])

    def test_redo_payment_does_not_release_again_or_duplicate_itself(self):
        line = gp.Line(7, 7, "FFS_CLAIM", 1, 2, 2, 20270101, 1, 1, 1)
        facts = {"dmf": [], "pdeath": [], "excl": [], "span": [], "released": [line]}
        self.assertEqual(gp.derive_claim(line, facts, set(), {7})["is_duplicate"], 0)
        self.assertEqual(gp.derive_claim(line, facts, set(), set())["is_duplicate"], 1)
        self.assertEqual(gp.released_by([(line, gp.Expect("ALLOW", ()), facts, [])], [7]), [])


class Classify(unittest.TestCase):
    def test_categories(self):
        E = gp.Expect
        self.assertEqual(gp.classify(E("ALLOW", ()), "APPROVED", None), "agree_allow")
        self.assertEqual(gp.classify(E("ALLOW", ()), "DENIED", "G9_RECIPIENT_DECEASED"), "local_denies_lean_allows")
        self.assertEqual(gp.classify(E("HOLD", ("MEMBER_DECEASED",)), "DENIED", "G9_RECIPIENT_DECEASED"), "agree_hold")
        self.assertEqual(gp.classify(E("HOLD", ("MEMBER_DECEASED",)), "DENIED", "G7_DUPLICATE_CLAIM"),
                         "hold_reason_differs")
        self.assertEqual(gp.classify(E("HOLD", ("MEMBER_DECEASED",)), "APPROVED", None),
                         "lean_holds_on_mapped_rule_local_approves")
        self.assertEqual(gp.classify(E("HOLD", ("ALREADY_DECIDED",)), "APPROVED", None),
                         "lean_holds_on_unmapped_rule_local_approves")
        self.assertEqual(gp.classify(E("HUMAN_REVIEW", ("STALE_DMF",)), "APPROVED", None), "lean_review_local_approves")
        self.assertEqual(gp.classify(E("HUMAN_REVIEW", ("STALE_DMF",)), "DENIED", "G1_IDENTITY_VERIFICATION_FAILED"),
                         "lean_review_local_denies")

    def test_every_category_has_a_note(self):
        self.assertEqual(gp.classify(None, "APPROVED", None), "no_lean_expectation")
        cats = {"no_lean_expectation", "agree_allow", "agree_hold", "hold_reason_differs", "local_denies_lean_allows",
                "lean_holds_on_mapped_rule_local_approves", "lean_holds_on_unmapped_rule_local_approves",
                "lean_review_local_approves", "lean_review_local_denies"}
        self.assertEqual(set(gp.CATEGORY_NOTES), cats)

    def test_mapping_matches_plan_section_3(self):
        self.assertEqual(gp.G_TO_LEAN["G9_RECIPIENT_DECEASED"], {"MEMBER_DECEASED"})
        self.assertEqual(gp.G_TO_LEAN["G7_DUPLICATE_CLAIM"], {"FFS_DUPLICATE_LINE"})
        self.assertEqual(gp.G_TO_LEAN["G1_IDENTITY_VERIFICATION_FAILED"], {"MEMBER_NOT_ENROLLED"})
        self.assertEqual(gp.G_TO_LEAN["G3_MONTH_OF_SERVICE_FAILED"], {"MEMBER_NOT_ENROLLED"})
        self.assertEqual(gp.G_TO_LEAN["G5_PROVIDER_NOT_ENROLLED"], {"PROVIDER_EXCLUDED", "PROVIDER_DECEASED"})


ENGINE = find_engine()


@unittest.skipUnless(ENGINE, "G-RULE PARITY END-TO-END NOT RUN: rust-engine binary not built "
                             "(cargo build in rust-engine/, or set LOCALBCE_RUST_ENGINE)")
class EndToEnd(unittest.TestCase):
    def test_synthetic_vectors_agree(self):
        records = gp.compare(gp.parse_vectors(pinned(SYNTHETIC)), ENGINE)
        got = {r["line_id"]: (r["category"], r["localbce_reason"]) for r in records}
        self.assertEqual(got, {
            1: ("agree_allow", None),
            2: ("agree_hold", "G9_RECIPIENT_DECEASED"),
            3: ("agree_hold", "G3_MONTH_OF_SERVICE_FAILED"),
            4: ("agree_hold", "G5_PROVIDER_NOT_ENROLLED"),
            5: ("agree_hold", "G5_PROVIDER_NOT_ENROLLED"),
            6: ("agree_hold", "G7_DUPLICATE_CLAIM"),
            7: ("agree_hold", "G1_IDENTITY_VERIFICATION_FAILED"),
        })

    def test_rules_v1_report_is_complete_and_non_authoritative(self):
        with open(gp.DEFAULT_VECTORS, encoding="utf-8") as f:
            cases = gp.parse_vectors(f.read())
        report = gp.summarize(gp.compare(cases, ENGINE), gp.DEFAULT_VECTORS)
        self.assertFalse(report["authoritative"])
        self.assertEqual(report["agreements"] + report["differences"] + report["not_compared"], report["lines"])
        self.assertTrue(set(report["by_category"]) <= set(gp.CATEGORY_NOTES))
        self.assertIn("## Differences", gp.markdown(report))


class NoRightRailWrites(unittest.TestCase):
    def test_harness_lives_outside_rightrail(self):
        self.assertFalse(os.path.abspath(gp.__file__).startswith(os.path.join(ROOT, "rightrail") + os.sep))


if __name__ == "__main__":
    unittest.main()
