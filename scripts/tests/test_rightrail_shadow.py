"""The shadow run's pure parts (scripts/rightrail_shadow.py), and the run itself where it can run.

**A shadow run is a test-key run. It decides nothing and binds no one.**

In CI (Python and the Rust engine only):
- the scenario set: its shape, its expected outcomes stated in advance, and that each claim's flags and its feed rows
  say the same thing on a matched scenario (so agreement there is by construction) and differ only where a scenario
  says so;
- the Rust engine gives each scenario its expected localBCE decision, and the adapter its expected request or
  set-aside;
- the comparison, the records and the summary, built from a stand-in for RightRail's answer: every record carries the
  statement in words, no raw member id is written, and an answer that is not the expected one is reported.

Local only: the run against RightRail's pinned engine.  Skipped with the reason named unless SHADOW_RUN=1 and
SHADOW_ALLOW_SCRATCH_KEYGEN=1 are set on Windows with RightRail's executables and the signer present; the owner accepted
the CI skip on 2026-11-28.  Design: docs/integration/SHADOW_RUN_DESIGN.md.  Synthetic, not legally verified, nonpayment.
"""

import contextlib
import copy
import datetime
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import rightrail_claim_adapter as ad  # noqa: E402
import rightrail_shadow as sh  # noqa: E402
import rightrail_shadow_child as child  # noqa: E402
from test_g_rule_parity import ENGINE  # noqa: E402  the built rust-engine binary, or None

ROOT = sh.ROOT


def stand_in(doc: dict, change: dict | None = None) -> tuple[dict, dict]:
    """(a stand-in for the child's answer that says exactly what each scenario expects, the adapter's requests).
    `change` maps a scenario to another (outcome, reasons)."""
    job, sent = sh.job_of(doc)
    by_name = {s["name"]: s for s in doc["scenarios"]}
    steps = []
    for step in job["steps"]:
        rows = []
        for r in step["requests"]:
            want = by_name[r["scenario"]]["expect"]["rightrail"]
            outcome, reasons = (change or {}).get(r["scenario"], (want["outcome"], want["reasons"]))
            rows += [[r["payment_id"], at, outcome, reasons] for at in range(len(r["lines"]))]
        steps.append({"name": step["name"], "store": step["store"], "rows": rows,
                      "feed_digests": dict.fromkeys(sh.FEEDS, "00"), "checkpoint_digests": []})
    return ({"today": job["today"], "steps": steps, "stores_removed": True, "scenario_set_sha3_512": "00",
             "engine": {"name": "gate_engine.exe", "sha256": "00", "is_the_pinned_program": True}}, sent)


def expected_local(doc: dict) -> dict:
    return {s["name"]: tuple(s["expect"]["local"]) for s in doc["scenarios"]}


class ScenarioSet(unittest.TestCase):
    def setUp(self):
        self.doc = sh.load_scenarios()
        self.by_name = {s["name"]: s for s in self.doc["scenarios"]}

    def feeds_for(self, name):
        return self.doc["feeds"][next(st["feeds"] for st in self.doc["steps"] if name in st["scenarios"])]

    def test_shape(self):
        kinds = [s["kind"] for s in self.doc["scenarios"]]
        self.assertEqual((len(kinds), kinds.count("matched"), kinds.count("differ"), kinds.count("not_sent")), (13, 7, 4, 2))
        self.assertEqual([st["name"] for st in self.doc["steps"]], ["first_batch", "second_batch", "stale_feed"])
        self.assertEqual(len({s["claim"]["claim_id"] for s in self.doc["scenarios"]}), 13)
        for s in self.doc["scenarios"]:
            self.assertTrue(s["why"], s["name"])

    def test_the_scenarios_expected_to_differ_are_stated_in_advance(self):
        """The owner's three: a stale feed, a member absent from the feed, an exact repeat of a paid claim."""
        differ = {s["name"]: s["expect"] for s in self.doc["scenarios"] if s["kind"] == "differ"}
        self.assertEqual(differ["stale_death_feed"]["rightrail"], {"outcome": "HUMAN_REVIEW", "reasons": ["STALE_DMF"]})
        self.assertEqual(differ["member_absent_from_feed"]["rightrail"], {"outcome": "HOLD", "reasons": ["MEMBER_NOT_ENROLLED"]})
        self.assertEqual(differ["repeat_of_a_paid_claim"]["rightrail"], {"outcome": "ANSWERED", "reasons": ["FFS_DUPLICATE_LINE"]})
        for name, want in differ.items():
            self.assertEqual(want["local"], ["APPROVED", None], name)  # localBCE approves each; RightRail does not allow
            self.assertNotIn(want["category"], sh.AGREEMENT, name)
            self.assertIn("Expected to differ.", self.by_name[name]["why"], name)

    def test_agreement_on_matched_scenarios_is_by_construction(self):
        """A matched scenario's flags are exactly what its feed rows say; a `differ` scenario's flags part from the
        rows only where it says so."""
        for s in self.doc["scenarios"]:
            derived = sh.flags_from_feeds(s["claim"], self.feeds_for(s["name"]))
            self.assertEqual(set(derived), set(sh.FEED_FLAGS))
            parts = sorted(k for k in derived if derived[k] != s["claim"][k])
            self.assertEqual(parts, sorted(s.get("disagrees_on", [])), s["name"])
            if s["kind"] == "matched":
                self.assertEqual(parts, [], s["name"])
                self.assertIn(s["expect"]["category"], sh.AGREEMENT, s["name"])

    def test_the_repeat_repeats_the_paid_claim(self):
        first, repeat = self.by_name["repeat_first_claim"]["claim"], self.by_name["repeat_of_a_paid_claim"]["claim"]
        self.assertNotEqual(first["claim_id"], repeat["claim_id"])
        self.assertEqual({k: v for k, v in first.items() if k != "claim_id"}, {k: v for k, v in repeat.items() if k != "claim_id"})
        order = [n for st in self.doc["steps"] for n in st["scenarios"]]
        steps = {n: st["name"] for st in self.doc["steps"] for n in st["scenarios"]}
        self.assertLess(order.index("repeat_first_claim"), order.index("repeat_of_a_paid_claim"))
        self.assertNotEqual(steps["repeat_first_claim"], steps["repeat_of_a_paid_claim"])  # paid in an earlier batch

    def test_feeds_are_usable_or_stale_as_stated(self):
        """RightRail's rule: a feed is usable only with at least one row and an as-of within its maximum age."""
        today = datetime.date.fromisoformat(self.doc["today"])
        limit = {"dmf": 90, "pdeath": 90, "excl": 31, "span": 7}

        def age(feed):
            return (today - datetime.date.fromisoformat(feed["as_of"])).days

        for name, feeds in self.doc["feeds"].items():
            for kind in sh.FEEDS:
                self.assertTrue(feeds[kind]["rows"], (name, kind))
        self.assertTrue(all(0 <= age(self.doc["feeds"]["fresh"][k]) <= limit[k] for k in sh.FEEDS))
        stale = self.doc["feeds"]["stale_deaths"]
        self.assertEqual(age(stale["dmf"]), 104)
        self.assertEqual({k: stale[k] for k in ("pdeath", "excl", "span")},
                         {k: self.doc["feeds"]["fresh"][k] for k in ("pdeath", "excl", "span")})
        for feeds in self.doc["feeds"].values():
            for r in feeds["dmf"]["rows"] + feeds["pdeath"]["rows"]:
                self.assertLessEqual(r["date"], feeds["dmf" if "member_id" in r else "pdeath"]["as_of"])

    def test_adapter_gives_each_scenario_its_expected_request_or_set_aside(self):
        _, sent = sh.job_of(self.doc)
        for s in self.doc["scenarios"]:
            got, want = sent[s["name"]], s["expect"]["rightrail"]
            if "set_aside" in want:
                self.assertEqual((type(got), got.cause), (ad.SetAside, want["set_aside"]), s["name"])
            else:
                self.assertIsInstance(got, ad.Request, s["name"])
                self.assertEqual(got.assumptions, ("rendering_party_is_billing_npi_test_only",), s["name"])

    def test_the_job_holds_no_raw_member_id(self):
        job, _ = sh.job_of(self.doc)
        text = json.dumps(job)
        for s in self.doc["scenarios"]:
            self.assertNotIn(s["claim"]["member_id"], text)
        self.assertEqual([(st["name"], st["store"], len(st["requests"])) for st in job["steps"]],
                         [("first_batch", "main", 9), ("second_batch", "main", 1), ("stale_feed", "separate", 1)])
        self.assertEqual(job["today"], 20270315)
        self.assertNotIn("allow_scratch_keygen", job)  # only `run` sets it, from the owner's switch

    def test_a_bad_scenario_set_is_refused(self):
        raw = json.loads(sh.SCENARIOS.read_text("utf-8"))
        for change in (lambda d: d.update(synthetic=False),
                       lambda d: d["scenarios"].append(copy.deepcopy(d["scenarios"][0])),
                       lambda d: d["steps"][0]["scenarios"].pop(),
                       lambda d: d["steps"][0].update(feeds="nope"),
                       lambda d: d["scenarios"][0].update(kind="guess"),
                       lambda d: d["scenarios"][0].update(disagrees_on=["aid_code"]),
                       lambda d: d["scenarios"][0]["expect"].update(category="lean_review_local_approves")):
            doc = copy.deepcopy(raw)
            change(doc)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "s.json"
                path.write_text(json.dumps(doc), "utf-8")
                with self.assertRaises((sh.ScenarioError, KeyError)):
                    sh.load_scenarios(path)


@unittest.skipUnless(ENGINE, "SHADOW LOCAL DECISIONS NOT RUN: rust-engine binary not built "
                             "(cargo build in rust-engine/, or set LOCALBCE_RUST_ENGINE)")
class LocalDecisions(unittest.TestCase):
    def test_the_rust_engine_gives_each_scenario_its_expected_decision(self):
        doc = sh.load_scenarios()
        self.assertEqual(sh.local_decisions(doc, ENGINE), expected_local(doc))


class Comparison(unittest.TestCase):
    def test_categories(self):
        def rr(outcome, reasons=()):
            return {"rightrail_outcome": outcome, "rightrail_reasons": list(reasons)}

        cases = [
            (("APPROVED", None), rr("ALLOW"), "agree_allow"),
            (("DENIED", "G9_RECIPIENT_DECEASED"), rr("ALLOW"), "local_denies_lean_allows"),
            (("DENIED", "G9_RECIPIENT_DECEASED"), rr("HOLD", ["MEMBER_DECEASED"]), "agree_hold"),
            (("DENIED", "G7_DUPLICATE_CLAIM"), rr("HOLD", ["MEMBER_DECEASED"]), "hold_reason_differs"),
            (("APPROVED", None), rr("HOLD", ["MEMBER_NOT_ENROLLED"]), "lean_holds_on_mapped_rule_local_approves"),
            (("APPROVED", None), rr("HOLD", ["ALREADY_DECIDED"]), "lean_holds_on_unmapped_rule_local_approves"),
            (("APPROVED", None), rr("HUMAN_REVIEW", ["STALE_DMF"]), "lean_review_local_approves"),
            (("DENIED", "G1_IDENTITY_VERIFICATION_FAILED"), rr("HUMAN_REVIEW", ["STALE_DMF"]), "lean_review_local_denies"),
            (("APPROVED", None), rr("ANSWERED", ["FFS_DUPLICATE_LINE"]), "rightrail_answered_local_approves"),
            (("DENIED", "G7_DUPLICATE_CLAIM"), rr("ANSWERED", ["FFS_DUPLICATE_LINE"]), "rightrail_answered_local_denies"),
            (("APPROVED", None), rr("SET_ASIDE"), "not_sent_local_approves"),
            (("DENIED", "G9_RECIPIENT_DECEASED"), rr("SET_ASIDE"), "not_sent_local_denies"),
            (("APPROVED", None), None, "no_rightrail_answer"),
            (("DENIED", "G9_RECIPIENT_DECEASED"), None, "no_rightrail_answer"),
        ]
        for local, rightrail, want in cases:
            self.assertEqual(sh.classify(local[0], local[1], rightrail), want, (local, rightrail))
            self.assertIn(want, sh.CATEGORY_NOTES)
        with self.assertRaises(ValueError):
            sh.classify("REVIEW", None, None)


class Records(unittest.TestCase):
    def setUp(self):
        self.doc = sh.load_scenarios()

    def build(self, change=None):
        answer, sent = stand_in(self.doc, change)
        return sh.build_records(self.doc, "shadow-test", expected_local(self.doc), sent, answer), answer

    def test_every_record_says_in_words_what_it_is(self):
        records, answer = self.build()
        summ = sh.summary("shadow-test", records, {"engine": answer["engine"]}, "t0", "t1", None)
        self.assertIn("decides nothing and binds no one", sh.STATEMENT)
        self.assertIn("Test-key run", sh.STATEMENT)
        for item in records + [summ]:
            self.assertEqual(item["statement"], sh.STATEMENT)
            for marker in ("synthetic", "not_legally_verified", "nonpayment", "decides_nothing", "test_keys"):
                self.assertIs(item[marker], True)
        for r in records:
            self.assertIs(r["localbce"]["is_the_decision"], True)
            self.assertIs(r["adapter"]["intake_bypassed"], True)
            if r["rightrail"]:
                self.assertIs(r["rightrail"]["recorded_only"], True)
        self.assertIn("bypassed", summ["intake_note"])
        self.assertIn("by construction", summ["matched_note"])

    def test_the_expected_answers_give_the_expected_records(self):
        records, answer = self.build()
        self.assertEqual(len(records), 13)
        self.assertTrue(all(r["as_expected"] for r in records), [r["scenario"] for r in records if not r["as_expected"]])
        by = {r["scenario"]: r for r in records}
        self.assertEqual(by["clean_two_lines"]["adapter"]["lines"], 2)
        self.assertEqual(by["claim_total_mismatch"]["adapter"], {
            "sent": False, "payment_id": None, "lines": 0, "cents": 12600, "service_date": None,
            "set_aside_cause": "total_mismatch", "assumptions": [], "intake_bypassed": True})
        self.assertEqual(by["repeat_of_a_paid_claim"]["rightrail"]["mapped_status"], "DENIED")  # never approved
        self.assertEqual(by["stale_death_feed"]["context"]["feeds"], "stale_deaths")
        self.assertEqual([r["agreement_is_by_construction"] for r in records], [r["kind"] == "matched" for r in records])
        summ = sh.summary("shadow-test", records, {}, "t0", "t1", {"accepted": True})
        self.assertEqual((summ["claims"], summ["sent"], summ["set_aside"], summ["no_rightrail_answer"], summ["as_expected"],
                          summ["not_as_expected"], summ["matched_scenarios"]), (13, 11, 2, 0, 13, [], 7))
        self.assertEqual(summ["by_category"], {"agree_allow": 3, "agree_hold": 4, "lean_holds_on_mapped_rule_local_approves": 1,
                                               "lean_review_local_approves": 2, "not_sent_local_approves": 2,
                                               "rightrail_answered_local_approves": 1})

    def test_an_answer_that_is_not_the_expected_one_is_reported(self):
        records, _ = self.build({"clean_one_line": ("HOLD", ["MEMBER_DECEASED"]), "member_deceased": ("ALLOW", [])})
        summ = sh.summary("shadow-test", records, {}, "t0", "t1", None)
        self.assertEqual(summ["not_as_expected"], ["clean_one_line", "member_deceased"])
        by = {r["scenario"]: r for r in records}
        self.assertEqual(by["clean_one_line"]["category"], "lean_holds_on_mapped_rule_local_approves")
        self.assertEqual(by["member_deceased"]["category"], "local_denies_lean_allows")

    def test_a_sent_claim_with_no_answer_is_recorded_as_such(self):
        answer, sent = stand_in(self.doc)
        answer["steps"][1]["rows"] = []  # the second batch came back empty
        records = sh.build_records(self.doc, "shadow-test", expected_local(self.doc), sent, answer)
        r = next(r for r in records if r["scenario"] == "repeat_of_a_paid_claim")
        self.assertEqual((r["rightrail"], r["category"], r["as_expected"]), (None, "no_rightrail_answer", False))
        self.assertEqual(r["localbce"]["status"], "APPROVED")  # localBCE's decision is untouched

    def test_no_raw_member_id_is_written_and_records_append(self):
        records, answer = self.build()
        summ = sh.summary("shadow-test", records, {"engine": answer["engine"]}, "t0", "t1", None)
        with tempfile.TemporaryDirectory() as tmp:
            log, summary_path = sh.write_out(Path(tmp) / "shadow", records, summ)
            sh.write_out(Path(tmp) / "shadow", records, summ)
            text = log.read_text("utf-8") + summary_path.read_text("utf-8")
            self.assertEqual(len(log.read_text("utf-8").splitlines()), 26)  # appended, not replaced
            self.assertEqual(sorted(p.name for p in (Path(tmp) / "shadow").iterdir()), ["rightrail_shadow.jsonl", "summary.json"])
        for s in self.doc["scenarios"]:
            self.assertNotIn(s["claim"]["member_id"], text)
        self.assertNotIn("SH-M-", text)
        self.assertNotIn(self.doc["secret"], text)
        leaky = copy.deepcopy(records)
        leaky[0]["note"] = "member SH-M-CLEAN-1"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            sh.write_out(Path(tmp) / "shadow", leaky, summ)

    def test_output_under_rightrail_or_parked_is_refused(self):
        records, _ = self.build()
        for place in (ROOT / "rightrail" / "shadow", ROOT / "parked" / "shadow"):
            with self.assertRaises(ValueError):
                sh.write_out(place, records, {})
            self.assertFalse(place.exists())

    def test_default_output_is_outside_git(self):
        self.assertEqual(sh.OUT_DIR, ROOT / "state" / "shadow")


class Switches(unittest.TestCase):
    def test_the_run_is_off_unless_switched_on(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SHADOW_RUN", None)
            self.assertIn("SHADOW_RUN=1", sh.cannot_run())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(sh.main([]), 3)
            self.assertIn("not run: local only", err.getvalue())
            with self.assertRaises(RuntimeError):
                sh.run()

    def test_the_child_makes_no_key_without_the_owners_switch(self):
        """Without `allow_scratch_keygen` the child stops before it imports RightRail or starts the signer."""
        for job in ({}, {"allow_scratch_keygen": False}, {"allow_scratch_keygen": "yes"}):
            with self.assertRaises(RuntimeError) as cm:
                child.run(job)
            self.assertIn("keygen", str(cm.exception))
        self.assertNotIn("app", {m.split(".")[0] for m in sys.modules if m.startswith("app.right_rail")})

    def test_only_the_pinned_engine(self):
        text = (ROOT / "scripts" / "rightrail_shadow_child.py").read_text("utf-8")
        self.assertIn("is not the pinned program", text)
        self.assertNotIn("gate_hist3", text)
        self.assertNotIn("mock", text)


class TheRun(unittest.TestCase):
    """The run against RightRail's pinned engine.  Local only."""

    def test_the_shadow_run_gives_every_scenario_its_expected_outcome(self):
        why = sh.cannot_run()
        if why:
            self.skipTest(why)
        with tempfile.TemporaryDirectory() as tmp:
            summ = sh.run(Path(tmp) / "shadow")
            records = [json.loads(x) for x in (Path(tmp) / "shadow" / "rightrail_shadow.jsonl").read_text("utf-8").splitlines()]
        self.assertEqual(summ["not_as_expected"], [], {r["scenario"]: (r["rightrail"], r["category"]) for r in records if not r["as_expected"]})
        self.assertEqual((summ["claims"], summ["sent"], summ["set_aside"]), (13, 11, 2))
        self.assertIs(summ["context"]["engine"]["is_the_pinned_program"], True)
        self.assertIs(summ["context"]["stores_removed"], True)
        self.assertEqual(summ["eligibility_extract"]["fact_rows"], 10)
        self.assertIs(summ["eligibility_extract"]["used_by_a_decision"], False)


if __name__ == "__main__":
    unittest.main()
