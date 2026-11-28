"""The two pure functions of the live wiring (scripts/rightrail_claim_adapter.py), by case table.

- `request_of`: a localBCE claim as a RightRail payment request, or the set-aside that says why it is not sent.  The
  day-count date rule; a set-aside on a total mismatch or a date that cannot be converted; nothing corrected.
- `result_of`: a RightRail decision as an adjudication result.  Only ALLOW on every line gives APPROVED.
- The ids, the member key and the NPI check are RightRail's: compared with the definitions in rightrail/app, taken from
  their source text (the modules themselves need Windows to import).
- `claim_input.json` is not changed: the existing files are read as they are.

Nothing here runs RightRail or decides a claim.  Design: docs/integration/ELIG_EXTRACT_AND_WIRING_DESIGN.md part 2.
Synthetic, not legally verified, nonpayment.
"""

import ast
import copy
import hashlib
import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import rightrail_claim_adapter as ad  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "claim_adapter"
CLAIMS = json.loads((FIXTURES / "claims.json").read_text("utf-8"))
DECISIONS = json.loads((FIXTURES / "decisions.json").read_text("utf-8"))
SECRET = CLAIMS["secret"].encode()
FLAGS = ("eligibility_active", "aid_code", "benefit_level_exists", "eligibility_period_from", "eligibility_period_thru",
         "soc_amount", "soc_met", "provider_enrolled", "provider_type_valid", "billing_code_valid", "units_valid",
         "is_duplicate", "disability_determination_valid", "recipient_not_deceased", "physician_certification_valid")


def claim_of(case: dict) -> dict:
    claim = copy.deepcopy(CLAIMS["base"])
    claim.update(copy.deepcopy(case.get("change", {})))
    for key in case.get("drop", ()):
        del claim[key]
    return claim


def from_source(relative: str, names: set, extra: dict) -> dict:
    """The named top-level functions and assignments of a RightRail module, run from its source text."""
    path = ROOT / "rightrail" / relative
    tree = ast.parse(path.read_text("utf-8"), str(path))
    body = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name in names)
            or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))]
    ns = dict(extra)
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), ns)  # noqa: S102  RightRail's own text
    missing = names - set(ns)
    if missing:
        raise AssertionError(f"{relative} no longer defines {sorted(missing)}")
    return ns


class RequestOf(unittest.TestCase):
    def test_case_names_are_unique(self):
        names = [c["name"] for c in CLAIMS["cases"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual((sum("request" in c for c in CLAIMS["cases"]), sum("set_aside" in c for c in CLAIMS["cases"])),
                         (7, 36))

    def test_each_case(self):
        for case in CLAIMS["cases"]:
            claim = claim_of(case)
            got = ad.request_of(claim, SECRET)
            if "set_aside" in case:
                self.assertIsInstance(got, ad.SetAside, case["name"])
                self.assertEqual(got.cause, case["set_aside"], case["name"])
                continue
            want = case["request"]
            self.assertIsInstance(got, ad.Request, case["name"])
            self.assertEqual((got.claim_id, got.flow, got.payee, got.cents), (claim["claim_id"], "FFS_CLAIM", claim["provider_npi"], want["cents"]), case["name"])
            self.assertEqual([[ln.line_number, ln.procedure, ln.units, ln.cents] for ln in got.lines], want["lines"], case["name"])
            self.assertEqual(sum(ln.cents for ln in got.lines), got.cents, case["name"])
            for ln in got.lines:
                self.assertEqual((ln.flow, ln.date, ln.payee, ln.member_key), ("FFS_CLAIM", want["date"], got.payee, got.member_key), case["name"])

    def test_a_claim_is_sent_whole_or_not_at_all(self):
        """A set-aside carries no line, and a fault on one line sets the whole claim aside."""
        case = next(c for c in CLAIMS["cases"] if c["name"] == "units_bad_on_second_line")
        got = ad.request_of(claim_of(case), SECRET)
        self.assertEqual(got, ad.SetAside("CLAIM-ADAPTER-001", "units", 15000))
        self.assertFalse(hasattr(got, "lines"))

    def test_nothing_is_corrected(self):
        """A total that is not the line sum is set aside with the stated amount: neither number is changed."""
        claim = claim_of({"change": {"claim_amount": 1000}})
        before = copy.deepcopy(claim)
        self.assertEqual(ad.request_of(claim, SECRET), ad.SetAside("CLAIM-ADAPTER-001", "total_mismatch", 1000))
        self.assertEqual(claim, before)

    def test_the_date_rule_is_days_since_1970(self):
        text = (ROOT / "rust-engine" / "rules.json").read_text("utf-8")
        self.assertIn("All dates encoded as integer days since 1970-01-01 (proleptic Gregorian)", text)
        self.assertEqual([ad.service_day(n) for n in (0, 1, 365, 19782, 20000, 2932896)],
                         [19700101, 19700102, 19710101, 20240229, 20241004, 99991231])
        for bad in (-1, 2932897, 20241004, 20000.0, "20000", True, None):
            self.assertIsNone(ad.service_day(bad), repr(bad))

    def test_no_decision_flag_crosses(self):
        base = ad.request_of(claim_of({}), SECRET)
        flipped = claim_of({})
        for flag in FLAGS:
            self.assertIn(flag, flipped)
            flipped[flag] = 0 if flipped[flag] else 1
        for extra in ("oracle_facts", "fee_schedule_entries", "diagnosis_codes"):
            flipped[extra] = [{"anything": 1}]
        self.assertEqual(ad.request_of(flipped, SECRET), base)
        self.assertFalse(set(FLAGS) & set(ad.Request._fields + ad.Line._fields))

    def test_rendering_party_is_a_flagged_test_only_assumption(self):
        got = ad.request_of(claim_of({}), SECRET)
        self.assertEqual(got.assumptions, ("rendering_party_is_billing_npi_test_only",))
        self.assertTrue(all(ln.rendering == got.payee for ln in got.lines))
        self.assertIn("for tests only", ad.__doc__)

    def test_ids_are_stable_and_distinct(self):
        a, b = ad.request_of(claim_of({}), SECRET), ad.request_of(claim_of({}), SECRET)
        self.assertEqual(a, b)  # a resubmitted claim is the same payment
        other = ad.request_of(claim_of({"change": {"claim_id": "CLAIM-ADAPTER-002"}}), SECRET)
        self.assertNotEqual(a.payment_id, other.payment_id)
        self.assertEqual(len({a.payment_id, *(ln.line_id for ln in a.lines)}), 3)
        self.assertTrue(re.fullmatch(r"C[0-9a-f]{32}", a.payment_id))
        self.assertTrue(all(re.fullmatch(r"L[0-9a-f]{32}", ln.line_id) for ln in a.lines))
        self.assertNotEqual(a.member_key, ad.request_of(claim_of({}), b"another-secret").member_key)
        self.assertNotIn("S00000001", json.dumps(a))  # the raw member id is not in the request

    def test_the_secret_is_required(self):
        for bad in (b"", "text", None):
            with self.assertRaises(ValueError):
                ad.request_of(claim_of({}), bad)

    def test_not_a_claim(self):
        for bad in (None, [], "claim", 7):
            self.assertEqual(ad.request_of(bad, SECRET), ad.SetAside("", "field", 0))

    def test_existing_claim_files_are_read_unchanged(self):
        """The repository's claim files keep their meaning.  Their total is not their line sum, so the converter sets
        them aside; it does not correct them, and the Rust engine still reads them (cargo test)."""
        for relative in ("rust-engine/claim_input.json", "ops/canaries/approved_claim_input.example.json",
                         "ops/canaries/denied_claim_input.example.json"):
            path = ROOT / relative
            before = path.read_bytes()
            claim = json.loads(before)
            got = ad.request_of(claim, SECRET)
            self.assertIsInstance(got, ad.SetAside, relative)
            self.assertEqual(got.cause, "total_mismatch", relative)
            self.assertEqual(path.read_bytes(), before, relative)


class RightRailDefinitions(unittest.TestCase):
    """The adapter's copies against RightRail's own text."""

    def test_ids_and_member_key_are_rightrails(self):
        rr = from_source("app/right_rail_gate_ffs.py", {"canonical_id", "member_key", "_IDS", "_MEMBER"}, {"hashlib": hashlib})
        self.assertEqual((ad._IDS, ad._MEMBER), (rr["_IDS"], rr["_MEMBER"]))
        for parts in (("1234567893", "CLAIM-ADAPTER-001"), ("1234567893", "CLAIM-ADAPTER-001", "1"), ("", ""), ("é", "x" * 300)):
            for prefix in ("C", "L"):
                self.assertEqual(ad.canonical_id(prefix, *parts), rr["canonical_id"](prefix, *parts))
        for secret, member in ((SECRET, "S00000001"), (b"k", ""), (b"x" * 300, "MEMBER-FIXTURE-001")):
            self.assertEqual(ad.member_key(secret, member), rr["member_key"](secret, member))
        got = ad.request_of(claim_of({}), SECRET)
        self.assertEqual(got.payment_id, rr["canonical_id"]("C", "1234567893", "CLAIM-ADAPTER-001"))
        self.assertEqual([ln.line_id for ln in got.lines],
                         [rr["canonical_id"]("L", "1234567893", "CLAIM-ADAPTER-001", n) for n in ("1", "2")])
        self.assertEqual(got.member_key, rr["member_key"](SECRET, "S00000001").hex())

    def test_npi_check_is_rightrails(self):
        rr = from_source("app/right_rail_reader_leie.py", {"npi_ok", "_NPI"}, {"re": re})
        samples = ["1234567893", "1234567890", "123456789", "12345678AB", "", "0000000000", "1245319599", "1111111111",
                   "1234567893\n", " 1234567893"] + [f"{n:010d}" for n in range(1234567880, 1234567900)]
        for npi in samples:
            self.assertEqual(ad.npi_ok(npi), rr["npi_ok"](npi), repr(npi))
        self.assertTrue(ad.npi_ok("1234567893"))
        self.assertFalse(ad.npi_ok(1234567893))


class ResultOf(unittest.TestCase):
    def setUp(self):
        self.claim = claim_of({})
        self.request = ad.request_of(self.claim, SECRET)

    def rows(self, case):
        pid = case.get("payment_id", self.request.payment_id)
        return [(pid, at, outcome, reasons) for at, outcome, reasons in case["rows"]]

    def test_case_names_are_unique(self):
        names = [c["name"] for c in DECISIONS["cases"]]
        self.assertEqual(len(names), len(set(names)))

    def test_each_case(self):
        for case in DECISIONS["cases"]:
            if case.get("no_decision"):
                with self.assertRaises(ad.NoDecision, msg=case["name"]):
                    ad.result_of(self.claim, (self.request, self.rows(case)))
                continue
            got = ad.result_of(self.claim, (self.request, self.rows(case)))
            self.assertEqual({k: got[k] for k in case["expect"]}, case["expect"], case["name"])
            self.assertEqual(got["rightrail_payment_id"], self.request.payment_id, case["name"])
            self.assertIsNone(got["rightrail_set_aside_cause"], case["name"])
            self.assertEqual([x["line"] for x in got["rightrail_lines"]], [1, 2], case["name"])

    def test_only_an_allow_on_every_line_is_approved(self):
        """Every combination of outcomes over the two lines: APPROVED exactly when both are ALLOW."""
        approved = []
        for a in ad.OUTCOMES:
            for b in ad.OUTCOMES:
                got = ad.result_of(self.claim, (self.request, [(self.request.payment_id, 0, a, ["X"] if a != "ALLOW" else []),
                                                              (self.request.payment_id, 1, b, ["X"] if b != "ALLOW" else [])]))
                self.assertIn(got["status"], ("APPROVED", "DENIED"))
                self.assertEqual(got["status"] == "APPROVED", got["rightrail_outcome"] == "ALLOW", (a, b))
                self.assertEqual(got["reason"] is None, got["status"] == "APPROVED", (a, b))
                if got["status"] == "APPROVED":
                    approved.append((a, b))
        self.assertEqual(approved, [("ALLOW", "ALLOW")])

    def test_a_set_aside_is_never_approved(self):
        for case in CLAIMS["cases"]:
            if "set_aside" not in case:
                continue
            claim = claim_of(case)
            aside = ad.request_of(claim, SECRET)
            if not aside.claim_id or not isinstance(claim.get("claim_amount"), int) or claim["claim_amount"] < 0:
                with self.assertRaises(ad.NoDecision, msg=case["name"]):  # nothing to report against
                    ad.result_of(claim, aside)
                continue
            got = ad.result_of(claim, aside)
            self.assertEqual((got["status"], got["reason"], got["rightrail_outcome"], got["rightrail_set_aside_cause"],
                              got["rightrail_final"], got["rightrail_payment_id"], got["rightrail_lines"]),
                             ("DENIED", "RIGHTRAIL_SET_ASIDE", "SET_ASIDE", case["set_aside"], False, None, []), case["name"])

    def test_a_hold_is_not_a_final_denial(self):
        for outcome, final in (("HOLD", False), ("HUMAN_REVIEW", False), ("ANSWERED", True), ("ALLOW", True)):
            got = ad.result_of(self.claim, (self.request, [(self.request.payment_id, at, outcome, []) for at in (0, 1)]))
            self.assertIs(got["rightrail_final"], final, outcome)
        self.assertIn("a RightRail hold is not a final denial", ad.__doc__)

    def test_no_decision_is_never_a_result(self):
        other = ad.request_of(claim_of({"change": {"claim_id": "CLAIM-ADAPTER-002"}}), SECRET)
        allow = [(other.payment_id, 0, "ALLOW", []), (other.payment_id, 1, "ALLOW", [])]
        for decision in (None, (), (self.request,), (self.request, None), (other, allow), ("request", allow),
                         ad.SetAside("CLAIM-ADAPTER-002", "units", 0), ad.SetAside("CLAIM-ADAPTER-001", "", 0),
                         (self.request, [(self.request.payment_id, 0, "ALLOW")])):
            with self.assertRaises(ad.NoDecision, msg=repr(decision)[:60]):
                ad.result_of(self.claim, decision)
        for claim in (None, {}, {"claim_id": "X"}, {"claim_id": "", "claim_amount": 1}, {"claim_id": "X", "claim_amount": 2 ** 64}):
            with self.assertRaises(ad.NoDecision):
                ad.result_of(claim, (self.request, []))

    def test_existing_fields_keep_their_meaning(self):
        got = ad.result_of(self.claim, (self.request, [(self.request.payment_id, at, "ALLOW", []) for at in (0, 1)]))
        self.assertEqual(list(got)[:6], ["claim_id", "claim_hash", "tx_submitted", "tx_hash", "status", "reason"])
        self.assertEqual((got["claim_id"], got["tx_submitted"], got["tx_hash"]), ("CLAIM-ADAPTER-001", False, None))
        self.assertEqual(sorted(k for k in got if k.startswith("rightrail_")),
                         ["rightrail_final", "rightrail_lines", "rightrail_outcome", "rightrail_payment_id",
                          "rightrail_reasons", "rightrail_set_aside_cause"])
        json.dumps(got)

    def test_claim_hash_is_the_rust_engines(self):
        existing = json.loads((ROOT / "rust-engine" / "adjudication_result.json").read_text("utf-8"))
        claim = json.loads((ROOT / "rust-engine" / "claim_input.json").read_text("utf-8"))
        self.assertEqual(claim["claim_id"], existing["claim_id"])
        self.assertEqual(ad.claim_hash(claim["claim_id"], claim["claim_amount"]), existing["claim_hash"])

    def test_reason_names(self):
        self.assertEqual(ad.LOCAL_NAME, {
            "MEMBER_DECEASED": "G9_RECIPIENT_DECEASED", "FFS_DUPLICATE_LINE": "G7_DUPLICATE_CLAIM",
            "PROVIDER_EXCLUDED": "G5_PROVIDER_NOT_ENROLLED", "PROVIDER_DECEASED": "G5_PROVIDER_NOT_ENROLLED",
            "PROGRAM_NOT_ELIGIBLE": "G2_PROGRAM_ELIGIBILITY_FAILED"})
        self.assertNotIn("MEMBER_NOT_ENROLLED", ad.LOCAL_NAME)  # G1 and G3 share it: the RightRail name is given


if __name__ == "__main__":
    unittest.main()
