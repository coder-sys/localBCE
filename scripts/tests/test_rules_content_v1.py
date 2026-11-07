"""Round-trip and digest tests for RR/RULES/CONTENT/v1 proposals (scripts/rules_content_v1.py)."""

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rules_content_v1 as rc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QUEUE = os.path.join(ROOT, "gov-rules-kg-prototype", "reports", "claude_web_promotion_ready.json")


def candidate(cid, **kw):
    c = {"candidate_id": cid, "statement": f"statement {cid}", "source_url": "https://example.gov/rule",
         "source_title": "T", "citation_text": "C", "source_type": "regulation", "program": "medicaid",
         "jurisdiction_level": "federal", "rule_unit_type": "eligibility_rule", "confidence_score": 0.97,
         "verification_status": "claude_web_grounded_candidate", "promotion_status": "candidate_only_not_verified"}
    c.update(kw)
    return c


class Export(unittest.TestCase):
    def setUp(self):
        self.queue = [candidate("b"), candidate("a")]
        self.doc = rc.export(self.queue, b"src", "corpus-test", 1)

    def test_is_non_authoritative_proposal(self):
        self.assertEqual((self.doc["status"], self.doc["authoritative"]), ("PROPOSAL", False))
        self.assertEqual(self.doc["format"], "RR/RULES/CONTENT/v1")

    def test_round_trip_through_json(self):
        back = json.loads(rc.dumps(self.doc))
        self.assertEqual(back, self.doc)
        self.assertEqual(rc.verify(back)["content_digest"], self.doc["content_digest"])

    def test_input_order_does_not_change_digest(self):
        other = rc.export(list(reversed(self.queue)), b"src", "corpus-test", 1)
        self.assertEqual(other["content_digest"], self.doc["content_digest"])
        self.assertEqual([r["rule_id"] for r in other["rules"]], ["a", "b"])

    def test_confidence_is_integer_basis_points(self):
        self.assertEqual(self.doc["rules"][0]["model_confidence_bp"], 9700)

    def test_digest_is_domain_separated(self):
        import hashlib
        body = {k: v for k, v in self.doc.items() if k != "content_digest"}
        self.assertNotEqual(hashlib.sha3_512(rc.canonical(body)).hexdigest(), self.doc["content_digest"])
        self.assertEqual(hashlib.sha3_512(b"RR/RULES/CONTENT/v1\x00" + rc.canonical(body)).hexdigest(),
                         self.doc["content_digest"])

    def test_every_field_change_breaks_the_digest(self):
        mutations = [
            ("version", 2), ("content_id", "x"), ("source_sha3_512", "0" * 128), ("producer", "other"),
        ]
        for key, value in mutations:
            with self.subTest(key):
                d = copy.deepcopy(self.doc)
                d[key] = value
                with self.assertRaisesRegex(rc.ContentError, "content_digest"):
                    rc.verify(d)
        d = copy.deepcopy(self.doc)
        d["rules"][0]["statement"] += "."
        with self.assertRaisesRegex(rc.ContentError, "content_digest"):
            rc.verify(d)

    def test_authoritative_or_decided_content_is_refused(self):
        for key, value in (("authoritative", True), ("status", "ACTIVE")):
            with self.subTest(key):
                d = copy.deepcopy(self.doc)
                d[key] = value
                d["content_digest"] = rc.digest(d)
                with self.assertRaisesRegex(rc.ContentError, "PROPOSAL"):
                    rc.verify(d)

    def test_proposal_with_lean_rule_is_refused(self):
        d = copy.deepcopy(self.doc)
        d["rules"][0]["lean_rule"] = "BlindLedger.Gate.Rules.R9"
        d["content_digest"] = rc.digest(d)
        with self.assertRaisesRegex(rc.ContentError, "no Lean rule"):
            rc.verify(d)

    def test_duplicates_floats_and_unverified_status_are_refused(self):
        with self.assertRaisesRegex(rc.ContentError, "duplicate"):
            rc.export([candidate("a"), candidate("a")], b"", "c", 1)
        with self.assertRaisesRegex(rc.ContentError, "promotion_status"):
            rc.export([candidate("a", promotion_status="verified")], b"", "c", 1)
        with self.assertRaisesRegex(rc.ContentError, "floats"):
            rc.canonical({"x": 0.5})

    def test_unknown_fields_are_refused(self):
        d = copy.deepcopy(self.doc)
        d["extra"] = 1
        with self.assertRaisesRegex(rc.ContentError, "fields"):
            rc.verify(d)


@unittest.skipUnless(os.path.isfile(QUEUE), f"RULES CONTENT CORPUS EXPORT NOT RUN: {QUEUE} missing")
class CorpusExport(unittest.TestCase):
    def test_promotion_queue_exports_and_verifies_via_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "content.json")
            self.assertEqual(rc.main(["export", QUEUE, out, "--content-id", "corpus-promotion-ready", "--version", "1"]), 0)
            self.assertEqual(rc.main(["verify", out]), 0)
            with open(out, encoding="utf-8") as f:
                doc = json.load(f)
        with open(QUEUE, encoding="utf-8") as f:
            self.assertEqual(len(doc["rules"]), len(json.load(f)))
        self.assertTrue(all(r["lean_rule"] is None for r in doc["rules"]))


if __name__ == "__main__":
    unittest.main()
