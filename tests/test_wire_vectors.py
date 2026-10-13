"""Python request encoders vs Lean (test-only): the live encoders must emit the same bytes as Lean for the same input.

`wire_vectors` (lean/BlindLedger/Financial/WireVectors.lean) prints `<name> <hex>` of the Lean-encoded request per fixed
input; each test below builds the same logical input and requires byte equality. A difference fails and is never
smoothed over: it means one side is wrong."""

import copy
import os
import shutil
import subprocess
import unittest
from unittest import mock

from app import right_rail_financial_engine as engine
from app import right_rail_financial_semantic_adapter as adapter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEAN = os.path.join(ROOT, "lean")
EXE = os.path.join(LEAN, ".lake", "build", "bin", "wire_vectors.exe" if os.name == "nt" else "wire_vectors")
# The proofs that the Lean encoders are the specified ones, and the runner itself (a stale runner fails `--no-build`).
PROOFS = ["BlindLedger.Financial.CodecLaws", "BlindLedger.Financial.WireVectors"]

ZERO = "00" * 64
CASH_AT, OFFSET_AT, REVERSAL_AT, DUE = 1_774_828_800_000, 1_774_864_800_000, 1_774_900_000_000, 1_774_915_200_000
LONG_ID = "a" + "b" * 127
ACT_ID = "a" + "b" * 113


def _pack():
    fields = {
        "pack_id": "control-pack:fixture-2026-01:v1", "state_id": "fixture-state", "deployment_id": "fixture-rightrail",
        "program_id": "fixture-provider-payment", "period_id": "fixture-2026-period-01", "version": 1,
        "source_refs": ["fixture-source:approved-schedule:v1"], "effective_start_ms": 100, "effective_end_ms": 200,
        "recorded_at_ms": 1, "approved_at_ms": 2, "calculation_rule_id": "calculation:per-recipient:v1",
        "adjustment_rule_id": "adjustment:offset:v1",
        "authorized_roles": ["FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"],
        "expected_tests": ["program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"],
    }
    digest = adapter.owner._digest(adapter.owner._EVIDENCE_DOMAIN, adapter._canonical(fields))
    return {"status": "APPROVED", "canonical_fields": fields, "digest": digest.hex().upper()}


def _evidence(evidence_id, kind, origin, source_version, local_ref, at, amount, reversal_of=None, source_id="fixture-payment-file"):
    return {"evidence_id": evidence_id, "item_id": "item-h", "kind": kind, "common_origin_id": origin,
            "source_id": source_id, "source_version": source_version, "local_ref": local_ref, "applicable_at_ms": at,
            "event_at_ms": at, "received_at_ms": at, "amount_cents": amount, "reversal_of": reversal_of, "supersedes": None}


CASH = _evidence("evidence:cash", "PAYMENT_CONFIRMATION", "origin:cash:h", "cash-v1", "ref:cash:h:v1", CASH_AT, 9_700_000)
OFFSET = _evidence("evidence:offset", "OFFSET_CLAIM", "claim:h:offset", "authority-v1", "ref:offset:h:approval", OFFSET_AT,
                   300_000, source_id="fixture-official")
CONFLICT_EVIDENCE = _evidence("evidence:conflict", "PAYMENT_CONFIRMATION", "origin:cash:h", "cash-conflict-v1",
                              "ref:cash:h:conflict", CASH_AT, 300_001)
REVERSAL = _evidence("evidence:reversal", "PAYMENT_REVERSAL", "reversal:payment:h:cash", "cash-reversal-v1",
                     "reversal:payment:h:cash", REVERSAL_AT, 9_700_000, reversal_of="payment:h:cash")
PAYMENT = {"payment_id": "payment:h:cash", "obligation_id": "obligation:item-h:period-01", "item_id": "item-h",
           "evidence_id": "evidence:cash", "common_origin_id": "origin:cash:h", "amount_cents": 9_700_000,
           "event_at_ms": CASH_AT, "reversed_by_evidence_id": None, "active": 1}
CLAIM = {"claim_id": "claim:h:offset", "obligation_id": "obligation:item-h:period-01", "evidence_id": "evidence:offset",
         "amount_cents": 300_000, "owner_role": "CASE_OWNER", "deadline_ms": DUE, "status": "AUTHORIZED"}
DETERMINATION = {"determination_id": "determination:action:h:offset", "obligation_id": "obligation:item-h:period-01",
                 "claim_id": "claim:h:offset", "actor_id": "synthetic-official", "actor_role": "FINANCE_DECISION",
                 "authority_id": "synthetic-authority-v1", "authority_epoch": 1, "authority_digest": ZERO,
                 "decision": "OFFSET_AUTHORIZED", "amount_cents": 300_000,
                 "supporting_evidence": [{"evidence_id": "evidence:offset", "record_digest": ZERO}],
                 "expected_revision": 0, "resulting_revision": 1, "decided_at_ms": OFFSET_AT}
CONFLICT = {"conflict_id": "conflict:h:cash", "obligation_id": "obligation:item-h:period-01",
            "common_origin_id": "origin:cash:h", "existing_payment_id": "payment:h:cash",
            "candidate_evidence_id": "evidence:conflict", "existing_amount_cents": 9_700_000,
            "candidate_amount_cents": 300_001, "reason": "CONFLICTING_COMMON_ORIGIN_AMOUNT", "visible_at_ms": CASH_AT}
ACTION = {"action_id": "action:h:offset", "obligation_id": "obligation:item-h:period-01",
          "determination_id": "determination:action:h:offset", "kind": "OFFSET_AUTHORIZATION",
          "payload": {"amount_cents": 300_000, "currency": "USD"}, "revision": 1, "status": "READY",
          "payload_digest": ZERO, "created_at_ms": OFFSET_AT}


def _case(case_id, reason, status):
    return {"case_id": case_id, "obligation_id": "obligation:item-h:period-01", "reason": reason,
            "next_action_owner": "CASE_OWNER", "due_at_ms": DUE, "status": status, "updated_at_ms": OFFSET_AT}


def _blfin02_base():
    return {
        "scope": {"state_id": "fixture-state", "deployment_id": "fixture-rightrail",
                  "program_id": "fixture-provider-payment", "period_id": "fixture-2026-period-01", "currency": "USD"},
        "owner": {"owner_id": "continuity-test-owner-v1", "mode": "TEST", "provenance": "ROOT"},
        "pre_evaluation": {"obligation_id": "obligation:item-h:period-01", "item_id": "item-h", "revision": 0},
        "authority": {"authority_id": "synthetic-authority-v1", "epoch": 1, "digest": ZERO, "actors": [
            {"actor_id": "synthetic-official", "roles": ["FINANCE_DECISION", "CASE_OWNER"]},
            {"actor_id": "synthetic-reporter", "roles": ["REPORTING_EDITOR"]},
            {"actor_id": "synthetic-receiver", "roles": ["RECEIVER"]}]},
        "obligation": {"population_id": "population:fixture-2026-01", "item_id": "item-h",
                       "obligation_id": "obligation:item-h:period-01", "owed_cents": 10_000_000, "due_at_ms": DUE,
                       "rule_version": 1, "reporting_complete": False},
        "population": {"population_id": "population:fixture-2026-01"},
        "control_pack": _pack(), "evaluation_time_ms": 1_774_922_400_000,
        "payments": [], "claims": [], "determinations": [], "evidence": [], "conflicts": [],
        "cases": [_case("case:h:base", "OPEN", "OPEN")], "actions": [],
    }


def _blfin02_authorized():
    data = _blfin02_base()
    data.update(payments=[dict(PAYMENT)], claims=[dict(CLAIM)], determinations=[copy.deepcopy(DETERMINATION)],
                evidence=[dict(CASH), dict(OFFSET)], cases=[_case("case:h:authorized", "OFFSET_AUTHORIZED", "AUTHORIZED")],
                actions=[copy.deepcopy(ACTION)])
    return data


def _blfin02_live_authorized():
    data = _blfin02_authorized()
    data["owner"]["mode"] = "LIVE"
    return data


def _blfin02_reversed_conflict_shadow_restore():
    data = _blfin02_authorized()
    data["owner"].update(mode="SHADOW", provenance="CONTINUITY_RESTORE")
    data["payments"] = [{**PAYMENT, "reversed_by_evidence_id": "evidence:reversal", "active": 0}]
    data["evidence"] = [dict(CASH), dict(CONFLICT_EVIDENCE), dict(OFFSET), dict(REVERSAL)]
    data["conflicts"] = [dict(CONFLICT)]
    return data


def _blfin02_max_length():
    data = _blfin02_authorized()
    data["evidence"] = [{**CASH, "source_id": LONG_ID, "source_version": LONG_ID, "local_ref": LONG_ID}, dict(OFFSET)]
    det_id = "determination:" + ACT_ID
    data["determinations"] = [{**copy.deepcopy(DETERMINATION), "determination_id": det_id}]
    data["cases"] = [_case(LONG_ID, LONG_ID, "AUTHORIZED")]
    data["actions"] = [{**copy.deepcopy(ACTION), "action_id": ACT_ID, "determination_id": det_id}]
    return data


BLFIN02 = {name: globals()["_" + name] for name in (
    "blfin02_base", "blfin02_authorized", "blfin02_live_authorized",
    "blfin02_reversed_conflict_shadow_restore", "blfin02_max_length")}


# BLFCMD03: CorrectionTransition/KAT.lean's correctionKatRequest (and two variants), the engine encoder against Lean.
BOUND = ("BF620150B21060DDFBA787A7DC8F2A38499294F3DD57DBFFC267FC4072031151831E9E083F0A0BA20EC10F7CFBCDAA85E764A17A09F6873EB93CD7D632DDFE99")
EVAL_ID, ACT = "evaluation:obligation:item-h:period-01:r4", "action:correction:h:v1"
DET = "determination:action:correction:h:v1"
OBLIGATION = "obligation:item-h:period-01"


def _dig(byte):
    return ("%02X" % byte) * 64


def _receipt():
    return {"contract_version": "RR/FINANCIAL/EVALUATION-RECEIPT/v1",
            "scope": {"state_id": "fixture-state", "deployment_id": "fixture-rightrail",
                      "program_id": "fixture-provider-payment", "period_id": "fixture-2026-period-01", "currency": "USD"},
            "control_pack": {"pack_id": "control-pack:fixture-2026-01:v1", "version": 1, "digest": _pack()["digest"]},
            "evidence_bindings": [{"evidence_id": "evidence:cash", "record_digest": _dig(68)},
                                  {"evidence_id": "evidence:offset", "record_digest": _dig(68)}],
            "input_snapshot_digest": _dig(91), "authority": {"epoch": 1, "digest": BOUND},
            "evaluation_id": EVAL_ID, "obligation_id": OBLIGATION, "revision": 4, "rule_version": 1,
            "evidence_ids": ["evidence:cash", "evidence:offset"], "authority_id": "synthetic-authority-v1",
            "evaluated_at_ms": 1_774_922_400_000, "owed_cents": 10_000_000, "claimed_adjustment_cents": 300_000,
            "lawful_adjustment_cents": 0, "received_cash_cents": 9_700_000, "shortfall_cents": 300_000,
            "overage_cents": 0, "cash_satisfied": 0, "amount_satisfied": 0, "timely": 0, "reporting_complete": 0,
            "verification_status": "SUPPORTED", "case_status": "OPEN", "delivery_status": "NONE",
            "result_digest": _dig(165), "evaluation_result_digest": _dig(165), "receipt_digest": _dig(90)}


def _query(predicate, subject, identity=None):
    return {"predicate": predicate, "subject": subject, "complete": True, "match_count": int(identity is not None),
            "result_identity": identity, "version_sequence": 10, "version_head": _dig(42)}


def _blfcmd03(variant):
    data = _blfin02_base()
    data["authority"]["digest"] = BOUND
    data["pre_evaluation"]["revision"] = 3
    data.update(payments=[dict(PAYMENT)], claims=[{**CLAIM, "status": "CLAIMED"}], evidence=[dict(CASH), dict(OFFSET)])
    data["current_evaluation"] = {"receipt": _receipt()}
    command = {"item_id": "item-h", "claim_id": "claim:h:offset", "action_id": ACT, "actor_id": "synthetic-official",
               "actor_role": "FINANCE_DECISION", "current_authority_id": "synthetic-authority-v1",
               "current_authority_epoch": 1, "current_authority_digest": BOUND, "expected_revision": 4,
               "evaluation_id": EVAL_ID, "evaluation_result_digest": _dig(165), "decision_at_ms": 1_774_922_400_010,
               "owner_now_ms": 1_774_922_400_020}
    lookup = {"kind": "absent"}
    queries = {"action_id": _query("ACTION_ID", ACT), "determination_id": _query("DETERMINATION_ID", "determination:" + ACT),
               "evaluation_consumed": _query("EVALUATION_CONSUMED", EVAL_ID)}
    sequence, head, links = 10, bytes([42]) * 64, []
    if variant == "conflicting":
        lookup = {"kind": "conflicting"}
    if variant == "existing_links":
        lookup = {"kind": "existing", "identity": {
            "action_id": ACT, "action_obligation_id": OBLIGATION, "determination_id": DET,
            "determination_obligation_id": OBLIGATION, "action_kind": "CORRECTION_PAYMENT_REQUEST",
            "claim_id": "claim:h:offset", "actor_id": "synthetic-official", "actor_role": "FINANCE_DECISION",
            "authority_id": "synthetic-authority-v1", "authority_epoch": 1, "authority_digest": BOUND,
            "decision": "OFFSET_REJECTED_CORRECTION_AUTHORIZED", "input_evaluation_id": EVAL_ID,
            "input_evaluation_result_digest": _dig(165), "expected_revision": 4, "decided_at_ms": 1_774_922_400_010}}
        queries = {"action_id": _query("ACTION_ID", ACT, ACT), "determination_id": _query("DETERMINATION_ID", DET, DET),
                   "evaluation_consumed": _query("EVALUATION_CONSUMED", EVAL_ID, DET)}
        for query in queries.values():
            query.update(version_sequence=11, version_head=_dig(43))
        sequence, head = 11, bytes([43]) * 64
        links = [{"payment_id": "payment:h:cash", "action_id": ACT}, {"payment_id": "payment:h:later", "action_id": ACT}]
    return engine.encode_correction_transition_request(
        snapshot=adapter._make_snapshot(data), command=command, action_lookup=lookup, query_observations=queries,
        current_event_sequence=sequence, previous_history_head=head, payment_links=links)

BLFCMD03 = {"blfcmd03_absent": "absent", "blfcmd03_existing_links": "existing_links", "blfcmd03_conflicting": "conflicting"}


def _blfpay01(receipt, foreign, expected_revision, command):
    return adapter.encode_payment_item(blfin02=adapter._encode_blfin02(_blfin02_authorized()), receipts=[receipt],
                                       foreign=foreign, expected_revision=expected_revision, command=command)


def _record(local_ref, pays_action_id):
    return {"kind": "record", "payment_id": "payment:h:new", "evidence_id": "evidence:new", "common_origin_id": "origin:new",
            "source_id": "fixture-payment-file", "source_version": "cash-v2", "local_ref": local_ref, "amount_cents": 250_000,
            "event_at_ms": REVERSAL_AT, "pays_action_id": pays_action_id}


def _reverse(origin, event_at):
    return {"kind": "reverse", "payment_id": "payment:h:cash", "evidence_id": "evidence:reversal",
            "common_origin_id": origin, "event_at_ms": event_at}


BLFPAY01 = {
    "blfpay01_record": lambda: _blfpay01(("payment:h:cash", 1, None), (False, False), 1, _record("ref:new", "action:h:offset")),
    "blfpay01_record_minimal": lambda: _blfpay01(("payment:h:cash", 0, "action:h:offset"), (True, False), None, _record(None, None)),
    "blfpay01_reverse": lambda: _blfpay01(("payment:h:cash", 2, None), (False, True), 2,
                                          _reverse("reversal:payment:h:cash", REVERSAL_AT)),
    "blfpay01_reverse_minimal": lambda: _blfpay01(("payment:h:cash", 2, None), (True, True), None, _reverse(None, None)),
}


def _lean_hex():
    run = subprocess.run([EXE], capture_output=True, text=True, timeout=120)
    lines = [line.split(" ") for line in run.stdout.split("\n") if line]
    return run.returncode, {name: hexed for name, hexed in lines}


@unittest.skipUnless(os.path.isfile(EXE), f"WIRE VECTORS NOT RUN: {EXE} is missing; run `lake build wire_vectors` in lean/")
class WireVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code, cls.lean = _lean_hex()

    def test_proofs_are_current(self):
        lake = shutil.which("lake") or os.path.join(os.path.expanduser("~"), ".elan", "bin", "lake")
        run = subprocess.run([lake, "build", "--no-build", *PROOFS, "wire_vectors"], cwd=LEAN, capture_output=True,
                             text=True, timeout=600)
        self.assertEqual(run.returncode, 0, "the codec proofs or wire_vectors are stale; run `lake build` in lean/\n" + run.stdout[-1500:])

    def test_lean_accepts_every_vector(self):
        self.assertEqual(self.code, 0, f"Lean refused a vector (NONE): {self.lean}")
        for name in (*BLFIN02, *BLFCMD03, *BLFPAY01, "blfofa01_absent"):
            self.assertIn(name, self.lean)

    def test_blfin02(self):
        for name, build in BLFIN02.items():
            with self.subTest(name):
                self.assertEqual(adapter._encode_blfin02(build()).hex(), self.lean[name])

    def test_blfcmd03(self):
        for name, variant in BLFCMD03.items():
            with self.subTest(name):
                self.assertEqual(_blfcmd03(variant).hex(), self.lean[name])

    def test_blfpay01(self):
        for name, build in BLFPAY01.items():
            with self.subTest(name):
                self.assertEqual(build().hex(), self.lean[name])

    def test_blfofa01(self):
        """The frame the live offset-authorization worker call sends: the engine's own frame + request, captured at the worker."""

        class Sent(Exception):
            pass

        def capture(wire, _rejections):
            raise Sent(wire)

        with mock.patch.object(engine, "_evaluate_wire", capture), self.assertRaises(Sent) as sent:
            engine.run_offset_authorization_v1(request=_blfcmd03("absent"))
        self.assertEqual(sent.exception.args[0].hex(), self.lean["blfofa01_absent"])


if __name__ == "__main__":
    unittest.main()
