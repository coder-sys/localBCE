"""Release by cause (Constitution I.2; docs/RIGHTRAIL_FULL_STACK_TARGET.md section 6): frozen acceptance tests, failing until
the engine admits `APPROVAL/v2` kind 3.  Each case is a list of frames sent in turn to one engine on one store
(``tests/test_gate_authority_frames.py``); a record rides the frame's approval list beside the bypasses.

``HeldTodayTests`` passes now: it shows each vector's payments are held for exactly the reasons the cases assume.
Synthetic, non-PHI.
"""

from __future__ import annotations

import datetime
from functools import lru_cache
from pathlib import Path
import tempfile
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_gate_authority_frames as af
from tests import test_right_rail_gate_formats as fx
from tests._test_only_counter import TestOnlyCounter

F, CLAIM, SDP, NONE = af.F, af.CLAIM, af.SDP, af.NONE
NOT_ENROLLED, FUTURE = decide.REASON_IDX["MEMBER_NOT_ENROLLED"], decide.REASON_IDX["SERVICE_DATE_FUTURE"]
ALREADY, DUP_LINE = decide.REASON_IDX["ALREADY_DECIDED"], decide.REASON_IDX["FFS_DUPLICATE_LINE"]
KEY = g.member(1003, 0)  # LAPSED's member: enrollment ended in January 2027
OTHER_PROGRAM = "medicaid-x"  # after the harness program in byte order, as a grant's entries must be


def held(n: int, proc: str, date: int = 20270305, program: str = fx.PROGRAM) -> gate.DecideRequest:
    """Payment ``pay-c<n>``: one claim line of the lapsed member (MEMBER_NOT_ENROLLED); each ``proc`` its own near key."""
    line = gate.encode_line("FFS_CLAIM", f"L{40 + n}", KEY, "P7001", "R7001", date, proc, 1, 12500 + n)
    return gate.DecideRequest(fx.TENANT, program, "FFS_CLAIM", f"cmd-c{n}", f"pay-c{n}", KEY, "P7001", 12500 + n, fx.PERIOD,
                              (line,), tuple(sorted((fx.D[2], fx.D[5]))))


C1, C2, C3 = held(1, "C99212"), held(2, "C99214"), held(3, "C99215")
TWO = held(4, "C99211", g.BAD_DATE)  # MEMBER_NOT_ENROLLED and SERVICE_DATE_FUTURE
C1_OTHER = held(1, "C99212", program=OTHER_PROGRAM)  # C1's payment id in another program
enc = gate.encode_decide_request


def ent(r: gate.DecideRequest, amount: int | None = None, digest: bytes | None = None) -> tuple[str, bytes, int]:
    return r.payment_id, digest or au.digest(enc(r)), r.amount_cents if amount is None else amount


def rec(*rs: gate.DecideRequest, reason: int = NOT_ENROLLED, **kw) -> bytes:
    return au.cause(reason, [ent(r) for r in rs], **kw)


def rid(doc: bytes) -> bytes:
    """A record's id: the digest of its unsigned bytes."""
    return au.H(fx.unsigned(doc))


def forged(signed: bytes, other: bytes) -> bytes:
    """``other``'s unsigned bytes under ``signed``'s signature block: a record changed after it was signed."""
    return fx.unsigned(other) + signed[len(fx.unsigned(signed)):]


def q(r: gate.DecideRequest) -> str:
    return str(af.pay_number(r))


allow = lambda: au.grant([(fx.PROGRAM, CLAIM | SDP, 3, 0)])  # noqa: E731
hold = lambda: au.grant([(fx.PROGRAM, CLAIM | SDP, 2, 1 << NOT_ENROLLED | 1 << FUTURE)])  # noqa: E731
two_programs = lambda: au.grant([(fx.PROGRAM, CLAIM | SDP, 3, 0), (OTHER_PROGRAM, CLAIM, 3, 0)])  # noqa: E731
lift = lambda: au.grant([(fx.PROGRAM, CLAIM | SDP, 2, 1 << FUTURE)])  # noqa: E731  (HOLD authority: lifts a hold for MEMBER_NOT_ENROLLED)
FILLER = [(f"pay-z{i:05d}", bytes(64), 1) for i in range(4095)]  # listed payments never sent: after pay-c1 in byte order


def capped_feeds() -> list[str]:
    """The frame's reference rows with 1024 more one-day enrollment spans of KEY's member, years before its service dates:
    1025 rows under one member is past the 1024-row cap, so each of the member's lines HOLDs with POSTING_CAP."""
    feeds = list(g._HEAD)
    at = next(i for i, row in enumerate(feeds) if row.startswith("snap span"))
    snap, n = feeds[at].split(), int(feeds[at].split()[3])
    days = (datetime.date(2020, 1, 1) + datetime.timedelta(days=i) for i in range(1024))
    rows = [*feeds[at + 1:at + 1 + n], *(f"span {g.nat(KEY)} 501 {d:%Y%m%d} {d:%Y%m%d}" for d in days)]
    snap[3] = str(len(rows))
    snap[4] = decide.feed("span", int(snap[2]), [tuple(map(int, r.split()[1:])) for r in rows])[0][13:].hex()
    return [*feeds[:at], " ".join(snap), *rows, *feeds[at + 1 + n:]]


def refused(x: bytes) -> list[dict]:
    """C1 held, then sent again with approval bytes ``x``."""
    return [F(allow(), [enc(C1)]), F(allow(), [enc(C1)], [x])]


# Whole-record refusals: (approval bytes, the note's word, its payment field).  The payment stays HOLD.
def record_refusals() -> dict[str, tuple[bytes, str, str]]:
    r1 = rec(C1)
    malformed = {
        "window_over_31_days": rec(C1, na=20270415),
        "cause_past_the_last_reason": rec(C1, reason=len(decide.REASON_IDX)),
        "cause_255": rec(C1, reason=255),
        "total_one_over": au.cause(NOT_ENROLLED, [ent(C1)], total=C1.amount_cents + 1),
        "total_one_under": au.cause(NOT_ENROLLED, [ent(C1)], total=C1.amount_cents - 1),
        "amount_past_2_63_minus_1": au.cause(NOT_ENROLLED, [ent(C1, amount=1 << 63)]),
        "total_past_2_63_minus_1": au.cause(NOT_ENROLLED, [ent(C1), ent(C2, amount=(1 << 63) - C1.amount_cents)]),
        "entries_out_of_order": rec(C2, C1),
        "entry_twice": rec(C1, C1),
        "no_entries": au.cause(NOT_ENROLLED, []),
        "4097_entries": au.cause(NOT_ENROLLED, [ent(C1), *FILLER, ("pay-zzzzzz", bytes(64), 1)]),
        "flows_0": rec(C1, flows=0),
        "flows_32": rec(C1, flows=32),
        "dates_reversed": rec(C1, dates=(20270331, 20270301)),
        "date_invalid": rec(C1, dates=(20270230, 20270331)),
        "trailing_byte": r1 + b"\x00",
        "truncated": r1[:-1],
        "bypass_bytes_relabeled_kind_3": (lambda b: b[:20] + b"\x03" + b[21:])(au.bypass(fx.PROGRAM, C1.payment_id, au.digest(enc(C1)), 1 << NOT_ENROLLED)),
    }
    return {
        **{k: (x, "MALFORMED", "-") for k, x in malformed.items()},
        "one_signer": (rec(C1, signers=("a1",)), "UNSIGNED", "-"),
        "two_approvers_of_one_subject": (rec(C1, signers=("a1", "a3")), "UNSIGNED", "-"),
        "roster_keys_are_not_approvers": (rec(C1, signers=("r1", "r2")), "UNSIGNED", "-"),
        "request_digest_changed_after_signing": (forged(r1, au.cause(NOT_ENROLLED, [ent(C1, digest=au.digest(enc(C2)))])), "UNSIGNED", "-"),
        "cause_changed_after_signing": (forged(r1, rec(C1, reason=FUTURE)), "UNSIGNED", "-"),
        "amount_and_total_raised_after_signing": (forged(r1, au.cause(NOT_ENROLLED, [ent(C1, amount=C1.amount_cents + 1)])), "UNSIGNED", "-"),
        "expired": (rec(C1, nb=20270201, na=20270228), "EXPIRED", "-"),
        "another_tenant": (rec(C1, tenant=fx.OTHER), "SCOPE", "-"),
        "another_state": (rec(C1, state=au.H(b"TEST/OTHER-STATE")), "SCOPE", "-"),
        "never_bypassable_cause": (rec(C1, reason=ALREADY), "REASONS", "-"),
        "exact_duplicate_is_never_a_cause": (rec(C1, reason=DUP_LINE), "REASONS", "-"),
        # one listed payment: the note names it
        "wrong_request": (au.cause(NOT_ENROLLED, [ent(C1, digest=au.digest(enc(C2)))]), "WRONG_REQUEST", q(C1)),
        "amount_differs": (au.cause(NOT_ENROLLED, [ent(C1, amount=C1.amount_cents - 1)]), "AMOUNT", q(C1)),
        "flow_outside_the_mask": (rec(C1, flows=SDP), "SCOPE", q(C1)),
        "service_date_outside_the_range": (rec(C1, dates=(20270306, 20270331)), "SCOPE", q(C1)),
        "held_for_another_cause_only": (rec(C1, reason=FUTURE), "NOT_HELD", q(C1)),
    }


def cases() -> dict[str, list[dict]]:
    c1, c2, two, clean = enc(C1), enc(C2), enc(TWO), enc(af.CLEAN)
    r12, cap = rec(C1, C2), capped_feeds()
    return {
        **{k: refused(x) for k, (x, _, _) in record_refusals().items()},
        "releases_every_listed_held_payment": [F(allow(), [c1, c2]), F(allow(), [c1, c2], [r12])],
        "an_unlisted_payment_held_for_the_cause_stays_held": [F(allow(), [c1, c2]), F(allow(), [c1, c2], [rec(C1)])],
        "one_record_in_two_batches_then_never_again": [F(allow(), [c1, c2]), F(allow(), [c1], [r12]), F(allow(), [c2], [r12]),
                                                       F(allow(), [c1], [r12])],
        "a_listed_payment_not_in_the_batch_is_silent": [F(allow(), [c1]), F(allow(), [c1], [rec(C1, C3)])],
        "4096_entries_are_read": [F(allow(), [c1]), F(allow(), [c1], [au.cause(NOT_ENROLLED, [ent(C1), *FILLER])])],
        "kind_4_is_no_approval": [F(allow(), [c1]), F(allow(), [c1], [(lambda b: b[:20] + b"\x04" + b[21:])(rec(C1))])],
        "cause_bytes_relabeled_kind_2": [F(allow(), [c1]), F(allow(), [c1], [(lambda b: b[:20] + b"\x02" + b[21:])(rec(C1))])],
        "past_the_64_approvals_read": [F(allow(), [c1]), F(allow(), [c1], [bytes.fromhex("deadbeef")] * 64 + [rec(C1)])],
        "an_entry_without_transfer_authority": [F(hold(), [c1]), F(hold(), [c1], [rec(C1)])],
        "a_redone_payment": [F(allow(), [clean]), F(allow(), [clean], [au.cause(NOT_ENROLLED, [ent(af.CLEAN)])],
                                                    redo=(af.pay_number(af.CLEAN),))],
        "a_bypass_and_a_record_name_one_payment": [F(allow(), [c1]), F(allow(), [c1], [
            au.bypass(fx.PROGRAM, C1.payment_id, au.digest(c1), 1 << NOT_ENROLLED), rec(C1)])],
        "two_records_name_one_payment": [F(allow(), [c1]), F(allow(), [c1], [rec(C1), rec(C1, nb=20270302)])],
        "held_for_another_cause_as_well": [F(allow(), [two]), F(allow(), [two], [rec(TWO, dates=(20270301, 20280131))])],
        "an_allowed_payment": [F(allow(), [clean], [au.cause(NOT_ENROLLED, [ent(af.CLEAN)])])],
        "second_use_is_not_held": [F(allow(), [c1]), F(allow(), [c1], [rec(C1)]), F(allow(), [c1], [rec(C1)])],
        "another_programs_payment_with_a_listed_id_is_silent": [F(two_programs(), [enc(C1_OTHER)]),
                                                                F(two_programs(), [enc(C1_OTHER)], [rec(C1)])],
        "a_capped_payment": [F(allow(), [c1], feeds=cap), F(allow(), [c1], [rec(C1)], feeds=cap)],
        "a_lifted_payment": [F(lift(), [c1])],
        "a_capped_payment_under_a_lift": [F(lift(), [c1], feeds=cap)],
    }


@lru_cache(maxsize=None)
def results() -> dict[str, list]:
    out = {}
    for name, frames in cases().items():
        with tempfile.TemporaryDirectory() as tmp:
            out[name] = af.run_case(frames, Path(tmp))
    return out


def pays(name: str) -> list[decide.Pay]:
    return [p for _, ps, _ in results()[name] for p in ps]


def notes(name: str) -> list[tuple[str, ...]]:
    """Every note of the case, sorted (their order is not part of the format)."""
    return sorted(tuple(x.split()) for _, _, ns in results()[name] for x in ns)


class HeldTodayTests(unittest.TestCase):
    """The vectors' preconditions, true before the amendment is built."""

    def test_the_held_payments_are_held_for_the_reasons_assumed(self):
        for name, req, why in (("held_for_another_cause_as_well", TWO, ("MEMBER_NOT_ENROLLED", "SERVICE_DATE_FUTURE")),
                               ("another_programs_payment_with_a_listed_id_is_silent", C1_OTHER, ("MEMBER_NOT_ENROLLED",))):
            first = results()[name][0][1]
            self.assertEqual([(p.payment_id, p.outcome, p.reasons) for p in first if p.payment_id == req.payment_id],
                             [(req.payment_id, "HOLD", why)], name)
        self.assertEqual([(p.payment_id, p.outcome, p.reasons) for p in results()["releases_every_listed_held_payment"][0][1]],
                         [(C1.payment_id, "HOLD", ("MEMBER_NOT_ENROLLED",)), (C2.payment_id, "HOLD", ("MEMBER_NOT_ENROLLED",))])


class CauseReleaseFrameTests(unittest.TestCase):
    def test_a_record_releases_exactly_its_listed_held_payments(self):
        r12 = rec(C1, C2)
        for name, outs, ids in (
                ("releases_every_listed_held_payment", ["HOLD", "HOLD", "ALLOW", "ALLOW"], [NONE, NONE, rid(r12), rid(r12)]),
                ("an_unlisted_payment_held_for_the_cause_stays_held", ["HOLD", "HOLD", "ALLOW", "HOLD"], [NONE, NONE, rid(rec(C1)), NONE]),
                ("a_listed_payment_not_in_the_batch_is_silent", ["HOLD", "ALLOW"], [NONE, rid(rec(C1, C3))]),
                ("4096_entries_are_read", ["HOLD", "ALLOW"], [NONE, rid(au.cause(NOT_ENROLLED, [ent(C1), *FILLER]))])):
            got = pays(name)
            self.assertEqual([p.outcome for p in got], outs, name)
            self.assertEqual([p.bypass for p in got], ids, name)
            self.assertTrue(all(p.authority == "TRANSFER" for p in got), name)
            self.assertEqual(notes(name), [], name)

    def test_one_record_over_many_batches_releases_each_payment_once(self):
        got = pays("one_record_in_two_batches_then_never_again")
        self.assertEqual([(p.payment_id, p.outcome) for p in got], [(C1.payment_id, "HOLD"), (C2.payment_id, "HOLD"),
                                                                   (C1.payment_id, "ALLOW"), (C2.payment_id, "ALLOW"), (C1.payment_id, "HOLD")])
        self.assertIn("ALREADY_DECIDED", got[4].reasons)
        self.assertEqual(got[4].bypass, NONE)
        self.assertEqual(notes("one_record_in_two_batches_then_never_again"), [("RULES_CAUSE", q(C1), "NOT_HELD")])
        again = pays("second_use_is_not_held")
        self.assertEqual([p.outcome for p in again], ["HOLD", "ALLOW", "HOLD"])
        self.assertEqual(notes("second_use_is_not_held"), [("RULES_CAUSE", q(C1), "NOT_HELD")])

    def test_a_refused_record_releases_nothing_and_says_why(self):
        for name, (_, why, pay) in record_refusals().items():
            with self.subTest(name):
                self.assertEqual([(p.outcome, p.bypass) for p in pays(name)], [("HOLD", NONE)] * 2)
                self.assertEqual(notes(name), [("RULES_CAUSE", pay, why)])

    def test_bytes_that_are_no_cause_record(self):
        for name in ("kind_4_is_no_approval", "cause_bytes_relabeled_kind_2"):
            self.assertEqual([p.outcome for p in pays(name)], ["HOLD", "HOLD"], name)
            self.assertEqual(notes(name), [("RULES_BYPASS", "-", "MALFORMED")], name)
        self.assertEqual([p.outcome for p in pays("past_the_64_approvals_read")], ["HOLD", "HOLD"])
        self.assertEqual(notes("past_the_64_approvals_read"), [("RULES_BYPASS", "-", "MALFORMED")] * 64 + [("RULES_CAUSE", "-", "TOO_MANY")])

    def test_what_a_record_never_releases(self):
        for name, outs, want in (
                ("an_entry_without_transfer_authority", ["HOLD", "HOLD"], [("RULES_CAUSE", q(C1), "SCOPE")]),
                ("a_redone_payment", ["ALLOW", "ALLOW"], [("RULES_CAUSE", q(af.CLEAN), "REDO")]),
                ("a_bypass_and_a_record_name_one_payment", ["HOLD", "HOLD"],
                 [("RULES_BYPASS", q(C1), "DUPLICATE"), ("RULES_CAUSE", q(C1), "DUPLICATE")]),
                ("two_records_name_one_payment", ["HOLD", "HOLD"], [("RULES_CAUSE", q(C1), "DUPLICATE")] * 2),
                ("held_for_another_cause_as_well", ["HOLD", "HOLD"], [("RULES_CAUSE", q(TWO), "NOT_HELD")]),
                ("an_allowed_payment", ["ALLOW"], [("RULES_CAUSE", q(af.CLEAN), "NOT_HELD")]),
                ("another_programs_payment_with_a_listed_id_is_silent", ["HOLD", "HOLD"], [])):
            with self.subTest(name):
                self.assertEqual([p.outcome for p in pays(name)], outs)
                self.assertEqual([p.bypass for p in pays(name)], [NONE] * len(outs))
                self.assertEqual(notes(name), want)

    def test_a_capped_payment_is_never_released_or_lifted(self):
        """POSTING_CAP is no cause a record or a holds mask overrides: C1 released by its record and lifted at HOLD authority
        without the cap (``an_unlisted_payment_held_for_the_cause_stays_held``, ``a_lifted_payment``) stays HOLD with it."""
        self.assertEqual([(p.outcome, p.authority) for p in pays("a_lifted_payment")], [("ALLOW", "HOLD")])
        for name, outs in (("a_capped_payment", ["HOLD", "HOLD"]), ("a_capped_payment_under_a_lift", ["HOLD"])):
            with self.subTest(name):
                got = pays(name)
                self.assertEqual([p.outcome for p in got], outs)
                self.assertEqual([p.bypass for p in got], [NONE] * len(outs))
                self.assertTrue(all("POSTING_CAP" in p.reasons for p in got), [p.reasons for p in got])
        self.assertEqual(notes("a_capped_payment"), [("RULES_CAUSE", q(C1), "NOT_HELD")])
        self.assertEqual(notes("a_capped_payment_under_a_lift"), [])


class CauseAnswerBindingTests(unittest.TestCase):
    """The host takes a record's id on a leaf only for a payment the record lists."""

    def test_a_record_id_on_an_unlisted_payment_is_refused(self):
        spec, head = cases()["an_unlisted_payment_held_for_the_cause_stays_held"], af.fw.GENESIS
        with tempfile.TemporaryDirectory() as tmp:
            eng = af.fw.Engine(Path(tmp) / "idx")
            try:
                first = af.build(spec[0], 1, head)
                head = decide._answer(eng.send(first), first)[2]
                data = af.build(spec[1], 2, head)
                answer = eng.send(data)
            finally:
                eng.close()
        got = decide._answer(answer, data)[5]
        self.assertEqual([(p.outcome, p.bypass) for p in got], [("ALLOW", rid(rec(C1))), ("HOLD", NONE)])
        at = answer.index(rid(rec(C1))) + 128  # C1's leaf ends with its bypass id and input; C2's leaf follows
        outcome, authority, flag = answer[at], answer[at + 5], answer[at + 6]
        self.assertEqual((outcome, flag), (1, 0))  # HOLD, no bypass id
        bad = answer[:at] + bytes([0]) + bytes(4) + bytes([authority, 1]) + rid(rec(C1)) + answer[at + 7:]
        with self.assertRaises(decide.GateDecideError):
            decide._answer(bad, data)


def through_payer(case: fx.Scratch, request: gate.DecideRequest, y: decide.Pay) -> list[str | None]:
    """Seal ``y`` as one batch and ask the payer to release ``request`` on its token twice: the two answers."""
    with case.scratch() as tmp:
        handle, held, cert = fx.custody(tmp)
        p = case.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                              shard_id=0, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(), key_cert=cert,
                                              payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(Path(tmp) / "shard.counter"),
                                              floors=lambda: (0, 0, 0, bytes(64))))
        p.prepared = ans = decide.Answer((), fx.STATE, b"", None, None, fx.D[1], 0, 1, (y,), fx.D[4])
        _, signed, (token,) = p.commit(request.program_id, ans, fx.NOW)
        store = case.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", links={fx.TENANT: held},
                                            grants=((fx.TENANT, y.grant_id, (fx.D[4],), (fx.D[4],)),)))
        store.install_cert(cert)
        case.assertEqual(store.store_checkpoint(signed), "stored")
        store.send(request, transmit=lambda data: None)
        return [store.release(request, gate.encode_token(token), now=fx.NOW) for _ in range(2)]


class CauseReleasePaidTests(fx.Scratch):
    def test_a_payment_released_by_cause_is_paid_once_with_no_new_payer_check(self):
        y = pays("releases_every_listed_held_payment")[2]
        self.assertEqual((y.payment_id, y.outcome, y.authority, y.bypass), (C1.payment_id, "ALLOW", "TRANSFER", rid(rec(C1, C2))))
        self.assertEqual(through_payer(self, C1, y), [None, "released"])


if __name__ == "__main__":
    unittest.main()
