"""The engine admits the state's signed grant and bypass at commit: positive and refused frames.

Each case is a list of request frames sent in turn to one engine on one store (each opens at the head the one before
answered), signed from fixed test-only seeds (``tests/_gate_authority.py``); the test reads each answer and asserts what it
shows.  Synthetic, non-PHI.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from app import right_rail_gate_chain as flatchain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide
from app import right_rail_gate_payer as payer
from app import right_rail_gate_producer as producer
from conformance import gate_rules_v1_ref as ref
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_flat_worker as fw
from tests import test_right_rail_gate_formats as fx
from tests._test_only_counter import TestOnlyCounter

CLAIM, SDP = 1 << 1, 1 << 3  # flow mask bits: tag - 1
BYPASSABLE, ALREADY = 1 << 9 | 1 << 16, 1 << 0  # MEMBER_NOT_ENROLLED and SERVICE_DATE_FUTURE are bypassable; ALREADY_DECIDED never is
NONE = bytes(64)


def sdp_request(payment: str = "pay-sdp", member: bytes | None = None) -> gate.DecideRequest:
    """A flow the rules do not decide line by line: HUMAN_REVIEW under any grant."""
    member = member or hashlib.sha3_256(payment.encode()).digest()
    return gate.DecideRequest(fx.TENANT, fx.PROGRAM, "SDP", "cmd-sdp", payment, member, "P7001", 100, fx.PERIOD, (), ())


CLEAN, HELD = g.request(1, 0, [10, 11]), g.request(2, 0, [12], bad=[12])  # ALLOW; MEMBER_NOT_ENROLLED (a bypassable reason)
REDONE = g.request(1, 0, [10, 11, 12], bad=[12])  # CLEAN's payment decided again with a line it does not own, held for bypassable reasons
CYCLE = 1 << 0


def cycle_request(payment: str = "pay-cyc", ids=(10, 11)) -> gate.DecideRequest:
    """An FFS_CYCLE payment whose lines carry the same claim ids and member as CLEAN's: ruled, but not a flow `allow(CLAIM)` covers."""
    rows = [g.claim(i, False).split() for i in ids]
    key, payee = g.member(int(rows[0][0]), 0), f"P{rows[0][1]}"
    lines = tuple(gate.encode_line("FFS_CYCLE", f"L{i}", key, payee, f"R{r[2]}", int(r[3]), f"C{r[4]}", int(r[5]), int(r[6])) for i, r in zip(ids, rows))
    return gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CYCLE", "cmd-cyc", payment, key, payee, sum(int(r[6]) for r in rows),
                              fx.PERIOD, lines, tuple(sorted((fx.D[2], fx.D[5]))))


# A payment held only because its member's enrollment ended in January (MEMBER_NOT_ENROLLED); `cleared_feeds` extends that span.
LAPSED = gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", "cmd-lapsed", "pay-lapsed", g.member(1003, 0), "P7001", 12500, fx.PERIOD,
                            (gate.encode_line("FFS_CLAIM", "L40", g.member(1003, 0), "P7001", "R7001", 20270305, "C99213", 1, 12500),),
                            tuple(sorted((fx.D[2], fx.D[5]))))


def cleared_feeds() -> list[str]:
    """The frame's reference rows with LAPSED's member enrolled through 2029: its enrollment snapshot line, count and pin follow."""
    feeds = list(g._HEAD)
    at = next(i for i, row in enumerate(feeds) if row.startswith("snap span"))
    snap, n = feeds[at].split(), int(feeds[at].split()[3])
    rows = [" ".join([*r.split()[:4], "20291231"]) if r.split()[1] == str(g.nat(g.member(1003, 0))) else r for r in feeds[at + 1:at + 1 + n]]
    vals = [tuple(int(x) for x in r.split()[1:]) for r in rows]
    snap[4] = hashlib.sha3_512(ref.pin_bytes("span", int(snap[2]), len(vals), vals)).hexdigest()
    return [*feeds[:at], " ".join(snap), *rows, *feeds[at + 1 + n:]]


def F(grant: bytes | None, reqs: list[bytes], byps=(), floor: int | None = None, keyset: bool = True,
      step: tuple[int, bytes] | None = None, feeds: list[str] | None = None, redo=()) -> dict:
    """One frame of a case: the grant, the requests' bytes, the signed bypasses, the redone payments and the key evidence it carries."""
    return {"grant": grant or b"", "reqs": reqs, "byps": byps, "floor": floor, "keyset": keyset, "step": step, "feeds": feeds, "redo": redo}


def pay_number(r: gate.DecideRequest) -> int:
    """Rules.payNat: 0x01, then the length-prefixed program and payment ids, big-endian."""
    u16 = lambda b: len(b).to_bytes(2, "big") + b  # noqa: E731
    return int.from_bytes(b"\x01" + u16(r.program_id.encode()) + u16(r.payment_id.encode()), "big")


def build(spec: dict, batch: int, prev: bytes) -> bytes:
    pin, doc = au.genesis()
    keys = decide.Keys(doc if spec["keyset"] else b"", (spec["step"],) if spec["step"] else ())
    data = decide.request_frame(g.feeds_of(spec["feeds"] or g._HEAD), 0, batch, g.ASOF, prev, pin, (spec["floor"] or 0, 0, 0, bytes(64)), keys, spec["grant"],
                                fx.D[4], spec["byps"], spec["reqs"], spec["redo"])
    if spec["floor"] is not None:
        return data
    body, at = data[82:], 76 + 4 * 77  # no floor asserted: the flag after the feeds' rows, the redone payments and the pin is cleared
    at += sum(int.from_bytes(body[76 + 77 * i + 9:76 + 77 * i + 13], "little") * w for i, w in enumerate(map(sum, decide.FEED_WIDTHS.values()))) + 261 * len(spec["redo"]) + 64
    body = body[:at] + b"\x00" + body[at + 1:]
    return data[:18] + hashlib.sha3_512(b"RR/GATE/FRAME2/v1\x00" + body).digest() + body


def cases() -> dict[str, list[dict]]:
    enc = gate.encode_decide_request
    a, s, f, held, cyc = enc(CLEAN), enc(sdp_request()), enc(HELD), enc(LAPSED), enc(cycle_request())
    allow = lambda mask=CLAIM | SDP, **kw: au.grant([(fx.PROGRAM, mask, 3, 0)], **kw)  # noqa: E731
    hold = au.grant([(fx.PROGRAM, CLAIM | SDP, 2, BYPASSABLE)])
    byp = lambda r, bits=BYPASSABLE, **kw: au.bypass(fx.PROGRAM, (HELD if r == "F" else CLEAN).payment_id, au.digest(f if r == "F" else a), bits, **kw)  # noqa: E731
    return {
        "transfer_grant": [F(allow(), [a, s])],
        "hold_grant": [F(hold, [a, f])],
        "observe_grant": [F(au.grant([(fx.PROGRAM, CLAIM, 1, 0)]), [a])],
        "no_grant": [F(None, [a])],
        "no_key_set": [F(allow(), [a], keyset=False)],
        "expired_grant": [F(allow(nb=20270201, na=20270228), [a])],
        "one_signer_grant": [F(allow(signers=("r1",)), [a])],
        "grant_of_another_tenant": [F(allow(tenant=fx.OTHER), [a])],
        "grant_that_does_not_cover_the_flow": [F(allow(CLAIM), [a, s])],
        # an uncovered request is held alone and its lines are not decided: a covered request with the same claim ids is decided on its own
        "uncovered_ruled_payment": [F(allow(SDP), [a, s])],
        "uncovered_request_shares_claims_with_a_covered_one": [F(allow(), [cyc, a])],
        "uncovered_request_then_covering_grant": [F(allow(), [cyc]), F(allow(CLAIM | CYCLE, serial=2), [cyc])],
        "grant_serial_below_the_floor_asserted": [F(allow(serial=3), [a], floor=4)],
        "member_not_enrolled_is_held": [F(allow(), [f])],
        "bypass_releases_the_held_payment": [F(allow(), [f]), F(allow(), [f], [byp("F")])],
        # a held payment whose facts have since cleared, sent again with a bypass: the bypass is the recorded cause of its release
        "held_payment_released_after_its_facts_clear": [F(allow(), [held]), F(
            allow(), [held], [au.bypass(fx.PROGRAM, LAPSED.payment_id, au.digest(held), BYPASSABLE)], feeds=cleared_feeds())],
        "cleared_hold_without_a_bypass_stays_held": [F(allow(), [held]), F(allow(), [held], feeds=cleared_feeds())],
        # a bad bypass is refused alone, with a line naming why; the rest of the batch is decided
        "malformed_bypass_is_refused_alone": [F(allow(), [a, f], [bytes.fromhex("deadbeef")])],
        "two_bypasses_for_one_payment_release_nothing": [F(allow(), [f]), F(allow(), [f, a], [byp("F"), byp("F", nb=20270302)])],
        "bypass_of_a_payment_not_in_the_batch": [F(allow(), [a], [byp("F")])],
        "bypass_of_a_redone_payment": [F(allow(), [a]), F(allow(), [a], [byp("A")], redo=(pay_number(CLEAN),))],
        "second_use_of_a_bypass_is_not_held": [F(allow(), [f]), F(allow(), [f], [byp("F")]), F(allow(), [f], [byp("F")])],
        "one_signer_bypass": [F(allow(), [f]), F(allow(), [f], [byp("F", signers=("a1",))])],
        "two_approvers_of_one_subject": [F(allow(), [f]), F(allow(), [f], [byp("F", signers=("a1", "a3"))])],
        "expired_bypass": [F(allow(), [f]), F(allow(), [f], [byp("F", nb=20270201, na=20270228)])],
        "never_bypassable_reason": [F(allow(), [f]), F(allow(), [f], [byp("F", ALREADY | BYPASSABLE)])],
        "bypass_of_an_allowed_payment": [F(allow(), [a], [byp("A")])],
        "bypass_of_a_payment_not_held": [F(allow(), [f], [byp("F")])],
        "bypass_for_another_request": [F(allow(), [f]), F(allow(), [f], [au.bypass(fx.PROGRAM, HELD.payment_id, au.digest(a), BYPASSABLE)])],
        "bypass_of_another_tenant": [F(allow(), [f]), F(allow(), [f], [byp("F", tenant=fx.OTHER)])],
        "lowered_floor": [F(allow(serial=5), [a]), F(allow(serial=5), [a], floor=3)],
        "superseded_grant": [F(allow(serial=5), [a]), F(allow(serial=4), [a])],
        "newer_grant_is_taken": [F(allow(serial=5), [a]), F(allow(serial=6), [a])],
        # L2: the request no entry covers is held alone for SCOPE; the covered one is decided
        "hold_grant_on_a_flow_without_lines": [F(hold, [a, s])],
        "bypass_where_the_entry_cannot_transfer": [F(hold, [f]), F(hold, [f], [byp("F")])],
        "rotated_key_set": [F(allow(), [a], step=au.kstep()), F(allow(), [a], step=au.kstep())],
        "rotated_key_set_cannot_be_forgotten": [F(allow(), [a], step=au.kstep()), F(allow(), [a])],
    }


def run_case(frames: list[dict], tmp: Path) -> list[tuple[str | None, list[decide.Pay], list[str]]]:
    """Each frame's answer in turn: (the refusal or grant hold, the leaves, the bypass notes)."""
    eng, head, out = fw.Engine(tmp / "idx"), fw.GENESIS, []
    try:
        for n, spec in enumerate(frames):
            data = build(spec, n + 1, head)
            answer = eng.send(data)
            why, recs, new, _, _, pays, _ = decide._answer(answer, data)
            notes = []
            if why is None:  # the notes follow the records, the head and root, the grant-hold word, the grant id and the authority record
                r = decide._Reader(answer)
                r.take(87 + 20 * len(recs) + 128 + 16 + 64 + flatchain.AUTH)
                notes = [r.blob(2).decode() for _ in range(r.num(4))]
                head = new
            out.append((why, pays, notes))
    finally:
        eng.close()
    return out


class AuthorityFrameTests(unittest.TestCase):
    def test_what_the_frames_show(self):
        by = {}
        for name, frames in cases().items():
            with tempfile.TemporaryDirectory() as tmp:
                by[name] = run_case(frames, Path(tmp))
        pay = lambda n: [p for _, ps, _ in by[n] for p in ps]  # noqa: E731
        outcomes = lambda n: [p.outcome for p in pay(n)]  # noqa: E731
        reasons = lambda p: ",".join(p.reasons) or "-"  # noqa: E731
        holds = lambda n: [w for w, _, _ in by[n] if w]  # noqa: E731
        notes = lambda n: [x.split() for _, _, ns in by[n] for x in ns]  # noqa: E731
        self.assertEqual(outcomes("transfer_grant"), ["ALLOW", "HUMAN_REVIEW"])
        # M1: a flow with no lines keeps the rules' outcome under a HOLD grant; the ruled payment is still ALLOW
        self.assertEqual([(p.outcome, p.authority) for p in pay("hold_grant_on_a_flow_without_lines")], [("ALLOW", "HOLD"), ("HUMAN_REVIEW", "HOLD")])
        # L2: the one request no entry covers is held for SCOPE alone; the covered one is decided
        self.assertEqual([(p.outcome, reasons(p)) for p in pay("grant_that_does_not_cover_the_flow")], [("ALLOW", "-"), ("HUMAN_REVIEW", "SCOPE")])
        self.assertEqual(holds("grant_that_does_not_cover_the_flow"), [])
        self.assertEqual([(p.outcome, reasons(p)) for p in pay("uncovered_ruled_payment")], [("HOLD", "SCOPE"), ("HUMAN_REVIEW", "-")])
        self.assertEqual([(p.outcome, reasons(p)) for p in pay("uncovered_request_shares_claims_with_a_covered_one")], [("HOLD", "SCOPE"), ("ALLOW", "-")])
        self.assertEqual([(p.outcome, reasons(p)) for p in pay("uncovered_request_then_covering_grant")], [("HOLD", "SCOPE"), ("ALLOW", "-")])
        # L1: a bypass under an entry that cannot transfer is refused, and the payment stays held
        self.assertEqual([x[-1] for x in notes("bypass_where_the_entry_cannot_transfer")], ["SCOPE"])
        self.assertEqual(outcomes("bypass_where_the_entry_cannot_transfer"), ["HOLD", "HOLD"])
        self.assertTrue(all(p.authority == "TRANSFER" for p in pay("transfer_grant")))
        for n, why in (("no_grant", "MISSING"), ("no_key_set", "MISSING"), ("expired_grant", "EXPIRED"), ("one_signer_grant", "UNSIGNED"),
                       ("grant_of_another_tenant", "SCOPE"), ("grant_serial_below_the_floor_asserted", "SUPERSEDED")):
            self.assertEqual(holds(n), [f"grant_{why.lower()}"], n)
            self.assertEqual(pay(n), [], n)
        self.assertEqual(holds("lowered_floor"), ["grant_floor"])
        self.assertEqual(holds("superseded_grant"), ["grant_superseded"])
        self.assertEqual(holds("newer_grant_is_taken"), [])
        self.assertEqual(holds("rotated_key_set_cannot_be_forgotten"), ["grant_head"])
        self.assertNotEqual(outcomes("member_not_enrolled_is_held")[0], "ALLOW")
        released = pay("bypass_releases_the_held_payment")
        self.assertEqual([p.outcome for p in released], ["HOLD", "ALLOW"])
        self.assertEqual((released[1].authority, released[0].bypass, released[1].bypass != released[0].bypass), ("TRANSFER", NONE, True))
        sent_again = pay("second_use_of_a_bypass_is_not_held")  # held, released by the bypass, then the same bypass again: decided already, so it releases nothing
        self.assertEqual([p.outcome for p in sent_again], ["HOLD", "ALLOW", "HOLD"])
        self.assertIn("ALREADY_DECIDED", sent_again[2].reasons)
        self.assertEqual([x[-1] for x in notes("second_use_of_a_bypass_is_not_held")], ["NOT_HELD"])
        cleared = pay("held_payment_released_after_its_facts_clear")
        self.assertEqual([p.outcome for p in cleared], ["HOLD", "ALLOW"])
        self.assertEqual((cleared[0].bypass, cleared[1].authority, cleared[1].bypass != NONE), (NONE, "TRANSFER", True))
        self.assertEqual(notes("held_payment_released_after_its_facts_clear"), [])
        self.assertEqual(cleared[1].reasons, ())  # the leaf states what is true now: no reason; the bypass is the recorded cause
        kept = pay("cleared_hold_without_a_bypass_stays_held")  # without a bypass, its facts clearing does not release it
        self.assertEqual([(p.outcome, p.bypass) for p in kept], [("HOLD", NONE)] * 2)
        self.assertIn("ALREADY_DECIDED", kept[1].reasons)
        # refused alone: one note naming the cause, the rest of the batch decided, the payment left as it was
        refused = lambda n: [tuple(x[1:]) for x in notes(n)]  # noqa: E731
        self.assertEqual(refused("malformed_bypass_is_refused_alone"), [("-", "MALFORMED")])
        self.assertEqual(outcomes("malformed_bypass_is_refused_alone"), ["ALLOW", "HOLD"])
        two = refused("two_bypasses_for_one_payment_release_nothing")
        self.assertEqual(([w for _, w in two], len({q for q, _ in two})), (["DUPLICATE", "DUPLICATE"], 1))
        self.assertEqual(outcomes("two_bypasses_for_one_payment_release_nothing"), ["HOLD", "HOLD", "ALLOW"])
        self.assertEqual([w for _, w in refused("bypass_of_a_payment_not_in_the_batch")], ["NOT_IN_BATCH"])
        self.assertEqual(outcomes("bypass_of_a_payment_not_in_the_batch"), ["ALLOW"])
        self.assertEqual([w for _, w in refused("bypass_of_a_redone_payment")], ["REDO"])
        self.assertEqual(outcomes("bypass_of_a_redone_payment"), ["ALLOW", "ALLOW"])
        for n, why in (("one_signer_bypass", "UNSIGNED"), ("two_approvers_of_one_subject", "UNSIGNED"), ("expired_bypass", "EXPIRED"),
                       ("never_bypassable_reason", "REASONS"), ("bypass_of_a_payment_not_held", "NOT_HELD"), ("bypass_of_an_allowed_payment", "NOT_HELD"),
                       ("bypass_for_another_request", "WRONG_REQUEST"), ("bypass_of_another_tenant", "SCOPE")):
            self.assertEqual([x[-1] for x in notes(n)], [why], n)
            self.assertEqual(outcomes(n), {"bypass_of_a_payment_not_held": ["HOLD"], "bypass_of_an_allowed_payment": ["ALLOW"]}.get(n, ["HOLD", "HOLD"]), n)


class AnswerBindingTests(unittest.TestCase):
    """The host binds an answer to the frame it sent: the leaves' grant id is its grant's, a bypass id is that of a signed
    bypass it sent for the payment, and an answer with no leaves for a batch with requests is refused."""

    def test_an_answer_the_host_cannot_bind_is_refused(self):
        spec, head = cases()["bypass_releases_the_held_payment"], fw.GENESIS
        with tempfile.TemporaryDirectory() as tmp:
            eng = fw.Engine(Path(tmp) / "idx")
            try:
                first = build(spec[0], 1, head)
                head = decide._answer(eng.send(first), first)[2]
                data = build(spec[1], 2, head)
                answer = eng.send(data)
            finally:
                eng.close()
        _, recs, _, _, _, pays, _ = decide._answer(answer, data)  # the engine's own answer is taken
        self.assertEqual([p.outcome for p in pays], ["ALLOW"])
        self.assertNotEqual(pays[0].bypass, NONE)
        r = decide._Reader(answer)
        r.take(87 + 20 * len(recs) + 128 + 16)
        grant_at = r.at
        r.take(64 + flatchain.AUTH)
        for _ in range(r.num(4)):
            r.blob(2)
        count_at = r.at
        self.assertEqual(r.num(4), 1)
        leaf_at = []
        for _ in range(1):
            leaf_at.append(r.at)
            r.take(6)
            if r.num(1):
                r.take(64)
            r.take(64)
        leaves_end = r.at
        flip = lambda at: answer[:at] + bytes([answer[at] ^ 1]) + answer[at + 1:]  # noqa: E731
        for name, bad in (
                ("another grant id", flip(grant_at)),
                ("an invented bypass id", flip(leaf_at[0] + 7)),
                ("no leaves for a batch with requests", answer[:count_at] + bytes(4) + answer[leaves_end:])):
            with self.subTest(name), self.assertRaises(decide.GateDecideError):
                decide._answer(bad, data)


class ClearedHoldReleaseTests(fx.Scratch):
    def test_a_cleared_hold_released_by_its_bypass_is_sealed_and_paid(self):
        """Lean's answer for the cleared hold resent with its bypass (ALLOW, the bypass id, no reasons) goes through the
        producer (build_batch and the Lean publish check) and the payer's Lean release, which pays it once."""
        with tempfile.TemporaryDirectory() as tmp_:
            y = run_case(cases()["held_payment_released_after_its_facts_clear"], Path(tmp_))[-1][1][-1]
        self.assertEqual((y.outcome, y.reasons, y.authority), ("ALLOW", (), "TRANSFER"))
        self.assertNotEqual(y.bypass, gate.ZERO_DIGEST)
        with self.scratch() as tmp:
            handle, held, cert = fx.custody(tmp)
            p = self.track(producer.ShardProducer(Path(tmp) / "shard.sqlite3", mark_path=Path(tmp) / "shard.mark", tenant_id=fx.TENANT,
                                                  shard_id=0, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(), key_cert=cert,
                                                  payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(Path(tmp) / "shard.counter"), floors=lambda: (0, 0, 0, bytes(64))))
            p.prepared = ans = decide.Answer((), fx.STATE, b"", None, None, fx.D[1], 0, 1, (y,), fx.D[4])
            _, signed, (token,) = p.commit(fx.PROGRAM, ans, fx.NOW)
            self.assertEqual((token.leaf.outcome, token.leaf.reason_codes, token.leaf.bypass), ("ALLOW", (), y.bypass))
            store = self.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", links={fx.TENANT: held},
                                                grants=((fx.TENANT, y.grant_id, (fx.D[4],), (fx.D[4],)),)))
            store.install_cert(cert)
            self.assertEqual(store.store_checkpoint(signed), "stored")
            store.send(LAPSED, transmit=lambda data: None)
            self.assertIsNone(store.release(LAPSED, gate.encode_token(token), now=fx.NOW))
            self.assertEqual(store.release(LAPSED, gate.encode_token(token), now=fx.NOW), "released")


class OldApprovalTests(unittest.TestCase):
    """Adding reasons 24-28 left the APPROVAL/v2 bytes as they were (holds and overrides stay u32 masks), so its tag is
    unchanged: an approval signed before reads, and is identified, exactly as it was.  The digests are those of the
    unsigned grant and bypass below, taken from the code before reasons 24-28."""

    GRANT = "35c40c8d00733535cdea88cde2d4fb9969319cd89b137a488cf54f6e08cfe04a9298e5ef776a8bec0816885e0deed3cd3fecf22b6189a5e498a601f54b3e2032"
    GRANT_SIGNED = "71647a1b6583c224041838d117bbdf1b47650ae7bd38f9e9dfd9ad1fc79baf9a900f1ebe3ef057af43d0b3541d4bb9f346f3bb073966a49685cd7ba677d06e32"
    BYPASS = "732544bbcaf5ee65d0e6369c9bae325a75b4625759bb8a5381dbc77f6d7a8070691829db785f8fa32b19f9b8243b76d0254546e5f7ad8602be63a2b3bd165815"
    BYPASS_SIGNED = "8cfec61214da53f26a5cf5a3c4d56a30facd3a4a5f37d6c6e54810b9e872979bcaeaea9b9da857082bfb2a1d51221e2876bed0aa8794cb2a3d2ece84c80ee89d"

    def test_old_approval_bytes_and_ids(self):
        grant = au.grant([(fx.PROGRAM, CLAIM | SDP, 2, BYPASSABLE)])
        byp = au.bypass(fx.PROGRAM, "pay-old", au.H(b"old-request"), BYPASSABLE)
        for doc, kind, ident, signed, pays in ((grant, 1, self.GRANT, self.GRANT_SIGNED, frozenset()),
                                               (byp, 2, self.BYPASS, self.BYPASS_SIGNED, {(fx.PROGRAM.encode(), b"pay-old")})):
            u = fx.unsigned(doc)
            self.assertEqual((len(u), au.H(u).hex(), au.H(b"RR/GATE/APPROVAL/v2/SIG\x00" + u).hex()),
                             ({1: 131, 2: 193}[kind], ident, signed))
            self.assertEqual(decide._approval(doc), (kind, bytes.fromhex(ident), pays))

    def test_engine_takes_the_old_grant_as_before(self):
        """The engine admits the old grant: each leaf names its id, and the held payment holds for MEMBER_NOT_ENROLLED."""
        with tempfile.TemporaryDirectory() as tmp:
            [(why, pays, notes)] = run_case(cases()["hold_grant"], Path(tmp))
        self.assertEqual((why, notes), (None, []))
        self.assertEqual({p.grant_id.hex() for p in pays}, {self.GRANT})
        self.assertEqual([(p.outcome, p.authority) for p in pays], [("ALLOW", "HOLD"), ("HOLD", "HOLD")])
        self.assertIn("MEMBER_NOT_ENROLLED", pays[1].reasons)


if __name__ == "__main__":
    unittest.main()
