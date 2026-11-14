"""The host side of the history index: the CHAIN/v1 codec (hex vectors the Lean side must match; the worker test below checks
the genesis and every step against the real worker), the producer signing the chain head, and the adapter driving the
resident engine with binary frames (test-only exes; synthetic, non-PHI)."""

import contextlib
from dataclasses import replace
import os
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_producer as producer
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_flat_worker as fw
from tests import test_gate_rules_vectors as rules
from tests import test_right_rail_gate_formats as fx

WORKER = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_engine.exe"
CRASH = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_rules_crashtest.exe"  # the one-shot runner that reads RR_FLAT_CRASH; tests only
# Lean must produce these (Flat.chainStart / encDelta / chainStep over SHA3-512); the host tests below check the worker's heads
# against this codec.
ASOF = 20270315
LEB = {0: "00", 127: "7f", 128: "8001", 300: "ac02"}
PIN = bytes(range(64))
AUTH = PIN + bytes(chain.AUTH - 64)  # an authority record: the pin, a zero ratchet and floor
ROOT = bytes(range(64, 128))  # a state root after a batch
GENESIS = ("f42585e614512837a44bf16f0ccf138ca1bbd6d72c932b8c2e60ea84efadfe6dd9b80eb2144830367a197458860f420214c5ca2a2cf608e58b1eabb363607db2")
FLAT_HOLDS = ({"HOLD flat_head"}, {"HOLD flat_not_next"}, {"HOLD flat_init"})  # a signed head or batch count the index does not hold (batch 1 on a held store is an init)
ROW = [2, 1001, 7001, 7001, 20270301, 99213, 1, 12500, 1000, 1000]  # flow tag, member, payee, rendering, date, proc, units, cents, id, pay
DELTA = "0102e907d936d936dd99d5098d870601d461e807e80700"  # one released row, no unresolved
STEP = ("b4225c0e7e31a1143f760919c9d8891ab30ba8a63ac2d55a25aafc5b4368077ba9401c45ac686ee436e8e831dd4812259dd0b77cb0c3ccf487909e584cb27aaa")
TWO = au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=2)  # the standing grant's entries at the next serial


def _bypass(req) -> bytes:
    """A signed bypass of ``req`` (another authority for the same request bytes)."""
    return au.bypass(fx.PROGRAM, req.payment_id, au.digest(gate.encode_decide_request(req)), 1)


def files(d: Path) -> dict[str, bytes]:
    return {f.name: f.read_bytes() for f in sorted(d.iterdir()) if f.name != "lock"}


def adds_row(tag: int, row: list[int]) -> bytes:
    """One RULES_ADDS row as the worker prints it: the set tag, then id, pay, flow, member, payee, rendering, date, proc, units, cents."""
    flow, member, payee, rend, date, proc, units, cents, i, pay = row
    return bytes([tag]) + b"".join(v.to_bytes(w, "big") for w, v in zip(chain._WIDTHS, (i, pay, flow, member, payee, rend, date, proc, units, cents)))


class ChainCodecTests(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual({n: chain.leb(n).hex() for n in LEB}, LEB)
        self.assertEqual(chain.genesis(0, ASOF, PIN).hex(), GENESIS)
        self.assertEqual(chain.enc_delta([ROW], []).hex(), DELTA)
        delta = chain.leb(chain.AUTH) + AUTH + bytes.fromhex(DELTA)
        self.assertEqual(chain.delta_of_adds(AUTH + ROOT + adds_row(1, ROW)), delta)
        step = chain.step_root(bytes.fromhex(GENESIS), chain.batch_digest(delta), ROOT)
        self.assertEqual(chain.step_adds(bytes.fromhex(GENESIS), AUTH + ROOT + adds_row(1, ROW)), step)
        self.assertEqual(chain.head_after(bytes.fromhex(GENESIS), PIN, [AUTH + ROOT + adds_row(1, ROW)]), step)
        self.assertEqual(chain.head_after(bytes.fromhex(GENESIS), PIN, []).hex(), GENESIS)

    def test_the_shard_the_date_and_the_pin_change_the_genesis(self):
        other = bytes(64)
        self.assertEqual(len({chain.genesis(0, ASOF, PIN), chain.genesis(1, ASOF, PIN), chain.genesis(0, ASOF + 1, PIN),
                              chain.genesis(0, ASOF, other)}), 4)

    def test_the_authority_record_changes_the_step(self):
        g0, rows = bytes.fromhex(GENESIS), ROOT + adds_row(1, ROW)
        for at in (0, 64, 200, chain.AUTH - 1):  # pin, ratchet, floor
            with self.subTest(at):
                moved = AUTH[:at] + bytes([AUTH[at] ^ 1]) + AUTH[at + 1:]
                self.assertNotEqual(chain.step_adds(g0, moved + rows), chain.step_adds(g0, AUTH + rows))

    def test_a_replay_refuses_another_pin_and_a_lowered_epoch_or_floor(self):
        g0, rows = bytes.fromhex(GENESIS), ROOT + adds_row(1, ROW)
        rec = lambda epoch, floor, pin=PIN: pin + epoch.to_bytes(4, "big") + bytes(chain.AUTH - 76) + floor.to_bytes(8, "big")  # noqa: E731
        self.assertIsNotNone(chain.head_after(g0, PIN, [rec(0, 0) + rows, rec(0, 0) + rows, rec(1, 5) + rows, rec(1, 5) + rows]))
        for name, batches in {"another pin": [rec(0, 0) + rows, rec(0, 0, bytes(64)) + rows], "epoch lowered": [rec(2, 0) + rows, rec(1, 0) + rows],
                              "floor lowered": [rec(0, 7) + rows, rec(0, 6) + rows]}.items():
            with self.subTest(name):
                self.assertIsNone(chain.head_after(g0, PIN, batches))

    def test_mutants_do_not_decode(self):
        one, two = adds_row(1, ROW), adds_row(2, [1, *ROW[1:8], 1001, 1001])
        rec = AUTH + ROOT
        self.assertEqual(chain.delta_of_adds(rec), chain.leb(chain.AUTH) + AUTH + chain.enc_delta([], []))
        for name, bad in {"trailing byte": one + b"\0", "short": one[:-1], "wrong tag 3": adds_row(3, ROW), "tag 0": adds_row(0, ROW),
                          "reordered sets": two + one, "flow 4": adds_row(1, [4, *ROW[1:]]), "flow 0": adds_row(1, [0, *ROW[1:]])}.items():
            with self.subTest(name):
                self.assertIsNone(chain.delta_of_adds(rec + bad))
                self.assertIsNone(chain.head_after(bytes(64), PIN, [rec + one, rec + bad]))
        for name, bad in {"no record": b"", "short record": rec[:-1], "rows, no record": one}.items():
            with self.subTest(name):
                self.assertIsNone(chain.delta_of_adds(bad))
        self.assertIsNotNone(chain.delta_of_adds(rec + one + two))

    def test_reordered_rows_and_batches_change_the_head(self):
        a, b = ROW, [1, *ROW[1:8], 1001, 1001]
        g0 = bytes.fromhex(GENESIS)
        step = lambda delta: chain.step_root(g0, chain.batch_digest(delta), ROOT)  # noqa: E731
        self.assertNotEqual(step(chain.enc_delta([a, b], [])), step(chain.enc_delta([b, a], [])))
        self.assertNotEqual(step(chain.enc_delta([a], [b])), step(chain.enc_delta([b], [a])))
        self.assertNotEqual(chain.head_after(g0, PIN, [AUTH + ROOT + adds_row(1, a), AUTH + ROOT + adds_row(1, b)]),
                            chain.head_after(g0, PIN, [AUTH + ROOT + adds_row(1, b), AUTH + ROOT + adds_row(1, a)]))

    def test_a_head_is_64_bytes(self):
        for bad in (bytes(63), bytes(65), b"", "x" * 64):
            with self.assertRaises(ValueError):
                chain.step_root(bad, bytes(64), bytes(64))


class FlatHostTests(fx.Scratch):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [str(x) for x in (rules.EXE, WORKER, CRASH) if not os.path.isfile(x)]
        if os.name == "nt" and missing:  # a missing pinned exe is a failure of the full suite, never a silent skip
            raise AssertionError(f"FLAT HOST NOT RUN: {missing} missing; run `lake build gate_engine gate_rules gate_rules_crashtest` in lean/")
        if os.name != "nt":
            raise unittest.SkipTest("the host runs the Windows exes")

    def worker(self) -> decider.RulesWorker:
        w = decider.RulesWorker(WORKER)
        self._workers.append(w)
        return w

    def setUp(self) -> None:
        super().setUp()
        self._workers, self.roots = [], []  # roots: the state root of each answer the real engine gave, in order
        real = decider.RulesWorker.run_frame

        def spy(w, directory, shard, data):
            out = real(w, directory, shard, data)
            why, _, _, root, _, _, _ = decider._answer(out, data)
            self.roots += [root] if why is None else []
            return out
        patch = mock.patch.object(decider.RulesWorker, "run_frame", spy)
        patch.start()
        self.addCleanup(patch.stop)

    def step(self, pre: bytes, ans) -> bytes:
        """The head after the batch `ans` decided last: the step over the signed head `pre`, the batch digest and the worker's state root."""
        return chain.step_adds(pre, ans.adds)

    @contextlib.contextmanager
    def scratch(self):
        """The scratch directory, with every worker closed first (a worker holds the index files open)."""
        with super().scratch() as tmp:
            try:
                yield tmp
            finally:
                for w in self._workers:
                    w.close()

    def cluster(self, tmp: str, name: str):
        (Path(tmp) / name).mkdir()
        c = self._c = g.Cluster(str(Path(tmp) / name), fx.custody(str(Path(tmp) / name)))
        return c, self.track(c.producer(0))

    def batch(self, c, prod, b: int, **kw):
        ans, leaves, status = g.decide_batch(c, prod, 0, {b: [b * 10, b * 10 + 1]}, **kw)
        return ans, leaves, status

    def commit(self, prod, ans, leaves) -> None:
        decider.commit(prod, fx.PROGRAM, ans, fx.NOW, self._c.tenant)

    def test_the_index_path_decides_as_the_lean_spec_on_random_batches_and_the_chain_is_signed(self):
        """Each batch's frame, rerun on the one-shot spec runner with the earlier batches' rows `load`ed (as test_flat_worker does),
        gives the same lines and added rows as the index path."""
        rng = random.Random(5)
        again, earlier, real_claim = random.Random(6), [], g.claim  # `again`: a second payment per later batch repeats lines of earlier batches
        copies: dict[int, tuple[int, bool]] = {}  # line id -> (earlier line id whose text it repeats, exactly or with other cents)

        def claim(i: int, dead: bool) -> str:
            if i not in copies:
                return real_claim(i, dead)
            text, exact = real_claim(copies[i][0], dead), copies[i][1]
            return text if exact else f"{text.rsplit(' ', 1)[0]} {int(text.rsplit(' ', 1)[1]) + 1}"

        def spec_lines(payments, bad):  # each request's lines as `line` directives: identifiers as Lean numbers (Rules.idNat)
            out = []
            for pay, ids in payments.items():
                r = g.request(pay, 0, ids, bad)
                q = g.nat(len(r.program_id).to_bytes(2, "big") + r.program_id.encode() + len(r.payment_id).to_bytes(2, "big") + r.payment_id.encode())
                for i in ids:
                    f = g.claim(i, False).split()
                    out.append(f"line {g.lid(i)}:{q} FFS_CLAIM {g.nat(r.member_key)} {g.nat(r.payee_ref.encode())} {g.nat(b'R' + f[2].encode())} "
                               f"{g.BAD_DATE if i in bad else f[3]} {g.nat(b'C' + f[4].encode())} {f[5]} {f[6]}")
            return out

        with self.scratch() as tmp, mock.patch.object(g, "claim", claim):
            new = self.cluster(tmp, "new")
            nw, flat = self.worker(), Path(tmp) / "new" / "idx"
            self.assertIsNone(new[1].flat_head())
            head, spec_adds, spec_digest = chain.genesis(0, g.ASOF, g.PIN), b"", ""
            for b in range(1, 6):
                payments = {10 * b + q: [100 * (10 * b + q) + t for t in range(rng.randrange(1, 4))] for q in range(rng.randrange(2, 5))}
                bad = {i for ids in payments.values() for i in ids if rng.randrange(5) == 0}
                if earlier:
                    payments[10 * b + 9] = extra = [100 * (10 * b + 9) + t for t in range(again.randrange(1, 3))]
                    copies.update({i: (again.choice(earlier), again.random() < 0.5) for i in extra})
                    bad |= {i for i in extra if again.randrange(5) == 0}
                earlier += [i for ids in payments.values() for i in ids]
                a_new, l_new, s_new = g.decide_batch(*new, 0, payments, bad=bad, worker=nw, flat=flat)
                self.assertTrue(a_new.digest and s_new, (b, a_new.lines))
                ctl = "# genesis" if b == 1 else f"load {g.ASOF} {spec_adds.hex() or '-'} {spec_digest}"
                text = [*g._HEAD, "case batch", ctl, *spec_lines(payments, bad), "commit SHOW", "end 0"]  # the spec holds the sets in memory: the full head
                (Path(tmp) / "spec.vectors").write_text("\n".join(text) + "\n", "utf-8")
                spec = subprocess.run([rules.EXE, str(Path(tmp) / "spec.vectors")], capture_output=True, text=True, timeout=600).stdout.splitlines()
                tag = lambda t: [x[len(t) + 1:] for x in spec if x.startswith(t + " ")]  # noqa: E731
                spec_row = bytes.fromhex("".join(x for x in tag("RULES_ADDS") if x))
                spec_status = {int(x.split()[1].split(":")[0]): " ".join(x.split()[10:12]) for x in spec if x.startswith("RULES_LINE")}
                self.assertEqual(({g.lid(i): v for i, v in s_new.items()}, a_new.adds[chain.ROOT:]), (spec_status, spec_row), f"batch {b}")
                spec_adds, spec_digest = spec_adds + spec_row, tag("RULES_DIGEST")[0]
                self.assertEqual(a_new.pre, head)  # the tokens' INPUT/v2 head: the signed head before the batch
                head = self.step(head, a_new)
                self.assertEqual(a_new.digest, head)  # the adapter recomputed the step before it took the worker's head
                self.commit(*new[1:], a_new, l_new)
                self.assertEqual(new[1].flat_head(), (head, b))  # the head the key signed in the checkpoint header
            # a restarted adapter and worker open the same index at the signed head
            nw.close()
            a, _, s = g.decide_batch(*new, 0, {60: [6000]}, worker=self.worker(), flat=flat)
            self.assertTrue(a.digest)

    def test_an_index_ahead_of_the_signed_head_is_kept_for_its_request_and_the_batch_decided_again(self):
        """Batch 2 is decided and its frame written, then the process dies before the seal (or the batch is simply never sealed).
        The next decide opens at the signed head and keeps that frame: another request is refused, the same request is decided
        again from the signed head to the same bytes, and the one after it chains from the seal."""
        for restart in ("same worker", "new worker"):
            with self.subTest(restart), self.scratch() as tmp:
                c, prod = self.cluster(tmp, "x")
                w, flat = self.worker(), Path(tmp) / "x" / "idx"
                a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
                self.commit(prod, a1, l1)
                a2, l2, _ = self.batch(c, prod, 2, worker=w, flat=flat)
                self.assertTrue(a2.digest)
                if restart != "same worker":
                    w.close()  # the process died with the index files ahead of the seal
                w3 = w if restart == "same worker" else self.worker()
                other, _, so = self.batch(c, prod, 3, worker=w3, flat=flat)
                self.assertEqual((other.digest, set(so.values())), (b"", {"HOLD flat_conflict"}))
                a3, l3, _ = self.batch(c, prod, 2, worker=w3, flat=flat)
                self.assertEqual((a3.recs, a3.adds, a3.digest), (a2.recs, a2.adds, a2.digest))
                self.assertEqual(a3.digest, self.step(a1.digest, a3))  # from the signed head
                self.commit(prod, a3, l3)
                self.assertEqual(prod.flat_head(), (a3.digest, 2))
                if restart == "new worker":
                    w3.close()  # one worker at a time holds the index
                a4, _, _ = self.batch(c, prod, 4, worker=w if restart == "same worker" else self.worker(), flat=flat)
                self.assertTrue(a4.digest)  # and the index opens at the new signed head

    def test_a_failed_open_decides_nothing(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "f")
            w, flat, calls = self.worker(), Path(tmp) / "f" / "idx", []
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            real = decider.RulesWorker.run_frame

            def flaky(self, directory, shard, data):  # the open fails once (say a scanner held a file), then would succeed
                calls.append(data)
                if len(calls) > 1:
                    return real(self, directory, shard, data)
                return b"RRDA" + struct.pack("<HBIQI", 1, decider.WORDS.index("IO"), shard, int.from_bytes(data[10:18], "little"), 0) + data[18:82]
            with mock.patch.object(decider.RulesWorker, "run_frame", flaky):
                a, l, s = self.batch(c, prod, 2, worker=w, flat=flat)
            self.assertEqual((a.digest, l, set(s.values()), len(calls)), (b"", [], {"HOLD flat_io"}, 1))
            again, l2, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            self.assertEqual(again.pre, a1.digest)
            self.commit(prod, again, l2)

    def test_a_relative_index_path_is_the_hosts_not_the_workers(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "r")
            w, here = self.worker(), os.getcwd()
            os.chdir(Path(tmp) / "r")
            try:
                a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=Path("idx"))
                self.commit(prod, a1, l1)
                a2, _, _ = self.batch(c, prod, 2, worker=w, flat=Path("idx"))
            finally:
                os.chdir(here)
            self.assertTrue(a2.digest)
            self.assertTrue(a2.flat.samefile(Path(tmp) / "r" / "idx"))

    def test_a_commit_after_another_decide_moved_the_index_is_refused(self):
        """Decide A, then B on the same shard: A's frame stays in the log, unsigned, and B is refused (another request on that
        head, HOLD RETRY): the store holds one decided batch past the signed head.  A can still be sealed, and B decides after."""
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "i")
            w, flat = self.worker(), Path(tmp) / "i" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            a, la, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            b, lb, sb = self.batch(c, prod, 3, worker=w, flat=flat)
            self.assertEqual((b.digest, lb, set(sb.values())), (b"", [], {"HOLD flat_conflict"}))
            self.assertRaisesRegex(decider.GateDecideError, "stale_answer", self.commit, prod, a, la)  # B's decide discarded A's prepared batch
            self.assertEqual(prod.flat_head(), (a1.digest, 1))
            a, la, _ = self.batch(c, prod, 2, worker=w, flat=flat)  # A sent again: decided afresh, the same bytes
            self.commit(prod, a, la)
            self.assertEqual(prod.flat_head(), (a.digest, 2))
            self.assertTrue(self.batch(c, prod, 3, worker=w, flat=flat)[0].digest)

    def test_tokens_are_leans_answers_and_a_caller_cannot_get_a_hold_signed_as_allowed(self):
        """The real worker HOLDs a payment with a line outside the member's enrollment; the only way to the signer is ``commit`` of the answer the
        producer holds from ``decide``, so an answer edited to ALLOW, or pointing Lean's answer at another request, seals
        nothing.  The sealed token carries Lean's outcome and reasons, the deciding worker's digest and INPUT/v2 over its
        request and the head before its batch."""
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "v")
            w, flat = self.worker(), Path(tmp) / "v" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.assertEqual(a1.pre, chain.genesis(0, g.ASOF, g.PIN))
            self.commit(prod, a1, l1)
            a2, l2, _ = self.batch(c, prod, 2, worker=w, flat=flat, bad=(20, 21))
            ((pay,),) = (a2.pays,)
            req, outcome, reasons = g.request(2, 0, [20, 21], (20, 21)), pay.outcome, pay.reasons
            self.assertEqual((pay.payment_id, pay.member_key, pay.payee_ref, pay.cents, pay.lines_root, outcome),
                             (req.payment_id, req.member_key, req.payee_ref, req.amount_cents, gate.lines_root(req.lines), "HOLD"))
            self.assertIn("MEMBER_NOT_ENROLLED", reasons)
            for name, forged in {"edited to ALLOW": a2._replace(pays=(pay._replace(outcome="ALLOW", reasons=()),)),
                                 "another request": a2._replace(pays=(pay._replace(payment_id="pay-0001"),)),
                                 "another engine": a2._replace(release=gate.sha3_512(b"other")),
                                 "edited adds": a2._replace(adds=a2.adds + b"x"),
                                 "edited head": a2._replace(pre=bytes(64)), "edited lines": a2._replace(lines=(*a2.lines, "x")),
                                 "edited authority": a2._replace(pays=(pay._replace(authority="OBSERVE" if pay.authority != "OBSERVE" else "TRANSFER"),)),
                                 "edited grant id": a2._replace(pays=(pay._replace(grant_id=bytes(64)),)),
                                 "edited bypass": a2._replace(pays=(pay._replace(bypass=b"\x01" * 64),))}.items():
                with self.subTest(name):
                    self.assertRaisesRegex(decider.GateDecideError, "stale_answer", decider.commit, prod, fx.PROGRAM,
                                           forged, fx.NOW, c.tenant)
            self.assertEqual(prod.flat_head(), (a1.digest, 1))  # nothing sealed
            checkpoint, _, tokens = decider.commit(prod, fx.PROGRAM, a2, fx.NOW, c.tenant)
            release = gate.sha3_512(g.ENGINE.read_bytes())
            self.assertEqual((checkpoint.state_digest, tokens[0].leaf.outcome, tokens[0].leaf.reason_codes,
                              tokens[0].leaf.rule_version, tokens[0].leaf.engine_release, tokens[0].leaf.input_commitment),
                             (a2.digest, "HOLD", reasons, release, release, fx.frame_inputs(a2.frame)[gate.encode_decide_request(req)]))

    def test_a_batch_with_a_request_the_grant_does_not_cover_seals_and_every_leaf_encodes(self):
        """The leaf of an uncovered request is HOLD (a ruled flow) or HUMAN_REVIEW (no rules) with SCOPE; the codec accepts it and
        the batch seals.  The covered request beside it is decided on its own, even with the same claim as the uncovered one."""
        from tests import test_gate_authority_frames as af
        clean, sdp = g.request(1, 0, [10, 11]), af.sdp_request(member=g.member(1002, 0))  # a member key that belongs to this shard
        for name, mask, requests, want in (  # the tokens come back in payment id order: pay-0001, pay-cyc, pay-sdp
                ("a flow with no rules", af.CLAIM, [clean, sdp], [("ALLOW", "-"), ("HUMAN_REVIEW", "SCOPE")]),
                ("a ruled flow", af.SDP, [clean, sdp], [("HOLD", "SCOPE"), ("HUMAN_REVIEW", "-")]),
                ("a ruled flow with the covered request's claim", af.CLAIM, [af.cycle_request(), clean], [("ALLOW", "-"), ("HOLD", "SCOPE")])):
            with self.subTest(name), self.scratch() as tmp:
                c, prod = self.cluster(tmp, "u")
                ans = decider.decide(g.HEAD, g.ASOF, prod, requests, Path(tmp) / "u" / "idx", self.worker(), au.grant([(fx.PROGRAM, mask, 3, 0)]), g.KEYS, c.tenant)
                _, _, tokens = decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
                self.assertEqual([(t.leaf.outcome, ",".join(t.leaf.reason_codes) or "-") for t in tokens], want)
                for t in tokens:
                    gate.encode_token_leaf(t.leaf)

    def test_a_good_answer_is_admitted_after_a_refused_forgery(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "f")
            w, flat = self.worker(), Path(tmp) / "f" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            a2, _, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            ((pay,),) = (a2.pays,)
            forged = a2._replace(pays=(pay._replace(grant_id=bytes(64)),))
            self.assertRaisesRegex(decider.GateDecideError, "stale_answer", decider.commit, prod, fx.PROGRAM, forged, fx.NOW, c.tenant)
            self.assertEqual(prod.flat_head(), (a1.digest, 1))
            checkpoint, _, tokens = decider.commit(prod, fx.PROGRAM, a2, fx.NOW, c.tenant)
            self.assertEqual((checkpoint.state_digest, prod.flat_head()), (a2.digest, (a2.digest, 2)))

    def test_a_batch_with_no_token_leaves_the_index_where_it_was(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "n")
            w, flat = self.worker(), Path(tmp) / "n" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            before = files(flat)
            a2, _, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            decided = files(flat)
            self.assertTrue(decided["log"].startswith(before["log"]) and len(decided["log"]) > len(before["log"]))  # the prepare appended a frame
            again, _, _ = self.batch(c, prod, 2, worker=w, flat=flat)  # nothing to seal: the open at the signed head puts the frame back
            self.assertEqual(again.digest, a2.digest)  # the same batch from the same head
            self.assertEqual(files(flat), decided)  # and writes the same files
            self.assertEqual(prod.flat_head(), (a1.digest, 1))

    def test_a_sealed_answer_is_spent(self):
        """Sealed once, an answer is never sealed again, whether its commit returned or raised after the seal was written."""
        for raises in (False, True):
            with self.subTest(raises=raises), self.scratch() as tmp:
                c, prod = self.cluster(tmp, f"sp{int(raises)}")
                w, flat = self.worker(), Path(tmp) / f"sp{int(raises)}" / "idx"
                a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
                real = type(prod).commit

                def seals_then_raises(*args, **kw):  # a store error in the producer's re-read
                    real(*args, **kw)
                    raise OSError("store unavailable after the seal")
                if raises:
                    with mock.patch.object(type(prod), "commit", seals_then_raises), self.assertRaises(OSError):
                        self.commit(prod, a1, l1)
                else:
                    self.commit(prod, a1, l1)
                after = files(flat)
                self.assertEqual(prod.flat_head(), (a1.digest, 1))  # the seal is durable
                self.assertRaisesRegex(decider.GateDecideError, "stale_answer", self.commit, prod, a1, l1)
                self.assertEqual((files(flat), prod.flat_head()), (after, (a1.digest, 1)))
                self.assertTrue(self.batch(c, prod, 2, worker=w, flat=flat)[0].digest)  # the next open applies the sealed batch

    def test_an_index_no_seal_covers_is_dropped_at_genesis(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "g")
            w, flat = self.worker(), Path(tmp) / "g" / "idx"
            first, _, _ = self.batch(c, prod, 1, worker=w, flat=flat)  # decided, never sealed
            again, _, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.assertEqual((again.digest, again.adds), (first.digest, first.adds))

    def test_a_stale_or_forged_signed_head_gives_hold_and_decides_nothing(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "x")
            w, flat = self.worker(), Path(tmp) / "x" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            a, l, s = self.batch(c, prod, 2, worker=w, flat=flat)
            self.assertTrue(a.digest)
            signed, count = prod.flat_head()
            # batch 2's stored frame is another request's: on its number the host HOLDs before the engine sees anything
            for forged in ((bytes(64), count), (b"\1" * 64, count), (signed, count + 1), (signed, count - 1)):
                with mock.patch.object(prod, "flat_head", return_value=forged):
                    a, l, s = self.batch(c, prod, 4, worker=w, flat=flat)
                self.assertEqual((a.digest, l), (b"", []), forged)
                if forged[1] == count:
                    self.assertEqual(set(s.values()), {"HOLD flat_conflict"}, forged)
                else:
                    self.assertIn(set(s.values()), FLAT_HOLDS, forged)
            a, l, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            self.commit(prod, a, l)  # no stored frame now: each forged head reaches the engine
            signed, count = prod.flat_head()
            for forged in ((bytes(64), count), (b"\1" * 64, count), (signed, count + 1), (signed, count - 1)):
                with mock.patch.object(prod, "flat_head", return_value=forged):
                    a, l, s = self.batch(c, prod, 4, worker=w, flat=flat)
                self.assertEqual((a.digest, l), (b"", []), forged)
                self.assertIn(set(s.values()), FLAT_HOLDS, forged)
            self.assertRaisesRegex(decider.GateDecideError, "hold_answer", decider.commit, prod, fx.PROGRAM, a, fx.NOW, c.tenant)

    def test_a_head_the_producer_signature_does_not_cover_gives_hold(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "y")
            w, flat = self.worker(), Path(tmp) / "y" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            prod._db.execute("DROP TRIGGER batches_fixed")  # an editor of the store file, not the owner
            prod._db.execute("UPDATE batches SET state_digest=?", (b"\2" * 64,))
            self.assertRaisesRegex(Exception, "head_unsigned", prod.flat_head)
            a, l, s = self.batch(c, prod, 2, worker=w, flat=flat)
            self.assertEqual((a.digest, l, set(s.values())), (b"", [], {"HOLD head_unsigned"}))

    def test_an_all_waiting_batch_and_a_missing_request_and_a_malformed_pay_row_are_typed_refusals(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "t")
            w, flat = self.worker(), Path(tmp) / "t" / "idx"
            a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
            self.commit(prod, a1, l1)
            tip = prod.tip()
            a2, l2, _ = self.batch(c, prod, 2, worker=w, flat=flat)
            # M6: no token to seal -> a typed refusal, nothing sealed, and the next batch decides and seals as usual
            self.assertRaisesRegex(decider.GateDecideError, "empty_batch", decider.commit, prod, fx.PROGRAM,
                                   a2._replace(pays=()), fx.NOW, c.tenant)
            self.assertEqual(prod.tip(), tip)
            a3, l3, _ = self.batch(c, prod, 2, worker=w, flat=flat)  # a2 again: the frame it left is kept for its own request
            self.commit(prod, a3, l3)
            self.assertNotEqual(prod.tip(), tip)
            # M7: a request that does not encode, or two for one payment, is refused before anything is decided
            good = g.request(9, 0, [90])
            for name, reqs in {"short member key": [replace(good, member_key=b"x")], "twice": [good, good],
                               "not a request": [None]}.items():
                with self.subTest(name):
                    self.assertRaisesRegex(decider.GateDecideError, "request_malformed", decider.decide, g.HEAD, g.ASOF, prod,
                                           reqs, flat, w, g.GRANT, g.KEYS, c.tenant)
            self.assertIsNone(prod.prepared)
            # an answer that is not whole is a refusal, never a stray exception
            real = decider.RulesWorker.run_frame
            for name, bend in {"short": lambda out: out[:-1], "long": lambda out: out + b"x"}.items():
                with self.subTest(name), mock.patch.object(decider.RulesWorker, "run_frame", lambda self, d, k, data, bend=bend: bend(real(self, d, k, data))):
                    self.assertRaisesRegex(decider.GateDecideError, "rules_refused", self.batch, c, prod, 4, worker=w, flat=flat)

    def test_a_grant_serial_admitted_on_one_shard_refuses_lower_serials_on_every_shard(self):
        """Serial 5 is admitted on shard 0; serial 3 is then refused on shard 1, which never saw serial 5 (its own stored floor
        is 0): the host sends the tenant's one grant floor in every frame.  Serial 5 still decides on shard 1."""
        with self.scratch() as tmp:
            c, prod0 = self.cluster(tmp, "f")
            prod1 = self.track(c.producer(1))
            five, three = (au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=s) for s in (5, 3))
            a = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", self.worker(), five, g.KEYS, c.tenant)
            self.assertTrue(a.digest and a.pays)
            self.assertEqual((c.tenant.raise_floors(0, 0)[0], int.from_bytes(a.adds[chain.AUTH - 8:chain.AUTH], "big")), (5, 5))
            w1 = self.worker()
            b = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", w1, three, g.KEYS, c.tenant)
            self.assertEqual((b.digest, b.pays, list(b.lines)), (b"", (), [f"{g.request(2, 1, [20]).payment_id} HOLD grant_superseded"]))
            b = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", w1, five, g.KEYS, c.tenant)
            self.assertTrue(b.digest and b.pays)
            self.assertEqual(c.tenant.raise_floors(0, 0)[0], 5)

    def test_a_key_set_rotated_on_one_shard_refuses_the_older_key_set_on_every_shard(self):
        """Shard 0 admits the rotated (epoch 1) key set; shard 1, whose own ratchet is still at the genesis, then refuses the
        genesis key set alone: the host sends the tenant's key-set epoch in every frame.  The rotated chain still decides there."""
        with self.scratch() as tmp:
            c, prod0 = self.cluster(tmp, "k")
            prod1 = self.track(c.producer(1))
            rotated = g.KEYS._replace(steps=(au.kstep(),))
            a = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", self.worker(), g.GRANT, rotated, c.tenant)
            self.assertTrue(a.digest and a.pays)
            self.assertEqual((c.tenant.raise_floors(0, 0)[1], int.from_bytes(a.adds[64:68], "big")), (1, 1))
            w1 = self.worker()
            b = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", w1, g.GRANT, g.KEYS, c.tenant)
            self.assertEqual((b.digest, b.pays, list(b.lines)), (b"", (), [f"{g.request(2, 1, [20]).payment_id} HOLD grant_stale_keyset"]))
            b = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", w1, g.GRANT, rotated, c.tenant)
            self.assertTrue(b.digest and b.pays)

    def test_a_floor_file_rolled_back_is_raised_from_every_shards_seal_and_a_deleted_one_is_refused(self):
        """Serial 7 is sealed on shard 0, then the tenant's floor file is put back to its provisioned copy.  Opening the
        tenant's authority over both shards raises it to 7 again, so serial 6 is refused on shard 1, which never saw 7.
        A deleted file refuses the decide (``tenant_floor``, naming the file)."""
        with self.scratch() as tmp:
            c, prod0 = self.cluster(tmp, "r")
            prod1, path = self.track(c.producer(1)), c.dir / "tenant.floor"
            zero = (c.tenant, path.read_bytes())[1]  # provisioned
            seven, six = (au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=s) for s in (7, 6))
            a = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", self.worker(), seven, g.KEYS, c.tenant)
            decider.commit(prod0, fx.PROGRAM, a, fx.NOW, c.tenant)
            path.write_bytes(zero)
            tenant = au.tenant(path, shards=[prod0, prod1])
            self.assertEqual(tenant.raise_floors(0, 0)[0], 7)
            b = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", self.worker(), six, g.KEYS, tenant)
            self.assertEqual((b.digest, list(b.lines)), (b"", [f"{g.request(2, 1, [20]).payment_id} HOLD grant_superseded"]))
            path.unlink()
            with self.assertRaises(decider.GateDecideError) as caught:
                decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", self.worker(), seven, g.KEYS, tenant)
            self.assertEqual(caught.exception.args, ("tenant_floor", str(path)))

    def test_a_commit_after_another_shard_raised_the_tenant_floors_is_refused_and_nothing_is_sealed(self):
        """Shard 0 decides under grant serial 5 (or the genesis key set); before it commits, shard 1 decides under serial 6
        (or the rotated key set).  Shard 0's commit is then ``grant_floor_risen``: its answer is discarded and nothing is
        sealed; shard 1 seals, and shard 0 decides again under the newer authority."""
        five, six = (au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=s) for s in (5, 6))
        rotated = g.KEYS._replace(steps=(au.kstep(),))
        for name, (old, new) in {"grant": ((five, g.KEYS), (six, g.KEYS)), "key set": ((g.GRANT, g.KEYS), (g.GRANT, rotated))}.items():
            with self.subTest(name), self.scratch() as tmp:
                c, prod0 = self.cluster(tmp, "s")
                prod1, w0 = self.track(c.producer(1)), self.worker()
                x = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", w0, *old, c.tenant)
                y = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", self.worker(), *new, c.tenant)
                self.assertTrue(x.pays and y.pays)
                self.assertRaisesRegex(decider.GateDecideError, "grant_floor_risen", decider.commit, prod0, fx.PROGRAM, x, fx.NOW, c.tenant)
                self.assertEqual((prod0.prepared, prod0.tip()), (None, None))
                self.assertRaisesRegex(decider.GateDecideError, "stale_answer", decider.commit, prod0, fx.PROGRAM, x, fx.NOW, c.tenant)
                decider.commit(prod1, fx.PROGRAM, y, fx.NOW, c.tenant)
                x = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", w0, *new, c.tenant)
                decider.commit(prod0, fx.PROGRAM, x, fx.NOW, c.tenant)
                self.assertEqual(prod0.flat_head()[1], 1)

    def test_a_later_batch_refused_for_a_risen_floor_does_not_block_the_shard(self):
        """The same as above on batch 2: the engine's log holds the refused batch's frame, unsigned.  The next decide under the
        newer authority is a different request, and decides (the old frame is cut), not ``flat_conflict``."""
        five, six = (au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=s) for s in (5, 6))
        with self.scratch() as tmp:
            c, prod0 = self.cluster(tmp, "w")
            prod1, w0 = self.track(c.producer(1)), self.worker()
            a = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", w0, five, g.KEYS, c.tenant)
            decider.commit(prod0, fx.PROGRAM, a, fx.NOW, c.tenant)
            x = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(3, 0, [30])], c.dir / "idx0", w0, five, g.KEYS, c.tenant)
            y = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", self.worker(), six, g.KEYS, c.tenant)
            self.assertTrue(x.pays and y.pays)
            self.assertRaisesRegex(decider.GateDecideError, "grant_floor_risen", decider.commit, prod0, fx.PROGRAM, x, fx.NOW, c.tenant)
            decider.commit(prod1, fx.PROGRAM, y, fx.NOW, c.tenant)
            x = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(3, 0, [30])], c.dir / "idx0", w0, six, g.KEYS, c.tenant)
            self.assertTrue(x.digest and x.pays, list(x.lines))
            decider.commit(prod0, fx.PROGRAM, x, fx.NOW, c.tenant)
            self.assertEqual(prod0.flat_head()[1], 2)

    def test_a_floor_file_rolled_back_while_an_answer_is_held_cannot_let_it_commit(self):
        """Shard 0 holds an answer decided under grant serial 5; shard 1 seals serial 6, and the floor file is then put back to
        its provisioned copy.  The commit reads shard 1's sealed record as well as the file, so it is ``grant_floor_risen``."""
        five, six = (au.grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)], serial=s) for s in (5, 6))
        with self.scratch() as tmp:
            c, prod0 = self.cluster(tmp, "l")
            prod1, path = self.track(c.producer(1)), c.dir / "tenant.floor"
            tenant = au.tenant(path, [prod0, prod1])
            zero = path.read_bytes()
            x = decider.decide(g.HEAD, g.ASOF, prod0, [g.request(1, 0, [10])], c.dir / "idx0", self.worker(), five, g.KEYS, tenant)
            y = decider.decide(g.HEAD, g.ASOF, prod1, [g.request(2, 1, [20])], c.dir / "idx1", self.worker(), six, g.KEYS, tenant)
            decider.commit(prod1, fx.PROGRAM, y, fx.NOW, tenant)
            path.write_bytes(zero)
            self.assertRaisesRegex(decider.GateDecideError, "grant_floor_risen", decider.commit, prod0, fx.PROGRAM, x, fx.NOW, tenant)
            self.assertEqual((prod0.prepared, prod0.tip(), tenant.raise_floors(0, 0)), (None, None, (6, 0)))

    def test_a_shard_begun_under_another_key_set_pin_cannot_continue_under_the_tenant_pin(self):
        """A shard is begun, and a batch sealed, under a pin other than the tenant's deployment pin (a key set the host made).
        Once the host decides under the tenant's pin, the worker refuses to open the index (its authority record names the
        other pin): every row HOLDs and nothing can be sealed, so nothing is published.  A worker told the other pin at the
        open decides, but its authority record names that pin and its answer commits to the frame it was told, so the host
        refuses it as ``rules_refused``.  A first batch on an index begun under another pin
        is refused as a wrong head (``flat_head``): its genesis head names the tenant's pin."""
        body = au.keyset_body(nb=au.NB + 1)  # another genesis key set (a valid later start date), signed by the same roster
        keys = decider.Keys(au.keyset_doc(body))
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "p")
            w, flat = self.worker(), c.dir / "idx0"
            other = au.tenant(c.dir / "other.floor", [prod], pin=au.H(body))
            a1 = decider.decide(g.HEAD, g.ASOF, prod, [g.request(1, 0, [10])], flat, w, g.GRANT, keys, other)
            self.assertTrue(a1.digest and a1.pays)
            self.assertEqual((a1.pre, a1.adds[:64]), (chain.genesis(0, g.ASOF, au.H(body)), au.H(body)))
            self.commit(prod, a1, None)
            tip = prod.tip()
            a2 = decider.decide(g.HEAD, g.ASOF, prod, [g.request(2, 0, [20])], flat, w, g.GRANT, keys, c.tenant)
            self.assertEqual((a2.digest, a2.pays, list(a2.lines)), (b"", (), [f"{g.request(2, 0, [20]).payment_id} HOLD flat_pin"]))
            self.assertRaisesRegex(decider.GateDecideError, "hold_answer", decider.commit, prod, fx.PROGRAM, a2, fx.NOW, c.tenant)
            lie = decider.RulesWorker.run_frame

            told = []

            def other_open(self, directory, shard, data, lie=lie):  # the worker is told the index's own pin, not the tenant's
                out = lie(self, directory, shard, fw.repin(data, au.H(body)))
                told.append(out)
                return out[:23] + data[18:82] + out[87:]  # the host's digest is put back in the echo
            with mock.patch.object(decider.RulesWorker, "run_frame", other_open):
                with self.assertRaisesRegex(decider.GateDecideError, "rules_refused"):  # its leaves commit to the frame it decided, not the one sent
                    decider.decide(g.HEAD, g.ASOF, prod, [g.request(2, 0, [20])], flat, w, g.GRANT, keys, c.tenant)
            count = int.from_bytes(told[0][19:23], "little")
            self.assertEqual(told[0][87 + 16 * count + 208:][:64], au.H(body))  # the cause: its authority record names the other pin
            self.assertEqual(prod.tip(), tip)
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "q")
            w, flat = self.worker(), c.dir / "idx0"
            lie = decider.RulesWorker.run_frame

            def other_init(self, directory, shard, data, lie=lie):  # the worker is handed another pin than the one the host's genesis names
                out = lie(self, directory, shard, fw.repin(data, au.H(body)))
                return out[:23] + data[18:82] + out[87:]
            with mock.patch.object(decider.RulesWorker, "run_frame", other_init):
                a = decider.decide(g.HEAD, g.ASOF, prod, [g.request(1, 0, [10])], flat, w, g.GRANT, keys, c.tenant)
            # the frame's genesis head names the tenant's pin while its pin is the other: the engine refuses it as a wrong head
            self.assertNotEqual(chain.genesis(0, g.ASOF, g.PIN), chain.genesis(0, g.ASOF, au.H(body)))
            self.assertEqual((a.digest, list(a.lines)), (b"", [f"{g.request(1, 0, [10]).payment_id} HOLD flat_head"]))
            self.assertIsNone(prod.tip())

    def _decide(self, c, prod, requests, ids, w, flat):
        return decider.decide(g.HEAD, g.ASOF, prod, requests, flat, w, g.GRANT, g.KEYS, c.tenant)

    def test_the_input_commits_to_grant_release_today_and_facts_and_the_record_is_the_frame(self):
        """Lean computes INPUT/v6 over the frame: a changed grant, release, today or facts byte changes it, it equals the format
        written out again in Python, and the sealed batch's record is the exact frame bytes."""
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "v")
            w, flat = self.worker(), Path(tmp) / "v" / "idx"
            req = g.request(1, 0, [10, 11])
            body = gate.encode_decide_request(req)

            def decide(head=None, grant=g.GRANT, release=None, at=flat):  # each other frame on its own index: a stored one holds its number
                if release:
                    w.launched_release = lambda: release
                try:
                    return decider.decide(g.feeds_of(head or g._HEAD), g.ASOF, prod, [req], at, w, grant, g.KEYS, c.tenant)
                finally:
                    w.__dict__.pop("launched_release", None)

            def flip(value: bytes) -> bytes:
                return bytes([value[0] ^ 1]) + value[1:]

            ans = decide()
            self.assertEqual(ans.pays[0].input, fx.frame_inputs(ans.frame)[body])
            kinds = {r.split()[1]: i for i, r in enumerate(g._HEAD) if r.startswith("snap ")}
            head = lambda i, row: [*g._HEAD[:i], row, *g._HEAD[i + 1:]]
            today = next(i for i, r in enumerate(g._HEAD) if r.startswith("today "))
            dmf = g._HEAD[kinds["dmf"]].split()
            changed = {  # the serial-2 grant raises the tenant's floor, so it goes last
                "release": decide(release=flip(gate.sha3_512(g.ENGINE.read_bytes())), at=flat.with_name("release")),
                "today": decide(head(today, f"today {int(g._HEAD[today].split()[1]) + 1}"), at=flat.with_name("today")),
                "facts": decide(head(kinds["dmf"], " ".join([*dmf[:4], flip(bytes.fromhex(dmf[4])).hex()])), at=flat.with_name("facts")),
                "grant id": decide(grant=TWO, at=flat.with_name("grant")),
            }
            for name, other in changed.items():
                with self.subTest(name):
                    self.assertNotEqual(other.pays[0].input, ans.pays[0].input)
            # a frame with no release is refused as a frame, never decided; one with no grant is a visible hold of the batch
            # (a new index directory each: the frame's own already holds a batch)
            for n, (grant, release, said) in enumerate(((b"", ans.release, "grant_missing"), (g.GRANT, b"", "flat_record"))):
                with self.subTest(said):
                    data = decider.request_frame(g.HEAD, 0, 1, g.ASOF, chain.genesis(0, g.ASOF, g.PIN), g.PIN, (0, 0), g.KEYS, grant, release, (), [body])
                    fresh = str(Path(tmp) / "v" / f"cut{n}").replace("\\", "/")
                    self.assertEqual(decider._answer(w.run_frame(fresh, 0, data), data)[0], said)
            prod.prepared = None
            first, ans = ans, decide(grant=TWO)  # the serial-1 grant is now below the tenant's floor; its stored frame is voided
            self.assertRaisesRegex(decider.GateDecideError, "stale_answer", decider.commit, prod, fx.PROGRAM, first, fx.NOW, c.tenant)
            decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
            self.assertEqual(prod.record(1), ans.frame)
            with self.assertRaisesRegex(producer.GateProducerError, "no_record"):
                prod.record(2)

    def test_a_resend_under_other_authority_never_replaces_a_stored_frame_that_can_still_seal(self):
        """Batch 1 is sealed; batch 2 is decided under grant serial 1 and not committed, so the engine's log holds its frame
        unsigned.  The same requests sent again with a bypass, or under grant serial 2 while the floors have not passed serial 1,
        are the stored request under other authority: without ``seal`` they HOLD ``flat_conflict`` and the stored file keeps its
        bytes; with ``seal`` the stored frame is sealed as batch 2 under its own grant, and the resend is decided on batch 3,
        where no line batch 2 allowed is allowed again."""
        with self.scratch() as tmp:
            c, prod, req, send, first, pend = self._stored_second(tmp)
            stored = pend.read_bytes()
            for name, kw in (("bypass", {"bypasses": (_bypass(req),)}), ("grant", {"grant": TWO})):
                with self.subTest(name):
                    held = send(**kw)
                    self.assertEqual((held.digest, held.lines, pend.read_bytes()), (b"", (f"{req.payment_id} HOLD flat_conflict",), stored))
                    self.assertRaisesRegex(decider.GateDecideError, "stale_answer", decider.commit, prod, fx.PROGRAM, first, fx.NOW, c.tenant)
            later = send(grant=TWO, seal=(fx.PROGRAM, fx.NOW))
            self.assertEqual((prod.flat_head(), prod.record(2)), ((first.digest, 2), first.frame))
            self.assertEqual((later.batches, [r.outcome for r in later.recs if r.outcome == "ALLOW"]), (3, []))
            self.assertTrue(later.recs)

    def test_a_voided_stored_frame_whose_file_will_not_go_is_a_machine_fault_not_decided_again(self):
        """The floors pass batch 2's stored frame, so its exact resend voids it; when its file will not go, the decide is
        ``MachineFault`` ``pending_not_removed`` after one send to the engine, the file keeps its bytes, and the next call
        drops it and decides afresh."""
        with self.scratch() as tmp:
            c, prod, req, send, first, pend = self._stored_second(tmp)
            stored, sent, real = pend.read_bytes(), [], decider.RulesWorker.run_frame
            c.tenant.raise_floors(2, 0)

            def counted(self_, *args):
                sent.append(args)
                return real(self_, *args)
            with mock.patch.object(decider.RulesWorker, "run_frame", counted), mock.patch.object(decider, "_drop", lambda path: None), \
                    self.assertRaises(decider.MachineFault) as caught:
                send()
            self.assertEqual((caught.exception.args, len(sent), pend.read_bytes()), (("pending_not_removed", str(pend)), 1, stored))
            again = send(grant=TWO)
            decider.commit(prod, fx.PROGRAM, again, fx.NOW, c.tenant)
            self.assertEqual(prod.flat_head(), (again.digest, 2))

    def test_a_timeout_on_a_stored_frame_holds_and_keeps_its_file(self):
        """Batch 2's stored frame, decided again for a resend of its request with a bypass, runs past its deadline on every
        launch: the request HOLDs ``timeout`` and the stored file keeps its bytes, never overwritten by the resend's frame."""
        with self.scratch() as tmp:
            c, prod, req, send, first, pend = self._stored_second(tmp)
            stored = pend.read_bytes()

            def stalled(self_, *args):
                raise decider.WorkerDied("rules_refused") from RuntimeError("worker_timeout")
            with mock.patch.object(decider.RulesWorker, "run_frame", stalled), self.assertLogs(decider.LOG, "WARNING"):
                held = send(bypasses=(_bypass(req),))
            self.assertEqual((held.digest, held.lines, pend.read_bytes()), (b"", (f"{req.payment_id} HOLD timeout",), stored))

    def _stored_second(self, tmp):
        """Batch 1 sealed, then batch 2 (one request) decided under grant serial 1 and not committed: its frame is stored and
        in the engine's log, unsigned.  -> (cluster, producer, request, send, batch 2's answer, the stored file)."""
        c, prod = self.cluster(tmp, "o")
        w, flat, req = self.worker(), Path(tmp) / "o" / "idx", g.request(2, 0, [20, 21])
        a1, l1, _ = self.batch(c, prod, 1, worker=w, flat=flat)
        self.commit(prod, a1, l1)

        def send(grant=g.GRANT, **kw):
            return decider.decide(g.HEAD, g.ASOF, prod, [req], flat, w, grant, g.KEYS, c.tenant, **kw)
        first = send()
        self.assertTrue(first.digest and first.pays)
        return c, prod, req, send, first, flat.with_name(f"{flat.name}.pending.2")

    def test_a_request_is_decided_and_signed_as_it_is_not_as_the_old_lines_were(self):
        """A foreign amount, member or payee in the request reaches the leaf and the decision from the request: the fields come
        from Lean's ``RULES_PAY`` line, which read the request's own bytes (the real worker, no stub)."""
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "f")
            w, flat = self.worker(), Path(tmp) / "f" / "idx"
            old = g.request(1, 0, [10, 11])
            line = lambda i, key, payee, cents: gate.encode_line("FFS_CLAIM", f"L{i}", key, payee, "R7001", 20270305, "C99213", 1, cents)
            forged = {
                "amount": replace(old, amount_cents=old.amount_cents + 5000,
                                  lines=(line(10, old.member_key, old.payee_ref, 12510 + 5000), line(11, old.member_key, old.payee_ref, 12511))),
                "member": replace(old, member_key=g.member(9001, 0), lines=tuple(line(i, g.member(9001, 0), old.payee_ref, 12500 + i) for i in (10, 11))),
                "payee": replace(old, payee_ref="P9999", lines=tuple(line(i, old.member_key, "P9999", 12500 + i) for i in (10, 11))),
            }
            for name, req in forged.items():
                with self.subTest(name):  # each on its own index: a stored frame holds its number for its own request
                    ans = self._decide(c, prod, [req], [10, 11], w, flat.with_name(name))
                    (pay,) = ans.pays
                    self.assertEqual((pay.payment_id, pay.member_key, pay.payee_ref, pay.cents, pay.lines_root),
                                     (req.payment_id, req.member_key, req.payee_ref, req.amount_cents, gate.lines_root(req.lines)))
                    self.assertEqual(pay.input, fx.frame_inputs(ans.frame)[gate.encode_decide_request(req)])
                    self.assertEqual(pay.outcome == "HOLD", name == "member")  # a dead member in the request, not in any old line
                    prod.prepared = None

    def test_a_request_of_another_tenant_is_refused_and_not_retried(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "w")
            w, flat = self.worker(), Path(tmp) / "w" / "idx"
            before, other = w.gen, replace(g.request(1, 0, [10]), tenant_id=fx.OTHER)
            with mock.patch.object(decider.LOG, "warning") as warned:
                self.assertRaisesRegex(decider.GateDecideError, "foreign_tenant", self._decide, c, prod, [other], [10], w, flat)
                warned.assert_not_called()
            self.assertEqual((prod.prepared, w.gen), (None, before))
            # the leaf carries no tenant: the token's fields are the request's, and a leaf whose input is not the one the
            # host computes from the request it sent is refused after the decision, whatever else the answer says
            real = decider.RulesWorker.run_frame

            def lie(self, directory, shard, data):
                out = real(self, directory, shard, data)
                (inp,) = fx.frame_inputs(data).values()
                assert out.count(inp) == 1
                return out.replace(inp, bytes([inp[0] ^ 1]) + inp[1:])
            with mock.patch.object(decider.RulesWorker, "run_frame", lie):
                self.assertRaisesRegex(decider.GateDecideError, "rules_refused", self._decide, c, prod, [g.request(1, 0, [10])], [10], w, flat)
            self.assertIsNone(prod.prepared)
            ans = self._decide(c, prod, [g.request(1, 0, [10])], [10], w, flat)
            self.assertEqual([p.tenant for p in ans.pays], [fx.TENANT])

    def test_nothing_in_a_returned_answer_can_be_edited_in_place(self):
        with self.scratch() as tmp:
            c, prod = self.cluster(tmp, "m")
            a, leaves, _ = self.batch(c, prod, 1, worker=self.worker(), flat=Path(tmp) / "m" / "idx")
            for field in ("lines", "pays"):
                self.assertIsInstance(getattr(a, field), tuple, field)
            for field in ("lines", "pays"):
                with self.assertRaises(AttributeError):
                    getattr(a, field).append(99)
            self.assertIs(prod.prepared, a)
            _, _, tokens = decider.commit(prod, fx.PROGRAM, a, fx.NOW, c.tenant)
            self.assertEqual(len(tokens), len(a.pays))

    def test_an_answer_whose_head_root_or_rows_do_not_chain_gives_hold(self):
        """The adapter recomputes the head from the answer's state root and the digest of its added rows, and holds
        chain_mismatch on any difference."""
        for what in ("head", "root", "adds"):
            with self.subTest(what), self.scratch() as tmp:
                c, prod = self.cluster(tmp, "z")
                w, flat = self.worker(), Path(tmp) / "z" / "idx"
                real = decider.RulesWorker.run_frame

                def lie(self, directory, shard, data):
                    out = bytearray(real(self, directory, shard, data))
                    at = 87 + 16 * int.from_bytes(out[19:23], "little")  # the head, then the root, after the records
                    out[len(out) - 1 if what == "adds" else at + 64 * (what == "root")] ^= 1
                    return bytes(out)
                with mock.patch.object(decider.RulesWorker, "run_frame", lie):
                    a, l, s = self.batch(c, prod, 1, worker=w, flat=flat)
                self.assertEqual((a.digest, l, set(s.values())), (b"", [], {"HOLD chain_mismatch"}))

    def host(self, c):
        """A new host over the same files: the old shard producer closed, a new one opened."""
        cluster = c[0]
        self.close(*c[1:])
        return self.track(cluster.producer(0))

    @staticmethod
    def close(*stores) -> None:
        for store in stores:
            store.close()

    def sealed_twice(self, c) -> list:
        allows = [x for v in g.sealed_allows(c, 0).values() for x in v]
        return [x for x in allows if allows.count(x) > 1]

    @staticmethod
    def crashing(point: str):
        """A stand-in worker: the crash-test program killed at `point`.  The contained launcher gives a program no environment,
        so the crash variable goes through a plain subprocess."""
        class Crashing:
            lost = 0

            def check(self) -> None:
                pass

            def run_frame(self, directory: str, shard: int, data: bytes) -> bytes:
                done = subprocess.run([str(CRASH), directory, str(shard)], input=struct.pack(">I", len(data) + 1) + b"\x04" + data,
                                      env={**os.environ, "RR_FLAT_CRASH": point}, capture_output=True, timeout=600)
                return done.stdout[4:]  # empty when the program died before it answered

            def launched_release(self) -> bytes:
                return gate.sha3_512(WORKER.read_bytes())  # the release the host names: a resend is the same bytes

            def close(self) -> None:
                pass
        return Crashing()

    def test_a_kill_before_the_seal_leaves_exactly_the_state_before_the_batch(self):
        """The one-shot runner dies at each write step of the prepare, or just after it; the batch is unsealed.  A new host and
        worker open at the signed head: the record is the one before the batch and its chunks are untouched, and the same
        requests get the same answers, once."""
        for point in (*fw.POINTS, "decided"):
            with self.subTest(point), self.scratch() as tmp:
                ref, c = self.cluster(tmp, "ref"), self.cluster(tmp, "x")
                rflat, flat, w = Path(tmp) / "ref" / "idx", Path(tmp) / "x" / "idx", self.worker()
                for who, f in ((ref, rflat), (c, flat)):
                    a1, l1, _ = self.batch(*who, 1, worker=w, flat=f)
                    self.commit(*who[1:], a1, l1)
                a2, l2, _ = self.batch(*ref, 2, worker=w, flat=rflat)
                want = (a2.recs, a2.adds, a2.digest)
                self.commit(*ref[1:], a2, l2)
                w.close()
                before = files(flat)
                if point == "decided":  # the prepare finished and the process died before the seal
                    self.batch(*c, 2, worker=self.worker(), flat=flat)
                    self.assertGreater(len(files(flat)["log"]), len(before["log"]))  # the log is one frame ahead of the signed head
                    self._workers[-1].close()
                else:
                    self.assertRaisesRegex(decider.GateDecideError, "rules_refused", self.batch, *c, 2, flat=flat, worker=self.crashing(point))
                prod = self.host(c)
                a, l, _ = self.batch(c[0], prod, 2, worker=self.worker(), flat=flat)  # the open at the signed head cuts a torn frame and keeps a whole one for this request
                self.assertEqual((a.recs, a.adds, a.digest), want)
                self.commit(prod, a, l)
                head = prod.flat_head()
                self.close(prod, *ref[1:])
                self.assertEqual(files(flat), files(rflat))  # the resent batch leaves the files an uninterrupted run leaves
                self.assertEqual((head, self.sealed_twice(c[0])), ((a.digest, 2), []))
                self.assertEqual(list(g.sealed_allows(c[0], 0).values()), list(g.sealed_allows(ref[0], 0).values()))

    def test_a_worker_killed_mid_write_is_relaunched_and_the_same_decide_resends_to_the_real_engine(self):
        """The first send runs the crash-test program, which dies with the batch's chunk on disk and no record; the host sees a
        dead worker.  The same decide relaunches the real engine, whose open puts the batch back, and sends the same frame: the
        answer, the signed head and the sealed allows equal a run that was never killed."""
        with self.scratch() as tmp:
            ref, c = self.cluster(tmp, "ref"), self.cluster(tmp, "x")
            rflat, flat, w = Path(tmp) / "ref" / "idx", Path(tmp) / "x" / "idx", self.worker()
            for who, f in ((ref, rflat), (c, flat)):
                a1, l1, _ = self.batch(*who, 1, worker=w, flat=f)
                self.commit(*who[1:], a1, l1)
            a2, l2, _ = self.batch(*ref, 2, worker=w, flat=rflat)
            want = (a2.recs, a2.adds, a2.digest)
            self.commit(*ref[1:], a2, l2)
            w.close()
            before = files(flat)
            real, crash, seen = decider.RulesWorker.run_frame, self.crashing("frame-torn").run_frame, []

            def killed_once(self_, directory, shard, data):
                seen.append(data)
                if len(seen) > 1:
                    return real(self_, directory, shard, data)
                crash(directory, shard, data)  # the program dies with the frame's body written, the trailer not
                seen.append(files(flat))
                self_.lost += 1
                raise decider.WorkerDied("rules_refused")
            with mock.patch.object(decider.RulesWorker, "run_frame", killed_once), self.assertLogs(decider.LOG, "WARNING"):
                a, l, _ = self.batch(*c, 2, worker=w, flat=flat)
            self.assertGreater(len(seen[1]["log"]), len(before["log"]))  # the torn batch's frame was on disk when the worker died
            self.assertEqual((seen[0] == seen[2], len(seen), a.attempts), (True, 3, 2))  # the same frame, to the real engine
            self.assertEqual((a.recs, a.adds, a.digest), want)
            self.commit(*c[1:], a, l)
            head = c[1].flat_head()
            self.close(*c[1:], *ref[1:])
            self.assertEqual((head, self.sealed_twice(c[0])), ((a.digest, 2), []))
            self.assertEqual(list(g.sealed_allows(c[0], 0).values()), list(g.sealed_allows(ref[0], 0).values()))

    def test_a_kill_after_the_seal_keeps_the_batch(self):
        """The head is signed, then the next batch's write is killed at a step (or not at all): the open at the signed head
        keeps the sealed batch, whatever the kill left beside it (a whole unsigned frame stays in the log).  The sealed requests, sent again, are an exact retry:
        given batch 2's signed checkpoint and tokens, byte for byte, and not decided a second time; the next batch is decided as with no kill."""
        want = None
        for point in ("", *fw.POINTS):
            with self.subTest(point or "no kill"), self.scratch() as tmp:
                c = self.cluster(tmp, "s")
                flat, w = Path(tmp) / "s" / "idx", self.worker()
                a1, l1, _ = self.batch(*c, 1, worker=w, flat=flat)
                self.commit(*c[1:], a1, l1)
                a2, l2, _ = self.batch(*c, 2, worker=w, flat=flat)
                _, signed2, tokens2 = decider.commit(c[1], fx.PROGRAM, a2, fx.NOW, c[0].tenant)
                w.close()
                self.assertEqual(c[1].flat_head(), (a2.digest, 2))
                prod = self.host(c)
                if point:  # batch 3's write dies at the step
                    self.assertRaisesRegex(decider.GateDecideError, "rules_refused", self.batch, c[0], prod, 3, flat=flat, worker=self.crashing(point))
                w = self.worker()
                a3, l3, _ = self.batch(c[0], prod, 3, worker=w, flat=flat)  # the killed request again: decided afresh
                want = want or (a3.recs, a3.adds, a3.digest)
                self.assertEqual((a3.recs, a3.adds, a3.digest), want)
                self.commit(prod, a3, l3)
                again, _, status = self.batch(c[0], prod, 2, worker=w, flat=flat)  # the sealed requests, sent again
                self.assertEqual((again.digest, again.sealed, status), (b"", (signed2, tuple(map(gate.encode_token, tokens2))), {}))
                head = prod.flat_head()
                self.close(prod)
                self.assertEqual((head, self.sealed_twice(c[0])), ((a3.digest, 3), []))

if __name__ == "__main__":
    unittest.main()
