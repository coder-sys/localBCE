"""``decide`` against a fake worker: the program pin, relaunch after a dead worker, and the sealed-quarantine refusals.  Synthetic; no exe."""

from __future__ import annotations

import contextlib
import hashlib
import msvcrt
import itertools
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from tests._test_only_counter import TestOnlyCounter
from app import minimal_clearance_verifier_process as process
from app import right_rail_deployment_slots as slots
from app import right_rail_gate_decide as decide
from app import right_rail_gate_chain as flatchain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_producer as producer
from tests import _gate_authority as au
from tests import test_right_rail_gate_formats as fx
from tests import test_ruleset_admission as ra
from tests import test_ruleset_v1_codec as rs


def _le(n: int, w: int) -> bytes:
    return n.to_bytes(w, "little")


def answer(frame: bytes, outcomes: list[int], leaves: list[bytes] | None = None, hold: bytes = bytes(16), floor: int = 0,
           epoch: int = 0, pin: bytes | None = None, rsv: int = 0, rs: bytes = flatchain.ZERO) -> bytes:
    """The binary answer (conformance/FRAME_V1.md section 4) to ``frame``: a record per outcome, the one-step head the adapter
    recomputes over a stand-in state root, the id of the frame's grant, the authority record after the batch (the tenant's
    key-set pin unless ``pin``, this grant floor, key-set epoch and rule set) and these leaves (default: one ALLOW leaf per request)."""
    root = bytes(64)
    auth = TenantAuthorityTests._record(floor, epoch, rsv, rs, au.genesis()[0] if pin is None else pin)
    _, bodies, signed = decide._requests(frame)[:3]
    grant = decide._approval(signed)[1] if bodies else fx.D[3]
    if leaves is None:
        leaves = [bytes([0]) + _le(0, 8) + bytes([2, 0]) + x for x in fx.frame_inputs(frame).values()] if bodies else []
    head = flatchain.step_adds(frame[82 + 8:82 + 72], auth + root)
    recs = b"".join(_le(i, 3) + bytes([o, 0]) + _le(0, 8) + _le(2**32 - 1, 4) + _le(2**24 - 1, 3) for i, o in enumerate(outcomes))
    return (b"RRDA" + _le(4, 2) + b"\0" + frame[6:18] + _le(len(outcomes), 4) + frame[18:82] + recs + head + root + hold + grant
            + auth + _le(0, 4) + _le(len(leaves), 4) + b"".join(leaves) + _le(0, 4))


def carried(frame: bytes) -> tuple[bytes, int | None, int, int, bytes]:
    """The key-set pin, the grant serial floor (None when none is asserted), the key-set epoch floor and the rule-set
    version and digest a request frame carries
    (conformance/FRAME_V1.md section 2: after the feeds, their rows and the redone payments)."""
    r = decide._Reader(frame)
    r.at = 82 + 4 + 4 + 64
    redo = r.num(4)
    descs = [r.take(77) for _ in range(4)]
    r.at += sum(int.from_bytes(d[9:13], "little") * w for d, w in zip(descs, map(sum, decide.FEED_WIDTHS.values()))) + 261 * redo
    pin, flag, floor, kfloor, rsv, rs = r.take(64), r.num(1), r.num(8), r.num(4), r.num(4), r.take(64)
    return pin, floor if flag else None, kfloor, rsv, rs


def leaf(r: gate.DecideRequest, frame: bytes) -> bytes:
    """The leaf the engine answers for a request of ``frame``: ALLOW, no reason, TRANSFER, no bypass, its INPUT/v6."""
    return bytes([0]) + _le(0, 8) + bytes([2, 0]) + fx.frame_inputs(frame)[gate.encode_decide_request(r)]


ROOT = bytes(64)  # a stand-in state root after a batch


def first_frame(shard: int, pin: bytes) -> bytes:
    """A stored request frame of a shard's first batch, as far as the producer reads it: its ``prev``, the genesis under
    ``pin`` dated 0, after the 82-byte header, today and asOf (conformance/FRAME_V1.md section 2)."""
    return b"RRDQ" + bytes(82 + 8 - 4) + flatchain.genesis(shard, 0, pin)


class _Producer:
    """Shard 0 before its first seal (``record``: the authority record it reports sealed, None for none)."""
    shard, tenant, record = 0, fx.TENANT, None

    def flat_head(self) -> None:
        return None

    def authority(self) -> bytes | None:
        return self.record

    def tip(self) -> None:
        return None

    def sealed_quar(self) -> None:
        return None

    def answered(self, key: bytes) -> None:
        return None

    def vouch(self, record: bytes) -> bytes:
        return b""


class _CutProducer(_Producer):
    """Shard 1 after its cutover."""
    shard = 1

    def sealed_quar(self) -> tuple[bytes, bytes]:
        return b"Q" * 9, bytes(64)


KNOWN: dict[str, list[str]] = {}  # request bytes (hex) -> the lines the fake worker "decodes" from them (one record each)


def req(*lines: str):
    """A payment request the fake worker answers with these line bodies (the real worker decodes the request itself)."""
    request = fx.payment_request(len(KNOWN))
    KNOWN[gate.encode_decide_request(request).hex()] = list(lines)
    return request


GRANT, KEYS = au.standing()
RUN_DOC = rs.with_(ra.BASE, version=1, prev=bytes(64), eff_from=10101, eff_to=99991231)  # a runnable rule set
RUN, RUN_ID = ra.sign(RUN_DOC), ra.digest(RUN_DOC)
OTHER = ra.sign(rs.with_(RUN_DOC, not_before=ra.NB + 1))  # another rule set
MORE = ra.sign(RUN_DOC, ("p1", "p2", "p3"))  # the same rule set with one signature more
V2_DOC = rs.with_(RUN_DOC, version=2, prev=RUN_ID)
V2, V2_ID = ra.sign(V2_DOC), ra.digest(V2_DOC)
NO_FEEDS = (0, ((bytes(77), b""),) * 4)  # today 0, every feed absent: the scripted workers below read no frame feeds
_FLOORS = tempfile.TemporaryDirectory()  # the tenant's grant floor file
PROD = _Producer()  # the one shard the module's tenant authority is opened with
TENANT = au.tenant(Path(_FLOORS.name) / "tenant.floor", [PROD])


class _Worker:
    """Records each frame and ALLOWs every line it is sent, with the one-step history head the adapter recomputes."""

    lost = 0

    def launched_release(self) -> bytes:
        return b""  # emits no RULES_PAY, so no token names it

    floor = 0  # the grant serial its authority record says the batch admitted
    epoch = 0  # the key-set epoch its authority record says the batch's head reached
    pin = None  # the key-set pin its authority record names (None: the tenant's)
    rsv, rs = 0, flatchain.ZERO  # the rule-set version and digest its authority record names

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.seen: list[str] = []  # the line bodies of the requests it was sent

    def check(self) -> None:
        pass

    def run_frame(self, directory: str, shard: int, data: bytes, leaves: list[bytes] | None = None) -> bytes:
        self.frames.append(data)
        lines = [x for r in fx.frame_inputs(data) for x in KNOWN[r.hex()]]
        self.seen += lines
        return answer(data, [0] * len(lines), leaves, floor=self.floor, epoch=self.epoch, pin=self.pin, rsv=self.rsv, rs=self.rs)


class PinTests(unittest.TestCase):
    def test_a_program_whose_bytes_are_not_the_pin_is_refused_before_it_starts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "engine.exe"
            exe.write_bytes(b"MZ not the engine")
            worker = decide.RulesWorker(exe)  # the committed pin, not the file's own hash
            self.addCleanup(worker.close)
            with self.assertRaisesRegex(decide.GateDecideError, "rules_pin_mismatch") as caught:
                worker.run_frame("idx", 0, b"x")
            self.assertNotIsInstance(caught.exception, decide.WorkerDied)  # a wrong program is not a dead worker
            self.assertEqual((worker._worker, worker.gen), (None, 0))

    def test_the_pin_comes_from_the_committed_source_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "engine.exe"
            exe.write_bytes(b"MZ not the engine")
            with mock.patch.object(decide, "committed_pin", lambda: hashlib.sha256(exe.read_bytes()).digest()):
                worker = decide.RulesWorker(exe)
            self.addCleanup(worker.close)
            worker.check()  # the patched source accepts these bytes
            with self.assertRaises(TypeError):
                decide.RulesWorker(exe, pin=hashlib.sha256(b"x").digest())  # no constructor argument names a pin

    def test_a_program_that_cannot_be_read_for_a_moment_is_read_again(self) -> None:
        """Final review M2 (Sonnet): a sharing violation reading the program is a machine fault, read again after a short
        wait; one that lasts every try is ``MachineFault`` ``rules_unreadable``, never ``rules_missing``."""
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "engine.exe"
            exe.write_bytes(b"MZ not the engine")
            with mock.patch.object(decide, "committed_pin", lambda: hashlib.sha256(exe.read_bytes()).digest()):
                worker = decide.RulesWorker(exe)
            self.addCleanup(worker.close)
            shared = PermissionError(13, "used by another process")
            for fails, want in ((decide.ATTEMPTS - 1, None), (decide.ATTEMPTS, "rules_unreadable")):
                with self.subTest(fails=fails):
                    worker.exe = mock.Mock(read_bytes=mock.Mock(side_effect=[shared] * fails + [exe.read_bytes()]))
                    with mock.patch.object(decide.time, "sleep"):
                        if want is None:
                            worker.check()
                        else:
                            with self.assertRaises(decide.MachineFault) as caught:
                                worker.check()
                            self.assertEqual((str(caught.exception), caught.exception.action), (want, "retry_later"))
                    self.assertEqual(worker.exe.read_bytes.call_count, min(fails + 1, decide.ATTEMPTS))

    def test_a_missing_or_wrong_program_is_refused_before_anything_is_decided_and_not_retried(self) -> None:
        for name, make, want in (("missing", lambda e: None, "rules_missing"), ("wrong", lambda e: e.write_bytes(b"MZ"), "rules_pin_mismatch")):
            with self.subTest(name), contextlib.ExitStack() as stack:
                tmp = stack.enter_context(tempfile.TemporaryDirectory())
                exe = Path(tmp) / "engine.exe"
                make(exe)
                worker = decide.RulesWorker(exe)
                self.addCleanup(worker.close)
                with mock.patch.object(decide.LOG, "warning") as warned:
                    with self.assertRaises(decide.GateDecideError) as caught:
                        decide.decide(NO_FEEDS, 0, PROD, [req(*["5:1 x"])], Path(tmp) / "idx", worker, GRANT, KEYS, TENANT)
                self.assertEqual((str(caught.exception), type(caught.exception), warned.called, worker.gen),
                                 (want, decide.GateDecideError, False, 0))

    def test_a_refusal_that_would_repeat_is_not_retried(self) -> None:
        """Fault hunt item 7: the same frame fails the same way on any launch (past a cap, a panic, or out of memory with the
        Job's peak near its cap, which leave a diagnostic on stderr): refused once with its cause, one action for all; a
        worker that died with no diagnostic, or out of memory well below the cap (final review M1: the machine ran out, not
        the batch), is a machine fault, decided again on a fresh launch, and so is one past the deadline (next test)."""
        cap, oom = decide.RulesWorker.JOB_MEMORY_CAP_BYTES, b"INTERNAL PANIC: out of memory\n"
        for n, (reason, diagnostic, peak, want) in itertools.product((1, 2), (("worker_frame_cap", b"", 0, "worker_frame_cap"), ("worker_stderr", b"", 0, "worker_stderr"),
                                               ("worker_response_cap", b"", 0, "worker_response_cap"),
                                               ("worker_exchange", b"PANIC at index out of bounds\n", 0, "worker_stderr"),
                                               ("worker_exchange", oom, cap - cap // 20, "worker_stderr"),
                                               ("worker_exchange", oom, cap // 4, None), ("worker_exchange", oom, None, None),
                                               ("worker_exchange", b"", 0, None), ("worker_unavailable", b"", 0, None))):
            with self.subTest(reason, diagnostic=diagnostic, peak=peak, requests=n), tempfile.TemporaryDirectory() as tmp:
                worker, launches = decide.RulesWorker(Path(tmp) / "engine.exe"), []
                self.addCleanup(worker.close)
                dying = mock.Mock(alive=True)
                dying.exchange.side_effect = process.VerifierProcessError(reason)
                dying.diagnostic.return_value, dying.peak_job_memory.return_value = diagnostic, peak

                def launch(*args, **kw):
                    launches.append(1)
                    return dying
                with mock.patch.object(worker, "_program", lambda: b"x"), mock.patch.object(process, "launch_contained_worker", launch), \
                        mock.patch.object(decide.LOG, "warning"):
                    requests = [req("5:1 x") for _ in range(n)]
                    if want and n == 1:  # final review L3: one request cannot be split, so it HOLDs for a person, as on a timeout
                        got = decide.decide(NO_FEEDS, 0, PROD, requests, Path(tmp) / "idx", worker, GRANT, KEYS, TENANT)
                        self.assertEqual((got.lines, got.digest, len(launches), worker.lost),
                                         ((f"{requests[0].payment_id} HOLD {want}",), b"", 1, 0))
                        continue
                    with self.assertRaises(decide.GateDecideError) as caught:
                        decide.decide(NO_FEEDS, 0, PROD, requests, Path(tmp) / "idx", worker, GRANT, KEYS, TENANT)
                if want:
                    self.assertEqual((str(caught.exception), type(caught.exception), caught.exception.action, len(launches), worker.lost),
                                     (want, decide.DataFault, "split_batch", 1, 0))
                else:  # final review M2: a machine cause past its retries carries its own action
                    self.assertEqual((str(caught.exception), type(caught.exception), caught.exception.action, len(launches)),
                                     ("rules_refused", decide.MachineFault, "retry_later", decide.ATTEMPTS))

    def test_a_batch_past_the_deadline_on_every_launch_is_split_or_held_not_retried_later(self) -> None:
        """Final review M3: every launch past its deadline is the batch's own slowness, so ``retry_later`` would loop: a batch
        of two is ``DataFault`` ``timeout`` (split it), one request alone HOLDs ``timeout`` for a person.  A death, then
        launches past the deadline, is still the machine (``MachineFault`` ``timeout``)."""
        for causes, n in ((["worker_timeout"] * decide.ATTEMPTS, 2), (["worker_timeout"] * decide.ATTEMPTS, 1),
                          (["worker_exchange"] + ["worker_timeout"] * (decide.ATTEMPTS - 1), 1)):
            with self.subTest(causes=causes, n=n), tempfile.TemporaryDirectory() as tmp:
                worker, launches = decide.RulesWorker(Path(tmp) / "engine.exe"), []
                self.addCleanup(worker.close)

                def launch(*args, **kw):
                    dying = mock.Mock(alive=True)
                    dying.exchange.side_effect = process.VerifierProcessError(causes[len(launches)])
                    dying.diagnostic.return_value = b""
                    launches.append(dying)
                    return dying
                requests = [req("5:1 x") for _ in range(n)]
                with mock.patch.object(worker, "_program", lambda: b"x"), mock.patch.object(process, "launch_contained_worker", launch), \
                        mock.patch.object(decide.LOG, "warning"):
                    try:
                        got = decide.decide(NO_FEEDS, 0, PROD, requests, Path(tmp) / "idx", worker, GRANT, KEYS, TENANT)
                    except decide.GateDecideError as error:
                        got = (type(error), str(error), error.action)
                self.assertEqual(len(launches), decide.ATTEMPTS)
                if causes[0] == "worker_exchange":
                    self.assertEqual(got, (decide.MachineFault, "timeout", "retry_later"))
                elif n == 2:
                    self.assertEqual(got, (decide.DataFault, "timeout", "split_batch"))
                else:
                    self.assertEqual((got.lines, got.digest), ((f"{requests[0].payment_id} HOLD timeout",), b""))

    def test_a_batch_past_the_codec_limit_is_refused_at_intake(self) -> None:
        """Fault hunt item 11: more requests than one checkpoint holds are refused before the program is checked, a floor is
        read or a frame is sent, as a data fault (split the batch)."""
        worker = _Worker()
        worker.check = mock.Mock()
        big = [fx.payment_request(i) for i in range(gate.MAX_BATCH + 1)]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(TENANT, "raise_floors") as floors:
            with self.assertRaises(decide.DataFault) as caught:
                decide.decide(NO_FEEDS, 0, PROD, big, Path(tmp) / "idx", worker, GRANT, KEYS, TENANT)
        self.assertEqual((str(caught.exception), caught.exception.action, worker.frames, worker.check.called, floors.called),
                         ("batch_too_large", "split_batch", [], False, False))


    def test_a_flat_directory_that_will_not_go_is_a_typed_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(decide.shutil, "rmtree", side_effect=OSError("held")), \
                mock.patch.object(decide.time, "sleep"):
            with self.assertRaisesRegex(decide.GateDecideError, "flat_cleanup"):
                decide._rm(Path(tmp))

    def test_a_missing_pin_is_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(decide, "PROVENANCE", Path(tmp) / "none.txt"):
            (Path(tmp) / "none.txt").write_text("pin gate_verify " + "0" * 64 + "\n", "utf-8")
            with self.assertRaisesRegex(decide.GateDecideError, "rules_pin_missing"):
                decide.RulesWorker(Path(tmp) / "engine.exe")


class RelaunchTests(unittest.TestCase):
    """A worker that dies mid-batch is relaunched and the same frame sent again; the answer says how many launches it took."""

    class Dying(_Worker):
        def __init__(self, deaths: int) -> None:
            super().__init__()
            self.deaths = deaths

        def run_frame(self, directory: str, shard: int, data: bytes, leaves: list[bytes] = ()) -> bytes:
            if len(self.frames) < self.deaths:
                self.frames.append(data)
                self.lost += 1
                raise decide.WorkerDied("rules_refused")
            return super().run_frame(directory, shard, data)

    def _decide(self, worker):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return decide.decide(NO_FEEDS, 0, PROD, [req(*["5:1 x"])], Path(tmp.name) / "idx", worker, GRANT, KEYS, TENANT)

    def test_the_frame_carries_the_pin_key_set_steps_grant_and_bypasses_and_a_refused_grant_holds_every_row(self) -> None:
        worker, step, byp = _Worker(), au.kstep(), au.bypass(fx.PROGRAM, "pay", bytes(64), 1)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        decide.decide(NO_FEEDS, 0, PROD, [req(*["5:1 x"])], Path(tmp.name) / "idx", worker, GRANT, KEYS._replace(steps=(step,)), TENANT, [byp])
        frame = worker.frames[0]
        for part in (KEYS.keyset, GRANT, byp, step[1], step[0].to_bytes(4, "little")):  # each travels in the frame, unchanged
            self.assertIn(part, frame)
        self.assertEqual(carried(frame), (au.genesis()[0], *TENANT.raise_floors(0, 0)))
        self.assertEqual(frame[82 + 8:82 + 72], flatchain.genesis(0, 0, au.genesis()[0]))  # the genesis under the tenant's pin
        self.assertEqual(len(fx.frame_inputs(frame)), 1)

        class Refusing(_Worker):
            def run_frame(self, directory: str, shard: int, data: bytes, leaves: list[bytes] = ()) -> bytes:
                return answer(data, [], hold=b"EXPIRED" + bytes(9))
        ans = decide.decide(NO_FEEDS, 0, PROD, [req(*["5:1 x"])], Path(tmp.name) / "idx2", Refusing(), GRANT, KEYS, TENANT)
        self.assertEqual((ans.digest, ans.pays), (b"", ()))
        self.assertTrue(ans.lines[0].endswith(" HOLD grant_expired"), ans.lines)

    def test_a_batch_is_decided_again_after_the_worker_dies_and_the_answer_counts_the_launches(self) -> None:
        worker = self.Dying(decide.ATTEMPTS - 1)
        ans = self._decide(worker)
        self.assertEqual(([r.outcome for r in ans.recs], ans.attempts, len(set(worker.frames))), (["ALLOW"], decide.ATTEMPTS, 1))  # the same frame each time

    def test_a_launch_past_its_deadline_is_a_machine_fault_decided_again(self) -> None:
        """One launch past its deadline, then an answer: the batch is decided on the next launch, not refused."""
        worker, answers = decide.RulesWorker(Path("engine.exe")), _Worker()
        self.addCleanup(worker.close)
        stalled = mock.Mock(alive=True)
        stalled.exchange.side_effect = process.VerifierProcessError("worker_timeout")
        answering = mock.Mock(alive=True)
        answering.exchange.side_effect = lambda data, **kw: answers.run_frame("idx", 0, data[1:])
        launched = iter((stalled, answering))
        with mock.patch.object(worker, "_program", lambda: b"x"), mock.patch.object(worker, "launched_release", lambda: b""), \
                mock.patch.object(process, "launch_contained_worker", lambda *a, **kw: next(launched)), \
                mock.patch.object(decide.LOG, "warning") as warned:
            ans = self._decide(worker)
        self.assertEqual(([r.outcome for r in ans.recs], ans.attempts, worker.gen, warned.call_count), (["ALLOW"], 2, 2, 1))

    def test_a_worker_that_dies_on_every_attempt_refuses_the_batch(self) -> None:
        worker = self.Dying(decide.ATTEMPTS)
        with self.assertRaisesRegex(decide.GateDecideError, "rules_refused"):
            self._decide(worker)
        self.assertEqual(len(worker.frames), decide.ATTEMPTS)


class TenantAuthorityTests(unittest.TestCase):
    """The key-set pin comes from the tenant's deployment slot; the grant floor is one file for every shard of the tenant."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def _decide(self, worker, tenant, name="idx"):
        return decide.decide(NO_FEEDS, 0, tenant._shards[0], [req(*["5:1 x"])], self.dir / name, worker, GRANT, KEYS, tenant)

    def _tenant(self, *shards, **kw):
        return au.tenant(self.dir / "tenant.floor", list(shards) or [_Producer()], **kw)

    @staticmethod
    def _record(serial: int, epoch: int, rsv: int = 0, rs: bytes = flatchain.ZERO, pin: bytes | None = None) -> bytes:
        """An authority record holding this grant floor, key-set epoch and rule set (the tenant's pin unless ``pin``)."""
        return ((au.genesis()[0] if pin is None else pin) + epoch.to_bytes(4, "big") + bytes(132) + serial.to_bytes(8, "big")
                + rs + rsv.to_bytes(4, "big"))

    def _sealed(self, shard: int, serial: int, epoch: int, rsv: int = 0, rs: bytes = flatchain.ZERO) -> _Producer:
        """Shard ``shard``, whose last sealed authority record holds this grant floor, key-set epoch and rule set."""
        prod = _Producer()
        prod.shard, prod.record = shard, self._record(serial, epoch, rsv, rs)
        return prod

    def test_a_step_whose_record_names_another_pin_holds_every_row_and_moves_no_floor(self) -> None:
        class OtherPin(_Worker):  # a consistent chain, but its record names another pin
            floor, pin = 9, bytes(64)
        tenant = self._tenant()
        ans = self._decide(OtherPin(), tenant)
        self.assertEqual((ans.digest, [x.split(" ", 1)[1] for x in ans.lines], tenant.raise_floors(0, 0)[0]), (b"", ["HOLD keyset_pin"], 0))

    def test_the_floor_rises_to_the_admitted_serial_for_every_shard_and_never_falls(self) -> None:
        tenant, worker = self._tenant(), _Worker()
        for n, (admitted, sent, after) in enumerate(((5, 0, 5), (3, 5, 5), (7, 5, 7))):
            with self.subTest(admitted=admitted):
                worker.floor = admitted
                ans = self._decide(worker, tenant, f"idx{n}")
                self.assertTrue(ans.digest)
                self.assertEqual(carried(worker.frames[-1])[1], sent)
                self.assertEqual(int.from_bytes(ans.adds[200:208], "big"), admitted)
                self.assertEqual(tenant.raise_floors(0, 0)[0], after)
        # another process's view of the same file: one floor for the tenant
        self.assertEqual(self._tenant(self._sealed(0, 0, 0)).raise_floors(0, 0)[0], 7)

    def test_the_key_set_epoch_floor_rises_for_every_shard_and_never_falls(self) -> None:
        tenant, worker = self._tenant(), _Worker()
        for n, (reached, sent, after) in enumerate(((1, 0, 1), (0, 1, 1), (2, 1, 2))):
            with self.subTest(reached=reached):
                worker.epoch = reached
                self.assertTrue(self._decide(worker, tenant, f"idx{n}").digest)
                self.assertEqual(carried(worker.frames[-1])[2], sent)
                self.assertEqual(tenant.raise_floors(0, 0)[:2], (0, after))

    def test_an_unauthored_pin_slot_reads_the_strictest_pin(self) -> None:
        for name in ("tenant.floor", "f2"):
            decide.TenantAuthority.provision(self.dir / name, fx.TENANT, [_Producer()])
        with self.assertLogs("rightrail.slots", "WARNING") as logs:
            tenant = decide.TenantAuthority(slots.Slots({}), fx.TENANT, self.dir / "tenant.floor", [_Producer()])
        self.assertIn("id=GATE_KEYSET_PIN", " ".join(logs.output))
        self.assertEqual(tenant.pin, bytes(64))  # no key set hashes to it: the worker admits none, so every row HOLDs
        another = decide.TenantAuthority(slots.Slots({"GATE_KEYSET_PIN": [["other", au.genesis()[0].hex()]]}), fx.TENANT, self.dir / "f2", [_Producer()])
        self.assertEqual(another.pin, bytes(64))  # another tenant's pin is not this tenant's
        worker = _Worker()
        self._decide(worker, tenant)
        self.assertEqual(carried(worker.frames[0])[0], bytes(64))

    def test_a_tenant_authority_of_another_tenant_is_refused(self) -> None:
        with self.assertRaisesRegex(decide.GateDecideError, "foreign_tenant"):
            self._decide(_Worker(), self._tenant(tenant_id="other-tenant"))

    def test_an_authority_needs_every_shard_once_and_decides_only_on_one_of_them(self) -> None:
        path, deployment = self.dir / "tenant.floor", slots.Slots({"GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]})
        for shards in ((), (_Producer(), _Producer())):
            with self.subTest(len(shards)):
                for fn in (lambda: decide.TenantAuthority.provision(path, fx.TENANT, shards),
                           lambda: decide.TenantAuthority(deployment, fx.TENANT, path, shards)):
                    self.assertRaisesRegex(decide.GateDecideError, "tenant_shards", fn)
        self.assertFalse(path.exists())
        tenant, worker = self._tenant(), _Worker()
        with self.assertRaisesRegex(decide.GateDecideError, "tenant_shards"):  # shard 1 is not one of the tenant's
            decide.decide(NO_FEEDS, 0, _CutProducer(), [req(*["5:1 x"])], self.dir / "idx", worker, GRANT, KEYS, tenant)
        self.assertEqual(worker.frames, [])

    def test_a_commit_on_a_shard_the_authority_was_not_opened_with_is_refused(self) -> None:
        tenant = self._tenant()
        ans = decide.Answer(("x",), bytes(64), b"", None, pays=(mock.Mock(program="p"),))
        with self.assertRaisesRegex(decide.GateDecideError, "tenant_shards"):  # shard 1 is not one of the tenant's
            decide.commit(_CutProducer(), "p", ans, 0, tenant)

    def test_the_floor_file_names_the_exact_shard_set(self) -> None:
        self._tenant(self._sealed(0, 5, 0), self._sealed(1, 0, 0))
        for shards in ((self._sealed(0, 5, 0),), (self._sealed(0, 5, 0), self._sealed(1, 0, 0), self._sealed(2, 0, 0)), (self._sealed(0, 5, 0), self._sealed(2, 0, 0))):
            with self.subTest(len(shards)):
                self.assertRaisesRegex(decide.GateDecideError, "tenant_shards", self._tenant, *shards)

    def test_a_closed_shard_counts_by_its_last_checked_floors_and_a_bad_sibling_is_refused_alone(self) -> None:
        a, b = self._sealed(0, 0, 0), self._sealed(1, 6, 1)
        tenant, worker = self._tenant(a, b), _Worker()
        self.assertEqual(tenant.raise_floors(0, 0)[:2], (6, 1))
        b.authority = mock.Mock(side_effect=producer.GateProducerError("producer_closed"))  # the shard closed: its floors stay
        self.assertEqual(tenant.raise_floors(0, 0)[:2], (6, 1))
        for reason in ("authority_unchained",):
            with self.subTest(reason):
                b.authority = mock.Mock(side_effect=producer.GateProducerError(reason))
                self.assertEqual(tenant.raise_floors(0, 0)[:2], (6, 1))  # the tenant goes on with b's cached floors
                self.assertTrue(self._decide(worker, tenant, "idx-" + reason).digest)  # shard 0 decides
                with self.assertRaises(decide.GateDecideError) as caught:
                    decide.decide(NO_FEEDS, 0, b, [req(*["5:1 x"])], self.dir / "idx-b", worker, GRANT, KEYS, tenant)
                self.assertEqual(caught.exception.args, (reason, 1))  # only shard 1 is refused, by name

    def assertFloorRefused(self, path: Path, fn, *args) -> None:
        with self.assertRaises(decide.GateDecideError) as caught:
            fn(*args)
        self.assertEqual(caught.exception.args, ("tenant_floor", str(path)))

    def test_a_corrupt_empty_missing_or_other_tenants_floor_file_is_refused_before_anything_is_decided(self) -> None:
        path = self.dir / "tenant.floor"
        tenant, worker = self._tenant(), _Worker()
        saved, deployment = path.read_bytes(), slots.Slots({"GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]})
        cases = {"corrupt": bytes(decide._SIZE) * 2,  # two whole records whose checks fail
                 "empty": b"", "missing": None}
        other = self.dir / "other.floor"
        stranger = _Producer()
        stranger.tenant = "other-tenant"
        au.tenant(other, [stranger], tenant_id="other-tenant")
        cases["another tenant's"] = other.read_bytes()  # its record verifies only under that tenant's domain
        for name, data in cases.items():
            with self.subTest(name):
                path.unlink(missing_ok=True)
                if data is not None:
                    path.write_bytes(data)
                self.assertFloorRefused(path, self._decide, worker, tenant)
                with self.assertLogs(decide.LOG, "ERROR"):  # an open logs it and decides nothing
                    opened = decide.TenantAuthority(deployment, fx.TENANT, path, [_Producer()])
                self.assertFloorRefused(path, opened.raise_floors, 0, 0)
                self.assertEqual(worker.frames, [])
        path.write_bytes(saved)
        self.assertFloorRefused(path, decide.TenantAuthority.provision, path, fx.TENANT, [_Producer()])  # provisioning never replaces a record
        self.assertEqual(path.read_bytes(), saved)

    def test_a_torn_tail_reads_as_the_previous_record_and_every_shards_seal_raises_it(self) -> None:
        path = self.dir / "tenant.floor"
        self._tenant().raise_floors(4, 1)
        good = path.read_bytes()
        path.write_bytes(good + bytes(5))  # a crash in the middle of the next record
        self.assertEqual(self._tenant().raise_floors(0, 0)[:2], (4, 1))  # the open reads the previous record: not a refusal
        path.write_bytes(good + bytes([7]) * 20)
        self.assertEqual(self._tenant(self._sealed(0, 6, 2)).raise_floors(0, 0)[:2], (6, 2))  # a shard's sealed record raises it
        self.assertEqual(self._tenant().raise_floors(0, 0)[:2], (6, 2))  # written back: the torn tail is gone

    def test_a_floor_file_that_cannot_be_read_for_a_moment_is_read_again(self) -> None:
        """Final review M2 (Sonnet): an OSError reading the floor file is read again after a short wait; one that lasts every
        try is ``MachineFault`` ``tenant_floor_unreadable``, never ``tenant_floor`` (the case a person replaces the file)."""
        tenant, real, calls = self._tenant(), decide.marks.read, []

        def flaky(*args):
            calls.append(1)
            if len(calls) <= fails:
                raise PermissionError(13, "used by another process")
            return real(*args)
        for fails in (decide.ATTEMPTS - 1, decide.ATTEMPTS):
            calls.clear()
            with self.subTest(fails=fails), mock.patch.object(decide.marks, "read", flaky), mock.patch.object(decide.time, "sleep"):
                if fails < decide.ATTEMPTS:
                    self.assertEqual(tenant.raise_floors(0, 0)[:2], (0, 0))
                else:
                    with self.assertRaises(decide.MachineFault) as caught:
                        tenant.raise_floors(0, 0)
                    self.assertEqual((caught.exception.args, caught.exception.action),
                                     (("tenant_floor_unreadable", str(self.dir / "tenant.floor")), "retry_later"))

    def test_a_lock_timeout_is_retried_a_bounded_number_of_times(self) -> None:
        tenant, real = self._tenant(), decide.msvcrt.locking
        calls = []

        def busy_then_free(fd, mode, size):
            calls.append(mode)
            if mode == decide.msvcrt.LK_LOCK and len(calls) < 3:
                raise OSError("timed out")  # LK_LOCK gave up after its own wait
            return real(fd, mode, size)
        with mock.patch.object(decide.msvcrt, "locking", busy_then_free):
            self.assertEqual(tenant.raise_floors(0, 0)[:2], (0, 0))
        self.assertEqual(calls.count(decide.msvcrt.LK_LOCK), 3)

        calls.clear()
        with mock.patch.object(decide.msvcrt, "locking", side_effect=OSError("busy")) as busy:
            with self.assertRaises(decide.GateDecideError) as caught:
                tenant.raise_floors(0, 0)
        self.assertEqual((caught.exception.args, type(caught.exception), caught.exception.action),
                         (("tenant_floor_busy", str(self.dir / "tenant.floor")), decide.MachineFault, "retry_later"))  # not a file to replace
        self.assertEqual(busy.call_count, decide._LOCK_TRIES)

    def test_only_a_partial_or_all_zero_last_record_is_torn(self) -> None:
        path, tenant = self.dir / "tenant.floor", self._tenant()
        tenant.raise_floors(4, 1)
        tenant.raise_floors(6, 1)
        both = path.read_bytes()
        for name, data in (("zero-filled", both[:-decide._SIZE] + bytes(decide._SIZE)), ("partial", both[:-3])):
            with self.subTest(name):
                path.write_bytes(data)
                self.assertEqual(tenant.raise_floors(0, 0)[:2], (4, 1))  # the previous record
        path.write_bytes(both[:-1] + bytes([both[-1] ^ 1]))  # a whole record that fails its check is damage, not a crash
        self.assertFloorRefused(path, tenant.raise_floors, 0, 0)

    def _v2(self, path: Path, *floors: tuple[int, int]) -> bytes:
        """A floor file of the format before rule sets (domain v2: serial, epoch, shard-set digest) holding these records."""
        domain, ids, end = decide._floor_domain(fx.TENANT, 2), decide._ids([_Producer()]), 0
        for serial, epoch in floors:
            decide.marks.append(path, domain, end, serial.to_bytes(8, "big") + epoch.to_bytes(4, "big") + ids)
            end = path.stat().st_size
        return path.read_bytes()

    def test_a_v2_floor_file_reads_as_no_rule_set_and_its_first_write_replaces_it_whole(self) -> None:
        """The format before rule sets reads as rule-set version 0 and the zero digest (none was admitted before it), its
        torn tail as the previous record.  The first write replaces the file with one v3 record, written beside it and
        renamed over it: a crash before the rename leaves the v2 file, read as before, and the next write replaces the
        leftover.  Provisioning never replaces a v2 file; nothing writes v2 again."""
        path, side, x = self.dir / "tenant.floor", self.dir / "tenant.floor.v3", bytes([3]) * 64
        old = self._v2(path, (4, 1), (6, 2))
        self.assertFloorRefused(path, decide.TenantAuthority.provision, path, fx.TENANT, [_Producer()])
        path.write_bytes(old + bytes(9))
        self.assertEqual(decide.TenantAuthority.floors_in(path, fx.TENANT), (6, 2, 0, flatchain.ZERO))
        path.write_bytes(old[:-3])
        self.assertEqual(decide.TenantAuthority.floors_in(path, fx.TENANT), (4, 1, 0, flatchain.ZERO))
        path.write_bytes(old)
        def cut(p: Path, *_) -> None:
            p.write_bytes(b"\x05" * 9)
            raise KeyboardInterrupt
        for name, crash in (("written beside", mock.patch.object(decide, "_rename_durably", side_effect=KeyboardInterrupt)),
                            ("cut short beside", mock.patch.object(decide.marks, "append", side_effect=cut))):
            with self.subTest(name), crash, self.assertRaises(KeyboardInterrupt):
                self._tenant()  # the open writes the file up: the process ends inside the replace
            self.assertEqual((path.read_bytes(), side.exists()), (old, True))
            self.assertEqual(decide.TenantAuthority.floors_in(path, fx.TENANT), (6, 2, 0, flatchain.ZERO))
        tenant = self._tenant()
        self.assertEqual((len(path.read_bytes()), side.exists()), (decide._SIZE, False))  # one v3 record, the leftover gone
        self.assertEqual(tenant.raise_floors(0, 0, 1, x), (6, 2, 1, x))
        self.assertEqual(len(path.read_bytes()), 2 * decide._SIZE)  # appended, as every v3 write is
        self.assertEqual(decide.TenantAuthority.floors_in(path, fx.TENANT), (6, 2, 1, x))

    def test_a_torn_v3_record_reads_as_the_record_before_with_its_rule_set(self) -> None:
        path, x, y = self.dir / "tenant.floor", bytes([3]) * 64, bytes([4]) * 64
        tenant = self._tenant()
        tenant.raise_floors(4, 1, 1, x)
        good = path.read_bytes()
        tenant.raise_floors(6, 1, 2, y)
        both = path.read_bytes()
        for name, data in (("partial", both[:-3]), ("zero-filled", good + bytes(decide._SIZE)), ("cut in the rule set", both[:len(good) + 60])):
            with self.subTest(name):
                path.write_bytes(data)
                self.assertEqual(decide.TenantAuthority.floors_in(path, fx.TENANT), (4, 1, 1, x))
        self.assertEqual(tenant.raise_floors(0, 0), (4, 1, 1, x))

    def test_a_rule_set_digest_changed_at_the_same_version_in_the_floor_file_is_refused(self) -> None:
        """The records' order key stops at the version: two whole records at one version under different digests (a
        substituted or forked rule set) do not rise, so the file is refused, whichever digest is the larger.  A digest
        edited inside a record fails its check."""
        path, x, y = self.dir / "tenant.floor", bytes([3]) * 64, bytes([4]) * 64
        tenant = self._tenant()
        tenant.raise_floors(4, 1, 1, x)
        good = path.read_bytes()
        for name, low, high in (("larger digest second", x, y), ("smaller digest second", y, x)):
            with self.subTest(name):
                path.write_bytes(b"")
                for rs in (low, high):
                    decide.marks.append(path, tenant._domain, len(path.read_bytes()), decide._floor_record((4, 1, 1, rs), tenant._ids))
                self.assertFloorRefused(path, decide.TenantAuthority.floors_in, path, fx.TENANT)
                self.assertFloorRefused(path, self._decide, _Worker(), tenant)
        path.write_bytes(good[:-33] + bytes([5]) + good[-32:])  # one byte of the digest edited, the check kept
        self.assertFloorRefused(path, decide.TenantAuthority.floors_in, path, fx.TENANT)

    def test_rule_set_floors_rise_to_the_highest_version_and_never_fall(self) -> None:
        """The rule-set floor is the highest version any shard sealed or any batch admitted, with its digest; a lower one,
        given or sealed, leaves it.  Every frame carries it."""
        x, y = bytes([3]) * 64, bytes([4]) * 64
        tenant, worker = self._tenant(self._sealed(0, 0, 0, 1, x)), _Worker()
        self.assertEqual(tenant.raise_floors(0, 0), (0, 0, 1, x))
        for n, (rsv, rs, sent, after) in enumerate(((2, y, (1, x), (2, y)), (1, x, (2, y), (2, y)))):
            with self.subTest(rsv=rsv):
                worker.rsv, worker.rs = rsv, rs
                self.assertTrue(self._decide(worker, tenant, f"idx{n}").digest)
                self.assertEqual(carried(worker.frames[-1])[3:], sent)
                self.assertEqual(tenant.raise_floors(0, 0)[2:], after)
        self.assertEqual(decide.TenantAuthority.floors_in(self.dir / "tenant.floor", fx.TENANT), (0, 0, 2, y))

    def test_two_shards_at_one_rule_set_version_under_different_digests_hold_every_frame(self) -> None:
        """A fork: no digest is chosen, the file keeps its own rule set (provisioning writes none), every decide on every
        shard HOLDs ``ruleset_fork`` before a frame is sent, and a batch admitting a fork cannot raise the file past it."""
        x, y = bytes([3]) * 64, bytes([4]) * 64
        a, b = self._sealed(0, 5, 1, 1, x), self._sealed(1, 6, 1, 1, y)
        tenant, worker = self._tenant(a, b), _Worker()
        self.assertEqual(tenant.raise_floors(0, 0), (6, 1, 1, None))
        self.assertEqual(decide.TenantAuthority.floors_in(self.dir / "tenant.floor", fx.TENANT), (6, 1, 0, flatchain.ZERO))
        for prod in (a, b):
            ans = decide.decide(NO_FEEDS, 0, prod, [req(*["5:1 x"])], self.dir / f"idx{prod.shard}", worker, GRANT, KEYS, tenant)
            self.assertEqual(([x.split(" ", 1)[1] for x in ans.lines], ans.digest), (["HOLD ruleset_fork"], b""))
        self.assertEqual(worker.frames, [])
        b.record = self._record(6, 1, 1, x)  # resolved: both at version 1 under x
        self.assertEqual(tenant.raise_floors(0, 0), (6, 1, 1, x))
        self.assertEqual(decide.TenantAuthority.floors_in(self.dir / "tenant.floor", fx.TENANT), (6, 1, 1, x))

    def test_an_answer_that_forks_the_rule_set_holds_at_decide_and_drops_its_frame(self) -> None:
        """Shard 1 sealed rule set y at version 1; shard 0's engine answers version 1 under x (each shard admitted another
        first record).  The decide HOLDs ``ruleset_fork`` instead of preparing an answer its commit would refuse: the engine
        is reopened at the signed head, the stored frame is dropped, and the file keeps y."""
        x, y = bytes([3]) * 64, bytes([4]) * 64

        class Forked(_Worker):
            rsv, rs, closed = 1, x, 0

            def close(self) -> None:
                self.closed += 1

        tenant, worker = self._tenant(_Producer(), self._sealed(1, 0, 0, 1, y)), Forked()
        ans = self._decide(worker, tenant)
        self.assertEqual(([x.split(" ", 1)[1] for x in ans.lines], ans.digest), (["HOLD ruleset_fork"], b""))
        self.assertEqual((carried(worker.frames[0])[3:], worker.closed, tenant._shards[0].prepared), ((1, y), 1, None))
        self.assertFalse(decide._pend(self.dir / "idx", 1).exists())
        self.assertEqual(decide.TenantAuthority.floors_in(self.dir / "tenant.floor", fx.TENANT), (0, 0, 1, y))

    def test_every_frame_presents_the_tenants_rule_set_record_with_the_same_bytes(self) -> None:
        """A shard holding the tenant's rule set and a shard behind it each present the record whose digest the floors
        carry, the same bytes on every frame, with the floors (1, its digest)."""
        tenant = self._tenant(_Producer(), self._sealed(1, 0, 0, 1, RUN_ID), rulesets=[RUN])
        worker = _Worker()
        worker.rsv, worker.rs = 1, RUN_ID
        for n, prod in enumerate((*tenant._shards, tenant._shards[0])):
            ans = decide.decide(NO_FEEDS, 0, prod, [req(*["5:1 x"])], self.dir / f"idx{n}", worker, GRANT, KEYS, tenant)
            self.assertTrue(ans.digest)
        self.assertEqual([(decide._requests(f)[4], carried(f)[3:]) for f in worker.frames], [([RUN], (1, RUN_ID))] * 3)

    def test_a_frame_presents_no_record_without_one_or_without_the_held_ones(self) -> None:
        """No shard holds a rule set and the tenant has no record: nothing is presented.  A held rule set whose record
        the tenant lacks (only another, or one that does not decode, which does not stop the authority) presents nothing,
        so the engine holds that shard's frame alone."""
        for n, (shards, records, sent) in enumerate((((), [], []), ((self._sealed(0, 0, 0, 1, RUN_ID),), [b"not a record", OTHER], []),
                                                     ((self._sealed(0, 0, 0, 1, RUN_ID),), [b"not a record", RUN], [RUN]))):
            with self.subTest(n=n):
                (self.dir / "tenant.floor").unlink(missing_ok=True)
                with self.assertLogs(decide.LOG, "WARNING") if b"not a record" in records else contextlib.nullcontext():
                    tenant = self._tenant(*shards, rulesets=records)
                worker = _Worker()
                worker.rsv, worker.rs = tenant.raise_floors(0, 0)[2:]
                self._decide(worker, tenant, f"idx{n}")
                self.assertEqual(decide._requests(worker.frames[0])[4], sent)

    def test_copies_of_one_rule_set_present_the_same_record_in_any_order(self) -> None:
        """Review round 1, finding 3: copies of one rule set differ only in their signatures; when one copy's signature
        entries include every other copy's (signatures added over time), it is presented, whatever the order given."""
        one = ra.sign(RUN_DOC, ("p1",))
        cases = [order for records in ([one, MORE], [one, RUN, MORE]) for order in (records, records[::-1])]
        for n, order in enumerate(cases):
            with self.subTest(n=n), self.assertNoLogs(decide.LOG, "WARNING"):
                self.assertEqual(self._presented(order, f"idx{n}"), [MORE])

    def test_copies_that_do_not_nest_hold_only_a_shard_that_would_admit_them(self) -> None:
        """Two copies of one rule set whose signers do not nest (neither has all of the other's) are logged.  Final
        review, LOW 2: a shard that already holds that rule set only reloads it, so it is given the lowest copy and
        decides; a frame of a shard behind the tenant, which would admit it, HOLDs ``ruleset_copies`` without being
        sent.  A frame asserting another rule set the tenant holds still presents it."""
        other_two, other_id = ra.sign(RUN_DOC, ("p1", "p3")), decide.rulecodec.digest(OTHER)
        for n, order in enumerate(([RUN, other_two, OTHER], [OTHER, other_two, RUN])):
            with self.subTest(n=n):
                (self.dir / "tenant.floor").unlink(missing_ok=True)
                with self.assertLogs(decide.LOG, "WARNING") as logs:
                    tenant = self._tenant(self._sealed(0, 0, 0, 1, RUN_ID), self._sealed(1, 0, 0), rulesets=order)
                self.assertIn(RUN_ID.hex(), logs.output[0])
                worker = _Worker()
                worker.rsv, worker.rs = 1, RUN_ID
                held = decide.decide(NO_FEEDS, 0, tenant._shards[1], [req(*["5:1 x"])], self.dir / f"behind{n}", worker,
                                     GRANT, KEYS, tenant)
                self.assertEqual(([x.split(" ", 1)[1] for x in held.lines], held.digest, worker.frames), (["HOLD ruleset_copies"], b"", []))
                self.assertTrue(self._decide(worker, tenant, f"holds{n}").digest)
                self.assertEqual(decide._requests(worker.frames[0])[4], [min(RUN, other_two)])
                with self.assertLogs(decide.LOG, "WARNING"):
                    ans, worker = self._decided(order, other_id, f"other{n}")
                self.assertEqual(decide._requests(worker.frames[0])[4], [OTHER])

    def test_copies_with_the_same_signers_present_the_lowest_bytes(self) -> None:
        """Final review, LOW 2: copies with the same signers whose signature bytes differ (randomized signing) are
        compared by their signers' key ids: the lowest bytes are presented, whatever the order given, and nothing is
        held.  Delta review: a warning names the rule set and says a damaged copy may be why it is refused."""
        twin = RUN[:-1] + bytes([RUN[-1] ^ 1])  # the last signature's last byte differs: the same body and signers
        for n, order in enumerate(([RUN, twin], [twin, RUN])):
            with self.subTest(n=n), self.assertLogs(decide.LOG, "WARNING") as logs:
                self.assertEqual(self._presented(order, f"idx{n}"), [min(RUN, twin)])
            self.assertEqual(len(logs.records), 1)
            self.assertIn(RUN_ID.hex(), logs.output[0])
            self.assertIn("damaged copy", logs.output[0])
            self.assertIn("keep one copy", logs.output[0])

    def test_a_sealable_stored_frame_is_sealed_before_copies_hold_its_shard(self) -> None:
        """Final review, LOW 2: the copies hold comes after the stored frame.  A batch decided on a shard behind the
        tenant, before a restart made the copies ambiguous, is sent again and sealed; the shard then holds the rule set,
        so the new request is decided with the lowest copy."""
        other_two = ra.sign(RUN_DOC, ("p1", "p3"))
        shards = (self._sealed(0, 0, 0, 1, RUN_ID), self._sealed(1, 0, 0))
        shards[1].vouched = lambda record, signature: signature == b""  # the fake producer's vouch
        worker = _Worker()
        worker.rsv, worker.rs = 1, RUN_ID
        run = lambda tenant, r: decide.decide(NO_FEEDS, 0, shards[1], [r], self.dir / "idx", worker, GRANT, KEYS, tenant,  # noqa: E731
                                              seal=(fx.PROGRAM, 1))
        self.assertTrue(run(self._tenant(*shards, rulesets=[RUN]), req(*["5:1 x"])).digest)  # decided, never sealed
        with self.assertLogs(decide.LOG, "WARNING"):
            tenant = self._tenant(*shards, rulesets=[RUN, other_two])

        def seal(prod, program, ans, created_at, tenant):  # the seal: the shard's record now holds the rule set
            decide._drop(decide._pend(self.dir / "idx", 1))
            prod.record = self._record(0, 0, 1, RUN_ID)
        with mock.patch.object(decide, "commit", side_effect=seal) as sealed:
            ans = run(tenant, req(*["5:1 y"]))
        self.assertEqual((sealed.call_count, sealed.call_args[0][2].frame), (1, worker.frames[0]))
        self.assertTrue(ans.digest)
        self.assertEqual([decide._requests(f)[4] for f in worker.frames], [[RUN], [RUN], [min(RUN, other_two)]])

    def test_a_restart_that_now_holds_the_record_decides_in_one_call(self) -> None:
        """Final review, LOW 1: a stored frame built without the record (the authority had none) is sent as stored after
        a restart that has it; the engine holds it for the missing record and its file goes, so the frame this call
        builds, which presents the record, is stored and decided in the same call."""
        class Missing(_Worker):  # holds a frame presenting no record, as a shard holding a rule set does
            def run_frame(self, directory, shard, data, leaves=None):
                if decide._requests(data)[4]:
                    return super().run_frame(directory, shard, data, leaves)
                self.frames.append(data)
                return answer(data, [], hold=b"RULESET_MISSING\x00")
        shards = (self._sealed(0, 0, 0, 1, RUN_ID),)
        shards[0].vouched = lambda record, signature: signature == b""  # the fake producer's vouch
        worker, r = Missing(), req(*["5:1 x"])
        worker.rsv, worker.rs = 1, RUN_ID
        with mock.patch.object(worker, "run_frame", side_effect=decide.MachineFault("rules_refused")):
            self.assertRaises(decide.MachineFault, self._run, self._tenant(*shards), worker, r)  # stored, outcome unknown
        ans = self._run(self._tenant(*shards, rulesets=[RUN]), worker, r)
        self.assertTrue(ans.digest)
        self.assertEqual([decide._requests(f)[4] for f in worker.frames], [[], [RUN]])
        self.assertEqual(decide._pending(decide._pend(self.dir / "idx", 1), shards[0], 1).frame, worker.frames[1])

    def test_an_identical_duplicate_is_one_copy(self) -> None:
        with self.assertNoLogs(decide.LOG, "WARNING"):
            self.assertEqual(self._presented([RUN, bytearray(RUN), memoryview(RUN)], "idx"), [RUN])

    def test_a_tenant_with_no_rule_set_presents_its_one_first_record(self) -> None:
        """No shard holds a rule set: every frame presents the tenant's one version-1 record, with the floors (0, zero),
        so the shard admits it as its first.  Once the answer holds it, the floors carry it, and a shard behind is sent it
        under them.  A version-1 record of another digest is not presented once one is held."""
        tenant = self._tenant(_Producer(), self._sealed(1, 0, 0), rulesets=[RUN])
        worker = _Worker()
        worker.rsv, worker.rs = 1, RUN_ID  # the engine admitted it
        self.assertTrue(self._decide(worker, tenant).digest)
        self.assertEqual((decide._requests(worker.frames[0])[4], carried(worker.frames[0])[3:]), ([RUN], (0, flatchain.ZERO)))
        self.assertEqual(tenant.raise_floors(0, 0)[2:], (1, RUN_ID))
        tenant = self._tenant(*tenant._shards, rulesets=[OTHER, RUN])  # a restart, the file holding the floors
        decide.decide(NO_FEEDS, 0, tenant._shards[1], [req(*["5:1 x"])], self.dir / "behind", worker, GRANT, KEYS, tenant)
        self.assertEqual((decide._requests(worker.frames[1])[4], carried(worker.frames[1])[3:]), ([RUN], (1, RUN_ID)))

    def test_two_first_versions_hold_every_frame_until_a_rule_set_is_held(self) -> None:
        """No shard holds a rule set and the tenant has two version-1 records: the host does not choose; every frame
        HOLDs ``ruleset_choice``, nothing sent.  With a rule set held, the other is not presented and nothing is held."""
        worker = _Worker()
        held = self._decide(worker, self._tenant(rulesets=[RUN, OTHER]))
        self.assertEqual(([x.split(" ", 1)[1] for x in held.lines], held.digest, worker.frames), (["HOLD ruleset_choice"], b"", []))
        self.assertEqual(self._presented([RUN, OTHER], "held"), [RUN])

    def test_a_later_version_holds_every_frame_and_keeps_a_stored_one(self) -> None:
        """A record of a version above the one held: the gate cannot run it, so every frame HOLDs ``ruleset_newer``, nothing
        sent, before a stored frame of the shard is decided: the stored frame stays.  With no rule set held, a version 2
        holds too.  A sealed answer is still given to its exact retry."""
        _, shards, worker, r, filed = self._seal_one()  # its frame stays stored: decided, never sealed
        stored = decide._pend(self.dir / "idx", 1).read_bytes()
        again = self._tenant(*shards, rulesets=[RUN, V2])
        self.assertEqual(self._run(again, worker, r).sealed, list(filed.values())[0])
        held = [self._run(again, worker, req(*["5:1 y"]))]
        (self.dir / "tenant.floor").unlink()
        held.append(self._decide(worker, self._tenant(rulesets=[V2]), "none"))  # no rule set held
        for ans in held:
            self.assertEqual(([x.split(" ", 1)[1] for x in ans.lines], ans.digest), (["HOLD ruleset_newer"], b""))
        self.assertEqual((len(worker.frames), decide._pend(self.dir / "idx", 1).read_bytes()), (1, stored))

    def test_the_rule_set_folder_is_read_before_every_frame(self) -> None:
        """Records placed in the folder count from the next frame, and a removed one stops being presented.  Each entry is
        read by itself, every time: one that is not a file, or another tenant's record, is skipped, named and logged once.
        An entry whose look-up is denied, or a file that cannot be read or does not decode (locked, torn, empty or junk
        put there by rename), holds every frame ``ruleset_file_bad``, logged once, and an authority built again on the
        folder (a restart) gives the same, until the file is fixed or removed: nothing read earlier stands in for it.  A
        configured folder that is not there or cannot be listed holds every frame ``ruleset_folder_missing``, logged
        once, until it is back.  An empty folder path, or one naming the current directory, is refused when the
        authority is built."""
        for empty in ("", ".", "./", ".\\", Path(".")):
            with self.subTest(path=empty), self.assertRaisesRegex(ValueError, "empty path"):
                au.tenant(self.dir / "tenant.floor", [_Producer()], ruleset_folder=empty)
        folder = self.dir / "rulesets"
        folder.mkdir()
        tenant = au.tenant(self.dir / "tenant.floor", [_Producer()], ruleset_folder=folder)
        worker, read, is_file, locked, denied = _Worker(), decide._record_file, Path.is_file, set(), set()

        def record_file(path):
            if path.name in locked:
                raise PermissionError(path)
            return read(path)

        def stat(path, *a, **k):
            if path.name in denied:
                raise PermissionError(path)
            return is_file(path, *a, **k)
        self.enterContext(mock.patch.object(decide, "_record_file", record_file))
        self.enterContext(mock.patch.object(Path, "is_file", stat))

        def sent(name, authority=tenant):
            ans = self._decide(worker, authority, name)
            return decide._requests(worker.frames[-1])[4] if ans.digest else ans.lines[0].split(" HOLD ", 1)[1]
        self.assertEqual(sent("empty"), [])
        (folder / "first.rec").write_bytes(RUN)
        (folder / "sub").mkdir()
        (folder / "theirs.rec").write_bytes(ra.sign(rs.with_(RUN_DOC, tenant=fx.OTHER)))
        with self.assertLogs(decide.LOG, "WARNING") as logs:
            self.assertEqual(sent("placed"), [RUN])
        self.assertEqual((len(logs.output), tenant.set_aside), (2, {"sub": "not_a_file", "theirs.rec": "other_tenant"}))
        for name in ("sub", "theirs.rec"):
            self.assertIn(name, " ".join(logs.output))
        with self.assertNoLogs(decide.LOG, "WARNING"):
            self.assertEqual(sent("again"), [RUN])
        (folder / "later.rec").write_bytes(V2)
        locked.add("later.rec")  # held by another program: skipped, it would lift the ruleset_newer it causes
        junk = self.dir / "junk.tmp"
        cases = (("locked", "later.rec", lambda: None), ("unreadable", "first.rec", lambda: locked.add("first.rec")),
                 ("look-up denied", "first.rec", lambda: denied.add("first.rec")),
                 ("torn", "first.rec", lambda: (folder / "first.rec").write_bytes(RUN[:-9])),
                 ("emptied", "first.rec", lambda: (folder / "first.rec").write_bytes(b"")),
                 ("junk by rename", "junk.rec", lambda: (junk.write_bytes(b"not a record"), os.replace(junk, folder / "junk.rec"))))
        for name, file, spoil in cases:
            with self.subTest(name):
                spoil()
                try:
                    with self.assertLogs(decide.LOG, "WARNING") as logs:
                        self.assertEqual(sent(name), "ruleset_file_bad")
                    self.assertIn(file, logs.output[0])
                    with self.assertNoLogs(decide.LOG, "WARNING"):
                        self.assertEqual(sent(name + " again"), "ruleset_file_bad")
                    with self.assertLogs(decide.LOG, "WARNING"):
                        restarted = au.tenant(self.dir / "tenant.floor", [_Producer()], ruleset_folder=folder)
                    self.assertEqual(sent(name + " restarted", restarted), "ruleset_file_bad")
                    if file == "later.rec":
                        locked.clear()
                        self.assertEqual(sent("readable"), "ruleset_newer")
                finally:  # fixed or removed, whatever the case found
                    locked.clear()
                    denied.clear()
                    for gone in ("later.rec", "junk.rec"):
                        (folder / gone).unlink(missing_ok=True)
                    (folder / "first.rec").write_bytes(RUN)
                self.assertEqual(sent(name + " fixed"), [RUN])
        (folder / "first.rec").unlink()
        self.assertEqual(sent("removed"), [])
        for path in folder.iterdir():
            path.rmdir() if path.is_dir() else path.unlink()
        folder.rmdir()
        with self.assertLogs(decide.LOG, "WARNING") as logs:
            self.assertEqual(sent("gone"), "ruleset_folder_missing")
        self.assertIn("ruleset_folder_missing", logs.output[0])
        with self.assertNoLogs(decide.LOG, "WARNING"):
            self.assertEqual(sent("still gone"), "ruleset_folder_missing")
        folder.mkdir()
        self.assertEqual(sent("back"), [])
        with self.assertLogs(decide.LOG, "WARNING"):
            again = au.tenant(self.dir / "tenant.floor", [_Producer()], ruleset_folder=self.dir / "never made")
        self.assertEqual(sent("at start", again), "ruleset_folder_missing")

    def test_copies_that_do_not_nest_hold_a_first_record(self) -> None:
        """A first record whose copies' signers do not nest: the shard would admit it, so its frame HOLDs ``ruleset_copies``."""
        with self.assertLogs(decide.LOG, "WARNING"):
            tenant = self._tenant(rulesets=[RUN, ra.sign(RUN_DOC, ("p1", "p3"))])
        worker = _Worker()
        held = self._decide(worker, tenant)
        self.assertEqual(([x.split(" ", 1)[1] for x in held.lines], held.digest, worker.frames), (["HOLD ruleset_copies"], b"", []))

    def _decided(self, records, rs, name):
        """(answer, worker) of a first frame on a shard holding rule set ``rs``, the tenant given ``records``."""
        (self.dir / "tenant.floor").unlink(missing_ok=True)
        tenant, worker = self._tenant(self._sealed(0, 0, 0, 1, rs), rulesets=records), _Worker()
        worker.rsv, worker.rs = 1, rs
        return self._decide(worker, tenant, name), worker

    def _presented(self, records, name):
        """The records the first frame presents on a shard holding ``RUN``, the tenant given ``records``."""
        return decide._requests(self._decided(records, RUN_ID, name)[1].frames[0])[4]

    def test_an_entry_that_is_not_a_record_is_logged_and_skipped(self) -> None:
        """Review round 1, finding 8: an entry that does not decode as a record, of any type, is logged and skipped at
        construction, never raised; the other records are kept."""
        with self.assertLogs(decide.LOG, "WARNING") as logs:
            self.assertEqual(self._presented([None, "text", 7, b"not a record", RUN], "idx"), [RUN])
        self.assertEqual(len(logs.records), 4)

    def _seal_one(self):
        """A request decided on shard 0 at rule-set version 1 (``RUN``), its answer filed under its retry key as a seal
        files it (``ShardProducer.answered``): (tenant, shards, worker, request, the filed answers)."""
        shards = (self._sealed(0, 0, 0, 1, RUN_ID), self._sealed(1, 0, 0, 1, RUN_ID))
        filed: dict[bytes, tuple] = {}
        shards[0].answered, shards[0].vouched = filed.get, lambda record, signature: signature == b""  # the fake's vouch
        tenant, worker = self._tenant(*shards, rulesets=[RUN]), _Worker()
        worker.rsv, worker.rs = 1, RUN_ID
        r = req(*["5:1 x"])
        ans = self._run(tenant, worker, r)
        self.assertEqual(decide._requests(worker.frames[0])[4], [RUN])
        filed[ans.retry] = (b"checkpoint", (b"token",), ((),))
        return tenant, shards, worker, r, filed

    def _run(self, tenant, worker, r):
        return decide.decide(NO_FEEDS, 0, tenant._shards[0], [r], self.dir / "idx", worker, GRANT, KEYS, tenant)

    def test_a_sealed_answer_is_found_whatever_rule_set_record_the_retry_carries(self) -> None:
        """Review round 1, findings 1 and 4: a sealed answer is filed and found under the key of its requests, grant and
        bypasses alone, the key of before rule-set records were presented.  With the same rule set carrying more
        signatures, with an authority built without the records (a restart), and after another shard seals version 2,
        the exact retry is given the first answer and nothing is decided again."""
        _, shards, worker, r, filed = self._seal_one()
        first = list(filed.values())[0]
        for name, records, rise in (("more signatures", [MORE], False), ("no records", [], False), ("version 2", [RUN, V2], True)):
            with self.subTest(name):
                if rise:
                    shards[1].record = self._record(0, 0, 2, V2_ID)
                again = self._tenant(*shards, rulesets=records)
                self.assertEqual((self._run(again, worker, r).sealed, len(worker.frames)), (first, 1))
        self.assertEqual(again.raise_floors(0, 0)[2:], (2, V2_ID))
        body = gate.encode_decide_request(r)  # filed under the key a frame without records had, byte for byte
        self.assertEqual(list(filed), [hashlib.sha3_256(b"RR/GATE/RETRY-KEY/v2\x00" + _le(1, 4) + _le(len(body), 4) + body
                                                        + _le(len(GRANT), 4) + GRANT + _le(0, 4)).digest()])

    def test_a_broken_floor_file_never_blocks_a_sealed_answer(self) -> None:
        """Review round 1, finding 2: the sealed answer is looked up before any floor is read, so a corrupt floor file
        still gives the exact retry its first answer; any other request is refused ``tenant_floor``."""
        tenant, _, worker, r, filed = self._seal_one()
        path = self.dir / "tenant.floor"
        path.write_bytes(bytes(decide._SIZE) * 2)  # two whole records whose checks fail
        self.assertEqual(self._run(tenant, worker, r).sealed, list(filed.values())[0])
        self.assertFloorRefused(path, self._run, tenant, worker, req(*["5:1 x"]))
        self.assertEqual(len(worker.frames), 1)

    def test_a_retry_with_more_signatures_on_its_record_is_decided_as_stored(self) -> None:
        """Review round 1, finding 4: a stored frame is compared by the digest of the rule set it presents, so the same
        requests under the same rule set carrying more signatures are decided as stored, its frame sent byte for byte."""
        shards = (self._sealed(0, 0, 0, 1, RUN_ID),)
        shards[0].vouched = lambda record, signature: signature == b""  # the fake producer's vouch
        worker, r = _Worker(), req(*["5:1 x"])
        worker.rsv, worker.rs = 1, RUN_ID
        self.assertTrue(self._run(self._tenant(*shards, rulesets=[RUN]), worker, r).digest)
        ans = self._run(self._tenant(*shards, rulesets=[MORE]), worker, r)
        self.assertTrue(ans.digest)
        self.assertEqual((ans.frame, worker.frames), (worker.frames[0], [worker.frames[0]] * 2))
        self.assertEqual(decide._requests(ans.frame)[4], [RUN])

    class Asserted(_Worker):  # admits the floors the frame asserts
        closed = 0

        def run_frame(self, directory, shard, data, leaves=None):
            _, floor, self.epoch, self.rsv, self.rs = carried(data)
            self.floor = floor or 0
            return super().run_frame(directory, shard, data, leaves)

        def close(self) -> None:
            self.closed += 1

    def _seals(self, *shards, worker=None, name="idx", **kw):
        """(tenant, worker, run): ``run(request, seal)`` decides one request on the first of ``shards`` under ``seal``."""
        shards[0].vouched = lambda record, signature: signature == b""  # the fake producer's vouch
        tenant, worker = self._tenant(*shards, **kw), worker or _Worker()
        return tenant, worker, lambda r, s: decide.decide(NO_FEEDS, 0, shards[0], [r], self.dir / name, worker, GRANT, KEYS,
                                                          tenant, seal=s)

    def test_another_requests_stored_frame_the_floors_have_passed_is_voided(self) -> None:
        """Review round 1, finding 6: another request's stored frame decided under floors the tenant has since passed can
        never seal; it is voided as these requests' own would be (the engine reopened, its file dropped) and this request
        is decided in its place on that number.  Review round 2, LOW 2: the same when the stored frame was decided under
        another program's seal, since it is voided, never sealed."""
        for name, (first, then) in (("unsealed", (None, None)), ("another program", (("program-a", 1), ("program-b", 2)))):
            with self.subTest(name):
                (self.dir / "tenant.floor").unlink(missing_ok=True)
                shards = (self._sealed(0, 0, 0), self._sealed(1, 0, 0))
                _, worker, run = self._seals(*shards, worker=self.Asserted(), name=name)
                self.assertTrue(run(req(*["5:1 x"]), first).digest)  # decided at serial 0 and never sealed
                shards[1].record = self._record(5, 0)  # another shard seals serial 5
                ans = run(req(*["5:1 y"]), then)
                self.assertEqual((bool(ans.digest), int.from_bytes(ans.adds[200:208], "big"), worker.closed), (True, 5, 1))
                self.assertEqual([carried(f)[1] for f in worker.frames], [0, 0, 5])
                stored = decide._pending(decide._pend(self.dir / name, 1), shards[0], 1)
                self.assertEqual((stored.frame, stored.program), (worker.frames[2], then and then[0]))

    def test_a_stored_frame_is_never_sent_with_a_first_record_the_folder_no_longer_gives(self) -> None:
        """A frame stored while no shard holds a rule set presents the first record presented then.  With that record
        removed from the folder, or another first record in its place, it is not sent, as its own retry or before another
        request with a seal: the lines HOLD ``ruleset_changed``, logged, and the file stays.  With the record back it is
        decided as stored.  The other way, a frame stored presenting no record is decided as stored after a record is
        placed: it takes up nothing."""
        folder = self.dir / "rulesets"
        folder.mkdir()

        def place(*records):
            for path in folder.iterdir():
                path.unlink()
            for n, x in enumerate(records):
                (folder / f"r{n}").write_bytes(x)
        place(RUN)
        shards = (self._sealed(0, 0, 0), self._sealed(1, 0, 0))
        _, worker, run = self._seals(*shards, ruleset_folder=folder)
        r = req(*["5:1 x"])
        self.assertTrue(run(r, None).digest)  # decided presenting RUN, never sealed
        pend = decide._pend(self.dir / "idx", 1)
        stored = pend.read_bytes()
        for name, records in (("removed", ()), ("another first record", (OTHER,))):
            with self.subTest(name):
                place(*records)
                for request, seal in ((r, None), (req(*["5:1 y"]), (fx.PROGRAM, 1))):
                    with self.assertLogs(decide.LOG, "WARNING") as logs:
                        ans = run(request, seal)
                    self.assertIn(RUN_ID.hex(), logs.output[-1])
                    self.assertEqual(([x.split(" ", 1)[1] for x in ans.lines], ans.digest), (["HOLD ruleset_changed"], b""))
                self.assertEqual((len(worker.frames), pend.read_bytes()), (1, stored))
        place(RUN)
        self.assertTrue(run(r, None).digest)
        self.assertEqual(worker.frames[1], worker.frames[0])  # decided as stored
        place()
        (self.dir / "tenant.floor").unlink()
        _, worker, run = self._seals(*shards, ruleset_folder=folder, name="none")
        r = req(*["5:1 z"])
        self.assertTrue(run(r, None).digest)  # stored presenting none
        place(RUN)
        self.assertTrue(run(r, None).digest)
        self.assertEqual([decide._requests(f)[4] for f in worker.frames], [[], []])

    def test_a_stored_frame_with_a_first_record_is_held_whatever_floors_rose_since(self) -> None:
        """While the tenant holds no rule set, a stored frame presenting a first record the folder no longer gives is held
        ``ruleset_changed`` even when the tenant's grant serial or key-set epoch rose since it was stored: its answer
        carries the grant's serial, not the frame's, so it could still seal and take the record up.  So too when its
        answer would be passed by serial (voiding it would already have carried the record into the floors).  As its own
        retry and before another request's seal alike: nothing is sent, the file stays and no floor moves."""
        cases = {"serial": ((0, 0), (3, 0), (3, 0)), "epoch": ((0, 0), (0, 1), (0, 1)), "passed by serial": ((5, 0), (6, 0), (5, 0))}
        for name, (then, now, answer) in cases.items():
            for other, seal in ((False, None), (True, (fx.PROGRAM, 1))):
                with self.subTest(name, other=other):
                    where = f"{name}-{other}"
                    (self.dir / "tenant.floor").unlink(missing_ok=True)
                    folder = self.dir / f"rulesets-{where}"
                    folder.mkdir()
                    (folder / "r0").write_bytes(RUN)
                    shards = (self._sealed(0, *then), self._sealed(1, *then))
                    tenant, worker, run = self._seals(*shards, ruleset_folder=folder, name=where)
                    worker.floor, worker.epoch = then
                    r = req(*["5:1 x"])
                    self.assertTrue(run(r, None).digest)  # decided presenting RUN, never sealed
                    pend = decide._pend(self.dir / where, 1)
                    stored = pend.read_bytes()
                    (folder / "r0").unlink()
                    shards[1].record = self._record(*now)  # another shard seals under a newer grant or key set, no rule set
                    (worker.floor, worker.epoch), worker.rsv, worker.rs = answer, 1, RUN_ID  # the engine would take RUN up
                    with self.assertLogs(decide.LOG, "WARNING") as logs:
                        ans = run(req(*["5:1 y"]) if other else r, seal)
                    self.assertIn(RUN_ID.hex(), logs.output[-1])
                    self.assertEqual(([x.split(" ", 1)[1] for x in ans.lines], ans.digest), (["HOLD ruleset_changed"], b""))
                    self.assertEqual((len(worker.frames), pend.read_bytes(), tenant.raise_floors(0, 0)),
                                     (1, stored, (*now, 0, flatchain.ZERO)))

    class TakesUp(Asserted):  # admits the floors the frame asserts, and takes up the first record it presents
        lose = False  # the next answer is lost after the engine decided it

        def run_frame(self, directory, shard, data, leaves=None):
            presented = decide._requests(data)[4]
            _, floor, self.epoch, self.rsv, self.rs = carried(data)
            self.floor = floor or 0
            if not self.rsv and presented:
                self.rsv, self.rs = 1, decide.rulecodec.digest(presented[0])
            out = _Worker.run_frame(self, directory, shard, data, leaves)
            if self.lose:
                self.lose = False
                raise RuntimeError("the answer was lost")
            return out

    def test_a_stored_frame_with_a_withdrawn_first_record_forks_once_the_tenant_holds_another(self) -> None:
        """Once another shard took up the record now in the folder, a stored frame presenting the withdrawn first record
        is not held ``ruleset_changed``: it is sent, its answer (the same version under another digest) HOLDs
        ``ruleset_fork`` and its file is dropped, the floors keep the tenant's record, and a frame presenting that record
        is decided in the same call, as its own retry and before another request's seal alike."""
        other_id = decide.rulecodec.digest(OTHER)
        for other, seal in ((False, None), (True, (fx.PROGRAM, 1))):
            with self.subTest(other=other):
                where = f"taken-{other}"
                (self.dir / "tenant.floor").unlink(missing_ok=True)
                folder = self.dir / f"rulesets-{where}"
                folder.mkdir()
                (folder / "r0").write_bytes(RUN)
                shards = (self._sealed(0, 0, 0), self._sealed(1, 0, 0))
                tenant, worker, run = self._seals(*shards, worker=self.TakesUp(), ruleset_folder=folder, name=where)
                worker.lose, r = True, req(*["5:1 x"])
                with self.assertRaises(RuntimeError):
                    run(r, None)  # decided presenting RUN, its outcome unknown: stored, no floor moved
                pend, worker.closed = decide._pend(self.dir / where, 1), 0
                self.assertEqual(tenant.raise_floors(0, 0)[2:], (0, flatchain.ZERO))
                (folder / "r0").unlink()
                (folder / "r1").write_bytes(OTHER)
                shards[1].record = self._record(0, 0, 1, other_id)  # another shard took up OTHER
                with self.assertLogs(decide.LOG, "WARNING") as logs:
                    ans = run(req(*["5:1 y"]) if other else r, seal)
                self.assertIn("ruleset_fork", " ".join(logs.output))
                self.assertTrue(ans.digest)
                self.assertEqual([decide._requests(f)[4] for f in worker.frames], [[RUN], [RUN], [OTHER]])
                self.assertEqual((flatchain.floors_of(ans.adds)[2:], tenant.raise_floors(0, 0)[2:], worker.closed),
                                 ((1, other_id), (1, other_id), 1))
                self.assertEqual(decide._pending(pend, shards[0], 1).frame, worker.frames[2])

    def test_another_requests_stored_frame_behind_in_one_floor_is_decided_and_voided(self) -> None:
        """Another request's stored frame whose floors are behind the tenant's in any one place goes to the engine and is
        voided once its answer is passed, even when another of its floors is ahead (a lower grant serial, a higher key-set
        epoch), and when its rule set is the tenant's version under another digest; this request is then decided.  The
        floors never fall below what the voided answer asserted (a floor file put back lower is the only way to be ahead)."""
        fork = bytes([7]) * 64
        cases = {"serial behind, epoch ahead": ((0, 1, 0, flatchain.ZERO), (5, 0, 0, flatchain.ZERO), (5, 1, 0, flatchain.ZERO)),
                 "same version, another digest": ((0, 0, 1, RUN_ID), (0, 0, 1, fork), (0, 0, 1, fork))}
        for name, (then, now, after) in cases.items():
            with self.subTest(name):
                (self.dir / "tenant.floor").unlink(missing_ok=True)
                shards = (self._sealed(0, *then), self._sealed(1, *then))
                _, worker, run = self._seals(*shards, worker=self.Asserted(), name=name)
                self.assertTrue(run(req(*["5:1 x"]), None).digest)  # decided under ``then`` and never sealed
                (self.dir / "tenant.floor").unlink()
                for shard in shards:
                    shard.record = self._record(*now)
                _, _, run = self._seals(*shards, worker=worker, name=name)  # the tenant's floors are now ``now``
                ans = run(req(*["5:1 y"]), None)
                self.assertEqual((bool(ans.digest), flatchain.floors_of(ans.adds), worker.closed), (True, after, 1))
                self.assertEqual([carried(f)[1:] for f in worker.frames], [then, then, after])

    def test_another_programs_stored_frame_that_can_still_seal_is_refused(self) -> None:
        """Review round 2, LOW 2: the program check stays for a stored frame that can still seal: under another
        program's seal it is refused ``pending_bad`` and nothing is prepared to seal."""
        shard = self._sealed(0, 0, 0)
        _, _, run = self._seals(shard)
        self.assertTrue(run(req(*["5:1 x"]), ("program-a", 1)).digest)
        shard.prepared = None
        with self.assertRaisesRegex(decide.GateDecideError, "^pending_bad:"):
            run(req(*["5:1 y"]), ("program-b", 2))
        self.assertIsNone(shard.prepared)

    def test_an_unsealed_retry_after_a_restart_with_other_records_is_decided_as_stored(self) -> None:
        """Review round 2, LOW 1: an unsealed stored frame is these requests' by its retry key and the rule set it
        asserts, not by the records presented: after a restart with no records, or only another rule set's, the retry is
        decided as stored, its frame sent byte for byte."""
        shards = (self._sealed(0, 0, 0, 1, RUN_ID),)
        shards[0].vouched = lambda record, signature: signature == b""  # the fake producer's vouch
        worker, r = _Worker(), req(*["5:1 x"])
        worker.rsv, worker.rs = 1, RUN_ID
        self.assertTrue(self._run(self._tenant(*shards, rulesets=[RUN]), worker, r).digest)
        for name, records in (("no records", []), ("another rule set", [OTHER])):
            with self.subTest(name):
                ans = self._run(self._tenant(*shards, rulesets=records), worker, r)
                self.assertEqual((bool(ans.digest), ans.frame, worker.frames[-1]), (True, worker.frames[0], worker.frames[0]))
                self.assertEqual(decide._requests(ans.frame)[4], [RUN])
        self.assertEqual(len(worker.frames), 3)

    def test_a_floor_file_corrupt_at_open_serves_sealed_answers_and_decides_nothing(self) -> None:
        """Review round 2, LOW 5: an authority opened over a corrupt floor file opens, and logs it: the exact retry of a
        sealed answer is given it, and every frame that needs the floors is refused ``tenant_floor``, nothing sent."""
        _, shards, worker, r, filed = self._seal_one()
        path = self.dir / "tenant.floor"
        path.write_bytes(bytes(decide._SIZE) * 2)  # two whole records whose checks fail
        with self.assertLogs(decide.LOG, "ERROR") as logs:
            opened = self._tenant(*shards, rulesets=[RUN, V2])
        self.assertIn(str(path), logs.output[0])
        self.assertEqual(self._run(opened, worker, r).sealed, list(filed.values())[0])
        self.assertFloorRefused(path, self._run, opened, worker, req(*["5:1 y"]))
        self.assertEqual((len(worker.frames), path.read_bytes()), (1, bytes(decide._SIZE) * 2))

    def test_provision_never_overwrites_a_whole_record_that_fails_its_check(self) -> None:
        other = self.dir / "other.floor"
        stranger = _Producer()
        stranger.tenant = "other-tenant"
        au.tenant(other, [stranger], tenant_id="other-tenant")
        theirs, path = other.read_bytes(), self.dir / "mine.floor"
        legacy = bytes(12) + bytes([9]) * 32  # a 44-byte record of the older format: a short file that is not the start of a record
        for name, data in (("another tenant's", theirs), ("flipped byte", bytes([theirs[0] ^ 1]) + theirs[1:]), ("long", theirs + bytes(3)),
                           ("legacy 44 bytes", legacy), ("short and foreign", bytes([1]) * 20)):
            with self.subTest(name):
                path.write_bytes(data)
                self.assertFloorRefused(path, decide.TenantAuthority.provision, path, fx.TENANT, [_Producer()])
                self.assertEqual(path.read_bytes(), data)  # left unchanged, byte for byte

    def test_a_crash_inside_provision_is_completed_by_the_next_provision(self) -> None:
        path = self.dir / "crashed.floor"
        shards = [self._sealed(0, 5, 1)]
        decide.TenantAuthority.provision(self.dir / "whole.floor", fx.TENANT, shards)
        start = (self.dir / "whole.floor").read_bytes()[:30]  # the first record of this tenant's shards, cut short
        for torn in (b"", bytes([1]) * 7, start):  # created but nothing written, or the first record cut short
            with self.subTest(len(torn)):
                path.write_bytes(torn)
                with self.assertLogs(decide.LOG, "ERROR"):  # an open logs it and decides nothing
                    opened = decide.TenantAuthority(slots.Slots({}), fx.TENANT, path, shards)
                self.assertFloorRefused(path, opened.raise_floors, 0, 0)
                decide.TenantAuthority.provision(path, fx.TENANT, shards)
                self.assertEqual(decide.TenantAuthority(slots.Slots({}), fx.TENANT, path, shards).raise_floors(0, 0)[:2], (5, 1))
                path.unlink()

    def test_a_rolled_back_floor_file_is_raised_to_every_shards_sealed_record(self) -> None:
        path = self.dir / "tenant.floor"
        shards = [self._sealed(0, 7, 1), self._sealed(1, 3, 2)]
        zero = (self._tenant(self._sealed(0, 0, 0), self._sealed(1, 0, 0)), path.read_bytes())[1]
        self.assertEqual(self._tenant(*shards).raise_floors(0, 0)[:2], (7, 2))  # the open takes the highest of each
        path.write_bytes(zero)  # an older copy put back
        tenant, worker = self._tenant(*shards), _Worker()
        self.assertEqual(tenant.raise_floors(0, 0)[:2], (7, 2))
        self._decide(worker, tenant)
        self.assertEqual(carried(worker.frames[-1])[1:3], (7, 2))
        path.write_bytes(zero)  # put back while open, and the other shard seals 9: every shard's sealed record raises what is sent
        shards[1].record = self._record(9, 2)
        self._decide(worker, tenant, "idx2")
        self.assertEqual(carried(worker.frames[-1])[1:3], (9, 2))
        self.assertEqual(tenant.raise_floors(0, 0)[:2], (9, 2))  # the file is rewritten upward

    def test_a_shard_of_another_tenant_is_refused_at_open(self) -> None:
        shard = self._sealed(0, 1, 0)
        shard.tenant = "other-tenant"
        with self.assertRaisesRegex(decide.GateDecideError, "foreign_tenant"):
            self._tenant(shard)


class LeafOrderTests(unittest.TestCase):
    """The answer must hold exactly one leaf per request, in the batch's order: a reordered or short answer is refused."""

    class Paying(_Worker):
        """Answers each request with a leaf, in the order ``pick`` gives."""

        def __init__(self, requests, pick) -> None:
            super().__init__()
            self.requests, self.pick = requests, pick

        def run_frame(self, directory: str, shard: int, data: bytes, leaves: list[bytes] = ()) -> bytes:
            return super().run_frame(directory, shard, data, [leaf(self.requests[i], data) for i in self.pick])

    def _decide(self, pick):
        requests = [req(*["5:1 x"]), req(*["6:1 x"])]
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return decide.decide(NO_FEEDS, 0, PROD, requests, Path(tmp.name) / "idx", self.Paying(requests, pick), GRANT, KEYS, TENANT)

    def test_one_leaf_per_request_in_order_is_taken(self) -> None:
        self.assertEqual(len(self._decide([0, 1]).pays), 2)

    def test_a_reordered_answer_is_refused(self) -> None:
        with self.assertRaisesRegex(decide.GateDecideError, "rules_refused"):
            self._decide([1, 0])

    def test_a_dropped_row_is_refused(self) -> None:
        with self.assertRaisesRegex(decide.GateDecideError, "rules_refused"):
            self._decide([0])


class DecideCutoverTests(unittest.TestCase):
    """The history index has no cutover: a sealed quarantine is refused, a torn one HOLDs its shard, and other shards decide."""

    def test_a_sealed_quarantine_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(decide.GateDecideError, "flat_cut"):
            cut = _CutProducer()
            decide.decide(NO_FEEDS, 0, cut, [req(*["5:1 x"])], Path(tmp) / "idx", _Worker(), GRANT, KEYS, au.tenant(Path(tmp) / "f", [cut]))

    def test_a_torn_qb_holds_that_shard_only(self) -> None:
        """Two real shard stores: shard 3's cutover row loses qb (trigger dropped), so it HOLDs ``quar_torn``; shard 4 decides."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "x"

        def opener(k: int):
            d = path.parent / str(k)
            d.mkdir()
            handle, held, cert = fx.custody(str(d))
            return lambda: self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT,
                                                              shard_id=k, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                              payer_newest=gate.ZERO_DIGEST,
                                                              counter=TestOnlyCounter(d / "s.counter"), floors=lambda: (0, 0, 0, bytes(64))))
        torn_open, other_open = opener(fx.SHARD), opener(fx.SHARD + 1)
        p = self._chained(torn_open(), ((b"Q" * 9, bytes(64)), None))
        p.close()
        with contextlib.closing(sqlite3.connect(path.parent / str(fx.SHARD) / "s.sqlite3")) as db:
            db.executescript("DROP TRIGGER batches_quar; UPDATE batches SET qb = NULL WHERE cut IS NOT NULL;")
        torn, fresh = torn_open(), other_open()
        tenant = au.tenant(path.with_name("tenant.floor"), [torn, fresh])
        ans = decide.decide(NO_FEEDS, 0, torn, [req(*["5:1 x"])], path.with_name("idx"), _Worker(), GRANT, KEYS, tenant)
        self.assertEqual(list(ans.lines), ["pay-0001 HOLD quar_torn"])
        other = decide.decide(NO_FEEDS, 0, fresh, [req(*["5:1 x"])], path.with_name("idx"), _Worker(), GRANT, KEYS, tenant)
        self.assertEqual([r.outcome for r in other.recs], ["ALLOW"])

    @staticmethod
    def _chained(p: producer.ShardProducer, cuts, serial=0, admit=contextlib.nullcontext,
                 lock=contextlib.nullcontext) -> producer.ShardProducer:
        """Seal one batch per entry of ``cuts`` whose ``adds`` step the previous head to the batch's state digest, from the
        genesis the first frame's ``flat init`` names (what ``authority`` checks before it trusts the record).  ``serial``: the
        grant serial of every record, or one per batch; ``admit``: the context each reservation is written inside."""
        pin = au.genesis()[0]
        head = flatchain.genesis(p.shard, 0, pin)
        for i, cut in enumerate(cuts):
            adds = TenantAuthorityTests._record(serial[i] if isinstance(serial, (tuple, list)) else serial, 0, pin=pin) + ROOT
            head = flatchain.step_adds(head, adds)
            frame = first_frame(p.shard, pin)
            ans = decide.Answer((), head, adds, None, None, fx.D[1], 0, 1, tuple(fx.batch_pays(1, i)), fx.D[6], frame)
            p.prepared = ans
            p.commit(fx.PROGRAM, ans, fx.NOW + i, cut, admit, lock)
        return p

    def test_a_seal_failure_closes_the_producer_and_a_reopen_below_the_tenant_floor_voids_the_reservation(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "a").mkdir()
        keys = fx.custody(str(root / "a"))  # one key for every open of the shard

        def opener(k: int, floors=lambda: (0, 0, 0, bytes(64))):
            d = root / "a"
            handle, held, cert = keys
            return lambda: self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=k,
                                                              epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                              payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
                                                              floors=floors))
        a, b = opener(fx.SHARD)(), _Producer()  # shard B stands in: it has sealed serial 9
        b.shard, b.record = fx.SHARD + 1, TenantAuthorityTests._record(9, 0)
        tenant = au.tenant(root / "tenant.floor", [a, b])
        with mock.patch.object(producer.signer, "seal", side_effect=producer.signer.GateSignerError("custody_down")):
            with self.assertRaisesRegex(producer.signer.GateSignerError, "custody_down"):
                self._chained(a, (None,), serial=5)  # decided under serial 5; the seal fails and leaves its reservation
        with self.assertRaisesRegex(producer.GateProducerError, "producer_closed"):
            a.authority()
        self.assertEqual(tenant.raise_floors(0, 0)[0], 9)
        cold = lambda: decide.TenantAuthority.floors_in(root / "tenant.floor", fx.TENANT)  # a restart: no authority, only the file
        with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
            opener(fx.SHARD, floors=cold)()  # must not release the batch
        again = opener(fx.SHARD, floors=cold)()  # the reservation is gone: the batch is decided again
        self.assertEqual((again.authority(), again.published()), (None, []))

    def test_a_reopen_checks_a_reservation_against_the_shards_own_sealed_record_too(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        handle, held, cert = fx.custody(str(d))
        open_ = lambda: self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                                           epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                                           payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
                                                           floors=lambda: (0, 0, 0, bytes(64))))  # a floor file rolled back to nothing
        a, calls = open_(), []

        @contextlib.contextmanager
        def crash_after_reserving():
            yield
            calls.append(1)
            if len(calls) > 1:  # the second reservation is written; its seal never starts
                raise OSError("power lost")
        with self.assertRaises(OSError):
            self._chained(a, (None, None), serial=(7, 5), admit=crash_after_reserving)  # sealed at serial 7, then a reservation at 5
        a.close()
        with self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
            open_()

    def test_a_floor_raised_between_the_reservation_and_its_seal_voids_it_as_a_reopen_would(self) -> None:
        """Final review L1: another shard's decide raises the tenant floor to 6 after this batch was admitted under serial 5
        but before its seal.  The seal reads the floor again: nothing is signed, the reservation is voided and the commit
        refuses ``reservation_below_floor``, as a crash and reopen at that point would; the shard serves on, and the batch
        decided again under serial 6 seals."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        handle, held, cert = fx.custody(str(d))
        floor = d / "tenant.floor"
        a = self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                               epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                               payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
                                               floors=lambda: decide.TenantAuthority.floors_in(floor, fx.TENANT)))
        b = _Producer()
        b.shard, b.record = fx.SHARD + 1, TenantAuthorityTests._record(0, 0)
        tenant = au.tenant(floor, [a, b])

        @contextlib.contextmanager
        def raised_after_admission():
            yield
            tenant.raise_floors(6, 0)  # shard B's decide, after the reservation is written
        with mock.patch.object(producer.signer, "seal", wraps=producer.signer.seal) as seal, \
                self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
            self._chained(a, (None,), serial=5, admit=raised_after_admission)
        seal.assert_not_called()
        self.assertEqual((a.authority(), a.published(), a._db.execute("SELECT count(*) FROM batches").fetchone()[0]), (None, [], 0))
        self._chained(a, (None,), serial=6)
        self.assertEqual(flatchain.floors_of(a.authority())[0], 6)

    def _floor_producer(self, d: Path, floors=None):
        handle, held, cert = fx.custody(str(d))
        floor = d / "tenant.floor"
        a = self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                               epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                               payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
                                               floors=floors or (lambda: decide.TenantAuthority.floors_in(floor, fx.TENANT))))
        return a, au.tenant(floor, [a])

    def test_a_floor_raised_while_signing_is_caught_before_the_signature_is_stored(self) -> None:
        """Final review M1: another shard raises the floor during the Lean signing.  The last floor check, under the floor lock
        just before the store, voids the reservation: no signature is stored, the counter does not move, and the batch decided
        again under the new floor seals."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, tenant = self._floor_producer(Path(tmp.name))
        seal = producer.signer.seal

        def raising(*args):
            out = seal(*args)
            tenant.raise_floors(6, 0)  # shard B's decide, while this shard signs
            return out
        with mock.patch.object(producer.signer, "seal", raising), \
                self.assertRaisesRegex(producer.GateProducerError, "reservation_below_floor"):
            self._chained(a, (None,), serial=5)
        self.assertEqual((a.published(), a._db.execute("SELECT count(*) FROM batches").fetchone()[0], a._counter.read()), ([], 0, None))
        self._chained(a, (None,), serial=6)
        self.assertEqual(len(a.published()), 1)

    def test_the_floor_lock_is_held_around_the_last_check_and_the_stored_signature(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, tenant = self._floor_producer(Path(tmp.name))
        held, inside = [], []

        @contextlib.contextmanager
        def lock():
            held.append(1)
            inside.append(True)
            try:
                yield
            finally:
                inside.append(False)
        increment = a._counter.increment
        a._counter.increment = lambda: (held.append(inside[-1]), increment())[1]
        self._chained(a, (None,), serial=5, lock=lock)
        self.assertEqual(held, [1, True])  # taken once, and the counter moved inside it

    def test_unreadable_floors_after_the_reservation_void_it_instead_of_orphaning_it(self) -> None:
        """Final review F2: ``floors()`` failing after the reservation voids it (nothing was signed) and raises the read error."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, tenant = self._floor_producer(Path(tmp.name), floors=mock.Mock(side_effect=OSError("floor file gone")))
        with mock.patch.object(producer.signer, "seal") as seal, self.assertRaisesRegex(OSError, "floor file gone"):
            self._chained(a, (None,), serial=5)
        seal.assert_not_called()
        self.assertEqual(a._db.execute("SELECT count(*) FROM batches").fetchone()[0], 0)

    def test_a_retry_finds_the_reservation_a_reported_commit_error_had_stored(self) -> None:
        """Final review L1: COMMIT lands but reports an error.  The retry looks for its own row by digest first, so the batch
        seals instead of failing on the unique digest and stalling the shard."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name))
        real, failed = a._db, []

        class Lying:
            in_transaction = property(lambda self: real.in_transaction)
            close = lambda self: real.close()

            def execute(self, sql, *args):
                out = real.execute(sql, *args)
                if sql == "COMMIT" and not failed:
                    failed.append(1)
                    raise sqlite3.OperationalError("disk I/O error")  # after the commit landed
                return out
        a._db = Lying()
        with mock.patch.object(producer.time, "sleep"):
            self._chained(a, (None,), serial=5)
        self.assertEqual((failed, len(a.published())), ([1], 1))

    def test_an_edited_authority_record_is_refused(self) -> None:
        """The newest record's floor bytes (adds[200:208]) are trusted only once the batch's adds step the chain to its digest."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        handle, held, cert = fx.custody(tmp.name)
        p = self._track(producer.ShardProducer(Path(tmp.name) / "s.sqlite3", mark_path=Path(tmp.name) / "s.mark", tenant_id=fx.TENANT,
                                               shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                               payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(Path(tmp.name) / "s.counter"), floors=lambda: (0, 0, 0, bytes(64))))
        self._chained(p, (None, None))
        self.assertEqual(p.authority(), au.genesis()[0] + bytes(flatchain.AUTH - 64))  # serial 0
        adds = bytes(p._db.execute("SELECT adds FROM batches ORDER BY id DESC LIMIT 1").fetchone()[0])
        p._db.execute("DROP TRIGGER batches_fixed")
        p._db.execute("UPDATE batches SET adds=? WHERE id=(SELECT max(id) FROM batches)", (adds[:200] + bytes(7) + bytes([9]) + adds[208:],))
        p._authority = (0, None)  # a fresh look at the stored bytes
        with self.assertRaisesRegex(producer.GateProducerError, "authority_unchained"):
            p.authority()
        p._db.execute("UPDATE batches SET adds=? WHERE id=(SELECT max(id) FROM batches)", (adds[:100],))  # adds that do not decode
        p._authority = (0, None)
        with self.assertRaisesRegex(producer.GateProducerError, "authority_unchained"):
            p.authority()

    def test_the_floor_lock_covers_the_check_and_the_reservation_not_the_seal(self) -> None:
        """Fault hunt item 6: a commit holds the tenant's floor lock from its floor check through its reservation (the pledge
        is signed inside it) and lets it go before the seal; the reservation is the admission, so a floor raised before it
        refuses the answer (``grant_floor_risen``) with nothing reserved, and one raised after it is a later admission."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        handle, held, cert = fx.custody(str(d))
        a = self._track(producer.ShardProducer(d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD,
                                               epoch=fx.EPOCH, handle=handle, link=held, cosign=fx.cosigner(),  key_cert=cert,
                                               payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
                                               floors=lambda: (0, 0, 0, bytes(64))))
        tenant = au.tenant(d / "tenant.floor", [a])
        pin, head = au.genesis()[0], None

        def answer(i: int, serial: int) -> decide.Answer:
            nonlocal head
            adds = TenantAuthorityTests._record(serial, 0, pin=pin) + ROOT
            head = flatchain.step_adds(head or flatchain.genesis(a.shard, 0, pin), adds)
            frame = first_frame(a.shard, pin)  # the genesis the authority record is checked from
            ans = decide.Answer((), head, adds, a.tip(), d / "idx", fx.D[1], 0, 1, tuple(fx.batch_pays(1, i)), fx.D[6], frame)
            a.prepared = ans
            return ans

        def held() -> bool:
            fd = os.open(f"{d / 'tenant.floor'}.lock", os.O_RDWR | os.O_BINARY)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                return False
            except OSError:
                return True
            finally:
                os.close(fd)
        seen, sign, seal = [], producer.signer.sign, producer.signer.seal
        with mock.patch.object(producer.signer, "sign", lambda *args: seen.append(("sign", held())) or sign(*args)), \
                mock.patch.object(producer.signer, "seal", lambda *args: seen.append(("seal", held())) or seal(*args)):
            decide.commit(a, fx.PROGRAM, answer(0, 5), fx.NOW, tenant)
        self.assertEqual(seen, [("sign", True), ("seal", False), ("sign", False)])  # the pledge, then the seal and its header
        self.assertEqual((len(a.published()), held()), (1, False))
        busy = answer(1, 5)  # final review L2: a lock that stays taken does not spend the answer
        with mock.patch.object(decide.msvcrt, "locking", side_effect=OSError("busy")), mock.patch.object(decide.time, "sleep"):
            with self.assertRaises(decide.GateDecideError) as caught:
                decide.commit(a, fx.PROGRAM, busy, fx.NOW + 1, tenant)
        self.assertEqual((caught.exception.args[0], a.prepared), ("tenant_floor_busy", busy))
        decide.commit(a, fx.PROGRAM, busy, fx.NOW + 1, tenant)  # the same answer, once the lock is free
        self.assertEqual((len(a.published()), a.prepared), (2, None))
        tenant.raise_floors(9, 0)  # another shard admitted serial 9
        late = answer(2, 5)
        with self.assertRaisesRegex(decide.GateDecideError, "grant_floor_risen"):
            decide.commit(a, fx.PROGRAM, late, fx.NOW + 2, tenant)
        self.assertEqual((a._db.execute("SELECT count(*) FROM batches").fetchone()[0], a.prepared, held()), (2, None, False))
        failing = answer(3, 9)  # final review M2: a database that fails every try of the reservation
        with mock.patch.object(producer.signer, "sign", side_effect=sqlite3.OperationalError("disk I/O error")) as sign,                 mock.patch.object(producer.time, "sleep"):
            with self.assertRaises(decide.MachineFault) as caught:
                decide.commit(a, fx.PROGRAM, failing, fx.NOW + 3, tenant)
        self.assertEqual((str(caught.exception), caught.exception.action, sign.call_count, a._db.execute("SELECT count(*) FROM batches").fetchone()[0]),
                         ("store_unavailable", "retry_later", producer._TRIES, 2))

    def _rows(self, a) -> int:
        return a._db.execute("SELECT count(*) FROM batches").fetchone()[0]

    def test_a_second_lock_that_fails_voids_the_reservation_and_leaves_the_producer_open(self) -> None:
        """Round 3 R1: nothing is signed yet, so a floor lock that fails at the seal's second acquisition voids the reservation
        and the machine fault passes as a true ``retry_later``; the producer is open and the batch decided again seals."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name))

        @contextlib.contextmanager
        def busy():
            raise decide.MachineFault("tenant_floor_busy", "floor")
            yield
        with self.assertRaises(decide.MachineFault):
            self._chained(a, (None,), serial=5, lock=busy)
        self.assertEqual((self._rows(a), a._closed, a._counter.read()), (0, False, None))
        self._chained(a, (None,), serial=5)
        self.assertEqual(len(a.published()), 1)

    def test_floors_unreadable_at_the_second_check_void_the_reservation_and_leave_the_producer_open(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name), floors=mock.Mock(side_effect=[(0, 0, 0, bytes(64)), decide.MachineFault("tenant_floor_unreadable", "f")]))
        with self.assertRaises(decide.MachineFault):
            self._chained(a, (None,), serial=5)
        self.assertEqual((self._rows(a), a._closed, a._counter.read()), (0, False, None))

    def _failing_db(self, a, fails: tuple[str, ...]) -> None:
        real = a._db

        class Failing:
            in_transaction = property(lambda self: real.in_transaction)
            close = lambda self: real.close()

            def execute(self, sql, *args):
                if sql.startswith(fails):
                    raise sqlite3.OperationalError("disk I/O error")
                return real.execute(sql, *args)
        a._db = Failing()

    def test_a_database_error_at_the_first_check_is_retry_later_only_if_the_reservation_was_voided(self) -> None:
        for fails, closed, error in ((("SELECT substr(adds",), False, "store_unavailable"),
                                     (("SELECT substr(adds", "DELETE FROM records"), True, "reservation_not_voided")):
            with self.subTest(error=error):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                a, _ = self._floor_producer(Path(tmp.name))
                self._failing_db(a, fails)
                with self.assertRaisesRegex(producer.GateProducerError, error):
                    self._chained(a, (None,), serial=5)
                self.assertEqual(a._closed, closed)

    def test_a_refused_signature_whose_void_fails_closes_the_producer(self) -> None:
        """Round 4 M1: the verifier refuses and the void fails: the reservation stays, so the producer closes."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name))
        self._failing_db(a, ("DELETE FROM records",))
        with mock.patch.object(producer.signer, "seal", side_effect=producer.signer.GateSignerError("gate_verify_refused")),                 self.assertRaisesRegex(producer.GateProducerError, "reservation_not_voided"):
            self._chained(a, (None,), serial=5)
        self.assertTrue(a._closed)

    def test_a_counter_read_failure_before_signing_voids_the_reservation(self) -> None:
        """Round 4 M2: the seal's counter read fails before anything is signed: voided, producer open."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name))
        read = a._counter.read
        calls = []
        a._counter.read = lambda: (calls.append(1), read())[1] if len(calls) < 1 else (_ for _ in ()).throw(OSError("tpm_gone"))
        with self.assertRaisesRegex(OSError, "tpm_gone"):
            self._chained(a, (None,), serial=5)
        self.assertEqual((self._rows(a), a._closed), (0, False))

    def test_an_interrupt_while_reading_the_floors_closes_the_producer(self) -> None:
        """Round 4 L1: a BaseException that is not an Exception leaves the reservation, so the producer closes."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, _ = self._floor_producer(Path(tmp.name), floors=mock.Mock(side_effect=KeyboardInterrupt))
        with self.assertRaises(KeyboardInterrupt):
            self._chained(a, (None,), serial=5)
        self.assertTrue(a._closed)

    def test_a_failure_once_the_signature_may_be_stored_closes_and_needs_a_reopen(self) -> None:
        """Round 3 R1/R2: a counter failure, whatever its type, closes the producer; none is a ``retry_later``."""
        for failure, error in ((producer.GateProducerError("counter_down"), "counter_down"), (OSError("gone"), "signature_not_stored"),
                               (decide.MachineFault("tenant_floor_busy"), "signature_not_stored")):
            with self.subTest(error=error):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                a, _ = self._floor_producer(Path(tmp.name))
                a._counter.increment = mock.Mock(side_effect=failure)
                with self.assertRaises(producer.GateProducerError) as caught:
                    self._chained(a, (None,), serial=5)
                self.assertEqual((str(caught.exception), a._closed), (error, True))

    def test_a_reseal_at_start_takes_the_floor_lock(self) -> None:
        """Round 3 R4: the restart path holds the lock around its last check and signature store, as a commit does."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d, entered = Path(tmp.name), []
        handle, held, cert = fx.custody(str(d))
        make = lambda **extra: self._track(producer.ShardProducer(
            d / "s.sqlite3", mark_path=d / "s.mark", tenant_id=fx.TENANT, shard_id=fx.SHARD, epoch=fx.EPOCH, handle=handle,
            link=held, cosign=fx.cosigner(),  key_cert=cert, payer_newest=gate.ZERO_DIGEST, counter=TestOnlyCounter(d / "s.counter"),
            floors=lambda: (0, 0, 0, bytes(64)), **extra))
        a = make()
        with mock.patch.object(producer.signer, "seal", side_effect=producer.signer.GateSignerError("custody_down")):
            with self.assertRaises(producer.signer.GateSignerError):
                self._chained(a, (None,), serial=5)

        @contextlib.contextmanager
        def lock():
            entered.append(1)
            yield
        a.close()
        again = make(lock=lock)
        self.assertEqual((entered, len(again.published())), ([1], 1))

    def test_a_transient_lock_or_floor_write_error_is_waited_out_then_a_machine_fault(self) -> None:
        """Round 3 R3: a sharing violation on the ``.lock`` open or the floor write is retried; past the tries it is
        ``MachineFault`` (``retry_later``), never ``tenant_floor`` (replace the file)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a, tenant = self._floor_producer(Path(tmp.name))
        with mock.patch.object(decide.time, "sleep"):
            opened = os.open
            tries = []

            def flaky(*args):
                tries.append(1)
                if len(tries) <= 2:
                    raise PermissionError("scanner")
                return opened(*args)
            with mock.patch.object(decide.os, "open", flaky):
                tenant.raise_floors(0, 0)  # two failures, the third try opens
            with mock.patch.object(decide.os, "open", side_effect=PermissionError("scanner")), self.assertRaises(decide.MachineFault) as caught:
                tenant.raise_floors(0, 0)
            self.assertEqual((caught.exception.args[0], caught.exception.action), ("tenant_floor_busy", "retry_later"))
            with mock.patch.object(decide.marks, "append", side_effect=PermissionError("scanner")), self.assertRaises(decide.MachineFault) as caught:
                tenant.raise_floors(9, 0)
            self.assertEqual((caught.exception.args[0], caught.exception.action), ("tenant_floor_unwritable", "retry_later"))
        self.assertEqual(tenant.raise_floors(9, 0)[0], 9)

    def _track(self, prod: producer.ShardProducer) -> producer.ShardProducer:
        self.addCleanup(prod.close)  # runs before the temp directory's cleanup (registered earlier): Windows file locks
        return prod


if __name__ == "__main__":
    unittest.main()
