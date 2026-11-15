"""The history store inside the engine (conformance/FLAT_V1.md, FRAME_V1.md): the engine answers as the one-shot rules runner on
small histories, a refused open writes nothing, a corrupt page or an unreadable log is a refusal, and a crash anywhere in a commit
leaves the store before or after the batch, as the signed head says; an unsigned whole frame left by a kill is kept for the same
request and nothing else (test-only exes; synthetic, non-PHI)."""

import functools
import hashlib
import msvcrt
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import right_rail_gate_chain as chain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests import test_gate_rules_vectors as rules

BIN = Path(rules.LEAN) / ".lake" / "build" / "bin"
ENGINE = BIN / "gate_engine.exe"
ONE = Path(rules.EXE)
CRASH = BIN / "gate_rules_crashtest.exe"  # the only exe that reads RR_FLAT_CRASH
PAGE = 4096
POINTS = ["frame-torn", "frame-write", "frame-sync"]  # where a commit can be killed: body written, trailer written, synced
NB = {"RR_FLAT_NB": "8"}  # a small directory: the second batch grows it, so the batches after rebuild it from the log
MEMBERS = [1001, 1002, 1003, 1005, 7701, 504, 1006, 1007]


@functools.lru_cache(maxsize=None)
def genesis() -> bytes:
    """Shard 0's genesis head under the harness key-set pin, computed at first use, so importing this module reads no ``g.PIN``
    (which runs the signer unless ``RR_GATE_UNSIGNED=1``)."""
    return chain.genesis(0, g.ASOF, g.PIN)


def __getattr__(name: str):
    """``GENESIS`` (``genesis()``) for the modules that read ``fw.GENESIS``."""
    if name == "GENESIS":
        return genesis()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def u16(b: bytes) -> bytes:
    return len(b).to_bytes(2, "big") + b


def batch(rng: random.Random, k: int, n: int) -> tuple[list[gate.DecideRequest], list[str]]:
    """``n`` one-line payments, and the one-shot runner's text rows for the same lines."""
    reqs, rows = [], []
    for j in range(n):
        i, key = 1000 * (k + 1) + j, g.member(rng.choice(MEMBERS), 0)
        date, proc, units, cents = 20270301 + rng.randrange(4), rng.choice([99213, 99214]), rng.randrange(1, 3), rng.choice([12500, 20000, 31000])
        line = gate.encode_line("FFS_CLAIM", f"L{i}", key, "P7001", "R7001", date, f"C{proc}", units, cents)
        reqs.append(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{i}", f"pay-{i}", key, "P7001", cents, fx.PERIOD, (line,),
                                       tuple(sorted((fx.D[2], fx.D[5])))))
        q = g.nat(u16(fx.PROGRAM.encode()) + u16(f"pay-{i}".encode()))
        rows.append(f"{g.nat(f'L{i}'.encode())}:{q} FFS_CLAIM {g.nat(key)} {g.nat(b'P7001')} {g.nat(b'R7001')} {date} {g.nat(f'C{proc}'.encode())} {units} {cents}")
    return reqs, rows


class Engine:
    """``gate_engine DIR 0`` over a pipe: a tag 4 frame is a request, the reply is the answer (empty if the process is gone)."""

    def __init__(self, d, exe: Path = ENGINE, env: dict | None = None) -> None:
        self.release = gate.sha3_512(ENGINE.read_bytes())  # the release the host names, whatever exe runs: a resend is the same bytes
        self.p = subprocess.Popen([str(exe), str(d).replace("\\", "/"), "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  env={**{k: v for k, v in os.environ.items() if k != "RR_FLAT_CRASH"}, **(env or {})})

    def ask(self, k: int, prev: bytes, reqs, redo=()) -> tuple[bytes, bytes]:
        """The batch ``k + 1`` frame on ``prev`` (redoing the payments numbered ``redo``) and the engine's answer to it."""
        data = decider.request_frame(g.HEAD, 0, k + 1, g.ASOF, prev, g.PIN, floors(prev), g.KEYS, g.GRANT, self.release, (), [gate.encode_decide_request(r) for r in reqs], redo)
        return data, self.send(data)

    def send(self, data: bytes) -> bytes:
        try:
            self.p.stdin.write(struct.pack(">I", len(data) + 1) + b"\x04" + data)
            self.p.stdin.flush()
            n = self.p.stdout.read(4)
            return self.p.stdout.read(struct.unpack(">I", n)[0]) if len(n) == 4 else b""
        except OSError:
            return b""

    def close(self) -> None:
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(timeout=60)


def repin(data: bytes, pin: bytes) -> bytes:
    """The request frame ``data`` with another key-set pin (after the feeds, their rows and the redone payments), its header digest redone."""
    at, redo = 82 + 8 + 64, int.from_bytes(data[82 + 8 + 64:82 + 8 + 68], "little")
    at += 4
    descs = [data[at + 77 * i:at + 77 * i + 77] for i in range(4)]
    at += 4 * 77 + sum(int.from_bytes(d[9:13], "little") * w for d, w in zip(descs, map(sum, decider.FEED_WIDTHS.values()))) + 261 * redo
    body = data[82:at] + pin + data[at + 64:]
    return data[:18] + hashlib.sha3_512(b"RR/GATE/FRAME/v1\x00" + body).digest() + body


FLOORS: dict[bytes, tuple[int, int]] = {}  # head -> the (grant serial, key-set epoch) floors its sealed record reports


def floors(prev: bytes) -> tuple[int, int]:
    """The floors a host asserts on the batch after the one that ended at ``prev``: those its sealed record reported."""
    return FLOORS.get(prev, (0, 0))


def read(data: bytes, out: bytes):
    """(why or None, records, head, root, authority record, leaves, adds) of the answer to the frame ``data``; the floors its
    record reports are kept for the next frame (a host asserts them: a lower floor is refused)."""
    got = decider._answer(out, data)
    if got[0] is None:
        FLOORS[got[2]] = chain.floors_of(got[4])
    return got


def status(recs, rows: list[str]) -> dict[str, str]:
    """Line id -> `OUTCOME REASONS`; a record's index is the line's position in the request (the answer is in decision order)."""
    return {rows[r.index].split()[0]: f"{r.outcome} {','.join(r.reasons) or '-'}" for r in recs}


def pay_number(i: int) -> int:
    return g.nat(u16(fx.PROGRAM.encode()) + u16(f"pay-{i}".encode()))


def one_shot(history: list[list[str]], tmp: Path, redos: dict[int, tuple[int, ...]] | None = None) -> list[dict[str, str]]:
    """The one-shot program's `OUTCOME REASONS` for each batch of rows in turn, the earlier batches' adds `load`ed onto the empty sets."""
    adds, digest, out = b"", "", []
    for k, rows in enumerate(history):
        ctl = "# genesis" if k == 0 else f"load {g.ASOF} {adds.hex() or '-'} {digest}"
        (tmp / "one.vectors").write_text("\n".join([*g._HEAD, "case batch", ctl, *(f"redo {p}" for p in (redos or {}).get(k, ())), *(f"line {r}" for r in rows), "commit SHOW", "end 0"]) + "\n", "utf-8")
        lines = subprocess.run([str(ONE), str(tmp / "one.vectors")], capture_output=True, text=True, timeout=600).stdout.splitlines()
        out.append({x.split()[1]: " ".join(x.split()[10:12]) for x in lines if x.startswith("RULES_LINE")})
        digest = next(x.split()[1] for x in lines if x.startswith("RULES_DIGEST"))
        adds += b"".join(bytes.fromhex(x.split(" ", 1)[1]) for x in lines if x.startswith("RULES_ADDS ") and " " in x)
    return out


def snap(d: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(d.iterdir()) if p.name != "lock"}


@unittest.skipUnless(os.name == "nt" and ENGINE.is_file() and ONE.is_file() and CRASH.is_file(),
                     f"FLAT WORKER NOT RUN: {ENGINE}, {ONE} or {CRASH} is missing; run `lake build gate_engine gate_rules gate_rules_crashtest` in lean/")
class FlatWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def engine(self, name: str, **kw) -> tuple[Engine, Path]:
        d = self.tmp / name
        eng = Engine(d, **kw)
        self.addCleanup(eng.close)
        return eng, d

    def test_engine_equals_one_shot_on_small_histories(self):
        rng, (eng, _), prev, history, want = random.Random(11), self.engine("w"), genesis(), [], []
        for k in range(5):
            reqs, rows = batch(rng, k, 12)
            data, out = eng.ask(k, prev, reqs)
            why, recs, prev, _, _, pays, adds = read(data, out)
            self.assertIsNone(why)
            self.assertEqual(len(pays), len(reqs))
            history.append(rows)
            self.assertEqual(status(recs, rows), one_shot(history, self.tmp)[k], f"batch {k}")
            self.assertTrue(adds)

    def test_a_redone_payment_is_decided_as_the_one_shot_decides(self):
        # batch 1 redoes a payment of batch 0 (it owns its line again) and one that is in no batch
        rng, (eng, _), prev, history, redos = random.Random(5), self.engine("r"), genesis(), [], {1: (pay_number(1000), pay_number(999999))}
        for k in range(3):
            reqs, rows = batch(rng, k, 12)
            data, out = eng.ask(k, prev, reqs, redos.get(k, ()))
            why, recs, prev, *_ = read(data, out)
            self.assertIsNone(why)
            history.append(rows)
            self.assertEqual(status(recs, rows), one_shot(history, self.tmp, redos)[k], f"batch {k}")

    def test_a_refused_open_decides_nothing_and_leaves_the_files_alone(self):
        for why, fresh in (("HEAD", False), ("HEAD", True), ("COUNT", False), ("COUNT", True), ("CORRUPT", True)):
            with self.subTest(why=why, fresh=fresh):
                rng = random.Random(9)
                eng, d = self.engine(f"o{why}{fresh}")
                data, out = eng.ask(0, genesis(), batch(rng, 0, 10)[0])
                head, second = read(data, out)[2], batch(rng, 1, 10)[0]
                if why == "CORRUPT":
                    p = d / "log"  # a byte of the first frame's metadata: the chain no longer holds
                    mo = 16 + struct.unpack("<I", p.read_bytes()[4:8])[0] * PAGE
                    p.write_bytes(bytes(b ^ (i == mo + 10) for i, b in enumerate(p.read_bytes())))
                if fresh:
                    eng.close()
                    eng = Engine(d)
                    self.addCleanup(eng.close)
                before = snap(d)
                data, out = eng.ask({"COUNT": 2}.get(why, 1), bytes(64) if why == "HEAD" else head, second)
                refused = read(data, out)
                self.assertIn(refused[0], ("flat_head", "flat_not_next", "flat_corrupt", "flat_replay"))
                self.assertEqual((refused[1], refused[5], refused[6]), ([], [], []))
                self.assertEqual(snap(d), before)
                if why != "CORRUPT":  # the right head still opens and decides the batch
                    self.assertIsNone(read(*eng.ask(1, head, second))[0])

    def test_a_corrupt_page_is_a_refusal_and_leaves_the_index_as_it_was(self):
        def start(name: str):
            rng = random.Random(5)
            eng, d = self.engine(name)
            data, out = eng.ask(0, genesis(), batch(rng, 0, 10)[0])
            return eng, d, read(data, out)[2], batch(rng, 1, 10)[0]

        eng, _, head, second = start("c")
        want = eng.ask(1, head, second)[1]
        eng2, d, head2, second2 = start("d")
        self.assertEqual(head2, head)
        path = d / "log"
        good = path.read_bytes()
        bad = bytearray(good)
        for off in range(16, 16 + struct.unpack("<I", good[4:8])[0] * PAGE, PAGE):  # every page of the first frame fails its checksum
            bad[off] ^= 0xFF
        path.write_bytes(bytes(bad))
        eng2.close()
        eng2 = Engine(d)  # a restarted engine reads the pages it needs from disk and checks them
        self.addCleanup(eng2.close)
        why, recs, *_ = read(*eng2.ask(1, head, second))
        self.assertIn(why, ("flat_corrupt", "flat_io", "flat_init"))
        self.assertEqual(recs, [])
        path.write_bytes(good)  # nothing was decided or written: the repaired index answers as the intact one did
        self.assertEqual(eng2.ask(1, head, second)[1], want)

    def crash_case(self, name: str, crash: str = "", env: dict | None = None, n1: int = 12):
        """Batch 1 in one process, then batch 2 on the store at its head in a second process, killed at `crash`:
        (dir, the batches' requests, head after batch 1, the second process's frame and answer)."""
        rng, d = random.Random(9), self.tmp / name
        reqs = [batch(rng, k, n1 if k == 1 else 12) for k in range(3)]
        first = Engine(d, env=env)
        head1 = read(*first.ask(0, genesis(), reqs[0][0]))[2]
        first.close()
        second = Engine(d, CRASH if crash else ENGINE, {"RR_FLAT_CRASH": crash} if crash else None)
        data, out = second.ask(1, head1, reqs[1][0])
        second.close()
        if crash:
            self.assertEqual((second.p.returncode, out), (99, b""), "the killed process answered")
        else:
            self.assertIsNone(read(data, out)[0])
        return d, reqs, head1, data, out

    def test_a_crash_leaves_the_batch_to_the_signed_head(self):
        """Killed at any write step of a commit: the host got no head, so it signs the old one and the same request decides the batch
        again to the same bytes as an uninterrupted run (a whole frame left by the kill is compared with the new one, not released);
        killed once the trailer is whole in the log, the host may have signed the new head and the next open at it continues.  Each
        time the batches after decide as the one-shot program does on the same history.  The second batch grows a small directory,
        is a plain one, or has no rows."""
        for kind, env in (("grow", NB), ("plain", None), ("empty", None)):
            n1 = 0 if kind == "empty" else 12
            ref, reqs, head1, data1, out1 = self.crash_case(f"ref{kind}", env=env, n1=n1)
            _, recs, head2, *_ = read(data1, out1)
            want = one_shot([r for _, r in reqs], self.tmp)
            self.assertEqual(status(recs, reqs[1][1]), want[1])
            refsnap, third = snap(ref), Engine(ref)
            data3, out3 = third.ask(2, head2, reqs[2][0])
            third.close()
            self.assertEqual(status(read(data3, out3)[1], reqs[2][1]), want[2])
            for crash in POINTS:
                with self.subTest("old head", kind=kind, crash=crash):
                    d = self.crash_case(f"u{kind}{crash}", crash, env, n1)[0]
                    again = Engine(d)
                    self.assertEqual(again.ask(1, head1, reqs[1][0]), (data1, out1))
                    again.close()
                    self.assertEqual(snap(d), refsnap)  # the torn or unsigned batch left nothing the resend does not replace
            for crash in POINTS[1:]:  # the trailer is whole in the log: the new head loads
                with self.subTest("new head", kind=kind, crash=crash):
                    d = self.crash_case(f"n{kind}{crash}", crash, env, n1)[0]
                    nxt = Engine(d)
                    self.assertEqual(nxt.ask(2, head2, reqs[2][0]), (data3, out3))
                    nxt.close()
            with self.subTest("no trailer", kind=kind):
                d = self.crash_case(f"p{kind}", "frame-torn", env, n1)[0]  # no trailer: no host signed the new head
                lone = Engine(d)
                self.assertEqual(read(*lone.ask(2, head2, reqs[2][0]))[0], "flat_head")
                lone.close()

    def test_an_unsigned_frame_is_kept_for_its_own_request_and_checked_against_it(self):
        """A whole frame past the signed head stays in the log.  Another request on that head is refused (CONFLICT) and writes
        nothing; the same request whose frame bytes were edited (a page byte, which a load does not read) decides again and is
        refused (REPLAY); a head older than one this process opened is refused (NOT_NEXT)."""
        _, _, _, data1, out1 = self.crash_case("pendref")
        d, reqs, head1, killed, _ = self.crash_case("pend", "frame-sync")
        self.assertEqual(killed, data1)  # the same request bytes, whichever exe ran them
        kept = snap(d)
        eng = Engine(d)
        other = read(*eng.ask(1, head1, batch(random.Random(77), 1, 12)[0]))
        self.assertEqual((other[0], other[1], other[5], other[6]), ("flat_conflict", [], [], []))
        self.assertEqual(snap(d), kept)
        eng.close()
        bad = bytearray(kept["log"])
        first = 16 + struct.unpack("<I", bad[4:8])[0] * PAGE + struct.unpack("<I", bad[8:12])[0] + struct.unpack("<I", bad[12:16])[0]
        bad[first + 16 + 5] ^= 0x01  # the second frame's first page
        (d / "log").write_bytes(bytes(bad))
        eng = Engine(d)
        forged = read(*eng.ask(1, head1, reqs[1][0]))
        self.assertEqual((forged[0], forged[1], forged[5], forged[6]), ("flat_replay", [], [], []))
        self.assertEqual(snap(d), {**kept, "log": bytes(bad)})
        eng.close()
        (d / "log").write_bytes(kept["log"])
        eng = Engine(d)
        self.addCleanup(eng.close)
        self.assertEqual(eng.ask(1, head1, reqs[1][0]), (data1, out1))  # the same request: decided again, the same bytes
        self.assertIsNone(read(*eng.ask(2, read(data1, out1)[2], reqs[2][0]))[0])  # the process has now opened at batch 2
        self.assertEqual(read(*eng.ask(1, head1, reqs[1][0]))[0], "flat_not_next")  # batch 1 < 2: a rewound head

    def locked_open(self, d: Path, at: int, size: int, n: int, prev: bytes, reqs):
        """The open while bytes [at, at+size) of the log are under another handle's byte-range lock, so the engine's read of
        them fails (a real read error, not a short read): IO, nothing written; after the unlock the open succeeds."""
        before = snap(d)
        eng = Engine(d)
        try:
            with open(d / "log", "r+b") as fh:
                fh.seek(at)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, size)
                try:
                    data, out = eng.ask(n, prev, reqs)
                finally:
                    fh.seek(at)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, size)
        finally:
            eng.close()
        self.assertEqual(read(data, out)[0], "flat_io")
        self.assertEqual(snap(d), before)

    def test_an_unreadable_log_is_io(self):
        """A log that cannot be read is neither absent nor a wrong head: IO, nothing written."""
        d, reqs, head1, data, out = self.crash_case("rt")
        head2 = read(data, out)[2]
        self.locked_open(d, 0, 16, 2, head2, reqs[2][0])
        self.locked_open(d, 0, 16, 1, head1, reqs[1][0])

    def test_a_second_writer_on_a_held_index_is_refused(self):
        rng = random.Random(4)
        eng, d = self.engine("lock")
        head = read(*eng.ask(0, genesis(), batch(rng, 0, 6)[0]))[2]
        head2 = read(*eng.ask(1, head, batch(rng, 1, 6)[0]))[2]
        third, was = batch(rng, 2, 6)[0], snap(d)
        other = Engine(d)
        self.addCleanup(other.close)
        for k, prev in ((2, head2), (0, genesis())):  # an open, then an init
            self.assertEqual(read(*other.ask(k, prev, third))[0], "flat_lock")
            self.assertEqual(snap(d), was)
        eng.close()
        again = Engine(d)  # the lock goes with the engine
        self.addCleanup(again.close)
        self.assertIsNone(read(*again.ask(2, head2, third))[0])

    def test_a_writer_behind_a_resident_engines_back_is_neither_trusted_nor_overwritten(self):
        """Another writer's frame lands past the signed head under a resident engine: the engine reads the disk again, keeps that
        frame as the unsigned one it is, and refuses a request that is not the one that made it (CONFLICT): nothing is released
        and the file is not touched."""
        rng = random.Random(8)
        eng, d = self.engine("back")
        head = read(*eng.ask(0, genesis(), batch(rng, 0, 6)[0]))[2]
        e = self.tmp / "back2"
        shutil.copytree(d, e, ignore=shutil.ignore_patterns("lock"))
        other = Engine(e)
        other.ask(1, head, batch(random.Random(9), 1, 6)[0])  # a second writer's batch
        other.close()
        for f in e.iterdir():  # its files land under the resident engine, whose in-memory store is now stale
            if f.name != "lock":
                (d / f.name).write_bytes(f.read_bytes())
        was = snap(d)
        got = read(*eng.ask(1, head, batch(rng, 1, 6)[0]))  # not the fast path: the disk is read again
        self.assertEqual((got[0], got[1], got[5], got[6]), ("flat_conflict", [], [], []))
        self.assertEqual(snap(d), was)

    def test_only_the_crash_test_exe_reads_the_crash_variable(self):
        def run(exe: Path, point: str, n: int) -> tuple[int, bytes]:
            eng = Engine(self.tmp / f"env{n}", exe, {"RR_FLAT_CRASH": point})
            out = eng.ask(0, genesis(), batch(random.Random(3), 0, 4)[0])[1]
            eng.close()
            return eng.p.returncode, out

        code, out = run(ENGINE, "frame-torn", 1)  # the pinned exe ignores it
        self.assertEqual((code, bool(out)), (0, True))
        self.assertEqual(run(CRASH, "typo", 2)[0], 2)  # a typo is not a silent no-crash run
        self.assertEqual(run(CRASH, "frame-torn", 3), (99, b""))


if __name__ == "__main__":
    unittest.main()
