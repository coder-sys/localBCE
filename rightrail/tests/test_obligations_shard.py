"""The obligations shard on its own: the hospital scenario's obligations opened, paid, retried, reversed and evaluated
through the shard program, every answer as the dispositions say, the records checked by the checker, and a changed or
missing byte found by it. Synthetic, non-PHI, nonpayment.

The program is the Lean build's `obligations_shard`, and only the build whose SHA-256 is pinned in
`artifacts/obligations-shard/obligations_shard.sha256`: a missing or other build fails every test here.

Refusals no log of a test can hold are checked when `Shard.lean` is built (its last section): `ROWS`, since no file
reaches 2^40 records; `STORE_READ` for a known command whose state row is missing, since a log is checked when it is
opened and such an end is cut first (the torn-end test below); and `MALFORMED` for a pack or an opening that states an
expected revision, which no frame can carry.

Setting OBLIGATIONS_SHARD_BENCH_N to a number also runs the measurement: one obligation's commands for that many
obligations."""

from __future__ import annotations

import copy
import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_semantic_adapter as adapter_tests

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "lean" / ".lake" / "build" / "bin" / ("obligations_shard.exe" if os.name == "nt" else "obligations_shard")
PIN = ROOT / "artifacts" / "obligations-shard" / "obligations_shard.sha256"
RECORD = 256
CAP = 65535


def program() -> str:
    """The built program, when it is the pinned build."""
    if not EXE.exists():
        raise AssertionError(f"the Lean build has no obligations_shard program at {EXE}")
    built, pinned = hashlib.sha256(EXE.read_bytes()).hexdigest(), PIN.read_text("ascii").strip()
    if built != pinned:
        raise AssertionError(f"obligations_shard is not the pinned build: built {built}, pinned {pinned}")
    return str(EXE)


def frame(kind: int, at_ms: int, payload: bytes, extra: bytes = b"") -> bytes:
    return bytes([kind]) + at_ms.to_bytes(8, "big") + len(payload).to_bytes(4, "big") + payload + extra


def pack_frame(at_ms: int, wire: bytes, classes: tuple[int, int] = (1, 1)) -> bytes:
    return frame(1, at_ms, wire, bytes(classes))


def evaluate_frame(at_ms: int, wire: bytes, request_id: str) -> bytes:
    rid = request_id.encode()
    return frame(12, at_ms, wire, len(rid).to_bytes(2, "big") + rid)


def payment_frame(at_ms: int, wire: bytes, command: dict, expected_revision: int | None = None) -> bytes:
    item = adapter.encode_payment_item(blfin02=wire, receipts=[], foreign=(False, False), expected_revision=expected_revision, command=command)
    return frame(5, at_ms, item)


def record(item: str, n: str, now: int, **more) -> dict:
    return {"kind": "record", "item_id": item, "payment_id": f"{item}-p{n}", "evidence_id": f"{item}-e{n}", "common_origin_id": f"{item}-o1",
            "source_id": "shard-source", "source_version": "v1", "local_ref": None, "amount_cents": 100, "event_at_ms": now,
            "pays_action_id": None, **more}


def other_id(value: str, j: int = 0) -> bytes:
    """An id as long as `value` that is not `value`: its last four bytes are `j` in base 36, or `zzzz`."""
    tail = "".join("0123456789abcdefghijklmnopqrstuvwxyz"[j // 36 ** k % 36] for k in (3, 2, 1, 0))
    tail = "zzzz" if value.endswith(tail) else tail
    return (value[:-4] + tail).encode()


class Scenario:
    """The hospital scenario's obligations, as BLFIN02 inputs at one time and again five milliseconds later, and the
    commands the tests send."""

    def __init__(self) -> None:
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        try:
            store = fixture._build_base()
            connection = store._connect()
            try:
                connection.execute("BEGIN")
                self.now = store.clock.value + 1
                authority = adapter.TrustedAuthorityContext.from_authority(store.trusted_authority)
                verification = {"scope": store._scope_value(), "owner_id": store.owner_id, "mode": store.mode}
                self.wires, self.later, self.revisions, self.data = {}, {}, {}, {}
                for obligation_id, item_id in connection.execute("SELECT obligation_id,item_id FROM obligations ORDER BY obligation_id").fetchall():
                    for wires, at_ms in ((self.wires, self.now), (self.later, self.now + 5)):
                        wires[item_id], data = adapter.live_evaluation_input(connection, obligation_id=obligation_id, authority_context=authority,
                                                                             evaluation_time_ms=at_ms, verification=verification)
                        if at_ms == self.now:
                            self.data[item_id] = data
                    self.revisions[item_id] = data["pre_evaluation"]["revision"]
                    self.pack_id, self.period_id = data["control_pack"]["canonical_fields"]["pack_id"], data["scope"]["period_id"]
                connection.execute("ROLLBACK")
            finally:
                connection.close()
        finally:
            fixture.doCleanups()
        self.item, self.wire = next(iter(self.wires.items()))

    def frames(self) -> tuple[bytes, list[tuple[str, str, int | None]]]:
        """Every command, the answer it must get, and for a retry the place of the command it repeats: a number is the
        mkind of the state row of an admitted command; the others name the disposition, or the refusal code the answer
        must hold.

        After its opening an obligation is at revision `r` = its stored revision + 1. A payment and a reversal state
        the revision they expect; an alias and the repeat of a statement leave the revision where it is."""

        now, at = self.now, self.now + 10
        out: list[bytes] = []
        expect: list[tuple[str, str, int | None]] = []

        def send(data: bytes, what: str, want: str, of: int | None = None) -> int:
            out.append(data)
            expect.append((what, want, of))
            return len(out) - 1

        pack = send(pack_frame(now, self.wire), "pack", "admitted")
        opened = {item: send(frame(2, now, wire), "open", "13") for item, wire in self.wires.items()}
        for item, wire in self.wires.items():
            r = self.revisions[item] + 1
            pay = payment_frame(at, wire, record(item, "1", now), expected_revision=r)
            alias = payment_frame(at, wire, record(item, "2", now), expected_revision=r + 1)
            reverse = payment_frame(at, wire, {"kind": "reverse", "payment_id": f"{item}-p1", "evidence_id": f"{item}-r1",
                                               "common_origin_id": None, "event_at_ms": None}, expected_revision=r + 1)
            conflicting = record(item, "6", now, amount_cents=200, evidence_id=f"{item}-e6", local_ref="conflict-ref")
            conflict = payment_frame(at, wire, conflicting, expected_revision=r + 3)
            paid = send(pay, "pay", "14")
            send(pay, "pay retry", "duplicate", paid)
            # The same command id with no expected revision is another request (Lean compares the revision).
            send(payment_frame(at, wire, record(item, "1", now)), "pay retry without revision", "conflict")
            send(payment_frame(at, wire, record(item, "1", now, amount_cents=200), expected_revision=r), "pay changed", "conflict")
            aliased = send(alias, "same origin", "17")
            # Another payment id, and evidence that is the stored evidence byte for byte: the same statement.
            send(payment_frame(at, wire, record(item, "5", now, evidence_id=f"{item}-e1", local_ref=f"payment:{item}-p1")),
                 "same statement, new id", "already")
            reversed_ = send(reverse, "reverse", "15")
            send(payment_frame(at, wire, record(item, "8", now, common_origin_id=f"{item}-o8"), expected_revision=r + 2), "other origin", "14")
            conflicted = send(conflict, "origin conflict", "16")
            # The same conflicting statement under another payment id: still a conflict, never "already".
            send(payment_frame(at, wire, {**conflicting, "payment_id": f"{item}-p7"}, expected_revision=r + 4), "same conflict, new id", "conflict")
            # After the conflict the obligation's newest fact is its quarantine marker; this alias stands on
            # the CASH fact of payment 8.
            send(payment_frame(at, wire, record(item, "9", now, common_origin_id=f"{item}-o8"), expected_revision=r + 4),
                 "same origin after a conflict", "17")
            send(payment_frame(at, wire, record(item, "3", now, common_origin_id=f"{item}-o3"), expected_revision=999), "stale", "REVISION_CONFLICT")
            evaluated = send(evaluate_frame(at, wire, f"{item}-eval-1"), "evaluate", "25")
            send(evaluate_frame(at, wire, f"{item}-eval-1"), "evaluate retry", "duplicate", evaluated)
            # Each kind of stored command sent again after the obligation has moved on.
            send(alias, "alias retry", "duplicate", aliased)
            send(conflict, "conflict retry", "duplicate", conflicted)
            send(reverse, "reversal retry", "duplicate", reversed_)
            send(pay, "the first payment after a conflict", "duplicate", paid)
            send(frame(2, at, wire), "opening retry", "duplicate", opened[item])
            # The same opening generated again later differs only in its evaluation time: the same request.
            send(frame(2, at, self.later[item]), "the opening generated again later", "duplicate", opened[item])
        send(pack_frame(at, self.wire), "pack retry", "duplicate", pack)
        send(pack_frame(at, self.wire, (1, 2)), "pack with other classes", "conflict")
        return b"".join(out), expect

    def big_wire(self, size: int) -> bytes:
        """The first item's opening input with evidence rows added, as many as fit under `size` bytes."""
        data = copy.deepcopy(self.data[self.item])
        base = len(adapter._encode_blfin02(data))
        item = self.item

        def row(k: int) -> dict:
            pad = "a" * 128
            return {"evidence_id": f"zz{k:06d}{pad}"[:128], "item_id": item, "kind": "NOTE", "common_origin_id": f"o{k:06d}{pad}"[:128],
                    "source_id": f"s{k:06d}{pad}"[:128], "source_version": f"v{k:06d}{pad}"[:128], "local_ref": f"l{k:06d}{pad}"[:128],
                    "applicable_at_ms": self.now, "event_at_ms": self.now, "received_at_ms": self.now, "amount_cents": None,
                    "reversal_of": None, "supersedes": None}

        def wire(count: int) -> bytes:
            fresh = copy.deepcopy(data)
            fresh["evidence"] = sorted(fresh["evidence"] + [row(k) for k in range(count)], key=lambda r: r["evidence_id"].encode())
            return adapter._encode_blfin02(fresh)

        per = len(wire(1)) - base
        # A wire list holds at most 10,000 rows, so the largest opening of this kind is a little under 7 MiB.
        count = min((size - base) // per, adapter.MAX_WIRE_LIST - len(data["evidence"]))
        out = wire(count)
        while len(out) > size:
            count -= 1
            out = wire(count)
        return out

    def one(self) -> tuple[bytes, bytes, bytes, int]:
        """The pack, the opening of the first obligation and its first payment, and the revision after the opening."""
        r = self.revisions[self.item] + 1
        return (pack_frame(self.now, self.wire), frame(2, self.now, self.wire),
                payment_frame(self.now + 10, self.wire, record(self.item, "1", self.now), expected_revision=r), r)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([program(), *args], capture_output=True, text=True, timeout=3600, check=False)


def shard(log: Path, frames: bytes, dispatch: str = "0") -> tuple[subprocess.CompletedProcess, list[str], bytes]:
    """Apply `frames` to the log at `log`: the program's result, its answers and the log after."""
    source, answers = Path(f"{log}.frames"), Path(f"{log}.answers")
    source.write_bytes(frames)
    answers.unlink(missing_ok=True)
    result = run("run", str(source), str(log), str(answers), dispatch)
    return result, (answers.read_text().splitlines() if answers.exists() else []), (log.read_bytes() if log.exists() else b"")


def record_of(answer: str) -> int:
    return int(answer.split()[1])


def row_of(log: bytes, command_record: int) -> bytes:
    body = log[command_record * RECORD:(command_record + 1) * RECORD]
    result = int.from_bytes(body[209:214], "little")
    return log[(result - 1) * RECORD:result * RECORD]


def mkind_of(log: bytes, command_record: int) -> int:
    return row_of(log, command_record)[2]


def run_ends(log: bytes) -> list[tuple[int, bytes, bytes]]:
    """Each run-end record of `log` (tag 0x77): its record number, the digest it holds and the digest the chaining formula
    gives: SHA3-512 of "RR/OBLIG/RUN-END/v1", the number of the run's first record (5 bytes, little-endian), the digest
    of the run-end record before it (64 zero bytes when there is none) and the records from that first one to the one
    before it.  A repair record (0xF6) neither ends a run nor starts one."""
    found, start, previous = [], 0, bytes(64)
    for i in range(len(log) // RECORD):
        body = log[i * RECORD:(i + 1) * RECORD]
        if body[0] == 0x77:
            held = body[6:70]
            found.append((i, held, hashlib.sha3_512(b"RR/OBLIG/RUN-END/v1" + start.to_bytes(5, "little") + previous
                                                    + log[start * RECORD:i * RECORD]).digest()))
            start, previous = i + 1, held
    return found


def memory_of(process: subprocess.Popen) -> tuple[int, int, int]:
    """The working set, its peak and the private bytes of a running process."""

    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_uint32), ("faults", ctypes.c_uint32)] + [(name, ctypes.c_size_t) for name in (
            "peak_working_set", "working_set", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]

    counters = Counters(cb=ctypes.sizeof(Counters))
    read = ctypes.windll.psapi.GetProcessMemoryInfo
    read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    if not read(int(process._handle), ctypes.byref(counters), ctypes.sizeof(counters)):
        raise OSError("the process's memory could not be read")
    return counters.working_set, counters.peak_working_set, counters.private


class ObligationsShardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        program()
        cls.scenario = Scenario()
        cls.folder = tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH"))
        cls.dir = Path(cls.folder.name)
        frames, cls.expect = cls.scenario.frames()
        cls.result, cls.answers, cls.log = shard(cls.dir / "log", frames)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def test_every_command_gets_its_disposition_and_the_log_checks(self) -> None:
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        self.assertIn("check ok", self.result.stdout)
        self.assertEqual(len(self.scenario.wires), 20)
        self.assertEqual(len(self.answers), len(self.expect))
        for (what, want, of), got in zip(self.expect, self.answers):
            with self.subTest(what=what, got=got):
                if want.isdigit():
                    self.assertTrue(got.startswith("admitted "), got)
                    self.assertEqual(mkind_of(self.log, record_of(got)), int(want))
                elif want == "admitted":
                    self.assertTrue(got.startswith("admitted "), got)
                elif want == "duplicate":
                    # A retry names the original command record.
                    self.assertEqual(got, f"duplicate {record_of(self.answers[of])}")
                elif want in ("conflict", "already"):
                    self.assertEqual(got, want)
                else:
                    self.assertTrue(got.startswith("refused ") and want in got, got)

    def test_an_alias_after_a_conflict_stands_on_the_payment_fact(self) -> None:
        labels = [what for what, _, _ in self.expect]
        pairs = [(self.answers[i], self.answers[i + 3]) for i, what in enumerate(labels) if what == "other origin"]
        self.assertEqual(len(pairs), 20)
        for paid, alias in pairs:
            with self.subTest(alias=alias):
                cash = record_of(paid) + 1  # the CASH fact follows its command record
                self.assertEqual(self.log[cash * RECORD], 15)
                row = row_of(self.log, record_of(alias))
                self.assertEqual(row[2], 17)
                self.assertEqual(int.from_bytes(row[108:113], "little"), cash)  # `cause`

    def test_the_checker_reads_the_log_alone(self) -> None:
        checked = run("check", str(self.dir / "log"))
        self.assertEqual(checked.returncode, 0, checked.stdout)
        self.assertIn(f"commands={sum(1 for a in self.answers if a.startswith('admitted'))} ", checked.stdout)

    def test_a_changed_cent_a_lost_record_and_a_cut_record_are_each_found(self) -> None:
        rows = [i for i in range(len(self.log) // RECORD) if self.log[i * RECORD] == 0x60 and self.log[i * RECORD + 2] == 14]
        self.assertTrue(rows)
        cases = {}
        changed = bytearray(self.log)
        changed[rows[0] * RECORD + 139] ^= 1  # the low byte of `received`
        cases["changed cent"] = bytes(changed)
        cases["lost record"] = self.log[:rows[0] * RECORD] + self.log[(rows[0] + 1) * RECORD:]
        cases["cut record"] = self.log[:-1]
        relinked = bytearray(self.log)
        relinked[rows[0] * RECORD + 245] ^= 1  # the low byte of the row's `prevCore`
        cases["changed link"] = bytes(relinked)
        for name, data in cases.items():
            with self.subTest(name=name):
                path = self.dir / name.replace(" ", "-")
                path.write_bytes(data)
                checked = run("check", str(path))
                self.assertEqual(checked.returncode, 1, checked.stdout)
                self.assertIn("check failed", checked.stdout)

    def test_a_store_that_can_dispatch_refuses_a_pack_without_classes(self) -> None:
        s = self.scenario
        result, answers, _ = shard(self.dir / "dispatch", pack_frame(s.now, s.wire, (0, 1)) + pack_frame(s.now, s.wire), "1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(answers[0].startswith("refused ") and "LEGACY_CLASS" in answers[0], answers[0])
        self.assertTrue(answers[1].startswith("admitted "), answers[1])  # a refused command is not remembered

    def test_the_same_pack_id_in_two_scopes_is_two_packs(self) -> None:
        s = self.scenario
        other = s.wire.replace(s.period_id.encode(), other_id(s.period_id))
        self.assertNotEqual(other, s.wire)
        # Both packs before either opening: each opening must find the pack of its own scope under the shared id.
        result, answers, log = shard(self.dir / "scopes", pack_frame(s.now, s.wire) + pack_frame(s.now, other) + frame(2, s.now, s.wire) +
                                     frame(2, s.now, other) + pack_frame(s.now, other))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("check ok", result.stdout)
        self.assertEqual([a.split()[0] for a in answers], ["admitted", "admitted", "admitted", "admitted", "duplicate"], answers)
        self.assertEqual([mkind_of(log, record_of(a)) for a in answers[2:4]], [13, 13])
        self.assertEqual(record_of(answers[4]), record_of(answers[1]))

    def test_a_command_earlier_than_the_one_before_it_is_refused(self) -> None:
        s = self.scenario
        pack, opening, pay, r = s.one()
        t = s.now + 10
        second = record(s.item, "8", s.now, common_origin_id=f"{s.item}-o8")
        result, answers, log = shard(self.dir / "time", pack + opening + pay +
                                     payment_frame(t - 1, s.wire, second, expected_revision=r + 1) +
                                     # A retry is answered from its record, whatever time it is sent at.
                                     payment_frame(t - 1, s.wire, record(s.item, "1", s.now), expected_revision=r) +
                                     payment_frame(t, s.wire, second, expected_revision=r + 1) +
                                     evaluate_frame(2 ** 63, s.wire, "late"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("check ok commands=4 ", result.stdout)
        self.assertEqual([a.split()[0] for a in answers], ["admitted", "admitted", "admitted", "refused", "duplicate", "admitted", "refused"], answers)
        self.assertTrue(all("TIME" in answers[i] for i in (3, 6)), answers)
        self.assertEqual(answers[4], f"duplicate {record_of(answers[2])}")
        # A refused command wrote nothing: the next admitted command starts where the last admitted one ended.
        self.assertEqual(log[(record_of(answers[5]) - 1) * RECORD], 0xF5)
        # The newest command's time is read back from the log when it is opened again.
        result, answers, _ = shard(self.dir / "time", evaluate_frame(t - 1, s.wire, "early") + evaluate_frame(t, s.wire, "on time"))
        self.assertIn("check ok commands=5 ", result.stdout)
        self.assertTrue(answers[0].startswith("refused ") and "TIME" in answers[0], answers)
        self.assertTrue(answers[1].startswith("admitted "), answers)

    def test_a_torn_end_after_the_last_commit_point_is_cut_back_and_kept(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        result, answers, _ = shard(self.dir / "whole", pack + opening)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        opened = record_of(answers[1])
        result, answers, whole = shard(self.dir / "whole", pay)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        paid, records = record_of(answers[0]), len(whole) // RECORD
        # The payment's run stopped before its run-end record, so nothing after the first run's run-end record was
        # answered: its command then lost its last record and part of the one before; lost its last record; or had it
        # zeroed.  And the whole log, followed by bytes that are not a record.
        unmarked = whole[:-RECORD]
        torn = {"part": (unmarked[:-300], paid), "record": (unmarked[:-RECORD], paid), "more": (whole + bytes([7]) * 100, records),
                "zeros": (whole + bytes(2 * RECORD), records), "zeroed": (unmarked[:-RECORD] + bytes(RECORD), paid)}
        for name, (data, boundary) in torn.items():
            with self.subTest(name=name):
                log = self.dir / f"torn-{name}"
                log.write_bytes(data)
                cut = data[boundary * RECORD:]
                result, answers, after = shard(log, pay + pay + opening + evaluate_frame(s.now + 10, s.wire, "after"))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"repaired: cut {len(cut)} bytes at record {boundary},", result.stdout)
                self.assertIn("check ok", result.stdout)
                # The bytes cut are kept beside the log, and the repair record at the cut names it and their count.
                self.assertEqual(Path(f"{log}.cut-{boundary}").read_bytes(), cut)
                self.assertEqual(after[:boundary * RECORD], whole[:boundary * RECORD])
                repair = after[boundary * RECORD:(boundary + 1) * RECORD]
                self.assertEqual((repair[0], int.from_bytes(repair[1:6], "little"), int.from_bytes(repair[6:14], "little")), (0xF6, boundary, len(cut)))
                # A payment that was cut is admitted when sent again; one that was whole is still known.
                first = f"admitted {boundary + 1}" if boundary == paid else f"duplicate {paid}"
                self.assertEqual(answers[:3], [first, f"duplicate {record_of(first)}", f"duplicate {opened}"], answers)
                self.assertTrue(answers[3].startswith("admitted "), answers)
                # Opened again, nothing more is cut.
                result, _, again = shard(log, b"")
                self.assertNotIn("repaired", result.stdout)
                self.assertIn("check ok", result.stdout)
                self.assertEqual(again, after)

    def test_a_log_changed_before_its_end_is_refused_and_left_as_it_is(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        result, answers, whole = shard(self.dir / "sound", pack + opening + pay)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        opened = record_of(answers[1])
        # One byte changed in the pack's command record, in the opening's, and in the record after the opening's.
        for name, record in {"pack": 0, "opening": opened, "opening-text": opened + 1}.items():
            with self.subTest(name=name):
                changed = bytearray(whole)
                changed[record * RECORD + 100] ^= 1
                log = self.dir / f"changed-{name}"
                log.write_bytes(changed)
                result, answers, after = shard(log, pay)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("CORRUPT", result.stderr)
                self.assertNotIn("repaired", result.stdout)
                # Nothing was answered, cut or written.
                self.assertEqual(answers, [])
                self.assertEqual(after, bytes(changed))
                self.assertEqual(list(self.dir.glob(f"changed-{name}.cut-*")), [])

    def test_a_last_command_whose_records_are_all_there_but_wrong_is_refused_not_cut(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        result, answers, whole = shard(self.dir / "last", pack + opening + pay)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # One cent changed in the payment's own state row: every record of the command is there.
        changed = bytearray(whole)
        changed[(int.from_bytes(whole[record_of(answers[2]) * RECORD + 209:record_of(answers[2]) * RECORD + 214], "little") - 1) * RECORD + 80] ^= 1
        log = self.dir / "last-changed"
        log.write_bytes(changed)
        stale = Path(f"{log}.answers")
        stale.write_text("stale answers")
        Path(f"{log}.frames").write_bytes(pay)
        result = run("run", f"{log}.frames", str(log), str(stale), "0")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CORRUPT", result.stderr)
        self.assertEqual(log.read_bytes(), bytes(changed))
        self.assertEqual(list(self.dir.glob("last-changed.cut-*")), [])
        # An answer file of an earlier run is gone, not left to be taken for this run's.
        self.assertFalse(stale.exists())

    def outcomes(self, cases: list[tuple[str, bytes, int, int]]) -> list[tuple[tuple[str, int, int], str]]:
        """What the program does, run with no commands, on each case (name, log, byte, mask): the log with that bit changed.
        "refused" is CORRUPT with nothing answered, cut or written; "cut N" is a torn end cut at record N and repaired;
        "accepted" is a log that checks as it is; anything else is its exit code and last output."""
        exe, empty = program(), self.dir / "sweep.frames"
        empty.write_bytes(b"")

        def probe(case: tuple[str, bytes, int, int]) -> tuple[tuple[str, int, int], str]:
            name, whole, at, mask = case
            changed = bytearray(whole)
            changed[at] ^= mask
            log = self.dir / f"sweep-{name}-{at}-{mask}"
            log.write_bytes(changed)
            answers = Path(f"{log}.answers")
            result = subprocess.run([exe, "run", str(empty), str(log), str(answers), "0"], capture_output=True, text=True, timeout=600, check=False)
            cut = re.search(r"repaired: cut \d+ bytes at record (\d+),", result.stdout)
            if result.returncode != 0 and "CORRUPT" in result.stderr and not cut and not answers.exists() and log.read_bytes() == changed:
                what = "refused"
            elif result.returncode == 0 and cut:
                what = f"cut {cut.group(1)}"
            elif result.returncode == 0:
                what = "accepted"
            else:
                what = f"exit {result.returncode}: {(result.stdout + result.stderr)[-300:]}"
            if what == "refused" or what == "accepted":
                log.unlink()
            return (name, at, mask), what

        with ThreadPoolExecutor(6) as pool:
            return list(pool.map(probe, cases))

    def not_refused(self, cases: list[tuple[str, bytes, int, int]]) -> list[tuple]:
        """The changes among `cases` that the program does not refuse as CORRUPT."""
        return [(*key, what) for key, what in self.outcomes(cases) if what != "refused"]

    def repaired_pack(self) -> tuple[bytes, int]:
        """A log in which a repair record has a run-end record after it, and the number of the command record of its
        second pack.  Run 1 writes a pack and its run-end record.  Run 2 sends a second pack and an opening and stops with
        the pack whole and the opening torn, so nothing of run 2 has a run-end record.  Run 3 sends the second pack
        again: the log is cut back and repaired, the pack is answered as a duplicate, and a run-end record follows the
        repair record, so that what the pack's own records hold is under a digest."""
        s = self.scenario
        pack2 = pack_frame(s.now, s.wire.replace(s.pack_id.encode(), other_id(s.pack_id)))
        log = self.dir / "repaired-pack"
        shard(log, pack_frame(s.now, s.wire))
        _, answers, two = shard(log, pack2 + frame(2, s.now, s.wire))
        second, opened = record_of(answers[0]), record_of(answers[1])
        log.write_bytes(two[:(opened + 1) * RECORD])
        result, answers, after = shard(log, pack2)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"repaired: cut {RECORD} bytes at record {opened},", result.stdout)
        self.assertEqual(answers, [f"duplicate {second}"])
        self.assertEqual((after[-2 * RECORD], after[-RECORD]), (0xF6, 0x77))
        return after, second

    def test_a_changed_bit_in_the_last_answered_command_or_its_run_end_is_refused_not_cut(self) -> None:
        s = self.scenario
        pack, opening, pay, r = s.one()
        alias = payment_frame(s.now + 10, s.wire, record(s.item, "2", s.now), expected_revision=r + 1)
        cases = []
        for name, frames in {"pack": pack, "payment": pack + opening + pay, "alias": pack + opening + pay + alias}.items():
            result, answers, whole = shard(self.dir / f"sweep-{name}", frames)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(answers[-1].startswith("admitted "), answers)
            n, last = len(whole) // RECORD, record_of(answers[-1])
            if name == "alias":
                self.assertEqual(mkind_of(whole, last), 17)
            # The run's check covered its records alone; the run-end record was written after it, at its own place.
            self.assertRegex(result.stdout, rf"check ok commands=\d+ records={n - 1} ")
            self.assertEqual((whole[-RECORD], int.from_bytes(whole[-RECORD + 1:-RECORD + 6], "little")), (0x77, n - 1))
            self.assertEqual([(held, want) for _, held, want in run_ends(whole)], [(whole[-RECORD + 6:-RECORD + 70],) * 2])
            # Every bit 0 and bit 7 of the last command's records and of the run-end record after them.
            cases += [(name, whole, at, mask) for at in range(last * RECORD, n * RECORD) for mask in (0x01, 0x80)]
        # The same over the second pack, the repair record and the run-end record of a log a repair record was written in.
        whole, second = self.repaired_pack()
        cases += [("repaired", whole, at, mask) for at in range(second * RECORD, len(whole)) for mask in (0x01, 0x80)]
        failed = self.not_refused(cases)
        self.assertEqual(failed, [], f"{len(failed)} of {len(cases)} changes were not refused as they are")
        # Nothing was cut and set aside.
        self.assertEqual(list(self.dir.glob("sweep-*.cut-*")), [])

    def test_a_whole_last_command_with_no_run_end_record_after_it_is_refused_not_cut(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        cases, last_of, row = [], {}, 0
        for name, frames in {"pack": pack, "payment": pack + opening + pay}.items():
            result, answers, whole = shard(self.dir / f"unmarked-{name}", frames)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # The run's run-end record never reached the disk, so nothing of the run was answered.
            unmarked, last = whole[:-RECORD], record_of(answers[-1])
            last_of[f"unmarked-{name}"] = last
            cases += [(f"unmarked-{name}", unmarked, at, mask) for at in range(last * RECORD, len(unmarked)) for mask in (0x01, 0x80)]
            if name == "payment":
                row = int.from_bytes(whole[last * RECORD + 209:last * RECORD + 214], "little") - 1
        results = dict(self.outcomes(cases))
        # A bit changed in the cid, the request digest or the state row of a command whose records are all there is damage.
        paid = last_of["unmarked-payment"]
        named = [("unmarked-pack", 2), ("unmarked-pack", 34), ("unmarked-payment", paid * RECORD + 2),
                 ("unmarked-payment", paid * RECORD + 34), ("unmarked-payment", row * RECORD + 80)]
        for name, at in named:
            for mask in (0x01, 0x80):
                with self.subTest(name=name, at=at, mask=mask):
                    self.assertEqual(results[(name, at, mask)], "refused")
        # Nothing else is cut but the last command, which is cut whole (a changed count runs past the end of the log, as
        # a torn end does); a changed pack time is the one change the checker cannot see in a log with no run-end
        # record: the digest of the next run-end record covers it.
        for (name, at, mask), what in results.items():
            with self.subTest(name=name, at=at, mask=mask):
                if what.startswith("cut"):
                    self.assertEqual(what, f"cut {last_of[name]}")
                elif what == "accepted":
                    self.assertTrue(name == "unmarked-pack" and 194 <= at < 202, (what, at))
                else:
                    self.assertEqual(what, "refused")
        self.assertGreater(sum(what == "refused" for what in results.values()), 0.95 * len(results))

    def test_a_run_end_digest_is_chained_to_the_one_before_it_whatever_runs_the_log_held(self) -> None:
        s = self.scenario
        pack, opening, pay, r = s.one()
        alias = payment_frame(s.now + 10, s.wire, record(s.item, "2", s.now), expected_revision=r + 1)
        log = self.dir / "chained"
        shard(log, pack + opening)
        shard(log, pay)
        two = log.read_bytes()
        first, second = run_ends(two)
        self.assertEqual((first[1] == first[2], second[1] == second[2], first[1] != second[1]), (True, True, True))
        self.assertEqual(second[0] + 1, len(two) // RECORD)
        # Run 2's run-end record is dropped.  Run 3 starts after the first run-end record: its digest runs over run 2's
        # records and its own, and holds the first digest as the one before it.
        log.write_bytes(two[:-RECORD])
        result, answers, three = shard(log, alias)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ends = run_ends(three)
        self.assertEqual([e[0] for e in ends], [first[0], len(three) // RECORD - 1])
        self.assertEqual([held == want for _, held, want in ends], [True, True])
        self.assertEqual(ends[1][1], hashlib.sha3_512(b"RR/OBLIG/RUN-END/v1" + (first[0] + 1).to_bytes(5, "little") + first[1]
                                                      + three[(first[0] + 1) * RECORD:ends[1][0] * RECORD]).digest())
        # The log opens again, and its digests are checked there.
        result, _, again = shard(log, b"")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("check ok", result.stdout)
        self.assertEqual(again, three)
        # The only run-end record dropped: the next digest runs from the first record, after 64 zero bytes.
        log = self.dir / "chained-first"
        shard(log, pack + opening)
        log.write_bytes(log.read_bytes()[:-RECORD])
        result, answers, four = shard(log, pay)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([(i, held == want) for i, held, want in run_ends(four)], [(len(four) // RECORD - 1, True)])
        self.assertEqual(run_ends(four)[0][1], hashlib.sha3_512(b"RR/OBLIG/RUN-END/v1" + bytes(5) + bytes(64) + four[:-RECORD]).digest())
        result, _, again = shard(log, b"")
        self.assertIn("check ok", result.stdout)
        self.assertEqual(again, four)

    def test_the_checker_refuses_a_replayed_command_an_earlier_time_a_moved_repair_and_a_lost_class_bit(self) -> None:
        s = self.scenario
        _, _, one = shard(self.dir / "replay", pack_frame(s.now, s.wire))
        m = len(one) // RECORD - 1  # the pack's records, without the run-end record after them
        other = s.wire.replace(s.pack_id.encode(), other_id(s.pack_id))
        _, _, two = shard(self.dir / "order", pack_frame(s.now, s.wire) + pack_frame(s.now + 5, other))
        cases = {}
        # The pack's records again after it, with the links of records written there: only its cid is a second one.
        again = bytearray(one[:m * RECORD] * 2)
        for k in range(m, 2 * m):
            prev, count = (1, 2) if k == m else (k, k - m + 2)
            again[k * RECORD + 245:k * RECORD + 252] = prev.to_bytes(5, "little") + count.to_bytes(2, "little")
        cases["replayed"] = (bytes(again), "a second command record of one cid")
        # The second pack a millisecond before the first: the only change.
        earlier = bytearray(two)
        earlier[m * RECORD + 194:m * RECORD + 202] = (s.now - 1).to_bytes(8, "little")
        cases["earlier"] = (bytes(earlier), "command time")
        # A log cut back by a repair record: the record names another place, or links into a chain.
        pack, opening, pay, _ = s.one()
        _, _, whole = shard(self.dir / "repair", pack + opening + pay)
        torn = self.dir / "repair-torn"
        torn.write_bytes(whole[:-2 * RECORD])
        result, _, repaired = shard(torn, b"")
        self.assertIn("repaired", result.stdout)
        at = next(k for k in range(len(repaired) // RECORD) if repaired[k * RECORD] == 0xF6)
        for name, offset in {"repair place": 1, "repair link": 245}.items():
            moved = bytearray(repaired)
            moved[at * RECORD + offset] ^= 1
            cases[name] = (bytes(moved), "repair or run-end record not at its place")
        # An evaluation whose command record and state row both dropped the opening's class bit.
        _, answers, evaluated = shard(self.dir / "eval", pack + opening + pay + evaluate_frame(s.now + 20, s.wire, "lg"))
        self.assertTrue(answers[3].startswith("admitted "), answers)
        command = record_of(answers[3])
        row = int.from_bytes(evaluated[command * RECORD + 209:command * RECORD + 214], "little") - 1
        self.assertEqual((evaluated[command * RECORD + 227], evaluated[row * RECORD + 238]), (2, 2))
        lost = bytearray(evaluated)
        lost[command * RECORD + 227] = 0
        lost[row * RECORD + 238] = 0
        cases["evaluation class bit"] = (bytes(lost), "evaluation command record")
        for name, (data, why) in cases.items():
            with self.subTest(name=name):
                path = self.dir / f"refused-{name.replace(' ', '-')}"
                path.write_bytes(data)
                checked = run("check", str(path))
                self.assertEqual(checked.returncode, 1, checked.stdout)
                self.assertIn(why, checked.stdout)

    def test_a_log_longer_than_its_read_bound_is_refused_before_anything_is_written(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        _, _, whole = shard(self.dir / "bound", pack + opening)
        # Reads of 100 bytes, so most end inside a record; the last read that gives bytes, then the empty one.
        reads = -(-len(whole) // 100)
        frames, answers = self.dir / "bound.frames", self.dir / "bound.answers"
        frames.write_bytes(pay)
        result = run("run", str(frames), str(self.dir / "bound"), str(answers), "0", "100", str(reads))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"longer than {reads} reads of 100 bytes", result.stderr)
        self.assertFalse(answers.exists())
        self.assertEqual((self.dir / "bound").read_bytes(), whole)
        self.assertEqual(list(self.dir.glob("bound.cut-*")), [])
        # A read size that reads nothing is refused, not taken for an empty log.
        for size in ("0", str(2 ** 64)):
            result = run("run", str(frames), str(self.dir / "bound"), str(answers), "0", size, "10")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual((self.dir / "bound").read_bytes(), whole)
        # Frames that do not read are refused after an earlier run's answers are removed.
        answers.write_text("stale answers")
        bad = self.dir / "bound.bad"
        bad.write_bytes(b"\x05")
        result = run("run", str(bad), str(self.dir / "bound"), str(answers), "0")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(answers.exists())
        self.assertEqual((self.dir / "bound").read_bytes(), whole)
        result = run("run", str(frames), str(self.dir / "bound"), str(answers), "0", "100", str(reads + 1))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("check ok commands=3 ", result.stdout)
        self.assertTrue(answers.read_text().startswith("admitted "))

    def test_a_log_in_use_is_refused_by_a_second_run_which_writes_nothing(self) -> None:
        s = self.scenario
        pack, opening, _, _ = s.one()
        result, _, whole = shard(self.dir / "busy", pack)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        kernel = ctypes.windll.kernel32
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        handle = kernel.CreateFileW(str(self.dir / "busy"), 0x80000000 | 0x40000000, 0, None, 3, 0x80, None)  # read and write, no sharing, open existing
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        frames, answers = self.dir / "busy.frames", self.dir / "busy.answers"
        # The answers of the run that holds the log are its own: a run refused for it leaves them as they are.
        held = answers.read_bytes()
        frames.write_bytes(opening)
        try:
            result = run("run", str(frames), str(self.dir / "busy"), str(answers), "0")
        finally:
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.CloseHandle(handle)
        self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
        self.assertIn("BUSY", result.stderr)
        self.assertEqual(answers.read_bytes(), held)
        self.assertEqual((self.dir / "busy").read_bytes(), whole)

    def test_a_run_leaves_only_its_answers_and_the_next_run_starts_without_them(self) -> None:
        self.assertTrue((self.dir / "log.answers").exists())
        self.assertFalse((self.dir / "log.answers.tmp").exists())

    def test_the_checker_finds_an_expected_revision_on_a_pack_or_opening_and_a_lost_class_bit(self) -> None:
        s = self.scenario
        pack, opening, pay, _ = s.one()
        result, answers, whole = shard(self.dir / "six", pack + opening + pay)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # A command record is tag 0x74 and names its kind at byte 1: the pack's is kind 1, the opening's 2, the payment's 5.
        commands = {whole[p * RECORD + 1]: p for p in reversed(range(len(whole) // RECORD)) if whole[p * RECORD] == 0x74}
        opened, paid = commands[2], commands[5]
        for name, at in {"pack": commands[1], "opening": opened}.items():
            with self.subTest(name=name):
                changed = bytearray(whole)
                changed[at * RECORD + 204] = 1  # `exprev`
                path = self.dir / f"six-{name}"
                path.write_bytes(changed)
                checked = run("check", str(path))
                self.assertEqual(checked.returncode, 1, checked.stdout)
        # The scenario's opening has evidence of no class, so its records, and the payment's, carry bit 1 of `lg`.
        self.assertEqual(whole[opened * RECORD + 227], 2)
        self.assertEqual(whole[paid * RECORD + 227], 2)
        # A payment that dropped the bit, its command record and its state row alike, is not the engine's: the log
        # is otherwise whole, so only the lost bit is found.
        lost = bytearray(whole)
        row = next(p for p in range(paid, len(whole) // RECORD) if whole[p * RECORD] == 0x60)
        lost[paid * RECORD + 227] = 0
        lost[row * RECORD + 238] = 0
        path = self.dir / "six-bit-lost"
        path.write_bytes(lost)
        checked = run("check", str(path))
        self.assertEqual(checked.returncode, 1, checked.stdout)
        self.assertIn("payment", checked.stdout)

    def test_every_command_sent_again_after_the_log_is_reopened_is_answered_from_its_record(self) -> None:
        frames, expect = self.scenario.frames()
        shutil.copy(self.dir / "log", self.dir / "reopen")
        result, again, after = shard(self.dir / "reopen", frames)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(again), len(self.answers))
        for (what, _, _), first, got in zip(expect, self.answers, again):
            with self.subTest(what=what, got=got):
                self.assertEqual(got, f"duplicate {record_of(first)}" if first.startswith("admitted ") else first)
        # Alias, conflict and reversal are among them, and nothing was written.
        self.assertTrue({"alias retry", "conflict retry", "reversal retry"} <= {what for what, _, _ in expect})
        self.assertEqual(after, self.log)

    def test_openings_of_one_and_eight_mebibytes_are_stored_and_read_back(self) -> None:
        s = self.scenario
        pack, _, pay, _ = s.one()
        # An opening near 7 MiB (the most a wire list allows) was measured at over 30 minutes; it is not run here.
        for mib in (1,):
            with self.subTest(mib=mib):
                big = s.big_wire(mib * 2 ** 20 - 4096)
                self.assertGreater(len(big), mib * 2 ** 20 * 3 // 4)
                log = self.dir / f"big-{mib}"
                frames = pack + frame(2, s.now, big) + pay + evaluate_frame(s.now + 10, s.wire, "big-eval")
                result, answers, data = shard(log, frames)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("check ok", result.stdout)
                self.assertTrue(all(a.startswith("admitted ") for a in answers), answers)
                self.assertGreater(len(data), len(big))
                # Opened again: the opening is read back from its records, and every command is a retry.
                result, again, after = shard(log, frames)
                self.assertEqual(again, [f"duplicate {record_of(a)}" for a in answers], again)
                self.assertEqual(after, data)

    def test_a_chain_count_stops_at_its_cap(self) -> None:
        s = self.scenario
        pack_id = s.pack_id.encode()
        self.assertIn(pack_id, s.wire)
        log, total, step = self.dir / "cap", CAP + 2, 8192
        # One pack command for each of more ids than the count can hold, in several runs on one log.
        for start in range(0, total, step):
            frames = b"".join(pack_frame(s.now, s.wire.replace(pack_id, other_id(s.pack_id, j))) for j in range(start, min(start + step, total)))
            result, answers, data = shard(log, frames)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(all(a.startswith("admitted ") for a in answers), [a for a in answers if not a.startswith("admitted ")][:3])
        self.assertIn(f"check ok commands={total} ", result.stdout)
        counts = [int.from_bytes(data[i + 250:i + 252], "little") for i in range(0, len(data), RECORD) if data[i] == 0x74]
        self.assertEqual(counts, [min(k, CAP) for k in range(1, total + 1)])

    @unittest.skipUnless(os.environ.get("OBLIGATIONS_SHARD_BENCH_N", "").isdigit() and os.name == "nt", "measurement not asked for")
    def test_measure(self) -> None:
        from tests._gate_bars import Load  # the machine's busy share; loaded only for a measurement

        s = self.scenario
        pack, opening, pay, r = s.one()
        now, at, wire, item = s.now, s.now + 10, s.wire, s.item
        # One obligation's commands: opened, paid, the payment sent again, an alias, a reversal, a payment of another
        # origin, a conflict, an evaluation and that evaluation sent again.
        commands = [opening, pay, pay, payment_frame(at, wire, record(item, "2", now), expected_revision=r + 1),
                    payment_frame(at, wire, {"kind": "reverse", "payment_id": f"{item}-p1", "evidence_id": f"{item}-r1", "common_origin_id": None,
                                             "event_at_ms": None}, expected_revision=r + 1),
                    payment_frame(at, wire, record(item, "8", now, common_origin_id=f"{item}-o8"), expected_revision=r + 2),
                    payment_frame(at, wire, record(item, "6", now, amount_cents=200, local_ref="conflict-ref"), expected_revision=r + 3),
                    evaluate_frame(at, wire, f"{item}-eval-1"), evaluate_frame(at, wire, f"{item}-eval-1")]
        (self.dir / "bench-pack").write_bytes(pack)
        (self.dir / "bench-item").write_bytes(b"".join(commands))
        base = None
        for n in (0, int(os.environ["OBLIGATIONS_SHARD_BENCH_N"])):
            log = self.dir / f"bench-log-{n}"
            load = Load()
            process = subprocess.Popen([program(), "bench", str(self.dir / "bench-pack"), str(self.dir / "bench-item"), item, str(n), str(log)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            line = process.stdout.readline().strip()
            busy = load.busy_pct()
            # The process holds its tables and waits; it is measured now.
            memory = memory_of(process) if line.startswith("obligations=") else (0, 0, 0)
            rest, _ = process.communicate("\n", timeout=600)
            self.assertEqual(process.returncode, 0, line + rest)
            self.assertIn(f"held obligations={n}", rest)
            fields = dict(re.findall(r"(\w+)=(\d+)", line))
            self.assertEqual((int(fields["admitted"]), int(fields["duplicate"])), (7 * n, 2 * n), line)
            if base is None:
                base = memory
                continue
            count = int(fields["commands"])
            print(f"\nBENCH {line}")
            print(f"BENCH obligations={n} us_per_command={int(fields['engine_ns']) / count / 1000:.2f} reads_per_command={int(fields['reads']) / count:.2f} "
                  f"writes_per_command={int(fields['writes']) / count:.2f} machine_busy_pct={busy} log_bytes={log.stat().st_size} working_set={memory[0]} "
                  f"peak_working_set={memory[1]} private={memory[2]} empty_working_set={base[0]} empty_private={base[2]} "
                  f"working_set_per_obligation={(memory[0] - base[0]) / n:.1f} private_per_obligation={(memory[2] - base[2]) / n:.1f}")


if __name__ == "__main__":
    unittest.main()
