"""H2 (rrb/reviews/safety-redteam-20261001.md; design rrb/designs/accountability-anchor-v1.md section 2): the custody
log outside the store refuses a store copied back after a restart, and only a signed, attributed operator act lowers it.
Each test reads the log and the store back and checks that every MARK and ANCHOR names a committed head."""

import atexit
from contextlib import closing
import functools
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import right_rail_gate_signer as signer
from app import right_rail_financial_custody as custody_module
from app.right_rail_financial_custody import Custody
from app.right_rail_financial_owner import FinancialInputError, FinancialIntegrityError, FinancialOwner
from tests import test_right_rail_financial_acceptance as acceptance
from tests.rightrail_intake_rows import pay
from tests.test_right_rail_financial_core_r1 import _pay


def _records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_bytes().splitlines()]


_FIXTURE_KEY: list[str] = []


def fixture_custody(owner: FinancialOwner) -> Custody:
    """The pack tests' custody: a log in a fresh directory under one process-wide key, adopted at the open owner's
    verified state, so the owner marks every later commit."""
    if not _FIXTURE_KEY:
        keys = tempfile.mkdtemp(prefix="rr-custody-keys-")
        atexit.register(shutil.rmtree, keys, True)
        _FIXTURE_KEY.append(str(Path(keys) / "custody.key"))
        signer.keygen(_FIXTURE_KEY[0])
    directory = tempfile.mkdtemp(prefix="rr-custody-")
    atexit.register(shutil.rmtree, directory, True)
    custody = Custody(Path(directory), _FIXTURE_KEY[0])
    owner.resolve_custody(custody, "ADOPTED", actor_id="synthetic-operator", reason_ref="test:fixture", expect_sequence=owner._high[0], expect_head=owner._high[1])
    return custody


class CustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keys = tempfile.TemporaryDirectory(prefix="rr-custody-keys-")
        cls.key, cls.other_key = (str(Path(cls.keys.name) / name) for name in ("custody.key", "attacker.key"))
        cls.public_key = signer.keygen(cls.key)
        signer.keygen(cls.other_key)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.keys.cleanup()

    def setUp(self) -> None:
        held = tempfile.TemporaryDirectory(prefix="rr-custody-")  # outside the store's directory; removed after the owners close
        self.addCleanup(held.cleanup)
        self.directory = Path(held.name)
        self.fixture = acceptance.RightRailFinancialAcceptanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _custody(self, key: str | None = None) -> Custody:
        return Custody(self.directory, key or self.key)  # a new object: what a restarted process holds

    def _open(self, path: Path, clock, custody: Custody | None = None) -> FinancialOwner:
        make = lambda: self.fixture._make_owner(path=path, clock=clock)
        return make() if custody is None else self._with(custody, make)

    def _with(self, custody: Custody, make):
        with patch.object(acceptance, "FinancialOwner", functools.partial(FinancialOwner, custody=custody)):
            return make()

    def _base(self) -> FinancialOwner:
        """The acceptance base store, under custody from its creation (a signed genesis ANCHOR at sequence 0)."""
        return self._with(self._custody(), self.fixture._build_base)

    def _log(self, store: FinancialOwner) -> Path:
        return self.directory / f"{store.owner_id}.custody"

    def _meta(self, path: Path) -> tuple[int, bytes]:
        with closing(sqlite3.connect(str(path))) as connection:
            return tuple(connection.execute("SELECT sequence,history_head FROM financial_meta").fetchone())

    def _copy(self, path: Path, into: Path) -> None:
        into.mkdir()
        for name in (path.name, path.name + "-wal"):
            if (path.parent / name).exists():
                shutil.copyfile(path.parent / name, into / name)

    def _restore(self, copy: Path, path: Path) -> None:
        for suffix in ("-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        for name in os.listdir(copy):
            shutil.copyfile(copy / name, path.parent / name)

    def _assert_names_committed_heads(self, log: Path, path: Path) -> None:
        """No record claims a head the store did not commit at that sequence (REWIND_ACCEPTED's from_* name the old tail)."""
        with closing(sqlite3.connect(str(path))) as connection:
            heads = dict(connection.execute("SELECT event_sequence,head FROM financial_events"))
            heads[0] = connection.execute("SELECT genesis_head FROM financial_identity").fetchone()[0]
        records = _records(log)
        lowered = max((n for n, record in enumerate(records) if record["kind"] == "REWIND_ACCEPTED"), default=0)
        for record in records[lowered:]:  # before an accepted rewind, records name the abandoned history
            self.assertEqual(bytes.fromhex(record["head"]), heads.get(record["sequence"]), record["kind"])

    def _rewound(self):
        """The red team's attack: copy the store and its -wal at T0, commit later, close, put T0 back."""
        store = self._base()
        pay(store, **_pay("item-05", "t0"))
        copy = Path(self.fixture.temp_dir.name) / "t0"
        self._copy(store.path, copy)
        t0 = store._high
        pay(store, **_pay("item-06", "later"))
        pay(store, **_pay("item-07", "later"))
        store.close()
        self._assert_names_committed_heads(self._log(store), store.path)
        with closing(sqlite3.connect(str(store.path))) as connection: self.lost = connection.execute("SELECT event_sequence,kind,head FROM financial_events WHERE event_sequence>?", (t0[0],)).fetchall()  # what the restore will lose, read before it
        self._restore(copy, store.path)
        return store, t0

    def test_the_red_team_rewind_is_refused_after_a_restart_and_nothing_is_written(self) -> None:
        store, t0 = self._rewound()
        self.assertEqual(self._meta(store.path), t0)  # the copy really is the older store
        log_bytes = self._log(store).read_bytes()
        self.assertEqual([r["kind"] for r in _records(self._log(store))][-1], "ANCHOR")  # close signed the last state
        with self.assertRaisesRegex(FinancialIntegrityError, "^store_rewound$"):
            self._open(store.path, store.clock, self._custody())
        with self.assertRaisesRegex(FinancialIntegrityError, "^store_rewound$"):  # and no pack is signed for it
            self._custody().pack_signer({"owner_id": store.owner_id, "sequence": t0[0], "history_head": t0[1].hex().upper()}, store.path)
        self.assertEqual(self._log(store).read_bytes(), log_bytes)
        self.assertEqual(self._meta(store.path), t0)

    def test_a_forked_store_is_refused(self) -> None:
        store = self._base()
        copy = Path(self.fixture.temp_dir.name) / "fork"
        self._copy(store.path, copy)
        pay(store, **_pay("item-05", "live"))
        store.close()
        self._restore(copy, store.path)
        other = self._open(store.path, store.clock)  # opened without custody: another history at the same sequence
        pay(other, **_pay("item-05", "fork"))
        other.close()
        with self.assertRaisesRegex(FinancialIntegrityError, "^store_forked$"):
            self._open(store.path, store.clock, self._custody())

    def test_a_forged_or_edited_signed_record_is_refused(self) -> None:
        store, t0 = self._rewound()
        log, good = self._log(store), self._log(store).read_bytes()
        forger = self._custody(self.other_key)  # chained and canonical, but signed by a key that is not the owner's
        forger._append(store.owner_id, "REWIND_ACCEPTED", t0, actor_id="attacker", reason_ref="none",
                       from_sequence=_records(log)[-1]["sequence"], from_head=_records(log)[-1]["head"])
        forger.close(store.owner_id, t0)  # releases the log; its tail is already signed at t0
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_signature$"):
            self._open(store.path, store.clock, self._custody())
        at = len(good) - 20  # one hex digit of the close ANCHOR's signature ("sig" sorts last)
        log.write_bytes(good[:at] + (b"1" if good[at:at + 1] == b"0" else b"0") + good[at + 1:])
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_signature$"):
            self._open(store.path, store.clock, self._custody())

    def test_a_reordered_cut_or_torn_log(self) -> None:
        store = self._base()
        pay(store, **_pay("item-05", "a"))
        pay(store, **_pay("item-06", "b"))
        store.close()
        log = self._log(store)
        lines = log.read_bytes().splitlines(keepends=True)
        for name, edited in {"reordered": lines[:-3] + [lines[-2], lines[-3], lines[-1]], "middle cut": lines[:-3] + lines[-2:]}.items():
            with self.subTest(name):
                log.write_bytes(b"".join(edited))
                with self.assertRaisesRegex(FinancialIntegrityError, "^custody_corrupt$"):
                    self._open(store.path, store.clock, self._custody())
        log.write_bytes(b"".join(lines) + lines[-2][:40])  # a torn append (a crash mid-write) is ignored, then cut
        reopened = self._open(store.path, store.clock, self._custody())
        pay(reopened, **_pay("item-07", "c"))
        reopened.close()
        self.assertTrue(log.read_bytes().endswith(b"\n"))
        self._assert_names_committed_heads(log, store.path)

    def test_a_tail_cut_that_stays_ahead_of_the_restored_store_is_still_refused(self) -> None:
        store, _t0 = self._rewound()
        lines = self._log(store).read_bytes().splitlines(keepends=True)
        self._log(store).write_bytes(b"".join(lines[:-1]))  # drop the close ANCHOR: the MARK before it is still ahead
        with self.assertRaisesRegex(FinancialIntegrityError, "^store_rewound$"):
            self._open(store.path, store.clock, self._custody())

    def test_a_deleted_log_fails_closed_until_an_operator_adopts(self) -> None:
        store = self._base()
        pay(store, **_pay("item-05", "a"))
        store.close()
        self._log(store).unlink()
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_missing$"):
            self._open(store.path, store.clock, self._custody())
        self.assertFalse(self._log(store).exists())
        plain = self._open(store.path, store.clock)  # the operator's verified open, without custody
        state = plain._high
        with self.assertRaisesRegex(FinancialInputError, "^actor_id$"):
            plain.resolve_custody(self._custody(), "ADOPTED", actor_id="", reason_ref="ticket-1", expect_sequence=state[0], expect_head=state[1])
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_expectation$"):
            plain.resolve_custody(self._custody(), "ADOPTED", actor_id="operator:ana", reason_ref="ticket-1", expect_sequence=state[0] - 1, expect_head=state[1])
        plain.resolve_custody(self._custody(), "ADOPTED", actor_id="operator:ana", reason_ref="ticket-1", expect_sequence=state[0], expect_head=state[1])
        plain.close()
        (adopted, *_rest) = _records(self._log(store))
        self.assertEqual((adopted["kind"], adopted["n"], adopted["actor_id"], adopted["reason_ref"], adopted["sequence"]), ("ADOPTED", 0, "operator:ana", "ticket-1", state[0]))
        self.assertTrue(signer.verify(self.public_key, custody_module.SIGNED + bytes.fromhex(adopted["digest"]), bytes.fromhex(adopted["sig"])))
        self._open(store.path, store.clock, self._custody()).close()
        again = self._open(store.path, store.clock)
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_present$"):
            again.resolve_custody(self._custody(), "ADOPTED", actor_id="operator:ana", reason_ref="ticket-2", expect_sequence=state[0], expect_head=state[1])

    def test_a_missing_signer_key_fails_closed(self) -> None:
        store = self._base()
        store.close()
        missing = str(Path(self.fixture.temp_dir.name) / "no-such.key")
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_signer$"):
            self._open(store.path, store.clock, self._custody(missing))
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_signer$"):  # a new store gets no unsigned genesis
            self._with(self._custody(missing), lambda: self.fixture._make_owner(clock=store.clock))

    def test_a_legitimate_restore_is_signed_and_attributed(self) -> None:
        store, t0 = self._rewound()
        tail = _records(self._log(store))[-1]
        plain = self._open(store.path, store.clock)
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_expectation$"):
            plain.resolve_custody(self._custody(), "REWIND_ACCEPTED", actor_id="operator:ana", reason_ref="restore-7", expect_sequence=t0[0], expect_head=bytes(64))
        plain.resolve_custody(self._custody(), "REWIND_ACCEPTED", actor_id="operator:ana", reason_ref="restore-7", expect_sequence=t0[0], expect_head=t0[1])
        plain.close()
        record = _records(self._log(store))[-1]
        self.assertEqual((record["kind"], record["actor_id"], record["reason_ref"], record["sequence"], record["head"], record["from_sequence"], record["from_head"]),
                         ("REWIND_ACCEPTED", "operator:ana", "restore-7", t0[0], t0[1].hex(), tail["sequence"], tail["head"]))
        self.assertEqual(([(sequence, kind) for sequence, kind, _ in self.lost], bytes(self.lost[-1][2]).hex()), ([(record["sequence"] + n, kind) for n, kind in enumerate(["PAYMENT_RECEIVED", "INTAKE_RECEIVED"] * 2, 1)], record["from_head"]))  # the record names every event the restore lost: two payments, each with its intake
        reopened = self._open(store.path, store.clock, self._custody())
        pay(reopened, **_pay("item-06", "re-entered"))
        reopened.close()
        self._assert_names_committed_heads(self._log(store), store.path)
        again = self._open(store.path, store.clock)
        with self.assertRaisesRegex(FinancialIntegrityError, "^custody_not_rewound$"):
            again.resolve_custody(self._custody(), "REWIND_ACCEPTED", actor_id="operator:ana", reason_ref="restore-8", expect_sequence=again._high[0], expect_head=again._high[1])

    def test_after_an_accepted_rewind_the_abandoned_store_cannot_catch_up(self) -> None:
        store = self._base()
        pay(store, **_pay("item-05", "t0"))
        early, late = (Path(self.fixture.temp_dir.name) / name for name in ("t0", "late"))
        self._copy(store.path, early)
        t0 = store._high
        pay(store, **_pay("item-06", "later"))
        store.close()
        self._copy(store.path, late)
        self._restore(early, store.path)
        plain = self._open(store.path, store.clock)
        plain.resolve_custody(self._custody(), "REWIND_ACCEPTED", actor_id="operator:ana", reason_ref="restore-7", expect_sequence=t0[0], expect_head=t0[1])
        plain.close()
        self._restore(late, store.path)  # ahead of the accepted tail and holding its head: a catch-up MARK would admit it
        with self.assertRaisesRegex(FinancialIntegrityError, "^store_forked$"):
            self._open(store.path, store.clock, self._custody())

    # LIMIT (review of 02c57d7): the local refusal is only as strong as the custody file's write ACL.  MARKs are
    # unsigned, so these two edits need no key and open succeeds.  They pass by documenting the hole; the fix they
    # await is an outside witness or per-commit signing under a separate account, both listed as not done.
    def test_limit_a_log_cut_back_to_an_earlier_mark_admits_the_copy_taken_there(self) -> None:
        store, t0 = self._rewound()
        lines = self._log(store).read_bytes().splitlines(keepends=True)
        at = next(n for n, line in enumerate(lines) if json.loads(line)["sequence"] == t0[0]) + 1
        self._log(store).write_bytes(b"".join(lines[:at]))  # one cut: the chain prefix is valid, the genesis ANCHOR verifies
        self._open(store.path, store.clock, self._custody()).close()

    def test_limit_one_appended_unsigned_mark_admits_a_fork(self) -> None:
        store = self._base()
        copy = Path(self.fixture.temp_dir.name) / "fork"
        self._copy(store.path, copy)
        pay(store, **_pay("item-05", "live"))
        store.close()
        self._restore(copy, store.path)
        other = self._open(store.path, store.clock)
        pay(other, **_pay("item-05", "fork"))
        pay(other, **_pay("item-06", "fork"))
        fork = other._high
        other.close()
        keyless = self._custody(str(Path(self.fixture.temp_dir.name) / "no-such.key"))
        keyless._append(store.owner_id, "MARK", fork)  # no key file exists: a MARK is never signed
        keyless._release()
        self._open(store.path, store.clock, self._custody()).close()

    def test_a_crash_between_commit_and_mark_leaves_custody_behind_never_ahead(self) -> None:
        store = self._base()
        log = self._log(store)
        before = log.read_bytes()
        with patch.object(Custody, "_append", side_effect=OSError("disk full")):  # the MARK append fails after COMMIT
            self.assertIn("status", pay(store, **_pay("item-05", "a")))  # committed: never failed after COMMIT
            committed = self._meta(store.path)
            with self.assertRaisesRegex(FinancialIntegrityError, "^custody_unwritable$"):  # no further write while custody is owed
                pay(store, **_pay("item-06", "b"))
        self.assertEqual(self._meta(store.path), committed)  # b never began
        self.assertEqual(log.read_bytes(), before)
        self.assertLess(_records(log)[-1]["sequence"], committed[0])
        with self.assertRaisesRegex(FinancialIntegrityError, "^pack_unanchored$"):  # a pack speaks only at the log's tail
            self._custody().pack_signer({"owner_id": store.owner_id, "sequence": committed[0], "history_head": committed[1].hex().upper()}, store.path)
        store._discard_writer()  # the crash: no close, no catch-up
        reopened = self._open(store.path, store.clock, self._custody())  # behind with matching heads: one catch-up MARK
        self.assertEqual((_records(log)[-1]["kind"], _records(log)[-1]["sequence"]), ("MARK", committed[0]))
        reopened.close()
        self._assert_names_committed_heads(log, store.path)

    def test_the_log_may_not_live_in_the_store_directory(self) -> None:
        store = self._base()
        store.close()
        for directory in (store.path.parent, store.path.parent / "custody"):
            directory.mkdir(exist_ok=True)
            with self.subTest(str(directory)), self.assertRaisesRegex(FinancialIntegrityError, "^custody_dir_in_store$"):
                self._open(store.path, store.clock, Custody(directory, self.key))

    def test_the_pinned_worker_verifies_what_it_signs(self) -> None:
        message = custody_module.SIGNED + bytes(64)
        signature = signer.sign(self.key, message)
        self.assertTrue(signer.verify(self.public_key, message, signature))
        self.assertFalse(signer.verify(self.public_key, message[:-1] + b"\x01", signature))
        self.assertFalse(signer.verify(signer.public_key(self.other_key), message, signature))


if __name__ == "__main__":
    unittest.main()
