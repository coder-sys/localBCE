"""The gate's per-tenant line-id registry (``app/right_rail_gate_idreg.py``): one id, one shard; first reserver
owns; durable before reply; atomic; chain replay.  Synthetic ids, non-PHI."""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg

ROOT = Path(__file__).resolve().parents[1]


def _id(n: int) -> bytes:
    return n.to_bytes(idreg.ID_LEN, "big")


def _run(code: str, *args: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", code, *args], cwd=ROOT, stdout=subprocess.PIPE, text=True)


_RESERVE_1000 = (  # argv: path shard start-time; the start time is the barrier that makes the two batches race
    "import sys, time\n"
    "from pathlib import Path\n"
    "from app.right_rail_gate_idreg import IdRegistry\n"
    "r = IdRegistry(Path(sys.argv[1]), timeout=30)\n"
    "ids = [n.to_bytes(129, 'big') for n in range(1000)]\n"
    "time.sleep(max(0.0, float(sys.argv[3]) - time.time()))\n"
    "print(len(r.reserve(int(sys.argv[2]), ids)[0]))\n")
_RESERVE_THEN_DIE = (  # the reply was never read: the process dies the moment reserve returns
    "import os, sys\n"
    "from pathlib import Path\n"
    "from app.right_rail_gate_idreg import IdRegistry\n"
    "IdRegistry(Path(sys.argv[1])).reserve(0, [n.to_bytes(129, 'big') for n in range(50)])\n"
    "os._exit(0)\n")


class _Dying:
    """Stands in for the registry's connection and breaks the COMMIT statement.  ``die``: the process dies
    there (the connection closes with the transaction uncommitted); otherwise COMMIT fails and the connection lives."""

    def __init__(self, db: sqlite3.Connection, die: bool) -> None:
        self._real, self._die, self._dead = db, die, False

    @property
    def in_transaction(self) -> bool:
        return not self._dead and self._real.in_transaction

    def execute(self, sql: str, *args):
        if sql == "COMMIT":
            if self._die:
                self._real.close()
                self._dead = True
            raise sqlite3.OperationalError("injected failure at COMMIT")
        return self._real.execute(sql, *args)

    def __getattr__(self, name: str):
        return getattr(self._real, name)


class IdRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # cleanups run last-in first: stores close before the directory goes
        self.path = Path(tmp.name) / "ids.sqlite3"

    def open(self, **kwargs) -> idreg.IdRegistry:
        reg = idreg.IdRegistry(self.path, **kwargs)
        self.addCleanup(reg.close)
        return reg

    def test_t1_the_second_shard_gets_the_first_shards_ids_as_foreign(self) -> None:
        reg = self.open()
        self.assertEqual(reg.reserve(0, [_id(1), _id(2)])[0], [])
        foreign, head = reg.reserve(1, [_id(1), _id(3)])
        self.assertEqual(foreign, [(_id(1), 0)])  # only the contested id, with its owner
        self.assertEqual(reg.reserve(1, [_id(3)])[0], [])  # the new id is shard 1's own now
        self.assertEqual(reg.reserve(0, [_id(3)])[0], [(_id(3), 1)])
        self.assertEqual(reg.reserve(1, [_id(1), _id(3)])[1], reg.verify())  # replay agrees with the returned head
        self.assertNotEqual(head, gate.ZERO_DIGEST)

    def test_t1_swap_whoever_reserves_first_owns(self) -> None:
        reg = self.open()
        self.assertEqual(reg.reserve(1, [_id(1)])[0], [])
        self.assertEqual(reg.reserve(0, [_id(1)])[0], [(_id(1), 1)])
        self.assertEqual(reg.reserve(1, [_id(1)])[0], [])  # the owner asking again is not foreign

    def test_reserving_again_changes_nothing(self) -> None:
        reg = self.open()
        _, head = reg.reserve(0, [_id(1), _id(2), _id(1)])  # a repeat inside one batch counts once
        self.assertEqual(reg.reserve(0, [_id(2), _id(1)])[1], head)
        self.assertEqual(reg.reserve(0, [])[1], head)

    def test_t2_two_processes_racing_one_batch_give_it_to_exactly_one(self) -> None:
        self.open()  # create the schema first so the two processes only race on the reservation
        start = str(time.time() + 3)
        procs = [_run(_RESERVE_1000, str(self.path), str(shard), start) for shard in (0, 1)]
        foreign_counts = []
        for proc in procs:
            out, _ = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0)
            foreign_counts.append(int(out))
        self.assertEqual(sorted(foreign_counts), [0, 1000])  # one shard owns all 1000, the other is refused all 1000
        foreign, head = self.open().reserve(2, [_id(n) for n in range(1000)])
        self.assertEqual(len({owner for _, owner in foreign}), 1)
        self.assertEqual((len(foreign), head), (1000, self.open().verify()))

    def test_t3_a_process_that_dies_after_reserve_returns_keeps_its_ids(self) -> None:
        self.open()
        proc = _run(_RESERVE_THEN_DIE, str(self.path))
        proc.communicate(timeout=120)
        self.assertEqual(proc.returncode, 0)
        reg = self.open()
        ids = [_id(n) for n in range(50)]
        self.assertEqual(reg.reserve(0, ids)[0], [])  # the same shard, after restart, sees them as its own
        self.assertEqual(reg.reserve(1, ids)[0], [(i, 0) for i in ids])  # the other shard is refused all of them

    def test_t4_a_process_that_dies_at_commit_reserves_nothing(self) -> None:
        reg = self.open()
        reg._db = _Dying(reg._db, die=True)
        with self.assertRaises(sqlite3.OperationalError):
            reg.reserve(1, [_id(1), _id(2)])
        again = self.open()
        self.assertEqual(again.verify(), gate.ZERO_DIGEST)  # no row survived
        self.assertEqual(again.reserve(0, [_id(1), _id(2)])[0], [])  # so shard 0, not shard 1, owns them

    def test_t4_a_failed_commit_rolls_back_and_the_registry_still_works(self) -> None:
        reg = self.open()
        live = reg._db
        reg._db = _Dying(live, die=False)
        with self.assertRaises(sqlite3.OperationalError):
            reg.reserve(1, [_id(1)])
        reg._db = live
        self.assertEqual(reg.verify(), gate.ZERO_DIGEST)
        self.assertEqual(reg.reserve(0, [_id(1)])[0], [])

    def test_t6_genesis_refuses_a_shared_id_and_reserves_nothing(self) -> None:
        reg = self.open()
        with self.assertRaisesRegex(idreg.IdRegistryError, "genesis_double_acceptance"):
            reg.genesis({0: [_id(1), _id(2)], 1: [_id(3), _id(2)]})
        self.assertEqual(reg.verify(), gate.ZERO_DIGEST)
        self.assertEqual(reg.reserve(2, [_id(1), _id(2), _id(3)])[0], [])  # even shard 0's ids were rolled back

    def test_genesis_reserves_every_shards_set(self) -> None:
        reg = self.open()
        head = reg.genesis({0: [_id(1)], 1: [_id(2)]})
        self.assertEqual(head, reg.verify())
        self.assertEqual(reg.reserve(2, [_id(1), _id(2)])[0], [(_id(1), 0), (_id(2), 1)])

    def test_verify_replays_the_chain_and_pins_the_hash_rule(self) -> None:
        reg = self.open()
        self.assertEqual(reg.verify(), gate.ZERO_DIGEST)
        _, head = reg.reserve(5, [_id(1), _id(2)])
        want = gate.ZERO_DIGEST
        for i in (_id(1), _id(2)):
            want = gate.sha3_512(b"RR/GATE/ID-REG/v1\x00" + want + i + (5).to_bytes(4, "big"))
        self.assertEqual((head, reg.verify()), (want, want))

    def _edit(self, sql: str) -> None:
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute(sql)

    def test_rows_cannot_be_changed_or_removed_and_tampering_is_caught(self) -> None:
        reg = self.open()
        reg.reserve(0, [_id(1), _id(2), _id(3)])
        for sql in ("UPDATE ids SET shard = 9 WHERE n = 1", "DELETE FROM ids WHERE n = 2"):
            with self.assertRaises(sqlite3.DatabaseError):  # the append-only triggers
                self._edit(sql)
            self.assertNotEqual(reg.verify(), gate.ZERO_DIGEST)
        self._edit("DROP TRIGGER ids_no_update")
        self._edit("DROP TRIGGER ids_no_delete")
        self._edit("UPDATE ids SET shard = 9 WHERE n = 1")  # a rewritten owner
        with self.assertRaisesRegex(idreg.IdRegistryError, "chain_broken"):
            reg.verify()
        self._edit("UPDATE ids SET shard = 0 WHERE n = 1")
        self.assertNotEqual(reg.verify(), gate.ZERO_DIGEST)  # restored: the chain verifies again
        self._edit("DELETE FROM ids WHERE n = 2")  # a removed middle row
        with self.assertRaisesRegex(idreg.IdRegistryError, "chain_broken"):
            reg.verify()

    def test_bad_input_is_refused_before_anything_is_reserved(self) -> None:
        reg = self.open()
        for shard, ids in ((-1, [_id(1)]), (1 << 32, [_id(1)]), (True, [_id(1)]), (0, [_id(1), b"short"]),
                           (0, [_id(1), "x" * idreg.ID_LEN]), (0, [_id(1), _id(2) + b"\x00"])):
            with self.assertRaises(idreg.IdRegistryError):
                reg.reserve(shard, ids)
        with self.assertRaises(idreg.IdRegistryError):
            reg.genesis({0: [_id(1)], 1: [b"short"]})
        self.assertEqual(reg.verify(), gate.ZERO_DIGEST)

    def test_an_unavailable_registry_is_a_typed_refusal(self) -> None:
        with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
            idreg.IdRegistry(self.path.parent / "missing" / "ids.sqlite3")
        self.open()
        busy = self.open(timeout=0.1)
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as other:
            other.execute("BEGIN IMMEDIATE")  # another writer holds the lock
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                busy.reserve(0, [_id(1)])
        self.assertEqual(busy.reserve(0, [_id(1)])[0], [])  # and it recovers once the lock is gone

    def test_refuse_multi_shard(self) -> None:
        with self.assertRaisesRegex(idreg.IdRegistryError, "multi_shard_without_registry"):
            idreg.refuse_multi_shard(8)
        idreg.refuse_multi_shard(1)
        idreg.refuse_multi_shard(8, self.open())


if __name__ == "__main__":
    unittest.main()
