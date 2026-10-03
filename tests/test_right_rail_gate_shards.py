"""Multi-shard scenarios (multi-shard-runtime-v1 section B): the id registry, the producers and ``gate_rules`` together,
with crashes as child processes.  After every scenario ``_gate_shards.inv`` holds.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx

T, BAD, NEXT = {1: [10], 2: [11, 12]}, (12,), {3: [20]}  # payment 1 ALLOW; payment 2 HOLD (line 12's member died), 11 is its ALLOW line
ELSEWHERE = {4: [10], 5: [11], 6: [12], 7: [20]}  # shard 1 sends every id shard 0 has seen


def count(c: g.Cluster, kind: int) -> int:
    db = sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True)
    try:
        return db.execute("SELECT COUNT(*) FROM log WHERE kind = ?", (kind,)).fetchone()[0]
    finally:
        db.close()


def snapshot(path: Path) -> dict[str, bytes]:
    return {s: Path(f"{path}{s}").read_bytes() for s in ("", "-wal") if Path(f"{path}{s}").exists()}


def restore(path: Path, files: dict[str, bytes]) -> None:
    for s in ("", "-wal", "-shm"):
        Path(f"{path}{s}").unlink(missing_ok=True)
        if s in files:
            Path(f"{path}{s}").write_bytes(files[s])


def tear(path: Path) -> None:
    wal = Path(f"{path}-wal")
    if wal.exists() and wal.stat().st_size > 100:
        wal.write_bytes(wal.read_bytes()[:-100])


def newest_row(c: g.Cluster, k: int):
    db = sqlite3.connect(f"file:{c.store(k)}?mode=ro", uri=True)
    try:
        return db.execute("SELECT idreg_n, header, signature FROM batches ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        db.close()


def head_at(c: g.Cluster, n: int) -> bytes:
    db = sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True)
    try:
        return db.execute("SELECT head FROM log WHERE n = ?", (n,)).fetchone()[0]
    finally:
        db.close()


class ShardTests(fx.Scratch):
    @contextlib.contextmanager
    def cluster(self):
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp))
            c.boot()
            yield c

    def finish(self, c: g.Cluster, *again: dict) -> None:
        """Restart, shard 0 sends ``again`` (sealed or not: a sealed batch's lines hold as already decided), shard 1
        sends every id, then the invariants."""
        c.boot()
        for batch in again:
            c.send(0, batch, BAD)
        c.send(1, ELSEWHERE)
        g.inv(self, c)
        self.assertEqual([s for s, _, line in g.allowed(c) if line == 10], [0])  # paid once, by shard 0

    def test_s1_hold_frees_allow_id(self) -> None:
        with self.cluster() as c:
            first = c.send(0, {1: [10, 11]}, bad=(11,))
            self.assertEqual([first[10], first[11].split()[0]], ["ALLOW -", "HOLD"])  # 10 is an ALLOW line in a HOLD payment
            second = c.send(1, {3: [10], 4: [11]})  # t's own settle freed 10 and recorded 11
            self.assertEqual((second[10], second[11]), ("ALLOW -", "HOLD ALREADY_DECIDED"))
            g.inv(self, c)

    def test_s2_retry_no_second_payment(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]}, crash="commit")  # reserved 10, died before the checkpoint
            c.boot()
            before = count(c, 0)
            for _ in range(3):
                self.assertEqual(c.send(1, {2: [10]}), {10: "WAIT -"})  # unavailable, and no shard-1 leaf or row
            self.assertEqual(count(c, 0), before)
            self.assertEqual(c.send(0, {1: [10]}), {10: "ALLOW -"})  # the retry frees and re-reserves 10
            self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD ALREADY_DECIDED"})
            self.assertEqual([x for x in g.allowed(c) if x[2] == 10], [(0, 1, 10)])
            g.inv(self, c)

    def test_paid_line_is_never_freed_or_paid_again(self) -> None:
        with self.cluster() as c:
            self.assertEqual(c.send(0, {1: [10]}), {10: "ALLOW -"})
            with contextlib.closing(c.producer(0)) as prod:
                self.assertNotIn(10, prod.sealed_frees()[2])  # batch 1's own free
            self.assertEqual(g.owned(c, self)[idreg._key(10)], 0)
            self.assertEqual(c.send(1, {4: [10]}), {10: "HOLD ALREADY_DECIDED"})
            g.inv(self, c)

    def test_k0_dies_in_the_registry_transaction(self) -> None:
        for torn in (False, True):
            with self.subTest(torn=torn), self.cluster() as c:
                before = count(c, 0)
                c.send(0, T, BAD, crash="reserve")
                if torn:
                    tear(c.reg)
                self.assertEqual(count(c, 0), before)
                self.finish(c, T, NEXT)

    def test_k1_dies_before_the_checkpoint(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD, crash="commit")
            self.assertEqual((count(c, 0), newest_row(c, 0)), (3, None))  # reserved, nothing signed
            self.finish(c, T, NEXT)

    def test_k2_dies_after_row_a_and_k3_after_the_batch(self) -> None:
        for point, torn in (("seal", False), ("seal", True), ("settle", False), ("after", False)):
            with self.subTest(point=point, torn=torn), self.cluster() as c:
                c.send(0, T, BAD, crash=point)
                if torn:
                    tear(c.store(0))
                row = newest_row(c, 0)
                if row:
                    self.assertEqual(row[1][-64:], head_at(c, row[0]))
                reserved = count(c, 0)
                c.boot()
                c.producer(0).close()  # opening re-seals the open row
                self.assertEqual(count(c, 0), reserved)  # a restart reserves nothing
                if row:
                    self.assertEqual(newest_row(c, 0)[:2], row[:2])  # the same header bytes
                    self.assertIsNotNone(newest_row(c, 0)[2])
                self.finish(c, T, NEXT)  # D3 resealed, D4 sealed: the resend pays nothing twice

    def test_k4_dies_in_the_next_transaction(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD, crash="settle")  # t sealed, its settle left to t+1's reserve transaction
            c.boot()
            rows = [count(c, kind) for kind in range(3)]
            c.send(0, NEXT, crash="reserve")
            self.assertEqual([count(c, kind) for kind in range(3)], rows)  # t's settle and t+1's reserve are both absent
            c.boot()
            c.send(0, NEXT)
            self.assertGreater(count(c, 1), rows[1])  # present after the retry: t's settle freed 11
            self.finish(c)

    def test_settle_failure_after_the_seal_is_never_recommitted(self) -> None:
        commit, seen = decider.commit, []

        def twice(*args):
            for _ in range(2):
                with self.assertRaises(decider.GateDecideError) as caught:
                    commit(*args)
                seen.append(str(caught.exception))
        with self.cluster() as c:
            with mock.patch.object(idreg.IdRegistry, "settle", side_effect=idreg.IdRegistryError("registry_unavailable")),                     mock.patch.object(decider, "commit", twice):
                c.send(0, T, BAD)
            self.assertEqual(seen, ["settle_pending", "already_sealed"])
            self.finish(c, T, NEXT)  # the next reserve settles t; 10 is in one sealed batch

    def test_voided_reservation_is_freed_on_retry(self) -> None:
        with self.cluster() as c:
            with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")), \
                    self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                c.send(0, T, BAD)
            self.assertIsNone(newest_row(c, 0))  # the voided row is gone
            self.finish(c, T, NEXT)

    def test_k5_dead_shard_keeps_its_ids_unavailable(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]}, crash="commit")
            c.boot()
            for _ in range(2):
                self.assertEqual(c.send(1, {2: [10]}), {10: "WAIT -"})
            self.assertEqual([x for x in g.allowed(c) if x[0] == 1], [])
            g.inv(self, c)

    def test_r1_registry_only_restore_is_rewound(self) -> None:
        for wal in (True, False):
            with self.subTest(wal=wal), self.cluster() as c:
                c.send(0, T, BAD, crash="after")
                old = snapshot(c.reg)
                c.boot()
                c.send(0, NEXT)
                restore(c.reg, old if wal else {"": old[""]})
                with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                    c.boot()

    def test_r2_lost_uncommitted_rows_still_boot(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.reg)
            c.send(0, NEXT, crash="reserve")
            restore(c.reg, old)
            self.finish(c, NEXT)

    def test_r3_producer_only_restore_is_refused(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.store(0))
            c.send(0, NEXT)
            restore(c.store(0), old)
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                c.boot()  # NEXT's settle follows its reserve
            with self.assertRaisesRegex(producer.GateProducerError, "store_rewound"):
                c.producer(0)  # and the store is behind its mark

    def test_r3_store_and_mark_restored_before_the_newest_batch(self) -> None:
        """A batch's SETTLE is in the registry before its tokens leave, so a store restored with its mark to before it
        is refused at boot.  Restored to before a batch that died before its settle (no token out), it boots and the
        ids are decided again, once."""
        for point in (None, "settle"):
            with self.subTest(point=point), self.cluster() as c:
                c.send(0, T, BAD)
                old = {path: snapshot(path) for path in (c.store(0), c.dir / "s0.mark")}
                c.send(0, NEXT, crash=point)
                for path, files in old.items():
                    restore(path, files)
                if point is None:  # NEXT paid 20
                    with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                        c.boot()  # lazily settled, boot passed and the next reserve freed the paid 20
                    with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                        c.send(0, {9: [20]})  # each batch too: the old BOOT nonce still opens the registry
                    self.assertEqual(c.send(1, {9: [20]}), {20: "HOLD ALREADY_DECIDED"})  # the refusal freed nothing
                else:
                    c.boot()  # the store is behind only a batch whose tokens never left
                    self.finish(c, NEXT)  # 20 freed, decided again and paid once; inv holds

    def test_r4_a_swapped_registry_is_not_booted(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.reg)
            c.boot()
            restore(c.reg, old)
            with self.assertRaisesRegex(idreg.IdRegistryError, "registry_not_booted"):
                c.send(0, NEXT)

    def test_r5_whole_directory_restore_boots_and_forks(self) -> None:
        with self.cluster() as c, tempfile.TemporaryDirectory() as keep:
            c.send(0, T, BAD)
            shutil.copytree(c.dir, keep, dirs_exist_ok=True)
            c.send(0, NEXT)
            published = c.producer(0)
            original = published.published()[-1]
            published.close()
            for f in c.dir.iterdir():
                f.unlink()
            shutil.copytree(keep, c.dir, dirs_exist_ok=True)
            c.boot()  # documented residual (design 9, R5): a whole-directory restore passes the boot check
            c.send(0, {3: [30]})  # the restored shard publishes a different batch at the same seq
            again = c.producer(0)
            new = again.published()[-1]
            again.close()
            handle, root_pk, cert = c.custody
            frame = root_pk + fx._list([signer.framed(cert)]) + fx._list([signer.framed(original)]) + fx._u16(0) + signer.framed(new)
            self.assertTrue(signer.gate_verify(3, frame).startswith("GATE_VERIFY=FORK"))

    def test_d7_lost_adds_stop_the_shard(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            with contextlib.closing(sqlite3.connect(c.store(0))) as db:  # an edit outside the producer drops a row
                db.execute("DROP TRIGGER batches_fixed")
                db.execute("UPDATE batches SET adds = substr(adds, 925)")
                db.commit()
            with self.assertRaisesRegex(decider.GateDecideError, "state_mismatch"):
                c.send(0, T, BAD)

    def test_same_shard_resend_of_a_paid_line(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]})
            c.send(0, NEXT)
            self.assertEqual(c.send(0, {8: [10]})[10].split()[0], "HOLD")
            g.inv(self, c)

    def test_shard_of_only_resends_is_not_stuck(self) -> None:
        with self.cluster() as c:
            c.send(0, {1: [10]})
            self.assertEqual(c.send(1, {4: [10]}), {10: "HOLD ALREADY_DECIDED"})  # shard 1's first batch joins no set: empty adds
            self.assertEqual(c.send(1, {5: [30]}), {30: "ALLOW -"})
            g.inv(self, c)

    def refused(self, c: g.Cluster, k: int, i: int, line: str, code: str) -> None:
        """``decide`` refuses with ``code`` and neither the registry nor shard ``k``'s store gains a row."""
        before = [count(c, kind) for kind in range(4)], newest_row(c, k) if c.store(k).exists() else None
        prod, reg = c.producer(k), idreg.IdRegistry(c.reg, boot=c.nonce)
        try:
            with self.assertRaisesRegex(decider.GateDecideError, code):
                decider.decide(g.rules.EXE, c.dir / f"batch{k}.vectors", g._HEAD, g.ASOF, prod, reg, k, [i], [line])
        finally:
            prod.close()
            reg.close()
        self.assertEqual(([count(c, kind) for kind in range(4)], newest_row(c, k)), before)

    def test_a_line_break_in_a_line_is_refused_before_the_reserve(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            line = f"10:9 FFS_CLAIM 1001 7001 7001 {20270301 + 10 % 14} 99213 1 12510"
            for injected in (f"{line}\nload {g.ASOF} - {'00' * 64}", f"{line}\rredo 9"):
                with self.subTest(injected=injected):
                    self.refused(c, 0, 10, injected, "frame_injection")

    def test_genesis_sets_are_refused_until_load_carries_them(self) -> None:
        with self.cluster() as c:  # L4: load replays onto empty sets, so a resend of a genesis id would be ALLOWed
            reg = idreg.IdRegistry(c.reg, boot=c.nonce)
            reg.genesis({1: [40]})
            reg.close()
            self.refused(c, 1, 40, f"40:1 FFS_CLAIM 1001 7001 7001 {20270301 + 40 % 14} 99213 1 12540", "genesis_sets")


if __name__ == "__main__":
    unittest.main()
