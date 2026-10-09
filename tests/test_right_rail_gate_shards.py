"""Multi-shard scenarios (multi-shard-runtime-v1 section B): the id registry, the producers and ``gate_rules`` together,
with crashes as child processes.  After every scenario ``_gate_shards.inv`` holds.  Synthetic, non-PHI."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_payer as payer
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


def request(p: int, k: int):
    """The payer's request for harness payment p on shard k: the one its ALLOW leaf (``g.decide_batch``) carries."""
    key, flow = fx.member(p, k), "FFS_CLAIM" if p % 4 else "FFS_CYCLE"
    return fx._request(flow, p, fx._lines(p, flow, key), member_key=key)


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


def link(at: Path, to: Path | None) -> Path:
    """Point the directory link ``at`` to ``to`` (None: remove it), replacing it if present; on Windows a junction."""
    if os.path.lexists(at):
        (os.rmdir if os.name == "nt" else os.unlink)(at)
    try:
        if to and os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(at), str(to)], check=True, capture_output=True)
        elif to:
            os.symlink(to, at, target_is_directory=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise unittest.SkipTest(f"LOUD SKIP: the OS refused a directory link: {error}") from error
    return at


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
    def cluster(self, shards: int = 2):
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=shards)
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
        commit = decider.commit

        def twice(*args):
            for _ in range(2):
                with self.assertRaises(decider.GateDecideError) as caught:
                    commit(*args)
                seen.append(str(caught.exception))
        for batch in (T, {8: [30]}):  # with adds, and without (30 is shard 1's paid id)
            seen = []
            with self.subTest(batch=batch), self.cluster() as c:
                if 8 in batch:
                    c.send(1, {9: [30]})
                with mock.patch.object(idreg.IdRegistry, "settle", side_effect=idreg.IdRegistryError("registry_unavailable")),                         mock.patch.object(decider, "commit", twice):
                    c.send(0, batch, BAD)
                self.assertEqual(seen, ["settle_pending", "stale_answer"])
                self.finish(c, T, NEXT)  # the next reserve settles t; 10 is in one sealed batch

    def test_a_stale_answer_is_refused_before_the_seal(self) -> None:
        # B2's reserve frees B1's in-flight 10.  HIGH: B2 (a resend of shard 1's paid 30, no fresh row) seals first, so
        # B1's seal would ALLOW 10 that shard 1 then pays again.  MED: B2 reserves 11, so B1's seal could never settle.
        for second, b2_first in (({8: [30]}, True), ({2: [11]}, False)):
            with self.subTest(second=second), self.cluster() as c:
                c.send(1, {9: [30]})
                prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
                try:
                    b1, b2 = [g.decide_batch(c, prod, reg, 0, p) for p in ({1: [10]}, second)]
                    commit = lambda b: decider.commit(prod, reg, fx.PROGRAM, b[1], b[0], fx.NOW)
                    if b2_first:
                        commit(b2)
                    with self.assertRaisesRegex(decider.GateDecideError, "stale_answer"):
                        commit(b1)
                    if not b2_first:
                        commit(b2)
                finally:
                    prod.close()
                    reg.close()
                self.assertEqual(c.send(1, {7: [10]}), {10: "ALLOW -"})
                g.inv(self, c)

    def test_a_second_decider_is_refused_inside_a_commit(self) -> None:
        # A reserve between commit's stale check and its seal freed the answer's 10, which the seal then paid.
        with self.cluster() as c:
            prod, reg, other, got = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce), idreg.IdRegistry(c.reg, boot=c.nonce), []
            commit = producer.ShardProducer.commit

            def raced(*args, **kwargs):
                try:
                    other.reserve(0, [], sealed=None)
                    got.append("reserved")
                except idreg.IdRegistryError as error:
                    got.append(str(error))
                return commit(*args, **kwargs)
            try:
                ans, leaves, _ = g.decide_batch(c, prod, reg, 0, {1: [10]})
                with mock.patch.object(producer.ShardProducer, "commit", raced), contextlib.suppress(decider.GateDecideError):
                    decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
            finally:
                for handle in (prod, reg, other):
                    handle.close()
            self.assertEqual(c.send(1, {7: [10]}), {10: "HOLD ALREADY_DECIDED"})
            self.assertEqual(got, ["shard_busy"])
            g.inv(self, c)

    def test_an_open_row_is_never_settled_as_sealed(self) -> None:
        # A seal that fails short of gate_verify_refused leaves an open row.  Settled as sealed by the next reserve, its
        # void at reopen made every boot and reserve registry_rewound; freed instead, a reseal at reopen would pay twice.
        for reseal in (False, True):
            with self.subTest(reseal=reseal), self.cluster() as c:
                prod, reg = c.producer(0), idreg.IdRegistry(c.reg, boot=c.nonce)
                try:
                    ans, leaves, _ = g.decide_batch(c, prod, reg, 0, T, BAD)
                    with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_failed")), \
                            self.assertRaises(signer.GateSignerError):
                        decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
                    try:
                        got = g.decide_batch(c, prod, reg, 0, NEXT) and "decided"
                    except producer.GateProducerError as error:
                        got = str(error)
                finally:
                    prod.close()
                    reg.close()
                if not reseal:
                    with mock.patch.object(signer, "seal", side_effect=signer.GateSignerError("gate_verify_refused")), \
                            self.assertRaisesRegex(producer.GateProducerError, "publish_refused"):
                        c.producer(0)
                self.finish(c, T, NEXT)
                self.assertEqual(got, "unsealed_reservation")

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
                        c.send(0, {9: [20]})  # each batch checks too: the running nonce still opens the registry
                    self.assertEqual(c.send(1, {9: [20]}), {20: "HOLD ALREADY_DECIDED"})  # the refusal freed nothing
                    with self.assertRaisesRegex(idreg.IdRegistryError, "registry_rewound"):
                        c.boot()  # lazily settled, boot passed and the next reserve freed the paid 20
                    with self.other_process():
                        self.assertEqual(c.send(1, {9: [20]}), {20: "HOLD registry_not_booted"})  # the refusal fenced the nonce
                else:
                    c.boot()  # the store is behind only a batch whose tokens never left
                    self.finish(c, NEXT)  # 20 freed, decided again and paid once; inv holds

    def test_r4_a_swapped_registry_is_not_booted(self) -> None:
        with self.cluster() as c:
            c.send(0, T, BAD)
            old = snapshot(c.reg)
            c.boot()
            restore(c.reg, old)
            reserved = count(c, 0)
            self.assertEqual((c.send(0, NEXT), count(c, 0)), ({20: "HOLD registry_not_booted"}, reserved))

    def pay(self, c: g.Cluster, store: payer.PayerStore, k: int, p: int) -> str | None:
        """Shard k decides payment p (line 10, X) and seals it; the payer stores the checkpoint, sends p and releases it."""
        prod, reg = c.producer(k), idreg.IdRegistry(c.reg, boot=c.nonce)
        try:
            ans, leaves, status = g.decide_batch(c, prod, reg, k, {p: [10]})
            _, signed, tokens = decider.commit(prod, reg, fx.PROGRAM, leaves, ans, fx.NOW)
        finally:
            prod.close()
            reg.close()
        self.assertEqual((status, store.store_checkpoint(signed)), ({10: "ALLOW -"}, "stored"))
        store.send(request(p, k), transmit=lambda data: None)
        return store.release(request(p, k), gate.encode_token(tokens[0]), now=fx.NOW)

    @contextlib.contextmanager
    def released_then_restored(self, restart: bool = True, shards: int = 2, k: int = 0, repoint: bool = False):
        """Copy the whole directory; shard ``k`` pays X in payment 1 (sealed, stored and released by the payer).  Then the
        copy comes back and, with ``restart``, the process restarts: it holds no nonce until a boot passes.  With
        ``repoint`` the cluster reaches its directory through a link, and the copy comes back by re-pointing the link."""
        with tempfile.TemporaryDirectory() as keep, self.cluster(shards) as c:
            copy, at = Path(keep) / "copy", Path(keep) / "current"
            shutil.copytree(c.dir, copy)
            c.payer = store = self.track(payer.PayerStore(Path(keep) / "payer.sqlite3", root_keys={fx.TENANT: c.custody[1]},
                                                          grants=((fx.D[3], (fx.D[4],), (fx.D[6],)),)))
            store.install_cert(c.custody[2])
            try:
                if repoint:
                    c.dir = link(at, c.dir)
                self.assertIsNone(self.pay(c, store, k, 1))
                if repoint:
                    link(at, copy)
                else:
                    for f in c.dir.iterdir():
                        f.unlink()
                    shutil.copytree(copy, c.dir, dirs_exist_ok=True)
                if restart:
                    c.nonce = b""
                yield c, store
            finally:
                link(at, None)

    def test_r5_restore_after_release_holds(self) -> None:
        """Design idreg-restore T1 (was ``test_r5_whole_directory_restore_boots_and_forks``, the residual): the restored
        store lacks the payer's newest stored checkpoint, so boot is refused and the gate HOLDs; X is released once."""
        with self.released_then_restored() as (c, store):
            with self.assertRaisesRegex(idreg.IdRegistryError, "store_rewound"):
                c.boot()
            reserved = count(c, 0)
            self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_restored"})  # shard 1 tries X for payment 2
            ans = g.decide_batch(c, None, None, 1, {2: [10]})[0]
            with self.assertRaisesRegex(decider.GateDecideError, "registry_restored"):
                decider.commit(None, None, fx.PROGRAM, [], ans, fx.NOW)  # a HOLD answer is never sealed
            self.assertEqual((count(c, 0), c.store(1).exists()), (reserved, False))  # no reserve, no checkpoint
            store.send(request(2, 1), transmit=lambda data: None)  # intake during HOLD is accepted
            self.assertEqual(store._db.execute("SELECT COUNT(*) FROM commands WHERE command_key=?",
                                               (request(2, 1).command_key,)).fetchone()[0], 1)
            self.assertEqual(store._db.execute("SELECT payment_id FROM releases").fetchall(), [("pay-0001",)])

    def releases(self, store: payer.PayerStore) -> list[str]:
        return [p for (p,) in store._db.execute("SELECT payment_id FROM releases ORDER BY payment_id")]

    @staticmethod
    def other_process():
        """Run as another process on the same nonce whose registry memory predates the copy: only a fence stops it."""
        return mock.patch.multiple(idreg, _SEEN={}, _STOPPED=set())

    def test_r5_refused_boot_fences_the_running_nonce(self) -> None:
        """Review HIGH-1: processes keep running with the copy's newest nonce; the refused boot's BOOT row fences them,
        so shard 1's X HOLDs and X is released once.  Mutant: without that row the old nonce reserves and X pays twice."""
        add = idreg._Tail.add
        for mutant in (False, True):
            fence = mock.patch.object(idreg._Tail, "add", lambda t, kind, *a: kind == idreg._BOOT or add(t, kind, *a)) \
                if mutant else contextlib.nullcontext()
            with self.subTest(mutant=mutant), self.released_then_restored(restart=False) as (c, store), fence:
                with self.assertRaisesRegex(idreg.IdRegistryError, "store_rewound"):
                    c.boot()
                with self.other_process():
                    if mutant:
                        self.assertIsNone(self.pay(c, store, 1, 2))
                    else:
                        self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertEqual(self.releases(store), ["pay-0001", "pay-0002"][: 1 + mutant])

    def test_r5_a_boot_that_cannot_read_its_inputs_fences(self) -> None:
        """Review HIGH-1b: the payer or a shard's store cannot be read while booting.  Boot reads them inside its
        transaction, so the refusal fences the running nonce and shard 1's X HOLDs (before: the caller read them first,
        boot raised before its fence and the old nonce ALLOWed X again)."""
        for target, name, error, label in ((None, "newest_stored", sqlite3.OperationalError("disk I/O error"), "payer_unavailable"),
                                           (producer, "newest", PermissionError(13, "denied"), "inputs_unavailable"),
                                           (producer, "newest", sqlite3.OperationalError("disk I/O error"), "inputs_unavailable"),
                                           (producer, "newest", producer.GateProducerError("store_unavailable"), "store_unavailable")):
            with self.subTest(label, error=error), self.released_then_restored(restart=False) as (c, store):
                if target:
                    c.store(1).touch()  # a store to read: the copy predates every batch
                with mock.patch.object(target or store, name, side_effect=error), self.assertRaises(idreg.IdRegistryError) as refused:
                    c.boot()
                with self.other_process():
                    self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertEqual(self.releases(store), ["pay-0001"])
                self.assertRegex(str(refused.exception), label)
                if target:
                    self.assertIsInstance(refused.exception.__cause__, type(error))

    def test_r5_the_refusal_and_its_fence_are_one_transaction(self) -> None:
        """Review M-A: the moment the refused boot's connection gives up the write lock, the running nonce's shard 1 tries
        X.  The fence committed with the refusal, so X HOLDs (before: ROLLBACK freed the lock, X ALLOWed, and only then
        did a second transaction write the fence)."""
        with self.released_then_restored(restart=False) as (c, store):
            seen, real = [], idreg._open

            class Hooked:  # the registry connection; the first COMMIT or ROLLBACK on it runs shard 1's batch
                def __init__(self, db):
                    self.db = db

                def __getattr__(self, name):
                    return getattr(self.db, name)

                def execute(self, sql, *args):
                    cursor = self.db.execute(sql, *args)
                    if sql in ("COMMIT", "ROLLBACK") and not seen:
                        seen.append(None)
                        with ShardTests.other_process():
                            seen[0] = c.send(1, {2: [10]})
                    return cursor
            with mock.patch.object(idreg, "_open", lambda *a: Hooked(real(*a))), \
                    self.assertRaisesRegex(idreg.IdRegistryError, "store_rewound"):
                c.boot()
            self.assertEqual((seen, self.releases(store)), ([{10: "HOLD registry_not_booted"}], ["pay-0001"]))

    def test_r5_a_payer_shard_outside_the_boot_is_refused(self) -> None:
        """Review MEDIUM-1: shard 2 of 3 pays X, the directory comes back and boots with 2 shards; the payer holds shard
        2 outside the commitments, so boot is ``anchor_missing`` and X is released once.  Mutant: an anchor map cut to
        the booted shards checks nothing, and shard 0 pays X again."""
        for mutant in (False, True):
            with self.subTest(mutant=mutant), self.released_then_restored(shards=3, k=2) as (c, store):
                c.shards = 2
                if mutant:
                    stored = store.newest_stored
                    with mock.patch.object(store, "newest_stored", lambda t: {s: d for s, d in stored(t).items() if s < 2}):
                        c.boot()
                    self.assertIsNone(self.pay(c, store, 0, 2))
                else:
                    with self.assertRaisesRegex(idreg.IdRegistryError, "anchor_missing"):
                        c.boot()
                    self.assertEqual(c.send(0, {2: [10]}), {10: "HOLD registry_restored"})
                self.assertEqual(self.releases(store), ["pay-0001", "pay-0002"][: 1 + mutant])

    def fenced(self, c: g.Cluster) -> bool:
        """The registry's newest BOOT row is not the running nonce's."""
        with contextlib.closing(sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True)) as db:
            newest = db.execute("SELECT id FROM log WHERE kind = 3 ORDER BY n DESC LIMIT 1").fetchone()[0]
        return newest != c.nonce.rjust(idreg.ID_LEN, b"\0")

    def test_r5_restore_while_running_no_boot(self) -> None:
        """Review HIGH-2: the directory comes back under a running process that never reboots.  It holds the copy's
        newest nonce, but the row it last wrote is gone, so shard 1's X HOLDs before any reserve, and the fence that
        check commits stops the other processes on the nonce too.  X is released once.  Review HIGH-1: the same when the
        restore re-points a directory link (the memory is keyed by the nonce, not the path)."""
        for repoint in (False, True):
            with self.subTest(repoint=repoint), self.released_then_restored(restart=False, repoint=repoint) as (c, store):
                reserved = count(c, idreg._RESERVE)
                self.assertEqual((self.fenced(c), self.releases(store), c.store(0).exists()), (False, ["pay-0001"], False))
                self.assertNotIn(c.nonce.rjust(idreg.ID_LEN, b"\0"), idreg._STOPPED)
                self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertIn(c.nonce.rjust(idreg.ID_LEN, b"\0"), idreg._STOPPED)  # review M-2: the memory mismatch stops the nonce
                with self.other_process():
                    self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertEqual((count(c, idreg._RESERVE), self.releases(store), g.sealed_allows(c, 1)), (reserved, ["pay-0001"], {}))

    def test_r5_a_boot_that_cannot_lock_or_commit_stops_the_process(self) -> None:
        """Review MEDIUM-1: another writer holds the lock past boot's timeout, or boot's COMMIT fails (always, or once),
        so its fence may not land and boot raises ``registry_unavailable``.  Every handle of this process then HOLDs
        until a boot passes, and the first to lock commits the fence (a COMMIT that failed once: the boot's own retry
        did), which stops the other processes on the nonce.  The memory of the restored-away row is cleared, so the
        HIGH-2 check is not what HOLDs here.  X is released once.  Review LOW-4: a boot that cannot open the registry
        (its directory missing) stops the process too; review HIGH-1: so does a boot that cannot lock, when the next
        restore re-points the directory link to a fresh copy (the stop is keyed by the newest nonce, not the path)."""
        real = idreg._open

        class Failing:  # boot's connection: COMMIT raises ``left`` times
            def __init__(self, db, left):
                self.db, self.left = db, left

            def __getattr__(self, name):
                return getattr(self.db, name)

            def execute(self, sql, *args):
                if sql == "COMMIT" and self.left:
                    self.left -= 1
                    raise sqlite3.OperationalError("disk I/O error")
                return self.db.execute(sql, *args)
        lock = lambda path, timeout=5.0: real(path, 0.1)
        for trigger, hook in (("lock", lock), ("lock, re-pointed", lock), ("commit", lambda *a: Failing(real(*a), 2)),
                              ("commit once", lambda *a: Failing(real(*a), 1)),
                              ("open", lambda path, *a: real(path.parent / "missing" / path.name, *a))):
            with self.subTest(trigger), self.released_then_restored(restart=False, repoint="re-pointed" in trigger) as (c, store), \
                    mock.patch.object(idreg, "_SEEN", {}), contextlib.closing(sqlite3.connect(c.reg, isolation_level=None)) as writer:
                if trigger.startswith("lock"):
                    writer.execute("BEGIN IMMEDIATE")
                with mock.patch.object(idreg, "_open", hook), self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                    c.boot()
                if trigger.startswith("lock"):
                    writer.execute("ROLLBACK")
                if "re-pointed" in trigger:  # restored again from the same copy, through the link
                    shutil.copytree(c.dir, c.dir.parent / "again")
                    link(c.dir, c.dir.parent / "again")
                self.assertEqual(self.fenced(c), trigger == "commit once")
                self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                with self.other_process():
                    self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertEqual(self.releases(store), ["pay-0001"])

    def test_r5_a_boot_after_a_restore_starts_a_fresh_memory(self) -> None:
        """Review LOW-3: worker W, handed its nonces and never booting, commits shard 0's batch; the directory then comes
        back from a copy taken at the boot and another process boots it (no payer, so B3 has nothing to check).  W's
        memory is kept per nonce, and a new nonce comes only from a passed boot, so W's shard 1 ALLOWs on it (before: W
        found its row gone and fenced this boot and every later one)."""
        with tempfile.TemporaryDirectory() as keep, self.cluster() as c:
            shutil.copytree(c.dir, Path(keep) / "copy")
            c.send(0, T, BAD)
            for f in c.dir.iterdir():
                f.unlink()
            shutil.copytree(Path(keep) / "copy", c.dir, dirs_exist_ok=True)
            with self.other_process():
                c.boot()
            self.assertEqual(c.send(1, NEXT), {20: "ALLOW -"})

    def test_r5_a_worker_that_never_boots_pays_x_once(self) -> None:
        """Review M-1 (s3fix1): worker W, never booting, commits shard 0 under N1; a copy is taken; this process reboots
        (N2); W's shard 0 pays X under N2, W's shard 1 still on N1 HOLDs; the copy comes back (newest BOOT N1, no boot).
        W's first pass on N2 stopped every older nonce in W, so shard 1 on N1 HOLDs (before: W's N1 memory matched the
        copy, and X paid twice).  Review M-1 (s3fix2): this process pays X, outside W; W never runs on N2, but its
        shard 1 found N1 displaced, which stops N1 in W, so after the copy comes back X HOLDs (before: W paid X again)."""
        for in_w in (True, False):
            w = {"_SEEN": {}, "_STOPPED": set()}  # W's process memory
            with self.subTest(in_w=in_w), tempfile.TemporaryDirectory() as keep, self.cluster() as c:
                n1 = c.nonce
                with mock.patch.multiple(idreg, **w):
                    self.assertEqual(c.send(0, NEXT), {20: "ALLOW -"})
                shutil.copytree(c.dir, Path(keep) / "copy")
                c.boot()
                with mock.patch.multiple(idreg, **w) if in_w else contextlib.nullcontext():
                    self.assertEqual(c.send(0, {1: [10]}), {10: "ALLOW -"})
                with mock.patch.multiple(idreg, **w):
                    c.nonce = n1
                    self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                    for f in c.dir.iterdir():
                        f.unlink()
                    shutil.copytree(Path(keep) / "copy", c.dir, dirs_exist_ok=True)
                    reserved = count(c, idreg._RESERVE)
                    self.assertEqual(c.send(1, {2: [10]}), {10: "HOLD registry_not_booted"})
                self.assertEqual(count(c, idreg._RESERVE), reserved)

    def test_r5_a_handle_open_across_a_copy_and_repoint_holds(self) -> None:
        """Review M-2 (s3fix1): handle P, opened through a directory link, lives on while the operator copies the
        directory and re-points the link; another process boots the copy and its shard 1 pays X.  P's next transaction
        finds another file at its path, so P's X HOLDs (before: P never saw the copy's BOOT and paid X again)."""
        with tempfile.TemporaryDirectory() as keep, self.cluster() as c:
            home, c.dir = c.dir, link(Path(keep) / "current", c.dir)
            try:
                with contextlib.closing(c.producer(0)) as prod, contextlib.closing(idreg.IdRegistry(c.reg, boot=c.nonce)) as p:
                    shutil.copytree(c.dir, Path(keep) / "copy")
                    link(c.dir, Path(keep) / "copy")
                    with self.other_process():
                        c.boot()
                        self.assertEqual(c.send(1, {2: [10]}), {10: "ALLOW -"})
                    self.assertEqual(g.decide_batch(c, prod, p, 0, {1: [10]})[2], {10: "HOLD registry_not_booted"})
                    self.assertIn(p._boot, idreg._STOPPED)
                real = idreg._open  # review M-2 (s3fix2): the link moves back between Q's connect and its identity read
                with mock.patch.object(idreg, "_open", lambda *a: (real(*a), link(c.dir, home))[0]), \
                        self.assertRaisesRegex(idreg.IdRegistryError, "registry_unavailable"):
                    idreg.IdRegistry(c.reg, boot=c.nonce)  # before: Q took the copy's identity while writing the other file
            finally:
                link(c.dir, None)

    def test_r5_mutant_without_the_store_check_pays_twice(self) -> None:
        """Mutant M1: with B3 a no-op the restored directory boots, shard 1 releases X again in payment 2, and the
        payer sees no fork (two shards); only shard 0 re-publishing its seq is a fork."""
        with self.released_then_restored() as (c, store):
            with mock.patch.object(producer, "holds", return_value=True):
                c.boot()
            self.assertIsNone(self.pay(c, store, 1, 2))
            self.assertEqual(store._db.execute("SELECT payment_id FROM releases ORDER BY payment_id").fetchall(),
                             [("pay-0001",), ("pay-0002",)])
            c.send(0, {3: [30]})  # the restored shard publishes a different batch at the same seq
            again = c.producer(0)
            new = again.published()[-1]
            again.close()
            self.assertEqual(store.store_checkpoint(new), "fork")

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
                decider.decide(g.rules.EXE, c.dir / f"batch{k}.vectors", g._HEAD, g.ASOF, prod, reg, [i], [line])
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
