"""The payer's certificate and fork witnesses decide as the whole history does, at the size of a long-lived store."""

from __future__ import annotations

import contextlib
from dataclasses import replace
from pathlib import Path
import random
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx

_GRANTS = ((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),)
# The clauses the mutation check drops: the fence witness, the forking-side fork witness, the shard fork witness.
_FENCE = "UNION SELECT min(id) FROM certs WHERE tenant=:t AND epoch=(SELECT max(epoch) FROM certs WHERE tenant=:t) "
_FORKING = "UNION SELECT min(id) FROM forks WHERE tenant=:t AND epoch_forking=:e"
_SHARD = "SELECT min(id) FROM forks WHERE tenant=:t AND shard=:s UNION "


def _key(*parts: object) -> bytes:
    """A public key nothing signs with: only its bytes are compared."""
    return (gate.sha3_512(repr(parts).encode()) * 41)[: gate.ML_DSA_87_PUBLIC_KEY]


def _timed(call) -> float:
    start = time.perf_counter()
    call()
    return time.perf_counter() - start


class _Big:
    """10,000 offered certificates (re-signatures, equivocations, fence-only, refused and other-tenant rows) and 5,000
    forks, installed through Lean INSTALL, which gives every row its role."""

    def __init__(self) -> None:
        rng = random.Random("witnesses-10000")
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.handles = {t: str(tmp / f"root-{t}.key") for t in ("w-big", "x-big")}
        roots = {t: signer.keygen(h) for t, h in self.handles.items()} | {fx.TENANT: fx.keypair(f"root-{fx.TENANT}")[0]}
        self.fields: dict[bytes, tuple[int, int, bytes]] = {}  # each certificate's epoch, shard count and key
        self.unsigned: set[bytes] = set()
        offered = [self.cert("w-big", 1, 4, _key("w", 1)), self.cert("x-big", 1, 3, _key("x", 1))]  # each tenant's shard count
        for tenant, top, shards, count in (("w-big", 2600, 4, 7600), ("x-big", 300, 3, 2398)):
            late = top - (600 if tenant == "w-big" else 60)  # no base certificate covers these epochs
            bases = [self.cert(tenant, e, shards, _key(tenant, e)) for e in range(2, late)]
            pool = list(bases)
            while len(pool) < count:
                kind, e = rng.randrange(5), rng.randrange(1, top)
                if kind == 0:  # a re-signature of a base body (hedged: other bytes)
                    epoch, n, key = self.fields[rng.choice(bases)]
                    pool.append(self.cert(tenant, epoch, n, key))
                elif kind == 1:  # another key: equivocates once the epoch has an installed body
                    pool.append(self.cert(tenant, e, shards, _key(tenant, e, len(pool))))
                elif kind == 2:  # another shard count: fence-only, or equivocation at an installed epoch
                    pool.append(self.cert(tenant, e, shards + 1, _key(tenant, e, "reshard")))
                elif kind == 3:  # not root-signed: refused, leaves no row
                    pool.append(self.cert(tenant, e, shards, _key(tenant, e, len(pool)), signed=False))
                else:
                    pool.append(self.cert(tenant, rng.randrange(late, top + 1), shards, _key(tenant, "late", len(pool))))
            offered += pool
        offered = offered[:2] + rng.sample(offered[2:], len(offered) - 2)
        if len(set(offered)) != 10_000:
            raise AssertionError(f"{len(set(offered))} distinct certificates")
        template = fx.build(fx.batch_leaves(0, 1))[0]

        def side(tenant: str, shard: int, epoch: int, counter: int) -> bytes:  # a fork's side is decoded, never re-verified
            return gate.encode_checkpoint(replace(template, tenant_id=tenant, shard_id=shard, epoch=epoch, counter=counter),
                                          bytes(gate.ML_DSA_87_SIGNATURE))
        forks = []
        for n in range(5000):  # shards 0-3 only: on shards 4-7 only the epoch clauses can block
            tenant, shard, epoch = "w-big" if n % 5 else "x-big", rng.randrange(4), rng.randrange(2700)
            forks.append((tenant, side(tenant, shard, epoch, 2 * n + 1), side(tenant, shard, epoch + rng.randrange(3), 2 * n + 2)))
        path = tmp / "payer.sqlite3"
        self.store = payer.PayerStore(path, root_keys=roots, grants=_GRANTS)
        with self.store._tx():
            for tenant, stored, forking in forks:  # a fork's sides are decoded, never re-verified
                side, other = payer._index(stored), payer._index(forking)
                self.store._db.execute("INSERT INTO forks(tenant, stored, forking, shard, epoch_stored, epoch_forking) VALUES(?,?,?,?,?,?)",
                                       (tenant, stored, forking, side[1], side[2], other[2]))
        for cert in offered:
            if cert in self.unsigned:
                try:
                    self.store.install_cert(cert)
                except payer.GatePayerError as fault:
                    if str(fault) != "cert_refused":
                        raise
                else:
                    raise AssertionError("a certificate that is not root-signed was installed")
            else:
                self.store.install_cert(cert)

    def cert(self, tenant: str, epoch: int, shards: int, key: bytes, *, signed: bool = True) -> bytes:
        body = gate.encode_key_cert(tenant, epoch, shards, key)
        out = gate.attach_signature(body, signer.sign(self.handles[tenant], body) if signed else bytes(gate.ML_DSA_87_SIGNATURE))
        self.fields[out] = (epoch, shards, key)
        if not signed:
            self.unsigned.add(out)
        return out

    def mismatches(self) -> list[str]:
        """Every item a STORE or RELEASE frame decides on (the proofs of ``select_decides`` and ``forks_witness``: the
        tenant's fence and shard count, the epoch's installed key and equivocation, and whether a fork blocks a shard and
        epoch), on the whole history and on the witnesses the store's SQL picks; the items that differ."""
        db, out = self.store._db, []
        rows = {r[0]: r for r in db.execute("SELECT id, tenant, epoch, role, cert FROM certs ORDER BY id")}
        forks = {f[0]: f for f in db.execute("SELECT id, tenant, shard, epoch_stored, epoch_forking FROM forks ORDER BY id")}
        cert_ids = payer._WITNESSES.replace("SELECT cert FROM", "SELECT id FROM", 1)
        fork_ids = payer._FORK_WITNESSES.replace("SELECT stored, forking FROM", "SELECT id FROM", 1)

        def items(chosen: list[tuple]) -> tuple:
            installed = {}
            for r in chosen:
                if r[3] == "INSTALLED":
                    installed.setdefault(r[2], self.fields[r[4]][1:])
            first = next((r for r in chosen if r[3] == "INSTALLED"), None)
            return (max((r[2] for r in chosen), default=None), first and self.fields[first[4]][1], installed,
                    {r[2] for r in chosen if r[3] == "EQUIVOCATES"})

        def blocked(chosen, shard: int, epoch: int | None) -> bool:
            return any(f[2] == shard or f[3] == epoch or f[4] == epoch for f in chosen)

        for tenant, top in (("w-big", 2702), ("x-big", 302), ("nobody", 2)):
            fence, shards, installed, equivocated = items([r for r in rows.values() if r[1] == tenant])
            mine = [f for f in forks.values() if f[1] == tenant]
            for epoch in (None, *range(top)):
                w = items([rows[i] for (i,) in db.execute(cert_ids, {"t": tenant, "e": epoch})])
                if (w[0], w[1], w[2].get(epoch), epoch in w[3]) != (fence, shards, installed.get(epoch), epoch in equivocated):
                    out.append(f"certs {tenant} {epoch}")
                for shard in range(8):
                    chosen = [forks[i] for (i,) in db.execute(fork_ids, {"t": tenant, "s": shard, "e": epoch})]
                    if blocked(chosen, shard, epoch) != blocked(mine, shard, epoch):
                        out.append(f"forks {tenant} {shard} {epoch}")
        return out


_BIG: list[_Big] = []


def _big() -> _Big:
    if not _BIG:
        _BIG.append(_Big())
    return _BIG[0]


def tearDownModule() -> None:
    for big in _BIG:
        big.store.close()
        big.tmp.cleanup()


class BigStoreTests(unittest.TestCase):
    """Every check reads one store, built once for the module (most of this module's time)."""

    def test_the_store_holds_every_kind_of_row(self) -> None:
        db = _big().store._db
        roles = dict(db.execute("SELECT role, count(*) FROM certs GROUP BY role").fetchall())
        self.assertEqual(sorted(roles), ["EQUIVOCATES", "FENCE_ONLY", "INSTALLED"])
        self.assertTrue(all(n >= 300 for n in roles.values()), roles)
        self.assertLessEqual({"w-big", "x-big"}, {t for (t,) in db.execute("SELECT DISTINCT tenant FROM certs")})  # the timing test adds one
        self.assertEqual(db.execute("SELECT count(*) FROM forks").fetchone()[0], 5000)

    def test_every_item_of_the_whole_history_equals_its_witnesses(self) -> None:
        self.assertEqual(_big().mismatches(), [])

    def test_dropping_the_fence_or_a_fork_witness_fails_the_differential(self) -> None:
        big = _big()
        for name, clause in (("_WITNESSES", _FENCE), ("_FORK_WITNESSES", _FORKING), ("_FORK_WITNESSES", _SHARD)):
            sql = getattr(payer, name)
            self.assertIn(clause, sql)
            with self.subTest(clause=clause), mock.patch.object(payer, name, sql.replace(clause, "", 1)):
                self.assertNotEqual(big.mismatches(), [])

    def test_a_release_and_an_install_take_less_time_than_a_64_cert_frame(self) -> None:
        """On the 10,000-cert, 5,000-fork store, against the frame every release carried at the old 64-certificate limit."""
        big = _big()
        store = big.store
        with tempfile.TemporaryDirectory() as tmp:
            handle, root_pk, cert = fx.custody(tmp)
            self.assertEqual(store.install_cert(cert), "INSTALLED")
            signed, tokens = fx.signed_genesis(handle, seal=(root_pk, cert))
            self.assertEqual(store.store_checkpoint(signed), "stored")
            request = fx.payment_request(0)
            store.send(request, transmit=lambda data: None)
            frame64 = (root_pk + payer._list([signer.framed(cert)] * 64) + payer._list([]) + signer.framed(signed)
                       + fx.NOW.to_bytes(8, "big") + store._grants + bytes([0, 1]) + request.member_key
                       + signer.framed(gate.encode_decide_request(request)) + signer.framed(tokens[0]))
            old = min(_timed(lambda: signer.gate_verify(5, frame64)) for _ in range(3))
            first = _timed(lambda: self.assertIsNone(store.release(request, tokens[0], now=fx.NOW)))
            again = min(_timed(lambda: self.assertEqual(store.release(request, tokens[0], now=fx.NOW), "released")) for _ in range(3))
            new = big.cert("w-big", 2601, 4, _key("w", "timing"))
            install = _timed(lambda: self.assertEqual(store.install_cert(new), "INSTALLED"))
        self.assertLess(max(first, again, install), old, (first, again, install, old))


class FullHistoryStore(payer.PayerStore):
    """The store as it was before witnesses: every frame carries every certificate offered so far and every fork."""

    def __init__(self, *args, history: list[bytes], **kwargs) -> None:
        self.history = history
        super().__init__(*args, **kwargs)

    def _witnesses(self, tenant: str, epoch: int | None) -> bytes:
        return payer._list([signer.framed(c) for c in self.history])

    def _fork_witnesses(self, tenant: str | None, shard: int | None, epoch: int | None) -> bytes:
        return payer._list([signer.framed(a) + signer.framed(b)
                            for a, b in self._db.execute("SELECT stored, forking FROM forks ORDER BY id")])


def _answer(call) -> object:
    try:
        return call()
    except payer.GatePayerError as refusal:
        return f"refused {refusal}"


def _signed_cp(handle: str, epoch: int, start: int) -> bytes:
    cp, _ = fx.build([replace(leaf, epoch=epoch) for leaf in fx.batch_leaves(0, 2, start)], gate.ZERO_DIGEST, gate.ZERO_DIGEST, 1)
    header = gate.encode_checkpoint_header(cp)
    return gate.attach_signature(header, signer.sign(handle, header))


class DecisionDifferentialTests(fx.Scratch):
    """Lean decides every INSTALL, STORE and RELEASE twice, on the witnesses and on the whole history, over random
    histories of real certificates (installed, re-signed, equivocating, fence-only, refused, other-tenant)."""

    def test_witness_and_whole_history_answers_are_equal(self) -> None:
        secret = {t: fx.keypair(f"root-{t}")[1] for t in (fx.TENANT, fx.OTHER)}
        roots = {t: fx.keypair(f"root-{t}")[0] for t in (fx.TENANT, fx.OTHER)}

        def cert(tenant: str, epoch: int, shards: int, key: bytes, rnd: int = 0) -> bytes:
            body = gate.encode_key_cert(tenant, epoch, shards, key)
            message = secret[tenant] + bytes([rnd]) * 32 + b"\x00\x00" + body
            return gate.attach_signature(body, fx._kat("kat-sign", message, gate.ML_DSA_87_SIGNATURE))

        for seed in range(3):
            with self.subTest(seed=seed), self.scratch() as tmp:
                rng, handles, certs = random.Random(f"decide-{seed}"), {}, []
                for name in ("e6", "e7", "e8"):
                    handles[name], _, real = fx.custody(tmp, name)
                    certs.append(real)
                for n in range(60):
                    e, kind = rng.randrange(12), rng.randrange(5)
                    if kind == 0:
                        certs.append(cert(fx.TENANT, e, fx.SHARDS, _key(seed, n)))
                    elif kind == 1:
                        certs.append(cert(fx.TENANT, e, fx.SHARDS + 1, _key(seed, n)))
                    elif kind == 2:
                        certs.append(cert(fx.OTHER, e, fx.OTHER_SHARDS, _key(seed, n)))
                    elif kind == 3:  # a copy with its signature zeroed: not root-signed
                        certs.append(rng.choice(certs)[: -gate.ML_DSA_87_SIGNATURE] + bytes(gate.ML_DSA_87_SIGNATURE))
                    else:  # one of nine bodies, signed with one of eight rnd values: re-signatures and repeated equivocations
                        certs.append(cert(fx.TENANT, 6 + n % 3, fx.SHARDS, _key(seed, "resign", n % 9), rng.randrange(1, 9)))
                order = certs[:1] + rng.sample(certs[1:], len(certs) - 1)
                history: list[bytes] = []
                a = self.track(payer.PayerStore(Path(tmp) / "a.sqlite3", root_keys=roots, grants=_GRANTS))
                b = self.track(FullHistoryStore(Path(tmp) / "b.sqlite3", root_keys=roots, grants=_GRANTS, history=history))
                checkpoints = [fx.signed_genesis(handles["e7"], n)[0] for n in (0, 5)] + [
                    _signed_cp(handles[name], epoch, start) for name, epoch in (("e6", fx.EPOCH - 1), ("e8", fx.EPOCH + 1))
                    for start in (0, 5)]
                tokens = fx.signed_genesis(handles["e7"], 0)[1]
                requests = [fx.payment_request(n) for n in range(2)]
                for store in (a, b):
                    for request in requests:
                        store.send(request, transmit=lambda data: None)
                for step, one in enumerate(order):
                    self.assertEqual(_answer(lambda: a.install_cert(one)), _answer(lambda: b.install_cert(one)), step)
                    history.append(one)
                    if step % 8 == 0:
                        for cp in rng.sample(checkpoints, 2):
                            self.assertEqual(_answer(lambda: a.store_checkpoint(cp)), _answer(lambda: b.store_checkpoint(cp)), step)
                        n = rng.randrange(2)
                        self.assertEqual(_answer(lambda: a.release(requests[n], tokens[n], now=fx.NOW)),
                                         _answer(lambda: b.release(requests[n], tokens[n], now=fx.NOW)), step)
                rows = "SELECT tenant, epoch, role, body_sha3_512, cert FROM certs ORDER BY id"
                self.assertEqual(a._db.execute(rows).fetchall(), b._db.execute(rows).fetchall())
                self.assertEqual(a.holds(), b.holds())


class MigrationTests(fx.Scratch):
    def test_a_store_from_before_certificate_roles_or_fork_shards_is_refused_untouched(self) -> None:
        for name, old in (
                ("certs", "DROP TABLE certs; CREATE TABLE certs(cert BLOB PRIMARY KEY)"),
                ("forks", "DROP TABLE forks; CREATE TABLE forks(id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, stored BLOB NOT NULL, "
                          "forking BLOB NOT NULL, UNIQUE(tenant, stored, forking))")):
            with self.subTest(name), self.scratch() as tmp:
                path = Path(tmp) / "payer.sqlite3"
                payer.PayerStore(path, root_keys={}, grants=_GRANTS).close()
                with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as db:
                    for statement in old.split("; "):
                        db.execute(statement)
                image = path.read_bytes()
                with self.assertRaisesRegex(payer.GatePayerError, "store_version"):
                    payer.PayerStore(path, root_keys={}, grants=_GRANTS)
                self.assertEqual(path.read_bytes(), image)

    def test_a_tenant_whose_rows_were_answered_under_another_root_is_refused(self) -> None:
        with self.scratch() as tmp:
            _, root_pk, cert = fx.custody(tmp)
            path = Path(tmp) / "payer.sqlite3"
            store = self.track(payer.PayerStore(path, root_keys={fx.TENANT: root_pk}, grants=_GRANTS))
            store.install_cert(cert)
            store.close()
            with self.assertRaisesRegex(payer.GatePayerError, f"root_changed: {fx.TENANT}"):
                payer.PayerStore(path, root_keys={fx.TENANT: fx.keypair(f"root-{fx.OTHER}")[0]}, grants=_GRANTS)
            payer.PayerStore(path, root_keys={}, grants=_GRANTS).close()  # a tenant this payer does not serve is no change

    def test_every_witness_clause_is_a_seek(self) -> None:
        with self.scratch() as tmp:
            self.track(payer.PayerStore(Path(tmp) / "payer.sqlite3", root_keys={}, grants=_GRANTS))
            with contextlib.closing(sqlite3.connect(Path(tmp) / "payer.sqlite3")) as db:
                for sql, args in ((payer._WITNESSES, {"t": "t", "e": 1}), (payer._FORK_WITNESSES, {"t": "t", "s": 0, "e": 1})):
                    plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN " + sql, args)]
                    self.assertFalse([row for row in plan if row.startswith(("SCAN certs", "SCAN forks"))], plan)


if __name__ == "__main__":
    unittest.main()
