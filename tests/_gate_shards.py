"""Test-only multi-shard scenario harness (multi-shard-runtime-v1 section B).  One batch per shard is the decide layer
(``right_rail_gate_decide``: settle, reserve, ``gate_rules`` on the shard's verified sets), then commit.  It holds no
policy beyond the leaf (a payment ALLOWs when all its lines do, as Lean's ``payOutcome``).  A crash is a child
process that exits at a monkeypatched point.  Synthetic, non-PHI."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer
from tests import test_gate_rules_vectors as rules
from tests import test_right_rail_gate_formats as fx

ROOT = Path(rules.ROOT)
_HEAD = []
for _row in (ROOT / "tests" / "gate_rules" / "shards_v1.vectors").read_text("utf-8").splitlines():
    if _row.startswith(("#", "case")):
        break
    _HEAD.append(_row)
ASOF = int(next(row for row in _HEAD if row.startswith("snap released")).split()[2])  # the genesis sets' date
EXIT = 77


class Cluster:
    """A scratch directory with one registry and one producer store per shard; ``lines`` maps (shard, payment number)
    to the ids it carries, because a token holds only the lines' root."""

    def __init__(self, tmp: str, custody: tuple[str, bytes, bytes], shards: int = 2, nonce: bytes = b"") -> None:
        self.dir, self.custody, self.shards, self.nonce, self.lines = Path(tmp), custody, shards, nonce, {}
        self.genesis = (0, gate.ZERO_DIGEST)

    def store(self, k: int) -> Path:
        return self.dir / f"s{k}.sqlite3"

    @property
    def reg(self) -> Path:
        return self.dir / "reg.sqlite3"

    def boot(self) -> None:
        """Boot the registry against every shard's newest signed commitment, else the tenant genesis commitment, which
        the first boot takes from the then-empty registry."""
        self.nonce = idreg.boot(self.reg, {k: (self.store(k).exists() and producer.newest(self.store(k))) or self.genesis
                                           for k in range(self.shards)})
        if self.genesis[0] == 0:
            reg = idreg.IdRegistry(self.reg, boot=self.nonce)
            self.genesis = reg.genesis({})
            reg.close()

    def producer(self, k: int) -> producer.ShardProducer:
        handle, root_pk, cert = self.custody
        return producer.ShardProducer(self.store(k), mark_path=self.dir / f"s{k}.mark", tenant_id=fx.TENANT, shard_id=k,
                                      epoch=fx.EPOCH, handle=handle, root_pk=root_pk, key_cert=cert)

    def send(self, k: int, payments: dict[int, list[int]], bad=(), crash: str | None = None) -> dict[int, str]:
        """One batch on shard ``k``: payment number -> its line ids (a line in ``bad`` is for a deceased member).  Returns
        id -> 'OUTCOME REASONS'.  With ``crash`` ('reserve', 'commit', 'seal' or 'after') a child runs it and dies there."""
        self.lines.update({(k, n): ids for n, ids in payments.items()})
        if crash is None:
            return run_batch(self, k, payments, bad)
        args = json.dumps([str(self.dir), [self.custody[0], self.custody[1].hex(), self.custody[2].hex()], self.shards,
                           self.nonce.hex(), k, payments, list(bad), crash])
        done = subprocess.run([sys.executable, "-m", "tests._gate_shards", args], cwd=ROOT, capture_output=True, timeout=900)
        if done.returncode != EXIT:
            raise AssertionError(f"the child did not die at {crash}: {done.returncode} {done.stderr.decode()[-600:]}")
        return {}


def run_batch(c: Cluster, k: int, payments: dict[int, list[int]], bad=()) -> dict[int, str]:
    prod, reg = c.producer(k), idreg.IdRegistry(c.reg, boot=c.nonce)
    try:
        ans = decider.decide(rules.EXE, c.dir / f"batch{k}.vectors", _HEAD, ASOF, prod, reg, k, [i for v in payments.values() for i in v],
                             [f"{i}:{p} FFS_CLAIM {9001 if i in bad else 1001} 7001 7001 {20270301 + i % 14} 99213 1 {12500 + i}"
                              for p, v in payments.items() for i in v])
        status, pay = {}, {}
        for row in ans.lines:
            f = row.split()
            i, p = map(int, f[0].split(":"))
            status[i] = " ".join(f[9:11])
            pay.setdefault(p, []).append(f[9])
        leaves = [fx._leaf(p, 0, "ALLOW" if set(o) == {"ALLOW"} else "HOLD", shard=k, member_key=fx.member(p, k))
                  for p, o in pay.items() if "WAIT" not in o]
        if leaves:
            prod.commit(fx.PROGRAM, leaves, state_digest=ans.digest, created_at=fx.NOW, idreg=ans.idreg, free=ans.free, adds=ans.adds)
        return status
    finally:
        prod.close()
        reg.close()


def allowed(c: Cluster) -> list[tuple[int, int, int]]:
    """(shard, payment number, line id) for every line of every ALLOW leaf in every sealed batch of every store."""
    found = []
    for k in filter(lambda k: c.store(k).exists(), range(c.shards)):  # a shard that never sent has no store
        db = sqlite3.connect(f"file:{c.store(k)}?mode=ro", uri=True)
        try:
            rows = db.execute("SELECT seq_from, tokens FROM batches WHERE signature IS NOT NULL ORDER BY id").fetchall()
        finally:
            db.close()
        for first, data in rows:
            i = 0
            while data:
                size = int.from_bytes(data[:4], "big")
                token, data = data[4 : 4 + size], data[4 + size :]
                p = next(p for (s, p) in c.lines if s == k and f"pay-{p:04d}".encode() in token[:200])
                leaf = fx._leaf(p, first + i, "ALLOW", shard=k, member_key=fx.member(p, k))
                if token.startswith(gate.encode_token_leaf(replace(leaf, issued_at=fx.NOW, expires_at=fx.NOW + producer.LIFETIME))):
                    found += [(k, p, line) for line in c.lines[(k, p)]]
                i += 1
    return found


def owned(c: Cluster, t) -> dict[bytes, int]:
    """Replay the registry log by hand: the id -> shard it is in the sets of; no RESERVE of an owned id may occur."""
    db, owner = sqlite3.connect(f"file:{c.reg}?mode=ro", uri=True), {}
    try:
        for kind, key, shard in db.execute("SELECT kind, id, shard FROM log WHERE kind < 2 ORDER BY n"):
            if kind == 0:
                t.assertNotIn(key, owner, "an id was reserved while owned")
                owner[key] = shard
            else:
                t.assertEqual(owner.pop(key), shard)
    finally:
        db.close()
    return owner


def inv(t, c: Cluster) -> None:
    """The invariants after every scenario (section B): a) no id ALLOWed twice; b) no id in two sets; c) one more settle
    leaves every reserved id recorded; d) every other id reserves fresh; e) a new boot (it replays the chain) passes."""
    paid = [line for _, _, line in allowed(c)]
    t.assertEqual(len(paid), len(set(paid)), "an id was ALLOWed twice")
    owned(c, t)
    reg = idreg.IdRegistry(c.reg, boot=c.nonce)
    try:
        for k in range(c.shards):
            prod = c.producer(k)
            try:
                reg.reserve(k, [], sealed=prod.sealed_frees())
            finally:
                prod.close()
        held, ids = owned(c, t), sorted({i for v in c.lines.values() for i in v})
        t.assertEqual(reg.reserve(0, ids, sealed=None)[0],
                      [(i, held[idreg._key(i)], True) if idreg._key(i) in held else (i, 0, False) for i in ids])
    finally:
        reg.close()
    c.boot()


def _main(argv: list[str]) -> None:
    tmp, (handle, root, cert), shards, nonce, k, payments, bad, crash = json.loads(argv[0])
    c = Cluster(tmp, (handle, bytes.fromhex(root), bytes.fromhex(cert)), shards, bytes.fromhex(nonce))
    die = lambda *_, **__: os._exit(EXIT)
    if crash == "reserve":
        add = idreg._Tail.add

        def add_then_die(self, kind, *rest):
            add(self, kind, *rest)
            if kind == idreg._RESERVE:
                die()
        idreg._Tail.add = add_then_die
    elif crash in ("commit", "seal"):
        setattr(producer.ShardProducer, "commit" if crash == "commit" else "_seal", die)
    run_batch(c, k, {int(p): v for p, v in payments.items()}, bad)
    if crash == "after":
        die()


if __name__ == "__main__":
    _main(sys.argv[1:])
