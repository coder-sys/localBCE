"""Test-only multi-shard scenario harness (multi-shard-runtime-v1 section B).  One batch per shard is the decide layer
(``right_rail_gate_decide``: ``gate_engine`` on the shard's history index), then commit.  It holds no
policy: every token's outcome is Lean's ``RULES_PAY`` answer.  A crash is a child
process that exits at a monkeypatched point.  Synthetic, non-PHI."""

from __future__ import annotations

import json
import os
import random
import shutil
from pathlib import Path
import sqlite3
import contextlib
import functools
import hashlib
from itertools import count
import subprocess
import sys

from tests._test_only_counter import TestOnlyCounter
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_producer as producer
from conformance import gate_rules_v2_ref as ref
from tests import _gate_authority as au
from tests import test_gate_rules_vectors as rules
from tests import test_right_rail_gate_formats as fx

ROOT = Path(rules.ROOT)
ENGINE = Path(rules.LEAN) / ".lake" / "build" / "bin" / "gate_engine.exe"
_HEAD = []
for _row in (ROOT / "tests" / "gate_rules" / "shards_v1.vectors").read_text("utf-8").splitlines():
    if _row.startswith(("#", "case")):
        break
    _HEAD.append(_row)
ASOF = int(next(row for row in _HEAD if row.startswith("snap released")).split()[2])  # the genesis sets' date


def nat(b: bytes) -> int:
    """Lean's identifier number for identifier bytes (Rules.idNat): 0x01, then the bytes, big-endian."""
    return int.from_bytes(b"\x01" + b, "big")


def lid(i: int) -> int:
    """Lean's number for the line identifier ``L<i>`` of harness line ``i``."""
    return nat(f"L{i}".encode())


def unlid(n: int) -> int:
    """The harness line number in Lean's identifier number for ``L<i>``."""
    return int(n.to_bytes((n.bit_length() + 7) // 8, "big")[2:])


@functools.lru_cache(maxsize=None)
def member(m: int, k: int) -> bytes:
    """The key of harness member ``m`` (the snapshots' small member numbers) that routes to shard ``k``: a publish is refused
    for a token whose member key routes elsewhere."""
    return next(key for i in count() if gate.shard_of(fx.TENANT, key := hashlib.sha3_256(f"harness-member-{m}/{i}".encode()).digest()[: gate.MEMBER_KEY], fx.SHARDS) == k)


def _with_members(head: list[str]) -> list[str]:
    """The vector header with an enrollment span and a death row added for every harness member: the member key's number
    stands where the snapshots have the small number, so a request (which names a key) is decided as its small-number line was."""
    old = {kind: [r for r in head if r.split()[:1] == [kind]] for kind in ("span", "dmf")}
    out = []
    for row in head:
        f = row.split()
        if f[:1] in (["span"], ["dmf"]):
            continue  # re-emitted after the snapshot line, with the harness members
        out.append(row)
        if f[:1] == ["snap"] and f[1] in old:
            mine = old[f[1]] + [" ".join([f[1], str(nat(member(int(r.split()[1]), k))), *r.split()[2:]]) for r in old[f[1]] for k in range(fx.SHARDS)]
            vals = [tuple(int(x) for x in r.split()[1:]) for r in mine]
            pin = hashlib.sha3_512(ref.pin_bytes(f[1], int(f[2]), len(vals), vals)).hexdigest()
            out[-1] = f"snap {f[1]} {f[2]} {len(mine)} {pin}"
            out += mine
    return out


_HEAD = _with_members(_HEAD)


def feeds_of(head: list[str]) -> tuple[int, tuple[tuple[bytes, bytes], ...]]:
    """A vector header as the host's read set: ``today``, and each feed framed from its rows with the ``snap`` line's own
    count and pin (so a header may carry wrong ones); no ``snap`` line is an absent feed, a ``snap`` line that does not parse a missing one."""
    def one(kind: str) -> tuple[bytes, bytes]:
        snap = next((r.split() for r in head if r.startswith(f"snap {kind} ")), None)
        if snap is None:
            return bytes(77), b""
        try:
            if len(snap) != 5 or len(pin := bytes.fromhex(snap[4])) != 64:
                raise ValueError
            desc, rows = decider.feed(kind, int(snap[2]), [tuple(map(int, r.split()[1:])) for r in head if r.split()[:1] == [kind]])
            count = int(snap[3]).to_bytes(4, "little")
        except (ValueError, OverflowError):
            return b"\x02" + bytes(76), b""
        return (desc[:5] + count + desc[9:13] + pin, rows) if desc[0] == 1 else (desc, rows)
    return next((int(r.split()[1]) for r in head if r.startswith("today ")), 0), tuple(map(one, decider.FEED_WIDTHS))


HEAD = feeds_of(_HEAD)
EXIT = 77
BAD_DATE = 20280101  # after every enrollment span: a line dated so is MEMBER_NOT_ENROLLED
UNSIGNED = "RR_GATE_UNSIGNED"  # test-only switch: "1" selects the signer-free authority (_gate_authority_unsigned)
_AUTHORITY: dict = {}


def _authority() -> dict:
    """The authority the harness decides under, built at first use (importing this module runs no signer):
    ``GRANT`` (the program's TRANSFER grant), ``KEYS`` (the key set it is admitted under), ``GRANT_ID`` and ``PIN`` (the
    tenant's key-set pin, its GATE_KEYSET_PIN deployment slot).  Unset ``RR_GATE_UNSIGNED`` (or "0"): the signed
    ``au.standing()`` and ``au.genesis()``, as always; a missing signer fails as before, never falls back.  "1": the
    signer-free fixture of the same shape, which only ``gate_engine_unsigned`` admits.  Read once; any other value is refused."""
    if not _AUTHORITY:
        mode = os.environ.get(UNSIGNED)
        if mode not in (None, "", "0", "1"):
            raise RuntimeError(f"{UNSIGNED}={mode!r}: only 1 (signer-free fixture) or unset (signed)")
        if mode == "1":
            from tests import _gate_authority_unsigned as source
        else:
            source = au
        grant, keys = source.standing()
        _AUTHORITY.update(GRANT=grant, KEYS=keys, GRANT_ID=source.grant_id(grant), PIN=source.genesis()[0], unsigned=mode == "1")
    return _AUTHORITY


def __getattr__(name: str):
    """``GRANT``, ``KEYS``, ``GRANT_ID`` and ``PIN`` resolve lazily (``_authority``); call sites keep ``g.GRANT`` and so on."""
    if name in ("GRANT", "KEYS", "GRANT_ID", "PIN"):
        return _authority()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class _Idle:
    """A shard of the tenant that is not open now: it has no sealed record to report."""

    def __init__(self, shard: int) -> None:
        self.shard, self.tenant = shard, fx.TENANT

    def authority(self) -> None:
        return None


class Cluster:
    """A scratch directory with one producer store per shard; ``lines`` maps (shard, payment number) to the ids it carries,
    because a token holds only the lines' root."""

    def __init__(self, tmp: str, custody: tuple[str, bytes, bytes], shards: int = 2) -> None:
        self.dir, self.custody, self.shards, self.lines = Path(tmp), custody, shards, {}
        self.payer = None  # the PayerStore whose newest stored checkpoint each store must hold when it opens
        self.open: dict[int, producer.ShardProducer] = {}  # each shard's newest producer
        self._tenant = None  # the one authority of the tenant, built when first asked for

    @property
    def tenant(self) -> decider.TenantAuthority:
        """The tenant's one authority (one grant floor file for every shard of the tenant), built over the shards open when it is
        first asked for; a shard opened later takes its place (``producer``)."""
        if self._tenant is None:
            live = {k: p for k, p in self.open.items() if not p._closed}  # a shard not open now stands in with no sealed record
            self._tenant = au.tenant(self.dir / "tenant.floor", [live.get(k) or _Idle(k) for k in range(self.shards)])
        return self._tenant

    def store(self, k: int) -> Path:
        return self.dir / f"s{k}.sqlite3"

    def producer(self, k: int) -> producer.ShardProducer:
        handle, root_pk, cert = self.custody
        newest = self.payer.newest_stored(fx.TENANT).get(k, gate.ZERO_DIGEST) if self.payer else gate.ZERO_DIGEST
        self.open[k] = producer.ShardProducer(self.store(k), mark_path=self.dir / f"s{k}.mark", tenant_id=fx.TENANT, shard_id=k,
                                              epoch=fx.EPOCH, handle=handle, root_pk=root_pk, key_cert=cert, payer_newest=newest,
                                              counter=TestOnlyCounter(self.dir / f"s{k}.counter"),
                                              floors=lambda: decider.TenantAuthority.floors_in(self.dir / "tenant.floor", fx.TENANT))
        if self._tenant is not None:
            self._tenant.member(self.open[k])
        return self.open[k]

    def send(self, k: int, payments: dict[int, list[int]], bad=(), crash: str | None = None) -> dict[int, str]:
        """One batch on shard ``k``: payment number -> its line ids (a line in ``bad`` is dated outside its member's enrollment).  Returns
        id -> 'OUTCOME REASONS'.  With ``crash`` ('commit', 'seal' or 'after') a child runs it and dies there."""
        if crash is None:
            return run_batch(self, k, payments, bad)
        self.lines.update({(k, n): ids for n, ids in payments.items()})
        args = json.dumps([str(self.dir), [self.custody[0], self.custody[1].hex(), self.custody[2].hex()], self.shards, k, payments, list(bad), crash])
        done = subprocess.run([sys.executable, "-m", "tests._gate_shards", args], cwd=ROOT, capture_output=True, timeout=900)
        if done.returncode != EXIT:
            raise AssertionError(f"the child did not die at {crash}: {done.returncode} {done.stderr.decode()[-600:]}")
        return {}



def release() -> bytes:
    """The engine's SHA3-512: every token's rule version and engine release (``RulesWorker.release``)."""
    return gate.sha3_512(ENGINE.read_bytes())


_MEMO: dict[int, tuple] = {}


def claim(i: int, dead: bool) -> str:
    """The line's fields after ``FFS_CLAIM``.  Default: every claim one member, provider and code (a near-duplicate of all earlier).
    ``RR_GATE_BENCH_CORPUS=realistic``: seeded and distinct (mostly enrolled members of the snapshot, the rest unknown ids; 200 providers;
    12 procedures; dates 1 Jan to 14 Mar 2027; lognormal cents), 1% exact and 1% near duplicates of an earlier line (same key, other cents)."""
    if os.environ.get("RR_GATE_BENCH_CORPUS") != "realistic":
        return f"{9001 if dead else 1001} 7001 7001 {20270301 + i % 14} 99213 1 {12500 + i}"
    if i not in _MEMO:
        r = random.Random(20261021 * 1000003 + i)
        x = r.random()
        if i > 1 and x < 0.02:  # an earlier line's key: exact (same cents) under 0.01, else near
            j = i - 1 - r.randrange(min(i - 1, 500))
            claim(j, False)
            m, p, d, c, u, a = _MEMO[j]
            a = a if x < 0.01 else a + 1 + r.randrange(99)
        else:
            m = r.choice((1001, 1002, 1006, 1007, 1009)) if r.random() < 0.7 else 10000 + r.randrange(20000)
            day = r.randrange(73)  # Jan 1-31, Feb 1-28, Mar 1-14
            d = 20270101 + day if day < 31 else 20270201 + day - 31 if day < 59 else 20270301 + day - 59
            p, u, a = 7000 + r.randrange(200), 1 + (r.random() < 0.1) * r.randrange(1, 4), int(r.lognormvariate(8.5, 0.8))
            c = r.choice((99213, 99214, 99212, 99203, 99204, 97110, 80053, 85025, 71046, 93000, 36415, 90834))
        _MEMO[i] = (m, p, d, c, u, a)
    m, p, d, c, u, a = _MEMO[i]
    return f"9001 {p} {p} {20270301 + i % 14} {c} {u} {a}" if dead else f"{m} {p} {p} {d} {c} {u} {a}"  # a death is only certain for service after it


def wipe(d: Path) -> None:
    """Empty a scratch directory, history-index directories included."""
    for f in d.iterdir():
        shutil.rmtree(f) if f.is_dir() else f.unlink()


def request(p: int, k: int, ids: list[int], bad=()) -> gate.DecideRequest:
    """The payer's request for harness payment ``p``, its lines built from ``claim`` (the old ``line`` text), A payment's lines share one member and payee (the decoder checks it): the first
    line's.  A line in ``bad`` is dated outside the member's enrollment (BAD_DATE), so Lean holds it and not its siblings."""
    rows = [claim(i, False).split() for i in ids]
    key, payee = member(int(rows[0][0]), k), f"P{rows[0][1]}"
    lines = tuple(gate.encode_line("FFS_CLAIM", f"L{i}", key, payee, f"R{r[2]}", BAD_DATE if i in bad else int(r[3]), f"C{r[4]}", int(r[5]), int(r[6]))
                  for i, r in zip(ids, rows))
    return gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{p:04d}", f"pay-{p:04d}", key, payee,
                              sum(int(r[6]) for r in rows), fx.PERIOD, lines, tuple(sorted((fx.D[2], fx.D[5]))))


def decide_batch(c: Cluster, prod, k: int, payments: dict[int, list[int]], bad=(), worker=None, flat=None, seal=None):
    """Decide one batch on shard ``k`` without committing it (``seal``: the program and time; first seal any batch left decided but unsealed): (answer, Lean's token answers, id -> 'OUTCOME REASONS')."""
    c.lines.update({(k, n): ids for n, ids in payments.items()})
    own = worker or decider.RulesWorker(ENGINE)  # without a worker the batch gets its own, closed at once: it holds the index open
    try:
        ans = decider.decide(HEAD, ASOF, prod, [request(p, k, v, bad) for p, v in payments.items()], flat or c.dir / f"idx{k}", own, _authority()["GRANT"], _authority()["KEYS"], c.tenant, seal=seal)
    finally:
        if worker is None:
            own.close()
    status = {}
    for row in ans.lines:  # a whole-answer HOLD is one row per payment: every line of it holds for that reason
        f = row.split()
        status.update({i: " ".join(f[1:3]) for i in payments[int(f[0][4:])]})
    for rec in ans.recs:  # the engine's records come in decision order; each names its line by position
        pid, at = ans.owners[rec.index]
        status[payments[int(pid[4:])][at]] = f"{rec.outcome} {','.join(rec.reasons) or '-'}"
    return ans, list(ans.pays), status


def run_batch(c: Cluster, k: int, payments: dict[int, list[int]], bad=()) -> dict[int, str]:
    prod = c.producer(k)
    try:
        ans, leaves, status = decide_batch(c, prod, k, payments, bad, seal=(fx.PROGRAM, fx.NOW))
        if leaves:  # a batch with no token is never sealed: the next open at the signed head discards it
            decider.commit(prod, fx.PROGRAM, ans, fx.NOW, c.tenant)
        return status
    finally:
        prod.close()


def read_only(path) -> sqlite3.Connection:
    """A closed store, read without creating or changing a file (a plain read-only connection makes -shm and -wal).
    ``immutable`` ignores any -wal, so a store with unmerged frames is refused rather than read short."""
    if Path(f"{path}-wal").exists() and Path(f"{path}-wal").stat().st_size:
        raise RuntimeError(f"{path} is open or was not closed cleanly")
    return sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro&immutable=1", uri=True)


def sealed_allows(c: Cluster, k: int) -> dict[bytes, list[tuple[int, int]]]:
    """Checkpoint digest -> (payment number, line id) for every line of every ALLOW leaf of each sealed batch of shard k.  A
    leaf counts only with the INPUT/v4 its batch frame gives (head before the batch: the previous state digest, or the genesis)."""
    db, found = read_only(c.store(k)), {}
    try:
        rows = db.execute("SELECT digest, seq_from, tokens, frame FROM batches JOIN records ON batch_id = id "
                          "WHERE signature IS NOT NULL ORDER BY id").fetchall()
    finally:
        db.close()
    engine = release()
    for digest, first, data, frame in rows:
        inputs = fx.frame_inputs(frame)
        i, found[digest] = 0, []
        while data:
            size = int.from_bytes(data[:4], "big")
            token, data = data[4 : 4 + size], data[4 + size :]
            p = next(p for (s, p) in c.lines if s == k and f"pay-{p:04d}".encode() in token[:200])
            r = request(p, k, c.lines[(k, p)])  # an ALLOW line has no reason (Rules.Spec), so an ALLOW payment's token has none
            leaf = gate.TokenLeaf(r.tenant_id, fx.PROGRAM, k, r.flow, 0, r.payment_id, r.member_key, r.payee_ref, r.amount_cents,
                                  r.period, gate.lines_root(r.lines), "ALLOW", (), "TRANSFER", _authority()["GRANT_ID"], bytes(64), engine, engine,
                                  inputs.get(gate.encode_decide_request(r), bytes(64)), fx.NOW, fx.EPOCH, first + i, fx.NOW, fx.NOW + producer.LIFETIME)
            if token.startswith(gate.encode_token_leaf(leaf)):
                found[digest] += [(p, line) for line in c.lines[(k, p)]]
            i += 1
    return found


def allowed(c: Cluster) -> list[tuple[int, int, int]]:
    """(shard, payment number, line id) for every line of every ALLOW leaf in every sealed batch of every store."""
    return [(k, p, line) for k in range(c.shards) if c.store(k).exists()  # a shard that never sent has no store
            for paid in sealed_allows(c, k).values() for p, line in paid]


def inv(t, c: Cluster) -> None:
    """The invariant after every scenario: no line ALLOWed twice by a shard."""
    paid = [(k, line) for k, _, line in allowed(c)]
    t.assertEqual(len(paid), len(set(paid)), "a line was ALLOWed twice by one shard")


def _main(argv: list[str]) -> None:
    tmp, (handle, root, cert), shards, k, payments, bad, crash = json.loads(argv[0])
    c = Cluster(tmp, (handle, bytes.fromhex(root), bytes.fromhex(cert)), shards)
    die = lambda *_, **__: os._exit(EXIT)
    if crash in ("commit", "seal"):
        setattr(producer.ShardProducer, "commit" if crash == "commit" else "_seal", die)
    run_batch(c, k, {int(p): v for p, v in payments.items()}, bad)
    if crash == "after":
        die()


if __name__ == "__main__":
    _main(sys.argv[1:])
