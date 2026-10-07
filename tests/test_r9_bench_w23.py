"""S13 (W2 + W3): the prefix-reusing hashes and the one-builder part loop store exactly what the code at 568ba4e1 stored. The oracle below is a byte copy of
that code (Writer.mutate, Writer.chunk and Shard.build, with only the class wrapper around them); per part, the BUILT digest, the head, the in-memory state and every table
digest are compared between it and the new code, on a seeded multi-part run and on a hostile part set. No timing asserts."""

import hashlib
import pickle
import random
import shutil
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import r9_bench as rb  # noqa: E402
from tools import r9_shard_bench as sb  # noqa: E402

sha, quote, ShardDiverged, verdict_of, SPINE_ID = rb.sha, rb.quote, sb.ShardDiverged, sb.verdict_of, sb.SPINE_ID
LINES = 300


class OracleWriter(rb.Writer):
    def mutate(self, t, touched, index, now, ob: str, key: str, cents: int, kind: str) -> None:
        rev = self.revision[ob]
        self.revision[ob] = rev + 1
        touched[ob] = touched.get(ob, 0) + cents
        ev = f"ev:{index:06d}:{key}"  # zero-padded, so the owner ids the adapter mints are monotone over the day
        pay = f"pay:{index:06d}:{key}"
        command, ckey = ("PAYMENT", pay) if kind == "PAYMENT_RECEIVED" else ("PAYMENT_REVERSAL", ev)
        # the owner's commands row (owner._record_command): the canonical request (keys sorted, ascii strings, compact) then its domain digest; the fixed
        # shape is written out by hand to skip json.dumps (the test pins the stored bytes)
        body = (f'{{"amount_cents":{cents},"command":"{command}","common_origin_id":{quote(f"x12/{key}")},"event_at_ms":{now},"evidence_id":{quote(ev)},'
                f'"item_id":{quote(self.obl[ob])},"key":{quote(ckey)},"local_ref":"","source_id":"x12","source_version":"v1"}}').encode("ascii")
        t["commands"].append((f"{command}:{ckey}", command, body.decode("ascii"), hashlib.sha3_512(b"RR/FINANCIAL/COMMAND/v1\x00" + body).digest(), self.seq + 1))
        t["evidence"].append((ev, self.obl[ob], "PAYMENT", f"x12/{key}", "x12", "v1", "", now, now, now, sha(ev, 1), sha(ev, 2), cents, None, None))
        t["payments"].append((pay, ob, self.obl[ob], ev, f"x12/{key}", abs(cents) or 1, now, 1, None))
        self.seq += 1  # one history event per mutation, hash-chained (SHA3-512)
        payload = f'{{"kind":"{kind}","obligation":"{ob}","before":{rev},"after":{rev + 1},"ref":"{key}"}}'
        pd, previous = sha(payload), self.head
        self.head = sha(previous, pd)
        t["financial_events"].append((self.seq, sha("event", self.seq), "OBLIGATION", ob, kind, rev, rev + 1, payload, pd, previous, self.head, now))

    def chunk(self, index: int, pool: str, rows, pending, resolved) -> None:
        t = {k: [] for k in ("cell_rows", "cells", "resolutions", "charges", "holds", "links", "evidence", "payments", "financial_events", "commands")}
        touched: dict[str, int] = {}  # obligation -> cents received in this chunk
        now = 1_700_000_000_000 + index
        began = dict(self.revision)
        base = index * rb.KEY

        mutate = lambda ob, key, cents, kind: self.mutate(t, touched, index, now, ob, key, cents, kind)  # noqa: E731

        prep = []
        for row_index, row in rows:
            tag, key = row.key[0], "/".join(row.key[1:])
            origin = f"{index}/{tag}/{key}"
            ref = row.key[4] if tag == "PLB" else row.key[1]
            ob = self.obligation(ref)
            cid = sha("RR/CELL/CASH/v2", "bench-tenant", self.obl[ob], origin)  # the real cell id: a random-looking 64-byte digest, so the UNIQUE index on it is the random one
            prep.append((row_index, row, tag, key, origin, ref, ob, cid))
        known = self.known_cells([p[7] for p in prep]) if self.fast else None
        seen: set[bytes] = set()  # keys this chunk creates are answered from memory
        for row_index, row, tag, key, origin, ref, ob, cid in prep:
            amount, rk = row.amount_cents, base + row_index
            if cid in seen or (cid in known if known is not None else self.c.execute("SELECT 1 FROM cells WHERE cell_id=?", (cid,)).fetchone() is not None):
                self.classes["duplicate"] = self.classes.get("duplicate", 0) + 1  # a row already judged (a replayed file) writes nothing
                continue
            seen.add(cid)
            t["cell_rows"].append((rk, origin, tag, amount, row.raw, hashlib.sha3_256(row.raw.encode()).digest()))
            if amount == 0:
                cls = "zero"
                t["cells"].append((rk, cid, origin, pool, ob, "ZERO", amount))
            elif tag == "RAW" or amount is None:
                cls = "held"
                t["cells"].append((rk, cid, origin, pool, ob, "HELD", amount))
            elif amount < 0:
                target = f"{index}/CLP/{ref}"  # "negatives first, then file order": a REV's target is resolved only if it came earlier
                t["cells"].append((rk, cid, origin, pool, ob, "NEGATIVE", amount))
                t["holds"].append((rk, cid, "TARGET"))
                t["links"].append((rk, cid, target, "EFFECTIVE" if target in resolved else "PENDING"))
                if target in resolved:
                    cls = "negative_applied"
                    t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                    t["charges"].append((rk, rk, ob, amount))
                    mutate(ob, key, amount, "PAYMENT_REVERSED")
                else:
                    cls = "negative_pending"
                    pending.setdefault(target, []).append((origin, cid, rk))
            else:
                cls = "applied"
                t["cells"].append((rk, cid, origin, pool, ob, "RESOLVED", amount))
                t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                t["charges"].append((rk, rk, ob, amount))
                for _, negcid, negrk in pending.pop(origin, ()):  # the target's resolution nets each pending link: its resolution and charge only
                    t["resolutions"].append((negrk, negcid, None, 0, "NET"))
                    t["charges"].append((negrk, negrk, ob, 0))
                resolved.add(origin)
                mutate(ob, key, amount, "PAYMENT_RECEIVED")
            self.classes[cls] = self.classes.get(cls, 0) + 1
        for table, data in t.items():
            self.write(table, data)
        self.finish(index, now, touched, began)


class OracleShard(sb.Shard):
    def __init__(self, k: int, db: Path) -> None:
        super().__init__(k, db)
        self.w.mutate = types.MethodType(OracleWriter.mutate, self.w)

    def build(self, n: int, index: int, pool: str, t_f: int, blob: bytes, pre_head: bytes, verdict: bytes) -> tuple[bytes, bytes]:
        t0, w = time.perf_counter(), self.w
        if w.head != pre_head:
            raise ShardDiverged(f"shard {self.k}: head differs from the spine's expected head")
        parts = pickle.loads(blob)
        if verdict_of(parts) != verdict:
            raise ShardDiverged(f"shard {self.k}: verdicts differ from the record")
        seq0, began = w.seq, dict(w.revision)
        if not w.c.in_transaction:  # the first part of a group opens the shard's one transaction; the group is only a commit boundary
            w.ckpt.before_begin()
            w.c.execute("BEGIN IMMEDIATE")
            self.undo, self.pre_mark = [seq0, pre_head, began, 0], 0
        w.c.execute("SAVEPOINT part")  # a refused part leaves no trace, the parts before it in the group stay until the spine aborts the group
        try:
            t = {name: [] for name in ("cell_rows", "resolutions", "charges", "evidence", "payments", "financial_events", "commands")}
            touched: dict[str, int] = {}
            for rk, origin, tag, key, amount, raw, rawdig, ob, cid in parts:
                t["cell_rows"].append((rk, origin, tag, amount, raw, rawdig))
                t["resolutions"].append((rk, cid, None, amount, "INTAKE"))
                t["charges"].append((rk, rk, ob, amount))
                w.mutate(t, touched, index, t_f, ob, key, amount, "PAYMENT_RECEIVED")
            digest = hashlib.sha3_256()
            for name, data in t.items():
                digest.update(pickle.dumps(data, 5))
                w.write(name, data)
            w.finish(index, t_f, touched, began)
            digest.update(pickle.dumps(sorted(touched.items()), 5) + w.head)
            self.seen = hashlib.sha3_256(blob).digest()  # what the shard was sent: BUILT returns it and the spine checks it against its own copy
            w.c.execute("INSERT INTO applied VALUES (?,?,?,?)", (n, SPINE_ID, rb.sha("RR/SHARD/RCORE/v1", n, index, pool, t_f), self.seen))
            w.c.execute("UPDATE financial_meta SET sequence=?,history_head=?", (w.seq, w.head))
            c0 = time.perf_counter()
            self.check(index, parts, seq0, pre_head, t["financial_events"])
            self.check_s += time.perf_counter() - c0
        except BaseException:
            if w.c.in_transaction:
                w.c.execute("ROLLBACK TO part")
                w.c.execute("RELEASE part")
                if not self.undo[3]:  # nothing of the group is built: leave no open transaction
                    w.c.execute("ROLLBACK")
                    self.undo = None
            w.seq, w.head, w.revision = seq0, pre_head, began  # the part leaves no trace in memory either
            raise
        w.c.execute("RELEASE part")
        self.undo[3] += len(parts)
        self.lines += len(parts)
        self.busy += time.perf_counter() - t0
        return w.head, digest.digest()


def table_digests(c: sqlite3.Connection) -> dict[str, str]:
    """One SHA-256 per table over `SELECT * ORDER BY 1`, through the shard's own connection (it sees the open transaction)."""
    names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {n: hashlib.sha256(repr(c.execute(f"SELECT * FROM {n} ORDER BY 1").fetchall()).encode()).hexdigest() for n in names}


def atom(rng: random.Random, depth: int = 0):
    kind = rng.randrange(9 if depth < 2 else 7)
    if kind == 0:
        return rng.randbytes(rng.randint(0, 80))
    if kind == 1:
        return "".join(rng.choice("abcXYZ019/:-_ ") for _ in range(rng.randint(0, 60)))
    if kind == 2:
        return "".join(rng.choice("é中☃\U0001f600\x1f\x00ab") for _ in range(rng.randint(0, 20)))
    if kind == 3:
        return rng.randint(-10**30, 10**30)
    if kind == 4:
        return rng.choice([0, 1, -1, 2, 3, 10**18])
    if kind == 5:
        return rng.choice([None, True, False, 1.5, -0.0])
    if kind == 6:
        return rng.randbytes(64)
    parts = tuple(atom(rng, depth + 1) for _ in range(rng.randint(0, 4)))
    return parts if kind == 7 else list(parts)


class W23(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="osb_w23_"))
        cls.template = cls.tmp / "template.sqlite3"
        rb.make_owner_db(cls.template)
        cls.tbl = sb.tables(cls.template, 1)
        cls.files = sb.corpus(20261007, LINES, 3)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_sha_helpers_hash_the_bytes_sha_hashes(self) -> None:
        rng = random.Random(20261007)
        for _ in range(3000):
            parts = [atom(rng) for _ in range(rng.randint(1, 5))]  # bytes (their repr is hashed), str, ints, None, floats, nested tuples and lists
            self.assertEqual(rb.sha(*parts), hashlib.sha3_512("\x1f".join(map(str, parts)).encode()).digest())
            self.assertEqual(rb.sha_from(rb._CELL, *parts), rb.sha("RR/CELL/CASH/v2", "bench-tenant", *parts))
            self.assertEqual(rb.sha_from(rb._EVENT, *parts), rb.sha("event", *parts))
            tags = [atom(rng) for _ in range(rng.randint(0, 4))]
            self.assertEqual(rb.sha_tags(parts[0], *tags), [rb.sha(parts[0], t) for t in tags])
        self.assertEqual(rb.sha_tags("ev:000001:k", 1, 2, 3), [rb.sha("ev:000001:k", n) for n in (1, 2, 3)])
        bad = "\ud800"  # a lone surrogate in a bare str is refused alike (inside a tuple its repr is escaped, and the equality loop above covers that)
        with self.assertRaises(UnicodeEncodeError):
            rb.sha("a", bad)
        with self.assertRaises(UnicodeEncodeError):
            rb.sha_from(rb._CELL, "a", bad)
        with self.assertRaises(UnicodeEncodeError):
            rb.sha_tags(bad, 1)

    def run_parts(self, cls, name: str, groups: list[tuple[int, list]]) -> list:
        """Build each (index, part) in order on one shard of `cls`, a fresh copy of the template; per part: the build's return (head, BUILT digest) or the
        refusal, the table digests inside the open transaction, and the in-memory seq, head and revisions. The last entry is the committed state."""
        db = self.tmp / f"{name}.sqlite3"
        shutil.copyfile(self.template, db)
        shard, out = cls(0, db), []
        for n, (index, part) in enumerate(groups, 1):
            blob = pickle.dumps(part, 5)
            try:
                got, refused = shard.build(n, index, "pool", sb.T0_MS + index, blob, shard.w.head, verdict_of(part)), None
            except Exception as error:  # the part's refusal, compared as type and text
                got, refused = None, (type(error).__name__, str(error))
            out.append((got, refused, table_digests(shard.c), shard.w.seq, shard.w.head, dict(shard.w.revision)))
        if shard.c.in_transaction:
            shard.c.execute("COMMIT")
        out.append(table_digests(shard.c))
        shard.stats()
        shard.c.close()
        return out

    def same(self, groups: list[tuple[int, list]], name: str) -> list:
        old, new = self.run_parts(OracleShard, name + "-old", groups), self.run_parts(sb.Shard, name + "-new", groups)
        self.assertEqual(len(old), len(new))
        for position, (a, b) in enumerate(zip(old, new)):
            self.assertEqual(a, b, f"{name} part {position}")
        return new

    def test_seeded_multi_part_run_stores_what_the_old_builder_stored(self) -> None:
        groups = []
        for index, (record, _) in enumerate(self.files):
            prep = sb.prepare(self.tbl, index, record.rows, index + 1)
            groups.append((index, pickle.loads(prep.blobs[0])))
        self.assertTrue(all(len(part) > 100 for _, part in groups))
        out = self.same(groups, "seeded")
        self.assertTrue(all(r[1] is None and r[0] is not None for r in out[:-1]))  # every part built
        self.assertEqual(len({r[0][1] for r in out[:-1]}), len(groups))  # and its BUILT digests differ part to part

    def test_hostile_parts_empty_zero_cent_non_ascii_max_length_and_duplicate_keys(self) -> None:
        rng, obl = random.Random(20261008), self.tbl.obl_ids

        def row(index: int, n: int, key: str, amount: int, raw: str, ob: str) -> tuple:  # shard `index` owns row keys index*KEY .. (index+1)*KEY-1
            return (index * rb.KEY + n, f"{index}/CLP/{key}", "CLP", key, amount, raw, hashlib.sha3_256(raw.encode()).digest(), ob, rng.randbytes(64))

        normal = [row(7, i, f"c{i}", rng.randint(1, 10**9), f"CLP*{i}~", obl[i % 3]) for i in range(40)]
        hostile = [row(9, 0, "k" * 4000 + "☃é中" * 500, 10**15, "x'); DROP TABLE evidence; --\x00☃" * 2000, obl[0]),  # max-length key and raw, non-ASCII, SQL in the text
                   row(9, 1, "\U0001f600/☃", 0, "", obl[1]),  # zero cents
                   row(9, 2, "'; DELETE FROM payments; --", 1, "\x1f\x00", obl[0]),
                   row(9, 3, "same-obligation", 5, "a", obl[0]), row(9, 4, "same-obligation-2", 7, "b", obl[0])]
        dup_key = [row(11, 0, "dup", 3, "a", obl[2]), row(11, 1, "dup", 4, "b", obl[2])]  # same key, so the same evidence id: refused
        dup_rk = [row(12, 0, "d1", 3, "a", obl[2]), row(12, 0, "d2", 4, "b", obl[2])]  # same row key: refused before any history row
        out = self.same([(7, normal), (9, hostile), (10, []), (11, dup_key), (12, dup_rk), (7, normal[:5]), (13, [row(13, 0, "after", 2, "z", obl[1])])], "hostile")
        built = [r[1] is None for r in out[:-1]]
        self.assertEqual(built, [True, True, True, False, False, False, True])  # a repeat of the first part's keys is refused; the last part builds after the refusals
        self.assertTrue(out[3][1][0].endswith("Error") and out[4][1][0].endswith("Error"))


    def test_chunk_stores_what_the_per_row_mutate_chunk_stored(self) -> None:
        """Writer.chunk (the deferred mutations) against its copy from 568ba4e1: after every file the table digests, seq, head and classes are equal."""
        stores = {}
        for name, cls in (("old", OracleWriter), ("new", rb.Writer)):
            db = self.tmp / f"chunk-{name}.sqlite3"
            shutil.copyfile(self.template, db)
            c = sqlite3.connect(str(db), isolation_level=None)
            for pragma in ("foreign_keys=ON", "recursive_triggers=ON"):
                c.execute(f"PRAGMA {pragma}")
            c.executescript(rb.STORE_DDL)
            stores[name] = (c, cls(c, True, None))
        for index, (record, deposit) in enumerate(self.files):
            for _, w in stores.values():
                w.run_file(index, record, deposit, [])
            (c_old, old), (c_new, new) = stores["old"], stores["new"]
            self.assertEqual(table_digests(c_old), table_digests(c_new), index)
            self.assertEqual((old.seq, old.head, old.classes, old.tally), (new.seq, new.head, new.classes, new.tally), index)
        for cls in ("applied", "negative_pending", "zero", "held"):  # every class the corpus reaches was stored (negative_applied is not reachable: a file's negatives are judged before any row resolves)
            self.assertGreater(new.classes.get(cls, 0), 0, cls)
        for c, _ in stores.values():
            c.close()


if __name__ == "__main__":
    unittest.main()
