"""Does sqlite3 (the pinned Python) run SQL without the GIL, and can a Python thread overlap an executemany? (OWC S11, bench only; synthetic.)
Case 1: a pure-SQL statement (one sqlite3_step for the whole query) next to a pure-Python loop in a second thread: SQL runs in parallel if concurrent < sum.
Case 2: an indexed executemany of rows next to the same loop, at the default switch interval and at 0.2 ms: executemany needs the GIL to bind every row."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import time


def timed(f, *a) -> float:
    t = time.perf_counter()
    f(*a)
    return time.perf_counter() - t


def py_job(n: int) -> None:
    x = 0
    for i in range(n):
        x += i


def both(sql, py) -> float:
    th = threading.Thread(target=sql)
    t = time.perf_counter()
    th.start()
    py()
    th.join()
    return time.perf_counter() - t


def main() -> None:
    print("python", sys.version.split()[0], "sqlite", sqlite3.sqlite_version, "cpus", os.cpu_count(), "switch_interval_s", sys.getswitchinterval())
    c = sqlite3.connect(":memory:", check_same_thread=False)
    cte = lambda: c.execute("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<4000000) SELECT sum(x) FROM c").fetchone()  # noqa: E731
    sql, py = timed(cte), timed(py_job, 15_000_000)
    con = both(cte, lambda: py_job(15_000_000))
    print(f"case1 pure SQL: sql {sql:.2f}s py {py:.2f}s concurrent {con:.2f}s sum {sql + py:.2f}s max {max(sql, py):.2f}s -> {'GIL released in sqlite3_step' if con < 0.8 * (sql + py) else 'no overlap'}")
    d = tempfile.mkdtemp()
    c = sqlite3.connect(os.path.join(d, "g.db"), isolation_level=None, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=OFF")
    c.execute("CREATE TABLE t(a INTEGER PRIMARY KEY, b BLOB, c TEXT)")
    c.execute("CREATE INDEX tb ON t(b)")
    rows = [(i, os.urandom(64), "x" * 100) for i in range(100_000)]

    def ins() -> None:
        c.execute("DELETE FROM t")
        c.execute("BEGIN")
        c.executemany("INSERT INTO t VALUES (?,?,?)", rows)
        c.execute("COMMIT")

    for interval in (sys.getswitchinterval(), 0.0002):
        sys.setswitchinterval(interval)
        sql, py = timed(ins), timed(py_job, 15_000_000)
        con = both(ins, lambda: py_job(15_000_000))
        print(f"case2 executemany, switch {interval * 1000:.1f} ms: insert {sql:.2f}s py {py:.2f}s concurrent {con:.2f}s sum {sql + py:.2f}s max {max(sql, py):.2f}s")


if __name__ == "__main__":
    main()
