"""The shared harness of the class tests: synthetic files read by the real readers, and one signed store with the pinned rules
engine that decides what right_rail_gate_ffs sends."""

from __future__ import annotations

import contextlib
import functools
import operator
import os
import unittest
from unittest import mock
from pathlib import Path

from app import right_rail_deployment_slots as slots
from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from app import right_rail_reader_leie as leie
from app import right_rail_x12_834 as r834
from app import right_rail_x12_837 as r837
from tests import _class_cases as cc
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests import test_right_rail_deployment_slots as ts

SECRET = b"synthetic tenant secret, 32 b.."


def read_case(p: cc.Parts) -> dict:
    """Read the case's files with the real readers; the requests, feeds and set-asides, and the kinds each source recorded."""
    reads = [r837.read_837(e.file837()) for e in p.earlier] + [r837.read_837(p.file837()) for _ in range(p.copies)]
    files = [r834.read_834(f) for f in (p.file834(), *(more() for more in p.more834))]  # each file read on its own, then joined
    enrolled = r834.Read834(*(functools.reduce(operator.add, parts) for parts in zip(*files)))
    listed = leie.read_leie(p.leie_bytes(), source="synthetic", as_of=cc.AS_OF, kind=p.leie_kind)
    sent, aside = ffs.requests_of(reads, fx.TENANT, fx.PROGRAM, fx.PERIOD, SECRET, listed)
    feed, left = ffs.feeds(au.TODAY, enrolled, listed, p.deaths, SECRET)
    names = lambda *rs: {c for r in rs for c in [*(q.cause for q in r.quarantines), *(f.cause for f in r.findings)]}  # noqa: E731
    seen = {"right_rail_x12_837": names(*reads), "right_rail_x12_834": names(enrolled),
            "right_rail_reader_leie": {*(q.cause for q in listed.quarantined), *(f.kind for f in listed.findings)},
            "right_rail_gate_ffs": {a.cause for a in (*aside, *left)}}
    seen["right_rail_x12"] = seen["right_rail_x12_837"] | seen["right_rail_x12_834"]
    seen["right_rail_reader_lines"] = seen["right_rail_reader_leie"]  # the framing both line readers share
    return {"sent": sent, "aside": aside, "feed": feed, "left": left, "seen": seen, "reads": reads,
            "pid": ffs.canonical_id("C", p.bill, p.cid)}


class Harness(fx.Scratch):
    """One signed store and rules worker for every case."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "nt":
            raise unittest.SkipTest("the host runs the Windows exes")
        if not g.ENGINE.is_file():
            raise AssertionError(f"CLASS TEST NOT RUN: {g.ENGINE} missing; run `lake build gate_engine` in lean/")

    @contextlib.contextmanager
    def session(self):
        """One signed store, tenant authority and rules worker; yields ``run(sent, feed, grant=, bypasses=)``, which is
        right_rail_gate_ffs.decide_claims (rows, groups, sealed) with the signed bypasses the claim path does not take itself given to
        every decide."""
        pack = {**ts.FULL, "GATE_KEYSET_PIN": [[fx.TENANT, au.genesis()[0].hex()]]}
        with self.scratch() as tmp:
            c = g.Cluster(tmp, fx.custody(tmp), shards=fx.SHARDS)
            shards = {k: self.track(c.producer(k)) for k in range(fx.SHARDS)}
            floor = Path(tmp) / "tenant.floor"
            decider.TenantAuthority.provision(floor, fx.TENANT, list(shards.values()))
            host = ffs.open_host(slots.Slots(pack), fx.TENANT, floor, list(shards.values()), g.ENGINE)
            flats = {k: Path(tmp) / f"idx{k}" for k in shards}
            real = decider.decide

            def run(sent, feed, grant=g.GRANT, bypasses=()):
                with_bypasses = lambda *a, **kw: real(*a, **{**kw, "bypasses": tuple(bypasses)})  # noqa: E731
                with mock.patch.object(decider, "decide", with_bypasses):
                    return ffs.decide_claims(sent, feed, host, shards, flats, grant, g.KEYS, fx.PROGRAM, fx.NOW)
            try:
                yield run
            finally:
                host[1].close()

    def decide(self, cases: list) -> list:
        """The decided rows of each ``read_case`` result in turn, on one store."""
        with self.session() as run:
            return [run(case["sent"], case["feed"])[0] if case["sent"] else [] for case in cases]
