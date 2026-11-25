"""Provider death list reader and its independent verifier (conformance/PROVIDER_DEATH_V1.md) on synthetic data only: the
NPIs belong to no one.  Both must give byte-equal fact rows and receipts on the golden files, refuse every hostile file
with its named cause, and the reader's list must be one the gate's feed takes."""

import io
import json
import os
import unittest

from app import right_rail_fact_codec as codec
from app import right_rail_fact_registry as reg
from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from app import right_rail_reader_leie as leie
from app import right_rail_x12_834 as r834
from app.right_rail_reader_fixed import sid
from app.right_rail_reader_lines import ReaderError
from app.right_rail_reader_provider_death import feed_of, read_provider_death, read_provider_deaths
from app.right_rail_reader_provider_death_independent import verify_provider_death
from tests import test_reader_leie as tl
from tests import test_x12_834 as t834
from tests import test_x12_837 as t837
from tests.test_reader_exclusion import Trickle, scratch_run

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "provdeath_vectors")


def _json(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


GOLDEN = _json("golden.json")
KW = GOLDEN["transport"]


def entry(over=None):
    e = {**GOLDEN["entry"], **(over or {})}
    e["kinds"] = reg.mask_of(e["ids"])
    e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
    return e


def raw(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return f.read()


def run(fn, data, e=None, stream=io.BytesIO):
    """(fact rows, receipt) from ``fn``; the scratch directory must be empty afterwards, refused or not."""
    rows = []
    receipt = scratch_run(lambda tmp: fn(stream(data), e or entry(), rows.append, scratch=tmp, **KW))
    return tuple(rows), receipt


class ProviderDeathReaderTest(unittest.TestCase):
    def test_golden_files_byte_equal(self):
        for g in GOLDEN["files"]:
            data = raw(g["name"])
            got = run(read_provider_death, data)
            self.assertEqual(got, run(verify_provider_death, data), g["name"])
            self.assertEqual(got, run(read_provider_death, data, stream=Trickle), g["name"])
            self.assertEqual(got, run(verify_provider_death, data, stream=Trickle), g["name"])
            self.assertEqual([s.hex() for s in got[0]], g["statements"], g["name"])
            self.assertEqual(got[1].hex(), g["receipt"], g["name"])

    def test_full_file_fields(self):
        data, e = raw("full.pdeath"), entry()
        self.assertTrue(reg.registry_ok([e]))
        statements, receipt = run(read_provider_death, data, e)
        r = codec.decode_receipt(receipt)
        self.assertTrue(reg.shape_ok(e, r))
        self.assertEqual((r["src"], r["cover"], r["asof"], r["fseq"], r["rows"], r["frows"], r["quar"]),
                         (11, 1, 20261031, 61, 4, 4, 0))
        rows = [codec.decode_fact(s) for s in statements]
        first = rows[0]
        npi = first["subject"][1:11].decode()
        self.assertTrue(leie.npi_ok(npi))
        self.assertEqual(first["subject"], reg.ident(21, npi) + bytes(11))
        self.assertEqual((first["kind"], first["op"], first["sid"], first["roff"], first["value"]),
                         (4, 0, sid(11, 4, [npi.encode()]), 1, {"proof": 1}))
        self.assertEqual((first["vstart"], first["vstop"], first["until"]), (20260315, reg.OPEN, reg.OPEN))
        self.assertEqual([f["vstart"] for f in rows], [20260315, 20240229, 19991231, 20261031])

    def test_the_list_is_the_tuple_the_gate_takes(self):
        stream = io.BytesIO(raw("full.pdeath"))
        got, receipt = scratch_run(lambda tmp: read_provider_deaths(stream, entry(), scratch=tmp, **KW))
        statements, same = run(read_provider_death, raw("full.pdeath"))
        self.assertEqual((got, receipt), (feed_of(statements, same), same))
        asof, deaths = got
        self.assertEqual(asof, "2026-10-31")
        self.assertEqual([d for _, d in deaths], ["2026-03-15", "2024-02-29", "1999-12-31", "2026-10-31"])
        self.assertEqual(got, feed_of(*run(verify_provider_death, raw("full.pdeath"))))
        self.assertEqual(scratch_run(lambda tmp: read_provider_deaths(io.BytesIO(raw("empty.pdeath")), entry(), scratch=tmp,
                                                                      **KW))[0], ("2026-11-30", []))

    def test_feeds_takes_the_list_and_sends_the_provider_death_feed(self):
        asof, deaths = scratch_run(lambda tmp: read_provider_deaths(io.BytesIO(raw("full.pdeath")), entry(), scratch=tmp,
                                                                    **KW))[0]
        enrollment = r834.read_834(t837.file_of([t834.header() + t834.member("M1")]))
        no_one = leie.read_leie(tl.HEAD.encode(), source="synthetic", as_of="2026-10-31")
        (_, sent), left = ffs.feeds(20261105, enrollment, no_one, (asof, deaths), b"s")
        self.assertEqual(left, ())
        self.assertNotEqual(sent[1], (bytes(77), b""))  # present, not the absent feed that holds every line
        self.assertEqual(sent[1], decider.feed("pdeath", 20261031, [(ffs.ident(n.encode()), int(d.replace("-", "")))
                                                                    for n, d in deaths]))

    def test_a_change_file_gives_fact_rows_but_never_a_feed_list(self):
        statements, receipt = run(read_provider_death, raw("change.pdeath"))  # its rows are facts, as the state death file's are
        self.assertEqual(codec.decode_receipt(receipt)["cover"], 2)
        with self.assertRaises(ReaderError) as cm:  # a list of the changed NPIs alone would pass a provider it leaves out
            scratch_run(lambda tmp: read_provider_deaths(io.BytesIO(raw("change.pdeath")), entry(), scratch=tmp, **KW))
        self.assertEqual(cm.exception.cause, "change_file")
        with self.assertRaises(ReaderError) as cm:  # nor from its rows and receipt directly
            feed_of(statements, receipt)
        self.assertEqual(cm.exception.cause, "change_file")

    def test_hostile_files_refused_by_both(self):
        cases = _json("hostile.json")
        self.assertEqual(len(cases), 38)
        for c in cases:
            data, e = c["data"].encode("latin-1"), entry(c.get("entry"))
            for fn in (read_provider_death, verify_provider_death):
                with self.subTest(case=c["name"], impl=fn.__name__):
                    with self.assertRaises(Exception) as cm:
                        run(fn, data, e)
                    self.assertEqual(getattr(cm.exception, "cause", repr(cm.exception)), c["cause"])


if __name__ == "__main__":
    unittest.main()
