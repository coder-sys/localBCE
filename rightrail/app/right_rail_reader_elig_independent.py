"""Independent verifier for the eligibility system extract, written from conformance/ELIG_EXTRACT_V1.md alone.

It shares only the fact codec with app/right_rail_reader_elig.py; the shared verifier machinery is
app/right_rail_reader_fixed_independent.py.  It makes the member key itself.  tests/test_reader_elig.py requires the
reader to match it byte for byte.
"""
from __future__ import annotations

import re

from app.right_rail_reader_fixed_independent import Refused, block, code, day, filler, mkey, text, verify_fixed

_ROW = re.compile(rb"D(.{20})(.{20})(.)(.)(.{20})(.{10})(.{8})(.{8})(.{8})(.{8})(.*)", re.S)
_STATUS = {b"E": 1, b"N": 2, b"P": 3, b"R": 4}
_BASIS = {b"G": 1, b"R": 2, b"P": 3, b"C": 4}


def _head_rest(rest: bytes) -> dict:
    filler(rest)
    return {}


def verify_elig(stream, secret: bytes, entry: dict, sink, *, scratch: str, channel: int, key: int, reader: int) -> bytes:
    def row(x, head):
        g = _ROW.fullmatch(x).groups()
        member, segment, status, basis = text(g[0]), text(g[1]), code(_STATUS, g[2]), code(_BASIS, g[3])
        program, aid = text(g[4]), text(g[5])
        start, end, determined, notice = day(g[6]), day(g[7]), day(g[8]), day(g[9])
        filler(g[10])
        if end < start:
            raise Refused("span_backwards")
        if head["asof"] < determined:
            raise Refused("determined_after_as_of")
        m = mkey(secret, member)
        return m, start, end, {"status": status, "basis": basis, "program": block(program), "aid": block(aid),
                               "determined": determined, "notice": notice}, {1: m, 2: segment}

    return verify_fixed(stream, entry, 1, b"RRELIG01", {1, 2}, _head_rest, row, sink, scratch=scratch,
                        channel=channel, key=key, reader=reader)
