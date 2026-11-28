"""Independent verifier for the state exclusion list, written from conformance/EXCLUSION_V1.md §1 alone.

It shares only the fact codec with app/right_rail_reader_state_exclusion.py; the shared verifier machinery is
app/right_rail_reader_fixed_independent.py.  tests/test_reader_exclusion.py requires the reader to match it byte for
byte.
"""
from __future__ import annotations

import re
from datetime import date, timedelta

from app.right_rail_reader_fixed_independent import Refused, block, day, filler, text, verify_fixed

_ROW = re.compile(rb"D(.{10})(.{8})(.{8})(.{8})(.*)", re.S)


def npi_checks(npi: bytes) -> bool:
    """Ten digits that pass the Luhn check once 80840 is put in front."""
    if len(npi) != 10 or not npi.isdigit():
        return False
    digits = [int(c) for c in "80840" + npi.decode()]
    for i in range(len(digits) - 2, -1, -2):  # every second digit from the right, the check digit not counted
        digits[i] = digits[i] * 2 - 9 * (digits[i] > 4)
    return sum(digits) % 10 == 0


def eve(v: int) -> int:
    d = date(v // 10000, v % 10000 // 100, v % 100) - timedelta(days=1)
    return int(d.strftime("%Y%m%d"))


def verify_state_exclusion(stream, entry: dict, sink, *, scratch: str, channel: int, key: int, reader: int) -> bytes:
    def row(x, head):
        npi, kind, start, back, tail = _ROW.fullmatch(x).groups()
        npi, kind, start, back = text(npi), text(kind), day(start), day(back)
        filler(tail)
        if not npi_checks(npi):
            raise Refused("bad_npi")
        if head["asof"] < start:
            raise Refused("excluded_after_as_of")
        if back < 99991231 and head["asof"] < back:
            raise Refused("reinstated_after_as_of")
        if not start < back:
            raise Refused("span_backwards")
        stop = 99991231 if back == 99991231 else eve(back)
        return (block(npi) + bytes(11), start, stop, {"list": 2, "type": block(kind, 9), "waiver": 0},
                {1: npi, 2: kind, 3: b"%08d" % start, 4: b"%08d" % stop})

    return verify_fixed(stream, entry, 3, b"RRSEXC01", {1, 2, 3, 4}, lambda rest: filler(rest) or {}, row, sink,
                        scratch=scratch,
                        channel=channel, key=key, reader=reader)
