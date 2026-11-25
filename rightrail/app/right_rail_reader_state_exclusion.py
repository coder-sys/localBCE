"""State exclusion list reader: the providers a state has excluded from its program, as a fixed-width file, to exclusion
fact rows (kind 3, list 2) and the file's receipt.

The layout is a table (SYNTHETIC_LAYOUT, specified in conformance/EXCLUSION_V1.md §1); framing, refusal, identity,
streaming and the receipt are app/right_rail_reader_fixed.py's.  Every row names its provider by NPI, checked as the
federal list's NPIs are; a row that does not read refuses the whole file.  A state list carries no waiver, so the
waiver is always 0.
"""
from __future__ import annotations

from typing import Callable

from app.right_rail_fact_registry import OPEN, ident
from app.right_rail_reader_fixed import COVER, HEADER, TRAILER, Layout, day_before, read_fixed
from app.right_rail_reader_leie import npi_ok
from app.right_rail_reader_lines import ReaderError

EXCL = 3
STATE_LIST = 2
SYNTHETIC_LAYOUT = Layout(
    b"RRSEXC01", EXCL, 120, HEADER,
    (("npi", 1, 11, "text"), ("authority", 11, 19, "text"), ("start", 19, 27, "date"),
     ("reinstated", 27, 35, "date")),
    TRAILER,
    {"cover": COVER},
    {1: "npi", 2: "authority", 3: "vstart", 4: "vstop"})


def read_state_exclusion(stream, entry: dict, sink: Callable[[bytes], None], *, scratch: str, channel: int, key: int,
                         reader: int) -> bytes:
    """Read one state exclusion list (read_fixed)."""

    def row(h, d, rec):
        npi, start, back = d["npi"].decode(), d["start"], d["reinstated"]
        if not npi_ok(npi):
            raise ReaderError("bad_npi")
        if start > h["asof"]:
            raise ReaderError("excluded_after_as_of")
        if back != OPEN and back > h["asof"]:
            raise ReaderError("reinstated_after_as_of")
        if back <= start:
            raise ReaderError("span_backwards")
        return (ident(21, npi) + bytes(11), start, OPEN if back == OPEN else day_before(back),
                {"list": STATE_LIST, "type": ident(9, d["authority"].decode()), "waiver": 0})

    return read_fixed(stream, entry, SYNTHETIC_LAYOUT, row, sink, scratch=scratch, channel=channel, key=key,
                      reader=reader)
