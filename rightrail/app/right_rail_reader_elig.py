"""State eligibility system extract reader: a fixed-width extract to eligibility fact rows (kind 1) and the file's receipt.

The layout is a table (SYNTHETIC_LAYOUT, specified in conformance/ELIG_EXTRACT_V1.md); another state's extract is
another table and its own golden vectors.  Framing, refusal, identity, streaming and the receipt are
app/right_rail_reader_fixed.py's.  The reader states only what the file says: one fact row per detail row, no ends,
no absence.  The subject and identity code 1 are the keyed member key; the raw member id is never in a fact row.
"""
from __future__ import annotations

from typing import Callable

from app.right_rail_fact_registry import ident
from app.right_rail_gate_ffs import member_key
from app.right_rail_reader_fixed import COVER, HEADER, TRAILER, Layout, read_fixed
from app.right_rail_reader_lines import ReaderError

ELIG = 1

SYNTHETIC_LAYOUT = Layout(
    b"RRELIG01", ELIG, 120, HEADER,
    (("member", 1, 21, "text"), ("segment", 21, 41, "text"), ("status", 41, 42, "code"), ("basis", 42, 43, "code"),
     ("program", 43, 63, "text"), ("aid", 63, 73, "text"), ("start", 73, 81, "date"), ("end", 81, 89, "date"),
     ("determined", 89, 97, "date"), ("notice", 97, 105, "date")),
    TRAILER,
    {"cover": COVER, "status": {b"E": 1, b"N": 2, b"P": 3, b"R": 4}, "basis": {b"G": 1, b"R": 2, b"P": 3, b"C": 4}},
    {1: "subject", 2: "segment"})


def read_elig(stream, secret: bytes, entry: dict, sink: Callable[[bytes], None], *, scratch: str, channel: int,
              key: int, reader: int) -> bytes:
    """Read one extract (read_fixed); ``secret`` is the tenant's member-key secret."""

    def row(h, d, rec):
        if d["start"] > d["end"]:
            raise ReaderError("span_backwards")
        if d["determined"] > h["asof"]:
            raise ReaderError("determined_after_as_of")
        return (member_key(secret, d["member"].decode()), d["start"], d["end"],
                {"status": d["status"], "basis": d["basis"], "program": ident(21, d["program"].decode()),
                 "aid": ident(21, d["aid"].decode()), "determined": d["determined"], "notice": d["notice"]})

    return read_fixed(stream, entry, SYNTHETIC_LAYOUT, row, sink, scratch=scratch, channel=channel, key=key, reader=reader)
