"""State death file reader: a fixed-width death file from the state's vital records or its eligibility system to death
fact rows (kind 2) and the file's receipt.

The layout is a table (SYNTHETIC_LAYOUT, specified in conformance/STATE_DEATH_V1.md); framing, refusal, identity,
streaming and the receipt are app/right_rail_reader_fixed.py's.  Both state sources share the layout and the header
says which one sent the file.  A death date must be a full calendar day: a partial date refuses the file.  The subject
and identity code 1 are the keyed member key, and the record hash is keyed the same way, so the raw member id is never
in a fact row and no fact row can be matched by hashing guessed ids.  The receipt's file digest is not keyed: for a
file of one or a few rows, whose other bytes the receipt and facts show, hashing candidate files with guessed member
ids can still find them.  The file digest must be keyed before files of real members are read.
"""
from __future__ import annotations

import hashlib
from typing import Callable

from app.right_rail_fact_registry import OPEN
from app.right_rail_gate_ffs import member_key
from app.right_rail_reader_fixed import COVER, HEADER, TRAILER, Layout, read_fixed
from app.right_rail_reader_lines import ReaderError

DEATH = 2
_RECORD = b"RR/GATE/DEATH-RECORD/v1\x00"  # the record hash is keyed as the member key is, under its own label
SYNTHETIC_LAYOUT = Layout(
    b"RRDETH01", DEATH, 120, HEADER + (("proof", 70, 71, "code"),),
    (("member", 1, 21, "text"), ("death", 21, 29, "date")),
    TRAILER,
    {"cover": COVER, "proof": {b"V": 1, b"E": 2}},  # V state vital records, E state eligibility system
    {1: "subject"})


def read_state_death(stream, secret: bytes, entry: dict, sink: Callable[[bytes], None], *, scratch: str,
                     channel: int, key: int, reader: int) -> bytes:
    """Read one death file (read_fixed); ``secret`` is the tenant's member-key secret."""

    def row(h, d, rec):
        if d["death"] > h["asof"]:
            raise ReaderError("death_after_as_of")
        return (member_key(secret, d["member"].decode()), d["death"], OPEN,
                {"proof": h["proof"], "record": hashlib.sha3_512(len(secret).to_bytes(2, "big") + secret + _RECORD
                                                                 + rec).digest()})

    return read_fixed(stream, entry, SYNTHETIC_LAYOUT, row, sink, scratch=scratch, channel=channel, key=key,
                      reader=reader)
