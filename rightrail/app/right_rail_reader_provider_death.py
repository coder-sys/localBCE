"""Provider death list reader: a fixed-width list of the providers a state's provider enrollment system knows died, to
provider death fact rows (kind 4) and the file's receipt, and, for a full file, the list as the gate's feed takes it.

The layout is a table (SYNTHETIC_LAYOUT, specified in conformance/PROVIDER_DEATH_V1.md); framing, refusal, identity,
streaming and the receipt are app/right_rail_reader_fixed.py's.  Every row names its provider by NPI, checked as the
federal list's NPIs are; a row that does not read, a death date that is not a full calendar day or one after the
header's as-of date, or one NPI listed twice refuses the whole file.  An NPI is a public identifier, not member data, so
nothing here is keyed.
"""
from __future__ import annotations

from typing import Callable

from app import right_rail_fact_codec as codec
from app.right_rail_fact_registry import OPEN, ident
from app.right_rail_reader_fixed import COVER, HEADER, TRAILER, Layout, read_fixed
from app.right_rail_reader_leie import npi_ok
from app.right_rail_reader_lines import ReaderError

PDEATH = 4
ENROLLMENT_SYSTEM = 1  # the fact's proof: the state's provider enrollment system
SYNTHETIC_LAYOUT = Layout(
    b"RRPDTH01", PDEATH, 120, HEADER,
    (("npi", 1, 11, "text"), ("death", 11, 19, "date")),
    TRAILER,
    {"cover": COVER},
    {1: "npi"})


def read_provider_death(stream, entry: dict, sink: Callable[[bytes], None], *, scratch: str, channel: int, key: int,
                        reader: int) -> bytes:
    """Read one provider death list (read_fixed)."""

    def row(h, d, rec):
        npi = d["npi"].decode()
        if not npi_ok(npi):
            raise ReaderError("bad_npi")
        if d["death"] > h["asof"]:
            raise ReaderError("death_after_as_of")
        return ident(21, npi) + bytes(11), d["death"], OPEN, {"proof": ENROLLMENT_SYSTEM}

    return read_fixed(stream, entry, SYNTHETIC_LAYOUT, row, sink, scratch=scratch, channel=channel, key=key,
                      reader=reader)


def _iso(v: int) -> str:
    return f"{v // 10000:04d}-{v // 100 % 100:02d}-{v % 100:02d}"


def feed_of(statements, receipt: bytes) -> tuple[str, list[tuple[str, str]]]:
    """The list as ``right_rail_gate_ffs.feeds`` takes provider deaths: (as-of, [(NPI, date of death)]), dates ISO, in
    file order, from the fact rows and the receipt of an accepted full file.  A change file names only some of the providers
    who died, so a list made of it would pass a provider it leaves out: it is refused (``change_file``), and the caller
    sends the absent feed, as the claim path does for a federal exclusion supplement."""
    if codec.decode_receipt(receipt)["cover"] != 1:
        raise ReaderError("change_file")
    out = []
    for s in statements:
        f = codec.decode_fact(s)
        out.append((f["subject"][1:1 + f["subject"][0]].decode(), _iso(f["vstart"])))
    return _iso(codec.decode_receipt(receipt)["asof"]), out


def read_provider_deaths(stream, entry: dict, *, scratch: str, channel: int, key: int,
                         reader: int) -> tuple[tuple[str, list[tuple[str, str]]], bytes]:
    """(the feed list, the receipt) of one full file; ReaderError on any fault, ``change_file`` for a change file
    (``feed_of``).  The rows are held in memory."""
    rows: list[bytes] = []
    receipt = read_provider_death(stream, entry, rows.append, scratch=scratch, channel=channel, key=key, reader=reader)
    return feed_of(rows, receipt), receipt
