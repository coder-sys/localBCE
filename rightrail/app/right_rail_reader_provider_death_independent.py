"""Independent verifier for the provider death list, written from conformance/PROVIDER_DEATH_V1.md alone.

It shares only the fact codec with app/right_rail_reader_provider_death.py; the shared verifier machinery is
app/right_rail_reader_fixed_independent.py.  tests/test_reader_provider_death.py requires the reader to match it byte
for byte.
"""
from __future__ import annotations

import re

from app.right_rail_reader_fixed_independent import Refused, block, day, filler, text, verify_fixed
from app.right_rail_reader_state_exclusion_independent import npi_checks

_ROW = re.compile(rb"D(.{10})(.{8})(.*)", re.S)


def verify_provider_death(stream, entry: dict, sink, *, scratch: str, channel: int, key: int, reader: int) -> bytes:
    def row(x, head):
        npi, died, tail = _ROW.fullmatch(x).groups()
        npi, died = text(npi), day(died)
        filler(tail)
        if not npi_checks(npi):
            raise Refused("bad_npi")
        if head["asof"] < died:
            raise Refused("death_after_as_of")
        return block(npi) + bytes(11), died, 99991231, {"proof": 1}, {1: npi}

    return verify_fixed(stream, entry, 4, b"RRPDTH01", {1}, lambda rest: filler(rest) or {}, row, sink,
                        scratch=scratch, channel=channel, key=key, reader=reader)
