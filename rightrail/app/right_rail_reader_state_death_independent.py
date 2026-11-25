"""Independent verifier for the state death file, written from conformance/STATE_DEATH_V1.md alone.

It shares only the fact codec with app/right_rail_reader_state_death.py; the shared verifier machinery is
app/right_rail_reader_fixed_independent.py.  tests/test_reader_state_death.py requires the reader to match it byte for
byte.
"""
from __future__ import annotations

import hashlib
import re

from app.right_rail_reader_fixed_independent import Refused, code, day, filler, mkey, text, verify_fixed

_ROW = re.compile(rb"D(.{20})(.{8})(.*)", re.S)
_REST = re.compile(rb"(.)(.*)", re.S)
_PROOF = {b"V": 1, b"E": 2}


def _head_rest(rest: bytes) -> dict:
    proof, tail = _REST.fullmatch(rest).groups()
    proof = code(_PROOF, proof)
    filler(tail)
    return {"proof": proof}


def verify_state_death(stream, secret: bytes, entry: dict, sink, *, scratch: str, channel: int, key: int,
                       reader: int) -> bytes:
    def row(x, head):
        member, died, tail = _ROW.fullmatch(x).groups()
        member, died = text(member), day(died)
        filler(tail)
        if head["asof"] < died:
            raise Refused("death_after_as_of")
        m = mkey(secret, member)
        h = hashlib.sha3_512(len(secret).to_bytes(2, "big"))
        for part in (secret, b"RR/GATE/DEATH-RECORD/v1\x00", x):
            h.update(part)
        return m, died, 99991231, {"proof": head["proof"], "record": h.digest()}, {1: m}

    return verify_fixed(stream, entry, 2, b"RRDETH01", {1}, _head_rest, row, sink, scratch=scratch, channel=channel,
                        key=key, reader=reader)
