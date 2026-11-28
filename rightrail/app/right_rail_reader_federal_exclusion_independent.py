"""Independent verifier for the federal exclusion list, written from conformance/EXCLUSION_V1.md §2 alone.

It shares only the fact codec with app/right_rail_reader_federal_exclusion.py (and the standard library's CSV parser,
which the spec names).  It frames the file from fixed-size reads, checks every field itself, and finds a repeated
statement identity after the whole file is read: each row's output is written to a scratch file, the identities are
sorted on disk (app/right_rail_reader_fixed_independent.py), and the output is then replayed in file order with each
repeat turned into its set-aside entry and each repeated identity's fact narrowed to the most restrictive reading.  So nothing reaches the sinks from a refused file, and memory does not grow with
the file.  tests/test_reader_exclusion.py requires the reader to match it byte for byte.
"""
from __future__ import annotations

import csv
import hashlib
import os
import re
import tempfile
import unicodedata
from datetime import date

from app import right_rail_fact_codec as codec
from app.right_rail_reader_fixed_independent import Refused, block, entry_sound, records, sort_file
from app.right_rail_reader_state_exclusion_independent import eve, npi_checks

_MAX_BYTES, _MAX_LINE, _CHUNK = 1 << 30, 1 << 16, 1 << 16
_COLUMNS = ("LASTNAME", "FIRSTNAME", "MIDNAME", "BUSNAME", "NPI", "EXCLTYPE", "EXCLDATE", "REINDATE", "WAIVERDATE",
            "WVRSTATE")
_TYPE = re.compile(r"1128a[0-9]|1128a[0-9][0-9]|1128b[0-9]|1128b[0-9][0-9]|1128Aa|11[3-9][0-9]|BRCH CIA|BRCH SA")
_NONE = {"", "0", "0" * 8, "0" * 10}
_DIRTY = {"Cc", "Cs", "Zl", "Zp"}
_WAIVER_FIELDS = ("EXCLTYPE", "EXCLDATE", "REINDATE", "WAIVERDATE", "WVRSTATE")  # each must read for a waiver
_ID = 56  # an identity record: statement identity 32, line 5, start 4, end 4, waiver 1, NPI 10


class _Unread(Exception):
    pass


def _frames(stream, whole):
    """(line number, line) for each line of the file, framed from fixed-size reads."""
    buf, at, seen, n, first = b"", 0, 0, 0, True
    while True:
        chunk = stream.read(_CHUNK)
        buf, at = buf[at:] + chunk, 0
        while (i := buf.find(b"\n", at)) >= 0:
            raw, at = buf[at:i + 1], i + 1
            seen += len(raw)
            if seen > _MAX_BYTES:
                raise Refused("file_too_large")
            whole.update(raw)
            body = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1]
            if len(body) > _MAX_LINE:
                raise Refused("line_too_long")
            if first and body[:3] == b"\xef\xbb\xbf":
                body = body[3:]
            first = False
            yield n, body
            n += 1
        if len(buf) - at > _MAX_LINE + 1:
            raise Refused("file_too_large" if seen + len(buf) - at > _MAX_BYTES else "line_too_long")
        if not chunk:
            break
    buf = buf[at:]
    if buf:
        if seen + len(buf) > _MAX_BYTES:
            raise Refused("file_too_large")
        whole.update(buf)
        raise Refused("line_too_long" if len(buf[:-1] if buf.endswith(b"\r") else buf) > _MAX_LINE
                      else "unterminated_record")


def _cells(line: bytes) -> list:
    try:
        s = line.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("not_utf8") from None
    try:
        return next(csv.reader([s], strict=True))
    except (csv.Error, StopIteration):
        raise Refused("unparseable") from None


def _text(s: str):
    if len(s) > 256 or any(unicodedata.category(c) in _DIRTY for c in s):
        raise _Unread
    return s or None


def _npi(s: str):
    if s in ("", "0", "0" * 10):
        return None
    if not (re.fullmatch(r"[0-9]{10}", s) and npi_checks(s.encode())):
        raise _Unread
    return s


def _kind(s: str):
    if s and not _TYPE.fullmatch(s):
        raise _Unread
    return s or None


def _date(s: str):
    if s in ("", "0", "0" * 8):
        return None
    if not re.fullmatch(r"[0-9]{8}", s):
        raise _Unread
    try:
        date(int(s[:4]), int(s[4:6]), int(s[6:]))
    except ValueError:
        raise _Unread from None
    return int(s)


_READ = {"LASTNAME": _text, "FIRSTNAME": _text, "MIDNAME": _text, "BUSNAME": _text, "NPI": _npi, "EXCLTYPE": _kind,
         "EXCLDATE": _date, "REINDATE": _date, "WAIVERDATE": _date, "WVRSTATE": _text}


def _entry(n: int, why: int, f: dict) -> bytes:
    names = b""
    for c in ("LASTNAME", "FIRSTNAME", "MIDNAME", "BUSNAME"):
        t = (f[c] or "").encode("utf-8")
        names += len(t).to_bytes(2, "little") + t
    return n.to_bytes(5, "little") + bytes([why]) + block((f["EXCLTYPE"] or "").encode(), 9) + names


def verify_federal_exclusion(stream, entry: dict, sink, aside, *, asof: int, cover: int, fseq: int, sender: str,
                             scope: str, state: str, scratch: str, channel: int, key: int, reader: int) -> bytes:
    ok = (isinstance(asof, int) and not isinstance(asof, bool) and isinstance(fseq, int) and not isinstance(fseq, bool)
          and cover in (1, 2) and 0 <= fseq <= 2**64 - 1 and isinstance(state, str)
          and re.fullmatch(r"[A-Z][A-Z]", state) is not None)
    for w in (sender, scope):
        ok = ok and isinstance(w, str) and 1 <= len(w) <= 20 and all("!" <= c <= "~" for c in w)
    try:
        date(asof // 10000, asof // 100 % 100, asof % 100)
    except (TypeError, ValueError):
        ok = False
    if not ok:
        raise Refused("bad_coverage")
    if not entry_sound(entry):
        raise Refused("bad_entry")
    wanted = [c for k, c in entry["ids"] if k == 3]
    if not wanted:
        raise Refused("kind_not_registered")
    if not set(wanted[0]) <= {1, 2, 3, 4}:
        raise Refused("unknown_identity_field")
    whole = hashlib.sha3_512()
    lines = _frames(stream, whole)
    head = next(lines, None)
    if head is None:
        raise Refused("no_header")
    try:
        cols = [c.strip().upper() for c in next(csv.reader([head[1].decode("utf-8")], strict=True))]
    except (UnicodeDecodeError, csv.Error, StopIteration):
        raise Refused("no_header") from None
    if len(cols) != len(set(cols)) or any(c not in cols for c in _COLUMNS):
        raise Refused("bad_header")

    frows = held = 0
    with tempfile.TemporaryDirectory(prefix="excl-verify-", dir=scratch) as tmp:
        out_path, ids_path = os.path.join(tmp, "out"), os.path.join(tmp, "ids")
        with open(out_path, "wb") as out, open(ids_path, "wb") as ids:
            for n, line in lines:
                if line.strip() == b"":
                    continue
                frows += 1
                cells = _cells(line)
                if len(cells) != len(cols):
                    raise Refused("column_count")
                got = dict(zip(cols, cells))
                f, bad = {}, []
                for c in _COLUMNS:
                    try:
                        f[c] = _READ[c](got[c].strip())
                    except _Unread:
                        f[c] = None
                        bad.append(c)
                has_name = bool(f["LASTNAME"] or f["BUSNAME"])
                held += has_name
                if f["NPI"] is None:
                    if "NPI" in bad:
                        if not has_name:
                            raise Refused("unholdable_row")
                        why = 2
                    elif not has_name:
                        why = 4
                    else:
                        why = 3 if got["EXCLTYPE"].strip() == "" else 1
                    e = _entry(n, why, f)
                    out.write(bytes(2) + len(e).to_bytes(2, "little") + e)
                    continue
                start, back, waived = f["EXCLDATE"], f["REINDATE"], f["WAIVERDATE"]
                doubt = (not has_name or got["EXCLTYPE"].strip() == "" or (start or 0) > asof or (back or 0) > asof
                         or (back is not None and back <= (start or 10101)))
                if doubt:
                    lo, hi = 10101, 99991231
                else:
                    lo, hi = start or 10101, 99991231 if back is None else eve(back)
                waiver = 1 if (not doubt and not any(c in bad for c in _WAIVER_FIELDS) and f["WVRSTATE"] == state
                               and waived is not None and start is not None and waived <= start) else 0
                part = {1: f["NPI"].encode(), 2: (f["EXCLTYPE"] or "").encode(), 3: b"%08d" % lo, 4: b"%08d" % hi}
                h = hashlib.sha3_256(b"RR/GATE/SID/v1\x00" + entry["src"].to_bytes(2, "little") + b"\x03")
                for c in wanted[0]:
                    h.update(len(part[c]).to_bytes(2, "little") + part[c])
                s = h.digest()
                ids.write(s + n.to_bytes(5, "big") + lo.to_bytes(4, "big") + hi.to_bytes(4, "big") + bytes([waiver])
                          + f["NPI"].encode())
                fact = codec.encode_fact({"kind": 3, "op": 0, "subject": block(f["NPI"].encode()) + bytes(11), "sid": s,
                                          "vstart": lo, "vstop": hi, "until": 99991231, "receipt": 0, "roff": n,
                                          "value": {"list": 1, "type": block((f["EXCLTYPE"] or "").encode(), 9),
                                                    "waiver": waiver}})
                e = _entry(n, 5, f)
                out.write(len(fact).to_bytes(2, "little") + fact + len(e).to_bytes(2, "little") + e)
        if held == 0 and (cover == 1 or frows > 0):
            raise Refused("no_rows")

        # Sorted by identity then line, each identity's first line comes first.  A later line of another NPI refuses
        # the file.  Later lines go to `later`; when there are any, the first line's fact is narrowed to the most
        # restrictive reading of all of them (earliest start, latest end, waiver 0 if any line has 0), kept in
        # `narrow` as line, start, end, waiver.
        later, narrow = os.path.join(tmp, "later"), os.path.join(tmp, "narrow")
        grouped = records(sort_file(ids_path, _ID, tmp), _ID)
        try:
            with open(later, "wb") as o, open(narrow, "wb") as m:
                first = None
                for r in grouped:
                    line, lo, hi, waiver = (r[32:37], int.from_bytes(r[37:41], "big"), int.from_bytes(r[41:45], "big"),
                                            r[45])
                    if first is not None and r[:32] == first[0]:
                        if r[46:] != first[6]:
                            raise Refused("identity_merges_npis")
                        o.write(line)
                        first = [first[0], first[1], min(first[2], lo), max(first[3], hi), min(first[4], waiver), True,
                                 first[6]]
                        continue
                    if first is not None and first[5]:
                        m.write(first[1] + first[2].to_bytes(4, "big") + first[3].to_bytes(4, "big")
                                + bytes([first[4]]))
                    first = [r[:32], line, lo, hi, waiver, False, r[46:]]
                if first is not None and first[5]:
                    m.write(first[1] + first[2].to_bytes(4, "big") + first[3].to_bytes(4, "big") + bytes([first[4]]))
        finally:
            grouped.close()
        repeats, narrowed = records(sort_file(later, 5, tmp), 5), records(sort_file(narrow, 14, tmp), 14)
        nxt, fix = next(repeats, None), next(narrowed, None)
        rows = quar = 0
        try:
            with open(out_path, "rb") as f:
                while size := f.read(2):
                    fact = f.read(int.from_bytes(size, "little"))
                    e = f.read(int.from_bytes(f.read(2), "little"))
                    at = int.from_bytes(e[:5], "little")
                    if fact and (nxt is None or int.from_bytes(nxt, "big") != at):
                        if fix is not None and int.from_bytes(fix[:5], "big") == at:
                            d = codec.decode_fact(fact)
                            d["vstart"], d["vstop"] = int.from_bytes(fix[5:9], "big"), int.from_bytes(fix[9:13], "big")
                            d["value"]["waiver"] = fix[13]
                            fact, fix = codec.encode_fact(d), next(narrowed, None)
                        sink(fact)
                        rows += 1
                        continue
                    if fact:
                        nxt = next(repeats, None)
                    aside(e)
                    quar += 1
        finally:
            repeats.close()
            narrowed.close()
    cfrom = asof if cover == 1 and entry["cfrom_rule"] != 1 else 0
    return codec.encode_receipt({
        "src": entry["src"], "cover": cover, "kb": 0, "asof": asof, "cfrom": cfrom, "fseq": fseq,
        "file": whole.digest(), "sender": block(sender.encode()), "channel": channel, "key": key, "reader": reader,
        "reread": 0, "rows": rows, "admitted": 0, "same": 0, "quar": quar, "scope": block(scope.encode()),
        "frows": frows})
