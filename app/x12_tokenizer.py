"""Bounded X12 5010 tokenizer: ISA-derived separators, envelope control numbers and counts, fixed refusal codes.

Pure and read-only. Every refusal is an `X12Error` whose message is one fixed code; input bytes, identifiers and inner
exceptions never cross the boundary. Checks run in this order: input type, byte cap, ASCII, ISA, segment cap, trailing or
truncated bytes, each segment (charset, tag, element, length, repeat and component caps), then the envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime
import re
import string
from typing import NoReturn

from app.mirror.error_boundary import raise_redacted


class X12Error(ValueError):
    """Fixed-code X12 refusal: the message is the code."""


def refuse(code: str) -> NoReturn:
    raise_redacted(X12Error, code)


MAX_BYTES = 1 << 20
MAX_SEGMENTS = 5_000  # after the ISA, IEA included
MAX_ELEMENTS = 64  # per segment
MAX_ELEMENT_LEN = 128  # per element, all repeats included
MAX_REPEATS = 8  # per element
MAX_COMPONENTS = 16  # per repeat
_ISA_LENGTHS = [2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1]
_SEPARATORS = frozenset(string.punctuation)
_PRINTABLE = re.compile(r"[ -~]*")
_TAG = re.compile(r"[A-Z][A-Z0-9]{1,2}")
_CONTROL = re.compile(r"[0-9]{1,9}")
_ID = re.compile(r"[A-Za-z0-9._,&'/-]+(?: +[A-Za-z0-9._,&'/-]+)*")  # an ISA06/ISA08/GS02/GS03 id, padding removed first
_ID_QUALIFIERS = frozenset(("01", "14", "20", "27", "28", "29", "30", "33", "ZZ"))
_TIME = re.compile(r"(?:[01][0-9]|2[0-3])[0-5][0-9](?:[0-5][0-9][0-9]{0,2})?")  # HHMM, HHMMSS, HHMMSSD or HHMMSSDD
_EMPTY = (("",),)

Element = tuple[tuple[str, ...], ...]  # repeats, each a tuple of components


@dataclass(frozen=True)
class Segment:
    tag: str
    elements: tuple[Element, ...]

    def parts(self, i: int) -> tuple[str, ...]:
        """Components of the 1-based element i (("",) when absent); a repeated element is refused."""
        repeats = self.elements[i - 1] if i <= len(self.elements) else _EMPTY
        if len(repeats) != 1:
            refuse("x12:shape")
        return repeats[0]

    def value(self, i: int) -> str:
        """The simple text of the 1-based element i ("" when absent); a repeated or composite element is refused."""
        parts = self.parts(i)
        if len(parts) != 1:
            refuse("x12:shape")
        return parts[0]

    def blank(self, first: int, last: int | None = None) -> None:
        """Refuse any non-empty element in first..last (1-based, inclusive); unmodeled content is never dropped."""
        if any(element != _EMPTY for element in self.elements[first - 1:last]):
            refuse("x12:extra")


@dataclass(frozen=True)
class Group:
    gs: Segment
    transactions: tuple[tuple[Segment, ...], ...]  # each ST..SE inclusive


@dataclass(frozen=True)
class Interchange:
    isa: Segment
    groups: tuple[Group, ...]


def _segment(text: str, esep: str, rsep: str, csep: str) -> Segment:
    if not _PRINTABLE.fullmatch(text):
        refuse("x12:charset")
    if not _TAG.fullmatch(text.partition(esep)[0]):
        refuse("x12:segment")
    if text.count(esep) > MAX_ELEMENTS:  # counted before splitting
        refuse("x12:cap-elements")
    tag, *raw = text.split(esep)
    elements = []
    for item in raw:
        if len(item) > MAX_ELEMENT_LEN:
            refuse("x12:cap-element-length")
        repeats = item.split(rsep)
        if len(repeats) > MAX_REPEATS:
            refuse("x12:cap-repeats")
        parts = tuple(tuple(repeat.split(csep)) for repeat in repeats)
        if any(len(part) > MAX_COMPONENTS for part in parts):
            refuse("x12:cap-components")
        elements.append(parts)
    return Segment(tag, tuple(elements))


def _real_date(year: int, text: str) -> bool:
    try:
        return 1900 <= datetime.date(year, int(text[:2]), int(text[2:])).year <= 2199
    except ValueError:
        return False


def _isa_valid(f: list[str]) -> bool:
    """ISA01-ISA10: qualifier code sets, a blank ISA02/ISA04 under qualifier 00, padded ids, a real YYMMDD date and an HHMM time."""
    return (f[0] in ("00", "03") and f[2] in ("00", "01") and f[4] in _ID_QUALIFIERS and f[6] in _ID_QUALIFIERS
            and all(_PRINTABLE.fullmatch(f[i]) for i in (1, 3)) and (f[1] == " " * 10 or f[0] != "00") and (f[3] == " " * 10 or f[2] != "00")
            and all(_ID.fullmatch(f[i].rstrip(" ")) for i in (5, 7)) and re.fullmatch("[0-9]{6}", f[8]) is not None
            and _real_date(2000 + int(f[8][:2]), f[8][2:]) and len(f[9]) == 4 and _TIME.fullmatch(f[9]) is not None)


def _group_valid(sender: str, receiver: str, day: str, time: str, agency: str) -> bool:
    """GS02-GS05 and GS07: 2-15 character ids, a real CCYYMMDD date, a time, and agency code X."""
    return (all(_ID.fullmatch(v) and 2 <= len(v) <= 15 for v in (sender, receiver)) and re.fullmatch("[0-9]{8}", day) is not None
            and _real_date(int(day[:4]), day[4:]) and _TIME.fullmatch(time) is not None and agency == "X")


def _match(close: Segment, opened: Segment, close_at: int, open_at: int, count: int) -> None:
    close.blank(3)
    control = opened.value(open_at)
    if close.value(close_at) != control or not _CONTROL.fullmatch(control):
        refuse("x12:control")
    if close.value(1) != str(count):
        refuse("x12:count")


def tokenize(data: bytes) -> Interchange:
    if type(data) is not bytes:
        refuse("x12:input")
    if len(data) > MAX_BYTES:
        refuse("x12:cap-bytes")
    if not data.isascii():
        refuse("x12:non-ascii")
    if len(data) < 106 or data[:3] != b"ISA":
        refuse("x12:isa")
    text = data.decode("ascii")
    esep, term = text[3], text[105]
    fields = text[4:105].split(esep)
    if [len(field) for field in fields] != _ISA_LENGTHS:
        refuse("x12:isa")
    rsep, csep = fields[10], fields[15]
    if not {esep, rsep, csep, term} <= _SEPARATORS or len({esep, rsep, csep, term}) != 4:
        refuse("x12:separator")
    if any(c in field for i, field in enumerate(fields) if i not in (10, 15) for c in (rsep, csep, term)):
        refuse("x12:separator")
    if fields[11] != "00501":
        refuse("x12:version")
    if not fields[12].isdecimal() or fields[13] not in ("0", "1") or fields[14] not in ("P", "T"):
        refuse("x12:isa")
    if not _isa_valid(fields):
        refuse("x12:isa")
    isa = Segment("ISA", tuple(((field,),) for field in fields))
    if text.count(term, 106) > MAX_SEGMENTS:  # counted before splitting
        refuse("x12:cap-segments")
    chunks = text[106:].split(term)
    tail = chunks.pop()
    tags = [chunk.partition(esep)[0] for chunk in chunks]
    if "IEA" in tags[:-1]:
        refuse("x12:trailing")
    if not tags or tags[-1] != "IEA":
        refuse("x12:truncated")
    if tail:
        refuse("x12:trailing")
    segments = [_segment(chunk, esep, rsep, csep) for chunk in chunks]
    groups, gs, sets, txn = [], None, [], None
    for seg in segments[:-1]:
        if seg.tag == "ISA":
            refuse("x12:envelope")
        elif seg.tag == "GS":
            if gs is not None:
                refuse("x12:envelope")
            seg.blank(9)
            if not _group_valid(*(seg.value(i) for i in (2, 3, 4, 5, 7))):
                refuse("x12:envelope")
            gs, sets = seg, []
        elif seg.tag == "ST":
            if gs is None or txn is not None:
                refuse("x12:envelope")
            seg.blank(4)
            if seg.value(3) not in ("", gs.value(8)):
                refuse("x12:version")
            txn = [seg]
        elif seg.tag == "SE":
            if txn is None:
                refuse("x12:envelope")
            txn.append(seg)
            _match(seg, txn[0], 2, 2, len(txn))
            sets.append(tuple(txn))
            txn = None
        elif seg.tag == "GE":
            if gs is None or txn is not None:
                refuse("x12:envelope")
            _match(seg, gs, 2, 6, len(sets))
            groups.append(Group(gs, tuple(sets)))
            gs = None
        elif txn is None:
            refuse("x12:envelope")
        else:
            txn.append(seg)
    if gs is not None or txn is not None or not groups:
        refuse("x12:envelope")
    iea = segments[-1]
    iea.blank(3)
    if iea.value(2) != isa.value(13):
        refuse("x12:control")
    if iea.value(1) != str(len(groups)):
        refuse("x12:count")
    return Interchange(isa, tuple(groups))
