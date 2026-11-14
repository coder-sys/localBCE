"""Shared framing for the line-oriented source readers (visit records, death file).

A reader gets the raw bytes, hashes them (SHA3-512), and walks them one line at a time. The only repairs made are the
fixed list: a leading byte-order mark, CRLF line ends, one trailing blank line, and whitespace padding. Everything
else a reader cannot take is quarantined at the smallest unit (a field, then a record) with a cause code, and the rest
of the file is applied. Only a file that cannot be framed or authenticated is refused whole.
"""

import csv
from dataclasses import dataclass, field
import hashlib
import unicodedata
from typing import Any, Iterator, NamedTuple

BOM = b"\xef\xbb\xbf"
MAX_FILE_BYTES = 1 << 30
MAX_LINE_BYTES = 1 << 16


class ReaderError(ValueError):
    """The whole file is refused; `cause` is a stable code."""

    def __init__(self, cause: str, detail: str = ""):
        super().__init__(f"{cause}: {detail}" if detail else cause)
        self.cause = cause


class Quarantine(NamedTuple):
    offset: int  # byte offset of the record's first byte in the raw file
    field: str | None  # None when the whole record is set aside
    cause: str


class Finding(NamedTuple):
    kind: str
    offset: int
    detail: str


@dataclass
class ReadResult:
    source_sha3_512: str
    rows: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    quarantined: list = field(default_factory=list)
    repairs: dict = field(default_factory=dict)
    coverage: Any = None

    def repair(self, name: str, count: int = 1) -> None:
        if count:
            self.repairs[name] = self.repairs.get(name, 0) + count


def open_source(data: bytes, expected_sha3_512: str | None) -> ReadResult:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if len(data) > MAX_FILE_BYTES:
        raise ReaderError("file_too_large")
    digest = hashlib.sha3_512(data).hexdigest()
    if expected_sha3_512 is not None and expected_sha3_512.lower() != digest:
        raise ReaderError("hash_mismatch")
    return ReadResult(digest)


def is_clean(text: str) -> bool:
    """False for control characters (C0 and C1), lone surrogates and line or paragraph separators."""
    return not any(unicodedata.category(c) in ("Cc", "Cs", "Zl", "Zp") for c in text)


def lines(data: bytes, result: ReadResult) -> Iterator[tuple[int, bytes | None]]:
    """Yield (raw byte offset, line without its line end). An over-long line is quarantined and yielded as None so a
    reader can tell when it was the header. A last line with no line feed may be cut short, so it is quarantined as
    "unterminated_record" and never yielded. One blank line at the very end counts as padding."""
    pos = 0
    if data.startswith(BOM):
        pos = len(BOM)
        result.repair("bom")
    end = len(data)
    crlf = 0
    while pos < end:
        nl = data.find(b"\n", pos)
        if nl < 0:
            result.quarantined.append(Quarantine(pos, None, "unterminated_record"))
            break
        line = data[pos:nl]
        if line.endswith(b"\r"):
            line = line[:-1]
            crlf += 1
        if nl + 1 == end and not line:
            result.repair("trailing_blank_line")
        elif len(line) > MAX_LINE_BYTES:
            result.quarantined.append(Quarantine(pos, None, "line_too_long"))
            yield pos, None
        else:
            yield pos, bytes(line)
        pos = nl + 1
    result.repair("crlf", crlf)


def csv_header(line: bytes | None, result: ReadResult, fold) -> list:
    """The header row of a CSV source: names stripped and case-folded with `fold` (str.lower or str.upper); a change
    of case is a repair. An over-long, unreadable or empty header refuses the file."""
    if line is None:
        raise ReaderError("header_too_long")
    try:
        raw = [h.strip() for h in next(csv.reader([line.decode("utf-8")], strict=True))]
    except (UnicodeDecodeError, csv.Error, StopIteration):
        raise ReaderError("no_header") from None
    header = [fold(h) for h in raw]
    result.repair("header_case", header != raw)
    return header
