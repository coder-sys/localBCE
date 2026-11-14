"""X12 envelope and segment layer for the benefit-enrollment (834) and premium-payment (820) readers.

The input is hostile. Four lossless repairs are applied, each counted by cause: a leading byte-order mark, whitespace
around a segment, a line feed or carriage return behind a terminator, and trailing padding after the last interchange.
Anything else wrong is quarantined at the smallest unit that holds it (a segment, a transaction set, a group, an
interchange), with a cause code, and everything else is still read. A whole file is refused only when its first
interchange header cannot be framed, because then no delimiter or control number can be trusted. Each envelope pair
(ISA/IEA, GS/GE, ST/SE) must agree on its control number and its count, or the unit it closes is quarantined: a count
or number that disagrees means some segment may be missing, added or spliced, and no value is guessed.

Bytes are scanned as Latin-1 so every character is one byte and every offset is a byte offset into the original file;
each element is then decoded as UTF-8, so a name is never rewritten. A segment holding bytes that are not valid UTF-8 keeps
its raw bytes as hex in `Segment.raw`, and one `bad_utf8` repair is counted. An element that is not valid UTF-8 reads as its
text with the bad bytes replaced, then its raw bytes in hex in brackets, so two different ids never read as the same id.

The file is read as a stream, twice: once for its SHA3-512, once for its segments, so memory does not grow with the file.
A transaction set is handed to its reader as soon as its ST is read, with its segments as a generator. The SE, GE and
IEA that close it come later; when one of them disagrees, the sink is told to retract the set, group or interchange it
covers. A sink must hold what it receives until the file ends, because any of it can still be retracted.
"""

from datetime import date, time
import hashlib
import io
import re
from typing import NamedTuple

_ID = re.compile(r"[A-Z0-9]{2,3}\Z")
_NUMBER = re.compile(r"(-?)([0-9]+|[0-9]*\.[0-9]+)\Z")
_SPACE = " \t\r\n"
_LENGTHS = (3, 2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1)
_BOM = "\xef\xbb\xbf"
_CHUNK = 1 << 20
_MAX_SEGMENT = 1 << 20  # a "segment" longer than this has lost its terminator; the rest of it is skipped
_END = object()  # a set's segments are over


class Segment(NamedTuple):
    offset: int  # of the first byte of the segment in the original file
    id: str
    elements: tuple  # elements[0] is segment element 01; each element is a tuple of its sub-elements
    raw: str = ""  # hex of the segment's bytes when they are not valid UTF-8, else ""


class Quarantine(NamedTuple):
    unit: str  # file, interchange, group, set, loop, segment
    cause: str
    offset: int
    detail: str = ""


class TransactionSet(NamedTuple):
    kind: str  # ST01, such as "834"
    control: str
    offset: int
    file_at: str  # the group's own date and time, ISO: when the sender says it made the file
    segments: object  # generator of every segment between ST and SE, exclusive; it is read once
    group: int  # offset of the GS above it
    interchange: int  # offset of the ISA above it


class Parsed(NamedTuple):
    sha3_512: str
    sets: tuple
    quarantines: tuple
    repairs: tuple  # (rule, count)
    refused: str  # cause when the file is untrusted, else ""


class Sink:
    """Where a scan reports. Everything here does nothing; a reader's own records arrive through `add`."""

    def quarantine(self, q):
        pass

    def repair(self, rule):
        pass

    def retract(self, unit, offset):
        """Everything added for the set, group or interchange that starts at `offset` is void; unit "file" voids it all."""

    def add(self, ts, kind, item):
        pass


class Collector(Sink):
    """The sink that keeps everything in memory, minus whatever was retracted."""

    def __init__(self):
        self.envelope, self.counts, self.kept, self.dead = [], {}, [], set()

    def quarantine(self, q):
        self.envelope.append(q)

    def repair(self, rule):
        self.counts[rule] = self.counts.get(rule, 0) + 1

    def retract(self, unit, offset):
        if unit == "file":
            self.kept.clear()
        self.dead.add((unit, offset))

    def add(self, ts, kind, item):
        self.kept.append((ts.offset, ts.group, ts.interchange, kind, item))

    def get(self, kind):
        dead = self.dead
        return tuple(item for s, g, i, k, item in self.kept
                     if k == kind and not (dead and (("set", s) in dead or ("group", g) in dead or ("interchange", i) in dead)))

    def duplicates(self):
        """(key, offsets) for each key the readers saw more than once, in the order first seen."""
        found = {}
        for key, offset in self.get("seen"):
            found.setdefault(key, []).append(offset)
        return tuple((key, tuple(offsets)) for key, offsets in found.items() if len(offsets) > 1)


def element(segment, number, part=1):
    """Segment element `number` (1-based, as the standard numbers them), sub-element `part`; "" when absent."""
    if number > len(segment.elements) or part > len(segment.elements[number - 1]):
        return ""
    return segment.elements[number - 1][part - 1]


def x12_date(text):
    """CCYYMMDD as ISO text, or None; a date that does not exist is None, never repaired."""
    if len(text) != 8 or not text.isascii() or not text.isdigit():
        return None
    try:
        return date(int(text[:4]), int(text[4:6]), int(text[6:])).isoformat()
    except ValueError:
        return None


def scaled(text, places):
    """A decimal as an exact integer count of 10**-places, or None. Digits beyond `places` must be zeros and at most 15 integer digits are read; 1e2, 1,200 and $5 are not read."""
    found = _NUMBER.match(text)
    if found is None:
        return None
    whole, _, frac = found.group(2).partition(".")
    whole = whole.lstrip("0")
    if frac[places:].strip("0") or len(whole) > 15:  # 15 integer digits keep cents inside a signed 64-bit count
        return None
    value = int(whole or "0") * 10 ** places + int((frac + "0" * places)[:places])
    return -value if found.group(1) else value


def cents(text):
    return scaled(text, 2)


def _file_at(day, clock):
    """GS04 and GS05 as ISO text (HHMM, HHMMSS, or HHMMSSd..), or None."""
    iso = x12_date(day)
    if iso is None or len(clock) not in (4, 6, 7, 8) or not clock.isascii() or not clock.isdigit():
        return None
    try:
        time(int(clock[:2]), int(clock[2:4]), int(clock[4:6]) if len(clock) > 4 else 0)
    except ValueError:
        return None
    return f"{iso}T{clock[:2]}:{clock[2:4]}:{clock[4:6] if len(clock) > 4 else '00'}"


def digest(source):
    """SHA3-512 of a seekable binary file, in capitals, read in chunks; the file is left at its start."""
    source.seek(0)
    hasher = hashlib.sha3_512()
    for block in iter(lambda: source.read(_CHUNK), b""):
        hasher.update(block)
    source.seek(0)
    return hasher.hexdigest().upper()


def run(data, sink, on_set):
    """Read `data` (bytes or a seekable binary file) into `sink`, calling on_set(sha, set) for each set; return (sha, refused)."""
    source = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
    sha = digest(source)
    stream = _Stream(source)
    walker = _walk(stream, sink)
    for ts in walker:  # only set openings reach here; a set's own segments are pulled by its reader
        ts = ts._replace(segments=_body(walker))
        on_set(sha, ts)
        for _ in ts.segments:
            pass
    if not stream.refused:
        for block in iter(lambda: source.read(_CHUNK), b""):  # the rest the scan did not need
            stream.hasher.update(block)
        if stream.hasher.hexdigest().upper() != sha:
            sink.quarantine(Quarantine("file", "file_changed", 0))
            sink.retract("file", 0)
            stream.refused = "file_changed"
    return sha, stream.refused


def read(data, sink, kind, read_set):
    """Run one reader: sets of another kind are quarantined; read_set(sha, set, emit) reads the rest, emit(kind, item) reports."""
    def on_set(sha, ts):
        def emit(what, item):
            sink.add(ts, what, item)
        if ts.kind == kind:
            read_set(sha, ts, emit)
        else:
            emit("quarantine", Quarantine("set", "not_" + kind, ts.offset))
    return run(data, sink, on_set)[1]


def parse(data):
    """Whole-file form of `run`, for tests and small files: every confirmed set with its segments in memory."""
    sink = Collector()
    sha, refused = run(data, sink, lambda _, ts: sink.add(ts, "set", ts._replace(segments=tuple(ts.segments))))
    return Parsed(sha, sink.get("set"), tuple(sink.envelope), tuple(sink.counts.items()), refused)


def _body(walker):
    for ev in walker:
        if ev is _END:
            return
        yield ev


class _Stream:
    """Latin-1 text of a binary file read in chunks; `base` is the file offset of text[0] and `pos` the read position."""

    def __init__(self, source):
        self.source, self.text, self.pos, self.base = source, "", 0, 0
        self.refused, self.iea_missing = "", False
        self.hasher = hashlib.sha3_512()  # of every byte read, to be compared with the first pass

    @property
    def at(self):
        return self.base + self.pos

    def seek(self, at):
        self.pos = at - self.base

    def need(self, n):
        """True when n characters are available from pos; text before pos is dropped when more is read."""
        while len(self.text) - self.pos < n:
            block = self.source.read(_CHUNK)
            if not block:
                return False
            self.hasher.update(block)
            self.text = self.text[self.pos:] + block.decode("latin-1")
            self.base += self.pos
            self.pos = 0
        return True

    def skip_space(self):
        start = self.at
        while self.need(1):
            i, n = self.pos, len(self.text)
            while i < n and self.text[i] in _SPACE:
                i += 1
            self.pos = i
            if i < n:
                break
        return self.at > start

    def isa(self):
        return _isa(self.text, self.pos) if self.need(106) else None

    def take(self, term):
        """(text up to the next `term`, found). The text is None when the segment ran past _MAX_SEGMENT; the rest of it is skipped."""
        long, scanned = False, 0
        while True:
            i = self.text.find(term, self.pos + scanned)
            if i >= 0:
                raw = None if long else self.text[self.pos:i]
                self.pos = i + 1
                return raw, True
            scanned = len(self.text) - self.pos
            if scanned > _MAX_SEGMENT:
                long, self.pos, scanned = True, len(self.text), 0
            if not self.need(scanned + 1):
                rest = None if long else self.text[self.pos:]
                self.pos = len(self.text)
                return rest, False


def _isa(text, pos):
    """(element, sub-element, terminator, control number, repetition separator or "", fields ok) from a fixed-width ISA header at `pos`, or None.

    The repetition separator is ISA11 in version 00501; one that is not a separator of its own is no separator. The fields
    are not ok when ISA09/ISA10 is not a real date and time; that is counted and the data is still read.
    """
    head = text[pos:pos + 106]
    if len(head) != 106 or not head.startswith("ISA"):
        return None
    sep, sub, term = head[3], head[104], head[105]
    if len({sep, sub, term}) != 3 or any(not c.isascii() or c.isalnum() or c == " " for c in (sep, sub, term)):
        return None
    parts = head[:105].split(sep)
    if len(parts) != 17 or tuple(len(p) for p in parts) != _LENGTHS or not parts[13].isdigit() or not parts[13].isascii():
        return None
    rep = parts[11] if parts[12] == "00501" else ""
    if rep.isalnum() or rep == " " or rep in (sep, sub, term):
        rep = ""
    return sep, sub, term, parts[13], rep, _isa_stamp(parts[9], parts[10])


def _isa_stamp(day, clock):
    """ISA09 (YYMMDD) and ISA10 (HHMM) name a real date and time."""
    if not (day.isascii() and day.isdigit() and clock.isascii() and clock.isdigit()):
        return False
    try:
        time(int(clock[:2]), int(clock[2:]))
    except ValueError:
        return False
    return any(x12_date(century + day) for century in ("20", "19"))


def _utf8(text):
    if text.isascii():
        return text
    raw = text.encode("latin-1")
    out = raw.decode("utf-8", "replace")
    return f"{out}[{raw.hex()}]" if "\ufffd" in out else out


def _walk(b, sink):
    """Yield each set that may be read (segments not yet filled in), then its segments and _END. Reports to the sink."""
    if b.need(3) and b.text.startswith(_BOM, b.pos):
        b.pos += 3
        sink.repair("bom")
    first, taken, confirmed = True, set(), 0
    while True:
        if b.skip_space():
            sink.repair("whitespace")
        if not b.need(1):
            break
        at = b.at
        delims = b.isa()
        if delims is None:
            if first:
                sink.quarantine(Quarantine("file", "isa_unframed", at))
                b.refused = "isa_unframed"
                return
            sink.quarantine(Quarantine("file", "isa_unframed", at, "rest of file after the last good interchange"))
            break
        first = False
        confirmed += yield from _interchange(b, delims, sink, taken)
    if first:
        sink.quarantine(Quarantine("file", "no_interchange", 0))
        b.refused = "no_interchange"
    elif not confirmed and b.iea_missing:
        b.refused = "iea_missing"


def _end(sink, current, why=""):
    """A set that never reached its SE: its reader is told it is over, and it is taken back."""
    if why:
        sink.quarantine(Quarantine("set", "set_unclosed", current[2], why))
    if current[3]:
        yield _END
        sink.retract("set", current[2])


def _interchange(b, delims, sink, taken):
    """Read one interchange starting at its ISA; return how many sets it confirmed.

    A framed ISA met before this interchange's IEA ends it as iea_missing; the caller starts the next one there.
    """
    sep, sub, term, control, rep, fields_ok = delims
    repeated = control in taken
    taken.add(control)
    isa = b.at
    if repeated:
        sink.quarantine(Quarantine("interchange", "duplicate_control", isa, control))
    if not fields_ok:
        sink.repair("bad_isa_stamp")
    void = repeated  # nothing in it is read
    b.pos += 106
    ok = groups_seen = 0  # sets confirmed by their group; groups opened
    group, current = None, None  # (control, count, bad cause or None, file_at, offset, set controls, sets read ok) and (ST, count, offset, live)
    group_controls = set()
    closed = False
    pad = _SPACE.replace(term, "")  # padding never includes the terminator itself
    while True:
        start = b.at
        raw, found = b.take(term)
        if not found:
            if raw is None or raw.strip(_SPACE):
                sink.quarantine(Quarantine("segment", "unterminated_segment", start, "last segment has no terminator"))
            break
        if raw is None:
            if current is not None:
                current[1] += 1
            sink.quarantine(Quarantine("segment", "segment_too_long", start))
            continue
        body = raw.strip(pad)
        lead = len(raw) - len(raw.lstrip(pad))
        at = start + lead
        if body != raw:
            sink.repair("whitespace")
            if not body:
                continue
        if body.startswith("ISA"):
            after = b.at
            b.seek(at)
            if b.isa() is not None:
                break
            b.seek(after)
        if current is not None:
            current[1] += 1
        pieces = body.split(sep)
        sid = pieces[0]
        if not _ID.match(sid):
            sink.quarantine(Quarantine("segment", "bad_segment_id", at))
            continue
        if rep and rep in body:
            sink.quarantine(Quarantine("segment", "repeated_element", at, sid))  # repetitions are not read; none is guessed
            continue
        raw_hex = ""
        if not body.isascii():
            try:
                body.encode("latin-1").decode("utf-8")
            except UnicodeDecodeError:
                raw_hex = body.encode("latin-1").hex()
        segment = Segment(at, sid, tuple(tuple(_utf8(q) for q in p.split(sub)) for p in pieces[1:]), raw_hex)
        if sid == "ST":
            if group is None:
                sink.quarantine(Quarantine("segment", "st_outside_group", at))
                continue
            if current is not None:
                yield from _end(sink, current, "next ST before SE")
            group[1] += 1
            kind, number = element(segment, 1), element(segment, 2)
            live = group[2] is None and not void and len(kind) == 3 and number != "" and number not in group[5]
            current = [segment, 1, at, live]
            if live:
                yield TransactionSet(kind, number, at, group[3], None, group[4], isa)
        elif sid == "SE":
            if current is None:
                sink.quarantine(Quarantine("segment", "se_without_st", at))
                continue
            st, cause = current[0], ""
            if not element(st, 2) or element(segment, 2) != element(st, 2):
                cause = "se_control_mismatch"
            elif element(segment, 1) != str(current[1]):
                cause = "se_count_mismatch"
            elif len(element(st, 1)) != 3:
                cause = "bad_st"
            elif element(st, 2) in group[5]:
                cause = "duplicate_control"
            group[5].add(element(st, 2))
            if cause:
                sink.quarantine(Quarantine("set", cause, current[2]))
            if current[3]:
                group[6] += not cause
                yield _END
                if cause:
                    sink.retract("set", current[2])
            current = None
        elif sid == "GS":
            if current is not None:
                yield from _end(sink, current)
                current = None
            if group is not None:
                sink.quarantine(Quarantine("group", "group_unclosed", group[4], "next GS before GE"))
                sink.retract("group", group[4])
            groups_seen += 1
            file_at = _file_at(element(segment, 4), element(segment, 5))
            bad = None if file_at else "bad_file_datetime"
            if element(segment, 6) in group_controls:
                bad = bad or "duplicate_control"
            group_controls.add(element(segment, 6))
            if bad:
                sink.quarantine(Quarantine("group", bad, at, "GS04/GS05" if file_at is None else "GS06"))
            group = [element(segment, 6), 0, bad, file_at, at, set(), 0]
        elif sid == "GE":
            if group is None:
                sink.quarantine(Quarantine("segment", "ge_without_gs", at))
                continue
            if current is not None:
                yield from _end(sink, current, "GE before SE")
                current = None
            cause = ""
            if not group[0] or element(segment, 2) != group[0]:
                cause = "ge_control_mismatch"
            elif element(segment, 1) != str(group[1]):
                cause = "ge_count_mismatch"
            if cause:
                sink.quarantine(Quarantine("group", cause, group[4]))
                sink.retract("group", group[4])
            else:
                ok += group[6]
            group = None
        elif sid == "IEA":
            if current is not None:
                yield from _end(sink, current)
                current = None
            if group is not None:
                sink.quarantine(Quarantine("group", "group_unclosed", group[4], "IEA before GE"))
                sink.retract("group", group[4])
            cause = ""
            if element(segment, 2) != control:
                cause = "iea_control_mismatch"
            elif element(segment, 1) != str(groups_seen):
                cause = "iea_count_mismatch"
            if cause:
                sink.quarantine(Quarantine("interchange", cause, isa, control))
            if cause or void:
                sink.retract("interchange", isa)
                ok = 0
            closed = True
            break
        elif current is not None:
            if current[3]:
                if raw_hex:
                    sink.repair("bad_utf8")  # counted only on a segment that is kept
                yield segment
        else:
            sink.quarantine(Quarantine("segment", "segment_outside_set", at, sid))
    if closed:
        return ok
    if current is not None:
        yield from _end(sink, current, "file ends before SE")
    if group is not None:
        sink.quarantine(Quarantine("group", "group_unclosed", group[4], "file ends before GE"))
        sink.retract("group", group[4])
    sink.quarantine(Quarantine("interchange", "iea_missing", isa, control))
    sink.retract("interchange", isa)
    b.iea_missing = True
    return 0
