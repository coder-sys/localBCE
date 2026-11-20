#!/usr/bin/env python3
"""Eligibility (kind 7) snapshot builder: test-only, synthetic data only, never a production feed.

Design: docs/integration/TRUNK_STEP3_ELIG_PRODUCER_DESIGN.md (revision 2, owner-approved defaults).  Source records in,
a pinned, dated `snap elig` fragment in the text runner's grammar plus a sidecar JSON out, or an explicit "no snapshot".

Pipeline (design section 4): normalize -> rows -> sort/dedupe/conflict -> pin -> fragment and sidecar.

- `pin_rows(asof, rows)`: pre-keyed 5-tuples of numbers in, sort and SNAPSHOT/v1 pin out.  No keying, no normalize and
  no `fits` pre-check (design 4.4).  Rows are encoded by `gate_rules_data.row("elig", ...)`, the head written locally
  as gate_rules_data.py writes it (decision 12); `gate_rules_v2_ref.pin_bytes` is the independent cross-check.
- `build(sources, secret, today, fits=route_a_fits)`: the keyed path.  member = ident(member_key(secret, member_id)),
  aid = ident(aid_text.encode()), both taken from rightrail/app/right_rail_gate_ffs.py.

This tool never adds kind 7 to `request_frame` or to any frame (decision 17).  It writes nothing into rightrail/: the
CLI refuses output paths there or on pinned files, and importing from rightrail/ writes no bytecode there.
It never prints, logs or raises with record fields or secret bytes: errors carry a cause and an origin only.

CLI exit codes: 0 snapshot; 1 no snapshot (the sidecar names the cause); 2 refused (usage, unreadable or refused
secret, refused output path), with a builder_error sidecar once the output paths are accepted; 3 internal error (a
builder_error sidecar is written when possible).  Any fragment or sidecar left at the output paths by an earlier run
is removed first, and both are written atomically, the sidecar last.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RIGHTRAIL = os.path.join(ROOT, "rightrail")
for _d in (os.path.join(RIGHTRAIL, "tools"), os.path.join(RIGHTRAIL, "conformance")):
    if _d not in sys.path:
        sys.path.insert(0, _d)

_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True  # importing from rightrail/ must leave no __pycache__ there
try:
    import gate_rules_data  # noqa: E402  rightrail/tools/gate_rules_data.py (read only)
    import gate_rules_v2_ref as ref  # noqa: E402  rightrail/conformance/gate_rules_v2_ref.py (read only)
finally:
    sys.dont_write_bytecode = _bytecode

FFS_PATH = os.path.join(RIGHTRAIL, "app", "right_rail_gate_ffs.py")


def _ffs_functions() -> dict:
    """`member_key`, `ident` and `_MEMBER`, executed from the exact source of rightrail/app/right_rail_gate_ffs.py.

    The module itself cannot be imported off Windows (it imports right_rail_gate_decide, which imports msvcrt), so
    only these definitions are taken from its syntax tree and run; no copy of them lives here."""
    with open(FFS_PATH, encoding="utf-8") as f:
        tree = ast.parse(f.read(), FFS_PATH)
    want = {"member_key", "ident", "_MEMBER"}
    body = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name in want)
            or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in want for t in n.targets))]
    got = {n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id for n in body}
    if got != want or len(body) != 3:
        raise ImportError("right_rail_gate_ffs.py no longer defines member_key, ident and _MEMBER once each")
    ns: dict = {"hashlib": hashlib, "__name__": "right_rail_gate_ffs_extract"}
    exec(compile(ast.Module(body=body, type_ignores=[]), FFS_PATH, "exec"), ns)  # noqa: S102  rightrail's own source
    return ns


_FFS = _ffs_functions()
member_key: Callable[[bytes, str], bytes] = _FFS["member_key"]
ident: Callable[[bytes], int] = _FFS["ident"]

PRODUCER_VERSION = "elig_snapshot/1"
KIND = gate_rules_data.KINDS.index("elig") + 1  # 7
DOMAIN = b"RR/GATE/SNAPSHOT/v1"
WIDTHS = gate_rules_data.WIDTHS["elig"]  # (129, 129, 1, 4, 4)
ROW_BYTES = sum(WIDTHS)  # 267
MAX_AGE_DAYS = ref.MAXAGE["elig"]  # placeholder 7 (Rules/Spec.lean maxAge for elig), taken from the reference checker
CAP = 1024  # rows per member, counted after dedupe (decision 6)
SET_ASIDE_LIMIT_PERCENT = 5  # placeholder (decision 9): more than this share of members set aside gives no snapshot
OPEN_END = 99991231
ALLOWED_AID_TEXT = ("13", "23", "53", "103", "104")  # Rules/Spec.lean:392

# The fixture source accepts only this public, synthetic test secret (decision 3).  It is published on purpose: a
# leaked fixture snapshot is keyed under it, so it matches no production member key and fails closed.
PUBLIC_TEST_SECRET = b"RR/ELIG/PUBLIC-TEST-SECRET/v1 synthetic fixtures only, never production"

# Closed cause lists (design section 6).  "blind" here is the fixture stand-in for a fault outside every member record.
SET_ASIDE_CAUSES = ("bad_member_id", "bad_aid", "bad_level", "bad_dates", "does_not_fit", "member_quarantined",
                    "conflicting_rows", "over_cap")
NO_SNAPSHOT_CAUSES = ("no_source", "many_sources", "not_full", "no_as_of", "future_source", "blind", "empty",
                      "too_many_set_aside", "builder_error")

_AID = re.compile(r"[A-Z0-9]+")
_ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class SecretRefused(Exception):
    """The fixture source was given a secret other than PUBLIC_TEST_SECRET.  The message never carries secret bytes."""

    MESSAGE = "fixture source refused: it accepts only the public test secret"

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


# ---- dates

def valid_date(d: object) -> bool:
    """A CCYYMMDD number on the calendar (Rules/Spec.lean validDate; years 1..9999)."""
    if not isinstance(d, int) or isinstance(d, bool):
        return False
    y, m, dd = d // 10000, d // 100 % 100, d % 100
    if not (1 <= y <= 9999 and 1 <= m <= 12 and dd >= 1):
        return False
    try:
        datetime.date(y, m, dd)
    except ValueError:
        return False
    return True


def iso_day(text: object) -> int | None:
    """ISO YYYY-MM-DD to a CCYYMMDD number, or None when it is not exactly that form or not a calendar day."""
    if not isinstance(text, str) or not _ISO.fullmatch(text):
        return None
    d = int(text.replace("-", ""))
    return d if valid_date(d) else None


def _ordinal(d: int) -> int:
    return datetime.date(d // 10000, d // 100 % 100, d % 100).toordinal()


def _from_ordinal(o: int) -> int:
    x = datetime.date.fromordinal(o)
    return x.year * 10000 + x.month * 100 + x.day


# ---- encoding and pin (design 4.4)

def ok_elig(row: Sequence[int]) -> bool:
    """`okElig` (Rules/Spec.lean:300): valid dates, start <= stop, level <= 1."""
    _, _, level, start, stop = row
    return valid_date(start) and valid_date(stop) and start <= stop and 0 <= level <= 1


def fits_widths(row: Sequence[int]) -> bool:
    """Every field fits its pin width (section 2.1)."""
    return all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 256 ** w for w, v in zip(WIDTHS, row, strict=True))


def route_a_fits(row: Sequence[int]) -> bool:
    """Route A frame limits (TRUNK_STEP2_FRAME_DESIGN.md:117, :125, :129): member 0x01 plus 32 key bytes, aid text of
    at most 20 bytes, level one byte, dates four bytes.  The (b) encoder supplies its own; this is the test tool's."""
    member, aid, level, start, stop = row
    if member >> 256 != 1:
        return False
    nbytes = (aid.bit_length() + 7) // 8
    if aid <= 0 or nbytes > 21 or aid >> (8 * (nbytes - 1)) != 1:
        return False
    return 0 <= level < 256 and 0 <= start < 2 ** 32 and 0 <= stop < 2 ** 32


def encode_row(row: Sequence[int]) -> bytes:
    """One 267-byte row, through gate_rules_data.row("elig", ...) (decision 12)."""
    return gate_rules_data.row("elig", list(row))


def pin_input(asof: int, count: int, encoded_rows: Iterable[bytes]) -> bytes:
    """"RR/GATE/SNAPSHOT/v1" 0x00, u32 kind, u32 asOf, u32 count, then the rows sorted by bytes (gate_rules_data.py:41-43)."""
    head = b"".join(int(v).to_bytes(4, "big") for v in (KIND, asof, count))
    return DOMAIN + b"\0" + head + b"".join(sorted(encoded_rows))


@dataclass(frozen=True)
class Pinned:
    as_of: int
    count: int
    rows: tuple  # numeric 5-tuples in pin (byte) order
    pin: str  # lower-case hex SHA3-512


def pin_rows(asof: int, rows: Sequence[Sequence[int]]) -> Pinned:
    """Pre-keyed 5-tuples in, sort and pin out: no keying, no normalize, no dedupe and no `fits` (test/internal only)."""
    enc = sorted((encode_row(r), tuple(int(v) for v in r)) for r in rows)
    data = pin_input(asof, len(enc), (e for e, _ in enc))
    return Pinned(asof, len(enc), tuple(r for _, r in enc), hashlib.sha3_512(data).hexdigest())


def fragment(p: Pinned) -> str:
    """`snap elig ASOF COUNT PIN` and its rows, one per line, in the text runner's grammar (Run.lean:19)."""
    return "".join([f"snap elig {p.as_of} {p.count} {p.pin}\n"] + [f"elig {' '.join(str(v) for v in r)}\n" for r in p.rows])


# ---- join (design 2.6)

def join_windows(aids: Sequence[tuple], levels: Sequence[tuple]) -> list[tuple]:
    """Join one member's aid windows `(aid_text, start, stop)` with level windows `(level, start, stop)` of the same
    member and the same source.  A level-1 row is emitted only over the intersection of an aid window and a level-1
    window; every other day of the aid window gets level 0.  An aid is never paired with a level from another window
    than the one covering that day.  Dates are CCYYMMDD numbers, already valid and ordered; level windows must not
    overlap each other (the caller sets the member aside when they do).  Returns `(aid_text, level, start, stop)`."""
    out = []
    for aid, a0, a1 in aids:
        lo, hi = _ordinal(a0), _ordinal(a1)
        cuts = sorted((max(lo, _ordinal(s)), min(hi, _ordinal(e))) for lv, s, e in levels
                      if lv == 1 and _ordinal(s) <= hi and _ordinal(e) >= lo)
        day = lo
        for c0, c1 in cuts:
            if c0 > day:
                out.append((aid, 0, _from_ordinal(day), _from_ordinal(c0 - 1)))
            out.append((aid, 1, _from_ordinal(c0), _from_ordinal(c1)))
            day = c1 + 1
        if day <= hi:
            out.append((aid, 0, _from_ordinal(day), _from_ordinal(hi)))
    return out


def _overlap(windows: Sequence[tuple]) -> bool:
    """Any two windows `(..., start, stop)` overlap inclusively."""
    reach = None  # the latest stop seen so far, in start order
    for s, e in sorted((w[-2], w[-1]) for w in windows):
        if reach is not None and s <= reach:
            return True
        reach = e if reach is None else max(reach, e)
    return False


# ---- the fixture source (design 3.1)

_FIXTURE_KEYS = frozenset(("_note", "as_of", "full_roster", "records", "split"))
_SPLIT_KEYS = frozenset(("member_id", "aids", "levels"))


def _unique_keys(pairs: list) -> dict:
    """json object_pairs_hook: a key given twice is ambiguous, so the whole fixture is refused (never last-one-wins)."""
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("fixture has a duplicate key")
    return dict(pairs)


@dataclass(frozen=True)
class FixtureSource:
    """Hand-written synthetic records.  `records`: `[member_id, aid, level, start, stop]` (ISO dates; stop None is a
    stated open end).  `split`: `{"member_id", "aids": [[aid, start, stop]], "levels": [[level, start, stop]]}`; all
    split entries of one member are joined together by `join_windows`.  `as_of`: the source's own date (ISO),
    `full_roster`: the source says it lists every member.  Record content and raw bytes are left out of the repr."""
    as_of: object
    full_roster: object
    records: tuple = field(default=(), repr=False)
    split: tuple = field(default=(), repr=False)
    raw: bytes = field(default=b"", repr=False)  # the bytes it was read from, hashed into the sidecar
    kind: str = field(default="fixture", init=False)  # fixed: the class, not this tag, is what build() checks

    @classmethod
    def from_json(cls, data: bytes) -> "FixtureSource":
        """Parse one fixture file.  A duplicate key, an unknown top-level key, or `records`/`split` that is present but
        not a list raises ValueError (the CLI turns it into a builder_error no-snapshot)."""
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
        if not isinstance(doc, dict):
            raise ValueError("fixture is not a JSON object")
        if set(doc) - _FIXTURE_KEYS:
            raise ValueError("fixture has an unknown top-level key")
        records, split = doc.get("records", []), doc.get("split", [])
        if not isinstance(records, list) or not isinstance(split, list):
            raise ValueError("fixture records and split must be lists")
        return cls(doc.get("as_of"), doc.get("full_roster"), tuple(records), tuple(split), data)

    def digest(self) -> str:
        raw = self.raw or json.dumps({"as_of": self.as_of, "full_roster": self.full_roster, "records": list(self.records),
                                      "split": list(self.split)}, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_512(raw).hexdigest()


# ---- build (design 4.1-4.5)

@dataclass
class Result:
    result: str  # "snapshot" or "no_snapshot"
    cause: str | None
    snapshot: Pinned | None
    fragment: str | None
    sidecar: dict
    set_aside: list = field(default_factory=list)


def _canonical_aid(aid: object) -> str | None:
    if isinstance(aid, int) and not isinstance(aid, bool):
        return str(aid) if aid >= 0 else None
    if not isinstance(aid, str) or not _AID.fullmatch(aid):
        return None
    if aid.isdigit() and len(aid) > 1 and aid[0] == "0":
        return None
    return aid


def _good_id(mid: str) -> bool:
    """Not empty, no leading or trailing whitespace, and encodable as UTF-8 (member_key hashes `mid.encode()`)."""
    if mid == "" or mid != mid.strip():
        return False
    try:
        mid.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _normal(rec: object) -> tuple[str | None, object]:
    """(member_id, (aid_text, level, start, stop)) or (member_id, cause); member_id None when the record names none."""
    if not isinstance(rec, (list, tuple)) or not rec or not isinstance(rec[0], str):
        return None, "blind"
    mid = rec[0]
    if len(rec) != 5:
        return mid, "member_quarantined"
    _, aid, level, start, stop = rec
    if not _good_id(mid):
        return mid, "bad_member_id"
    text = _canonical_aid(aid)
    if text is None:
        return mid, "bad_aid"
    if not isinstance(level, int) or isinstance(level, bool) or level not in (0, 1):
        return mid, "bad_level"
    s = iso_day(start)
    e = OPEN_END if stop is None else iso_day(stop)
    if s is None or e is None or s > e:
        return mid, "bad_dates"
    return mid, (text, level, s, e)


def _split(entry: object) -> tuple[str | None, object]:
    """One split entry: (member_id, (aid windows, level windows)) or (member_id, cause).  The windows are joined only
    after every split entry of the member is gathered (design 2.6: same member and same source)."""
    if not isinstance(entry, dict) or not isinstance(entry.get("member_id"), str):
        return None, "blind"
    mid = entry["member_id"]
    if set(entry) - _SPLIT_KEYS:
        return mid, "member_quarantined"
    if not _good_id(mid):
        return mid, "bad_member_id"
    aids, levels = entry.get("aids"), entry.get("levels")
    if not isinstance(aids, list) or not isinstance(levels, list) or not aids:
        return mid, "member_quarantined"  # an entry with no aid window states no row: never silently nothing
    aw, lw = [], []
    for w in aids:
        got = _normal([mid, w[0], 0, w[1], w[2]]) if isinstance(w, list) and len(w) == 3 else (mid, "member_quarantined")
        if not isinstance(got[1], tuple):
            return got
        aw.append((got[1][0], got[1][2], got[1][3]))
    for w in levels:
        got = _normal([mid, "13", *w]) if isinstance(w, list) and len(w) == 3 else (mid, "member_quarantined")
        if not isinstance(got[1], tuple):
            return got
        lw.append((got[1][1], got[1][2], got[1][3]))
    return mid, (aw, lw)


def _key_forms(secret: bytes, mid: str) -> list[int]:
    """The keyed member numbers a record for `mid` is filed under: its own first, then (when it has leading or trailing
    whitespace) that of the trimmed id, the member an 837 for the same person would name, so a fault sent under a padded
    id also sets that member aside.  An id that does not encode is keyed with each lone surrogate replaced by U+FFFD."""
    safe = "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in mid)
    forms = [ident(member_key(secret, safe))]
    trimmed = safe.strip()
    if trimmed and trimmed != safe:
        forms.append(ident(member_key(secret, trimmed)))
    return forms


def _no(cause: str, sidecar: dict, set_aside: list | None = None) -> Result:
    if cause not in NO_SNAPSHOT_CAUSES:  # an explicit check, kept under python -O
        raise ValueError("no-snapshot cause outside the closed list")
    sidecar.update(result="no_snapshot", cause=cause, count=0, set_aside=set_aside or [])
    return Result("no_snapshot", cause, None, None, sidecar, set_aside or [])


def build(sources: Sequence[FixtureSource], secret: bytes, today: int, *,
          fits: Callable[[Sequence[int]], bool] = route_a_fits,
          clock: str = "caller-supplied today (timezone not stated)") -> Result:
    """The keyed path: one full-roster source, keyed under `secret`, dated by the source, checked against `today`.

    The only source type that exists is the fixture source, so any secret other than PUBLIC_TEST_SECRET is refused
    whatever the sources are (decision 3), and a source that is not a FixtureSource gives builder_error."""
    if not isinstance(secret, bytes) or secret != PUBLIC_TEST_SECRET:
        raise SecretRefused()
    sidecar = {"producer_version": PRODUCER_VERSION, "source_hashes": [], "as_of": None, "as_of_source": None,
               "clock": {"today": today, "basis": clock}, "count": 0, "set_aside": [], "result": None}
    try:
        if any(type(s) is not FixtureSource for s in sources):
            return _no("builder_error", sidecar)
        sidecar["source_hashes"] = [s.digest() for s in sources]
        return _build(sources, secret, today, fits, sidecar)
    except Exception:  # noqa: BLE001  never re-raised: its text could carry record fields
        return _no("builder_error", sidecar)


def _build(sources, secret, today, fits, sidecar) -> Result:
    if not sources:
        return _no("no_source", sidecar)
    if len(sources) > 1:
        return _no("many_sources", sidecar)
    src = sources[0]
    if src.full_roster is not True:
        return _no("not_full", sidecar)
    asof = iso_day(src.as_of)
    if asof is None:
        return _no("no_as_of", sidecar)
    sidecar.update(as_of=asof, as_of_source="fixture.as_of")
    if not valid_date(today):
        return _no("builder_error", sidecar)
    if asof > today:
        return _no("future_source", sidecar)
    age = _ordinal(today) - _ordinal(asof)
    sidecar.update(age_days=age, stale=age > MAX_AGE_DAYS)

    tag = src.digest()[:16]
    facts: dict[int, dict] = {}  # keyed member -> what the source states for it
    faults: dict[int, str] = {}  # keyed member -> its first cause
    origins: dict[int, list] = {}
    counts_as: dict[int, int] = {}  # keyed member -> the member it counts as for the threshold (a padded id's trimmed one)

    def member(mid: str, origin: str) -> list[int]:
        forms = _key_forms(secret, mid)
        for m in forms:
            origins.setdefault(m, []).append(origin)
            counts_as.setdefault(m, forms[-1])
            facts.setdefault(m, {"rows": set(), "row_levels": set(), "aids": set(), "levels": set(), "split": False})
        return forms

    def fault(forms: list[int], cause: str) -> None:
        for m in forms:
            faults.setdefault(m, cause)

    for i, rec in enumerate(src.records):
        mid, got = _normal(rec)
        if mid is None:
            return _no("blind", sidecar)
        forms = member(mid, f"fixture:{tag}#records/{i}")
        if isinstance(got, str):
            fault(forms, got)
            continue
        f = facts[forms[0]]
        f["rows"].add(got)
        f["row_levels"].add((got[1], got[2], got[3]))
    for i, entry in enumerate(src.split):
        mid, got = _split(entry)
        if mid is None:
            return _no("blind", sidecar)
        forms = member(mid, f"fixture:{tag}#split/{i}")
        if isinstance(got, str):
            fault(forms, got)
            continue
        f = facts[forms[0]]
        f["split"] = True
        f["aids"].update(got[0])
        f["levels"].update(got[1])

    kept: list = []
    for m in sorted(facts):
        if m in faults:
            continue
        f = facts[m]
        stated = set(f["rows"])
        if f["split"]:
            # Every level window of the member, from split entries and from full records, must not overlap another
            # (exact duplicates aside): two level facts for one day contradict each other, so the member is set aside.
            if _overlap(sorted(f["levels"] | f["row_levels"])):
                faults[m] = "conflicting_rows"
                continue
            stated.update(join_windows(sorted(f["aids"]), sorted(f["levels"])))
        rows: set = set()
        for aid_text, level, s, e in sorted(stated):
            row = (m, ident(aid_text.encode()), level, s, e)
            if not ok_elig(row):
                faults[m] = "bad_dates" if level <= 1 else "bad_level"
                break
            if not fits_widths(row) or not fits(row):
                faults[m] = "does_not_fit"
                break
            rows.add(row)
        if m in faults:
            continue
        uniq = sorted(rows)
        if not uniq:
            faults[m] = "member_quarantined"  # a member the source names with no row is a fault, never a good member
        elif len(uniq) > CAP:
            faults[m] = "over_cap"
        elif _overlap(uniq):
            faults[m] = "conflicting_rows"
        else:
            kept.extend(uniq)
    set_aside = [{"member_number": m.to_bytes((m.bit_length() + 7) // 8 or 1, "big").hex(), "cause": faults[m],
                  "origins": sorted(origins[m])} for m in sorted(faults)]
    if any(a["cause"] not in SET_ASIDE_CAUSES for a in set_aside):  # an explicit check, kept under python -O
        raise ValueError("set-aside cause outside the closed list")
    members = {counts_as[m] for m in facts}
    faulted = {counts_as[m] for m in faults}
    if len(faulted) * 100 > SET_ASIDE_LIMIT_PERCENT * len(members):
        return _no("too_many_set_aside", sidecar, set_aside)
    if not kept:
        return _no("empty", sidecar, set_aside)
    p = pin_rows(asof, kept)
    check = ref.pin_bytes("elig", asof, p.count, list(p.rows))  # independent cross-check, never the encoder
    if check is None or hashlib.sha3_512(check).hexdigest() != p.pin:
        return _no("builder_error", sidecar, set_aside)
    sidecar.update(result="snapshot", cause=None, count=p.count, pin=p.pin, set_aside=set_aside)
    return Result("snapshot", None, p, fragment(p), sidecar, set_aside)


# ---- CLI (decision 15: the secret comes from a file or an environment variable, never argv)

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # never echo arguments: a mistyped option could carry a secret
        sys.stderr.write("elig_snapshot: usage error (see --help)\n")
        raise SystemExit(2)


def _secret(args) -> bytes:
    """The secret as bytes.  On POSIX the environment is read as bytes, so a value that is not UTF-8 is never decoded
    (and never shows in an encoding error); elsewhere the text is encoded with surrogateescape."""
    if args.secret_file:
        with open(args.secret_file, "rb") as f:
            data = f.read()
        return data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data
    environb = getattr(os, "environb", None)
    if environb is not None:
        value = environb.get(os.fsencode(args.secret_env))
        if value is None:
            raise KeyError("secret environment variable is not set")
        return bytes(value)
    text = os.environ.get(args.secret_env)
    if text is None:
        raise KeyError("secret environment variable is not set")
    return text.encode("utf-8", "surrogateescape")


_PINNED_NAMES = frozenset(("MANIFEST.sha256", "PROVENANCE", "STMT_PIN"))


def _norm(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _refused_output(path: str, inputs: set) -> bool:
    """An output path under rightrail/, on a pinned file, on rust-engine/config.json, or on an input file."""
    real, rr = _norm(path), _norm(RIGHTRAIL)
    name = os.path.basename(real).lower()
    return (real == rr or real.startswith(rr.rstrip(os.sep) + os.sep) or name in {n.lower() for n in _PINNED_NAMES}
            or name.startswith("tcb_report") or real == _norm(os.path.join(ROOT, "rust-engine", "config.json"))
            or real in inputs)


def _write_atomic(path: str, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".elig_snapshot-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _write_outputs(fragment_path: str, sidecar_path: str, res: Result) -> None:
    """The fragment (only for a snapshot) first, then the sidecar; a failed sidecar write removes the fragment."""
    if res.fragment is not None:
        _write_atomic(fragment_path, res.fragment)
    try:
        _write_atomic(sidecar_path, json.dumps(res.sidecar, indent=2, sort_keys=True) + "\n")
    except BaseException:
        if res.fragment is not None and os.path.lexists(fragment_path):
            os.remove(fragment_path)
        raise


def _utc_offset(now: datetime.datetime) -> str:
    mins = int((now.utcoffset() or datetime.timedelta(0)).total_seconds()) // 60
    sign, mins = ("+" if mins >= 0 else "-"), abs(mins)
    return f"{sign}{mins // 60:02d}:{mins % 60:02d}"


def main(argv: Sequence[str] | None = None) -> int:
    p = _Parser(prog="elig_snapshot", allow_abbrev=False,
                description="Build a synthetic kind-7 eligibility snapshot fragment and sidecar from one fixture file (test-only).")
    p.add_argument("--fixture", action="append", default=[], help="fixture JSON (exactly one gives a snapshot)")
    p.add_argument("--today", type=int, help="host date CCYYMMDD (default: the host's local date)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--secret-file", help="file holding the tenant secret")
    g.add_argument("--secret-env", help="environment variable holding the tenant secret")
    p.add_argument("--fragment", required=True, help="where to write the fragment (written only for a snapshot)")
    p.add_argument("--sidecar", required=True, help="where to write the sidecar JSON")
    args = p.parse_args(argv)
    if args.today is None:
        now = datetime.datetime.now().astimezone()
        today = now.year * 10000 + now.month * 100 + now.day
        clock = f"host local date, timezone {now.tzname()}, UTC offset {_utc_offset(now)}"
    else:
        today, clock = args.today, "--today argument (timezone not stated)"

    inputs = {_norm(x) for x in args.fixture + ([args.secret_file] if args.secret_file else [])}
    if _norm(args.fragment) == _norm(args.sidecar) or any(_refused_output(x, inputs) for x in (args.fragment, args.sidecar)):
        sys.stderr.write("elig_snapshot: output path refused\n")
        return 2
    try:  # an earlier run's outputs never stand beside this run's result
        for path in (args.fragment, args.sidecar):
            if os.path.lexists(path):
                os.remove(path)
    except OSError:
        sys.stderr.write("elig_snapshot: an earlier output could not be removed\n")
        return 2

    base = {"producer_version": PRODUCER_VERSION, "source_hashes": [], "as_of": None, "as_of_source": None,
            "clock": {"today": today, "basis": clock}}

    def refuse(message: str) -> int:
        sys.stderr.write(f"elig_snapshot: {message}\n")
        _write_outputs(args.fragment, args.sidecar, _no("builder_error", dict(base)))
        return 2

    try:
        try:
            secret = _secret(args)
        except Exception:  # noqa: BLE001  the text of a decoding error could carry secret bytes
            return refuse("secret unreadable")
        try:
            sources = []
            for path in args.fixture:
                with open(path, "rb") as f:
                    sources.append(FixtureSource.from_json(f.read()))
        except Exception:  # noqa: BLE001  never re-raised: its text could carry record fields
            sources = None
        if sources is None:
            res = _no("builder_error", dict(base))
        else:
            try:
                res = build(sources, secret, today, clock=clock)
            except SecretRefused:
                return refuse(SecretRefused.MESSAGE)
        _write_outputs(args.fragment, args.sidecar, res)
    except Exception:  # noqa: BLE001  never re-raised: its text could carry record fields
        sys.stderr.write("elig_snapshot: internal error (builder_error)\n")
        try:
            if os.path.lexists(args.fragment):
                os.remove(args.fragment)
            _write_outputs(args.fragment, args.sidecar, _no("builder_error", dict(base)))
        except Exception:  # noqa: BLE001
            pass
        return 3
    print(f"ELIG_SNAPSHOT={res.result}" + (f" cause={res.cause}" if res.cause else f" count={res.snapshot.count}"))
    return 0 if res.result == "snapshot" else 1


if __name__ == "__main__":
    sys.exit(main())
