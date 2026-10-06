"""Read-only 835 intake (X221A1 subset): BPR, TRN, DTM, N1, CLP, CAS, SVC, PLB mapped to a frozen record in integer cents.

Evidence only: this module reads bytes and returns a record. It calls no owner and makes no determination. Anything outside
the subset (another segment, an unmodeled element, a production ISA15, a second transaction) is refused, never dropped.
Money is exact integer cents; one tree-sum rule closes every level: SVC02 - line CAS = SVC03; CLP03 - claim and service CAS =
CLP04, and with services CLP04 = sum(SVC03) - claim CAS; BPR02 = sum(CLP04) - sum(PLB amounts). PLB adjustments are kept whole,
each with its reason code and reference, and `forward_balance_cents` totals the ones coded FB (sign as on the wire).

Fold keys (hold-release r4.2 section 2). `rows` folds every CLP block of one file with the same key into one row, and every PLB
tuple likewise. The 835 tag comes from CLP02 alone (REV iff 22; the amount never changes it), so a sign flip keeps the key. A CLP02,
CLP07 or PLB reason or reference that cannot be read does not refuse the file: the block keys as ("RAW", H(raw block)). A folded
amount of 0 is a zero row (a receipt fact: the S3 verdict engine, not this parser, gives it no cell). `flags` carry the sign checks.
Raw text is a canonical re-encoding (element, repeat, component and segment ends are control characters) so the key does not
depend on the file's delimiters.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime
import hashlib
import re

from app.mirror.error_boundary import raise_redacted
from app.x12_tokenizer import Segment, X12Error, refuse, tokenize

_MONEY = re.compile(r"(-?)(0|[1-9][0-9]{0,11})(?:\.([0-9]{1,2}))?")
_QUANTITY = re.compile(r"-?(0|[1-9][0-9]{0,9})(\.[0-9]{1,4})?")
_DATE = re.compile(r"[0-9]{8}")
_TEXT = re.compile(r"[A-Za-z0-9._,&'/-](?:[A-Za-z0-9 ._,&'/-]{0,58}[A-Za-z0-9._,&'/-])?")
_CODE = re.compile(r"[A-Z0-9]{1,5}")
_DTM_QUALIFIER = re.compile(r"[0-9]{3}")
_PLB_REASON = re.compile(r"[A-Z0-9]{2}")
_CREDIT = re.compile(r"C")  # credit only: a debit needs an owner design first


@dataclass(frozen=True)
class Dtm:
    qualifier: str
    date: str  # ISO


@dataclass(frozen=True)
class Party:
    name: str
    id_qualifier: str
    id: str


@dataclass(frozen=True)
class Cas:
    group: str
    reason: str
    amount_cents: int
    quantity: str


@dataclass(frozen=True)
class Service:
    qualifier: str
    code: str
    charge_cents: int
    paid_cents: int
    revenue: str
    units: str
    adjustments: tuple[Cas, ...]
    dates: tuple[Dtm, ...]


@dataclass(frozen=True)
class Claim:
    control: str
    status: str | None  # CLP02; None when unreadable
    charge_cents: int
    paid_cents: int
    patient_cents: int
    filing: str
    payer_control: str | None  # CLP07; None when unreadable
    facility: str
    frequency: str
    adjustments: tuple[Cas, ...]
    dates: tuple[Dtm, ...]
    services: tuple[Service, ...]


@dataclass(frozen=True)
class PlbAdjustment:
    provider_id: str
    fiscal_date: str  # ISO
    reason: str | None  # None when the reason or reference cannot be read
    reference: str | None
    amount_cents: int  # positive reduces the payment


@dataclass(frozen=True)
class Row:
    key: tuple[str, ...]  # ("CLP"|"REV", CLP07), ("PLB", PLB01, PLB02, reason, reference) or ("RAW", H(raw block))
    amount_cents: int  # sum of CLP04, or minus the sum of the PLB wire amounts; 0 is a zero row
    raw: str  # the folded blocks' canonical text, in file order
    flags: tuple[str, ...]  # rev_sign: REV with amount > 0; clp_sign: CLP with amount < 0


@dataclass(frozen=True)
class Remittance:
    interchange_control: str
    group_control: str
    set_control: str
    interchange_sender: str  # ISA06, padding removed
    interchange_receiver: str  # ISA08, padding removed
    group_sender: str  # GS02
    group_receiver: str  # GS03
    handling: str
    total_cents: int
    credit_debit: str
    method: str
    format: str
    effective_date: str  # ISO
    trace: str
    trace_origin: str
    dates: tuple[Dtm, ...]
    payer: Party
    payee: Party
    claims: tuple[Claim, ...]
    adjustments: tuple[PlbAdjustment, ...]
    claims_paid_cents: int
    plb_total_cents: int
    forward_balance_cents: int
    rows: tuple[Row, ...]


def cents(text: str) -> int:
    match = _MONEY.fullmatch(text)
    if match is None:
        refuse("835:amount")
    value = int(match[2]) * 100 + int((match[3] or "").ljust(2, "0"))
    if match[1] and value == 0:
        refuse("835:amount")
    return -value if match[1] else value


def _date(text: str) -> str:
    if not _DATE.fullmatch(text):
        refuse("835:date")
    try:
        when = datetime.date(int(text[:4]), int(text[4:6]), int(text[6:]))
    except ValueError:
        raise_redacted(X12Error, "835:date")
    if not 1900 <= when.year <= 2199:
        refuse("835:date")
    return when.isoformat()


def _text(seg: Segment, i: int, pattern: re.Pattern = _TEXT, blank: bool = False) -> str:
    value = seg.value(i)
    if value == "" and blank:
        return ""
    if not pattern.fullmatch(value):
        refuse("835:field")
    return value


def _soft(seg: Segment, i: int, pattern: re.Pattern = _TEXT) -> str | None:
    try:
        return _text(seg, i, pattern)
    except X12Error:
        return None


def _raw(seg: Segment, *at: int) -> str:
    return seg.tag + "".join("\x1f" + "\x1e".join("\x1d".join(r) for r in (seg.elements[i - 1] if i <= len(seg.elements) else ())) for i in at) + "\n"


def _h(*parts: str) -> str:
    return hashlib.sha3_256("\0".join(parts).encode("ascii")).hexdigest()


def origin_id(sender: str, key: tuple[str, ...]) -> str:
    """common_origin_id of a row key for the channel's `sender` (section 2)."""
    if key[0] == "PLB":
        return f"x12/{sender}/PLB/{_h(*key)}"
    return f"x12/{sender}/{'raw' if key[0] == 'RAW' else key[0]}/{key[1]}"


def pool(sender: str, record: Remittance) -> tuple[str, str, str]:
    return (sender, record.trace_origin, record.trace)


def _fold(parts: list[tuple[tuple[str, ...], int, str]]) -> tuple[Row, ...]:
    folded: dict[tuple[str, ...], tuple[int, str]] = {}
    for key, amount, raw in parts:
        total, text = folded.get(key, (0, ""))
        folded[key] = (total + amount, text + raw)
    return tuple(Row(k, a, r, ("rev_sign",) if k[0] == "REV" and a > 0 else ("clp_sign",) if k[0] == "CLP" and a < 0 else ()) for k, (a, r) in folded.items())


def _quantity(text: str) -> str:
    if text and not _QUANTITY.fullmatch(text):
        refuse("835:field")
    return text


def _dtm(seg: Segment) -> Dtm:
    seg.blank(3)
    return Dtm(_text(seg, 1, _DTM_QUALIFIER), _date(seg.value(2)))


def _party(seg: Segment, role: str) -> Party:
    seg.blank(5)
    if seg.value(1) != role:
        refuse("835:segment")
    return Party(_text(seg, 2), _text(seg, 3, _CODE), _text(seg, 4))


def _cas(seg: Segment) -> list[Cas]:
    group, found = _text(seg, 1, _CODE), []
    for k in range(2, 20, 3):
        if seg.value(k) == "":
            seg.blank(k)
            break
        found.append(Cas(group, _text(seg, k, _CODE), cents(seg.value(k + 1)), _quantity(seg.value(k + 2))))
    else:
        seg.blank(20)
    if not found:
        refuse("835:field")
    return found


def _plb(seg: Segment) -> list[tuple[PlbAdjustment, str]]:
    provider, fiscal, found = _text(seg, 1), _date(seg.value(2)), []
    for k in range(3, 15, 2):
        try:
            parts = seg.parts(k)
        except X12Error:
            parts = None
        if parts == ("",):
            seg.blank(k)
            break
        readable = parts is not None and len(parts) <= 2 and _PLB_REASON.fullmatch(parts[0]) and (len(parts) == 1 or _TEXT.fullmatch(parts[1]))
        reason, reference = (parts[0], parts[1] if len(parts) == 2 else "") if readable else (None, None)
        found.append((PlbAdjustment(provider, fiscal, reason, reference, cents(seg.value(k + 1))), _raw(seg, 1, 2, k, k + 1)))
    else:
        seg.blank(15)
    if not found:
        refuse("835:field")
    return found


class _Cursor:
    def __init__(self, segments: tuple[Segment, ...]) -> None:
        self._segments, self._at = segments, 0

    def peek(self) -> str:
        return self._segments[self._at].tag if self._at < len(self._segments) else ""

    def next(self, tag: str) -> Segment:
        if self.peek() != tag:
            refuse("835:segment")
        self._at += 1
        return self._segments[self._at - 1]

    def take(self, *tags: str) -> list[Segment]:
        taken = []
        while self.peek() in tags:
            taken.append(self.next(self.peek()))
        return taken


def _level(cursor: _Cursor) -> tuple[tuple[Cas, ...], tuple[Dtm, ...]]:
    segments = cursor.take("CAS", "DTM")
    return (tuple(a for s in segments if s.tag == "CAS" for a in _cas(s)), tuple(_dtm(s) for s in segments if s.tag == "DTM"))


def _closes(node: Claim | Service, children: tuple[Service, ...] = ()) -> bool:
    """One tree-sum rule: paid = charge - own CAS - children's CAS, and, with children, paid = sum(children paid) - own CAS."""
    own = sum(a.amount_cents for a in node.adjustments)
    below = sum(a.amount_cents for k in children for a in k.adjustments)
    return node.charge_cents - own - below == node.paid_cents and (not children or sum(k.paid_cents for k in children) - own == node.paid_cents)


def _service(cursor: _Cursor) -> Service:
    seg = cursor.next("SVC")
    seg.blank(6)
    parts = seg.parts(1)
    if len(parts) != 2 or not _CODE.fullmatch(parts[0]) or not _TEXT.fullmatch(parts[1]):
        refuse("835:field")
    fields = (parts[0], parts[1], cents(seg.value(2)), cents(seg.value(3)), _text(seg, 4, _CODE, True), _quantity(seg.value(5)))
    return Service(*fields, *_level(cursor))


def _claim(cursor: _Cursor) -> tuple[Claim, str]:
    start, seg = cursor._at, cursor.next("CLP")
    seg.blank(10)
    fields = (_text(seg, 1), _soft(seg, 2, _CODE), cents(seg.value(3)), cents(seg.value(4)), cents(seg.value(5)),
              _text(seg, 6, _CODE), _soft(seg, 7), _text(seg, 8, _CODE, True), _text(seg, 9, _CODE, True))
    adjustments, dates = _level(cursor)
    services = []
    while cursor.peek() == "SVC":
        services.append(_service(cursor))
    claim = Claim(*fields, adjustments, dates, tuple(services))
    if not all(_closes(s) for s in services) or not _closes(claim, claim.services):
        refuse("835:claim-balance")
    return claim, "".join(_raw(s, *range(1, len(s.elements) + 1)) for s in cursor._segments[start:cursor._at])


def parse_835(data: bytes) -> Remittance:
    interchange = tokenize(data)
    if interchange.isa.value(15) != "T":
        refuse("835:production")
    if len(interchange.groups) != 1 or len(interchange.groups[0].transactions) != 1:
        refuse("835:envelope")
    group = interchange.groups[0]
    (transaction,) = group.transactions
    if group.gs.value(1) != "HP" or group.gs.value(8) != "005010X221A1":
        refuse("835:version")
    if transaction[0].value(1) != "835":
        refuse("835:envelope")
    cursor = _Cursor(transaction[1:-1])
    bpr, trn = cursor.next("BPR"), cursor.next("TRN")
    bpr.blank(6, 15)
    bpr.blank(17)
    trn.blank(4)
    if trn.value(1) != "1":
        refuse("835:field")
    total = cents(bpr.value(2))
    if total < 0:
        refuse("835:amount")
    head = (_text(bpr, 1, _CODE), total, _text(bpr, 3, _CREDIT), _text(bpr, 4, _CODE), _text(bpr, 5, _CODE),
            _date(bpr.value(16)), _text(trn, 2), _text(trn, 3))
    dates = tuple(_dtm(s) for s in cursor.take("DTM"))
    payer, payee = _party(cursor.next("N1"), "PR"), _party(cursor.next("N1"), "PE")
    claims, parts = [], []
    while cursor.peek() == "CLP":
        claim, raw = _claim(cursor)
        claims.append(claim)
        key = ("RAW", _h(raw)) if None in (claim.status, claim.payer_control) else ("REV" if claim.status == "22" else "CLP", claim.payer_control)
        parts.append((key, claim.paid_cents, raw))
    plbs = [p for s in cursor.take("PLB") for p in _plb(s)]
    adjustments = tuple(a for a, _ in plbs)
    for a, raw in plbs:
        parts.append((("RAW", _h(raw)) if a.reason is None else ("PLB", a.provider_id, a.fiscal_date, a.reason, a.reference), -a.amount_cents, raw))
    if cursor.peek():
        refuse("835:segment")
    claims_paid = sum(c.paid_cents for c in claims)
    plb_total = sum(a.amount_cents for a in adjustments)
    if total != claims_paid - plb_total:
        refuse("835:balance")
    return Remittance(interchange.isa.value(13), group.gs.value(6), transaction[0].value(2), interchange.isa.value(6).rstrip(" "),
                      interchange.isa.value(8).rstrip(" "), group.gs.value(2), group.gs.value(3), *head, dates, payer, payee,
                      tuple(claims), adjustments, claims_paid, plb_total,
                      sum(a.amount_cents for a in adjustments if a.reason == "FB"), _fold(parts))
