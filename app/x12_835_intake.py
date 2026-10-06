"""Read-only 835 intake (X221A1 subset): BPR, TRN, DTM, N1, CLP, CAS, SVC, PLB mapped to a frozen record in integer cents.

Evidence only: this module reads bytes and returns a record. It calls no owner and makes no determination. Anything outside
the subset (another segment, an unmodeled element, a production ISA15, a second transaction) is refused, never dropped.
Money is exact integer cents; one tree-sum rule closes every level: SVC02 - line CAS = SVC03; CLP03 - claim and service CAS =
CLP04, and with services CLP04 = sum(SVC03) - claim CAS; BPR02 = sum(CLP04) - sum(PLB amounts). PLB adjustments are kept whole,
each with its reason code and reference, and `forward_balance_cents` totals the ones coded FB (sign as on the wire).

Fold keys (hold-release r4.2 section 2). `rows` folds every CLP block of one file with the same key into one row, and every PLB
tuple likewise. The 835 tag comes from CLP02 alone (REV iff 22; the amount never changes it), so a sign flip keeps the key. One bad
claim or PLB pair never sinks the remittance: a block with any fault (CLP01, CLP02, CLP06-09, CLP07, a child segment, the claim
balance, PLB01, PLB02, a PLB reason or reference) keys as ("RAW", H(raw block)) and its flag says why; `claims` and `adjustments`
list only what was read, and the RAW row is the record of the rest. An unreadable CLP03-05 or PLB amount makes the row amount None
and the file `balance_unverified` (one unknown amount can absorb another's error in BPR02): S3 holds every row. An unreadable BPR02
still refuses the file: nothing can balance. A folded amount of 0 is a zero row (a receipt fact: S3, not this parser, gives it no
cell). Raw text is a canonical re-encoding (element, repeat, component and segment ends are control characters, trailing empties
dropped) so the key does not depend on the file's delimiters; the S3 line_digest covers this canonical form, not the wire bytes.
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
    status: str
    charge_cents: int
    paid_cents: int
    patient_cents: int
    filing: str
    payer_control: str
    facility: str
    frequency: str
    adjustments: tuple[Cas, ...]
    dates: tuple[Dtm, ...]
    services: tuple[Service, ...]


@dataclass(frozen=True)
class PlbAdjustment:
    provider_id: str
    fiscal_date: str  # ISO
    reason: str
    reference: str
    amount_cents: int  # positive reduces the payment


@dataclass(frozen=True)
class Row:
    key: tuple[str, ...]  # ("CLP"|"REV", CLP07), ("PLB", PLB01, PLB02, reason, reference) or ("RAW", H(raw block))
    amount_cents: int | None  # sum of CLP04, or minus the sum of the PLB wire amounts; 0 is a zero row; None: a block amount was unreadable
    raw: str  # the folded blocks' canonical text, in file order
    flags: tuple[str, ...]  # sorted union over the blocks: rev_sign (REV block > 0), clp_sign (CLP block < 0), or a RAW block's refusal code


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
    balance_unverified: bool  # a block amount was unreadable, so BPR02 was not checked: S3 holds every row


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


def _try(read):
    try:
        return read()
    except X12Error:
        return None


def _trim(items: list[str]) -> list[str]:
    while items and items[-1] == "":
        items.pop()
    return items


def _raw(seg: Segment, *at: int) -> str:
    """Canonical text of elements `at`; trailing empty elements, repeats and components are dropped (they are not content)."""
    slots = ["\x1e".join(_trim(["\x1d".join(_trim(list(r))) for r in (seg.elements[i - 1] if i <= len(seg.elements) else ())])) for i in at]
    return seg.tag + "".join("\x1f" + x for x in _trim(slots)) + "\n"


def _h(domain: str, *parts: str) -> str:
    """SHA3-256 over the domain and the parts, each length-prefixed, so no two part lists can share an input."""
    return hashlib.sha3_256("".join(f"{len(p)}:{p}" for p in (domain, *parts)).encode("ascii")).hexdigest()


def origin_id(sender: str, key: tuple[str, ...]) -> str:
    """common_origin_id of a row key for the channel's `sender` (section 2): injective in (sender, tag, parts)."""
    return _h("RR/835/ORIGIN/v1", sender, *key)


def pool(sender: str, record: Remittance) -> tuple[str, str, str]:
    return (sender, record.trace_origin, record.trace)


Part = tuple[tuple[str, ...], int | None, str, tuple[str, ...]]  # key, amount, raw, flags of one block


def _guard(raw: str, amount: int | None, read, key) -> tuple[object, Part]:
    """The one block-fault path. read() builds the block's record, key(record) its fold key; any refusal makes the block a RAW part
    whose flag is the refusal code. Flags are per block (the fold ORs them), so REV -100.00 and +30.00 cannot hide the +30.00."""
    try:
        item = read()
    except X12Error as fault:
        return None, (("RAW", _h("RR/835/RAW/v1", raw)), amount, raw, (str(fault),))
    k = key(item)
    return item, (k, amount, raw, ("rev_sign",) if k[0] == "REV" and amount > 0 else ("clp_sign",) if k[0] == "CLP" and amount < 0 else ())


def _fold(parts: list[Part]) -> tuple[Row, ...]:
    folded: dict[tuple[str, ...], tuple[list, list, set]] = {}
    for key, amount, raw, flags in parts:
        amounts, texts, seen = folded.setdefault(key, ([], [], set()))
        amounts.append(amount)
        texts.append(raw)
        seen.update(flags)
    return tuple(Row(k, None if None in a else sum(a), "".join(t), tuple(sorted(f))) for k, (a, t, f) in folded.items())


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


def _pairs(seg: Segment) -> list[int]:
    """The 1-based element of each PLB pair; a fault in the segment's own shape (no pair, or content past six pairs) refuses it."""
    found = []
    for k in range(3, 15, 2):
        if _try(lambda: seg.parts(k)) == ("",):
            seg.blank(k)
            break
        found.append(k)
    else:
        seg.blank(15)
    if not found:
        refuse("835:field")
    return found


def _pair(seg: Segment, k: int) -> PlbAdjustment:
    provider, fiscal, parts = _text(seg, 1), _date(seg.value(2)), seg.parts(k)
    if len(parts) > 2 or not _PLB_REASON.fullmatch(parts[0]) or (len(parts) == 2 and not _TEXT.fullmatch(parts[1])):
        refuse("835:field")
    return PlbAdjustment(provider, fiscal, parts[0], parts[1] if len(parts) == 2 else "", cents(seg.value(k + 1)))


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
    adjustments, dates = [], []
    for s in cursor.take("CAS", "DTM"):  # file order, so the first fault in a block is the same fault the independent parser meets
        adjustments += _cas(s) if s.tag == "CAS" else []
        dates += [_dtm(s)] if s.tag == "DTM" else []
    return tuple(adjustments), tuple(dates)


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


def _claim(segments: list[Segment]) -> Claim:
    cursor, seg = _Cursor(tuple(segments)), segments[0]
    cursor.next("CLP")
    seg.blank(10)
    fields = (_text(seg, 1), _text(seg, 2, _CODE), cents(seg.value(3)), cents(seg.value(4)), cents(seg.value(5)),
              _text(seg, 6, _CODE), _text(seg, 7), _text(seg, 8, _CODE, True), _text(seg, 9, _CODE, True))
    adjustments, dates = _level(cursor)
    services = []
    while cursor.peek() == "SVC":
        services.append(_service(cursor))
    claim = Claim(*fields, adjustments, dates, tuple(services))
    if not all(_closes(s) for s in services) or not _closes(claim, claim.services):
        refuse("835:claim-balance")
    return claim


def _paid(seg: Segment) -> int | None:
    """CLP04 when CLP03-05 all read, else None: one unknown amount can absorb another's error in BPR02."""
    amounts = [_try(lambda: cents(seg.value(i))) for i in (3, 4, 5)]
    return None if None in amounts else amounts[1]


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
    total = cents(bpr.value(2))  # bpr02-unreadable: nothing can balance, so this one refuses the whole file
    if total < 0:
        refuse("835:amount")
    head = (_text(bpr, 1, _CODE), total, _text(bpr, 3, _CREDIT), _text(bpr, 4, _CODE), _text(bpr, 5, _CODE),
            _date(bpr.value(16)), _text(trn, 2), _text(trn, 3))
    dates = tuple(_dtm(s) for s in cursor.take("DTM"))
    payer, payee = _party(cursor.next("N1"), "PR"), _party(cursor.next("N1"), "PE")
    claims, adjustments, parts, paid, withheld = [], [], [], [], []
    while cursor.peek() == "CLP":
        segments = [cursor.next("CLP"), *cursor.take("CAS", "DTM", "SVC")]
        amount = _paid(segments[0])
        claim, part = _guard("".join(_raw(s, *range(1, len(s.elements) + 1)) for s in segments), amount, lambda: _claim(segments),
                             lambda c: ("REV" if c.status == "22" else "CLP", c.payer_control))
        claims += [claim] if claim else []
        paid.append(amount)
        parts.append(part)
    for seg in cursor.take("PLB"):
        try:
            ks = _pairs(seg)
        except X12Error as fault:
            raw, wires = _raw(seg, *range(1, len(seg.elements) + 1)), [None]
            parts.append((("RAW", _h("RR/835/RAW/v1", raw)), None, raw, (str(fault),)))
        else:
            wires = [_try(lambda: cents(seg.value(k + 1))) for k in ks]
            for k, wire in zip(ks, wires):
                adjustment, part = _guard(_raw(seg, 1, 2, k, k + 1), None if wire is None else -wire, lambda: _pair(seg, k),
                                          lambda a: ("PLB", a.provider_id, a.fiscal_date, a.reason, a.reference))
                adjustments += [adjustment] if adjustment else []
                parts.append(part)
        withheld += wires
    if cursor.peek():
        refuse("835:segment")
    unverified = None in paid or None in withheld
    claims_paid, plb_total = sum(a for a in paid if a is not None), sum(a for a in withheld if a is not None)
    if not unverified and total != claims_paid - plb_total:
        refuse("835:balance")
    return Remittance(interchange.isa.value(13), group.gs.value(6), transaction[0].value(2), interchange.isa.value(6).rstrip(" "),
                      interchange.isa.value(8).rstrip(" "), group.gs.value(2), group.gs.value(3), *head, dates, payer, payee,
                      tuple(claims), tuple(adjustments), claims_paid, plb_total,
                      sum(a.amount_cents for a in adjustments if a.reason == "FB"),  # a RAW pair is not here: its RAW row is the record
                      _fold(parts), unverified)
