"""Independent re-derivation of the 835 intake record from raw bytes.

Written separately: it imports nothing from `app.x12_tokenizer` or `app.x12_835_intake` (regex ISA match, lazy element
splitting, recursive-descent envelope, tag-sequence regex for the 835 order, Decimal for money). It must agree with the intake
on every input: the same record, or a refusal. Envelope-level (x12:) codes match exactly; where one file has several faults the
835: code can differ, because this checks segment order before fields and the intake checks them as it walks.
"""

from __future__ import annotations

import dataclasses
from decimal import Context, Decimal
import re
from datetime import datetime
from typing import NoReturn


class IndependentX12Error(ValueError):
    """Fixed-code refusal of the independent 835 re-derivation."""


def _no(code: str) -> NoReturn:
    raise IndependentX12Error(code) from None


_PUNCT = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_WIDTHS = (2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1)
_ISA = re.compile("ISA(?P<e>.)" + "(?P=e)".join("((?:(?!(?P=e)).){%d})" % w for w in _WIDTHS) + "(?P<t>.)", re.DOTALL)
_FRAME = frozenset(("ISA", "GS", "ST", "SE", "GE"))
_ORDER = re.compile(r"BPR TRN( DTM)* N1 N1( CLP( (?:CAS|DTM))*( SVC( (?:CAS|DTM))*)*)*( PLB)*")
_MONEY = re.compile(r"-?(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,2})?")
_QTY = re.compile(r"-?(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,4})?")
_TEXT = re.compile(r"(?=.{1,60}$)[A-Za-z0-9._,&'/-]+(?: +[A-Za-z0-9._,&'/-]+)*")
_ID = re.compile(r"[!-~]+(?: +[!-~]+)*")  # ISA06/ISA08/GS02/GS03: printable AN; this file's delimiters never reach it
_CODE = re.compile(r"[A-Z0-9]{1,5}")
_QUALIFIERS = frozenset("01 14 20 27 28 29 30 33 ZZ".split())
_CONTEXT = Context(prec=28)  # never the ambient decimal context


class _Seg:
    def __init__(self, tag: str, raw: list[str], r: str, c: str) -> None:
        self.tag, self.raw, self.r, self.c = tag, raw, r, c

    def parts(self, i: int) -> list[str]:
        item = self.raw[i - 1] if i <= len(self.raw) else ""
        if self.r in item:
            _no("x12:shape")
        return item.split(self.c)

    def val(self, i: int) -> str:
        parts = self.parts(i)
        if len(parts) > 1:
            _no("x12:shape")
        return parts[0]

    def blank(self, first: int, last: int | None = None) -> None:
        if any(self.raw[first - 1:last]):
            _no("x12:extra")

    def text(self, i: int, pattern: re.Pattern = _TEXT, optional: bool = False) -> str:
        v = self.val(i)
        if v == "" and optional:
            return v
        if not pattern.fullmatch(v):
            _no("835:field")
        return v

    def dtm(self) -> dict:
        self.blank(3)
        return {"qualifier": self.text(1, re.compile("[0-9]{3}")), "date": _iso(self.val(2))}


def _lex(chunk: str, e: str, r: str, c: str) -> _Seg:
    if not re.fullmatch("[ -~]*", chunk):
        _no("x12:charset")
    tag, has, rest = chunk.partition(e)
    if not re.fullmatch("[A-Z][A-Z0-9]{1,2}", tag):
        _no("x12:segment")
    if has and rest.count(e) >= 64:
        _no("x12:cap-elements")
    raw = rest.split(e) if has else []
    for item in raw:
        if len(item) > 128:
            _no("x12:cap-element-length")
        repeats = item.split(r)
        if len(repeats) > 8:
            _no("x12:cap-repeats")
        if any(len(x.split(c)) > 16 for x in repeats):
            _no("x12:cap-components")
    return _Seg(tag, raw, r, c)


def _check(close: _Seg, opened: _Seg, close_at: int, open_at: int, n: int) -> None:
    close.blank(3)
    control = opened.val(open_at)
    if close.val(close_at) != control or not re.fullmatch("[0-9]{1,9}", control):
        _no("x12:control")
    if close.val(1) != str(n):
        _no("x12:count")


def _cents(text: str) -> int:
    if not _MONEY.fullmatch(text):
        _no("835:amount")
    d = _CONTEXT.create_decimal(text)
    if text[0] == "-" and d == 0:
        _no("835:amount")
    return int(_CONTEXT.scaleb(d, 2))


def _when(text: str, digits: int = 8, fmt: str = "%Y%m%d") -> datetime | None:
    if re.fullmatch("[0-9]{%d}" % digits, text):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _iso(text: str) -> str:
    when = _when(text)
    if when is None or not 1900 <= when.year <= 2199:
        _no("835:date")
    return when.strftime("%Y-%m-%d")


def _clock(text: str) -> bool:
    return re.fullmatch("[0-9]{4}(?:[0-9]{2}(?:[0-9]{1,2})?)?", text) is not None and int(text[:2]) < 24 and int(text[2:4]) < 60 and int(text[4:6] or 0) < 60


def _isa_ok(f: tuple[str, ...]) -> bool:
    quiet = (f[0] != "00" or f[1] == " " * 10) and (f[2] != "00" or f[3] == " " * 10)
    return (f[0] in ("00", "03") and f[2] in ("00", "01") and quiet and f[4] in _QUALIFIERS and f[6] in _QUALIFIERS
            and all(re.fullmatch("[ -~]*", f[i]) for i in (1, 3)) and all(_ID.fullmatch(f[i].rstrip(" ")) for i in (5, 7))
            and _when(f[8], 6, "%y%m%d") is not None and len(f[9]) == 4 and _clock(f[9]))


def _qty(text: str) -> str:
    if text and not _QTY.fullmatch(text):
        _no("835:field")
    return text


def _cas(s: _Seg) -> list[dict]:
    group, found = s.text(1, _CODE), []
    for k in range(2, 20, 3):
        if s.val(k) == "":
            s.blank(k)
            break
        found.append({"group": group, "reason": s.text(k, _CODE), "amount_cents": _cents(s.val(k + 1)), "quantity": _qty(s.val(k + 2))})
    else:
        s.blank(20)
    if not found:
        _no("835:field")
    return found


def _plb(s: _Seg) -> list[dict]:
    provider, fiscal, found = s.text(1), _iso(s.val(2)), []
    for k in range(3, 15, 2):
        p = s.parts(k)
        if p == [""]:
            s.blank(k)
            break
        if len(p) > 2 or not re.fullmatch("[A-Z0-9]{2}", p[0]) or (len(p) == 2 and not _TEXT.fullmatch(p[1])):
            _no("835:field")
        found.append({"provider_id": provider, "fiscal_date": fiscal, "reason": p[0], "reference": p[1] if len(p) == 2 else "",
                      "amount_cents": _cents(s.val(k + 1))})
    else:
        s.blank(15)
    if not found:
        _no("835:field")
    return found


def _closes(node: dict, children: list[dict] | tuple = ()) -> bool:
    """One tree-sum rule: paid = charge - own CAS - children's CAS, and, with children, paid = sum(children paid) - own CAS."""
    own = sum(a["amount_cents"] for a in node["adjustments"])
    below = sum(a["amount_cents"] for k in children for a in k["adjustments"])
    return node["charge_cents"] - own - below == node["paid_cents"] and (not children or sum(k["paid_cents"] for k in children) - own == node["paid_cents"])


def _party(s: _Seg, role: str) -> dict:
    s.blank(5)
    if s.val(1) != role:
        _no("835:segment")
    return {"name": s.text(2), "id_qualifier": s.text(3, _CODE), "id": s.text(4)}


def rederive_835(data: bytes) -> dict:
    if type(data) is not bytes:
        _no("x12:input")
    if len(data) > 1 << 20:
        _no("x12:cap-bytes")
    if any(b > 127 for b in data):
        _no("x12:non-ascii")
    text = data.decode("ascii")
    m = _ISA.match(text)
    if m is None:
        _no("x12:isa")
    g = m.groups()
    e, f, t = g[0], g[1:17], g[17]
    r, c = f[10], f[15]
    if len({e, r, c, t}) != 4 or not {e, r, c, t} <= _PUNCT:
        _no("x12:separator")
    if any(x in f[i] for i in range(16) if i not in (10, 15) for x in (r, c, t)):
        _no("x12:separator")
    if f[11] != "00501":
        _no("x12:version")
    if not re.fullmatch("[0-9]{9}", f[12]) or f[13] not in "01" or f[14] not in "PT" or not _isa_ok(f):
        _no("x12:isa")
    if text.count(t, 106) > 5000:
        _no("x12:cap-segments")
    body, found, tail = text[106:].rpartition(t)
    chunks = body.split(t) if found else []
    tags = [chunk.partition(e)[0] for chunk in chunks]
    if "IEA" in tags[:-1]:
        _no("x12:trailing")
    if not tags or tags[-1] != "IEA":
        _no("x12:truncated")
    if tail:
        _no("x12:trailing")
    segs = [_lex(chunk, e, r, c) for chunk in chunks]
    mid, groups, i = segs[:-1], [], 0
    while i < len(mid):
        gs, sets, i = mid[i], [], i + 1
        if gs.tag != "GS":
            _no("x12:envelope")
        gs.blank(9)
        sender, receiver, day, clock, agency = (gs.val(k) for k in (2, 3, 4, 5, 7))
        when = _when(day)
        if not (all(_ID.fullmatch(v) and 1 < len(v) < 16 for v in (sender, receiver))
                and when and 1900 <= when.year <= 2199 and _clock(clock) and agency == "X"):
            _no("x12:envelope")
        while i < len(mid) and mid[i].tag == "ST":
            mid[i].blank(4)
            if mid[i].val(3) not in ("", gs.val(8)):
                _no("x12:version")
            j = i + 1
            while j < len(mid) and mid[j].tag not in _FRAME:
                j += 1
            if j == len(mid) or mid[j].tag != "SE":
                _no("x12:envelope")
            _check(mid[j], mid[i], 2, 2, j - i + 1)
            sets.append(mid[i:j + 1])
            i = j + 1
        if i == len(mid) or mid[i].tag != "GE":
            _no("x12:envelope")
        _check(mid[i], gs, 2, 6, len(sets))
        groups.append((gs, sets))
        i += 1
    if not groups:
        _no("x12:envelope")
    segs[-1].blank(3)
    if segs[-1].val(2) != f[12]:
        _no("x12:control")
    if segs[-1].val(1) != str(len(groups)):
        _no("x12:count")
    if f[14] != "T":
        _no("835:production")
    if len(groups) != 1 or len(groups[0][1]) != 1:
        _no("835:envelope")
    gs, ((st, *body, _),) = groups[0][0], groups[0][1]
    if gs.val(1) != "HP" or gs.val(8) != "005010X221A1":
        _no("835:version")
    if st.val(1) != "835":
        _no("835:envelope")
    if not _ORDER.fullmatch(" ".join(s.tag for s in body)):
        _no("835:segment")
    bpr, trn = body[0], body[1]
    bpr.blank(6, 15)
    bpr.blank(17)
    trn.blank(4)
    if trn.val(1) != "1":
        _no("835:field")
    total = _cents(bpr.val(2))
    if total < 0:
        _no("835:amount")
    record = {"interchange_control": f[12], "group_control": gs.val(6), "set_control": st.val(2),
              "interchange_sender": f[5].rstrip(" "), "interchange_receiver": f[7].rstrip(" "),
              "group_sender": gs.val(2), "group_receiver": gs.val(3),
              "handling": bpr.text(1, _CODE), "total_cents": total, "credit_debit": bpr.text(3, re.compile("C")),
              "method": bpr.text(4, _CODE), "format": bpr.text(5, _CODE), "effective_date": _iso(bpr.val(16)),
              "trace": trn.text(2), "trace_origin": trn.text(3), "dates": [], "payer": None, "payee": None, "claims": [], "adjustments": []}
    level, parties = record["dates"], []
    for s in body[2:]:
        if s.tag == "DTM":
            level.append(s.dtm())
        elif s.tag == "N1":
            parties.append(_party(s, "PR" if not parties else "PE"))
        elif s.tag == "CLP":
            s.blank(10)
            claim = {"control": s.text(1), "status": s.text(2, _CODE), "charge_cents": _cents(s.val(3)), "paid_cents": _cents(s.val(4)),
                     "patient_cents": _cents(s.val(5)), "filing": s.text(6, _CODE), "payer_control": s.text(7),
                     "facility": s.text(8, _CODE, True), "frequency": s.text(9, _CODE, True), "adjustments": [], "dates": [], "services": []}
            record["claims"].append(claim)
            level, adjust = claim["dates"], claim["adjustments"]
        elif s.tag == "SVC":
            s.blank(6)
            q = s.parts(1)
            if len(q) != 2 or not _CODE.fullmatch(q[0]) or not _TEXT.fullmatch(q[1]):
                _no("835:field")
            service = {"qualifier": q[0], "code": q[1], "charge_cents": _cents(s.val(2)), "paid_cents": _cents(s.val(3)),
                       "revenue": s.text(4, _CODE, True), "units": _qty(s.val(5)), "adjustments": [], "dates": []}
            claim["services"].append(service)
            level, adjust = service["dates"], service["adjustments"]
        elif s.tag == "CAS":
            adjust.extend(_cas(s))
        else:
            record["adjustments"].extend(_plb(s))
        if s.tag == "N1" and len(parties) == 2:
            record["payer"], record["payee"] = parties
    if not all(_closes(s) for c in record["claims"] for s in c["services"]) or not all(_closes(c, c["services"]) for c in record["claims"]):
        _no("835:claim-balance")
    claims_paid = sum(c["paid_cents"] for c in record["claims"])
    plb_total = sum(a["amount_cents"] for a in record["adjustments"])
    if total != claims_paid - plb_total:
        _no("835:balance")
    record.update(claims_paid_cents=claims_paid, plb_total_cents=plb_total,
                  forward_balance_cents=sum(a["amount_cents"] for a in record["adjustments"] if a["reason"] == "FB"))
    return record


def _same(stored: object, derived: object) -> bool:
    """Exact types: a frozen dataclass where the derivation has a dict, a tuple where it has a list, int (never bool or float), str."""
    if type(derived) is dict:
        return (dataclasses.is_dataclass(stored) and not isinstance(stored, type) and stored.__dataclass_params__.frozen
                and {f.name for f in dataclasses.fields(stored)} == derived.keys()
                and all(_same(getattr(stored, k), v) for k, v in derived.items()))
    if type(derived) is list:
        return type(stored) is tuple and len(stored) == len(derived) and all(map(_same, stored, derived))
    return type(stored) is type(derived) and stored == derived


def verify_835(data: bytes, record: object) -> None:
    """Raise unless `record` (the intake's frozen record) equals the independent re-derivation of `data`."""
    if not _same(record, rederive_835(data)):
        _no("835:disagree")
