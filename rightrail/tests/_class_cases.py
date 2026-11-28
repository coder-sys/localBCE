"""Synthetic inputs, one for each kind of finding or set-aside a reader on the claim path can record (tests/_class_kinds.py lists
the kinds from the source), and the claim they are about.  Members, providers and claims are invented; each case has its own
member, provider and claim, so no case can hold or free another through the engine's history.

A case is a ``Parts``: the 834 member loops, the 837 claim, the exclusion list rows and the provider death rows.  Without a fault it
is paid (ALLOW).  A ``Variant`` turns one kind of fault on, at the subject it is about: a member, a claim, a line or a provider.
"""

from __future__ import annotations

import io
import re
from typing import Callable, NamedTuple

from tests import test_reader_leie as tl
from tests import test_x12_834 as t834
from tests import test_x12_837 as t837
from tests.test_x12 import file_of

DAY = 20270305  # the claims' service day, inside the members' span
SPAN = {"begin": "20270101", "end": "20271231"}
GS = "20270314"  # the 834's file date
AS_OF = "2027-03-10"  # the exclusion file's as-of date
DEATHS_ASOF = "2027-03-01"


def claim_of(cid: str, lines: int = 1, *, total: str | None = None, freq: str = "1", ref: str = "", charge: str = "10.00", day: int = DAY) -> list[str]:
    segs = [f"CLM*{cid}*{total or f'{lines * 10}.00'}***11:B:{freq}*Y*A*Y*Y"] + ([f"REF*F8*{ref}"] if ref else []) + ["HI*ABK:E119"]
    for n in range(1, lines + 1):
        segs += [f"LX*{n}", f"SV1*HC:9921{n}*{charge}*UN*1***1", f"DTP*472*D8*{day}"]
    return segs


class Parts:
    """One case.  ``f834`` and ``f837`` build the files (bytes or a file object); a variant may replace them."""

    def __init__(self, n: int) -> None:
        self.n, self.member, self.cid, self.npi = n, f"M{n:07d}", f"C{n:06d}", tl.make_npi(300000 + n)
        self.bill = self.npi  # the billing NPI as the claim names it
        self.hdr834 = t834.header()
        self.loops = [t834.member(self.member, **SPAN)]
        self.claim = claim_of(self.cid)
        self.sub837, self.hl_bad, self.dependent = self.member, False, False  # faults in the 837's head
        self.leie, self.leie_kind, self.leie_raw = [], "full", None
        self.deaths = (DEATHS_ASOF, [(tl.make_npi(2), "2027-02-01")])  # a feed with no row is unknown, never "nobody died"
        self.filler = t834.member(f"D{n:07d}", death="20270302", **SPAN)  # a member who died, for the same reason
        self.copies = 1  # how many times the 837 is read (a file sent twice)
        self.f834 = self.f837 = None
        self.more834: list[Callable[[], bytes]] = []  # more 834 files, each read on its own
        self.extra_claims: list[list[str]] = []
        self.earlier: list[Parts] = []  # cases whose 837 was read before this one's (the same claim sent before)

    def body834(self) -> list[str]:
        return self.hdr834 + [s for loop in self.loops + [self.filler] for s in loop]

    def body837(self) -> list[str]:
        head = t837.head(self.bill, self.sub837)
        if self.hl_bad:
            head = [s.replace("HL*2*1*22*0", "HL*2*1*99*0") for s in head]
        if self.dependent:
            head = head + ["HL*3*2*23*0", "NM1*QC*1*DOE*KID"]
        return head + self.claim + [s for c in self.extra_claims for s in c]

    def file834(self):
        return self.f834() if self.f834 else file_of([self.body834()], kind="834", gs_date=GS)

    def file837(self):
        return self.f837() if self.f837 else file_of([self.body837()], kind="837", gs_date=GS)

    def leie_bytes(self) -> bytes:
        if self.leie_raw is not None:
            return self.leie_raw
        return (tl.HEAD + tl.row(npi=tl.make_npi(1)) + "".join(self.leie)).encode()


class Variant(NamedTuple):
    module: str  # the module that records the kind (right_rail_...)
    kind: str
    subject: str  # member, claim, line or provider
    make: Callable[[int], Parts]
    where: str = "in_subject"  # "file_wide": the fault is elsewhere in the subject's file
    mode: str = "never_allow"  # "allow_once": a retry; "trigger_only": the fault has no identifier to attach to a subject
    triggers: bool = True  # False: another variant of the kind is the one that makes the reader record it
    clean: Callable[[int], Parts] | None = None  # the same case with its fault removed (every variant must ALLOW so); None: a case with no fault


# ---- the X12 envelope -------------------------------------------------------------------------------------------------------

class Changing(io.BytesIO):
    """A file whose bytes are not the ones first hashed once it has been rewound: it changed while it was read."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.rewinds = 0

    def seek(self, *a):
        self.rewinds += a == (0,)
        return super().seek(*a)

    def read(self, n=-1):
        data = super().read(n)
        return data.replace(b"SYNTHETIC", b"SYNTHETIX") if self.rewinds > 1 else data


def _cut(data: bytes, sid: bytes) -> bytes:
    return re.sub(rb"(?<=~)" + sid + rb"\*[^~]*~", b"", data, count=1)


def _put(body: list[str], anchor: str, seg: str) -> list[str]:
    i = next(i for i, s in enumerate(body) if s.startswith(anchor))
    return body[:i + 1] + [seg] + body[i + 1:]


def _renumber(data: bytes, kind: str, to: str) -> bytes:
    return re.sub(rb"(ST\*)" + kind.encode() + rb"\*0002", rb"\g<1>" + to.encode() + rb"*0002", data)


def _same_control(data: bytes, kind: str) -> bytes:
    data = data.replace(f"ST*{kind}*0002~".encode(), f"ST*{kind}*0001~".encode())
    return re.sub(rb"SE\*(\d+)\*0002~", rb"SE*\1*0001~", data)


ENVELOPE = {  # kind -> how to build the file from the subject's body ``b``, another subject's ``o``, the kind of file ``k`` and the anchor ``a``
    "bad_file_datetime": lambda b, o, k, a: file_of([b], kind=k, gs_date="20271340"),
    "bad_segment_id": lambda b, o, k, a: file_of([_put(b, a, "a*b")], kind=k, gs_date=GS),
    "repeated_element": lambda b, o, k, a: file_of([_put(b, a, "ZZ*A^B")], kind=k, gs_date=GS),
    "segment_too_long": lambda b, o, k, a: file_of([_put(b, a, "ZZ*" + "A" * (3 << 20))], kind=k, gs_date=GS),
    "unterminated_segment": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS)[:-1],
    "isa_unframed": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS) + b"GARBAGE AFTER THE LAST INTERCHANGE",
    "no_interchange": lambda b, o, k, a: b"   \n",
    "file_changed": lambda b, o, k, a: (lambda: Changing(file_of([b], kind=k, gs_date=GS))),
    "bad_st": lambda b, o, k, a: file_of([b], kind="83", gs_date=GS),
    "duplicate_control": lambda b, o, k, a: _same_control(file_of([o, b], kind=k, gs_date=GS), k),
    "not_834": lambda b, o, k, a: _renumber(file_of([o, b], kind=k, gs_date=GS), k, "999"),
    "not_837": lambda b, o, k, a: _renumber(file_of([o, b], kind=k, gs_date=GS), k, "999"),
    "ge_control_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, ge_control="9"),
    "ge_count_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, ge_count=9),
    "iea_control_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, iea_control="9"),
    "iea_count_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, iea_count=9),
    "se_control_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, se_control="9999"),
    "se_count_mismatch": lambda b, o, k, a: file_of([b], kind=k, gs_date=GS, se_count=99),
    "group_unclosed": lambda b, o, k, a: _cut(file_of([b], kind=k, gs_date=GS), b"GE"),
    "iea_missing": lambda b, o, k, a: (lambda f: f[:f.rindex(b"SE*")])(file_of([b], kind=k, gs_date=GS)),  # the file ends in the subject's set; the sets before a cut are whole
    "set_unclosed": lambda b, o, k, a: _cut(file_of([b], kind=k, gs_date=GS), b"SE"),
}
for _kind in ("st_outside_group", "segment_outside_set", "se_without_st", "ge_without_gs"):  # one file with no GS makes all four
    ENVELOPE[_kind] = lambda b, o, k, a: _cut(file_of([b], kind=k, gs_date=GS), b"GS")
ONLY = {"not_834": "834", "not_837": "837"}
FILE_WIDE = {"isa_unframed"}  # trailing bytes after the last good interchange: no unit of the subject holds the fault


def envelope(kind: str, file: str, clean: bool = False) -> Callable[[int], Parts]:
    def make(n: int) -> Parts:
        p, other = Parts(n), Parts(n + 7000)
        anchor, mine, theirs = ("REF*0F", p.body834(), other.body834()) if file == "834" else ("CLM", p.body837(), other.body837())
        built = file_of([theirs, mine] if kind in ("duplicate_control", "not_834", "not_837") else [mine], kind=file, gs_date=GS) if clean else             ENVELOPE[kind](mine, theirs, file, anchor)
        build = built if callable(built) else (lambda: built)
        if file == "834":
            p.f834 = build
        else:
            p.f837 = build
        return p
    return make


# ---- the 834 reader and the member feeds ------------------------------------------------------------------------------------------

def _without(*heads: str) -> Callable[[list[str]], list[str]]:
    return lambda loop: [s for s in loop if not s.startswith(heads)]


# kind -> (loop keywords, edit of the loop, extra segments at its end, fixed INS03 or None)
MEMBER_FAULTS: dict[str, tuple] = {
    "bad_date": ({"end": "20271340"}, None, (), None),
    "bad_death_date": ({"death": "20271301"}, None, (), None),
    "bad_ins": ({}, lambda l: ["INS*Z" + l[0][5:]] + l[1:], (), None),
    "empty_member_id": ({}, lambda l: [s if not s.startswith("REF*0F") else "REF*0F*" for s in l], (), None),
    "no_member_id": ({}, _without("REF*0F"), (), None),
    "member_id_conflict": ({}, lambda l: [s.replace("*34*", "*MI*") if s.startswith("NM1") else s for s in l], (), None),
    "repeated_loop": ({}, None, ("NM1*IL*1*DOE*JOHN",), None),
    "repeated_segment": ({}, None, ("DTP*349*D8*20271231",), None),
    "unknown_segment": ({}, None, ("QQ*1",), None),
    "unread_segment": ({}, None, ("DTP*357*D8*20271231",), None),
    "dependent_member": ({}, lambda l: ["INS*N" + l[0][5:]] + l[1:], (), None),
    "deleted": ({}, None, (), "002"),
    "termination": ({}, _without("DTP*348", "DTP*349", "DTP*356"), (), "024"),
    "no_plan": ({"plan": ""}, None, (), None),
    "no_dates": ({}, _without("DTP*348", "DTP*356"), (), None),
    "bad_dates": ({"begin": "20271231", "end": "20270101"}, None, (), None),
}
FFS_ALIAS = {"member_quarantined": "bad_date"}  # the claim path's name for a fault inside a member loop


def member_case(fault: str, placement: str, clean: bool = False) -> Callable[[int], Parts]:
    """``own``: the fault is in the member's only loop.  ``hidden``: the member has a good loop and the fault is in a later loop
    for the same member, which is a cancellation (what a lost cancellation would be).  ``clean``: the same loops with the fault left
    out (the hidden loop still a cancellation, but ending after the claim's day)."""
    kw, edit, extra, fixed = ({}, None, (), None) if clean else MEMBER_FAULTS[FFS_ALIAS.get(fault, fault)]

    def make(n: int) -> Parts:
        p = Parts(n)
        good = t834.member(p.member, **SPAN)
        ins03 = fixed or ("024" if placement == "hidden" else "021")
        before = {"end": "20270228"} if placement == "hidden" and not clean else {}  # a cancellation that ends before the claim's day
        bad = t834.member(p.member, ins03=ins03, **{**SPAN, **before, **kw})
        bad = (edit(bad) if edit else bad) + list(extra)
        p.loops = [good, bad] if placement == "hidden" else [bad]
        return p
    return make


def mixed_times(n: int, clean: bool = False) -> Parts:
    """The member's file is made at 0930 and the filler's file at 1830: a roster of mixed file times (``clean``: both at 0930)."""
    p = Parts(n)
    p.f834 = lambda: file_of([p.hdr834 + p.loops[0]], kind="834", gs_date=GS)
    p.more834 = [lambda: file_of([p.hdr834 + p.filler], kind="834", gs_date=GS, gs_time="0930" if clean else "1830", control="000000002")]
    return p


def tied_files(n: int, clean: bool = False) -> Parts:
    """A second file made at the same time names the member with another plan (``clean``: the same rows)."""
    p = Parts(n)
    p.more834 = [lambda: file_of([p.hdr834 + t834.member(p.member, **SPAN, plan="PLAN-A" if clean else "PLAN-B")], kind="834", gs_date=GS,
                                 control="000000002")]
    return p


def empty_newest(n: int, clean: bool = False) -> Parts:
    """A later full roster with no member loop (``clean``: a later change file with none, which changes nothing)."""
    p = Parts(n)
    p.more834 = [lambda: file_of([[p.hdr834[0] + ("****2" if clean else ""), *p.hdr834[1:]]], kind="834", gs_date=GS, gs_time="1830",
                                 control="000000002")]
    return p


def stale_base(n: int, clean: bool = False) -> Parts:
    """The full roster is 48 days older than a later change file with no member loop (``clean``: 41 days older)."""
    p = Parts(n)
    p.f834 = lambda: file_of([p.body834()], kind="834", gs_date="20270201" if clean else "20270125")
    p.more834 = [lambda: file_of([[p.hdr834[0] + "****2", *p.hdr834[1:]]], kind="834", gs_date=GS, control="000000002")]
    return p


def two_adds(n: int) -> Parts:
    p = Parts(n)
    p.loops = [t834.member(p.member, **SPAN), t834.member(p.member, **SPAN)]
    return p


# ---- the 837 reader and the claim set-asides --------------------------------------------------------------------------------------

LINE_FAULTS = ("bad_line_charge", "bad_units", "partial_line", "bad_service_date", "bad_date_line", "no_sv_segment", "repeated_segment_line", "unknown_segment_line")


def claim_case(fault: str, clean: bool = False) -> Callable[[int], Parts]:
    def make(n: int) -> Parts:
        p = Parts(n)
        if clean:  # the scaffolding the fault is made in, with no fault
            if fault in LINE_FAULTS:
                p.claim = claim_of(p.cid, 2)
            elif fault == "no_revenue_code":
                p.claim = [f"CLM*{p.cid}*10.00***13:A:1*Y*A*Y*Y", "HI*ABK:E119", "LX*1", "SV2*0450*HC:99285*10.00*UN*1", f"DTP*472*D8*{DAY}"]
            return p
        two = claim_of(p.cid, 2)  # a line fault is in the second line of two
        line2 = lambda **kw: claim_of(p.cid, 2, **kw)  # noqa: E731
        if fault == "no_claim_id":
            p.claim[0] = "CLM**10.00***11:B:1*Y*A*Y*Y"
        elif fault == "bad_total_charge":
            p.claim[0] = p.claim[0].replace("10.00", "ten", 1)
        elif fault == "no_frequency_code":
            p.claim[0] = p.claim[0].replace("11:B:1", "11:B")
        elif fault == "no_rendering_npi":
            p.claim = _put(p.claim, "CLM", "NM1*82*1*ROE*RAY")
        elif fault == "missing_original_ref":
            p.claim = claim_of(p.cid, freq="7")
        elif fault == "no_billing_npi":
            p.bill = ""
        elif fault == "no_subscriber":
            p.sub837 = ""
        elif fault == "no_service_lines":
            p.claim = claim_of(p.cid, 0, total="10.00")
        elif fault == "bad_hl":
            p.hl_bad = True
        elif fault == "total_mismatch":
            p.claim[0] = p.claim[0].replace("10.00", "99.00", 1)
        elif fault == "header_without_hl":
            p.claim = _put(p.claim, "LX", "SBR*P*18")
        elif fault in ("unknown_segment", "total_unchecked"):
            p.claim = _put(p.claim, "CLM", "QQ*1")
        elif fault == "repeated_segment_claim":
            p.claim = _put(_put(p.claim, "CLM", "REF*F8*A"), "REF*F8", "REF*F8*B")
        elif fault in ("bad_line_charge", "partial_line", "bad_units"):
            p.claim = two
            repl = {"bad_line_charge": ("*10.00*UN", "*abc*UN"), "bad_units": ("UN*1", "UN*x"), "partial_line": ("UN*1", "UN*x")}[fault]
            i = max(i for i, s in enumerate(p.claim) if s.startswith("SV1"))
            p.claim[i] = p.claim[i].replace(*repl)
        elif fault in ("bad_service_date", "bad_date_line"):
            p.claim = two
            p.claim[-1] = "DTP*472*D8*20271340"
        elif fault == "no_sv_segment":
            p.claim = two[:-3] + ["LX*2"]
        elif fault == "repeated_segment_line":
            p.claim = two[:-1] + [two[-2], two[-1]]
        elif fault == "unknown_segment_line":
            p.claim = _put(two, "LX*2", "QQ*1")
        elif fault == "no_revenue_code":
            p.claim = [f"CLM*{p.cid}*10.00***13:A:1*Y*A*Y*Y", "HI*ABK:E119", "LX*1", "SV2**HC:99285*10.00*UN*1", f"DTP*472*D8*{DAY}"]
        elif fault == "payment_id_conflict":
            p.extra_claims = [claim_of(p.cid, charge="20.00")]
        elif fault == "retry":
            p.copies = 2
        elif fault == "replacement_or_void":
            p.claim = claim_of(p.cid, freq="8", ref="C0")
        elif fault == "replaced_or_voided":  # the claim as first sent, and a void of it in the same file
            p.extra_claims = [claim_of(p.cid + "V", freq="8", ref=p.cid)]
        elif fault == "dependent_patient":
            p.dependent = True
        elif fault == "bad_npi":
            p.bill = p.npi[:9] + str((int(p.npi[9]) + 3) % 10)
        elif fault == "service_date":
            p.claim[-1] = f"DTP*472*RD8*{DAY}-{DAY + 1}"
        elif fault == "units":
            p.claim[3] = p.claim[3].replace("UN*1", "UN*0")
        elif fault == "field":
            p.claim[3] = p.claim[3].replace("HC:99211", "HC:99 211")
        else:
            raise KeyError(fault)
        return p
    return make


# ---- the exclusion list and the provider death rows ----------------------------------------------------------------------------------

def listed(n: int) -> Parts:
    """The provider is on the list but was reinstated before the claim's day: a list as a fault-free twin must have, with its scaffolding."""
    p = Parts(n)
    p.leie = [tl.row(npi=p.npi, rein="20270101")]
    return p


def lookalike(n: int) -> Parts:
    """Another provider's row, named as the claim's provider is: held only when its NPI cannot be read."""
    p = Parts(n)
    p.leie = [tl.row(last="", bus="SYNTHETIC CLINIC", npi=tl.make_npi(500000 + n))]
    return p


def leie_case(fault: str, lifted: bool = False) -> Callable[[int], Parts]:
    """``lifted``: the provider's row is reinstated before the claim's day, so it holds nothing whatever else is wrong with it."""
    def make(n: int) -> Parts:
        p = Parts(n)
        row = lambda **kw: tl.row(npi=p.npi, **({"rein": "20270101"} if lifted else {}), **kw)  # noqa: E731
        if fault == "bad_date":
            p.leie = [row(excl="notadate")]
        elif fault == "bad_npi":
            p.leie = [tl.row(last="", bus="SYNTHETIC CLINIC", npi=p.npi[:9] + str((int(p.npi[9]) + 3) % 10))]  # the claim's own NPI is good: only the list holds it
        elif fault in ("bad_text", "no_name"):
            p.leie = [row(last="TES\x01TER") if fault == "bad_text" else row(last="")]
        elif fault == "empty_file":
            p.leie_raw = (tl.HEAD + "  \n").encode()
        elif fault == "unknown_exclusion_type":
            p.leie = [row(typ="ZZZ9")]
        elif fault == "no_exclusion_type":
            p.leie = [row(typ="")]
        elif fault == "column_count":
            p.leie = [row().rstrip("\n") + ",EXTRA\n"]
        elif fault == "unparseable":
            p.leie = [row(last='"TESTER"X')]
        elif fault == "not_utf8":
            p.leie_raw = (tl.HEAD + tl.row(npi=tl.make_npi(1))).encode() + row().encode().replace(b"TESTER", b"TES\xffER")
        elif fault == "unreadable_no_npi":  # bytes that do not decode and no NPI: nothing names its party, so every line is reviewed
            p.leie_raw = (tl.HEAD + tl.row(npi=tl.make_npi(1))).encode() + tl.row().encode().replace(b"TESTER", b"TES\xffER")
        elif fault in ("unterminated_record", "line_too_long"):
            p.leie_raw = (tl.HEAD + tl.row(npi=tl.make_npi(1))).encode() + (row(last="X" * 70000) if fault == "line_too_long" else row().rstrip("\n")).encode()
        elif fault == "duplicate_row":
            p.leie = [row(), row()]
        elif fault == "excluded_after_as_of":
            p.leie = [row(excl="20270401")]
        elif fault == "exclusion_date_missing":
            p.leie = [row(excl="00000000")]
        elif fault == "reinstated_after_as_of":  # served after the reinstatement, which the file (as of before it) cannot yet know to be real
            p.claim, p.leie = claim_of(p.cid, day=20270313), [row(rein="20270312")]
        elif fault in ("npi_11_digits", "npi_9_digits", "npi_float"):  # the provider's own row, its NPI spoiled, named as the claim names it
            spoiled = {"npi_11_digits": p.npi + "0", "npi_9_digits": p.npi[:9], "npi_float": p.npi + ".0"}[fault]
            p.leie = [tl.row(last="", bus="SYNTHETIC CLINIC", npi=spoiled)]
        elif fault == "waiver_after_as_of":
            p.leie = [row(waiver="20270601", wst="ZZ")]
        elif fault == "waiver_without_state":
            p.leie = [row(waiver="20260101")]
        elif fault == "reinstated_before_excluded":
            p.leie = [row(excl="20270301", rein="20270201")]
        elif fault == "npi_two_names":
            p.leie = [row(), row(last="OTHERNAME")]
        elif fault == "reinstated_in_exclusion_file":
            p.leie, p.leie_kind = [row(rein="20260101")], "exclusions"
        elif fault == "no_reinstatement_in_reinstatement_file":
            p.leie, p.leie_kind = [row()], "reinstatements"
        elif fault == "no_npi":
            p.leie = [tl.row(last="NONUMBER")]
        elif fault == "death_bad_npi":
            p.bill = p.npi[:9] + str((int(p.npi[9]) + 3) % 10)
            p.deaths = (DEATHS_ASOF, [(p.bill, "2027-02-01")])
        elif fault == "death_bad_as_of":
            p.deaths = ("2027-13-45", [(p.npi, "2027-02-01")])
        elif fault == "death_bad_dates":
            p.deaths = (DEATHS_ASOF, [(p.npi, "2027-13-40")])
        elif fault == "leie_bad_dates":
            p.leie = [row(excl="20270301", rein="20270201")]
        else:
            raise KeyError(fault)
        return p
    return make


CLAIM_FAULTS = (  # (module, kind, subject, fault)
    *(("right_rail_x12_837", k, "claim", k) for k in ("no_claim_id", "bad_total_charge", "no_frequency_code", "no_rendering_npi", "missing_original_ref",
                                                     "no_billing_npi", "no_subscriber", "no_service_lines", "bad_hl", "header_without_hl", "total_mismatch", "unknown_segment",
                                                     "total_unchecked")),
    ("right_rail_x12_837", "repeated_segment", "claim", "repeated_segment_claim"),
    *(("right_rail_x12_837", k, "line", k) for k in ("bad_line_charge", "bad_units", "bad_service_date", "no_sv_segment", "no_revenue_code")),
    ("right_rail_x12_837", "repeated_segment", "line", "repeated_segment_line"),
    ("right_rail_x12_837", "unknown_segment", "line", "unknown_segment_line"),
    ("right_rail_x12_837", "bad_date", "line", "bad_date_line"),
    *(("right_rail_gate_ffs", k, "claim", k) for k in ("payment_id_conflict", "total_mismatch", "replacement_or_void", "replaced_or_voided", "dependent_patient",
                                                     "bad_npi", "service_date", "units", "field")),
    ("right_rail_gate_ffs", "partial", "line", "partial_line"),
)
LEIE_FAULTS = ("empty_file", "bad_date", "bad_npi", "bad_text", "unknown_exclusion_type", "no_exclusion_type", "no_name", "column_count", "unparseable", "not_utf8",
               "duplicate_row", "excluded_after_as_of", "exclusion_date_missing", "reinstated_after_as_of", "waiver_after_as_of", "waiver_without_state",
               "reinstated_before_excluded", "npi_two_names", "reinstated_in_exclusion_file", "no_reinstatement_in_reinstatement_file")
READER_834 = frozenset(("bad_date", "bad_death_date", "bad_ins", "empty_member_id", "no_member_id", "member_id_conflict", "repeated_loop", "repeated_segment",
                        "unknown_segment", "unread_segment"))


def variants() -> list[Variant]:
    out: list[Variant] = []
    for kind in ENVELOPE:
        for file, subject in (("834", "member"), ("837", "claim")):
            if ONLY.get(kind, file) == file:
                out.append(Variant("right_rail_x12", kind, subject, envelope(kind, file), "file_wide" if kind in FILE_WIDE else "in_subject",
                                   clean=envelope(kind, file, True)))
    for kind in MEMBER_FAULTS:
        for placement in ("own",) if kind == "dependent_member" else ("own", "hidden"):  # a dependent's loop never cancels the subscriber
            out.append(Variant("right_rail_x12_834" if kind in READER_834 else "right_rail_gate_ffs", kind, "member", member_case(kind, placement),
                               triggers=placement == "own", clean=member_case(kind, placement, True)))
    out.append(Variant("right_rail_gate_ffs", "no_member_id", "member", member_case("no_member_id", "hidden"), clean=member_case("no_member_id", "hidden", True)))
    out.append(Variant("right_rail_gate_ffs", "member_quarantined", "member", member_case("member_quarantined", "hidden"), clean=member_case("member_quarantined", "hidden", True)))
    out.append(Variant("right_rail_gate_ffs", "conflicting_rows", "member", two_adds, clean=member_case("bad_date", "hidden", True)))
    out.append(Variant("right_rail_gate_ffs", "mixed_file_times", "member", mixed_times, clean=lambda n: mixed_times(n, True)))
    out.append(Variant("right_rail_gate_ffs", "tied_files_disagree", "member", tied_files, clean=lambda n: tied_files(n, True)))
    out.append(Variant("right_rail_gate_ffs", "empty_roster", "member", empty_newest, clean=lambda n: empty_newest(n, True)))
    out.append(Variant("right_rail_gate_ffs", "stale_roster", "member", stale_base, clean=lambda n: stale_base(n, True)))
    out += [Variant(m, k, subject, claim_case(f), clean=claim_case(f, True)) for m, k, subject, f in CLAIM_FAULTS]
    out.append(Variant("right_rail_gate_ffs", "quarantined", "claim", envelope("segment_too_long", "837"), clean=envelope("segment_too_long", "837", True)))
    out.append(Variant("right_rail_gate_ffs", "unreadable_row", "provider", leie_case("unreadable_no_npi"), clean=listed))
    out.append(Variant("right_rail_gate_ffs", "retry", "claim", claim_case("retry"), mode="allow_once", clean=claim_case("retry", True)))
    out += [Variant("right_rail_reader_leie", k, "provider", leie_case(k), clean=lookalike if k == "bad_npi" else listed) for k in LEIE_FAULTS]
    out += [Variant("right_rail_reader_lines", k, "provider", leie_case(k), clean=listed) for k in ("unterminated_record", "line_too_long")]
    out += [Variant("right_rail_gate_ffs", "exclusion_npi_unreadable", "provider", leie_case(f), clean=lookalike) for f in ("npi_11_digits", "npi_9_digits", "npi_float")]
    out += [Variant("right_rail_gate_ffs", k, "provider", leie_case(k), clean=listed) for k in ("excluded_after_as_of", "reinstated_after_as_of")]
    out.append(Variant("right_rail_gate_ffs", "no_npi", "provider", leie_case("no_npi"), mode="trigger_only"))  # no identifier
    out += [Variant("right_rail_gate_ffs", k, "provider", leie_case(f)) for k, f in
            (("bad_npi", "death_bad_npi"), ("bad_as_of", "death_bad_as_of"), ("bad_dates", "death_bad_dates"), ("bad_dates", "leie_bad_dates"))]
    return out


# ---- a file of many claims ----------------------------------------------------------------------------------------------------------

LAYOUT = (  # interchanges > groups > sets > claims, in the one 837
    ((("A1", "A2", "A3"), ("B1", "B2")), (("D1",),)),
    ((("C1",),),),
)


def _flat(x) -> list[str]:
    return [x] if isinstance(x, str) else [t for y in x for t in _flat(y)]


TAGS = _flat(LAYOUT)


def _within(tag: str, level: int) -> set[str]:
    """The claims in the same interchange (0), group (1) or set (2) as ``tag``."""
    for ic in LAYOUT:
        for g in ic:
            for s in g:
                if tag in s:
                    return set(_flat((ic, g, s)[level]))
    raise KeyError(tag)


def multi(n: int, edit: Callable | None = None, tweak: Callable[[bytes], bytes] | None = None) -> Parts:
    """The layout's claims, each of its own member and service day, in one 837 of two interchanges.  ``edit(tag, k, header, claim)``
    returns the segments of the claim that is ``k``-th in its set; ``tweak`` changes the file's bytes."""
    p = Parts(n)
    p.cids, p.members = {t: f"C{n:04d}{t}" for t in TAGS}, {t: f"M{n:04d}{t}" for t in TAGS}
    p.loops = [t834.member(m, **SPAN) for m in p.members.values()]

    def body(tags) -> list[str]:
        out: list[str] = []
        for k, t in enumerate(tags):
            head = t837.head(p.bill, p.members[t]) if k == 0 else [f"HL*{k + 2}*1*22*0", "SBR*P*18", f"NM1*IL*1*DOE*JANE****MI*{p.members[t]}"]
            head, seg = (edit or (lambda *a: a[2:]))(t, k, head, claim_of(p.cids[t], day=DAY + TAGS.index(t)))
            out += head + seg
        return out
    build = lambda: b"".join(file_of([], kind="837", gs_date=GS, control=f"{j:09d}", groups=[[body(s) for s in g] for g in ic])  # noqa: E731
                             for j, ic in enumerate(LAYOUT, 1))
    p.f837 = (lambda: tweak(build())) if tweak else build
    return p


class MultiFault(NamedTuple):
    name: str
    make: Callable[[int], Parts]
    hurt: frozenset  # claims that must never be ALLOW
    touched: frozenset  # claims the fault may hold; every other claim must be sent and ALLOW
    refused: bool = False  # the file cannot be read: one item for it


IN_CLAIM = {
    "garbled_segment": lambda h, s: (h, s[:1] + ["ZZ*A^B"] + s[1:]),
    "unknown_segment": lambda h, s: (h, s[:1] + ["QQ*1"] + s[1:]),
    "bad_service_date": lambda h, s: (h, s[:-1] + ["DTP*472*D8*20271340"]),
}
IN_HEADER = {  # before the claim's CLM: after the claim above it, and its HL, SBR and NM1 loops
    "garbled_header_segment": lambda h, s: (["ZZ*A^B"] + h, s),
    "garbled_patient_name": lambda h, s: (h + ["NM1*QC*1*DOE*KID^X"], s),
    "garbled_member_level": lambda h, s: ([x + "^X" if i == max(j for j, y in enumerate(h) if y.startswith("HL*")) else x for i, x in enumerate(h)], s),
    "unknown_header_segment": lambda h, s: (["QQ*1"] + h, s),
}
HIERARCHY = {  # the member's HL lost or changed, in a claim that is not first in its set: its NM1*IL must never be read under the claim above
    "unknown_segment_for_hl": lambda h, s: ([("XL" + x[2:]) if x.startswith("HL*") else x for x in h], s),
    "hl_removed": lambda h, s: ([x for x in h if not x.startswith("HL*")], s),  # the set's count is made again, so the set is whole
    "hl_number_gap": lambda h, s: ([re.sub(r"^HL\*(\d+)", lambda m: f"HL*{int(m[1]) + 1}", x) for x in h], s),
}
LEGAL = {  # not faults: an other-payer loop and its name loops are the claim's (2320 and 2330), whatever NM1 codes they carry
    "other_payer_loops": lambda h, s: (h, s[:2] + ["SBR*S*01", "NM1*IL*1*ROE*JOHN****MI*Z0001", "NM1*PR*2*OTHER INSURER*****PI*99999", "NM1*82*1*ROE*RAY****XX*1234567890",
                                                  "NM1*85*2*OTHER CLINIC*****XX*1234567890", "NM1*DN*1*DOC*DAN", "NM1*77*2*SOME PLACE"] + s[2:]),
}
UNIT = {  # kind of unit -> (change of the file's bytes, a claim in the unit, level of the unit)
    "set_count": (lambda d: re.sub(rb"SE\*\d+\*0002~", b"SE*99*0002~", d), "B1", 2),
    "group_count": (lambda d: re.sub(rb"GE\*1\*2~", b"GE*9*2~", d), "D1", 1),
    "interchange_count": (lambda d: re.sub(rb"IEA\*1\*000000002~", b"IEA*9*000000002~", d), "C1", 0),
}


def multi_faults() -> list[MultiFault]:
    out = []
    for tag in ("A1", "A2", "A3", "B1", "C1"):
        for name, inject in IN_CLAIM.items():
            out.append(MultiFault(f"{name} in {tag}", lambda n, t=tag, f=inject: multi(n, lambda u, k, h, s: f(h, s) if u == t else (h, s)),
                                  frozenset({tag}), frozenset({tag})))
    for tags, injects in ((("A1", "A2", "B1"), IN_HEADER), (("A2", "A3", "B2"), HIERARCHY)):
        for tag in tags:
            above = {s[s.index(tag) - 1] for g in LAYOUT for ic in g for s in ic if tag in s and s.index(tag)}
            for name, inject in injects.items():
                out.append(MultiFault(f"{name} before {tag}", lambda n, t=tag, f=inject: multi(n, lambda u, k, h, s: f(h, s) if u == t else (h, s)),
                                      frozenset({tag} | above), frozenset(_within(tag, 2))))
    for name, inject in LEGAL.items():
        out.append(MultiFault(f"{name} in A2", lambda n, f=inject: multi(n, lambda u, k, h, s: f(h, s) if u == "A2" else (h, s)), frozenset(), frozenset()))
    code = lambda h, s: ([x.replace("*22*", "*99*") if i == max(j for j, y in enumerate(h) if y.startswith("HL*")) else x for i, x in enumerate(h)], s)
    out.append(MultiFault("one garbled HL code before A2", lambda n: multi(n, lambda u, k, h, s: code(h, s) if u == "A2" else (h, s)), frozenset({"A2"}), frozenset({"A1", "A2"})))
    out.append(MultiFault("a patient name inside A2", lambda n: multi(n, lambda u, k, h, s: (h, s[:1] + ["NM1*QC*1*DOE*KID"] + s[1:]) if u == "A2" else (h, s)),
                          frozenset({"A2"}), frozenset({"A2", "A3"})))
    lost = lambda u, k, h, s: (h, s[:2]) if u == "A2" else (["H?" + h[0][2:]] + h[1:], s) if u == "A3" else (h, s)  # A2 has no line and A3's HL is dropped: A3's header looks like A2's other payer
    out.append(MultiFault("a claim with no line, then the next claim's HL dropped", lambda n: multi(n, lost), frozenset({"A2", "A3"}), frozenset({"A2", "A3"})))
    for name, (tweak, tag, level) in UNIT.items():
        out.append(MultiFault(name, lambda n, w=tweak: multi(n, tweak=w), frozenset(_within(tag, level)), frozenset(_within(tag, level))))
    everything = frozenset(TAGS)
    out.append(MultiFault("bytes after the last interchange", lambda n: multi(n, tweak=lambda d: d + b"GARBAGE AFTER THE LAST INTERCHANGE"), everything, everything))
    out.append(MultiFault("no interchange", lambda n: multi(n, tweak=lambda d: b"   \n"), everything, everything, refused=True))
    return out
