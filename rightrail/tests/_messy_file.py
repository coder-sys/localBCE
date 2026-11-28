"""A deliberately messy, realistic state file for the replay path, generated from a fixed seed, with a side manifest that names every
injected defect and what ought to happen to the claims it touches.  Synthetic, non-PHI.

``build()`` returns the files a state hands over (837 claims, 835 remittances, 834 roster, exclusion list, provider deaths) and the
manifest.  The world is billing-provider blocks, each holding subscriber groups, each holding claims.  Every claim has a ``role``:
``allow`` (a clean claim, or one whose defect the reader repairs or ignores: it must be paid), ``hold`` (a defect: it must not be
paid) or ``genuine`` (a true hold the rules ought to make, with its ``reason``, such as an excluded provider).  A claim is keyed by
(billing NPI, claim id).  Only the claims named by a defect may be held; every other held claim is a collateral hold.
"""

import datetime
import random
import re

from tests import test_reader_leie as tl
from tests import test_x12_834 as t834
from tests.test_x12 import file_of
from tests.test_x12_835 import head as head835

SEED = 20261121
AS_OF = "20270315"  # the newest remittance day, so the day decided
ROSTER_DAY = "20270314"
N_PROVIDERS, N_MEMBERS, N_CLEAN = 36, 1500, 2300
PROCS = ("99213", "99214", "99212", "99203", "97110", "97530", "90837", "92004", "36415", "81002", "71046", "93000", "G0463", "T1019", "H0015",
         "A0428", "J3490", "85025", "80053", "99395")
LAST = ("SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "DAVIS", "MILLER", "WILSON", "MOORE", "TAYLOR", "ANDERSON", "THOMAS", "JACKSON", "WHITE",
        "HARRIS", "MARTIN", "THOMPSON", "ROBINSON", "CLARK", "LEWIS", "LEE", "WALKER", "HALL", "ALLEN", "YOUNG", "KING", "WRIGHT", "SCOTT", "GREEN", "BAKER")
FIRST = ("JAMES", "MARY", "ROBERT", "PATRICIA", "JOHN", "JENNIFER", "MICHAEL", "LINDA", "DAVID", "ELIZABETH", "WILLIAM", "BARBARA", "RICHARD", "SUSAN",
         "JOSEPH", "JESSICA", "THOMAS", "SARAH", "CHARLES", "KAREN")
EXCLUDED, DEAD, SECTION, GLUED, NO_NPI, TRUNCATED = 1, 2, 32, 33, 34, 31  # provider numbers with a part to play; the last five hold only clean claims
SMALL = (SECTION, GLUED, NO_NPI, TRUNCATED)
# Defect kind -> how many.  Rates are those of a state export: duplicates and corrections about a percent, field faults a few in a thousand.
CLAIM_KINDS = {  # kind: (count, role of the claim it touches)
    "date_feb30": (5, "hold"), "date_month13": (3, "hold"), "date_text": (3, "hold"), "date_zero": (2, "hold"), "date_future": (4, "hold"),
    "date_before_1990": (2, "hold"), "date_range": (4, "hold"), "date_missing": (3, "hold"),
    "sv1_short": (4, "hold"), "clm_short": (3, "hold"), "charge_text": (3, "hold"), "charge_negative": (4, "hold"), "charge_absurd": (3, "hold"),
    "charge_zero": (3, "hold"), "units_zero": (3, "hold"), "units_fraction": (3, "hold"), "units_absurd": (2, "hold"), "total_mismatch": (5, "hold"),
    "member_id_missing": (4, "hold"), "rendering_npi_missing": (3, "hold"), "npi_bad_check_digit": (4, "hold"), "npi_nine_digits": (2, "hold"),
    "claim_id_missing": (2, "hold"), "unknown_segment_in_claim": (3, "hold"), "unknown_segment_after_claim": (2, "hold"),
    "delimiter_inside_name": (2, "hold"), "stray_byte_in_member_id": (2, "hold"), "hl_gap": (2, "hold"), "second_sv1": (2, "hold"),
    "second_dtp": (2, "hold"), "claim_without_lines": (2, "hold"), "dependent_patient": (6, "hold"),
    "unknown_procedure_code": (6, "allow"), "unknown_facility_code": (3, "allow"), "lowercase_qualifier": (3, "allow"), "padded_fields": (4, "allow"),
    "stray_byte_in_name": (4, "allow"), "utf8_accent_in_name": (4, "allow"), "repeated_line_control": (3, "allow"),
    "member_not_in_roster": (10, "genuine"), "member_enrolled_after_service": (8, "genuine"), "member_deceased": (14, "genuine"),
    "roster_exact_duplicate": (12, "allow"), "roster_conflicting_span": (5, "hold"), "roster_member_id_missing": (3, "hold"),
    "roster_bad_date": (4, "hold"), "roster_unknown_segment": (3, "hold"), "roster_stray_byte_in_name": (3, "allow"),
}
PAIR_KINDS = {"exact_duplicate": 26, "near_duplicate_changed_field": 10, "same_service_new_claim_id": 8, "replacement_after_original": 14,
              "replacement_before_original": 6, "void_after_original": 8, "void_before_original": 4, "claim_id_reused_by_other_provider": 6}
# Replacements and voids that do not read whole or name their original another way, drawn from a second generator so the rest of the file is unchanged.
NAMING_KINDS = {"void_without_lines": 2, "void_without_ref": 2, "void_ref_in_lower_case": 1, "replacement_correcting_billing_npi": 1,
                "void_by_payer_number_for_corrected_member": 1}
# Roster loops with no member id whose name is not the roster's as written: each one's member is still held, drawn from the second generator too.
NAMELESS_KINDS = ("roster_member_id_missing_name_changed", "roster_member_id_missing_names_swapped", "roster_member_id_missing_name_spaced")
GENUINE_REASON = {"member_not_in_roster": "MEMBER_NOT_ENROLLED", "member_enrolled_after_service": "MEMBER_NOT_ENROLLED", "member_deceased": "MEMBER_DECEASED"}
# Defects in the 835 the incumbent sent (counted by what its reader sets aside) and in the exclusion list (rows its reader sets aside).
REMITTANCE_KINDS = {"remittance_claim_sent_twice": 4, "remittance_amount_unreadable": 3, "remittance_claim_never_paid": 6}
LEIE_KINDS = {"leie_row_missing_column": 1, "leie_row_impossible_date": 1, "leie_row_no_name": 1, "leie_row_repeated": 1, "leie_row_not_utf8": 1}


def cents(n):
    return ("-" if n < 0 else "") + f"{abs(n) // 100}.{abs(n) % 100:02d}"


class Claim:
    def __init__(self, cid, npi, member, form, lines):
        self.id, self.npi, self.member, self.form, self.lines = cid, npi, member, form, lines  # lines: [(procedure, charge cents, units, day)]
        self.freq, self.ref, self.total, self.rend, self.edits = "1", "", None, None, []
        self.role, self.reason, self.defect, self.copy = "allow", "", "", False

    key = property(lambda self: f"{self.npi}/{self.id}")

    def segs(self):
        total = sum(c for _, c, _, _ in self.lines) if self.total is None else self.total
        out = [f"CLM*{self.id}*{cents(total)}***{'11:B' if self.form == 'P' else '13:A'}:{self.freq}*Y*A*Y*Y"]
        out += [f"REF*F8*{self.ref}"] if self.ref else []
        out.append("HI*ABK:E119")
        if self.rend:
            out.append(f"NM1*82*1*{self.rend[1]}*{self.rend[2]}****XX*{self.rend[0]}")
        for n, (proc, charge, units, day) in enumerate(self.lines, 1):
            out += [f"LX*{n}", f"SV1*HC:{proc}*{cents(charge)}*UN*{units}***1" if self.form == "P" else f"SV2*0450*HC:{proc}*{cents(charge)}*UN*{units}",
                    f"DTP*472*D8*{day}", f"REF*6R*{self.id}L{n}"]
        for edit in self.edits:
            out = edit(out)
        return out


class Group:
    def __init__(self, member):
        self.member, self.claims, self.edits, self.dependent, self.hl_skip = member, [], [], False, 0  # member: (id, last, first)

    def segs(self, number):
        mid, last, first = self.member
        head = [f"HL*{number + self.hl_skip}*1*22*0", "SBR*P*18", f"NM1*IL*1*{last}*{first}****MI*{mid}"]
        if self.dependent:
            head += [f"HL*{number + 1}*{number}*23*0", "NM1*QC*1*DOE*KID"]
        for edit in self.edits:
            head = edit(head)
        return head + [s for c in self.claims for s in c.segs()]


class Block:
    def __init__(self, npi, name, form):
        self.npi, self.name, self.form, self.groups, self.edits = npi, name, form, [], []
        self.first = {}  # a member's first group here, found without a scan

    def body(self):
        out = ["BHT*0019*00*1*20270314*0930*CH", "HL*1**20*1", f"NM1*85*2*{self.name}*****XX*{self.npi}"]
        for edit in self.edits:
            out = edit(out)
        number = 2
        for g in self.groups:
            out += g.segs(number)
            number += 2 if g.dependent else 1
        return out

    @property
    def claims(self):
        return [c for g in self.groups for c in g.claims]


def first(prefix, fn):
    """An edit: ``fn`` applied to the first segment that starts with ``prefix``."""
    def edit(segs):
        out, done = [], False
        for s in segs:
            out.append(fn(s) if not done and s.startswith(prefix) else s)
            done = done or s.startswith(prefix)
        return out
    return edit


def after(prefix, text):
    return lambda segs: [t for s in segs for t in ((s, text) if s.startswith(prefix) else (s,))]


def without(prefixes):
    return lambda segs: [s for s in segs if not s.startswith(prefixes)]


def bad_npi(npi, nine=False):
    """An NPI with a wrong check digit, or the first nine digits only."""
    return npi[:9] if nine else npi[:9] + str((int(npi[9]) + 1) % 10)


class World:
    def __init__(self, seed, skip=(), claims=N_CLEAN):
        self.skip = skip  # defect kinds left out of this build
        self.n_clean, self.n_members = claims, max(N_MEMBERS, claims * N_MEMBERS // N_CLEAN)  # members grow with the file, so claims per member stay as they are
        self.rng = rng = random.Random(seed)
        self.more = random.Random(seed + 1)  # the cases added later: the first generator's draws, so the file around them, stay as they were
        self.serial = 0
        self.claims, self.manifest, self.pool = [], [], []
        self.providers = [(tl.make_npi(500000 + i), f"{LAST[i % 30]} MEDICAL GROUP {i}", "I" if i % 6 == 5 else "P") for i in range(N_PROVIDERS)]
        self.blocks = {p[0]: Block(*p) for p in self.providers}
        self.rendering = [(tl.make_npi(700000 + i), LAST[(i * 7) % 30], FIRST[(i * 3) % 20]) for i in range(60)]
        self.rendering[0] = (self.rendering[0][0], "GARCIA", "MARIA")  # the name a garbled exclusion row will share
        self.members = [(f"M{n:07d}", LAST[(n * 11) % 30], FIRST[(n * 7) % 20]) for n in range(1, self.n_members + 1)]
        self.span = {m[0]: ("20270220" if n % 20 == 0 else "20270101", "20271231") for n, m in enumerate(self.members, 1)}
        self.death, self.absent, self.roster_edit = {}, set(), {}
        self.taken, self.per_member = set(), {}

    # ---- the clean world
    def day(self, begin):
        start = max(datetime.date(2027, 1, 4), datetime.date(int(begin[:4]), int(begin[4:6]), int(begin[6:])))
        return (start + datetime.timedelta(days=self.rng.randrange((datetime.date(2027, 3, 12) - start).days + 1))).strftime("%Y%m%d")

    def line(self, member, npi, begin="20270104"):
        while True:
            proc, day = self.rng.choice(PROCS), self.day(begin)
            if (member, npi, proc, day) not in self.taken:
                self.taken.add((member, npi, proc, day))
                return proc, self.rng.randrange(1500, 40000), self.rng.choice((1, 1, 1, 2)), day

    def claim(self, block, member, lines, new_group=False):
        self.serial += 1
        c = Claim(f"C{self.serial:07d}", block.npi, member[0], block.form, lines)
        group = block.first.get(member[0]) if not new_group else None
        if group is None:
            group = Group(member)
            block.groups.append(group)
            block.first.setdefault(member[0], group)
        group.claims.append(c)
        self.claims.append(c)
        self.per_member[member[0]] = self.per_member.get(member[0], 0) + 1
        return c, group

    def clean(self):
        rng = self.rng
        weights = [10 if i in SMALL else 8 if i in (EXCLUDED, DEAD) else 60 for i in range(N_PROVIDERS)]
        for _ in range(self.n_clean):
            i = rng.choices(range(N_PROVIDERS), weights)[0]
            npi = self.providers[i][0]
            member = rng.choice(self.members)
            begin = "20270125" if i == DEAD else self.span[member[0]][0]
            c, g = self.claim(self.blocks[npi], member, [self.line(member[0], npi, begin) for _ in range(rng.choice((1, 1, 1, 2, 2, 3, 4)))])
            c.rend = rng.choice(self.rendering) if rng.random() < 0.3 else None
            if i in (EXCLUDED, DEAD):
                c.role, c.reason, c.defect = "genuine", "PROVIDER_EXCLUDED" if i == EXCLUDED else "PROVIDER_DECEASED", "provider_excluded" if i == EXCLUDED else "provider_deceased"
            elif i not in SMALL:
                self.pool.append((c, g))

    def take(self, count, own_member=False, rng=None):
        """Clean claims for a defect: each alone in its subscriber group (and, when asked, its member's only claim in the file)."""
        got = []
        while len(got) < count:
            c, g = self.pool.pop((rng or self.rng).randrange(len(self.pool)))
            if len(g.claims) == 1 and (not own_member or self.per_member[c.member] == 1) and not any(c is x[0] for x in got):
                got.append((c, g))
        return got

    def mark(self, kind, claims, role=None, **more):
        for c in claims:
            c.defect = kind
            if role:
                c.role = role
        self.manifest.append({"id": f"{kind}#{len([m for m in self.manifest if m['kind'] == kind]) + 1}", "kind": kind,
                              "claims": [f"{c.key}" for c in claims], **more})

    def twin(self, c, g, **change):
        """A second claim like ``c``: the same id (a copy) unless a new id is asked for; it sits in a subscriber group of its own."""
        self.serial += 1
        t = Claim(c.id if change.pop("same_id", True) else f"C{self.serial:07d}", change.pop("npi", c.npi), c.member, change.pop("form", c.form), list(c.lines))
        t.rend, t.copy = c.rend, True
        for k, v in change.items():
            setattr(t, k, v)
        later = Group(g.member)
        later.claims.append(t)
        return t, later


def inject(w):
    rng = w.rng
    # corrections and copies: pairs of claims
    for n, (c, g) in enumerate(w.take(PAIR_KINDS["exact_duplicate"])):
        t, later = w.twin(c, g)
        (g.claims.append(t) if n % 2 else w.blocks[c.npi].groups.append(later))  # next to the first, or in a group of its own later
        w.mark("exact_duplicate", [c], "allow")
    for n, (c, g) in enumerate(w.take(PAIR_KINDS["near_duplicate_changed_field"])):
        t, later = w.twin(c, g)
        p, ch, u, d = t.lines[0]
        t.lines[0] = [(p, ch + 100, u, d), (p, ch, u, str(int(d) + 1)), ("99499", ch, u, d)][n % 3]
        w.blocks[c.npi].groups.append(later)
        w.mark("near_duplicate_changed_field", [c], "hold")
    for c, g in w.take(PAIR_KINDS["same_service_new_claim_id"]):
        t, later = w.twin(c, g, same_id=False)
        w.claims.append(t)
        w.blocks[c.npi].groups.append(later)
        w.mark("same_service_new_claim_id", [c, t], "pair", original=c.key, copy=t.key)  # exactly one of the two is paid, whichever comes first
    for kind, freq, late in (("replacement_after_original", "7", True), ("replacement_before_original", "7", False),
                             ("void_after_original", "8", True), ("void_before_original", "8", False)):
        for c, g in w.take(PAIR_KINDS[kind]):
            t, later = w.twin(c, g, same_id=False, freq=freq, ref=c.id, role="hold")
            if freq == "7":
                p, ch, u, d = t.lines[0]
                t.lines[0] = (p, ch + 500, u, d)
            groups = w.blocks[c.npi].groups
            groups.insert(groups.index(g) + (1 if late else 0), later)
            w.claims.append(t)
            # a claim voided or replaced in the same file must not be paid as first sent: both go to staff
            w.mark(kind, [t, c], "hold", original=c.key)
    for c, g in w.take(PAIR_KINDS["claim_id_reused_by_other_provider"]):
        other = rng.choice([p for i, p in enumerate(w.providers) if p[0] != c.npi and p[2] == c.form and i not in (EXCLUDED, DEAD, *SMALL)])
        t, later = w.twin(c, g, npi=other[0])
        t.lines = [(PROCS[(PROCS.index(c.lines[0][0]) + 3) % 20], c.lines[0][1], 1, c.lines[0][3])]
        w.blocks[other[0]].groups.append(later)
        w.claims.append(t)
        w.mark("claim_id_reused_by_other_provider", [c, t], "allow")

    def on_claim(kind, fn, own_member=False):
        for c, g in w.take(0 if kind in w.skip else CLAIM_KINDS[kind][0], own_member):
            fn(c, g)
            w.mark(kind, [c], CLAIM_KINDS[kind][1], **({"reason": GENUINE_REASON[kind]} if kind in GENUINE_REASON else {}))
            c.reason = GENUINE_REASON.get(kind, "")

    def charge(text):
        return lambda c, g: c.edits.append(first("SV", lambda s: re.sub(r"\*[-0-9.A-Z/]+\*UN", f"*{text}*UN", s)))

    def set_charge(amount):  # the line and the claim total both carry it, so only the amount itself is wrong
        return lambda c, g: c.lines.__setitem__(0, (c.lines[0][0], amount(c.lines[0][1]), c.lines[0][2], c.lines[0][3]))

    def units(text):
        return lambda c, g: c.edits.append(first("SV", lambda s: re.sub(r"UN\*[0-9]+", f"UN*{text}", s)))

    def date(text):
        return lambda c, g: c.edits.append(first("DTP*472", lambda s: f"DTP*472*{text}"))

    def rend_npi(nine=False, none=False):
        def fn(c, g):
            c.rend = c.rend or w.rendering[5]
            c.rend = ("" if none else bad_npi(c.rend[0], nine), c.rend[1], c.rend[2])
        return fn

    for kind, text in (("date_feb30", "D8*20270230"), ("date_month13", "D8*20271301"), ("date_text", "D8*03/05/2027"), ("date_zero", "D8*00000000"),
                       ("date_future", "D8*20280101"), ("date_before_1990", "D8*19000101"), ("date_range", "RD8*20270301-20270303")):
        on_claim(kind, date(text))
    on_claim("date_missing", lambda c, g: c.edits.append(without("DTP*472")))
    on_claim("sv1_short", lambda c, g: c.edits.append(first("SV", lambda s: "*".join(s.split("*")[:2]))))
    on_claim("clm_short", lambda c, g: c.edits.append(first("CLM", lambda s: "*".join(s.split("*")[:2]))))
    on_claim("charge_text", charge("N/A"))
    on_claim("charge_negative", lambda c, g: c.edits.append(first("SV", lambda s: re.sub(r"\*([0-9.]+)\*UN", r"*-\1*UN", s))))
    on_claim("charge_absurd", charge("9999999.99"))
    on_claim("charge_zero", charge("0.00"))
    on_claim("units_zero", units("0"))
    on_claim("units_fraction", units("1.5"))
    on_claim("units_absurd", units("99999"))
    on_claim("total_mismatch", lambda c, g: setattr(c, "total", sum(x[1] for x in c.lines) + 1234))
    on_claim("member_id_missing", lambda c, g: g.edits.append(first("NM1*IL", lambda s: s.replace(f"MI*{c.member}", "MI*"))))
    on_claim("rendering_npi_missing", rend_npi(none=True))
    on_claim("npi_bad_check_digit", rend_npi())
    on_claim("npi_nine_digits", rend_npi(nine=True))
    on_claim("claim_id_missing", lambda c, g: c.edits.append(first("CLM", lambda s: s.replace(c.id, "", 1))))
    on_claim("unknown_segment_in_claim", lambda c, g: c.edits.append(after("HI*", "ZZZ*1*2")))
    on_claim("unknown_segment_after_claim", lambda c, g: c.edits.append(lambda segs: segs + ["ZZZ*3"]))
    on_claim("delimiter_inside_name", lambda c, g: g.edits.append(first("NM1*IL", lambda s: s.replace(g.member[1], "O~" + g.member[1], 1))))
    on_claim("stray_byte_in_member_id", lambda c, g: g.edits.append(first("NM1*IL", lambda s: s[:-1]  + chr(0xE9))))
    on_claim("hl_gap", lambda c, g: setattr(g, "hl_skip", 2))
    on_claim("second_sv1", lambda c, g: c.edits.append(after("SV", "SV1*HC:99999*1.00*UN*1***1")))
    on_claim("second_dtp", lambda c, g: c.edits.append(after("DTP*472", "DTP*472*D8*20270102")))
    on_claim("claim_without_lines", lambda c, g: c.edits.append(without(("LX", "SV", "DTP", "REF*6R"))))
    on_claim("dependent_patient", lambda c, g: setattr(g, "dependent", True))
    on_claim("unknown_procedure_code", lambda c, g: c.edits.append(first("SV", lambda s: re.sub(r"HC:[0-9A-Z]+", "HC:ZZ999", s))))
    on_claim("unknown_facility_code", lambda c, g: c.edits.append(first("CLM", lambda s: s.replace("***11:B", "***99:B").replace("***13:A", "***99:A"))))
    on_claim("lowercase_qualifier", lambda c, g: c.edits.append(first("SV", lambda s: s.replace("HC:", "hc:", 1))))
    on_claim("padded_fields", lambda c, g: c.edits.append(first("SV", lambda s: s.replace("HC:", "HC: ", 1).replace("*UN*", "* UN *", 1))))
    on_claim("stray_byte_in_name", lambda c, g: g.edits.append(first("NM1*IL", lambda s: s.replace(g.member[1], g.member[1][:-1]  + chr(0xE9), 1))))
    on_claim("utf8_accent_in_name", lambda c, g: g.edits.append(first("NM1*IL", lambda s: s.replace(g.member[1], "MU" + chr(0xC3) + chr(0x91) + "OZ", 1))))
    on_claim("repeated_line_control", lambda c, g: c.edits.append(lambda segs: [re.sub(r"REF\*6R\*\S+", "REF*6R*SAME", s) for s in segs]))

    def not_in_roster(c, g):
        w.absent.add(c.member)

    def enrolled_after(c, g):
        w.span[c.member] = ("20270220", "20271231")
        c.lines = [(p, ch, u, "20270118") for p, ch, u, _ in c.lines[:1]]
        w.taken.add((c.member, c.npi, c.lines[0][0], "20270118"))

    def deceased(c, g):
        w.death[c.member] = "20270302"
        c.lines = [(p, ch, u, "20270310") for p, ch, u, _ in c.lines[:1]]
        w.taken.add((c.member, c.npi, c.lines[0][0], "20270310"))

    on_claim("member_not_in_roster", not_in_roster, True)
    on_claim("member_enrolled_after_service", enrolled_after, True)
    on_claim("member_deceased", deceased, True)
    for kind in ("roster_exact_duplicate", "roster_conflicting_span", "roster_member_id_missing", "roster_bad_date", "roster_unknown_segment",
                 "roster_stray_byte_in_name"):
        on_claim(kind, lambda c, g, kind=kind: w.roster_edit.setdefault(c.member, kind), True)
    # a billing provider with no NPI: nothing in its block can be tied to a provider
    block = w.blocks[w.providers[NO_NPI][0]]
    block.edits.append(first("NM1*85", lambda s: s.replace(f"XX*{block.npi}", "XX*")))
    w.mark("billing_npi_missing_for_provider", block.claims, "hold")
    # claims rendered by the provider a garbled exclusion row names
    for c in w.claims:
        if c.rend and c.rend[0] == w.rendering[0][0] and c.role == "allow" and not c.defect:
            c.role, c.defect = "hold", "leie_garbled_npi_name_match"
    w.mark("leie_garbled_npi_name_match", [c for c in w.claims if c.defect == "leie_garbled_npi_name_match"], "hold")
    for kind in ("provider_excluded", "provider_deceased"):
        w.mark(kind, [c for c in w.claims if c.defect == kind], "genuine")
    for kind, edit in (("void_without_lines", lambda t: t.edits.append(without(("LX", "SV", "DTP", "REF*6R")))),  # the void itself is set aside
                       ("void_without_ref", lambda t: setattr(t, "ref", ""))):  # it names no claim: it holds the originals of its provider and member it overlaps
        for c, g in w.take(NAMING_KINDS[kind], rng=w.more):
            t, later = w.twin(c, g, same_id=False, freq="8", ref=c.id, role="hold")
            edit(t)
            groups = w.blocks[c.npi].groups
            groups.insert(groups.index(g) + 1, later)
            w.claims.append(t)
            w.mark(kind, [t, c], "hold", original=c.key)
    c, g = w.take(NAMING_KINDS["void_ref_in_lower_case"], rng=w.more)[0]
    t, later = w.twin(c, g, same_id=False, freq="8", ref=c.id.lower(), role="hold")
    w.blocks[c.npi].groups.append(later)
    w.claims.append(t)
    w.mark("void_ref_in_lower_case", [t, c], "hold", original=c.key)
    c, g = w.take(NAMING_KINDS["replacement_correcting_billing_npi"], rng=w.more)[0]  # sent under the right provider: the original was billed under the wrong one
    other = w.more.choice([p for i, p in enumerate(w.providers) if p[0] != c.npi and p[2] == c.form and i not in (EXCLUDED, DEAD, *SMALL)])
    t, later = w.twin(c, g, same_id=False, npi=other[0], freq="7", ref=c.id, role="hold")
    w.blocks[other[0]].groups.append(later)
    w.claims.append(t)
    w.mark("replacement_correcting_billing_npi", [t, c], "hold", original=c.key)
    c, g = next((c, g) for c, g in iter(lambda: w.take(1, rng=w.more)[0], None)  # REF*F8 is the payer's number (the 835's CLP07), the member id corrected,
                if not any(x.defect == "delimiter_inside_name" for x in w.blocks[c.npi].claims))  # in a set that reads, so only that number ties it to its claim
    t, later = w.twin(c, g, same_id=False, freq="8", ref=f"PCN-{c.id}", role="hold")
    later.member = w.more.choice([m for m in w.members if m[0] != c.member])
    w.blocks[c.npi].groups.append(later)
    w.claims.append(t)
    w.mark("void_by_payer_number_for_corrected_member", [t, c], "hold", original=c.key)
    for kind in NAMELESS_KINDS:
        c, g = w.take(1, True, rng=w.more)[0]
        w.roster_edit[c.member] = kind
        w.mark(kind, [c], "hold")
    for b in w.blocks.values():
        rng.shuffle(b.groups)  # dates and members arrive in no order, as from several queues


def x12_837(w, cut):
    """The 837 bytes: sets in random order, one clean section sent twice, mixed line ends and a BOM.  Without ``cut``, a second
    interchange is glued on (a header in the middle).  With it the file is one interchange and its last line stops mid-segment."""
    rng = w.rng
    last, again, glued = (w.blocks[w.providers[i][0]] for i in (TRUNCATED, SECTION, GLUED))
    rest = [b for b in w.blocks.values() if b.groups and b not in (last, glued)]
    rng.shuffle(rest)
    bodies = [b.body() for b in rest]
    bodies.insert(rng.randrange(len(bodies)), again.body())  # the whole section repeated, as a resend
    w.manifest.append({"id": "whole_section_repeated#1", "kind": "whole_section_repeated", "claims": [c.key for c in again.claims]})
    if cut:
        text = file_of(bodies + [glued.body(), last.body()], kind="837", gs_date=ROSTER_DAY, control="000000001")
    else:
        text = file_of(bodies, kind="837", gs_date=ROSTER_DAY, control="000000001") + file_of([glued.body(), last.body()], kind="837", gs_date=ROSTER_DAY, control="000000002")
        w.manifest.append({"id": "second_interchange_glued_on#1", "kind": "second_interchange_glued_on", "claims": [c.key for c in glued.claims + last.claims]})
    ends = ("", chr(10), chr(13) + chr(10), chr(13) + chr(10))
    data = "".join(seg + "~" + rng.choice(ends) for seg in text.decode("latin-1").split("~")[:-1]).encode("latin-1")
    w.manifest += [{"id": "bom#1", "kind": "bom", "claims": [], "signal": "bom"}, {"id": "mixed_line_endings#1", "kind": "mixed_line_endings", "claims": [], "signal": "whitespace"}]
    if cut:
        victim = last.groups[-1].claims[-1]
        w.mark("truncated_last_line", [victim], "hold")
        data = data[:data.rfind(b"SV1*HC:") + 9]
    return bytes((0xEF, 0xBB, 0xBF)) + data


def roster_834(w, nobody=False):
    """The roster; with ``nobody``, also a cancellation with no member id under a name and birth date no member has."""
    body = t834.header()
    seen = {}
    for mid, last, first_name in w.members:
        if mid in w.absent:
            continue
        begin, end = w.span[mid]
        loop = t834.member(mid, begin=begin, end=end, death=w.death.get(mid, ""))
        loop[3] = f"NM1*IL*1*{last}*{first_name}*Q***34*999{mid[-4:]}"
        n = int(mid[1:])
        born = datetime.date(1940, 1, 1) + datetime.timedelta(days=n * 7919 % 25000)  # spread over 68 years, as a roster's are
        loop[6] = f"DMG*D8*{born:%Y%m%d}*{'FM'[n % 2]}"  # members of one name are told apart by birth date
        kind = w.roster_edit.get(mid)
        if kind == "roster_conflicting_span":
            body += loop + t834.member(mid, begin="20270601", end=end)
            continue
        if kind and kind.startswith("roster_member_id_missing"):  # a later change for a member on the roster, sent with no member id
            body += loop
            loop = [loop[0].replace("*18*021*", "*18*001*"), "REF*0F*", *loop[2:]]
            name = {"roster_member_id_missing_name_changed": ("RIVERA", first_name), "roster_member_id_missing_names_swapped": (first_name, last),
                    "roster_member_id_missing_name_spaced": (f"{last[:2]} {last[2:]}", first_name)}.get(kind, (last, first_name))
            loop[3] = loop[3].replace(f"*{last}*{first_name}*", f"*{name[0]}*{name[1]}*")
        elif kind == "roster_bad_date":
            loop[8] = "DTP*348*D8*20270231"
        elif kind == "roster_unknown_segment":
            loop.insert(5, "ZZZ*1*2")
        elif kind == "roster_stray_byte_in_name":
            loop[3] = loop[3].replace(last, last[:-1]  + chr(0xE9))
        body += loop + (loop if kind == "roster_exact_duplicate" else [])
    if nobody:
        loop = t834.member("M9999999", ins03="024", begin="20270101", end="20270131")
        loop[1], loop[3], loop[6] = "REF*0F*", "NM1*IL*1*NOBODY*ZED*Q***34*9999999", "DMG*D8*19010101*F"
        body += loop
    data = file_of([body], kind="834", gs_date=ROSTER_DAY)
    return data + b"\r\n\r\n  "


def leie_csv(w):
    """The exclusion list: the excluded provider (by NPI), a garbled-NPI row for a name a rendering provider shares, and rows of the kinds a real file breaks."""
    ex = w.providers[EXCLUDED]
    rows = [tl.row(last="", first="", bus=ex[1], npi=ex[0]), tl.row(npi=tl.make_npi(1)),
            tl.row(last="GARCIA", first="MARIA", npi="12345ABCDE")]
    rows += [tl.row(last=f"NOBODY{i}", first=FIRST[i % 20], npi="0000000000", excl="20240601") for i in range(200)]  # people with no NPI on the list
    good = tl.row(last="PERSON", first="ONE", npi=tl.make_npi(910000))
    mess = {"leie_row_repeated": good + good, "leie_row_missing_column": good.rstrip(chr(10)).rsplit(",", 1)[0] + chr(10),
            "leie_row_impossible_date": tl.row(last="X", first="Y", npi=tl.make_npi(910001), excl="20250231"),
            "leie_row_no_name": tl.row(last="", first="", bus="", npi=tl.make_npi(910002))}
    rows += [good] + [text for kind, text in mess.items() if kind not in w.skip]
    # a row with no NPI that is not UTF-8 outside its name (a Latin-1 city): held by its name, which no provider here has, so nothing else is held
    latin = tl.row(last="NOVAK", first="ZOE", npi="").replace("NOWHERE", "NOWH" + chr(0xC9) + "RE").encode("latin-1") if "leie_row_not_utf8" not in w.skip else b""
    return (tl.HEAD + "".join(rows)).encode() + latin


def remittance_835(w):
    """The incumbent's remittance: one payment set per billing provider, every claim paid 80 percent, with the faults of ``REMITTANCE_KINDS``."""
    rng = w.rng
    paid_claims = [c for c in w.claims if c.freq == "1" and not c.copy and c.id and c.defect not in ("claim_id_missing",)]
    paid_set = set(paid_claims)
    # a claim the incumbent never paid: it is in the 837 and not here
    skipped = {c.key for c in rng.sample([c for c in paid_claims if c.role == "allow"], REMITTANCE_KINDS["remittance_claim_never_paid"])}
    sets, notes = [], {"remittance_claim_never_paid": sorted(skipped)}
    twice = unreadable = 0
    for n, block in enumerate(b for b in w.blocks.values() if b.groups):
        body, total = [], 0
        for c in block.claims:
            if c.key in skipped or c not in paid_set:
                continue
            billed = sum(x[1] for x in c.lines)
            paid = sum(x[1] * 8 // 10 for x in c.lines)
            total += paid
            for repeat in range(2 if twice < REMITTANCE_KINDS["remittance_claim_sent_twice"] and rng.random() < 0.01 else 1):
                twice += repeat
                body.append(f"CLP*{c.id}*1*{cents(billed)}*{cents(paid)}*0.00*MC*PCN-{c.id}*11*1")
                for i, (proc, ch, u, day) in enumerate(c.lines, 1):
                    body += [f"SVC*HC:{proc}*{cents(ch)}*{cents(ch * 8 // 10)}**{u}", f"DTM*472*{day}", f"CAS*CO*45*{cents(ch - ch * 8 // 10)}", f"REF*6R*{c.id}L{i}"]
            if unreadable < REMITTANCE_KINDS["remittance_amount_unreadable"] and rng.random() < 0.01:
                unreadable += 1
                body.append(f"CLP*{c.id}Z*1*1.00*8O.00*0.00*MC*PCN*11*1")
        sets.append(head835(cents(total), trace=f"T{n:05d}", payee=block.npi) + body)
    return file_of(sets, kind="835", gs_date=AS_OF), notes


# Parallel runs of the same paid claims by three claims systems, for the report that names the system at fault: a few clean claims
# carry one planted defect each, tagged with the system at fault (a denial for a member the state's own eligibility office never
# sent is the state's, not the system that denied it).  Drawn from a third generator, so the rest of the file is unchanged.
SYSTEMS_KINDS = {"old_underprices": ("old", 5), "new_overprices": ("new", 4), "new_never_paid": ("new", 3),
                 "new_denies_unsent_member": ("state_eligibility_office", 4), "old_denies_non_covered": ("old", 4)}


def systems_835(w):
    """``({"old": bytes, "new": bytes, "shadow": bytes}, {"<claim id>#<line control>": (system at fault, cents at stake)})``: each system pays 80
    percent of every line of every clean claim that has a unique id, except the planted claims (``SYSTEMS_KINDS``).  The cents at stake of a
    planted line come from its charge alone: the spread of the prices (70, 80 or 90 percent), else the 80 percent the other systems paid."""
    rng, ids = random.Random(SEED + 2), {}
    for c in w.claims:
        ids[c.id] = ids.get(c.id, 0) + 1
    clean = [c for c in w.claims if c.freq == "1" and not c.copy and c.id and ids[c.id] == 1 and c.role == "allow" and not c.defect]
    ok, plan, planted = {c.key for c in clean}, {}, {}
    for kind, (fault, count) in SYSTEMS_KINDS.items():
        for c in rng.sample([c for c in clean if c.key not in plan], count):
            plan[c.key] = kind
            for i, (_, ch, _, _) in enumerate(c.lines, 1):
                planted[f"{c.id}#{c.id}L{i}"] = (fault, {"old_underprices": ch * 8 // 10 - ch * 7 // 10, "new_overprices": ch * 9 // 10 - ch * 8 // 10}.get(kind, ch * 8 // 10))
    by = {("old", "old_underprices"): (7, 10, "45"), ("new", "new_overprices"): (9, 10, "45"), ("old", "old_denies_non_covered"): (0, 10, "96"),
          ("new", "new_denies_unsent_member"): (0, 10, "31")}
    files = {}
    for name in ("old", "new", "shadow"):
        sets = []
        for n, block in enumerate(b for b in w.blocks.values() if b.groups):
            body, total = [], 0
            for c in block.claims:
                kind = plan.get(c.key)
                if c.key not in ok or (kind, name) == ("new_never_paid", "new"):
                    continue
                num, den, carc = by.get((name, kind), (8, 10, "45"))
                paid = [x[1] * num // den for x in c.lines]
                total += sum(paid)
                body.append(f"CLP*{c.id}*1*{cents(sum(x[1] for x in c.lines))}*{cents(sum(paid))}*0.00*MC*PCN-{c.id}*11*1")
                for i, ((proc, ch, u, day), got) in enumerate(zip(c.lines, paid), 1):
                    body += [f"SVC*HC:{proc}*{cents(ch)}*{cents(got)}**{u}", f"DTM*472*{day}"] + [f"CAS*CO*{carc}*{cents(ch - got)}"] * (ch > got) + [f"REF*6R*{c.id}L{i}"]
            sets.append(head835(cents(total), trace=f"T{n:05d}", payee=block.npi) + body)
        files[name] = file_of(sets, kind="835", gs_date=AS_OF)
    return files, planted


def build(seed=SEED, skip=(), cut=False, nobody=False, lines=None):
    """``lines``: a replay-volume file of about that many service lines (a claim has two on average): the clean world grows and the injected
    defects stay as many as before, so the defect rate falls with the size.  Same seed, same bytes."""
    w = World(seed, skip, N_CLEAN if lines is None else max(N_CLEAN, lines // 2))
    w.clean()
    inject(w)
    files = {"837": x12_837(w, cut), "834": roster_834(w, nobody), "leie": leie_csv(w)}
    files["835"], notes = remittance_835(w)
    return w, files, notes
