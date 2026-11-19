"""Independent checker for conformance/GATE_RULES_V2.md (written from that page alone; stdlib only).

``run(text)`` returns the lines `gate_rules` prints for a vector file, without the RULES_SOURCE header.
"""

import datetime
import hashlib
import re
import sys

FLOWS = {"FFS_CYCLE": 1, "FFS_CLAIM": 2, "CAP_820": 3}
FNAME = {v: k for k, v in FLOWS.items()}
KINDS = ("dmf", "pdeath", "excl", "span", "released", "unresolved", "elig")  # kind number = position + 1
ID, PAY = 129, 261
WIDTHS = {"dmf": (ID, 4), "pdeath": (ID, 4), "excl": (ID, 4, 4), "span": (ID, ID, 4, 4), "elig": (ID, ID, 1, 4, 4)}
LINEW = (ID, PAY, 1, ID, ID, ID, 4, ID, 4, 8)  # id pay flow member payee rend date proc units cents
DOMAIN = {"released": "RR/GATE/RELEASED/v1", "unresolved": "RR/GATE/UNRESOLVED/v1"}
MAXAGE = {"dmf": 90, "pdeath": 90, "excl": 31, "span": 7, "elig": 7}
REASONS = sorted("""ALREADY_DECIDED BENEFIT_LEVEL_MISSING BENEFIT_LEVEL_MISSING_UNVERIFIED CAP_MEMBER_MONTH_DUPLICATE COLLIDES_WITH_UNRESOLVED_NEAR DUPLICATE_OF_UNRESOLVED
FFS_DUPLICATE_LINE FFS_DUPLICATE_UNVERIFIED FFS_NEAR_DUPLICATE MEMBER_DECEASED MEMBER_DECEASED_UNVERIFIED
MEMBER_NOT_ENROLLED MEMBER_NOT_ENROLLED_UNVERIFIED POSTING_CAP PROGRAM_NOT_ELIGIBLE PROGRAM_NOT_ELIGIBLE_UNVERIFIED
PROVIDER_DECEASED PROVIDER_DECEASED_UNVERIFIED
PROVIDER_EXCLUDED PROVIDER_EXCLUDED_UNVERIFIED SERVICE_DATE_FUTURE SERVICE_DATE_INVALID STALE_DMF STALE_ELIGIBILITY
STALE_ENROLLMENT STALE_EXCLUSION STALE_PROVIDER_DEATH STALE_RELEASED STALE_UNRESOLVED""".split())
REVIEW = {"COLLIDES_WITH_UNRESOLVED_NEAR", "FFS_NEAR_DUPLICATE", "SERVICE_DATE_FUTURE", "SERVICE_DATE_INVALID", "STALE_DMF",
          "STALE_ENROLLMENT", "STALE_EXCLUSION", "STALE_PROVIDER_DEATH", "STALE_RELEASED", "STALE_UNRESOLVED",
          "MEMBER_DECEASED_UNVERIFIED", "MEMBER_NOT_ENROLLED_UNVERIFIED", "PROVIDER_DECEASED_UNVERIFIED",
          "PROVIDER_EXCLUDED_UNVERIFIED", "FFS_DUPLICATE_UNVERIFIED", "STALE_ELIGIBILITY", "PROGRAM_NOT_ELIGIBLE_UNVERIFIED",
          "BENEFIT_LEVEL_MISSING_UNVERIFIED"}
GENESIS = (0, 0, ())


def aid_id(text):
    """An aid code's number: 1, then times 256 plus each UTF-8 byte (section 1)."""
    n = 1
    for b in text.encode("utf-8"):
        n = n * 256 + b
    return n


ALLOWED_AID = {aid_id(s) for s in ("13", "23", "53", "103", "104")}


def num(s):
    if not re.fullmatch("[0-9]+", s):
        return None
    n = 0
    for i in range(0, len(s), 4000):  # chunked, so any length parses without touching the process-wide int digit limit
        n = n * 10 ** len(s[i:i + 4000]) + int(s[i:i + 4000])
    return n


def nums(fs):
    v = [num(s) for s in fs]
    return None if None in v else v


def valid(d):
    y, m, dd = d // 10000, d // 100 % 100, d % 100
    if not (1 <= y <= 9999 and 1 <= m <= 12):
        return False
    return 1 <= dd <= mdays(y, m)


def mdays(y, m):
    if m == 2:
        return 29 if y % 4 == 0 and (y % 100 or y % 400 == 0) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def ordinal(d):
    return datetime.date(d // 10000, d // 100 % 100, d % 100).toordinal()


def parse_line(fs):
    """(id, pay, flow, member, payee, rend, date, proc, units, cents) or None."""
    if len(fs) != 9 or fs[1] not in FLOWS:
        return None
    ip = fs[0].split(":")
    if len(ip) > 2:
        return None
    v = nums([ip[0], ip[-1]] + fs[2:])
    if v is None:
        return None
    return (v[0], v[1], FLOWS[fs[1]], *v[2:])


def row_of(kind, fs):
    if kind in ("dmf", "pdeath"):
        v = nums(fs)
        return tuple(v) if v and len(v) == 2 else None
    if kind in ("excl", "span", "elig"):
        v = nums(fs)
        return tuple(v) if v and len(v) == {"excl": 3, "span": 4, "elig": 5}[kind] else None
    return parse_line(fs)


def enc(widths, vals):
    if any(v >= 256 ** w for w, v in zip(widths, vals)):
        return None
    return b"".join(v.to_bytes(w, "big") for w, v in zip(widths, vals))


def pin_bytes(kind, asof, count, rows):
    """Pin input of a snapshot, or None when a value does not fit."""
    widths = LINEW if kind in DOMAIN else WIDTHS[kind]
    encs = [enc(widths, r) for r in rows]
    if None in encs:
        return None
    dom = DOMAIN.get(kind, "RR/GATE/SNAPSHOT/v1")
    head = enc((4, 4, 4), (KINDS.index(kind) + 1, asof, count))
    return dom.encode() + b"\0" + head + b"".join(sorted(encs))


def sha3(b):
    return hashlib.sha3_512(b).digest()


class Run:
    def __init__(self):
        self.today = 0
        self.snaps = {}
        self.rows = {k: [] for k in KINDS}
        self.reset()
        self.checked = self.failed = 0
        self.expected = None

    def reset(self):
        self.extra, self.held = [], []
        self.rprior = self.uprior = GENESIS
        self.anchor = None
        self.batch, self.redo, self.pays, self.done = [], [], [], []

    # ---- snapshots
    def snapshot(self, kind):
        """(asof, count, rows) or None."""
        d = self.snaps.get(kind)
        if d is None:
            return None
        rows = [row_of(kind, fs) for fs in self.rows[kind]]
        if None in rows:
            return None
        pb = pin_bytes(kind, d[0], d[1], rows)
        if pb is None or sha3(pb).hex() != d[2]:
            return None
        return (d[0], d[1], tuple(rows))

    def usable(self, kind, s):
        if s is None:
            return False
        asof, count, rows = s
        if not (valid(self.today) and valid(asof) and asof <= self.today):
            return False
        if ordinal(self.today) > ordinal(asof) + MAXAGE[kind] or len(rows) != count or count == 0:
            return False
        for r in rows:
            if kind in ("dmf", "pdeath"):
                if not (valid(r[1]) and r[1] <= asof):
                    return False
            elif not (valid(r[-2]) and valid(r[-1]) and r[-2] <= r[-1]):
                return False
            elif kind == "elig" and r[2] > 1:
                return False
        return True

    def chained(self, prior, s):
        return (s is not None and len(s[2]) == s[1] and valid(s[0]) and s[0] <= self.today and prior[0] <= s[0]
                and all(x in s[2] for x in prior[2]))

    # ---- decide
    def decide(self, batch):
        """Returns (decisions, new released lines, new unresolved lines). A decision is (line, outcome, reasons, ids)."""
        t = self.today
        snaps = {k: self.snapshot(k) for k in KINDS}
        use = {k: self.usable(k, snaps[k]) for k in MAXAGE}
        rel, unr = snaps["released"], snaps["unresolved"]
        if rel:
            rel = (rel[0], rel[1] + len(self.extra), rel[2] + tuple(self.extra))
        if unr:
            unr = (unr[0], unr[1] + len(self.held), unr[2] + tuple(self.held))
        chr_, chu = self.chained(self.rprior, rel), self.chained(self.uprior, unr)
        relset = list(rel[2]) if chr_ else list(self.rprior[2])
        unrset = list(unr[2]) if chu else list(self.uprior[2])
        loose_r = [] if chr_ or not rel else [x for x in rel[2] if x not in self.rprior[2]]
        loose_u = [] if chu or not unr else [x for x in unr[2] if x not in self.uprior[2]]
        rows = {k: (snaps[k][2] if snaps[k] else ()) for k in MAXAGE}
        lines = batch

        def cap(x):
            return x[2] == 3

        def exact(x):
            return (3 if cap(x) else 1, x[3], x[4], x[6], x[7], x[8], x[9])

        def near(x):
            return (0, x[3], x[6] // 100) if cap(x) else (2, x[3], x[5], x[6], x[7])

        def idk(x):
            return (4, x[0])

        def own(x):
            return x[1] in self.redo and x in relset

        def certain(k, x):
            return use[k] and valid(x[6])

        def unver(k, x):
            return snaps[k] is not None and not use[k] and valid(x[6])

        def enrolled(x):
            return any(s[0] == x[3] and s[2] <= x[6] <= s[3] and (not cap(x) or s[1] == x[4]) for s in rows["span"])

        def notenr(x):
            return certain("span", x) and not enrolled(x)

        def claim(x):
            return {exact(x), idk(x)} if cap(x) and notenr(x) and not own(x) else {exact(x), near(x), idk(x)}

        def overlap(x):
            f = x[6] // 100 * 100 + 1
            last = f - 1 + mdays(x[6] // 10000, x[6] // 100 % 100)
            ss = [s for s in rows["span"] if s[0] == x[3]]
            return any(a[1] != b[1] and max(f, a[2], b[2]) <= min(last, a[3], b[3]) for a in ss for b in ss)

        def covering(x):
            return [e for e in rows["elig"] if e[0] == x[3] and e[3] <= x[6] <= e[4]]

        def aid_ok(x):
            return any(e[1] in ALLOWED_AID for e in covering(x))

        def level_ok(x):
            return any(e[1] in ALLOWED_AID and e[2] == 1 for e in covering(x))

        pending = set()
        for x in unrset:
            pending |= claim(x)
        loosek = {exact(x) for x in loose_r + loose_u}
        seen = set()
        for x in relset:
            if not (own(x) and x in lines):
                seen |= {exact(x), near(x), idk(x)}

        def key(x):
            return (x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[0], x[1])

        ordered = sorted([x for x in lines if own(x)], key=key) + sorted([x for x in lines if not own(x)], key=key)
        out = []
        for x in ordered:
            c = cap(x)
            e, n, i = exact(x), near(x), idk(x)
            dead_m = any(r[0] == x[3] and r[1] < x[6] for r in rows["dmf"])
            dead_p = any(r[0] in (x[4], x[5]) and r[1] < x[6] for r in rows["pdeath"])
            excl = any(r[0] in (x[4], x[5]) and r[1] <= x[6] <= r[2] for r in rows["excl"])
            f = {
                "ALREADY_DECIDED": i in seen or i in pending,
                "BENEFIT_LEVEL_MISSING": certain("elig", x) and aid_ok(x) and not level_ok(x),
                "BENEFIT_LEVEL_MISSING_UNVERIFIED": unver("elig", x) and aid_ok(x) and not level_ok(x),
                "PROGRAM_NOT_ELIGIBLE": certain("elig", x) and not aid_ok(x),
                "PROGRAM_NOT_ELIGIBLE_UNVERIFIED": unver("elig", x) and not aid_ok(x),
                "STALE_ELIGIBILITY": not use["elig"],
                "CAP_MEMBER_MONTH_DUPLICATE": c and (e in seen or n in seen or certain("span", x) and overlap(x)),
                "COLLIDES_WITH_UNRESOLVED_NEAR": not c and n in pending and e not in pending,
                "DUPLICATE_OF_UNRESOLVED": e in pending or c and n in pending,
                "FFS_DUPLICATE_LINE": not c and e in seen,
                "FFS_DUPLICATE_UNVERIFIED": not c and e in loosek,
                "FFS_NEAR_DUPLICATE": not c and n in seen and e not in seen,
                "MEMBER_DECEASED": certain("dmf", x) and dead_m,
                "MEMBER_DECEASED_UNVERIFIED": unver("dmf", x) and dead_m,
                "MEMBER_NOT_ENROLLED": notenr(x),
                "MEMBER_NOT_ENROLLED_UNVERIFIED": unver("span", x) and not enrolled(x),
                "PROVIDER_DECEASED": certain("pdeath", x) and dead_p,
                "PROVIDER_DECEASED_UNVERIFIED": unver("pdeath", x) and dead_p,
                "PROVIDER_EXCLUDED": certain("excl", x) and excl,
                "PROVIDER_EXCLUDED_UNVERIFIED": unver("excl", x) and excl,
                "SERVICE_DATE_FUTURE": t < x[6],
                "SERVICE_DATE_INVALID": not valid(x[6]),
                "STALE_DMF": not use["dmf"], "STALE_ENROLLMENT": not use["span"], "STALE_EXCLUSION": not use["excl"],
                "STALE_PROVIDER_DEATH": not use["pdeath"], "STALE_RELEASED": not chr_, "STALE_UNRESOLVED": not chu,
            }
            rs = [r for r in REASONS if f.get(r)]
            oc = "ALLOW" if not rs else "HOLD" if any(r not in REVIEW for r in rs) else "HUMAN_REVIEW"
            ids = [y[0] for y in relset + loose_r if {exact(x), near(x), idk(x)} & {exact(y), near(y), idk(y)}]
            ids += [y[0] for y in unrset + loose_u if {exact(x), near(x), idk(x)} & claim(y)]
            out.append((x, oc, rs, ids))
            seen |= claim(x)
        rl = [d[0] for d in out if d[1] == "ALLOW" and d[0][1] not in self.redo and self.pay_outcome(out, d[0][1], own) == "ALLOW"]
        ul = [d[0] for d in out if d[1] != "ALLOW" and "ALREADY_DECIDED" not in d[2] and not own(d[0])]
        nr = (rel[0] if chr_ else self.rprior[0], tuple(relset) + tuple(rl))
        nu = (unr[0] if chu else self.uprior[0], tuple(unrset) + tuple(ul))
        return out, rl, ul, (nr[0], len(nr[1]), nr[1]), (nu[0], len(nu[1]), nu[1]), lambda p: self.pay_outcome(out, p, own)

    def pay_outcome(self, ds, p, own):
        ls = [d for d in ds if d[0][1] == p]
        if any(d[1] == "HOLD" for d in ls):
            return "HOLD"
        if ls and all(d[1] == "ALLOW" and (p not in self.redo or own(d[0])) for d in ls):
            return "ALLOW"
        return "HUMAN_REVIEW"

    # ---- commit
    def state_digest(self):
        r = sha3(pin_bytes("released", *self.rprior[:2], self.rprior[2]))
        u = sha3(pin_bytes("unresolved", *self.uprior[:2], self.uprior[2]))
        return hashlib.sha3_512(b"RR/GATE/STATE/v1\0" + r + u).hexdigest()

    def commit(self, unanchored):
        if self.anchor is not None and self.state_digest() != self.anchor:
            self.batch, self.redo, self.pays, self.anchor = [], [], [], None
            if unanchored:
                self.checked += 1
                return []
            self.failed += 1
            return ["RULES_UNANCHORED commit"]
        allx = [b[0] for b in self.batch]
        bad_pay = {x[1] for x in allx if enc(LINEW, x) is None}
        kept = [x for x in allx if x[1] not in bad_pay]
        ds, rl, ul, nr, nu, pay = self.decide(kept)
        got = [line_text(d[0]) + f" {d[1]} {','.join(d[2]) or '-'}" + (f" with={','.join(map(str, d[3]))}" if d[3] else "")
               for d in ds]
        quar = sorted(line_text(x) + (" HOLD UNENCODABLE_PAYMENT" if enc(LINEW, x) else " HOLD UNENCODABLE_FIELD")
                      for x in allx if x[1] in bad_pay)
        got += quar
        exp = [b[1] for b in self.batch if b[1]]
        if not exp:
            ok, n, msg = True, 0, []
        elif len(exp) == len(allx) and sorted(exp) == sorted(got):
            ok, n, msg = True, len(allx), []
        else:
            ok, n, msg = False, 0, ["RULES_GOT " + g for g in sorted(got) if g not in exp]
        bad = [(q, o) for q, o in self.pays
               if ("HOLD" if q in bad_pay else pay(q)) != o]
        ok = ok and not bad and not unanchored
        msg += [f"RULES_PAY {q} expected={o}" for q, o in bad] + (["RULES_ANCHORED commit"] if unanchored else [])
        self.extra += rl
        self.held += ul
        self.rprior, self.uprior = nr, nu
        self.done += ds + [(x, "HOLD", [], []) for x in allx if x[1] in bad_pay]
        self.checked += n + len(self.pays) if ok else 0
        self.failed += 0 if ok else 1
        self.batch, self.redo, self.pays, self.anchor = [], [], [], None
        return [] if ok else ["RULES_VECTOR_MISMATCH commit"] + msg

    # ---- directives
    def step(self, fs):
        """Output lines, or None when malformed."""
        k, n = fs[0], len(fs)
        if k == "case" and n == 2:
            self.reset()
        elif k == "anchor" and n == 2:
            if not re.fullmatch("[0-9a-f]{128}", fs[1]):
                return None
            self.anchor = fs[1]
        elif k == "today" and n == 2:
            v = num(fs[1])
            if v is None or v >= 2 ** 64:
                return None
            self.today = v
        elif k == "snap" and n == 5:
            a, c = num(fs[2]), num(fs[3])
            if a is None or c is None:
                return None
            self.snaps[fs[1]] = (a, c, fs[4])
            if fs[1] in self.rows:
                self.rows[fs[1]] = []
            if fs[1] == "released":
                self.extra = []
            if fs[1] == "unresolved":
                self.held = []
        elif k == "drop" and n == 2:
            self.snaps.pop(fs[1], None)
        elif k == "line":
            x = parse_line(fs[1:10])
            if x is None or len(fs) - 10 not in (0, 2, 3):
                return None
            self.batch.append((x, " ".join([line_text(x)] + fs[10:]) if len(fs) > 10 else None))
        elif k == "redo" and n == 2:
            v = num(fs[1])
            if v is None:
                return None
            if v < 256 ** PAY:
                self.redo.append(v)
        elif k == "pay" and n == 3:
            v = num(fs[1])
            if v is None:
                return None
            self.pays.append((v, fs[2]))
        elif k == "commit" and n in (1, 2) and (n == 1 or fs[1] == "UNANCHORED"):
            return self.commit(n == 2)
        elif k == "report" and n == 1:
            return self.report()
        elif k == "end" and n == 2:
            v = num(fs[1])
            if v is None:
                return None
            self.expected = v
        elif k in KINDS:
            self.rows[k].append(fs[1:])
        else:
            return None
        return []

    def report(self):
        def tally(p):
            ds = [d for d in self.done if p(d)]
            c = sum(d[0][9] for d in ds)
            return f"lines={len(ds)} cents={c} (${c // 100}.{c % 100:02d})"
        out = ["REPORT all " + tally(lambda d: True)]
        out += [f"REPORT {o} " + tally(lambda d, o=o: d[1] == o) for o in ("ALLOW", "HOLD", "HUMAN_REVIEW")]
        return out + [f"REPORT {r} " + tally(lambda d, r=r: r in d[2]) for r in REASONS]


def line_text(x):
    return f"{x[0]}:{x[1]} {FNAME[x[2]]} " + " ".join(map(str, x[3:]))


def run(text):
    r, out = Run(), []
    for n, raw in enumerate(text.split("\n"), 1):
        fs = [f for f in raw.replace("\r", "").split(" ") if f]
        if not fs or fs[0].startswith("#"):
            continue
        before = r.failed
        res = r.step(fs)
        if res is None:
            r.failed += 1
            out.append(f"RULES_VECTOR_MALFORMED line={n}")
            continue
        if r.failed > before:
            out.append(f"RULES_VECTOR_FAIL line={n}")
        out += res
    ok = r.failed == 0 and r.expected == r.checked
    return out + [f"RULES_VECTORS={'PASS' if ok else 'FAIL'} checked={r.checked} expected={r.expected or 0} failed={r.failed}"]


if __name__ == "__main__":
    print("\n".join(run(open(sys.argv[1], encoding="utf-8").read())))
