"""Fee-for-service claims to gate decisions: 837 claim lines to decide requests (FFS_CLAIM), and 834, LEIE and provider
death rows to the frame's feeds, decided by the engine through right_rail_gate_decide.  No rule is here: the engine decides
every line.  A claim that cannot be sent whole is set aside with its cause and its cents, never guessed and never sent in
part, and the rest are decided."""

from __future__ import annotations

import bisect
import collections
import csv
import hashlib
import itertools
from datetime import date, timedelta
from typing import NamedTuple, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_x12 as x12
from app.right_rail_reader_leie import name_text, npi_ok
from app.right_rail_reader_lines import name_tokens

_IDS = b"RR/GATE/FFS-ID/v1\x00"
_MEMBER = b"RR/GATE/MEMBER-KEY/v1\x00"
_IN_LOOP = frozenset(("bad_date", "bad_death_date", "repeated_segment", "empty_member_id", "bad_ins", "repeated_loop", "member_id_conflict",
                      "unknown_segment", "unread_segment"))  # an unread or unknown segment in a member loop may be one of its dates, misplaced or mistyped
_FRESH_DAYS = 45  # the newest full roster may be at most this many days older than the newest file: a lost change file cannot be seen


def canonical_id(prefix: str, *parts: str) -> str:
    """``prefix`` and 32 hex digits of SHA3-256 over the length-prefixed ``parts``: the same claim always gets the same id."""
    return prefix + hashlib.sha3_256(_IDS + b"".join(len(p.encode()).to_bytes(2, "big") + p.encode() for p in parts)).hexdigest()[:32]


def member_key(secret: bytes, member_id: str) -> bytes:
    """The member's 32-byte key under the tenant's secret, from the member id that the 837 and the 834 both carry."""
    return hashlib.sha3_256(len(secret).to_bytes(2, "big") + secret + _MEMBER + member_id.encode()).digest()


class SetAside(NamedTuple):
    id: str  # the claim id (837), member id (834), NPI (provider death) or name (exclusion)
    cause: str  # 837: payment_id_conflict, retry, replaced_or_voided, partial, total_mismatch, replacement_or_void, dependent_patient, bad_npi,
    # service_date, units, quarantined or field; 834: dependent_member, member_quarantined, deleted, conflicting_rows, termination, no_plan, no_dates, bad_dates, tied_files_disagree,
    # mixed_file_times, stale_roster or empty_roster (these three name a whole file: "interchange <ISA offset> made <time>", at the ISA);
    # provider deaths: bad_npi, bad_as_of or bad_dates; exclusions: no_npi, exclusion_npi_unreadable, excluded_after_as_of,
    # reinstated_after_as_of or bad_dates
    cents: int  # the claim's line charges (its CLM02 when it has no lines); 0 for an 834 row
    offset: int  # its CLM (837) or INS (834) segment or exclusion row in the file; a provider death's position in its list
    reader: str = ""  # a ``quarantined`` claim: the cause the reader gave the fault that holds it; a ``replaced_or_voided`` one: the claims naming it


def _near(claims: list, starts: list, at: int) -> list:
    """The claims a fault at byte ``at`` outside any unit can belong to: the claim whose segments it falls among; in the gap that heads
    a claim (its HL, SBR, NM1 and QC), that claim and the one above it in its set; before a set's first claim, that claim.  ``starts``: the claims' offsets, made once."""
    n = bisect.bisect_right(starts, at)
    above, below = claims[n - 1] if n else None, claims[n] if n < len(claims) else None
    if above and at <= above.end:
        return [above]
    if above and below and above.set == below.set:
        return [above, below]
    return [c for c in (above if above and (not below or at < below.set) else None, below if below and at >= below.set else None) if c]


def _by_name(exclusions) -> dict:
    """Offset -> cause of each exclusion row its claims are held by name for: an NPI that did not read, or no NPI and no exclusion type."""
    return {q.offset: q.cause for q in exclusions.quarantined if q.field == "npi" or q.cause == "no_exclusion_type" and not q.detail}


class _Name(NamedTuple):
    """A name an exclusion row that did not read holds: a person's (last and first name) or a business's."""
    last_name: str | None
    first_name: str | None
    business_name: str | None


def _typos(born: str) -> set:
    """Each ISO birth date one typo from ``born``, itself included: one digit differs, two neighbouring digits are swapped, or day and month are."""
    at = [i for i, x in enumerate(born) if x in "0123456789"]
    return ({born, f"{born[:4]}-{born[8:]}-{born[5:7]}"} | {born[:i] + d + born[i + 1:] for i in at for d in "0123456789"}
            | {born[:i] + born[i + 1] + born[i] + born[i + 2:] for i in at if i + 1 in at}) if len(born) == 10 else {born}


def _namesakes(rows):
    """``(open, may, weak)``: ``open``, the members of ``rows`` (the 834's) whose own last name is blank or not UTF-8, so it cannot be compared and a
    member loop with no identifier may be any of them; ``weak(name)``, the members with no birth date whose last and first names both agree with
    the loop's (either way round): it may be them, so they are held, but they never keep the member feeds live; ``may(name)``, the other members such a loop may be, from what it sent ("last*first*birth date", right_rail_x12_834):
    each that agrees with it on last name and birth date, or first name and birth date, whatever the third,
    or on both names with a birth date one typo away (``_typos``).  Last names agree when one shares a word with the other or is its
    words joined (O'BRIEN, OBRIEN; MC DONALD, MCDONALD), first names when their first words are one or one is the other's initial,
    the two names tried either way round; an empty value in what the loop sent agrees with any member's, but a member agrees only on a first name or birth date it has: its blank one agrees with nothing.  None, every member, when its last name does not read
    or no such member is on the roster: it may be no member, whoever is in ``open``.  The roster is indexed once, so a lookup
    costs the same on any roster size beyond the members it finds, and each name is looked up once."""
    words = lambda text: name_tokens(text).order  # noqa: E731
    lasts = lambda ws: {*ws, "".join(ws)} - {""}  # noqa: E731
    given = lambda ws: ws[0] if ws else ""  # noqa: E731
    keys = lambda f: (("w", f), ("i", f[:1])) if f else ()  # noqa: E731  a member's first name, whole and as an initial; none when it has none
    asks = lambda q: {("w", q), ("w", q[:1])} | ({("i", q)} if len(q) == 1 else set()) if q else None  # noqa: E731  the keys of each first name agreeing with ``q``; None: any
    open_ = {r.member_id for r in rows if r.name_raw_hex or not words(r.last_name)}
    ix = collections.defaultdict(set)  # (last word, first key, birth date), each part or none of the three -> its members
    for r in rows:  # each member under the parts it has: a blank first name or birth date is indexed under none
        f, b = keys(given(words(r.first_name))), r.birth_date or None
        for k in (*((("b", b),) if b else ()), *(("fb", fk, b) for fk in f if b), *(("f", fk) for fk in f)):
            ix[k].add(r.member_id)
        for w in lasts(words(r.last_name)):
            for k in (("l", w), *((("lb", w, b),) if b else ()), *(("lfb", w, fk, b) for fk in f if b), *(("lf", w, fk) for fk in f if not b)):
                ix[k].add(r.member_id)
    get = lambda *k: ix.get(k, ())  # noqa: E731
    memo: dict = {}

    def look(name):
        if name in memo:
            return memo[name]
        parts = name.split("*")
        if len(parts) != 3 or not words(parts[0]):
            return memo.setdefault(name, (None, set()))
        last, first, born = words(parts[0]), words(parts[1]), parts[2]
        found, near, weak = set(), _typos(born), set()
        for these, other in ((last, first), (first, last)):  # last name and birth date, or both names and a birth date a typo away
            o = asks(given(other))
            for w in lasts(these):
                if o is not None:  # both names, a member with no birth date
                    weak.update(*(get("lf", w, k) for k in o))
                found.update(*([get("l", w)] if not born else [get("lb", w, born)] +
                               [get("lb", w, t) if o is None else get("lfb", w, k, t) for t in near for k in (o or (None,))]))
        q = asks(given(first))
        if born:  # first name and birth date, under any last name
            found.update(*([get("b", born)] if q is None else [get("fb", k, born) for k in q]))
        elif q is not None:
            found.update(*(get("f", k) for k in q))
        return memo.setdefault(name, (found or None, weak))
    return open_, lambda name: look(name)[0], lambda name: look(name)[1]


def _npis(detail: str) -> list:
    """The NPIs a set-aside exclusion row still names (its quarantine's detail, right_rail_reader_leie): none when the detail is its name cells."""
    ids = detail.split()
    return ids if ids and all(npi_ok(n) for n in ids) else []


def _cells(detail: str) -> list:
    """The names a row that did not read and holds no NPI holds: its detail is its LASTNAME, FIRSTNAME, MIDNAME and BUSNAME cells
    (right_rail_reader_leie.name_text), held as a person's and as a business's; none when its name cells could not be placed ("")."""
    cells = next(csv.reader([detail])) if detail and not _npis(detail) else []
    if len(cells) != 4:  # an NPI, or nothing that names anyone
        return []
    last, first, _, business = cells
    return ([_Name(last, first, None)] if last else []) + ([_Name(None, None, business)] if business else [])


def _row_match(row):
    """Whether a claim's provider name (words as written) is the exclusion row's: a person's last name with the claim's given-name words
    (the others) holding a word that starts with the first letter of any given-name word of the row; a row with no first name, or a business,
    every word of its name; or the row's words joined with no spaces, found in the claim's words joined the same way (for one word, a run of
    consecutive claim words joining to it: O'BRIEN and OBRIEN).  A row of suffix words only (DO, CO) keeps them.  A row with no word matches nothing.
    Returns the row's words, its joined words and ``match(pool, have, text, spans)``: the claim's words in order, as a set, joined, and
    ``spans()``, the claim's word boundaries in the joined text (``_spans``), asked for only by a one-word row whose word is in it."""
    words = name_tokens(row.last_name or row.business_name)
    given = name_tokens(row.first_name).order if row.last_name and row.first_name else ()
    initials, joined = frozenset(g[:1] for g in given), "".join(words.order)

    def match(pool, have, text, spans) -> bool:
        if words <= have and (not initials or any(w[:1] in initials and w not in words for w in pool)):
            return True
        if len(words) > 1:
            return joined in text
        at = text.find(joined)  # one word: a run of consecutive claim words that join to it, the rest holding the initial
        while at >= 0:
            starts, ends, firsts = spans()
            i, k = starts.get(at), ends.get(at + len(joined))
            if i is not None and k is not None:  # the run begins and ends on word boundaries
                if not initials or sum(firsts[g] for g in initials) > sum(w[:1] in initials for w in pool[i:k]):
                    return True
            at = text.find(joined, at + 1)
        return False
    return words, joined, initials, match


def _spans(pool):
    """The claim's words in their joined text: ``{start offset: word number}``, ``{end offset: word number after}``, and how many words begin with each letter."""
    starts, ends, at = {}, {}, 0
    for i, w in enumerate(pool):
        starts[at] = i
        at += len(w)
        ends[at] = i + 1
    return starts, ends, collections.Counter(w[:1] for w in pool)


def _row_finder(rows):
    """``find(names)``: the offset of the first of ``rows`` (offset, exclusion row) whose name the claim name matches, else None; a
    batch costs its claim names plus its rows, not their product.  Rows alike in every way that counts are one; a name seen is not judged again;
    a row is looked up by its rarest-looking word (its longest) or by the first three letters of its joined words."""
    kinds: set = set()
    by_word: dict = {False: {}, True: {}}
    by_gram: dict = {False: {}, True: {}}
    for n, (at, row) in enumerate(rows):
        words, joined, initials, match = _row_match(row)
        kind = (words.bare, frozenset(words), joined, initials)
        if words and kind not in kinds:
            kinds.add(kind)
            by_word[words.bare].setdefault(max(words, key=lambda w: (len(w), w)), []).append((n, at, match))
            by_gram[words.bare].setdefault(joined[:3], []).append((n, at, match))
    sizes = {bare: sorted({len(k) for k in by_gram[bare]}) for bare in by_gram}
    seen: dict = {}

    def find(names):
        key = (names.order, names.every)
        if key not in seen:
            best = None
            for bare, pool in ((False, names.order), (True, names.every)):
                if not by_word[bare]:
                    continue
                have, text, box = frozenset(pool), "".join(pool), []

                def spans():
                    if not box:
                        box.append(_spans(pool))
                    return box[0]
                found = [c for w in have if w in by_word[bare] for c in by_word[bare][w]]  # a lookup per claim word: set.intersection(dict) would walk the whole dict
                for g in sizes[bare]:
                    found += [c for k in {text[i:i + g] for i in range(len(text) - g + 1)} if k in by_gram[bare] for c in by_gram[bare][k]]
                for c in sorted(set(found), key=lambda c: c[0]):
                    if best is not None and c[0] >= best[0]:
                        break
                    if c[2](pool, have, text, spans):
                        best = c
                        break
            seen[key] = best[1] if best else None
        return seen[key]
    return find


def requests_of(reads: Sequence, tenant: str, program: str, period: str, secret: bytes, exclusions, paid: Sequence = ()) -> tuple[tuple, tuple]:
    """One FFS_CLAIM request per original claim (frequency 1) in ``reads`` (right_rail_x12_837.Read837), and the claims set
    aside.  Its payment and command id come from the billing NPI and claim id, each line's from them and its line number, so a
    resubmitted claim is the same payment (decided once).  The member is the subscriber; payee the billing NPI; the amount the
    billed line charges; a line's procedure its code and sorted modifiers; the evidence the file's SHA3-512.  Claims under
    one payment id that are the same claim (every value, the reader's finding on its total included, but where and when
    the file was sent and modifier order) are one claim: the first is
    read, each later copy is a ``retry``; claims under one id that differ are each set aside as ``payment_id_conflict``.  A
    claim is sent whole or not at all: it is set aside when the reader set a line of it aside (``partial``) or its total is
    not its lines' sum (``total_mismatch``), it is a replacement or void, a replacement or void anywhere in ``reads``, before or after
    it, names it (one of its REF*F8, a repeat included, is the claim id, spaces dropped and case folded, or the payer's claim number a remittance in ``paid``,
    right_rail_x12_835.Read835, gave that claim, each claim given it when two were, which its item says, under the same billing NPI or the same subscriber, each spaces dropped and case folded too; ``replaced_or_voided``, never
    paid as first sent; read from ``ClaimAt``, so a replacement or void the reader set aside or took back with its set still holds
    it, and one with no REF*F8 or with one naming no claim read holds each original of its billing NPI and subscriber whose service days
    meet its own, any day when a line of it has no day that read), its patient is a dependent, a billing or rendering
    NPI is not ten digits with its check digit, a line's service is not one dated day or not a whole number of units above
    zero, the reader set a segment aside in it or in the header ahead of it (its HL, SBR and NM1 loops), or anywhere in its set, group, interchange
    or file (``quarantined``), its provider's name is an exclusion row's whose NPI would not read, or the name in the name cells of a row that
    did not read and holds no NPI (``exclusions``, the list's read; ``exclusion_npi_unreadable``, its reason quoting the row's name
    and why it did not read), or a field does not encode.  Every claim in ``reads`` is in one list or the other, once: a claim the
    reader could not read or took back with its set, group or interchange is set aside (``quarantined``) under its id, else its offset,
    and a refused file as one item; an interchange with no closing is an item of its own too, since a replacement or void after the
    cut cannot be seen.  A later copy of a claim set aside is judged on its own; one of a claim sent is a ``retry``."""
    ids: dict = {}
    found: dict = {}  # (read, CLM offset) -> the reader's finding on that claim's total
    for i, read in enumerate(reads):  # a file read twice is two copies of each claim: the second a retry, never merged lines
        for r in read.rows:  # payment id -> each claim (its read and CLM segment) under it -> the claim's lines
            at, copies = (i, r.offsets[0]), ids.setdefault(canonical_id("C", r.billing_npi, r.claim_id), [])
            if copies and copies[-1][0] == at:  # a claim's lines are read together, so a claim seen again is the last one
                copies[-1][1].append(r)
            else:
                copies.append((at, [r]))
        found.update(((i, f.offset), f.cause) for f in read.findings)
    fold = lambda id_: "".join(id_.split()).casefold()  # noqa: E731  a claim id, NPI or subscriber id however spaced or cased
    who = lambda npi, sub: (fold(npi), fold(sub))  # noqa: E731
    icn, sent_as = {}, {}  # CLP07 -> each CLP01 the remittances give it -> the id as sent: a number given to two claims names both
    for p in (p for read in paid for p in read.claims if p.payer_claim_control):
        k, cid, got = fold(p.payer_claim_control), fold(p.claim_id), icn.setdefault(fold(p.payer_claim_control), {})
        got[cid] = min(got.get(cid, p.claim_id), p.claim_id)  # each as the least of its spellings: the text never depends on remittance order
        sent_as[k] = min(sent_as.get(k, p.payer_claim_control), p.payer_claim_control)
    shared = {r: f"; the payer's claim number {sent_as[n]} is given to claims {' '.join(sorted(ids.values()))} in the remittance"
              for n, ids in icn.items() if len(ids) > 1 for r in ids}  # its item says so
    voids = [c for read in reads for c in read.claims if c.frequency in ("7", "8")]  # read whole or not, in any read and either order
    asked = {r for c in voids for x in c.refs for r in (fold(x), *icn.get(fold(x), ())) if r}
    have: dict = {}  # claim id a replacement or void may name -> (billing NPI, subscriber) of each claim read under it
    for read in reads if asked else ():
        for c in read.claims:
            if (k := fold(c.id)) in asked:
                have.setdefault(k, []).append(who(c.npi, c.subscriber))
    meets = lambda npi, sub, npi_, sub_: npi in ("", npi_) or sub in ("", sub_)  # noqa: E731  same provider or same member
    named: dict = {}  # claim id -> (billing NPI, subscriber, claim id) of each replacement or void naming it
    loose: dict = {}  # (billing NPI, subscriber) -> (first day, last day, claim id) of each that names no claim read: it may be any of theirs it overlaps
    for c in voids:
        refs = [{r for r in (fold(x), *icn.get(fold(x), ())) if r and any(meets(*who(c.npi, c.subscriber), *h) for h in have.get(r, ()))} for x in c.refs or ("",)]
        for r in set().union(*refs):  # each claim each of its REF*F8 names
            named.setdefault(r, []).append((*who(c.npi, c.subscriber), c.id))
        if not all(refs):  # one REF*F8 names no claim read, or none was sent
            loose.setdefault(who(c.npi, c.subscriber), []).append((c.first, c.last, c.id))
    hurt: dict = {}  # (read, CLM offset) -> the reader's cause, of each claim a fault may belong to: held, never sent
    spoiled = _by_name(exclusions)
    why = {r.offset: (name_text((r.last_name, r.first_name, r.middle_name, r.business_name)), spoiled[r.offset]) for r in exclusions.rows if r.offset in spoiled}
    why.update((q.offset, (q.detail, q.cause)) for q in exclusions.quarantined if q.field is None and _cells(q.detail))  # exclusion row -> its name, why it did not read
    find = _row_finder([(r.offset, r) for r in exclusions.rows if r.offset in spoiled] +
                       [(q.offset, n) for q in exclusions.quarantined if q.field is None for n in _cells(q.detail)])
    sent, aside, lone = [], [], {}
    for i, read in enumerate(reads):
        starts, inside, done = [c.offset for c in read.claims], {}, set()  # made once per read, a unit's claims when a fault in that unit first needs them
        for q in read.quarantines:
            wide = q.unit in ("file", "set", "group", "interchange")  # a unit holds the claims inside it, a smaller fault the claims near it
            if wide and (q.unit, q.offset) in done:
                continue  # its claims are held already, by the first fault of the unit
            done.add((q.unit, q.offset))
            if wide and q.unit != "file" and q.unit not in inside:
                inside[q.unit] = [getattr(c, q.unit) for c in read.claims]  # the claims lie in file order, so each unit's claims are one run of this list
            near = (read.claims if q.unit == "file" else read.claims[bisect.bisect_left(inside[q.unit], q.offset):bisect.bisect_right(inside[q.unit], q.offset)]) if wide else _near(read.claims, starts, q.offset)
            if q.cause in ("group_unclosed", "iea_missing"):
                near = [c for c in near if c.void]  # a file cut short loses only the set it ends in: the sets its reader kept closed whole
            for c in near:
                hurt.setdefault((i, c.offset), q.cause)
            if (not near or q.cause == "iea_missing") and not (q.unit == "file" and read.refused):  # no claim to hold, or a file cut short (what followed is unseen): the unit itself is the item, once
                lone.setdefault((i, q.unit, q.offset), q.cause)
        have = {r.offsets[0] for r in read.rows}
        aside += [SetAside(c.id or f"offset {c.offset}", "quarantined", c.cents, c.offset, hurt.get((i, c.offset), "")) for c in read.claims if c.offset not in have]
        if read.refused:
            aside.append(SetAside(f"file {i}", "quarantined", 0, 0, read.refused))
    aside += [SetAside(f"{unit} {at}", "quarantined", 0, at, cause) for (_, unit, at), cause in lone.items()]
    for pid, claims in ids.items():
        alike = len(claims) == 1 or len({(found.get(at), *(r._replace(file_at="", file_sha3_512="", set_control="", offsets=(), line_control="", modifiers=tuple(sorted(r.modifiers)))
                                                         for r in c)) for at, c in claims}) == 1
        done = False  # a copy is sent: each later copy is its retry; a copy set aside never makes another one a retry
        for n, (at, lines) in enumerate(claims):
            c, cents, total = lines[0], sum(r.line_charge_cents for r in lines), found.get(at)
            row = min((at_ for at_ in map(find, {id(n): n for r in lines for n in r.names}.values()) if at_ is not None), default=None)  # the first exclusion row its name matches
            (npi, sub), maybe = who(c.billing_npi, c.subscriber_id), ()
            by = {v for n, s, v in named.get(fold(c.claim_id), ()) if meets(n, s, npi, sub)}
            if not by and c.frequency_code == "1" and loose:  # a void naming no claim read: each original of its provider and member it overlaps
                first, last = min((r.service_begin for r in lines if r.service_begin), default=""), max((r.service_end for r in lines if r.service_end), default="")
                maybe = {v for k in {(npi, sub), (npi, ""), ("", sub), ("", "")} for f, l, v in loose.get(k, ())
                         if not (f and last and f > last or l and first and l < first)}
            cause = ("payment_id_conflict" if not alike else "retry" if done else "replaced_or_voided" if by or maybe else "partial" if total == "total_unchecked" else
                     "total_mismatch" if total == "total_mismatch" else "replacement_or_void" if c.frequency_code != "1" else
                     "dependent_patient" if c.dependent else "bad_npi" if not all(npi_ok(r.billing_npi) and npi_ok(r.rendering_npi) for r in lines)
                     else "service_date" if any(not r.service_begin or r.service_begin != r.service_end for r in lines)
                     else "units" if any(r.units_milli is None or r.units_milli <= 0 or r.units_milli % 1000 for r in lines)
                     else "exclusion_npi_unreadable" if row is not None else "quarantined" if at in hurt else "field")
            if cause == "field":  # every check above passed: "field" stands only when a value does not encode
                key = member_key(secret, c.subscriber_id)
                try:
                    enc = tuple(gate.encode_line("FFS_CLAIM", canonical_id("L", c.billing_npi, c.claim_id, r.line_number), key, r.billing_npi,
                                                 r.rendering_npi, int(r.service_begin.replace("-", "")),
                                                 ":".join((r.procedure, *sorted(r.modifiers))), r.units_milli // 1000, r.line_charge_cents)
                                for r in lines)
                    req = gate.DecideRequest(tenant, program, "FFS_CLAIM", pid, pid, key, c.billing_npi, cents, period, enc,
                                             (bytes.fromhex(c.file_sha3_512),))
                    gate.encode_decide_request(req)
                    sent.append(req)
                    done = True
                    continue
                except gate.GateCodecError:
                    pass
            aside.append(SetAside(c.claim_id, cause, cents, c.offsets[0],
                                  hurt.get(at, "") if cause == "quarantined" else f'exclusion row {row} ("{why[row][0]}", {why[row][1]}) names this provider' if cause == "exclusion_npi_unreadable"
                                  else "named by claim " + " ".join(sorted(by)) + shared.get(fold(c.claim_id), "") if cause == "replaced_or_voided" and by
                                  else "named by claim " + " ".join(sorted(maybe)) + ": its REF*F8 is missing or one names no claim read, and it has this claim's provider, member and service days" if cause == "replaced_or_voided" else ""))
    return tuple(sent), tuple(aside)


def ident(b: bytes) -> int:
    """The rules' identifier number (Rules/Request.lean idNat): 0x01, then the bytes, big-endian."""
    return int.from_bytes(b"\x01" + b, "big")


def feeds(today: int, enrollment, exclusions, provider_deaths: tuple[str, Sequence[tuple[str, str]]], secret: bytes) -> tuple[tuple, tuple]:
    """The frame's read set (``decider.request_frame``) on ``today``: member deaths and enrollment spans from an 834
    (right_rail_x12_834.Read834, as of its newest file day; reads joined field by field place each fault by its own file
    hash, and when the per-read counts do not add up to the faults, or one is negative, no fault is placed: each is in no
    member loop).  The read may hold several files, each named by its file hash; each set's time and BGN08 come from its own
    header, with or without a member loop.  A set is a change set when its whole BGN08 is 2, else a full roster.  The full
    roster interchanges of one file made on one GS date are one roster, made at the newest of their times; every other
    interchange stands alone (a change interchange, or a full roster of another date even in the same file), and they are
    compared by time.  The newest full roster is the base: each interchange older than it is set aside as one
    ``mixed_file_times`` item; its deaths still count, and a fault in it holds its member or makes the member feeds absent as
    one in the base would.  A lost change file cannot be seen, so the base must be recent: when it is more than 45 days older than the newest
    file the span feed is absent (``stale_roster``).  From the base on, in time order, a file replaces a member's rows plan by
    plan: the member's first file gives all its rows, a later one each plan it gives a coverage begin (DTP 348), and the
    member's other plans stay.  A later change row with no coverage begin updates, never erases, as if filed after the rows of
    files before its own: a cancellation cuts the member's spans as in one file (its own file's too), an end date alone cuts
    only those of earlier files (never lengthening one), a delete holds the member, an eligibility begin (DTP 356) later than
    a span's begin starts that span there (never earlier; past its end the span is gone and the member holds as not
    enrolled), and a row with none of these (a change of name or address) leaves the coverage as it was.  Such a row that
    names a plan and changed nothing (an end at or after the span's end changes nothing) is set aside at its INS, once per
    member loop (``no_dates``): its plan has no begin to pay from, and the member's earlier span stays.  Items follow the rows
    in force: a row whose plan a later file gives a coverage begin, or a row with no plan once a later file gives the member
    any plan, gives no ``no_dates``, ``no_plan``, ``termination`` or ``deleted`` item.  A member no file names after the base
    keeps its rows, and with no full roster change files apply on nothing.
    Interchanges made at one time are unordered: a member named by one of them takes its rows, a member named by
    several with the same rows takes them once, and one they give different rows holds (``tied_files_disagree``); several
    sets in one interchange are not a tie.  A full roster at the base time with no member loop is set aside
    (``empty_roster``, or only ``stale_roster`` when the base is also stale) and the span feed is absent, since the newest
    roster could not be read.  A member missing from the
    newest full roster and from every later change file has no span and holds as not enrolled.  A death in any file counts,
    since a death never reverses.  File times carry no time zone, so a later time is trusted as newer only within one
    sender's files; exclusions from a full LEIE file (right_rail_reader_leie; a
    supplement says nothing of who is not on it, so the feed is absent and the engine holds every line), and provider
    deaths as (as-of, [(NPI, date)]), dates ISO.  An exclusion ends the day before its reinstatement; a waiver is not
    applied (a person lifts the hold).  A plan id longer than 20 bytes is sent as 0 (no fee-for-service rule reads it).  A
    cancellation (INS03 or HD01 024) ends each span of its member that begins on or before its end, wherever either stands
    in the file, at the earliest of its end dates and the day before its effective date (the first day not covered); a
    span that begins after it stands (a plan change: one plan ends, the next begins later).  A row with coverage and eligibility dates both spans from the later begin
    to the earlier end.  An 834 row gives no span and is set aside when it is a dependent's (INS01 N: it carries the
    subscriber's REF*0F, and a dependent's claim is set aside; ``dependent_member``), it deletes its coverage (HD01 002) or
    its member is deleted anywhere in the file (INS03 002, which the guide does not list; an add in the same file does not
    restore it; ``deleted``), its member is added in two member loops
    (``conflicting_rows``), was cancelled with neither date (``termination``), or the
    row has no plan or no begin date (``no_plan``, ``no_dates``): a member with no other span holds as not enrolled.  A
    segment the reader set aside in a member loop (a date on no calendar day, a repeated date, an INS that does not read, a
    name loop naming another member, an unknown segment) sets every row of that member aside (``member_quarantined``).  A member loop
    with no identifier is one item (``no_member_id``) and sets aside, the same way, every member its name may be (``_namesakes``), for
    itself and each fault in it; with no last name that reads, a name no member's may be, or counts that place no fault, it is a fault outside every member loop.  A fault outside every
    member loop (a voided set, group or interchange, a segment that does not read) may hide a
    cancellation or a death, so the member death and span feeds are absent and the engine reviews every line.  A provider death whose NPI is not ten
    digits with its check digit (``bad_npi``), every provider death when the list's as-of is no calendar day (``bad_as_of``:
    the feed is absent, so the engine reviews every line), and an exclusion with no valid NPI (``no_npi``, which no line can match) are
    set aside too.  An exclusion row that does not read is set aside with what it still names: each NPI in it is sent excluded from
    0001-01-01 with no end; with none, its claims are held by name (``requests_of``); one that names nothing readable makes the feed absent.  So is a row whose dates would make its whole feed unusable to the engine (``bad_dates``): a death on no
    calendar day or after its feed's as-of date (in any file: every row of that member), a span that ends before it begins, an exclusion reinstated on or before
    its start.  A provider so set aside still holds every claim: it is sent dead since 0001-01-01, or excluded from then on
    with no end.  Returns the read set and the rows
    set aside."""
    day = lambda iso: int(iso.replace("-", ""))  # noqa: E731
    before = lambda iso: (date.fromisoformat(iso) - timedelta(1)).isoformat() if iso > "0001-01-01" else ""  # noqa: E731
    every, absent = enrollment.rows, (bytes(77), b"")
    whole: dict = {}  # each interchange (file time, file hash, ISA offset): True when any of its sets is a full roster
    for s in enrollment.rosters:
        whole[s.file_at, s.file_sha3_512, s.interchange] = whole.get((s.file_at, s.file_sha3_512, s.interchange), False) or s.action != "2"
    newest = {}  # (file hash, GS date) -> (newest time, first ISA offset) of its full roster interchanges: one roster
    for (at, sha, isa), roster in whole.items():
        if roster:
            t, i = newest.get((sha, at[:10]), (at, isa))
            newest[sha, at[:10]] = (max(t, at), min(i, isa))
    unit = {}  # each interchange's roster; a change interchange stands alone
    for (at, sha, isa), roster in whole.items():
        t, i = newest[sha, at[:10]] if roster else (at, isa)
        unit[at, sha, isa] = (t, sha, i)
    u = lambda r: unit.get((r.file_at, r.file_sha3_512, r.interchange), (r.file_at, r.file_sha3_512, r.interchange))  # noqa: E731
    files = set(unit.values())
    full_files = {unit[f] for f, roster in whole.items() if roster}
    base = max((f[0] for f in full_files), default="")  # the newest full roster's time ("": change files apply on nothing)
    older = sorted(f for f in files if f[0] < base)
    filled = {u(r) for r in every}
    empty = sorted(f for f in full_files if f[0] == base and f not in filled)  # the newest full roster is unreadable
    asof = max((f[0][:10] for f in whole), default="0000-00-00")
    stale = sorted(f for f in full_files if f[0] == base and (date.fromisoformat(asof) - date.fromisoformat(base[:10])).days > _FRESH_DAYS)[:1]
    faults, counts = [], enrollment.reads
    placed = all(type(c) is tuple and len(c) == 3 and type(c[0]) is str and type(c[1]) is type(c[2]) is int and c[1] >= 0 <= c[2] for c in counts) and (
        sum(c[1] for c in counts), sum(c[2] for c in counts)) == (len(enrollment.quarantines), len(enrollment.findings))
    if placed:
        qs, fs = iter(enrollment.quarantines), iter(enrollment.findings)
        for sha, nq, nf in counts:  # each read's faults with its file hash: offsets of two files never meet
            faults += [(sha, q) for q in itertools.islice(qs, nq)] + [(sha, f) for f in itertools.islice(fs, nf)]
    else:  # counts that do not match the faults place no fault: each is in no member loop
        faults = [("", q) for q in enrollment.quarantines + enrollment.findings]
    ins = {(r.file_sha3_512, r.offsets[0]): r for r in every}  # a member loop's row by its file and INS
    unnamed = {(sha, q.offset): q.detail for sha, q in faults if q.cause == "no_member_id"}  # a member loop with no identifier: its name as sent
    nameless = unnamed if placed else {}  # unplaced, it is in no member loop: no name is matched, so it and each fault after it blind both feeds
    starts, heads = collections.defaultdict(list), collections.defaultdict(list)
    for s in enrollment.rosters:
        starts[s.file_sha3_512].append(s.start)
    for sha, at in sorted(ins.keys() | nameless.keys()):  # every member loop's INS, named or not
        heads[sha].append(at)
    for st in starts.values():
        st.sort()
    open_, namesakes, weak = _namesakes(every) if nameless else (set(), None, None)
    hurt, blind = set(open_), not every  # a member whose name cannot be compared may be any member loop with no identifier
    for sha, q in faults:  # in every file, older ones too: a fault may hide a death, and a death never reverses
        h, st = heads[sha], starts[sha]
        i, s = bisect.bisect_right(h, q.offset) - 1, bisect.bisect_right(st, q.offset) - 1  # the nearest loop and set above it in its file
        own = i >= 0 and (s < 0 or h[i] > st[s])  # that loop is in the fault's own set
        mine = q.cause in _IN_LOOP and own and (sha, h[i]) in ins
        if mine and ins[sha, h[i]].subscriber != "N":  # a dependent's loop carries its subscriber's REF*0F and is set aside anyway
            hurt.add(ins[sha, h[i]].member_id)
        name = nameless[sha, h[i]] if own and (q.cause in _IN_LOOP or q.cause == "no_member_id") and (sha, h[i]) in nameless else None  # the loop's name as sent
        may = namesakes(name) if name is not None else None
        hurt |= (may or set()) | (weak(name) if name is not None else set())  # a member with both names and no birth date is held, but keeps no feed live
        blind |= not mine and may is None
    seen: dict = {}  # time -> member -> file -> its subscriber rows, from the base on
    for r in every:
        if r.subscriber == "Y" and u(r)[0] >= base:
            seen.setdefault(u(r)[0], {}).setdefault(r.member_id, {}).setdefault(u(r)[1:], []).append(r)
    same = lambda rows: tuple(sorted(r._replace(file_at="", file_sha3_512="", set_control="", offsets=(), interchange=0) for r in rows))  # noqa: E731
    pick, tied, carry, planned = {}, set(), {}, {}  # (member, plan) -> the newest file that states it; tied: two files of one time differ
    for at in sorted(seen):
        for m, by in seen[at].items():
            if len({same(v) for v in by.values()}) > 1:
                tied.add(m)
            first = m not in carry  # a member's first file states all its rows; a later one only each plan it gives a coverage begin
            stated = {r.plan for r in by[min(by)] if first or r.coverage_begin}
            pick.update(((m, p), (at, *min(by))) for p in stated)
            if stated - {""}:
                planned[m] = at  # the newest file that gives the member a plan: its earlier rows with no plan are replaced
            carry.setdefault(m, []).extend(r for r in by[min(by)] if r.plan not in stated)  # updates, never erases
    rows = [r for r in every if u(r)[0] >= base and (r.subscriber != "Y" or pick.get((r.member_id, r.plan)) == u(r))]
    dead_after = {r.member_id for r in every if r.subscriber == "Y" and r.death_date > asof}  # in any file: the death feed would be unusable
    full = exclusions.coverage is not None and exclusions.coverage.kind == "full"  # a supplement: no feed, so no row of it is used
    mem = {r.member_id: ident(member_key(secret, r.member_id)) for r in every}  # a death never reverses: its feed reads every file
    cancel = lambda r: "024" in (r.maintenance_type, r.coverage_type)  # noqa: E731
    cut = lambda r: min(filter(None, (r.coverage_end, r.eligibility_end, before(r.maintenance_effective) if cancel(r) else "")), default="")  # noqa: E731
    begin = lambda r: max(r.coverage_begin, r.eligibility_begin)  # noqa: E731  two sources: the later begin and the earlier end
    cuts, gone, floors, loops = {}, {}, {}, {}  # per member: (date, file, offset, reaches its own file) of each cut, delete and begin floor
    for r in (r for r in rows if r.subscriber == "Y"):  # a dependent carries its subscriber's REF*0F: never the subscriber's rows
        if cancel(r):  # "" (before every date): a cancellation with no date ends every span
            cuts.setdefault(r.member_id, []).append((cut(r), u(r), max(r.offsets), True))
        if r.maintenance_type == "002":  # a member deleted anywhere in its file: none of its rows there gives coverage
            gone.setdefault(r.member_id, []).append(("", u(r), max(r.offsets), True))
        elif r.maintenance_type != "024":
            loops.setdefault((r.member_id, u(r)), set()).add(r.offsets[0])
    for m, later in carry.items():  # each applies to the rows of files before its own, as if filed after them
        for r in later:
            if "002" in (r.maintenance_type, r.coverage_type):
                gone.setdefault(m, []).append(("", u(r), max(r.offsets), True))
            elif cancel(r) or r.coverage_end or r.eligibility_end:  # never lengthens a span; an end alone never reaches its own file
                cuts.setdefault(m, []).append((cut(r), u(r), max(r.offsets), cancel(r)))
            if begin(r):  # a later begin moves the span's begin, never earlier
                floors.setdefault(m, []).append((begin(r), u(r), max(r.offsets), False))
    on = lambda r, kind: [(d, f, at) for d, f, at, own in kind.get(r.member_id, ()) if f[0] > u(r)[0] or own and f == u(r)]  # noqa: E731  a later file, or its own
    two = {k for k, at in loops.items() if len(at) > 1}
    ends = lambda r: [d for d, _, _ in on(r, cuts) if begin(r) <= d or not d]  # noqa: E731  in any order in its own file
    late = lambda r: any(begin(r) > d and (f != u(r) or at >= max(r.offsets)) for d, f, at in on(r, cuts))  # noqa: E731  cut before it, filed in or after its own loop
    floor = lambda r: max([begin(r), *(d for d, _, _ in on(r, floors))])  # noqa: E731
    stop = lambda r: min([r.coverage_end or "9999-12-31", r.eligibility_end or "9999-12-31", *ends(r)])  # noqa: E731
    taken: dict = {}  # each member's rows that may give a span
    for r in rows:
        taken.setdefault(r.member_id, []).append(r)
    spans = lambda m: [r for r in taken.get(m, ()) if r.subscriber == "Y" and begin(r)]  # noqa: E731
    moved = lambda c: any(begin(c) > begin(r) and u(r)[0] < u(c)[0] for r in spans(c.member_id))  # noqa: E731  its floor moved a span
    mine = lambda c: (cut(c), u(c), max(c.offsets))  # noqa: E731
    changed = lambda c: any(mine(c) in on(r, cuts) and (not cut(c) or cut(c) < begin(r) and (u(c) != u(r) or max(c.offsets) >= max(r.offsets))  # noqa: E731
                                                     or begin(r) <= cut(c) == stop(r) < min(r.coverage_end or "9999-12-31", r.eligibility_end or "9999-12-31"))
                            for r in spans(c.member_id))  # its cut ended a span earlier, or before it begins: an end at or after a span's end changes nothing
    replaced = lambda r: pick.get((r.member_id, r.plan), ("",))[0] > u(r)[0] or not r.plan and planned.get(r.member_id, "") > u(r)[0]  # noqa: E731
    undated = [(u(r), SetAside(m, "no_dates", 0, r.offsets[0])) for m, later in carry.items() for r in later  # a later plan row that changed nothing
               if r.plan and "002" not in (r.maintenance_type, r.coverage_type) and not (changed(r) or moved(r) or replaced(r))]
    end = lambda r: day(before(r.reinstatement_date)) if r.reinstatement_date else 99991231  # noqa: E731
    cause = lambda r: ("dependent_member" if r.subscriber == "N" else "member_quarantined" if r.member_id in hurt else "tied_files_disagree" if r.member_id in tied  # noqa: E731
                       else "deleted" if on(r, gone) or r.coverage_type == "002"
                       else "conflicting_rows" if (r.member_id, u(r)) in two else "bad_dates" if r.member_id in dead_after else "termination"
                       if "" in ends(r) or late(r) else "no_plan" if not r.plan else
                       ("" if cancel(r) else "no_dates") if not begin(r) else "bad_dates" if stop(r) < begin(r) else "")  # in one file a cancellation is applied as filed
    dated = x12.x12_date(provider_deaths[0].replace("-", "")) == provider_deaths[0]  # an as-of on no calendar day: no feed
    fine = lambda d: (x12.x12_date(d.replace("-", "")) or "9") <= provider_deaths[0]  # noqa: E731  a calendar day not after the as-of
    wrong = lambda r: r.reinstatement_date and r.reinstatement_date <= (r.exclusion_date or "0001-01-01")  # noqa: E731
    held = _by_name(exclusions)  # a spoiled field, or no exclusion type, keeps its row: its claims are held by name
    lost = [q for q in exclusions.quarantined if q.field is None and not (q.cause == "no_exclusion_type" and not q.detail)] if full else []  # a row that does not read
    future = [f for f in exclusions.findings if f.kind in ("excluded_after_as_of", "reinstated_after_as_of")] if full else []  # its dates cannot be trusted: held from 0001-01-01
    badnpi = {q.offset for q in exclusions.quarantined if q.field == "npi"}  # a row with no name has no NPI to hold it by, if its own did not read
    after, by_row = {f.offset for f in future}, {r.offset: r for r in exclusions.rows}
    named = {n for q in lost for n in _npis(q.detail)} | {r.npi for r in exclusions.rows if r.npi and r.offset in after}
    unread = any(not (_npis(q.detail) or _cells(q.detail)) and not (q.cause == "no_name" and q.offset not in badnpi) for q in lost)  # no provider to hold: the list is unverified, so every line is reviewed
    listed = {r.npi for r in exclusions.rows}
    items = [(u(r), SetAside(r.member_id, cause(r), 0, r.offsets[0])) for r in rows  # a row no longer in force gives none of these
             if cause(r) and not (cause(r) in ("no_dates", "no_plan", "termination", "deleted") and r.subscriber == "Y" and replaced(r))] + undated
    once = {(f, a.id, a.offset): a for f, a in items if a.cause == "no_dates"}  # one per member loop, however many plan loops it has
    left = (tuple(a for _, a in items if a.cause != "no_dates") + tuple(once.values()) +
            tuple(SetAside(f"interchange {isa} made {at}", "stale_roster", 0, isa) for at, _, isa in stale) +
            tuple(SetAside(f"interchange {isa} made {at}", "mixed_file_times", 0, isa) for at, _, isa in older) +
            tuple(SetAside(f"interchange {isa} made {at}", "empty_roster", 0, isa) for at, _, isa in empty if not stale) +  # one item
            tuple(SetAside(f"member loop {at}", "no_member_id", 0, at) for _, at in sorted(unnamed)) +  # one item each: its namesakes hold
            tuple(SetAside(n, "bad_npi" if not npi_ok(n) else "bad_as_of" if not dated else "bad_dates", 0, i)
                  for i, (n, d) in enumerate(provider_deaths[1]) if not (npi_ok(n) and dated and fine(d))) +
            tuple(SetAside(r.last_name or r.business_name, "bad_dates" if r.npi else "exclusion_npi_unreadable" if r.offset in held else "no_npi", 0, r.offset) for r in exclusions.rows if full and (not r.npi or wrong(r))) +
            tuple(SetAside(q.detail or f"row {q.offset}", q.cause if q.detail else "unreadable_row", 0, q.offset) for q in lost) +
            tuple(SetAside(by_row[f.offset].last_name or by_row[f.offset].business_name if f.offset in by_row else "",
                      "excluded_after_as_of" if f.kind == "excluded_after_as_of" else "reinstated_after_as_of", 0, f.offset) for f in future))
    return (today, (decider.feed("dmf", day(asof), [(mem[r.member_id], day(r.death_date)) for r in every if "" < r.death_date <= asof and r.subscriber == "Y"])
                    if not blind else absent,  # a provider row set aside for its dates holds: dead since 0001-01-01, excluded from then on
                    decider.feed("pdeath", day(provider_deaths[0]), [(ident(n.encode()), day(d) if fine(d) else 10101)
                                                                    for n, d in provider_deaths[1] if npi_ok(n)]) if dated else absent,
                    decider.feed("excl", day(exclusions.coverage.as_of), [(ident(r.npi.encode()), *((10101, 99991231) if wrong(r) or r.npi in named else
                                                                           (day(r.exclusion_date or "0001-01-01"), end(r))))
                                 for r in exclusions.rows if r.npi] + [(ident(n.encode()), 10101, 99991231) for n in sorted(named)
                                                                       if n not in listed]) if full and not unread else absent,
                    decider.feed("span", day(asof), [(mem[r.member_id], ident(r.plan.encode()) if len(r.plan.encode()) <= 20 else 0,
                                                      day(floor(r)), day(stop(r))) for r in rows if not cause(r) and begin(r) and floor(r) <= stop(r)])
                    if not (blind or empty or stale) else absent)), left  # a later begin past a span's end leaves no span: not enrolled


def open_host(deployment, tenant: str, floor_path, shards: Sequence, engine, ruleset_folder=None):
    """The tenant's authority over its ``shards`` and a rules worker on the pinned ``engine``, only once every deployment slot
    is authored: else ``SlotError`` ``slots_unauthored``, before any file is read or program launched (constitution XI.10).
    ``ruleset_folder``: the folder of the tenant's signed rule-set records, read before every batch
    (``TenantAuthority``); none, no records."""
    deployment.require_active()
    return (decider.TenantAuthority(deployment, tenant, floor_path, shards, ruleset_folder=ruleset_folder),
            decider.RulesWorker(engine))


def given(tokens: Sequence[bytes]) -> dict:
    """Each payment's outcome and reasons as its signed token says: ALLOW; ANSWERED with the token's reasons (an exact
    repeat of a paid line, answered at once and never paid); else HOLD whose reasons are in the first answer.  A payment
    with no token is absent: the caller holds it (never paid)."""
    why = ("held_in_first_answer",)
    said = {}
    for token in tokens:
        payment, outcome, reasons, _ = gate.read_token(token)
        said.setdefault(payment, {"ALLOW": ("ALLOW", ()), "ANSWERED": ("ANSWERED", reasons)}.get(outcome, ("HOLD", why)))
    return said


def decide_claims(requests: Sequence, read_set: tuple, host: tuple, shards: dict, flats: dict, grant: bytes,
                  keys, program: str, now: int) -> tuple[list, dict, list]:
    """Decide ``requests`` (``requests_of``) against ``read_set`` (``feeds``) on the shard each member routes to, at most
    ``MAX_BATCH`` a batch, each sealed at ``now`` before the next.  The shard count is the one the shards' key certificate
    names.  Two requests under one payment id (``request_malformed``), or ``shards`` other than every shard number below
    that count, all certified for it (``tenant_shards``), refuse the whole call before anything is decided.  Returns one
    row per line (payment id, line position, outcome, reasons: a batch the engine held whole holds each line with its
    cause, a request no grant entry covers each line with its payment's SCOPE outcome, an answered payment each line
    ANSWERED with its payment's reasons, an exact resend each payment's outcome read from the signed tokens it is given
    again: ALLOW, ANSWERED, or HOLD with ``held_in_first_answer``), the lines and cents per (outcome, reasons)
    (constitution XII), and each sealed batch's (signed checkpoint, token bytes, per token its earlier list, empty unless
    ANSWERED), a resend's as its sealing gave them.  Each shard's requests are sorted by payment id before batching, so the same requests in another order are
    that resend.  A resend that is re-enveloped or extended is another batch: its paid lines HOLD ALREADY_DECIDED, never paid
    twice.  When a batch fails, its error carries the commits sealed before it as ``sealed`` (empty when nothing was sealed):
    those stand, and sending the same requests again returns them."""
    rows, groups, sealed = [], {}, []
    try:
        if len({r.payment_id for r in requests}) != len(requests):  # never one kept and the other dropped
            raise decider.GateDecideError("request_malformed")
        tenant, worker = host
        count = {gate.key_cert_shards(p._cert) for p in shards.values()}
        if len(count) != 1 or set(shards) != set(range(*count)):  # never a caller's count or a subset of the shards
            raise decider.GateDecideError("tenant_shards")
        routed: dict = {}
        for r in requests:
            routed.setdefault(gate.shard_of(tenant.tenant, r.member_key, *count), []).append(r)
        for k, mine in sorted(routed.items()):
            mine.sort(key=lambda r: r.payment_id)
            for at in range(0, len(mine), gate.MAX_BATCH):
                batch = {r.payment_id: r for r in mine[at:at + gate.MAX_BATCH]}
                ans = decider.decide(read_set, read_set[0], shards[k], list(batch.values()), flats[k], worker, grant, keys, tenant,
                                     seal=(program, now))
                if ans.sealed:  # an exact resend of a sealed batch: given again what its commit gave
                    sealed.append(ans.sealed)
                elif ans.digest:
                    _, signed, tokens = decider.commit(shards[k], program, ans, now, tenant)
                    earlier = {y.payment_id: y.earlier for y in ans.pays}
                    sealed.append((signed, tuple(map(gate.encode_token, tokens)), tuple(earlier[t.leaf.payment_id] for t in tokens)))
                said = given(ans.sealed[1]) if ans.sealed else {}
                # each line takes its payment's outcome when no grant entry covers it (SCOPE: no records) or it was answered at once
                whole = {y.payment_id: y for y in ans.pays if "SCOPE" in y.reasons or y.outcome == "ANSWERED"}
                got = ([(p, i, *said.get(p, ("HOLD", ("held_in_first_answer",)))) for p, r in batch.items()
                        for i in range(len(r.lines))] if ans.sealed else
                       [(*ans.owners[x.index], x.outcome, x.reasons) for x in ans.recs if ans.owners[x.index][0] not in whole] +
                       [(p, i, y.outcome, y.reasons) for p, y in whole.items() for i in range(len(batch[p].lines))] +
                       [(p, i, "HOLD", (why,)) for p, _, why in map(str.split, ans.lines) for i in range(len(batch[p].lines))])
                for p, i, outcome, why in got:
                    rows.append((p, i, outcome, why))
                    n, cents = groups.get((outcome, why), (0, 0))
                    groups[outcome, why] = (n + 1, cents + int.from_bytes(batch[p].lines[i][-8:], "big"))  # a line's last 8 bytes: its cents
    except Exception as error:  # the commits before it stand; their tokens go with the error
        error.sealed = sealed
        raise
    return rows, groups, sealed
