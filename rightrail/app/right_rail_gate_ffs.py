"""Fee-for-service claims to gate decisions: 837 claim lines to decide requests (FFS_CLAIM), and 834, LEIE and provider
death rows to the frame's feeds, decided by the engine through right_rail_gate_decide.  No rule is here: the engine decides
every line.  A claim that cannot be sent whole is set aside with its cause and its cents, never guessed and never sent in
part, and the rest are decided."""

from __future__ import annotations

import bisect
import hashlib
from datetime import date, timedelta
from typing import NamedTuple, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_x12 as x12
from app.right_rail_reader_leie import npi_ok

_IDS = b"RR/GATE/FFS-ID/v1\x00"
_MEMBER = b"RR/GATE/MEMBER-KEY/v1\x00"
_IN_LOOP = frozenset(("bad_date", "bad_death_date", "repeated_segment", "empty_member_id", "bad_ins", "repeated_loop", "member_id_conflict",
                      "unknown_segment", "unread_segment"))  # an unread or unknown segment in a member loop may be one of its dates, misplaced or mistyped


def canonical_id(prefix: str, *parts: str) -> str:
    """``prefix`` and 32 hex digits of SHA3-256 over the length-prefixed ``parts``: the same claim always gets the same id."""
    return prefix + hashlib.sha3_256(_IDS + b"".join(len(p.encode()).to_bytes(2, "big") + p.encode() for p in parts)).hexdigest()[:32]


def member_key(secret: bytes, member_id: str) -> bytes:
    """The member's 32-byte key under the tenant's secret, from the member id that the 837 and the 834 both carry."""
    return hashlib.sha3_256(len(secret).to_bytes(2, "big") + secret + _MEMBER + member_id.encode()).digest()


class SetAside(NamedTuple):
    id: str  # the claim id (837), member id (834), NPI (provider death) or name (exclusion)
    cause: str  # 837: payment_id_conflict, retry, partial, total_mismatch, replacement_or_void, dependent_patient, bad_npi,
    # service_date, units or field; 834: dependent_member, member_quarantined, deleted, conflicting_rows, termination, no_plan, no_dates or bad_dates;
    # provider deaths: bad_npi, bad_as_of or bad_dates; exclusions: no_npi or bad_dates
    cents: int  # the claim's line charges; 0 for an 834 row
    offset: int  # its CLM (837) or INS (834) segment or exclusion row in the file; a provider death's position in its list


def requests_of(reads: Sequence, tenant: str, program: str, period: str, secret: bytes) -> tuple[tuple, tuple]:
    """One FFS_CLAIM request per original claim (frequency 1) in ``reads`` (right_rail_x12_837.Read837), and the claims set
    aside.  Its payment and command id come from the billing NPI and claim id, each line's from them and its line number, so a
    resubmitted claim is the same payment (decided once).  The member is the subscriber; payee the billing NPI; the amount the
    billed line charges; a line's procedure its code and sorted modifiers; the evidence the file's SHA3-512.  Claims under
    one payment id that are the same claim (every value, the reader's finding on its total included, but where and when
    the file was sent and modifier order) are one claim: the first is
    read, each later copy is a ``retry``; claims under one id that differ are each set aside as ``payment_id_conflict``.  A
    claim is sent whole or not at all: it is set aside when the reader set a line of it aside (``partial``) or its total is
    not its lines' sum (``total_mismatch``), it is a replacement or void, its patient is a dependent, a billing or rendering
    NPI is not ten digits with its check digit, a line's service is not one dated day or not a whole number of units above
    zero, or a field does not encode.  A later copy of a claim set aside is set aside with the first copy's cause."""
    ids: dict = {}
    found: dict = {}  # (read, CLM offset) -> the reader's finding on that claim's total
    for i, read in enumerate(reads):  # a file read twice is two copies of each claim: the second a retry, never merged lines
        for r in read.rows:  # payment id -> each claim (its read and CLM segment) under it -> the claim's lines
            ids.setdefault(canonical_id("C", r.billing_npi, r.claim_id), {}).setdefault((i, r.offsets[0]), []).append(r)
        found.update(((i, f.offset), f.cause) for f in read.findings)
    sent, aside = [], []
    for pid, claims in ids.items():
        alike = len({(found.get(at), *(r._replace(file_at="", file_sha3_512="", set_control="", offsets=(), modifiers=tuple(sorted(r.modifiers)))
                                       for r in c)) for at, c in claims.items()}) == 1
        first = None  # the first copy's cause, "" once it is sent: a later copy is a retry of a sent claim, else set aside as the first
        for n, (at, lines) in enumerate(claims.items()):
            c, cents, total = lines[0], sum(r.line_charge_cents for r in lines), found.get(at)
            cause = ("payment_id_conflict" if not alike else ("retry" if first == "" else first) if n else "partial" if total == "total_unchecked" else
                     "total_mismatch" if total == "total_mismatch" else "replacement_or_void" if c.frequency_code != "1" else
                     "dependent_patient" if c.dependent else "bad_npi" if not all(npi_ok(r.billing_npi) and npi_ok(r.rendering_npi) for r in lines)
                     else "service_date" if any(not r.service_begin or r.service_begin != r.service_end for r in lines)
                     else "units" if any(r.units_milli is None or r.units_milli <= 0 or r.units_milli % 1000 for r in lines) else "field")
            first = cause if first is None else first
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
                    first = ""
                    continue
                except gate.GateCodecError:
                    pass
            aside.append(SetAside(c.claim_id, cause, cents, c.offsets[0]))
    return tuple(sent), tuple(aside)


def ident(b: bytes) -> int:
    """The rules' identifier number (Rules/Request.lean idNat): 0x01, then the bytes, big-endian."""
    return int.from_bytes(b"\x01" + b, "big")


def feeds(today: int, enrollment, exclusions, provider_deaths: tuple[str, Sequence[tuple[str, str]]], secret: bytes) -> tuple[tuple, tuple]:
    """The frame's read set (``decider.request_frame``) on ``today``: member deaths and enrollment spans from an 834
    (right_rail_x12_834.Read834, as of its newest file time), exclusions from a full LEIE file (right_rail_reader_leie; a
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
    name loop naming another member, an unknown segment) sets every row of that member aside (``member_quarantined``); a fault outside every
    member loop (a voided set, group or interchange, a member with no identifier, a segment that does not read) may hide a
    cancellation or a death, so the member death and span feeds are absent and the engine reviews every line.  A provider death whose NPI is not ten
    digits with its check digit (``bad_npi``), every provider death when the list's as-of is no calendar day (``bad_as_of``:
    the feed is absent, so the engine reviews every line), and an exclusion with no valid NPI (``no_npi``, which no line can match) are
    set aside too.  So is a row whose dates would make its whole feed unusable to the engine (``bad_dates``): a death on no
    calendar day or after its feed's as-of date, a span that ends before it begins, an exclusion reinstated on or before
    its start.  A provider so set aside still holds every claim: it is sent dead since 0001-01-01, or excluded from then on
    with no end.  Returns the read set and the rows
    set aside."""
    day = lambda iso: int(iso.replace("-", ""))  # noqa: E731
    before = lambda iso: (date.fromisoformat(iso) - timedelta(1)).isoformat() if iso > "0001-01-01" else ""  # noqa: E731
    rows, absent, loops, cuts, gone = enrollment.rows, (bytes(77), b""), {}, {}, set()
    ins = {r.offsets[0]: r for r in rows}  # a member loop's row by its INS
    heads = sorted(ins.keys() | {q.offset for q in enrollment.quarantines if q.cause == "no_member_id"})  # every member loop's INS, named or not
    sets, hurt, blind = sorted(enrollment.sets), set(), not rows
    for q in enrollment.quarantines + enrollment.findings:  # each fault in a named member loop sets that member aside; any other may hide one
        i, s = bisect.bisect_right(heads, q.offset) - 1, bisect.bisect_right(sets, q.offset) - 1  # the nearest loop and set above it
        mine = q.cause in _IN_LOOP and i >= 0 and heads[i] in ins and (s < 0 or heads[i] > sets[s])  # that loop is in the fault's own set
        if mine and ins[heads[i]].subscriber != "N":  # a dependent's loop carries its subscriber's REF*0F and is set aside anyway
            hurt.add(ins[heads[i]].member_id)
        blind |= not mine
    full = exclusions.coverage is not None and exclusions.coverage.kind == "full"  # a supplement: no feed, so no row of it is used
    asof = max((r.file_at[:10] for r in rows), default="0000-00-00")
    mem = {r.member_id: ident(member_key(secret, r.member_id)) for r in rows}
    for r in (r for r in rows if r.subscriber == "Y"):  # a dependent carries its subscriber's REF*0F: never the subscriber's rows
        if "024" in (r.maintenance_type, r.coverage_type):  # "" (before every date): a cancellation with no date ends every span
            cuts.setdefault(r.member_id, []).append((min(filter(None, (r.coverage_end, r.eligibility_end, before(r.maintenance_effective))), default=""),
                                                     max(r.offsets)))
        if r.maintenance_type == "002":  # a member deleted anywhere in the file: none of its rows gives coverage
            gone.add(r.member_id)
        elif r.maintenance_type != "024":
            loops.setdefault(r.member_id, set()).add(r.offsets[0])
    two = {m for m, at in loops.items() if len(at) > 1}
    ends = lambda r: [on for on, _ in cuts.get(r.member_id, ()) if begin(r) <= on or not on]  # noqa: E731  in any file order
    late = lambda r: any(begin(r) > on and where >= max(r.offsets) for on, where in cuts.get(r.member_id, ()))  # noqa: E731  cut before it, filed in or after its own loop
    begin = lambda r: max(r.coverage_begin, r.eligibility_begin)  # noqa: E731  two sources: the later begin and the earlier end
    stop = lambda r: min([r.coverage_end or "9999-12-31", r.eligibility_end or "9999-12-31", *ends(r)])  # noqa: E731
    end = lambda r: day(before(r.reinstatement_date)) if r.reinstatement_date else 99991231  # noqa: E731
    cause = lambda r: ("dependent_member" if r.subscriber == "N" else "member_quarantined" if r.member_id in hurt else "deleted" if r.member_id in gone or r.coverage_type == "002"  # noqa: E731
                       else "conflicting_rows" if r.member_id in two else "bad_dates" if r.death_date > asof else "termination"
                       if "" in ends(r) or late(r) else "no_plan" if not r.plan else
                       "no_dates" if not begin(r) else "bad_dates" if stop(r) < begin(r) else "")
    dated = x12.x12_date(provider_deaths[0].replace("-", "")) == provider_deaths[0]  # an as-of on no calendar day: no feed
    fine = lambda d: (x12.x12_date(d.replace("-", "")) or "9") <= provider_deaths[0]  # noqa: E731  a calendar day not after the as-of
    wrong = lambda r: r.reinstatement_date and r.reinstatement_date <= (r.exclusion_date or "0001-01-01")  # noqa: E731
    left = (tuple(SetAside(r.member_id, cause(r), 0, r.offsets[0]) for r in rows if cause(r)) +
            tuple(SetAside(n, "bad_npi" if not npi_ok(n) else "bad_as_of" if not dated else "bad_dates", 0, i)
                  for i, (n, d) in enumerate(provider_deaths[1]) if not (npi_ok(n) and dated and fine(d))) +
            tuple(SetAside(r.last_name or r.business_name, "bad_dates" if r.npi else "no_npi", 0, r.offset) for r in exclusions.rows if full and (not r.npi or wrong(r))))
    return (today, (decider.feed("dmf", day(asof), [(mem[r.member_id], day(r.death_date)) for r in rows if "" < r.death_date <= asof and r.subscriber == "Y"])
                    if not blind else absent,  # a provider row set aside for its dates holds: dead since 0001-01-01, excluded from then on
                    decider.feed("pdeath", day(provider_deaths[0]), [(ident(n.encode()), day(d) if fine(d) else 10101)
                                                                    for n, d in provider_deaths[1] if npi_ok(n)]) if dated else absent,
                    decider.feed("excl", day(exclusions.coverage.as_of), [(ident(r.npi.encode()), *((10101, 99991231) if wrong(r) else
                                                                           (day(r.exclusion_date or "0001-01-01"), end(r))))
                                 for r in exclusions.rows if r.npi]) if full else absent,
                    decider.feed("span", day(asof), [(mem[r.member_id], ident(r.plan.encode()) if len(r.plan.encode()) <= 20 else 0,
                                                      day(begin(r)), day(stop(r))) for r in rows if not cause(r)]) if not blind else absent)), left


def open_host(deployment, tenant: str, floor_path, shards: Sequence, engine):
    """The tenant's authority over its ``shards`` and a rules worker on the pinned ``engine``, only once every deployment slot
    is authored: else ``SlotError`` ``slots_unauthored``, before any file is read or program launched (constitution XI.10)."""
    deployment.require_active()
    return decider.TenantAuthority(deployment, tenant, floor_path, shards), decider.RulesWorker(engine)


def given(tokens: Sequence[bytes]) -> dict:
    """Each payment's outcome and reasons as its signed token says: ALLOW, else HOLD whose reasons are in the first answer.
    A payment with no token is absent: the caller holds it (never paid)."""
    why = ("held_in_first_answer",)
    said = {}
    for token in tokens:
        at = len(gate.TOKEN)
        for _ in range(2):  # tenant, program
            at += 2 + int.from_bytes(token[at : at + 2], "big")
        at += 4 + 1 + 8  # shard, flow, revision
        end = at + 2 + int.from_bytes(token[at : at + 2], "big")
        payment = token[at + 2 : end].decode("ascii")
        at = end + gate.MEMBER_KEY
        at += 2 + int.from_bytes(token[at : at + 2], "big") + 8  # payee, amount
        at += 2 + int.from_bytes(token[at : at + 2], "big") + gate.DIGEST  # period, lines root
        said.setdefault(payment, ("ALLOW", ()) if gate.OUTCOMES[token[at] - 1] == "ALLOW" else ("HOLD", why))
    return said


def decide_claims(requests: Sequence, read_set: tuple, host: tuple, shards: dict, flats: dict, grant: bytes,
                  keys, program: str, now: int) -> tuple[list, dict, list]:
    """Decide ``requests`` (``requests_of``) against ``read_set`` (``feeds``) on the shard each member routes to, at most
    ``MAX_BATCH`` a batch, each sealed at ``now`` before the next.  The shard count is the one the shards' key certificate
    names.  Two requests under one payment id (``request_malformed``), or ``shards`` other than every shard number below
    that count, all certified for it (``tenant_shards``), refuse the whole call before anything is decided.  Returns one
    row per line (payment id, line position, outcome, reasons: a batch the engine held whole holds each line with its
    cause, a request no grant entry covers each line with its payment's SCOPE outcome, an exact resend each payment's outcome
    read from the signed tokens it is given again: ALLOW, or HOLD with ``held_in_first_answer``), the lines and cents per
    (outcome, reasons) (constitution XIV), and each sealed batch's (signed checkpoint, token bytes), a resend's as its sealing
    gave them.  Each shard's requests are sorted by payment id before batching, so the same requests in another order are
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
                    sealed.append((signed, tuple(map(gate.encode_token, tokens))))
                said = given(ans.sealed[1]) if ans.sealed else {}
                got = ([(p, i, *said.get(p, ("HOLD", ("held_in_first_answer",)))) for p, r in batch.items()
                        for i in range(len(r.lines))] if ans.sealed else
                       [(*ans.owners[x.index], x.outcome, x.reasons) for x in ans.recs] +
                       [(y.payment_id, i, y.outcome, y.reasons) for y in ans.pays if "SCOPE" in y.reasons  # no grant entry covers it: no records
                        for i in range(len(batch[y.payment_id].lines))] +
                       [(p, i, "HOLD", (why,)) for p, _, why in map(str.split, ans.lines) for i in range(len(batch[p].lines))])
                for p, i, outcome, why in got:
                    rows.append((p, i, outcome, why))
                    n, cents = groups.get((outcome, why), (0, 0))
                    groups[outcome, why] = (n + 1, cents + int.from_bytes(batch[p].lines[i][-8:], "big"))  # a line's last 8 bytes: its cents
    except Exception as error:  # the commits before it stand; their tokens go with the error
        error.sealed = sealed
        raise
    return rows, groups, sealed
