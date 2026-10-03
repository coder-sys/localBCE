"""Mutation check of the gate rules (test-only).

The lean tree is copied to a temporary directory; each mutant weakens one
check in the copy's ``BlindLedger/Gate/Rules/Fast.lean`` (the code the runner
executes), in ``Spec.lean`` for the functions Fast shares with it (dates,
snapshot age, keys, spans, review, order), or, for the runner's commit,
``Run.lean``.  It rebuilds ``gate_rules`` and must make ``rules_v1.vectors``
FAIL.  Each demo mutant mislabels lines of the demo file and must FAIL against
the unmutated rules.  The tracked tree is never written; the hashes of its
Spec.lean, Fast.lean and Run.lean are checked before and after.  The optional
``start:stop`` slices the Spec, Fast, Run mutant list, for batches.
Run only under the guard:
``python tools/gate_rules_mutants.py <lean dir> <rules vectors> <demo vectors> <lake.exe> [start:stop]``.
An ``old``/``new`` that is a tuple makes several edits at once, each ``old`` occurring once.
"""

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

EXACT_KEY = "[if isCap l then 3 else 1, l.member, l.payee, l.date, l.proc, l.units, l.cents]"
NEAR_KEY = "[2, l.member, l.rendering, l.date, l.proc]"
CAP_KEY = "[0, l.member, l.date / 100]"
KEYS = "[exactKey l, nearKey l, idKey l]"
REVIEW = ("| .COLLIDES_WITH_UNRESOLVED_NEAR | .FFS_NEAR_DUPLICATE | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID\n"
          "  | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH | .STALE_RELEASED\n"
          "  | .STALE_UNRESOLVED | .MEMBER_DECEASED_UNVERIFIED | .MEMBER_NOT_ENROLLED_UNVERIFIED\n"
          "  | .PROVIDER_DECEASED_UNVERIFIED | .PROVIDER_EXCLUDED_UNVERIFIED | .FFS_DUPLICATE_UNVERIFIED => true")
# A mutant the vectors miss is still killed if these proofs no longer build: the Spec's order independence
# (the runner no longer re-decides each batch in reverse) and the twin's equality with the Spec.
PROOFS = ("BlindLedger.Gate.Rules.Theorems", "BlindLedger.Gate.Rules.FastEq")
PROOF_FILES = ("Theorems.lean", "FastEq.lean")
KEPT = "d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED"
# Fast.lean text.
R2 = "x.seen s (exactKey l) || x.seen s (nearKey l) || x.spanOk && validDate l.date && x.overlap l"
OVERLAP = "max first (max s.start t.start) ≤ min last (min s.stop t.stop)"
CHAINED = ("| some s => s.entries.length == s.count && validDate s.asOf && s.asOf ≤ today && prior.asOf ≤ s.asOf &&\n"
           "      prior.entries.all (HashSet.ofList s.entries).contains")
REL_ROW = "released := ⟨x.relV.asOf, x.relN + ra.length, x.relV.entries ++ ra⟩,"
UNR_ROW = "unresolved := ⟨x.unrV.asOf, x.unrN + ua.length, x.unrV.entries ++ ua⟩ }"
# `Ix.run` and `Ix.runIn` share their last lines: the same six mutants anchor on the whole of each body.
BODY = ("let ds := x.decideAll %s(x.order b)\n  let ra := x.releasedLines ds\n"
        "  let ua := x.unresolvedLines ds\n  { decisions := ds, " + REL_ROW + "\n    " + UNR_ROW)
RUN = "def Ix.run (x : Ix) (b : List Line) : Result :=\n  " + BODY % "∅ "
RUNIN = BODY % "(HashSet.ofList (idSeen f)) "


def edit(base, *edits):
    new = base
    for old, repl in edits:
        assert old in new, old
        new = new.replace(old, repl)
    return base, new


def runin(*edits):
    return edit(RUNIN, *edits)


LOOSE_KEYS = "HashSet.ofList ((ra.drop rv.entries.length ++ ua.drop uv.entries.length).map exactKey)"
FFS_UNVERIFIED = "| .FFS_DUPLICATE_UNVERIFIED => !isCap l && x.looseKeys.contains (exactKey l)"
# The four snapshot checks: tag, the fact each fires on.
CHECKS = (("dmf", "x.memberDead l"), ("pd", "x.providerDead l"), ("excl", "x.excluded l"), ("span", "!x.enrolled l"))


def unverified_rows(row):
    """One edit per snapshot check of its UNVERIFIED row: `row(tag, fact)` is the new text."""
    old = tuple(f"x.{t}Some && !x.{t}Ok && validDate l.date && {f}" for t, f in CHECKS)
    return old, tuple(row(t, f) for t, f in CHECKS)


SPEC = [
    ("R2 key is the day", CAP_KEY, "[0, l.member, l.date]"),
    ("R2 key without member", CAP_KEY, "[0, l.date / 100]"),
    ("R2 key without year", CAP_KEY, "[0, l.member, l.date / 100 % 100]"),
    ("no near keys claimed", KEYS, "[exactKey l, idKey l]"),
    ("no identities claimed", KEYS, "[exactKey l, nearKey l]"),
    ("CAP_820 line claims an FFS near key", KEYS, "[exactKey l, nearKey l, idKey l, [2, l.member, l.rendering, l.date, l.proc]]"),
    ("R5 any member", "s.member == l.member && s.start", "s.start"),
    ("R5 span start", "s.start ≤ l.date && ", ""),
    ("R5 span stop", " && l.date ≤ s.stop", ""),
    ("R5 any plan", "(!isCap l || s.plan == l.payee)", "true"),
    ("R5 plan on FFS too", "!isCap l || s.plan", "s.plan"),
    ("R5 plan is the rendering party", "s.plan == l.payee", "s.plan == l.rendering"),
    ("year 0 valid", "0 < y && ", ""),
    ("year 10000 valid", "y ≤ 9999 && ", ""),
    ("month 0 valid", "0 < m && ", ""),
    ("month 13 valid", "m ≤ 12 && ", ""),
    ("month 12 invalid", "m ≤ 12 && ", "m < 12 && "),
    ("day 0 valid", "0 < d % 100 && ", ""),
    ("any day valid", " && d % 100 ≤ monthDays y m", ""),
    ("last day invalid", "d % 100 ≤ monthDays y m", "d % 100 < monthDays y m"),
    ("30-day months have 31", "m == 4 || m == 6 || m == 9 || m == 11", "false"),
    ("31-day months have 30", "then 30 else 31", "then 30 else 30"),
    ("February has 29 days", "(if leap y then 29 else 28)", "29"),
    ("no leap years", "y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)", "false"),
    ("every fourth year leap", "y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)", "y % 4 == 0"),
    ("no 400-year leap", "(y % 100 != 0 || y % 400 == 0)", "y % 100 != 0"),
    ("missing snapshot usable", "| none => false\n  | some s => validDate today", "| none => true\n  | some s => validDate today"),
    ("invalid today usable", "validDate today && validDate s.asOf", "validDate s.asOf"),
    ("invalid asOf usable", "validDate today && validDate s.asOf && ", "validDate today && "),
    ("future snapshot usable", "s.asOf ≤ today &&\n      dayNum", "\n      dayNum"),
    ("snapshot dated today unusable", "s.asOf ≤ today &&\n      dayNum", "s.asOf < today &&\n      dayNum"),
    ("declared count unchecked", "s.entries.length == s.count && 0 < s.count", "0 < s.count"),
    ("empty snapshot usable", " && 0 < s.count", ""),
    ("rows unchecked", "s.entries.all (ok s.asOf)", "true"),
    ("rows checked against today", "s.entries.all (ok s.asOf)", "s.entries.all (ok today)"),
    ("death date validity unchecked", "validDate d.date && d.date ≤ asOf", "d.date ≤ asOf"),
    ("death after the snapshot accepted", " && d.date ≤ asOf", ""),
    ("death on the snapshot date rejected", "d.date ≤ asOf", "d.date < asOf"),
    ("exclusion start unchecked", "validDate e.start && ", ""),
    ("exclusion stop unchecked", "validDate e.stop && ", ""),
    ("exclusion order unchecked", " && e.start ≤ e.stop", ""),
    ("span start unchecked", "validDate s.start && ", ""),
    ("span stop unchecked", "validDate s.stop && ", ""),
    ("span order unchecked", " && s.start ≤ s.stop", ""),
    ("day count without leap days", "y * 365 + y / 4 - y / 100", "y * 365 - y / 100"),
    ("day count without century rule", "- y / 100 + y / 400", "+ y / 400"),
    ("day count without 400-year rule", "- y / 100 + y / 400", "- y / 100"),
    ("review outranks HOLD", "if rs.any (!review ·) then .HOLD else .HUMAN_REVIEW",
     "if rs.any review then .HUMAN_REVIEW else .HOLD"),
    ("review is HOLD", "if rs.any (!review ·) then .HOLD", "if true then .HOLD"),
    ("HOLD reasons reviewed", "  | _ => false", "  | _ => true"),
    ("near duplicate is HOLD", REVIEW, REVIEW.replace("| .FFS_NEAR_DUPLICATE ", "")),
    ("future service date is HOLD", REVIEW, REVIEW.replace("| .SERVICE_DATE_FUTURE ", "")),
    ("invalid service date is HOLD", REVIEW, REVIEW.replace(" | .SERVICE_DATE_INVALID", "")),
    ("stale released set is HOLD", REVIEW, REVIEW.replace(" | .STALE_RELEASED", "")),
    ("stale unresolved set is HOLD", REVIEW, REVIEW.replace("\n  | .STALE_UNRESOLVED", "")),
    ("near collision is HOLD", REVIEW, REVIEW.replace("| .COLLIDES_WITH_UNRESOLVED_NEAR ", "")),
    ("unverified member death is HOLD", REVIEW, REVIEW.replace(" | .MEMBER_DECEASED_UNVERIFIED", "")),
    ("unverified enrollment is HOLD", REVIEW, REVIEW.replace(" | .MEMBER_NOT_ENROLLED_UNVERIFIED", "")),
    ("unverified provider death is HOLD", REVIEW, REVIEW.replace("| .PROVIDER_DECEASED_UNVERIFIED ", "")),
    ("unverified exclusion is HOLD", REVIEW, REVIEW.replace(" | .PROVIDER_EXCLUDED_UNVERIFIED", "")),
    ("duplicate of unresolved is review", REVIEW, "| .DUPLICATE_OF_UNRESOLVED " + REVIEW),
    ("already decided is review", REVIEW, "| .ALREADY_DECIDED " + REVIEW),
    ("unverified duplicate is HOLD", REVIEW, REVIEW.replace(" | .FFS_DUPLICATE_UNVERIFIED", "")),
    ("arrival order", "batch.mergeSort lineLe", "batch"),
    ("canonical order without identity", "l.cents, l.id, l.pay]", "l.cents]"),
] + [(f"exact key without {f}", EXACT_KEY, EXACT_KEY.replace(f", l.{f}", ""))
     for f in ("member", "payee", "date", "proc", "units", "cents")] + [
    (f"near key without {f}", NEAR_KEY, NEAR_KEY.replace(f", l.{f}", ""))
     for f in ("member", "rendering", "date", "proc")]

CERTAIN = ("=> x.dmfOk && validDate l.date && x.memberDead l", "=> x.pdOk && validDate l.date && x.providerDead l",
           "=> x.exclOk && validDate l.date && x.excluded l", "Bool := x.spanOk && validDate l.date && !x.enrolled l",
           "|| x.spanOk && validDate l.date && x.overlap l")
FAST = [
    ("R1 off", "(x.dmf.getD l.member []).any (·.date < l.date)", "false"),
    ("R1 death on the service date", "(x.dmf.getD l.member []).any (·.date < l.date)",
     "(x.dmf.getD l.member []).any (·.date ≤ l.date)"),
    ("R1 any member", ("dmf := group (·.id) (entries c.dmf)", "(x.dmf.getD l.member [])"),
     ("dmf := group (fun _ => 0) (entries c.dmf)", "(x.dmf.getD 0 [])")),
    ("R1 on an unusable DMF", "=> x.dmfOk && validDate l.date && x.memberDead l", "=> x.memberDead l"),
    ("R1 unverified off", "=> x.dmfSome && !x.dmfOk && validDate l.date && x.memberDead l", "=> false"),
    ("R2 off", "isCap l &&\n      (" + R2 + ")", "false"),
    ("R2 released or earlier lines ignored", R2, "x.spanOk && validDate l.date && x.overlap l"),
    ("R2 exact key ignored", "(x.seen s (exactKey l) || ", "("),
    ("R2 member-month ignored", " || x.seen s (nearKey l) || ", " || "),
    ("R2 overlapping plans ignored", " || x.spanOk && validDate l.date && x.overlap l", ""),
    ("R2 overlap on an unusable enrollment", "|| x.spanOk && validDate l.date && x.overlap l", "|| x.overlap l"),
    ("R2 also on FFS", "| .CAP_MEMBER_MONTH_DUPLICATE => isCap l &&", "| .CAP_MEMBER_MONTH_DUPLICATE =>"),
    ("overlap within one plan", "s.plan != t.plan && ", ""),
    ("overlap across members", "let ss := x.span.getD l.member []",
     "let ss := x.span.getD l.member [] ++ x.span.getD (l.member + 1) []"),
    ("overlap needs two days", OVERLAP, OVERLAP.replace("≤", "<")),
    ("overlap month is 28 days", "+ monthDays (l.date / 10000) (l.date / 100 % 100)", "+ 28"),
    ("overlap ignores span starts", "max first (max s.start t.start)", "first"),
    ("overlap ignores span stops", "min last (min s.stop t.stop)", "last"),
    ("R3 exclusion off", "(x.excl.getD l.payee []).any inForce || (x.excl.getD l.rendering []).any inForce", "false"),
    ("R3 exclusion start exclusive", "e.start ≤ l.date", "e.start < l.date"),
    ("R3 exclusion stop exclusive", "l.date ≤ e.stop", "l.date < e.stop"),
    ("R3 exclusion on an unusable snapshot", "=> x.exclOk && validDate l.date && x.excluded l", "=> x.excluded l"),
    ("R3 exclusion unverified off", "=> x.exclSome && !x.exclOk && validDate l.date && x.excluded l", "=> false"),
    ("R3 provider death off",
     "(x.pdeath.getD l.payee []).any (·.date < l.date) || (x.pdeath.getD l.rendering []).any (·.date < l.date)", "false"),
    ("R3 provider death on the service date",
     ("(x.pdeath.getD l.payee []).any (·.date < l.date)", "(x.pdeath.getD l.rendering []).any (·.date < l.date)"),
     ("(x.pdeath.getD l.payee []).any (·.date ≤ l.date)", "(x.pdeath.getD l.rendering []).any (·.date ≤ l.date)")),
    ("R3 provider death on an unusable list", "=> x.pdOk && validDate l.date && x.providerDead l", "=> x.providerDead l"),
    ("R3 provider death unverified off", "=> x.pdSome && !x.pdOk && validDate l.date && x.providerDead l", "=> false"),
    ("R3 payee only", (" || (x.pdeath.getD l.rendering []).any (·.date < l.date)",
                      " || (x.excl.getD l.rendering []).any inForce"), ("", "")),
    ("R3 rendering only", ("(x.pdeath.getD l.payee []).any (·.date < l.date) || ",
                          "(x.excl.getD l.payee []).any inForce || "), ("", "")),
    ("R4 off", "| .FFS_DUPLICATE_LINE => !isCap l && x.seen s (exactKey l)", "| .FFS_DUPLICATE_LINE => false"),
    ("R4 also on CAP_820", "| .FFS_DUPLICATE_LINE => !isCap l && ", "| .FFS_DUPLICATE_LINE => "),
    ("near duplicate off", "!isCap l && x.seen s (nearKey l) && !x.seen s (exactKey l)", "false"),
    ("near duplicate also on exact duplicates", " && !x.seen s (exactKey l)", ""),
    ("near duplicate also on CAP_820", "!isCap l && x.seen s (nearKey l)", "x.seen s (nearKey l)"),
    ("R5 off", "| .MEMBER_NOT_ENROLLED => x.notEnrolled l", "| .MEMBER_NOT_ENROLLED => false"),
    ("R5 unverified off", "=> x.spanSome && !x.spanOk && validDate l.date && !x.enrolled l", "=> false"),
    ("R5 on an unusable enrollment", "Bool := x.spanOk && validDate l.date && !x.enrolled l", "Bool := !x.enrolled l"),
    ("checks on an invalid service date", CERTAIN, tuple(o.replace("validDate l.date && ", "") for o in CERTAIN)),
    ("unverified on usable snapshots", *unverified_rows(lambda t, f: f"x.{t}Some && validDate l.date && {f}")),
    ("unverified on missing snapshots", *unverified_rows(lambda t, f: f"!x.{t}Ok && validDate l.date && {f}")),
    ("unverified on an invalid service date", *unverified_rows(lambda t, f: f"x.{t}Some && !x.{t}Ok && {f}")),
    ("not-enrolled FFS lines claim nothing", "if isCap l && x.notEnrolled l && !x.own l then [exactKey l, idKey l] else keys l",
     "if x.notEnrolled l && !x.own l then (if isCap l then [exactKey l, idKey l] else []) else keys l"),
    ("not-enrolled CAP_820 line claims the member-month",
     "if isCap l && x.notEnrolled l && !x.own l then [exactKey l, idKey l] else keys l", "keys l"),
    ("not-enrolled CAP_820 line claims no exact key", "then [exactKey l, idKey l] else", "then [idKey l] else"),
    ("CAP_820 line on an unusable enrollment claims no member-month", "if isCap l && x.notEnrolled l",
     "if isCap l && !x.enrolled l"),
    ("held lines claim nothing", "x.decideAll (s.insertMany (x.claim l)) ls",
     "x.decideAll (if (x.decideLine s l).outcome == .ALLOW then s.insertMany (x.claim l) else s) ls"),
    ("earlier lines unseen", "x.decideAll (s.insertMany (x.claim l)) ls", "x.decideAll s ls"),
    ("released set unread",
     "(x.relPost.getD k []).any fun i => i < x.relN && x.rel[i]?.any fun y => !(x.own y && x.batch.contains y)", "false"),
    ("released near keys ignored", "def Ix.seen0 (x : Ix) (k : Key) : Bool :=\n  ",
     "def Ix.seen0 (x : Ix) (k : Key) : Bool :=\n  k.head? != some 0 && k.head? != some 2 && "),
    ("released identities ignored", "def Ix.seen0 (x : Ix) (k : Key) : Bool :=\n  ",
     "def Ix.seen0 (x : Ix) (k : Key) : Bool :=\n  k.head? != some 4 && "),
    ("re-decided lines seen", "fun y => !(x.own y && x.batch.contains y)", "fun y => true"),
    ("released lines outside the batch unseen", "!(x.own y && x.batch.contains y)", "!x.own y"),
    ("re-decided lines not first", "canonical (b.filter x.own) ++ canonical (b.filter fun y => !x.own y)", "canonical b"),
    ("re-decided capitation line claims no member-month", "x.notEnrolled l && !x.own l", "x.notEnrolled l"),
    ("re-decided lines unresolved", " && !x.own d.line", ""),
    ("nothing released", *runin(("let ra := x.releasedLines ds", "let ra : List Line := []"))),
    ("held lines released", *runin(("let ra := x.releasedLines ds", "let ra := ds.map (·.line)"))),
    ("held payment's ALLOW lines released", " && x.payOutcome ds l.pay == .ALLOW", ""),
    ("re-decision released again", "!x.redo.contains l.pay && x.payOutcome", "x.payOutcome"),
    ("payment HOLD ignored", "if ls.any (·.outcome == .HOLD) then .HOLD\n  else ", ""),
    ("payment without a line ALLOW", "!ls.isEmpty && ", ""),
    ("re-decision of an unreleased line ALLOW", "(!x.redo.contains p || x.own d.line)", "true"),
    ("checkpoint drops the batch's additions", *runin((REL_ROW, "released := x.relV,"), (UNR_ROW, "unresolved := x.unrV }"))),
    ("checkpoint advances only when chained",
     *runin((REL_ROW, REL_ROW.replace("released := ", "released := if !x.relChained then x.relV else ")),
            (UNR_ROW, UNR_ROW.replace("unresolved := ", "unresolved := if !x.unrChained then x.unrV else ")))),
    ("checkpoint forgets the view's rows",
     *runin((REL_ROW, "released := ⟨x.relV.asOf, ra.length, ra⟩,"), (UNR_ROW, "unresolved := ⟨x.unrV.asOf, ua.length, ua⟩ }"))),
    ("unchained set read as is", "if ch then o.getD prior else prior", "o.getD prior"),
    ("set read ignored", "if ch then o.getD prior else prior", "prior"),
    ("reviewed payments ALLOW", "d.outcome == .ALLOW && (", "d.outcome != .HOLD && ("),
    ("service date validity off", "| .SERVICE_DATE_INVALID => !validDate l.date", "| .SERVICE_DATE_INVALID => false"),
    ("future service date off", "| .SERVICE_DATE_FUTURE => x.today < l.date", "| .SERVICE_DATE_FUTURE => false"),
    ("service date today is future", "x.today < l.date", "x.today ≤ l.date"),
    ("DMF 89 days", "usable c.today 90 okDeath c.dmf", "usable c.today 89 okDeath c.dmf"),
    ("DMF 91 days", "usable c.today 90 okDeath c.dmf", "usable c.today 91 okDeath c.dmf"),
    ("provider deaths 89 days", "usable c.today 90 okDeath c.providerDeaths", "usable c.today 89 okDeath c.providerDeaths"),
    ("provider deaths 91 days", "usable c.today 90 okDeath c.providerDeaths", "usable c.today 91 okDeath c.providerDeaths"),
    ("exclusions 30 days", "usable c.today 31 okExclusion", "usable c.today 30 okExclusion"),
    ("exclusions 32 days", "usable c.today 31 okExclusion", "usable c.today 32 okExclusion"),
    ("enrollment 6 days", "usable c.today 7 okSpan", "usable c.today 6 okSpan"),
    ("enrollment 8 days", "usable c.today 7 okSpan", "usable c.today 8 okSpan"),
    ("set count unchecked", "s.entries.length == s.count && validDate s.asOf", "validDate s.asOf"),
    ("missing set chained", "| none => false\n  | some s => s.entries", "| none => true\n  | some s => s.entries"),
    ("set asOf validity unchecked", CHAINED, CHAINED.replace("validDate s.asOf && ", "")),
    ("set dated after today", CHAINED, CHAINED.replace("s.asOf ≤ today && ", "")),
    ("set dated before the checkpoint", CHAINED, CHAINED.replace("prior.asOf ≤ s.asOf &&\n      ", "")),
    ("set need not extend the checkpoint", CHAINED,
     CHAINED.replace(" &&\n      prior.entries.all (HashSet.ofList s.entries).contains", "")),
    ("released set unchecked", "| .STALE_RELEASED => !x.relChained", "| .STALE_RELEASED => false"),
    ("unresolved set unchecked", "| .STALE_UNRESOLVED => !x.unrChained", "| .STALE_UNRESOLVED => false"),
    ("checkpoints swapped", "chainedF c.today c.releasedPrior c.released", "chainedF c.today c.unresolvedPrior c.released"),
    ("already decided off", "| .ALREADY_DECIDED => x.seen s (idKey l) || x.pending (idKey l)", "| .ALREADY_DECIDED => false"),
    ("already decided ignores the batch and released set", "x.seen s (idKey l) || x.pending", "x.pending"),
    ("already decided ignores the unresolved set", " || x.pending (idKey l)", ""),
    ("duplicate of unresolved off",
     "| .DUPLICATE_OF_UNRESOLVED => x.pending (exactKey l) || isCap l && x.pending (nearKey l)",
     "| .DUPLICATE_OF_UNRESOLVED => false"),
    ("unresolved member-month ignored", " || isCap l && x.pending (nearKey l)", ""),
    ("near collision off", "!isCap l && x.pending (nearKey l) && !x.pending (exactKey l)", "false"),
    ("near collision also on exact collisions", " && !x.pending (exactKey l)", ""),
    ("near collision also on CAP_820", "!isCap l && x.pending (nearKey l)", "x.pending (nearKey l)"),
    ("unresolved set unread",
     "(x.unrPost.getD k []).any fun i => i < x.unrN && x.unr[i]?.any fun y => (x.claim y).contains k", "false"),
    ("unresolved near keys ignored", "fun y => (x.claim y).contains k", "fun y => ((x.claim y).filter (· != nearKey y)).contains k"),
    ("no counterparts", "counterparts := x.counterparts l", "counterparts := []"),
    ("no released counterparts", "hits x.rel x.relPost (keys l) (fun _ => true) ++\n    ", ""),
    ("every unresolved line a counterpart", "fun y => (keys l).any (x.claim y).contains", "fun _ => true"),
    ("released counterparts by claim", "hits x.rel x.relPost (keys l) (fun _ => true)",
     "hits x.rel x.relPost (keys l) (fun y => (keys l).any (x.claim y).contains)"),
    ("no loose released counterparts", "let ra := rv.entries ++ looseF rc c.releasedPrior c.released", "let ra := rv.entries"),
    ("no loose unresolved counterparts", "let ua := uv.entries ++ looseF uc c.unresolvedPrior c.unresolved", "let ua := uv.entries"),
    ("unverified duplicate off", FFS_UNVERIFIED, "| .FFS_DUPLICATE_UNVERIFIED => false"),
    ("unverified duplicate on capitation lines", FFS_UNVERIFIED, FFS_UNVERIFIED.replace("!isCap l && ", "")),
    ("unverified duplicate by near key", FFS_UNVERIFIED, FFS_UNVERIFIED.replace("(exactKey l)", "(nearKey l)")),
    ("chained rows loose", "if ch then [] else\n    let p := HashSet.ofList prior.entries\n    (entries o)",
     "let p := HashSet.ofList prior.entries\n  (entries o)"),
    ("loose rows of the released set ignored", LOOSE_KEYS, "HashSet.ofList ((ua.drop uv.entries.length).map exactKey)"),
    ("loose rows of the unresolved set ignored", LOOSE_KEYS, "HashSet.ofList ((ra.drop rv.entries.length).map exactKey)"),
    ("gate leaves nothing unresolved", *runin(("let ua := x.unresolvedLines ds", "let ua : List Line := []"))),
    ("not-enrolled lines left out of the unresolved set", KEPT, KEPT + " && !d.reasons.contains .MEMBER_NOT_ENROLLED"),
    ("already decided lines unresolved", KEPT, "d.outcome != .ALLOW"),
    ("ALLOW lines unresolved", KEPT, "!d.reasons.contains .ALREADY_DECIDED"),
]

# The runner's commit, which carries each batch's additions and checkpoints to the next.
RUN_MUTANTS = [
    ("commit drops the released store's length", "r.released.entries.drop x.relN", "r.released.entries.drop (x.relN + 1)"),
    ("commit drops the unresolved store's length", "r.unresolved.entries.drop x.unrN",
     "r.unresolved.entries.drop (x.unrN + 1)"),
    ("commit adds nothing released", "extra := st.extra ++ r.released.entries.drop", "extra := st.extra ++ [].drop"),
    ("commit adds nothing unresolved", "held := st.held ++ r.unresolved.entries.drop", "held := st.held ++ [].drop"),
    ("commit adds every released line", "st.extra ++ r.released.entries.drop x.relN", "st.extra ++ r.released.entries"),
    ("commit keeps the released checkpoint", "rprior := r.released", "rprior := st.rprior"),
    ("commit keeps the unresolved checkpoint", "uprior := r.unresolved", "uprior := st.uprior"),
    ("commit ignores the foreign ids", "x.runIn st.foreign lines", "x.runIn [] lines"),
]

# Shard uniqueness: only shards_v1.vectors sees these (a foreign id must be ALREADY_DECIDED).
SHARD_MUTANTS = [
    ("foreign ids ignored by the twin", "x.decideAll (HashSet.ofList (idSeen f)) (x.order b)", "x.decideAll ∅ (x.order b)"),
    ("foreign ids are none", "f.map fun i => [4, i]", "([] : List Nat).map fun i => [4, i]"),
]

# The six `runIn` mutants of FAST again, on the `Ix.run` body that `decideBatchF` uses.
RUN_BODY = [(n + " (Ix.run)", *edit(RUN, *e)) for n, *e in [
    ("nothing released", ("let ra := x.releasedLines ds", "let ra : List Line := []")),
    ("held lines released", ("let ra := x.releasedLines ds", "let ra := ds.map (·.line)")),
    ("checkpoint drops the batch's additions", (REL_ROW, "released := x.relV,"), (UNR_ROW, "unresolved := x.unrV }")),
    ("checkpoint advances only when chained",
     (REL_ROW, REL_ROW.replace("released := ", "released := if !x.relChained then x.relV else ")),
     (UNR_ROW, UNR_ROW.replace("unresolved := ", "unresolved := if !x.unrChained then x.unrV else "))),
    ("checkpoint forgets the view's rows", (REL_ROW, "released := ⟨x.relV.asOf, ra.length, ra⟩,"),
     (UNR_ROW, "unresolved := ⟨x.unrV.asOf, ua.length, ua⟩ }")),
    ("gate leaves nothing unresolved", ("let ua := x.unresolvedLines ds", "let ua : List Line := []"))]]


def swap_reasons(lines):
    """Swap the reasons of the first two held lines with different reasons."""
    held = [i for i, x in enumerate(lines) if x.split()[-2:-1] == ["HOLD"]]
    a = held[0]
    b = next(i for i in held if lines[i].split()[-1] != lines[a].split()[-1])
    fa, fb = lines[a].split(), lines[b].split()
    fa[-1], fb[-1] = fb[-1], fa[-1]
    lines[a], lines[b] = " ".join(fa), " ".join(fb)


def swap_outcomes(lines):
    """ALLOW the first held line and HOLD an allowed line of the same amount."""
    a = next(i for i, x in enumerate(lines) if x.split()[-2:-1] == ["HOLD"])
    fa = lines[a].split()
    b = next(i for i, x in enumerate(lines) if x.split()[-2:] == ["ALLOW", "-"] and x.split()[-3] == fa[-3])
    fb = lines[b].split()
    fa[-2:], fb[-2:] = fb[-2:], fa[-2:]
    lines[a], lines[b] = " ".join(fa), " ".join(fb)


DEMO_MUTANTS = [("demo: two held lines swap reasons", swap_reasons),
                ("demo: a held and an allowed line of one amount swap", swap_outcomes)]


def build(lean: Path, lake: str, *targets: str) -> tuple[bool, str]:
    run = subprocess.run([lake, "-d", str(lean), "build", *(targets or ("gate_rules",))],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return run.returncode == 0, run.stdout.decode("utf-8", "replace")  # Lean prints characters such as ✝


def proof_error(output: str) -> str:
    """The first Lean `error:` line in a proof file, or ""."""
    return next((s for s in output.splitlines() if s.startswith("error:") and any(f in s for f in PROOF_FILES)), "")


def vectors(lean: Path, path: Path) -> str:
    out = subprocess.run([str(lean / ".lake" / "build" / "bin" / "gate_rules.exe"), str(path)],
                         capture_output=True, text=True).stdout.splitlines()
    first = [line.split("line=")[1] for line in out if line.startswith("RULES_VECTOR_FAIL")][:3]
    return out[-1].split()[0] + (" first_lines=" + ",".join(first) if first else "")


def main(lean_dir: str, rules: str, demo: str, lake: str, part: str = ":") -> int:
    tracked = [Path(lean_dir) / "BlindLedger" / "Gate" / "Rules" / f for f in ("Spec.lean", "Fast.lean", "Run.lean")]
    before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked]
    killed = 0
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        lean = Path(tmp) / "lean"
        shutil.copytree(lean_dir, lean)
        built = build(lean, lake)[0]
        shards = Path(rules).with_name("shards_v1.vectors")
        base = [vectors(lean, Path(p)) if built else "BUILD_ERROR" for p in (rules, demo, shards)]
        proved = build(lean, lake, *PROOFS)[0]  # a proof kill below means nothing unless the unmutated proofs build
        print(f"BASELINE rules={base[0]} demo={base[1]} shards={base[2]} proofs={'BUILT' if proved else 'BUILD_ERROR'}", flush=True)
        for name, mutate in DEMO_MUTANTS:
            lines = Path(demo).read_text(encoding="utf-8").splitlines()
            mutate(lines)
            path = Path(tmp) / "demo_mutant.vectors"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = vectors(lean, path)
            killed += result.startswith("RULES_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
        chosen = ([("Spec.lean", *m) for m in SPEC] + [("Fast.lean", *m) for m in FAST] +
                  [("Run.lean", *m) for m in RUN_MUTANTS] + [("Fast.lean", *SHARD_MUTANTS[0])] +
                  [("Spec.lean", *m) for m in SHARD_MUTANTS[1:]] + [("Fast.lean", *m) for m in RUN_BODY])[
            slice(*(int(x) if x else None for x in part.split(":")))]
        for file, name, old, new in chosen:
            src = lean / "BlindLedger" / "Gate" / "Rules" / file
            text = src.read_text(encoding="utf-8")
            edits = list(zip(*(([old], [new]) if isinstance(old, str) else (old, new))))
            if any(text.count(o) != 1 for o, _ in edits):
                print(f"MUTANT {name}: SCRIPT_ERROR occurrences={[text.count(o) for o, _ in edits]}")
                continue
            mutated = text
            for o, n in edits:
                mutated = mutated.replace(o, n)
            src.write_text(mutated, encoding="utf-8")
            result = vectors(lean, Path(rules)) if build(lean, lake)[0] else "BUILD_ERROR"
            if result == "RULES_VECTORS=PASS":
                result = vectors(lean, shards)
            if result == "RULES_VECTORS=PASS":  # the vectors cannot see it: killed only by a Lean error in a proof file
                ok, output = build(lean, lake, *PROOFS)
                error = proof_error(output)
                result = "RULES_VECTORS=FAIL by_proof " + error if error else f"SURVIVED proofs_ok={ok}"
            src.write_text(text, encoding="utf-8")
            killed += result.startswith("RULES_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
    after = [hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked]
    total = len(chosen) + len(DEMO_MUTANTS)
    print(f"TRACKED_SOURCES sha256_before={before} sha256_after={after}")
    print(f"MUTANTS part={part} total={total} killed={killed}")
    ok = proved and base == ["RULES_VECTORS=PASS"] * 3 and killed == total and before == after
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
