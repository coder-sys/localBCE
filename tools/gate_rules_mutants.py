"""Mutation check of the gate rules (test-only).

The lean tree is copied to a temporary directory; each spec mutant weakens one
check in the copy's ``BlindLedger/Gate/Rules/Spec.lean``, rebuilds its
``gate_rules`` and must make ``rules_v1.vectors`` FAIL.  Each demo mutant
mislabels lines of the demo file and must FAIL against the unmutated rules.
The tracked tree is never written; its Spec.lean hash is checked before and
after.  Run only under the v4 guard:
``python tools/gate_rules_mutants.py <lean dir> <rules vectors> <demo vectors> <lake.exe>``.
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
CLAIM = "if isCap l && notEnrolled c l then [exactKey l, idKey l] else keys l"
R2 = "seen.contains (exactKey l) || seen.contains (nearKey l) || certain c 7 okSpan c.enrollment l && overlap c l"
OVERLAP = "max first (max s.start t.start) ≤ min last (min s.stop t.stop)"
REVIEW = ("| .COLLIDES_WITH_UNRESOLVED_NEAR | .FFS_NEAR_DUPLICATE | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID\n"
          "  | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH | .STALE_RELEASED\n"
          "  | .STALE_UNRESOLVED | .MEMBER_DECEASED_UNVERIFIED | .MEMBER_NOT_ENROLLED_UNVERIFIED\n"
          "  | .PROVIDER_DECEASED_UNVERIFIED | .PROVIDER_EXCLUDED_UNVERIFIED => true")
CHAINED = ("| some s => s.entries.length == s.count && validDate s.asOf && s.asOf ≤ today && prior.asOf ≤ s.asOf &&\n"
           "      prior.entries.isPrefixOf s.entries")
KEPT = "d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED"
RELEASED_CP = "(releasedSet c).filter (fun x => (keys l).any (keys x).contains)"
UNRESOLVED_CP = "(unresolvedSet c).filter fun x => (keys l).any (claim c x).contains"
COUNTERPARTS = f"({RELEASED_CP} ++\n      {UNRESOLVED_CP}).map (·.id)"
UNVERIFIED = "o.isSome && !usable c.today maxAge ok o && validDate l.date"
ADVANCE = "  let v := view today prior o\n  ⟨v.asOf, v.entries.length + adds.length, v.entries ++ adds⟩"
MUTANTS = [
    ("R1 off", "d.id == l.member && d.date < l.date", "false"),
    ("R1 death on the service date", "d.id == l.member && d.date < l.date", "d.id == l.member && d.date ≤ l.date"),
    ("R1 any member", "d.id == l.member && d.date", "d.date"),
    ("R1 on an unusable DMF", "certain c 90 okDeath c.dmf l &&", "true &&"),
    ("R1 on a 91-day DMF", "certain c 90 okDeath c.dmf l", "certain c 91 okDeath c.dmf l"),
    ("R1 unverified off", "unverified c 90 okDeath c.dmf l && memberDead c l", "false"),
    ("R2 off", "isCap l &&\n      (" + R2 + ")", "false"),
    ("R2 released or earlier lines ignored", R2, "certain c 7 okSpan c.enrollment l && overlap c l"),
    ("R2 exact key ignored", "(seen.contains (exactKey l) || ", "("),
    ("R2 member-month ignored", " || seen.contains (nearKey l) || ", " || "),
    ("R2 overlapping plans ignored", " || certain c 7 okSpan c.enrollment l && overlap c l", ""),
    ("R2 overlap on an unusable enrollment", "|| certain c 7 okSpan c.enrollment l && overlap c l", "|| overlap c l"),
    ("R2 also on FFS", "| .CAP_MEMBER_MONTH_DUPLICATE => isCap l &&", "| .CAP_MEMBER_MONTH_DUPLICATE =>"),
    ("R2 key is the day", CAP_KEY, "[0, l.member, l.date]"),
    ("R2 key without member", CAP_KEY, "[0, l.date / 100]"),
    ("R2 key without year", CAP_KEY, "[0, l.member, l.date / 100 % 100]"),
    ("overlap within one plan", "s.plan != t.plan && ", ""),
    ("overlap across members", "(entries c.enrollment).filter (·.member == l.member)", "entries c.enrollment"),
    ("overlap needs two days", OVERLAP, OVERLAP.replace("≤", "<")),
    ("overlap month is 28 days", "+ monthDays (l.date / 10000) (l.date / 100 % 100)", "+ 28"),
    ("overlap ignores span starts", "max first (max s.start t.start)", "first"),
    ("overlap ignores span stops", "min last (min s.stop t.stop)", "last"),
    ("R3 exclusion off", "party l e.id && e.start", "false && e.start"),
    ("R3 exclusion start exclusive", "e.start ≤ l.date", "e.start < l.date"),
    ("R3 exclusion stop exclusive", "l.date ≤ e.stop", "l.date < e.stop"),
    ("R3 exclusion on an unusable snapshot", "certain c 31 okExclusion c.exclusions l &&", "true &&"),
    ("R3 exclusion on a 32-day snapshot", "certain c 31 okExclusion", "certain c 32 okExclusion"),
    ("R3 exclusion unverified off", "unverified c 31 okExclusion c.exclusions l && excluded c l", "false"),
    ("R3 provider death off", "party l d.id && d.date < l.date", "false"),
    ("R3 provider death on the service date", "party l d.id && d.date < l.date", "party l d.id && d.date ≤ l.date"),
    ("R3 provider death on an unusable list", "certain c 90 okDeath c.providerDeaths l &&", "true &&"),
    ("R3 provider death on a 91-day list", "certain c 90 okDeath c.providerDeaths l",
     "certain c 91 okDeath c.providerDeaths l"),
    ("R3 provider death unverified off", "unverified c 90 okDeath c.providerDeaths l && providerDead c l", "false"),
    ("R3 payee only", "id == l.payee || id == l.rendering", "id == l.payee"),
    ("R3 rendering only", "id == l.payee || id == l.rendering", "id == l.rendering"),
    ("R4 off", "| .FFS_DUPLICATE_LINE => !isCap l && seen.contains (exactKey l)", "| .FFS_DUPLICATE_LINE => false"),
    ("R4 also on CAP_820", "| .FFS_DUPLICATE_LINE => !isCap l && ", "| .FFS_DUPLICATE_LINE => "),
] + [(f"exact key without {f}", EXACT_KEY, EXACT_KEY.replace(f", l.{f}", ""))
     for f in ("member", "payee", "date", "proc", "units", "cents")] + [
    ("near duplicate off", "!isCap l && seen.contains (nearKey l) && !seen.contains (exactKey l)", "false"),
    ("near duplicate also on exact duplicates", " && !seen.contains (exactKey l)", ""),
    ("near duplicate also on CAP_820", "!isCap l && seen.contains (nearKey l)", "seen.contains (nearKey l)"),
] + [(f"near key without {f}", NEAR_KEY, NEAR_KEY.replace(f", l.{f}", ""))
     for f in ("member", "rendering", "date", "proc")] + [
    ("no near keys claimed", KEYS, "[exactKey l, idKey l]"),
    ("no identities claimed", KEYS, "[exactKey l, nearKey l]"),
    ("CAP_820 line claims an FFS near key", KEYS, "[exactKey l, nearKey l, idKey l, [2, l.member, l.rendering, l.date, l.proc]]"),
    ("R5 off", "| .MEMBER_NOT_ENROLLED => notEnrolled c l", "| .MEMBER_NOT_ENROLLED => false"),
    ("R5 unverified off", "unverified c 7 okSpan c.enrollment l && !enrolled c l", "false"),
    ("R5 on an unusable enrollment", "certain c 7 okSpan c.enrollment l && !enrolled c l", "!enrolled c l"),
    ("R5 on an 8-day enrollment", "certain c 7 okSpan c.enrollment l && !enrolled c l",
     "certain c 8 okSpan c.enrollment l && !enrolled c l"),
    ("R5 any member", "s.member == l.member && s.start", "s.start"),
    ("R5 span start", "s.start ≤ l.date && ", ""),
    ("R5 span stop", " && l.date ≤ s.stop", ""),
    ("R5 any plan", "(!isCap l || s.plan == l.payee)", "true"),
    ("R5 plan on FFS too", "!isCap l || s.plan", "s.plan"),
    ("R5 plan is the rendering party", "s.plan == l.payee", "s.plan == l.rendering"),
    ("checks on an invalid service date", "\n  usable c.today maxAge ok o && validDate l.date",
     "\n  usable c.today maxAge ok o"),
    ("unverified on usable snapshots", UNVERIFIED, "o.isSome && validDate l.date"),
    ("unverified on missing snapshots", UNVERIFIED, "!usable c.today maxAge ok o && validDate l.date"),
    ("unverified on an invalid service date", UNVERIFIED, "o.isSome && !usable c.today maxAge ok o"),
    ("not-enrolled FFS lines claim nothing", CLAIM,
     "if notEnrolled c l then (if isCap l then [exactKey l, idKey l] else []) else keys l"),
    ("not-enrolled CAP_820 line claims the member-month", CLAIM, "keys l"),
    ("not-enrolled CAP_820 line claims no exact key", "then [exactKey l, idKey l] else", "then [idKey l] else"),
    ("CAP_820 line on an unusable enrollment claims no member-month", "if isCap l && notEnrolled c l",
     "if isCap l && !enrolled c l"),
    ("held lines claim nothing", "decideAll c (claim c l ++ seen) ls",
     "decideAll c (if (decideLine c seen l).outcome == .ALLOW then claim c l ++ seen else seen) ls"),
    ("earlier lines unseen", "decideAll c (claim c l ++ seen) ls", "decideAll c seen ls"),
    ("released set unread", "decideAll c ((releasedSet c).flatMap keys)", "decideAll c []"),
    ("released near keys ignored", "(releasedSet c).flatMap keys",
     "(releasedSet c).flatMap fun x => [exactKey x, idKey x]"),
    ("released identities ignored", "(releasedSet c).flatMap keys",
     "(releasedSet c).flatMap fun x => [exactKey x, nearKey x]"),
    ("nothing released", "c.released (allowedLines ds)", "c.released []"),
    ("held lines released", "c.released (allowedLines ds)", "c.released (ds.map (·.line))"),
    ("checkpoint drops the batch's additions", ADVANCE, "  view today prior o"),
    ("checkpoint advances only when chained", ADVANCE,
     ADVANCE.replace("  ⟨", "  if !chained today prior o then prior else ⟨")),
    ("checkpoint is the prior, not the view", ADVANCE, ADVANCE.replace("view today prior o", "prior")),
    ("unchained set read as is", "if chained today prior o then o.getD prior else prior", "o.getD prior"),
    ("set read ignored", "if chained today prior o then o.getD prior else prior", "prior"),
    ("reviewed lines released", "(ds.filter (·.outcome == .ALLOW))", "(ds.filter (·.outcome != .HOLD))"),
    ("service date validity off", "| .SERVICE_DATE_INVALID => !validDate l.date", "| .SERVICE_DATE_INVALID => false"),
    ("future service date off", "| .SERVICE_DATE_FUTURE => c.today < l.date", "| .SERVICE_DATE_FUTURE => false"),
    ("service date today is future", "c.today < l.date", "c.today ≤ l.date"),
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
    ("DMF 89 days", "usable c.today 90 okDeath c.dmf", "usable c.today 89 okDeath c.dmf"),
    ("DMF 91 days", "usable c.today 90 okDeath c.dmf", "usable c.today 91 okDeath c.dmf"),
    ("provider deaths 89 days", "usable c.today 90 okDeath c.providerDeaths", "usable c.today 89 okDeath c.providerDeaths"),
    ("provider deaths 91 days", "usable c.today 90 okDeath c.providerDeaths", "usable c.today 91 okDeath c.providerDeaths"),
    ("exclusions 30 days", "usable c.today 31 okExclusion", "usable c.today 30 okExclusion"),
    ("exclusions 32 days", "usable c.today 31 okExclusion", "usable c.today 32 okExclusion"),
    ("enrollment 6 days", "usable c.today 7 okSpan", "usable c.today 6 okSpan"),
    ("enrollment 8 days", "usable c.today 7 okSpan", "usable c.today 8 okSpan"),
    ("day count without leap days", "y * 365 + y / 4 - y / 100", "y * 365 - y / 100"),
    ("day count without century rule", "- y / 100 + y / 400", "+ y / 400"),
    ("day count without 400-year rule", "- y / 100 + y / 400", "- y / 100"),
    ("set count unchecked", "s.entries.length == s.count && validDate s.asOf", "validDate s.asOf"),
    ("missing set chained", "| none => false\n  | some s => s.entries", "| none => true\n  | some s => s.entries"),
    ("set asOf validity unchecked", CHAINED, CHAINED.replace("validDate s.asOf && ", "")),
    ("set dated after today", CHAINED, CHAINED.replace("s.asOf ≤ today && ", "")),
    ("set dated before the checkpoint", CHAINED, CHAINED.replace("prior.asOf ≤ s.asOf &&\n      ", "")),
    ("set need not extend the checkpoint", CHAINED, CHAINED.replace(" &&\n      prior.entries.isPrefixOf s.entries", "")),
    ("released set unchecked", "| .STALE_RELEASED => !chained c.today c.releasedPrior c.released",
     "| .STALE_RELEASED => false"),
    ("unresolved set unchecked", "| .STALE_UNRESOLVED => !chained c.today c.unresolvedPrior c.unresolved",
     "| .STALE_UNRESOLVED => false"),
    ("checkpoints swapped", "!chained c.today c.releasedPrior c.released", "!chained c.today c.unresolvedPrior c.released"),
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
    ("already decided off", "| .ALREADY_DECIDED => seen.contains (idKey l) || (pending c).contains (idKey l)",
     "| .ALREADY_DECIDED => false"),
    ("already decided ignores the batch and released set", "seen.contains (idKey l) || (pending c)", "(pending c)"),
    ("already decided ignores the unresolved set", " || (pending c).contains (idKey l)", ""),
    ("duplicate of unresolved off",
     "| .DUPLICATE_OF_UNRESOLVED => (pending c).contains (exactKey l) || isCap l && (pending c).contains (nearKey l)",
     "| .DUPLICATE_OF_UNRESOLVED => false"),
    ("unresolved member-month ignored", " || isCap l && (pending c).contains (nearKey l)", ""),
    ("near collision off", "!isCap l && (pending c).contains (nearKey l) && !(pending c).contains (exactKey l)", "false"),
    ("near collision also on exact collisions", " && !(pending c).contains (exactKey l)", ""),
    ("near collision also on CAP_820", "!isCap l && (pending c).contains (nearKey l)", "(pending c).contains (nearKey l)"),
    ("unresolved set unread", "(unresolvedSet c).flatMap (claim c)", "[]"),
    ("unresolved near keys ignored", "(unresolvedSet c).flatMap (claim c)",
     "(unresolvedSet c).flatMap fun x => (claim c x).filter (· != nearKey x)"),
    ("no counterparts", COUNTERPARTS, "[]"),
    ("no released counterparts", RELEASED_CP + " ++\n      ", ""),
    ("every released line a counterpart", RELEASED_CP, "releasedSet c"),
    ("every unresolved line a counterpart", UNRESOLVED_CP, "unresolvedSet c"),
    ("gate leaves nothing unresolved", "c.unresolved (unresolvedLines ds)", "c.unresolved []"),
    ("not-enrolled lines left out of the unresolved set", KEPT, KEPT + " && !d.reasons.contains .MEMBER_NOT_ENROLLED"),
    ("already decided lines unresolved", KEPT, "d.outcome != .ALLOW"),
    ("ALLOW lines unresolved", KEPT, "!d.reasons.contains .ALREADY_DECIDED"),
    ("arrival order", "batch.mergeSort lineLe", "batch"),
    ("canonical order without identity", "l.cents, l.id]", "l.cents]"),
]


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


def build(lean: Path, lake: str) -> bool:
    return subprocess.run([lake, "-d", str(lean), "build", "gate_rules"], capture_output=True).returncode == 0


def vectors(lean: Path, path: Path) -> str:
    out = subprocess.run([str(lean / ".lake" / "build" / "bin" / "gate_rules.exe"), str(path)],
                         capture_output=True, text=True).stdout.splitlines()
    first = [line.split("line=")[1] for line in out if line.startswith("RULES_VECTOR_FAIL")][:3]
    return out[-1].split()[0] + (" first_lines=" + ",".join(first) if first else "")


def main(lean_dir: str, rules: str, demo: str, lake: str) -> int:
    tracked = Path(lean_dir) / "BlindLedger" / "Gate" / "Rules" / "Spec.lean"
    before = hashlib.sha256(tracked.read_bytes()).hexdigest()
    killed = 0
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        lean = Path(tmp) / "lean"
        shutil.copytree(lean_dir, lean)
        spec = lean / "BlindLedger" / "Gate" / "Rules" / "Spec.lean"
        text = spec.read_text(encoding="utf-8")
        built = build(lean, lake)
        base = [vectors(lean, Path(p)) if built else "BUILD_ERROR" for p in (rules, demo)]
        print(f"BASELINE rules={base[0]} demo={base[1]}", flush=True)
        for name, mutate in DEMO_MUTANTS:
            lines = Path(demo).read_text(encoding="utf-8").splitlines()
            mutate(lines)
            path = Path(tmp) / "demo_mutant.vectors"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = vectors(lean, path)
            killed += result.startswith("RULES_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
        for name, old, new in MUTANTS:
            if text.count(old) != 1:
                print(f"MUTANT {name}: SCRIPT_ERROR occurrences={text.count(old)}")
                continue
            spec.write_text(text.replace(old, new), encoding="utf-8")
            result = vectors(lean, Path(rules)) if build(lean, lake) else "BUILD_ERROR"
            killed += result.startswith("RULES_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
    after = hashlib.sha256(tracked.read_bytes()).hexdigest()
    total = len(MUTANTS) + len(DEMO_MUTANTS)
    print(f"TRACKED_SPEC sha256_before={before} sha256_after={after}")
    print(f"MUTANTS total={total} killed={killed}")
    ok = base == ["RULES_VECTORS=PASS"] * 2 and killed == total and before == after
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
