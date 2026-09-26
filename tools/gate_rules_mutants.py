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

FFS_KEY = "[1, l.member, l.payee, l.date, l.proc, l.units, l.cents]"
NEAR_KEY = "[2, l.member, l.rendering, l.date, l.proc]"
CAP_KEY = "[0, l.member, l.date / 100]"
OVERLAP = "max first (max s.start t.start) ≤ min last (min s.stop t.stop)"
REVIEW = ("| .COLLIDES_WITH_UNRESOLVED | .FFS_NEAR_DUPLICATE | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID\n"
          "  | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH | .STALE_RELEASED\n"
          "  | .STALE_UNRESOLVED => true")
UNRESOLVED = "((entries c.unresolved).flatMap keys)"
MUTANTS = [
    ("R1 off", "d.id == l.member && d.date < l.date", "false"),
    ("R1 death on the service date", "d.id == l.member && d.date < l.date", "d.id == l.member && d.date ≤ l.date"),
    ("R1 any member", "d.id == l.member && d.date", "d.date"),
    ("R2 off", "isCap l && (seen.contains (key l) || overlap c l)", "false"),
    ("R2 released or earlier lines ignored", "seen.contains (key l) || overlap c l", "overlap c l"),
    ("R2 overlapping plans ignored", "seen.contains (key l) || overlap c l", "seen.contains (key l)"),
    ("R2 also on FFS", "isCap l && (seen.contains (key l)", "(seen.contains (key l)"),
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
    ("R3 provider death off", "party l d.id && d.date < l.date", "false"),
    ("R3 provider death on the service date", "party l d.id && d.date < l.date", "party l d.id && d.date ≤ l.date"),
    ("R3 payee only", "id == l.payee || id == l.rendering", "id == l.payee"),
    ("R3 rendering only", "id == l.payee || id == l.rendering", "id == l.rendering"),
    ("R4 off", "| .FFS_DUPLICATE_LINE => !isCap l && seen.contains (key l)", "| .FFS_DUPLICATE_LINE => false"),
    ("R4 also on CAP_820", "| .FFS_DUPLICATE_LINE => !isCap l && ", "| .FFS_DUPLICATE_LINE => "),
] + [(f"R4 key without {f}", FFS_KEY, FFS_KEY.replace(f", l.{f}", ""))
     for f in ("member", "payee", "date", "proc", "units", "cents")] + [
    ("near duplicate off", "!isCap l && seen.contains (nearKey l) && !seen.contains (key l)", "false"),
    ("near duplicate also on exact duplicates", " && !seen.contains (key l)", ""),
    ("near duplicate also on CAP_820", "!isCap l && seen.contains (nearKey l)", "seen.contains (nearKey l)"),
] + [(f"near key without {f}", NEAR_KEY, NEAR_KEY.replace(f", l.{f}", ""))
     for f in ("member", "rendering", "date", "proc")] + [
    ("FFS claims no near key", "else [key l, nearKey l]", "else [key l]"),
    ("R5 off", "| .MEMBER_NOT_ENROLLED => !enrolled c l", "| .MEMBER_NOT_ENROLLED => false"),
    ("R5 any member", "s.member == l.member && s.start", "s.start"),
    ("R5 span start", "s.start ≤ l.date && ", ""),
    ("R5 span stop", " && l.date ≤ s.stop", ""),
    ("R5 any plan", "(!isCap l || s.plan == l.payee)", "true"),
    ("R5 plan on FFS too", "!isCap l || s.plan", "s.plan"),
    ("R5 plan is the rendering party", "s.plan == l.payee", "s.plan == l.rendering"),
    ("unenrolled lines claim keys", "if enrolled c l then keys l else []", "keys l"),
    ("held lines claim nothing", "decideAll c (claim c l ++ seen) ls",
     "decideAll c (if (decideLine c seen l).outcome == .ALLOW then keys l ++ seen else seen) ls"),
    ("earlier lines unseen", "decideAll c (claim c l ++ seen) ls", "decideAll c seen ls"),
    ("released set unread", "decideAll c ((entries c.released).flatMap keys)", "decideAll c []"),
    ("released near keys ignored", "decideAll c ((entries c.released).flatMap keys)",
     "decideAll c ((entries c.released).map key)"),
    ("nothing released", "entries c.released ++ allowedLines ds", "entries c.released"),
    ("held lines released", "entries c.released ++ allowedLines ds", "entries c.released ++ ds.map (·.line)"),
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
    ("future snapshot usable", "s.asOf ≤ today &&", ""),
    ("snapshot dated today unusable", "s.asOf ≤ today &&", "s.asOf < today &&"),
    ("declared count unchecked", "s.entries.length == s.count && 0 < s.count", "0 < s.count"),
    ("empty snapshot usable", " && 0 < s.count", ""),
    ("rows unchecked", "s.entries.all ok", "true"),
    ("death rows unchecked", "okDeath (d : Death) : Bool := validDate d.date", "okDeath (d : Death) : Bool := true"),
    ("exclusion start unchecked", "validDate e.start && ", ""),
    ("exclusion stop unchecked", "validDate e.stop && ", ""),
    ("exclusion order unchecked", " && e.start ≤ e.stop", ""),
    ("span start unchecked", "validDate s.start && ", ""),
    ("span stop unchecked", "validDate s.stop && ", ""),
    ("span order unchecked", " && s.start ≤ s.stop", ""),
    ("released count unchecked", "| some s => s.entries.length == s.count", "| some s => true"),
    ("missing released set whole", "| none => false\n  | some s => s.entries", "| none => true\n  | some s => s.entries"),
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
    ("review is HOLD", "else if rs.any review then .HUMAN_REVIEW", "else if false then .HUMAN_REVIEW"),
    ("HOLD reasons reviewed", "  | _ => false", "  | _ => true"),
    ("near duplicate is HOLD", REVIEW, REVIEW.replace("| .FFS_NEAR_DUPLICATE ", "")),
    ("future service date is HOLD", REVIEW, REVIEW.replace("| .SERVICE_DATE_FUTURE ", "")),
    ("invalid service date is HOLD", REVIEW, REVIEW.replace(" | .SERVICE_DATE_INVALID", "")),
    ("stale released set is HOLD", REVIEW, REVIEW.replace(" | .STALE_RELEASED", "")),
    ("unresolved collision is HOLD", REVIEW, REVIEW.replace("| .COLLIDES_WITH_UNRESOLVED ", "")),
    ("stale unresolved set is HOLD", REVIEW, REVIEW.replace("\n  | .STALE_UNRESOLVED", "")),
    ("unresolved keys ignored (ALLOW)", f"(keys l).any {UNRESOLVED}.contains", "false"),
    ("unresolved near keys ignored", UNRESOLVED, "((entries c.unresolved).map key)"),
    ("unresolved set unchecked", "| .STALE_UNRESOLVED => !whole c.unresolved", "| .STALE_UNRESOLVED => false"),
    ("gate leaves nothing unresolved", "unresolved := entries c.unresolved ++ unresolvedLines c ds",
     "unresolved := entries c.unresolved"),
    ("unenrolled lines unresolved", "d.outcome != .ALLOW && enrolled c d.line", "d.outcome != .ALLOW"),
    ("ALLOW lines unresolved", "d.outcome != .ALLOW && enrolled", "enrolled"),
    ("arrival order", "batch.mergeSort lineLe", "batch"),
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
