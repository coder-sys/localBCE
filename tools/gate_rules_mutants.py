"""Mutation check of the gate rules against tests/gate_rules/rules_v1.vectors (test-only).

Each mutant weakens one check in ``BlindLedger/Gate/Rules/Spec.lean``, rebuilds
``gate_rules`` and must make the vectors FAIL; the spec is then restored byte
for byte and must PASS.  Run only under the v4 guard:
``python tools/gate_rules_mutants.py <lean dir> <vectors file> <lake.exe>``.
"""

import hashlib
from pathlib import Path
import subprocess
import sys

FFS_KEY = "[1, l.member, l.payee, l.date, l.proc, l.units, l.cents]"
MUTANTS = [
    ("R1 off", "d.id == l.member && d.date < l.date", "false"),
    ("R1 death on the service date", "d.id == l.member && d.date < l.date", "d.id == l.member && d.date ≤ l.date"),
    ("R1 any member", "d.id == l.member && d.date", "d.date"),
    ("R2 off", "=> isCap l && seen", "=> false && seen"),
    ("R2 also on FFS", "=> isCap l && seen", "=> seen"),
    ("R2 key is the day", "[0, l.member, l.date / 100]", "[0, l.member, l.date]"),
    ("R2 key without member", "[0, l.member, l.date / 100]", "[0, l.date / 100]"),
    ("R2/R4 earlier lines unseen", "decideAll c (key l :: seen) ls", "decideAll c seen ls"),
    ("R2/R4 nothing released", "released ++ allowedKeys ds", "released"),
    ("R2/R4 held lines released", "released ++ allowedKeys ds", "released ++ ds.map (key ·.line)"),
    ("R3 exclusion off", "party l e.id && e.start", "false && e.start"),
    ("R3 exclusion start exclusive", "e.start ≤ l.date", "e.start < l.date"),
    ("R3 exclusion stop exclusive", "l.date ≤ e.stop", "l.date < e.stop"),
    ("R3 provider death off", "party l d.id && d.date < l.date", "false"),
    ("R3 provider death on the service date", "party l d.id && d.date < l.date", "party l d.id && d.date ≤ l.date"),
    ("R3 payee only", "id == l.payee || id == l.rendering", "id == l.payee"),
    ("R3 rendering only", "id == l.payee || id == l.rendering", "id == l.rendering"),
    ("R4 off", "=> !isCap l && seen", "=> false && seen"),
    ("R4 also on CAP_820", "=> !isCap l && seen", "=> seen"),
] + [(f"R4 key without {f}", FFS_KEY, FFS_KEY.replace(f", l.{f}", ""))
     for f in ("member", "payee", "date", "proc", "units", "cents")] + [
    ("R5 off", "!(entries c.enrollment).any (covers l)", "false"),
    ("R5 any member", "s.member == l.member && ", ""),
    ("R5 span start", "s.start ≤ l.date && ", ""),
    ("R5 span stop", " && l.date ≤ s.stop", ""),
    ("R5 any plan", "(!isCap l || s.plan == l.payee)", "true"),
    ("R5 plan on FFS too", "!isCap l || s.plan", "s.plan"),
    ("missing snapshot is fresh", "| none => false", "| none => true"),
    ("future snapshot is fresh", "s.asOf ≤ today && ", ""),
    ("DMF 89 days", "fresh c.today 90 c.dmf", "fresh c.today 89 c.dmf"),
    ("DMF 91 days", "fresh c.today 90 c.dmf", "fresh c.today 91 c.dmf"),
    ("provider deaths 89 days", "fresh c.today 90 c.providerDeaths", "fresh c.today 89 c.providerDeaths"),
    ("provider deaths 91 days", "fresh c.today 90 c.providerDeaths", "fresh c.today 91 c.providerDeaths"),
    ("exclusions 30 days", "fresh c.today 31 c.exclusions", "fresh c.today 30 c.exclusions"),
    ("exclusions 32 days", "fresh c.today 31 c.exclusions", "fresh c.today 32 c.exclusions"),
    ("enrollment 6 days", "fresh c.today 7 c.enrollment", "fresh c.today 6 c.enrollment"),
    ("enrollment 8 days", "fresh c.today 7 c.enrollment", "fresh c.today 8 c.enrollment"),
    ("no leap days", "y * 365 + y / 4 - y / 100", "y * 365 - y / 100"),
    ("stale is only HOLD", "if rs.any stale then .HUMAN_REVIEW", "if false then .HUMAN_REVIEW"),
    ("arrival order", "batch.mergeSort lineLe", "batch"),
]


def vectors(lean: Path, path: str, lake: str) -> str:
    if subprocess.run([lake, "-d", str(lean), "build", "gate_rules"], capture_output=True).returncode:
        return "BUILD_ERROR"
    out = subprocess.run([str(lean / ".lake" / "build" / "bin" / "gate_rules.exe"), path],
                         capture_output=True, text=True).stdout.splitlines()
    first = [line.split("line=")[1] for line in out if line.startswith("RULES_VECTOR_FAIL")][:3]
    return out[-1].split()[0] + (" first_lines=" + ",".join(first) if first else "")


def main(lean_dir: str, path: str, lake: str) -> int:
    lean = Path(lean_dir)
    spec = lean / "BlindLedger" / "Gate" / "Rules" / "Spec.lean"
    original = spec.read_bytes()
    text = original.decode("utf-8")
    killed = 0
    try:
        for name, old, new in MUTANTS:
            if text.count(old) != 1:
                print(f"MUTANT {name}: SCRIPT_ERROR occurrences={text.count(old)}")
                continue
            spec.write_bytes(text.replace(old, new).encode("utf-8"))
            result = vectors(lean, path, lake)
            killed += result.startswith("RULES_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
    finally:
        spec.write_bytes(original)
    restored = vectors(lean, path, lake)
    print(f"RESTORED sha256={hashlib.sha256(spec.read_bytes()).hexdigest()} {restored}")
    print(f"MUTANTS total={len(MUTANTS)} killed={killed}")
    return 0 if restored == "RULES_VECTORS=PASS" and killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
