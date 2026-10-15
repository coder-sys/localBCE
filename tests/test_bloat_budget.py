"""Size budget for the trunk (CONSTITUTION Art. IX, X.1, XI).

Ceilings only ratchet down. Raising one needs a commit message that names the
felt effect (Art. XII) the extra size buys; lower them whenever work shrinks
the code (the core-v8 merge must lower the core-file ceilings).
"""

import hashlib
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".lake", "__pycache__", "node_modules", "target", "parked", ".venv", "build", ".pytest_cache"}
CODE_EXTS = {".py", ".lean", ".js", ".rs", ".c", ".h", ".cpp", ".ps1", ".css", ".html"}
# Product code (what runs and must be read to be trusted); lower it as the code shrinks.
PRODUCT_CODE_LINES = 36_897  # HIST-FLAT A r3: +47 over 36,850 = a history of any size loads in parts under 512 KB (no size fallback to the one-shot), a running chain digest kept by producer and worker (resume costs O(batch)), holds per shard, a logged one-shot only on worker death; earlier: HIST-FLAT A r2: +17 over 36,833 = decide `resume` (the felt effect, XII: a held worker keeps its state, so no per-batch load rebuild and no 2x load peak); earlier: exact actual of TRAIN-7: -4 under 36,837 (FLOAT-2 nets -4 product lines in the owner; SG1B and S3d add none); earlier: exact actual of TRAIN-6: +57 over 36,780 = IDREG S4 +57 (a moved, forked, hard-linked or aliased registry file is refused; granted delta 36,752 -> 36,809); earlier: FLOAT-1: +28 (floats and past-Lean-bound JSON refused at intake; read-only quarantine scan). MAN-0 S1 fix: +11 (a batch without one well-formed RULES_READS is refused) on 36,741 exact actual; earlier: exact actual: 3 C-L1 review fixes (restored duplicate-receipt guard and requested-id check in the keyed begin, malformed-payload fault class) + 36,738 exact actual of cfi-cl merged with IDREG S3 81f58a22: 86 CFI-C-L1 (v4 unique receipt/alias indexes, committed row counter, keyed begin through them) + exact actual of the merged tree with trunk 442de49c (grant-tenant nets 0 product lines here): 7 IDREG S3-FIX4 (only boot creates or writes the registry file; boot names the file it opens, after the lock) + 36,645 = 5 IDREG S3-FIX3 (a displaced nonce stops, file identity read before and after connect, a boot lock timeout stops the path) + 36,640 = 29 IDREG S3-FIX2 (first pass on a nonce stops the older ones, per-txn file identity, boot lock timeout) + 36,611 = 8 IDREG S3-FIX1 (memory keyed by boot nonce so path aliases cannot fool it, recorded before COMMIT, one boot at a time per process) + 36,603 = 34 IDREG S3 (restore-while-running row check, a failed boot stops its process, fence-only retry) + 36,569 = 95 IDREG restore fence (boot anchor reads, store_rewound, fence-before-read, typed store/inputs errors; lead call: exact actual) + 36,474 trunk CFI-C1 = 35,823 trunk + 78 S2 codec + 103 D7 slots + 13 S7a payer + 214 S3a 835 fold (one bad claim no longer sinks the remittance) + 10 b2 review fixes (cert cap and totals under one rule) + 82 PERF-A 835 fast lane (remittance fold 6.9x faster, 13.4k->92.2k lines/s/core) + 151 CFI-C1 history bench (measures a cash file's begin against history size: begin sql_ops identical at 2,560 and 7,500 history rows)
# Test code and the Python gate tools under lean/; Lean files are not counted.
EVIDENCE_CODE_LINES = 41_025  # HIST-FLAT A r3: +35 over 40,990 = part-load, 3000-row no-fallback and logged-death tests net of the removed size-fallback test; earlier: HIST-FLAT A r2: +176 over 40,802 = +30 already in 3a8948cb (40,832) and +146 resume tests (one test per refusal path and the one call site); earlier: exact actual of TRAIN-7: +254 over 40,548 (which holds FLOAT-2's +24) = SEMGATE-1B +40 semantic gate tests and ENGINE-0 S3d +214 (snapshot v2 vectors, log vectors and no-sorry tests); earlier: FLOAT-2: +24 over 40,524 (Art. XII: a float, NaN, Infinity, duplicate key or non-canonical JSON is refused at every writer parse and on export/import; the kill check gave 24 failures); earlier: exact actual of TRAIN-6: +313 over 40,211 = R2P bench stage timers +27, FLOAT-1 refusal tests +82, IDREG S4 tests +201 and producer test +3; earlier: exact actual of TRAIN-5: +359 over 39,852 = prooflink +43 semantic gate tool and +6 tcb test, B4-S1 +127 publish-tree tests and +1 formats test, ENGINE-0 S2 +182 snapshot vectors test; earlier: exact actual of the train merged with trunk f00db7f1: +289 ENGINE-0 S1 (v3 tenant-log reference codec and vectors tests, trunk 34,918 = 34,629 + 289) on 39,563 = exact actual of os-bench d44e6042 merged into train: +4,559 os-bench evidence (owner-scale bench and shard-check harness moved from tools/ to tests/ with their tests; Art. XII felt effect: the 50k lines/s throughput claim is measured, not asserted) on 35,004 = train: 34,715 MAN-0 S1 + 289 LINKFIX-ENC (wire_vectors tests); MAN-0 S1 fix exact actual: +42 (read manifest v2 proofs, vector and refusal tests) on 34,673; earlier: MAN-0 S1 read manifest (+44) on 34,629 exact actual of cfi-cl merged with trunk afbce35a: +6 shard-h (RGL-FIX2 tests) on 34,623 = 27 C-L1 review-fix tests (forged-payload begin refusals, malformed fault class) + 34,596 exact actual of cfi-cl merged with IDREG S3 81f58a22: 402 (398 CFI-C-L1 + 4 slack: trunk 442de49c carried its ceiling at 33,907 against an actual of 33,903, so the C-L1 tests are 4 above the 398 counted from the ceiling; every evidence file of the merge equals ours + theirs - base line for line, no real residue) CFI-C-L1 tests (test_cfi_cl_history + E1/E2/partial-index updates) + exact actual of the merged tree with trunk 442de49c: 14 grant-tenant tests net (trunk measured +18 on 33,889) + 34,180 IDREG S3-FIX4 branch = 74 IDREG S3-FIX4 tests (a handle open creates and writes no registry file and closes when refused; a boot re-pointed during its lock wait or open ends no other file's stop) + 34,106 earlier (trunk 33,889 = idreg-restore + CFI-C1); earlier: 32,533 trunk + 71 S2 + 101 test-speed (fixture/server reuse; measured net) + 99 D7 slots (empty slots refuse activation loudly) + 131 S7a payer tests + 121 S3a fold tests + 6 A1 empty-table slot test + 48 b2 review-fix tests + 102 PERF-A lane-vs-slow-path differential tests
MARKDOWN_FILES = 18
# Prose Markdown outside conformance/ (the normative wire spec has its own limit).
MARKDOWN_BYTES = 92_902  # exact actual of TRAIN-5: +70 ENGINE-0 S2 ENGINE-SNAP tag row (every domain tag the gate signs is named in one place) on 92,832; earlier: exact actual of train merged with trunk f00db7f1: +3 where MAN-0 S1's read-manifest tag row (Art. XII: every domain tag the gate signs is named in one table) meets trunk's TENANT-LOG/v3 row in RIGHTRAIL_FULL_STACK_TARGET.md on 92,829 = +89 ENGINE-0 S1 TENANT-LOG/v3 tag row (every domain tag the gate signs is named in one place) on 92,740 = 91,150 trunk + 305 absorb-ladder + 1,285 amend-bypass (D6 bypass amendment text; its base had 29 bytes of slack: true delta +1,285, not +1,256)
CONFORMANCE_MARKDOWN_BYTES = 30_970
STATUS_BYTES = 8_000
CORE_FILE_LINES = {
    "app/right_rail_financial_owner.py": 6_803,
    "app/right_rail_financial_owner_independent.py": 4_512,
    "app/right_rail_financial_semantic_adapter.py": 2_279,
    "app/right_rail_financial_mirror.py": 1_369,
    "app/right_rail_financial_engine.py": 1_249,
    "app/right_rail_financial_switch.py": 1_098,
    "app/right_rail_financial_line_pack.py": 253,
    "app/right_rail_financial_followthrough.py": 336,
}
FORBIDDEN_NAMES = {"CURRENT_TASK.md", "STATE.md", "AGENTS.override.md"}
# Copy-paste: repeated 6-line windows (>=120 chars) across product Python.
# Independent checkers may restate a small shared schema by design; the rest
# is duplication to delete.
PRODUCT_DIRS = ("app", "tools", os.path.join("provider_app", "provider_app"))
DUPLICATED_WINDOWS = 210


def _live_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _lines(path):
    with open(path, "rb") as handle:
        return handle.read().count(b"\n")


class BloatBudgetTest(unittest.TestCase):
    def test_live_code_stays_under_ceiling(self):
        totals = {"product": 0, "evidence": 0}
        for p in _live_files():
            ext = os.path.splitext(p)[1].lower()
            if ext in CODE_EXTS and ext != ".lean":
                parts = os.path.relpath(p, ROOT).split(os.sep)
                totals["evidence" if "tests" in parts[:-1] or parts[0] == "lean" else "product"] += _lines(p)
        self.assertLessEqual(totals["product"], PRODUCT_CODE_LINES)
        self.assertLessEqual(totals["evidence"], EVIDENCE_CODE_LINES)

    def test_core_files_stay_under_ceiling(self):
        for rel, ceiling in CORE_FILE_LINES.items():
            with self.subTest(rel):
                self.assertLessEqual(_lines(os.path.join(ROOT, rel)), ceiling)

    def test_markdown_stays_small(self):
        docs = [p for p in _live_files() if p.endswith(".md")]
        self.assertLessEqual(len(docs), MARKDOWN_FILES)
        conformance_root = os.path.join(ROOT, "conformance") + os.sep
        prose = [p for p in docs if not p.startswith(conformance_root)]
        conformance = [p for p in docs if p.startswith(conformance_root)]
        self.assertLessEqual(sum(os.path.getsize(p) for p in prose), MARKDOWN_BYTES)
        self.assertLessEqual(sum(os.path.getsize(p) for p in conformance), CONFORMANCE_MARKDOWN_BYTES)
        self.assertLessEqual(os.path.getsize(os.path.join(ROOT, "STATUS.md")), STATUS_BYTES)

    def test_no_per_team_status_files(self):
        found = [os.path.relpath(p, ROOT) for p in _live_files() if os.path.basename(p) in FORBIDDEN_NAMES]
        self.assertEqual(found, [])

    def test_no_exact_duplicate_code_files(self):
        seen = {}
        duplicates = []
        for path in _live_files():
            if os.path.splitext(path)[1].lower() not in CODE_EXTS:
                continue
            with open(path, "rb") as handle:
                data = handle.read()
            if len(data) <= 200:
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen:
                duplicates.append((os.path.relpath(seen[digest], ROOT), os.path.relpath(path, ROOT)))
            else:
                seen[digest] = path
        self.assertEqual(duplicates, [])

    def test_copy_paste_stays_under_ceiling(self):
        windows = {}
        for top in PRODUCT_DIRS:
            for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for name in filenames:
                    if not name.endswith(".py"):
                        continue
                    with open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                        lines = [line.strip() for line in handle]
                    lines = [line for line in lines if line and not line.startswith("#")]
                    for start in range(len(lines) - 5):
                        text = "\n".join(lines[start:start + 6])
                        if len(text) >= 120:
                            windows[text] = windows.get(text, 0) + 1
        repeated = sum(count for count in windows.values() if count > 1)
        self.assertLessEqual(repeated, DUPLICATED_WINDOWS)


if __name__ == "__main__":
    unittest.main()
