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

# Founder 2026-09-28 split the old single 80,000 total so the budget stops charging
# tests and proofs as bloat. Product code (what runs and must be read to be trusted)
# ratchets down; lower it to the actual size after the in-flight merges (B+, G2, G3).
# lean-leak merge (2026-09-30): +236 over trunk's 36,951 for the Lean worker's pool and frame in minimal_clearance_verifier_process.py (Lean is the only evaluator, so the Python evaluator and its
# comparison are gone: the semantic adapter, engine and owner shrank 89), and a quarter-end cash-file lock that verifies about 0.65 s less (logs lta-probe2-a1-L2, lta-probe3-a1-L1).
# TCB gate: +3 for tools/tcb_pin.ps1, the guarded run that pins the report the suite checks.
# Decoder cross-check (dec-xcheck, 2026-09-30): +116 for the BLFCRES3 re-encoder (Lean-expansion plan item 7; the BLFRES02 and frame sites already re-encode): a Python decoder that drops, defaults or normalises a field can no longer change the money decision Lean made, so the auditor need not trust it. Tests +80 (the round trip, five lenient-decoder mutants each refused, a lenient BLFRES02 decoder, an inexact rejection frame) and +325 markdown bytes (one STATUS line).
# Worker frame boundary (dec-xcheck, 2026-09-30): +10 product lines (process +4, engine +6) and +53 test lines (a well-behaved control, and an extra answer frame in the same write or arriving late, each refused with the worker dead; the watchdog test now runs over real pipes): a second answer frame that lands before the next request is written is refused, so it cannot become the next decision's answer (a late frame inside that window is still possible; the fix is a request digest echoed by Lean, a later wire change). Markdown +239 bytes: the dec-xcheck STATUS line cites the full run on the final tree (the old one cited an earlier commit) and describes the frame check.
# batch-frames-v1 D4 (d4, 2026-09-30): +2 owner lines (the second evidence query and _evidence_bindings are gone, but _insert_evaluation now takes ids or bindings and checks exactly one; the correction path keeps its receipt bindings): about 0.35 s less per quarter-end lock at E=8,500, same stored bytes. Tests +20 (a second item's evidence cited by an evaluation now fails as evaluation_evidence_missing; ids and bindings together or neither are refused).
PRODUCT_CODE_LINES = 37_524  # core-r1c: +4 (owner +3: the v3 kind index and the history_sequence refusal; checker +1: the v3 index set). Before: core-r1a2 review fix: +9 owner lines for the high-water (sequence, head) that keeps a rewound store refused for the owner's life. Before: r1a2 merge with trunk 22a090c (2026-10-01): sums the deltas over 2fa43bb's 37,411: R1a +77, cash-qe +4. Before: core-r1a2: +77 (owner +66: the kept writer, its mark and full re-verification, close and the context manager; CLI +6, staff +5, cash file +1, load tool -1: owners closed). Before: core-r05-only: +10 owner lines for R0.5 (synchronous=FULL in _connect, a new store born WAL, a pre-WAL store switched only after a migrating open verifies and refused by SHADOW or existing-only opens, the restore checkpoint and its refusal; one checker comment reworded). ui-m51: +7 (+5 the demo clock's as_of, so a read's time is the fixture's own and the screen's year rule needs no wall clock; +1 staff.js year rule; +1 the scorecard's as-of year). Before: ui-2 merge with trunk 5e2e552: trunk's 37_374 + ui-2's +20 (the record download, one time convention (program time on screen, UTC in the record) and the director's record rows, net of the deleted `allows` and reduced-motion branches and three hidden attributes). Trunk's reasons follow. r2-shrink: +17 over trunk d4383f1 (owner +13, checker +3, staff.js +1) for the derived open amount of a correction request: the linked-payment cap becomes the request's open amount and the package shows it (R2). Trunk's own reasons follow. hidden-objects: +4 checker lines (one inventory query, run first) so a case-variant trigger, a view or a sqlite_-named object can no longer change what the Owner's SQL does unseen. table-sql-pin: +31 checker lines (26 table digests and their comment; the schema check reads all table SQL once, 6 lines fewer) so a planted ON CONFLICT REPLACE or a dropped NOT NULL or CHECK is refused at open, not written through. r1-link-cap: +3 (owner +2, checker +1) for the linked-payment cap: a request can no longer collect money that is not owed (F1). color-a (2026-09-30): +1 for the dark-theme rail override that palette A specifies (staff.css)
# Tests and Lean proofs: raising needs a commit line naming the behaviours or
# theorems the new lines cover.
# Lean paid sum (lean-paid-sum, 2026-09-29): +1,251 over trunk's 41,327 (42,585 measured on the merge, 7 more than the sum of the two deltas) for the 3 PaidSum laws
# (`linkedActivePaidCents_reverse`, `_retarget`, `_total_le_active`), the 7 PaidSumTheorems
# (`derivedCorrectionPaid_sound`, `_complete`, `outstandingCorrectionCents_eq_linked`,
# `applyCorrectionTransition_links_admissible`, `_paid_eq_linked`, `_action_amount_eq_linked`,
# `_outstanding_within_shortfall_linked`), the 2 KATs `reversed_linked_payment_pays_nothing`
# and `link_naming_unknown_request_rejected`, and their tests.
# Direction-6 staff workspace (ui-1: 1b7e390, 7663741), +284 over that (283 test lines, one comment line): the tests prove every staff control in a real browser, so an approver's lost answer, a stale confirm and each role's keys are checked, not assumed.
# lean-leak merge (2026-09-30): +863 over that, for the Lean worker's 10 `WorkerLaws` theorems (`workerRespondBA_eq`, `evaluateWire_evaluated`,
# `workerRespond_length_le`, `maxWorkerFrameBytes_fits_u32`, the codec and decoder equalities), the worker and its panic probe (`Worker`, `WorkerCli`, `PanicProbe`, `FastDecode`,
# `FastEncode`) and their tests, net of the deleted Python-evaluator tests: a Lean panic or a bad worker frame refuses the write instead of passing.
# TCB gate (tcb-gate, 2026-09-30): +313 for tools/tcb_gate.lean (152) and tests/test_tcb_gate.py (158): an auditor gets a machine-checked list of every escape hatch (axiom, partial, extern, implemented_by) each pinned exe can reach, and a violation fails the suite.  rr-check fixes: +60 more (partial bodies walked, lcProof and bare-initializer cases, the report bound to the pinned exe bytes).
# Lean partials A (2026-09-30): +533 for `ReadUpTo`, `serveWorker_run`, `serveWorker_stateless`, `readUpTo_pipe`, `workerRun_frames/oversize/truncated`, their KATs and pins, the TCB gate's `fixpoint` kind
# and `tests/test_lean_io_loops.py`, net of the deleted `serve`, `readExact` and `readFinancialBounded` loops: an auditor reads the worker's frame loop as a theorem, not a claim, and the byte-identical I/O is tested.
# Lean partials B (2026-09-30): +202 (three of them this comment) for the six ML-DSA sampler laws in `Gate/MlDsa87Laws.lean` (`rejNtt`/`sampleInBall` never read past Table 3, `verify` rejects when they give up, the fill/sign/limit lemmas),
# their KATs and axiom pins, and the TCB gate's `loop` kind with its negative fixture: an auditor reads gate_verify's samplers as bounded theorems, and a new while/repeat anywhere fails the gate.
# Worker linearity guard (quad, 2026-09-30): +13 for one test that fails if worker time is quadratic in rows (10,000 rows took 16 s until ea42222).
EVIDENCE_CODE_LINES = 59_530  # core-r1c review fix: +16 (the hidden-index test's follow-through events case and its per-case check). Before: core-r1c: +84 (the R1c input tamper test ported from 958947a +71; index tests for the v3 set and the v1/v2 upgrades +13). Before: core-r1a2 review fix: +4 (the in-place rewind test that runs on Windows; the fork test now refused). Before: r1a2 merge with trunk 22a090c (2026-10-01): sums the deltas over 2fa43bb's 54,148: R1a +243, M3 rev 1.2 +5,035. Before: core-r1a2: +243 (core_r1 tests +213; every fixture closes its owners; main-file bytes become the serialize() image). Before: mldsa-t4 merge with trunk a52f852 (2026-10-01): base 51,611 + NTT proofs +811 + trunk +1,726 (R0.5, bf-lean). Before: mldsa-t4: +811 in tools/mldsa87_goals.lean (proofs of invNtt_ntt and invNtt_pointwise with axiom pins; the zeta tables are bit-reversal identities, not kernel evaluation of zetas). Before: mldsa-t3 merge with trunk 6bb097c: +669 in tools/mldsa87_goals.lean (proofs of verify_true_checks, sig_canonical and sponge_prefix; rejNtt_stable and sampleInBall_stable now unconditional). Before: stale-corr: +257 over trunk b6ae33b for three acceptance tests (a moot request is not waiting on delivery; every asking action must be delivered; the 28-ordering owner-versus-oracle sweep), the browser test of the acknowledge step, the oracle's independent delivery rule, and tools/stale_correction_goals.lean (statements and the proofs of all six). Trunk's own reasons follow. ui-m51 merge with trunk 0e59bc4: +19 for ui-m51 (the chronology-fact unit test, the 2027-read crawl check and the year-aware time regex). Before: core-thm merge with trunk 5c2c7bc: +113 for ui-2 (+111 M5 crawl tests, +2 role-neutral download fix). Before: core-thm merge with trunk 5e2e552: trunk's 48,646 + core-thm's +1,907 over adc8b53 (15 proved correction and evaluator theorems incl. N2a/N2, 18 axiom pins; adds no compiled code). Trunk's reasons follow. r2-shrink: +290 over trunk d4383f1 for R2's four acceptance tests, the invariant test, the browser test of the record-cash button, the oracle's independent open_cents loop and the Lean goals file tools/r2_request_shrink_goals.lean (155 lines, statements only until M3 step 2). Trunk's own reasons follow. hidden-objects: +28 for test_checker_refuses_every_hidden_schema_object (seven hidden objects refused, red on 53fa427). table-sql-pin: +28 for test_checker_pins_every_table_clause (four forgeries refused, a whitespace-only edit accepted). keccak-dedupe merge with trunk d02458a: -99 over trunk's 48_399 (-112 for the deleted duplicate `Keccak.lean`, +13 for the block-boundary SHA-3/SHAKE KATs and four WorkerLaws pins net). Trunk's own reasons follow. +58 r1-link-cap: the F1 regression test (a linked payment never pays past the balance), the scenario-B, still-owed and forged-link tests and the S4 mutant rebuilt on two requests so the checker's request limit is tested alone, so the double collection stays refused, owner and checker. +478 mldsa-thm-stmts merge: tools/mldsa87_goals.lean, the fixed ML-DSA-87 statements and proofs of the non-bypass group, rejNtt/sampleInBall stability and useHint_lt with axiom pins (5 still sorry). +2 LF manifest (one dict line in each of the two manifest tests). m3-step1 merge: +2,731 Lean lines (27 pinned Payment theorems, form-A codec, KATs; nothing calls them yet). dpk-window-fix: +40 for the two window tests (every window gives the full-window verdict, incl. a reversed-payment page). Before that: +7 mirror test: the store-counter leak check walks leaf values instead of a substring search that hit "10" in the D5A06E9F pin hex. partials merge with trunk b42f3f4: measured; trunk 44,323 + Lean partials A and B (proofs, KATs, TCB kinds, io-loop tests), the worker linearity test and the gate's loop fixtures
MARKDOWN_FILES = 20
# 2026-09-28 split (lead decision): the conformance/ wire spec is a normative
# contract, like test vectors, not compressible prose; it gets its own ceiling. 2026-09-30 review fixes (lean-paid-sum): +1,235 over the 157,858 measured, after cuts, for the seven XI.2 fields the paid-sum record lost, the true forged-link boundary and an accurate pin trail (auditability). The ui-1 merge with its STATUS line measures 158,372; the ceiling is that. 2026-09-30 lean-leak merge: +3,868 (162,240 measured, after cutting two stale lines) for the XI.2 records of Lean-live M1, M1.5 and M1.6 (2,473) and the worker's provenance (837), the merged STATUS and ARCHITECTURE lines (approx 550); Lean is the only evaluator and its pin is auditable. lean-leak re-pin (2026-09-30): +3,618 for the XI.2 record, the worker and gate_verify provenance, and the correction reproduction note (a change under lean/ cannot ship with an unreproduced pin), after cutting a stale STATUS run line.
# TCB gate: +381 bytes in STATUS.md so the five open VIOLATION-TODO loops (with their owning plan items) are visible where status is read; +379 more for what the gate trusts and does not prove (Init/Std, the C arena call, lcProof).
# Lean partials A: +3,057 bytes for its XI.2 record in docs/CORE_REDESIGN.md, the worker re-pin in PROVENANCE.md and the STATUS.md TCB line.
# Lean partials B: +3,588 bytes for its XI.2 record in docs/CORE_REDESIGN.md and the STATUS.md TCB line (now zero open loops), so the bounded-sampler claim, its evidence and the worker re-pin reason are on the record.
MARKDOWN_BYTES = 220_836  # core-r1c review fix: +2,081 for the record's table of every financial_events read and its plans, the follow-through strength entry, the SHADOW wording and the run counts. Before: core-r1c: +3,870 for its XI.2 record (per-check strength, the quarter-end split) and STATUS line. Before: core-r1a2 review fix: +1,472 for the R1a record's high-water, the weaker raw-edit vector and the known lows. Before: r1a2 merge with trunk 22a090c (2026-10-01): sums the deltas over 2fa43bb's 208,942: R1a +3,918, trunk +553 (M3 +416, cash-qe +137). Before: core-r1a2: +3,918 for its XI.2 record and STATUS line. Before: bf-lean merge with trunk ceaf396 (2026-10-01): base 201,280 + bf-lean +4,194 + R0.5 +3,468. Before: bf-lean merge with trunk 6bb097c: trunk's 201,280 (0e59bc4's 197,705 + stale-corr +3,575) + bf-lean +4,194 (+3,701 for the cursor re-pin record, +493 for the review fixes: the coverage test's gate note, the corrected `ba.toList` and ten-theorem wording, the scope-and-duration, ByteArray.beq and FastEncode notes, the wider differential), after trimming 1,142 bytes from the first draft; measured, bf1m-bloat4. Bf-lean's reasons: bf-lean cursor re-pin (2026-10-01): +3,701 measured over trunk 0e59bc4's 197,705 for its XI.2 record (the M-1 numbers, the pin, the differential), the re-pin section of the correction PROVENANCE.md, the gate_verify manifest note and the STATUS line. Trunk's reasons follow. core-thm re-pin (2026-10-01): +2,389 measured over 195,316 for XI.2 record 4, the re-pin section of the correction PROVENANCE.md, the gate_verify manifest note and the STATUS.md pin line (a pin change cannot ship without its evidence trail). Before that, core-thm merge with trunk 5e2e552: trunk's 191,641 + core-thm's +3,675 over adc8b53 (its XI.2 record and theorem list in docs/CORE_REDESIGN.md, with the review's evidence and gate-closure corrections). Trunk's reasons follow. r2-shrink: +5,232 over trunk d4383f1 for XI.2 record 4 in docs/CORE_REDESIGN.md (open correction requests shrink, with predicate, invariant, evidence and kill criteria) and its STATUS.md line. keccak-dedupe merge with trunk d02458a: +3,823 over trunk's 178_291 for its XI.2 records in docs/CORE_REDESIGN.md, the correction re-pin in PROVENANCE.md and the STATUS.md receipt scope. Trunk's own reasons follow. hidden-objects: +1,459 for the corrected XI.2 record (+1,322: the case trick, the inventory, the withdrawn claim) and STATUS line (+137). table-sql-pin: +2,836 for its XI.2 record (+2,617) and STATUS line (+219). keccak-dedupe merge with trunk d02458a: +3,823 over trunk's 178_291 for its XI.2 records in docs/CORE_REDESIGN.md, the correction re-pin in PROVENANCE.md and the STATUS.md receipt scope. Trunk's own reasons follow. r1-link-cap: +2,583 over trunk for XI.2 records 3 and 2 in docs/CORE_REDESIGN.md (the F1 claim withdrawn, restored by the linked-payment cap; pre-R1 stores that fail by design; store scan and mutation evidence). +1,143 LF-manifest XI.2 record and PROVENANCE note. m3-step1 merge: +1,933 for its XI.2 record. dpk-window-fix: +3,037 for its XI.2 record in docs/CORE_REDESIGN.md and a STATUS.md line (verdicts on partial windows change; contract stays v2). Before that: partials merge with trunk b42f3f4: measured; trunk 159,603 + the partials XI.2 records, PROVENANCE receipts and STATUS lines  Trunk 6bb097c's reasons (stale-corr): stale-corr: +3,575 over trunk b6ae33b for its XI.2 record in docs/CORE_REDESIGN.md (the delivery verdict reads every asking action, not the newest; the receipt's newest-action delivery_status named as a V.1/V.2 gap) and the rewritten STATUS.md stale-corrections line. Trunk's own reasons follow. core-thm re-pin (2026-10-01): +2,389 measured over 195,316 for XI.2 record 4, the re-pin section of the correction PROVENANCE.md, the gate_verify manifest note and the STATUS.md pin line (a pin change cannot ship without its evidence trail). Before that, core-thm merge with trunk 5e2e552: trunk's 191,641 + core-thm's +3,675 over adc8b53 (its XI.2 record and theorem list in docs/CORE_REDESIGN.md, with the review's evidence and gate-closure corrections). Trunk's reasons follow. r2-shrink: +5,232 over trunk d4383f1 for XI.2 record 4 in docs/CORE_REDESIGN.md (open correction requests shrink, with predicate, invariant, evidence and kill criteria) and its STATUS.md line. keccak-dedupe merge with trunk d02458a: +3,823 over trunk's 178_291 for its XI.2 records in docs/CORE_REDESIGN.md, the correction re-pin in PROVENANCE.md and the STATUS.md receipt scope. Trunk's own reasons follow. hidden-objects: +1,459 for the corrected XI.2 record (+1,322: the case trick, the inventory, the withdrawn claim) and STATUS line (+137). table-sql-pin: +2,836 for its XI.2 record (+2,617) and STATUS line (+219). keccak-dedupe merge with trunk d02458a: +3,823 over trunk's 178_291 for its XI.2 records in docs/CORE_REDESIGN.md, the correction re-pin in PROVENANCE.md and the STATUS.md receipt scope. Trunk's own reasons follow. r1-link-cap: +2,583 over trunk for XI.2 records 3 and 2 in docs/CORE_REDESIGN.md (the F1 claim withdrawn, restored by the linked-payment cap; pre-R1 stores that fail by design; store scan and mutation evidence). +1,143 LF-manifest XI.2 record and PROVENANCE note. m3-step1 merge: +1,933 for its XI.2 record. dpk-window-fix: +3,037 for its XI.2 record in docs/CORE_REDESIGN.md and a STATUS.md line (verdicts on partial windows change; contract stays v2). Before that: partials merge with trunk b42f3f4: measured; trunk 159,603 + the partials XI.2 records, PROVENANCE receipts and STATUS lines
CONFORMANCE_MARKDOWN_BYTES = 30_000
STATUS_BYTES = 40_000
CORE_FILE_LINES = {
    "app/right_rail_financial_owner.py": 7_330,  # core-r1c: +3 for the v3 events-by-kind index and the history_sequence refusal. Before: core-r1a2 review fix: +9 for the rewind high-water. r1a2 merge with trunk 22a090c (2026-10-01): sums the deltas over 2fa43bb's 7,248: R1a +66, cash-qe +4. Before: core-r1a2: +66 for R1a (writer, mark, re-verification, close). core-r05-only: +10 for R0.5 (sync, WAL at creation and on a migrating open, the restore checkpoint). r2-shrink: +13 for the derived open amount (helper, link cap, package field). r1-link-cap: +2 for the linked-payment cap (F1)
    "app/right_rail_financial_owner_independent.py": 4_614,  # core-r1c: +1 for the v3 private index set. r2-shrink: +3 for the closed-form open-amount limit on a linked payment. hidden-objects: +4 for the schema inventory. table-sql-pin: +31 for the table SQL pin. r1-link-cap: +1 for the checker's matching limit (F1)
    "app/right_rail_financial_semantic_adapter.py": 2_097,
    "app/right_rail_financial_mirror.py": 1_497,
    "app/right_rail_financial_engine.py": 1_502,
    "app/right_rail_financial_switch.py": 1_314,
    "app/right_rail_financial_line_pack.py": 253,
    "app/right_rail_financial_followthrough.py": 337,
}
FORBIDDEN_NAMES = {"CURRENT_TASK.md", "STATE.md", "AGENTS.override.md"}
# Copy-paste: repeated 6-line windows (>=120 chars) across product Python.
# Independent checkers may restate a small shared schema by design; the rest
# is duplication to delete.
PRODUCT_DIRS = ("app", "tools", os.path.join("provider_app", "provider_app"))
DUPLICATED_WINDOWS = 410


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
            if ext in CODE_EXTS:
                parts = os.path.relpath(p, ROOT).split(os.sep)
                totals["evidence" if ext == ".lean" or "tests" in parts[:-1] or parts[0] == "lean" else "product"] += _lines(p)
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
