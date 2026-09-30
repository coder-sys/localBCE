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
PRODUCT_CODE_LINES = 37_319  # color-a (2026-09-30): +1 for the dark-theme rail override that palette A specifies (staff.css)
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
EVIDENCE_CODE_LINES = 45_083  # partials merge with trunk b42f3f4: measured; trunk 44,323 + Lean partials A and B (proofs, KATs, TCB kinds, io-loop tests), the worker linearity test and the gate's loop fixtures
MARKDOWN_FILES = 20
# 2026-09-28 split (lead decision): the conformance/ wire spec is a normative
# contract, like test vectors, not compressible prose; it gets its own ceiling. 2026-09-30 review fixes (lean-paid-sum): +1,235 over the 157,858 measured, after cuts, for the seven XI.2 fields the paid-sum record lost, the true forged-link boundary and an accurate pin trail (auditability). The ui-1 merge with its STATUS line measures 158,372; the ceiling is that. 2026-09-30 lean-leak merge: +3,868 (162,240 measured, after cutting two stale lines) for the XI.2 records of Lean-live M1, M1.5 and M1.6 (2,473) and the worker's provenance (837), the merged STATUS and ARCHITECTURE lines (approx 550); Lean is the only evaluator and its pin is auditable. lean-leak re-pin (2026-09-30): +3,618 for the XI.2 record, the worker and gate_verify provenance, and the correction reproduction note (a change under lean/ cannot ship with an unreproduced pin), after cutting a stale STATUS run line.
# TCB gate: +381 bytes in STATUS.md so the five open VIOLATION-TODO loops (with their owning plan items) are visible where status is read; +379 more for what the gate trusts and does not prove (Init/Std, the C arena call, lcProof).
# Lean partials A: +3,057 bytes for its XI.2 record in docs/CORE_REDESIGN.md, the worker re-pin in PROVENANCE.md and the STATUS.md TCB line.
# Lean partials B: +3,588 bytes for its XI.2 record in docs/CORE_REDESIGN.md and the STATUS.md TCB line (now zero open loops), so the bounded-sampler claim, its evidence and the worker re-pin reason are on the record.
MARKDOWN_BYTES = 169_595  # partials merge with trunk b42f3f4: measured; trunk 159,603 + the partials XI.2 records, PROVENANCE receipts and STATUS lines
CONFORMANCE_MARKDOWN_BYTES = 30_000
STATUS_BYTES = 40_000
CORE_FILE_LINES = {
    "app/right_rail_financial_owner.py": 7_223,
    "app/right_rail_financial_owner_independent.py": 4_555,
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
