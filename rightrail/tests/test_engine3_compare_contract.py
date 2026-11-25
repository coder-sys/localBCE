"""Independent journal and mismatch-direction fixtures for engine3_compare."""
import importlib.util
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("engine3_compare.py")
SPEC = importlib.util.spec_from_file_location("engine3_compare_contract", SCRIPT)
compare = importlib.util.module_from_spec(SPEC)
with patch.object(sys, "argv", [str(SCRIPT)]):
    SPEC.loader.exec_module(compare)


class JournalFrameTests(unittest.TestCase):
    def test_actual_rrf4_frame_is_counted(self):
        trailer = bytearray(627 + compare.chain.AUTH)  # the journal trailer's fixed parts plus the authority record
        trailer[100] = 1
        trailer[105] = 1
        trailer[174] = 1
        raw = b"RRF4" + struct.pack("<III", 1, 1, len(trailer)) + b"q" + b"a" + trailer
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "log"
            path.write_bytes(raw)
            self.assertEqual(compare.events(path), {"frames": 1, "seals": 1, "installs": 1, "reclaims": 1, "torn_tail_bytes": 0})

    def test_old_magic_and_truncated_frame_are_rejected(self):
        for raw in (b"RRF3" + b"\0" * 12, b"RRF4" + struct.pack("<III", 0, 0, 1)):
            with self.subTest(raw=raw[:4]), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "log"
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    compare.events(path)

    def test_incomplete_final_frame_is_reported_as_torn_tail_coverage(self):
        raw = b"RRF4" + struct.pack("<III", 0, 0, 627 + compare.chain.AUTH) + b"partial"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "log"
            path.write_bytes(raw)
            result = compare.events(path)
            self.assertEqual(result["frames"], 0)
            self.assertEqual(result["torn_tail_bytes"], len(raw))


class DecisionPresenceTests(unittest.TestCase):
    def test_missing_counterpart_in_either_direction_is_mismatch(self):
        row = SimpleNamespace(outcome="allow", rule="r", reasons=(), chunk=compare.NONE)
        self.assertEqual(compare.mismatch_indices({1: row}, {}), [1])
        self.assertEqual(compare.mismatch_indices({}, {2: row}), [2])

    def test_where_a_counterpart_is_stored_is_not_compared(self):
        absent = SimpleNamespace(outcome="allow", rule="r", reasons=(), chunk=compare.NONE)
        present = SimpleNamespace(outcome="allow", rule="r", reasons=(), chunk=0)
        elsewhere = SimpleNamespace(outcome="allow", rule="r", reasons=(), chunk=7)
        self.assertEqual(compare.mismatch_indices({1: present}, {1: absent}), [])  # an entry still in a window has no place in v3
        self.assertEqual(compare.mismatch_indices({1: present}, {1: elsewhere}), [])
        self.assertEqual(compare.mismatch_indices({1: absent}, {1: present}), [1])  # a place the old engine does not have
        for field, value in (("outcome", "hold"), ("rule", "s"), ("reasons", ("X",))):
            other = SimpleNamespace(**{**vars(present), field: value})
            self.assertEqual(compare.mismatch_indices({1: present}, {1: other}), [1], field)

    def test_mismatch_report_contains_both_observations(self):
        out = StringIO()
        with redirect_stdout(out):
            compare.report_mismatch("fixture", 7, 3, "old-result", None)
        self.assertEqual(out.getvalue(), "MISMATCH fixture batch 7 line 3: old old-result new None\n")


class CliExitTests(unittest.TestCase):
    def test_subprocess_cli_returns_nonzero_for_mismatch_or_refusal(self):
        code = (
            "import importlib.util,sys; "
            f"p={str(SCRIPT)!r}; "
            "s=importlib.util.spec_from_file_location('cmp_cli',p); m=importlib.util.module_from_spec(s); "
            "sys.argv=[p]; s.loader.exec_module(m); "
            "raise SystemExit(m.main([p,'unused','mixed','1','1'], "
            "bench_fn=lambda *a:{'mismatch':1,'refused':0,'lines':1,'batches':1}))"
        )
        result = subprocess.run([sys.executable, "-c", code], cwd=SCRIPT.parents[1], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_missing_worktree_is_refused(self):
        missing = str(SCRIPT.parents[1] / "no-such-worktree")
        result = subprocess.run([sys.executable, str(SCRIPT), missing, "golden"], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("STOP expected an existing WORKTREE", result.stderr)
        self.assertNotIn("SUMMARY", result.stdout)

    def test_zero_mismatch_cli_result_returns_zero(self):
        status = compare.main([str(SCRIPT), "unused", "mixed", "1", "1"],
                              bench_fn=lambda *a: {"mismatch": 0, "refused": 0, "lines": 1, "batches": 1})
        self.assertEqual(status, 0)

    def test_nonempty_mismatch_and_refusal_fail(self):
        for mismatch, refused in ((1, 0), (0, 1)):
            self.assertEqual(compare.main([str(SCRIPT), "unused", "mixed", "1", "1"],
                             bench_fn=lambda *a: {"mismatch": mismatch, "refused": refused, "lines": 1, "batches": 1}), 1)

    def test_zero_lines_batches_or_cases_cannot_pass(self):
        for lines, batches in ((0, 1), (1, 0)):
            self.assertEqual(compare.main([str(SCRIPT), "unused", "mixed", "1", "1"],
                             bench_fn=lambda *a: {"mismatch": 0, "refused": 0, "lines": lines, "batches": batches}), 1)
        self.assertEqual(compare.main([str(SCRIPT), "unused", "golden"],
                         golden_fn=lambda: {"mismatch": 0, "refused": 0, "lines": 1, "batches": 1, "cases_used": 0}), 1)

    def test_nonpositive_parameters_fail_before_running_engine(self):
        for args in (("0", "1"), ("1", "0"), ("-1", "2")):
            with patch.object(compare, "Pair", side_effect=AssertionError("must not launch")):
                self.assertEqual(compare.main([str(SCRIPT), "unused", "mixed", *args]), 1)


class SemanticLeafTests(unittest.TestCase):
    def test_only_engine_local_input_is_excluded(self):
        fields = compare.decider.Pay._fields
        leaf = compare.decider.Pay(*range(len(fields)))
        other = leaf._replace(input="different head commitment")
        self.assertEqual(compare.semantic_leaves([leaf]), compare.semantic_leaves([other]))
        for field in fields:
            if field == "input":
                continue
            with self.subTest(field=field):
                changed = leaf._replace(**{field: "different"})
                self.assertNotEqual(compare.semantic_leaves([leaf]), compare.semantic_leaves([changed]))

